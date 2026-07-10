#include "rules/NullDerefRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/DataflowEngine.h"
#include "engine/FunctionSummary.h"
#include "engine/ConditionWalk.h"
#include "engine/GuardedDisjuncts.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- NullState lattice ---
//
// Unknown : no information (parameter, opaque function return)
// Null    : definitely null on all paths
// NonNull : definitely not null on all paths
// MaybeNull: null on at least one path (reportable signal)

enum class NullState { Unknown, Null, NonNull, MaybeNull };

NullState mergeNullStates(NullState a, NullState b) {
    if (a == b) return a;
    // Null knowledge on any path is preserved; only NonNull + Unknown
    // decays to no knowledge (same shape as the DivByZero merge)
    bool anyNullInfo = a == NullState::Null || a == NullState::MaybeNull ||
                       b == NullState::Null || b == NullState::MaybeNull;
    return anyNullInfo ? NullState::MaybeNull : NullState::Unknown;
}

// --- Expression null-ness evaluation ---

const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

NullState evaluateNullness(const Expr* expr) {
    if (!expr) return NullState::Unknown;
    // Strip explicit casts too: (int*)0, (Node*)nullptr
    expr = expr->IgnoreParenCasts();

    if (isa<CXXNullPtrLiteralExpr>(expr)) return NullState::Null;
    if (isa<GNUNullExpr>(expr)) return NullState::Null;
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0 ? NullState::Null : NullState::NonNull;

    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() == UO_AddrOf) return NullState::NonNull;
    }
    if (isa<CXXNewExpr>(expr)) return NullState::NonNull;
    if (isa<StringLiteral>(expr)) return NullState::NonNull;
    if (isa<CXXThisExpr>(expr)) return NullState::NonNull;

    // Interprocedural: the null-ness of a call's return comes from the
    // function summary. A "may return null" summary produces MaybeNull —
    // an unguarded dereference becomes a warning; guarded use stays
    // clean via the assume-edge.
    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        using RN = zerodefect::SummaryRegistry::ReturnNullness;
        const auto* summary =
            zerodefect::SummaryRegistry::instance().lookup(
                call->getDirectCallee());
        if (summary) {
            if (summary->returnNullness == RN::NeverNull)
                return NullState::NonNull;
            if (summary->returnNullness == RN::MaybeNull)
                return NullState::MaybeNull;
        }
        return NullState::Unknown;
    }

    return NullState::Unknown;
}

// --- Statement classification ---

enum class EffectKind { None, Assign, AssignUnknown, Deref };

struct Effect {
    const VarDecl* var = nullptr;
    EffectKind kind = EffectKind::None;
    NullState value = NullState::Unknown;  // only for Assign
};

Effect classifyStmt(const Stmt* stmt) {
    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        // In a multi-declaration the first pointer init is taken; the
        // rest start Unknown (conservative). Rare case, noted in the todo.
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (vd->getType()->isPointerType() && vd->hasInit())
                    return {vd, EffectKind::Assign,
                            evaluateNullness(vd->getInit())};
            }
        }
        return {};
    }
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign)
            if (const auto* var = asVar(binOp->getLHS()))
                return {var, EffectKind::Assign,
                        evaluateNullness(binOp->getRHS())};
        return {};
    }
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
        // If &p goes to a function, p may have been assigned a value
        if (unary->getOpcode() == UO_AddrOf)
            if (const auto* var = asVar(unary->getSubExpr()))
                return {var, EffectKind::AssignUnknown};
        if (unary->getOpcode() == UO_Deref)
            if (const auto* var = asVar(unary->getSubExpr()))
                return {var, EffectKind::Deref};
        return {};
    }
    if (const auto* member = dyn_cast<MemberExpr>(stmt)) {
        if (member->isArrow())
            if (const auto* var = asVar(member->getBase()))
                return {var, EffectKind::Deref};
        return {};
    }
    if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(stmt)) {
        if (const auto* var = asVar(subscript->getBase()))
            return {var, EffectKind::Deref};
        return {};
    }
    return {};
}

// --- Branch condition refinement (assume edges) ---

using NullVarState = std::map<const VarDecl*, NullState>;

void setIfTracked(NullVarState& state, const VarDecl* var, NullState value) {
    if (!var) return;
    auto it = state.find(var);
    if (it != state.end()) it->second = value;
}

// Via the shared walk skeleton (engine/ConditionWalk.h): `if (p)`,
// `!p`, `p ==/!= nullptr/NULL/0`, && / || short-circuiting.
void applyCondition(const Expr* cond, bool isTrue, NullVarState& state) {
    zerodefect::walkNullCondition(
        cond, isTrue, [&](const VarDecl* var, bool isNull) {
            setIfTracked(state, var,
                         isNull ? NullState::Null : NullState::NonNull);
        });
}

// --- Collect tracked pointer variables ---

std::vector<const VarDecl*> collectTrackedVars(const FunctionDecl* funcDecl,
                                                ASTContext& ctx) {
    std::set<const VarDecl*> vars;

    // All pointer local variables and parameters appearing in the
    // function. Parameters start Unknown — no assumption is made about
    // the caller.
    auto ptrVarMatcher = varDecl(hasType(pointerType())).bind("var");
    auto wrapper = functionDecl(equalsNode(funcDecl),
                                 forEachDescendant(ptrVarMatcher));
    for (const auto& result : match(wrapper, *funcDecl, ctx)) {
        if (const auto* v = result.getNodeAs<VarDecl>("var"))
            vars.insert(v);
    }
    for (const auto* param : funcDecl->parameters()) {
        if (param->getType()->isPointerType())
            vars.insert(param);
    }
    return {vars.begin(), vars.end()};
}

// --- Analysis struct for DataflowEngine ---

class NullDerefAnalysis {
public:
    // Guarded disjuncts (targeted path sensitivity): the Juliet
    // int_07/08/09 pattern — `if(staticTrue) data = alloc; ...
    // if(staticTrue) *data;` — produced a false "may be null" under
    // correlation-free analysis. The shared machinery is in
    // engine/GuardedDisjuncts.h; the pointer nullness refinement
    // (applyCondition) is additionally applied per disjunct.
    using State = zerodefect::GuardedState<NullVarState>;

    NullDerefAnalysis(const std::vector<const VarDecl*>& trackedVars,
                      std::set<const ValueDecl*> mutatedDecls,
                      std::string funcName,
                      zerodefect::DiagnosticList& results)
        : mutated_(std::move(mutatedDecls)),
          funcName_(std::move(funcName)), results_(results) {
        zerodefect::Guarded<NullVarState> init;
        for (const auto* var : trackedVars)
            init.vars[var] = NullState::Unknown;
        initState_.push_back(std::move(init));
    }

    State initialState() const { return initState_; }

    // The per-variable NullState chain makes at most 3 transitions;
    // the number of disjuncts multiplies the height
    unsigned latticeHeight() const {
        return (static_cast<unsigned>(initState_.front().vars.size()) * 3 +
                1) * static_cast<unsigned>(zerodefect::kMaxDisjuncts) + 4;
    }

    State merge(const State& a, const State& b) const {
        return zerodefect::mergeGuarded(a, b, mergeNullStates);
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& /*ctx*/) const {
        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Assign &&
            effect.kind != EffectKind::AssignUnknown)
            return in;

        State out = in;
        for (auto& d : out) {
            auto it = d.vars.find(effect.var);
            if (it == d.vars.end()) continue;  // not tracked
            it->second = (effect.kind == EffectKind::Assign)
                             ? effect.value
                             : NullState::Unknown;
        }
        return out;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        const auto* condExpr = dyn_cast<Expr>(cond);
        zerodefect::refineGuardedFacts(state, condExpr, isTrueBranch,
                                       mutated_, mergeNullStates);
        for (auto& d : state)
            applyCondition(condExpr, isTrueBranch, d.vars);
    }

    // Guard trace (Trace v2): during the reporting pass, if the edge
    // refinement made a variable DEFINITELY null, a trace note is added
    // at the condition point — the "why null" question for the
    // `if (p == 0) { *p }` finding now has an answer (null coming purely
    // from a guard, with no assignment, used to be traceless).
    void onEdgeRefined(const Stmt* cond, bool /*isTrueBranch*/,
                       const State& beforeDisjuncts,
                       const State& afterDisjuncts, ASTContext& ctx) {
        NullVarState before =
            zerodefect::flattenGuarded(beforeDisjuncts, mergeNullStates);
        NullVarState after =
            zerodefect::flattenGuarded(afterDisjuncts, mergeNullStates);
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState == NullState::Null)
                recordEvent(cond, var, ctx,
                            zerodefect::MsgId::TraceAssumedNullHere);
        }
    }

    void onStatement(const Stmt* stmt, const State& beforeDisjuncts,
                     const State& afterDisjuncts, ASTContext& ctx) {
        NullVarState before =
            zerodefect::flattenGuarded(beforeDisjuncts, mergeNullStates);
        NullVarState after =
            zerodefect::flattenGuarded(afterDisjuncts, mergeNullStates);
        // Dataflow trace: record transitions to null / possibly-null
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState == NullState::Null)
                recordEvent(stmt, var, ctx,
                            zerodefect::MsgId::TraceAssignedNullHere);
            else if (afterState == NullState::MaybeNull)
                recordEvent(stmt, var, ctx,
                            zerodefect::MsgId::TraceAssignedMaybeNullHere);
        }

        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Deref) return;

        auto it = before.find(effect.var);
        if (it == before.end()) return;
        if (it->second != NullState::Null &&
            it->second != NullState::MaybeNull)
            return;

        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reported_.emplace(effect.var, line).second) return;

        zerodefect::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "null-deref";
        diag.function = funcName_;
        if (it->second == NullState::Null) {
            diag.severity = zerodefect::Severity::Error;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::NullDerefDefinite,
                effect.var->getNameAsString());
        } else {
            diag.severity = zerodefect::Severity::Warning;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::NullDerefMaybe,
                effect.var->getNameAsString());
        }
        results_.push_back(diag);
        noteTargets_.emplace_back(results_.size() - 1, effect.var);
    }

    // After the run finishes: attach the null-assignment traces to reports
    void attachTraces() {
        for (const auto& [index, var] : noteTargets_) {
            auto it = events_.find(var);
            if (it == events_.end()) continue;
            auto notes = it->second;
            std::sort(notes.begin(), notes.end());
            if (notes.size() > 6) notes.resize(6);
            results_[index].notes = std::move(notes);
        }
        noteTargets_.clear();
    }

private:
    void recordEvent(const Stmt* stmt, const VarDecl* var,
                     ASTContext& ctx, zerodefect::MsgId msgId) {
        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        zerodefect::TraceNote note;
        note.file = sm.getFilename(loc).str();
        note.line = sm.getSpellingLineNumber(loc);
        note.column = sm.getSpellingColumnNumber(loc);
        note.message = zerodefect::msg(msgId, var->getNameAsString());

        auto& list = events_[var];
        for (const auto& existing : list)
            if (existing.line == note.line) return;
        list.push_back(std::move(note));
    }

    std::set<const ValueDecl*> mutated_;
    std::string funcName_;
    zerodefect::DiagnosticList& results_;
    State initState_;
    std::set<std::pair<const VarDecl*, unsigned>> reported_;
    std::map<const VarDecl*, std::vector<zerodefect::TraceNote>> events_;
    std::vector<std::pair<size_t, const VarDecl*>> noteTargets_;
};

// --- Matcher callback ---

class NullDerefCallback : public MatchFinder::MatchCallback {
public:
    explicit NullDerefCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;
        if (!zerodefect::functionFilterAllows(*func)) return;
        if (!zerodefect::lineFilterAllows(*func, sm)) return;

        auto trackedVars = collectTrackedVars(func, *result.Context);
        if (trackedVars.empty()) return;

        NullDerefAnalysis analysis(
            trackedVars, zerodefect::collectMutatedDecls(func),
            func->getQualifiedNameAsString(), results_);
        auto df = zerodefect::runDataflow(func, *result.Context, analysis);
        if (!df.converged)
            std::cerr << zerodefect::msg(
                zerodefect::MsgId::AnalysisNotConverged,
                func->getQualifiedNameAsString()) << "\n";
        analysis.attachTraces();
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string NullDerefRule::id() const {
    return "null-deref";
}

std::string NullDerefRule::description() const {
    return "CFG-based null pointer dereference analysis with branch "
           "condition refinement";
}

Severity NullDerefRule::defaultSeverity() const {
    return Severity::Error;
}

void NullDerefRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    MatchFinder finder;
    NullDerefCallback callback(results);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
