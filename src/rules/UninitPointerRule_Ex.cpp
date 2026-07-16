#include "rules/UninitPointerRule_Ex.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CoverageReport.h"
#include "engine/CallRefArgs.h"
#include "engine/DataflowEngine.h"
#include "engine/GuardedDisjuncts.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
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

// --- PtrState lattice ---

enum class PtrState { Uninit, MaybeInit, Init };

PtrState mergePtrStates(PtrState a, PtrState b) {
    if (a == b) return a;
    return PtrState::MaybeInit;
}

// --- Statement classification ---
// CFG elements contain sub-expressions as separate elements; looking only
// at the top node of each element is enough (no nested search inside the
// statement is needed). The node itself tells which variable it touches —
// no per-variable loop is needed either.

enum class EffectKind { None, Assigns, Dereferences };

struct Effect {
    const VarDecl* var = nullptr;
    EffectKind kind = EffectKind::None;
};

const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

Effect classifyStmt(const Stmt* stmt) {
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign)
            if (const auto* var = asVar(binOp->getLHS()))
                return {var, EffectKind::Assigns};
        return {};
    }
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
        // &p: may have been initialized via out-param — conservative Assigns
        if (unary->getOpcode() == UO_AddrOf)
            if (const auto* var = asVar(unary->getSubExpr()))
                return {var, EffectKind::Assigns};
        if (unary->getOpcode() == UO_Deref)
            if (const auto* var = asVar(unary->getSubExpr()))
                return {var, EffectKind::Dereferences};
        return {};
    }
    if (const auto* member = dyn_cast<MemberExpr>(stmt)) {
        if (member->isArrow())
            if (const auto* var = asVar(member->getBase()))
                return {var, EffectKind::Dereferences};
        return {};
    }
    if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(stmt)) {
        if (const auto* var = asVar(subscript->getBase()))
            return {var, EffectKind::Dereferences};
        return {};
    }
    return {};
}

// --- Structural must-assign filter ---
//
// The TFLite resize_bilinear lesson (2026-07-16): a pointer assigned
// unconditionally inside `for (int c = 0; c < 8; ++c)` IS assigned
// when a later statement runs — the loop provably executes — but the
// dataflow cannot keep that proof: the zero-trip path's infeasibility
// lives in a literal-stamped fact disjunct, and in large functions the
// kMaxDisjuncts collapse erases it (24 false ERROR reports). No local
// collapse heuristic can know which fact a later edge will need, so
// the proof is re-established STRUCTURALLY at report time, the same
// way Java's definite-assignment (JLS 16) reasons: suppression-only,
// and only when every obligation is discharged —
//   * the function has no goto/label/switch (no unstructured entry);
//   * a for-loop L: `for (int i = A; i </<= B; ...)` with integer
//     literals A < B (first trip guaranteed), whose body contains a
//     TOP-LEVEL `var = ...` and NO break/continue/return/goto anywhere
//     (the assignment cannot be bypassed);
//   * the dereference sits in a LATER SIBLING of L in the same
//     compound — structured flow reaches it only through L.
// Anything unproven keeps its report.

bool hasUnstructuredFlow(const Stmt* body) {
    struct V : RecursiveASTVisitor<V> {
        bool bad = false;
        bool VisitGotoStmt(GotoStmt*) { bad = true; return false; }
        bool VisitIndirectGotoStmt(IndirectGotoStmt*) {
            bad = true; return false;
        }
        bool VisitLabelStmt(LabelStmt*) { bad = true; return false; }
        bool VisitSwitchStmt(SwitchStmt*) { bad = true; return false; }
    } v;
    v.TraverseStmt(const_cast<Stmt*>(body));
    return v.bad;
}

bool hasEarlyExit(const Stmt* s) {
    struct V : RecursiveASTVisitor<V> {
        bool bad = false;
        bool VisitBreakStmt(BreakStmt*) { bad = true; return false; }
        bool VisitContinueStmt(ContinueStmt*) { bad = true; return false; }
        bool VisitReturnStmt(ReturnStmt*) { bad = true; return false; }
        bool VisitGotoStmt(GotoStmt*) { bad = true; return false; }
    } v;
    v.TraverseStmt(const_cast<Stmt*>(s));
    return v.bad;
}

bool subtreeContains(const Stmt* root, const Stmt* needle) {
    if (!root) return false;
    if (root == needle) return true;
    for (const Stmt* c : root->children())
        if (subtreeContains(c, needle)) return true;
    return false;
}

// `for (int i = A; i < B; ...)` / `<=` with integer literals and A
// below B: the body runs at least once on every execution of the loop
// statement.
bool guaranteedFirstTrip(const ForStmt* loop) {
    const auto* ds = dyn_cast_or_null<DeclStmt>(loop->getInit());
    if (!ds || !ds->isSingleDecl()) return false;
    const auto* iv = dyn_cast<VarDecl>(ds->getSingleDecl());
    if (!iv || !iv->hasInit()) return false;
    const auto* initLit =
        dyn_cast<IntegerLiteral>(iv->getInit()->IgnoreParenImpCasts());
    if (!initLit) return false;

    const auto* cond = dyn_cast_or_null<BinaryOperator>(loop->getCond());
    if (!cond ||
        (cond->getOpcode() != BO_LT && cond->getOpcode() != BO_LE))
        return false;
    const auto* lhs =
        dyn_cast<DeclRefExpr>(cond->getLHS()->IgnoreParenImpCasts());
    if (!lhs || lhs->getDecl() != iv) return false;
    const auto* boundLit =
        dyn_cast<IntegerLiteral>(cond->getRHS()->IgnoreParenImpCasts());
    if (!boundLit) return false;

    // Plain literals are non-negative (a negative constant is a
    // UnaryOperator and fails the cast above), so unsigned compare.
    llvm::APInt a = initLit->getValue();
    llvm::APInt b = boundLit->getValue();
    const unsigned w = std::max(a.getBitWidth(), b.getBitWidth());
    a = a.zext(w);
    b = b.zext(w);
    return cond->getOpcode() == BO_LT ? a.ult(b) : a.ule(b);
}

// The loop body assigns `var` as a top-level statement and contains no
// way to bypass it (conservative: no early exit anywhere in the body).
bool bodyAssignsUnconditionally(const ForStmt* loop, const VarDecl* var) {
    const auto* body = dyn_cast_or_null<CompoundStmt>(loop->getBody());
    if (!body) return false;
    bool found = false;
    for (const Stmt* s : body->body()) {
        if (const auto* bin = dyn_cast<BinaryOperator>(s))
            if (bin->getOpcode() == BO_Assign && asVar(bin->getLHS()) == var) {
                found = true;
                break;
            }
    }
    return found && !hasEarlyExit(loop->getBody());
}

bool provenAssignedBefore(const FunctionDecl* fn, const VarDecl* var,
                          const Stmt* use) {
    const Stmt* body = fn ? fn->getBody() : nullptr;
    if (!body || hasUnstructuredFlow(body)) return false;

    struct V : RecursiveASTVisitor<V> {
        const VarDecl* var = nullptr;
        const Stmt* use = nullptr;
        bool proven = false;
        bool VisitCompoundStmt(CompoundStmt* cs) {
            bool sawQualifying = false;
            for (const Stmt* s : cs->body()) {
                if (sawQualifying && subtreeContains(s, use)) {
                    proven = true;
                    return false;
                }
                if (const auto* fs = dyn_cast<ForStmt>(s))
                    if (guaranteedFirstTrip(fs) &&
                        bodyAssignsUnconditionally(fs, var))
                        sawQualifying = true;
            }
            return true;
        }
    } v;
    v.var = var;
    v.use = use;
    v.TraverseStmt(const_cast<Stmt*>(body));
    return v.proven;
}

// --- Collect tracked pointer variables ---

std::vector<const VarDecl*> collectTrackedVars(const FunctionDecl* funcDecl,
                                                ASTContext& ctx) {
    std::set<const VarDecl*> vars;

    // Static- and thread-storage-duration pointers are NOT tracked as
    // uninitialized: C zero-initializes them (`static char *buf;`
    // starts as NULL — defined, not indeterminate). Their null-ness
    // is NullDeref's domain, not this rule's. Only automatic-storage
    // locals without an initializer are genuinely uninitialized.
    // (tmux screen_print/buf FP, 2026-07-13.)
    auto uninitPtrMatcher = varDecl(
        hasType(pointerType()),
        unless(hasInitializer(anything())),
        unless(parmVarDecl()),
        unless(hasStaticStorageDuration()),
        unless(hasThreadStorageDuration())
    ).bind("var");

    auto wrapper = functionDecl(equalsNode(funcDecl),
                                 forEachDescendant(uninitPtrMatcher));
    for (const auto& result : match(wrapper, *funcDecl, ctx)) {
        if (const auto* v = result.getNodeAs<VarDecl>("var"))
            vars.insert(v);
    }
    return {vars.begin(), vars.end()};
}

// --- Analysis struct for DataflowEngine ---

using PtrVarState = std::map<const VarDecl*, PtrState>;

class UninitPtrAnalysis {
public:
    // Guarded disjuncts (targeted path sensitivity): the Juliet char_07
    // pattern — `if(staticTrue) data = ...; ... if(staticTrue) use(data);`
    // — produced a false "may not be assigned" under correlation-free
    // analysis. The shared machinery is in engine/GuardedDisjuncts.h.
    using State = zerodefect::GuardedState<PtrVarState>;

    UninitPtrAnalysis(const std::vector<const VarDecl*>& trackedVars,
                      std::set<const ValueDecl*> unkeyableDecls,
                      std::set<const ValueDecl*> stampableDecls,
                      const FunctionDecl* func,
                      zerodefect::DiagnosticList& results)
        : mutated_(std::move(unkeyableDecls)),
          stampable_(std::move(stampableDecls)), func_(func),
          funcName_(func->getQualifiedNameAsString()), results_(results) {
        zerodefect::Guarded<PtrVarState> init;
        for (const auto* var : trackedVars)
            init.vars[var] = PtrState::Uninit;
        initState_.push_back(std::move(init));
    }

    State initialState() const { return initState_; }

    // Per-variable chain: Uninit -> MaybeInit -> Init (height 2);
    // the number of disjuncts multiplies the height
    unsigned latticeHeight() const {
        return (static_cast<unsigned>(initState_.front().vars.size()) * 2 +
                1) * static_cast<unsigned>(zerodefect::kMaxDisjuncts) + 4 + factBudget();
    }

    // Fact records add lattice climbs the var-state formula above
    // never counted (v2b); bounded so pathological functions do not
    // explode the iteration cap.
    unsigned factBudget() const {
        auto n = static_cast<unsigned>(stampable_.size());
        return (n > 16 ? 16u : n) * 2 *
               static_cast<unsigned>(zerodefect::kMaxDisjuncts);
    }

    // Engine convergence hook: collapse the disjuncts when a block is
    // revisited beyond any monotone explanation (see DataflowEngine).
    void widen(State& s) const { zerodefect::widenGuarded(s, mergePtrStates); }

    State merge(const State& a, const State& b) const {
        return zerodefect::mergeGuarded(a, b, mergePtrStates);
    }

    State transfer(const Stmt* stmt, const State& inRaw,
                   ASTContext& /*ctx*/) const {
        // Fact lifecycle first (v2b): see NullDerefRule — erase facts
        // on assigned locals, stamp integer-constant stores.
        State in = inRaw;
        zerodefect::applyStmtFacts(in, stmt, stampable_, mergePtrStates);

        // `f(p)` with a non-const reference parameter (`T*& p`) is an
        // out-param assignment with no AddrOf node to observe — the
        // callee may initialize p (same call-boundary rule as `f(&p)`).
        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            State out = in;
            bool changed = false;
            zerodefect::forEachNonConstRefArg(call, [&](const Expr* arg) {
                const VarDecl* var = asVar(arg);
                if (!var) return;
                for (auto& d : out) {
                    auto it = d.vars.find(var);
                    if (it == d.vars.end()) continue;
                    it->second = PtrState::Init;
                    changed = true;
                }
            });
            return changed ? out : in;
        }

        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Assigns) return in;

        State out = in;
        for (auto& d : out) {
            auto it = d.vars.find(effect.var);
            if (it != d.vars.end()) it->second = PtrState::Init;
        }
        return out;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        zerodefect::refineGuardedFacts(state, dyn_cast<Expr>(cond),
                                       isTrueBranch, mutated_,
                                       mergePtrStates);
    }

    void onStatement(const Stmt* stmt, const State& beforeDisjuncts,
                     const State& /*after*/, ASTContext& ctx) {
        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Dereferences) return;

        PtrVarState before =
            zerodefect::flattenGuarded(beforeDisjuncts, mergePtrStates);
        auto it = before.find(effect.var);
        if (it == before.end() || it->second == PtrState::Init) return;

        // Structural must-assign proof beats the dataflow's "maybe":
        // see provenAssignedBefore above (suppression-only).
        if (provenAssignedBefore(func_, effect.var, stmt)) return;

        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);

        if (reported_.emplace(effect.var, line).second) {
            zerodefect::Diagnostic diag;
            // Evidence ladder (aligned with every other rule,
            // 2026-07-16): unassigned on ALL paths = proven = Error;
            // unassigned on SOME path = "may" = Warning. Reporting the
            // maybe-class as Error made every imprecision in this rule
            // a false PROOF — the worst defect our own spec names.
            diag.severity = (it->second == PtrState::Uninit)
                                ? zerodefect::Severity::Error
                                : zerodefect::Severity::Warning;
            diag.file = sm.getFilename(loc).str();
            diag.line = line;
            diag.column = sm.getSpellingColumnNumber(loc);
            diag.rule_id = "uninit-ptr";
            diag.function = funcName_;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::UninitPtrDeref,
                effect.var->getNameAsString());

            // Trace: declaration point (definition without an initial value)
            SourceLocation declLoc =
                sm.getExpansionLoc(effect.var->getLocation());
            zerodefect::TraceNote note;
            note.file = sm.getFilename(declLoc).str();
            note.line = sm.getSpellingLineNumber(declLoc);
            note.column = sm.getSpellingColumnNumber(declLoc);
            note.message = zerodefect::msg(
                zerodefect::MsgId::TraceDeclaredHere,
                effect.var->getNameAsString());
            diag.notes.push_back(std::move(note));

            results_.push_back(diag);
        }
    }

private:
    std::set<const ValueDecl*> mutated_;
    std::set<const ValueDecl*> stampable_;
    const FunctionDecl* func_ = nullptr;
    std::string funcName_;
    zerodefect::DiagnosticList& results_;
    State initState_;
    std::set<std::pair<const VarDecl*, unsigned>> reported_;
};

// --- Matcher callback ---

class FindUninitPtrCallback : public MatchFinder::MatchCallback {
public:
    explicit FindUninitPtrCallback(zerodefect::DiagnosticList& results)
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

        UninitPtrAnalysis analysis(
            trackedVars, zerodefect::collectUnkeyableDecls(func),
            zerodefect::collectFactDecls(func), func, results_);
        auto df = zerodefect::runDataflow(func, *result.Context, analysis);
        if (!df.converged)
            zerodefect::CoverageReport::instance().recordNonConvergence(
                func->getQualifiedNameAsString());
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string UninitPointerRule_Ex::id() const {
    return "uninit-ptr";
}

std::string UninitPointerRule_Ex::description() const {
    return "CFG-based uninitialized pointer use analysis";
}

Severity UninitPointerRule_Ex::defaultSeverity() const {
    return Severity::Error;
}

void UninitPointerRule_Ex::check(clang::ASTContext& ctx,
                                  DiagnosticList& results) {
    MatchFinder finder;
    FindUninitPtrCallback callback(results);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
