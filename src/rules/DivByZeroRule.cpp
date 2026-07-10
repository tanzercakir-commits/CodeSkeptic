#include "rules/DivByZeroRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/ConditionWalk.h"
#include "engine/DataflowEngine.h"
#include "engine/FunctionSummary.h"

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

// --- ZeroState lattice ---

enum class ZeroState { Unknown, Zero, NonZero, MaybeZero };

// --- Evaluate constant zero-ness ---

ZeroState evaluateAsZero(const Expr* expr) {
    if (!expr) return ZeroState::Unknown;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0 ? ZeroState::Zero : ZeroState::NonZero;
    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() == UO_Minus)
            return evaluateAsZero(unary->getSubExpr());
    }
    return ZeroState::Unknown;
}

// Zero-ness of the assigned value: constants directly; calls via the
// summary (returnZeroness) — `data = badSource();` is visible even when
// the source lives in another function/file. Summary consumption is
// DELIBERATELY assignment-path only: we do not report a direct `x / f()`
// divisor — a call result cannot be guarded without being assigned
// (`if (f() != 0) x / f()` is a fresh call), and reporting it would
// spawn a family of FPs in real code. An assigned value, by contrast,
// is tracked by dataflow and refined by guards.
ZeroState evaluateAssignedValue(const Expr* expr) {
    ZeroState lit = evaluateAsZero(expr);
    if (lit != ZeroState::Unknown) return lit;
    if (!expr) return ZeroState::Unknown;
    const Expr* stripped = expr->IgnoreParenImpCasts();
    if (const auto* call = dyn_cast<CallExpr>(stripped)) {
        using RZ = zerodefect::SummaryRegistry::ReturnZeroness;
        if (const auto* summary = zerodefect::SummaryRegistry::instance()
                                      .lookup(call->getDirectCallee())) {
            if (summary->returnZeroness == RZ::NeverZero)
                return ZeroState::NonZero;
            if (summary->returnZeroness == RZ::MaybeZero)
                return ZeroState::MaybeZero;
        }
    }
    return ZeroState::Unknown;
}

// --- Helpers ---

bool refersToVar(const Expr* expr, const VarDecl* var) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return ref->getDecl() == var;
    return false;
}

const VarDecl* getReferencedVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// --- Collect divisor variables ---

std::set<const VarDecl*> collectDivisorVars(const FunctionDecl* funcDecl,
                                             ASTContext& ctx) {
    std::set<const VarDecl*> vars;
    auto divMatcher = binaryOperator(
        anyOf(hasOperatorName("/"), hasOperatorName("%")),
        hasRHS(expr().bind("divisor"))
    );
    for (const auto& result :
         match(findAll(divMatcher), *funcDecl->getBody(), ctx)) {
        const auto* divisor = result.getNodeAs<Expr>("divisor");
        if (!divisor) continue;
        if (const auto* var = getReferencedVar(divisor))
            vars.insert(var);
    }
    return vars;
}

// --- Statement classification ---

enum class StmtEffect {
    None, AssignsZero, AssignsNonZero, AssignsMaybeZero, AssignsUnknown
};

StmtEffect effectOfValue(ZeroState val) {
    switch (val) {
        case ZeroState::Zero:      return StmtEffect::AssignsZero;
        case ZeroState::NonZero:   return StmtEffect::AssignsNonZero;
        case ZeroState::MaybeZero: return StmtEffect::AssignsMaybeZero;
        case ZeroState::Unknown:   break;
    }
    return StmtEffect::AssignsUnknown;
}

StmtEffect classifyStmt(const Stmt* stmt, const VarDecl* targetVar) {
    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (vd == targetVar && vd->hasInit())
                    return effectOfValue(evaluateAssignedValue(vd->getInit()));
            }
        }
        return StmtEffect::None;
    }
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign &&
            refersToVar(binOp->getLHS(), targetVar))
            return effectOfValue(evaluateAssignedValue(binOp->getRHS()));
    }
    return StmtEffect::None;
}

// --- DivFinder ---

class DivFinder : public RecursiveASTVisitor<DivFinder> {
public:
    struct DivOp {
        const BinaryOperator* op;
        const VarDecl* divisorVar;
        bool isLiteralZero;
    };

    std::vector<DivOp> divs;

    bool VisitBinaryOperator(BinaryOperator* op) {
        if (op->getOpcode() != BO_Div && op->getOpcode() != BO_Rem)
            return true;
        if (op->getType()->isFloatingType())
            return true;

        const Expr* rhs = op->getRHS()->IgnoreParenImpCasts();
        ZeroState litState = evaluateAsZero(rhs);

        DivOp d;
        d.op = op;
        if (litState == ZeroState::Zero) {
            d.divisorVar = nullptr;
            d.isLiteralZero = true;
        } else {
            d.divisorVar = getReferencedVar(rhs);
            d.isLiteralZero = false;
        }
        divs.push_back(d);
        return true;
    }
};

// --- Branch condition refinement (assume edges) ---

using VarState = std::map<const VarDecl*, ZeroState>;

void setIfTracked(VarState& state, const VarDecl* var, ZeroState value) {
    if (!var) return;
    auto it = state.find(var);
    if (it != state.end()) it->second = value;
}

// Refines variable states on the edge where the condition expression is
// true/false. Example: on the true edge of `z != 0`, z = NonZero. The
// walk comes from the shared skeleton (engine/ConditionWalk.h) — !,
// && / || short-circuiting and variable-on-the-left normalization live
// there; the zero-domain interpretation lives here.
void applyCondition(const Expr* cond, bool isTrue, VarState& state) {
    zerodefect::walkCondition(
        cond, isTrue,
        // if (z) / while (z): truthiness
        [&](const VarDecl* var, bool truthy) {
            setIfTracked(state, var,
                         truthy ? ZeroState::NonZero : ZeroState::Zero);
        },
        [&](const VarDecl* var, BinaryOperatorKind opc,
            const Expr* other, bool edgeTrue) {
            ZeroState litState = evaluateAsZero(other);

            if (opc == BO_EQ || opc == BO_NE) {
                // `z == 0` true → Zero; `z != 0` true → NonZero
                // (the reverse on false). With a nonzero constant:
                // `z == 5` true → NonZero; no information on the false
                // side.
                bool eqHolds = (opc == BO_EQ) == edgeTrue;
                if (litState == ZeroState::Zero)
                    setIfTracked(state, var, eqHolds ? ZeroState::Zero
                                                     : ZeroState::NonZero);
                else if (litState == ZeroState::NonZero && eqHolds)
                    setIfTracked(state, var, ZeroState::NonZero);
                return;
            }

            // Orderings only against the zero constant: infer NonZero in
            // the direction where the inequality excludes zero (opc
            // arrives variable-on-the-left)
            if (litState != ZeroState::Zero) return;
            switch (opc) {
                case BO_GT:  // z > 0
                case BO_LT:  // z < 0
                    if (edgeTrue)
                        setIfTracked(state, var, ZeroState::NonZero);
                    break;
                case BO_GE:  // z >= 0: if false then z < 0 → NonZero
                case BO_LE:  // z <= 0: if false then z > 0 → NonZero
                    if (!edgeTrue)
                        setIfTracked(state, var, ZeroState::NonZero);
                    break;
                default:
                    break;
            }
        });
}

// --- Analysis struct for DataflowEngine ---

class DivByZeroAnalysis {
public:
    using State = VarState;

    DivByZeroAnalysis(const std::set<const VarDecl*>& trackedVars,
                      std::string funcName,
                      zerodefect::DiagnosticList& results,
                      std::set<unsigned>& reportedLines)
        : trackedVars_(trackedVars), funcName_(std::move(funcName)),
          results_(results), reportedLines_(reportedLines) {
        for (const auto* var : trackedVars_)
            initState_[var] = ZeroState::Unknown;
    }

    State initialState() const { return initState_; }

    // The per-variable ZeroState chain makes at most 3 transitions
    unsigned latticeHeight() const {
        return static_cast<unsigned>(trackedVars_.size()) * 3 + 1;
    }

    State merge(const State& a, const State& b) const {
        State result = a;
        for (const auto& [var, stateB] : b) {
            auto it = result.find(var);
            if (it == result.end())
                result[var] = stateB;
            else {
                if (it->second == stateB) continue;
                // If any path has definite/possible zero, the knowledge
                // is preserved: Zero|MaybeZero + anything = MaybeZero.
                // Only NonZero + Unknown decays to no knowledge.
                bool anyZeroInfo =
                    it->second == ZeroState::Zero ||
                    it->second == ZeroState::MaybeZero ||
                    stateB == ZeroState::Zero ||
                    stateB == ZeroState::MaybeZero;
                it->second = anyZeroInfo ? ZeroState::MaybeZero
                                         : ZeroState::Unknown;
            }
        }
        return result;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& /*ctx*/) const {
        State out = in;
        for (const auto* var : trackedVars_) {
            StmtEffect effect = classifyStmt(stmt, var);
            switch (effect) {
                case StmtEffect::AssignsZero:
                    out[var] = ZeroState::Zero; break;
                case StmtEffect::AssignsNonZero:
                    out[var] = ZeroState::NonZero; break;
                case StmtEffect::AssignsMaybeZero:
                    // From the summary: the callee may return 0 on some paths
                    out[var] = ZeroState::MaybeZero; break;
                case StmtEffect::AssignsUnknown:
                    out[var] = ZeroState::Unknown; break;
                case StmtEffect::None: break;
            }
        }
        return out;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        applyCondition(dyn_cast<Expr>(cond), isTrueBranch, state);
    }

    // Guard trace (Trace v2): if the edge refinement made the variable
    // DEFINITELY zero, add a trace note at the condition point — the
    // "why zero" question for the `if (n == 0) 100 / n` finding now has
    // an answer
    void onEdgeRefined(const Stmt* cond, bool /*isTrueBranch*/,
                       const State& before, const State& after,
                       ASTContext& ctx) {
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState == ZeroState::Zero)
                recordEvent(cond, var, ctx,
                            zerodefect::MsgId::TraceAssumedZeroHere);
        }
    }

    void onStatement(const Stmt* stmt, const State& before,
                     const State& after, ASTContext& ctx) {
        // Dataflow trace: record transitions to zero / possibly-zero
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState == ZeroState::Zero)
                recordEvent(stmt, var, ctx,
                            zerodefect::MsgId::TraceAssignedZeroHere);
            else if (afterState == ZeroState::MaybeZero)
                recordEvent(stmt, var, ctx,
                            zerodefect::MsgId::TraceAssignedMaybeZeroHere);
        }

        // Top node ONLY: in the fine-grained CFG every division arrives
        // as its own element. Nested search (the old DivFinder approach)
        // rediscovered the same division a second time in the enclosing
        // expression's element — with the wrong (join) state — and
        // produced FPs (the ternary guard case).
        const auto* op = dyn_cast<BinaryOperator>(stmt);
        if (!op) return;
        if (op->getOpcode() != BO_Div && op->getOpcode() != BO_Rem) return;
        if (op->getType()->isFloatingType()) return;

        const Expr* rhs = op->getRHS()->IgnoreParenImpCasts();
        if (evaluateAsZero(rhs) == ZeroState::Zero) return;  // in Phase 1
        const VarDecl* var = getReferencedVar(rhs);
        if (!var) return;

        auto stateIt = before.find(var);
        if (stateIt == before.end()) return;
        ZeroState state = stateIt->second;
        if (state != ZeroState::Zero && state != ZeroState::MaybeZero)
            return;

        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(op->getOperatorLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines_.insert(line).second) return;

        zerodefect::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "div-by-zero";
        diag.function = funcName_;
        if (state == ZeroState::Zero) {
            diag.severity = zerodefect::Severity::Error;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::DivByZeroDefinite,
                var->getNameAsString());
        } else {
            diag.severity = zerodefect::Severity::Warning;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::DivByZeroMaybe,
                var->getNameAsString());
        }
        results_.push_back(diag);
        noteTargets_.emplace_back(results_.size() - 1, var);
    }

    // After the run finishes: attach the zero-assignment traces to reports
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

    const std::set<const VarDecl*>& trackedVars_;
    std::string funcName_;
    zerodefect::DiagnosticList& results_;
    std::set<unsigned>& reportedLines_;
    VarState initState_;
    std::map<const VarDecl*, std::vector<zerodefect::TraceNote>> events_;
    std::vector<std::pair<size_t, const VarDecl*>> noteTargets_;
};

// --- Function-level analysis ---

void analyzeFunction(const FunctionDecl* funcDecl,
                     ASTContext& ctx,
                     zerodefect::DiagnosticList& results) {
    if (!funcDecl->hasBody()) return;

    const SourceManager& sm = ctx.getSourceManager();
    std::set<unsigned> reportedLines;

    // Phase 1: Literal zero divisions (no CFG)
    DivFinder literalFinder;
    literalFinder.TraverseStmt(funcDecl->getBody());
    for (const auto& div : literalFinder.divs) {
        if (div.isLiteralZero) {
            SourceLocation loc =
                sm.getExpansionLoc(div.op->getOperatorLoc());
            unsigned line = sm.getSpellingLineNumber(loc);
            if (reportedLines.insert(line).second) {
                zerodefect::Diagnostic diag;
                diag.severity = zerodefect::Severity::Error;
                diag.file = sm.getFilename(loc).str();
                diag.line = line;
                diag.column = sm.getSpellingColumnNumber(loc);
                diag.rule_id = "div-by-zero";
                diag.function = funcDecl->getQualifiedNameAsString();
                diag.message = zerodefect::msg(
                    zerodefect::MsgId::DivByZeroLiteral);
                results.push_back(diag);
            }
        }
    }

    // Phase 2: Variable divisor analysis via DataflowEngine
    auto trackedVars = collectDivisorVars(funcDecl, ctx);
    if (trackedVars.empty()) return;

    DivByZeroAnalysis analysis(
        trackedVars, funcDecl->getQualifiedNameAsString(), results,
        reportedLines);
    auto df = zerodefect::runDataflow(funcDecl, ctx, analysis);
    if (!df.converged)
        std::cerr << zerodefect::msg(zerodefect::MsgId::AnalysisNotConverged,
                                     funcDecl->getQualifiedNameAsString())
                  << "\n";
    analysis.attachTraces();
}

// --- Matcher callback ---

class DivByZeroCallback : public MatchFinder::MatchCallback {
public:
    explicit DivByZeroCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;
        if (!zerodefect::functionFilterAllows(*func)) return;
        if (!zerodefect::lineFilterAllows(*func, sm)) return;

        analyzeFunction(func, *result.Context, results_);
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string DivByZeroRule::id() const {
    return "div-by-zero";
}

std::string DivByZeroRule::description() const {
    return "Definite and potential division-by-zero detection";
}

Severity DivByZeroRule::defaultSeverity() const {
    return Severity::Error;
}

void DivByZeroRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    MatchFinder finder;
    DivByZeroCallback callback(results);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
