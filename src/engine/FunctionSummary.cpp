#include "engine/FunctionSummary.h"

#include "engine/ConditionWalk.h"
#include "engine/DataflowEngine.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/ParentMapContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <set>
#include <utility>
#include <vector>

using namespace clang;

namespace {

constexpr unsigned kMaxSweeps = 5;

using ReturnNullness = codeskeptic::SummaryRegistry::ReturnNullness;
using ReturnZeroness = codeskeptic::SummaryRegistry::ReturnZeroness;
using ParamEffect = codeskeptic::SummaryRegistry::ParamEffect;
using FunctionSummary = codeskeptic::SummaryRegistry::FunctionSummary;
using SummaryTable = std::map<const FunctionDecl*, FunctionSummary>;

// --- Return nullness ---

// Nullness of the return expression: literal/new/&x/string directly;
// call chains are resolved with the previous sweep's summaries.
// Look up the callee's summary in the TU-local table first, else in
// the cross-TU store. (Whole-program pass 1 fills the store; in
// single-TU mode the store is empty and behavior is unchanged.)
const FunctionSummary* lookupPrev(const SummaryTable& previous,
                                  const FunctionDecl* callee) {
    if (!callee) return nullptr;
    auto it = previous.find(callee->getCanonicalDecl());
    if (it != previous.end()) return &it->second;
    return codeskeptic::SummaryRegistry::instance().lookupGlobal(callee);
}

// Value-level "bad value" state. The two domains share one shape: in
// the null domain Bad = null, in the zero domain Bad = 0. Same as
// NullDeref's lattice; lives in summary context (TU-anonymous, no clash).
enum class VState { Unknown, Bad, NonBad, MaybeBad };

VState mergeVState(VState a, VState b) {
    if (a == b) return a;
    bool anyBadInfo = a == VState::Bad || a == VState::MaybeBad ||
                      b == VState::Bad || b == VState::MaybeBad;
    return anyBadInfo ? VState::MaybeBad : VState::Unknown;
}

// Null state of an expression: literal/new/&x/string directly; call
// chains are resolved with the previous sweep's summaries (+ cross-TU
// store).
VState vstateOf(const Expr* expr, const SummaryTable& previous) {
    if (!expr) return VState::Unknown;
    expr = expr->IgnoreParenCasts();

    if (isa<CXXNullPtrLiteralExpr>(expr)) return VState::Bad;
    if (isa<GNUNullExpr>(expr)) return VState::Bad;
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0 ? VState::Bad : VState::NonBad;
    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() == UO_AddrOf) return VState::NonBad;
    }
    if (isa<CXXNewExpr>(expr)) return VState::NonBad;
    if (isa<StringLiteral>(expr)) return VState::NonBad;
    // A named ARRAY decays to the address of its first element — never
    // null (`return table0;` in the picojpeg getHuffVal shape).
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) {
        if (const auto* vd = dyn_cast<VarDecl>(ref->getDecl()))
            if (vd->getType()->isArrayType()) return VState::NonBad;
    }

    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        if (const auto* summary =
                lookupPrev(previous, call->getDirectCallee())) {
            if (summary->returnNullness == ReturnNullness::NeverNull)
                return VState::NonBad;
            if (summary->returnNullness == ReturnNullness::MaybeNull)
                return VState::MaybeBad;
        }
        return VState::Unknown;
    }
    return VState::Unknown;
}

// Zero state of an expression (zero domain): integer constants
// directly, call chains resolved via the summaries' returnZeroness.
VState zstateOf(const Expr* expr, const SummaryTable& previous) {
    if (!expr) return VState::Unknown;
    expr = expr->IgnoreParenCasts();

    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0 ? VState::Bad : VState::NonBad;
    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() == UO_Minus)
            return zstateOf(unary->getSubExpr(), previous);
    }

    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        if (const auto* summary =
                lookupPrev(previous, call->getDirectCallee())) {
            if (summary->returnZeroness == ReturnZeroness::NeverZero)
                return VState::NonBad;
            if (summary->returnZeroness == ReturnZeroness::MaybeZero)
                return VState::MaybeBad;
            // Zero-passthrough: the call's zero-state IS argument
            // #zeroFromParam's (`x = id(5)` -> NonBad). Recursion is
            // over the finite expression tree. A variable argument
            // stays Unknown here (this evaluator is stateless); the
            // PT harvest pass and the DivByZero copy path own that
            // case.
            if (summary->zeroFromParam >= 0 &&
                static_cast<unsigned>(summary->zeroFromParam) <
                    call->getNumArgs())
                return zstateOf(call->getArg(summary->zeroFromParam),
                                previous);
        }
        return VState::Unknown;
    }
    return VState::Unknown;
}

const VarDecl* exprAsVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// Domain refinements on condition edges — via the shared walking
// skeleton (engine/ConditionWalk.h)
void applyNullCond(const Expr* cond, bool isTrue,
                   std::map<const VarDecl*, VState>& state) {
    codeskeptic::walkNullCondition(
        cond, isTrue, [&](const VarDecl* var, bool isNull) {
            auto it = state.find(var);
            if (it != state.end())
                it->second = isNull ? VState::Bad : VState::NonBad;
        });
}

void applyZeroCond(const Expr* cond, bool isTrue,
                   std::map<const VarDecl*, VState>& state) {
    codeskeptic::walkZeroCondition(
        cond, isTrue, [&](const VarDecl* var, bool isZero) {
            auto it = state.find(var);
            if (it != state.end())
                it->second = isZero ? VState::Bad : VState::NonBad;
        });
}

// --- Mini value-flow for variable-returning paths ---
//
// `return p;` paths used to stay Unknown under structural evaluation
// (a v1 limit). Now tracked locals/parameters are followed flow-
// SENSITIVELY with our own engine (runDataflow: two-phase reporting +
// assume-edge refinement) and each return element takes its
// contribution from the converged state. The flow-insensitive
// shortcut was deliberately rejected: on the `p = NULL; p = &g;
// return p;` pattern it yields a false MaybeNull, burning precision.
//
// The domain comes as template parameters: ValueOf is expression
// evaluation (vstateOf / zstateOf), Refine is edge refinement
// (applyNullCond / applyZeroCond). The same backbone serves both the
// null and the zero domain — Bad means "null" in the null domain and
// "0" in the zero domain.
//
// Contribution mapping: Bad/MaybeBad -> "this path may return a bad
// value"; NonBad -> a Never* contribution; Unknown -> Unknown.
// Function total: any bad path -> Maybe*; ALL paths NonBad -> Never*;
// otherwise Unknown. Returns the CFG cannot reach (dead code)
// contribute nothing.
template <VState (*ValueOf)(const Expr*, const SummaryTable&),
          void (*Refine)(const Expr*, bool,
                         std::map<const VarDecl*, VState>&)>
class ReturnFlowAnalysis {
public:
    using State = std::map<const VarDecl*, VState>;

    ReturnFlowAnalysis(std::vector<const VarDecl*> trackedVars,
                       const SummaryTable& previous)
        : previous_(previous) {
        for (const auto* var : trackedVars)
            initState_[var] = VState::Unknown;
    }

    State initialState() const { return initState_; }

    unsigned latticeHeight() const {
        return static_cast<unsigned>(initState_.size()) * 3 + 1;
    }

    State merge(const State& a, const State& b) const {
        State result = a;
        for (const auto& [var, sb] : b) {
            auto it = result.find(var);
            if (it == result.end()) result[var] = sb;
            else it->second = mergeVState(it->second, sb);
        }
        return result;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& /*ctx*/) const {
        if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
            State out = in;
            for (const auto* decl : declStmt->decls()) {
                if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                    auto it = out.find(vd);
                    if (it != out.end() && vd->hasInit())
                        it->second = ValueOf(vd->getInit(), previous_);
                }
            }
            return out;
        }
        if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
            if (binOp->getOpcode() != BO_Assign) return in;
            const VarDecl* var = exprAsVar(binOp->getLHS());
            auto it = var ? in.find(var) : in.end();
            if (it == in.end()) return in;
            State out = in;
            out[var] = ValueOf(binOp->getRHS(), previous_);
            return out;
        }
        if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
            // if &p goes into a function, p may have changed
            if (unary->getOpcode() == UO_AddrOf) {
                const VarDecl* var = exprAsVar(unary->getSubExpr());
                auto it = var ? in.find(var) : in.end();
                if (it == in.end()) return in;
                State out = in;
                out[var] = VState::Unknown;
                return out;
            }
        }
        return in;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        Refine(dyn_cast<Expr>(cond), isTrueBranch, state);
    }

    // After the fixpoint: each REACHABLE return's contribution is collected
    void onStatement(const Stmt* stmt, const State& before,
                     const State& /*after*/, ASTContext& /*ctx*/) {
        const auto* ret = dyn_cast<ReturnStmt>(stmt);
        if (!ret || !ret->getRetValue()) return;

        const Expr* expr = ret->getRetValue();
        VState v;
        if (const VarDecl* var = exprAsVar(expr)) {
            auto it = before.find(var);
            v = (it != before.end()) ? it->second
                                     : ValueOf(expr, previous_);
        } else {
            v = ValueOf(expr, previous_);
        }
        contributions.push_back(v);
    }

    std::vector<VState> contributions;

private:
    const SummaryTable& previous_;
    State initState_;
};

// Contribution total (rule shared by both domains): any bad path ->
// Maybe*; ALL paths surely NonBad -> Never* (strong claim); else Unknown.
struct AggregateFlags {
    bool empty = true;
    bool sawBad = false;
    bool allNonBad = true;
};

AggregateFlags aggregateFlags(const std::vector<VState>& contribs) {
    AggregateFlags flags;
    flags.empty = contribs.empty();
    for (VState v : contribs) {
        if (v == VState::Bad || v == VState::MaybeBad) flags.sawBad = true;
        if (v != VState::NonBad) flags.allNonBad = false;
    }
    return flags;
}

// Return collector + tracked-variable collector — shared by both domains.
struct ReturnCollector : RecursiveASTVisitor<ReturnCollector> {
    std::vector<const Expr*> returns;
    bool anyVarReturn = false;
    bool VisitReturnStmt(ReturnStmt* ret) {
        returns.push_back(ret->getRetValue());
        if (exprAsVar(ret->getRetValue())) anyVarReturn = true;
        return true;
    }
    // Do not count the returns of nested functions (lambdas)
    bool TraverseLambdaExpr(LambdaExpr*) { return true; }
};

template <typename TypePred>
std::vector<const VarDecl*> collectTypedVars(const FunctionDecl* func,
                                             TypePred matches) {
    struct VarCollector : RecursiveASTVisitor<VarCollector> {
        TypePred* pred;
        std::set<const VarDecl*> vars;
        bool VisitVarDecl(VarDecl* vd) {
            if ((*pred)(vd->getType())) vars.insert(vd);
            return true;
        }
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    };
    VarCollector collector;
    collector.pred = &matches;
    collector.TraverseStmt(func->getBody());
    for (const auto* param : func->parameters())
        if (matches(param->getType())) collector.vars.insert(param);
    return {collector.vars.begin(), collector.vars.end()};
}

// Shared body of the two domains: fast structural path (no CFG when
// no return returns a variable), otherwise the mini value-flow.
template <VState (*ValueOf)(const Expr*, const SummaryTable&),
          void (*Refine)(const Expr*, bool,
                         std::map<const VarDecl*, VState>&),
          typename TypePred>
AggregateFlags computeReturnFlow(const FunctionDecl* func, ASTContext& ctx,
                                 const SummaryTable& previous,
                                 TypePred varMatches) {
    ReturnCollector collector;
    collector.TraverseStmt(func->getBody());
    if (collector.returns.empty()) return {};

    if (!collector.anyVarReturn) {
        std::vector<VState> contribs;
        contribs.reserve(collector.returns.size());
        for (const auto* ret : collector.returns)
            contribs.push_back(ValueOf(ret, previous));
        return aggregateFlags(contribs);
    }

    ReturnFlowAnalysis<ValueOf, Refine> analysis(
        collectTypedVars(func, varMatches), previous);
    codeskeptic::runDataflow(func, ctx, analysis);
    return aggregateFlags(analysis.contributions);
}

ReturnNullness computeReturnNullness(const FunctionDecl* func,
                                     ASTContext& ctx,
                                     const SummaryTable& previous) {
    if (!func->getReturnType()->isPointerType())
        return ReturnNullness::Unknown;

    AggregateFlags flags = computeReturnFlow<vstateOf, applyNullCond>(
        func, ctx, previous,
        [](QualType t) { return t->isPointerType(); });
    if (flags.empty) return ReturnNullness::Unknown;
    if (flags.sawBad) return ReturnNullness::MaybeNull;
    if (flags.allNonBad) return ReturnNullness::NeverNull;
    return ReturnNullness::Unknown;
}

// --- Zero-passthrough harvest (the zeroness-through-summaries slice) ---
//
// Parameters whose entry value survives the whole function: never the
// target of an assignment / compound assignment / ++ / --, never
// address-taken. C parameters are copies, so `return p;` on ANY path
// then returns the caller's argument verbatim — path-independently,
// which is what lets this pass run structurally after the flow.
std::set<const VarDecl*> unwrittenParams(const FunctionDecl* func) {
    std::set<const VarDecl*> params(func->param_begin(), func->param_end());
    struct V : RecursiveASTVisitor<V> {
        std::set<const VarDecl*>* params;
        bool VisitBinaryOperator(BinaryOperator* bin) {
            if (bin->isAssignmentOp())
                if (const VarDecl* v = exprAsVar(bin->getLHS()))
                    params->erase(v);
            return true;
        }
        bool VisitUnaryOperator(UnaryOperator* u) {
            if (u->isIncrementDecrementOp() || u->getOpcode() == UO_AddrOf)
                if (const VarDecl* v = exprAsVar(u->getSubExpr()))
                    params->erase(v);
            return true;
        }
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    } v;
    v.params = &params;
    if (func->getBody()) v.TraverseStmt(func->getBody());
    return params;
}

// One return expression's contribution to the passthrough claim.
// NonZero (proven never zero), Passthrough (returns param #*pt's entry
// value — directly or through a passthrough chain), or Blocked (kills
// the claim).
//
// WIDTH DISCIPLINE: the claim "result == 0 implies the source value was
// 0" survives integer conversions only when no step NARROWS — a
// truncation maps 2^32 to 0, fabricating a zero from a nonzero
// argument. `targetWidth` is the width of the slot this expression's
// value flows into; every node whose own width exceeds it is Blocked,
// and each cast / callee-parameter hop re-anchors the target. Same- or
// widening conversions (any signedness) preserve zeroness exactly.
enum class PtRes { NonZero, Passthrough, Blocked };

PtRes resolveZeroReturn(const Expr* e, const FunctionDecl* func,
                        const std::set<const VarDecl*>& unwritten,
                        const SummaryTable& previous, ASTContext& ctx,
                        unsigned targetWidth, int* pt) {
    if (!e) return PtRes::Blocked;
    e = e->IgnoreParens();
    if (!e->getType()->isIntegerType()) return PtRes::Blocked;
    if (ctx.getIntWidth(e->getType()) > targetWidth) return PtRes::Blocked;

    if (const auto* lit = dyn_cast<IntegerLiteral>(e))
        return lit->getValue() == 0 ? PtRes::Blocked : PtRes::NonZero;
    if (const auto* cast = dyn_cast<CastExpr>(e))
        return resolveZeroReturn(cast->getSubExpr(), func, unwritten,
                                 previous, ctx,
                                 ctx.getIntWidth(e->getType()), pt);
    if (const auto* u = dyn_cast<UnaryOperator>(e)) {
        // -x == 0 iff x == 0, at any width.
        if (u->getOpcode() == UO_Minus)
            return resolveZeroReturn(u->getSubExpr(), func, unwritten,
                                     previous, ctx, targetWidth, pt);
        return PtRes::Blocked;
    }
    if (const auto* ref = dyn_cast<DeclRefExpr>(e)) {
        const auto* parm = dyn_cast<ParmVarDecl>(ref->getDecl());
        if (!parm || !unwritten.count(parm)) return PtRes::Blocked;
        int idx = -1;
        for (unsigned i = 0; i < func->getNumParams(); ++i)
            if (func->getParamDecl(i) == parm) {
                idx = static_cast<int>(i);
                break;
            }
        if (idx < 0) return PtRes::Blocked;
        if (*pt >= 0 && *pt != idx) return PtRes::Blocked;  // mixed params
        *pt = idx;
        return PtRes::Passthrough;
    }
    if (const auto* call = dyn_cast<CallExpr>(e)) {
        const auto* summary = lookupPrev(previous, call->getDirectCallee());
        if (!summary) return PtRes::Blocked;
        if (summary->returnZeroness == ReturnZeroness::NeverZero)
            return PtRes::NonZero;
        if (summary->zeroFromParam >= 0 &&
            static_cast<unsigned>(summary->zeroFromParam) <
                call->getNumArgs()) {
            // The argument flows into the CALLEE PARAMETER's slot; the
            // callee's own harvest enforced param -> its return.
            const FunctionDecl* callee = call->getDirectCallee();
            unsigned argTarget = targetWidth;
            if (callee &&
                static_cast<unsigned>(summary->zeroFromParam) <
                    callee->getNumParams()) {
                QualType pt_ty =
                    callee
                        ->getParamDecl(
                            static_cast<unsigned>(summary->zeroFromParam))
                        ->getType();
                if (!pt_ty->isIntegerType()) return PtRes::Blocked;
                argTarget = ctx.getIntWidth(pt_ty);
            }
            return resolveZeroReturn(call->getArg(summary->zeroFromParam),
                                     func, unwritten, previous, ctx,
                                     argTarget, pt);
        }
        return PtRes::Blocked;
    }
    return PtRes::Blocked;
}

ReturnZeroness computeReturnZeroness(const FunctionDecl* func,
                                     ASTContext& ctx,
                                     const SummaryTable& previous,
                                     int* zeroFromParam) {
    // bool excluded: the falses in the `return ok;` pattern would count
    // as zero, yielding MaybeZero everywhere; a bool divisor is
    // meaningless anyway
    *zeroFromParam = -1;
    QualType retType = func->getReturnType();
    if (!retType->isIntegerType() || retType->isBooleanType())
        return ReturnZeroness::Unknown;

    AggregateFlags flags = computeReturnFlow<zstateOf, applyZeroCond>(
        func, ctx, previous, [](QualType t) {
            return t->isIntegerType() && !t->isBooleanType();
        });
    if (flags.empty) return ReturnZeroness::Unknown;
    if (flags.sawBad) return ReturnZeroness::MaybeZero;
    if (flags.allNonBad) return ReturnZeroness::NeverZero;

    // Neither strong claim held — try the conditional one: every path
    // either proven NeverZero or returns param #k's entry value. Runs
    // structurally: an unwritten param's entry value holds at every
    // return regardless of path, and NeverZero contributions do not
    // depend on which param the claim names.
    std::set<const VarDecl*> unwritten = unwrittenParams(func);
    if (unwritten.empty()) return ReturnZeroness::Unknown;
    ReturnCollector collector;
    collector.TraverseStmt(func->getBody());
    const unsigned retWidth = ctx.getIntWidth(retType);
    int pt = -1;
    bool sawPassthrough = false;
    for (const auto* ret : collector.returns) {
        switch (resolveZeroReturn(ret, func, unwritten, previous, ctx,
                                  retWidth, &pt)) {
            case PtRes::NonZero: break;
            case PtRes::Passthrough: sawPassthrough = true; break;
            case PtRes::Blocked: return ReturnZeroness::Unknown;
        }
    }
    if (sawPassthrough && pt >= 0) *zeroFromParam = pt;
    return ReturnZeroness::Unknown;
}

// --- #69b: value-conditioned null return ---
//
// When the plain harvest says MaybeNull, try to PROVE the stronger
// claim "null is returned ONLY IF parameter #i lies outside interval
// R" (the picojpeg getHuffVal shape: null only in the switch default,
// the caller's argument provably within the cases). Recognized guard
// shapes, v1 — deliberately narrow, every widening must argue
// soundness:
//   A. `switch (param) { case c...: ...; default: return null; }` —
//      the bad return sits under the DEFAULT of a switch whose
//      condition is the (never-reassigned) parameter, the case
//      constants form a CONTIGUOUS range (a hull with holes would let
//      an in-hull value reach default — unsound), and NO case region
//      can fall through into another (a fallthrough would let an
//      in-range value execute the default's return).
//   B. `if (param CMP const) return null;` — the bad return is inside
//      the then (or else, polarity flipped) branch of a comparison of
//      the parameter against an integer constant, and the FALSE set of
//      the condition is representable as one interval.
// Requirements common to both: exactly ONE structurally-null return,
// every other return structurally NonBad (no variable returns — the
// mini-flow's per-return attribution is not exposed), and the
// parameter never reassigned / address-taken (the guard must still
// speak about the CALLER's argument value).

// Any write to `param` (assignment, ++/--, &param) breaks the
// argument-to-guard link.
bool paramIsNeverMutated(const FunctionDecl* func, const ParmVarDecl* param) {
    struct MutVisitor : RecursiveASTVisitor<MutVisitor> {
        const ParmVarDecl* target = nullptr;
        bool mutated = false;
        bool refersToTarget(const Expr* e) {
            const auto* var = exprAsVar(e);
            return var == target;
        }
        bool VisitBinaryOperator(BinaryOperator* bin) {
            if (bin->isAssignmentOp() && refersToTarget(bin->getLHS()))
                mutated = true;
            return !mutated;
        }
        bool VisitUnaryOperator(UnaryOperator* un) {
            if ((un->isIncrementDecrementOp() ||
                 un->getOpcode() == UO_AddrOf) &&
                refersToTarget(un->getSubExpr()))
                mutated = true;
            return !mutated;
        }
    };
    MutVisitor visitor;
    visitor.target = param;
    visitor.TraverseStmt(func->getBody());
    return !visitor.mutated;
}

// Flat-body fallthrough scan: every labeled region that is followed by
// another label must end in a return or break. goto/continue anywhere
// in the switch body → bail (control flow we do not model).
bool switchHasNoFallthrough(const SwitchStmt* sw) {
    const auto* body = dyn_cast_or_null<CompoundStmt>(sw->getBody());
    if (!body) return false;

    bool inRegion = false;
    bool regionTerminated = false;
    for (const Stmt* child : body->body()) {
        // Unwrap label chains (`case 0: case 1: return X;`): the chain
        // plus its first statement arrive as ONE nested child.
        const Stmt* inner = child;
        bool isLabel = false;
        while (const auto* sc = dyn_cast_or_null<SwitchCase>(inner)) {
            isLabel = true;
            inner = sc->getSubStmt();
        }
        if (isLabel) {
            if (inRegion && !regionTerminated) return false;  // fallthrough
            inRegion = true;
            regionTerminated = false;
        }
        if (!inner) continue;
        struct BadFlowVisitor : RecursiveASTVisitor<BadFlowVisitor> {
            bool bad = false;
            bool VisitGotoStmt(GotoStmt*) { bad = true; return false; }
            bool VisitContinueStmt(ContinueStmt*) { bad = true; return false; }
        };
        BadFlowVisitor flow;
        flow.TraverseStmt(const_cast<Stmt*>(inner));
        if (flow.bad) return false;
        if (isa<ReturnStmt>(inner) || isa<BreakStmt>(inner))
            regionTerminated = true;
        // A compound region ending in return/break also terminates.
        if (const auto* comp = dyn_cast<CompoundStmt>(inner)) {
            if (!comp->body_empty()) {
                const Stmt* last = comp->body_back();
                if (isa<ReturnStmt>(last) || isa<BreakStmt>(last))
                    regionTerminated = true;
            }
        }
    }
    return true;
}

// The parameter index of `expr` if it is a plain reference to one of
// func's parameters; -1 otherwise.
int paramIndexOf(const FunctionDecl* func, const Expr* expr) {
    const auto* var = exprAsVar(expr);
    const auto* param = dyn_cast_or_null<ParmVarDecl>(var);
    if (!param) return -1;
    for (unsigned i = 0; i < func->getNumParams(); ++i)
        if (func->getParamDecl(i) == param) return static_cast<int>(i);
    return -1;
}

bool asInt64Const(const Expr* expr, ASTContext& ctx, int64_t* out) {
    if (!expr) return false;
    Expr::EvalResult result;
    if (!expr->EvaluateAsInt(result, ctx)) return false;
    const llvm::APSInt& v = result.Val.getInt();
    if (v.getSignificantBits() > 63) return false;
    *out = v.getExtValue();
    return true;
}

// Pattern A: the bad return sits under this switch's DEFAULT.
// Returns true and fills (paramIdx, range) on success.
bool matchSwitchDefaultGuard(const SwitchStmt* sw, const FunctionDecl* func,
                             ASTContext& ctx, int* paramIdx,
                             codeskeptic::Interval* range) {
    int idx = paramIndexOf(func, sw->getCond());
    if (idx < 0) return false;
    if (!paramIsNeverMutated(func, func->getParamDecl(idx))) return false;
    if (!switchHasNoFallthrough(sw)) return false;

    std::vector<int64_t> values;
    for (const SwitchCase* sc = sw->getSwitchCaseList(); sc;
         sc = sc->getNextSwitchCase()) {
        if (isa<DefaultStmt>(sc)) continue;
        const auto* cs = cast<CaseStmt>(sc);
        if (cs->getRHS()) return false;  // GNU case range: bail (v1)
        int64_t v;
        if (!asInt64Const(cs->getLHS(), ctx, &v)) return false;
        values.push_back(v);
    }
    if (values.empty()) return false;
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    // Contiguity is REQUIRED: with holes, an in-hull value still lands
    // in default — recording the hull would be an unsound safe zone.
    const int64_t lo = values.front(), hi = values.back();
    if (hi - lo + 1 != static_cast<int64_t>(values.size())) return false;

    *paramIdx = idx;
    *range = codeskeptic::Interval::range(lo, hi);
    return true;
}

// Pattern B: `cond` (an if condition; already polarity-adjusted so the
// bad return runs when it is TRUE) compares a parameter against an
// integer constant, and its FALSE set is one interval → that interval
// is the safe zone.
bool matchComparisonGuard(const Expr* cond, bool nullWhenTrue,
                          const FunctionDecl* func, ASTContext& ctx,
                          int* paramIdx, codeskeptic::Interval* range) {
    if (!cond) return false;
    const Expr* e = codeskeptic::stripBoolPreservingCasts(
        cond->IgnoreParenImpCasts());
    // `!cond` flips which branch returns null.
    if (const auto* un = dyn_cast<UnaryOperator>(e)) {
        if (un->getOpcode() == UO_LNot)
            return matchComparisonGuard(un->getSubExpr(), !nullWhenTrue,
                                        func, ctx, paramIdx, range);
        return false;
    }
    const auto* bin = dyn_cast<BinaryOperator>(e);
    if (!bin || !bin->isComparisonOp()) return false;

    int idx = paramIndexOf(func, bin->getLHS());
    const Expr* other = bin->getRHS();
    BinaryOperatorKind opc = bin->getOpcode();
    if (idx < 0) {
        idx = paramIndexOf(func, bin->getRHS());
        other = bin->getLHS();
        opc = codeskeptic::condwalk_detail::mirror(opc);
    }
    if (idx < 0) return false;
    if (!paramIsNeverMutated(func, func->getParamDecl(idx))) return false;

    int64_t k;
    if (!asInt64Const(other, ctx, &k)) return false;

    // Null fires when `param OPC k` is `nullWhenTrue`; the safe zone is
    // the OTHER truth value's set, usable only when it is one interval.
    if (!nullWhenTrue) {
        // null when cond FALSE → safe zone = cond TRUE set
        switch (opc) {
            case BO_LT: *range = codeskeptic::Interval::atMost(k - 1); break;
            case BO_LE: *range = codeskeptic::Interval::atMost(k); break;
            case BO_GT: *range = codeskeptic::Interval::atLeast(k + 1); break;
            case BO_GE: *range = codeskeptic::Interval::atLeast(k); break;
            case BO_EQ: *range = codeskeptic::Interval::constant(k); break;
            default: return false;  // != true-set: two rays
        }
    } else {
        // null when cond TRUE → safe zone = cond FALSE set
        switch (opc) {
            case BO_LT: *range = codeskeptic::Interval::atLeast(k); break;
            case BO_LE: *range = codeskeptic::Interval::atLeast(k + 1); break;
            case BO_GT: *range = codeskeptic::Interval::atMost(k); break;
            case BO_GE: *range = codeskeptic::Interval::atMost(k - 1); break;
            case BO_NE: *range = codeskeptic::Interval::constant(k); break;
            default: return false;  // == false-set: two rays
        }
    }
    // ±1 adjustments must not have wrapped.
    if ((opc == BO_LT && k == INT64_MIN) || (opc == BO_LE && k == INT64_MAX) ||
        (opc == BO_GT && k == INT64_MAX) || (opc == BO_GE && k == INT64_MIN))
        return false;
    *paramIdx = idx;
    return true;
}

// Walk the parent chain from the bad return looking for a recognized
// guard. Extra ENCLOSING conditions only further restrict when the
// return runs — they never weaken the claim.
bool findGuardAbove(const ReturnStmt* badRet, const FunctionDecl* func,
                    ASTContext& ctx, int* paramIdx,
                    codeskeptic::Interval* range) {
    DynTypedNode node = DynTypedNode::create(*badRet);
    const Stmt* childStmt = badRet;
    // Labels are not nesting parents of everything in their region —
    // only of their FIRST statement. The chain passes through a
    // DefaultStmt exactly when the bad return IS the default's own
    // statement (`default: return null;`); anything looser is a
    // conservative miss.
    const SwitchCase* viaLabel = nullptr;
    for (unsigned depth = 0; depth < 64; ++depth) {
        auto parents = ctx.getParents(node);
        if (parents.empty()) return false;
        const Stmt* parent = parents[0].get<Stmt>();
        if (!parent) return false;  // reached the FunctionDecl

        if (const auto* sc = dyn_cast<SwitchCase>(parent)) viaLabel = sc;
        if (const auto* sw = dyn_cast<SwitchStmt>(parent)) {
            // The label we came through must be THIS switch's default
            // (an inner switch's label must not leak outward).
            bool viaThisDefault = false;
            for (const SwitchCase* sc = sw->getSwitchCaseList(); sc;
                 sc = sc->getNextSwitchCase())
                if (sc == viaLabel && isa<DefaultStmt>(sc)) {
                    viaThisDefault = true;
                    break;
                }
            if (viaThisDefault &&
                matchSwitchDefaultGuard(sw, func, ctx, paramIdx, range))
                return true;
            viaLabel = nullptr;
        }
        if (const auto* ifStmt = dyn_cast<IfStmt>(parent)) {
            const bool inThen = ifStmt->getThen() == childStmt;
            const bool inElse = ifStmt->getElse() == childStmt;
            if ((inThen || inElse) &&
                matchComparisonGuard(ifStmt->getCond(), /*nullWhenTrue=*/inThen,
                                     func, ctx, paramIdx, range))
                return true;
        }
        childStmt = parent;
        node = DynTypedNode::create(*parent);
    }
    return false;
}

// Entry point, called only when the plain harvest said MaybeNull.
// Fills (paramIdx, range) when the conditioned claim is PROVEN.
bool detectNullCondition(const FunctionDecl* func, ASTContext& ctx,
                         const SummaryTable& previous, int* paramIdx,
                         codeskeptic::Interval* range) {
    struct RetStmtCollector : RecursiveASTVisitor<RetStmtCollector> {
        std::vector<const ReturnStmt*> returns;
        bool VisitReturnStmt(ReturnStmt* ret) {
            returns.push_back(ret);
            return true;
        }
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    };
    RetStmtCollector collector;
    collector.TraverseStmt(func->getBody());

    const ReturnStmt* badRet = nullptr;
    for (const ReturnStmt* ret : collector.returns) {
        VState v = vstateOf(ret->getRetValue(), previous);
        if (v == VState::NonBad) continue;
        // Anything not structurally proven — variable returns, unknown
        // calls — makes per-return attribution unsafe: bail to plain
        // MaybeNull. Exactly one bad return is supported (v1).
        if (v != VState::Bad || badRet) return false;
        badRet = ret;
    }
    if (!badRet) return false;
    return findGuardAbove(badRet, func, ctx, paramIdx, range);
}

// --- Parameter effects (v2: with alias tracking) ---
//
// Two passes:
//  A) Copy edges are collected (`T* L = X;` / `L = X;`, X a direct
//     param/local reference, L a local) + taint seeds (non-direct-ref
//     assignment, address-taken local, static local).
//  B) Effect contexts are resolved to the parameter via clean aliases.
//
// Taint rules: a local fed from a dirty source, address-taken, or
// reachable from more than one parameter is NOT a "clean alias"; a
// parameter reaching such a local conservatively falls to Stores (a
// false Frees/ReadsOnly claim could have produced FPs).
//
// Known over-approximation (may-semantics): even if the parameter
// itself is reassigned, its name keeps denoting the original value —
// cJSON_Delete-style `while(item){ ...; free(item); item = next; }`
// loops are thus seen as Frees (the first iteration frees the original).

struct ParamFlags {
    bool frees = false;
    bool stores = false;
};

llvm::StringRef calleeIdentifier(const FunctionDecl* callee) {
    if (!callee) return {};
    if (const auto* id = callee->getIdentifier()) return id->getName();
    return {};
}

const ValueDecl* asVarOrParam(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());  // includes ParmVarDecl
    return nullptr;
}

bool isPlainLocal(const ValueDecl* d) {
    const auto* var = dyn_cast_or_null<VarDecl>(d);
    return var && !isa<ParmVarDecl>(var) && var->hasLocalStorage();
}

// Pass A: copy graph + taint seeds
class AliasCollector : public RecursiveASTVisitor<AliasCollector> {
public:
    std::vector<std::pair<const ValueDecl*, const VarDecl*>> edges;
    std::set<const VarDecl*> tainted;

    bool VisitVarDecl(VarDecl* var) {
        if (!var->hasInit() || isa<ParmVarDecl>(var)) return true;
        if (!var->hasLocalStorage()) return true;  // static local: pass B
        recordAssign(var, var->getInit());
        return true;
    }

    bool VisitBinaryOperator(BinaryOperator* binOp) {
        if (binOp->getOpcode() != BO_Assign) return true;
        const ValueDecl* lhs = asVarOrParam(binOp->getLHS());
        if (isPlainLocal(lhs))
            recordAssign(cast<VarDecl>(lhs), binOp->getRHS());
        return true;
    }

    bool VisitUnaryOperator(UnaryOperator* unary) {
        if (unary->getOpcode() != UO_AddrOf) return true;
        // An address-taken local can be written from outside — untrackable
        const ValueDecl* operand = asVarOrParam(unary->getSubExpr());
        if (isPlainLocal(operand))
            tainted.insert(cast<VarDecl>(operand));
        return true;
    }

private:
    void recordAssign(const VarDecl* target, const Expr* value) {
        const ValueDecl* source = asVarOrParam(value);
        bool directRef = source && (isa<ParmVarDecl>(source) ||
                                    isPlainLocal(source));
        if (directRef)
            edges.emplace_back(source, target);
        else
            tainted.insert(target);  // dirty source (call, member, arithmetic)
    }
};

struct AliasInfo {
    // clean local alias -> its single parameter source
    std::map<const VarDecl*, const ParmVarDecl*> cleanAlias;
    // parameter -> {parameter + its clean aliases} (for containment)
    std::map<const ParmVarDecl*, std::set<const ValueDecl*>> family;
    // parameters that reach a dirty/multi-source local
    std::set<const ParmVarDecl*> taintedReach;
};

AliasInfo computeAliases(const FunctionDecl* func,
                         const AliasCollector& collected) {
    AliasInfo info;

    // Taint propagation: a copy of a dirty local is dirty too
    std::set<const VarDecl*> tainted = collected.tainted;
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& [from, to] : collected.edges) {
            const auto* fromLocal = dyn_cast<VarDecl>(from);
            if (fromLocal && !isa<ParmVarDecl>(fromLocal) &&
                tainted.count(fromLocal) && tainted.insert(to).second)
                changed = true;
        }
    }

    // Origin sets: BFS from the parameters through clean locals. A
    // parameter that REACHES a dirty local enters taintedReach.
    std::map<const VarDecl*, std::set<const ParmVarDecl*>> origins;
    for (const auto* p : func->parameters()) {
        if (!p->getType()->isPointerType()) continue;
        std::set<const ValueDecl*> frontier{p};
        std::set<const ValueDecl*> visited{p};
        while (!frontier.empty()) {
            std::set<const ValueDecl*> next;
            for (const auto& [from, to] : collected.edges) {
                if (!frontier.count(from) || visited.count(to)) continue;
                visited.insert(to);
                if (tainted.count(to)) {
                    info.taintedReach.insert(p);
                    continue;  // we carry no origin past a dirty local
                }
                origins[to].insert(p);
                next.insert(to);
            }
            frontier = std::move(next);
        }
    }

    for (const auto& [local, params] : origins) {
        if (params.size() == 1) {
            const ParmVarDecl* p = *params.begin();
            info.cleanAlias[local] = p;
            info.family[p].insert(local);
        } else {
            // A local reachable from several parameters: cannot be
            // safely tied to any — the involved parameters go conservative
            for (const auto* p : params) info.taintedReach.insert(p);
        }
    }
    for (const auto* p : func->parameters())
        if (p->getType()->isPointerType()) info.family[p].insert(p);

    return info;
}

// Does expr contain any member of the family (param + clean aliases)?
bool containsAnyRef(const Expr* expr,
                    const std::set<const ValueDecl*>& family) {
    if (!expr) return false;
    struct Finder : RecursiveASTVisitor<Finder> {
        const std::set<const ValueDecl*>* family;
        bool found = false;
        bool VisitDeclRefExpr(DeclRefExpr* ref) {
            if (family->count(ref->getDecl())) {
                found = true;
                return false;
            }
            return true;
        }
    };
    Finder finder;
    finder.family = &family;
    finder.TraverseStmt(const_cast<Expr*>(expr));
    return finder.found;
}

// Pass B: effects — contexts are resolved to the parameter via aliases
class ParamEffectVisitor : public RecursiveASTVisitor<ParamEffectVisitor> {
public:
    ParamEffectVisitor(const FunctionDecl* func,
                       const SummaryTable& previous,
                       const AliasInfo& aliases,
                       std::map<const ParmVarDecl*, ParamFlags>& flags)
        : previous_(previous), aliases_(aliases), flags_(flags) {
        for (const auto* p : func->parameters())
            if (p->getType()->isPointerType()) flags_[p];  // open the entry
    }

    bool VisitCXXDeleteExpr(CXXDeleteExpr* del) {
        if (const auto* p = resolve(del->getArgument()))
            flags_[p].frees = true;
        return true;
    }

    bool VisitCallExpr(CallExpr* call) {
        const FunctionDecl* callee = call->getDirectCallee();
        bool isFreeByName = calleeIdentifier(callee) == "free";
        const FunctionSummary* summary = lookupPrev(previous_, callee);

        for (unsigned i = 0; i < call->getNumArgs(); ++i) {
            const Expr* arg = call->getArg(i);
            if (const auto* p = resolve(arg)) {
                if (isFreeByName && i == 0) {
                    flags_[p].frees = true;
                } else if (summary) {
                    switch (summary->paramEffect(i)) {
                        case ParamEffect::Frees:
                            flags_[p].frees = true; break;
                        case ParamEffect::ReadsOnly:
                            break;  // no effect
                        case ParamEffect::Stores:
                        case ParamEffect::Opaque:
                            flags_[p].stores = true; break;
                    }
                } else {
                    flags_[p].stores = true;  // opaque call
                }
            } else {
                // If a family member occurs INSIDE the argument
                // (p ? p : q) a derived value may escape — conservative
                for (auto& [param, f] : flags_) {
                    if (containsAnyRef(arg, aliases_.family.at(param)))
                        f.stores = true;
                }
            }
        }
        return true;
    }

    bool VisitBinaryOperator(BinaryOperator* binOp) {
        if (binOp->getOpcode() != BO_Assign) return true;
        const auto* p = resolve(binOp->getRHS());
        if (!p) return true;
        // A copy into a local/param target is the alias graph's job
        // (pass A + taint); any other target (global, member, deref,
        // array) is a real escape
        const ValueDecl* lhs = asVarOrParam(binOp->getLHS());
        bool lhsIsLocalish =
            lhs && (isa<ParmVarDecl>(lhs) || isPlainLocal(lhs));
        if (!lhsIsLocalish) flags_[p].stores = true;
        return true;
    }

    bool VisitVarDecl(VarDecl* var) {
        // static local init: storage outliving the function
        if (isa<ParmVarDecl>(var) || !var->hasInit()) return true;
        if (var->hasLocalStorage()) return true;  // pass A handled it
        if (const auto* p = resolve(var->getInit()))
            flags_[p].stores = true;
        return true;
    }

    bool VisitReturnStmt(ReturnStmt* ret) {
        // return p / return alias — escape back to the caller
        if (const auto* p = resolve(ret->getRetValue()))
            flags_[p].stores = true;
        return true;
    }

    bool VisitUnaryOperator(UnaryOperator* unary) {
        if (unary->getOpcode() != UO_AddrOf) return true;
        // &p (address of the parameter) — untrackable write channel.
        // (&alias is a taint seed in pass A; taintedReach handles it.)
        const ValueDecl* operand = asVarOrParam(unary->getSubExpr());
        if (const auto* p = dyn_cast_or_null<ParmVarDecl>(operand))
            if (flags_.count(p)) flags_[p].stores = true;
        return true;
    }

private:
    const ParmVarDecl* resolve(const Expr* expr) const {
        const ValueDecl* d = asVarOrParam(expr);
        if (!d) return nullptr;
        if (const auto* p = dyn_cast<ParmVarDecl>(d))
            return flags_.count(p) ? p : nullptr;
        auto it = aliases_.cleanAlias.find(cast<VarDecl>(d));
        return it != aliases_.cleanAlias.end() ? it->second : nullptr;
    }

    const SummaryTable& previous_;
    const AliasInfo& aliases_;
    std::map<const ParmVarDecl*, ParamFlags>& flags_;
};

std::vector<ParamEffect> computeParamEffects(const FunctionDecl* func,
                                             const SummaryTable& previous) {
    AliasCollector collector;
    collector.TraverseStmt(func->getBody());
    AliasInfo aliases = computeAliases(func, collector);

    std::map<const ParmVarDecl*, ParamFlags> flags;
    ParamEffectVisitor visitor(func, previous, aliases, flags);
    visitor.TraverseStmt(func->getBody());

    // A parameter reaching a dirty/multi-source local: untrackable flow
    for (const auto* p : aliases.taintedReach)
        if (flags.count(p)) flags[p].stores = true;

    std::vector<ParamEffect> effects;
    effects.reserve(func->getNumParams());
    for (const auto* p : func->parameters()) {
        if (!p->getType()->isPointerType()) {
            effects.push_back(ParamEffect::Opaque);
            continue;
        }
        const ParamFlags& f = flags[p];
        if (f.stores)
            effects.push_back(ParamEffect::Stores);
        else if (f.frees)
            effects.push_back(ParamEffect::Frees);
        else
            effects.push_back(ParamEffect::ReadsOnly);
    }
    return effects;
}

// --- Collect the functions with bodies in the TU ---

struct FunctionCollector : RecursiveASTVisitor<FunctionCollector> {
    std::vector<const FunctionDecl*> functions;
    bool VisitFunctionDecl(FunctionDecl* func) {
        if (func->isThisDeclarationADefinition() && func->hasBody())
            functions.push_back(func);
        return true;
    }
};

} // anonymous namespace

namespace codeskeptic {

SummaryRegistry& SummaryRegistry::instance() {
    static SummaryRegistry registry;
    return registry;
}

void SummaryRegistry::clear() {
    summaries_.clear();
    stable_ = false;
}

void SummaryRegistry::rebuild(clang::ASTContext& ctx) {
    stable_ = false;
    summaries_.clear();

    FunctionCollector collector;
    collector.TraverseDecl(ctx.getTranslationUnitDecl());

    // Fixpoint sweeping: each round recomputes the summaries FROM
    // SCRATCH against the previous round's table; we stop when nothing
    // changes. Recursion sees its own old summary — strong claims
    // (NeverNull, ReadsOnly) form only when supported.
    SummaryTable current;
    for (unsigned sweep = 0; sweep < kMaxSweeps; ++sweep) {
        SummaryTable next;
        bool changed = false;
        for (const auto* func : collector.functions) {
            FunctionSummary summary;
            summary.returnNullness = computeReturnNullness(func, ctx, current);
            summary.returnZeroness = computeReturnZeroness(
                func, ctx, current, &summary.zeroFromParam);
            summary.params = computeParamEffects(func, current);

            // #69b: try to strengthen a plain MaybeNull into the
            // value-conditioned form (null only if param outside R).
            if (summary.returnNullness == ReturnNullness::MaybeNull) {
                int condParam = -1;
                Interval condRange = Interval::top();
                if (detectNullCondition(func, ctx, current, &condParam,
                                        &condRange)) {
                    summary.nullCondParam = condParam;
                    summary.nullCondRange = condRange;
                }
            }

            const auto* key = func->getCanonicalDecl();
            next[key] = summary;

            auto prev = current.find(key);
            if (prev == current.end() ||
                prev->second.returnNullness != summary.returnNullness ||
                prev->second.returnZeroness != summary.returnZeroness ||
                prev->second.zeroFromParam != summary.zeroFromParam ||
                prev->second.nullCondParam != summary.nullCondParam ||
                prev->second.nullCondRange != summary.nullCondRange ||
                prev->second.params != summary.params) {
                changed = true;
            }
        }
        current = std::move(next);
        if (!changed) break;
    }
    summaries_ = std::move(current);
    stable_ = true;  // consumers may now fold on these (see stable())
}

const SummaryRegistry::FunctionSummary*
SummaryRegistry::lookup(const clang::FunctionDecl* func) const {
    if (!func) return nullptr;
    auto it = summaries_.find(func->getCanonicalDecl());
    if (it != summaries_.end()) return &it->second;
    return lookupGlobal(func);
}

namespace {

std::string globalKey(const FunctionDecl* func) {
    return func->getQualifiedNameAsString() + "/" +
           std::to_string(func->getNumParams());
}

// Different summaries landing on the same key (C++ overloads) merge
// conservatively: a mismatched field falls to the weak claim — a false
// strong claim (NeverNull/Frees/ReadsOnly) cannot arise from a collision.
void mergeConservative(SummaryRegistry::FunctionSummary& into,
                       const SummaryRegistry::FunctionSummary& from) {
    using RN = SummaryRegistry::ReturnNullness;
    using RZ = SummaryRegistry::ReturnZeroness;
    using PE = SummaryRegistry::ParamEffect;
    if (into.returnNullness != from.returnNullness)
        into.returnNullness = RN::Unknown;
    // A conditioned claim survives a merge only when BOTH sides carry
    // the identical condition; any disagreement falls back to plain
    // MaybeNull (weaker, always sound).
    if (into.nullCondParam != from.nullCondParam ||
        into.nullCondRange != from.nullCondRange) {
        into.nullCondParam = -1;
        into.nullCondRange = codeskeptic::Interval::top();
    }
    if (into.returnNullness != RN::MaybeNull) {
        into.nullCondParam = -1;
        into.nullCondRange = codeskeptic::Interval::top();
    }
    if (into.returnZeroness != from.returnZeroness)
        into.returnZeroness = RZ::Unknown;
    // The passthrough claim survives a merge only on exact agreement,
    // and only in its defined home (returnZeroness == Unknown).
    if (into.zeroFromParam != from.zeroFromParam ||
        into.returnZeroness != RZ::Unknown)
        into.zeroFromParam = -1;
    if (into.params.size() != from.params.size()) {
        into.params.clear();  // paramEffect() defaults to Opaque
        return;
    }
    for (size_t i = 0; i < into.params.size(); ++i)
        if (into.params[i] != from.params[i]) into.params[i] = PE::Opaque;
}

// --- Disk format ---
//
// v2: key<TAB>return-null<TAB>params<TAB>return-zero
// v1 (legacy): no last column — recognized on load, zeroness stays Unknown.
// Returns: U/N/M; params are a char string of O/R/F/S, empty vector "-".
// Qualified names cannot contain TAB/newline — the key is safe.
constexpr const char* kSummaryFileHeader = "codeskeptic-summaries v4";
constexpr const char* kSummaryFileHeaderV3 = "codeskeptic-summaries v3";
constexpr const char* kSummaryFileHeaderV2 = "codeskeptic-summaries v2";
constexpr const char* kSummaryFileHeaderV1 = "codeskeptic-summaries v1";

char rnToChar(ReturnNullness v) {
    switch (v) {
        case ReturnNullness::NeverNull: return 'N';
        case ReturnNullness::MaybeNull: return 'M';
        case ReturnNullness::Unknown:   break;
    }
    return 'U';
}

bool rnFromChar(char c, ReturnNullness& out) {
    switch (c) {
        case 'U': out = ReturnNullness::Unknown;   return true;
        case 'N': out = ReturnNullness::NeverNull; return true;
        case 'M': out = ReturnNullness::MaybeNull; return true;
    }
    return false;
}

char rzToChar(ReturnZeroness v) {
    switch (v) {
        case ReturnZeroness::NeverZero: return 'N';
        case ReturnZeroness::MaybeZero: return 'M';
        case ReturnZeroness::Unknown:   break;
    }
    return 'U';
}

bool rzFromChar(char c, ReturnZeroness& out) {
    switch (c) {
        case 'U': out = ReturnZeroness::Unknown;   return true;
        case 'N': out = ReturnZeroness::NeverZero; return true;
        case 'M': out = ReturnZeroness::MaybeZero; return true;
    }
    return false;
}

char peToChar(ParamEffect v) {
    switch (v) {
        case ParamEffect::ReadsOnly: return 'R';
        case ParamEffect::Frees:     return 'F';
        case ParamEffect::Stores:    return 'S';
        case ParamEffect::Opaque:    break;
    }
    return 'O';
}

bool peFromChar(char c, ParamEffect& out) {
    switch (c) {
        case 'O': out = ParamEffect::Opaque;    return true;
        case 'R': out = ParamEffect::ReadsOnly; return true;
        case 'F': out = ParamEffect::Frees;     return true;
        case 'S': out = ParamEffect::Stores;    return true;
    }
    return false;
}

} // anonymous namespace

void SummaryRegistry::harvestGlobal() {
    for (const auto& [func, summary] : summaries_) {
        if (!func->isExternallyVisible()) continue;
        auto [it, inserted] = globalStore_.emplace(globalKey(func), summary);
        if (!inserted) mergeConservative(it->second, summary);
    }
}

const SummaryRegistry::FunctionSummary*
SummaryRegistry::lookupGlobal(const clang::FunctionDecl* func) const {
    if (!func || globalStore_.empty()) return nullptr;
    if (!func->isExternallyVisible()) return nullptr;
    auto it = globalStore_.find(globalKey(func));
    if (it == globalStore_.end()) return nullptr;
    return &it->second;
}

void SummaryRegistry::clearGlobal() { globalStore_.clear(); }

bool SummaryRegistry::saveGlobal(const std::string& path) const {
    std::ofstream out(path);
    if (!out.is_open()) return false;
    out << kSummaryFileHeader << "\n";
    // std::map iterates in order — output is deterministic (diffable;
    // "did the summary change" is answered by comparing files)
    for (const auto& [key, summary] : globalStore_) {
        out << key << '\t' << rnToChar(summary.returnNullness) << '\t';
        if (summary.params.empty()) {
            out << '-';
        } else {
            for (ParamEffect effect : summary.params)
                out << peToChar(effect);
        }
        out << '\t' << rzToChar(summary.returnZeroness) << '\t';
        // v3 column: value-conditioned null return, "-" when absent,
        // else "paramIdx:lo:hi" with "~" for an infinite bound.
        if (!summary.hasNullCondition()) {
            out << '-';
        } else {
            out << summary.nullCondParam << ':';
            if (summary.nullCondRange.loIsInf()) out << '~';
            else out << summary.nullCondRange.lo();
            out << ':';
            if (summary.nullCondRange.hiIsInf()) out << '~';
            else out << summary.nullCondRange.hi();
        }
        // v4 column: zero-passthrough param index, "-" when absent.
        out << '\t';
        if (summary.zeroFromParam < 0) out << '-';
        else out << summary.zeroFromParam;
        out << '\n';
    }
    return out.good();
}

bool SummaryRegistry::parseSummaryFile(
    const std::string& path,
    std::map<std::string, FunctionSummary>& out) {
    std::ifstream in(path);
    if (!in.is_open()) return false;

    std::string line;
    if (!std::getline(in, line)) return false;
    int version = 0;
    if (line == kSummaryFileHeader) version = 4;
    else if (line == kSummaryFileHeaderV3) version = 3;
    else if (line == kSummaryFileHeaderV2) version = 2;
    else if (line == kSummaryFileHeaderV1) version = 1;
    else return false;
    // Field count is VERSION-strict: extra columns under an old header
    // are corruption, not a future format (rejected wholesale).
    const size_t maxFields = (version >= 4) ? 6 : (version == 3) ? 5 : 4;

    // Parse fully first, then hand over: a corrupt file is rejected
    // without leaving partial state behind
    std::map<std::string, FunctionSummary> parsed;
    while (std::getline(in, line)) {
        if (line.empty()) continue;

        std::vector<std::string> fields;
        size_t start = 0;
        for (auto tab = line.find('\t'); tab != std::string::npos;
             tab = line.find('\t', start)) {
            fields.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }
        fields.push_back(line.substr(start));

        // v1: 3 fields (no zeroness -> Unknown); v2: 4; v3: 5 (null
        // cond); v4: 6 (zero-passthrough param)
        if (fields.size() < 3 || fields.size() > maxFields) return false;
        const std::string& key = fields[0];
        const std::string& rn = fields[1];
        const std::string& pe = fields[2];
        if (key.empty() || rn.size() != 1 || pe.empty()) return false;

        FunctionSummary summary;
        if (!rnFromChar(rn[0], summary.returnNullness)) return false;
        if (fields.size() >= 4) {
            if (fields[3].size() != 1 ||
                !rzFromChar(fields[3][0], summary.returnZeroness))
                return false;
        }
        if (fields.size() >= 5 && fields[4] != "-") {
            // "paramIdx:lo:hi", "~" = infinite bound
            const std::string& cond = fields[4];
            size_t c1 = cond.find(':');
            size_t c2 = (c1 == std::string::npos)
                            ? std::string::npos
                            : cond.find(':', c1 + 1);
            if (c2 == std::string::npos) return false;
            auto parseBound = [](const std::string& s, bool* inf,
                                 int64_t* v) {
                if (s == "~") { *inf = true; return true; }
                *inf = false;
                if (s.empty()) return false;
                errno = 0;
                char* end = nullptr;
                long long r = std::strtoll(s.c_str(), &end, 10);
                if (errno != 0 || end != s.c_str() + s.size()) return false;
                *v = r;
                return true;
            };
            int64_t paramIdx = 0, lo = 0, hi = 0;
            bool dummyInf = false, loInf = false, hiInf = false;
            if (!parseBound(cond.substr(0, c1), &dummyInf, &paramIdx) ||
                dummyInf || paramIdx < 0)
                return false;
            if (!parseBound(cond.substr(c1 + 1, c2 - c1 - 1), &loInf, &lo))
                return false;
            if (!parseBound(cond.substr(c2 + 1), &hiInf, &hi)) return false;
            // A condition is only meaningful on a MaybeNull summary.
            if (summary.returnNullness != ReturnNullness::MaybeNull)
                return false;
            summary.nullCondParam = static_cast<int>(paramIdx);
            if (loInf && hiInf)
                summary.nullCondRange = codeskeptic::Interval::top();
            else if (loInf)
                summary.nullCondRange = codeskeptic::Interval::atMost(hi);
            else if (hiInf)
                summary.nullCondRange = codeskeptic::Interval::atLeast(lo);
            else if (lo <= hi)
                summary.nullCondRange = codeskeptic::Interval::range(lo, hi);
            else
                return false;
        }
        if (fields.size() == 6 && fields[5] != "-") {
            const std::string& zf = fields[5];
            errno = 0;
            char* end = nullptr;
            long long idx = std::strtoll(zf.c_str(), &end, 10);
            if (errno != 0 || end != zf.c_str() + zf.size() || idx < 0)
                return false;
            // The claim lives only where it is defined: zeroness Unknown.
            if (summary.returnZeroness != ReturnZeroness::Unknown)
                return false;
            summary.zeroFromParam = static_cast<int>(idx);
        }
        if (pe != "-") {
            summary.params.reserve(pe.size());
            for (char c : pe) {
                ParamEffect effect;
                if (!peFromChar(c, effect)) return false;
                summary.params.push_back(effect);
            }
        }
        auto [it, inserted] = parsed.emplace(key, summary);
        if (!inserted) mergeConservative(it->second, summary);
    }

    out = std::move(parsed);
    return true;
}

bool SummaryRegistry::loadGlobal(const std::string& path) {
    std::map<std::string, FunctionSummary> parsed;
    if (!parseSummaryFile(path, parsed)) return false;

    for (const auto& [key, summary] : parsed) {
        auto [it, inserted] = globalStore_.emplace(key, summary);
        if (!inserted) mergeConservative(it->second, summary);
    }
    return true;
}

} // namespace codeskeptic
