#include "engine/FunctionSummary.h"

#include "engine/ConditionWalk.h"
#include "engine/DataflowEngine.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>

#include <algorithm>
#include <fstream>
#include <set>
#include <utility>
#include <vector>

using namespace clang;

namespace {

constexpr unsigned kMaxSweeps = 5;

using ReturnNullness = zerodefect::SummaryRegistry::ReturnNullness;
using ReturnZeroness = zerodefect::SummaryRegistry::ReturnZeroness;
using ParamEffect = zerodefect::SummaryRegistry::ParamEffect;
using FunctionSummary = zerodefect::SummaryRegistry::FunctionSummary;
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
    return zerodefect::SummaryRegistry::instance().lookupGlobal(callee);
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
    zerodefect::walkNullCondition(
        cond, isTrue, [&](const VarDecl* var, bool isNull) {
            auto it = state.find(var);
            if (it != state.end())
                it->second = isNull ? VState::Bad : VState::NonBad;
        });
}

void applyZeroCond(const Expr* cond, bool isTrue,
                   std::map<const VarDecl*, VState>& state) {
    zerodefect::walkZeroCondition(
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
    zerodefect::runDataflow(func, ctx, analysis);
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

ReturnZeroness computeReturnZeroness(const FunctionDecl* func,
                                     ASTContext& ctx,
                                     const SummaryTable& previous) {
    // bool excluded: the falses in the `return ok;` pattern would count
    // as zero, yielding MaybeZero everywhere; a bool divisor is
    // meaningless anyway
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
    return ReturnZeroness::Unknown;
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

namespace zerodefect {

SummaryRegistry& SummaryRegistry::instance() {
    static SummaryRegistry registry;
    return registry;
}

void SummaryRegistry::clear() { summaries_.clear(); }

void SummaryRegistry::rebuild(clang::ASTContext& ctx) {
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
            summary.returnZeroness = computeReturnZeroness(func, ctx, current);
            summary.params = computeParamEffects(func, current);

            const auto* key = func->getCanonicalDecl();
            next[key] = summary;

            auto prev = current.find(key);
            if (prev == current.end() ||
                prev->second.returnNullness != summary.returnNullness ||
                prev->second.returnZeroness != summary.returnZeroness ||
                prev->second.params != summary.params) {
                changed = true;
            }
        }
        current = std::move(next);
        if (!changed) break;
    }
    summaries_ = std::move(current);
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
    if (into.returnZeroness != from.returnZeroness)
        into.returnZeroness = RZ::Unknown;
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
constexpr const char* kSummaryFileHeader = "zerodefect-summaries v2";
constexpr const char* kSummaryFileHeaderV1 = "zerodefect-summaries v1";

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
        out << '\t' << rzToChar(summary.returnZeroness) << '\n';
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
    if (line != kSummaryFileHeader && line != kSummaryFileHeaderV1)
        return false;

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

        // v1: 3 fields (no zeroness -> Unknown); v2: 4 fields
        if (fields.size() != 3 && fields.size() != 4) return false;
        const std::string& key = fields[0];
        const std::string& rn = fields[1];
        const std::string& pe = fields[2];
        if (key.empty() || rn.size() != 1 || pe.empty()) return false;

        FunctionSummary summary;
        if (!rnFromChar(rn[0], summary.returnNullness)) return false;
        if (fields.size() == 4) {
            if (fields[3].size() != 1 ||
                !rzFromChar(fields[3][0], summary.returnZeroness))
                return false;
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

} // namespace zerodefect
