#include "engine/FunctionSummary.h"

#include "contracts/GuardContracts.h"
#include "engine/AllocFunctions.h"
#include "engine/CallRefArgs.h"
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
#include <optional>
#include <set>
#include <utility>
#include <vector>

using namespace clang;

namespace codeskeptic {
void mergeConservative(
    SummaryRegistry::FunctionSummary& into,
    const SummaryRegistry::FunctionSummary& from);
void mergeTargetSummaries(
    SummaryRegistry::FunctionSummary& into,
    const SummaryRegistry::FunctionSummary& from);
} // namespace codeskeptic

using codeskeptic::mergeConservative;
using codeskeptic::mergeTargetSummaries;

namespace {

constexpr unsigned kMinimumSccSweeps = 16;

using ReturnNullness = codeskeptic::SummaryRegistry::ReturnNullness;
using ReturnZeroness = codeskeptic::SummaryRegistry::ReturnZeroness;
using ReturnOwnership = codeskeptic::SummaryRegistry::ReturnOwnership;
using ParamEffect = codeskeptic::SummaryRegistry::ParamEffect;
using ParamAccess = codeskeptic::SummaryRegistry::ParamAccess;
using ParamOwnership = codeskeptic::SummaryRegistry::ParamOwnership;
using ParamPrecondition = codeskeptic::SummaryRegistry::ParamPrecondition;
using ParamPostcondition = codeskeptic::SummaryRegistry::ParamPostcondition;
using ParamAllocatorSize =
    codeskeptic::SummaryRegistry::ParamAllocatorSize;
using FieldWriteSet = codeskeptic::SummaryRegistry::FieldWriteSet;
using FunctionSummary = codeskeptic::SummaryRegistry::FunctionSummary;
using SummaryTable = std::map<const FunctionDecl*, FunctionSummary>;
using FunctionTargetSet = std::set<const FunctionDecl*>;
using IndirectTargetMap =
    std::map<const CallExpr*, std::vector<const FunctionDecl*>>;

const IndirectTargetMap* activeIndirectTargets = nullptr;

const VarDecl* targetVarRef(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

bool containsTargetVar(const Expr* expr, const VarDecl* variable) {
    if (!expr || !variable) return false;
    struct Finder : RecursiveASTVisitor<Finder> {
        const VarDecl* variable = nullptr;
        bool found = false;
        bool VisitDeclRefExpr(DeclRefExpr* reference) {
            if (reference->getDecl() == variable) {
                found = true;
                return false;
            }
            return true;
        }
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    };
    Finder finder;
    finder.variable = variable;
    finder.TraverseStmt(const_cast<Expr*>(expr));
    return finder.found;
}

bool isFunctionPointerType(QualType type) {
    return !type.isNull() && type->isPointerType() &&
           type->getPointeeType()->isFunctionType();
}

// Closed, flow-insensitive target sets for automatic local function
// pointers. Every visible initializer/assignment contributes a target.
// Any unknown source or rebinding exposure rejects the whole set.
class LocalFunctionPointerResolver {
public:
    explicit LocalFunctionPointerResolver(const FunctionDecl* function)
        : function_(function) {}

    std::optional<FunctionTargetSet> resolve(const Expr* expr) {
        if (!expr) return std::nullopt;
        expr = expr->IgnoreParenImpCasts();

        if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) {
            if (const auto* function =
                    dyn_cast<FunctionDecl>(ref->getDecl())) {
                return FunctionTargetSet{function->getCanonicalDecl()};
            }
            if (const auto* variable = dyn_cast<VarDecl>(ref->getDecl()))
                return resolveVariable(variable);
            return std::nullopt;
        }
        if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
            if (unary->getOpcode() == UO_AddrOf ||
                unary->getOpcode() == UO_Deref)
                return resolve(unary->getSubExpr());
            return std::nullopt;
        }
        if (const auto* choice = dyn_cast<ConditionalOperator>(expr)) {
            auto yes = resolve(choice->getTrueExpr());
            auto no = resolve(choice->getFalseExpr());
            if (!yes || !no) return std::nullopt;
            yes->insert(no->begin(), no->end());
            return yes;
        }
        if (const auto* choice = dyn_cast<ChooseExpr>(expr))
            return resolve(choice->getChosenSubExpr());
        return std::nullopt;
    }

private:
    struct MutationCollector : RecursiveASTVisitor<MutationCollector> {
        const VarDecl* variable = nullptr;
        std::vector<const Expr*> assignments;
        bool unsafe = false;

        bool VisitBinaryOperator(BinaryOperator* assignment) {
            if (assignment->getOpcode() == BO_Assign &&
                containsTargetVar(assignment->getLHS(), variable))
                assignments.push_back(assignment->getRHS());
            return true;
        }

        bool VisitUnaryOperator(UnaryOperator* unary) {
            if (unary->getOpcode() == UO_AddrOf &&
                containsTargetVar(unary->getSubExpr(), variable))
                unsafe = true;
            return true;
        }

        bool VisitGCCAsmStmt(GCCAsmStmt* statement) {
            for (unsigned i = 0; i < statement->getNumOutputs(); ++i) {
                if (containsTargetVar(statement->getOutputExpr(i), variable)) {
                    unsafe = true;
                    break;
                }
            }
            return true;
        }

        bool VisitMSAsmStmt(MSAsmStmt*) {
            unsafe = true;
            return true;
        }

        bool VisitVarDecl(VarDecl* alias) {
            if (!alias->hasInit() || !alias->getType()->isReferenceType())
                return true;
            if (alias->getType().getNonReferenceType().isConstQualified())
                return true;
            if (containsTargetVar(alias->getInit(), variable)) unsafe = true;
            return true;
        }

        bool VisitCallExpr(CallExpr* call) {
            codeskeptic::forEachNonConstRefArg(
                call, [&](const Expr* argument) {
                    if (containsTargetVar(argument, variable)) unsafe = true;
                });
            return true;
        }

        bool TraverseLambdaExpr(LambdaExpr* lambda) {
            auto init = lambda->capture_init_begin();
            for (const LambdaCapture& capture : lambda->captures()) {
                const Expr* captureInit = *init++;
                if (capture.getCaptureKind() != LCK_ByRef) continue;
                if ((capture.capturesVariable() &&
                     capture.getCapturedVar() == variable) ||
                    containsTargetVar(captureInit, variable))
                    unsafe = true;
            }
            return true;
        }
    };

    std::optional<FunctionTargetSet> resolveVariable(
            const VarDecl* variable) {
        auto cached = cache_.find(variable);
        if (cached != cache_.end()) return cached->second;
        if (!resolving_.insert(variable).second) return std::nullopt;

        std::optional<FunctionTargetSet> result;
        const bool controlled =
            variable->getDeclContext() == function_ &&
            variable->getStorageDuration() == SD_Automatic &&
            isFunctionPointerType(variable->getType()) &&
            !variable->getType().isVolatileQualified() &&
            variable->hasInit();
        if (controlled) {
            MutationCollector mutations;
            mutations.variable = variable;
            mutations.TraverseStmt(
                const_cast<Stmt*>(function_->getBody()));
            if (!mutations.unsafe) {
                FunctionTargetSet targets;
                std::vector<const Expr*> sources{variable->getInit()};
                sources.insert(sources.end(), mutations.assignments.begin(),
                               mutations.assignments.end());
                bool exact = true;
                for (const Expr* source : sources) {
                    auto resolved = resolve(source);
                    if (!resolved || resolved->empty()) {
                        exact = false;
                        break;
                    }
                    targets.insert(resolved->begin(), resolved->end());
                }
                if (exact && !targets.empty()) result = std::move(targets);
            }
        }

        resolving_.erase(variable);
        cache_[variable] = result;
        return result;
    }

    const FunctionDecl* function_;
    std::map<const VarDecl*, std::optional<FunctionTargetSet>> cache_;
    std::set<const VarDecl*> resolving_;
};

struct ControlledIndirectCallCollector
    : RecursiveASTVisitor<ControlledIndirectCallCollector> {
    explicit ControlledIndirectCallCollector(const FunctionDecl* function)
        : resolver(function) {}

    bool VisitCallExpr(CallExpr* call) {
        if (call->getDirectCallee()) return true;
        auto targets = resolver.resolve(call->getCallee());
        if (!targets || targets->empty()) return true;
        (*output)[call] = {targets->begin(), targets->end()};
        return true;
    }

    bool TraverseLambdaExpr(LambdaExpr*) { return true; }

    LocalFunctionPointerResolver resolver;
    IndirectTargetMap* output = nullptr;
};

IndirectTargetMap buildIndirectTargetMap(
        const std::vector<const FunctionDecl*>& functions) {
    IndirectTargetMap out;
    for (const FunctionDecl* function : functions) {
        ControlledIndirectCallCollector collector(function);
        collector.output = &out;
        collector.TraverseStmt(
            const_cast<Stmt*>(function->getBody()));
    }
    return out;
}

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

std::optional<FunctionSummary> lookupPrev(
        const SummaryTable& previous, const CallExpr* call) {
    if (!call) return std::nullopt;
    if (const FunctionDecl* direct = call->getDirectCallee()) {
        if (const FunctionSummary* summary = lookupPrev(previous, direct))
            return *summary;
        return std::nullopt;
    }
    if (!activeIndirectTargets) return std::nullopt;
    auto found = activeIndirectTargets->find(call);
    if (found == activeIndirectTargets->end() || found->second.empty())
        return std::nullopt;

    std::optional<FunctionSummary> combined;
    for (const FunctionDecl* target : found->second) {
        const FunctionSummary* summary = lookupPrev(previous, target);
        if (!summary) return std::nullopt;
        if (!combined) combined = *summary;
        else mergeTargetSummaries(*combined, *summary);
    }
    return combined;
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
        if (const auto summary = lookupPrev(previous, call)) {
            if (summary->returnNullness == ReturnNullness::NeverNull)
                return VState::NonBad;
            if (summary->returnNullness == ReturnNullness::MaybeNull)
                return VState::MaybeBad;
            // Null-passthrough: the call's nullness IS argument
            // #nullFromParam's (`p = keep(fopen(...))` -> MaybeBad).
            // Finite recursion over the expression tree; a variable
            // argument stays Unknown here (stateless evaluator).
            if (summary->nullFromParam >= 0 &&
                static_cast<unsigned>(summary->nullFromParam) <
                    call->getNumArgs())
                return vstateOf(call->getArg(summary->nullFromParam),
                                previous);
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
        if (const auto summary = lookupPrev(previous, call)) {
            if (summary->returnZeroness == ReturnZeroness::AlwaysZero)
                return VState::Bad;
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
    bool allBad = true;
    bool allNonBad = true;
};

AggregateFlags aggregateFlags(const std::vector<VState>& contribs) {
    AggregateFlags flags;
    flags.empty = contribs.empty();
    for (VState v : contribs) {
        if (v == VState::Bad || v == VState::MaybeBad) flags.sawBad = true;
        if (v != VState::Bad) flags.allBad = false;
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

// --- Exact pointer return-alias relation (interprocedural v2) ---
//
// The lattice is deliberately tiny: -1 means "not proven"; otherwise
// the value is the index of the pointer parameter whose ENTRY object the
// variable denotes. A merge keeps a relation only on exact agreement.
// This is stricter than nullFromParam: returning either p or &global
// preserves null correspondence with p, but not object identity.
class ReturnAliasAnalysis {
public:
    using State = std::map<const VarDecl*, int>;

    ReturnAliasAnalysis(const FunctionDecl* func,
                        std::vector<const VarDecl*> trackedVars,
                        const SummaryTable& previous)
        : previous_(previous) {
        for (const auto* var : trackedVars) initState_[var] = -1;
        for (unsigned i = 0; i < func->getNumParams(); ++i) {
            const auto* param = func->getParamDecl(i);
            if (param->getType()->isPointerType())
                initState_[param] = static_cast<int>(i);
        }
    }

    State initialState() const { return initState_; }

    unsigned latticeHeight() const {
        return static_cast<unsigned>(initState_.size()) * 2 + 1;
    }

    State merge(const State& a, const State& b) const {
        State result = a;
        for (const auto& [var, source] : b) {
            auto it = result.find(var);
            if (it == result.end())
                result[var] = source;
            else if (it->second != source)
                it->second = -1;
        }
        return result;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& /*ctx*/) const {
        State out = in;

        if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
            for (const auto* decl : declStmt->decls()) {
                const auto* vd = dyn_cast<VarDecl>(decl);
                auto it = vd ? out.find(vd) : out.end();
                if (it != out.end())
                    it->second = vd->hasInit()
                                     ? originOf(vd->getInit(), out)
                                     : -1;
            }
        } else if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
            if (binOp->isAssignmentOp()) {
                const VarDecl* var = exprAsVar(binOp->getLHS());
                auto it = var ? out.find(var) : out.end();
                if (it != out.end())
                    it->second = binOp->getOpcode() == BO_Assign
                                     ? originOf(binOp->getRHS(), in)
                                     : -1;
            }
        } else if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
            if (unary->isIncrementDecrementOp())
                kill(exprAsVar(unary->getSubExpr()), out);
        }

        // Address-taking and non-const reference arguments expose a
        // write channel. Scan the current CFG element because these
        // expressions can be nested in an initializer or assignment.
        struct EscapeVisitor : RecursiveASTVisitor<EscapeVisitor> {
            State* state;
            static void killExpr(const Expr* expr, State& state) {
                const VarDecl* var = exprAsVar(expr);
                auto it = var ? state.find(var) : state.end();
                if (it != state.end()) it->second = -1;
            }
            bool VisitUnaryOperator(UnaryOperator* unary) {
                if (unary->getOpcode() == UO_AddrOf)
                    killExpr(unary->getSubExpr(), *state);
                return true;
            }
            bool VisitCallExpr(CallExpr* call) {
                codeskeptic::forEachNonConstRefArg(
                    call, [&](const Expr* arg) { killExpr(arg, *state); });
                return true;
            }
            bool TraverseLambdaExpr(LambdaExpr*) { return true; }
        } visitor;
        visitor.state = &out;
        visitor.TraverseStmt(const_cast<Stmt*>(stmt));
        return out;
    }

    void refineOnEdge(const Stmt*, bool, State&, ASTContext&) const {}

    void onStatement(const Stmt* stmt, const State& before,
                     const State&, ASTContext&) {
        const auto* ret = dyn_cast<ReturnStmt>(stmt);
        if (!ret || !ret->getRetValue()) return;
        contributions.push_back(originOf(ret->getRetValue(), before));
    }

    std::vector<int> contributions;

private:
    int originOf(const Expr* expr, const State& state) const {
        if (!expr) return -1;
        expr = expr->IgnoreParens();
        if (!expr->getType()->isPointerType()) return -1;

        if (const auto* cast = dyn_cast<CastExpr>(expr)) {
            if (isa<CXXDynamicCastExpr>(cast)) return -1;
            const Expr* sub = cast->getSubExpr();
            return sub->getType()->isPointerType()
                       ? originOf(sub, state)
                       : -1;
        }
        if (const VarDecl* var = exprAsVar(expr)) {
            auto it = state.find(var);
            return it == state.end() ? -1 : it->second;
        }
        if (const auto* call = dyn_cast<CallExpr>(expr)) {
            bool hasNonConstRefArg = false;
            codeskeptic::forEachNonConstRefArg(
                call, [&](const Expr*) { hasNonConstRefArg = true; });
            if (hasNonConstRefArg) return -1;

            const auto summary = lookupPrev(previous_, call);
            if (!summary || summary->returnAliasParam < 0) return -1;

            unsigned argOffset = 0;
            if (isa<CXXOperatorCallExpr>(call)) {
                const auto* method =
                    dyn_cast_or_null<CXXMethodDecl>(call->getDirectCallee());
                if (method && !method->isStatic()) argOffset = 1;
            }
            unsigned argIndex =
                static_cast<unsigned>(summary->returnAliasParam) + argOffset;
            if (argIndex >= call->getNumArgs()) return -1;
            return originOf(call->getArg(argIndex), state);
        }
        if (const auto* cond = dyn_cast<ConditionalOperator>(expr)) {
            int lhs = originOf(cond->getTrueExpr(), state);
            int rhs = originOf(cond->getFalseExpr(), state);
            return lhs >= 0 && lhs == rhs ? lhs : -1;
        }
        return -1;
    }

    static void kill(const VarDecl* var, State& state) {
        auto it = var ? state.find(var) : state.end();
        if (it != state.end()) it->second = -1;
    }

    const SummaryTable& previous_;
    State initState_;
};

int computeReturnAliasParam(const FunctionDecl* func, ASTContext& ctx,
                            const SummaryTable& previous) {
    if (!func->getReturnType()->isPointerType()) return -1;
    ReturnAliasAnalysis analysis(
        func,
        collectTypedVars(func, [](QualType t) { return t->isPointerType(); }),
        previous);
    codeskeptic::runDataflow(func, ctx, analysis);
    if (analysis.contributions.empty()) return -1;
    int source = analysis.contributions.front();
    if (source < 0) return -1;
    for (int contribution : analysis.contributions)
        if (contribution != source) return -1;
    return source;
}

// --- Exact pointer return ownership (interprocedural v2) ---
//
// The claim is conditional on a non-null result: allocator/new results are
// Owned, aliases of caller/global storage are Borrowed, and a null return is
// neutral. Mixed or unmodelled non-null paths collapse to Unknown.
enum class OwnershipState { Unknown, Owned, Borrowed, Null };

OwnershipState mergeOwnership(OwnershipState lhs, OwnershipState rhs) {
    if (lhs == rhs) return lhs;
    if (lhs == OwnershipState::Null) return rhs;
    if (rhs == OwnershipState::Null) return lhs;
    return OwnershipState::Unknown;
}

class ReturnOwnershipAnalysis {
public:
    using State = std::map<const VarDecl*, OwnershipState>;

    ReturnOwnershipAnalysis(const FunctionDecl* func,
                            std::vector<const VarDecl*> trackedVars,
                            const SummaryTable& previous)
        : previous_(previous) {
        for (const auto* var : trackedVars)
            initState_[var] = isa<ParmVarDecl>(var)
                                  ? OwnershipState::Borrowed
                                  : OwnershipState::Unknown;
    }

    State initialState() const { return initState_; }
    unsigned latticeHeight() const {
        return static_cast<unsigned>(initState_.size()) * 4 + 1;
    }
    State merge(const State& lhs, const State& rhs) const {
        State out = lhs;
        for (const auto& [var, value] : rhs) {
            auto it = out.find(var);
            if (it == out.end())
                out[var] = value;
            else
                it->second = mergeOwnership(it->second, value);
        }
        return out;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& /*ctx*/) const {
        State out = in;
        if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
            for (const auto* decl : declStmt->decls()) {
                const auto* var = dyn_cast<VarDecl>(decl);
                auto it = var ? out.find(var) : out.end();
                if (it != out.end())
                    it->second = var->hasInit()
                                     ? ownershipOf(var->getInit(), in)
                                     : OwnershipState::Unknown;
            }
        } else if (const auto* assign = dyn_cast<BinaryOperator>(stmt)) {
            if (assign->isAssignmentOp()) {
                const VarDecl* var = exprAsVar(assign->getLHS());
                auto it = var ? out.find(var) : out.end();
                if (it != out.end())
                    it->second = assign->getOpcode() == BO_Assign
                                     ? ownershipOf(assign->getRHS(), in)
                                     : OwnershipState::Unknown;
            }
        } else if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
            if (unary->isIncrementDecrementOp() ||
                unary->getOpcode() == UO_AddrOf)
                kill(exprAsVar(unary->getSubExpr()), out);
        } else if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            const auto summary = lookupPrev(previous_, call);
            unsigned argOffset = 0;
            if (isa<CXXOperatorCallExpr>(call)) {
                const auto* method = dyn_cast_or_null<CXXMethodDecl>(
                    call->getDirectCallee());
                if (method && !method->isStatic()) argOffset = 1;
            }
            for (unsigned argIndex = argOffset;
                 argIndex < call->getNumArgs(); ++argIndex) {
                const VarDecl* var = exprAsVar(call->getArg(argIndex));
                auto it = var ? out.find(var) : out.end();
                if (it == out.end()) continue;
                const unsigned paramIndex = argIndex - argOffset;
                if (!summary ||
                    summary->paramOwnership(paramIndex) !=
                        ParamOwnership::Borrowed)
                    it->second = OwnershipState::Unknown;
            }
        }
        return out;
    }

    void refineOnEdge(const Stmt*, bool, State&, ASTContext&) const {}

    void onStatement(const Stmt* stmt, const State& before,
                     const State&, ASTContext&) {
        const auto* ret = dyn_cast<ReturnStmt>(stmt);
        if (ret && ret->getRetValue())
            contributions.push_back(ownershipOf(ret->getRetValue(), before));
    }

    std::vector<OwnershipState> contributions;

private:
    OwnershipState ownershipOf(const Expr* expr, const State& state) const {
        if (!expr) return OwnershipState::Unknown;
        if (codeskeptic::isOwnedAllocationExpr(expr))
            return OwnershipState::Owned;
        expr = expr->IgnoreParenCasts();
        if (isa<CXXNullPtrLiteralExpr>(expr) || isa<GNUNullExpr>(expr))
            return OwnershipState::Null;
        if (const auto* literal = dyn_cast<IntegerLiteral>(expr))
            return literal->getValue() == 0 ? OwnershipState::Null
                                            : OwnershipState::Unknown;
        if (isa<StringLiteral>(expr) || isa<CXXThisExpr>(expr))
            return OwnershipState::Borrowed;
        if (const auto* unary = dyn_cast<UnaryOperator>(expr))
            if (unary->getOpcode() == UO_AddrOf)
                return OwnershipState::Borrowed;
        if (const VarDecl* var = exprAsVar(expr)) {
            auto it = state.find(var);
            return it == state.end() ? OwnershipState::Borrowed
                                     : it->second;
        }
        if (const auto* call = dyn_cast<CallExpr>(expr)) {
            const auto summary = lookupPrev(previous_, call);
            if (!summary) return OwnershipState::Unknown;
            if (summary->returnAliasParam >= 0) {
                unsigned argOffset = 0;
                if (isa<CXXOperatorCallExpr>(call)) {
                    const auto* method = dyn_cast_or_null<CXXMethodDecl>(
                        call->getDirectCallee());
                    if (method && !method->isStatic()) argOffset = 1;
                }
                const unsigned argIndex =
                    static_cast<unsigned>(summary->returnAliasParam) +
                    argOffset;
                if (argIndex < call->getNumArgs())
                    return ownershipOf(call->getArg(argIndex), state);
            }
            if (summary->returnOwnership == ReturnOwnership::Owned)
                return OwnershipState::Owned;
            if (summary->returnOwnership == ReturnOwnership::Borrowed)
                return OwnershipState::Borrowed;
            return OwnershipState::Unknown;
        }
        if (const auto* conditional = dyn_cast<ConditionalOperator>(expr))
            return mergeOwnership(
                ownershipOf(conditional->getTrueExpr(), state),
                ownershipOf(conditional->getFalseExpr(), state));
        return OwnershipState::Unknown;
    }

    static void kill(const VarDecl* var, State& state) {
        auto it = var ? state.find(var) : state.end();
        if (it != state.end()) it->second = OwnershipState::Unknown;
    }

    const SummaryTable& previous_;
    State initState_;
};

ReturnOwnership computeReturnOwnership(const FunctionDecl* func,
                                       ASTContext& ctx,
                                       const SummaryTable& previous) {
    if (!func->getReturnType()->isPointerType())
        return ReturnOwnership::Unknown;
    ReturnOwnershipAnalysis analysis(
        func,
        collectTypedVars(func, [](QualType type) {
            return type->isPointerType();
        }),
        previous);
    auto result = codeskeptic::runDataflow(func, ctx, analysis);
    if (!result.converged || analysis.contributions.empty())
        return ReturnOwnership::Unknown;
    OwnershipState aggregate = OwnershipState::Null;
    for (OwnershipState contribution : analysis.contributions) {
        if (contribution == OwnershipState::Unknown)
            return ReturnOwnership::Unknown;
        aggregate = mergeOwnership(aggregate, contribution);
        if (aggregate == OwnershipState::Unknown)
            return ReturnOwnership::Unknown;
    }
    if (aggregate == OwnershipState::Owned) return ReturnOwnership::Owned;
    if (aggregate == OwnershipState::Borrowed)
        return ReturnOwnership::Borrowed;
    return ReturnOwnership::Unknown;
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

// Null-passthrough resolver (F7A.1) — the pointer twin of
// resolveZeroReturn. POINTER DISCIPLINE replaces width discipline:
// every node must be pointer-typed and every cast a plain
// pointer-to-pointer conversion. dynamic_cast is Blocked (it can
// produce null FROM non-null), as is any integer hop (an intptr
// round-trip's null-correspondence is not this pass's business).
enum class PtrRes { NonNull, Passthrough, Blocked };

PtrRes resolveNullReturn(const Expr* e, const FunctionDecl* func,
                         const std::set<const VarDecl*>& unwritten,
                         const SummaryTable& previous, int* pt) {
    if (!e) return PtrRes::Blocked;
    e = e->IgnoreParens();
    if (!e->getType()->isPointerType()) return PtrRes::Blocked;

    if (const auto* cast = dyn_cast<CastExpr>(e)) {
        if (isa<CXXDynamicCastExpr>(e)) return PtrRes::Blocked;
        const Expr* sub = cast->getSubExpr();
        if (!sub->getType()->isPointerType()) {
            // Array decay / new / string are NonNull via the
            // structural evaluator below, not through the cast walk.
            return vstateOf(e, previous) == VState::NonBad
                       ? PtrRes::NonNull
                       : PtrRes::Blocked;
        }
        return resolveNullReturn(sub, func, unwritten, previous, pt);
    }
    if (const auto* ref = dyn_cast<DeclRefExpr>(e)) {
        const auto* parm = dyn_cast<ParmVarDecl>(ref->getDecl());
        if (!parm || !unwritten.count(parm))
            return vstateOf(e, previous) == VState::NonBad
                       ? PtrRes::NonNull
                       : PtrRes::Blocked;
        int idx = -1;
        for (unsigned i = 0; i < func->getNumParams(); ++i)
            if (func->getParamDecl(i) == parm) {
                idx = static_cast<int>(i);
                break;
            }
        if (idx < 0) return PtrRes::Blocked;
        if (*pt >= 0 && *pt != idx) return PtrRes::Blocked;  // mixed
        *pt = idx;
        return PtrRes::Passthrough;
    }
    if (const auto* call = dyn_cast<CallExpr>(e)) {
        const auto summary = lookupPrev(previous, call);
        if (!summary) return PtrRes::Blocked;
        if (summary->returnNullness == ReturnNullness::NeverNull)
            return PtrRes::NonNull;
        if (summary->nullFromParam >= 0 &&
            static_cast<unsigned>(summary->nullFromParam) <
                call->getNumArgs())
            return resolveNullReturn(call->getArg(summary->nullFromParam),
                                     func, unwritten, previous, pt);
        return PtrRes::Blocked;
    }
    return vstateOf(e, previous) == VState::NonBad ? PtrRes::NonNull
                                                   : PtrRes::Blocked;
}

ReturnNullness computeReturnNullness(const FunctionDecl* func,
                                     ASTContext& ctx,
                                     const SummaryTable& previous,
                                     int* nullFromParam) {
    *nullFromParam = -1;
    if (!func->getReturnType()->isPointerType())
        return ReturnNullness::Unknown;

    AggregateFlags flags = computeReturnFlow<vstateOf, applyNullCond>(
        func, ctx, previous,
        [](QualType t) { return t->isPointerType(); });
    if (flags.empty) return ReturnNullness::Unknown;
    if (flags.sawBad) return ReturnNullness::MaybeNull;
    if (flags.allNonBad) return ReturnNullness::NeverNull;

    // The passthrough pass (mirror of the zero domain's): every return
    // must be proven NonNull or hand back an unwritten pointer
    // parameter's entry value.
    std::set<const VarDecl*> unwritten = unwrittenParams(func);
    if (unwritten.empty()) return ReturnNullness::Unknown;
    ReturnCollector collector;
    collector.TraverseStmt(func->getBody());
    int pt = -1;
    bool sawPassthrough = false;
    for (const auto* ret : collector.returns) {
        switch (resolveNullReturn(ret, func, unwritten, previous, &pt)) {
            case PtrRes::NonNull: break;
            case PtrRes::Passthrough: sawPassthrough = true; break;
            case PtrRes::Blocked: return ReturnNullness::Unknown;
        }
    }
    if (sawPassthrough && pt >= 0) *nullFromParam = pt;
    return ReturnNullness::Unknown;
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
        const auto summary = lookupPrev(previous, call);
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
    if (flags.allBad) return ReturnZeroness::AlwaysZero;
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

bool isPointerCarrier(QualType type) {
    return type->isPointerType() ||
           (type->isLValueReferenceType() &&
            type.getNonReferenceType()->isPointerType());
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
        if (!isPointerCarrier(p->getType())) continue;
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
        if (isPointerCarrier(p->getType())) info.family[p].insert(p);

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
        const auto summary = lookupPrev(previous_, call);

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

// --- Independent pointee access and ownership-transfer relations ---

struct ParamRelationFlags {
    bool reads = false;
    bool writes = false;
    bool consumes = false;
    bool transfers = false;
    bool unknownAccess = false;
    bool unknownOwnership = false;
    FieldWriteSet fieldWrites;
};

enum class DirectAccess { None, Read, Write, ReadWrite };

DirectAccess classifyDirectAccess(const Expr* expr, ASTContext& ctx) {
    if (!expr) return DirectAccess::Read;
    DynTypedNode node = DynTypedNode::create(*expr);
    const Stmt* child = expr;
    for (unsigned depth = 0; depth < 12; ++depth) {
        auto parents = ctx.getParents(node);
        if (parents.empty()) break;
        const Stmt* parent = parents[0].get<Stmt>();
        if (!parent) break;

        if (const auto* unary = dyn_cast<UnaryOperator>(parent)) {
            if (unary->getOpcode() == UO_AddrOf) return DirectAccess::None;
            if (unary->isIncrementDecrementOp())
                return DirectAccess::ReadWrite;
        }
        if (isa<UnaryExprOrTypeTraitExpr>(parent))
            return DirectAccess::None;
        if (const auto* assign = dyn_cast<BinaryOperator>(parent)) {
            const auto* childExpr = dyn_cast<Expr>(child);
            if (assign->isAssignmentOp() && childExpr &&
                assign->getLHS()->IgnoreParenImpCasts() ==
                    childExpr->IgnoreParenImpCasts()) {
                return assign->getOpcode() == BO_Assign
                           ? DirectAccess::Write
                           : DirectAccess::ReadWrite;
            }
        }

        // Keep walking through lvalue wrappers until the expression's
        // actual use site is reached (`(*p).field = ...`, `p[i].x++`).
        if (isa<ParenExpr>(parent) || isa<CastExpr>(parent) ||
            isa<MemberExpr>(parent) || isa<ArraySubscriptExpr>(parent)) {
            child = parent;
            node = DynTypedNode::create(*parent);
            continue;
        }
        break;
    }
    return DirectAccess::Read;
}

unsigned callParamOffset(const CallExpr* call) {
    if (!isa_and_nonnull<CXXOperatorCallExpr>(call)) return 0;
    const auto* method =
        dyn_cast_or_null<CXXMethodDecl>(call->getDirectCallee());
    return method && !method->isStatic() ? 1u : 0u;
}

bool isReleaseCall(const CallExpr* call) {
    const llvm::StringRef name = calleeIdentifier(call->getDirectCallee());
    if (name == "free" || name == "fclose" || name == "closedir")
        return true;
    return !name.empty() &&
           codeskeptic::freeFunctionNames().count(name.str()) != 0;
}

bool pointsToRecord(QualType type) {
    if (type->isReferenceType()) {
        type = type.getNonReferenceType();
        return !type.isNull() && type->isRecordType();
    }
    if (!type->isPointerType()) return false;
    QualType pointee = type->getPointeeType();
    return !pointee.isNull() && pointee->isRecordType();
}

class ParamRelationVisitor
    : public RecursiveASTVisitor<ParamRelationVisitor> {
public:
    ParamRelationVisitor(const FunctionDecl* func, ASTContext& ctx,
                         const SummaryTable& previous,
                         const AliasInfo& aliases,
                         std::map<const ParmVarDecl*, ParamRelationFlags>& flags)
        : func_(func), ctx_(ctx), previous_(previous), aliases_(aliases),
          flags_(flags) {
        for (const auto* param : func->parameters())
            if (isPointerCarrier(param->getType()) ||
                pointsToRecord(param->getType())) {
                flags_[param].fieldWrites.known =
                    pointsToRecord(param->getType());
            }
    }

    bool VisitCXXDeleteExpr(CXXDeleteExpr* deletion) {
        if (const auto* param = resolve(deletion->getArgument()))
            flags_[param].consumes = true;
        return true;
    }

    bool VisitCallExpr(CallExpr* call) {
        const auto summary = lookupPrev(previous_, call);
        const unsigned offset = callParamOffset(call);
        for (unsigned argIndex = offset; argIndex < call->getNumArgs();
             ++argIndex) {
            const Expr* arg = call->getArg(argIndex);
            const auto* param = resolve(arg);
            if (!param) {
                for (auto& [candidate, relation] : flags_) {
                    if (!containsParamRef(arg, candidate))
                        continue;
                    relation.unknownAccess = true;
                    relation.unknownOwnership = true;
                    relation.fieldWrites.known = false;
                }
                continue;
            }
            ParamRelationFlags& relation = flags_[param];
            const unsigned paramIndex = argIndex - offset;
            if (isReleaseCall(call) && paramIndex == 0) {
                relation.consumes = true;
                continue;
            }
            if (!summary) {
                relation.unknownAccess = true;
                relation.unknownOwnership = true;
                relation.fieldWrites.known = false;
                continue;
            }
            switch (summary->paramAccess(paramIndex)) {
                case ParamAccess::Reads: relation.reads = true; break;
                case ParamAccess::Writes: relation.writes = true; break;
                case ParamAccess::ReadsWrites:
                    relation.reads = true;
                    relation.writes = true;
                    break;
                case ParamAccess::None: break;
                case ParamAccess::Unknown: relation.unknownAccess = true; break;
            }
            composeFieldWrites(relation, &*summary, paramIndex);
            switch (summary->paramOwnership(paramIndex)) {
                case ParamOwnership::Consumed:
                    relation.consumes = true;
                    break;
                case ParamOwnership::Transferred:
                    relation.transfers = true;
                    break;
                case ParamOwnership::Borrowed:
                    break;
                case ParamOwnership::Unknown:
                    relation.unknownOwnership = true;
                    break;
            }
        }
        return true;
    }

    bool VisitCXXOperatorCallExpr(CXXOperatorCallExpr* call) {
        if (call->getNumArgs() == 0) return true;
        const OverloadedOperatorKind op = call->getOperator();
        if (op != OO_Equal && op != OO_PlusEqual && op != OO_MinusEqual &&
            op != OO_StarEqual && op != OO_SlashEqual &&
            op != OO_PercentEqual)
            return true;
        const Expr* receiver = call->getArg(0)->IgnoreParenImpCasts();
        const DirectAccess access =
            op == OO_Equal ? DirectAccess::Write
                           : DirectAccess::ReadWrite;
        if (const auto* dereference =
                dyn_cast<UnaryOperator>(receiver)) {
            if (dereference->getOpcode() == UO_Deref)
                if (const auto* param = resolve(dereference->getSubExpr()))
                    recordAccess(param, access);
            return true;
        }
        if (const auto* member = dyn_cast<MemberExpr>(receiver)) {
            if (const auto field = resolveField(member))
                recordAccess(field->first, access, field->second);
            return true;
        }
        if (const auto* param = resolve(receiver))
            recordAccess(param, access);
        return true;
    }

    bool VisitUnaryOperator(UnaryOperator* unary) {
        if (unary->getOpcode() == UO_Deref) {
            if (isMemberBase(unary)) return true;
            if (const auto* param = resolve(unary->getSubExpr()))
                recordAccess(param, classifyDirectAccess(unary, ctx_));
        } else if (unary->getOpcode() == UO_AddrOf) {
            const auto* member = dyn_cast<MemberExpr>(
                unary->getSubExpr()->IgnoreParenImpCasts());
            if (member) {
                if (const auto field = resolveField(member))
                    recordAccess(field->first, DirectAccess::Write,
                                 field->second);
            }
            const ValueDecl* value = asVarOrParam(unary->getSubExpr());
            if (const auto* param = dyn_cast_or_null<ParmVarDecl>(value))
                if (flags_.count(param)) {
                    flags_[param].unknownOwnership = true;
                    if (param->getType()->isReferenceType() &&
                        pointsToRecord(param->getType()))
                        recordAccess(param, DirectAccess::Write);
                }
        }
        return true;
    }

    bool VisitMemberExpr(MemberExpr* member) {
        if (const auto field = resolveField(member))
            recordAccess(field->first, classifyDirectAccess(member, ctx_),
                         field->second);
        return true;
    }

    bool VisitCXXMemberCallExpr(CXXMemberCallExpr* call) {
        const CXXMethodDecl* method = call->getMethodDecl();
        if (!method) return true;
        std::vector<const FieldDecl*> mutableFields;
        if (method->isConst()) {
            for (const FieldDecl* field : method->getParent()->fields()) {
                if (field->isMutable() && field->getIdentifier())
                    mutableFields.push_back(field);
            }
            if (mutableFields.empty()) return true;
        }
        const Expr* object = call->getImplicitObjectArgument();
        if (!object) return true;
        object = object->IgnoreParenImpCasts();
        if (const auto* member = dyn_cast<MemberExpr>(object)) {
            if (const auto field = resolveField(member))
                recordAccess(field->first, DirectAccess::Write,
                             field->second);
            return true;
        }
        if (const auto* dereference = dyn_cast<UnaryOperator>(object)) {
            if (dereference->getOpcode() == UO_Deref)
                if (const auto* param = resolve(dereference->getSubExpr())) {
                    if (method->isConst()) {
                        for (const auto& field : mutableFields)
                            recordAccess(param, DirectAccess::Write, field);
                    } else {
                        recordAccess(param, DirectAccess::Write);
                    }
                }
            return true;
        }
        if (const auto* param = resolve(object)) {
            if (method->isConst()) {
                for (const auto& field : mutableFields)
                    recordAccess(param, DirectAccess::Write, field);
            } else {
                recordAccess(param, DirectAccess::Write);
            }
        }
        return true;
    }

    bool VisitArraySubscriptExpr(ArraySubscriptExpr* subscript) {
        if (const auto* param = resolve(subscript->getBase()))
            recordAccess(param, classifyDirectAccess(subscript, ctx_));
        return true;
    }

    bool VisitBinaryOperator(BinaryOperator* assign) {
        if (assign->getOpcode() != BO_Assign) return true;
        const Expr* lhsExpr = assign->getLHS()->IgnoreParenImpCasts();
        if (const auto* dereference =
                dyn_cast<UnaryOperator>(lhsExpr)) {
            if (dereference->getOpcode() == UO_Deref)
                if (const auto* param =
                        resolve(dereference->getSubExpr()))
                    recordAccess(param, DirectAccess::Write);
        }
        const ValueDecl* lhsValue = asVarOrParam(assign->getLHS());
        if (const auto* lhsParam =
                dyn_cast_or_null<ParmVarDecl>(lhsValue)) {
            if (lhsParam->getType()->isLValueReferenceType() &&
                lhsParam->getType().getNonReferenceType()->isPointerType() &&
                flags_.count(lhsParam)) {
                flags_[lhsParam].writes = true;
                flags_[lhsParam].unknownOwnership = true;
            }
        }
        const auto* param = resolve(assign->getRHS());
        if (!param) return true;
        const ValueDecl* lhs = lhsValue;
        const bool localCopy =
            lhs && (isa<ParmVarDecl>(lhs) || isPlainLocal(lhs));
        if (!localCopy) flags_[param].transfers = true;
        return true;
    }

    bool VisitVarDecl(VarDecl* var) {
        if (isa<ParmVarDecl>(var) || !var->hasInit()) return true;
        if (var->getType()->isReferenceType() &&
            !var->getType().getNonReferenceType().isConstQualified()) {
            const Expr* init = var->getInit()->IgnoreParenImpCasts();
            if (const auto* member = dyn_cast<MemberExpr>(init)) {
                if (const auto field = resolveField(member))
                    recordAccess(field->first, DirectAccess::Write,
                                 field->second);
            } else if (const auto* dereference =
                           dyn_cast<UnaryOperator>(init)) {
                if (dereference->getOpcode() == UO_Deref)
                    if (const auto* param =
                            resolve(dereference->getSubExpr()))
                        recordAccess(param, DirectAccess::Write);
            } else if (const auto* param = resolve(init)) {
                recordAccess(param, DirectAccess::Write);
            }
        }
        if (var->hasLocalStorage()) return true;
        if (const auto* param = resolve(var->getInit()))
            flags_[param].transfers = true;
        return true;
    }

    bool VisitReturnStmt(ReturnStmt* ret) {
        QualType type = func_->getReturnType();
        if (!type->isReferenceType() ||
            type.getNonReferenceType().isConstQualified())
            return true;
        const Expr* value = ret->getRetValue();
        const auto* member = value
            ? dyn_cast<MemberExpr>(value->IgnoreParenImpCasts()) : nullptr;
        if (member) {
            if (const auto field = resolveField(member))
                recordAccess(field->first, DirectAccess::Write,
                             field->second);
            return true;
        }
        value = value ? value->IgnoreParenImpCasts() : nullptr;
        if (const auto* dereference =
                dyn_cast_or_null<UnaryOperator>(value)) {
            if (dereference->getOpcode() == UO_Deref)
                if (const auto* param = resolve(dereference->getSubExpr()))
                    recordAccess(param, DirectAccess::Write);
        } else if (const auto* param = resolve(value)) {
            recordAccess(param, DirectAccess::Write);
        }
        return true;
    }

    bool TraverseLambdaExpr(LambdaExpr* lambda) {
        for (auto& [param, relation] : flags_) {
            if (!containsParamRef(lambda, param)) continue;
            relation.unknownAccess = true;
            relation.unknownOwnership = true;
            relation.fieldWrites.known = false;
        }
        return true;
    }

private:
    bool containsParamRef(const Expr* root,
                          const ParmVarDecl* param) const {
        const auto it = aliases_.family.find(param);
        if (it != aliases_.family.end())
            return containsAnyRef(root, it->second);
        const std::set<const ValueDecl*> direct{param};
        return containsAnyRef(root, direct);
    }

    bool isMemberBase(const Expr* expr) const {
        const Expr* child = expr;
        DynTypedNode node = DynTypedNode::create(*expr);
        for (unsigned depth = 0; depth < 8; ++depth) {
            const auto parents = ctx_.getParents(node);
            if (parents.empty()) return false;
            const Stmt* parent = parents[0].get<Stmt>();
            if (!parent) return false;
            if (isa<ParenExpr>(parent) || isa<CastExpr>(parent)) {
                child = cast<Expr>(parent);
                node = DynTypedNode::create(*parent);
                continue;
            }
            const auto* member = dyn_cast<MemberExpr>(parent);
            return member &&
                   member->getBase()->IgnoreParenImpCasts() ==
                       child->IgnoreParenImpCasts();
        }
        return false;
    }

    const ParmVarDecl* resolve(const Expr* expr) const {
        const ValueDecl* decl = asVarOrParam(expr);
        if (!decl) return nullptr;
        if (const auto* param = dyn_cast<ParmVarDecl>(decl))
            return flags_.count(param) ? param : nullptr;
        auto it = aliases_.cleanAlias.find(cast<VarDecl>(decl));
        return it == aliases_.cleanAlias.end() ? nullptr : it->second;
    }

    std::optional<std::pair<const ParmVarDecl*, const FieldDecl*>>
    resolveField(const MemberExpr* member) const {
        const FieldDecl* topField = nullptr;
        const Expr* cursor = member;
        while (const auto* current = dyn_cast<MemberExpr>(
                   cursor->IgnoreParenImpCasts())) {
            const auto* field = dyn_cast<FieldDecl>(current->getMemberDecl());
            if (!field || field->getName().empty()) return std::nullopt;
            topField = field;
            cursor = current->getBase();
        }
        cursor = cursor->IgnoreParenImpCasts();
        if (const auto* dereference = dyn_cast<UnaryOperator>(cursor)) {
            if (dereference->getOpcode() != UO_Deref) return std::nullopt;
            cursor = dereference->getSubExpr();
        }
        const ParmVarDecl* param = resolve(cursor);
        if (!param || !topField) return std::nullopt;
        return std::make_pair(param, topField);
    }

    void composeFieldWrites(ParamRelationFlags& relation,
                            const FunctionSummary* summary,
                            unsigned paramIndex) {
        if (!relation.fieldWrites.known) return;
        if (const FieldWriteSet* exact =
                summary->exactParamFieldWrites(paramIndex)) {
            relation.fieldWrites.fields.insert(exact->fields.begin(),
                                                exact->fields.end());
            return;
        }
        const ParamAccess access = summary->paramAccess(paramIndex);
        if (access == ParamAccess::Writes ||
            access == ParamAccess::ReadsWrites ||
            access == ParamAccess::Unknown)
            relation.fieldWrites.known = false;
    }

    void recordAccess(const ParmVarDecl* param, DirectAccess access,
                      const FieldDecl* field = nullptr) {
        ParamRelationFlags& relation = flags_[param];
        if (access == DirectAccess::Read || access == DirectAccess::ReadWrite)
            relation.reads = true;
        if (access == DirectAccess::Write || access == DirectAccess::ReadWrite) {
            relation.writes = true;
            if (!relation.fieldWrites.known) return;
            if (!field || field->getName().empty()) {
                relation.fieldWrites.known = false;
                return;
            }
            relation.fieldWrites.fields.insert(field->getNameAsString());
        }
    }

    const FunctionDecl* func_;
    ASTContext& ctx_;
    const SummaryTable& previous_;
    const AliasInfo& aliases_;
    std::map<const ParmVarDecl*, ParamRelationFlags>& flags_;
};

struct ParamRelations {
    std::vector<ParamAccess> accesses;
    std::vector<ParamOwnership> ownerships;
    std::vector<FieldWriteSet> fieldWrites;
};

ParamRelations computeParamRelations(const FunctionDecl* func,
                                     ASTContext& ctx,
                                     const SummaryTable& previous) {
    AliasCollector collector;
    collector.TraverseStmt(func->getBody());
    AliasInfo aliases = computeAliases(func, collector);
    std::map<const ParmVarDecl*, ParamRelationFlags> flags;
    ParamRelationVisitor visitor(func, ctx, previous, aliases, flags);
    visitor.TraverseStmt(func->getBody());

    for (const auto* param : aliases.taintedReach) {
        auto it = flags.find(param);
        if (it == flags.end()) continue;
        it->second.unknownAccess = true;
        it->second.unknownOwnership = true;
        it->second.fieldWrites.known = false;
    }

    ParamRelations out;
    out.accesses.reserve(func->getNumParams());
    out.ownerships.reserve(func->getNumParams());
    out.fieldWrites.reserve(func->getNumParams());
    for (const auto* param : func->parameters()) {
        if (!isPointerCarrier(param->getType()) &&
            !pointsToRecord(param->getType())) {
            out.accesses.push_back(ParamAccess::Unknown);
            out.ownerships.push_back(ParamOwnership::Unknown);
            out.fieldWrites.push_back(FieldWriteSet{});
            continue;
        }
        const ParamRelationFlags& relation = flags[param];
        if (relation.unknownAccess)
            out.accesses.push_back(ParamAccess::Unknown);
        else if (relation.reads && relation.writes)
            out.accesses.push_back(ParamAccess::ReadsWrites);
        else if (relation.reads)
            out.accesses.push_back(ParamAccess::Reads);
        else if (relation.writes)
            out.accesses.push_back(ParamAccess::Writes);
        else
            out.accesses.push_back(ParamAccess::None);

        if (relation.unknownOwnership ||
            (relation.consumes && relation.transfers))
            out.ownerships.push_back(ParamOwnership::Unknown);
        else if (relation.transfers)
            out.ownerships.push_back(ParamOwnership::Transferred);
        else if (relation.consumes)
            out.ownerships.push_back(ParamOwnership::Consumed);
        else
            out.ownerships.push_back(ParamOwnership::Borrowed);
        out.fieldWrites.push_back(relation.fieldWrites);
    }
    return out;
}

// --- POSIX integer-resource ownership summaries ---
//
// Phase 5 reuses the persisted v10 ownership axes for file descriptors.
// This is deliberately narrower than native memory ownership: only exact
// global POSIX primitives, visible wrappers, and reviewed loaded models can
// create a strong relation.

bool isFdIntegerType(QualType type) {
    return !type.isNull() && type->isIntegerType() &&
           !type->isBooleanType();
}

llvm::StringRef globalFdCalleeName(const FunctionDecl* callee) {
    if (!callee || isa<CXXMethodDecl>(callee)) return {};
    const IdentifierInfo* id = callee->getIdentifier();
    if (!id) return {};
    if (callee->getQualifiedNameAsString() != id->getName().str()) return {};
    return id->getName();
}

bool isFdAcquireName(llvm::StringRef name) {
    return name == "open" || name == "openat" || name == "socket" ||
           name == "dup" || name == "mkstemp";
}

bool isKnownFdPrimitive(llvm::StringRef name) {
    return isFdAcquireName(name) || name == "close" || name == "shutdown";
}

bool isMinusOneFdFailure(const Expr* expr) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    const auto* unary = dyn_cast<UnaryOperator>(expr);
    if (!unary || unary->getOpcode() != UO_Minus) return false;
    const auto* literal = dyn_cast<IntegerLiteral>(
        unary->getSubExpr()->IgnoreParenImpCasts());
    return literal && literal->getValue() == 1;
}

bool isFdAcquisitionExpr(const Expr* expr,
                         const SummaryTable& previous) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    const auto* call = dyn_cast<CallExpr>(expr);
    if (!call || !isFdIntegerType(call->getType())) return false;
    if (isFdAcquireName(globalFdCalleeName(call->getDirectCallee())))
        return true;
    const auto summary = lookupPrev(previous, call);
    return summary &&
           summary->returnOwnership == ReturnOwnership::Owned;
}

enum class FdReturnState { Unknown, Owned, Borrowed, Failure };

FdReturnState mergeFdReturnState(FdReturnState lhs,
                                 FdReturnState rhs) {
    if (lhs == rhs) return lhs;
    if (lhs == FdReturnState::Failure) return rhs;
    if (rhs == FdReturnState::Failure) return lhs;
    return FdReturnState::Unknown;
}

class FdReturnOwnershipAnalysis {
public:
    using State = std::map<const VarDecl*, FdReturnState>;

    FdReturnOwnershipAnalysis(std::vector<const VarDecl*> trackedVars,
                              const SummaryTable& previous)
        : previous_(previous) {
        for (const VarDecl* var : trackedVars)
            initial_[var] = isa<ParmVarDecl>(var)
                                ? FdReturnState::Borrowed
                                : FdReturnState::Unknown;
    }

    State initialState() const { return initial_; }

    unsigned latticeHeight() const {
        return static_cast<unsigned>(initial_.size()) * 4 + 4;
    }

    State merge(const State& lhs, const State& rhs) const {
        State out = lhs;
        for (const auto& [var, value] : rhs) {
            auto it = out.find(var);
            if (it == out.end())
                out[var] = value;
            else
                it->second = mergeFdReturnState(it->second, value);
        }
        return out;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext&) const {
        State out = in;
        if (const auto* declaration = dyn_cast<DeclStmt>(stmt)) {
            for (const Decl* decl : declaration->decls()) {
                const auto* var = dyn_cast<VarDecl>(decl);
                auto it = var ? out.find(var) : out.end();
                if (it == out.end()) continue;
                it->second = var->hasInit()
                                 ? ownershipOf(var->getInit(), in)
                                 : FdReturnState::Unknown;
            }
        } else if (const auto* assignment =
                       dyn_cast<BinaryOperator>(stmt)) {
            if (assignment->isAssignmentOp()) {
                const auto* var = dyn_cast_or_null<VarDecl>(
                    asVarOrParam(assignment->getLHS()));
                auto it = var ? out.find(var) : out.end();
                if (it != out.end())
                    it->second = assignment->getOpcode() == BO_Assign
                                     ? ownershipOf(assignment->getRHS(), in)
                                     : FdReturnState::Unknown;
            }
        } else if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
            if (unary->isIncrementDecrementOp() ||
                unary->getOpcode() == UO_AddrOf)
                kill(asVarOrParam(unary->getSubExpr()), out);
        } else if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            applyCallEffects(call, out);
        }
        return out;
    }

    void refineOnEdge(const Stmt*, bool, State&, ASTContext&) const {}

    void onStatement(const Stmt* stmt, const State& before,
                     const State&, ASTContext&) {
        const auto* ret = dyn_cast<ReturnStmt>(stmt);
        if (ret && ret->getRetValue())
            contributions.push_back(
                ownershipOf(ret->getRetValue(), before));
    }

    std::vector<FdReturnState> contributions;

private:
    FdReturnState ownershipOf(const Expr* expr,
                              const State& state) const {
        if (!expr) return FdReturnState::Unknown;
        if (isFdAcquisitionExpr(expr, previous_))
            return FdReturnState::Owned;
        if (isMinusOneFdFailure(expr)) return FdReturnState::Failure;
        expr = expr->IgnoreParenImpCasts();
        if (const auto* var = dyn_cast_or_null<VarDecl>(
                asVarOrParam(expr))) {
            auto it = state.find(var);
            return it == state.end() ? FdReturnState::Borrowed
                                     : it->second;
        }
        if (const auto* conditional = dyn_cast<ConditionalOperator>(expr))
            return mergeFdReturnState(
                ownershipOf(conditional->getTrueExpr(), state),
                ownershipOf(conditional->getFalseExpr(), state));
        const auto* call = dyn_cast<CallExpr>(expr);
        if (!call || !isFdIntegerType(call->getType()))
            return FdReturnState::Unknown;
        const auto summary = lookupPrev(previous_, call);
        if (!summary) return FdReturnState::Unknown;
        if (summary->returnOwnership == ReturnOwnership::Owned)
            return FdReturnState::Owned;
        if (summary->returnOwnership == ReturnOwnership::Borrowed)
            return FdReturnState::Borrowed;
        return FdReturnState::Unknown;
    }

    void applyCallEffects(const CallExpr* call, State& state) const {
        const llvm::StringRef direct =
            globalFdCalleeName(call->getDirectCallee());
        const unsigned offset = callParamOffset(call);
        const auto summary = lookupPrev(previous_, call);
        for (unsigned argIndex = offset;
             argIndex < call->getNumArgs(); ++argIndex) {
            const unsigned paramIndex = argIndex - offset;
            if (isKnownFdPrimitive(direct)) {
                if (direct == "close" && paramIndex == 0)
                    kill(asVarOrParam(call->getArg(argIndex)), state);
                continue;
            }
            if (!summary ||
                summary->paramOwnership(paramIndex) !=
                    ParamOwnership::Borrowed)
                kill(asVarOrParam(call->getArg(argIndex)), state);
        }
    }

    static void kill(const ValueDecl* value, State& state) {
        const auto* var = dyn_cast_or_null<VarDecl>(value);
        auto it = var ? state.find(var) : state.end();
        if (it != state.end()) it->second = FdReturnState::Unknown;
    }

    const SummaryTable& previous_;
    State initial_;
};

ReturnOwnership computeFdReturnOwnership(const FunctionDecl* func,
                                         ASTContext& ctx,
                                         const SummaryTable& previous) {
    if (!isFdIntegerType(func->getReturnType()))
        return ReturnOwnership::Unknown;
    FdReturnOwnershipAnalysis analysis(
        collectTypedVars(func, [](QualType type) {
            return isFdIntegerType(type);
        }),
        previous);
    auto result = codeskeptic::runDataflow(func, ctx, analysis);
    if (!result.converged || analysis.contributions.empty())
        return ReturnOwnership::Unknown;

    FdReturnState aggregate = FdReturnState::Failure;
    for (FdReturnState contribution : analysis.contributions) {
        if (contribution == FdReturnState::Unknown)
            return ReturnOwnership::Unknown;
        aggregate = mergeFdReturnState(aggregate, contribution);
        if (aggregate == FdReturnState::Unknown)
            return ReturnOwnership::Unknown;
    }
    // Only acquisition ownership is a strong descriptor fact. Returning an
    // ordinary integer/parameter is not enough to assert a resource borrow.
    if (aggregate == FdReturnState::Owned) return ReturnOwnership::Owned;
    return ReturnOwnership::Unknown;
}

struct FdParamBinding {
    std::set<unsigned> sources;
    bool opaque = false;

    bool operator==(const FdParamBinding& other) const {
        return sources == other.sources && opaque == other.opaque;
    }
    bool operator!=(const FdParamBinding& other) const {
        return !(*this == other);
    }
};

enum class FdParamEffect { None, Consumed, Transferred, Unknown };

struct FdParamState {
    std::map<const VarDecl*, FdParamBinding> bindings;
    std::vector<FdParamEffect> effects;

    bool operator==(const FdParamState& other) const {
        return bindings == other.bindings && effects == other.effects;
    }
    bool operator!=(const FdParamState& other) const {
        return !(*this == other);
    }
};

FdParamEffect mergeFdParamEffect(FdParamEffect lhs,
                                 FdParamEffect rhs) {
    return lhs == rhs ? lhs : FdParamEffect::Unknown;
}

FdParamEffect sequenceFdParamEffect(FdParamEffect current,
                                    FdParamEffect next) {
    if (next == FdParamEffect::None) return current;
    if (current == FdParamEffect::None || current == next) return next;
    return FdParamEffect::Unknown;
}

FdParamBinding fdParamBindingFor(const Expr* expr,
                                 const FdParamState& state) {
    const auto* var = dyn_cast_or_null<VarDecl>(asVarOrParam(expr));
    if (!var) return FdParamBinding{{}, true};
    auto it = state.bindings.find(var);
    return it == state.bindings.end()
               ? FdParamBinding{{}, true} : it->second;
}

void applyFdParamEffect(const FdParamBinding& binding,
                        FdParamEffect effect,
                        FdParamState& state) {
    if (binding.sources.empty()) return;
    if (binding.opaque || binding.sources.size() != 1) {
        for (unsigned source : binding.sources)
            state.effects[source] = FdParamEffect::Unknown;
        return;
    }
    const unsigned source = *binding.sources.begin();
    state.effects[source] = sequenceFdParamEffect(
        state.effects[source], effect);
}

class FdParamOwnershipAnalysis {
public:
    using State = FdParamState;

    FdParamOwnershipAnalysis(const FunctionDecl* func,
                             const SummaryTable& previous)
        : previous_(previous) {
        initial_.effects.assign(func->getNumParams(), FdParamEffect::None);
        for (unsigned i = 0; i < func->getNumParams(); ++i) {
            const ParmVarDecl* param = func->getParamDecl(i);
            if (isFdIntegerType(param->getType()))
                initial_.bindings[param] = FdParamBinding{{i}, false};
        }
    }

    State initialState() const { return initial_; }

    unsigned latticeHeight() const {
        return static_cast<unsigned>(initial_.effects.size()) * 8 + 16;
    }

    State merge(const State& lhs, const State& rhs) const {
        State out;
        out.effects.resize(lhs.effects.size(), FdParamEffect::Unknown);
        for (size_t i = 0; i < out.effects.size(); ++i)
            out.effects[i] = mergeFdParamEffect(
                lhs.effects[i], rhs.effects[i]);

        std::set<const VarDecl*> vars;
        for (const auto& [var, binding] : lhs.bindings) {
            (void)binding;
            vars.insert(var);
        }
        for (const auto& [var, binding] : rhs.bindings) {
            (void)binding;
            vars.insert(var);
        }
        for (const VarDecl* var : vars) {
            auto left = lhs.bindings.find(var);
            auto right = rhs.bindings.find(var);
            if (left == lhs.bindings.end()) {
                FdParamBinding merged = right->second;
                merged.opaque = true;
                out.bindings[var] = std::move(merged);
            } else if (right == rhs.bindings.end()) {
                FdParamBinding merged = left->second;
                merged.opaque = true;
                out.bindings[var] = std::move(merged);
            } else {
                FdParamBinding merged = left->second;
                merged.sources.insert(right->second.sources.begin(),
                                      right->second.sources.end());
                merged.opaque = left->second.opaque || right->second.opaque;
                out.bindings[var] = std::move(merged);
            }
        }
        return out;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext&) const {
        State out = in;
        if (const auto* declaration = dyn_cast<DeclStmt>(stmt)) {
            for (const Decl* decl : declaration->decls()) {
                const auto* var = dyn_cast<VarDecl>(decl);
                if (!var || !isFdIntegerType(var->getType()) ||
                    !var->hasInit())
                    continue;
                FdParamBinding source =
                    fdParamBindingFor(var->getInit(), out);
                if (var->hasLocalStorage())
                    out.bindings[var] = std::move(source);
                else
                    applyFdParamEffect(source,
                                       FdParamEffect::Transferred, out);
            }
            return out;
        }

        if (const auto* assignment = dyn_cast<BinaryOperator>(stmt)) {
            if (assignment->getOpcode() != BO_Assign) return out;
            FdParamBinding source =
                fdParamBindingFor(assignment->getRHS(), out);
            const auto* target = dyn_cast_or_null<VarDecl>(
                asVarOrParam(assignment->getLHS()));
            if (target && (isa<ParmVarDecl>(target) ||
                           target->hasLocalStorage()))
                out.bindings[target] = std::move(source);
            else
                applyFdParamEffect(source,
                                   FdParamEffect::Transferred, out);
            return out;
        }

        if (const auto* call = dyn_cast<CallExpr>(stmt))
            applyCall(call, out);
        return out;
    }

    void refineOnEdge(const Stmt*, bool, State&, ASTContext&) const {}

private:
    void applyCall(const CallExpr* call, State& state) const {
        const llvm::StringRef direct =
            globalFdCalleeName(call->getDirectCallee());
        const unsigned offset = callParamOffset(call);
        if (isKnownFdPrimitive(direct)) {
            if (direct == "close" && call->getNumArgs() > offset)
                applyFdParamEffect(
                    fdParamBindingFor(call->getArg(offset), state),
                    FdParamEffect::Consumed, state);
            return;
        }

        const auto summary = lookupPrev(previous_, call);
        for (unsigned argIndex = offset;
             argIndex < call->getNumArgs(); ++argIndex) {
            const unsigned paramIndex = argIndex - offset;
            FdParamEffect effect = FdParamEffect::Unknown;
            if (summary) {
                switch (summary->paramOwnership(paramIndex)) {
                    case ParamOwnership::Borrowed:
                        effect = FdParamEffect::None;
                        break;
                    case ParamOwnership::Consumed:
                        effect = FdParamEffect::Consumed;
                        break;
                    case ParamOwnership::Transferred:
                        effect = FdParamEffect::Transferred;
                        break;
                    case ParamOwnership::Unknown:
                        break;
                }
            }
            applyFdParamEffect(
                fdParamBindingFor(call->getArg(argIndex), state),
                effect, state);
        }
    }

    const SummaryTable& previous_;
    State initial_;
};

std::vector<ParamOwnership> computeFdParamOwnerships(
        const FunctionDecl* func, ASTContext& ctx,
        const SummaryTable& previous) {
    std::vector<ParamOwnership> out(
        func->getNumParams(), ParamOwnership::Unknown);
    bool hasFdParam = false;
    for (const ParmVarDecl* param : func->parameters())
        hasFdParam = hasFdParam || isFdIntegerType(param->getType());
    if (!hasFdParam) return out;
    FdParamOwnershipAnalysis analysis(func, previous);
    auto result = codeskeptic::runDataflow(func, ctx, analysis);
    if (!result.converged) return out;
    auto exit = result.blockExitStates.find(result.exitBlockID);
    if (exit == result.blockExitStates.end()) return out;

    for (unsigned i = 0; i < func->getNumParams(); ++i) {
        if (!isFdIntegerType(func->getParamDecl(i)->getType())) continue;
        switch (exit->second.effects[i]) {
            case FdParamEffect::Consumed:
                out[i] = ParamOwnership::Consumed;
                break;
            case FdParamEffect::Transferred:
                out[i] = ParamOwnership::Transferred;
                break;
            case FdParamEffect::None:
            case FdParamEffect::Unknown:
                break;
        }
    }
    return out;
}
// --- Parameter preconditions and postconditions (interprocedural v2) ---

std::vector<ParamPrecondition> computeParamPreconditions(
        const FunctionDecl* func, ASTContext& ctx) {
    std::vector<ParamPrecondition> out(
        func->getNumParams(), ParamPrecondition::None);
    for (const auto& guard : codeskeptic::inferGuardRequires(func, ctx)) {
        if (guard.paramIndex >= out.size()) continue;
        const ParamPrecondition inferred =
            guard.consequence == codeskeptic::GuardConsequence::Crash
                ? ParamPrecondition::NonNullCrash
                : ParamPrecondition::NonNullRejected;
        // Several equivalent leading guards can mention one parameter.
        // Preserve the more severe observable consequence independent of
        // AST visitation order.
        if (out[guard.paramIndex] == ParamPrecondition::None ||
            inferred == ParamPrecondition::NonNullCrash)
            out[guard.paramIndex] = inferred;
    }
    return out;
}

bool isRefToPointer(const ParmVarDecl* param) {
    if (!param) return false;
    QualType type = param->getType();
    return type->isLValueReferenceType() &&
           type.getNonReferenceType()->isPointerType();
}

bool isPointerToPointer(const ParmVarDecl* param) {
    if (!param) return false;
    QualType type = param->getType();
    return type->isPointerType() && type->getPointeeType()->isPointerType();
}

struct ParamPostState {
    std::vector<ParamPostcondition> values;
    // For T** parameters, a direct store through `*p` still targets the
    // caller only while p denotes its entry value. T*& references cannot
    // be rebound, so their bit stays true.
    std::vector<bool> entryTargets;

    bool operator==(const ParamPostState& other) const {
        return values == other.values && entryTargets == other.entryTargets;
    }
    bool operator!=(const ParamPostState& other) const {
        return !(*this == other);
    }
};

class ParamPostAnalysis {
public:
    using State = ParamPostState;

    ParamPostAnalysis(const FunctionDecl* func,
                      const SummaryTable& previous)
        : previous_(previous) {
        init_.values.assign(func->getNumParams(),
                            ParamPostcondition::Unknown);
        init_.entryTargets.assign(func->getNumParams(), false);
        for (unsigned i = 0; i < func->getNumParams(); ++i) {
            const ParmVarDecl* param = func->getParamDecl(i);
            if (isRefToPointer(param) || isPointerToPointer(param)) {
                outputIndexes_[param] = i;
                init_.entryTargets[i] = true;
            }
        }
    }

    State initialState() const { return init_; }
    unsigned latticeHeight() const {
        return static_cast<unsigned>(init_.values.size()) * 3 + 2;
    }
    void widen(State& state) const {
        std::fill(state.values.begin(), state.values.end(),
                  ParamPostcondition::Unknown);
        std::fill(state.entryTargets.begin(), state.entryTargets.end(), false);
    }
    State merge(const State& a, const State& b) const {
        State out = a;
        for (size_t i = 0; i < out.values.size(); ++i) {
            if (out.values[i] != b.values[i])
                out.values[i] = ParamPostcondition::Unknown;
            out.entryTargets[i] =
                out.entryTargets[i] && b.entryTargets[i];
        }
        return out;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& /*ctx*/) const {
        State out = in;
        if (const auto* bin = dyn_cast<BinaryOperator>(stmt)) {
            if (bin->getOpcode() == BO_Assign) {
                if (auto index = outputTarget(bin->getLHS(), in)) {
                    out.values[*index] = valueOf(bin->getRHS(), in);
                    return out;
                }
                // Rebinding a T** parameter changes what subsequent
                // `*p = ...` stores denote; no caller guarantee may be
                // learned after that point.
                if (const auto* param = dyn_cast_or_null<ParmVarDecl>(
                        asVarOrParam(bin->getLHS()))) {
                    auto found = outputIndexes_.find(param);
                    if (found != outputIndexes_.end() &&
                        isPointerToPointer(param))
                        out.entryTargets[found->second] = false;
                }
            } else if (bin->isCompoundAssignmentOp()) {
                if (const auto* param = dyn_cast_or_null<ParmVarDecl>(
                        asVarOrParam(bin->getLHS()))) {
                    auto found = outputIndexes_.find(param);
                    if (found != outputIndexes_.end()) {
                        out.values[found->second] =
                            ParamPostcondition::Unknown;
                        if (isPointerToPointer(param))
                            out.entryTargets[found->second] = false;
                    }
                }
            }
            return out;
        }
        if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
            if (unary->isIncrementDecrementOp()) {
                if (const auto* param = dyn_cast_or_null<ParmVarDecl>(
                        asVarOrParam(unary->getSubExpr()))) {
                    auto found = outputIndexes_.find(param);
                    if (found != outputIndexes_.end()) {
                        out.values[found->second] =
                            ParamPostcondition::Unknown;
                        if (isPointerToPointer(param))
                            out.entryTargets[found->second] = false;
                    }
                }
            }
            if (unary->getOpcode() == UO_AddrOf) {
                if (const auto* param = dyn_cast_or_null<ParmVarDecl>(
                        asVarOrParam(unary->getSubExpr()))) {
                    auto found = outputIndexes_.find(param);
                    if (found != outputIndexes_.end()) {
                        out.values[found->second] =
                            ParamPostcondition::Unknown;
                        if (isPointerToPointer(param))
                            out.entryTargets[found->second] = false;
                    }
                }
            }
            return out;
        }
        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            const auto summary = lookupPrev(previous_, call);
            unsigned argOffset = 0;
            if (isa<CXXOperatorCallExpr>(call)) {
                const auto* method = dyn_cast_or_null<CXXMethodDecl>(
                    call->getDirectCallee());
                if (method && !method->isStatic()) argOffset = 1;
            }
            for (unsigned argIndex = argOffset;
                 argIndex < call->getNumArgs(); ++argIndex) {
                auto target = forwardedOutput(call->getArg(argIndex), in);
                if (!target) continue;
                const unsigned paramIndex = argIndex - argOffset;
                out.values[*target] = summary
                    ? summary->paramPostcondition(paramIndex)
                    : ParamPostcondition::Unknown;
            }
        }
        return out;
    }

private:
    std::optional<unsigned> outputTarget(const Expr* expr,
                                         const State& state) const {
        if (!expr) return std::nullopt;
        expr = expr->IgnoreParenImpCasts();
        if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) {
            const auto* param = dyn_cast<ParmVarDecl>(ref->getDecl());
            auto found = outputIndexes_.find(param);
            if (found != outputIndexes_.end() && isRefToPointer(param))
                return found->second;
            return std::nullopt;
        }
        const auto* unary = dyn_cast<UnaryOperator>(expr);
        if (!unary || unary->getOpcode() != UO_Deref)
            return std::nullopt;
        const auto* param = dyn_cast_or_null<ParmVarDecl>(
            asVarOrParam(unary->getSubExpr()));
        auto found = outputIndexes_.find(param);
        if (found == outputIndexes_.end() || !isPointerToPointer(param) ||
            !state.entryTargets[found->second])
            return std::nullopt;
        return found->second;
    }

    std::optional<unsigned> forwardedOutput(const Expr* expr,
                                            const State& state) const {
        if (!expr) return std::nullopt;
        expr = expr->IgnoreParenImpCasts();
        if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
            if (unary->getOpcode() == UO_AddrOf) {
                const auto* param = dyn_cast_or_null<ParmVarDecl>(
                    asVarOrParam(unary->getSubExpr()));
                auto found = outputIndexes_.find(param);
                // `&ref` addresses the caller's pointer slot, but `&out`
                // for a by-value T** parameter addresses only this
                // function's local parameter variable. Rebinding that
                // local T** must not become a postcondition on `*out`.
                if (found != outputIndexes_.end() &&
                    isRefToPointer(param))
                    return found->second;
            }
        }
        const auto* param = dyn_cast_or_null<ParmVarDecl>(
            asVarOrParam(expr));
        auto found = outputIndexes_.find(param);
        if (found == outputIndexes_.end() ||
            !state.entryTargets[found->second])
            return std::nullopt;
        return found->second;
    }

    ParamPostcondition valueOf(const Expr* expr,
                               const State& state) const {
        if (!expr) return ParamPostcondition::Unknown;
        expr = expr->IgnoreParenCasts();
        if (const auto target = outputTarget(expr, state))
            return state.values[*target];
        if (const auto* cond = dyn_cast<ConditionalOperator>(expr)) {
            ParamPostcondition yes = valueOf(cond->getTrueExpr(), state);
            ParamPostcondition no = valueOf(cond->getFalseExpr(), state);
            return yes == no ? yes : ParamPostcondition::Unknown;
        }
        if (const auto* call = dyn_cast<CallExpr>(expr)) {
            const auto summary = lookupPrev(previous_, call);
            if (summary) {
                if (summary->returnNullness == ReturnNullness::NeverNull)
                    return ParamPostcondition::NonNull;
                if (summary->returnNullness == ReturnNullness::MaybeNull)
                    return ParamPostcondition::Unknown;
                if (summary->nullFromParam >= 0 &&
                    static_cast<unsigned>(summary->nullFromParam) <
                        call->getNumArgs())
                    return valueOf(call->getArg(summary->nullFromParam),
                                   state);
            }
            return ParamPostcondition::Unknown;
        }
        switch (vstateOf(expr, previous_)) {
            case VState::Bad: return ParamPostcondition::Null;
            case VState::NonBad: return ParamPostcondition::NonNull;
            case VState::MaybeBad:
            case VState::Unknown: break;
        }
        return ParamPostcondition::Unknown;
    }

    const SummaryTable& previous_;
    State init_;
    std::map<const ParmVarDecl*, unsigned> outputIndexes_;
};

// A strong output guarantee is emitted only while every use of the output
// slot stays in the dataflow's exact vocabulary: direct `*out = value`,
// direct `ref = value`, or forwarding to another summarized callee. Copying
// the slot into another local/member (or capturing it in a lambda) creates an
// alias whose later writes are outside that vocabulary, so the affected
// parameter is forced back to Unknown.
class OutputAliasCollector
    : public RecursiveASTVisitor<OutputAliasCollector> {
public:
    explicit OutputAliasCollector(const FunctionDecl* func)
        : unsafe(func->getNumParams(), false) {
        for (unsigned i = 0; i < func->getNumParams(); ++i) {
            const ParmVarDecl* param = func->getParamDecl(i);
            if (isRefToPointer(param) || isPointerToPointer(param))
                outputIndexes_[param] = i;
        }
    }

    bool VisitVarDecl(VarDecl* var) {
        if (!isa<ParmVarDecl>(var) && var->hasInit())
            markRefs(var->getInit());
        return true;
    }

    bool VisitBinaryOperator(BinaryOperator* bin) {
        if (bin->isAssignmentOp()) markRefs(bin->getRHS());
        return true;
    }

    bool TraverseLambdaExpr(LambdaExpr* lambda) {
        if (lambda) markRefs(lambda->getBody());
        return true;
    }

    std::vector<bool> unsafe;

private:
    void markRefs(const Stmt* root) {
        if (!root) return;
        struct Finder : RecursiveASTVisitor<Finder> {
            const std::map<const ParmVarDecl*, unsigned>* indexes = nullptr;
            std::vector<bool>* unsafe = nullptr;
            bool VisitDeclRefExpr(DeclRefExpr* ref) {
                const auto* param = dyn_cast<ParmVarDecl>(ref->getDecl());
                auto found = indexes->find(param);
                if (found != indexes->end())
                    (*unsafe)[found->second] = true;
                return true;
            }
        } finder;
        finder.indexes = &outputIndexes_;
        finder.unsafe = &unsafe;
        finder.TraverseStmt(const_cast<Stmt*>(root));
    }

    std::map<const ParmVarDecl*, unsigned> outputIndexes_;
};

std::vector<ParamPostcondition> computeParamPostconditions(
        const FunctionDecl* func, ASTContext& ctx,
        const SummaryTable& previous) {
    std::vector<ParamPostcondition> unknown(
        func->getNumParams(), ParamPostcondition::Unknown);
    OutputAliasCollector aliasCollector(func);
    aliasCollector.TraverseStmt(func->getBody());
    ParamPostAnalysis analysis(func, previous);
    auto result = codeskeptic::runDataflow(func, ctx, analysis);
    if (!result.converged) return unknown;
    auto exit = result.blockExitStates.find(result.exitBlockID);
    if (exit == result.blockExitStates.end()) return unknown;
    std::vector<ParamPostcondition> values = exit->second.values;
    for (size_t i = 0; i < values.size(); ++i)
        if (aliasCollector.unsafe[i])
            values[i] = ParamPostcondition::Unknown;
    return values;
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

using FunctionNode = const FunctionDecl*;
using CallEdges = std::map<FunctionNode, std::vector<FunctionNode>>;

struct DirectCallCollector : RecursiveASTVisitor<DirectCallCollector> {
    const std::set<FunctionNode>* known = nullptr;
    const IndirectTargetMap* indirectTargets = nullptr;
    std::set<FunctionNode> callees;

    bool VisitCallExpr(CallExpr* call) {
        if (const FunctionDecl* callee = call->getDirectCallee()) {
            const FunctionNode key = callee->getCanonicalDecl();
            if (known->count(key)) callees.insert(key);
            return true;
        }
        auto found = indirectTargets->find(call);
        if (found == indirectTargets->end()) return true;
        for (const FunctionDecl* target : found->second) {
            const FunctionNode key = target->getCanonicalDecl();
            if (known->count(key)) callees.insert(key);
        }
        return true;
    }

    // A lambda body has its own FunctionDecl and summary. Calls inside it
    // must not become dependencies of the enclosing function.
    bool TraverseLambdaExpr(LambdaExpr*) { return true; }
};

struct FunctionCallGraph {
    std::vector<FunctionNode> order;
    std::map<FunctionNode, const FunctionDecl*> definitions;
    CallEdges edges;
};

FunctionCallGraph buildCallGraph(
        const std::vector<const FunctionDecl*>& functions,
        const IndirectTargetMap& indirectTargets) {
    FunctionCallGraph graph;
    std::set<FunctionNode> known;
    for (const FunctionDecl* func : functions) {
        const FunctionNode key = func->getCanonicalDecl();
        if (!known.insert(key).second) continue;
        graph.order.push_back(key);
        graph.definitions[key] = func;
    }
    for (FunctionNode key : graph.order) {
        DirectCallCollector collector;
        collector.known = &known;
        collector.indirectTargets = &indirectTargets;
        collector.TraverseStmt(const_cast<Stmt*>(
            graph.definitions.at(key)->getBody()));
        graph.edges[key] = {collector.callees.begin(),
                            collector.callees.end()};
    }
    return graph;
}

// Tarjan over caller -> callee edges emits sink components first. That is
// exactly the summary evaluation order: every acyclic callee is finalized
// before its caller, independent of source order or chain depth.
class SccFinder {
public:
    explicit SccFinder(const CallEdges& edges) : edges_(edges) {}

    std::vector<std::vector<FunctionNode>> run(
            const std::vector<FunctionNode>& order) {
        for (FunctionNode node : order)
            if (!index_.count(node)) visit(node);
        return components_;
    }

private:
    void visit(FunctionNode node) {
        index_[node] = nextIndex_;
        low_[node] = nextIndex_;
        ++nextIndex_;
        stack_.push_back(node);
        onStack_.insert(node);

        for (FunctionNode callee : edges_.at(node)) {
            if (!index_.count(callee)) {
                visit(callee);
                low_[node] = std::min(low_[node], low_[callee]);
            } else if (onStack_.count(callee)) {
                low_[node] = std::min(low_[node], index_[callee]);
            }
        }

        if (low_[node] != index_[node]) return;
        std::vector<FunctionNode> component;
        for (;;) {
            FunctionNode member = stack_.back();
            stack_.pop_back();
            onStack_.erase(member);
            component.push_back(member);
            if (member == node) break;
        }
        components_.push_back(std::move(component));
    }

    const CallEdges& edges_;
    int nextIndex_ = 0;
    std::map<FunctionNode, int> index_;
    std::map<FunctionNode, int> low_;
    std::vector<FunctionNode> stack_;
    std::set<FunctionNode> onStack_;
    std::vector<std::vector<FunctionNode>> components_;
};

const ParmVarDecl* exactIntegerParam(const Expr* expr, ASTContext& ctx) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParens();
    while (const auto* cast = dyn_cast<CastExpr>(expr)) {
        const Expr* sub = cast->getSubExpr()->IgnoreParens();
        const CastKind kind = cast->getCastKind();
        bool exact = kind == CK_LValueToRValue || kind == CK_NoOp;
        if (kind == CK_IntegralCast && cast->getType()->isIntegerType() &&
            sub->getType()->isIntegerType()) {
            exact = ctx.getIntWidth(cast->getType()) ==
                        ctx.getIntWidth(sub->getType()) &&
                    cast->getType()->isSignedIntegerType() ==
                        sub->getType()->isSignedIntegerType();
        }
        if (!exact) return nullptr;
        expr = sub;
    }
    const auto* reference = dyn_cast<DeclRefExpr>(expr);
    const auto* param =
        reference ? dyn_cast<ParmVarDecl>(reference->getDecl()) : nullptr;
    return param && param->getType()->isIntegerType() ? param : nullptr;
}

std::vector<ParamAllocatorSize> computeParamAllocatorSizes(
        const FunctionDecl* func, ASTContext& ctx,
        const SummaryTable& previous) {
    std::vector<ParamAllocatorSize> result(
        func->getNumParams(), ParamAllocatorSize::None);
    std::map<const ParmVarDecl*, unsigned> indexes;
    for (unsigned i = 0; i < func->getNumParams(); ++i)
        indexes[func->getParamDecl(i)] = i;

    struct Visitor : RecursiveASTVisitor<Visitor> {
        ASTContext& ctx;
        const SummaryTable& previous;
        const std::map<const ParmVarDecl*, unsigned>& indexes;
        std::vector<ParamAllocatorSize>& result;

        Visitor(
            ASTContext& context, const SummaryTable& summaries,
            const std::map<const ParmVarDecl*, unsigned>& paramIndexes,
            std::vector<ParamAllocatorSize>& relations)
            : ctx(context), previous(summaries), indexes(paramIndexes),
              result(relations) {}

        void mark(const Expr* expr) {
            const ParmVarDecl* param = exactIntegerParam(expr, ctx);
            auto found = indexes.find(param);
            if (found != indexes.end())
                result[found->second] = ParamAllocatorSize::Sink;
        }

        bool VisitCallExpr(CallExpr* call) {
            if (codeskeptic::isAllocatorCall(call)) {
                for (const Expr* argument : call->arguments())
                    mark(argument);
                return true;
            }

            auto summary = lookupPrev(previous, call);
            if (!summary) return true;
            for (unsigned i = 0; i < call->getNumArgs(); ++i)
                if (summary->paramAllocatorSize(i) ==
                    ParamAllocatorSize::Sink)
                    mark(call->getArg(i));
            return true;
        }

        // cs:ai ensures return != 0
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    } visitor{ctx, previous, indexes, result};
    visitor.TraverseStmt(const_cast<Stmt*>(func->getBody()));
    return result;
}

FunctionSummary summarizeFunction(const FunctionDecl* func, ASTContext& ctx,
                                  const SummaryTable& previous) {
    FunctionSummary summary;
    summary.returnNullness = computeReturnNullness(
        func, ctx, previous, &summary.nullFromParam);
    summary.returnZeroness = computeReturnZeroness(
        func, ctx, previous, &summary.zeroFromParam);
    summary.returnOwnership = isFdIntegerType(func->getReturnType())
                                  ? computeFdReturnOwnership(
                                        func, ctx, previous)
                                  : computeReturnOwnership(
                                        func, ctx, previous);
    summary.params = computeParamEffects(func, previous);
    ParamRelations relations = computeParamRelations(func, ctx, previous);
    summary.paramAccesses = std::move(relations.accesses);
    summary.paramOwnerships = std::move(relations.ownerships);
    std::vector<ParamOwnership> fdOwnerships =
        computeFdParamOwnerships(func, ctx, previous);
    for (size_t i = 0; i < fdOwnerships.size(); ++i)
        if (fdOwnerships[i] != ParamOwnership::Unknown)
            summary.paramOwnerships[i] = fdOwnerships[i];
    summary.paramFieldWrites = std::move(relations.fieldWrites);
    summary.paramPreconditions = computeParamPreconditions(func, ctx);
    summary.paramPostconditions =
        computeParamPostconditions(func, ctx, previous);
    summary.paramAllocatorSizes =
        computeParamAllocatorSizes(func, ctx, previous);
    summary.returnAliasParam = computeReturnAliasParam(func, ctx, previous);

    if (summary.returnNullness == ReturnNullness::MaybeNull) {
        int condParam = -1;
        codeskeptic::Interval condRange = codeskeptic::Interval::top();
        if (detectNullCondition(func, ctx, previous, &condParam,
                                &condRange)) {
            summary.nullCondParam = condParam;
            summary.nullCondRange = condRange;
        }
    }
    return summary;
}

bool sameSummary(const FunctionSummary& lhs, const FunctionSummary& rhs) {
    return lhs.returnNullness == rhs.returnNullness &&
           lhs.returnZeroness == rhs.returnZeroness &&
           lhs.returnOwnership == rhs.returnOwnership &&
           lhs.zeroFromParam == rhs.zeroFromParam &&
           lhs.nullFromParam == rhs.nullFromParam &&
           lhs.returnAliasParam == rhs.returnAliasParam &&
           lhs.nullCondParam == rhs.nullCondParam &&
           lhs.nullCondRange == rhs.nullCondRange &&
           lhs.params == rhs.params &&
           lhs.paramAccesses == rhs.paramAccesses &&
           lhs.paramOwnerships == rhs.paramOwnerships &&
           lhs.paramFieldWrites == rhs.paramFieldWrites &&
           lhs.paramPreconditions == rhs.paramPreconditions &&
           lhs.paramPostconditions == rhs.paramPostconditions &&
           lhs.paramAllocatorSizes == rhs.paramAllocatorSizes;
}

bool sameComponent(const std::vector<FunctionNode>& component,
                   const SummaryTable& lhs, const SummaryTable& rhs) {
    for (FunctionNode node : component) {
        auto left = lhs.find(node);
        auto right = rhs.find(node);
        if (left == lhs.end() || right == rhs.end() ||
            !sameSummary(left->second, right->second))
            return false;
    }
    return true;
}

} // anonymous namespace

namespace codeskeptic {

SummaryRegistry& SummaryRegistry::instance() {
    static SummaryRegistry registry;
    return registry;
}

void SummaryRegistry::clear() {
    summaries_.clear();
    callSummaries_.clear();
    stable_ = false;
}

void SummaryRegistry::rebuild(clang::ASTContext& ctx) {
    stable_ = false;
    summaries_.clear();
    callSummaries_.clear();

    FunctionCollector collector;
    collector.TraverseDecl(ctx.getTranslationUnitDecl());
    IndirectTargetMap indirectTargets =
        buildIndirectTargetMap(collector.functions);
    activeIndirectTargets = &indirectTargets;

    // Solve the direct-call graph component-by-component. Tarjan emits
    // callee SCCs before callers, so an acyclic wrapper is evaluated once
    // with all dependencies final instead of waiting for a global sweep.
    // Recursive SCCs start from conservative summaries and iterate
    // synchronously to a fixed point; a guard fallback keeps the first
    // conservative round if a future relation ever oscillates.
    FunctionCallGraph graph = buildCallGraph(collector.functions,
                                             indirectTargets);
    auto components = SccFinder(graph.edges).run(graph.order);
    SummaryTable current;

    for (const auto& component : components) {
        const FunctionNode first = component.front();
        const auto& firstEdges = graph.edges.at(first);
        const bool recursive =
            component.size() > 1 ||
            std::find(firstEdges.begin(), firstEdges.end(), first) !=
                firstEdges.end();

        if (!recursive) {
            current[first] = summarizeFunction(
                graph.definitions.at(first), ctx, current);
            continue;
        }

        SummaryTable previous;
        for (FunctionNode node : component)
            previous[node] = FunctionSummary{};
        SummaryTable conservativeFirst;
        bool converged = false;
        const unsigned maxSweeps = std::max(
            kMinimumSccSweeps,
            static_cast<unsigned>(component.size()) * 4u + 4u);
        SummaryTable visible = current;

        for (unsigned sweep = 0; sweep < maxSweeps; ++sweep) {
            for (const auto& [node, summary] : previous)
                visible[node] = summary;

            SummaryTable next;
            for (FunctionNode node : component)
                next[node] = summarizeFunction(
                    graph.definitions.at(node), ctx, visible);
            if (sweep == 0) conservativeFirst = next;
            if (sameComponent(component, previous, next)) {
                previous = std::move(next);
                converged = true;
                break;
            }
            previous = std::move(next);
        }

        if (!converged) previous = std::move(conservativeFirst);
        for (auto& [node, summary] : previous)
            current[node] = std::move(summary);
    }
    summaries_ = std::move(current);
    for (const auto& [call, targets] : indirectTargets) {
        std::optional<FunctionSummary> combined;
        bool complete = true;
        for (const FunctionDecl* target : targets) {
            const FunctionSummary* summary = lookup(target);
            if (!summary) {
                complete = false;
                break;
            }
            if (!combined) combined = *summary;
            else mergeTargetSummaries(*combined, *summary);
        }
        if (complete && combined)
            callSummaries_[call] = std::move(*combined);
    }
    activeIndirectTargets = nullptr;
    stable_ = true;  // consumers may now fold on these (see stable())
}

const SummaryRegistry::FunctionSummary*
SummaryRegistry::lookup(const clang::FunctionDecl* func) const {
    if (!func) return nullptr;
    auto it = summaries_.find(func->getCanonicalDecl());
    if (it != summaries_.end()) return &it->second;
    return lookupGlobal(func);
}

const SummaryRegistry::FunctionSummary*
SummaryRegistry::lookup(const clang::CallExpr* call) const {
    if (!call) return nullptr;
    if (const FunctionDecl* direct = call->getDirectCallee())
        return lookup(direct);
    auto found = callSummaries_.find(call);
    return found == callSummaries_.end() ? nullptr : &found->second;
}

namespace {

std::string globalKey(const FunctionDecl* func) {
    return func->getQualifiedNameAsString() + "/" +
           std::to_string(func->getNumParams());
}

} // anonymous namespace

// Different summaries landing on the same key (C++ overloads) merge
// conservatively: a mismatched field falls to the weak claim — a false
// strong claim (NeverNull/Frees/ReadsOnly) cannot arise from a collision.
void mergeConservative(SummaryRegistry::FunctionSummary& into,
                       const SummaryRegistry::FunctionSummary& from) {
    using RN = SummaryRegistry::ReturnNullness;
    using RZ = SummaryRegistry::ReturnZeroness;
    using RO = SummaryRegistry::ReturnOwnership;
    using PE = SummaryRegistry::ParamEffect;
    using PA = SummaryRegistry::ParamAccess;
    using PO = SummaryRegistry::ParamOwnership;
    using PPre = SummaryRegistry::ParamPrecondition;
    using PPost = SummaryRegistry::ParamPostcondition;
    using PAS = SummaryRegistry::ParamAllocatorSize;
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
    if (into.returnOwnership != from.returnOwnership)
        into.returnOwnership = RO::Unknown;
    // The passthrough claims survive a merge only on exact agreement,
    // and only in their defined homes (the Unknown side of each axis).
    if (into.zeroFromParam != from.zeroFromParam ||
        into.returnZeroness != RZ::Unknown)
        into.zeroFromParam = -1;
    if (into.nullFromParam != from.nullFromParam ||
        into.returnNullness != RN::Unknown)
        into.nullFromParam = -1;
    if (into.returnAliasParam != from.returnAliasParam)
        into.returnAliasParam = -1;
    if (into.params.size() != from.params.size()) {
        into.params.clear();  // paramEffect() defaults to Opaque
    } else {
        for (size_t i = 0; i < into.params.size(); ++i)
            if (into.params[i] != from.params[i])
                into.params[i] = PE::Opaque;
    }
    if (into.paramAccesses.size() != from.paramAccesses.size()) {
        into.paramAccesses.clear();
    } else {
        for (size_t i = 0; i < into.paramAccesses.size(); ++i)
            if (into.paramAccesses[i] != from.paramAccesses[i])
                into.paramAccesses[i] = PA::Unknown;
    }
    if (into.paramOwnerships.size() != from.paramOwnerships.size()) {
        into.paramOwnerships.clear();
    } else {
        for (size_t i = 0; i < into.paramOwnerships.size(); ++i)
            if (into.paramOwnerships[i] != from.paramOwnerships[i])
                into.paramOwnerships[i] = PO::Unknown;
    }
    if (into.paramFieldWrites.size() != from.paramFieldWrites.size()) {
        into.paramFieldWrites.clear();
    } else {
        for (size_t i = 0; i < into.paramFieldWrites.size(); ++i) {
            FieldWriteSet& target = into.paramFieldWrites[i];
            const FieldWriteSet& source = from.paramFieldWrites[i];
            if (!target.known || !source.known) {
                target = FieldWriteSet{};
                continue;
            }
            target.fields.insert(source.fields.begin(), source.fields.end());
        }
    }
    if (into.paramPreconditions.size() !=
        from.paramPreconditions.size()) {
        into.paramPreconditions.clear();
    } else {
        for (size_t i = 0; i < into.paramPreconditions.size(); ++i)
            if (into.paramPreconditions[i] != from.paramPreconditions[i])
                into.paramPreconditions[i] = PPre::None;
    }
    if (into.paramPostconditions.size() !=
        from.paramPostconditions.size()) {
        into.paramPostconditions.clear();
    } else {
        for (size_t i = 0; i < into.paramPostconditions.size(); ++i)
            if (into.paramPostconditions[i] != from.paramPostconditions[i])
                into.paramPostconditions[i] = PPost::Unknown;
    }
    if (into.paramAllocatorSizes.size() !=
        from.paramAllocatorSizes.size()) {
        into.paramAllocatorSizes.clear();
    } else {
        for (size_t i = 0; i < into.paramAllocatorSizes.size(); ++i)
            if (into.paramAllocatorSizes[i] !=
                from.paramAllocatorSizes[i])
                into.paramAllocatorSizes[i] = PAS::Unknown;
    }
}

void mergeTargetSummaries(
        SummaryRegistry::FunctionSummary& into,
        const SummaryRegistry::FunctionSummary& from) {
    using RN = SummaryRegistry::ReturnNullness;
    using RZ = SummaryRegistry::ReturnZeroness;
    using PA = SummaryRegistry::ParamAccess;
    const SummaryRegistry::FunctionSummary left = into;

    mergeConservative(into, from);

    auto joinNullness = [](RN lhs, RN rhs) {
        if (lhs == RN::Unknown || rhs == RN::Unknown)
            return RN::Unknown;
        if (lhs == rhs) return lhs;
        return RN::MaybeNull;
    };
    into.returnNullness =
        joinNullness(left.returnNullness, from.returnNullness);
    into.nullCondParam = -1;
    into.nullCondRange = codeskeptic::Interval::top();
    if (into.returnNullness == RN::MaybeNull) {
        const SummaryRegistry::FunctionSummary* conditioned = nullptr;
        if (left.returnNullness == RN::MaybeNull &&
            from.returnNullness == RN::NeverNull)
            conditioned = &left;
        else if (left.returnNullness == RN::NeverNull &&
                 from.returnNullness == RN::MaybeNull)
            conditioned = &from;
        else if (left.returnNullness == RN::MaybeNull &&
                 from.returnNullness == RN::MaybeNull &&
                 left.nullCondParam == from.nullCondParam &&
                 left.nullCondRange == from.nullCondRange)
            conditioned = &left;
        if (conditioned) {
            into.nullCondParam = conditioned->nullCondParam;
            into.nullCondRange = conditioned->nullCondRange;
        }
    }

    auto joinZeroness = [](RZ lhs, RZ rhs) {
        if (lhs == RZ::Unknown || rhs == RZ::Unknown)
            return RZ::Unknown;
        if (lhs == rhs) return lhs;
        return RZ::MaybeZero;
    };
    into.returnZeroness =
        joinZeroness(left.returnZeroness, from.returnZeroness);

    auto joinAccess = [](PA lhs, PA rhs) {
        if (lhs == PA::Unknown || rhs == PA::Unknown)
            return PA::Unknown;
        auto bits = [](PA value) {
            switch (value) {
                case PA::None: return 0u;
                case PA::Reads: return 1u;
                case PA::Writes: return 2u;
                case PA::ReadsWrites: return 3u;
                case PA::Unknown: break;
            }
            return 3u;
        };
        switch (bits(lhs) | bits(rhs)) {
            case 0: return PA::None;
            case 1: return PA::Reads;
            case 2: return PA::Writes;
            default: return PA::ReadsWrites;
        }
    };
    if (left.paramAccesses.size() == from.paramAccesses.size()) {
        into.paramAccesses.resize(left.paramAccesses.size());
        for (size_t i = 0; i < left.paramAccesses.size(); ++i)
            into.paramAccesses[i] =
                joinAccess(left.paramAccesses[i], from.paramAccesses[i]);
    }
}

namespace {

// --- Disk format ---
//
// v2: key<TAB>return-null<TAB>params<TAB>return-zero
// v1 (legacy): no last column — recognized on load, zeroness stays Unknown.
// Returns: U/Z/N/M; params are a char string of O/R/F/S, empty vector "-".
// Qualified names cannot contain TAB/newline — the key is safe.
constexpr const char* kSummaryFileHeader = "codeskeptic-summaries v11";
constexpr const char* kSummaryFileHeaderV10 = "codeskeptic-summaries v10";
constexpr const char* kSummaryFileHeaderV9 = "codeskeptic-summaries v9";
constexpr const char* kSummaryFileHeaderV8 = "codeskeptic-summaries v8";
constexpr const char* kSummaryFileHeaderV7 = "codeskeptic-summaries v7";
constexpr const char* kSummaryFileHeaderV6 = "codeskeptic-summaries v6";
constexpr const char* kSummaryFileHeaderV5 = "codeskeptic-summaries v5";
constexpr const char* kSummaryFileHeaderV4 = "codeskeptic-summaries v4";
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
        case ReturnZeroness::AlwaysZero: return 'Z';
        case ReturnZeroness::NeverZero:  return 'N';
        case ReturnZeroness::MaybeZero:  return 'M';
        case ReturnZeroness::Unknown:   break;
    }
    return 'U';
}

bool rzFromChar(char c, ReturnZeroness& out) {
    switch (c) {
        case 'U': out = ReturnZeroness::Unknown;    return true;
        case 'Z': out = ReturnZeroness::AlwaysZero; return true;
        case 'N': out = ReturnZeroness::NeverZero;  return true;
        case 'M': out = ReturnZeroness::MaybeZero; return true;
    }
    return false;
}

char roToChar(ReturnOwnership value) {
    switch (value) {
        case ReturnOwnership::Owned: return 'O';
        case ReturnOwnership::Borrowed: return 'B';
        case ReturnOwnership::Unknown: break;
    }
    return 'U';
}

bool roFromChar(char c, ReturnOwnership& out) {
    switch (c) {
        case 'U': out = ReturnOwnership::Unknown; return true;
        case 'O': out = ReturnOwnership::Owned; return true;
        case 'B': out = ReturnOwnership::Borrowed; return true;
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

char preToChar(ParamPrecondition value) {
    switch (value) {
        case ParamPrecondition::NonNullCrash: return 'C';
        case ParamPrecondition::NonNullRejected: return 'R';
        case ParamPrecondition::None: break;
    }
    return 'O';
}

bool preFromChar(char c, ParamPrecondition& out) {
    switch (c) {
        case 'O': out = ParamPrecondition::None; return true;
        case 'C': out = ParamPrecondition::NonNullCrash; return true;
        case 'R': out = ParamPrecondition::NonNullRejected; return true;
    }
    return false;
}

char postToChar(ParamPostcondition value) {
    switch (value) {
        case ParamPostcondition::Null: return '0';
        case ParamPostcondition::NonNull: return 'N';
        case ParamPostcondition::Unknown: break;
    }
    return 'U';
}

bool postFromChar(char c, ParamPostcondition& out) {
    switch (c) {
        case 'U': out = ParamPostcondition::Unknown; return true;
        case '0': out = ParamPostcondition::Null; return true;
        case 'N': out = ParamPostcondition::NonNull; return true;
    }
    return false;
}

char accessToChar(ParamAccess value) {
    switch (value) {
        case ParamAccess::None: return 'O';
        case ParamAccess::Reads: return 'R';
        case ParamAccess::Writes: return 'W';
        case ParamAccess::ReadsWrites: return 'B';
        case ParamAccess::Unknown: break;
    }
    return 'U';
}

bool accessFromChar(char c, ParamAccess& out) {
    switch (c) {
        case 'U': out = ParamAccess::Unknown; return true;
        case 'O': out = ParamAccess::None; return true;
        case 'R': out = ParamAccess::Reads; return true;
        case 'W': out = ParamAccess::Writes; return true;
        case 'B': out = ParamAccess::ReadsWrites; return true;
    }
    return false;
}

char ownershipToChar(ParamOwnership value) {
    switch (value) {
        case ParamOwnership::Borrowed: return 'B';
        case ParamOwnership::Consumed: return 'C';
        case ParamOwnership::Transferred: return 'T';
        case ParamOwnership::Unknown: break;
    }
    return 'U';
}

bool ownershipFromChar(char c, ParamOwnership& out) {
    switch (c) {
        case 'U': out = ParamOwnership::Unknown; return true;
        case 'B': out = ParamOwnership::Borrowed; return true;
        case 'C': out = ParamOwnership::Consumed; return true;
        case 'T': out = ParamOwnership::Transferred; return true;
    }
    return false;
}

// cs:ai ensures return != 0
char allocatorSizeToChar(ParamAllocatorSize value) {
    switch (value) {
        case ParamAllocatorSize::None: return 'O';
        case ParamAllocatorSize::Sink: return 'S';
        case ParamAllocatorSize::Unknown: break;
    }
    return '?';
}

bool allocatorSizeFromChar(char c, ParamAllocatorSize& out) {
    switch (c) {
        case '?': out = ParamAllocatorSize::Unknown; return true;
        case 'O': out = ParamAllocatorSize::None; return true;
        case 'S': out = ParamAllocatorSize::Sink; return true;
    }
    return false;
}

template <typename Value, typename ToChar>
void writeParamVector(std::ostream& out, size_t count, ToChar toChar,
                      const std::vector<Value>& values, Value fallback) {
    if (count == 0) { out << '-'; return; }
    for (size_t i = 0; i < count; ++i)
        out << toChar(i < values.size() ? values[i] : fallback);
}

void writeFieldWriteVector(std::ostream& out, size_t count,
                           const std::vector<FieldWriteSet>& values) {
    if (count == 0) {
        out << '-';
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        if (i != 0) out << ';';
        if (i >= values.size() || !values[i].known) {
            out << '?';
            continue;
        }
        if (values[i].fields.empty()) {
            out << '!';
            continue;
        }
        bool first = true;
        for (const std::string& field : values[i].fields) {
            if (!first) out << ',';
            out << field;
            first = false;
        }
    }
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
        // v5 column: null-passthrough param index, "-" when absent.
        out << '\t';
        if (summary.nullFromParam < 0) out << '-';
        else out << summary.nullFromParam;
        // v7 column: exact pointer return-alias param, "-" when absent.
        out << '\t';
        if (summary.returnAliasParam < 0) out << '-';
        else out << summary.returnAliasParam;
        // v8 columns: inferred non-null preconditions and exact pointer
        // out-parameter postconditions.
        out << '\t';
        writeParamVector(out, summary.params.size(), preToChar,
                         summary.paramPreconditions, ParamPrecondition::None);
        out << '\t';
        writeParamVector(out, summary.params.size(), postToChar,
                         summary.paramPostconditions,
                         ParamPostcondition::Unknown);
        // v9 columns: pointee access, parameter ownership, and exact
        // ownership of every non-null pointer return.
        out << '\t';
        if (summary.params.empty()) {
            out << '-';
        } else {
            for (size_t i = 0; i < summary.params.size(); ++i)
                out << accessToChar(summary.paramAccess(
                    static_cast<unsigned>(i)));
        }
        out << '\t';
        if (summary.params.empty()) {
            out << '-';
        } else {
            for (size_t i = 0; i < summary.params.size(); ++i)
                out << ownershipToChar(summary.paramOwnership(
                    static_cast<unsigned>(i)));
        }
        out << '\t' << roToChar(summary.returnOwnership);
        // v10: exact one-hop field writes per parameter.
        out << '\t';
        writeFieldWriteVector(out, summary.params.size(),
                              summary.paramFieldWrites);
        // v11: exact unchanged parameter-to-allocator-size relation.
        out << '\t';
        writeParamVector(out, summary.params.size(),
                         allocatorSizeToChar,
                         summary.paramAllocatorSizes,
                         ParamAllocatorSize::Unknown);
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
    if (line == kSummaryFileHeader) version = 11;
    else if (line == kSummaryFileHeaderV10) version = 10;
    else if (line == kSummaryFileHeaderV9) version = 9;
    else if (line == kSummaryFileHeaderV8) version = 8;
    else if (line == kSummaryFileHeaderV7) version = 7;
    else if (line == kSummaryFileHeaderV6) version = 6;
    else if (line == kSummaryFileHeaderV5) version = 5;
    else if (line == kSummaryFileHeaderV4) version = 4;
    else if (line == kSummaryFileHeaderV3) version = 3;
    else if (line == kSummaryFileHeaderV2) version = 2;
    else if (line == kSummaryFileHeaderV1) version = 1;
    else return false;
    // Field count is VERSION-strict: extra columns under an old header
    // are corruption, not a future format (rejected wholesale).
    const size_t maxFields =
        (version >= 11) ? 15 : (version >= 10) ? 14
                           : (version >= 9) ? 13
                           : (version >= 8) ? 10
                           : (version >= 7) ? 8 : (version >= 5) ? 7
                       : (version == 4) ? 6 : (version == 3) ? 5 : 4;

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
        if (version == 9 && fields.size() != 13) return false;
        if (version == 8 && fields.size() != 10) return false;
        if (version == 10 && fields.size() != 14) return false;
        if (version == 11 && fields.size() != 15) return false;
        const std::string& key = fields[0];
        const std::string& rn = fields[1];
        const std::string& pe = fields[2];
        if (key.empty() || rn.size() != 1 || pe.empty()) return false;

        FunctionSummary summary;
        if (!rnFromChar(rn[0], summary.returnNullness)) return false;
        if (fields.size() >= 4) {
            if (fields[3].size() != 1 ||
                (fields[3][0] == 'Z' && version < 6) ||
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
        if (fields.size() >= 6 && fields[5] != "-") {
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
        if (fields.size() >= 7 && fields[6] != "-") {
            const std::string& nf = fields[6];
            errno = 0;
            char* end = nullptr;
            long long idx = std::strtoll(nf.c_str(), &end, 10);
            if (errno != 0 || end != nf.c_str() + nf.size() || idx < 0)
                return false;
            if (summary.returnNullness != ReturnNullness::Unknown)
                return false;
            summary.nullFromParam = static_cast<int>(idx);
        }
        if (fields.size() >= 8 && fields[7] != "-") {
            const std::string& alias = fields[7];
            errno = 0;
            char* end = nullptr;
            long long idx = std::strtoll(alias.c_str(), &end, 10);
            if (errno != 0 || end != alias.c_str() + alias.size() ||
                idx < 0)
                return false;
            summary.returnAliasParam = static_cast<int>(idx);
        }
        if (pe != "-") {
            summary.params.reserve(pe.size());
            for (char c : pe) {
                ParamEffect effect;
                if (!peFromChar(c, effect)) return false;
                summary.params.push_back(effect);
            }
        }
        if (version >= 8) {
            const std::string& pre = fields[8];
            const std::string& post = fields[9];
            const size_t paramCount = summary.params.size();
            if ((pre == "-") != (paramCount == 0) ||
                (post == "-") != (paramCount == 0))
                return false;
            if (paramCount != 0) {
                if (pre.size() != paramCount || post.size() != paramCount)
                    return false;
                summary.paramPreconditions.reserve(paramCount);
                summary.paramPostconditions.reserve(paramCount);
                for (char c : pre) {
                    ParamPrecondition value;
                    if (!preFromChar(c, value)) return false;
                    summary.paramPreconditions.push_back(value);
                }
                for (char c : post) {
                    ParamPostcondition value;
                    if (!postFromChar(c, value)) return false;
                    summary.paramPostconditions.push_back(value);
                }
            }
        }
        if (version >= 9) {
            const std::string& access = fields[10];
            const std::string& ownership = fields[11];
            const std::string& returnOwnership = fields[12];
            const size_t paramCount = summary.params.size();
            if ((access == "-") != (paramCount == 0) ||
                (ownership == "-") != (paramCount == 0))
                return false;
            if (paramCount != 0) {
                if (access.size() != paramCount ||
                    ownership.size() != paramCount)
                    return false;
                summary.paramAccesses.reserve(paramCount);
                summary.paramOwnerships.reserve(paramCount);
                for (char c : access) {
                    ParamAccess value;
                    if (!accessFromChar(c, value)) return false;
                    summary.paramAccesses.push_back(value);
                }
                for (char c : ownership) {
                    ParamOwnership value;
                    if (!ownershipFromChar(c, value)) return false;
                    summary.paramOwnerships.push_back(value);
                }
            }
            if (returnOwnership.size() != 1 ||
                !roFromChar(returnOwnership[0], summary.returnOwnership))
                return false;
        }
        if (version >= 10) {
            const std::string& encoded = fields[13];
            const size_t paramCount = summary.params.size();
            if ((encoded == "-") != (paramCount == 0)) return false;
            if (paramCount != 0) {
                size_t fieldSetStart = 0;
                for (size_t i = 0; i < paramCount; ++i) {
                    const size_t end = encoded.find(';', fieldSetStart);
                    if ((i + 1 == paramCount) !=
                        (end == std::string::npos))
                        return false;
                    const std::string part = encoded.substr(
                        fieldSetStart,
                        end == std::string::npos
                            ? std::string::npos : end - fieldSetStart);
                    FieldWriteSet parsedFields;
                    if (part == "?") {
                        parsedFields.known = false;
                    } else {
                        parsedFields.known = true;
                        if (part != "!") {
                            size_t nameStart = 0;
                            for (;;) {
                                const size_t comma = part.find(',', nameStart);
                                const std::string name = part.substr(
                                    nameStart,
                                    comma == std::string::npos
                                        ? std::string::npos
                                        : comma - nameStart);
                                if (name.empty()) return false;
                                for (unsigned char c : name)
                                    if (c <= 0x20 || c == ',' || c == ';' ||
                                        c == '!' || c == '?')
                                        return false;
                                if (!parsedFields.fields.insert(name).second)
                                    return false;
                                if (comma == std::string::npos) break;
                                nameStart = comma + 1;
                            }
                        }
                    }
                    summary.paramFieldWrites.push_back(
                        std::move(parsedFields));
                    if (end == std::string::npos) break;
                    fieldSetStart = end + 1;
                }
            }
        }
        if (version >= 11) {
            const std::string& encoded = fields[14];
            const size_t paramCount = summary.params.size();
            if ((encoded == "-") != (paramCount == 0)) return false;
            if (paramCount != 0) {
                if (encoded.size() != paramCount) return false;
                summary.paramAllocatorSizes.reserve(paramCount);
                for (char c : encoded) {
                    ParamAllocatorSize value;
                    if (!allocatorSizeFromChar(c, value)) return false;
                    summary.paramAllocatorSizes.push_back(value);
                }
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
