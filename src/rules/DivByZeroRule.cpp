#include "rules/DivByZeroRule.h"

#include "contracts/ContractInfo.h"
#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CoverageReport.h"
#include "engine/CallRefArgs.h"
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
#include <optional>
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
// An INTRINSIC source of a possibly-zero integer: a value parsed from
// untrusted input or drawn from the RNG. This is the div-by-zero twin
// of #92's known allocator — the zero-ness is intrinsic to the source
// (atoi("0") is 0, rand() can be 0), NOT caller-dependent the way a
// bare parameter's is. A parameter divisor was tried (#94) and
// REJECTED: it fails Juliet CWE369 precision (0.71 < 0.95) because a
// callee's parameter is often validated by its caller — that case is a
// missing PRECONDITION (AssumptionRule's domain), not a div-by-zero
// bug. Keying on the intrinsic source keeps precision while catching
// the "parse input, divide without checking" defect (CWE-369).
bool isUntrustedZeroSource(const CallExpr* call) {
    const FunctionDecl* callee = call->getDirectCallee();
    if (!callee) return false;
    const IdentifierInfo* id = callee->getIdentifier();
    if (!id) return false;
    const llvm::StringRef n = id->getName();
    return n == "atoi" || n == "atol" || n == "atoll" || n == "strtol" ||
           n == "strtoul" || n == "strtoll" || n == "strtoull" ||
           n == "rand" || n == "random";
}

// Unwrap zero-passthrough call chains: when `id`'s summary proves
// "result is zero only if argument #k is zero", `id(e)` stands for `e`
// zeroness-wise, so the copy/state machinery can flow the ARGUMENT's
// zero-state into the assignment target. WIDTH DISCIPLINE mirrors the
// harvest: the (implicit-cast-stripped) argument's width must not
// exceed the callee parameter's slot, or a narrowing conversion could
// fabricate a zero from a nonzero value and the propagated NonZero
// would wrongly SUPPRESS a real division hazard. An explicit cast in
// the argument simply stops the unwrap (IgnoreParenImpCasts keeps it),
// which downgrades to Unknown - sound.
const Expr* unwrapZeroPassthrough(const Expr* expr, const ASTContext& ctx) {
    while (expr) {
        const Expr* stripped = expr->IgnoreParenImpCasts();
        const auto* call = dyn_cast<CallExpr>(stripped);
        if (!call) break;
        const FunctionDecl* callee = call->getDirectCallee();
        const auto* summary =
            codeskeptic::SummaryRegistry::instance().lookup(callee);
        if (!summary || summary->zeroFromParam < 0) break;
        const unsigned idx = static_cast<unsigned>(summary->zeroFromParam);
        if (idx >= call->getNumArgs()) break;
        QualType paramTy;
        if (callee && idx < callee->getNumParams())
            paramTy = callee->getParamDecl(idx)->getType();
        const Expr* arg = call->getArg(idx);
        const Expr* argCore = arg->IgnoreParenImpCasts();
        if (paramTy.isNull() || !paramTy->isIntegerType() ||
            !argCore->getType()->isIntegerType() ||
            ctx.getIntWidth(argCore->getType()) > ctx.getIntWidth(paramTy))
            break;
        expr = arg;
    }
    return expr;
}

ZeroState evaluateAssignedValue(const Expr* expr) {
    ZeroState lit = evaluateAsZero(expr);
    if (lit != ZeroState::Unknown) return lit;
    if (!expr) return ZeroState::Unknown;
    const Expr* stripped = expr->IgnoreParenImpCasts();
    if (const auto* call = dyn_cast<CallExpr>(stripped)) {
        using RZ = codeskeptic::SummaryRegistry::ReturnZeroness;
        if (const auto* summary = codeskeptic::SummaryRegistry::instance()
                                      .lookup(call->getDirectCallee())) {
            if (summary->returnZeroness == RZ::NeverZero)
                return ZeroState::NonZero;
            if (summary->returnZeroness == RZ::MaybeZero)
                return ZeroState::MaybeZero;
        }
        // No summary (opaque): an intrinsic untrusted-input source can
        // be zero — MaybeZero so an unguarded `x / atoi(...)`-derived
        // divisor warns; a guard refines it to NonZero.
        if (isUntrustedZeroSource(call)) return ZeroState::MaybeZero;
    }
    return ZeroState::Unknown;
}

// The concrete integer value of a literal expression (with a leading
// unary minus), if any. Used to refine zero-ness against non-zero
// bounds (`if (n <= 1) return;` proves n != 0 on the fall-through).
std::optional<long long> constIntValue(const Expr* expr) {
    if (!expr) return std::nullopt;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr)) {
        if (lit->getValue().getSignificantBits() > 63) return std::nullopt;
        return lit->getValue().getSExtValue();
    }
    if (const auto* unary = dyn_cast<UnaryOperator>(expr))
        if (unary->getOpcode() == UO_Minus)
            if (auto v = constIntValue(unary->getSubExpr())) return -*v;
    return std::nullopt;
}

// Does 0 satisfy `0 <opc> c`? (opc arrives variable-on-the-left, so
// this asks whether the value 0 lies in the constraint region.)
bool zeroSatisfies(BinaryOperatorKind opc, long long c) {
    switch (opc) {
        case BO_LT: return 0 < c;
        case BO_LE: return 0 <= c;
        case BO_GT: return 0 > c;
        case BO_GE: return 0 >= c;
        default:    return true;  // non-ordering: no exclusion
    }
}

BinaryOperatorKind negateOrdering(BinaryOperatorKind opc) {
    switch (opc) {
        case BO_LT: return BO_GE;
        case BO_LE: return BO_GT;
        case BO_GT: return BO_LE;
        case BO_GE: return BO_LT;
        default:    return opc;
    }
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

    // Copy-source closure (v0.4 recall round): `int dataCopy = data;
    // ... 100 / dataCopy` — the divisor's zeroness comes FROM `data`,
    // so every transitive var-to-var copy source must be tracked too,
    // or the source's state is never computed and the copy assigns
    // Unknown (the Juliet fgets *_31/_33 family FN).
    struct CopyEdges : RecursiveASTVisitor<CopyEdges> {
        // target -> direct sources
        std::map<const VarDecl*, std::set<const VarDecl*>> edges;
        const ASTContext* ctx = nullptr;
        void addEdge(const VarDecl* dst, const Expr* rhs) {
            if (!dst || !rhs) return;
            // `r = id(d)` copies d zeroness-wise (zero-passthrough) —
            // the edge must exist or d's state is never computed.
            if (const auto* src =
                    getReferencedVar(unwrapZeroPassthrough(rhs, *ctx)))
                edges[dst].insert(src);
        }
        bool VisitBinaryOperator(BinaryOperator* op) {
            if (op->getOpcode() == BO_Assign)
                addEdge(getReferencedVar(op->getLHS()), op->getRHS());
            return true;
        }
        bool VisitVarDecl(VarDecl* vd) {
            if (vd->hasInit() && !vd->isStaticLocal())
                addEdge(vd, vd->getInit());
            return true;
        }
    } copies;
    copies.ctx = &ctx;
    copies.TraverseStmt(funcDecl->getBody());
    bool grew = true;
    while (grew) {
        grew = false;
        for (const auto& [dst, srcs] : copies.edges) {
            if (!vars.count(dst)) continue;
            for (const auto* src : srcs)
                if (vars.insert(src).second) grew = true;
        }
    }
    return vars;
}

// Variables passed at `requires n != 0` positions of contracted callees
// (CONTRACTS.md Round C): tracking them lets the caller-side check see
// `int z = 0; f(z);` as a definite violation, not just literal zeros.
// Returns whether ANY such call site exists — a function with no
// divisions but a contracted call still needs the dataflow pass for the
// literal-argument check in onStatement.
bool addContractArgVars(const FunctionDecl* funcDecl, ASTContext& ctx,
                        std::set<const VarDecl*>& vars) {
    bool anyContractCall = false;
    auto callMatcher = callExpr().bind("call");
    for (const auto& result :
         match(findAll(callMatcher), *funcDecl->getBody(), ctx)) {
        const auto* call = result.getNodeAs<CallExpr>("call");
        if (!call) continue;
        const FunctionDecl* callee = call->getDirectCallee();
        if (!callee) continue;
        codeskeptic::ParsedContracts parsed =
            codeskeptic::allContractClausesForDecl(callee, ctx);
        if (parsed.clauses.empty()) continue;
        auto req = codeskeptic::analyzeRequires(parsed, callee);
        for (const auto& info : req.enforced) {
            if (info.kind != codeskeptic::RequiresInfo::Kind::NonZeroParam)
                continue;
            if (info.paramIndex >= call->getNumArgs()) continue;
            anyContractCall = true;
            if (const auto* var =
                    getReferencedVar(call->getArg(info.paramIndex)))
                vars.insert(var);
        }
    }
    return anyContractCall;
}

// --- Statement classification ---

enum class StmtEffect {
    None, AssignsZero, AssignsNonZero, AssignsMaybeZero, AssignsUnknown,
    // `target = src;` where src is another tracked variable: the
    // effect is src's CURRENT state (resolved in transfer, where the
    // in-state is visible) — zeroness flows through copies (v0.4).
    AssignsCopy
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

StmtEffect classifyStmt(const Stmt* stmt, const VarDecl* targetVar,
                        const VarDecl** copySrc, const ASTContext& ctx) {
    // The RHS value's effect; when it is opaque but a plain var-to-var
    // copy, the state flows from the source (resolved in transfer).
    // Zero-passthrough calls unwrap to their argument first, so
    // `r = id(d)` classifies exactly like `r = d` (value or copy).
    auto effectOfRhs = [&](const Expr* rhs) {
        rhs = unwrapZeroPassthrough(rhs, ctx);
        StmtEffect e = effectOfValue(evaluateAssignedValue(rhs));
        if (e == StmtEffect::AssignsUnknown) {
            if (const auto* src = getReferencedVar(rhs)) {
                *copySrc = src;
                return StmtEffect::AssignsCopy;
            }
        }
        return e;
    };
    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (vd == targetVar && vd->hasInit()) {
                    // Static locals initialize once per program, not
                    // per call — the init value is not this call's
                    // state (see NullDeref classifyStmt, #86).
                    if (vd->isStaticLocal())
                        return StmtEffect::AssignsUnknown;
                    return effectOfRhs(vd->getInit());
                }
            }
        }
        return StmtEffect::None;
    }
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign &&
            refersToVar(binOp->getLHS(), targetVar))
            return effectOfRhs(binOp->getRHS());
        // Compound assignments (`z += n`) change the value too —
        // without this a counter initialized to 0 stayed "definitely
        // zero" forever (the llama.cpp ngram-cache FP: `++n_done; ...
        // x / n_done` was reported as certain division by zero).
        if (binOp->isCompoundAssignmentOp() &&
            refersToVar(binOp->getLHS(), targetVar))
            return StmtEffect::AssignsUnknown;
        return StmtEffect::None;
    }
    // `f(&z)` may store into z: the fact is gone. The fine-grained CFG
    // presents the AddrOf as its own element.
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
        if (unary->getOpcode() == UO_AddrOf &&
            refersToVar(unary->getSubExpr(), targetVar))
            return StmtEffect::AssignsUnknown;
        // `++z` / `z--`: the same visibility gap as compound
        // assignment.
        if (unary->isIncrementDecrementOp() &&
            refersToVar(unary->getSubExpr(), targetVar))
            return StmtEffect::AssignsUnknown;
        return StmtEffect::None;
    }
    if (const auto* call = dyn_cast<CallExpr>(stmt)) {
        // scanf("%d", &z): z is filled from external text, which can be
        // 0 — MaybeZero, the same intrinsic-source signal as an atoi
        // divisor. This element follows the `&z` AddrOf element (which
        // set z Unknown) in the fine-grained CFG, so it lands last and
        // wins. `x / z` after an unguarded scanf now warns; a guard
        // (`if (z)`) refines it back to NonZero.
        if (const FunctionDecl* fd = call->getDirectCallee()) {
            if (const IdentifierInfo* id = fd->getIdentifier()) {
                const llvm::StringRef n = id->getName();
                const bool scanf = n == "scanf" || n == "fscanf" ||
                                   n == "sscanf" || n == "vscanf" ||
                                   n == "vfscanf" || n == "vsscanf";
                if (scanf)
                    for (const Expr* arg : call->arguments()) {
                        const Expr* a = arg->IgnoreParenImpCasts();
                        if (const auto* u = dyn_cast<UnaryOperator>(a))
                            if (u->getOpcode() == UO_AddrOf &&
                                refersToVar(u->getSubExpr(), targetVar))
                                return StmtEffect::AssignsMaybeZero;
                    }
            }
        }
        // `f(z)` where the parameter is a non-const reference (`int&`):
        // an out-param with no AddrOf node to observe — only the
        // parameter type reveals that z may be reassigned by the callee.
        bool invalidated = false;
        codeskeptic::forEachNonConstRefArg(call, [&](const Expr* arg) {
            if (refersToVar(arg, targetVar)) invalidated = true;
        });
        if (invalidated) return StmtEffect::AssignsUnknown;
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
    codeskeptic::walkCondition(
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

            // Orderings against ANY non-negative constant: on a given
            // edge the constraint `var <effOp> c` holds; if 0 does NOT
            // satisfy it, var cannot be zero there. This subsumes the
            // zero-constant cases (`z > 0` true → NonZero) AND catches
            // non-zero bounds: `if (n <= 1) return;` leaves `n > 1` on
            // the fall-through, and 0 fails `0 > 1`, so n is NonZero
            // (the tmux layout_spread_cell FP, 2026-07-13). Restricted
            // to c >= 0 so the signed comparison of 0 vs c matches the
            // real (possibly unsigned) comparison — a negative bound
            // would need signedness the fact layer doesn't carry here.
            auto c = constIntValue(other);
            if (!c || *c < 0) return;
            BinaryOperatorKind effOp = edgeTrue ? opc : negateOrdering(opc);
            if (!zeroSatisfies(effOp, *c))
                setIfTracked(state, var, ZeroState::NonZero);
        });
}

// --- Analysis struct for DataflowEngine ---

class DivByZeroAnalysis {
public:
    using State = VarState;

    DivByZeroAnalysis(const std::set<const VarDecl*>& trackedVars,
                      std::string funcName,
                      codeskeptic::DiagnosticList& results,
                      std::set<unsigned>& reportedLines)
        : trackedVars_(trackedVars), funcName_(std::move(funcName)),
          results_(results), reportedLines_(reportedLines) {
        for (const auto* var : trackedVars_)
            initState_[var] = ZeroState::Unknown;
    }

    State initialState() const { return initState_; }

    // Declared `requires n != 0` (CONTRACTS.md Round C): the parameter
    // enters the function NonZero — the proof burden moved to the
    // contract, and every visible call site is checked instead
    // (checkCallContracts below).
    void seedRequires(const FunctionDecl* func,
                      const std::vector<codeskeptic::RequiresInfo>& infos) {
        for (const auto& info : infos) {
            if (info.kind != codeskeptic::RequiresInfo::Kind::NonZeroParam)
                continue;
            if (info.paramIndex >= func->getNumParams()) continue;
            auto it = initState_.find(func->getParamDecl(info.paramIndex));
            if (it != initState_.end()) it->second = ZeroState::NonZero;
        }
    }

    // Seed a parameter to MaybeZero from the interprocedural
    // param-zeroness pass — the caller(s) provably pass a possibly-zero
    // value (never manufactured from Unknown; see buildParamZeroness).
    // Only lifts an Unknown seed, so a `requires` NonZero contract or a
    // literal never loses to it.
    void seedParamMaybeZero(const VarDecl* param) {
        auto it = initState_.find(param);
        if (it != initState_.end() && it->second == ZeroState::Unknown)
            it->second = ZeroState::MaybeZero;
    }

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
                   ASTContext& ctx) const {
        State out = in;
        for (const auto* var : trackedVars_) {
            const VarDecl* copySrc = nullptr;
            StmtEffect effect = classifyStmt(stmt, var, &copySrc, ctx);
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
                case StmtEffect::AssignsCopy: {
                    // Zeroness flows through the copy: the target takes
                    // the source's IN-state (an untracked source is
                    // honest Unknown). Trace notes come free — the
                    // state transition at this stmt is recorded by
                    // onStatement like any other assignment.
                    auto it = in.find(copySrc);
                    out[var] = (it != in.end()) ? it->second
                                                : ZeroState::Unknown;
                    break;
                }
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
                            codeskeptic::MsgId::TraceAssumedZeroHere);
        }
    }

    // The entry state at a call site (for the interprocedural
    // param-zeroness pass: it reads back the zeroness of each argument
    // as the caller passes it). Populated only when recordCallStates_
    // is on — the ordinary rule pass does not pay for it.
    const State* stateAtCall(const Stmt* call) const {
        auto it = atCall_.find(call);
        return it == atCall_.end() ? nullptr : &it->second;
    }
    void enableCallStateRecording() { recordCallStates_ = true; }

    void onStatement(const Stmt* stmt, const State& before,
                     const State& after, ASTContext& ctx) {
        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            checkCallContracts(call, before, ctx);
            if (recordCallStates_) atCall_[call] = before;
        }

        // Dataflow trace: record transitions to zero / possibly-zero
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState == ZeroState::Zero)
                recordEvent(stmt, var, ctx,
                            codeskeptic::MsgId::TraceAssignedZeroHere);
            else if (afterState == ZeroState::MaybeZero)
                recordEvent(stmt, var, ctx,
                            codeskeptic::MsgId::TraceAssignedMaybeZeroHere);
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

        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "div-by-zero";
        diag.function = funcName_;
        if (state == ZeroState::Zero) {
            diag.severity = codeskeptic::Severity::Error;
            diag.message = codeskeptic::msg(
                codeskeptic::MsgId::DivByZeroDefinite,
                var->getNameAsString());
        } else {
            diag.severity = codeskeptic::Severity::Warning;
            diag.message = codeskeptic::msg(
                codeskeptic::MsgId::DivByZeroMaybe,
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
    // Caller side of `requires n != 0` (CONTRACTS.md Round C). Only the
    // zero domain — NullDeref owns the non-null clauses. A literal 0
    // argument or a tracked variable in Zero state is a definite
    // violation; MaybeZero is a possible one. Anything the state cannot
    // decide stays silent — evidence-per-path, as everywhere else.
    void checkCallContracts(const CallExpr* call, const State& before,
                            ASTContext& ctx) {
        const FunctionDecl* callee = call->getDirectCallee();
        if (!callee) return;
        codeskeptic::ParsedContracts parsed =
            codeskeptic::allContractClausesForDecl(callee, ctx);
        if (parsed.clauses.empty()) return;
        auto req = codeskeptic::analyzeRequires(parsed, callee);

        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(call->getBeginLoc());
        const unsigned line = sm.getSpellingLineNumber(loc);

        for (const auto& info : req.enforced) {
            if (info.kind != codeskeptic::RequiresInfo::Kind::NonZeroParam)
                continue;
            if (info.paramIndex >= call->getNumArgs()) continue;
            const Expr* arg = call->getArg(info.paramIndex);

            bool definite = false;
            bool maybe = false;
            const VarDecl* var = nullptr;
            if (auto lit = codeskeptic::intLiteralArg(arg)) {
                definite = (*lit == 0);
            } else if ((var = getReferencedVar(arg))) {
                auto it = before.find(var);
                if (it != before.end()) {
                    definite = it->second == ZeroState::Zero;
                    maybe = it->second == ZeroState::MaybeZero;
                }
            }
            if (!definite && !maybe) continue;
            if (!reportedContracts_.insert({line, info.text}).second)
                continue;

            codeskeptic::Diagnostic diag;
            diag.file = sm.getFilename(loc).str();
            diag.line = line;
            diag.column = sm.getSpellingColumnNumber(loc);
            diag.rule_id = "contract";
            diag.function = funcName_;
            diag.severity = (definite && !info.machineProposed)
                                ? codeskeptic::Severity::Error
                                : codeskeptic::Severity::Warning;
            diag.message = codeskeptic::msg(
                codeskeptic::MsgId::ContractViolated, info.text);
            results_.push_back(std::move(diag));
            // Violation trace (Round D): why is the argument zero?
            if (var) noteTargets_.emplace_back(results_.size() - 1, var);
        }
    }

    void recordEvent(const Stmt* stmt, const VarDecl* var,
                     ASTContext& ctx, codeskeptic::MsgId msgId) {
        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        codeskeptic::TraceNote note;
        note.file = sm.getFilename(loc).str();
        note.line = sm.getSpellingLineNumber(loc);
        note.column = sm.getSpellingColumnNumber(loc);
        note.message = codeskeptic::msg(msgId, var->getNameAsString());

        auto& list = events_[var];
        for (const auto& existing : list)
            if (existing.line == note.line) return;
        list.push_back(std::move(note));
    }

    const std::set<const VarDecl*>& trackedVars_;
    std::string funcName_;
    codeskeptic::DiagnosticList& results_;
    std::set<unsigned>& reportedLines_;
    VarState initState_;
    std::map<const VarDecl*, std::vector<codeskeptic::TraceNote>> events_;
    std::vector<std::pair<size_t, const VarDecl*>> noteTargets_;
    std::set<std::pair<unsigned, std::string>> reportedContracts_;
    bool recordCallStates_ = false;
    std::map<const Stmt*, VarState> atCall_;
};

// --- Interprocedural param-zeroness (v0.4.2) ---
//
// The Juliet CWE369 "flow" slice: an untrusted value crosses a call
// boundary before the division (`data = atoi(buf); sink(data)` where
// sink does `100 / d`). The divisor's zeroness lives in the CALLER, so
// the intraprocedural pass sees an unconstrained parameter and stays
// silent. This pass bridges it, mirroring ParamIntervals exactly:
// only for INTERNAL-LINKAGE, address-not-taken callees (every caller
// visible), join the zeroness each call site passes.
//
// PRECISION INVARIANT: a parameter is seeded MaybeZero ONLY when a call
// site provably passes a possibly-zero value (an atoi/scanf/rand
// source, a literal 0, or a MaybeZero summary return). An Unknown
// argument NEVER manufactures MaybeZero — that is the same bar that
// keeps unguarded parameters from spamming warnings.
using ParamZeronessMap =
    std::map<const FunctionDecl*, std::vector<ZeroState>>;

const FunctionDecl* zeronessCandidate(const FunctionDecl* fn) {
    if (!fn) return nullptr;
    fn = fn->getCanonicalDecl();
    if (fn->isExternallyVisible()) return nullptr;
    return fn;
}

// Zeroness of a call argument as the caller passes it: a proven source
// (atoi/literal/summary) evaluates directly; a bare tracked variable
// reads the caller's state; everything else is Unknown.
ZeroState argZeroness(const Expr* arg, const VarState& callerState,
                      const ASTContext& ctx) {
    if (!arg) return ZeroState::Unknown;
    arg = unwrapZeroPassthrough(arg, ctx);
    ZeroState direct = evaluateAssignedValue(arg);
    if (direct != ZeroState::Unknown) return direct;
    if (const auto* var = getReferencedVar(arg)) {
        auto it = callerState.find(var);
        if (it != callerState.end()) return it->second;
    }
    return ZeroState::Unknown;
}

ParamZeronessMap buildParamZeroness(ASTContext& ctx) {
    struct TuV : RecursiveASTVisitor<TuV> {
        std::set<const FunctionDecl*> candidates;
        std::set<const FunctionDecl*> addressTaken;
        std::set<const Expr*> calleeRefs;
        std::vector<const FunctionDecl*> bodies;
        bool VisitFunctionDecl(FunctionDecl* fn) {
            if (fn->isThisDeclarationADefinition() && fn->hasBody()) {
                bodies.push_back(fn);
                if (const auto* c = zeronessCandidate(fn))
                    candidates.insert(c);
            }
            return true;
        }
        bool VisitCallExpr(CallExpr* call) {
            if (call->getDirectCallee())
                if (const auto* ref = dyn_cast<DeclRefExpr>(
                        call->getCallee()->IgnoreParenImpCasts()))
                    calleeRefs.insert(ref);
            return true;
        }
        bool VisitDeclRefExpr(DeclRefExpr* ref) {
            if (const auto* fn = dyn_cast<FunctionDecl>(ref->getDecl()))
                if (const auto* c = zeronessCandidate(fn))
                    if (!calleeRefs.count(ref)) addressTaken.insert(c);
            return true;
        }
    } v;
    v.TraverseDecl(ctx.getTranslationUnitDecl());

    std::set<const FunctionDecl*> tracked;
    for (const auto* fn : v.candidates)
        if (!v.addressTaken.count(fn)) tracked.insert(fn);
    if (tracked.empty()) return {};

    // Accumulator per (callee, param): sawZeroable / allNonZero / any.
    struct Acc { bool sawZeroable = false; bool allNonZero = true;
                 bool any = false; };
    std::map<const FunctionDecl*, std::vector<Acc>> acc;
    for (const auto* c : tracked)
        acc[c] = std::vector<Acc>(c->getNumParams());

    for (const auto* caller : v.bodies) {
        // Calls from this caller into a tracked callee.
        struct CallV : RecursiveASTVisitor<CallV> {
            const std::set<const FunctionDecl*>* tracked;
            std::vector<const CallExpr*> calls;
            bool VisitCallExpr(CallExpr* call) {
                if (const auto* c = zeronessCandidate(call->getDirectCallee()))
                    if (tracked->count(c)) calls.push_back(call);
                return true;
            }
        } cv;
        cv.tracked = &tracked;
        cv.TraverseStmt(caller->getBody());
        if (cv.calls.empty()) continue;

        // Track the argument variables so their zeroness is computed at
        // each call site (an atoi-assigned local, a guarded value, …).
        std::set<const VarDecl*> argVars;
        for (const auto* call : cv.calls)
            for (const Expr* a : call->arguments())
                if (const auto* var =
                        getReferencedVar(unwrapZeroPassthrough(a, ctx)))
                    argVars.insert(var);

        codeskeptic::DiagnosticList sink;   // discarded
        std::set<unsigned> sinkLines;
        DivByZeroAnalysis analysis(argVars, caller->getQualifiedNameAsString(),
                                   sink, sinkLines);
        analysis.enableCallStateRecording();
        codeskeptic::runDataflow(caller, ctx, analysis);

        for (const auto* call : cv.calls) {
            const FunctionDecl* callee =
                zeronessCandidate(call->getDirectCallee());
            auto it = acc.find(callee);
            if (it == acc.end()) continue;
            const VarState* st = analysis.stateAtCall(call);
            VarState empty;
            const VarState& state = st ? *st : empty;
            const unsigned nArgs = call->getNumArgs();
            for (unsigned i = 0; i < it->second.size(); ++i) {
                ZeroState z = (i < nArgs)
                    ? argZeroness(call->getArg(i), state, ctx)
                    : ZeroState::Unknown;
                Acc& a = it->second[i];
                a.any = true;
                if (z == ZeroState::Zero || z == ZeroState::MaybeZero)
                    a.sawZeroable = true;
                if (z != ZeroState::NonZero) a.allNonZero = false;
            }
        }
    }

    ParamZeronessMap out;
    for (const auto& [fn, accs] : acc) {
        std::vector<ZeroState> entry(accs.size(), ZeroState::Unknown);
        bool useful = false;
        for (size_t i = 0; i < accs.size(); ++i) {
            if (accs[i].sawZeroable) { entry[i] = ZeroState::MaybeZero;
                                       useful = true; }
        }
        if (useful) out[fn] = std::move(entry);
    }
    return out;
}

// --- Function-level analysis ---

void analyzeFunction(const FunctionDecl* funcDecl,
                     ASTContext& ctx,
                     codeskeptic::DiagnosticList& results,
                     const ParamZeronessMap& paramZeroness) {
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
                codeskeptic::Diagnostic diag;
                diag.severity = codeskeptic::Severity::Error;
                diag.file = sm.getFilename(loc).str();
                diag.line = line;
                diag.column = sm.getSpellingColumnNumber(loc);
                diag.rule_id = "div-by-zero";
                diag.function = funcDecl->getQualifiedNameAsString();
                diag.message = codeskeptic::msg(
                    codeskeptic::MsgId::DivByZeroLiteral);
                results.push_back(diag);
            }
        }
    }

    // Phase 2: Variable divisor analysis via DataflowEngine
    auto trackedVars = collectDivisorVars(funcDecl, ctx);
    const bool hasContractCalls = addContractArgVars(funcDecl, ctx,
                                                     trackedVars);
    if (trackedVars.empty() && !hasContractCalls) return;

    DivByZeroAnalysis analysis(
        trackedVars, funcDecl->getQualifiedNameAsString(), results,
        reportedLines);
    codeskeptic::ParsedContracts ownContracts =
        codeskeptic::allContractClausesForDecl(funcDecl, ctx);
    if (!ownContracts.clauses.empty()) {
        auto req = codeskeptic::analyzeRequires(ownContracts, funcDecl);
        analysis.seedRequires(funcDecl, req.enforced);
    }
    // Interprocedural seeding (v0.4.2): a parameter the callers provably
    // pass a possibly-zero value into starts MaybeZero, so an unguarded
    // division by it warns; a guard inside refines it back to NonZero.
    auto pz = paramZeroness.find(funcDecl->getCanonicalDecl());
    if (pz != paramZeroness.end()) {
        for (unsigned i = 0; i < funcDecl->getNumParams() &&
                             i < pz->second.size(); ++i)
            if (pz->second[i] == ZeroState::MaybeZero)
                analysis.seedParamMaybeZero(funcDecl->getParamDecl(i));
    }
    auto df = codeskeptic::runDataflow(funcDecl, ctx, analysis);
    if (!df.converged)
        codeskeptic::CoverageReport::instance().recordNonConvergence(
            funcDecl->getQualifiedNameAsString());
    analysis.attachTraces();
}

// --- Matcher callback ---

class DivByZeroCallback : public MatchFinder::MatchCallback {
public:
    DivByZeroCallback(codeskeptic::DiagnosticList& results,
                      const ParamZeronessMap& paramZeroness)
        : results_(results), paramZeroness_(paramZeroness) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;
        if (!codeskeptic::functionFilterAllows(*func)) return;
        if (!codeskeptic::lineFilterAllows(*func, sm)) return;

        analyzeFunction(func, *result.Context, results_, paramZeroness_);
    }

private:
    codeskeptic::DiagnosticList& results_;
    const ParamZeronessMap& paramZeroness_;
};

} // anonymous namespace

namespace codeskeptic {

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
    // Built once per TU: the interprocedural zeroness each internal
    // callee's parameters receive from their (fully visible) callers.
    ParamZeronessMap paramZeroness = buildParamZeroness(ctx);

    MatchFinder finder;
    DivByZeroCallback callback(results, paramZeroness);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace codeskeptic
