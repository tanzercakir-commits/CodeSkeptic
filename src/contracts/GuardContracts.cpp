#include "contracts/GuardContracts.h"

#include "engine/ConditionWalk.h"
#include "engine/FatalCalls.h"

#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/SourceManager.h>
#include <clang/AST/Stmt.h>

using namespace clang;

namespace {

// Does this statement (a guard's branch) provably NOT fall through to
// the code below — and how does it leave? Return semantics decide the
// consequence class: a branch that RETURNS rejects the call (the
// program lives on); a branch that reaches a noreturn/fatal call
// crashes/aborts. A branch doing neither (fallthrough) is NOT a guard.
enum class BranchExit { FallsThrough, Returns, Aborts };

BranchExit branchExit(const Stmt* s, int depth = 0);

// A call is noreturn if the callee says so — or if the callee's
// VISIBLE body provably never returns (its exit is Aborts). The
// transitive case is real: Carbon's CheckFail is `[[noreturn]]` only
// `#ifdef NDEBUG`, but in every build its body is a single call to
// the unconditionally-[[noreturn]] CheckFailFormat. Depth-capped so a
// mutual-recursion cycle of body-visible functions cannot loop us;
// beyond the cap we conservatively say "may return".
bool isNoreturnCall(const Stmt* s, int depth = 0) {
    const auto* call = dyn_cast_or_null<CallExpr>(s);
    if (!call) return false;
    if (zerodefect::isFatalCall(call)) return true;
    const FunctionDecl* callee = call->getDirectCallee();
    if (!callee) return false;
    if (callee->isNoReturn()) return true;
    const FunctionDecl* def = nullptr;
    if (depth >= 2 || !callee->hasBody(def)) return false;
    return branchExit(def->getBody(), depth + 1) == BranchExit::Aborts;
}

BranchExit branchExit(const Stmt* s, int depth) {
    if (!s) return BranchExit::FallsThrough;
    if (isa<ReturnStmt>(s)) return BranchExit::Returns;
    if (isa<CXXThrowExpr>(s)) return BranchExit::Aborts;  // leaves; guard
    if (isNoreturnCall(s, depth)) return BranchExit::Aborts;
    if (const auto* cs = dyn_cast<CompoundStmt>(s)) {
        // The ERR_FAIL expansion shape: `{ _err_print_error(...);
        // return m_retval; }` — the LAST statement decides; earlier
        // statements (prints, bookkeeping) are allowed but must not
        // themselves branch away invisibly, which plain expression
        // statements cannot.
        if (cs->body_empty()) return BranchExit::FallsThrough;
        return branchExit(cs->body_back(), depth);
    }
    if (const auto* expr = dyn_cast<Expr>(s))
        return isNoreturnCall(expr->IgnoreParenImpCasts(), depth)
                   ? BranchExit::Aborts
                   : BranchExit::FallsThrough;
    return BranchExit::FallsThrough;
}

// The single (param, mustBeNull) pair a guard condition talks about,
// or nullopt. v1 keys ONE parameter only: a compound condition
// (`!p && n > 0`) is skipped — its relational contract is v-next, and
// half-reading it would fabricate an unconditional requires the code
// does not enforce.
struct GuardCond {
    const ParmVarDecl* param = nullptr;
    bool firesWhenNull = false;  // guard triggers when param IS null
};

// Peel CHECK-macro wrappers off a guard condition. Carbon's
// CARBON_CHECK (the §6.16 "CHECK opacity" gap, easy half) hides the
// condition as `CheckCondition(true && (cond))`:
//  - an identity call — the callee's body is exactly `return <its
//    only param>;` (Carbon's CheckCondition exists only to diagnose
//    constant conditions) — is replaced by its argument. Only a
//    BODY-VISIBLE exact identity qualifies; a declared-only or
//    transforming wrapper stays opaque (sound: we never guess).
//  - a literal-true conjunct — `true && x` (inserted to force the
//    contextual bool conversion) — is replaced by x. Only a literal
//    `true` is stripped; a variable conjunct keeps the compound-
//    condition bail below in force.
const Expr* peelConditionWrappers(const Expr* e) {
    for (;;) {
        e = e->IgnoreParenImpCasts();
        if (const auto* call = dyn_cast<CallExpr>(e)) {
            const FunctionDecl* fd = call->getDirectCallee();
            const FunctionDecl* def = nullptr;
            if (fd && fd->hasBody(def) && call->getNumArgs() == 1 &&
                def->getNumParams() == 1) {
                if (const auto* body =
                        dyn_cast<CompoundStmt>(def->getBody());
                    body && body->size() == 1) {
                    if (const auto* ret =
                            dyn_cast<ReturnStmt>(body->body_front());
                        ret && ret->getRetValue()) {
                        const Expr* rv =
                            ret->getRetValue()->IgnoreParenImpCasts();
                        if (const auto* dre = dyn_cast<DeclRefExpr>(rv);
                            dre &&
                            dre->getDecl() == def->getParamDecl(0)) {
                            e = call->getArg(0);
                            continue;
                        }
                    }
                }
            }
        }
        if (const auto* bo = dyn_cast<BinaryOperator>(e);
            bo && bo->getOpcode() == BO_LAnd) {
            const Expr* lhs = bo->getLHS()->IgnoreParenImpCasts();
            if (const auto* bl = dyn_cast<CXXBoolLiteralExpr>(lhs);
                bl && bl->getValue()) {
                e = bo->getRHS();
                continue;
            }
        }
        return e;
    }
}

std::optional<GuardCond> singleParamNullCond(const Expr* cond,
                                             bool guardFiresOnTrue) {
    cond = peelConditionWrappers(cond);
    int hits = 0;
    GuardCond out;
    bool nonParamOrExtra = false;
    zerodefect::walkNullCondition(
        cond, guardFiresOnTrue,
        [&](const VarDecl* var, bool isNull) {
            const auto* p = dyn_cast<ParmVarDecl>(var);
            if (!p) { nonParamOrExtra = true; return; }
            ++hits;
            out.param = p;
            out.firesWhenNull = isNull;
        });
    if (nonParamOrExtra || hits != 1) return std::nullopt;
    // Deliberate conjunction check: walkNullCondition decomposes
    // `a && b` on its true edge into BOTH operands; a second operand
    // over a NON-pointer (n > 0) yields no callback, so `!p && n > 0`
    // arrives here as a clean single hit — which would be WRONG to
    // accept (the guard does not fire for p==null when n==0). Detect
    // any conjunction/disjunction structurally and bail.
    const Expr* e = cond->IgnoreParenImpCasts();
    e = zerodefect::stripBoolPreservingCasts(e);
    while (const auto* un = dyn_cast<UnaryOperator>(e)) {
        if (un->getOpcode() != UO_LNot) break;
        e = un->getSubExpr()->IgnoreParenImpCasts();
    }
    if (const auto* bo = dyn_cast<BinaryOperator>(e))
        if (bo->getOpcode() == BO_LAnd || bo->getOpcode() == BO_LOr)
            return std::nullopt;
    return out;
}

// A guard that merely RETURNS is only contract evidence when it
// COMPLAINS first. The cJSON lesson (corpus pin, 53 -> 88): a silent
// early return — `if (item == NULL) return false;` in the cJSON_Is*
// predicates, or InitHooks' reset-to-defaults-then-return — is a
// null-TOLERANT API: null is a documented input with a defined answer,
// and callers (their tests!) pass it deliberately. The ERR_FAIL shape
// that motivated the Rejected class complains before refusing
// (`{ _err_print_error(...); return ret; }`): the error-report call is
// the author saying "this is a caller bug". So: at least one
// expression-statement CALL before the terminal return. Assignments
// (InitHooks) and bare returns (cJSON_Is*) do not qualify; a branch
// whose only call is inside the return value (`return make_default();`)
// is alternative work, not a complaint, and does not qualify either.
bool complainsBeforeReturn(const Stmt* s) {
    const auto* cs = dyn_cast<CompoundStmt>(s);
    if (!cs || cs->body_empty()) return false;  // `return X;` — silent
    for (const Stmt* b : cs->body()) {
        if (b == cs->body_back()) break;  // the return itself
        const auto* e = dyn_cast<Expr>(b);
        if (!e) continue;
        if (isa<CallExpr>(e->IgnoreImplicit()->IgnoreParenImpCasts()))
            return true;
    }
    return false;
}

unsigned lineOf(const Stmt* s, ASTContext& ctx) {
    const SourceManager& sm = ctx.getSourceManager();
    return sm.getSpellingLineNumber(sm.getExpansionLoc(s->getBeginLoc()));
}

// glibc's C++ assert: `static_cast<bool>(cond) ? void(0) :
// __assert_fail(...)` as a top-level expression statement. The C
// statement-expression variant materializes as an IfStmt and is caught
// by the if-guard path below.
std::optional<zerodefect::GuardRequire> matchAssertTernary(
        const Stmt* s, const FunctionDecl* fn, ASTContext& ctx) {
    const auto* expr = dyn_cast<Expr>(s);
    if (!expr) return std::nullopt;
    const Expr* e = expr->IgnoreParenImpCasts();
    const auto* co = dyn_cast<AbstractConditionalOperator>(e);
    if (!co) return std::nullopt;
    if (branchExit(co->getFalseExpr()->IgnoreParenImpCasts()) !=
        BranchExit::Aborts)
        return std::nullopt;
    // assert(EXPR): the process survives only when EXPR is TRUE, so
    // walk the condition's TRUE edge; the guard "fires" when the
    // condition FAILS — i.e. we need (param, isNull=false) on true.
    auto gc = singleParamNullCond(co->getCond(), /*guardFiresOnTrue=*/true);
    if (!gc || gc->firesWhenNull) return std::nullopt;
    unsigned idx = 0;
    for (const ParmVarDecl* p : fn->parameters()) {
        if (p == gc->param)
            return zerodefect::GuardRequire{
                idx, zerodefect::GuardConsequence::Crash, lineOf(s, ctx)};
        ++idx;
    }
    return std::nullopt;
}

std::optional<zerodefect::GuardRequire> matchIfGuard(
        const Stmt* s, const FunctionDecl* fn, ASTContext& ctx) {
    const auto* ifs = dyn_cast<IfStmt>(s);
    if (!ifs || ifs->getElse() || ifs->getConditionVariable() ||
        ifs->getInit())
        return std::nullopt;
    const BranchExit exit = branchExit(ifs->getThen());
    if (exit == BranchExit::FallsThrough) return std::nullopt;
    if (exit == BranchExit::Returns &&
        !complainsBeforeReturn(ifs->getThen()))
        return std::nullopt;  // silent return = null-tolerant API
    // `if (COND) <leave>;` — the guard fires when COND is TRUE, so the
    // surviving path has COND false. We need the guard to fire exactly
    // when the parameter IS null: (param, isNull=true) on true.
    auto gc = singleParamNullCond(ifs->getCond(), /*guardFiresOnTrue=*/true);
    if (!gc || !gc->firesWhenNull) return std::nullopt;
    unsigned idx = 0;
    for (const ParmVarDecl* p : fn->parameters()) {
        if (p == gc->param)
            return zerodefect::GuardRequire{
                idx,
                exit == BranchExit::Aborts
                    ? zerodefect::GuardConsequence::Crash
                    : zerodefect::GuardConsequence::Rejected,
                lineOf(s, ctx)};
        ++idx;
    }
    return std::nullopt;
}

// Does the parameter get REASSIGNED or address-taken anywhere in the
// body? Then the guard's promise does not survive to later uses in a
// form a CALL-SITE check may rely on... actually the call-site check
// asks only about the ENTRY value, which the guard tests before any
// reassignment (we only scan leading statements). Reassignment is
// irrelevant to the caller-side question; no ban needed.

} // anonymous namespace

namespace zerodefect {

std::vector<GuardRequire> inferGuardRequires(const FunctionDecl* fn,
                                             ASTContext& ctx) {
    std::vector<GuardRequire> out;
    if (!fn || !fn->hasBody()) return out;
    const auto* body = dyn_cast_or_null<CompoundStmt>(fn->getBody());
    if (!body) return out;

    // Leading-statement scan: guards count only BEFORE any other work.
    // A DeclStmt whose initializer does not dereference anything is
    // tolerated between guards (the `Variant ret;` shape); the first
    // real statement ends the entry region. This keeps the claim
    // honest: a guard after arbitrary code might sit below an earlier
    // dereference of the same parameter, and lifting it would claim a
    // precondition the function does not actually enforce at entry.
    for (const Stmt* s : body->body()) {
        if (auto g = matchIfGuard(s, fn, ctx)) {
            out.push_back(*g);
            continue;
        }
        if (auto g = matchAssertTernary(s, fn, ctx)) {
            out.push_back(*g);
            continue;
        }
        if (isa<DeclStmt>(s)) continue;  // local decls between guards
        break;  // first non-guard statement ends the entry region
    }
    return out;
}

} // namespace zerodefect
