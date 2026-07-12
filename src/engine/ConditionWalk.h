#ifndef ZERODEFECT_CONDITION_WALK_H
#define ZERODEFECT_CONDITION_WALK_H

// Condition-walk skeleton: the shared backbone of ALL analyses that
// extract edge information from branch conditions. The structure is
// the same in every domain:
//   - `!c`     : descend into the opposite edge
//   - `a && b` : on the TRUE edge both sides are true
//   - `a || b` : on the FALSE edge both sides are false
//   - truthiness (`if (x)`) and binary comparisons → callback
// The domain-specific reading (pointer nullness, integer zeroness,
// path-fact) lives in the callbacks. In comparisons, whichever side
// the variable is on, the operator is MIRRORED so the variable is on
// the left — clients think in one direction only.
//
// walkNullCondition: the ready-made digest of the pointer-nullness
// domain — the shared walk of three users (NullDerefRule,
// MemoryLeakRule, FunctionSummary). setNull(var, isNullOnEdge) is
// called in both directions; a client that only cares about the null
// edge (MemLeak) ignores the other.

#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/OperationKinds.h>

#include <utility>

namespace zerodefect {

namespace condwalk_detail {

inline const clang::VarDecl* asVar(const clang::Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    // An assignment inside a condition tests the just-assigned value
    // of its LHS — the classic C idiom `if ((p = alloc()) == NULL)`,
    // `while ((e = next()) != NULL)`, `!(page = git__malloc(n))`.
    // Refining the LHS variable on the edges is exactly right; without
    // this look-through the guard is invisible and every use after it
    // warns (the dominant libgit2 false-positive family, 2026-07-12).
    // isAssignmentOp covers compound forms too (`(n -= 1) == 0`).
    while (const auto* bin = llvm::dyn_cast<clang::BinaryOperator>(expr)) {
        if (!bin->isAssignmentOp()) break;
        expr = bin->getLHS()->IgnoreParenImpCasts();
    }
    if (const auto* ref = llvm::dyn_cast<clang::DeclRefExpr>(expr))
        return llvm::dyn_cast<clang::VarDecl>(ref->getDecl());
    return nullptr;
}

inline bool isNullLiteral(const clang::Expr* expr) {
    if (!expr) return false;
    expr = expr->IgnoreParenCasts();
    if (llvm::isa<clang::CXXNullPtrLiteralExpr>(expr) ||
        llvm::isa<clang::GNUNullExpr>(expr))
        return true;
    if (const auto* lit = llvm::dyn_cast<clang::IntegerLiteral>(expr))
        return lit->getValue() == 0;
    return false;
}

// Zeroness of an integer constant: IntegerLiteral (+ unary minus
// chain). Three values: 1 = surely zero, 0 = surely non-zero,
// -1 = not a constant.
inline int zeroLiteralState(const clang::Expr* expr) {
    if (!expr) return -1;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* lit = llvm::dyn_cast<clang::IntegerLiteral>(expr))
        return lit->getValue() == 0 ? 1 : 0;
    if (const auto* unary = llvm::dyn_cast<clang::UnaryOperator>(expr)) {
        if (unary->getOpcode() == clang::UO_Minus)
            return zeroLiteralState(unary->getSubExpr());
    }
    return -1;
}

inline clang::BinaryOperatorKind mirror(clang::BinaryOperatorKind opc) {
    switch (opc) {
        case clang::BO_LT: return clang::BO_GT;
        case clang::BO_GT: return clang::BO_LT;
        case clang::BO_LE: return clang::BO_GE;
        case clang::BO_GE: return clang::BO_LE;
        default: return opc;  // EQ/NE are symmetric
    }
}

} // namespace condwalk_detail

// The general skeleton. onTruth(var, isTrue): the `if (x)` form.
// onCompare(var, opc, other, isTrue): the `x OPC other` form; opc is
// always normalized variable-on-left, other is the opposite side.
template <typename TruthFn, typename CompareFn>
void walkCondition(const clang::Expr* cond, bool isTrue,
                   TruthFn&& onTruth, CompareFn&& onCompare) {
    namespace d = condwalk_detail;
    if (!cond) return;
    cond = cond->IgnoreParenImpCasts();

    // __builtin_expect(x, c) is branch-semantics-transparent: real-world
    // likely()/unlikely() macros (absl ABSL_PREDICT_*, the Linux kernel)
    // wrap REAL conditions in it. Without looking through it the edge
    // refinement is lost — worse, the short-circuit value blocks INSIDE
    // the call still refine, so a "null" fact born there leaks past the
    // un-refined if-edge (the abseil ABSL_RAW_CHECK false-positive
    // family, 2026-07-12).
    if (const auto* call = llvm::dyn_cast<clang::CallExpr>(cond)) {
        if (const auto* callee = call->getDirectCallee()) {
            if (const auto* id = callee->getIdentifier()) {
                const llvm::StringRef name = id->getName();
                if ((name == "__builtin_expect" ||
                     name == "__builtin_expect_with_probability") &&
                    call->getNumArgs() >= 1) {
                    walkCondition(call->getArg(0), isTrue,
                                  std::forward<TruthFn>(onTruth),
                                  std::forward<CompareFn>(onCompare));
                    return;
                }
            }
        }
    }

    if (const clang::VarDecl* var = d::asVar(cond)) {
        onTruth(var, isTrue);
        return;
    }
    if (const auto* unary = llvm::dyn_cast<clang::UnaryOperator>(cond)) {
        if (unary->getOpcode() == clang::UO_LNot)
            walkCondition(unary->getSubExpr(), !isTrue, onTruth, onCompare);
        return;
    }
    const auto* binOp = llvm::dyn_cast<clang::BinaryOperator>(cond);
    if (!binOp) return;
    const clang::BinaryOperatorKind opc = binOp->getOpcode();

    if (opc == clang::BO_LAnd) {
        if (isTrue) {
            walkCondition(binOp->getLHS(), true, onTruth, onCompare);
            walkCondition(binOp->getRHS(), true, onTruth, onCompare);
        }
        return;
    }
    if (opc == clang::BO_LOr) {
        if (!isTrue) {
            walkCondition(binOp->getLHS(), false, onTruth, onCompare);
            walkCondition(binOp->getRHS(), false, onTruth, onCompare);
        }
        return;
    }
    if (!binOp->isComparisonOp()) return;

    const clang::Expr* lhs = binOp->getLHS()->IgnoreParenImpCasts();
    const clang::Expr* rhs = binOp->getRHS()->IgnoreParenImpCasts();
    // Both sides get a callback when both are variables (`i < end`
    // informs about i AND end); clients filter what they can't use.
    const clang::VarDecl* lhsVar = d::asVar(lhs);
    const clang::VarDecl* rhsVar = d::asVar(rhs);
    if (lhsVar) onCompare(lhsVar, opc, rhs, isTrue);
    if (rhsVar && rhsVar != lhsVar) onCompare(rhsVar, d::mirror(opc), lhs, isTrue);
}

// Pointer-nullness domain: setNull(var, isNullOnEdge) — the fact that
// on this edge var is surely null (true) or surely non-null (false).
// Pointer-typed variables; null-literal equality comparisons; and
// pointer-pointer relational comparisons (see below).
template <typename SetNullFn>
void walkNullCondition(const clang::Expr* cond, bool isTrue,
                       SetNullFn&& setNull) {
    namespace d = condwalk_detail;
    walkCondition(
        cond, isTrue,
        [&](const clang::VarDecl* var, bool truthy) {
            if (var->getType()->isPointerType())
                setNull(var, !truthy);  // `if (p)` true → non-null
        },
        [&](const clang::VarDecl* var, clang::BinaryOperatorKind opc,
            const clang::Expr* other, bool edgeTrue) {
            if (!var->getType()->isPointerType()) return;

            // Relational pointer comparison: C11 6.5.8p5 defines
            // `p < q` only when both point into (one past the end of)
            // the same object — which a null pointer never does. So
            // EVALUATING the comparison proves both operands non-null,
            // on BOTH edges; the result direction carries no nullness
            // information at all. This is the FOREACH_ARRAY family
            // (systemd, 235 of 302 null findings): in
            // `end && i < end` the truthiness conjunct refines only
            // `end`; `i` is proven by this rule.
            if (opc == clang::BO_LT || opc == clang::BO_GT ||
                opc == clang::BO_LE || opc == clang::BO_GE) {
                const clang::Expr* o = other->IgnoreParenImpCasts();
                if (!o->getType()->isPointerType()) return;
                if (d::isNullLiteral(o)) return;
                setNull(var, false);
                return;
            }

            if (opc != clang::BO_EQ && opc != clang::BO_NE) return;
            if (!d::isNullLiteral(other)) return;
            bool eqHolds = (opc == clang::BO_EQ) == edgeTrue;
            setNull(var, eqHolds);
        });
}

// Integer-zeroness domain: setZero(var, isZeroOnEdge) — the fact that
// on this edge var is surely zero (true) or surely non-zero (false).
// Supported patterns: truthiness, ==/!= (with zero and non-zero
// constants), orderings against the zero constant (the direction
// where the inequality excludes zero). Two clients: DivByZeroRule
// (edge refinement) and FunctionSummary's zeroness mini-flow.
template <typename SetZeroFn>
void walkZeroCondition(const clang::Expr* cond, bool isTrue,
                       SetZeroFn&& setZero) {
    namespace d = condwalk_detail;
    walkCondition(
        cond, isTrue,
        [&](const clang::VarDecl* var, bool truthy) {
            setZero(var, !truthy);  // `if (z)` true → non-zero
        },
        [&](const clang::VarDecl* var, clang::BinaryOperatorKind opc,
            const clang::Expr* other, bool edgeTrue) {
            const int lit = d::zeroLiteralState(other);

            if (opc == clang::BO_EQ || opc == clang::BO_NE) {
                // `z == 0` true → Zero; `z != 0` true → NonZero
                // (inverted on false edges). Equality with a non-zero
                // constant, if it holds → NonZero; if not, no info.
                const bool eqHolds = (opc == clang::BO_EQ) == edgeTrue;
                if (lit == 1)
                    setZero(var, eqHolds);
                else if (lit == 0 && eqHolds)
                    setZero(var, false);
                return;
            }

            // Orderings only against the zero constant (opc variable-on-left)
            if (lit != 1) return;
            switch (opc) {
                case clang::BO_GT:  // z > 0
                case clang::BO_LT:  // z < 0
                    if (edgeTrue) setZero(var, false);
                    break;
                case clang::BO_GE:  // z >= 0: if false then z < 0
                case clang::BO_LE:  // z <= 0: if false then z > 0
                    if (!edgeTrue) setZero(var, false);
                    break;
                default:
                    break;
            }
        });
}

} // namespace zerodefect

#endif // ZERODEFECT_CONDITION_WALK_H
