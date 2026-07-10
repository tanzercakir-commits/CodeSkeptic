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
    if (const clang::VarDecl* var = d::asVar(lhs)) {
        onCompare(var, opc, rhs, isTrue);
        return;
    }
    if (const clang::VarDecl* var = d::asVar(rhs)) {
        onCompare(var, d::mirror(opc), lhs, isTrue);
    }
}

// Pointer-nullness domain: setNull(var, isNullOnEdge) — the fact that
// on this edge var is surely null (true) or surely non-null (false).
// Only pointer-typed variables and null-literal comparisons.
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
            if (opc != clang::BO_EQ && opc != clang::BO_NE) return;
            if (!var->getType()->isPointerType()) return;
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
