#ifndef ZERODEFECT_CONDITION_WALK_H
#define ZERODEFECT_CONDITION_WALK_H

// Kosul-yuruyusu iskeleti: dallanma kosullarindan kenar-bilgisi cikaran
// TUM analizlerin ortak omurgasi. Yapi her domain'de ayni:
//   - `!c`     : ters kenara in
//   - `a && b` : DOGRU kenarda iki taraf da dogru
//   - `a || b` : YANLIS kenarda iki taraf da yanlis
//   - truthiness (`if (x)`) ve ikili karsilastirmalar → callback
// Domain'e ozgu yorum (pointer nullness, tamsayi sifirligi, path-fact)
// callback'lerde yasar. Karsilastirmalarda degisken hangi taraftaysa
// operator degisken-solda olacak sekilde AYNALANIR — istemciler tek
// yonu dusunur.
//
// walkNullCondition: pointer-nullness domain'inin hazir ozeti — uc
// kullanicinin (NullDerefRule, MemoryLeakRule, FunctionSummary) ortak
// yuruyusu. setNull(var, isNullOnEdge) iki yonde de cagrilir; yalnizca
// null kenariyla ilgilenen istemci (MemLeak) digerini yok sayar.

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

// Tamsayi sabitinin sifirligi: IntegerLiteral (+ unary eksi zinciri).
// Uc deger: 1 = kesin sifir, 0 = kesin sifir-degil, -1 = sabit degil.
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
        default: return opc;  // EQ/NE simetrik
    }
}

} // namespace condwalk_detail

// Genel iskelet. onTruth(var, isTrue): `if (x)` bicimi.
// onCompare(var, opc, other, isTrue): `x OPC other` bicimi; opc her
// zaman degisken-solda normalize edilmistir, other karsi taraftir.
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

// Pointer-nullness domain'i: setNull(var, isNullOnEdge) — bu kenarda
// var'in kesin null (true) ya da kesin non-null (false) oldugu bilgisi.
// Yalnizca pointer tipli degiskenler ve null-literal karsilastirmalari.
template <typename SetNullFn>
void walkNullCondition(const clang::Expr* cond, bool isTrue,
                       SetNullFn&& setNull) {
    namespace d = condwalk_detail;
    walkCondition(
        cond, isTrue,
        [&](const clang::VarDecl* var, bool truthy) {
            if (var->getType()->isPointerType())
                setNull(var, !truthy);  // `if (p)` dogru → non-null
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

// Tamsayi-sifirlik domain'i: setZero(var, isZeroOnEdge) — bu kenarda
// var'in kesin sifir (true) ya da kesin sifir-degil (false) oldugu
// bilgisi. Desteklenen kaliplar: truthiness, ==/!= (sifir ve sifir
// olmayan sabit), sifir sabitiyle siralamalar (esitsizligin sifiri
// disladigi yon). Iki istemci: DivByZeroRule (kenar iyilestirmesi) ve
// FunctionSummary'nin sifirlik mini-akisi.
template <typename SetZeroFn>
void walkZeroCondition(const clang::Expr* cond, bool isTrue,
                       SetZeroFn&& setZero) {
    namespace d = condwalk_detail;
    walkCondition(
        cond, isTrue,
        [&](const clang::VarDecl* var, bool truthy) {
            setZero(var, !truthy);  // `if (z)` dogru → sifir-degil
        },
        [&](const clang::VarDecl* var, clang::BinaryOperatorKind opc,
            const clang::Expr* other, bool edgeTrue) {
            const int lit = d::zeroLiteralState(other);

            if (opc == clang::BO_EQ || opc == clang::BO_NE) {
                // `z == 0` dogru → Zero; `z != 0` dogru → NonZero
                // (yanlislarda tersi). Sifir olmayan sabitle esitlik
                // tutuyorsa → NonZero; tutmuyorsa bilgi yok.
                const bool eqHolds = (opc == clang::BO_EQ) == edgeTrue;
                if (lit == 1)
                    setZero(var, eqHolds);
                else if (lit == 0 && eqHolds)
                    setZero(var, false);
                return;
            }

            // Siralamalar yalnizca sifir sabitiyle (opc degisken-solda)
            if (lit != 1) return;
            switch (opc) {
                case clang::BO_GT:  // z > 0
                case clang::BO_LT:  // z < 0
                    if (edgeTrue) setZero(var, false);
                    break;
                case clang::BO_GE:  // z >= 0: yanlis ise z < 0
                case clang::BO_LE:  // z <= 0: yanlis ise z > 0
                    if (!edgeTrue) setZero(var, false);
                    break;
                default:
                    break;
            }
        });
}

} // namespace zerodefect

#endif // ZERODEFECT_CONDITION_WALK_H
