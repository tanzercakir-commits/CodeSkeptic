#include "engine/PathFacts.h"

#include <clang/AST/RecursiveASTVisitor.h>

using namespace clang;

namespace {

// Tamsayi sabiti degerlendir: literal veya -literal. EvaluateAsInt
// KULLANILMAZ: const global degiskenler (GLOBAL_CONST_FIVE) sabit
// katlanabilirdi ama onlar zaten DeclRef tarafinda anahtarlaniyor.
std::optional<int64_t> intLiteralValue(const Expr* expr) {
    if (!expr) return std::nullopt;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr)) {
        // 64-bit'e sigmayan literaller (pratikte gorulmez) atlanir
        if (lit->getValue().getSignificantBits() > 64) return std::nullopt;
        return lit->getValue().getSExtValue();
    }
    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() == UO_Minus) {
            if (auto v = intLiteralValue(unary->getSubExpr())) return -*v;
        }
    }
    return std::nullopt;
}

const ValueDecl* stableDeclRef(
        const Expr* expr,
        const std::set<const ValueDecl*>& mutated) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    const auto* ref = dyn_cast<DeclRefExpr>(expr);
    if (!ref) return nullptr;
    const auto* vd = dyn_cast<VarDecl>(ref->getDecl());
    // Yalnizca degiskenler (fonksiyon cagrisi/enum sabiti degil) ve
    // yalnizca tamsayi tipliler: pointer truthiness'i null-refinement'in
    // isi, onunla cakismayalim.
    if (!vd || !vd->getType()->isIntegerType()) return nullptr;
    if (vd->getType().isVolatileQualified()) return nullptr;  // her okuma degisebilir
    if (mutated.count(vd)) return nullptr;
    return vd;
}

// (var REL lit) formunu EQ/LT/LE tabanina indirger. `holds`: kosul dogru
// oldugunda anahtarin degeri.
std::optional<std::pair<zerodefect::FactKey, bool>> normalizeCompare(
        const ValueDecl* var, BinaryOperatorKind opc, int64_t lit,
        bool varOnLeft) {
    using K = zerodefect::FactKey;
    if (!varOnLeft) {
        // "lit OP var" -> operatoru aynala: 5 < X  ≡  X > 5
        switch (opc) {
            case BO_LT: opc = BO_GT; break;
            case BO_GT: opc = BO_LT; break;
            case BO_LE: opc = BO_GE; break;
            case BO_GE: opc = BO_LE; break;
            default: break;  // EQ/NE simetrik
        }
    }
    switch (opc) {
        case BO_EQ: return {{K{var, BO_EQ, lit}, true}};
        case BO_NE: return {{K{var, BO_EQ, lit}, false}};
        case BO_LT: return {{K{var, BO_LT, lit}, true}};
        case BO_GE: return {{K{var, BO_LT, lit}, false}};
        case BO_LE: return {{K{var, BO_LE, lit}, true}};
        case BO_GT: return {{K{var, BO_LE, lit}, false}};
        default: return std::nullopt;
    }
}

class MutatedDeclCollector
    : public RecursiveASTVisitor<MutatedDeclCollector> {
public:
    std::set<const ValueDecl*> mutated;

    bool VisitBinaryOperator(BinaryOperator* op) {
        if (op->isAssignmentOp()) record(op->getLHS());
        return true;
    }
    bool VisitUnaryOperator(UnaryOperator* op) {
        if (op->isIncrementDecrementOp() || op->getOpcode() == UO_AddrOf)
            record(op->getSubExpr());
        return true;
    }

private:
    void record(const Expr* expr) {
        if (!expr) return;
        expr = expr->IgnoreParenImpCasts();
        if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
            mutated.insert(ref->getDecl());
    }
};

} // anonymous namespace

namespace zerodefect {

std::optional<std::pair<FactKey, bool>> conditionFact(
        const Expr* cond,
        const std::set<const ValueDecl*>& mutated) {
    if (!cond) return std::nullopt;
    cond = cond->IgnoreParenImpCasts();

    // if (X): truthiness  ≡  (X == 0) yanlis
    if (const ValueDecl* var = stableDeclRef(cond, mutated))
        return {{FactKey{var, BO_EQ, 0}, false}};

    if (const auto* unary = dyn_cast<UnaryOperator>(cond)) {
        if (unary->getOpcode() == UO_LNot) {
            auto fact = conditionFact(unary->getSubExpr(), mutated);
            if (fact) fact->second = !fact->second;
            return fact;
        }
        return std::nullopt;
    }

    const auto* binOp = dyn_cast<BinaryOperator>(cond);
    if (!binOp) return std::nullopt;
    const BinaryOperatorKind opc = binOp->getOpcode();
    if (opc != BO_EQ && opc != BO_NE && opc != BO_LT && opc != BO_GT &&
        opc != BO_LE && opc != BO_GE)
        return std::nullopt;

    const Expr* lhs = binOp->getLHS();
    const Expr* rhs = binOp->getRHS();
    if (const ValueDecl* var = stableDeclRef(lhs, mutated)) {
        if (auto lit = intLiteralValue(rhs))
            return normalizeCompare(var, opc, *lit, /*varOnLeft=*/true);
        return std::nullopt;
    }
    if (const ValueDecl* var = stableDeclRef(rhs, mutated)) {
        if (auto lit = intLiteralValue(lhs))
            return normalizeCompare(var, opc, *lit, /*varOnLeft=*/false);
    }
    return std::nullopt;
}

std::set<const ValueDecl*> collectMutatedDecls(const FunctionDecl* func) {
    MutatedDeclCollector collector;
    if (func && func->hasBody())
        collector.TraverseStmt(func->getBody());
    return std::move(collector.mutated);
}

} // namespace zerodefect
