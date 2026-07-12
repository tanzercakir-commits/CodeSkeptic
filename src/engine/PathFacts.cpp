#include "engine/PathFacts.h"

#include <clang/AST/RecursiveASTVisitor.h>

using namespace clang;

namespace {

// Evaluate an integer constant: literal or -literal. EvaluateAsInt is
// NOT used: const global variables (GLOBAL_CONST_FIVE) could have
// been constant-folded, but those are already keyed on the DeclRef side.
std::optional<int64_t> intLiteralValue(const Expr* expr) {
    if (!expr) return std::nullopt;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr)) {
        // Literals that do not fit 64 bits (unseen in practice) are skipped
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

// A direct zero-argument call whose entire visible body is
// `return <integer literal>;` is as invariant as a const variable —
// the function CANNOT return anything else, so keying the condition
// on the callee is sound (no purity guess involved). This is the
// Juliet flow-variant shape (`static int staticReturnsTrue()
// { return 1; }`) that produced ~24 realloc-family FPs once the
// realloc coverage gap closed (2026-07-12). Anything weaker — extern
// declarations (rand()), bodies reading globals — stays unkeyed.
const FunctionDecl* constReturningCallee(const Expr* expr) {
    const auto* call = dyn_cast<CallExpr>(expr);
    if (!call || call->getNumArgs() != 0) return nullptr;
    const FunctionDecl* callee = call->getDirectCallee();
    if (!callee) return nullptr;
    const FunctionDecl* def = nullptr;
    if (!callee->hasBody(def) || !def) return nullptr;
    const auto* body = dyn_cast<CompoundStmt>(def->getBody());
    if (!body || body->size() != 1) return nullptr;
    const auto* ret = dyn_cast<ReturnStmt>(body->body_front());
    if (!ret) return nullptr;
    if (!intLiteralValue(ret->getRetValue())) return nullptr;
    return def->getCanonicalDecl();
}

const ValueDecl* stableDeclRef(
        const Expr* expr,
        const std::set<const ValueDecl*>& mutated) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    const auto* ref = dyn_cast<DeclRefExpr>(expr);
    if (!ref) return nullptr;
    const auto* vd = dyn_cast<VarDecl>(ref->getDecl());
    // Only variables (not function calls/enum constants) and only
    // integer-typed ones: pointer truthiness is null-refinement's
    // job, let's not clash with it.
    if (!vd || !vd->getType()->isIntegerType()) return nullptr;
    if (vd->getType().isVolatileQualified()) return nullptr;  // every read may differ
    if (mutated.count(vd)) return nullptr;
    return vd;
}

// Reduces the (var REL lit) form to the EQ/LT/LE base. `holds`: the
// key's value when the condition is true.
std::optional<std::pair<zerodefect::FactKey, bool>> normalizeCompare(
        const ValueDecl* var, BinaryOperatorKind opc, int64_t lit,
        bool varOnLeft) {
    using K = zerodefect::FactKey;
    if (!varOnLeft) {
        // "lit OP var" -> mirror the operator: 5 < X  ≡  X > 5
        switch (opc) {
            case BO_LT: opc = BO_GT; break;
            case BO_GT: opc = BO_LT; break;
            case BO_LE: opc = BO_GE; break;
            case BO_GE: opc = BO_LE; break;
            default: break;  // EQ/NE are symmetric
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

    // if (X): truthiness  ≡  (X == 0) is false
    if (const ValueDecl* var = stableDeclRef(cond, mutated))
        return {{FactKey{var, BO_EQ, 0}, false}};

    // if (f()): constant-returning helpers key on the callee
    // (FunctionDecl is a ValueDecl — the key structure is unchanged)
    if (const FunctionDecl* callee = constReturningCallee(cond))
        return {{FactKey{callee, BO_EQ, 0}, false}};

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
