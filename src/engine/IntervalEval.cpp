#include "engine/IntervalEval.h"

#include "engine/CallRefArgs.h"
#include "engine/ConditionWalk.h"

#include <clang/AST/Stmt.h>
#include <cstdint>
#include <optional>

using namespace clang;

namespace zerodefect {

namespace {

const VarDecl* asIntVar(const Expr* e) {
    if (!e) return nullptr;
    e = e->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(e))
        if (const auto* vd = dyn_cast<VarDecl>(ref->getDecl()))
            if (vd->getType()->isIntegerType()) return vd;
    return nullptr;
}

std::optional<int64_t> constInt(const Expr* e) {
    if (!e) return std::nullopt;
    e = e->IgnoreParenImpCasts();
    if (const auto* lit = dyn_cast<IntegerLiteral>(e)) {
        if (lit->getValue().getSignificantBits() > 63) return std::nullopt;
        return lit->getValue().getSExtValue();
    }
    if (const auto* u = dyn_cast<UnaryOperator>(e))
        if (u->getOpcode() == UO_Minus)
            if (auto v = constInt(u->getSubExpr())) return -*v;
    return std::nullopt;
}

// Negation of a comparison operator (for the false edge).
BinaryOperatorKind negateCmp(BinaryOperatorKind op) {
    switch (op) {
        case BO_LT: return BO_GE;
        case BO_LE: return BO_GT;
        case BO_GT: return BO_LE;
        case BO_GE: return BO_LT;
        case BO_EQ: return BO_NE;
        case BO_NE: return BO_EQ;
        default:    return op;
    }
}

Interval constrainBy(const Interval& iv, BinaryOperatorKind op, int64_t c) {
    switch (op) {
        case BO_LT: return iv.constrainLt(c);
        case BO_LE: return iv.constrainLe(c);
        case BO_GT: return iv.constrainGt(c);
        case BO_GE: return iv.constrainGe(c);
        case BO_EQ: return iv.constrainEq(c);
        case BO_NE: return iv.constrainNe(c);
        default:    return iv;
    }
}

} // namespace

Interval evalInterval(const Expr* expr, const IntervalMap& state) {
    if (!expr) return Interval::top();
    expr = expr->IgnoreParens();

    // Casts: only the value-preserving ones are transparent. A narrowing
    // integral cast can WRAP (`(char)300 == 44`), so its value set is
    // not a subset of the source's — passing it through would be
    // UNSOUND (miss values). Anything but an lvalue-load / no-op → top.
    if (const auto* cast = dyn_cast<ImplicitCastExpr>(expr)) {
        if (cast->getCastKind() == CK_LValueToRValue ||
            cast->getCastKind() == CK_NoOp)
            return evalInterval(cast->getSubExpr(), state);
        return Interval::top();
    }

    if (const auto* lit = dyn_cast<IntegerLiteral>(expr)) {
        if (lit->getValue().getSignificantBits() > 63) return Interval::top();
        return Interval::constant(lit->getValue().getSExtValue());
    }
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) {
        if (const auto* vd = dyn_cast<VarDecl>(ref->getDecl())) {
            auto it = state.find(vd);
            if (it != state.end()) return it->second;
        }
        return Interval::top();
    }
    if (const auto* u = dyn_cast<UnaryOperator>(expr)) {
        if (u->getOpcode() == UO_Minus)
            return Interval::negate(evalInterval(u->getSubExpr(), state));
        if (u->getOpcode() == UO_Plus)
            return evalInterval(u->getSubExpr(), state);
        return Interval::top();
    }
    if (const auto* bin = dyn_cast<BinaryOperator>(expr)) {
        Interval l = evalInterval(bin->getLHS(), state);
        Interval r = evalInterval(bin->getRHS(), state);
        switch (bin->getOpcode()) {
            case BO_Add: return Interval::add(l, r);
            case BO_Sub: return Interval::sub(l, r);
            case BO_Mul: return Interval::mul(l, r);
            default:     return Interval::top();
        }
    }
    return Interval::top();
}

void applyIntervalAssign(IntervalMap& state, const Stmt* stmt,
                         const std::set<const VarDecl*>& vars) {
    auto set = [&](const VarDecl* v, Interval iv) {
        if (vars.count(v)) state[v] = iv;
    };

    if (const auto* ds = dyn_cast<DeclStmt>(stmt)) {
        for (const auto* d : ds->decls())
            if (const auto* vd = dyn_cast<VarDecl>(d))
                if (vars.count(vd))
                    state[vd] = vd->hasInit()
                                    ? evalInterval(vd->getInit(), state)
                                    : Interval::top();
        return;
    }
    if (const auto* bin = dyn_cast<BinaryOperator>(stmt)) {
        if (bin->getOpcode() == BO_Assign)
            if (const VarDecl* v = asIntVar(bin->getLHS()))
                set(v, evalInterval(bin->getRHS(), state));
        // Compound assignment (`x += ...`) not modeled yet → top.
        if (bin->isCompoundAssignmentOp())
            if (const VarDecl* v = asIntVar(bin->getLHS()))
                set(v, Interval::top());
        return;
    }
    if (const auto* u = dyn_cast<UnaryOperator>(stmt)) {
        // ++/-- and &x both put the value out of our precise reach.
        if (u->isIncrementDecrementOp() || u->getOpcode() == UO_AddrOf)
            if (const VarDecl* v = asIntVar(u->getSubExpr()))
                set(v, Interval::top());
        return;
    }
    if (const auto* call = dyn_cast<CallExpr>(stmt)) {
        // An int passed by non-const reference may be rewritten.
        forEachNonConstRefArg(call, [&](const Expr* arg) {
            if (const VarDecl* v = asIntVar(arg)) set(v, Interval::top());
        });
    }
}

void refineIntervalOnEdge(IntervalMap& state, const Expr* cond, bool isTrue,
                          const std::set<const VarDecl*>& vars) {
    walkCondition(
        cond, isTrue,
        // `if (x)`: true → x != 0; false → x == 0.
        [&](const VarDecl* var, bool truthy) {
            if (!vars.count(var)) return;
            auto it = state.find(var);
            if (it == state.end()) return;
            it->second = truthy ? it->second.constrainNe(0)
                                : it->second.constrainEq(0);
        },
        // `x OPC other`: refine when `other` is a constant. opc arrives
        // variable-on-the-left; on the false edge the negation holds.
        [&](const VarDecl* var, BinaryOperatorKind opc, const Expr* other,
            bool edgeTrue) {
            if (!vars.count(var)) return;
            auto c = constInt(other);
            if (!c) return;
            auto it = state.find(var);
            if (it == state.end()) return;
            BinaryOperatorKind eff = edgeTrue ? opc : negateCmp(opc);
            it->second = constrainBy(it->second, eff, *c);
        });
}

} // namespace zerodefect
