#include "engine/IntervalEval.h"

#include "engine/CallRefArgs.h"
#include "engine/ConditionWalk.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/AST/Type.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <algorithm>
#include <cstdint>
#include <optional>

using namespace clang;

namespace zerodefect {

namespace {

// Bitwise AND with a non-negative mask: `x & c` (c >= 0) has every bit a
// subset of c's bits, so the result is in [0, c] for ANY x (the sign bit
// is masked off -> non-negative). Mask may be on either side. When both
// operands are known non-negative finite intervals with no constant, the
// result is bounded by the smaller upper bound. Sound over-approximation;
// unknown -> top.
Interval bitAnd(const Interval& l, const Interval& r) {
    int64_t c;
    if (r.isSingleton(&c) && c >= 0) return Interval::range(0, c);
    if (l.isSingleton(&c) && c >= 0) return Interval::range(0, c);
    const bool lNonNeg = !l.loIsInf() && l.lo() >= 0;
    const bool rNonNeg = !r.loIsInf() && r.lo() >= 0;
    if (lNonNeg && rNonNeg && !l.hiIsInf() && !r.hiIsInf())
        return Interval::range(0, std::min(l.hi(), r.hi()));
    if (lNonNeg && !l.hiIsInf()) return Interval::range(0, l.hi());
    if (rNonNeg && !r.hiIsInf()) return Interval::range(0, r.hi());
    return Interval::top();
}

// Remainder by a constant divisor: C truncates toward zero, so `x % c`
// has the sign of x and magnitude < |c|. Result in [-(|c|-1), |c|-1],
// tightened to [0, |c|-1] when x is known non-negative. Divisor unknown
// or zero -> top (a zero divisor is UB; the div-by-zero rule owns it).
Interval intRem(const Interval& l, const Interval& r) {
    int64_t d;
    if (!r.isSingleton(&d) || d == 0) return Interval::top();
    // |d| - 1, guarding the INT64_MIN abs-overflow (|INT64_MIN|-1 fits).
    const int64_t bound =
        d == INT64_MIN ? INT64_MAX : (d < 0 ? -d : d) - 1;
    if (!l.loIsInf() && l.lo() >= 0) return Interval::range(0, bound);
    return Interval::range(-bound, bound);
}

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

std::optional<int64_t> boundedTypeSizeInChars(ASTContext& ctx,
                                              QualType type) {
    if (type.isNull()) return std::nullopt;
    // getTypeInfo's stack usage scales with type NESTING DEPTH (array
    // element / field / base chains), not breadth, so the budget is a
    // depth cap plus a total-node runaway guard. 128 is far beyond any
    // hand-written type and far below what threatens even a default
    // stack; wide (but shallow) generated structs stay well inside the
    // node budget because shared canonical types are visited once.
    constexpr unsigned kMaxDepth = 128;
    constexpr unsigned kMaxNodes = 4096;

    llvm::SmallVector<std::pair<const clang::Type*, unsigned>, 32> work;
    llvm::SmallPtrSet<const clang::Type*, 32> seen;
    work.push_back({type.getCanonicalType().getTypePtr(), 0});
    unsigned nodes = 0;

    auto push = [&](QualType t, unsigned depth) {
        const clang::Type* ty = t.getCanonicalType().getTypePtr();
        if (seen.insert(ty).second) work.push_back({ty, depth});
    };

    while (!work.empty()) {
        auto [ty, depth] = work.pop_back_val();
        if (!ty) return std::nullopt;
        if (depth > kMaxDepth || ++nodes > kMaxNodes) return std::nullopt;
        if (ty->isIncompleteType() || ty->isDependentType())
            return std::nullopt;

        if (const auto* arr = dyn_cast<clang::ConstantArrayType>(ty)) {
            push(arr->getElementType(), depth + 1);
        } else if (const auto* vec = dyn_cast<clang::VectorType>(ty)) {
            push(vec->getElementType(), depth + 1);
        } else if (const auto* cx = dyn_cast<clang::ComplexType>(ty)) {
            push(cx->getElementType(), depth + 1);
        } else if (const auto* at = dyn_cast<clang::AtomicType>(ty)) {
            push(at->getValueType(), depth + 1);
        } else if (const auto* rec = ty->getAs<clang::RecordType>()) {
            const clang::RecordDecl* rd = rec->getDecl()->getDefinition();
            if (!rd) return std::nullopt;
            if (const auto* cxx = dyn_cast<clang::CXXRecordDecl>(rd))
                for (const auto& base : cxx->bases())
                    push(base.getType(), depth + 1);
            for (const auto* field : rd->fields())
                push(field->getType(), depth + 1);
        }
        // Pointers, references, builtins, enums: leaves — their size
        // does not depend on any pointee's layout.
    }
    return ctx.getTypeSizeInChars(type).getQuantity();
}

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
            case BO_And: return bitAnd(l, r);
            case BO_Rem: return intRem(l, r);
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

Interval evalSizeInterval(const Expr* e, ASTContext& ctx,
                          const IntervalMap& state) {
    if (!e) return Interval::top();
    e = e->IgnoreParens();

    // Value-preserving casts are transparent; a narrowing cast stops here
    // so the size can never be over-estimated into a false overflow.
    if (const auto* cast = dyn_cast<ImplicitCastExpr>(e)) {
        const CastKind k = cast->getCastKind();
        if (k == CK_LValueToRValue || k == CK_NoOp)
            return evalSizeInterval(cast->getSubExpr(), ctx, state);
        if (k == CK_IntegralCast &&
            cast->getType()->isIntegerType() &&
            cast->getSubExpr()->getType()->isIntegerType() &&
            ctx.getIntWidth(cast->getType()) >=
                ctx.getIntWidth(cast->getSubExpr()->getType()))
            return evalSizeInterval(cast->getSubExpr(), ctx, state);
        return Interval::top();
    }

    // sizeof(T) / sizeof(expr) — a compile-time byte constant.
    if (const auto* uett = dyn_cast<UnaryExprOrTypeTraitExpr>(e)) {
        if (uett->getKind() == UETT_SizeOf && !uett->isValueDependent()) {
            QualType t = uett->getTypeOfArgument();
            if (auto sz = boundedTypeSizeInChars(ctx, t))
                return Interval::constant(*sz);
        }
        return Interval::top();
    }

    // Constant arithmetic over sizes: count * sizeof(T), etc.
    if (const auto* bo = dyn_cast<BinaryOperator>(e)) {
        Interval l = evalSizeInterval(bo->getLHS(), ctx, state);
        Interval r = evalSizeInterval(bo->getRHS(), ctx, state);
        switch (bo->getOpcode()) {
            case BO_Mul: return Interval::mul(l, r);
            case BO_Add: return Interval::add(l, r);
            case BO_Sub: return Interval::sub(l, r);
            default:     return Interval::top();
        }
    }

    // Literals and tracked variables — the plain evaluator, same state.
    return evalInterval(e, state);
}

} // namespace zerodefect
