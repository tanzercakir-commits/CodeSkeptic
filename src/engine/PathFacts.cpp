#include "engine/PathFacts.h"

#include <clang/AST/RecursiveASTVisitor.h>

using namespace clang;

namespace {

// Evaluate an integer constant: literal, -literal, or an enum
// constant (fprime's `status == OK` correlations key on the enum's
// value). EvaluateAsInt is NOT used: const global variables
// (GLOBAL_CONST_FIVE) could have been constant-folded, but those are
// already keyed on the DeclRef side.
std::optional<int64_t> intLiteralValue(const Expr* expr) {
    if (!expr) return std::nullopt;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr)) {
        // Literals that do not fit 64 bits (unseen in practice) are skipped
        if (lit->getValue().getSignificantBits() > 64) return std::nullopt;
        return lit->getValue().getSExtValue();
    }
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) {
        if (const auto* ec = dyn_cast<EnumConstantDecl>(ref->getDecl())) {
            if (ec->getInitVal().getSignificantBits() > 64)
                return std::nullopt;
            return ec->getInitVal().getSExtValue();
        }
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
        const std::set<const ValueDecl*>& unkeyable) {
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
    if (unkeyable.count(vd)) return nullptr;
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

const ValueDecl* refTarget(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) return ref->getDecl();
    return nullptr;
}

bool isLocalVar(const ValueDecl* d) {
    const auto* vd = dyn_cast_or_null<VarDecl>(d);
    return vd && vd->hasLocalStorage();
}

// Null pointer constant: 0 / NULL ((void*)0 — explicit cast!) /
// nullptr / __null.
bool isNullConstant(const Expr* expr) {
    if (!expr) return false;
    expr = expr->IgnoreParenCasts();
    if (isa<CXXNullPtrLiteralExpr>(expr) || isa<GNUNullExpr>(expr))
        return true;
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0;
    return false;
}

// Keyable pointer variable (see the ptrKeyable note in the header).
const ValueDecl* ptrDeclRef(const Expr* expr,
                            const std::set<const ValueDecl*>& unkeyable,
                            const std::set<const ValueDecl*>& ptrKeyable) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    const auto* ref = dyn_cast<DeclRefExpr>(expr);
    if (!ref) return nullptr;
    const auto* vd = dyn_cast<VarDecl>(ref->getDecl());
    if (!vd || !vd->getType()->isPointerType()) return nullptr;
    if (vd->getType().isVolatileQualified()) return nullptr;
    if (!ptrKeyable.count(vd) || unkeyable.count(vd)) return nullptr;
    return vd;
}

// Permanent bans: address-taken decls (any call may write through the
// pointer) and ASSIGNED non-locals (globals/statics also change
// through calls; a visible assignment proves the function treats it
// as mutable state, so flow-erasure would be a false comfort).
class UnkeyableDeclCollector
    : public RecursiveASTVisitor<UnkeyableDeclCollector> {
public:
    std::set<const ValueDecl*> banned;

    bool VisitBinaryOperator(BinaryOperator* op) {
        if (op->isAssignmentOp()) recordIfNonLocal(op->getLHS());
        return true;
    }
    bool VisitUnaryOperator(UnaryOperator* op) {
        if (op->getOpcode() == UO_AddrOf) {
            if (const ValueDecl* d = refTarget(op->getSubExpr()))
                banned.insert(d);
        } else if (op->isIncrementDecrementOp()) {
            recordIfNonLocal(op->getSubExpr());
        }
        return true;
    }

private:
    void recordIfNonLocal(const Expr* expr) {
        const ValueDecl* d = refTarget(expr);
        if (d && !isLocalVar(d)) banned.insert(d);
    }
};

// Stamping relevance: integer-typed locals that some keyable condition
// shape asks about — either side of a comparison whose other side is
// an integer constant, or a bare truth-value use (`if (x)`, `!x`,
// `a && x`). Overapproximation is fine; the set only GATES stamping.
class FactDeclCollector : public RecursiveASTVisitor<FactDeclCollector> {
public:
    std::set<const ValueDecl*> relevant;

    bool VisitBinaryOperator(BinaryOperator* op) {
        if (op->isComparisonOp()) {
            if (intLiteralValue(op->getRHS())) record(op->getLHS());
            if (intLiteralValue(op->getLHS())) record(op->getRHS());
        } else if (op->getOpcode() == BO_LAnd || op->getOpcode() == BO_LOr) {
            record(op->getLHS());
            record(op->getRHS());
        }
        return true;
    }
    bool VisitUnaryOperator(UnaryOperator* op) {
        if (op->getOpcode() == UO_LNot) record(op->getSubExpr());
        return true;
    }
    bool VisitIfStmt(IfStmt* s) { record(s->getCond()); return true; }
    bool VisitWhileStmt(WhileStmt* s) { record(s->getCond()); return true; }
    bool VisitDoStmt(DoStmt* s) { record(s->getCond()); return true; }
    bool VisitForStmt(ForStmt* s) { record(s->getCond()); return true; }
    bool VisitConditionalOperator(ConditionalOperator* s) {
        record(s->getCond());
        return true;
    }
    bool VisitSwitchStmt(SwitchStmt* s) { record(s->getCond()); return true; }

private:
    void record(const Expr* expr) {
        const ValueDecl* d = refTarget(expr);
        if (d && isLocalVar(d) && d->getType()->isIntegerType())
            relevant.insert(d);
    }
};

} // anonymous namespace

namespace zerodefect {

std::optional<std::pair<FactKey, bool>> conditionFact(
        const Expr* cond,
        const std::set<const ValueDecl*>& unkeyable,
        const std::set<const ValueDecl*>& ptrKeyable) {
    if (!cond) return std::nullopt;
    cond = cond->IgnoreParenImpCasts();

    // if (X): truthiness  ≡  (X == 0) is false
    if (const ValueDecl* var = stableDeclRef(cond, unkeyable))
        return {{FactKey{var, BO_EQ, 0}, false}};
    if (const ValueDecl* var = ptrDeclRef(cond, unkeyable, ptrKeyable))
        return {{FactKey{var, BO_EQ, 0}, false}};

    // if (f()): constant-returning helpers key on the callee
    // (FunctionDecl is a ValueDecl — the key structure is unchanged)
    if (const FunctionDecl* callee = constReturningCallee(cond))
        return {{FactKey{callee, BO_EQ, 0}, false}};

    if (const auto* unary = dyn_cast<UnaryOperator>(cond)) {
        if (unary->getOpcode() == UO_LNot) {
            auto fact = conditionFact(unary->getSubExpr(), unkeyable,
                                      ptrKeyable);
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

    // Keyed pointer against the null constant: `s == NULL` ≡ (s EQ 0).
    if (opc == BO_EQ || opc == BO_NE) {
        const ValueDecl* pvar = ptrDeclRef(lhs, unkeyable, ptrKeyable);
        const Expr* other = rhs;
        if (!pvar) {
            pvar = ptrDeclRef(rhs, unkeyable, ptrKeyable);
            other = lhs;
        }
        if (pvar && isNullConstant(other))
            return {{FactKey{pvar, BO_EQ, 0}, opc == BO_EQ}};
    }

    if (const ValueDecl* var = stableDeclRef(lhs, unkeyable)) {
        if (auto lit = intLiteralValue(rhs))
            return normalizeCompare(var, opc, *lit, /*varOnLeft=*/true);
        return std::nullopt;
    }
    if (const ValueDecl* var = stableDeclRef(rhs, unkeyable)) {
        if (auto lit = intLiteralValue(lhs))
            return normalizeCompare(var, opc, *lit, /*varOnLeft=*/false);
    }
    return std::nullopt;
}

std::optional<std::pair<FactKey, bool>> conditionFact(
        const Expr* cond,
        const std::set<const ValueDecl*>& unkeyable) {
    static const std::set<const ValueDecl*> kNone;
    return conditionFact(cond, unkeyable, kNone);
}

std::set<const ValueDecl*> collectUnkeyableDecls(const FunctionDecl* func) {
    UnkeyableDeclCollector collector;
    if (func && func->hasBody())
        collector.TraverseStmt(func->getBody());
    return std::move(collector.banned);
}

std::set<const ValueDecl*> collectFactDecls(const FunctionDecl* func) {
    FactDeclCollector collector;
    if (func && func->hasBody())
        collector.TraverseStmt(func->getBody());
    return std::move(collector.relevant);
}

namespace {

// The bare-pointer side of a short-circuit operand: `s`, `!s`,
// `s == NULL`, `s != NULL`.
const VarDecl* ptrOperandVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* un = dyn_cast<UnaryOperator>(expr)) {
        if (un->getOpcode() == UO_LNot)
            return ptrOperandVar(un->getSubExpr());
        return nullptr;
    }
    if (const auto* bin = dyn_cast<BinaryOperator>(expr)) {
        if (bin->getOpcode() != BO_EQ && bin->getOpcode() != BO_NE)
            return nullptr;
        if (isNullConstant(bin->getRHS())) return ptrOperandVar(bin->getLHS());
        if (isNullConstant(bin->getLHS())) return ptrOperandVar(bin->getRHS());
        return nullptr;
    }
    const auto* ref = dyn_cast<DeclRefExpr>(expr);
    if (!ref) return nullptr;
    const auto* vd = dyn_cast<VarDecl>(ref->getDecl());
    if (!vd || !vd->getType()->isPointerType()) return nullptr;
    return vd;
}

class PtrFactDeclCollector
    : public RecursiveASTVisitor<PtrFactDeclCollector> {
public:
    std::set<const ValueDecl*> relevant;

    bool VisitBinaryOperator(BinaryOperator* op) {
        if (op->getOpcode() != BO_LAnd && op->getOpcode() != BO_LOr)
            return true;
        static const std::set<const ValueDecl*> kNone;
        const Expr* lhs = op->getLHS();
        const Expr* rhs = op->getRHS();
        // A pointer operand qualifies only when its PARTNER operand is
        // itself keyable — an integer condition (`assert(s || l <= 0)`)
        // or ANOTHER bare-pointer nullness operand (`!a && b`, the
        // comparator-ladder case exhaustion: after `if (!a && !b) ...
        // if (!a && b) ... if (a && !b) ...` falls through, both are
        // provably non-null, but only if both sides split disjuncts).
        // `p && p->x` self-guards do NOT qualify (the member side is
        // not a bare pointer var) — keying every plain guard would
        // burn the disjunct cap.
        const VarDecl* lp = ptrOperandVar(lhs);
        const VarDecl* rp = ptrOperandVar(rhs);
        if (lp && (rp || conditionFact(rhs, kNone, kNone)))
            relevant.insert(lp);
        if (rp && (lp || conditionFact(lhs, kNone, kNone)))
            relevant.insert(rp);
        return true;
    }
};

} // anonymous namespace

std::set<const ValueDecl*> collectPtrFactDecls(const FunctionDecl* func) {
    PtrFactDeclCollector collector;
    if (func && func->hasBody())
        collector.TraverseStmt(func->getBody());
    return std::move(collector.relevant);
}

const ValueDecl* assignedDecl(const Stmt* stmt) {
    if (!stmt) return nullptr;
    if (const auto* bin = dyn_cast<BinaryOperator>(stmt)) {
        if (bin->isAssignmentOp()) return refTarget(bin->getLHS());
        return nullptr;
    }
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
        if (unary->isIncrementDecrementOp())
            return refTarget(unary->getSubExpr());
        return nullptr;
    }
    if (const auto* decl = dyn_cast<DeclStmt>(stmt)) {
        if (decl->isSingleDecl())
            if (const auto* vd = dyn_cast<VarDecl>(decl->getSingleDecl()))
                if (vd->hasInit()) return vd;
        return nullptr;
    }
    return nullptr;
}

std::optional<std::pair<const ValueDecl*, int64_t>> assignedIntLiteral(
        const Stmt* stmt) {
    if (!stmt) return std::nullopt;
    const ValueDecl* target = nullptr;
    const Expr* value = nullptr;
    if (const auto* bin = dyn_cast<BinaryOperator>(stmt)) {
        // Plain `=` only: `x += 1` needs the OLD value — erasure
        // (assignedDecl) handles it, no stamp.
        if (bin->getOpcode() != BO_Assign) return std::nullopt;
        target = refTarget(bin->getLHS());
        value = bin->getRHS();
    } else if (const auto* decl = dyn_cast<DeclStmt>(stmt)) {
        if (!decl->isSingleDecl()) return std::nullopt;
        const auto* vd = dyn_cast<VarDecl>(decl->getSingleDecl());
        if (!vd || !vd->hasInit()) return std::nullopt;
        target = vd;
        value = vd->getInit();
    } else {
        return std::nullopt;
    }
    if (!target || !value) return std::nullopt;
    auto lit = intLiteralValue(value);
    if (!lit) return std::nullopt;
    return {{target, *lit}};
}

bool factsContradict(const std::map<FactKey, bool>& facts,
                     const FactKey& key, bool wanted) {
    auto exact = facts.find(key);
    if (exact != facts.end()) return exact->second != wanted;

    // A stamped equality on the same var answers every relation:
    // (x EQ 6)=true decides (x EQ 5) -> false, (x LT 10) -> true, ...
    // Only EQ=true stamps entail; inequalities are left alone (partial
    // information, no contradiction derivable in the simple cases we
    // stamp). The maps hold a handful of entries — a plain scan.
    for (const auto& [known, value] : facts) {
        if (known.var != key.var || known.rel != BO_EQ || !value) continue;
        bool holds = false;
        switch (key.rel) {
            case BO_EQ: holds = (known.literal == key.literal); break;
            case BO_LT: holds = (known.literal < key.literal); break;
            case BO_LE: holds = (known.literal <= key.literal); break;
            default: continue;  // keys are canonicalized to EQ/LT/LE
        }
        if (holds != wanted) return true;
    }
    return false;
}

} // namespace zerodefect
