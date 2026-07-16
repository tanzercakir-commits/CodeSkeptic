#include "engine/ExtentMap.h"

#include "engine/CallRefArgs.h"
#include "engine/IntervalEval.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Type.h>

#include <set>

using namespace clang;

namespace zerodefect {

namespace {

// The exact element count of a fixed-size array declaration, if the
// variable has ConstantArrayType and the count fits a signed 64-bit
// range (a wider extent cannot be exceeded by an int64 index interval
// anyway, so dropping it loses no soundness).
bool fixedExtent(const VarDecl* vd, ASTContext& ctx, int64_t* out) {
    if (!vd) return false;
    const auto* arr = ctx.getAsConstantArrayType(vd->getType());
    if (!arr) return false;
    const llvm::APInt& size = arr->getSize();
    if (size.getActiveBits() > 63) return false;
    *out = static_cast<int64_t>(size.getZExtValue());
    return true;
}

const VarDecl* refVar(const Expr* e) {
    if (!e) return nullptr;
    e = e->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(e))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// Floor-divide a (non-negative size) interval by a positive constant —
// element count = bytes / element-size. Floor is sound for an upper
// bound: index i is out of bounds once i >= floor(bytes/size).
Interval divByPositive(const Interval& iv, int64_t d) {
    if (d <= 0 || iv.isEmpty()) return Interval::top();
    if (iv.loIsInf() && iv.hiIsInf()) return Interval::top();
    if (iv.loIsInf()) return Interval::atMost(iv.hi() / d);
    if (iv.hiIsInf()) return Interval::atLeast(iv.lo() / d);
    return Interval::range(iv.lo() / d, iv.hi() / d);
}

// If `init` is a malloc/calloc call, the element count for a buffer of
// `pointee` elements. malloc(bytes) → bytes / sizeof(pointee);
// calloc(n, sz) → (n * sz) / sizeof(pointee). Returns false when the
// shape is not a recognized allocation or the element count cannot be
// determined (leaving the pointer without a proven extent — sound).
bool heapElementCount(const Expr* init, QualType pointee, ASTContext& ctx,
                      Interval* out) {
    if (!init || pointee.isNull() || pointee->isIncompleteType()) return false;
    const Expr* e = init->IgnoreParenImpCasts();
    // The result is cast to the pointer type; look through that cast.
    if (const auto* cast = dyn_cast<CastExpr>(e))
        e = cast->getSubExpr()->IgnoreParenImpCasts();
    const auto* call = dyn_cast<CallExpr>(e);
    if (!call) return false;
    const FunctionDecl* callee = call->getDirectCallee();
    if (!callee || !callee->getIdentifier()) return false;
    const llvm::StringRef name = callee->getName();

    const int64_t elemBytes = ctx.getTypeSizeInChars(pointee).getQuantity();
    if (elemBytes <= 0) return false;

    const IntervalMap empty;
    Interval bytes;
    if (name == "malloc" && call->getNumArgs() == 1) {
        bytes = evalSizeInterval(call->getArg(0), ctx, empty);
    } else if (name == "calloc" && call->getNumArgs() == 2) {
        bytes = Interval::mul(evalSizeInterval(call->getArg(0), ctx, empty),
                              evalSizeInterval(call->getArg(1), ctx, empty));
    } else {
        return false;
    }
    if (bytes.isTop() || bytes.isEmpty()) return false;  // nothing proven
    *out = divByPositive(bytes, elemBytes);
    return !out->isTop();
}

// Pointers whose value may change after the initializer — reassigned,
// address-taken, or handed to an out-parameter. Their declared malloc
// extent can no longer be trusted at a later subscript, so they are
// excluded from the heap extent map (a fixed-array extent, by contrast,
// is a property of the type and never invalidated).
struct Invalidations : RecursiveASTVisitor<Invalidations> {
    std::set<const VarDecl*> vars;
    bool VisitBinaryOperator(BinaryOperator* b) {
        if (b->isAssignmentOp())
            if (const auto* v = refVar(b->getLHS())) vars.insert(v);
        return true;
    }
    bool VisitUnaryOperator(UnaryOperator* u) {
        if (u->getOpcode() == UO_AddrOf)
            if (const auto* v = refVar(u->getSubExpr())) vars.insert(v);
        if (u->isIncrementDecrementOp())
            if (const auto* v = refVar(u->getSubExpr())) vars.insert(v);
        return true;
    }
    bool VisitCallExpr(CallExpr* call) {
        forEachNonConstRefArg(call, [&](const Expr* arg) {
            if (const auto* v = refVar(arg)) vars.insert(v);
        });
        return true;
    }
};

struct ExtentCollector : RecursiveASTVisitor<ExtentCollector> {
    ASTContext& ctx;
    const std::set<const VarDecl*>& invalidated;
    ExtentMap map;
    ExtentCollector(ASTContext& c, const std::set<const VarDecl*>& inv)
        : ctx(c), invalidated(inv) {}

    bool VisitVarDecl(VarDecl* vd) {
        // Fixed-size array (extent is a property of the type — always safe).
        int64_t n;
        if (fixedExtent(vd, ctx, &n)) {
            map.emplace(vd, Interval::constant(n));
            return true;
        }
        // Heap buffer: a pointer whose SOLE definition is its malloc/calloc
        // initializer (never reassigned / address-taken afterwards).
        if (vd->getType()->isPointerType() && vd->hasInit() &&
            !invalidated.count(vd)) {
            Interval elems;
            if (heapElementCount(vd->getInit(),
                                 vd->getType()->getPointeeType(), ctx, &elems))
                map.emplace(vd, elems);
        }
        return true;
    }
    // Global / static fixed arrays are reached through their uses.
    bool VisitDeclRefExpr(DeclRefExpr* dre) {
        if (const auto* vd = dyn_cast<VarDecl>(dre->getDecl())) {
            int64_t n;
            if (fixedExtent(vd, ctx, &n)) map.emplace(vd, Interval::constant(n));
        }
        return true;
    }
};

} // namespace

ExtentMap buildExtentMap(const FunctionDecl* fn, ASTContext& ctx) {
    if (!fn->hasBody()) return {};
    Invalidations inv;
    inv.TraverseStmt(fn->getBody());
    ExtentCollector c(ctx, inv.vars);
    c.TraverseStmt(fn->getBody());
    return std::move(c.map);
}

} // namespace zerodefect
