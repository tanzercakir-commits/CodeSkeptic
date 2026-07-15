#include "engine/ExtentMap.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Type.h>

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

struct ExtentCollector : RecursiveASTVisitor<ExtentCollector> {
    ASTContext& ctx;
    ExtentMap map;
    explicit ExtentCollector(ASTContext& c) : ctx(c) {}

    void record(const VarDecl* vd) {
        int64_t n;
        if (fixedExtent(vd, ctx, &n))
            map.emplace(vd, Interval::constant(n));
    }

    // Local fixed arrays are declared inside the body.
    bool VisitVarDecl(VarDecl* vd) {
        record(vd);
        return true;
    }
    // Global / static fixed arrays are reached through their uses.
    bool VisitDeclRefExpr(DeclRefExpr* dre) {
        record(dyn_cast<VarDecl>(dre->getDecl()));
        return true;
    }
};

} // namespace

ExtentMap buildExtentMap(const FunctionDecl* fn, ASTContext& ctx) {
    ExtentCollector c(ctx);
    if (fn->hasBody()) c.TraverseStmt(fn->getBody());
    return std::move(c.map);
}

} // namespace zerodefect
