#include "engine/ImmutableFlags.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>

#include <set>

using namespace clang;

namespace {

const VarDecl* refTo(const Expr* e) {
    if (!e) return nullptr;
    e = e->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(e))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// Every variable the TU mutates or exposes: assignment targets,
// ++/--, address-taken, bound to a reference. Conservative — anything
// that MIGHT let the value change disqualifies.
struct MutationScan : RecursiveASTVisitor<MutationScan> {
    std::set<const VarDecl*> tainted;

    void taint(const Expr* e) {
        if (const auto* vd = refTo(e)) tainted.insert(vd);
    }
    bool VisitBinaryOperator(BinaryOperator* op) {
        if (op->isAssignmentOp()) taint(op->getLHS());
        return true;
    }
    bool VisitUnaryOperator(UnaryOperator* op) {
        if (op->isIncrementDecrementOp() || op->getOpcode() == UO_AddrOf)
            taint(op->getSubExpr());
        return true;
    }
    bool VisitVarDecl(VarDecl* vd) {
        // `int& r = flag;` — a reference alias could mutate it later.
        if (vd->getType()->isReferenceType() && vd->hasInit())
            taint(vd->getInit());
        return true;
    }
    bool VisitCallExpr(CallExpr* call) {
        // A callee taking T& / T* could write through it. AddrOf args
        // are already tainted above; C++ reference parameters have no
        // AddrOf node, so taint every by-reference argument.
        const FunctionDecl* fd = call->getDirectCallee();
        for (unsigned i = 0; i < call->getNumArgs(); ++i) {
            const Expr* arg = call->getArg(i);
            if (fd && i < fd->getNumParams()) {
                QualType pt = fd->getParamDecl(i)->getType();
                if (pt->isReferenceType() &&
                    !pt.getNonReferenceType().isConstQualified())
                    taint(arg);
            } else if (!fd) {
                taint(arg);  // unknown callee: be conservative
            }
        }
        return true;
    }
};

std::optional<int64_t> constInit(const VarDecl* vd, ASTContext& ctx) {
    const Expr* init = vd->getInit();
    if (!init) return std::nullopt;
    Expr::EvalResult res;
    if (!init->EvaluateAsInt(res, ctx) || !res.Val.isInt())
        return std::nullopt;
    const llvm::APSInt& ap = res.Val.getInt();
    if (ap.isSigned()) {
        if (!ap.isSignedIntN(64)) return std::nullopt;
        return ap.getSExtValue();
    }
    if (ap.getActiveBits() > 63) return std::nullopt;
    return static_cast<int64_t>(ap.getZExtValue());
}

} // anonymous namespace

namespace codeskeptic {

ImmutableFlagMap buildImmutableFlags(ASTContext& ctx) {
    ImmutableFlagMap map;

    // Pass 1: candidates — file-scope integer variables whose value no
    // other TU can change (internal linkage, or const), non-volatile,
    // with a foldable initializer.
    for (const Decl* d : ctx.getTranslationUnitDecl()->decls()) {
        const auto* vd = dyn_cast<VarDecl>(d);
        if (!vd || !vd->hasGlobalStorage()) continue;
        if (vd->hasExternalStorage()) continue;
        QualType t = vd->getType();
        if (!t->isIntegerType() || t.isVolatileQualified()) continue;
        const bool internal =
            vd->getFormalLinkage() == Linkage::Internal;
        if (!internal && !t.isConstQualified()) continue;
        if (auto v = constInit(vd, ctx)) map[vd] = *v;
    }
    if (map.empty()) return map;

    // Pass 2: strike everything the TU mutates or exposes.
    MutationScan scan;
    scan.TraverseDecl(ctx.getTranslationUnitDecl());
    for (const auto* vd : scan.tainted) map.erase(vd);
    return map;
}

ImmutableFlagCache& ImmutableFlagCache::instance() {
    static ImmutableFlagCache cache;
    return cache;
}

const ImmutableFlagMap& ImmutableFlagCache::get(ASTContext& ctx) {
    if (!built_) {
        map_ = buildImmutableFlags(ctx);
        built_ = true;
    }
    return map_;
}

void ImmutableFlagCache::clear() {
    map_.clear();
    built_ = false;
}

bool edgeInfeasibleByFlags(const Stmt* leafCond, bool edgeIsTrue,
                           ASTContext& ctx) {
    const auto* expr = dyn_cast_or_null<Expr>(leafCond);
    if (!expr) return false;
    const ImmutableFlagMap& flags = ImmutableFlagCache::instance().get(ctx);
    if (flags.empty()) return false;

    auto flagValue = [&](const Expr* e) -> std::optional<int64_t> {
        if (const auto* vd = refTo(e)) {
            auto it = flags.find(vd->getCanonicalDecl());
            if (it == flags.end()) it = flags.find(vd);
            if (it != flags.end()) return it->second;
        }
        return std::nullopt;
    };
    auto litValue = [&](const Expr* e) -> std::optional<int64_t> {
        if (!e) return std::nullopt;
        Expr::EvalResult res;
        if (!e->EvaluateAsInt(res, ctx) || !res.Val.isInt())
            return std::nullopt;
        const llvm::APSInt& ap = res.Val.getInt();
        if (ap.isSigned() ? !ap.isSignedIntN(64) : ap.getActiveBits() > 63)
            return std::nullopt;
        return ap.isSigned() ? ap.getSExtValue()
                             : static_cast<int64_t>(ap.getZExtValue());
    };

    const Expr* stripped = expr->IgnoreParenImpCasts();

    // Bare flag: `if (flag)` — truth is value != 0.
    if (auto v = flagValue(stripped)) {
        const bool truth = (*v != 0);
        return truth != edgeIsTrue;
    }

    // flag ==/!= constant (either side).
    if (const auto* bin = dyn_cast<BinaryOperator>(stripped)) {
        if (bin->getOpcode() != BO_EQ && bin->getOpcode() != BO_NE)
            return false;
        std::optional<int64_t> fv = flagValue(bin->getLHS());
        std::optional<int64_t> cv = litValue(bin->getRHS());
        if (!fv || !cv) {
            fv = flagValue(bin->getRHS());
            cv = litValue(bin->getLHS());
        }
        if (!fv || !cv) return false;
        const bool truth =
            (bin->getOpcode() == BO_EQ) ? (*fv == *cv) : (*fv != *cv);
        return truth != edgeIsTrue;
    }
    return false;
}

} // namespace codeskeptic
