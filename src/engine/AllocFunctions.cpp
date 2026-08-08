#include "engine/AllocFunctions.h"

#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>

#include <string>
#include <utility>

namespace codeskeptic {

// A call to a heap allocator whose size argument, over-large, is met by
// a NULL return: the intrinsic C family plus any --alloc-functions
// wrapper. Shared by SignConversionRule (which EXCLUDES allocator args —
// the NULL-return net is the null-deref rule's domain) and
// AllocSizeOverflowRule (which TARGETS them — the size computation that
// wraps before the allocator ever sees it). The two rules partition the
// allocator-size space between them, so they must agree on what an
// allocator is; that agreement lives here.
bool isAllocatorCall(const clang::CallExpr* call) {
    if (!call) return false;
    const clang::FunctionDecl* fd = call->getDirectCallee();
    if (!fd || !fd->getIdentifier()) return false;
    const std::string n = fd->getName().str();
    static const std::set<std::string> kIntrinsic = {
        "malloc",  "calloc",        "realloc", "reallocarray",
        "alloca",  "aligned_alloc", "valloc",  "pvalloc",
        "memalign",
    };
    if (kIntrinsic.count(n)) return true;
    const auto& extra = allocFunctionNames();
    return !extra.empty() && extra.count(n) > 0;
}

namespace {

bool isStdNothrowT(const clang::CXXRecordDecl* record) {
    if (!record || record->getName() != "nothrow_t") return false;
    for (const clang::DeclContext* context = record->getDeclContext(); context;
         context = context->getParent()) {
        if (const auto* ns = llvm::dyn_cast<clang::NamespaceDecl>(context))
            if (ns->getName() == "std") return true;
    }
    return false;
}

} // anonymous namespace

bool isOwnedPointerReturnCall(const clang::CallExpr* call) {
    if (!call) return false;
    const clang::FunctionDecl* fd = call->getDirectCallee();
    if (!fd || !fd->getIdentifier()) return false;
    const std::string name = fd->getName().str();
    static const std::set<std::string> kOwnedReturns = {
        "malloc", "calloc", "realloc", "reallocarray", "aligned_alloc",
        "valloc", "pvalloc", "memalign", "strdup", "strndup", "fopen",
        "freopen", "fdopen", "tmpfile", "opendir", "fdopendir",
    };
    if (kOwnedReturns.count(name)) return true;
    const auto& extra = allocFunctionNames();
    return !extra.empty() && extra.count(name) > 0;
}

bool isOwnedAllocationExpr(const clang::Expr* expr) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* cleanups =
            llvm::dyn_cast<clang::ExprWithCleanups>(expr))
        return isOwnedAllocationExpr(cleanups->getSubExpr());
    if (const auto* materialized =
            llvm::dyn_cast<clang::MaterializeTemporaryExpr>(expr))
        return isOwnedAllocationExpr(materialized->getSubExpr());
    if (const auto* bound =
            llvm::dyn_cast<clang::CXXBindTemporaryExpr>(expr))
        return isOwnedAllocationExpr(bound->getSubExpr());
    if (const auto* allocation = llvm::dyn_cast<clang::CXXNewExpr>(expr)) {
        for (unsigned i = 0; i < allocation->getNumPlacementArgs(); ++i) {
            clang::QualType type = allocation->getPlacementArg(i)->getType();
            if (type->isPointerType()) return false;
            clang::QualType plain =
                type.getNonReferenceType().getUnqualifiedType();
            if (const auto* record = plain->getAsCXXRecordDecl())
                if (!isStdNothrowT(record)) return false;
        }
        return true;
    }
    if (const auto* cast = llvm::dyn_cast<clang::CastExpr>(expr))
        return isOwnedAllocationExpr(cast->getSubExpr());
    if (const auto* call = llvm::dyn_cast<clang::CallExpr>(expr))
        return isOwnedPointerReturnCall(call);
    return false;
}
namespace {
std::set<std::string>& allocStorage() {
    static std::set<std::string> names;
    return names;
}
std::set<std::string>& freeStorage() {
    static std::set<std::string> names;
    return names;
}
std::set<std::string>& owningPtrStorage() {
    static std::set<std::string> names;
    return names;
}
std::set<std::string>& untrustedIntStorage() {
    static std::set<std::string> names;
    return names;
}
} // namespace

void setAllocFunctionNames(std::set<std::string> names) {
    allocStorage() = std::move(names);
}

const std::set<std::string>& allocFunctionNames() {
    return allocStorage();
}

void setFreeFunctionNames(std::set<std::string> names) {
    freeStorage() = std::move(names);
}

const std::set<std::string>& freeFunctionNames() {
    return freeStorage();
}

void setOwningPointerNames(std::set<std::string> names) {
    owningPtrStorage() = std::move(names);
}

const std::set<std::string>& owningPointerNames() {
    return owningPtrStorage();
}

void setUntrustedIntSourceNames(std::set<std::string> names) {
    untrustedIntStorage() = std::move(names);
}

const std::set<std::string>& untrustedIntSourceNames() {
    return untrustedIntStorage();
}

} // namespace codeskeptic
