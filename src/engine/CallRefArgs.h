#ifndef ZERODEFECT_ENGINE_CALLREFARGS_H
#define ZERODEFECT_ENGINE_CALLREFARGS_H

#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Type.h>

namespace zerodefect {

// Calls the callback for every argument that binds to a NON-CONST
// reference parameter of the callee. Such a parameter is an out-param:
// the callee may reassign the caller's variable through it, so any
// dataflow fact about that variable must be invalidated at the call
// (the shadPS4 `ResolveEpollBinding(id, int*& out, ...)` pattern —
// keeping a "definitely null" fact across the call produced
// error-level false positives).
//
// Unlike `f(&x)` there is no AddrOf node in the AST to observe: the
// argument is a bare lvalue DeclRefExpr, indistinguishable from a
// by-value use without looking at the parameter type. Rvalue
// references are treated the same way (the callee may move from /
// clobber the referent).
//
// The parameter list is taken from the direct callee when there is
// one, otherwise from the callee expression's function prototype
// (function pointers). No prototype (K&R C) means no references —
// nothing to do.
template <typename Callback>
void forEachNonConstRefArg(const clang::CallExpr* call, Callback cb) {
    if (!call) return;

    // Operator calls on methods pass the object as argument 0; the
    // parameter list starts at argument 1.
    unsigned argOffset = 0;
    const clang::FunctionDecl* callee = call->getDirectCallee();
    if (llvm::isa<clang::CXXOperatorCallExpr>(call) && callee &&
        llvm::isa<clang::CXXMethodDecl>(callee) &&
        !llvm::cast<clang::CXXMethodDecl>(callee)->isStatic())
        argOffset = 1;

    auto isNonConstRef = [](clang::QualType t) {
        return t->isReferenceType() &&
               !t.getNonReferenceType().isConstQualified();
    };

    if (callee) {
        for (unsigned i = 0; i < callee->getNumParams(); ++i) {
            unsigned argIndex = i + argOffset;
            if (argIndex >= call->getNumArgs()) break;
            if (isNonConstRef(callee->getParamDecl(i)->getType()))
                cb(call->getArg(argIndex));
        }
        return;
    }

    // Indirect call: recover the prototype from the callee expression
    const clang::Expr* calleeExpr = call->getCallee();
    if (!calleeExpr) return;
    clang::QualType calleeType = calleeExpr->getType();
    if (const auto* ptr = calleeType->getAs<clang::PointerType>())
        calleeType = ptr->getPointeeType();
    const auto* proto = calleeType->getAs<clang::FunctionProtoType>();
    if (!proto) return;
    for (unsigned i = 0; i < proto->getNumParams(); ++i) {
        unsigned argIndex = i + argOffset;
        if (argIndex >= call->getNumArgs()) break;
        if (isNonConstRef(proto->getParamType(i)))
            cb(call->getArg(argIndex));
    }
}

} // namespace zerodefect

#endif // ZERODEFECT_ENGINE_CALLREFARGS_H
