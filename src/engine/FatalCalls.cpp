#include "engine/FatalCalls.h"

#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>

#include <utility>

namespace codeskeptic {

namespace {
std::set<std::string>& storage() {
    static std::set<std::string> names;
    return names;
}
} // namespace

void setFatalCallNames(std::set<std::string> names) {
    storage() = std::move(names);
}

const std::set<std::string>& fatalCallNames() {
    return storage();
}

bool isFatalCall(const clang::Stmt* stmt) {
    const auto& names = storage();
    if (names.empty() || !stmt) return false;
    const auto* call = llvm::dyn_cast<clang::CallExpr>(stmt);
    if (!call) return false;
    const clang::FunctionDecl* callee = call->getDirectCallee();
    if (!callee) return false;
    if (const auto* id = callee->getIdentifier())
        return names.count(id->getName().str()) != 0;
    return false;
}

} // namespace codeskeptic
