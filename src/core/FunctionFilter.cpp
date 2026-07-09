#include "core/FunctionFilter.h"

#include <clang/AST/Decl.h>

namespace zerodefect {

namespace {
std::set<std::string> g_filter;
} // anonymous namespace

void setFunctionFilter(std::set<std::string> names) {
    g_filter = std::move(names);
}

const std::set<std::string>& functionFilter() { return g_filter; }

bool functionFilterAllows(const clang::FunctionDecl& func) {
    if (g_filter.empty()) return true;
    if (g_filter.count(func.getNameAsString())) return true;
    return g_filter.count(func.getQualifiedNameAsString()) > 0;
}

} // namespace zerodefect
