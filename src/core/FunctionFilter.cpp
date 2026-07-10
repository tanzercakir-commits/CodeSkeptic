#include "core/FunctionFilter.h"

#include <clang/AST/Decl.h>
#include <clang/Basic/SourceManager.h>

namespace zerodefect {

namespace {
std::set<std::string> g_filter;
LineRanges g_lineRanges;
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

void setLineRanges(LineRanges ranges) {
    g_lineRanges = std::move(ranges);
}

const LineRanges& lineRanges() { return g_lineRanges; }

bool lineFilterAllows(const clang::FunctionDecl& func,
                      const clang::SourceManager& sm) {
    if (g_lineRanges.empty()) return true;

    clang::SourceLocation begin = sm.getExpansionLoc(func.getBeginLoc());
    clang::SourceLocation end = sm.getExpansionLoc(func.getEndLoc());
    // Changed lines belong to the main file being analyzed; functions
    // in headers are not in this scope
    if (!sm.isInMainFile(begin)) return false;

    unsigned funcBegin = sm.getSpellingLineNumber(begin);
    unsigned funcEnd = sm.getSpellingLineNumber(end);
    for (const auto& [from, to] : g_lineRanges) {
        if (from <= funcEnd && funcBegin <= to) return true;
    }
    return false;
}

} // namespace zerodefect
