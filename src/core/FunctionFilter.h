#ifndef ZERODEFECT_FUNCTION_FILTER_H
#define ZERODEFECT_FUNCTION_FILTER_H

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace clang {
class FunctionDecl;
class SourceManager;
}

namespace zerodefect {

// Incremental analysis primitives: when the filters are non-empty,
// ONLY the functions in scope are analyzed. For the "re-check only
// what changed" agent/IDE loop. Process-wide single setting like
// setLang (analysis runs on a single thread).

// --- Name filter (--function) ---
void setFunctionFilter(std::set<std::string> names);
const std::set<std::string>& functionFilter();

// An empty filter allows everything; otherwise a match on the plain
// name ("parse") or the qualified name ("Parser::parse") is required.
bool functionFilterAllows(const clang::FunctionDecl& func);

// --- Line-range filter (--lines, hunk -> function mapping) ---
// Ranges apply to the MAIN file being analyzed (diff hunks belong to
// that file anyway); functions in headers are out of scope.
using LineRanges = std::vector<std::pair<unsigned, unsigned>>;
void setLineRanges(LineRanges ranges);
const LineRanges& lineRanges();

// An empty filter allows everything; otherwise the function's [begin,
// end] line range must intersect one of the given ranges.
bool lineFilterAllows(const clang::FunctionDecl& func,
                      const clang::SourceManager& sm);

} // namespace zerodefect

#endif // ZERODEFECT_FUNCTION_FILTER_H
