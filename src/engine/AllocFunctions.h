#ifndef ZERODEFECT_ENGINE_ALLOCFUNCTIONS_H
#define ZERODEFECT_ENGINE_ALLOCFUNCTIONS_H

#include <set>
#include <string>

namespace zerodefect {

// Custom allocator registry (--alloc-functions / --free-functions).
//
// Every sizable C project wraps the heap: libgit2's git__malloc /
// git__free, redis' zmalloc/zfree, nginx's ngx_alloc... The built-in
// list (malloc/calloc/strdup/realloc/new and free/delete) cannot see
// those, so the leak/double-free/UAF analysis is completely BLIND in
// such codebases — the libgit2 scan produced literally zero
// memory-leak findings, true or false (2026-07-12). Registering the
// wrapper names turns the domain on. Same lifecycle discipline as the
// fatal-call registry: set at startup from Config, cleared in
// ~StaticAnalyzer (the MCP server runs many analyses per process).

void setAllocFunctionNames(std::set<std::string> names);
const std::set<std::string>& allocFunctionNames();

void setFreeFunctionNames(std::set<std::string> names);
const std::set<std::string>& freeFunctionNames();

} // namespace zerodefect

#endif // ZERODEFECT_ENGINE_ALLOCFUNCTIONS_H
