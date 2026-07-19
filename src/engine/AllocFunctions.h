#ifndef CODESKEPTIC_ENGINE_ALLOCFUNCTIONS_H
#define CODESKEPTIC_ENGINE_ALLOCFUNCTIONS_H

#include <set>
#include <string>

namespace codeskeptic {

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

// Custom owning-smart-pointer registry (--owning-pointers).
//
// std::unique_ptr / shared_ptr / auto_ptr are recognized built-in, but
// every engine and game framework ships its own single-owner or
// ref-counted wrapper: Jolt's Ref<T>/RefConst<T>, WebKit's RefPtr<T>,
// Chromium's scoped_refptr<T>. Constructing one of these from a raw
// pointer TRANSFERS ownership into the wrapper (which frees it), so the
// raw pointer is no longer leaked. Without the wrapper name the leak
// rule sees a raw `new` whose owner it cannot follow and reports a
// false positive on idiomatic modern C++. Same lifecycle as the alloc
// registry: set at startup from Config, cleared in ~StaticAnalyzer.
void setOwningPointerNames(std::set<std::string> names);
const std::set<std::string>& owningPointerNames();

} // namespace codeskeptic

#endif // CODESKEPTIC_ENGINE_ALLOCFUNCTIONS_H
