#ifndef CODESKEPTIC_EXTENT_MAP_H
#define CODESKEPTIC_EXTENT_MAP_H

// ExtentMap (2026-07-15): the spatial counterpart to the interval
// dataflow. Where IntervalAnalysis answers "what value range does index
// i hold?", the extent map answers "how many elements does buffer b
// hold?". A bounds rule joins the two: an access b[i] is out-of-bounds
// when i's proven range escapes b's extent.
//
// Two extent sources, both stored as an Interval element count:
//   * fixed-size arrays (`int a[N]`, `char buf[32]` — ConstantArrayType),
//     whose count is a constant and is a property of the TYPE (never
//     invalidated);
//   * heap buffers — a pointer whose SOLE definition is its
//     `malloc(bytes)` / `calloc(n, sz)` initializer, converted to an
//     element count via the pointee size (`n * sizeof(T)` cancels to n,
//     `malloc(40)` on an int* is 10). A pointer that is later reassigned,
//     address-taken, or handed to an out-parameter is excluded — its
//     declared extent can no longer be trusted at a subscript.
// v0 proves heap extents from constant / sizeof sizes; a size that flows
// in as a variable stays unknown. An unknown extent is simply absent
// from the map (the consumer then proves nothing — sound).

#include "engine/Interval.h"

#include <clang/AST/Decl.h>

#include <map>

namespace clang {
class ASTContext;
class FunctionDecl;
}

namespace codeskeptic {

// VarDecl -> element-count interval. A present entry means "this variable
// names a buffer whose element count lies in this interval"; a singleton
// is an exactly-known size. Absence means unknown (prove nothing).
using ExtentMap = std::map<const clang::VarDecl*, Interval>;

// Collect the extents provable for a function's local and global buffers.
// v0: fixed-size array declarations only (ConstantArrayType), extent =
// constant element count.
ExtentMap buildExtentMap(const clang::FunctionDecl* fn,
                         clang::ASTContext& ctx);

} // namespace codeskeptic

#endif // CODESKEPTIC_EXTENT_MAP_H
