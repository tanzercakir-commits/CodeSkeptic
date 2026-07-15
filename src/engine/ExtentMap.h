#ifndef ZERODEFECT_EXTENT_MAP_H
#define ZERODEFECT_EXTENT_MAP_H

// ExtentMap (2026-07-15): the spatial counterpart to the interval
// dataflow. Where IntervalAnalysis answers "what value range does index
// i hold?", the extent map answers "how many elements does buffer b
// hold?". A bounds rule joins the two: an access b[i] is out-of-bounds
// when i's proven range escapes b's extent.
//
// v0 models only what is EXACTLY and SOUNDLY known at compile time:
// fixed-size arrays (`int a[N]`, `char buf[32]` — clang's
// ConstantArrayType), whose element count is a constant. The extent is
// stored as an Interval (element count) so heap sources — `malloc(n)`,
// `calloc(m, k)` sized by a known interval — can slot in later as a
// range without changing the consumer's shape. An unknown extent is
// simply absent from the map (the consumer then proves nothing — sound).

#include "engine/Interval.h"

#include <clang/AST/Decl.h>

#include <map>

namespace clang {
class ASTContext;
class FunctionDecl;
}

namespace zerodefect {

// VarDecl -> element-count interval. A present entry means "this variable
// names a buffer whose element count lies in this interval"; a singleton
// is an exactly-known size. Absence means unknown (prove nothing).
using ExtentMap = std::map<const clang::VarDecl*, Interval>;

// Collect the extents provable for a function's local and global buffers.
// v0: fixed-size array declarations only (ConstantArrayType), extent =
// constant element count.
ExtentMap buildExtentMap(const clang::FunctionDecl* fn,
                         clang::ASTContext& ctx);

} // namespace zerodefect

#endif // ZERODEFECT_EXTENT_MAP_H
