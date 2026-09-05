#ifndef CODESKEPTIC_BOUNDS_RULE_H
#define CODESKEPTIC_BOUNDS_RULE_H

#include "core/Rule.h"

namespace codeskeptic {

// Out-of-bounds array access (CWE-125 read / CWE-787 write, the
// stack/global-buffer-overflow class), the second consumer of the
// interval dataflow (2026-07-15). It joins two facts: the ExtentMap's
// proven element count of a fixed-size array, and IntervalAnalysis's
// proven range of the subscript index. An access `a[i]` is a definite
// out-of-bounds when i's ENTIRE proven range lies outside [0, extent) —
// either every value reaches past the end, or every value is negative.
//
// v0 scope (precision-first): fixed-size arrays (ConstantArrayType,
// exact extent) subscripted by a fully-out-of-range index. This covers
// the classic definite bugs — a constant index past the end (`a[10]` on
// `int a[10]`), a negative constant, or a variable proven by guards to
// have left the valid range. Partial overlaps (some paths in range, some
// out) are deliberately silent for now: on real loops they are the FP
// minefield, and the interval domain over-approximates loop counters.
// Copy destination extents and the string-copy family are also modeled.
// memcpy/memmove source reads use independent byte capacities (CWE-125):
// fixed arrays/literals and stable local constant malloc/calloc allocations.
// Definite source over-read is Error, still subject to the rule's experimental
// report-only capability. Unknown capacities, flexible pointer-based tails,
// ambiguous pointer bindings and non-definite length ranges stay silent.
// Contradictory paths stay infeasible through later assignments and loops.
// memset does not read a source; strncpy's termination/padding differs and is
// not part of the source-read model. Constant pointer offsets (buf+k, &buf[k])
// and bounded stable alias chains use the arithmetic pointer's element size
// for independent source/destination remaining-byte capacity. One-past address
// formation is not an element read; a positive copy still exceeds its zero
// remaining capacity. Offset integer initializers must actually have executed
// and remain unchanged. Unsupported/oversized calculations remain unknown.
class BoundsRule : public Rule {
public:
    std::string id() const override { return "bounds"; }
    std::string description() const override {
        return "Out-of-bounds fixed-array access via range analysis";
    }
    Severity defaultSeverity() const override { return Severity::Error; }

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_BOUNDS_RULE_H
