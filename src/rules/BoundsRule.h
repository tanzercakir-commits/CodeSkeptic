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
// Heap extents (`malloc(n)`) and the memcpy/strcpy size family are the
// v0.2 follow-ups; only definite OOB is reported, at Error severity.
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
