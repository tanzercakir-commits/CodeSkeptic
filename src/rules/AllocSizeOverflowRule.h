#ifndef CODESKEPTIC_ALLOC_SIZE_OVERFLOW_RULE_H
#define CODESKEPTIC_ALLOC_SIZE_OVERFLOW_RULE_H

#include "core/Rule.h"

namespace codeskeptic {

// Untrusted allocation-size overflow (CWE-131 / CWE-190-unsigned) — the
// rule the LVGL binfont hunt named (docs/PLAN.md section 4, 2026-07-30).
// An untrusted length drives an UNSIGNED size computation that WRAPS
// before the allocator sees it: `lv_malloc(sizeof(uint32_t) *
// (loca_count + 1))` where loca_count is read from a font file — at
// 0xFFFFFFFF the `+ 1` wraps to 0 in uint32, lv_malloc(0) returns a tiny
// buffer, and the following fill loop of loca_count entries overflows
// the heap.
//
// Every existing rule misses this by design: IntOverflowRule is
// signed-only (unsigned wrap is defined behaviour, correctly out of its
// UB scope), sign-conversion needs a signed->unsigned cast AND excludes
// allocator arguments, bounds is fixed-extent. This rule is the
// nlohmann lesson one level over — there an untrusted SIGNED value
// became a huge unsigned length; here an untrusted UNSIGNED value wraps
// a computed allocation size. It inverts sign-conversion's allocator
// exclusion: the allocator sink is precisely this rule's target, so the
// two partition the allocator-size space cleanly.
//
// Precision-first gates, all required:
//   - the arithmetic is UNSIGNED `*` or `+` (signed is IntOverflow's);
//   - an operand derives from a declared untrusted source (returns AND
//     out-params — provenance opt-in, never guessed);
//   - it is (transitively) the size argument to an allocator
//     (engine/AllocFunctions.h isAllocatorCall);
//   - its proven interval PROVABLY reaches past the unsigned result
//     type's max (a finite witness; an unknown operand stays silent).
// A guard (`if (n < LIMIT)`) narrows the interval and silences on its
// own edge. Phase 6.1 adds 64-bit multiplication through an exact
// operand-corner proof: one side must be a finite constant and the other
// a declared untrusted unsigned value. The operands are widened to 128
// bits for the mathematical comparison; runtime/unknown factors remain
// silent. Phase 6.2 preserves the exact modulo corner through stable local
// signed-to-unsigned casts and aliases, including narrowing conversions. It
// also tracks compiler checked-multiply outputs: a proven no-overflow edge is
// silent, while an unchecked/overflow-edge result needs the same finite
// corner proof. Reassigned, escaped, or otherwise unstable relations remain
// silent. Phase 6.3 consumes only exact unchanged parameter-to-allocator-size
// relations from the versioned function summaries, including visible chains
// and harvested cross-TU wrappers. Bodyless, transformed, conflicting, and
// unknown relations stay silent. When an exact local allocation binding is
// later indexed or passed to a bounded memory-access primitive with the same
// declared-untrusted origin, a trace note records that evidence without
// replacing the allocation-wrap proof. Sub-64 arithmetic continues to use
// the shared int64 interval.
class AllocSizeOverflowRule : public Rule {
public:
    std::string id() const override { return "alloc-size-overflow"; }
    std::string description() const override {
        return "Untrusted length wraps an unsigned allocation size";
    }
    Severity defaultSeverity() const override { return Severity::Warning; }

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_ALLOC_SIZE_OVERFLOW_RULE_H
