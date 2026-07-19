#ifndef CODESKEPTIC_INTERVAL_H
#define CODESKEPTIC_INTERVAL_H

// Interval lattice — the numeric foundation CodeSkeptic lacked
// (2026-07-14). Every existing lattice is SYMBOLIC (null? freed?
// zero?); none is QUANTITATIVE. Spatial safety (buffer/heap overflow)
// and integer overflow are quantitative — they ask "is index i within
// [0, size)?" and "does a*b exceed the type?". This type is the answer.
//
// An Interval over-approximates a set of mathematical integers as
// [lo, hi] with ±infinity endpoints and an empty (⊥) case. The
// SOUNDNESS INVARIANT is absolute: an Interval must contain EVERY real
// value the program variable can hold. When an operation cannot
// preserve that cheaply, it returns top() ([-∞,+∞]) — always sound,
// just imprecise. We never produce a too-narrow interval: a false
// "safe" conclusion is worse than a missed finding (precision-first).
//
// v0 models values as mathematical integers within int64 range. C's
// unsigned wraparound and sub-64-bit width semantics are the
// CONSUMER's responsibility (e.g. the overflow rule interprets the
// int64 result interval against a 32-bit type's range). Any int64
// arithmetic overflow inside an operation collapses the result to
// top() — sound, and the common 32-bit-operand case never triggers it.

#include <cstdint>
#include <string>

namespace codeskeptic {

class Interval {
public:
    // Default is TOP (fully unknown) — the safe starting point for a
    // variable we know nothing about.
    Interval() = default;

    static Interval top();                 // [-∞, +∞]
    static Interval bottom();              // ⊥ (empty / unreachable)
    static Interval constant(int64_t c);   // [c, c]
    static Interval range(int64_t lo, int64_t hi);  // [lo, hi]
    static Interval atLeast(int64_t lo);   // [lo, +∞]
    static Interval atMost(int64_t hi);    // [-∞, hi]

    bool isEmpty() const { return empty_; }
    bool isTop() const { return !empty_ && loInf_ && hiInf_; }
    bool loIsInf() const { return loInf_; }
    bool hiIsInf() const { return hiInf_; }
    int64_t lo() const { return lo_; }     // meaningful only if !loIsInf()
    int64_t hi() const { return hi_; }     // meaningful only if !hiIsInf()

    // Membership.
    bool contains(int64_t v) const;
    bool containsZero() const { return contains(0); }
    // Definitely non-zero: non-empty and 0 is excluded. THE div-by-zero
    // query.
    bool isKnownNonZero() const { return !empty_ && !contains(0); }
    // A single concrete value, if the interval pins one.
    bool isSingleton(int64_t* out = nullptr) const;

    bool operator==(const Interval& o) const;
    bool operator!=(const Interval& o) const { return !(*this == o); }

    // Lattice ops.
    static Interval join(const Interval& a, const Interval& b);   // ⊔ (union-hull)
    static Interval meet(const Interval& a, const Interval& b);   // ⊓ (intersection)
    // Widening for loop termination: unstable bounds jump to infinity.
    // `prev` is the old value, `next` the newly computed (⊇ prev) one.
    static Interval widen(const Interval& prev, const Interval& next);

    // Arithmetic (interval arithmetic; any int64 overflow → top()).
    static Interval add(const Interval& a, const Interval& b);
    static Interval sub(const Interval& a, const Interval& b);
    static Interval mul(const Interval& a, const Interval& b);
    static Interval negate(const Interval& a);

    // Guard refinement: the sub-interval satisfying `x REL c`. Sound
    // (returns a superset of the truth); a contradiction yields ⊥.
    Interval constrainLt(int64_t c) const;   // x <  c
    Interval constrainLe(int64_t c) const;   // x <= c
    Interval constrainGt(int64_t c) const;   // x >  c
    Interval constrainGe(int64_t c) const;   // x >= c
    Interval constrainEq(int64_t c) const;   // x == c
    Interval constrainNe(int64_t c) const;   // x != c

    // Whether [lo,hi] fits inside a signed N-bit type (the overflow
    // query): both bounds finite and within [-2^(N-1), 2^(N-1)-1].
    bool fitsSignedBits(unsigned bits) const;

    std::string toString() const;

private:
    bool empty_ = false;
    bool loInf_ = true;   // default TOP
    bool hiInf_ = true;
    int64_t lo_ = 0;      // valid iff !loInf_
    int64_t hi_ = 0;      // valid iff !hiInf_
};

} // namespace codeskeptic

#endif // CODESKEPTIC_INTERVAL_H
