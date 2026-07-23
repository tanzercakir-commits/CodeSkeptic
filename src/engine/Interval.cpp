#include "engine/Interval.h"

#include <algorithm>
#include <cstdint>

namespace codeskeptic {

namespace {

// Saturating helpers on FINITE int64. Return false on overflow so the
// caller can collapse to top() (sound).
#if defined(__GNUC__) || defined(__clang__)
bool addChecked(int64_t a, int64_t b, int64_t* out) {
    return !__builtin_add_overflow(a, b, out);
}
bool subChecked(int64_t a, int64_t b, int64_t* out) {
    return !__builtin_sub_overflow(a, b, out);
}
bool mulChecked(int64_t a, int64_t b, int64_t* out) {
    return !__builtin_mul_overflow(a, b, out);
}
#else
// MSVC has no __builtin_*_overflow: classic pre-checks against the
// int64 limits (CERT INT32-C shape). Must stay behavior-identical to
// the builtin path — IntervalTest pins the edge cases on both.
bool addChecked(int64_t a, int64_t b, int64_t* out) {
    if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b))
        return false;
    *out = a + b;
    return true;
}
bool subChecked(int64_t a, int64_t b, int64_t* out) {
    if ((b < 0 && a > INT64_MAX + b) || (b > 0 && a < INT64_MIN + b))
        return false;
    *out = a - b;
    return true;
}
bool mulChecked(int64_t a, int64_t b, int64_t* out) {
    if (a != 0 && b != 0) {
        const bool overflows =
            a > 0 ? (b > 0 ? a > INT64_MAX / b : b < INT64_MIN / a)
                  : (b > 0 ? a < INT64_MIN / b : b < INT64_MAX / a);
        if (overflows) return false;
    }
    *out = a * b;
    return true;
}
#endif

} // namespace

// --- Constructors ---

Interval Interval::top() {
    Interval i;
    i.empty_ = false;
    i.loInf_ = true;
    i.hiInf_ = true;
    return i;
}

Interval Interval::bottom() {
    Interval i;
    i.empty_ = true;
    return i;
}

Interval Interval::constant(int64_t c) { return range(c, c); }

Interval Interval::range(int64_t lo, int64_t hi) {
    if (lo > hi) return bottom();
    Interval i;
    i.empty_ = false;
    i.loInf_ = false;
    i.hiInf_ = false;
    i.lo_ = lo;
    i.hi_ = hi;
    return i;
}

Interval Interval::atLeast(int64_t lo) {
    Interval i;
    i.empty_ = false;
    i.loInf_ = false;
    i.hiInf_ = true;
    i.lo_ = lo;
    return i;
}

Interval Interval::atMost(int64_t hi) {
    Interval i;
    i.empty_ = false;
    i.loInf_ = true;
    i.hiInf_ = false;
    i.hi_ = hi;
    return i;
}

// --- Queries ---

bool Interval::contains(int64_t v) const {
    if (empty_) return false;
    if (!loInf_ && v < lo_) return false;
    if (!hiInf_ && v > hi_) return false;
    return true;
}

bool Interval::isSingleton(int64_t* out) const {
    if (empty_ || loInf_ || hiInf_ || lo_ != hi_) return false;
    if (out) *out = lo_;
    return true;
}

bool Interval::operator==(const Interval& o) const {
    if (empty_ || o.empty_) return empty_ == o.empty_;
    if (loInf_ != o.loInf_ || hiInf_ != o.hiInf_) return false;
    if (!loInf_ && lo_ != o.lo_) return false;
    if (!hiInf_ && hi_ != o.hi_) return false;
    return true;
}

// --- Lattice ops ---

Interval Interval::join(const Interval& a, const Interval& b) {
    if (a.empty_) return b;
    if (b.empty_) return a;
    Interval r;
    r.empty_ = false;
    // lo = min of the two lows (−∞ if either is −∞).
    if (a.loInf_ || b.loInf_) {
        r.loInf_ = true;
    } else {
        r.loInf_ = false;
        r.lo_ = std::min(a.lo_, b.lo_);
    }
    if (a.hiInf_ || b.hiInf_) {
        r.hiInf_ = true;
    } else {
        r.hiInf_ = false;
        r.hi_ = std::max(a.hi_, b.hi_);
    }
    return r;
}

Interval Interval::meet(const Interval& a, const Interval& b) {
    if (a.empty_ || b.empty_) return bottom();
    Interval r;
    r.empty_ = false;
    // lo = max of the two lows (a finite bound beats −∞).
    if (a.loInf_ && b.loInf_) {
        r.loInf_ = true;
    } else if (a.loInf_) {
        r.loInf_ = false;
        r.lo_ = b.lo_;
    } else if (b.loInf_) {
        r.loInf_ = false;
        r.lo_ = a.lo_;
    } else {
        r.loInf_ = false;
        r.lo_ = std::max(a.lo_, b.lo_);
    }
    // hi = min of the two highs.
    if (a.hiInf_ && b.hiInf_) {
        r.hiInf_ = true;
    } else if (a.hiInf_) {
        r.hiInf_ = false;
        r.hi_ = b.hi_;
    } else if (b.hiInf_) {
        r.hiInf_ = false;
        r.hi_ = a.hi_;
    } else {
        r.hiInf_ = false;
        r.hi_ = std::min(a.hi_, b.hi_);
    }
    if (!r.loInf_ && !r.hiInf_ && r.lo_ > r.hi_) return bottom();
    return r;
}

Interval Interval::widen(const Interval& prev, const Interval& next) {
    if (prev.empty_) return next;
    if (next.empty_) return next;  // ⊥ is stable
    Interval r;
    r.empty_ = false;
    // Lower bound: unstable (fell below prev) → −∞; otherwise keep it.
    if (next.loInf_) {
        r.loInf_ = true;
    } else if (!prev.loInf_ && next.lo_ < prev.lo_) {
        r.loInf_ = true;  // decreased — widen down to −∞ for termination
    } else {
        r.loInf_ = false;
        r.lo_ = next.lo_;  // stable or rising (more precise) — keep
    }
    // Upper bound: unstable (rose above prev) → +∞; otherwise keep it.
    if (next.hiInf_) {
        r.hiInf_ = true;
    } else if (!prev.hiInf_ && next.hi_ > prev.hi_) {
        r.hiInf_ = true;  // increased — widen up to +∞
    } else {
        r.hiInf_ = false;
        r.hi_ = next.hi_;
    }
    return r;
}

// --- Arithmetic ---

Interval Interval::negate(const Interval& a) {
    if (a.empty_) return a;
    Interval r;
    r.empty_ = false;
    // -[lo,hi] = [-hi,-lo]; ±∞ swap sides.
    if (a.hiInf_) {
        r.loInf_ = true;
    } else {
        int64_t v;
        if (!subChecked(0, a.hi_, &v)) return top();  // -INT64_MIN
        r.loInf_ = false;
        r.lo_ = v;
    }
    if (a.loInf_) {
        r.hiInf_ = true;
    } else {
        int64_t v;
        if (!subChecked(0, a.lo_, &v)) return top();
        r.hiInf_ = false;
        r.hi_ = v;
    }
    return r;
}

Interval Interval::add(const Interval& a, const Interval& b) {
    if (a.empty_ || b.empty_) return bottom();
    Interval r;
    r.empty_ = false;
    if (a.loInf_ || b.loInf_) {
        r.loInf_ = true;
    } else {
        int64_t v;
        if (!addChecked(a.lo_, b.lo_, &v)) return top();
        r.loInf_ = false;
        r.lo_ = v;
    }
    if (a.hiInf_ || b.hiInf_) {
        r.hiInf_ = true;
    } else {
        int64_t v;
        if (!addChecked(a.hi_, b.hi_, &v)) return top();
        r.hiInf_ = false;
        r.hi_ = v;
    }
    return r;
}

Interval Interval::sub(const Interval& a, const Interval& b) {
    return add(a, negate(b));
}

Interval Interval::mul(const Interval& a, const Interval& b) {
    if (a.empty_ || b.empty_) return bottom();
    // A zero factor pins the product to 0 regardless of the other side
    // (even if the other is unbounded).
    int64_t sa, sb;
    if (a.isSingleton(&sa) && sa == 0) return constant(0);
    if (b.isSingleton(&sb) && sb == 0) return constant(0);
    // Unbounded operands: the product is unbounded (top). Precise-enough
    // v0 — bounded×bounded (constants, small ranges) is the useful case.
    if (a.loInf_ || a.hiInf_ || b.loInf_ || b.hiInf_) return top();
    // Both finite: min/max of the four endpoint products.
    int64_t p[4];
    if (!mulChecked(a.lo_, b.lo_, &p[0]) ||
        !mulChecked(a.lo_, b.hi_, &p[1]) ||
        !mulChecked(a.hi_, b.lo_, &p[2]) ||
        !mulChecked(a.hi_, b.hi_, &p[3]))
        return top();
    int64_t lo = std::min({p[0], p[1], p[2], p[3]});
    int64_t hi = std::max({p[0], p[1], p[2], p[3]});
    return range(lo, hi);
}

// --- Guard refinement ---

Interval Interval::constrainLe(int64_t c) const {
    return meet(*this, atMost(c));
}
Interval Interval::constrainLt(int64_t c) const {
    if (c == INT64_MIN) return bottom();  // x < MIN impossible
    return meet(*this, atMost(c - 1));
}
Interval Interval::constrainGe(int64_t c) const {
    return meet(*this, atLeast(c));
}
Interval Interval::constrainGt(int64_t c) const {
    if (c == INT64_MAX) return bottom();  // x > MAX impossible
    return meet(*this, atLeast(c + 1));
}
Interval Interval::constrainEq(int64_t c) const {
    return meet(*this, constant(c));
}
Interval Interval::constrainNe(int64_t c) const {
    if (empty_) return *this;
    // Intervals cannot punch a hole; only trim a matching endpoint
    // (still a sound over-approximation).
    if (!loInf_ && lo_ == c) {
        if (!hiInf_ && lo_ == hi_) return bottom();  // singleton {c}
        return meet(*this, atLeast(c == INT64_MAX ? c : c + 1));
    }
    if (!hiInf_ && hi_ == c)
        return meet(*this, atMost(c == INT64_MIN ? c : c - 1));
    return *this;
}

bool Interval::fitsSignedBits(unsigned bits) const {
    if (empty_) return true;
    if (loInf_ || hiInf_) return false;
    if (bits == 0 || bits > 64) return false;
    // Signed N-bit range: [-2^(N-1), 2^(N-1)-1].
    int64_t maxv = (bits == 64) ? INT64_MAX
                                : ((int64_t(1) << (bits - 1)) - 1);
    int64_t minv = (bits == 64) ? INT64_MIN : -(int64_t(1) << (bits - 1));
    return lo_ >= minv && hi_ <= maxv;
}

std::string Interval::toString() const {
    if (empty_) return "empty";
    std::string s = "[";
    s += loInf_ ? "-inf" : std::to_string(lo_);
    s += ", ";
    s += hiInf_ ? "+inf" : std::to_string(hi_);
    s += "]";
    return s;
}

} // namespace codeskeptic
