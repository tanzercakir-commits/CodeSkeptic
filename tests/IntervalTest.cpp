#include "engine/Interval.h"

#include <gtest/gtest.h>

#include <cstdint>

using zerodefect::Interval;

// The interval lattice (2026-07-14): the numeric foundation for
// bounds/overflow checking. The soundness invariant — an Interval
// contains EVERY real value — is what these tests defend. Any
// operation that could narrow below the truth is a bug worse than a
// crash (it would make the analyzer report "safe" when it isn't).

// --- Construction & membership ---

TEST(IntervalTest, ConstantAndContains) {
    Interval c = Interval::constant(5);
    EXPECT_TRUE(c.contains(5));
    EXPECT_FALSE(c.contains(4));
    EXPECT_FALSE(c.contains(6));
    int64_t s = 0;
    EXPECT_TRUE(c.isSingleton(&s));
    EXPECT_EQ(s, 5);
}

TEST(IntervalTest, RangeReversedIsEmpty) {
    EXPECT_TRUE(Interval::range(5, 3).isEmpty());
    EXPECT_FALSE(Interval::range(3, 5).isEmpty());
}

TEST(IntervalTest, TopContainsEverything) {
    Interval t = Interval::top();
    EXPECT_TRUE(t.isTop());
    EXPECT_TRUE(t.contains(0));
    EXPECT_TRUE(t.contains(INT64_MAX));
    EXPECT_TRUE(t.contains(INT64_MIN));
    EXPECT_FALSE(t.isKnownNonZero());  // top includes 0
}

TEST(IntervalTest, HalfBounded) {
    Interval ge1 = Interval::atLeast(1);
    EXPECT_FALSE(ge1.contains(0));
    EXPECT_TRUE(ge1.contains(1));
    EXPECT_TRUE(ge1.contains(INT64_MAX));
    EXPECT_TRUE(ge1.isKnownNonZero());
}

TEST(IntervalTest, EmptyIsNotNonZeroButExcludesAll) {
    Interval e = Interval::bottom();
    EXPECT_TRUE(e.isEmpty());
    EXPECT_FALSE(e.contains(0));
    EXPECT_FALSE(e.isKnownNonZero());  // empty: no values at all
}

// --- The div-by-zero query: isKnownNonZero ---

TEST(IntervalTest, KnownNonZero) {
    EXPECT_TRUE(Interval::range(1, 10).isKnownNonZero());
    EXPECT_TRUE(Interval::range(-10, -1).isKnownNonZero());
    EXPECT_FALSE(Interval::range(0, 10).isKnownNonZero());
    EXPECT_FALSE(Interval::range(-5, 5).isKnownNonZero());
    EXPECT_FALSE(Interval::constant(0).isKnownNonZero());
    EXPECT_TRUE(Interval::constant(3).isKnownNonZero());
}

// --- Join (⊔) ---

TEST(IntervalTest, JoinHull) {
    Interval j = Interval::join(Interval::range(1, 3), Interval::range(7, 9));
    EXPECT_TRUE(j.contains(1));
    EXPECT_TRUE(j.contains(9));
    EXPECT_TRUE(j.contains(5));  // hull fills the gap (over-approx)
    EXPECT_FALSE(j.contains(0));
    EXPECT_FALSE(j.contains(10));
}

TEST(IntervalTest, JoinWithEmptyIsIdentity) {
    Interval a = Interval::range(2, 4);
    EXPECT_EQ(Interval::join(a, Interval::bottom()), a);
    EXPECT_EQ(Interval::join(Interval::bottom(), a), a);
}

TEST(IntervalTest, JoinWithInfinity) {
    Interval j = Interval::join(Interval::atLeast(5), Interval::constant(1));
    EXPECT_TRUE(j.contains(1));
    EXPECT_TRUE(j.contains(1000));
    EXPECT_FALSE(j.contains(0));
    EXPECT_TRUE(j.hiIsInf());
}

// --- Meet (⊓) ---

TEST(IntervalTest, MeetIntersection) {
    Interval m = Interval::meet(Interval::range(0, 10), Interval::range(5, 20));
    EXPECT_EQ(m, Interval::range(5, 10));
}

TEST(IntervalTest, MeetDisjointIsEmpty) {
    Interval m = Interval::meet(Interval::range(0, 3), Interval::range(7, 9));
    EXPECT_TRUE(m.isEmpty());
}

// --- Guard refinement ---

TEST(IntervalTest, ConstrainOrderings) {
    Interval t = Interval::top();
    EXPECT_EQ(t.constrainLt(5), Interval::atMost(4));
    EXPECT_EQ(t.constrainLe(5), Interval::atMost(5));
    EXPECT_EQ(t.constrainGt(5), Interval::atLeast(6));
    EXPECT_EQ(t.constrainGe(5), Interval::atLeast(5));
    EXPECT_EQ(t.constrainEq(5), Interval::constant(5));
}

TEST(IntervalTest, ConstrainLeOneProvesNonZeroOnFalseEdge) {
    // The tmux layout_spread_cell shape: `if (n <= 1) return;` — on the
    // fall-through, n > 1, i.e. n ∈ [2, +∞], which excludes 0.
    Interval n = Interval::top();          // unknown count
    Interval fallThrough = n.constrainGt(1);   // NOT (n <= 1)
    EXPECT_TRUE(fallThrough.isKnownNonZero());
    EXPECT_EQ(fallThrough, Interval::atLeast(2));
}

TEST(IntervalTest, ConstrainNeTrimsEndpoint) {
    // [0,5] with x != 0 → [1,5] (sound endpoint trim).
    Interval r = Interval::range(0, 5).constrainNe(0);
    EXPECT_EQ(r, Interval::range(1, 5));
    EXPECT_TRUE(r.isKnownNonZero());
    // Interior hole cannot be represented — stays as-is (still sound).
    Interval interior = Interval::range(0, 5).constrainNe(3);
    EXPECT_EQ(interior, Interval::range(0, 5));
}

TEST(IntervalTest, ConstrainNeSingletonEmpties) {
    EXPECT_TRUE(Interval::constant(0).constrainNe(0).isEmpty());
}

TEST(IntervalTest, ConstrainContradictionEmpties) {
    // x >= 10 AND x <= 5 → empty.
    Interval r = Interval::atLeast(10).constrainLe(5);
    EXPECT_TRUE(r.isEmpty());
}

// --- Arithmetic ---

TEST(IntervalTest, AddRanges) {
    Interval r = Interval::add(Interval::range(1, 2), Interval::range(10, 20));
    EXPECT_EQ(r, Interval::range(11, 22));
}

TEST(IntervalTest, SubRanges) {
    Interval r = Interval::sub(Interval::range(10, 20), Interval::range(1, 5));
    EXPECT_EQ(r, Interval::range(5, 19));
}

TEST(IntervalTest, MulRangesIncludingNegatives) {
    // [-2,3] * [4,5] → endpoints {-10,-8,12,15} → [-10,15].
    Interval r = Interval::mul(Interval::range(-2, 3), Interval::range(4, 5));
    EXPECT_EQ(r, Interval::range(-10, 15));
}

TEST(IntervalTest, MulByZeroIsZeroEvenIfOtherUnbounded) {
    Interval r = Interval::mul(Interval::top(), Interval::constant(0));
    EXPECT_EQ(r, Interval::constant(0));
}

TEST(IntervalTest, Negate) {
    EXPECT_EQ(Interval::negate(Interval::range(-3, 5)), Interval::range(-5, 3));
    // -[2,+∞] = [-∞,-2].
    Interval n = Interval::negate(Interval::atLeast(2));
    EXPECT_TRUE(n.loIsInf());
    EXPECT_FALSE(n.hiIsInf());
    EXPECT_EQ(n.hi(), -2);
}

// --- Overflow SOUNDNESS: arithmetic must never wrap silently ---

TEST(IntervalTest, AddOverflowCollapsesToTop) {
    // INT64_MAX + 1 would wrap; the result must be TOP (sound), never a
    // small wrapped number.
    Interval r = Interval::add(Interval::constant(INT64_MAX),
                               Interval::constant(1));
    EXPECT_TRUE(r.isTop());
    EXPECT_TRUE(r.contains(INT64_MAX));  // truth is preserved, not wrapped
}

TEST(IntervalTest, MulOverflowCollapsesToTop) {
    Interval big = Interval::constant(int64_t(1) << 40);
    Interval r = Interval::mul(big, big);  // 2^80 overflows int64
    EXPECT_TRUE(r.isTop());
}

// --- The overflow-detection query ---

TEST(IntervalTest, FitsSignedBits) {
    EXPECT_TRUE(Interval::range(-128, 127).fitsSignedBits(8));
    EXPECT_FALSE(Interval::range(-128, 128).fitsSignedBits(8));   // 128 > max
    EXPECT_FALSE(Interval::range(-129, 127).fitsSignedBits(8));   // -129 < min
    EXPECT_TRUE(Interval::range(0, 2147483647).fitsSignedBits(32));
    EXPECT_FALSE(Interval::range(0, 2147483648LL).fitsSignedBits(32));
    EXPECT_FALSE(Interval::top().fitsSignedBits(32));   // unbounded never fits
    EXPECT_TRUE(Interval::bottom().fitsSignedBits(32));  // empty vacuously fits
}

TEST(IntervalTest, MallocProductOverflowDetectable) {
    // a,b ∈ [0, 2^31-1]; a*b can reach ~2^62, far past int32 — the
    // int-overflow rule's core query. int64 mul does NOT overflow here,
    // so we get a precise (large) interval that fails fitsSignedBits(32).
    Interval a = Interval::range(0, 2147483647);
    Interval prod = Interval::mul(a, a);
    EXPECT_FALSE(prod.isTop());  // int64 held it precisely
    EXPECT_FALSE(prod.fitsSignedBits(32));
}

// --- Widening (loop termination) ---

TEST(IntervalTest, WidenUnstableUpperGoesInfinite) {
    // A loop counter climbing [0,0] → [0,1] → widen → [0,+∞].
    Interval prev = Interval::range(0, 0);
    Interval next = Interval::range(0, 1);
    Interval w = Interval::widen(prev, next);
    EXPECT_FALSE(w.loIsInf());
    EXPECT_EQ(w.lo(), 0);
    EXPECT_TRUE(w.hiIsInf());
}

TEST(IntervalTest, WidenStableKeepsBound) {
    Interval prev = Interval::range(0, 10);
    Interval next = Interval::range(0, 10);
    EXPECT_EQ(Interval::widen(prev, next), Interval::range(0, 10));
}

TEST(IntervalTest, WidenLowerUnstableGoesNegInfinite) {
    Interval prev = Interval::range(0, 5);
    Interval next = Interval::range(-1, 5);
    Interval w = Interval::widen(prev, next);
    EXPECT_TRUE(w.loIsInf());
    EXPECT_FALSE(w.hiIsInf());
    EXPECT_EQ(w.hi(), 5);
}
