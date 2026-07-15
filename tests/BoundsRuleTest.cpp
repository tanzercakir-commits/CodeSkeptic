#include "TestHelper.h"
#include "rules/BoundsRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// bounds (CWE-125/787), v0: a fixed-size array subscripted by an index
// whose ENTIRE proven range is outside [0, extent). Precision-first —
// only definite out-of-bounds is an Error; partial overlaps stay silent.

// --- Definite out-of-bounds: report ---

TEST(BoundsRuleTest, ConstantIndexPastEnd) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int a[10];
            return a[10];
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "bounds");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, NegativeConstantIndex) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int a[10];
            return a[-1];
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, GuardedIndexProvenPastEnd) {
    // `if (i < 10) return 0;` leaves i ∈ [10,+∞] on the fall-through —
    // every value is out of [0,10).
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f(int i) {
            int a[10];
            if (i < 10) return 0;
            return a[i];
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, ComputedConstantIndexPastEnd) {
    // n = 8 + 8 = 16, proven past a[10].
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int a[10];
            int n = 8 + 8;
            return a[n];
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

// --- In-bounds / unprovable: clean ---

TEST(BoundsRuleTest, ConstantIndexInRange) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int a[10];
            return a[9] + a[0];
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, UnknownIndexSilent) {
    // Caller-unknown index → top() → nothing proven (precision-first).
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f(int i) {
            int a[10];
            return a[i];
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, PartialOverlapSilent) {
    // i ∈ [5,15] straddles the bound — some paths in range. v0 does NOT
    // report partial overlaps (loop-counter FP minefield).
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f(int i) {
            int a[10];
            if (i < 5) return 0;
            if (i > 15) return 0;
            return a[i];
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, GuardedIndexInRangeClean) {
    // 0 <= i <= 9 — fully in bounds.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f(int i) {
            int a[10];
            if (i < 0) return 0;
            if (i > 9) return 0;
            return a[i];
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Interprocedural (C3): parameter entry intervals ---

TEST(BoundsRuleTest, StaticHelperOutOfRangeIndexFromCaller) {
    // `at` is static and called only with 20, so i enters as [20,20] —
    // past a[10]. The caller's constant index reaches the bounds check.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        static int at(int i) { int a[10]; return a[i]; }
        int f(void) { return at(20); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, StaticHelperInRangeIndexFromCallerClean) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        static int at(int i) { int a[10]; return a[i]; }
        int f(void) { return at(3); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, PointerParamHasNoExtentSilent) {
    // A pointer parameter has no ConstantArrayType — extent unknown, so
    // even a large constant index proves nothing.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f(int* a) {
            return a[1000000];
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}
