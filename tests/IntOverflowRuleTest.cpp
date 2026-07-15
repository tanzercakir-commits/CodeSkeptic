#include "TestHelper.h"
#include "rules/IntOverflowRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// int-overflow (CWE-190), v0: signed integer multiplication whose proven
// operand ranges yield a product that escapes the expression's own signed
// type. Precision-first — reported only when BOTH operands are bounded and
// the product provably overflows; an unknown operand stays silent.

// --- Proven overflow: report ---

TEST(IntOverflowRuleTest, ConstantProductOverflows) {
    // 100000 * 100000 = 1e10, far past int32's ~2.1e9 ceiling.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int a = 100000;
            int b = 100000;
            return a * b;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "int-overflow");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(IntOverflowRuleTest, WidenedAssignmentStillOverflows) {
    // The classic bite: int*int overflows in `int` BEFORE the widening to
    // long. The multiplication's own type (int) is the overflow point.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        long f() {
            int w = 100000;
            int h = 100000;
            long size = w * h;
            return size;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(IntOverflowRuleTest, GuardedRangeOverflows) {
    // a,b ∈ [50000,60000] ⇒ product ∈ [2.5e9, 3.6e9] — even the minimum
    // exceeds int32, so the whole range overflows.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        int f(int a, int b) {
            if (a < 50000) return 0;
            if (a > 60000) return 0;
            if (b < 50000) return 0;
            if (b > 60000) return 0;
            return a * b;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// --- Proven safe: clean ---

TEST(IntOverflowRuleTest, SmallConstantsClean) {
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int a = 1000;
            int b = 1000;
            return a * b;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(IntOverflowRuleTest, GuardedRangeFitsClean) {
    // a,b ∈ [1,10000] ⇒ product ∈ [1,1e8], comfortably inside int32.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        int f(int a, int b) {
            if (a < 1) return 0;
            if (a > 10000) return 0;
            if (b < 1) return 0;
            if (b > 10000) return 0;
            return a * b;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Unknown / out-of-scope: silent (precision-first) ---

TEST(IntOverflowRuleTest, UnknownOperandSilent) {
    // `a` is caller-unknown → top() product → no claim either way.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        int f(int a) {
            int b = 100000;
            return a * b;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(IntOverflowRuleTest, UnsignedNotReported) {
    // Unsigned wraparound is defined behavior, not UB — out of scope.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        unsigned f() {
            unsigned a = 100000;
            unsigned b = 100000;
            return a * b;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(IntOverflowRuleTest, SixtyFourBitProductNotReported) {
    // A 64-bit product that overflows int64 collapses to top() in the
    // interval math and is soundly, silently dropped.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        long f() {
            long a = 100000000000L;
            long b = 100000000000L;
            return a * b;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}
