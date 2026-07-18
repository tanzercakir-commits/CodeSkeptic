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

// --- Interprocedural (C3): parameter entry intervals ---

TEST(IntOverflowRuleTest, StaticHelperBoundedLiteralOverflows) {
    // scale is static (closed call graph) and called only with 100000,
    // so n enters as [100000,100000] and n*65536 overflows int.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        static int scale(int n) { return n * 65536; }
        int f(void) { return scale(100000); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(IntOverflowRuleTest, StaticHelperBoundedLocalOverflows) {
    // v0.2: the caller passes a bounded LOCAL (not a literal); the two-pass
    // reads k = [100000,100000] from the caller's dataflow.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        static int scale(int n) { return n * 65536; }
        int f(void) { int k = 100000; return scale(k); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(IntOverflowRuleTest, StaticHelperMixedCallerIsTopSilent) {
    // One caller passes an unknown value → the entry interval joins to
    // top() → nothing proven (sound).
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        static int scale(int n) { return n * 65536; }
        int f(int x) { return scale(100000) + scale(x); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(IntOverflowRuleTest, ExternalFunctionNotSeeded) {
    // Non-static: a caller in another TU could pass anything, so the
    // parameter stays top() even with a bounded local caller.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        int scale(int n) { return n * 65536; }
        int f(void) { return scale(100000); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(IntOverflowRuleTest, StaticHelperBoundedButSafeClean) {
    // 1000 * 65536 = 6.5e7, comfortably inside int — seeded but no overflow.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        static int scale(int n) { return n * 65536; }
        int f(void) { return scale(1000); }
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

// --- #96: untrusted-source recall (CWE-190) ---
//
// An intrinsic untrusted source (atoi/strtol/rand) seeds the divisor's
// interval to its return type's FULL range, so an unguarded multiply on
// it provably overflows — the canonical `int n = atoi(input); n * k`
// shape an AI writes on a first draft.

TEST(IntOverflowRuleTest, UntrustedSourceMultiplyOverflows) {
    // atoi() returns the full int range; `n > 0` refines to [1, INT_MAX];
    // [1, INT_MAX] * 2 escapes int32 on its upper half → report.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        int f(const char* s) {
            int n = atoi(s);
            if (n > 0) return n * 2;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "int-overflow");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(IntOverflowRuleTest, UntrustedSourceOverflowGuardedClean) {
    // The caller who bounds the value before multiplying is believed:
    // `n < 10000` refines the range, product fits int32 → silent.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        int f(const char* s) {
            int n = atoi(s);
            if (n > 0 && n < 10000) return n * 2;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(IntOverflowRuleTest, ConstantFoldedGuardRefines) {
    // Part 1: an overflow guard written with constant ARITHMETIC
    // (`x < LIMIT/2`, the Juliet good-sink idiom) must refine like a
    // plain literal. x is pinned to 2e9; the folded guard makes the
    // guarded branch infeasible (⊥), so the multiply is never reported.
    // Without the fold x keeps [2e9] and x*2 would be a false positive.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        int f(void) {
            int x = 2000000000;
            if (x < 2000000000 / 2) return x * 2;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(IntOverflowRuleTest, SelfSquareSilent) {
    // KNOWN LIMITATION (honest FN): a square's safe form is guarded by
    // `abs(x) < sqrt(TYPE_MAX)`, which the integer refiner cannot fold —
    // so a guarded-safe square is indistinguishable from an unguarded
    // one and reporting `x * x` would false-positive. We stay silent on
    // self-multiply until abs/sqrt guards are modeled.
    IntOverflowRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        int f(const char* s) {
            int n = atoi(s);
            if (n > 0) return n * n;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}
