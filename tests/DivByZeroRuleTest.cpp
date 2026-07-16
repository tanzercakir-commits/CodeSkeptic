#include "TestHelper.h"
#include "rules/DivByZeroRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// --- Phase 1: Literal zero ---

TEST(DivByZeroRuleTest, LiteralDivByZero) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int x = 100 / 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "div-by-zero");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(DivByZeroRuleTest, LiteralModByZero) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int x = 100 % 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(DivByZeroRuleTest, LiteralNonZero_Clean) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int x = 100 / 1;
            int y = 50 % 3;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- Phase 2: Variable divisor (CFG) ---

TEST(DivByZeroRuleTest, VarDefinitelyZero) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int z = 0;
            int x = 1 / z;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(DivByZeroRuleTest, VarDefinitelyNonZero_Clean) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int z = 5;
            int x = 1 / z;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(DivByZeroRuleTest, ParameterUnknown_Clean) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int z) {
            int x = 1 / z;
        }
    )");
    // Unknown → no report (conservative)
    ASSERT_EQ(results.size(), 0);
}

TEST(DivByZeroRuleTest, ConditionalMaybeZero) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int z = 0;
            if (c) z = 5;
            int x = 1 / z;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(DivByZeroRuleTest, ReassignToNonZero_Clean) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int z = 0;
            z = 10;
            int x = 1 / z;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- Assume edges: branch condition refinement ---

TEST(DivByZeroRuleTest, GuardedDivision_Clean) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int z = 0;
            if (c) z = 5;
            if (z != 0) {
                int x = 1 / z;
            }
        }
    )");
    // Division inside the z != 0 guard is safe — the old FP is gone
    ASSERT_EQ(results.size(), 0);
}

TEST(DivByZeroRuleTest, GuardEqualsZero_DefiniteError) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int z) {
            if (z == 0) {
                int x = 1 / z;
            }
        }
    )");
    // Division on the true branch of z == 0 → definite division by zero
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(DivByZeroRuleTest, GuardTruthiness_Clean) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int z = 0;
            if (c) z = c;
            if (z) {
                int x = 1 / z;
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(DivByZeroRuleTest, GuardNotOperator_DefiniteError) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int z) {
            if (!z) {
                int x = 1 / z;
            }
        }
    )");
    // !z is true → z is zero → definite error
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(DivByZeroRuleTest, GuardGreaterThanZero_Clean) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int z) {
            int zero = 0;
            if (z > 0) {
                int x = 1 / z;
            }
            if (0 < z) {
                int y = 1 / z;
            }
            (void)zero;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(DivByZeroRuleTest, WhileGuard_CleanInside_ErrorAfter) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int z) {
            int total = 0;
            while (z != 0) {
                total = total + 100 / z;
                z = z - 1;
            }
            int x = 1 / z;
        }
    )");
    // Safe inside the loop; on loop exit z == 0 → definite error
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(DivByZeroRuleTest, GuardThenFix_Clean) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int z) {
            if (z == 0) z = 1;
            int x = 1 / z;
        }
    )");
    // Fixed up if zero: both paths are NonZero
    ASSERT_EQ(results.size(), 0);
}

TEST(DivByZeroRuleTest, ZeroOnSomePathUnguarded_Warning) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int z) {
            int d = 0;
            if (z > 0) d = z;
            int x = 100 / d;
        }
    )");
    // On one path d is definitely zero, on the other unknown → possible
    // division by zero. (The old merge silently escaped via
    // Zero+Unknown=Unknown.)
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(DivByZeroRuleTest, LogicalAndGuard_Clean) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int z, int c) {
            if (c && z != 0) {
                int x = 1 / z;
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(DivByZeroRuleTest, FloatDivision_Ignored) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f() {
            double d = 1.0 / 0.0;
        }
    )");
    // IEEE 754: 1.0/0.0 = inf, defined behavior
    ASSERT_EQ(results.size(), 0);
}

TEST(DivByZeroRuleTest, NoDivision_Clean) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int add(int a, int b) {
            return a + b;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(DivByZeroTraceTest, GuardOnlyZero_TraceShowsCondition) {
    // Trace v2: the "why zero" answer for the `if (n == 0) 100 / n`
    // finding is the guard note at the condition point
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f(int n) {
            if (n == 0) {
                return 100 / n;
            }
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
    ASSERT_FALSE(results[0].notes.empty());
    EXPECT_NE(results[0].notes[0].message.find("zero on this branch"),
              std::string::npos);
    EXPECT_LT(results[0].notes[0].line, results[0].line);
}

// --- shadPS4 FP hunt (2026-07-12): call-boundary soundness ---

TEST(ShadPS4FpTest, RefOutParam_InvalidatesZeroFact) {
    // `int z = 0; set(z);` where set takes `int&` — the callee may
    // write z, so the zero fact must die at the call.
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void set(int& out);
        int f(int a) {
            int z = 0;
            set(z);
            return a / z;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ShadPS4FpTest, AddrOfArg_InvalidatesZeroFact) {
    // Same rule through the C spelling: `set(&z)`.
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void set(int* out);
        int f(int a) {
            int z = 0;
            set(&z);
            return a / z;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ShadPS4FpTest, ValueParam_ZeroFactStaysReported) {
    // Passing z by value cannot change it — the division is still by
    // definite zero.
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void use(int v);
        int f(int a) {
            int z = 0;
            use(z);
            return a / z;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

// --- libgit2 FP hunt (2026-07-12): assignment inside condition ---

TEST(LibGit2FpTest, AssignInCondition_ZeroGuard_Refines) {
    // Same look-through in the zero domain:
    // `if ((n = count()) == 0) return;` — n is non-zero afterwards.
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int count();
        int f(int a) {
            int n;
            if ((n = count()) == 0)
                return -1;
            return a / n;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- Mutation visibility (llama.cpp ngram-cache FP, 2026-07-12) ---

TEST(DivByZeroMutationTest, IncrementedCounter_NotDefinitelyZero) {
    // `++n_done` before the division: the increment must not be
    // invisible, or the zero fact from the initializer survives
    // forever and the division reports a certain crash that cannot
    // happen.
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        long f(long total, long elapsed, int steps) {
            long n = 0;
            for (int i = 0; i < steps; ++i) {
                ++n;
                if (n % 10000000 == 0) {
                    long eta = (total - n) * elapsed / n;
                    (void)eta;
                }
            }
            return n;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DivByZeroMutationTest, CompoundAssign_AlsoVisible) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f(int x, int step) {
            int n = 0;
            n += step;
            if (n != 0)
                return x / n;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DivByZeroMutationTest, UntouchedZero_StillDefinite) {
    // The sharp end must stay sharp: no mutation between init and use
    // keeps the certain-crash error.
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f(int x) {
            int z = 0;
            return x / z;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(DivByZeroBoundTest, LeOneGuard_ProvesNonZero) {
    // tmux layout_spread_cell (2026-07-13): `if (n <= 1) return;`
    // leaves n > 1 on the fall-through — never zero. The refinement
    // used to only understand comparisons against 0, so this warned.
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f(int size, unsigned number) {
            number = 0;
            for (int i = 0; i < size; i++)
                number++;
            if (number <= 1)
                return 0;
            return size / number;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DivByZeroBoundTest, LtTwoGuard_ProvesNonZero) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f(int a, int n) {
            n = 0;
            if (a) n = a;
            if (n < 2)
                return 0;
            return a / n;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DivByZeroBoundTest, GeOneGuard_ProvesNonZero) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f(int a, int n) {
            n = 0;
            if (a) n = a;
            if (n >= 1)
                return a / n;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DivByZeroBoundTest, ZeroConstantOrderings_StillWork) {
    // Regression: the generalized rule must preserve the original
    // zero-constant behavior. `n > 0` true edge proves NonZero.
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f(int a, int n) {
            n = 0;
            if (a) n = a;
            if (n > 0)
                return a / n;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DivByZeroBoundTest, LeOneUnprovenPath_StillWarns) {
    // The bound only exempts the excluded-zero edge. Here nothing
    // rules out zero before the division, so the warning stays.
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f(int a, int n) {
            n = 0;
            if (a) n = a;
            if (n <= 1) {
                /* n could be 0 here */
                return a / n;
            }
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// --- #79 negative control: narrowing casts stay OPAQUE ---
//
// Clang hides the real conversion of `(char)x` in an implicit
// part_of_explicit_cast child and marks the explicit node CK_NoOp —
// a CastKind-based strip would see it as transparent and refine
// `!(char)x` as `!x`, "proving" x zero when x=256 also takes the
// branch. The type-based strip must keep it opaque: NO definite
// division-by-zero may be reported here.
TEST(DivByZeroRuleTest, NarrowingCastCondition_NoFalseProof) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f(int x) {
            if (!(char)x) {
                return 10 / x;
            }
            return 0;
        }
    )");
    for (const auto& r : results)
        EXPECT_NE(r.severity, Severity::Error)
            << "narrowing cast refined as transparent: " << r.message;
}
