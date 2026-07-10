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

// --- Assume edges: dal koşulu iyileştirmesi ---

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
    // z != 0 guard'i icinde bolme guvenli — eski FP artik yok
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
    // z == 0 dogru dalinda bolme → kesin sifira bolme
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
    // !z dogru → z sifir → kesin hata
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
    // Dongu icinde guvenli; donguden cikista z == 0 → kesin hata
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
    // Sifirsa duzeltiliyor: her iki yol da NonZero
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
    // Bir yolda d kesin sifir, digerinde bilinmiyor → olasi sifira bolme.
    // (Eski merge Zero+Unknown=Unknown ile sessizce kaciyordu.)
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
    // Iz v2: `if (n == 0) 100 / n` bulgusunun "neden sifir" cevabi
    // kosul noktasindaki guard notu
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
