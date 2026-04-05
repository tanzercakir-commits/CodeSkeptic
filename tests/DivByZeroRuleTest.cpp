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
