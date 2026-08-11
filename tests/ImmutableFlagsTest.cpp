#include "TestHelper.h"
#include "rules/DivByZeroRule.h"

#include <gtest/gtest.h>

using namespace codeskeptic;
using namespace codeskeptic::testing;

namespace {

class NoOpRule final : public Rule {
public:
    std::string id() const override { return "no-op"; }
    std::string description() const override { return "no-op test rule"; }
    void check(clang::ASTContext&, DiagnosticList&) override {}
};

} // anonymous namespace

TEST(ImmutableFlagsTest, FormatHeaderEqualityDoesNotEvaluateNonFlagOperands) {
    NoOpRule rule;
    auto results = runRuleWithArgs(rule, R"(
        #if __has_include(<format>)
        #include <format>
        #include <string>
        #if defined(__cpp_lib_format)
        std::string render_value(int value) {
            return std::format("{}", value);
        }
        #endif
        #endif
    )", {"-std=c++20"}, "format_regression.cpp");
    EXPECT_TRUE(results.empty());
}

TEST(ImmutableFlagsTest, EqualityOperatorsPreserveBothOperandOrders) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        static int disabled = 0;
        static int enabled = 1;
        int divide(int value) {
            int divisor = 7;
            if (disabled == 1) divisor = 0;
            if (1 == disabled) divisor = 0;
            if (enabled != 1) divisor = 0;
            if (1 != enabled) divisor = 0;
            return value / divisor;
        }
    )");
    EXPECT_TRUE(results.empty());
}
