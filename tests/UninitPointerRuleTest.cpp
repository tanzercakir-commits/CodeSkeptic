#include "TestHelper.h"
#include "rules/UninitPointerRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

TEST(UninitPointerRuleTest, BasicUninit) {
    UninitPointerRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* ptr;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "uninit-ptr");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(UninitPointerRuleTest, MultipleUninit) {
    UninitPointerRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* a;
            double* b;
            char* c;
        }
    )");
    ASSERT_EQ(results.size(), 3);
}

TEST(UninitPointerRuleTest, InitializedWithNullptr_Clean) {
    UninitPointerRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* ptr = nullptr;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleTest, InitializedWithAddressOf_Clean) {
    UninitPointerRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int x = 10;
            int* ptr = &x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleTest, InitializedWithNew_Clean) {
    UninitPointerRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* ptr = new int(42);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleTest, InitializedWithFunctionReturn_Clean) {
    UninitPointerRule rule;
    auto results = runRule(rule, R"(
        int* getPtr();
        void f() {
            int* ptr = getPtr();
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleTest, ParameterIgnored) {
    UninitPointerRule rule;
    auto results = runRule(rule, R"(
        void f(int* param) {
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleTest, MixedInitAndUninit) {
    UninitPointerRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* good = nullptr;
            int* bad;
            double* worse;
        }
    )");
    ASSERT_EQ(results.size(), 2);
}

TEST(UninitPointerRuleTest, MessageContainsVarName) {
    UninitPointerRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* myPointer;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].message.find("myPointer"), std::string::npos);
}

TEST(UninitPointerRuleTest, NoPointerNoFinding) {
    UninitPointerRule rule;
    auto results = runRule(rule, R"(
        int add(int a, int b) {
            return a + b;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleTest, LocationInfo) {
    UninitPointerRule rule;
    auto results = runRule(rule, "void f() {\n    int* ptr;\n}\n");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].line, 2);
}
