#include "TestHelper.h"
#include "rules/MemoryLeakRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

TEST(MemoryLeakRuleTest, RawNewInt) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(42);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(MemoryLeakRuleTest, RawNewArray) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        void f() {
            char* buf = new char[256];
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(MemoryLeakRuleTest, NoNewNoFinding) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int x = 42;
            int* p = &x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleTest, StackAllocationClean) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        int add(int a, int b) {
            return a + b;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleTest, DeleteStillWarns) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(99);
            delete p;
        }
    )");
    // Raw new kullanıldı — delete olsa bile uyar
    ASSERT_EQ(results.size(), 1);
}

TEST(MemoryLeakRuleTest, MessageContainsVarName) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* myBuffer = new int(10);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].message.find("myBuffer"), std::string::npos);
}

TEST(MemoryLeakRuleTest, AssignmentAfterDecl) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p;
            p = new int(42);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
}

TEST(MemoryLeakRuleTest, ReturnRawNew) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        int* createValue() {
            return new int(100);
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(MemoryLeakRuleTest, ReturnNullptr_Clean) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        int* maybeCreate(bool flag) {
            if (flag) return nullptr;
            return nullptr;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleTest, MultiplePatterns) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        int* create() {
            return new int(1);
        }
        void f() {
            int* a = new int(2);
            int* b;
            b = new int(3);
        }
    )");
    ASSERT_EQ(results.size(), 3);
}

TEST(MemoryLeakRuleTest, AssignMessageContainsVarName) {
    MemoryLeakRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* buffer;
            buffer = new int(10);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].message.find("buffer"), std::string::npos);
}
