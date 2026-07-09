#include "TestHelper.h"
#include "rules/MemoryLeakRule_Ex.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

TEST(MemoryLeakRuleExTest, SimpleLeak) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(42);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(MemoryLeakRuleExTest, CorrectUsage_NewDelete) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(42);
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, ConditionalLeak) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int* p = new int(42);
            if (c) delete p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(MemoryLeakRuleExTest, BothBranchesDelete_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int* p = new int(42);
            if (c) delete p;
            else delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, ReturnEscape_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int* create() {
            int* p = new int(42);
            return p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, ReassignmentLeak) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(1);
            p = new int(2);
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(MemoryLeakRuleExTest, MallocFree_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" {
            void* malloc(unsigned long);
            void free(void*);
        }
        void f() {
            int* p = (int*)malloc(sizeof(int));
            free(p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, MallocNoFree_Leak) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" {
            void* malloc(unsigned long);
        }
        void f() {
            int* p = (int*)malloc(sizeof(int));
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(MemoryLeakRuleExTest, FunctionParamEscape_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void consume(int* p);
        void f() {
            int* p = new int(1);
            consume(p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, DoubleFree) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(42);
            delete p;
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(MemoryLeakRuleExTest, ArrayNewDelete_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int[10];
            delete[] p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, NoAllocation_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int x = 42;
            int* p = &x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, MultipleVars_OneLeaks) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* a = new int(1);
            int* b = new int(2);
            delete a;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// --- Use-after-free ---

TEST(MemoryLeakRuleExTest, UseAfterFree_Delete) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(1);
            delete p;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(MemoryLeakRuleExTest, UseAfterFree_CFree_Arrow) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        struct Node { int data; };
        void f() {
            Node* n = (Node*)malloc(sizeof(Node));
            free(n);
            int x = n->data;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

TEST(MemoryLeakRuleExTest, DeleteThenReassignThenUse_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(1);
            delete p;
            p = new int(2);
            int x = *p;
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, UseBeforeFree_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(1);
            int x = *p;
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, UseAfterFree_Subscript) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* arr = new int[10];
            delete[] arr;
            int x = arr[3];
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}
