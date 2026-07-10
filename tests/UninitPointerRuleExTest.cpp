#include "TestHelper.h"
#include "rules/UninitPointerRule_Ex.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

TEST(UninitPointerRuleExTest, BothBranchesInit_Clean) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int cond) {
            int* p;
            int a = 1, b = 2;
            if (cond) { p = &a; }
            else { p = &b; }
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleExTest, OneBranchOnly_Dangerous) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int cond) {
            int* p;
            int a = 1;
            if (cond) { p = &a; }
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "uninit-ptr");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(UninitPointerRuleExTest, LoopWithInitBeforeUse_Clean) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p;
            int x = 5;
            for (int i = 0; i < 10; i++) {
                p = &x;
                int v = *p;
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleExTest, LoopWithoutInit_Dangerous) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p;
            for (int i = 0; i < 10; i++) {
                int v = *p;
            }
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(UninitPointerRuleExTest, EarlyReturnBeforeUse_Clean) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int cond) {
            int* p;
            if (cond) return;
            int x = 1;
            p = &x;
            int v = *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleExTest, AddressOfOutParam_Clean) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void init(int** pp);
        void f() {
            int* p;
            init(&p);
            int v = *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleExTest, SwitchAllCasesInit_Clean) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int x) {
            int* p;
            int a = 1, b = 2, c = 3;
            switch (x) {
                case 0: p = &a; break;
                case 1: p = &b; break;
                default: p = &c; break;
            }
            int v = *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleExTest, BasicUninitDereferenced) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* ptr;
            int v = *ptr;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "uninit-ptr");
}

TEST(UninitPointerRuleExTest, InitializedNullptr_NoDereference_Clean) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* ptr = nullptr;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleExTest, NoDereference_NoDiagnostic) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* ptr;
        }
    )");
    // Eski rule bunu raporlardı, yeni rule raporlamaz
    // çünkü dereference noktası yok
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPointerRuleExTest, ArrowDeref_Dangerous) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Node { int data; };
        void f() {
            Node* n;
            int x = n->data;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(UninitPointerRuleExTest, ArraySubscriptDeref_Dangerous) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* arr;
            int x = arr[0];
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(UninitPointerRuleExTest, MultipleUninitSameFunction) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* a;
            int* b;
            int x = *a;
            int y = *b;
        }
    )");
    ASSERT_EQ(results.size(), 2);
}

TEST(UninitPointerRuleExTest, NestedIf_DeepMerge) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int x, int y, int z) {
            int* p;
            int val = 1;
            if (x) {
                if (y) {
                    if (z) {
                        p = &val;
                    }
                }
            }
            int r = *p;
        }
    )");
    // Sadece x && y && z path'inde init var, diğer 7 path'te uninit
    ASSERT_EQ(results.size(), 1);
}

// --- Hedefli yol duyarliligi (GuardedDisjuncts) ---

TEST(UninitPtrPathSensitivityTest, CorrelatedGuards_InitUse_Clean) {
    // Juliet char_07 kalibi: init ve kullanim ayni degismez kosul altinda
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        int flag;
        void f() {
            int v = 1;
            int* data;
            if (flag == 5) data = &v;
            if (flag == 5) { int x = *data; (void)x; }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(UninitPtrPathSensitivityTest, AntiCorrelatedGuards_ErrorStays) {
    // Init yanlis dalda: flag!=5 yolunda data init'siz dereference edilir
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        int flag;
        void f() {
            int v = 1;
            int* data;
            if (flag == 5) data = &v;
            if (flag != 5) { int x = *data; (void)x; }
        }
    )");
    ASSERT_EQ(results.size(), 1);
}
