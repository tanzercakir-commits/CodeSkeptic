#include "TestHelper.h"
#include "rules/NullDerefRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// --- Kesin null dereference ---

TEST(NullDerefRuleTest, DefiniteNullDeref) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = nullptr;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "null-deref");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(NullDerefRuleTest, ZeroLiteralInit) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = 0;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(NullDerefRuleTest, ArrowDeref) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Node { int data; };
        void f() {
            Node* n = nullptr;
            int x = n->data;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(NullDerefRuleTest, SubscriptDeref) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* a = nullptr;
            int x = a[0];
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(NullDerefRuleTest, AssignNullInsideGuard) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int* p) {
            if (p) {
                p = nullptr;
                int x = *p;
            }
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

// --- Olasi null (MaybeNull) ---

TEST(NullDerefRuleTest, MaybeNull_Warning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int v = 1;
            int* p = nullptr;
            if (c) p = &v;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// --- Guard'lar: eski NullPointerRule'un FP mezarligi ---

TEST(NullDerefRuleTest, TruthinessGuard_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int v = 1;
            int* p = nullptr;
            if (c) p = &v;
            if (p) {
                int x = *p;
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, EarlyReturnGuard_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int v = 1;
            int* p = nullptr;
            if (c) p = &v;
            if (!p) return;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, NotEqualGuard_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = nullptr;
            if (p != nullptr) {
                int x = *p;
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, EqualsNullGuard_DefiniteError) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int* p) {
            if (p == nullptr) {
                int x = *p;
            }
        }
    )");
    // p == nullptr dogru dalinda dereference: kesin hata
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(NullDerefRuleTest, ShortCircuitAnd_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Node { int data; };
        void f(Node* n) {
            if (n && n->data > 0) {
                int x = n->data;
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, WhileGuard_ErrorAfterLoop) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Node { int data; Node* next; };
        void f(Node* n) {
            while (n) {
                n = n->next;
            }
            int x = n->data;
        }
    )");
    // Dongu icinde n NonNull (temiz); donguden cikista n kesin null
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

// --- Muhafazakarlik: bilinmeyen sessiz kalir ---

TEST(NullDerefRuleTest, ParamUnguarded_Silent) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int* p) {
            int x = *p;
        }
    )");
    // Parametre Unknown -> rapor yok. Eski kuralin 68-FP tuzagi buydu.
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, AssignAddressOf_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int v = 1;
            int* p = nullptr;
            p = &v;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, AssignNew_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = nullptr;
            p = new int(5);
            int x = *p;
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, OutParamEscape_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void init(int** pp);
        void f() {
            int* p = nullptr;
            init(&p);
            int x = *p;
        }
    )");
    // &p bir fonksiyona gitti -> p Unknown -> sessiz (muhafazakar)
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, OpaqueFunctionReturn_Silent) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* make();
        void f() {
            int* p = make();
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}
