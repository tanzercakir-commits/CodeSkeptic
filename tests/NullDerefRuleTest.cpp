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
    EXPECT_EQ(results[0].function, "f");  // Juliet puanlamasi buna dayanir
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

TEST(NullDerefRuleTest, LinkedListBuildLoop_WarningNotError) {
    // cJSON parse_array kalibi: cur ilk iterasyonda then-dalinda atanir,
    // sonrakilerde else-dalinda dereference edilir. head/cur korelasyonu
    // izlenmedigi icin MaybeNull (Warning) durustce raporlanir — ama
    // fixpoint oncesi erken state ile "kesinlikle null" (Error) DEMEK
    // yanlisti (motor regresyon testi).
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Node { Node* next; };
        void f(int n) {
            Node* head = nullptr;
            Node* cur = nullptr;
            for (int i = 0; i < n; i++) {
                Node* item = new Node;
                if (head == nullptr) {
                    head = item;
                    cur = item;
                } else {
                    cur->next = item;
                    cur = item;
                }
            }
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);  // Error DEGIL
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

// --- Hedefli yol duyarliligi (GuardedDisjuncts) ---

TEST(NullDerefPathSensitivityTest, CorrelatedGuards_AssignDeref_Clean) {
    // Juliet int_07/08/09 kalibi: atama ve dereference ayni degismez
    // kosul altinda — "may be null" FP'si dogmamali
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int flag;
        void f() {
            int v = 1;
            int* data = nullptr;
            if (flag) data = &v;
            if (flag) { int x = *data; (void)x; }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefPathSensitivityTest, AntiCorrelatedGuards_ErrorStays) {
    // Dereference yanlis dalda: flag==0 yolunda data kesin null
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int flag;
        void f() {
            int v = 1;
            int* data = nullptr;
            if (flag) data = &v;
            if (!flag) { int x = *data; (void)x; }
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(NullDerefPathSensitivityTest, PointerGuardStillWorks_WithFacts) {
    // Int gercekleri pointer nullness iyilestirmesiyle birlikte calisir:
    // hem flag korelasyonu hem if(p) guard'i ayni fonksiyonda
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int flag;
        int* make();
        void f() {
            int v = 1;
            int* data = nullptr;
            if (flag) data = &v;
            if (data) { int x = *data; (void)x; }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, MultiDeclaration_SecondPointerTracked) {
    // Eski "bilinen FN" notu gecersiz cikti: ince taneli CFG coklu
    // bildirimi degisken basina sentetik DeclStmt'lere boler — ikinci
    // pointer da izlenir. Regresyon testi olarak sabitlendi.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int *a = nullptr, *b = nullptr;
            int x = *b;
            (void)x; (void)a;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(NullDerefTraceTest, GuardOnlyNull_TraceShowsCondition) {
    // Iz v2: atama olmadan, salt guard'dan gelen kesin-null onceden
    // IZSIZDI — simdi kosul noktasi "bu dalda null" notuyla gorunur
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int* p) {
            if (p == 0) {
                int x = *p;
                (void)x;
            }
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
    ASSERT_FALSE(results[0].notes.empty());
    EXPECT_NE(results[0].notes[0].message.find("null on this branch"),
              std::string::npos);
    // Not, kosulun satirini gostermeli (dereference'in degil)
    EXPECT_LT(results[0].notes[0].line, results[0].line);
}
