#include "TestHelper.h"
#include "rules/NullDerefRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// --- Definite null dereference ---

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
    EXPECT_EQ(results[0].function, "f");  // Juliet scoring relies on this
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

// --- Possible null (MaybeNull) ---

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

// --- Guards: the old NullPointerRule's FP graveyard ---

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
    // Dereference on the true branch of p == nullptr: definite error
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
    // Inside the loop n is NonNull (clean); on loop exit n is definitely null
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

// --- Conservatism: unknown stays silent ---

TEST(NullDerefRuleTest, ParamUnguarded_Silent) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int* p) {
            int x = *p;
        }
    )");
    // Parameter is Unknown -> no report. This was the old rule's 68-FP trap.
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
    // &p went into a function -> p Unknown -> silent (conservative)
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, LinkedListBuildLoop_WarningNotError) {
    // The cJSON parse_array pattern: cur is assigned on the then-branch
    // in the first iteration and dereferenced on the else-branch in
    // later ones. Since the head/cur correlation is not tracked,
    // MaybeNull (Warning) is honestly reported — but calling it
    // "definitely null" (Error) from the early pre-fixpoint state WAS
    // wrong (engine regression test).
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
    EXPECT_EQ(results[0].severity, Severity::Warning);  // NOT Error
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

// --- Targeted path sensitivity (GuardedDisjuncts) ---

TEST(NullDerefPathSensitivityTest, CorrelatedGuards_AssignDeref_Clean) {
    // The Juliet int_07/08/09 pattern: assignment and dereference are
    // under the same invariant condition — no "may be null" FP must arise
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
    // Dereference on the wrong branch: on the flag==0 path data is
    // definitely null
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
    // Int facts work together with pointer nullness refinement:
    // both the flag correlation and the if(p) guard in the same function
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
    // The old "known FN" note turned out invalid: the fine-grained CFG
    // splits a multi-declaration into per-variable synthetic DeclStmts —
    // the second pointer is tracked too. Pinned as a regression test.
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
    // Trace v2: a definite-null coming purely from a guard, with no
    // assignment, used to have NO trace — now the condition point shows
    // up with a "null on this branch" note
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
    // The note must point to the condition's line (not the dereference's)
    EXPECT_LT(results[0].notes[0].line, results[0].line);
}
