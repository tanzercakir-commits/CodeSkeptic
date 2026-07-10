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
    EXPECT_EQ(results[0].rule_id, "double-free");
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

// ===================================================================
// Targeted path sensitivity: correlated guards (PathFacts)
// Root cause of the Juliet FP hunt — paths getting mixed when the same
// invariant condition is tested twice. Solved by the analysis state,
// not the engine (guarded disjuncts).
// ===================================================================

TEST(PathSensitivityTest, CorrelatedGuards_AllocFree_Clean) {
    // Verbatim Juliet goodB2G/goodG2B pattern: source and sink are
    // guarded by the same global condition — no leak
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int globalFive = 5;
        void f() {
            int* data = 0;
            if (globalFive == 5) data = (int*)malloc(4);
            if (globalFive == 5) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(PathSensitivityTest, CorrelatedGuards_Truthiness_Clean) {
    // The if (flag) ... if (flag) ... form (Juliet staticTrue variant)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int flag;
        void f() {
            int* data = 0;
            if (flag) data = (int*)malloc(4);
            if (flag) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(PathSensitivityTest, CorrelatedGuards_NegatedPair_Clean) {
    // if (!flag) alloc; if (!flag) free — negation matches too
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int flag;
        void f() {
            int* data = 0;
            if (!flag) data = (int*)malloc(4);
            if (!flag) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(PathSensitivityTest, AntiCorrelatedGuards_LeakStays) {
    // if (flag) alloc; if (!flag) free — free is on the WRONG branch:
    // the leak is real
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int flag;
        void f() {
            int* data = 0;
            if (flag) data = (int*)malloc(4);
            if (!flag) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(PathSensitivityTest, MutatedBetweenGuards_WarningStays) {
    // The condition variable changes between the two tests: NO
    // correlation is established (not keyed), the conservative warning
    // is kept — if c==5 is true at the first test the alloc happens,
    // the second test is now false, the free is missed
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void f(int c) {
            int* data = 0;
            if (c == 5) data = (int*)malloc(4);
            c = 0;
            if (c == 5) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(PathSensitivityTest, FunctionCallGuard_NotCorrelated) {
    // A function call is NEVER keyed (a rand() correlation would be
    // wrong): two check() calls may give different results → the
    // warning stays
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int check();
        void f() {
            int* data = 0;
            if (check()) data = (int*)malloc(4);
            if (check()) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(PathSensitivityTest, CorrelatedGuards_DoubleFree_NowCaught) {
    // Used to be an FN: the Freed+Allocated mix at the join hid the
    // second free. With disjuncts only the Freed path enters the second
    // if(flag) body → double-free. Also no free at all on the flag==0
    // path → the real exit-leak is reported too (both findings are
    // correct).
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int flag;
        void f() {
            int* data = (int*)malloc(4);
            if (flag) free(data);
            if (flag) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[0].rule_id, "double-free");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_EQ(results[1].rule_id, "memory-leak");
    EXPECT_EQ(results[1].severity, Severity::Warning);
}

TEST(PathSensitivityTest, CorrelatedGuards_UAF_NowCaught) {
    // Likewise: free and use under the same guard → definite UAF
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int flag;
        void f() {
            int* data = (int*)malloc(4);
            if (flag) free(data);
            if (flag) { int x = *data; (void)x; }
            free(data);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

TEST(DocumentedLimitTest, CallBetweenCorrelatedGuards_MayMaskLeak) {
    // DELIBERATE TRADE-OFF: a call between the two guards may change
    // the global (a real leak can be hidden — FN direction). Not
    // propagating call effects to globals is the price of staying
    // FP-free on Juliet's printLine-laden patterns. For local/param
    // conditions this risk does NOT exist (a call cannot touch a local
    // whose address does not escape).
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void mayToggle();
        int flag;
        void f() {
            int* data = 0;
            if (flag) data = (int*)malloc(4);
            mayToggle();
            if (flag) free(data);
        }
    )");
    EXPECT_EQ(results.size(), 0);  // documented limit
}

TEST(MemoryLeakRuleExTest, AddrOfArg_Escapes_NoLeak) {
    // sink(&p): the callee may free/reassign p — tracking stops.
    // (Juliet 63x variant: when &data went unseen, a bogus exit-leak
    // was born.)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void sink(int** pp);
        void f() {
            int* p = (int*)malloc(4);
            sink(&p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}
