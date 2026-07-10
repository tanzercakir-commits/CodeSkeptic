// Best-case / worst-case matrix:
//  - Best case: defensive, correctly written code must stay CLEAN (FP
//    bound)
//  - Worst case: pathological CFG shapes must converge and seeded bugs
//    MUST be caught (FN + convergence bound)
//  - Documented limits: known FNs are pinned as tests so we notice if
//    the behavior changes (in sync with todo.md)

#include "TestHelper.h"
#include "rules/DivByZeroRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/NullDerefRule.h"
#include "rules/UninitPointerRule_Ex.h"

#include <string>
#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// ===================================================================
// BEST CASE — defensive patterns must stay clean
// ===================================================================

TEST(BestCaseTest, GotoFailCleanup_Clean) {
    // The idiom cJSON uses everywhere: error paths jump to a single
    // cleanup label. Both paths free — neither a leak nor a double-free.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int f(int c) {
            int* p = (int*)malloc(4);
            if (p == 0) return -1;
            if (c) goto fail;
            free(p);
            return 0;
        fail:
            free(p);
            return -1;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(BestCaseTest, TernaryGuardDivision_Clean) {
    // A ternary condition is a branch edge too: on the true arm z is NonZero
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f(int z) {
            int zero = 0;
            if (z == 0) zero = 1;
            int x = z ? 100 / z : 0;
            (void)zero;
            return x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(BestCaseTest, TernaryGuardNullDeref_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int f(int* p) {
            int v = 0;
            if (p == nullptr) v = 1;
            return p ? *p : v;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(BestCaseTest, BreakEdgeGuard_Clean) {
    // The loop can only be exited while z != 0 — via the break edge,
    // z is NonZero after the loop
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int next();
        int f() {
            int z = 0;
            while (true) {
                z = next();
                if (z != 0) break;
            }
            return 100 / z;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(BestCaseTest, ContinueGuard_Clean) {
    // The unguarded path is skipped via continue
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Node { int data; Node* next; };
        int f(Node** items, int n) {
            int total = 0;
            for (int i = 0; i < n; i++) {
                Node* p = items[i];
                if (!p) continue;
                total += p->data;
            }
            return total;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(BestCaseTest, CommaOperatorOrdering_Clean) {
    // The fine-grained CFG preserves evaluation order: the assignment
    // comes before the division
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int z = 0;
            int x = (z = 5, 100 / z);
            return x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// ===================================================================
// WORST CASE — pathological shapes: convergence + seeded bugs
// ===================================================================

TEST(WorstCaseTest, DeepNesting_OnePathInits) {
    // 8 levels of nested ifs; only the innermost path initializes.
    // 255/256 paths are uninit — a report is a MUST, the analysis must
    // converge.
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int a, int b, int c, int d, int e, int g, int h, int k) {
            int v = 1;
            int* p;
            if (a) { if (b) { if (c) { if (d) {
            if (e) { if (g) { if (h) { if (k) {
                p = &v;
            }}}}}}}}
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(WorstCaseTest, WideProductLattice_AllLeaksFound) {
    // A 30-variable product lattice: the iteration cap must scale with
    // the height and ALL leaks must be found (no half-done analysis)
    std::string code = "void f() {\n";
    for (int i = 0; i < 30; i++)
        code += "    int* p" + std::to_string(i) + " = new int(" +
                std::to_string(i) + ");\n";
    code += "}\n";

    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, code);
    ASSERT_EQ(results.size(), 30);
}

TEST(WorstCaseTest, LongElseIfChain_OneArmZero) {
    // Only one arm of the 12-arm chain assigns zero → possible div-by-zero
    std::string code = "void f(int x) {\n    int z = 1;\n";
    code += "    if (x == 1) z = 2;\n";
    for (int i = 2; i <= 10; i++)
        code += "    else if (x == " + std::to_string(i) + ") z = " +
                std::to_string(i + 1) + ";\n";
    code += "    else if (x == 11) z = 0;\n";
    code += "    int r = 100 / z;\n    (void)r;\n}\n";

    DivByZeroRule rule;
    auto results = runRule(rule, code);
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(WorstCaseTest, NestedLoopConditionalFree) {
    // a,b,c NEVER change inside the function: single-threaded, the only
    // way out of while(a) is a==0 — on that path p is never allocated.
    // The path-sensitive analysis is right not to report an exit-leak
    // (the old 2nd finding was an artifact of path insensitivity). The
    // reassign-leak inside the loop is real and is reported.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int a, int b, int c) {
            int* p = nullptr;
            while (a) {
                while (b) {
                    p = new int(1);
                    if (c) delete p;
                }
            }
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(WorstCaseTest, NestedLoopConditionalFree_MutatedConds) {
    // Realistic loop: the conditions change (a--, b--) → they are not
    // keyed, the exit is genuinely reachable → reassign-leak +
    // exit-leak together
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int a, int b, int c) {
            int* p = nullptr;
            while (a--) {
                while (b--) {
                    p = new int(1);
                    if (c) delete p;
                }
            }
        }
    )");
    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[0].severity, Severity::Warning);
    EXPECT_EQ(results[1].severity, Severity::Warning);
}

TEST(WorstCaseTest, DoWhileFirstIteration_UninitDeref) {
    // A do-while body runs unconditionally on the first iteration: the
    // dereference BEFORE the init must be caught (fixpoint reporting
    // must not miss it)
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int v = 1;
            int* p;
            do {
                int x = *p;
                p = &v;
                (void)x;
            } while (c);
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(WorstCaseTest, GotoBackwardLoop) {
    // goto ile kurulmus dongu: n <= 0 yolunda p hic init edilmiyor
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int n) {
            int v = 1;
            int* p;
        again:
            if (n > 0) {
                p = &v;
                n--;
                goto again;
            }
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(WorstCaseTest, SwitchWithoutDefault_MaybeUninit) {
    // default'suz switch: hicbir case eslesmezse p uninit kalir
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int x) {
            int a = 1;
            int* p;
            switch (x) {
                case 0: p = &a; break;
                case 1: p = &a; break;
            }
            int v = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

// ===================================================================
// BELGELENMIS SINIRLAR — bilinen FN'ler (davranis degisirse fark edelim)
// ===================================================================

TEST(DocumentedLimitTest, UnreachableCodeNotAnalyzed) {
    // return sonrasi kod CFG'de erisimsiz — analiz edilmez (bilincli:
    // olu koddaki "hatalar" calisan programi etkilemez)
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            return;
            int* p;
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(DocumentedLimitTest, SelfAssignmentHidesUninit_KnownFN) {
    // p = p atamasi p'yi "Init" isaretler — bilinen soundness acigi.
    // Duzeltilirse bu test kirilir ve todo guncellenir.
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p;
            p = p;
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(DocumentedLimitTest, CompoundAssignNotModeled_KnownFN) {
    // z -= z sifir uretir ama CompoundAssignOperator izlenmiyor
    // (todo'da: BO_Assign disindaki atamalar AssignsUnknown bile degil)
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int z = 5;
            z -= z;
            return 100 / z;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(DocumentedLimitTest, ConditionalDoubleFree_KnownFN) {
    // if(c) delete p; delete p; — merge Freed+Allocated=Allocated,
    // ikinci delete yakalanmiyor. Path-sensitivity gerektirir (todo).
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int* p = new int(1);
            if (c) delete p;
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// ===================================================================
// DATAFLOW IZLERI — bulgular olay zinciriyle gelmeli
// ===================================================================

TEST(TraceTest, UseAfterFree_HasAllocAndFreeNotes) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(1);
            delete p;
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
    ASSERT_EQ(results[0].notes.size(), 2u);
    // Notlar kaynak sirasina gore: once alloc (satir 3), sonra free (4)
    EXPECT_EQ(results[0].notes[0].line, 3u);
    EXPECT_NE(results[0].notes[0].message.find("allocated"),
              std::string::npos);
    EXPECT_EQ(results[0].notes[1].line, 4u);
    EXPECT_NE(results[0].notes[1].message.find("freed"),
              std::string::npos);
}

TEST(TraceTest, ExitLeak_HasAllocNote) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(1);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0].notes.size(), 1u);
    EXPECT_EQ(results[0].notes[0].line, 3u);
}

TEST(TraceTest, NullDeref_HasAssignedNullNote) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int v = 1;
            int* p = nullptr;
            if (c) p = &v;
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0].notes.size(), 1u);
    EXPECT_EQ(results[0].notes[0].line, 4u);
    EXPECT_NE(results[0].notes[0].message.find("null"), std::string::npos);
}

TEST(TraceTest, DivByZero_HasAssignedZeroNote) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int z = 0;
            if (c) z = 5;
            int x = 100 / z;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0].notes.size(), 1u);
    EXPECT_EQ(results[0].notes[0].line, 3u);
}

TEST(TraceTest, UninitPtr_HasDeclaredNote) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p;
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0].notes.size(), 1u);
    EXPECT_EQ(results[0].notes[0].line, 3u);
    EXPECT_NE(results[0].notes[0].message.find("declared"),
              std::string::npos);
}
