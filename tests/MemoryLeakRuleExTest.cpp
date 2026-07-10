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
// Hedefli yol duyarliligi: korelasyonlu guard'lar (PathFacts)
// Juliet FP avinin kok nedeni — ayni degismez kosul iki kez test
// edildiginde yollarin karismasi. Motor degil, analiz state'i cozer
// (guard'li disjunktlar).
// ===================================================================

TEST(PathSensitivityTest, CorrelatedGuards_AllocFree_Clean) {
    // Juliet goodB2G/goodG2B kalibi birebir: kaynak ve lavabo ayni
    // global kosulla korunur — leak yok
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
    // if (flag) ... if (flag) ... bicimi (Juliet staticTrue varyanti)
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
    // if (!flag) alloc; if (!flag) free — olumsuzlama da eslesir
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
    // if (flag) alloc; if (!flag) free — free YANLIS dalda: leak gercek
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
    // Kosul degiskeni iki test arasinda degisiyor: korelasyon KURULMAZ
    // (anahtarlanmaz), muhafazakar uyari korunur — c==5 ilk testte
    // dogruysa alloc olur, ikinci test artik yanlis, free kacar
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
    // Fonksiyon cagrisi ASLA anahtarlanmaz (rand() korelasyonu yanlis
    // olurdu): iki check() cagrisi farkli sonuc verebilir → uyari kalir
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
    // Onceden FN'di: join'de Freed+Allocated karisimi ikinci free'yi
    // gizliyordu. Disjunktlarla ikinci if(flag) govdesine yalnizca
    // Freed yolu girer → double-free. Ayrica flag==0 yolunda hic free
    // yok → gercek exit-leak de raporlanir (iki bulgu da dogru).
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
    // Ayni sekilde: free ve kullanim ayni guard altinda → kesin UAF
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
    // BILINCLI TAVIZ: iki guard arasindaki cagri globali degistirebilir
    // (gercek leak gizlenebilir — FN yonu). Cagri etkilerini globallere
    // yaymamak Juliet'in printLine'li kaliplarinda FP'siz kalmanin
    // bedeli. Yerel/param kosullar icin bu risk YOKTUR (adresi kacmayan
    // yerele cagri dokunamaz).
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
    EXPECT_EQ(results.size(), 0);  // dokumante sinir
}
