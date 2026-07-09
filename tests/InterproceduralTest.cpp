// Interprosedurel v1 — fonksiyon ozetleri:
//  - Donus nullness'i: "null donebilir" fonksiyonun korumasiz kullanimi
//    uyari; guard'li kullanim temiz; NeverNull zinciri sessiz.
//  - Parametre etkileri: free-wrapper'lar double-free/UAF gorunur kilar;
//    salt-okur yardimcilar arkalarindaki leak'i gizlemez; saklayan/opak
//    cagrilar bugunku muhafazakarligi korur (regresyon yok).
//  - Rekursiyon guclu iddia uretmez (soundness).

#include "TestHelper.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/NullDerefRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// ===================================================================
// Donus nullness'i
// ===================================================================

TEST(InterprocNullTest, MaybeNullReturn_UnguardedDeref_Warning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* find(int key) {
            if (key < 0) return nullptr;
            return new int(key);
        }
        int use(int key) {
            int* p = find(key);
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
    // Iz: olasi-null atamanin kaynagi gorunmeli
    ASSERT_EQ(results[0].notes.size(), 1u);
    EXPECT_NE(results[0].notes[0].message.find("possibly-null"),
              std::string::npos);
}

TEST(InterprocNullTest, MaybeNullReturn_Guarded_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* find(int key) {
            if (key < 0) return nullptr;
            return new int(key);
        }
        int use(int key) {
            int* p = find(key);
            if (!p) return -1;
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocNullTest, NeverNullChain_Clean) {
    // a() kesin non-null; b() a'yi zincirler → b de NeverNull.
    // Korumasiz dereference sessiz kalmali.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* a() { return new int(1); }
        int* b() { return a(); }
        int use() {
            int* p = b();
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocNullTest, MaybeNullChain_TwoLevels_Warning) {
    // Null donebilirlik zincirden sizmali: inner null donebilir → outer da
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* inner(int k) {
            if (k) return nullptr;
            return new int(1);
        }
        int* outer(int k) { return inner(k); }
        int use(int k) {
            int* p = outer(k);
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(InterprocNullTest, RecursiveReturn_StaysUnknown_Silent) {
    // Rekursif fonksiyon kendi ozetini gorur (Unknown baslar) —
    // NeverNull iddiasi olusamaz ama MaybeNull de uydurulmaz → sessiz
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* r(int n) {
            if (n > 0) return r(n - 1);
            return new int(0);
        }
        int use(int n) {
            int* p = r(n);
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocNullTest, VariableReturn_Unknown_Silent) {
    // Degisken donduren yol v1'de Unknown — sessiz (belgelenmis sinir)
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* pick(int* a, int* b, int c) {
            if (c) return a;
            return b;
        }
        int use(int* a, int* b, int c) {
            int* p = pick(a, b, c);
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// ===================================================================
// Parametre etkileri
// ===================================================================

TEST(InterprocLeakTest, FreeWrapper_DoubleFree_Error) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void my_free(int* p) { free(p); }
        void f() {
            int* q = (int*)malloc(4);
            my_free(q);
            my_free(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "double-free");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(InterprocLeakTest, GuardedFreeWrapper_StillFrees) {
    // if (p) free(p) kalibi da Frees sayilir ("serbest birakabilir")
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void safe_free(int* p) { if (p) free(p); }
        void f() {
            int* q = (int*)malloc(4);
            safe_free(q);
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

TEST(InterprocLeakTest, FreeWrapperChain_TwoLevels) {
    // w2 → w1 → free zinciri sabit-nokta taramasiyla cozulmeli
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void w1(int* p) { free(p); }
        void w2(int* p) { w1(p); }
        void f() {
            int* q = (int*)malloc(4);
            w2(q);
            w2(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(InterprocLeakTest, ReadOnlyCallee_LeakVisible) {
    // Salt-okur yardimci sahiplik almaz: arkasindaki leak GORUNMELI.
    // (Onceden Escaped muhafazakarligi gizliyordu — yeni tespit.)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int read_value(const int* p) { return *p; }
        void f() {
            int* q = new int(7);
            int x = read_value(q);
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
    EXPECT_NE(results[0].message.find("q"), std::string::npos);
}

TEST(InterprocLeakTest, StoringCallee_NoLeakReport) {
    // Saklayan cagri sahiplik devri olabilir → Escaped (bugunku davranis)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int* g_slot = nullptr;
        void keep(int* p) { g_slot = p; }
        void f() {
            int* q = new int(7);
            keep(q);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocLeakTest, AliasingCallee_NowFrees_DoubleFree) {
    // cJSON_Delete kalibi: parametre yerel imlece alinip free edilir.
    // v2 alias izleme: cur, p'nin temiz alias'i → delete_list = Frees →
    // cift cagri double-free. (v1'de muhafazakar sessizdi.)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void delete_list(int* p) {
            int* cur = p;
            free(cur);
        }
        void f() {
            int* q = (int*)malloc(4);
            delete_list(q);
            delete_list(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_EQ(results[0].rule_id, "double-free");
}

// ===================================================================
// Alias izleme (v2)
// ===================================================================

TEST(InterprocAliasTest, CursorLoopWalk_RealCJSONDeleteShape) {
    // Gercek cJSON_Delete sekli: parametre dongude yeniden atanir,
    // her iterasyonda free edilir. May-semantik: ilk iterasyon orijinali
    // serbest birakir → Frees → wrapper sonrasi kullanim UAF.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        struct Node { struct Node* next; };
        void delete_all(struct Node* item) {
            struct Node* next = nullptr;
            while (item != nullptr) {
                next = item->next;
                free(item);
                item = next;
            }
        }
        void f() {
            Node* list = (Node*)malloc(sizeof(Node));
            list->next = nullptr;
            delete_all(list);
            Node* again = list->next;
            (void)again;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

TEST(InterprocAliasTest, AliasChain_TwoHops_Frees) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void destroy(int* p) {
            int* a = p;
            int* b = a;
            free(b);
        }
        void f() {
            int* q = (int*)malloc(4);
            destroy(q);
            destroy(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(InterprocAliasTest, TaintedAlias_ImpureSource_Conservative) {
    // Alias once p'den, sonra kirli kaynaktan besleniyor → izlenemez →
    // Stores → sessiz (yanlis Frees iddiasi FP dogururdu)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int* pick();
        void maybe_free(int* p, int c) {
            int* l = p;
            if (c) l = pick();
            free(l);
        }
        void f() {
            int* q = (int*)malloc(4);
            maybe_free(q, 0);
            maybe_free(q, 1);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocAliasTest, MultiParamAlias_Conservative) {
    // Ayni yerel iki parametreden birden ulasilabiliyor → hicbirine
    // guvenle baglanamaz → ikisi de Stores → sessiz
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void free_one(int* a, int* b, int c) {
            int* l = a;
            if (c) l = b;
            free(l);
        }
        void f() {
            int* q = (int*)malloc(4);
            int* r = (int*)malloc(4);
            free_one(q, r, 0);
            free_one(q, r, 0);
            free(r);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocAliasTest, AliasStoredToGlobal_Stores) {
    // Alias globale yaziliyor → sahiplik devri olabilir → Stores →
    // cagiran tarafta leak raporu YOK (yanlis ReadsOnly FP'si engellendi)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int* g_slot = nullptr;
        void keep_via_alias(int* p) {
            int* l = p;
            g_slot = l;
        }
        void f() {
            int* q = new int(7);
            keep_via_alias(q);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocAliasTest, AliasReturned_Stores) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int* identity(int* p) {
            int* l = p;
            return l;
        }
        void f() {
            int* q = new int(7);
            int* r = identity(q);
            (void)r;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocAliasTest, AddressTakenAlias_Conservative) {
    // Alias'in adresi aliniyor → disaridan yazilabilir → izlenemez
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void reseat(int** pp);
        void weird_free(int* p) {
            int* l = p;
            reseat(&l);
            free(l);
        }
        void f() {
            int* q = (int*)malloc(4);
            weird_free(q);
            weird_free(q);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocAliasTest, ReadOnlyThroughAlias_LeakVisible) {
    // Salt-okur kullanim alias uzerinden de ReadsOnly kalmali:
    // arkasindaki leak gorunur
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int peek(int* p) {
            int* l = p;
            return *l;
        }
        void f() {
            int* q = new int(7);
            int x = peek(q);
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(InterprocLeakTest, ExternalCallee_StillEscapes) {
    // Govdesi gorunmeyen fonksiyon Opaque → Escaped → sessiz (regresyon yok)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void unknown(int* p);
        void f() {
            int* q = new int(7);
            unknown(q);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocLeakTest, MutualRecursionParam_Conservative_Silent) {
    // Karsilikli rekursiyon: Opaque baslangic Stores'a oturur —
    // guclu iddia (Frees/ReadsOnly) rekursiyondan sizamaz
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void r2(int* p, int n);
        void r1(int* p, int n) { if (n) r2(p, n - 1); }
        void r2(int* p, int n) { if (n) r1(p, n - 1); }
        void f() {
            int* q = new int(7);
            r1(q, 3);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocLeakTest, DeleteWrapper_UAF) {
    // C++ delete iceren wrapper da Frees
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void destroy(int* p) { delete p; }
        void f() {
            int* q = new int(7);
            destroy(q);
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}
