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

// ===================================================================
// Cross-TU ozetler (Ufuk 2: whole-program modu)
// Cagrilan BASKA dosyada tanimli: ozet 1. geciste hasat edilir,
// 2. gecis kurali cagiran dosyada Opaque yerine gercek ozeti gorur.
// ===================================================================

TEST(CrossTUTest, MaybeNullReturn_AcrossTU_Warning) {
    NullDerefRule rule;
    auto results = runRuleCrossTU(rule, R"(
        int* find(int c) {
            static int v = 1;
            if (c) return &v;
            return 0;
        }
    )", R"(
        int* find(int c);
        void f(int c) {
            int* p = find(c);
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "null-deref");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(CrossTUTest, FreeWrapper_AcrossTU_DoubleFree) {
    MemoryLeakRule_Ex rule;
    auto results = runRuleCrossTU(rule, R"(
        extern "C" void free(void*);
        void my_free(int* p) { free(p); }
    )", R"(
        extern "C" void* malloc(unsigned long);
        void my_free(int* p);
        void f() {
            int* q = (int*)malloc(4);
            my_free(q);
            my_free(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "double-free");
}

TEST(CrossTUTest, ReadsOnlyCallee_AcrossTU_LeakVisible) {
    // Baska dosyadaki salt-okur yardimci leak'i artik GIZLEMEZ
    // (tek-TU modda Opaque -> Escapes -> sessizdi)
    MemoryLeakRule_Ex rule;
    auto results = runRuleCrossTU(rule, R"(
        void use(int* p) { int x = *p; (void)x; }
    )", R"(
        extern "C" void* malloc(unsigned long);
        void use(int* p);
        void f() {
            int* q = (int*)malloc(4);
            use(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
}

TEST(CrossTUTest, StaticCallee_NotShared) {
    // callee-TU'daki static (dosya-yerel) make ile caller-TU'nun
    // extern bildirimi FARKLI fonksiyonlar — ozet TASINMAMALI.
    // Tasinsaydi NeverNull... yerine null donebilirlik iddia edilirdi.
    NullDerefRule rule;
    auto results = runRuleCrossTU(rule, R"(
        static int* make() { return 0; }
        int* unused() { return make(); }
    )", R"(
        int* make();
        void f() {
            int* p = make();
            int x = *p;
            (void)x;
        }
    )");
    // Opaque kalmali -> Unknown -> sessiz (muhafazakar)
    ASSERT_EQ(results.size(), 0);
}

TEST(CrossTUTest, WithoutHarvest_StaysConservative) {
    // Ayni cagiran kod TEK-TU modda (hasatsiz): Opaque -> sessiz.
    // Cross-TU kazancinin kontrol grubu.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* find(int c);
        void f(int c) {
            int* p = find(c);
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// ===================================================================
// Donus-nullness dataflow'u (v2): `return p;` yollari
// Yapisal degerlendirme Unknown birakirdi; mini null-akisi (kendi
// motorumuzla) degisken donduren yollari akis-DUYARLI cozer.
// ===================================================================

TEST(ReturnFlowTest, InitNullThenSet_NeverNull_Silent) {
    // FP-katili vaka: akis-duyarsiz "bir yerde NULL atanmis" kestirmesi
    // burada yanlis MaybeNull uretirdi. Akis-duyarli: return aninda
    // p = &g kesin non-null -> fonksiyon NeverNull -> sessiz.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g;
        int* get() {
            int* p = 0;
            p = &g;
            return p;
        }
        void f() {
            int* q = get();
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ReturnFlowTest, MaybeNullVarFlow_Warning) {
    // find() kalibi: r bazi yollarda null kalir -> MaybeNull ->
    // korumasiz dereference uyari + iz notu
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g;
        int* find(int k) {
            int* r = 0;
            if (k) r = &g;
            return r;
        }
        void f(int k) {
            int* p = find(k);
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
    ASSERT_EQ(results[0].notes.size(), 1u);
    EXPECT_NE(results[0].notes[0].message.find("possibly-null"),
              std::string::npos);
}

TEST(ReturnFlowTest, GuardedFallthrough_NeverNull_Silent) {
    // Erken-donus guard'i: `if (!p) return &fb;` sonrasi p kesin
    // non-null (assume-edge) -> iki yol da NonNull -> NeverNull
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g; int fb;
        int* wrap(int k) {
            int* p = 0;
            if (k) p = &g;
            if (!p) return &fb;
            return p;
        }
        void f(int k) {
            int* q = wrap(k);
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ReturnFlowTest, DefiniteNullVar_Warning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* bad() {
            int* p = 0;
            return p;
        }
        void f() {
            int* q = bad();
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ReturnFlowTest, ParamPassthrough_StaysUnknown_Silent) {
    // Parametre-duyarli ozet v2 kapsami disinda (belgelenmis sinir):
    // `return p;` (p param, hic atanmamis) Unknown kalir -> sessiz
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* id(int* p) { return p; }
        void f(int* a) {
            int* q = id(a);
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ReturnFlowTest, ChainThroughVariable_Warning) {
    // Zincir: inner degisken-akisiyla MaybeNull; outer onu degiskene
    // alip dondurur -> taramalar arasi yayilim (sweep 2) outer'i da
    // MaybeNull yapar
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g;
        int* inner(int k) {
            int* r = 0;
            if (k) r = &g;
            return r;
        }
        int* outer(int k) {
            int* t = inner(k);
            return t;
        }
        void f(int k) {
            int* p = outer(k);
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ReturnFlowTest, JulietBadSourceShape_ParamReassignedNull_Warning) {
    // Juliet akis-varyanti kaynagi birebir: parametre NULL'a atanip
    // dondurulur -> MaybeNull -> cagiranin korumasiz kullanimi uyari
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* badSource(int* data) {
            data = 0;
            return data;
        }
        void f(int* data) {
            data = badSource(data);
            int x = *data;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ReturnFlowTest, CrossTU_VarFlowMaybeNull_Warning) {
    // Degisken-akisli MaybeNull cross-TU depodan da tasinir
    NullDerefRule rule;
    auto results = runRuleCrossTU(rule, R"(
        int g;
        int* find(int k) {
            int* r = 0;
            if (k) r = &g;
            return r;
        }
    )", R"(
        int* find(int k);
        void f(int k) {
            int* p = find(k);
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// ===================================================================
// Ozet kaliciligi (Cross-TU v2): saveGlobal / loadGlobal +
// --summary-out / --summary-in uctan uca.
// Degismezler: (1) yukleme davranis olarak hasatla es-deger, (2) bozuk
// dosya butunuyle reddedilir — kismi veri guclu iddiaya donusemez,
// (3) cakisan kayitlar muhafazakar birlesir.
// ===================================================================

#include "analyzer/StaticAnalyzer.h"
#include "config/Config.h"
#include "engine/FunctionSummary.h"

#include <fstream>

namespace {

std::string writePersistFile(const std::string& name,
                             const std::string& content) {
    std::string path = ::testing::TempDir() + name;
    std::ofstream file(path);
    file << content;
    return path;
}

std::string readWholeFile(const std::string& path) {
    std::ifstream file(path);
    return {std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()};
}

// Test izolasyonu: global depo surec-omurlu — her test temiz baslasin
// ve temiz biraksin (tek-surec kosumda sizinti sonraki testleri bozar)
struct GlobalStoreGuard {
    GlobalStoreGuard() { SummaryRegistry::instance().clearGlobal(); }
    ~GlobalStoreGuard() { SummaryRegistry::instance().clearGlobal(); }
};

} // anonymous namespace

TEST(SummaryPersistTest, FileFormat_RoundTripDeterministic) {
    GlobalStoreGuard guard;
    const std::string content =
        "zerodefect-summaries v1\n"
        "alpha/1\tN\tR\n"
        "beta/2\tM\tOF\n"
        "gamma/0\tU\t-\n";
    auto inPath = writePersistFile("sum_roundtrip_in.txt", content);

    auto& registry = SummaryRegistry::instance();
    ASSERT_TRUE(registry.loadGlobal(inPath));
    EXPECT_EQ(registry.globalSize(), 3u);

    auto outPath = ::testing::TempDir() + "sum_roundtrip_out.txt";
    ASSERT_TRUE(registry.saveGlobal(outPath));
    EXPECT_EQ(readWholeFile(outPath), content);
}

TEST(SummaryPersistTest, ConflictingLoad_MergesConservative) {
    GlobalStoreGuard guard;
    auto pathA = writePersistFile("sum_conflict_a.txt",
        "zerodefect-summaries v1\n"
        "foo/1\tN\tR\n");
    auto pathB = writePersistFile("sum_conflict_b.txt",
        "zerodefect-summaries v1\n"
        "foo/1\tM\tF\n");

    auto& registry = SummaryRegistry::instance();
    ASSERT_TRUE(registry.loadGlobal(pathA));
    ASSERT_TRUE(registry.loadGlobal(pathB));
    EXPECT_EQ(registry.globalSize(), 1u);

    // Uyusmayan alanlar zayif iddiaya duser: N vs M -> U, R vs F -> O
    auto outPath = ::testing::TempDir() + "sum_conflict_out.txt";
    ASSERT_TRUE(registry.saveGlobal(outPath));
    EXPECT_EQ(readWholeFile(outPath),
              "zerodefect-summaries v1\nfoo/1\tU\tO\n");
}

TEST(SummaryPersistTest, CorruptFile_RejectedWhole) {
    GlobalStoreGuard guard;
    auto& registry = SummaryRegistry::instance();

    auto good = writePersistFile("sum_good.txt",
        "zerodefect-summaries v1\n"
        "keep/1\tN\tR\n");
    ASSERT_TRUE(registry.loadGlobal(good));

    // Yanlis baslik: reddet
    auto badHeader = writePersistFile("sum_bad_header.txt",
        "some-other-format v9\nfoo/1\tN\tR\n");
    EXPECT_FALSE(registry.loadGlobal(badHeader));

    // Gecerli baslik ama bozuk kayit (bilinmeyen etki karakteri):
    // dosyanin TAMAMI reddedilir — onceki gecerli satiri da almayiz
    auto badLine = writePersistFile("sum_bad_line.txt",
        "zerodefect-summaries v1\n"
        "bar/1\tN\tR\n"
        "baz/1\tX\tqq\n");
    EXPECT_FALSE(registry.loadGlobal(badLine));

    // Eksik alanli satir: reddet
    auto badFields = writePersistFile("sum_bad_fields.txt",
        "zerodefect-summaries v1\n"
        "noeffects/1\tN\n");
    EXPECT_FALSE(registry.loadGlobal(badFields));

    // Depo ilk yuklemeden beri degismemis olmali
    EXPECT_EQ(registry.globalSize(), 1u);
    auto outPath = ::testing::TempDir() + "sum_untouched_out.txt";
    ASSERT_TRUE(registry.saveGlobal(outPath));
    EXPECT_EQ(readWholeFile(outPath),
              "zerodefect-summaries v1\nkeep/1\tN\tR\n");
}

TEST(SummaryPersistTest, MissingFile_ReturnsFalse) {
    GlobalStoreGuard guard;
    EXPECT_FALSE(SummaryRegistry::instance().loadGlobal(
        ::testing::TempDir() + "sum_no_such_file.txt"));
    EXPECT_EQ(SummaryRegistry::instance().globalSize(), 0u);
}

TEST(SummaryPersistTest, EndToEnd_SummaryOutThenIn_CrossTUFinding) {
    // Artimli whole-program hikayesinin tamami: 1. kosu callee
    // dosyasindan ozet hasat edip diske yazar; 2. kosu YALNIZ caller
    // dosyasini ozet dosyasiyla analiz eder ve cross-TU bulguyu verir.
    // Analizorlerin dtor'u global depoyu temizler — bilgiyi 2. kosuya
    // tasiyan tek sey DOSYAdir.
    GlobalStoreGuard guard;
    auto calleePath = writePersistFile("sumpersist_callee.cpp", R"(
        int g;
        int* find(int c) {
            if (c) return &g;
            return 0;
        }
    )");
    auto callerPath = writePersistFile("sumpersist_caller.cpp", R"(
        int* find(int c);
        void f(int c) {
            int* p = find(c);
            int x = *p;
            (void)x;
        }
    )");
    auto summaryPath = ::testing::TempDir() + "sumpersist_store.txt";

    {
        Config config;
        config.setSourcePath(calleePath);
        config.setSummaryOut(summaryPath);
        StaticAnalyzer analyzer(std::move(config));
        analyzer.addRule<NullDerefRule>();
        analyzer.run();
    }
    EXPECT_NE(readWholeFile(summaryPath).find("find/1\tM"),
              std::string::npos);

    // Kontrol: ozetsiz kosu muhafazakar — Opaque, sessiz
    {
        Config config;
        config.setSourcePath(callerPath);
        StaticAnalyzer analyzer(std::move(config));
        analyzer.addRule<NullDerefRule>();
        analyzer.run();
        EXPECT_EQ(analyzer.diagnostics().size(), 0u);
    }

    // Ozet dosyasiyla: yalniz caller analiz edilir, bulgu gorunur
    {
        Config config;
        config.setSourcePath(callerPath);
        config.setSummaryIn(summaryPath);
        StaticAnalyzer analyzer(std::move(config));
        analyzer.addRule<NullDerefRule>();
        analyzer.run();
        ASSERT_EQ(analyzer.diagnostics().size(), 1u);
        EXPECT_EQ(analyzer.diagnostics()[0].rule_id, "null-deref");
        EXPECT_EQ(analyzer.diagnostics()[0].severity, Severity::Warning);
    }
}
