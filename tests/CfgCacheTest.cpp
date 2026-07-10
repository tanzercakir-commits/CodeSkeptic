// CFG onbellegi: fonksiyon basina TEK insa, tuketiciler paylasir.
// Degismezler: (1) ayni TU icinde ozet akislari + kural ayni CFG'yi
// kullanir (isabet), (2) TU bitiminde depo bosalir — bayat FunctionDecl*
// anahtari sonraki TU'ya SIZAMAZ (adres yeniden kullanimi sahte isabet
// ureteceginden bu dogruluk kosuludur, hijyen degil).

#include "TestHelper.h"
#include "engine/CfgCache.h"
#include "rules/NullDerefRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

TEST(CfgCacheTest, SharedWithinTU_SummaryFlowAndRuleReuse) {
    CfgCache::resetCounters();
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g;
        int* find(int k) { int* r = 0; if (k) r = &g; return r; }
        void f(int k) {
            int* p = find(k);
            if (p) { int x = *p; (void)x; }
        }
    )");
    EXPECT_EQ(results.size(), 0u);  // guard'li kullanim temiz
    // Iki fonksiyon = tam iki insa; gerisi isabet (ozet taramalari +
    // kuralin kendi kosusu ayni CFG'leri paylasir)
    EXPECT_EQ(CfgCache::misses(), 2u);
    EXPECT_GE(CfgCache::hits(), 2u);
}

TEST(CfgCacheTest, ClearedAtTUEnd_NoStaleCarryover) {
    NullDerefRule rule;
    runRule(rule, R"(
        void a1() { int* p = 0; if (p) { int x = *p; (void)x; } }
    )");
    // TU bitti: depo bos olmali (sarkan FunctionDecl* anahtari yok)
    EXPECT_EQ(CfgCache::instance().size(), 0u);

    CfgCache::resetCounters();
    runRule(rule, R"(
        void b1() { int* q = 0; if (q) { int y = *q; (void)y; } }
    )");
    // Yeni TU sifirdan insa etmeli — onceki TU'dan sahte isabet yok
    EXPECT_GE(CfgCache::misses(), 1u);
    EXPECT_EQ(CfgCache::instance().size(), 0u);
}
