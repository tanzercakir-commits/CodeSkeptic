// CFG cache: ONE build per function, shared by consumers.
// Invariants: (1) within the same TU, summary flows + the rule use the
// same CFG (a hit), (2) the store empties at TU end — a stale
// FunctionDecl* key must NOT leak into the next TU (address reuse would
// produce false hits, so this is a correctness condition, not hygiene).

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
    EXPECT_EQ(results.size(), 0u);  // guarded use is clean
    // Two functions = exactly two builds; the rest are hits (summary
    // scans + the rule's own run share the same CFGs)
    EXPECT_EQ(CfgCache::misses(), 2u);
    EXPECT_GE(CfgCache::hits(), 2u);
}

TEST(CfgCacheTest, ClearedAtTUEnd_NoStaleCarryover) {
    NullDerefRule rule;
    runRule(rule, R"(
        void a1() { int* p = 0; if (p) { int x = *p; (void)x; } }
    )");
    // TU ended: the store must be empty (no dangling FunctionDecl* keys)
    EXPECT_EQ(CfgCache::instance().size(), 0u);

    CfgCache::resetCounters();
    runRule(rule, R"(
        void b1() { int* q = 0; if (q) { int y = *q; (void)y; } }
    )");
    // A new TU must build from scratch — no false hits from the previous TU
    EXPECT_GE(CfgCache::misses(), 1u);
    EXPECT_EQ(CfgCache::instance().size(), 0u);
}
