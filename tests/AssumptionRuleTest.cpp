#include "TestHelper.h"
#include "engine/AssumptionMode.h"
#include "rules/AssumptionRule.h"

#include <gtest/gtest.h>

using namespace codeskeptic;
using namespace codeskeptic::testing;

// AssumptionRule (spec §20.2), v0: inferred undeclared non-null parameter
// preconditions. Opt-in — the rule is silent unless assumption mode is
// on, so the fixture toggles the process-global that StaticAnalyzer would
// otherwise set from --assumptions.

namespace {
class AssumptionRuleTest : public ::testing::Test {
protected:
    void SetUp() override { setAssumptionMode(true); }
    void TearDown() override { setAssumptionMode(false); }
};
} // namespace

// --- Opt-in gating ---

TEST(AssumptionRuleOptIn, SilentWhenModeOff) {
    setAssumptionMode(false);
    AssumptionRule rule;
    auto results = runRule(rule, R"(
        int f(int* p) { return *p; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Reported: dereferenced, never checked, undeclared ---

TEST_F(AssumptionRuleTest, DerefWithoutCheckIsInferredAssumption) {
    AssumptionRule rule;
    auto results = runRule(rule, R"(
        int f(int* p) { return *p; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "assumption");
    EXPECT_EQ(results[0].severity, Severity::Info);
}

TEST_F(AssumptionRuleTest, ArrowDerefCounts) {
    AssumptionRule rule;
    auto results = runRule(rule, R"(
        struct S { int x; };
        int f(struct S* s) { return s->x; }
    )");
    ASSERT_EQ(results.size(), 1u);
}

// --- Suppressed: guarded ---

TEST_F(AssumptionRuleTest, NullCheckedIsClean) {
    AssumptionRule rule;
    auto results = runRule(rule, R"(
        int f(int* p) { if (p == 0) return 0; return *p; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST_F(AssumptionRuleTest, TruthinessGuardIsClean) {
    AssumptionRule rule;
    auto results = runRule(rule, R"(
        int f(int* p) { if (!p) return 0; return *p; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Suppressed: not dereferenced ---

TEST_F(AssumptionRuleTest, NotDereferencedIsClean) {
    // p is only passed along, never dereferenced here — no non-null claim.
    AssumptionRule rule;
    auto results = runRule(rule, R"(
        void g(int*);
        void f(int* p) { g(p); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST_F(AssumptionRuleTest, NonPointerParamIgnored) {
    AssumptionRule rule;
    auto results = runRule(rule, R"(
        int f(int n) { return n + 1; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Suppressed: declared via contract (the "where verified?" answer) ---

TEST_F(AssumptionRuleTest, ContractedNonNullIsClean) {
    // The assumption is DOCUMENTED — requires p != null — so it is not
    // intent debt and stays silent.
    AssumptionRule rule;
    auto results = runRule(rule, R"(
        // cs: requires p != null
        int f(int* p) { return *p; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Multiple params ---

TEST_F(AssumptionRuleTest, OnlyUnguardedUnvalidatedParamReported) {
    // a is checked, b is dereferenced-unchecked → only b is reported.
    AssumptionRule rule;
    auto results = runRule(rule, R"(
        int f(int* a, int* b) {
            if (!a) return 0;
            return *a + *b;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}
