#include "engine/CoverageReport.h"

#include <gtest/gtest.h>

using namespace codeskeptic;

// CoverageReport (2026-07-15): the process-global accumulator that lets
// a run say "I could not fully analyze these functions" instead of
// letting silence read as proof. The singleton is cleared per run by
// StaticAnalyzer; each test clears it first for isolation.

TEST(CoverageReportTest, EmptyByDefault) {
    CoverageReport::instance().clear();
    EXPECT_EQ(CoverageReport::instance().incompleteCount(), 0u);
    EXPECT_TRUE(CoverageReport::instance().entries().empty());
}

TEST(CoverageReportTest, RecordsOneGap) {
    auto& cov = CoverageReport::instance();
    cov.clear();
    cov.recordNonConvergence("f");
    ASSERT_EQ(cov.incompleteCount(), 1u);
    EXPECT_EQ(cov.entries()[0].function, "f");
    EXPECT_EQ(cov.entries()[0].gap, CoverageGap::NonConvergence);
}

TEST(CoverageReportTest, DedupsSameFunction) {
    // The six rules each analyze the same function; the gap belongs to
    // the function, so only the first report per function is kept.
    auto& cov = CoverageReport::instance();
    cov.clear();
    cov.recordNonConvergence("f");
    cov.recordNonConvergence("f");
    cov.recordNonConvergence("f");
    EXPECT_EQ(cov.incompleteCount(), 1u);
}

TEST(CoverageReportTest, KeepsDistinctFunctionsInOrder) {
    auto& cov = CoverageReport::instance();
    cov.clear();
    cov.recordNonConvergence("a");
    cov.recordNonConvergence("b");
    ASSERT_EQ(cov.incompleteCount(), 2u);
    EXPECT_EQ(cov.entries()[0].function, "a");
    EXPECT_EQ(cov.entries()[1].function, "b");
}

TEST(CoverageReportTest, ClearResets) {
    auto& cov = CoverageReport::instance();
    cov.clear();
    cov.recordNonConvergence("f");
    cov.clear();
    EXPECT_EQ(cov.incompleteCount(), 0u);
    EXPECT_TRUE(cov.entries().empty());
}
