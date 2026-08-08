#include "core/AnalysisResult.h"

#include <gtest/gtest.h>

using codeskeptic::AnalysisResult;
using codeskeptic::AnalysisStatus;

TEST(AnalysisResultTest, CompleteCleanAndFindingsHaveStableExitCodes) {
    AnalysisResult clean;
    clean.attempted_tus = 2;
    clean.analyzed_tus = 2;
    EXPECT_TRUE(clean.complete());
    EXPECT_EQ(clean.status(), AnalysisStatus::Clean);
    EXPECT_EQ(clean.exitCode(), 0);

    clean.findings = 3;
    EXPECT_EQ(clean.status(), AnalysisStatus::Findings);
    EXPECT_EQ(clean.exitCode(), 1);
}

TEST(AnalysisResultTest, ExperimentalFindingsAreVisibleButReportOnly) {
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.findings = 3;
    result.report_only_findings = 3;

    EXPECT_TRUE(result.complete());
    EXPECT_EQ(result.blockingFindings(), 0u);
    EXPECT_EQ(result.status(), AnalysisStatus::ReportOnly);
    EXPECT_STREQ(result.statusName(), "report-only");
    EXPECT_EQ(result.exitCode(), 0);

    result.report_only_findings = 2;
    EXPECT_EQ(result.blockingFindings(), 1u);
    EXPECT_EQ(result.status(), AnalysisStatus::Findings);
    EXPECT_EQ(result.exitCode(), 1);
}

TEST(AnalysisResultTest, PartialCoverageCannotProduceCleanVerdict) {
    AnalysisResult result;
    result.attempted_tus = 3;
    result.analyzed_tus = 2;
    result.broken_tus = 1;
    EXPECT_FALSE(result.complete());
    EXPECT_EQ(result.status(), AnalysisStatus::Incomplete);
    EXPECT_EQ(result.exitCode(), 2);
}

TEST(AnalysisResultTest, PartialCoverageRequiresExplicitAcceptance) {
    AnalysisResult result;
    result.attempted_tus = 3;
    result.analyzed_tus = 2;
    result.broken_tus = 1;
    result.accept_partial_coverage = true;
    EXPECT_TRUE(result.complete());
    EXPECT_EQ(result.status(), AnalysisStatus::Clean);
    EXPECT_EQ(result.exitCode(), 0);
}

TEST(AnalysisResultTest, EvidenceAndArtifactFailuresAreLoud) {
    AnalysisResult stale;
    stale.attempted_tus = stale.analyzed_tus = 1;
    stale.summary_stale = true;
    EXPECT_EQ(stale.status(), AnalysisStatus::Incomplete);
    EXPECT_EQ(stale.exitCode(), 2);

    AnalysisResult output;
    output.attempted_tus = output.analyzed_tus = 1;
    output.report_write_failed = true;
    EXPECT_EQ(output.status(), AnalysisStatus::Failed);
    EXPECT_EQ(output.exitCode(), 2);

    AnalysisResult tool;
    tool.attempted_tus = 2;
    tool.analyzed_tus = 1;
    tool.tool_failed = true;
    EXPECT_EQ(tool.status(), AnalysisStatus::Failed);
    EXPECT_EQ(tool.exitCode(), 2);
}

TEST(AnalysisResultTest, SuccessfulBaselineRecordingIsZero) {
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.findings = 4;
    result.baseline_recorded = true;
    EXPECT_EQ(result.status(), AnalysisStatus::Recorded);
    EXPECT_EQ(result.exitCode(), 0);
}
