#include "core/AnalysisResult.h"

#include <gtest/gtest.h>

using codeskeptic::AnalysisResult;
using codeskeptic::AnalysisStatus;
using codeskeptic::TranslationUnitReceipt;
using codeskeptic::TranslationUnitStatus;

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

TEST(AnalysisResultTest, BrokenCoverageCannotBeAcceptedAsAVerdict) {
    AnalysisResult result;
    result.attempted_tus = 3;
    result.analyzed_tus = 2;
    result.broken_tus = 1;
    result.analyze_broken_tus = true;
    result.accept_partial_coverage = true;
    EXPECT_FALSE(result.complete());
    EXPECT_EQ(result.status(), AnalysisStatus::Incomplete);
    EXPECT_EQ(result.exitCode(), 2);
}

TEST(AnalysisResultTest, MissingRequestedTusCannotBeAcceptedAsAVerdict) {
    AnalysisResult result;
    result.attempted_tus = 3;
    result.analyzed_tus = 2;
    EXPECT_FALSE(result.complete());
    EXPECT_EQ(result.status(), AnalysisStatus::Incomplete);
    EXPECT_EQ(result.exitCode(), 2);

    result.accept_partial_coverage = true;
    EXPECT_FALSE(result.complete());
    EXPECT_EQ(result.status(), AnalysisStatus::Incomplete);
    EXPECT_EQ(result.exitCode(), 2);
}

TEST(AnalysisResultTest, IncompleteReceiptCannotBeMaskedByCounts) {
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.tu_receipts.push_back(TranslationUnitReceipt{
        "/src/missing.cpp", "", 0, "analysis",
        TranslationUnitStatus::Missing, 0, 0, 300, 4096});

    EXPECT_FALSE(result.complete());
    EXPECT_EQ(result.status(), AnalysisStatus::Incomplete);
    EXPECT_EQ(result.exitCode(), 2);
}

TEST(AnalysisResultTest, ZeroAnalyzedCannotBeAcceptedAsClean) {
    AnalysisResult result;
    result.attempted_tus = 3;
    result.analyze_broken_tus = true;
    result.accept_partial_coverage = true;

    EXPECT_FALSE(result.complete());
    EXPECT_EQ(result.status(), AnalysisStatus::Failed);
    EXPECT_EQ(result.exitCode(), 2);
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

    AnalysisResult compile_database;
    compile_database.attempted_tus = 1;
    compile_database.compile_database_failed = true;
    EXPECT_EQ(compile_database.status(), AnalysisStatus::Failed);
    EXPECT_EQ(compile_database.exitCode(), 2);
}

TEST(AnalysisResultTest, SuccessfulBaselineRecordingIsZero) {
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.findings = 4;
    result.baseline_recorded = true;
    EXPECT_EQ(result.status(), AnalysisStatus::Recorded);
    EXPECT_EQ(result.exitCode(), 0);
}

TEST(AnalysisResultTest, ResourceFailurePreservesCompletedReceiptsButNoVerdict) {
    AnalysisResult result;
    result.attempted_tus = 3;
    result.analyzed_tus = 2;
    result.findings = 1;
    result.tu_receipts = {
        TranslationUnitReceipt{"/src/a.cpp", "sha-a", 0,
                               "analysis", TranslationUnitStatus::Completed,
                               120, 64000, 300, 4096},
        TranslationUnitReceipt{"/src/b.cpp", "sha-b", 0,
                               "analysis", TranslationUnitStatus::TimedOut,
                               1001, 70000, 1, 4096},
        TranslationUnitReceipt{"/src/c.cpp", "sha-c", 0,
                               "analysis", TranslationUnitStatus::Completed,
                               80, 62000, 300, 4096},
    };

    EXPECT_EQ(result.completedReceiptCount(), 2u);
    EXPECT_TRUE(result.hasResourceFailure());
    EXPECT_FALSE(result.complete());
    EXPECT_EQ(result.status(), AnalysisStatus::Failed);
    EXPECT_EQ(result.exitCode(), 2);
    EXPECT_EQ(result.findings, 1u);
}

TEST(AnalysisResultTest, TuIdentityIncludesCompileCommandAndOrdinal) {
    AnalysisResult result;
    result.tu_receipts = {
        TranslationUnitReceipt{"/src/shared.cpp", "sha-command-1", 0,
                               "analysis", TranslationUnitStatus::Completed,
                               10, 1000, 300, 4096},
        TranslationUnitReceipt{"/src/shared.cpp", "sha-command-2", 1,
                               "analysis", TranslationUnitStatus::Completed,
                               12, 1100, 300, 4096},
    };

    ASSERT_EQ(result.tu_receipts.size(), 2u);
    EXPECT_EQ(result.tu_receipts[0].canonical_path,
              result.tu_receipts[1].canonical_path);
    EXPECT_NE(result.tu_receipts[0].compile_command_sha256,
              result.tu_receipts[1].compile_command_sha256);
    EXPECT_NE(result.tu_receipts[0].command_ordinal,
              result.tu_receipts[1].command_ordinal);
}
