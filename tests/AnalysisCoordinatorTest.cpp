#include "analyzer/AnalysisCoordinator.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace codeskeptic;

namespace {

TranslationUnitExecution unit(const char* path, const char* hash,
                              std::size_t ordinal = 0) {
    return TranslationUnitExecution{path, "/build", {"clang++", path},
                                    {}, hash, ordinal};
}

UnitExecutionResult completed(const char* file, const char* message) {
    UnitExecutionResult outcome;
    outcome.resource.status = ResourceRunStatus::Completed;
    outcome.resource.exit_code = 0;
    outcome.resource.duration_ms = 12;
    outcome.resource.peak_memory_kib = 64000;
    outcome.analysis.attempted_tus = 1;
    outcome.analysis.analyzed_tus = 1;
    outcome.analysis.findings = 1;
    outcome.diagnostics.push_back(
        Diagnostic{Severity::Warning, file, 1, 1, "div-by-zero", message});
    return outcome;
}

} // anonymous namespace

TEST(AnalysisCoordinatorTest, ResourceFailureKeepsEarlierAndLaterUnits) {
    const std::vector<TranslationUnitExecution> units = {
        unit("/src/a.cpp", "sha-a"),
        unit("/src/b.cpp", "sha-b"),
        unit("/src/c.cpp", "sha-c"),
    };
    std::vector<std::string> calls;
    const auto result = AnalysisCoordinator::run(
        units, ResourceLimits{1, 4096}, false,
        [&](const TranslationUnitExecution& execution,
            TranslationUnitPhase phase) {
            calls.push_back(execution.canonical_path + ":" +
                            translationUnitPhaseName(phase));
            if (execution.canonical_path == "/src/b.cpp") {
                UnitExecutionResult timeout;
                timeout.resource.status = ResourceRunStatus::TimedOut;
                timeout.resource.exit_code = -2;
                timeout.resource.duration_ms = 1001;
                return timeout;
            }
            return completed(execution.canonical_path.c_str(),
                             execution.canonical_path.c_str());
        });

    EXPECT_EQ(calls.size(), 3u);
    EXPECT_EQ(result.analysis.attempted_tus, 3u);
    EXPECT_EQ(result.analysis.analyzed_tus, 2u);
    EXPECT_EQ(result.analysis.completedReceiptCount(), 2u);
    EXPECT_TRUE(result.analysis.hasResourceFailure());
    EXPECT_EQ(result.analysis.exitCode(), 2);
    EXPECT_EQ(result.diagnostics.size(), 2u);
    ASSERT_EQ(result.analysis.tu_receipts.size(), 3u);
    EXPECT_EQ(result.analysis.tu_receipts[1].canonical_path, "/src/b.cpp");
    EXPECT_EQ(result.analysis.tu_receipts[1].compile_command_sha256,
              "sha-b");
    EXPECT_EQ(result.analysis.tu_receipts[1].status,
              TranslationUnitStatus::TimedOut);
}

TEST(AnalysisCoordinatorTest, ReceiptPreservesCheckpointOriginAndPayload) {
    const std::vector<TranslationUnitExecution> units = {
        unit("/src/a.cpp", "sha-a"),
    };
    const auto result = AnalysisCoordinator::run(
        units, ResourceLimits{10, 256}, false,
        [](const TranslationUnitExecution& execution,
           TranslationUnitPhase) {
            auto outcome = completed(execution.canonical_path.c_str(), "cached");
            outcome.origin = TranslationUnitOrigin::Checkpoint;
            outcome.checkpoint_key_sha256 = std::string(64, 'a');
            outcome.payload_sha256 = std::string(64, 'b');
            return outcome;
        });

    ASSERT_EQ(result.analysis.tu_receipts.size(), 1u);
    const auto& receipt = result.analysis.tu_receipts.front();
    EXPECT_EQ(receipt.origin, TranslationUnitOrigin::Checkpoint);
    EXPECT_STREQ(translationUnitOriginName(receipt.origin), "checkpoint");
    EXPECT_EQ(receipt.checkpoint_key_sha256, std::string(64, 'a'));
    EXPECT_EQ(receipt.payload_sha256, std::string(64, 'b'));
}

TEST(AnalysisCoordinatorTest, WholeProgramPrepassFailureStopsAnalysisPhase) {
    const std::vector<TranslationUnitExecution> units = {
        unit("/src/a.cpp", "sha-a"), unit("/src/b.cpp", "sha-b")};
    std::size_t harvest_calls = 0;
    std::size_t analysis_calls = 0;
    const auto result = AnalysisCoordinator::run(
        units, ResourceLimits{1, 4096}, true,
        [&](const TranslationUnitExecution& execution,
            TranslationUnitPhase phase) {
            if (phase == TranslationUnitPhase::Analysis) {
                ++analysis_calls;
                return completed(execution.canonical_path.c_str(), "late");
            }
            ++harvest_calls;
            if (execution.canonical_path == "/src/b.cpp") {
                UnitExecutionResult timeout;
                timeout.resource.status = ResourceRunStatus::TimedOut;
                timeout.resource.duration_ms = 1001;
                return timeout;
            }
            UnitExecutionResult harvested;
            harvested.resource.status = ResourceRunStatus::Completed;
            harvested.resource.exit_code = 0;
            harvested.resource.duration_ms = 10;
            harvested.resource.peak_memory_kib = 62000;
            harvested.analysis.attempted_tus = 1;
            harvested.analysis.analyzed_tus = 1;
            return harvested;
        });

    EXPECT_EQ(harvest_calls, 2u);
    EXPECT_EQ(analysis_calls, 0u);
    EXPECT_EQ(result.analysis.exitCode(), 2);
    ASSERT_EQ(result.analysis.tu_receipts.size(), 2u);
    EXPECT_EQ(result.analysis.tu_receipts[0].phase, "summary-harvest");
    EXPECT_EQ(result.analysis.tu_receipts[1].status,
              TranslationUnitStatus::TimedOut);
}

TEST(AnalysisCoordinatorTest, WholeProgramBrokenPrepassPreservesCoverage) {
    const std::vector<TranslationUnitExecution> units = {
        unit("/src/a.cpp", "sha-a"), unit("/src/b.cpp", "sha-b")};
    const auto result = AnalysisCoordinator::run(
        units, ResourceLimits{10, 256}, true,
        [](const TranslationUnitExecution& execution,
           TranslationUnitPhase phase) {
            UnitExecutionResult outcome;
            outcome.resource.status = ResourceRunStatus::Completed;
            outcome.resource.exit_code = 0;
            outcome.analysis.attempted_tus = 1;
            if (phase == TranslationUnitPhase::SummaryHarvest &&
                execution.canonical_path == "/src/b.cpp") {
                outcome.analysis.broken_tus = 1;
                outcome.analysis.summary_load_failed = true;
            } else {
                outcome.analysis.analyzed_tus = 1;
            }
            return outcome;
        });

    EXPECT_EQ(result.analysis.attempted_tus, 2u);
    EXPECT_EQ(result.analysis.analyzed_tus, 0u);
    EXPECT_EQ(result.analysis.broken_tus, 1u);
    EXPECT_TRUE(result.analysis.summary_load_failed);
    EXPECT_EQ(result.analysis.exitCode(), 2);
    ASSERT_EQ(result.analysis.tu_receipts.size(), 2u);
    EXPECT_EQ(result.analysis.tu_receipts[0].status,
              TranslationUnitStatus::Completed);
    EXPECT_EQ(result.analysis.tu_receipts[1].status,
              TranslationUnitStatus::Broken);
}

TEST(AnalysisCoordinatorTest, MissingUnitIsIncompleteNotAResourceCrash) {
    const std::vector<TranslationUnitExecution> units = {
        unit("/tmp/complete.cpp", "a", 0),
        unit("/tmp/missing.cpp", "b", 0),
    };
    const auto result = AnalysisCoordinator::run(
        units, ResourceLimits{10, 256}, false,
        [](const TranslationUnitExecution& execution,
           TranslationUnitPhase) {
            UnitExecutionResult outcome;
            outcome.resource.status = ResourceRunStatus::Completed;
            outcome.analysis.attempted_tus = 1;
            if (execution.canonical_path.find("missing") != std::string::npos)
                outcome.analysis.no_inputs = true;
            else
                outcome.analysis.analyzed_tus = 1;
            return outcome;
        });

    ASSERT_EQ(result.analysis.tu_receipts.size(), 2u);
    EXPECT_EQ(result.analysis.tu_receipts[0].status,
              TranslationUnitStatus::Completed);
    EXPECT_EQ(result.analysis.tu_receipts[1].status,
              TranslationUnitStatus::Missing);
    EXPECT_FALSE(result.analysis.hasResourceFailure());
    EXPECT_EQ(result.analysis.status(), AnalysisStatus::Incomplete);
    EXPECT_EQ(result.analysis.exitCode(), 2);
}
