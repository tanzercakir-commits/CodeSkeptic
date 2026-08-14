#include "analyzer/StaticAnalyzer.h"
#include "config/Config.h"
#include "core/Rule.h"
#include "engine/CoverageReport.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

using namespace codeskeptic;

namespace {

class ForcedCoverageGapRule : public Rule {
public:
    std::string id() const override { return "forced-coverage-gap"; }
    std::string description() const override { return "test-only gap"; }
    void check(clang::ASTContext&, DiagnosticList&) override {
        CoverageReport::instance().recordCfgUnavailable("forced_gap");
    }
};

} // namespace

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

TEST(CoverageReportTest, RecordsConcreteCfgFailurePrecisely) {
    auto& cov = CoverageReport::instance();
    cov.clear();
    cov.recordCfgUnavailable("f");
    ASSERT_EQ(cov.incompleteCount(), 1u);
    EXPECT_EQ(cov.entries()[0].gap, CoverageGap::CfgUnavailable);
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

TEST(CoverageReportTest, AnalyzerGapMakesVerdictUnavailable) {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "cs_forced_coverage_gap";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    const fs::path source = dir / "gap.cpp";
    {
        std::ofstream file(source);
        file << "int gap() { return 0; }\n";
    }

    Config config;
    config.setSourcePath(source.string());
    config.setBuildPath(dir.string());
    StaticAnalyzer analyzer(std::move(config));
    analyzer.addRule<ForcedCoverageGapRule>();
    const AnalysisResult result = analyzer.run();

    EXPECT_EQ(result.attempted_tus, 1u);
    EXPECT_EQ(result.analyzed_tus, 1u);
    EXPECT_EQ(result.incomplete_functions, 1u);
    EXPECT_FALSE(result.complete());
    EXPECT_EQ(result.status(), AnalysisStatus::Incomplete);
    EXPECT_EQ(result.exitCode(), 2);
    fs::remove_all(dir, ec);
}
