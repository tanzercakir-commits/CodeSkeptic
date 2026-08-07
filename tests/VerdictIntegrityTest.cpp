#include "analyzer/StaticAnalyzer.h"
#include "config/Config.h"
#include "rules/DivByZeroRule.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;
using namespace codeskeptic;

namespace {

std::string writeCleanSource(const char* name) {
    const fs::path path = fs::path(::testing::TempDir()) / name;
    std::ofstream file(path);
    file << "int f() { return 1; }\n";
    return path.string();
}

Config configFor(std::initializer_list<std::string> values) {
    std::vector<std::string> storage(values);
    std::vector<char*> argv;
    for (auto& value : storage) argv.push_back(value.data());
    Config config;
    EXPECT_TRUE(config.parseArgs(static_cast<int>(argv.size()), argv.data()));
    return config;
}

AnalysisResult runWithOneRule(Config config) {
    StaticAnalyzer analyzer(std::move(config));
    analyzer.addRule<DivByZeroRule>();
    return analyzer.run();
}

} // anonymous namespace

TEST(VerdictIntegrityTest, ReportWriteFailureIsExitTwo) {
    const auto source = writeCleanSource("verdict_report.cpp");
    const auto output =
        (fs::path(::testing::TempDir()) / "missing-report-dir" / "out.json")
            .string();
    auto result = runWithOneRule(
        configFor({"codeskeptic", source, "--json", output}));

    EXPECT_EQ(result.analyzed_tus, 1u);
    EXPECT_TRUE(result.report_write_failed);
    EXPECT_EQ(result.status(), AnalysisStatus::Failed);
    EXPECT_EQ(result.exitCode(), 2);
}

TEST(VerdictIntegrityTest, BaselineWriteFailureIsExitTwo) {
    const auto source = writeCleanSource("verdict_baseline_write.cpp");
    const auto output =
        (fs::path(::testing::TempDir()) / "missing-baseline-dir" / "base.txt")
            .string();
    auto result = runWithOneRule(
        configFor({"codeskeptic", source, "--write-baseline", output}));

    EXPECT_TRUE(result.baseline_write_failed);
    EXPECT_FALSE(result.baseline_recorded);
    EXPECT_EQ(result.exitCode(), 2);
}

TEST(VerdictIntegrityTest, RequestedMissingBaselineIsExitTwo) {
    const auto source = writeCleanSource("verdict_baseline_load.cpp");
    const auto baseline =
        (fs::path(::testing::TempDir()) / "missing-baseline.txt").string();
    auto result = runWithOneRule(
        configFor({"codeskeptic", source, "--baseline", baseline}));

    EXPECT_TRUE(result.baseline_load_failed);
    EXPECT_EQ(result.exitCode(), 2);
}
