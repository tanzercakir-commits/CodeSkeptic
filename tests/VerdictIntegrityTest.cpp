#include "analyzer/StaticAnalyzer.h"
#include "config/Config.h"
#include "core/Rule.h"
#include "rules/DivByZeroRule.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using namespace codeskeptic;

namespace {

class FixedFindingRule : public Rule {
public:
    explicit FixedFindingRule(std::string finding_id)
        : finding_id_(std::move(finding_id)) {}

    std::string id() const override { return finding_id_; }
    std::string description() const override { return "fixed test finding"; }
    void check(clang::ASTContext&, DiagnosticList& results) override {
        Diagnostic diagnostic;
        diagnostic.severity = Severity::Warning;
        diagnostic.file = "fixed.cpp";
        diagnostic.line = 1;
        diagnostic.column = 1;
        diagnostic.rule_id = finding_id_;
        diagnostic.message = "fixed test finding";
        results.push_back(std::move(diagnostic));
    }

private:
    std::string finding_id_;
};

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

TEST(VerdictIntegrityTest, AllRegisteredRulesDisabledIsExitTwo) {
    const auto source = writeCleanSource("verdict_no_enabled_rules.cpp");
    auto result = runWithOneRule(configFor(
        {"codeskeptic", source, "--disable-rule", "div-by-zero"}));

    EXPECT_TRUE(result.no_rules);
    EXPECT_EQ(result.status(), AnalysisStatus::Failed);
    EXPECT_EQ(result.exitCode(), 2);
}

TEST(VerdictIntegrityTest, ExperimentalFindingIsVisibleButDoesNotBlock) {
    const auto source = writeCleanSource("verdict_experimental.cpp");
    StaticAnalyzer analyzer(configFor({"codeskeptic", source}));
    analyzer.addRule<FixedFindingRule>("memory-leak");

    const auto result = analyzer.run();

    EXPECT_EQ(analyzer.diagnostics().size(), 1u);
    EXPECT_EQ(analyzer.diagnostics()[0].fingerprint.rfind("csf1-", 0), 0u);
    EXPECT_EQ(result.findings, 1u);
    EXPECT_EQ(result.report_only_findings, 1u);
    EXPECT_EQ(result.blockingFindings(), 0u);
    EXPECT_EQ(result.status(), AnalysisStatus::ReportOnly);
    EXPECT_EQ(result.exitCode(), 0);
}

TEST(VerdictIntegrityTest, SupportedFindingStillBlocks) {
    const auto source = writeCleanSource("verdict_supported.cpp");
    StaticAnalyzer analyzer(configFor({"codeskeptic", source}));
    analyzer.addRule<FixedFindingRule>("null-deref");

    const auto result = analyzer.run();

    EXPECT_EQ(result.findings, 1u);
    EXPECT_EQ(result.report_only_findings, 0u);
    EXPECT_EQ(result.blockingFindings(), 1u);
    EXPECT_EQ(result.status(), AnalysisStatus::Findings);
    EXPECT_EQ(result.exitCode(), 1);
}
