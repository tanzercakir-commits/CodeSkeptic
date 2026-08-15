#include "reporter/JsonReporter.h"

#include <fstream>
#include <gtest/gtest.h>

using namespace codeskeptic;

namespace {

std::string readJsonReport(const AnalysisResult& result,
                           const DiagnosticList& diagnostics = {}) {
    const auto* test =
        ::testing::UnitTest::GetInstance()->current_test_info();
    const std::string path = ::testing::TempDir() + test->test_suite_name() +
                             "_" + test->name() + ".json";
    JsonReporter reporter(path);
    EXPECT_TRUE(reporter.report(diagnostics, &result));

    std::ifstream file(path);
    return {std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()};
}

} // anonymous namespace

TEST(JsonReporterTest, PublishesCompleteVerdictContract) {
    AnalysisResult result;
    result.attempted_tus = 2;
    result.analyzed_tus = 1;
    result.broken_tus = 1;
    result.summary_stale = true;

    const std::string json = readJsonReport(result);

    EXPECT_NE(json.find("\"status\": \"incomplete\""), std::string::npos);
    EXPECT_NE(json.find("\"complete\": false"), std::string::npos);
    EXPECT_NE(json.find("\"exit_code\": 2"), std::string::npos);
    EXPECT_NE(json.find("\"summary_stale\": true"), std::string::npos);
    EXPECT_NE(json.find("\"attempted_tus\": 2"), std::string::npos);
    EXPECT_NE(json.find("\"analyzed_tus\": 1"), std::string::npos);
    EXPECT_NE(json.find("\"broken_tus\": 1"), std::string::npos);
}

TEST(JsonReporterTest, PublishesBlockingAndReportOnlyCounts) {
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.findings = 2;
    result.report_only_findings = 2;

    const std::string json = readJsonReport(result);

    EXPECT_NE(json.find("\"status\": \"report-only\""),
              std::string::npos);
    EXPECT_NE(json.find("\"exit_code\": 0"), std::string::npos);
    EXPECT_NE(json.find("\"blocking\": 0"), std::string::npos);
    EXPECT_NE(json.find("\"report_only\": 2"), std::string::npos);
}

TEST(JsonReporterTest, PublishesPerFindingCapabilityMetadata) {
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.findings = result.report_only_findings = 1;
    Diagnostic diagnostic;
    diagnostic.severity = Severity::Warning;
    diagnostic.rule_id = "bounds";
    diagnostic.file = "sample.cpp";
    diagnostic.line = diagnostic.column = 1;
    diagnostic.message = "leak";

    const std::string json = readJsonReport(result, {diagnostic});

    EXPECT_NE(json.find("\"capability_tier\": \"experimental\""),
              std::string::npos);
    EXPECT_NE(json.find("\"blocks_verdict\": false"),
              std::string::npos);
    EXPECT_NE(json.find("\"fingerprint\": \"csf1-"),
              std::string::npos);
}

TEST(JsonReporterTest, PublishesExactTranslationUnitReceipts) {
    AnalysisResult result;
    result.attempted_tus = 2;
    result.analyzed_tus = 1;
    result.tu_receipts.push_back(TranslationUnitReceipt{
        "/project/a.cpp", std::string(64, 'a'), 3, "analysis",
        TranslationUnitStatus::TimedOut, 1005, 24576, 1, 96});

    const std::string json = readJsonReport(result);

    EXPECT_NE(json.find("\"translation_units\""), std::string::npos);
    EXPECT_NE(json.find("\"path\": \"/project/a.cpp\""),
              std::string::npos);
    EXPECT_NE(json.find("\"compile_command_sha256\": \"" +
                        std::string(64, 'a') + "\""),
              std::string::npos);
    EXPECT_NE(json.find("\"command_ordinal\": 3"), std::string::npos);
    EXPECT_NE(json.find("\"status\": \"timed-out\""),
              std::string::npos);
    EXPECT_NE(json.find("\"duration_ms\": 1005"), std::string::npos);
    EXPECT_NE(json.find("\"peak_memory_kib\": 24576"),
              std::string::npos);
    EXPECT_NE(json.find("\"timeout_seconds\": 1"), std::string::npos);
    EXPECT_NE(json.find("\"memory_mib\": 96"), std::string::npos);
}
