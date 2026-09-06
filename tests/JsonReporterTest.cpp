#include "reporter/JsonReporter.h"
#include "reporter/Coverage.h"

#include <fstream>
#include <gtest/gtest.h>
#include <llvm/Support/JSON.h>

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

TEST(JsonReporterTest, PublishesCweExplanationWithoutParsingMessage) {
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    Diagnostic diagnostic{Severity::Error, "sample.cpp", 1, 1,
                          "null-deref", "arbitrary translated message"};
    auto parsed = llvm::json::parse(readJsonReport(result, {diagnostic}));
    ASSERT_TRUE(static_cast<bool>(parsed));
    const auto* root = parsed->getAsObject();
    ASSERT_NE(root, nullptr);
    const auto* diagnostics = root->getArray("diagnostics");
    ASSERT_NE(diagnostics, nullptr);
    ASSERT_EQ(diagnostics->size(), 1u);
    const auto* row = diagnostics->front().getAsObject();
    ASSERT_NE(row, nullptr);
    const auto* metadata = row->getObject("rule_metadata");
    ASSERT_NE(metadata, nullptr);
    const auto* cwes = metadata->getArray("cwes");
    ASSERT_NE(cwes, nullptr);
    ASSERT_EQ(cwes->size(), 1u);
    const auto* cwe = cwes->front().getAsObject();
    ASSERT_NE(cwe, nullptr);
    EXPECT_EQ(cwe->getInteger("id"), 476);
    EXPECT_EQ(cwe->getString("help_uri"), "https://cwe.mitre.org/data/definitions/476.html");
}

TEST(JsonReporterTest, SourceIdentitiesAndReasonsRoundTripEveryControlByte) {
    std::string identity = "quote\"-backslash\\-";
    for (int byte = 0; byte < 32; ++byte) identity.push_back(static_cast<char>(byte));
    AnalysisResult result;
    SourceCoverage source{identity, SourceStatus::Failed, identity};
    source.prepass_status = "failed";
    source.prepass_reason = identity;
    result.sources = {source};
    result.reconcileSources();
    auto parsed = llvm::json::parse(readJsonReport(result));
    ASSERT_TRUE(static_cast<bool>(parsed));
    const auto* report = parsed->getAsObject();
    ASSERT_NE(report, nullptr);
    const auto* coverage = report->getObject("coverage");
    ASSERT_NE(coverage, nullptr);
    EXPECT_EQ(coverage->getBoolean("complete"), false);
    const auto* sources = coverage->getArray("sources");
    ASSERT_NE(sources, nullptr);
    ASSERT_EQ(sources->size(), 1u);
    const auto* row = sources->front().getAsObject();
    ASSERT_NE(row, nullptr);
    EXPECT_EQ(row->getString("file"), identity);
    EXPECT_EQ(row->getString("reason"), identity);
    ASSERT_NE(row->getObject("prepass"), nullptr);
    EXPECT_EQ(row->getObject("prepass")->getString("reason"), identity);
}

TEST(JsonReporterTest, FindingAndOrderedTraceRoundTripEveryControlByte) {
    std::string text = "quote\"-backslash\\-";
    for (int byte = 0; byte < 32; ++byte) text += static_cast<char>(byte);
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.findings = 1;
    Diagnostic finding{Severity::Error, "dir/" + text, 4, 7, "null-deref", text};
    finding.function = text;
    finding.notes = {{"first/" + text, 2, 3, text}, {"second/" + text, 9, 11, text}};
    auto parsed = llvm::json::parse(readJsonReport(result, {finding}));
    ASSERT_TRUE(static_cast<bool>(parsed));
    const auto* root = parsed->getAsObject();
    ASSERT_NE(root, nullptr);
    const auto* rows = root->getArray("diagnostics");
    ASSERT_NE(rows, nullptr);
    ASSERT_EQ(rows->size(), 1u);
    const auto* row = rows->front().getAsObject();
    ASSERT_NE(row, nullptr);
    EXPECT_EQ(row->getString("file"), finding.file);
    EXPECT_EQ(row->getString("message"), text);
    EXPECT_EQ(row->getString("function"), text);
    const auto* notes = row->getArray("notes");
    ASSERT_NE(notes, nullptr);
    ASSERT_EQ(notes->size(), finding.notes.size());
    for (size_t index = 0; index < notes->size(); ++index) {
        const auto* note = (*notes)[index].getAsObject();
        ASSERT_NE(note, nullptr);
        EXPECT_EQ(note->getString("file"), finding.notes[index].file);
        EXPECT_EQ(note->getString("message"), text);
        EXPECT_EQ(note->getInteger("line"), finding.notes[index].line);
        EXPECT_EQ(note->getInteger("column"), finding.notes[index].column);
    }
}

TEST(JsonReporterTest, BytePathIdentitiesAreLosslessDistinctAndValidUtf8) {
    const std::vector<std::string> invalid{
        std::string("/\xff.cpp"), std::string("/\xfe.cpp"),
        std::string("/\xc0\xaf.cpp"), std::string("/\xe2\x82"),
        std::string("/\xed\xa0\x80.cpp"), std::string("/\xf4\x90\x80\x80.cpp")};
    const std::vector<std::string> expected{
        "codeskeptic-bytes:2fff2e637070", "codeskeptic-bytes:2ffe2e637070",
        "codeskeptic-bytes:2fc0af2e637070", "codeskeptic-bytes:2fe282",
        "codeskeptic-bytes:2feda0802e637070", "codeskeptic-bytes:2ff49080802e637070"};
    AnalysisResult result;
    for (const auto& path : invalid)
        result.sources.push_back(SourceCoverage{path, SourceStatus::Failed, "source_path_not_utf8"});
    result.reconcileSources();
    const auto text = readJsonReport(result);
    ASSERT_TRUE(llvm::json::isUTF8(text));
    auto parsed = llvm::json::parse(text);
    ASSERT_TRUE(static_cast<bool>(parsed));
    const auto* rows = parsed->getAsObject()->getObject("coverage")->getArray("sources");
    ASSERT_EQ(rows->size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i)
        EXPECT_EQ((*rows)[i].getAsObject()->getString("file"), expected[i]);
    // A caller's literal marker text must not alias the encoded identity.
    EXPECT_NE(coveragePathIdentity(expected.front()), expected.front());
    const std::string unicode = "/\xc3\xa7-\xce\xbb-\xef\xbf\xbd.cpp";
    EXPECT_EQ(coveragePathIdentity(unicode), unicode);
}
