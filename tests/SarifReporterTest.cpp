#include "reporter/SarifReporter.h"

#include <fstream>
#include <sstream>
#include <set>
#include <gtest/gtest.h>
#include <llvm/Support/JSON.h>

using namespace codeskeptic;

namespace {

std::string reportToString(const DiagnosticList& diags,
                           const AnalysisResult* result = nullptr) {
    const auto* test =
        ::testing::UnitTest::GetInstance()->current_test_info();
    std::string path = ::testing::TempDir() + test->test_suite_name() + "_" +
                       test->name() + ".sarif";
    SarifReporter reporter(path);
    EXPECT_TRUE(reporter.report(diags, result));

    std::ifstream file(path);
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

} // anonymous namespace

TEST(SarifReporterTest, MinimalStructure) {
    DiagnosticList diags = {
        {Severity::Error, "/src/a.cpp", 10, 5, "uninit-ptr", "msg1"},
        {Severity::Warning, "b.cpp", 20, 3, "memory-leak", "msg2"},
    };
    std::string out = reportToString(diags);

    EXPECT_NE(out.find("\"version\": \"2.1.0\""), std::string::npos);
    EXPECT_NE(out.find("sarif-schema-2.1.0.json"), std::string::npos);
    EXPECT_NE(out.find("\"name\": \"CodeSkeptic\""), std::string::npos);
    // Rules are listed uniquely under driver.rules
    auto parsed = llvm::json::parse(out);
    ASSERT_TRUE(static_cast<bool>(parsed));
    const auto* descriptors = parsed->getAsObject()->getArray("runs")->front()
        .getAsObject()->getObject("tool")->getObject("driver")->getArray("rules");
    ASSERT_NE(descriptors, nullptr);
    ASSERT_EQ(descriptors->size(), 2u);
    std::set<std::string> ids;
    for (const auto& entry : *descriptors) {
        const auto* descriptor = entry.getAsObject();
        ASSERT_NE(descriptor, nullptr);
        ASSERT_TRUE(descriptor->getString("id").has_value());
        ids.insert(descriptor->getString("id")->str());
        EXPECT_NE(descriptor->getObject("shortDescription"), nullptr);
        EXPECT_TRUE(descriptor->getString("helpUri").has_value());
    }
    EXPECT_EQ(ids, (std::set<std::string>{"uninit-ptr", "memory-leak"}));
}

TEST(SarifReporterTest, ResultFields) {
    DiagnosticList diags = {
        {Severity::Error, "/src/a.cpp", 10, 5, "uninit-ptr", "bad deref"},
    };
    std::string out = reportToString(diags);

    EXPECT_NE(out.find("\"ruleId\": \"uninit-ptr\""), std::string::npos);
    EXPECT_NE(out.find("\"level\": \"error\""), std::string::npos);
    EXPECT_NE(out.find("\"text\": \"bad deref\""), std::string::npos);
    EXPECT_NE(out.find("\"startLine\": 10"), std::string::npos);
    EXPECT_NE(out.find("\"startColumn\": 5"), std::string::npos);
    EXPECT_NE(out.find("\"codeskeptic/capabilityTier\": \"experimental\""),
              std::string::npos);
    EXPECT_NE(out.find("\"codeskeptic/blocksVerdict\": false"),
              std::string::npos);
    EXPECT_NE(out.find("\"partialFingerprints\": { \"codeskeptic/v1\": \"csf1-"),
              std::string::npos);
    // Absolute paths are converted to file:// URIs
    EXPECT_NE(out.find("\"uri\": \"file:///src/a.cpp\""), std::string::npos);
}

TEST(SarifReporterTest, PerResultCwesDoNotBecomeFamilyWideTags) {
    Diagnostic read{Severity::Error, "a.cpp", 1, 1, "bounds", "identical message"};
    Diagnostic write = read;
    read.kind = FindingKind::BoundsRead;
    write.kind = FindingKind::BoundsWrite;
    auto parsed = llvm::json::parse(reportToString({read, write}));
    ASSERT_TRUE(static_cast<bool>(parsed));
    const auto* root = parsed->getAsObject();
    ASSERT_NE(root, nullptr);
    const auto* runs = root->getArray("runs");
    ASSERT_NE(runs, nullptr);
    ASSERT_EQ(runs->size(), 1u);
    const auto* run = runs->front().getAsObject();
    ASSERT_NE(run, nullptr);
    const auto* results = run->getArray("results");
    ASSERT_NE(results, nullptr);
    ASSERT_EQ(results->size(), 2u);
    for (size_t i = 0; i < 2; ++i) {
        const auto* row = (*results)[i].getAsObject();
        ASSERT_NE(row, nullptr);
        EXPECT_EQ(row->getString("ruleId"), "bounds");
        const auto* properties = row->getObject("properties");
        ASSERT_NE(properties, nullptr);
        EXPECT_EQ(properties->getBoolean("codeskeptic/blocksVerdict"), false);
        const auto* metadata = properties->getObject("codeskeptic/ruleMetadata");
        ASSERT_NE(metadata, nullptr);
        const auto* cwes = metadata->getArray("cwes");
        ASSERT_NE(cwes, nullptr);
        ASSERT_EQ(cwes->size(), 1u);
        ASSERT_NE(cwes->front().getAsObject(), nullptr);
        EXPECT_EQ(cwes->front().getAsObject()->getInteger("id"), i == 0 ? 125 : 787);
    }
}

TEST(SarifReporterTest, SeverityLevelMapping) {
    DiagnosticList diags = {
        {Severity::Info, "a.cpp", 1, 1, "r", "m"},
        {Severity::Warning, "a.cpp", 2, 1, "r", "m"},
        {Severity::Error, "a.cpp", 3, 1, "r", "m"},
    };
    std::string out = reportToString(diags);

    EXPECT_NE(out.find("\"level\": \"note\""), std::string::npos);
    EXPECT_NE(out.find("\"level\": \"warning\""), std::string::npos);
    EXPECT_NE(out.find("\"level\": \"error\""), std::string::npos);
}

TEST(SarifReporterTest, EmptyDiagnostics_ValidSkeleton) {
    std::string out = reportToString({});

    EXPECT_NE(out.find("\"results\": []"), std::string::npos);
    EXPECT_NE(out.find("\"rules\": []"), std::string::npos);
}

TEST(SarifReporterTest, InvocationPublishesCompleteVerdictContract) {
    AnalysisResult result;
    result.attempted_tus = 2;
    result.analyzed_tus = 1;
    result.broken_tus = 1;

    std::string out = reportToString({}, &result);

    EXPECT_NE(out.find("\"executionSuccessful\": false"),
              std::string::npos);
    EXPECT_NE(out.find("\"codeskeptic/status\": \"incomplete\""),
              std::string::npos);
    EXPECT_NE(out.find("\"codeskeptic/exitCode\": 2"),
              std::string::npos);
}

TEST(SarifReporterTest, InvocationPublishesReportOnlyCounts) {
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.findings = result.report_only_findings = 2;

    std::string out = reportToString({}, &result);

    EXPECT_NE(out.find("\"codeskeptic/status\": \"report-only\""),
              std::string::npos);
    EXPECT_NE(out.find("\"codeskeptic/exitCode\": 0"),
              std::string::npos);
    EXPECT_NE(out.find("\"codeskeptic/blockingFindings\": 0"),
              std::string::npos);
    EXPECT_NE(out.find("\"codeskeptic/reportOnlyFindings\": 2"),
              std::string::npos);
}

TEST(SarifReporterTest, MessageEscaping) {
    DiagnosticList diags = {
        {Severity::Error, "a.cpp", 1, 1, "r", "quote \" and \\ slash"},
    };
    std::string out = reportToString(diags);

    EXPECT_NE(out.find("quote \\\" and \\\\ slash"), std::string::npos);
}

TEST(SarifReporterTest, WindowsAbsolutePathsGetFileUris) {
    // docs/windows-support.md §4: drive-letter and UNC paths are
    // absolute; they must become file URIs (forward slashes), not be
    // emitted verbatim as "relative" paths.
    DiagnosticList diags = {
        {Severity::Error, "C:\\work\\a.cpp", 1, 1, "r", "m1"},
        {Severity::Error, "d:/proj/b.cpp", 2, 1, "r", "m2"},
        {Severity::Error, "\\\\srv\\share\\c.cpp", 3, 1, "r", "m3"},
        {Severity::Error, "rel\\dir\\d.cpp", 4, 1, "r", "m4"},
    };
    std::string out = reportToString(diags);

    EXPECT_NE(out.find("\"uri\": \"file:///C:/work/a.cpp\""), std::string::npos);
    EXPECT_NE(out.find("\"uri\": \"file:///d:/proj/b.cpp\""), std::string::npos);
    EXPECT_NE(out.find("\"uri\": \"file://srv/share/c.cpp\""), std::string::npos);
    // A relative Windows-style path stays relative (verbatim, escaped).
    EXPECT_NE(out.find("\"uri\": \"rel\\\\dir\\\\d.cpp\""), std::string::npos);
}
