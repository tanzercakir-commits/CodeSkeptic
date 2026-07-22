#include "reporter/SarifReporter.h"

#include <fstream>
#include <sstream>
#include <gtest/gtest.h>

using namespace codeskeptic;

namespace {

std::string reportToString(const DiagnosticList& diags) {
    std::string path = ::testing::TempDir() + "sarif_test_output.sarif";
    SarifReporter reporter(path);
    reporter.report(diags);

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
    EXPECT_NE(out.find("{ \"id\": \"uninit-ptr\" }"), std::string::npos);
    EXPECT_NE(out.find("{ \"id\": \"memory-leak\" }"), std::string::npos);
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
    // Absolute paths are converted to file:// URIs
    EXPECT_NE(out.find("\"uri\": \"file:///src/a.cpp\""), std::string::npos);
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
