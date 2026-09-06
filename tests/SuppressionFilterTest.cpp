#include "analyzer/SuppressionFilter.h"

#include <fstream>
#include <gtest/gtest.h>

using namespace codeskeptic;

namespace {

// Creates a temporary source file, returns its path
std::string writeTempSource(const std::string& name,
                            const std::string& content) {
    std::string path = ::testing::TempDir() + name;
    std::ofstream file(path);
    file << content;
    return path;
}

Diagnostic makeDiag(const std::string& file, unsigned line,
                    const std::string& rule) {
    return {Severity::Warning, file, line, 1, rule, "msg"};
}

} // anonymous namespace

// --- markerSuppressesRule unit tests ---

TEST(SuppressionMarkerTest, BareMarkerSuppressesAllRules) {
    EXPECT_TRUE(markerSuppressesRule(
        "int x = 1/z; // codeskeptic-disable-line",
        "codeskeptic-disable-line", "div-by-zero"));
    EXPECT_TRUE(markerSuppressesRule(
        "int x = 1/z; // codeskeptic-disable-line",
        "codeskeptic-disable-line", "memory-leak"));
}

TEST(SuppressionMarkerTest, RuleListLimitsSuppression) {
    const std::string line =
        "int x = 1/z; // codeskeptic-disable-line div-by-zero, uninit-ptr";
    EXPECT_TRUE(markerSuppressesRule(line, "codeskeptic-disable-line",
                                     "div-by-zero"));
    EXPECT_TRUE(markerSuppressesRule(line, "codeskeptic-disable-line",
                                     "uninit-ptr"));
    EXPECT_FALSE(markerSuppressesRule(line, "codeskeptic-disable-line",
                                      "memory-leak"));
}

TEST(SuppressionMarkerTest, NextLineVariantDoesNotMatchLineMarker) {
    // A disable-next-line line must not count as a disable-line marker
    EXPECT_FALSE(markerSuppressesRule(
        "// codeskeptic-disable-next-line",
        "codeskeptic-disable-line", "div-by-zero"));
}

TEST(SuppressionMarkerTest, TrailingCommentAfterRuleList) {
    EXPECT_TRUE(markerSuppressesRule(
        "// codeskeptic-disable-line div-by-zero (deliberate: demo)",
        "codeskeptic-disable-line", "div-by-zero"));
    EXPECT_FALSE(markerSuppressesRule(
        "// codeskeptic-disable-line div-by-zero (deliberate: demo)",
        "codeskeptic-disable-line", "memory-leak"));
}

TEST(SuppressionMarkerTest, NoMarker_NoSuppression) {
    EXPECT_FALSE(markerSuppressesRule("int x = 1/z; // normal comment",
                                      "codeskeptic-disable-line",
                                      "div-by-zero"));
}

TEST(SuppressionMarkerTest, NonCommentAndMalformedMarkersNeverSuppress) {
    for (const std::string line : {
             "const char *text = \"codeskeptic-disable-line\";",
             "// not-codeskeptic-disable-line",
             "// codeskeptic-disable-line !!!",
             "// codeskeptic-disable-line ,"}) {
        SCOPED_TRACE(line);
        EXPECT_FALSE(markerSuppressesRule(line, "codeskeptic-disable-line", "div-by-zero"));
    }
}

TEST(SuppressionFilterTest, StringLiteralMarkerDoesNotHideRealFinding) {
    const auto path = writeTempSource("suppression_literal.cpp",
        "int f(){const char *text=\"codeskeptic-disable-line\";int zero=0;return 1/zero;}\n");
    SuppressionFilter filter;
    DiagnosticList findings = {makeDiag(path, 1, "div-by-zero")};
    EXPECT_EQ(filter.filter(findings), 0u);
    ASSERT_EQ(findings.size(), 1u);
}

// --- SuppressionFilter file tests ---

TEST(SuppressionFilterTest, DisableLineSameLine) {
    auto path = writeTempSource("supp1.cpp",
        "int a;\n"
        "int x = 1/z; // codeskeptic-disable-line\n"
        "int y = 1/w;\n");

    SuppressionFilter filter;
    DiagnosticList diags = {
        makeDiag(path, 2, "div-by-zero"),  // suppressed
        makeDiag(path, 3, "div-by-zero"),  // stays
    };
    size_t removed = filter.filter(diags);

    EXPECT_EQ(removed, 1u);
    ASSERT_EQ(diags.size(), 1u);
    EXPECT_EQ(diags[0].line, 3u);
}

TEST(SuppressionFilterTest, DisableNextLine) {
    auto path = writeTempSource("supp2.cpp",
        "// codeskeptic-disable-next-line div-by-zero\n"
        "int x = 1/z;\n"
        "int y = 1/w;\n");

    SuppressionFilter filter;
    DiagnosticList diags = {
        makeDiag(path, 2, "div-by-zero"),   // suppressed
        makeDiag(path, 2, "memory-leak"),   // rule not in the list -> stays
        makeDiag(path, 3, "div-by-zero"),   // stays
    };
    filter.filter(diags);

    ASSERT_EQ(diags.size(), 2u);
    EXPECT_EQ(diags[0].rule_id, "memory-leak");
    EXPECT_EQ(diags[1].line, 3u);
}

TEST(SuppressionFilterTest, MissingFile_NothingSuppressed) {
    SuppressionFilter filter;
    DiagnosticList diags = {
        makeDiag("/nonexistent/file.cpp", 5, "div-by-zero"),
    };
    size_t removed = filter.filter(diags);

    EXPECT_EQ(removed, 0u);
    EXPECT_EQ(diags.size(), 1u);
}

TEST(SuppressionFilterTest, LineBeyondFileEnd_NothingSuppressed) {
    auto path = writeTempSource("supp3.cpp", "int a;\n");

    SuppressionFilter filter;
    DiagnosticList diags = { makeDiag(path, 99, "div-by-zero") };
    size_t removed = filter.filter(diags);

    EXPECT_EQ(removed, 0u);
}

TEST(SuppressionFilterTest, PhysicalNewlinesCannotMoveAMarkerOntoAnotherFinding) {
    for (const std::string newline : {"\n", "\r\n", "\r"}) {
        const auto path = writeTempSource("supp_newlines.cpp",
            "int f(){int z=0;return 1/z;}" + newline +
            "// codeskeptic-disable-line div-by-zero" + newline);
        SuppressionFilter filter;
        DiagnosticList findings{makeDiag(path, 1, "div-by-zero")};
        EXPECT_EQ(filter.filter(findings), 0u);
        EXPECT_TRUE(filter.records().empty());
    }
    const auto path = writeTempSource("supp_mixed_newlines.cpp",
        "/* decoration\r\n * codeskeptic-disable-next-line div-by-zero -- reviewed fixture\r"
        " */ int f(){return 1/0;}\nint g(){return 1/0;}\r\n");
    SuppressionFilter filter;
    DiagnosticList findings{makeDiag(path, 3, "div-by-zero"), makeDiag(path, 4, "div-by-zero")};
    EXPECT_EQ(filter.filter(findings), 1u);
    ASSERT_EQ(filter.records().size(), 1u);
    EXPECT_EQ(filter.records()[0].marker_line, 2u);
    EXPECT_EQ(filter.records()[0].target_line, 3u);
    EXPECT_EQ(findings.front().line, 4u);
}

TEST(SuppressionFilterTest, RawStringsDigitSeparatorsAndEscapesCannotForgeComments) {
    for (const std::string content : {
        "auto n=1'000; const char* s=\"// codeskeptic-disable-line\";\n",
        "const char* s=R\"tag(\n// codeskeptic-disable-line\n)tag\";\n",
        "const char* s=\"escaped \\\" // codeskeptic-disable-line\";\n",
        "const char* s=\"continued \\\n// codeskeptic-disable-line\";\n"}) {
        const auto path = writeTempSource("supp_lexical.cpp", content);
        SuppressionFilter filter;
        DiagnosticList findings{makeDiag(path, 1, "div-by-zero"), makeDiag(path, 2, "div-by-zero")};
        EXPECT_EQ(filter.filter(findings), 0u) << content;
        EXPECT_TRUE(filter.records().empty());
    }
}

TEST(SuppressionMarkerTest, EmptyReasonsAndMalformedSelectorsNeverApply) {
    for (const std::string suffix : {" --", " --   ", " ()", " div-by-zero,", " ,div-by-zero",
                                    " div-by-zero,,memory-leak", " div-by-zero!", " div-by-zero (broken"}) {
        EXPECT_FALSE(markerSuppressesRule("// codeskeptic-disable-line" + suffix,
            "codeskeptic-disable-line", "div-by-zero")) << suffix;
    }
}

TEST(SuppressionFilterTest, RetainsReasonScopeFingerprintAndLogicalAuditCopies) {
    const auto path = writeTempSource("supp_audit.cpp",
        "// codeskeptic-disable-next-line div-by-zero -- bounded fixture rationale\n"
        "int f(){return 1/0;}\nint g(){return 1/0;} // codeskeptic-disable-line\n");
    auto finding = makeDiag(path, 2, "div-by-zero");
    auto unaffected = makeDiag(path, 2, "memory-leak");
    SuppressionFilter filter;
    DiagnosticList findings{finding, finding, unaffected, makeDiag(path, 3, "div-by-zero")};
    EXPECT_EQ(filter.filter(findings), 3u);
    ASSERT_EQ(findings.size(), 1u);
    EXPECT_EQ(findings.front().rule_id, "memory-leak");
    auto records = filter.takeRecords();
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(records[0].occurrences, 2u);
    EXPECT_EQ(records[0].reason, "bounded fixture rationale");
    EXPECT_TRUE(records[0].has_reason);
    EXPECT_EQ(records[0].rules, std::vector<std::string>{"div-by-zero"});
    EXPECT_FALSE(records[0].finding.fingerprint.empty());
    EXPECT_FALSE(records[1].has_reason);
    EXPECT_TRUE(records[1].reason.empty());
    EXPECT_TRUE(records[1].rules.empty());
    writeTempSource("supp_audit.cpp", "int f(){return 1/0;}\nint g(){return 1/0;}\n");
    findings = {finding};
    EXPECT_EQ(filter.filter(findings), 0u);
    EXPECT_TRUE(filter.records().empty());
}
