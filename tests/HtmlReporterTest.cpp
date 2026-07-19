// HTML report: a single self-contained file. Invariants: (1) all user
// data is HTML-escaped (a <script> in source code cannot leak into the
// report), (2) traces are embedded with source context (the report is
// portable), (3) summary cards/filter skeleton and the empty-report
// state are generated correctly.

#include "reporter/HtmlReporter.h"

#include <fstream>
#include <gtest/gtest.h>

using namespace codeskeptic;

namespace {

std::string readWhole(const std::string& path) {
    std::ifstream file(path);
    return {std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()};
}

Diagnostic makeDiag(const std::string& file, unsigned line,
                    const std::string& rule, const std::string& message,
                    Severity sev = Severity::Warning) {
    Diagnostic d{sev, file, line, 1, rule, message};
    d.function = "f";
    return d;
}

} // anonymous namespace

TEST(HtmlReporterTest, BasicStructure_CardsFiltersFindings) {
    std::string out = ::testing::TempDir() + "report_basic.html";
    DiagnosticList diags = {
        makeDiag("a.cpp", 3, "null-deref", "maybe null", Severity::Warning),
        makeDiag("b.cpp", 7, "memory-leak", "leaked", Severity::Error),
    };
    HtmlReporter reporter(out);
    reporter.report(diags);

    std::string html = readWhole(out);
    EXPECT_NE(html.find("<!DOCTYPE html>"), std::string::npos);
    // Summary cards (also filters): severity + rule
    EXPECT_NE(html.find("data-sev=\"error\""), std::string::npos);
    EXPECT_NE(html.find("data-rule=\"memory-leak\""), std::string::npos);
    // Finding body and location
    EXPECT_NE(html.find("a.cpp:3:1"), std::string::npos);
    EXPECT_NE(html.find("maybe null"), std::string::npos);
    // Filter skeleton: text box + script
    EXPECT_NE(html.find("id=\"q\""), std::string::npos);
    EXPECT_NE(html.find("<script>"), std::string::npos);
    // No external resources (self-contained file)
    EXPECT_EQ(html.find("http://"), std::string::npos);
    EXPECT_EQ(html.find("https://"), std::string::npos);
}

TEST(HtmlReporterTest, UserData_IsHtmlEscaped) {
    std::string out = ::testing::TempDir() + "report_escape.html";
    DiagnosticList diags = {
        makeDiag("evil<script>.cpp", 1, "null-deref",
                 "deref of 'p' where a<b & c>\"d\""),
    };
    HtmlReporter reporter(out);
    reporter.report(diags);

    std::string html = readWhole(out);
    EXPECT_EQ(html.find("evil<script>"), std::string::npos);
    EXPECT_NE(html.find("evil&lt;script&gt;"), std::string::npos);
    EXPECT_NE(html.find("a&lt;b &amp; c&gt;&quot;d&quot;"),
              std::string::npos);
}

TEST(HtmlReporterTest, Trace_EmbedsSourceContext) {
    // A real source file: the trace note and finding must be embedded
    // with ±2 lines of context and the target line marked — the context
    // survives when the report is moved
    std::string src = ::testing::TempDir() + "ctx_demo.cpp";
    {
        std::ofstream f(src);
        f << "int line_one;\n"
          << "int* p = 0;\n"
          << "int x = *p;\n"
          << "int line_four;\n";
    }
    Diagnostic d = makeDiag(src, 3, "null-deref", "p is null",
                            Severity::Error);
    d.notes.push_back({src, 2, 1, "p assigned null here"});

    std::string out = ::testing::TempDir() + "report_ctx.html";
    HtmlReporter reporter(out);
    reporter.report({d});

    std::string html = readWhole(out);
    EXPECT_NE(html.find("Dataflow trace"), std::string::npos);
    EXPECT_NE(html.find("p assigned null here"), std::string::npos);
    // Source lines are embedded (escaped)
    EXPECT_NE(html.find("int* p = 0;"), std::string::npos);
    EXPECT_NE(html.find("int x = *p;"), std::string::npos);
    // Target line is marked
    EXPECT_NE(html.find("cl hit"), std::string::npos);
}

TEST(HtmlReporterTest, EmptyReport_ShowsClean) {
    std::string out = ::testing::TempDir() + "report_empty.html";
    HtmlReporter reporter(out);
    reporter.report({});

    std::string html = readWhole(out);
    EXPECT_NE(html.find("Clean! No issues found."), std::string::npos);
}

TEST(HtmlReporterTest, MissingSourceFile_NoContextButNoCrash) {
    // If the source is missing (moved/deleted) context is skipped, the
    // report is still generated
    std::string out = ::testing::TempDir() + "report_nosrc.html";
    Diagnostic d = makeDiag("/no/such/file.cpp", 10, "memory-leak", "leak");
    d.notes.push_back({"/no/such/file.cpp", 5, 1, "allocated here"});
    HtmlReporter reporter(out);
    reporter.report({d});

    std::string html = readWhole(out);
    EXPECT_NE(html.find("allocated here"), std::string::npos);
    EXPECT_EQ(html.find("cl hit"), std::string::npos);
}
