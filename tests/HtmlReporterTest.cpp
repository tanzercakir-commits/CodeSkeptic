// HTML report: a single self-contained file. Invariants: (1) all user
// data is HTML-escaped (a <script> in source code cannot leak into the
// report), (2) traces are embedded with source context (the report is
// portable), (3) summary cards/filter skeleton and the empty-report
// state are generated correctly.

#include "reporter/HtmlReporter.h"
#include "reporter/ConsoleReporter.h"
#include "reporter/JsonReporter.h"
#include "reporter/SarifReporter.h"

#include <fstream>
#include <sstream>
#include <gtest/gtest.h>
#include <llvm/Support/JSON.h>

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
    // Informational CWE links are not dependencies. The report has no external
    // script, stylesheet, frame or image, including relative network resources.
    EXPECT_EQ(html.find("<script src="), std::string::npos);
    EXPECT_EQ(html.find("<link "), std::string::npos);
    EXPECT_EQ(html.find("<img "), std::string::npos);
    EXPECT_EQ(html.find("<iframe"), std::string::npos);
    EXPECT_EQ(html.find("@import"), std::string::npos);
    EXPECT_EQ(html.find("url("), std::string::npos);
    EXPECT_NE(html.find("href=\"https://cwe.mitre.org/data/definitions/476.html\""), std::string::npos);
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
    AnalysisResult result;
    HtmlReporter reporter(out);
    reporter.report({}, &result);

    std::string html = readWhole(out);
    EXPECT_NE(html.find("Clean! No issues found."), std::string::npos);
}

TEST(HtmlReporterTest, MissingVerdictNeverClaimsClean) {
    std::string out = ::testing::TempDir() + "report_no_verdict.html";
    HtmlReporter reporter(out);
    reporter.report({});

    std::string html = readWhole(out);
    EXPECT_NE(html.find("Verdict: not-recorded"), std::string::npos);
    EXPECT_NE(html.find("Exit code: not-recorded"), std::string::npos);
    EXPECT_EQ(html.find("Clean! No issues found."), std::string::npos);
}

TEST(HtmlReporterTest, TracePreservesDirectoryAndColumnIdentity) {
    const std::string out = ::testing::TempDir() + "trace_identity.html";
    Diagnostic finding{Severity::Error, "/product/end/a.cpp", 8, 12, "null-deref", "end"};
    finding.notes = {{"/product/first/a.cpp", 2, 3, "first"},
                     {"/product/second/a.cpp", 2, 7, "second"}};
    HtmlReporter reporter(out);
    ASSERT_TRUE(reporter.report({finding}));
    const auto html = readWhole(out);
    EXPECT_NE(html.find("/product/first/a.cpp:2:3</span>"), std::string::npos);
    EXPECT_NE(html.find("/product/second/a.cpp:2:7</span>"), std::string::npos);
    EXPECT_LT(html.find("/product/first/a.cpp:2:3</span>"),
              html.find("/product/second/a.cpp:2:7</span>"));
}

TEST(OutputParityReporterTest, ConsoleMissingVerdictNeverClaimsClean) {
    ConsoleReporter reporter;
    ::testing::internal::CaptureStderr();
    const bool reported = reporter.report({});
    const auto output = ::testing::internal::GetCapturedStderr();
    ASSERT_TRUE(reported);
    EXPECT_EQ(output.find("Clean!"), std::string::npos);
    EXPECT_NE(output.find("not-recorded"), std::string::npos);
}

TEST(HtmlReporterTest, ReportOnlyVerdictPublishesTierCounts) {
    std::string out = ::testing::TempDir() + "report_only.html";
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.findings = result.report_only_findings = 2;

    HtmlReporter reporter(out);
    reporter.report({}, &result);

    std::string html = readWhole(out);
    EXPECT_NE(html.find("Verdict: report-only"), std::string::npos);
    EXPECT_NE(html.find("Exit code: 0"), std::string::npos);
    EXPECT_NE(html.find("Blocking findings: 0"), std::string::npos);
    EXPECT_NE(html.find("report-only: 2"), std::string::npos);
}

TEST(HtmlReporterTest, FindingPublishesSemanticFingerprint) {
    std::string out = ::testing::TempDir() + "fingerprint.html";
    Diagnostic diagnostic{Severity::Warning, "sample.cpp", 1, 1,
                          "memory-leak", "leak"};

    HtmlReporter reporter(out);
    reporter.report({diagnostic});

    std::string html = readWhole(out);
    EXPECT_NE(html.find("data-fingerprint=\"csf1-"), std::string::npos);
    EXPECT_NE(html.find("<span class=\"fp\">csf1-"), std::string::npos);
}

TEST(HtmlReporterTest, IncompleteEmptyReportNeverClaimsClean) {
    std::string out = ::testing::TempDir() + "report_incomplete.html";
    AnalysisResult result;
    result.attempted_tus = 2;
    result.analyzed_tus = 1;
    result.broken_tus = 1;
    result.incomplete_functions = 3;

    HtmlReporter reporter(out);
    reporter.report({}, &result);

    std::string html = readWhole(out);
    EXPECT_NE(html.find("Verdict: incomplete"), std::string::npos);
    EXPECT_NE(html.find("Exit code: 2"), std::string::npos);
    EXPECT_NE(html.find("TUs: 1 / 2 analyzed"), std::string::npos);
    EXPECT_EQ(html.find("Clean! No issues found."), std::string::npos);
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

TEST(HtmlReporterTest, AcceptedPartialAndRecoveryEscapeSourceEvidenceWithoutCleanLabel) {
    const std::string out = ::testing::TempDir() + "source_coverage_escape.html";
    for (bool recovery : {false, true}) {
        AnalysisResult result;
        SourceCoverage safe{"safe.cpp", SourceStatus::Analyzed, "analyzed"};
        safe.commands = safe.analyzed_commands = 1;
        SourceCoverage risky{"bad<script>&\".cpp", recovery ? SourceStatus::Analyzed : SourceStatus::Skipped,
                             "reason<&\""};
        risky.commands = 1;
        risky.analyzed_commands = risky.recovery_commands = recovery ? 1 : 0;
        risky.skipped_commands = recovery ? 0 : 1;
        result.sources = {safe, risky};
        result.reconcileSources();
        result.analyze_broken_tus = recovery;
        result.accept_partial_coverage = !recovery;
        ASSERT_EQ(result.exitCode(), 0);
        HtmlReporter reporter(out);
        ASSERT_TRUE(reporter.report({}, &result));
        const auto html = readWhole(out);
        EXPECT_EQ(html.find("Clean! No issues found."), std::string::npos);
        EXPECT_NE(html.find("Full coverage: no"), std::string::npos);
        EXPECT_NE(html.find(recovery ? "recovery-accepted" : "partial-accepted"), std::string::npos);
        EXPECT_EQ(html.find(risky.file), std::string::npos);
        EXPECT_NE(html.find("bad&lt;script&gt;&amp;&quot;.cpp"), std::string::npos);
        EXPECT_NE(html.find("reason&lt;&amp;&quot;"), std::string::npos);
    }
}

namespace {

std::string decodeReportHtml(std::string text) {
    // Decode exactly one layer. Ampersand last prevents entity-looking source
    // text from being interpreted a second time by the test normalizer.
    for (const auto& [encoded, decoded] : {
             std::pair{"&quot;", "\""}, {"&#39;", "'"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&amp;", "&"}}) {
        std::size_t position = 0;
        while ((position = text.find(encoded, position)) != std::string::npos) {
            text.replace(position, std::char_traits<char>::length(encoded), decoded);
            position += std::char_traits<char>::length(decoded);
        }
    }
    return text;
}

void checkSurfaceSnapshots(const DiagnosticList& findings, const AnalysisResult* result) {
    const std::string prefix = ::testing::TempDir() + "surface_snapshot";
    ASSERT_TRUE(JsonReporter(prefix + ".json").report(findings, result));
    ASSERT_TRUE(HtmlReporter(prefix + ".html").report(findings, result));
    ASSERT_TRUE(SarifReporter(prefix + ".sarif").report(findings, result));
    ::testing::internal::CaptureStderr();
    const bool consoleReported = ConsoleReporter().report(findings, result);
    const auto console = ::testing::internal::GetCapturedStderr();
    ASSERT_TRUE(consoleReported);
    const std::string html = readWhole(prefix + ".html");
    const std::string marker = "<pre id=\"codeskeptic-report\">";
    const auto start = html.find(marker);
    ASSERT_NE(start, std::string::npos);
    const auto end = html.find("</pre>", start + marker.size());
    ASSERT_NE(end, std::string::npos);
    auto jsonValue = llvm::json::parse(readWhole(prefix + ".json"));
    auto htmlValue = llvm::json::parse(decodeReportHtml(html.substr(start + marker.size(), end - start - marker.size())));
    auto sarifValue = llvm::json::parse(readWhole(prefix + ".sarif"));
    ASSERT_TRUE(static_cast<bool>(jsonValue));
    ASSERT_TRUE(static_cast<bool>(htmlValue));
    ASSERT_TRUE(static_cast<bool>(sarifValue));
    EXPECT_EQ(*htmlValue, *jsonValue);
    const auto* reference = jsonValue->getAsObject();
    ASSERT_NE(reference, nullptr);
    EXPECT_EQ(reference->getString("schema"), "codeskeptic-report/v1");
    EXPECT_EQ(reference->getString("tool_version"), CODESKEPTIC_VERSION);
    EXPECT_EQ(reference->getString("status"), result ? result->statusName() : "not-recorded");
    const auto* sarif = sarifValue->getAsObject();
    ASSERT_NE(sarif, nullptr);
    EXPECT_EQ(sarif->getString("version"), "2.1.0");
    const auto* runs = sarif->getArray("runs");
    ASSERT_NE(runs, nullptr);
    ASSERT_EQ(runs->size(), 1u);
    const auto* run = runs->front().getAsObject();
    ASSERT_NE(run, nullptr);
    ASSERT_NE(run->getObject("tool"), nullptr);
    const auto* driver = run->getObject("tool")->getObject("driver");
    ASSERT_NE(driver, nullptr);
    EXPECT_EQ(driver->getString("version"), reference->getString("tool_version"));
    const auto* properties = run->getObject("properties");
    ASSERT_NE(properties, nullptr);
    const auto* sarifHeader = properties->getObject("codeskeptic/report");
    ASSERT_NE(sarifHeader, nullptr);
    const std::string headerMarker = "[CodeSkeptic] report: ";
    ASSERT_EQ(console.find(headerMarker), 0u);
    auto consoleValue = llvm::json::parse(console.substr(headerMarker.size(), console.find('\n') - headerMarker.size()));
    ASSERT_TRUE(static_cast<bool>(consoleValue));
    const auto* consoleHeader = consoleValue->getAsObject();
    ASSERT_NE(consoleHeader, nullptr);
    for (const auto& [key, value] : *reference) {
        if (key == "coverage" || key == "diagnostics") continue;
        ASSERT_NE(sarifHeader->get(key), nullptr);
        ASSERT_NE(consoleHeader->get(key), nullptr);
        EXPECT_EQ(*sarifHeader->get(key), value);
        EXPECT_EQ(*consoleHeader->get(key), value);
    }
    if (result) {
        const auto* invocations = run->getArray("invocations");
        ASSERT_NE(invocations, nullptr);
        ASSERT_EQ(invocations->size(), 1u);
        const auto* invocation = invocations->front().getAsObject();
        ASSERT_NE(invocation, nullptr);
        EXPECT_EQ(invocation->getBoolean("executionSuccessful"), result->complete());
        const auto* evidence = invocation->getObject("properties");
        ASSERT_NE(evidence, nullptr);
        ASSERT_NE(evidence->get("codeskeptic/coverage"), nullptr);
        EXPECT_EQ(*evidence->get("codeskeptic/coverage"), *reference->get("coverage"));
        EXPECT_EQ(evidence->getString("codeskeptic/status"), result->statusName());
        EXPECT_EQ(evidence->getInteger("codeskeptic/exitCode"), result->exitCode());
    } else {
        EXPECT_EQ(run->getArray("invocations"), nullptr);
        EXPECT_EQ(*reference->get("complete"), llvm::json::Value(nullptr));
        EXPECT_EQ(*reference->get("coverage"), llvm::json::Value(nullptr));
        EXPECT_EQ(*reference->get("evidence"), llvm::json::Value(nullptr));
        EXPECT_EQ(*reference->get("exit_code"), llvm::json::Value(nullptr));
        EXPECT_EQ(html.find("Clean!"), std::string::npos);
        EXPECT_EQ(console.find("Clean!"), std::string::npos);
    }
    const auto* rows = reference->getArray("diagnostics");
    const auto* nativeRows = run->getArray("results");
    ASSERT_NE(rows, nullptr);
    ASSERT_NE(nativeRows, nullptr);
    ASSERT_EQ(rows->size(), findings.size());
    ASSERT_EQ(nativeRows->size(), findings.size());
    std::istringstream lines(console);
    std::string line;
    std::size_t index = 0;
    const std::string findingMarker = "[CodeSkeptic] finding: ";
    while (std::getline(lines, line)) {
        if (line.rfind(findingMarker, 0) != 0) continue;
        ASSERT_LT(index, rows->size());
        auto parsed = llvm::json::parse(line.substr(findingMarker.size()));
        ASSERT_TRUE(static_cast<bool>(parsed));
        EXPECT_EQ(*parsed, (*rows)[index]);
        const auto* native = (*nativeRows)[index].getAsObject();
        const auto* row = (*rows)[index].getAsObject();
        ASSERT_NE(native, nullptr);
        ASSERT_NE(row, nullptr);
        EXPECT_EQ(native->getString("ruleId"), row->getString("rule_id"));
        EXPECT_EQ(native->getString("level"), findings[index].severity == Severity::Info ? "note" : findings[index].severityToString());
        const auto* metadata = native->getObject("properties");
        ASSERT_NE(metadata, nullptr);
        ASSERT_NE(metadata->get("codeskeptic/ruleMetadata"), nullptr);
        EXPECT_EQ(*metadata->get("codeskeptic/ruleMetadata"), *row->get("rule_metadata"));
        ASSERT_NE(native->getObject("message"), nullptr);
        EXPECT_EQ(native->getObject("message")->getString("text"), row->getString("message"));
        ++index;
    }
    EXPECT_EQ(index, findings.size());
}

} // namespace

TEST(OutputParityReporterTest, SpecialTextWindowsPathsAndTypedCwesAgree) {
    std::string text = "</pre><script>untrusted-marker</script> &quot; ' \\\"";
    for (int byte = 0; byte < 32; ++byte) text += static_cast<char>(byte);
    Diagnostic read{Severity::Warning, "C:\\first dir\\a.cpp", 12, 8, "bounds", text};
    read.kind = FindingKind::BoundsRead;
    read.additional_kinds = {FindingKind::BoundsWrite, FindingKind::Unspecified};
    read.function = text;
    read.fingerprint = "explicit-fingerprint";
    read.notes = {{"\\\\srv\\share\\a.cpp", 1, 2, text}, {"rel\\dir\\a.cpp", 1, 7, text}};
    Diagnostic info{Severity::Info, "relative.cpp", 2, 3, "extension-rule", text};
    Diagnostic error{Severity::Error, "/src/a.cpp", 4, 5, "null-deref", text};
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.findings = 3;
    result.report_only_findings = 1;
    checkSurfaceSnapshots({read, info, error}, &result);
    checkSurfaceSnapshots({read}, nullptr);
    const auto html = readWhole(::testing::TempDir() + "surface_snapshot.html");
    EXPECT_EQ(html.find("<script>untrusted-marker"), std::string::npos);
    EXPECT_NE(html.find("CWE-125</a>"), std::string::npos);
    EXPECT_NE(html.find("CWE-787</a>"), std::string::npos);
    EXPECT_NE(html.find("\\\\srv\\share\\a.cpp:1:2</span>"), std::string::npos);
    EXPECT_NE(html.find("rel\\dir\\a.cpp:1:7</span>"), std::string::npos);
}

TEST(OutputParityReporterTest, EveryVerdictEvidenceFlagAgreesWithoutInventingCoverage) {
    AnalysisResult base;
    SourceCoverage source{"safe.cpp", SourceStatus::Analyzed, "analyzed"};
    source.commands = source.analyzed_commands = 1;
    source.prepass_status = "analyzed";
    source.prepass_reason = "full prepass";
    base.sources = {source};
    base.reconcileSources();
    checkSurfaceSnapshots({}, &base);
    for (auto flag : {&AnalysisResult::no_inputs, &AnalysisResult::no_rules,
                       &AnalysisResult::tool_failed, &AnalysisResult::summary_load_failed,
                       &AnalysisResult::summary_stale, &AnalysisResult::summary_save_failed,
                       &AnalysisResult::baseline_load_failed, &AnalysisResult::baseline_write_failed,
                       &AnalysisResult::baseline_recorded, &AnalysisResult::report_write_failed}) {
        auto result = base;
        result.*flag = true;
        checkSurfaceSnapshots({}, &result);
    }
    auto recovery = base;
    recovery.sources.front().recovery_commands = 1;
    recovery.sources.front().prepass_recovery_commands = 1;
    recovery.analyze_broken_tus = true;
    recovery.reconcileSources();
    ASSERT_TRUE(recovery.complete());
    ASSERT_FALSE(recovery.coverageComplete());
    checkSurfaceSnapshots({}, &recovery);
    checkSurfaceSnapshots({}, nullptr);
}

TEST(OutputParityReporterTest, InvalidUtf8AndReservedIdentityPrefixDoNotAliasPaths) {
    Diagnostic bytes{Severity::Error, std::string("/src/") + char(0xff) + ".cpp",
                     1, 1, "null-deref", "message"};
    Diagnostic literal = bytes;
    literal.file = "codeskeptic-bytes:2f";
    bytes.notes = {{literal.file, 2, 3, "literal prefix"}};
    AnalysisResult result;
    result.attempted_tus = result.analyzed_tus = 1;
    result.findings = 2;
    checkSurfaceSnapshots({bytes, literal}, &result);
    auto parsed = llvm::json::parse(readWhole(::testing::TempDir() + "surface_snapshot.json"));
    ASSERT_TRUE(static_cast<bool>(parsed));
    const auto* rows = parsed->getAsObject()->getArray("diagnostics");
    ASSERT_NE(rows, nullptr);
    EXPECT_EQ((*rows)[0].getAsObject()->getString("file"), "codeskeptic-bytes:2f7372632fff2e637070");
    EXPECT_EQ((*rows)[1].getAsObject()->getString("file"),
              "codeskeptic-bytes:636f6465736b65707469632d62797465733a3266");
    const auto sarif = readWhole(::testing::TempDir() + "surface_snapshot.sarif");
    EXPECT_NE(sarif.find("\"uri\": \"file:///src/%FF.cpp\""), std::string::npos);
    EXPECT_NE(sarif.find("\"uri\": \"codeskeptic-bytes%3A2f\""), std::string::npos);
    const auto html = readWhole(::testing::TempDir() + "surface_snapshot.html");
    EXPECT_NE(html.find("codeskeptic-bytes:2f7372632fff2e637070:1:1</span>"), std::string::npos);
}
