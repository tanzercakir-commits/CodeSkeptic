#include "analyzer/Baseline.h"

#include <fstream>
#include <gtest/gtest.h>

using namespace codeskeptic;

namespace {

Diagnostic makeDiag(const std::string& file, unsigned line,
                    const std::string& rule, const std::string& message) {
    return {Severity::Warning, file, line, 1, rule, message};
}

std::string writeSource(const std::string& name,
                        const std::string& content) {
    std::string path = ::testing::TempDir() + name;
    std::ofstream file(path);
    file << content;
    return path;
}

// Frozen legacy fixture producer, NOT the current writer. These tests keep
// v2's original semantics explicit while the production writer advances to v3.
bool writeLegacyV2(const std::string& path, const DiagnosticList& diagnostics) {
    std::ofstream file(path);
    file << "# codeskeptic-baseline v2\n";
    for (const auto& diagnostic : diagnostics) file << Baseline::keyV2(diagnostic) << '\n';
    file.close();
    return !file.fail();
}

Diagnostic boundDiag(const std::string& source, unsigned line = 1, unsigned column = 1) {
    auto diagnostic = makeDiag(source, line, "div-by-zero", "division by zero");
    diagnostic.column = column;
    diagnostic.function = "f";
    diagnostic.baseline_function = "csb-fn1:int (int)";
    return diagnostic;
}

} // anonymous namespace

TEST(BaselineTest, WriteLoadFilterRoundtrip) {
    std::string path = ::testing::TempDir() + "baseline1.txt";

    DiagnosticList original = {
        boundDiag(writeSource("baseline_roundtrip_a.cpp", "return 1/z;\n")),
        boundDiag(writeSource("baseline_roundtrip_b.cpp", "return 1/z;\n")),
    };
    ASSERT_TRUE(Baseline::write(path, original));

    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));

    // Same findings + one new finding
    DiagnosticList current = original;
    current.push_back(makeDiag("c.cpp", 5, "uninit-ptr", "new finding"));

    size_t filtered = baseline.filter(current);
    EXPECT_EQ(filtered, 2u);
    ASSERT_EQ(current.size(), 1u);
    EXPECT_EQ(current[0].rule_id, "uninit-ptr");
}

TEST(BaselineTest, KeyV1IncludesLineAndMessage) {
    auto d1 = makeDiag("a.cpp", 10, "memory-leak", "leak of p");
    auto d2 = makeDiag("a.cpp", 11, "memory-leak", "leak of p");
    auto d3 = makeDiag("a.cpp", 10, "memory-leak", "leak of q");

    EXPECT_NE(Baseline::keyV1(d1), Baseline::keyV1(d2));
    EXPECT_NE(Baseline::keyV1(d1), Baseline::keyV1(d3));
}

TEST(BaselineTest, MissingFile_LoadFailsButFilterIsNoop) {
    Baseline baseline;
    EXPECT_FALSE(baseline.load("/nonexistent/baseline.txt"));

    DiagnosticList diags = { makeDiag("a.cpp", 1, "r", "m") };
    EXPECT_EQ(baseline.filter(diags), 0u);
    EXPECT_EQ(diags.size(), 1u);
}

TEST(BaselineTest, EmptyDiagnostics_WritesEmptyFile) {
    std::string path = ::testing::TempDir() + "baseline2.txt";
    ASSERT_TRUE(Baseline::write(path, {}));

    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList diags = { makeDiag("a.cpp", 1, "r", "m") };
    EXPECT_EQ(baseline.filter(diags), 0u);
}

TEST(BaselineSafetyTest, NewFunctionCannotConsumeRemovedFunctionsBudget) {
    const auto source = writeSource("baseline_function_identity.cpp",
        "int old_function(){\nint zero=0;\nreturn 1/zero;\n}\n");
    const std::string path = ::testing::TempDir() + "baseline_function_identity.txt";
    auto original = makeDiag(source, 3, "div-by-zero", "division by zero");
    original.function = "old_function";
    original.baseline_function = "csb-fn1:int ()";
    original.fingerprint = "original-fingerprint";
    ASSERT_TRUE(Baseline::write(path, {original}));
    writeSource("baseline_function_identity.cpp",
        "int replacement_function(){\nint zero=0;\nreturn 1/zero;\n}\n");
    auto replacement = original;
    replacement.function = "replacement_function";
    replacement.fingerprint = "replacement-fingerprint";
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList current = {replacement};
    EXPECT_EQ(baseline.filter(current), 0u);
    ASSERT_EQ(current.size(), 1u);
    EXPECT_EQ(current.front().function, "replacement_function");
}

TEST(BaselineSafetyTest, UnknownVersionsAndMalformedRowsRejectTheWholeLoad) {
    const std::string path = ::testing::TempDir() + "baseline_malformed.txt";
    for (const std::string contents : {
             "# codeskeptic-baseline v999\n",
             "# codeskeptic-baseline v2\nnot a baseline record\n",
             "# codeskeptic-baseline v2\nr|a.cpp|not-a-hash|message\n"}) {
        SCOPED_TRACE(contents);
        { std::ofstream file(path); file << contents; }
        Baseline baseline;
        EXPECT_FALSE(baseline.load(path));
        DiagnosticList current = {makeDiag("a.cpp", 1, "r", "message")};
        EXPECT_EQ(baseline.filter(current), 0u);
        EXPECT_EQ(current.size(), 1u);
    }
}

// ===================================================================
// Baseline v2: line-independent key (hash of the line content)
// Invariants: (1) the baseline stays valid when code shifts, (2) the
// finding resurfaces when the line ITSELF changes, (3) identical lines
// are tracked by count — baselining one does not hide the other,
// (4) old v1 files keep working with their old semantics.
// ===================================================================

TEST(BaselineV2Test, LineShift_StillSuppressed) {
    // Code is added ABOVE the finding line: the line number shifts but
    // the content is the same — v1's known limitation, solved in v2
    auto src = writeSource("blv2_shift.cpp",
        "void f() {\n"
        "    int* p = new int(1);\n"
        "}\n");
    std::string path = ::testing::TempDir() + "blv2_shift.txt";
    ASSERT_TRUE(writeLegacyV2(path,
        { makeDiag(src, 2, "memory-leak", "leak of p") }));

    // Two lines added above: the finding is now on line 4
    writeSource("blv2_shift.cpp",
        "// new comment\n"
        "// one more line\n"
        "void f() {\n"
        "    int* p = new int(1);\n"
        "}\n");
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList current = { makeDiag(src, 4, "memory-leak", "leak of p") };
    EXPECT_EQ(baseline.filter(current), 1u);
    EXPECT_TRUE(current.empty());
}

TEST(BaselineV2Test, ReindentedLine_StillSuppressed) {
    // Only the indentation changed (e.g. the block was wrapped in an if
    // but the finding line is the same): trimmed content is the same ->
    // stays suppressed
    auto src = writeSource("blv2_indent.cpp",
        "int* p = new int(1);\n");
    std::string path = ::testing::TempDir() + "blv2_indent.txt";
    ASSERT_TRUE(writeLegacyV2(path,
        { makeDiag(src, 1, "memory-leak", "leak of p") }));

    writeSource("blv2_indent.cpp",
        "        int* p = new int(1);\n");
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList current = { makeDiag(src, 1, "memory-leak", "leak of p") };
    EXPECT_EQ(baseline.filter(current), 1u);
}

TEST(BaselineV2Test, ChangedLine_ResurfacesAsNew) {
    // The line ITSELF changed: the finding must resurface — a changed
    // line should be re-reviewed (deliberate behavior)
    auto src = writeSource("blv2_changed.cpp",
        "int* p = new int(1);\n");
    std::string path = ::testing::TempDir() + "blv2_changed.txt";
    ASSERT_TRUE(writeLegacyV2(path,
        { makeDiag(src, 1, "memory-leak", "leak of p") }));

    writeSource("blv2_changed.cpp",
        "int* p = new int(42);\n");
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList current = { makeDiag(src, 1, "memory-leak", "leak of p") };
    EXPECT_EQ(baseline.filter(current), 0u);
    EXPECT_EQ(current.size(), 1u);
}

TEST(BaselineV2Test, IdenticalLines_CountedSeparately) {
    // IDENTICAL line + identical message at two separate locations: with
    // ONE record in the baseline only ONE finding is suppressed — the
    // second counts as new (with set semantics both would be silently
    // swallowed)
    auto src = writeSource("blv2_dup.cpp",
        "void f() { delete p; }\n"
        "void g() { delete p; }\n");
    std::string path = ::testing::TempDir() + "blv2_dup.txt";
    ASSERT_TRUE(writeLegacyV2(path,
        { makeDiag(src, 1, "double-free", "double free of p") }));

    // Trimmed line contents differ (f vs g) — this test must force the
    // same CONTENT: make the two lines exactly identical
    src = writeSource("blv2_dup2.cpp",
        "    delete p;\n"
        "    delete p;\n");
    path = ::testing::TempDir() + "blv2_dup2.txt";
    ASSERT_TRUE(writeLegacyV2(path,
        { makeDiag(src, 1, "double-free", "double free of p") }));

    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList current = {
        makeDiag(src, 1, "double-free", "double free of p"),
        makeDiag(src, 2, "double-free", "double free of p"),
    };
    EXPECT_EQ(baseline.filter(current), 1u);
    ASSERT_EQ(current.size(), 1u);

    // A baseline with two records suppresses both
    ASSERT_TRUE(writeLegacyV2(path, {
        makeDiag(src, 1, "double-free", "double free of p"),
        makeDiag(src, 2, "double-free", "double free of p"),
    }));
    Baseline full;
    ASSERT_TRUE(full.load(path));
    DiagnosticList both = {
        makeDiag(src, 1, "double-free", "double free of p"),
        makeDiag(src, 2, "double-free", "double free of p"),
    };
    EXPECT_EQ(full.filter(both), 2u);
    EXPECT_TRUE(both.empty());
}

TEST(BaselineV2Test, OldV1File_StillMatchesByLine) {
    // Hand-written v1 file (headerless, line-numbered key): a finding on
    // the same line is suppressed, a shifted one is NOT (old behavior is
    // preserved — refreshing migrates to v2)
    std::string path = ::testing::TempDir() + "blv2_v1compat.txt";
    {
        std::ofstream file(path);
        file << "memory-leak|old.cpp|10|leak of p\n";
    }
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));

    DiagnosticList same = { makeDiag("old.cpp", 10, "memory-leak", "leak of p") };
    EXPECT_EQ(baseline.filter(same), 1u);

    DiagnosticList shifted = { makeDiag("old.cpp", 11, "memory-leak", "leak of p") };
    EXPECT_EQ(baseline.filter(shifted), 0u);
}

TEST(BaselineV3Test, FileHeaderWritten) {
    // The new writer must not silently reinterpret a v2 record.
    std::string path = ::testing::TempDir() + "blv2_header.txt";
    ASSERT_TRUE(Baseline::write(path, {}));
    std::ifstream file(path);
    std::string first;
    std::getline(file, first);
    EXPECT_EQ(first, "# codeskeptic-baseline v3");
}

TEST(BaselineV3Test, LineShiftAndIndentationPreserveStrongIdentity) {
    const auto source = writeSource("baseline_v3_shift.cpp", "  return 1/z;\n");
    auto old = boundDiag(source, 1, 3);
    const auto fingerprint = Baseline::keyV3(old);
    ASSERT_FALSE(fingerprint.empty());
    writeSource("baseline_v3_shift.cpp", "// inserted\r\n\r    return 1/z;\r");
    auto moved = old;
    moved.line = 3;
    moved.column = 5;
    EXPECT_EQ(Baseline::keyV3(moved), fingerprint);
}

TEST(BaselineV3Test, DistinguishesFunctionSignatureSeverityColumnPathAndContent) {
    const auto source = writeSource("baseline_v3_identity.cpp", "return 1/z;\n");
    auto original = boundDiag(source);
    const auto key = Baseline::keyV3(original);
    ASSERT_FALSE(key.empty());
    for (int change = 0; change < 6; ++change) {
        auto changed = original;
        if (change == 0) changed.function = "g";
        if (change == 1) changed.baseline_function = "csb-fn1:int (long)";
        if (change == 2) changed.severity = Severity::Error;
        if (change == 3) changed.column = 2;
        if (change == 4) changed.file = writeSource("baseline_v3_other.cpp", "return 1/z;\n");
        if (change == 5) changed.message += " changed";
        EXPECT_NE(Baseline::keyV3(changed), key) << change;
    }
    writeSource("baseline_v3_identity.cpp", "return 2/z;\n");
    EXPECT_NE(Baseline::keyV3(original), key);
}

TEST(BaselineV3Test, CallbackMultiplicityCannotHideANewLogicalFinding) {
    const auto source = writeSource("baseline_v3_multiplicity.cpp", "return 1/z;\nreturn 1/z;\n");
    const auto path = ::testing::TempDir() + "baseline_v3_multiplicity.txt";
    auto original = boundDiag(source);
    auto fresh = original;
    fresh.line = 2;
    ASSERT_TRUE(Baseline::write(path, {original, original, original}));
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    EXPECT_EQ(baseline.version(), 3u);
    EXPECT_FALSE(baseline.legacy());
    for (int copies : {1, 2, 5}) {
        DiagnosticList findings(copies, original);
        findings.push_back(fresh);
        EXPECT_EQ(baseline.filter(findings), static_cast<std::size_t>(copies));
        ASSERT_EQ(findings.size(), 1u);
        EXPECT_EQ(findings.front().line, 2u);
    }
}

TEST(BaselineV3Test, MissingOrConflictingProofNeverFallsBackToPublicFingerprint) {
    const auto source = writeSource("baseline_v3_unbound.cpp", "return 1/z;\n");
    const auto path = ::testing::TempDir() + "baseline_v3_unbound.txt";
    auto bound = boundDiag(source);
    auto unbound = bound;
    unbound.baseline_function.clear();
    unbound.fingerprint = "csf1-do-not-use-as-baseline-authority";
    EXPECT_TRUE(Baseline::keyV3(unbound).empty());
    std::size_t unboundCount = 0;
    ASSERT_TRUE(Baseline::write(path, {bound, unbound}, &unboundCount));
    EXPECT_EQ(unboundCount, 1u);
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    EXPECT_EQ(baseline.unboundRecords(), 1u);
    DiagnosticList findings{bound};
    EXPECT_EQ(baseline.filter(findings), 0u);
    ASSERT_TRUE(Baseline::write(path, {bound}));
    ASSERT_TRUE(baseline.load(path));
    findings = {bound, unbound};
    EXPECT_EQ(baseline.filter(findings), 0u);
    auto conflict = bound;
    conflict.baseline_function = "csb-fn1:int (long)";
    findings = {bound, conflict};
    EXPECT_EQ(baseline.filter(findings), 0u);
    for (auto unavailable : {bound, bound, bound}) {
        unavailable.file = "/nonexistent/baseline_v3_source.cpp";
        EXPECT_TRUE(Baseline::keyV3(unavailable).empty());
        unavailable = bound;
        unavailable.line = 1000;
        EXPECT_TRUE(Baseline::keyV3(unavailable).empty());
    }
}

TEST(BaselineV3Test, ExactEncodingAndAtomicLoadRejectMixedOrMalformedFiles) {
    const auto source = writeSource("baseline_v3_encoding.cpp", "return 1/z;\n");
    auto diagnostic = boundDiag(source);
    diagnostic.message = "delimiter | tab\t newline\n";
    diagnostic.function = "f|name";
    const auto path = ::testing::TempDir() + "baseline_v3_encoding.txt";
    ASSERT_TRUE(Baseline::write(path, {diagnostic}));
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList findings{diagnostic};
    EXPECT_EQ(baseline.filter(findings), 1u);
    const auto key = Baseline::keyV3(diagnostic);
    for (const auto suffix : {"broken", "unbound|gg", "# codeskeptic-baseline v2", "r|file|2|message"}) {
        { std::ofstream file(path); file << "# codeskeptic-baseline v3\n" << key << '\n' << suffix << '\n'; }
        EXPECT_FALSE(baseline.load(path));
        findings = {diagnostic};
        EXPECT_EQ(baseline.filter(findings), 0u);
        EXPECT_EQ(baseline.version(), 0u);
    }
}

#ifndef _WIN32
TEST(BaselineV3Test, BufferedWriteFailureIsNotSuccess) {
    EXPECT_FALSE(Baseline::write("/dev/full", {}));
}
#endif

// --- --files UX hardening (systemd lesson, 2026-07-12) ---

#include "analyzer/StaticAnalyzer.h"

TEST(FilesUxTest, ZeroAnalyzableFiles_IsAnError) {
    // Analyzing nothing must not look like a clean pass.
    codeskeptic::Config config;
    config.setSourcePath("/nonexistent/definitely/missing.c");
    codeskeptic::StaticAnalyzer analyzer(std::move(config));
    const auto result = analyzer.run();
    EXPECT_EQ(result.exitCode(), 2);
    EXPECT_EQ(result.status(), codeskeptic::AnalysisStatus::Failed);
}
