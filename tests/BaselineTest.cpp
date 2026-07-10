#include "analyzer/Baseline.h"

#include <fstream>
#include <gtest/gtest.h>

using namespace zerodefect;

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

} // anonymous namespace

TEST(BaselineTest, WriteLoadFilterRoundtrip) {
    std::string path = ::testing::TempDir() + "baseline1.txt";

    DiagnosticList original = {
        makeDiag("a.cpp", 10, "memory-leak", "leak of p"),
        makeDiag("b.cpp", 20, "div-by-zero", "z is zero"),
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
    ASSERT_TRUE(Baseline::write(path,
        { makeDiag(src, 2, "memory-leak", "leak of p") }));

    // Two lines added above: the finding is now on line 4
    writeSource("blv2_shift.cpp",
        "// yeni aciklama\n"
        "// bir satir daha\n"
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
    ASSERT_TRUE(Baseline::write(path,
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
    ASSERT_TRUE(Baseline::write(path,
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
    ASSERT_TRUE(Baseline::write(path,
        { makeDiag(src, 1, "double-free", "double free of p") }));

    // Trimmed line contents differ (f vs g) — this test must force the
    // same CONTENT: make the two lines exactly identical
    src = writeSource("blv2_dup2.cpp",
        "    delete p;\n"
        "    delete p;\n");
    path = ::testing::TempDir() + "blv2_dup2.txt";
    ASSERT_TRUE(Baseline::write(path,
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
    ASSERT_TRUE(Baseline::write(path, {
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

TEST(BaselineV2Test, FileHeaderWritten) {
    // The v2 file starts with a versioned header — distinguishable if
    // the format changes later; '#' lines are comments when loading
    std::string path = ::testing::TempDir() + "blv2_header.txt";
    ASSERT_TRUE(Baseline::write(path, {}));
    std::ifstream file(path);
    std::string first;
    std::getline(file, first);
    EXPECT_EQ(first, "# zerodefect-baseline v2");
}
