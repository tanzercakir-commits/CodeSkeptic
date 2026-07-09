#include "analyzer/Baseline.h"

#include <gtest/gtest.h>

using namespace zerodefect;

namespace {

Diagnostic makeDiag(const std::string& file, unsigned line,
                    const std::string& rule, const std::string& message) {
    return {Severity::Warning, file, line, 1, rule, message};
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

    // Ayni bulgular + bir yeni bulgu
    DiagnosticList current = original;
    current.push_back(makeDiag("c.cpp", 5, "uninit-ptr", "new finding"));

    size_t filtered = baseline.filter(current);
    EXPECT_EQ(filtered, 2u);
    ASSERT_EQ(current.size(), 1u);
    EXPECT_EQ(current[0].rule_id, "uninit-ptr");
}

TEST(BaselineTest, KeyIncludesLineAndMessage) {
    auto d1 = makeDiag("a.cpp", 10, "memory-leak", "leak of p");
    auto d2 = makeDiag("a.cpp", 11, "memory-leak", "leak of p");
    auto d3 = makeDiag("a.cpp", 10, "memory-leak", "leak of q");

    EXPECT_NE(Baseline::key(d1), Baseline::key(d2));
    EXPECT_NE(Baseline::key(d1), Baseline::key(d3));
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
