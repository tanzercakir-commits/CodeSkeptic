#include "analyzer/SuppressionFilter.h"

#include <fstream>
#include <gtest/gtest.h>

using namespace zerodefect;

namespace {

// Gecici kaynak dosyasi olusturur, path'ini dondurur
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

// --- markerSuppressesRule birim testleri ---

TEST(SuppressionMarkerTest, BareMarkerSuppressesAllRules) {
    EXPECT_TRUE(markerSuppressesRule(
        "int x = 1/z; // zerodefect-disable-line",
        "zerodefect-disable-line", "div-by-zero"));
    EXPECT_TRUE(markerSuppressesRule(
        "int x = 1/z; // zerodefect-disable-line",
        "zerodefect-disable-line", "memory-leak"));
}

TEST(SuppressionMarkerTest, RuleListLimitsSuppression) {
    const std::string line =
        "int x = 1/z; // zerodefect-disable-line div-by-zero, uninit-ptr";
    EXPECT_TRUE(markerSuppressesRule(line, "zerodefect-disable-line",
                                     "div-by-zero"));
    EXPECT_TRUE(markerSuppressesRule(line, "zerodefect-disable-line",
                                     "uninit-ptr"));
    EXPECT_FALSE(markerSuppressesRule(line, "zerodefect-disable-line",
                                      "memory-leak"));
}

TEST(SuppressionMarkerTest, NextLineVariantDoesNotMatchLineMarker) {
    // disable-next-line satiri, disable-line markeri olarak sayilmamali
    EXPECT_FALSE(markerSuppressesRule(
        "// zerodefect-disable-next-line",
        "zerodefect-disable-line", "div-by-zero"));
}

TEST(SuppressionMarkerTest, TrailingCommentAfterRuleList) {
    EXPECT_TRUE(markerSuppressesRule(
        "// zerodefect-disable-line div-by-zero (kasitli: demo)",
        "zerodefect-disable-line", "div-by-zero"));
    EXPECT_FALSE(markerSuppressesRule(
        "// zerodefect-disable-line div-by-zero (kasitli: demo)",
        "zerodefect-disable-line", "memory-leak"));
}

TEST(SuppressionMarkerTest, NoMarker_NoSuppression) {
    EXPECT_FALSE(markerSuppressesRule("int x = 1/z; // normal yorum",
                                      "zerodefect-disable-line",
                                      "div-by-zero"));
}

// --- SuppressionFilter dosya testleri ---

TEST(SuppressionFilterTest, DisableLineSameLine) {
    auto path = writeTempSource("supp1.cpp",
        "int a;\n"
        "int x = 1/z; // zerodefect-disable-line\n"
        "int y = 1/w;\n");

    SuppressionFilter filter;
    DiagnosticList diags = {
        makeDiag(path, 2, "div-by-zero"),  // bastirilir
        makeDiag(path, 3, "div-by-zero"),  // kalir
    };
    size_t removed = filter.filter(diags);

    EXPECT_EQ(removed, 1u);
    ASSERT_EQ(diags.size(), 1u);
    EXPECT_EQ(diags[0].line, 3u);
}

TEST(SuppressionFilterTest, DisableNextLine) {
    auto path = writeTempSource("supp2.cpp",
        "// zerodefect-disable-next-line div-by-zero\n"
        "int x = 1/z;\n"
        "int y = 1/w;\n");

    SuppressionFilter filter;
    DiagnosticList diags = {
        makeDiag(path, 2, "div-by-zero"),   // bastirilir
        makeDiag(path, 2, "memory-leak"),   // kural listede yok -> kalir
        makeDiag(path, 3, "div-by-zero"),   // kalir
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
