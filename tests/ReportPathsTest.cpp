#include "config/Config.h"

#include <gtest/gtest.h>

using namespace codeskeptic;

// --report-paths parsing (the filter itself runs inside
// StaticAnalyzer's reporting pipeline on canonical paths; the
// smoke-level behavior is covered by CI's real-binary smoke run).

TEST(ReportPathsTest, CommaListSplitsAndTrims) {
    Config config;
    config.addReportPaths(" src/mylib , third_party/keepme ");
    ASSERT_EQ(config.reportPaths().size(), 2u);
    EXPECT_EQ(config.reportPaths()[0], "src/mylib");
    EXPECT_EQ(config.reportPaths()[1], "third_party/keepme");
}

TEST(ReportPathsTest, InteriorSpacesPreserved) {
    // Unlike identifier lists, paths may contain interior spaces.
    Config config;
    config.addReportPaths("/home/user/My Project/src");
    ASSERT_EQ(config.reportPaths().size(), 1u);
    EXPECT_EQ(config.reportPaths()[0], "/home/user/My Project/src");
}

TEST(ReportPathsTest, EmptyTokensDropped) {
    Config config;
    config.addReportPaths(",a,,b,");
    ASSERT_EQ(config.reportPaths().size(), 2u);
}

TEST(ReportPathsTest, DefaultIsEmpty_NoFiltering) {
    Config config;
    EXPECT_TRUE(config.reportPaths().empty());
}

TEST(ReportPathsTest, CliFlagParsed) {
    Config config;
    const char* argv[] = {"codeskeptic", "--report-paths", "src,include",
                          "dummy.cpp"};
    ASSERT_TRUE(config.parseArgs(4, const_cast<char**>(argv)));
    ASSERT_EQ(config.reportPaths().size(), 2u);
    EXPECT_EQ(config.reportPaths()[0], "src");
    EXPECT_EQ(config.reportPaths()[1], "include");
}
