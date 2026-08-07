#include "reporter/JsonReporter.h"

#include <fstream>
#include <gtest/gtest.h>

using namespace codeskeptic;

namespace {

std::string readJsonReport(const AnalysisResult& result) {
    const std::string path = ::testing::TempDir() + "verdict_report.json";
    JsonReporter reporter(path);
    EXPECT_TRUE(reporter.report({}, &result));

    std::ifstream file(path);
    return {std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()};
}

} // anonymous namespace

TEST(JsonReporterTest, PublishesCompleteVerdictContract) {
    AnalysisResult result;
    result.attempted_tus = 2;
    result.analyzed_tus = 1;
    result.broken_tus = 1;
    result.summary_stale = true;

    const std::string json = readJsonReport(result);

    EXPECT_NE(json.find("\"status\": \"incomplete\""), std::string::npos);
    EXPECT_NE(json.find("\"complete\": false"), std::string::npos);
    EXPECT_NE(json.find("\"exit_code\": 2"), std::string::npos);
    EXPECT_NE(json.find("\"summary_stale\": true"), std::string::npos);
    EXPECT_NE(json.find("\"attempted_tus\": 2"), std::string::npos);
    EXPECT_NE(json.find("\"analyzed_tus\": 1"), std::string::npos);
    EXPECT_NE(json.find("\"broken_tus\": 1"), std::string::npos);
}
