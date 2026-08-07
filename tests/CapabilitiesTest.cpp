#include "core/Capabilities.h"

#include <gtest/gtest.h>

#include <sstream>
#include <string>

TEST(CapabilitiesTest, JsonSurfacePublishesVersionVerdictAndRules) {
    std::ostringstream out;
    codeskeptic::writeCapabilities(out, true);
    const std::string value = out.str();

    EXPECT_NE(value.find("\"schema_version\": 1"), std::string::npos);
    EXPECT_NE(value.find("\"version\":"), std::string::npos);
    EXPECT_NE(value.find("\"2\": \"unavailable\""), std::string::npos);
    EXPECT_NE(value.find("\"alloc-size-overflow\""), std::string::npos);
    EXPECT_NE(value.find("\"mcp\""), std::string::npos);
}

TEST(CapabilitiesTest, TextSurfaceIsHumanReadable) {
    std::ostringstream out;
    codeskeptic::writeCapabilities(out, false);
    EXPECT_NE(out.str().find("verdict-exit-codes"), std::string::npos);
    EXPECT_NE(out.str().find("rules:"), std::string::npos);
}
