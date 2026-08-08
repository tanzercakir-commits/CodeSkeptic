#include "core/Capabilities.h"

#include <gtest/gtest.h>
#include <llvm/Support/JSON.h>

#include <sstream>
#include <string>

TEST(CapabilitiesTest, RegistryEnforcesTierBehavior) {
    const auto& rules = codeskeptic::ruleCapabilities();
    EXPECT_EQ(rules.size(), 14u);

    for (const auto& rule : rules) {
        if (rule.tier == codeskeptic::CapabilityTier::Supported) {
            EXPECT_TRUE(rule.default_enabled) << rule.id;
            EXPECT_TRUE(rule.quality_gated) << rule.id;
            EXPECT_TRUE(rule.blocks_verdict) << rule.id;
        } else {
            EXPECT_EQ(rule.tier, codeskeptic::CapabilityTier::Experimental)
                << rule.id;
            EXPECT_FALSE(rule.blocks_verdict) << rule.id;
        }
    }

    EXPECT_TRUE(codeskeptic::findingBlocksVerdict("use-after-free"));
    EXPECT_FALSE(codeskeptic::findingBlocksVerdict("memory-leak"));
    EXPECT_FALSE(codeskeptic::findingBlocksVerdict("contract-syntax"));
    EXPECT_FALSE(codeskeptic::findingBlocksVerdict("contract-unsupported"));
    // Extensions and unknown future diagnostics fail closed until they are
    // classified deliberately.
    EXPECT_TRUE(codeskeptic::findingBlocksVerdict("unknown-rule"));
}

TEST(CapabilitiesTest, JsonSurfacePublishesTieredScopeContract) {
    std::ostringstream out;
    codeskeptic::writeCapabilities(out, true);
    const std::string value = out.str();

    auto parsed = llvm::json::parse(value);
    EXPECT_TRUE(static_cast<bool>(parsed));
    EXPECT_NE(value.find("\"schema_version\": 2"), std::string::npos);
    EXPECT_NE(value.find("\"version\":"), std::string::npos);
    // The v1 name arrays stay additive/backward-compatible in schema v2.
    EXPECT_NE(value.find("\"languages\": [\"c\", \"cpp\"]"),
              std::string::npos);
    EXPECT_NE(value.find("\"rules\": [\"uninit-ptr\""),
              std::string::npos);
    EXPECT_NE(value.find("\"2\": \"unavailable\""), std::string::npos);
    EXPECT_NE(value.find("\"rule_capabilities\": ["),
              std::string::npos);
    EXPECT_NE(value.find("\"alloc-size-overflow\""), std::string::npos);
    EXPECT_NE(value.find("\"mcp\""), std::string::npos);
    EXPECT_NE(value.find("\"supported\""), std::string::npos);
    EXPECT_NE(value.find("\"experimental\""), std::string::npos);
    EXPECT_NE(value.find("\"out-of-scope\""), std::string::npos);
    EXPECT_NE(value.find("\"injection-taint\""), std::string::npos);
    EXPECT_NE(value.find("\"race-detection\""), std::string::npos);
    EXPECT_NE(value.find("\"automatic-fixes\""), std::string::npos);
    EXPECT_NE(value.find("\"ide\""), std::string::npos);
    EXPECT_NE(value.find("\"cloud-dashboard\""), std::string::npos);
    EXPECT_NE(value.find("\"cwe_count\": false"), std::string::npos);
}

TEST(CapabilitiesTest, TextSurfaceIsHumanReadable) {
    std::ostringstream out;
    codeskeptic::writeCapabilities(out, false);
    EXPECT_NE(out.str().find("verdict-exit-codes"), std::string::npos);
    EXPECT_NE(out.str().find("supported rules:"), std::string::npos);
    EXPECT_NE(out.str().find("experimental rules:"), std::string::npos);
    EXPECT_NE(out.str().find("out-of-scope:"), std::string::npos);
}
