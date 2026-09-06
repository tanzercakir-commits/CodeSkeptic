#include "core/Capabilities.h"
#include "core/Diagnostic.h"

#include <gtest/gtest.h>
#include <llvm/Support/JSON.h>

#include <sstream>
#include <set>
#include <string>

TEST(CapabilitiesTest, RegistryEnforcesTierBehavior) {
    const auto& rules = codeskeptic::ruleCapabilities();
    EXPECT_EQ(rules.size(), 15u);

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
    EXPECT_TRUE(codeskeptic::findingBlocksVerdict("memory-leak"));
    const auto* resource =
        codeskeptic::findRuleCapability("resource-leak");
    ASSERT_NE(resource, nullptr);
    EXPECT_EQ(resource->tier, codeskeptic::CapabilityTier::Supported);
    EXPECT_TRUE(resource->quality_gated);
    EXPECT_TRUE(resource->blocks_verdict);
    EXPECT_TRUE(codeskeptic::findingBlocksVerdict("resource-leak"));
    EXPECT_FALSE(codeskeptic::findingBlocksVerdict("contract-syntax"));
    EXPECT_FALSE(codeskeptic::findingBlocksVerdict("contract-unsupported"));
    // Extensions and unknown future diagnostics fail closed until they are
    // classified deliberately.
    EXPECT_TRUE(codeskeptic::findingBlocksVerdict("unknown-rule"));
}

TEST(CapabilitiesTest, ScalarInitializationIsSeparateAndReportOnly) {
    const auto* scalar = codeskeptic::findRuleCapability("uninit-scalar");
    ASSERT_NE(scalar, nullptr);
    EXPECT_EQ(scalar->tier, codeskeptic::CapabilityTier::Experimental);
    EXPECT_TRUE(scalar->default_enabled);
    EXPECT_FALSE(scalar->quality_gated);
    EXPECT_FALSE(scalar->blocks_verdict);
    EXPECT_FALSE(codeskeptic::findingBlocksVerdict("uninit-scalar"));
    EXPECT_NE(codeskeptic::findRuleCapability("uninit-ptr"), nullptr);
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

TEST(CapabilitiesTest, EveryFamilyPublishesDescriptionAndPotentialCwes) {
    std::ostringstream out;
    codeskeptic::writeCapabilities(out, true);
    auto parsed = llvm::json::parse(out.str());
    ASSERT_TRUE(static_cast<bool>(parsed));
    const auto* root = parsed->getAsObject();
    ASSERT_NE(root, nullptr);
    const auto* rules = root->getArray("rule_capabilities");
    ASSERT_NE(rules, nullptr);
    ASSERT_EQ(rules->size(), 15u);
    for (const auto& entry : *rules) {
        const auto* rule = entry.getAsObject();
        ASSERT_NE(rule, nullptr);
        EXPECT_TRUE(rule->getString("description").has_value());
        EXPECT_TRUE(rule->getString("help_uri").has_value());
        EXPECT_NE(rule->getArray("potential_cwes"), nullptr);
    }
}

TEST(CapabilitiesTest, ProducerInventoryContainsEverySiblingFamily) {
    using codeskeptic::producerFindingFamilies;
    EXPECT_EQ(producerFindingFamilies("memory-leak"),
              (std::vector<std::string>{"memory-leak", "double-free", "use-after-free", "resource-leak"}));
    for (const char* producer : {"div-by-zero", "null-deref", "policy"})
        EXPECT_EQ(producerFindingFamilies(producer),
                  (std::vector<std::string>{producer, "contract"}));
    for (const char* producer : {"uninit-ptr", "uninit-scalar", "resource-leak",
         "int-overflow", "sign-conversion", "alloc-size-overflow", "bounds", "assumption", "contract"})
        EXPECT_EQ(producerFindingFamilies(producer), std::vector<std::string>{producer});
    EXPECT_EQ(producerFindingFamilies("contract-syntax"), std::vector<std::string>{"contract"});
    EXPECT_EQ(producerFindingFamilies("future-extension"), std::vector<std::string>{"future-extension"});
}

TEST(CapabilitiesTest, TypedFindingCwesAreNotFamilyWideOrMessageDerived) {
    using namespace codeskeptic;
    struct Case { const char* rule; FindingKind kind; std::vector<int> ids; };
    const Case cases[] = {
        {"bounds", FindingKind::BoundsRead, {125}},
        {"bounds", FindingKind::BoundsWrite, {787}},
        {"bounds", FindingKind::BoundsReadWrite, {125,787}},
        {"bounds", FindingKind::BoundsAddress, {823}},
        {"bounds", FindingKind::BoundsUnboundedCopy, {120}},
        {"int-overflow", FindingKind::ArithmeticUpper, {190}},
        {"int-overflow", FindingKind::ArithmeticLower, {191}},
        {"int-overflow", FindingKind::ArithmeticBoth, {190,191}},
        {"int-overflow", FindingKind::NarrowingUpper, {681}},
        {"int-overflow", FindingKind::NarrowingLower, {681}},
        {"int-overflow", FindingKind::NarrowingBoth, {681}},
        {"sign-conversion", FindingKind::SignedToUnsigned, {195}},
        {"sign-conversion", FindingKind::LossyConversion, {681}},
        {"double-free", FindingKind::MemoryDoubleRelease, {415}},
        {"double-free", FindingKind::ResourceDoubleRelease, {675}},
        {"use-after-free", FindingKind::MemoryUseAfterRelease, {416}},
        {"use-after-free", FindingKind::ResourceUseAfterRelease, {672}},
        {"memory-leak", FindingKind::MemoryLeak, {401}},
        {"memory-leak", FindingKind::HandleLeak, {775}},
        {"memory-leak", FindingKind::GenericResourceLeak, {772}},
        {"resource-leak", FindingKind::MemoryLeak, {401}},
        {"resource-leak", FindingKind::HandleLeak, {775}},
        {"resource-leak", FindingKind::GenericResourceLeak, {772}},
        {"memory-leak", FindingKind::Unspecified, {}},
        {"resource-leak", FindingKind::Unspecified, {}},
        {"memory-leak", FindingKind::ResourceUseAfterRelease, {}},
        {"bounds", FindingKind::Unspecified, {}},
        {"bounds", FindingKind::ArithmeticUpper, {}},
        {"int-overflow", FindingKind::BoundsWrite, {}},
        {"null-deref", FindingKind::BoundsRead, {}},
        {"unknown-rule", FindingKind::BoundsRead, {}},
        {"contract-syntax", FindingKind::Unspecified, {}},
        {"policy", FindingKind::Unspecified, {}},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.rule);
        Diagnostic finding{Severity::Warning, "a.cpp", 1, 1, c.rule,
                           "CWE-787 write overflow underflow arbitrary text"};
        finding.kind = c.kind;
        EXPECT_EQ(findingCweIds(finding), c.ids);
        std::ostringstream out;
        writeFindingMetadataJson(out, finding);
        auto parsed = llvm::json::parse(out.str());
        ASSERT_TRUE(static_cast<bool>(parsed));
        const auto* row = parsed->getAsObject();
        ASSERT_NE(row, nullptr);
        const auto* cwes = row->getArray("cwes");
        ASSERT_NE(cwes, nullptr);
        EXPECT_EQ(cwes->size(), c.ids.size());
        if (!c.ids.empty()) EXPECT_EQ(row->getString("cwe_mapping"), "mapped");
        const auto original = finding;
        finding.kind = FindingKind::Unspecified;
        EXPECT_EQ(finding, original);
        EXPECT_FALSE(finding < original);
        EXPECT_FALSE(original < finding);
    }
}

TEST(CapabilitiesTest, RegistryCwesHaveUniqueExplanationsAndStableLinks) {
    using namespace codeskeptic;
    for (const auto& rule : ruleCapabilities()) {
        EXPECT_FALSE(rule.description.empty()) << rule.id;
        EXPECT_FALSE(rule.help_uri.empty()) << rule.id;
        std::set<int> unique;
        for (const int id : rule.cwe_ids) {
            EXPECT_TRUE(unique.insert(id).second) << rule.id;
            const auto* cwe = findCweMetadata(id);
            ASSERT_NE(cwe, nullptr) << id;
            EXPECT_FALSE(cwe->description.empty());
        }
    }
    EXPECT_EQ(findCweMetadata(0), nullptr);
    EXPECT_EQ(findCweMetadata(-1), nullptr);
    EXPECT_EQ(findCweMetadata(999999), nullptr);
}

TEST(CapabilitiesTest, MetadataUnionIsCanonicalIdempotentAndKeepsUnknownEvidence) {
    using namespace codeskeptic;
    Diagnostic read{Severity::Error, "a.cpp", 2, 3, "bounds", "same"};
    read.kind = FindingKind::BoundsRead;
    read.fingerprint = "fixed-source-fingerprint";
    auto write = read;
    write.kind = FindingKind::BoundsWrite;
    auto forward = read;
    auto reverse = write;
    mergeFindingMetadata(forward, write);
    mergeFindingMetadata(reverse, read);
    mergeFindingMetadata(forward, forward);
    EXPECT_EQ(findingCweIds(forward), (std::vector<int>{125,787}));
    EXPECT_EQ(forward.fingerprint, read.fingerprint);
    EXPECT_EQ(forward, read);
    std::ostringstream one, two;
    writeFindingMetadataJson(one, forward);
    writeFindingMetadataJson(two, reverse);
    EXPECT_EQ(one.str(), two.str());
    EXPECT_NE(one.str().find("\"kind\": \"multiple\""), std::string::npos);
    auto unrelated = read;
    unrelated.rule_id = "null-deref";
    mergeFindingMetadata(forward, unrelated);
    std::ostringstream after;
    writeFindingMetadataJson(after, forward);
    EXPECT_EQ(one.str(), after.str());
    auto unknown = read;
    unknown.kind = FindingKind::Unspecified;
    mergeFindingMetadata(forward, unknown);
    EXPECT_EQ(findingCweIds(forward), (std::vector<int>{125,787}));
    std::ostringstream partial;
    writeFindingMetadataJson(partial, forward);
    EXPECT_NE(partial.str().find("\"cwe_mapping\": \"partial\""), std::string::npos);
}
