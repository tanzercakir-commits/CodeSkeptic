#include "core/Capabilities.h"

#include <algorithm>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#ifndef CODESKEPTIC_VERSION
#define CODESKEPTIC_VERSION "0.0.0-dev"
#endif

namespace codeskeptic {

namespace {

using TieredCapability = std::pair<std::string_view, CapabilityTier>;

const std::vector<TieredCapability> kLanguages = {
    {"c", CapabilityTier::Supported},
    {"cpp", CapabilityTier::Supported},
};

const std::vector<TieredCapability> kFrontends = {
    {"cli", CapabilityTier::Supported},
    {"mcp", CapabilityTier::Supported},
};

const std::vector<TieredCapability> kOutputs = {
    {"console", CapabilityTier::Supported},
    {"json", CapabilityTier::Supported},
    {"sarif-2.1.0", CapabilityTier::Supported},
    {"html", CapabilityTier::Supported},
};

const std::vector<TieredCapability> kModes = {
    {"baseline", CapabilityTier::Supported},
    {"function-scope", CapabilityTier::Supported},
    {"line-scope", CapabilityTier::Supported},
    {"whole-program", CapabilityTier::Experimental},
    {"incremental-summaries", CapabilityTier::Experimental},
};

const std::vector<TieredCapability> kOutOfScope = {
    {"injection-taint", CapabilityTier::OutOfScope},
    {"race-detection", CapabilityTier::OutOfScope},
    {"automatic-fixes", CapabilityTier::OutOfScope},
    {"ide", CapabilityTier::OutOfScope},
    {"cloud-dashboard", CapabilityTier::OutOfScope},
};

std::string escapeJson(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char c : value) {
        switch (c) {
        case '"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped += c;
            break;
        }
    }
    return escaped;
}

void writeTieredArray(std::ostream& out,
                      const std::vector<TieredCapability>& capabilities,
                      const char* indent) {
    out << "[";
    for (std::size_t i = 0; i < capabilities.size(); ++i) {
        if (i > 0)
            out << ",";
        out << "\n"
            << indent << "{\"id\": \"" << escapeJson(capabilities[i].first)
            << "\", \"tier\": \"" << capabilityTierName(capabilities[i].second)
            << "\"}";
    }
    if (!capabilities.empty())
        out << "\n    ";
    out << "]";
}

void writeTextList(std::ostream& out, std::string_view label,
                   CapabilityTier tier) {
    out << label << ": ";
    bool first = true;
    for (const auto& rule : ruleCapabilities()) {
        if (rule.tier != tier)
            continue;
        if (!first)
            out << ", ";
        out << rule.id;
        first = false;
    }
    out << "\n";
}

} // namespace

const std::vector<RuleCapability>& ruleCapabilities() {
    // A rule becomes supported only when its default behavior is guarded by
    // a measured precision floor. Low-sample and sub-85% families remain
    // visible for measurement but cannot turn a complete verdict red.
    static const std::vector<RuleCapability> rules = {
#define CODESKEPTIC_RULE_CAPABILITY(id, tier, default_enabled, quality_gated,  \
                                    blocks_verdict, evidence)                  \
    {id,                                                                       \
     CapabilityTier::tier,                                                     \
     default_enabled,                                                          \
     quality_gated,                                                            \
     blocks_verdict,                                                           \
     evidence},
#include "core/RuleCapabilities.def"
#undef CODESKEPTIC_RULE_CAPABILITY
    };
    return rules;
}

const RuleCapability* findRuleCapability(std::string_view finding_id) {
    // Parser/engine-limit diagnostics belong to the contract capability
    // rather than separately user-selectable detection rules.
    if (finding_id == "contract-syntax" || finding_id == "contract-unsupported")
        finding_id = "contract";
    const auto& rules = ruleCapabilities();
    const auto it = std::find_if(rules.begin(), rules.end(),
                                 [finding_id](const RuleCapability& rule) {
                                     return rule.id == finding_id;
                                 });
    return it == rules.end() ? nullptr : &*it;
}

const char* capabilityTierName(CapabilityTier tier) {
    switch (tier) {
    case CapabilityTier::Supported:
        return "supported";
    case CapabilityTier::Experimental:
        return "experimental";
    case CapabilityTier::OutOfScope:
        return "out-of-scope";
    }
    return "out-of-scope";
}

bool findingBlocksVerdict(std::string_view finding_id) {
    const RuleCapability* capability = findRuleCapability(finding_id);
    return capability ? capability->blocks_verdict : true;
}

void writeCapabilities(std::ostream& out, bool json) {
    if (!json) {
        out << "CodeSkeptic " << CODESKEPTIC_VERSION << "\n"
            << "languages: C, C++\n"
            << "outputs: console, json, sarif-2.1.0, html\n"
            << "frontends: cli, mcp\n"
            << "verdict-exit-codes: 0=no blocking findings, "
               "1=supported findings, 2=unavailable\n";
        writeTextList(out, "supported rules", CapabilityTier::Supported);
        writeTextList(out, "experimental rules", CapabilityTier::Experimental);
        out << "experimental modes: whole-program, incremental-summaries\n"
            << "out-of-scope: injection-taint, race-detection, "
               "automatic-fixes, ide, cloud-dashboard\n"
            << "success-metric: CWE count is not a success metric\n";
        return;
    }

    out << "{\n"
        << "  \"schema_version\": 2,\n"
        << "  \"product\": \"CodeSkeptic\",\n"
        << "  \"version\": \"" << CODESKEPTIC_VERSION
        << "\",\n"
        // Schema v2 is additive: retain the v1 arrays so wrappers that only
        // enumerate names keep working while adopting tier metadata.
        << "  \"languages\": [\"c\", \"cpp\"],\n"
        << "  \"frontends\": [\"cli\", \"mcp\"],\n"
        << "  \"outputs\": [\"console\", \"json\", \"sarif-2.1.0\", "
           "\"html\"],\n"
        << "  \"modes\": [\"whole-program\", \"incremental-summaries\", "
           "\"baseline\", \"function-scope\", \"line-scope\"],\n"
        << "  \"rules\": [";
    const auto& rules = ruleCapabilities();
    for (std::size_t i = 0; i < rules.size(); ++i) {
        if (i > 0)
            out << ", ";
        out << "\"" << escapeJson(rules[i].id) << "\"";
    }
    out << "],\n"
        << "  \"tier_definitions\": {\n"
        << "    \"supported\": \"default-enabled and quality-gated; findings "
           "block\",\n"
        << "    \"experimental\": \"measured and report-only; findings do not "
           "block\",\n"
        << "    \"out-of-scope\": \"not implemented in the v1 product scope\"\n"
        << "  },\n"
        << "  \"success_metrics\": {\"cwe_count\": false},\n"
        << "  \"capabilities\": {\n"
        << "    \"languages\": ";
    writeTieredArray(out, kLanguages, "      ");
    out << ",\n    \"frontends\": ";
    writeTieredArray(out, kFrontends, "      ");
    out << ",\n    \"outputs\": ";
    writeTieredArray(out, kOutputs, "      ");
    out << ",\n    \"modes\": ";
    writeTieredArray(out, kModes, "      ");
    out << ",\n    \"out_of_scope\": ";
    writeTieredArray(out, kOutOfScope, "      ");
    out << "\n  },\n"
        << "  \"verdict\": {\"0\": \"no-blocking-findings\", "
           "\"1\": \"supported-findings\", \"2\": \"unavailable\"},\n"
        << "  \"rule_capabilities\": [";
    for (std::size_t i = 0; i < rules.size(); ++i) {
        const auto& rule = rules[i];
        if (i > 0)
            out << ",";
        out << "\n    {\"id\": \"" << escapeJson(rule.id) << "\", \"tier\": \""
            << capabilityTierName(rule.tier) << "\", \"default_enabled\": "
            << (rule.default_enabled ? "true" : "false")
            << ", \"quality_gated\": "
            << (rule.quality_gated ? "true" : "false")
            << ", \"blocks_verdict\": "
            << (rule.blocks_verdict ? "true" : "false") << ", \"evidence\": \""
            << escapeJson(rule.evidence) << "\"}";
    }
    out << "\n  ]\n"
        << "}\n";
}

} // namespace codeskeptic
