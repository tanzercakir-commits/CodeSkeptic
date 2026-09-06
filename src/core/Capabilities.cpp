#include "core/Capabilities.h"
#include "core/Diagnostic.h"

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

constexpr std::string_view kRuleHelpUri =
    "https://github.com/tanzercakir-commits/CodeSkeptic/blob/main/docs/capabilities.md#finding-rules";

const char* findingKindName(FindingKind kind) {
    switch (kind) {
    case FindingKind::Unspecified: return "unspecified";
    case FindingKind::ArithmeticUpper: return "arithmetic-upper";
    case FindingKind::ArithmeticLower: return "arithmetic-lower";
    case FindingKind::ArithmeticBoth: return "arithmetic-both";
    case FindingKind::NarrowingUpper: return "narrowing-upper";
    case FindingKind::NarrowingLower: return "narrowing-lower";
    case FindingKind::NarrowingBoth: return "narrowing-both";
    case FindingKind::BoundsRead: return "bounds-read";
    case FindingKind::BoundsWrite: return "bounds-write";
    case FindingKind::BoundsReadWrite: return "bounds-read-write";
    case FindingKind::BoundsAddress: return "bounds-address";
    case FindingKind::BoundsUnboundedCopy: return "bounds-unbounded-copy";
    case FindingKind::SignedToUnsigned: return "signed-to-unsigned";
    case FindingKind::LossyConversion: return "lossy-conversion";
    case FindingKind::MemoryDoubleRelease: return "memory-double-release";
    case FindingKind::ResourceDoubleRelease: return "resource-double-release";
    case FindingKind::MemoryUseAfterRelease: return "memory-use-after-release";
    case FindingKind::ResourceUseAfterRelease: return "resource-use-after-release";
    }
    return "unclassified";
}

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
#define CODESKEPTIC_CWE_IDS(...) std::vector<int>{__VA_ARGS__}
#define CODESKEPTIC_RULE_CAPABILITY(id, tier, default_enabled, quality_gated,  \
                                    blocks_verdict, evidence, description, cwes) \
    {id,                                                                       \
     CapabilityTier::tier,                                                     \
     default_enabled,                                                          \
     quality_gated,                                                            \
     blocks_verdict,                                                           \
     evidence, description, kRuleHelpUri, CODESKEPTIC_CWE_IDS cwes},
#include "core/RuleCapabilities.def"
#undef CODESKEPTIC_RULE_CAPABILITY
#undef CODESKEPTIC_CWE_IDS
    };
    return rules;
}

const CweMetadata* findCweMetadata(int id) {
    static const CweMetadata entries[] = {
#define CODESKEPTIC_CWE(number, description) {number, description},
#include "core/RuleCapabilities.def"
#undef CODESKEPTIC_CWE
    };
    for (const auto& entry : entries)
        if (entry.id == id) return &entry;
    return nullptr;
}

namespace {

std::vector<FindingKind> findingKinds(const Diagnostic& diagnostic) {
    auto kinds = diagnostic.additional_kinds;
    kinds.push_back(diagnostic.kind);
    std::sort(kinds.begin(), kinds.end());
    kinds.erase(std::unique(kinds.begin(), kinds.end()), kinds.end());
    return kinds;
}

std::vector<int> kindCweIds(std::string_view ruleId, FindingKind kind) {
    const auto* rule = findRuleCapability(ruleId);
    if (!rule) return {};
    if (kind == FindingKind::Unspecified)
        return rule->cwe_ids.size() == 1 ? rule->cwe_ids : std::vector<int>{};
    std::vector<int> ids;
    if (rule->id == "bounds") {
        switch (kind) {
        case FindingKind::BoundsRead: ids = {125}; break;
        case FindingKind::BoundsWrite: ids = {787}; break;
        case FindingKind::BoundsReadWrite: ids = {125,787}; break;
        case FindingKind::BoundsAddress: ids = {823}; break;
        case FindingKind::BoundsUnboundedCopy: ids = {120}; break;
        default: break;
        }
    } else if (rule->id == "int-overflow") {
        switch (kind) {
        case FindingKind::ArithmeticUpper: ids = {190}; break;
        case FindingKind::ArithmeticLower: ids = {191}; break;
        case FindingKind::ArithmeticBoth: ids = {190,191}; break;
        case FindingKind::NarrowingUpper:
        case FindingKind::NarrowingLower:
        case FindingKind::NarrowingBoth: ids = {681}; break;
        default: break;
        }
    } else if (rule->id == "sign-conversion") {
        if (kind == FindingKind::SignedToUnsigned) ids = {195};
        else if (kind == FindingKind::LossyConversion) ids = {681};
    } else if (rule->id == "double-free") {
        if (kind == FindingKind::MemoryDoubleRelease) ids = {415};
        else if (kind == FindingKind::ResourceDoubleRelease) ids = {675};
    } else if (rule->id == "use-after-free") {
        if (kind == FindingKind::MemoryUseAfterRelease) ids = {416};
        else if (kind == FindingKind::ResourceUseAfterRelease) ids = {672};
    }
    // A mismatched producer subtype never imports another family's CWE.
    for (const int id : ids)
        if (!findCweMetadata(id) ||
            std::find(rule->cwe_ids.begin(), rule->cwe_ids.end(), id) == rule->cwe_ids.end())
            return {};
    return ids;
}

} // namespace

std::vector<int> findingCweIds(const Diagnostic& diagnostic) {
    std::vector<int> ids;
    for (const auto kind : findingKinds(diagnostic)) {
        const auto selected = kindCweIds(diagnostic.rule_id, kind);
        ids.insert(ids.end(), selected.begin(), selected.end());
    }
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return ids;
}

void mergeFindingMetadata(Diagnostic& target, const Diagnostic& source) {
    // Only evidence belonging to an already-equivalent finding may combine.
    if (!(target == source)) return;
    auto kinds = findingKinds(target);
    const auto others = findingKinds(source);
    kinds.insert(kinds.end(), others.begin(), others.end());
    std::sort(kinds.begin(), kinds.end());
    kinds.erase(std::unique(kinds.begin(), kinds.end()), kinds.end());
    target.kind = kinds.front();
    target.additional_kinds.assign(kinds.begin() + 1, kinds.end());
}

void writeCweReferencesJson(std::ostream& out, const std::vector<int>& ids) {
    out << "[";
    bool first = true;
    for (const int id : ids) {
        const auto* cwe = findCweMetadata(id);
        if (!cwe) continue;
        if (!first) out << ", ";
        first = false;
        out << "{\"id\": " << id << ", \"name\": \"CWE-" << id
            << "\", \"description\": \"" << escapeJson(cwe->description)
            << "\", \"help_uri\": \"https://cwe.mitre.org/data/definitions/"
            << id << ".html\"}";
    }
    out << "]";
}

void writeFindingMetadataJson(std::ostream& out, const Diagnostic& diagnostic) {
    const auto* rule = findRuleCapability(diagnostic.rule_id);
    const auto ids = findingCweIds(diagnostic);
    const auto kinds = findingKinds(diagnostic);
    const bool incomplete = std::any_of(kinds.begin(), kinds.end(), [&](FindingKind kind) {
        return kindCweIds(diagnostic.rule_id, kind).empty();
    });
    const char* mapping = !ids.empty() ? (incomplete ? "partial" : "mapped") :
        rule && rule->cwe_ids.empty() && kinds.size() == 1 && kinds.front() == FindingKind::Unspecified
        ? "not-applicable" : "unclassified";
    out << "{\"kind\": \"" << (kinds.size() == 1 ? findingKindName(kinds.front()) : "multiple")
        << "\", \"kinds\": [";
    for (size_t index = 0; index < kinds.size(); ++index) {
        if (index) out << ", ";
        out << "\"" << findingKindName(kinds[index]) << "\"";
    }
    out << "], \"description\": \""
        << escapeJson(rule ? rule->description : "Unclassified rule")
        << "\", \"help_uri\": \"" << escapeJson(rule ? rule->help_uri : "")
        << "\", \"cwe_mapping\": \"" << mapping << "\", \"cwes\": ";
    writeCweReferencesJson(out, ids);
    out << "}";
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

std::vector<std::string> producerFindingFamilies(const std::string& producer_id) {
    if (producer_id == "memory-leak")
        return {"memory-leak", "double-free", "use-after-free", "resource-leak"};
    if (producer_id == "div-by-zero" || producer_id == "null-deref" ||
        producer_id == "policy")
        return {producer_id, "contract"};
    if (const auto* family = findRuleCapability(producer_id))
        return {std::string(family->id)};
    // Extension producers are not silently discarded by a public allowlist.
    return {producer_id};
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
        for (const auto& rule : ruleCapabilities()) {
            out << rule.id << ": " << rule.description << "; potential CWEs:";
            for (const int id : rule.cwe_ids) out << " CWE-" << id;
            if (rule.cwe_ids.empty()) out << " not applicable";
            out << "; " << rule.help_uri << "\n";
        }
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
            << escapeJson(rule.evidence) << "\", \"description\": \""
            << escapeJson(rule.description) << "\", \"help_uri\": \""
            << escapeJson(rule.help_uri) << "\", \"potential_cwes\": ";
        writeCweReferencesJson(out, rule.cwe_ids);
        out << "}";
    }
    out << "\n  ]\n"
        << "}\n";
}

} // namespace codeskeptic
