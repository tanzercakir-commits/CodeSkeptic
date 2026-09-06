#ifndef CODESKEPTIC_CAPABILITIES_H
#define CODESKEPTIC_CAPABILITIES_H

#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

namespace codeskeptic {

struct Diagnostic;

enum class CapabilityTier {
    Supported,
    Experimental,
    OutOfScope,
};

// Public finding families, not implementation classes. Some families share
// one dataflow pass (memory-leak/double-free/use-after-free/resource-leak),
// but their maturity and verdict behavior are intentionally independent.
struct RuleCapability {
    std::string_view id;
    CapabilityTier tier;
    bool default_enabled;
    bool quality_gated;
    bool blocks_verdict;
    std::string_view evidence;
    std::string_view description;
    std::string_view help_uri;
    // Possible family mappings, NOT tags to apply to every finding.
    std::vector<int> cwe_ids;
};

struct CweMetadata {
    int id;
    std::string_view description;
};

const CweMetadata* findCweMetadata(int id);
std::vector<int> findingCweIds(const Diagnostic& diagnostic);
void mergeFindingMetadata(Diagnostic& target, const Diagnostic& source);
// Shared additive machine metadata for CLI discovery, JSON and SARIF.
void writeCweReferencesJson(std::ostream& out, const std::vector<int>& ids);
void writeFindingMetadataJson(std::ostream& out, const Diagnostic& diagnostic);

const std::vector<RuleCapability>& ruleCapabilities();
const RuleCapability* findRuleCapability(std::string_view finding_id);
// Producer IDs are implementation identities. Selection is by every public
// family they can emit; internal contract aliases belong to "contract".
std::vector<std::string> producerFindingFamilies(const std::string& producer_id);
const char* capabilityTierName(CapabilityTier tier);

// Unknown diagnostics fail closed. `contract-syntax` and
// `contract-unsupported` are internal aliases of the public experimental
// `contract` capability.
bool findingBlocksVerdict(std::string_view finding_id);

// Stable discovery surface for CI, wrappers, and AI agents. The JSON form is
// intentionally dependency-free so it is available before analysis starts.
void writeCapabilities(std::ostream& out, bool json);
// Build identity shared by discovery and report surfaces; not a schema version.
const char* toolVersion();

} // namespace codeskeptic

#endif // CODESKEPTIC_CAPABILITIES_H
