#ifndef CODESKEPTIC_CAPABILITIES_H
#define CODESKEPTIC_CAPABILITIES_H

#include <iosfwd>
#include <string_view>
#include <vector>

namespace codeskeptic {

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
};

const std::vector<RuleCapability>& ruleCapabilities();
const RuleCapability* findRuleCapability(std::string_view finding_id);
const char* capabilityTierName(CapabilityTier tier);

// Unknown diagnostics fail closed. `contract-syntax` and
// `contract-unsupported` are internal aliases of the public experimental
// `contract` capability.
bool findingBlocksVerdict(std::string_view finding_id);

// Stable discovery surface for CI, wrappers, and AI agents. The JSON form is
// intentionally dependency-free so it is available before analysis starts.
void writeCapabilities(std::ostream& out, bool json);

} // namespace codeskeptic

#endif // CODESKEPTIC_CAPABILITIES_H
