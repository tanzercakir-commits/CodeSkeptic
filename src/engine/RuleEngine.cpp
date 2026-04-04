#include "engine/RuleEngine.h"

namespace zerodefect {

void RuleEngine::enableRule(const std::string& rule_id, bool enabled) {
    for (auto& rule : rules_) {
        if (rule->id() == rule_id) {
            rule->setEnabled(enabled);
            return;
        }
    }
}

DiagnosticList RuleEngine::runAll(clang::ASTContext& ctx) {
    DiagnosticList results;
    for (auto& rule : rules_) {
        if (rule->isEnabled()) {
            rule->check(ctx, results);
        }
    }
    return results;
}

size_t RuleEngine::ruleCount() const {
    return rules_.size();
}

std::vector<std::string> RuleEngine::ruleIds() const {
    std::vector<std::string> ids;
    ids.reserve(rules_.size());
    for (const auto& rule : rules_) {
        ids.push_back(rule->id());
    }
    return ids;
}

} // namespace zerodefect
