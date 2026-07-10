#include "engine/RuleEngine.h"

#include "engine/CfgCache.h"
#include "engine/FunctionSummary.h"

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
    // Interprocedural summaries are built once per TU, BEFORE the rules.
    // Independent of function/line filters: we also need summaries of
    // out-of-scope functions called by in-scope functions.
    SummaryRegistry::instance().rebuild(ctx);

    DiagnosticList results;
    for (auto& rule : rules_) {
        if (rule->isEnabled()) {
            rule->check(ctx, results);
        }
    }

    // Harvest BEFORE the cleanup: the store is string-keyed (TU-
    // independent), while the local table is about to be deleted
    if (harvest_global_) SummaryRegistry::instance().harvestGlobal();

    // FunctionDecl* keys are specific to this TU — leave no dangling
    // pointers (summary table and CFG cache are cleared together for
    // the same reason)
    SummaryRegistry::instance().clear();
    CfgCache::instance().clear();
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
