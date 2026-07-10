#include "engine/RuleEngine.h"

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
    // Interprosedurel ozetler TU basina bir kez, kurallardan ONCE kurulur.
    // Fonksiyon/satir filtrelerinden bagimsizdir: kapsam-ici fonksiyonun
    // cagirdigi kapsam-disi fonksiyonlarin da ozetine ihtiyac var.
    SummaryRegistry::instance().rebuild(ctx);

    DiagnosticList results;
    for (auto& rule : rules_) {
        if (rule->isEnabled()) {
            rule->check(ctx, results);
        }
    }

    // Hasat, temizlikten ONCE: depo string-anahtarli (TU'dan bagimsiz),
    // yerel tablo ise birazdan silinecek
    if (harvest_global_) SummaryRegistry::instance().harvestGlobal();

    // FunctionDecl* anahtarlari bu TU'ya ozgu — sarkan pointer birakma
    SummaryRegistry::instance().clear();
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
