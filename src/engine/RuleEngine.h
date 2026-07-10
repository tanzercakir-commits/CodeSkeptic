#ifndef ZERODEFECT_RULE_ENGINE_H
#define ZERODEFECT_RULE_ENGINE_H

#include "core/Diagnostic.h"
#include "core/Rule.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace clang {
class ASTContext;
}

namespace zerodefect {

class RuleEngine {
public:
    template <typename T, typename... Args>
    void addRule(Args&&... args) {
        rules_.push_back(std::make_unique<T>(std::forward<Args>(args)...));
    }

    void enableRule(const std::string& rule_id, bool enabled);
    DiagnosticList runAll(clang::ASTContext& ctx);

    // --summary-out icin: runAll TU-yerel ozet tablosunu temizlemeden
    // once cross-TU depoya hasat etsin (tablo temizligi sarkan-pointer
    // guvenligi geregi runAll icinde — hasat da orada olmali).
    void enableGlobalHarvest(bool enabled) { harvest_global_ = enabled; }

    size_t ruleCount() const;
    std::vector<std::string> ruleIds() const;

private:
    std::vector<std::unique_ptr<Rule>> rules_;
    bool harvest_global_ = false;
};

} // namespace zerodefect

#endif // ZERODEFECT_RULE_ENGINE_H
