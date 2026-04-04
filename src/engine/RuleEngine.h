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

    size_t ruleCount() const;
    std::vector<std::string> ruleIds() const;

private:
    std::vector<std::unique_ptr<Rule>> rules_;
};

} // namespace zerodefect

#endif // ZERODEFECT_RULE_ENGINE_H
