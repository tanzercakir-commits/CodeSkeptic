#ifndef ZERODEFECT_DIV_BY_ZERO_RULE_H
#define ZERODEFECT_DIV_BY_ZERO_RULE_H

#include "core/Rule.h"

namespace zerodefect {

class DivByZeroRule : public Rule {
public:
    std::string id() const override;
    std::string description() const override;
    Severity defaultSeverity() const override;

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace zerodefect

#endif // ZERODEFECT_DIV_BY_ZERO_RULE_H
