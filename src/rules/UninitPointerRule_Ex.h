#ifndef ZERODEFECT_UNINIT_POINTER_RULE_EX_H
#define ZERODEFECT_UNINIT_POINTER_RULE_EX_H

#include "core/Rule.h"

namespace zerodefect {

class UninitPointerRule_Ex : public Rule {
public:
    std::string id() const override;
    std::string description() const override;
    Severity defaultSeverity() const override;

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace zerodefect

#endif // ZERODEFECT_UNINIT_POINTER_RULE_EX_H
