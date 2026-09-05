#ifndef CODESKEPTIC_UNINIT_SCALAR_RULE_H
#define CODESKEPTIC_UNINIT_SCALAR_RULE_H

#include "core/Rule.h"

namespace codeskeptic {

// Experimental CWE-457 subset: actual reads of automatic integer/bool locals
// in straight-line code. Escaped bindings are unknown, not proven initialized.
// CFG joins/loops, aggregates, heap storage and interprocedural writes are not
// covered by this first unit. Unsupported execution shapes produce no proof.
class UninitScalarRule : public Rule {
public:
    std::string id() const override;
    std::string description() const override;
    Severity defaultSeverity() const override;
    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace codeskeptic

#endif
