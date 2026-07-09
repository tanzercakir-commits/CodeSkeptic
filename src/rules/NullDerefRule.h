#ifndef ZERODEFECT_NULL_DEREF_RULE_H
#define ZERODEFECT_NULL_DEREF_RULE_H

#include "core/Rule.h"

namespace zerodefect {

// CFG dataflow ile null pointer dereference tespiti. nullptr/NULL/0
// akisini izler; dal kosulu iyilestirmesi (assume edges) sayesinde
// `if (p)` / `if (p != nullptr)` guard'lari anlasilir — eski
// NullPointerRule'un yuksek false-positive orani bu yuzden yoktur.
class NullDerefRule : public Rule {
public:
    std::string id() const override;
    std::string description() const override;
    Severity defaultSeverity() const override;

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace zerodefect

#endif // ZERODEFECT_NULL_DEREF_RULE_H
