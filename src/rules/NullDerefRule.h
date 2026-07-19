#ifndef CODESKEPTIC_NULL_DEREF_RULE_H
#define CODESKEPTIC_NULL_DEREF_RULE_H

#include "core/Rule.h"

namespace codeskeptic {

// Null pointer dereference detection via CFG dataflow. Tracks the flow
// of nullptr/NULL/0; thanks to branch condition refinement (assume
// edges), `if (p)` / `if (p != nullptr)` guards are understood — which
// is why the old NullPointerRule's high false-positive rate is absent.
class NullDerefRule : public Rule {
public:
    std::string id() const override;
    std::string description() const override;
    Severity defaultSeverity() const override;

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_NULL_DEREF_RULE_H
