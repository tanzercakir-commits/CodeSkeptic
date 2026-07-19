#ifndef CODESKEPTIC_POLICY_RULE_H
#define CODESKEPTIC_POLICY_RULE_H

#include "core/Rule.h"

namespace codeskeptic {

// Policy enforcement (CONTRACTS.md §2.3, Round E). Policies are
// AST-level pattern prohibitions under the shared cs: surface —
// activated per file by a `// cs:policy <name>` comment, or
// project-wide from the idiom profile (`policy = <name>` in
// .codeskeptic.conf / --policy).
//
// v1 ships one policy: no-absolute-paths — a hard-coded absolute
// path in a string literal is an error (the founding Ruledsl
// release incident, immortalized as a machine-checked rule).
// Unknown policy names are contract-syntax errors: a policy that
// silently fails to activate would be a false comfort.
class PolicyRule : public Rule {
public:
    std::string id() const override { return "policy"; }
    std::string description() const override {
        return "Enforces cs:policy pattern prohibitions "
               "(no-absolute-paths)";
    }
    Severity defaultSeverity() const override { return Severity::Error; }

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_POLICY_RULE_H
