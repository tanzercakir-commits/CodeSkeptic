#ifndef ZERODEFECT_POLICY_RULE_H
#define ZERODEFECT_POLICY_RULE_H

#include "core/Rule.h"

namespace zerodefect {

// Policy enforcement (CONTRACTS.md §2.3, Round E). Policies are
// AST-level pattern prohibitions under the shared zd: surface —
// activated per file by a `// zd:policy <name>` comment, or
// project-wide from the idiom profile (`policy = <name>` in
// .zerodefect.conf / --policy).
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
        return "Enforces zd:policy pattern prohibitions "
               "(no-absolute-paths)";
    }
    Severity defaultSeverity() const override { return Severity::Error; }

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace zerodefect

#endif // ZERODEFECT_POLICY_RULE_H
