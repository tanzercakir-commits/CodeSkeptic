#ifndef CODESKEPTIC_CONTRACT_RULE_H
#define CODESKEPTIC_CONTRACT_RULE_H

#include "core/Rule.h"

namespace codeskeptic {

// Contract verification (CONTRACTS.md). A contract is a DECLARED
// function summary: `// cs: ensures return != null` pins the intent,
// and the same dataflow that infers summaries checks the pin.
//
// Round B scope: unconditional return postconditions
// (`ensures return != null` / `!= 0`) verified against the inferred
// return-nullness/zeroness summaries; `cs:ai` proposals downgrade
// violations to warnings; unparseable lines are contract-syntax
// errors; parseable-but-not-yet-checkable clauses are reported
// explicitly (never silently accepted).
class ContractRule : public Rule {
public:
    std::string id() const override { return "contract"; }
    std::string description() const override {
        return "Verifies declared cs: contracts against the inferred "
               "dataflow summaries";
    }
    Severity defaultSeverity() const override { return Severity::Error; }

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_CONTRACT_RULE_H
