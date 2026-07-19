#ifndef CODESKEPTIC_ASSUMPTION_RULE_H
#define CODESKEPTIC_ASSUMPTION_RULE_H

#include "core/Rule.h"

namespace codeskeptic {

// Assumption extraction (spec §20.2 — the design doc's self-declared #1
// idea, 2026-07-15). AI-written code routinely relies on preconditions
// it never states: "input is never null", "the length fits", "the
// callback is not concurrent". This rule makes the FIRST such class
// explicit and asks the spec's key question — "where is this assumption
// verified?".
//
// v0: NON-NULL PARAMETER PRECONDITIONS. A pointer parameter that the
// function DEREFERENCES but NEVER guards (never appears in a branch/loop
// condition or a null comparison anywhere in the body) is an implicit
// "this parameter is non-null" assumption. The "where verified?" answer:
// if the function already declares `requires p != null` (a contract),
// the assumption is DOCUMENTED and stays silent — only the UNDECLARED
// ones are surfaced, as Info-severity intent debt.
//
// OPT-IN (--assumptions, engine/AssumptionMode). This is an intent-debt
// report, not a bug hunt: it is high-volume by nature (every unguarded
// deref), so it is off by default and never perturbs the normal finding
// stream or the referees. Precision-leaning: "never appears in ANY
// condition" over-approximates "checked", so a parameter validated even
// indirectly is suppressed — fewer, higher-confidence findings.
class AssumptionRule : public Rule {
public:
    std::string id() const override { return "assumption"; }
    std::string description() const override {
        return "Inferred undeclared preconditions (opt-in intent-debt report)";
    }
    Severity defaultSeverity() const override { return Severity::Info; }

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_ASSUMPTION_RULE_H
