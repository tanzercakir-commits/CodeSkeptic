#ifndef CODESKEPTIC_SIGN_CONVERSION_RULE_H
#define CODESKEPTIC_SIGN_CONVERSION_RULE_H

#include "core/Rule.h"

namespace codeskeptic {

// Untrusted sign conversion (CWE-195 neighbourhood) — the rule the
// nlohmann retro-detection test asked for (docs/PLAN-untrusted-sign.md,
// 2026-07-29). The proven false negative: a signed value an attacker
// chooses (`std::int8_t number` filled by a declared untrusted source)
// converted to an unsigned size (`static_cast<std::size_t>(number)`) —
// a negative wraps to a huge length and the downstream read walks off
// the buffer (nlohmann/json #3491/#3492, fixed upstream by adding the
// `number < 0` guard this rule demands).
//
// Deliberately NOT part of IntOverflowRule, whose two exclusions are
// correct for ITS question and unchanged: an explicit cast is stated
// intent for a narrowing (you asked for truncation), and unsigned
// wrap-on-arithmetic is defined behaviour. This rule asks a different
// question of the same expression: does an UNTRUSTED signed value
// reach an unsigned integer type while provably able to be negative?
// There the explicit cast is not intent, it is the defect's vehicle —
// nlohmann's bug WAS the cast, written deliberately.
//
// The second, sink-specific subcase reports proven implicit scalar/literal
// narrowing at native memcpy/memmove/memset lengths or array indices. A finite
// source range must exceed the destination type; direct local value copies are
// followed through CFG assignments. Explicit casts, enum/bool/dependent/unknown/volatile
// values, mixed-origin CFG joins, address/reference-exposed source/destination
// locals and arithmetic-origin propagation are outside that subset.
// Captured ranges and equal-source witnesses belong to each stored value, not a
// globally mutable cast record. Guards refine that value's surviving input range;
// source writes break equality, not the old captured value. Infeasible paths stay
// infeasible across later assignments; widened loop-carried identities are unknown.
// Existing signed arithmetic and negative-to-unsigned
// reports are not duplicated. Both subcases retain the registry's experimental,
// report-only sign-conversion ID; this is not a generic cast warning.
//
// Precision-first gates for the original negative-to-unsigned subcase:
//   - the operand derives from a declared untrusted source (the
//     atoi/strtol intrinsics, scanf outputs, or --untrusted-int-sources
//     returns AND out-params) — provenance is opt-in, never guessed;
//   - its proven interval still contains a NEGATIVE with a finite
//     witness (a merely-unknown value stays silent);
//   - so a dominating `x >= 0` / `x < 0` guard silences on its own
//     edge, while an upper-bound-only guard (`if (x > 100) return;`)
//     does NOT — the negative range survives it, which is exactly the
//     nlohmann shape.
class SignConversionRule : public Rule {
public:
    std::string id() const override { return "sign-conversion"; }
    std::string description() const override {
        return "Untrusted negative-to-unsigned conversion or proven lossy "
               "narrowing reaching a length/index sink";
    }
    Severity defaultSeverity() const override { return Severity::Warning; }

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_SIGN_CONVERSION_RULE_H
