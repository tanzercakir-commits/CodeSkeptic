#ifndef ZERODEFECT_INT_OVERFLOW_RULE_H
#define ZERODEFECT_INT_OVERFLOW_RULE_H

#include "core/Rule.h"

namespace zerodefect {

// Integer overflow (CWE-190) — the first consumer of the interval
// dataflow (2026-07-14). v0 scope: SIGNED integer MULTIPLICATION whose
// proven operand ranges yield a product exceeding the expression's own
// signed type range. Signed overflow is undefined behavior in C, and
// the classic bite is allocation sizing (`malloc(a * b)`) — the width
// times height that quietly wraps to a tiny value and hands back a
// buffer far smaller than the code believes.
//
// Precision-first: reported ONLY when both operand ranges are bounded
// and the product provably escapes the type. An unbounded (unknown)
// operand → top() product → silent. Multiplication only for v0 (the
// highest-signal, lowest-FP shape); addition/subtraction and unsigned
// wraparound (which is defined, not UB) are deliberately out of scope
// here.
class IntOverflowRule : public Rule {
public:
    std::string id() const override { return "int-overflow"; }
    std::string description() const override {
        return "Signed integer multiplication overflow via range analysis";
    }
    Severity defaultSeverity() const override { return Severity::Warning; }

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace zerodefect

#endif // ZERODEFECT_INT_OVERFLOW_RULE_H
