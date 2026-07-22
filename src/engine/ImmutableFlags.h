#ifndef CODESKEPTIC_IMMUTABLE_FLAGS_H
#define CODESKEPTIC_IMMUTABLE_FLAGS_H

// Immutable file-static flag constants (v0.4, the leak-FP round).
//
// The Juliet flag-variant FP family (all 12 sampled CWE401 case-FPs
// shared it): an allocation guarded by `if (staticTrue)` and the free
// guarded by `if (staticFalse) … else free(p)`, where both flags are
// file-static ints that are NEVER written. The "allocated but not
// freed" path walks the staticFalse-true edge — an edge that cannot
// execute, since the flag provably holds 0 forever. Real code has the
// same shape with `static const bool debug = false;` config flags.
//
// This pass computes, once per TU, the set of variables whose value is
// a compile-time certainty for every instant of execution:
//   * file-scope with INTERNAL linkage (a TU we can fully see), or
//     const-qualified — either way no other TU can write it;
//   * integer-typed, non-volatile, with a constant initializer;
//   * never mutated in this TU: no assignment, no ++/--, never
//     address-taken, never bound to a non-const reference/pointer.
// Everything else is conservatively absent from the map.
//
// The DataflowEngine consults the map on assume edges: an edge whose
// branch condition contradicts a flag's known value is INFEASIBLE and
// contributes no state — the same semantics as an unreachable
// predecessor (the fatal-call pathKilled treatment). Sound: removing
// impossible paths can only remove impossible conclusions.

#include <cstdint>
#include <map>

namespace clang {
class ASTContext;
class Stmt;
class VarDecl;
}

namespace codeskeptic {

using ImmutableFlagMap = std::map<const clang::VarDecl*, int64_t>;

// Full-TU scan; call once per TU (use the cache below).
ImmutableFlagMap buildImmutableFlags(clang::ASTContext& ctx);

// Per-TU cache, same lifecycle as ParamIntervalCache (cleared by
// RuleEngine::runAll and the test harness).
class ImmutableFlagCache {
public:
    static ImmutableFlagCache& instance();
    const ImmutableFlagMap& get(clang::ASTContext& ctx);
    void clear();

private:
    ImmutableFlagMap map_;
    bool built_ = false;
};

// Does `leafCond` (an assume-edge leaf condition), taken in the
// `edgeIsTrue` sense, contradict a known immutable flag value?
// Handles the leaf shapes the condition walker produces: a bare flag
// reference and flag-vs-constant ==/!= comparisons (either side).
// Returns false (feasible) whenever anything is not certain.
bool edgeInfeasibleByFlags(const clang::Stmt* leafCond, bool edgeIsTrue,
                           clang::ASTContext& ctx);

} // namespace codeskeptic

#endif // CODESKEPTIC_IMMUTABLE_FLAGS_H
