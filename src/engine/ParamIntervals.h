#ifndef CODESKEPTIC_PARAM_INTERVALS_H
#define CODESKEPTIC_PARAM_INTERVALS_H

// Interprocedural parameter intervals (C3, 2026-07-15): the numeric
// bridge across function boundaries. Real overflow/OOB bugs rarely have
// locally-provable operands — the sizes flow in as parameters. This pass
// answers "what range can parameter i of function f actually hold on
// entry?" so IntervalAnalysis can seed a parameter with a proven range
// instead of top().
//
// SOUNDNESS — the entry interval must contain EVERY value the parameter
// can take at runtime, so it may be narrowed below top() ONLY when the
// call graph for f is CLOSED and fully visible:
//   * f has INTERNAL LINKAGE (static / anonymous namespace) — it cannot
//     be called from another TU, so every caller is in this TU; and
//   * f's address is NEVER TAKEN — no indirect call can reach it with
//     an argument we did not see.
// For such an f, the entry interval of parameter i is the JOIN of the
// argument intervals at every call site. Any externally-visible or
// address-taken function keeps ALL parameters at top() (today's
// behaviour) — a caller we cannot see could pass anything.
//
// v0.2 (two-pass) evaluates each call argument with the CALLER's local
// interval state at the call site: pass 1 runs IntervalAnalysis
// (parameters = top, so no fixpoint and no optimistic recursion) over
// every function that calls a candidate, records the state at each call,
// and evaluates the arguments there — so a caller's bounded local
// (`int n = 5; helper(n)`) or guard-bounded value reaches the callee, not
// just a literal. A parameter a call site does not cover (variadic /
// default argument / fewer args) still widens to top().

#include "engine/Interval.h"

#include <clang/AST/Decl.h>

#include <map>
#include <vector>

namespace clang {
class ASTContext;
}

namespace codeskeptic {

// f (canonical decl) -> per-parameter entry interval. A function absent
// from the map has no proven entry constraint (treat every parameter as
// top()); a present vector is indexed by parameter position.
using ParamIntervalMap =
    std::map<const clang::FunctionDecl*, std::vector<Interval>>;

// Compute the entry intervals for every internal-linkage, address-not-
// taken function in the TU. Call once per TU.
ParamIntervalMap buildParamIntervals(clang::ASTContext& ctx);

// The proven entry interval of parameter `index` of `fn`, or top() when
// unconstrained (external/address-taken/uncalled/out-of-range).
Interval paramEntryInterval(const ParamIntervalMap& map,
                            const clang::FunctionDecl* fn, unsigned index);

// Seed map (parameter VarDecl -> proven entry interval) for `fn`,
// restricted to parameters whose entry is actually narrower than top()
// — the value IntervalAnalysis consumes to start a parameter below top().
std::map<const clang::VarDecl*, Interval> paramSeeds(
    const ParamIntervalMap& map, const clang::FunctionDecl* fn);

// Per-TU cache. The two-pass build runs a dataflow over every caller, so
// it is computed ONCE per TU and shared by every consuming rule
// (int-overflow, bounds). Built lazily on first access, cleared per TU
// alongside the summary/CFG caches (RuleEngine::runAll and the test
// harness) — the FunctionDecl* keys are TU-specific.
class ParamIntervalCache {
public:
    static ParamIntervalCache& instance();
    const ParamIntervalMap& get(clang::ASTContext& ctx);
    void clear();

private:
    ParamIntervalMap map_;
    bool built_ = false;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_PARAM_INTERVALS_H
