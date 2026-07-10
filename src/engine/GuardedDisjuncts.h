#ifndef ZERODEFECT_GUARDED_DISJUNCTS_H
#define ZERODEFECT_GUARDED_DISJUNCTS_H

// Guarded-disjunct state: the data structure of targeted path
// sensitivity.
//
// An analysis state is kept not as one merged VarMap but as a small
// number of (condition-facts, VarMap) pairs. When refineOnEdge sees
// the same condition a second time, it drops the contradicting
// disjunct — so the phantom paths in the "if(g==5) produce; ...
// if(g==5) consume;" pattern (produced but not consumed) are never
// born. Root fix of the Juliet FP hunt; first validated in
// MemoryLeakRule, now a shared component of three rules.
//
// Fit with the engine contract: State = std::vector<Guarded<VarMap>>
// is compared with operator==; normalizeGuarded applies a canonical
// order and a cap (widening) — the engine's "did the state change"
// test stays stable. On cap overflow we widen to a single disjunct:
// common facts are intersected, VarMaps merged (a fallback to the
// classic merged analysis).
//
// VarMap requirements: std::map<K, V>; the caller supplies a
// mergeVal(V, V) -> V combiner for V.

#include "engine/PathFacts.h"

#include <clang/AST/Expr.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <set>
#include <vector>

namespace zerodefect {

template <typename VarMap>
struct Guarded {
    std::map<FactKey, bool> facts;
    VarMap vars;

    bool operator==(const Guarded& o) const {
        return facts == o.facts && vars == o.vars;
    }
    bool operator!=(const Guarded& o) const { return !(*this == o); }
    bool operator<(const Guarded& o) const {
        if (facts != o.facts) return facts < o.facts;
        return vars < o.vars;
    }
};

template <typename VarMap>
using GuardedState = std::vector<Guarded<VarMap>>;

// Disjunct cap. Kept small: the goal is the correlated-guard pattern,
// not general path sensitivity. On overflow, widening falls back to
// today's (merged) behavior — no loss of soundness, some loss of
// sharpness.
constexpr std::size_t kMaxDisjuncts = 4;

template <typename VarMap, typename MergeVal>
void mergeVarMaps(VarMap& into, const VarMap& from, MergeVal mergeVal) {
    for (const auto& [var, s] : from) {
        auto it = into.find(var);
        if (it == into.end())
            into.emplace(var, s);
        else
            it->second = mergeVal(it->second, s);
    }
}

// Canonical form: sorted; same-facts disjuncts merged; widened on cap
// overflow. Order stability is required for the engine's != comparison.
template <typename VarMap, typename MergeVal>
void normalizeGuarded(GuardedState<VarMap>& state, MergeVal mergeVal) {
    std::sort(state.begin(), state.end());
    GuardedState<VarMap> merged;
    for (auto& d : state) {
        if (!merged.empty() && merged.back().facts == d.facts)
            mergeVarMaps(merged.back().vars, d.vars, mergeVal);
        else
            merged.push_back(std::move(d));
    }
    state = std::move(merged);

    if (state.size() > kMaxDisjuncts) {
        Guarded<VarMap> widened = std::move(state.front());
        for (std::size_t i = 1; i < state.size(); ++i) {
            for (auto it = widened.facts.begin();
                 it != widened.facts.end();) {
                auto found = state[i].facts.find(it->first);
                if (found == state[i].facts.end() ||
                    found->second != it->second)
                    it = widened.facts.erase(it);
                else
                    ++it;
            }
            mergeVarMaps(widened.vars, state[i].vars, mergeVal);
        }
        state.clear();
        state.push_back(std::move(widened));
    }
}

template <typename VarMap, typename MergeVal>
GuardedState<VarMap> mergeGuarded(const GuardedState<VarMap>& a,
                                  const GuardedState<VarMap>& b,
                                  MergeVal mergeVal) {
    GuardedState<VarMap> result = a;
    result.insert(result.end(), b.begin(), b.end());
    normalizeGuarded(result, mergeVal);
    return result;
}

// Reporting view: the pointwise merge of all disjuncts — the exact
// counterpart of a single-state analysis. Reporting logic runs
// unchanged; the payoff of path sensitivity is that dropped disjuncts
// never enter this merge.
template <typename VarMap, typename MergeVal>
VarMap flattenGuarded(const GuardedState<VarMap>& state, MergeVal mergeVal) {
    VarMap out;
    for (const auto& d : state) mergeVarMaps(out, d.vars, mergeVal);
    return out;
}

// If the condition can be keyed: contradicting disjuncts are
// impossible on this edge (dropped), the fact is recorded into the
// rest. A condition that cannot be keyed is a no-op. If all disjuncts
// drop, the state empties = the edge is infeasible (correct
// semantics: no report is born from that edge).
template <typename VarMap, typename MergeVal>
void refineGuardedFacts(GuardedState<VarMap>& state,
                        const clang::Expr* cond, bool isTrueBranch,
                        const std::set<const clang::ValueDecl*>& mutated,
                        MergeVal mergeVal) {
    auto fact = conditionFact(cond, mutated);
    if (!fact) return;

    const bool value = isTrueBranch ? fact->second : !fact->second;
    GuardedState<VarMap> kept;
    for (auto& d : state) {
        auto it = d.facts.find(fact->first);
        if (it != d.facts.end() && it->second != value) continue;
        d.facts[fact->first] = value;
        kept.push_back(std::move(d));
    }
    state = std::move(kept);
    normalizeGuarded(state, mergeVal);
}

} // namespace zerodefect

#endif // ZERODEFECT_GUARDED_DISJUNCTS_H
