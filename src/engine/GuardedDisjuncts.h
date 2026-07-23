#ifndef CODESKEPTIC_GUARDED_DISJUNCTS_H
#define CODESKEPTIC_GUARDED_DISJUNCTS_H

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

#include "engine/ConditionWalk.h"
#include "engine/PathFacts.h"

#include <clang/AST/Expr.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <set>
#include <vector>

namespace codeskeptic {

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
// sharpness. Measured 2026-07-12: raising to 8 cost ~2.7x systemd
// scan time for 2 fewer findings — the remaining correlation misses
// cluster in functions with MANY interacting conditions, where the
// right lever is fact-prioritized widening (keep pointer facts over
// integer facts when collapsing), not a bigger cap.
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

// Collapse to a SINGLE disjunct: facts intersected (only unanimously
// agreed facts survive), VarMaps merged. This is both the cap-overflow
// fallback and the engine's convergence widening (see widen() in the
// analyses): an upper approximation, so always sound to apply.
template <typename VarMap, typename MergeVal>
void widenGuarded(GuardedState<VarMap>& state, MergeVal mergeVal) {
    if (state.size() <= 1) return;
    Guarded<VarMap> widened = std::move(state.front());
    for (std::size_t i = 1; i < state.size(); ++i) {
        for (auto it = widened.facts.begin(); it != widened.facts.end();) {
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

// Bundled value hooks for a CORRELATION-MINING analysis (#70).
//
//  - mergeVal(a, b): plain pairwise upper bound, as everywhere else.
//  - meetVal(facts, a, b): pairwise combine of two disjuncts that
//    share the SAME fact map — the shared facts are passed so the
//    analysis can keep information the facts prove vacuous. The
//    motivating case: a guard implication "flag != 0 ⟹ ptr NonNull"
//    meeting a definitely-null value under shared fact flag == 0.
//    The condition is ruled out on every path either side represents,
//    so the implication holds vacuously and survives; a fact-blind
//    merge had to drop it, and that drop was the poison that spread
//    MaybeNull-without-implication through every later join
//    (measured on stb_image's tga loader).
//  - mine(preCollapse, widened): the widening correlation miner; see
//    widenGuarded below.
template <typename MergeVal, typename MeetVal, typename MineFn>
struct GuardedOps {
    MergeVal mergeVal;
    MeetVal meetVal;
    MineFn mine;
};

template <typename MergeVal, typename MeetVal, typename MineFn>
GuardedOps<MergeVal, MeetVal, MineFn> makeGuardedOps(MergeVal mergeVal,
                                                     MeetVal meetVal,
                                                     MineFn mine) {
    return {mergeVal, meetVal, mine};
}

// Widening with a CORRELATION MINER (#70). Same collapse as above,
// but the pre-collapse disjunct set is offered to
// `mine(preCollapse, widened)` before the state is replaced, so the
// analysis can preserve per-variable guard implications (e.g.
// "flag != 0 ⟹ ptr NonNull") that the fact intersection is about to
// erase. This is what breaks the guard cross-product: N independently
// guarded variables need N implications in ONE disjunct, not 2^N
// disjuncts (the stb_image tga_palette wall). The miner must only
// record information valid on EVERY path the collapsed disjunct
// represents — it sharpens the collapse, never the truth.
// (Cross-disjunct var merging uses plain mergeVal: members have
// DIFFERENT fact maps, so no shared-fact context exists — the miner
// re-derives what the merge had to drop.)
template <typename VarMap, typename Ops>
void widenGuardedOps(GuardedState<VarMap>& state, const Ops& ops) {
    if (state.size() <= 1) return;
    Guarded<VarMap> widened = state.front();  // copy: `state` must
    for (std::size_t i = 1; i < state.size(); ++i) {  // survive for mine()
        for (auto it = widened.facts.begin(); it != widened.facts.end();) {
            auto found = state[i].facts.find(it->first);
            if (found == state[i].facts.end() ||
                found->second != it->second)
                it = widened.facts.erase(it);
            else
                ++it;
        }
        mergeVarMaps(widened.vars, state[i].vars, ops.mergeVal);
    }
    ops.mine(static_cast<const GuardedState<VarMap>&>(state), widened);
    state.clear();
    state.push_back(std::move(widened));
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

    if (state.size() > kMaxDisjuncts)
        widenGuarded(state, mergeVal);
}

// Ops-aware canonical form: same-facts merges combine values UNDER
// the shared fact map (ops.meetVal), and the cap-overflow collapse
// runs the correlation miner.
template <typename VarMap, typename Ops>
void normalizeGuardedOps(GuardedState<VarMap>& state, const Ops& ops) {
    std::sort(state.begin(), state.end());
    GuardedState<VarMap> merged;
    for (auto& d : state) {
        if (!merged.empty() && merged.back().facts == d.facts) {
            auto& into = merged.back();
            for (const auto& [var, s] : d.vars) {
                auto it = into.vars.find(var);
                if (it == into.vars.end())
                    into.vars.emplace(var, s);
                else
                    it->second = ops.meetVal(into.facts, it->second, s);
            }
        } else {
            merged.push_back(std::move(d));
        }
    }
    state = std::move(merged);

    if (state.size() > kMaxDisjuncts)
        widenGuardedOps(state, ops);
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

// Ops-aware join: the cap-overflow collapse inside the join is the
// COMMON widening point (loop-body joins overflow long before the
// engine's convergence widening kicks in), so a mining analysis must
// route its merge() through this overload too.
template <typename VarMap, typename Ops>
GuardedState<VarMap> mergeGuardedOps(const GuardedState<VarMap>& a,
                                     const GuardedState<VarMap>& b,
                                     const Ops& ops) {
    GuardedState<VarMap> result = a;
    result.insert(result.end(), b.begin(), b.end());
    normalizeGuardedOps(result, ops);
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

// Structural, per-disjunct condition refinement (v2b, 2026-07-12).
//
// The walk mirrors walkCondition: `!` flips, __builtin_expect and the
// comma operator pass through, `a && b` on its TRUE edge (and
// `a || b` on its FALSE edge) hold BOTH operands — recurse into each.
// At a decomposition leaf, conditionFact keys the expression:
// contradicting disjuncts drop (factsContradict handles both exact
// recordings and entailment from stamped equalities), the rest record.
//
// The genuinely new piece is the branch a walk cannot decide:
// `a || b` on its TRUE edge. Whole-state refinement must give up (it
// cannot know which operand held), but a DISJUNCT often can: if the
// disjunct's own knowledge refutes one operand, the other operand
// held ON THAT DISJUNCT and is applied to it alone. This is exactly
// the systemd assert shape — `assert(s || l <= 0)` materialized as a
// value (the `!!(!(...))` + __builtin_expect wrappers make Clang
// join the operand paths BEFORE the branch), where the s-is-null
// disjunct refutes the left operand, so (l <= 0) is recorded into it.
// The refuter is analysis-supplied: refutes(disjunct, expr) answers
// "is expr definitely FALSE here" from domain knowledge (pointer
// nullness) — facts alone cannot see it.
//
// If all disjuncts drop, the state empties = the edge is infeasible
// (correct semantics: no report is born from that edge).
// Per-disjunct condition context: which decls may be keyed and how
// leaves land on this disjunct. applyLeaf(d, leaf, leafIsTrue) must
// return false when the disjunct contradicts the leaf (drop);
// refutes(d, expr, wanted) answers "can expr be `wanted` here" with
// false meaning DEFINITELY NOT (used for disjunction elimination).
template <typename VarMap, typename RefuteFn, typename ApplyLeafFn>
bool refineDisjunctCondition(Guarded<VarMap>& d, const clang::Expr* cond,
                             bool isTrue, RefuteFn&& refutes,
                             ApplyLeafFn&& applyLeaf) {
    if (!cond) return true;
    cond = stripBoolPreservingCasts(cond->IgnoreParenImpCasts());

    if (const auto* call = llvm::dyn_cast<clang::CallExpr>(cond)) {
        const clang::FunctionDecl* callee = call->getDirectCallee();
        const clang::IdentifierInfo* id =
            callee ? callee->getIdentifier() : nullptr;
        if (id && (id->getName() == "__builtin_expect" ||
                   id->getName() == "__builtin_expect_with_probability") &&
            call->getNumArgs() >= 1)
            return refineDisjunctCondition(d, call->getArg(0), isTrue,
                                           refutes, applyLeaf);
        // fall through: a plain call may still be a keyable leaf
    }
    if (const auto* un = llvm::dyn_cast<clang::UnaryOperator>(cond)) {
        if (un->getOpcode() == clang::UO_LNot)
            return refineDisjunctCondition(d, un->getSubExpr(), !isTrue,
                                           refutes, applyLeaf);
    }
    if (const auto* bo = llvm::dyn_cast<clang::BinaryOperator>(cond)) {
        const clang::BinaryOperatorKind opc = bo->getOpcode();
        if (opc == clang::BO_Comma)
            return refineDisjunctCondition(d, bo->getRHS(), isTrue,
                                           refutes, applyLeaf);
        const bool bothHold = (opc == clang::BO_LAnd && isTrue) ||
                              (opc == clang::BO_LOr && !isTrue);
        const bool oneHolds = (opc == clang::BO_LOr && isTrue) ||
                              (opc == clang::BO_LAnd && !isTrue);
        if (bothHold) {
            // On this edge both operands have a known value.
            return refineDisjunctCondition(d, bo->getLHS(), isTrue,
                                           refutes, applyLeaf) &&
                   refineDisjunctCondition(d, bo->getRHS(), isTrue,
                                           refutes, applyLeaf);
        }
        if (oneHolds) {
            // Disjunction elimination: `a || b` true / `a && b` false
            // — whole-state refinement cannot know which operand held,
            // but a disjunct that REFUTES one operand knows the other
            // held on it (the systemd assert shape: the s-is-null
            // disjunct of `assert(s || l <= 0)` learns l <= 0).
            const clang::Expr* lhs = bo->getLHS();
            const clang::Expr* rhs = bo->getRHS();
            const bool operandValue = (opc == clang::BO_LOr);
            const bool lhsOut = refutes(d, lhs, operandValue);
            const bool rhsOut = refutes(d, rhs, operandValue);
            if (lhsOut && rhsOut) return false;  // edge infeasible here
            if (lhsOut)
                return refineDisjunctCondition(d, rhs, operandValue,
                                               refutes, applyLeaf);
            if (rhsOut)
                return refineDisjunctCondition(d, lhs, operandValue,
                                               refutes, applyLeaf);
            return true;  // undecided: no information
        }
    }

    return applyLeaf(d, cond, isTrue);
}

// Fact-level building blocks shared by every client. keyLeaf: record
// or contradict one leaf on one disjunct. keyRefutes: can the leaf's
// wanted value be ruled out from recorded/stamped facts alone.
template <typename VarMap>
bool applyFactLeaf(Guarded<VarMap>& d, const clang::Expr* leaf, bool isTrue,
                   const std::set<const clang::ValueDecl*>& unkeyable,
                   const std::set<const clang::ValueDecl*>& ptrKeyable) {
    // TRUE-EDGE-ONLY unsigned-bound fact (#87): `X < n` (both unsigned)
    // true ⟹ n != 0. Applied ONLY on the true edge (never flipped —
    // the false edge carries no n==0 information), so it lives beside
    // the flippable conditionFact, not inside it. Refutes the `n == 0`
    // disjunct on a loop body edge (the file_access null+zero-length
    // class, and the relational-requires escape).
    if (isTrue) {
        if (auto nz = unsignedStrictUpperBoundNonzero(leaf, unkeyable)) {
            if (factsContradict(d.facts, *nz, /*wanted=*/false))
                return false;
            d.facts[*nz] = false;  // n != 0 on this edge
        }
    }

    auto fact = conditionFact(leaf, unkeyable, ptrKeyable);
    if (!fact) return true;
    const bool value = isTrue ? fact->second : !fact->second;
    if (factsContradict(d.facts, fact->first, value)) return false;
    d.facts[fact->first] = value;
    return true;
}

template <typename VarMap>
bool factsRefute(const Guarded<VarMap>& d, const clang::Expr* expr,
                 bool wanted,
                 const std::set<const clang::ValueDecl*>& unkeyable,
                 const std::set<const clang::ValueDecl*>& ptrKeyable) {
    auto fact = conditionFact(expr, unkeyable, ptrKeyable);
    if (!fact) return false;
    const bool value = wanted ? fact->second : !fact->second;
    return factsContradict(d.facts, fact->first, value);
}

// Whole-state wrapper with analysis-supplied hooks. extraRefutes may
// add DOMAIN knowledge on top of the fact-based refuter (NullDeref:
// a pointer whose var-state is Null refutes a truthiness operand);
// extraApply lets the analysis refine its VarMap for exactly the
// leaves (and eliminated-survivor operands) this disjunct is known to
// satisfy.
template <typename VarMap, typename MergeVal, typename ExtraRefuteFn,
          typename ExtraApplyFn>
void refineGuardedFactsWith(GuardedState<VarMap>& state,
                            const clang::Expr* cond, bool isTrueBranch,
                            const std::set<const clang::ValueDecl*>& unkeyable,
                            const std::set<const clang::ValueDecl*>& ptrKeyable,
                            MergeVal mergeVal, ExtraRefuteFn&& extraRefutes,
                            ExtraApplyFn&& extraApply) {
    if (!cond) return;
    auto refutes = [&](const Guarded<VarMap>& d, const clang::Expr* e,
                       bool wanted) {
        return factsRefute(d, e, wanted, unkeyable, ptrKeyable) ||
               extraRefutes(d, e, wanted);
    };
    auto applyLeaf = [&](Guarded<VarMap>& d, const clang::Expr* leaf,
                         bool leafTrue) {
        if (!applyFactLeaf(d, leaf, leafTrue, unkeyable, ptrKeyable))
            return false;
        extraApply(d, leaf, leafTrue);
        return true;
    };
    GuardedState<VarMap> kept;
    for (auto& d : state) {
        if (!refineDisjunctCondition(d, cond, isTrueBranch, refutes,
                                     applyLeaf))
            continue;
        kept.push_back(std::move(d));
    }
    state = std::move(kept);
    normalizeGuarded(state, mergeVal);
}

// Ops-aware refinement: identical walk, but the trailing
// normalization combines same-facts disjuncts under their shared fact
// map (refinement is a fact-RECORDING step, so freshly equalized fact
// maps meet here first).
template <typename VarMap, typename Ops, typename ExtraRefuteFn,
          typename ExtraApplyFn>
void refineGuardedFactsOps(GuardedState<VarMap>& state,
                           const clang::Expr* cond, bool isTrueBranch,
                           const std::set<const clang::ValueDecl*>& unkeyable,
                           const std::set<const clang::ValueDecl*>& ptrKeyable,
                           const Ops& ops, ExtraRefuteFn&& extraRefutes,
                           ExtraApplyFn&& extraApply) {
    if (!cond) return;
    auto refutes = [&](const Guarded<VarMap>& d, const clang::Expr* e,
                       bool wanted) {
        return factsRefute(d, e, wanted, unkeyable, ptrKeyable) ||
               extraRefutes(d, e, wanted);
    };
    auto applyLeaf = [&](Guarded<VarMap>& d, const clang::Expr* leaf,
                         bool leafTrue) {
        // Leaf-level domain contradiction drop: when the disjunct's
        // established state already REFUTES this leaf (a NonNull
        // pointer meeting a `!p`-true edge — the short-circuit path of
        // `if (!p && cond)` where cond is false), no path this disjunct
        // covers can take the edge. Drop it, exactly as a fact
        // contradiction drops. The motivating receipt (contract
        // seeding, 2026-07-17): `requires p != null` seeds p NonNull,
        // then a partial guard `if (!p && n>0) return;` short-circuits
        // to a fall-through where `!p` held and `n>0` did not — clang
        // routes p-is-null through to the deref. Overwriting p to Null
        // (the old extraApply-only behavior) fabricated a path the
        // contract rules out; dropping the disjunct discharges the
        // proof burden the contract promised. Only the fact-based +
        // domain refuters vote here (extraRefutes), so a plain guard
        // on an unconstrained pointer is untouched.
        if (refutes(d, leaf, leafTrue)) return false;
        if (!applyFactLeaf(d, leaf, leafTrue, unkeyable, ptrKeyable))
            return false;
        extraApply(d, leaf, leafTrue);
        return true;
    };
    GuardedState<VarMap> kept;
    for (auto& d : state) {
        if (!refineDisjunctCondition(d, cond, isTrueBranch, refutes,
                                     applyLeaf))
            continue;
        kept.push_back(std::move(d));
    }
    state = std::move(kept);
    normalizeGuardedOps(state, ops);
}

template <typename VarMap, typename MergeVal>
void refineGuardedFacts(GuardedState<VarMap>& state,
                        const clang::Expr* cond, bool isTrueBranch,
                        const std::set<const clang::ValueDecl*>& unkeyable,
                        MergeVal mergeVal) {
    static const std::set<const clang::ValueDecl*> kNoPtrKeys;
    refineGuardedFactsWith(
        state, cond, isTrueBranch, unkeyable, kNoPtrKeys, mergeVal,
        [](const Guarded<VarMap>&, const clang::Expr*, bool) {
            return false;
        },
        [](Guarded<VarMap>&, const clang::Expr*, bool) {});
}

// Statement-level fact lifecycle (v2b, 2026-07-12). An assignment to
// a local makes every fact keyed on it stale — they are ERASED from
// all disjuncts (the old whole-function keying ban is gone; this is
// its flow-sensitive replacement). When the assigned value is an
// integer constant and the target is stamping-relevant
// (collectFactDecls), the fresh truth (var EQ lit)=true is STAMPED —
// at a later join, paths that assigned different constants stay
// separate disjuncts, which is exactly the flag/status correlation
// (`have = 1; ... if (have) use(x);`). Returns whether anything
// changed.
// Member-assignment lifecycle shared by both applyStmtFacts variants:
// `c.f = X` erases the (c, f) facts in every disjunct and re-stamps
// when X is an integer constant (scope admission of the base is the
// stamping gate — assignedMemberFact answers only for admitted
// bases). Facts on OTHER fields of c survive: a field store cannot
// change its siblings.
template <typename VarMap>
bool applyMemberStmtFacts(GuardedState<VarMap>& state,
                          const clang::Stmt* stmt) {
    auto ma = assignedMemberFact(stmt);
    if (!ma) return false;
    bool changed = false;
    for (auto& d : state) {
        for (auto it = d.facts.begin(); it != d.facts.end();) {
            if (it->first.var == ma->base && it->first.field == ma->field) {
                it = d.facts.erase(it);
                changed = true;
            } else {
                ++it;
            }
        }
        if (ma->literal) {
            d.facts[FactKey{ma->base, clang::BO_EQ, *ma->literal,
                            ma->field}] = true;
            changed = true;
        }
    }
    return changed;
}

// Call-statement lifecycle for member facts: a call that receives the
// BASE'S ADDRESS may write any of its fields (that is what a
// parse(&c) is for) — every (c, *) fact dies. Calls without &c cannot
// reach an admitted base (see the deliberate-limit note in
// PathFacts.h) and erase nothing.
template <typename VarMap>
bool eraseMemberFactsAtCall(GuardedState<VarMap>& state,
                            const clang::CallExpr* call) {
    const auto* bases = activeMemberFactBases();
    if (!bases || bases->empty()) return false;
    bool changed = false;
    for (const clang::Expr* arg : call->arguments()) {
        const clang::VarDecl* base = addrOfBaseVar(arg);
        if (!base || !bases->count(base)) continue;
        for (auto& d : state) {
            for (auto it = d.facts.begin(); it != d.facts.end();) {
                if (it->first.var == base && it->first.field) {
                    it = d.facts.erase(it);
                    changed = true;
                } else {
                    ++it;
                }
            }
        }
    }
    return changed;
}

template <typename VarMap, typename MergeVal>
bool applyStmtFacts(GuardedState<VarMap>& state, const clang::Stmt* stmt,
                    const std::set<const clang::ValueDecl*>& stampable,
                    const std::set<const clang::ValueDecl*>& ptrStampable,
                    MergeVal mergeVal) {
    const clang::ValueDecl* target = assignedDecl(stmt);
    if (!target) {
        if (applyMemberStmtFacts(state, stmt)) {
            normalizeGuarded(state, mergeVal);
            return true;
        }
        return false;
    }

    auto lit = assignedIntLiteral(stmt);
    // Integer stamp: any constant. Pointer stamp: only the null
    // constant (`p = NULL;` — the fresh truth (p EQ 0)=true).
    const bool stamp =
        lit && (stampable.count(target) ||
                (ptrStampable.count(target) && lit->second == 0));

    bool changed = false;
    for (auto& d : state) {
        for (auto it = d.facts.begin(); it != d.facts.end();) {
            if (it->first.var == target) {
                it = d.facts.erase(it);
                changed = true;
            } else {
                ++it;
            }
        }
        if (stamp) {
            d.facts[FactKey{target, clang::BO_EQ, lit->second}] = true;
            changed = true;
        }
    }
    if (changed) normalizeGuarded(state, mergeVal);
    return changed;
}

template <typename VarMap, typename MergeVal>
bool applyStmtFacts(GuardedState<VarMap>& state, const clang::Stmt* stmt,
                    const std::set<const clang::ValueDecl*>& stampable,
                    MergeVal mergeVal) {
    static const std::set<const clang::ValueDecl*> kNoPtrs;
    return applyStmtFacts(state, stmt, stampable, kNoPtrs, mergeVal);
}

// Ops-aware fact lifecycle: fact ERASURE equalizes fact maps, so the
// same-facts merges right after it are a prime implication-drop site
// without the shared-fact meet.
template <typename VarMap, typename Ops>
bool applyStmtFactsOps(GuardedState<VarMap>& state, const clang::Stmt* stmt,
                       const std::set<const clang::ValueDecl*>& stampable,
                       const std::set<const clang::ValueDecl*>& ptrStampable,
                       const Ops& ops) {
    const clang::ValueDecl* target = assignedDecl(stmt);
    if (!target) {
        bool memberChanged = applyMemberStmtFacts(state, stmt);
        if (const auto* call = clang::dyn_cast<clang::CallExpr>(stmt))
            memberChanged |= eraseMemberFactsAtCall(state, call);
        if (memberChanged) normalizeGuardedOps(state, ops);
        return memberChanged;
    }

    auto lit = assignedIntLiteral(stmt);
    const bool stamp =
        lit && (stampable.count(target) ||
                (ptrStampable.count(target) && lit->second == 0));

    bool changed = false;
    for (auto& d : state) {
        for (auto it = d.facts.begin(); it != d.facts.end();) {
            if (it->first.var == target) {
                it = d.facts.erase(it);
                changed = true;
            } else {
                ++it;
            }
        }
        if (stamp) {
            d.facts[FactKey{target, clang::BO_EQ, lit->second}] = true;
            changed = true;
        }
    }
    if (changed) normalizeGuardedOps(state, ops);
    return changed;
}

} // namespace codeskeptic

#endif // CODESKEPTIC_GUARDED_DISJUNCTS_H
