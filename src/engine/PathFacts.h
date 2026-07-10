#ifndef ZERODEFECT_PATH_FACTS_H
#define ZERODEFECT_PATH_FACTS_H

// Condition facts (path facts) for targeted path sensitivity.
//
// Motivation (Juliet FP hunt, 2026-07-10): analyses could not build a
// correlation in patterns where the same invariant condition is
// tested twice:
//
//   if (globalFive == 5) data = malloc(...);   // source
//   if (globalFive == 5) free(data);           // sink — SAME condition
//
// At the first if's join, {Allocated, None} mix; at the second if a
// phantom "allocated but not freed" path is born. Solution: conditions
// are reduced to a canonical key (FactKey) and the analysis state is
// kept as a small number of "guarded disjuncts"; when the same key is
// seen a second time, the contradicting disjunct is dropped.
//
// DELIBERATE LIMITS (precision-first):
//  - Only DeclRef variable vs integer-constant comparisons are keyed
//    (function calls NEVER — a rand() correlation would be wrong).
//  - Variables assigned / address-taken inside the function are not
//    keyed.
//  - That calls may modify globals is ignored: if a call between two
//    correlated guards changes the global, a real defect can be
//    hidden (FN direction). A trade-off accepted to stay FP-free —
//    documented in a test.

#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/OperationKinds.h>

#include <cstdint>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

namespace zerodefect {

// Canonical condition key: "var REL literal". REL is only EQ/LT/LE —
// NE/GT/GE reduce to these by flipping the value (X!=5 ≡ !(X==5)).
struct FactKey {
    const clang::ValueDecl* var = nullptr;
    clang::BinaryOperatorKind rel = clang::BO_EQ;  // BO_EQ | BO_LT | BO_LE
    int64_t literal = 0;

    bool operator==(const FactKey& o) const {
        return var == o.var && rel == o.rel && literal == o.literal;
    }
    bool operator<(const FactKey& o) const {
        return std::tie(var, rel, literal) <
               std::tie(o.var, o.rel, o.literal);
    }
};

// Reduces a condition to a (key, value) pair: the returned bool is the
// key's value WHEN THE CONDITION IS TRUE. Example: `X != 5` gives
// {(X,EQ,5), false}. On a false edge the caller flips the value. A
// condition that cannot be keyed -> nullopt. `mutated`: decls
// assigned/address-taken inside the function (excluded from keying).
std::optional<std::pair<FactKey, bool>> conditionFact(
    const clang::Expr* cond,
    const std::set<const clang::ValueDecl*>& mutated);

// Collects decls that are assigned, ++/--'d, or address-taken in the
// body. Conditions based on these decls can change between two tests
// — they are not keyed.
std::set<const clang::ValueDecl*> collectMutatedDecls(
    const clang::FunctionDecl* func);

} // namespace zerodefect

#endif // ZERODEFECT_PATH_FACTS_H
