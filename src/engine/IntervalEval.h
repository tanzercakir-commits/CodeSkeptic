#ifndef ZERODEFECT_INTERVAL_EVAL_H
#define ZERODEFECT_INTERVAL_EVAL_H

// Reusable interval evaluation over the AST (2026-07-14): given the
// current per-variable intervals, evaluate an integer expression to an
// Interval, apply an assignment statement, and refine on a branch
// edge. Shared by every quantitative consumer — div-by-zero (nonzero
// via range), the integer-overflow rule, and the bounds rule — so the
// numeric transfer logic lives in exactly one place.
//
// Soundness carries over from Interval: an unknown or unhandled form
// evaluates to top(); an assignment we cannot model sets the target to
// top(). We never invent a narrower range than the truth.

#include "engine/Interval.h"

#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>

#include <map>
#include <set>

namespace zerodefect {

using IntervalMap = std::map<const clang::VarDecl*, Interval>;

// Evaluate an integer-typed expression to an interval. Literals, tracked
// variable reads, unary +/-, and binary + - * are modeled; everything
// else (calls, unknown vars, bitwise, division, …) is top().
Interval evalInterval(const clang::Expr* expr, const IntervalMap& state);

// If `stmt` assigns one of `vars`, update its interval in `state`.
// DeclStmt initializers and plain `=` take the RHS interval; compound
// assignment, ++/--, address-of, and non-const-reference call arguments
// conservatively reset the target to top() (v0 — no relational loop
// modeling yet).
void applyIntervalAssign(IntervalMap& state, const clang::Stmt* stmt,
                         const std::set<const clang::VarDecl*>& vars);

// Refine the intervals of `vars` on the edge where `cond` is
// true/false (assume-edge). Handles `var REL const` and truthiness via
// the shared ConditionWalk skeleton; a contradiction narrows to ⊥.
void refineIntervalOnEdge(IntervalMap& state, const clang::Expr* cond,
                          bool isTrue,
                          const std::set<const clang::VarDecl*>& vars);

} // namespace zerodefect

#endif // ZERODEFECT_INTERVAL_EVAL_H
