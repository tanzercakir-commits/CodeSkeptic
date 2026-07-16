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

#include <cstdint>
#include <map>
#include <optional>
#include <set>

namespace zerodefect {

using IntervalMap = std::map<const clang::VarDecl*, Interval>;

// Evaluate an integer-typed expression to an interval. Literals, tracked
// variable reads, unary +/-, and binary + - * are modeled; everything
// else (calls, unknown vars, bitwise, division, …) is top().
Interval evalInterval(const clang::Expr* expr, const IntervalMap& state);

// Context-aware variant (#69b): narrowing integral casts are checked by
// VALUE — an operand interval that fits the destination type's range
// passes through unchanged (it cannot wrap); otherwise top() as before.
// `ctx` may be null (identical to the 2-arg form).
Interval evalInterval(const clang::Expr* expr, const IntervalMap& state,
                      const clang::ASTContext* ctx);

// SOLE-DEFINITION intervals for a function's integer locals (#69b): a
// local whose ONLY write is its declaration initializer — never
// reassigned, never ++/--, never address-taken — holds its
// initializer's value at every later read, so `evalInterval(init)` is
// its interval for the whole function, flow-insensitively. The heap
// extents' sole-definition discipline, applied to integers. Locals
// with any other write, and initializers that evaluate to top(), are
// simply absent (consumers prove nothing — sound). Initializers are
// evaluated against the empty state: a masked expression over
// PARAMETERS still lands (`int idx = ((x>>3)&2)+(x&1)` → [0,3], the
// picojpeg getHuffVal caller), while inter-local chains stay top (v1).
IntervalMap soleDefIntervals(const clang::FunctionDecl* fn,
                             clang::ASTContext& ctx);

// Byte size of a type, guarded by a STRUCTURAL BUDGET. Clang's
// getTypeInfo recurses once per nesting level (array element, record
// field, base class), and metaprogram-generated types in real code can
// nest deep enough to smash the stack (TensorFlow Lite's
// neon_tensor_utils.cc drove getTypeInfoImpl 104k frames deep —
// SIGSEGV). This helper walks the type's structure first, with a depth
// and node budget; a type too deep/large to walk safely yields
// nullopt, which callers treat as "size unknown" (rules stay sound via
// top()). ALL rule-side type-size queries go through here.
std::optional<int64_t> boundedTypeSizeInChars(clang::ASTContext& ctx,
                                              clang::QualType type);

// Evaluate an allocation/copy SIZE expression to a BYTE interval. Extends
// evalInterval with `sizeof(T)` (a compile-time constant) and constant
// arithmetic over it, so `n * sizeof(int)`, `sizeof(struct X)`, and plain
// byte counts evaluate; a variable factor uses `state`. Value-preserving
// casts (lvalue-load / no-op / WIDENING integral) are transparent; a
// NARROWING cast stops (→ top), so a size is never over-estimated into a
// false overflow. Needs ASTContext for type sizes. The one place size
// semantics live — shared by the extent map and the copy-size check.
Interval evalSizeInterval(const clang::Expr* expr, clang::ASTContext& ctx,
                          const IntervalMap& state);

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
