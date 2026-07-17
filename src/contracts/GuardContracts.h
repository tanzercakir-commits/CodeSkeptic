#ifndef ZERODEFECT_GUARD_CONTRACTS_H
#define ZERODEFECT_GUARD_CONTRACTS_H

// Guard-as-contract (#89, §4.A v1): a function's OWN entry guard is a
// precondition the code already enforces at runtime — but only
// locally. This component lifts it into a checkable contract so every
// CALLER can be asked "who violates the callee's own rule?" — the
// interprocedural question no compiler answers (a compiler warns
// about narrowing conversions; it never warns that this call site
// passes NULL into a function whose first line is `assert(p)`).
//
// Three real-world evidence points shaped this (ROADMAP 6.16/6.22):
// Carbon's CARBON_CHECK preconditions, Godot's
// `ERR_FAIL_COND_V(!p_object && ..., ...)` placeholder guards, and
// Godot's `ERR_FAIL_COND_V(!p_src && p_length > 0, false)` in
// FileAccess::store_buffer.
//
// v1 scope (deliberately the compiler-silent, zero-noise slice):
//  - recognized guards: a leading `if (<p is null>) <no-fallthrough>`
//    (the ERR_FAIL expansion shape) and the assert ternary
//    (`cond ? void(0) : __assert_fail(...)`);
//  - extracted contract: plain `requires p != null` only (compound /
//    relational escapes are v-next);
//  - consumers report DEFINITE violations only.
//
// The guard's KIND tells the violation's CONSEQUENCE — the severity
// axis the caller-side check needs (user decision, 2026-07-17):
//  - Crash: the guard vanishes in release builds (assert / NDEBUG) or
//    aborts; a violating call crashes or is UB. Definite -> error.
//  - Rejected: the guard is always compiled in and RETURNS; the callee
//    refuses and the call silently does nothing. Definite -> warning
//    ("this call will always be refused") — a logic bug, not a crash.

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>

#include <vector>

namespace zerodefect {

enum class GuardConsequence {
    Crash,     // assert-style: gone in release, or aborts — UB/crash
    Rejected,  // if-return style: callee refuses, call does nothing
};

struct GuardRequire {
    unsigned paramIndex = 0;          // the parameter proven non-null
    GuardConsequence consequence = GuardConsequence::Rejected;
    unsigned guardLine = 0;           // guard's line (messages/traces)
};

// Scan the LEADING statements of `fn`'s body (guards before any other
// work) and return the null-preconditions they enforce. Empty when the
// body is absent or no leading guard matches. Sound by construction:
// only guards whose branch provably does not fall through qualify.
std::vector<GuardRequire> inferGuardRequires(const clang::FunctionDecl* fn,
                                             clang::ASTContext& ctx);

} // namespace zerodefect

#endif // ZERODEFECT_GUARD_CONTRACTS_H
