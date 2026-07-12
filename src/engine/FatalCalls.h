#ifndef ZERODEFECT_ENGINE_FATALCALLS_H
#define ZERODEFECT_ENGINE_FATALCALLS_H

#include <clang/AST/Stmt.h>

#include <set>
#include <string>

namespace zerodefect {

// Fatal-call registry (--fatal-asserts): function names the user
// declares to never return, even though their declarations carry no
// [[noreturn]] attribute.
//
// Why this exists: projects with continue-able assert machinery
// (shadPS4's `assert_fail_impl`, and every codebase that funnels
// ASSERT failures through a deliberately-returning handler) defeat
// the CFG's noreturn pruning. The analyzer then correctly concludes
// that the failure path falls through — and floods the report with
// technically-true-but-useless warnings after every ASSERT (170+ of
// shadPS4's findings). Declaring the handler fatal kills those paths
// at the engine level, exactly like a real [[noreturn]].
//
// The list is EMPTY by default: assuming termination that the code
// does not promise is the user's deliberate, per-project decision
// (the industrial-standard approach — same idea as Coverity's
// kill-path models).

// Replaces the fatal-call name set (comma-splitting happens in
// Config). Called once at startup; tests may call it repeatedly —
// it fully overwrites the previous set.
void setFatalCallNames(std::set<std::string> names);

const std::set<std::string>& fatalCallNames();

// True if the statement is a call to a registered fatal function.
// Only direct callees by identifier are matched (methods and operator
// overloads have no place in an assert-handler list).
bool isFatalCall(const clang::Stmt* stmt);

} // namespace zerodefect

#endif // ZERODEFECT_ENGINE_FATALCALLS_H
