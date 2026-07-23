#ifndef CODESKEPTIC_PATH_FACTS_H
#define CODESKEPTIC_PATH_FACTS_H

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
//  - DeclRef variable vs integer-constant comparisons are keyed, plus
//    ONE class of calls (2026-07-12): direct zero-argument calls whose
//    entire visible body is `return <integer literal>;` — such a
//    function cannot return anything else, so the correlation is
//    sound. Anything weaker (rand(), extern declarations, bodies that
//    read state) is NEVER keyed — that correlation would be wrong.
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
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

namespace codeskeptic {

// Canonical condition key: "var REL literal". REL is only EQ/LT/LE —
// NE/GT/GE reduce to these by flipping the value (X!=5 ≡ !(X==5)).
//
// MEMBER keys (2026-07-22, the rtp2httpd msrc_res / libgit2-battery
// family): `field` non-null keys a single dot-member of a local
// struct — "base.field REL literal" (`components.has_source`). The
// guard idiom `if (c.has_flag) produce; ... if (c.has_flag) consume;`
// is the struct-field twin of the flag correlation this layer exists
// for. Member keying is OPT-IN per analysis run via
// MemberFactScope — with no scope active, conditionFact never
// produces member keys and every other client is unchanged.
struct FactKey {
    const clang::ValueDecl* var = nullptr;
    clang::BinaryOperatorKind rel = clang::BO_EQ;  // BO_EQ | BO_LT | BO_LE
    int64_t literal = 0;
    const clang::ValueDecl* field = nullptr;  // dot-member of var, or null

    bool operator==(const FactKey& o) const {
        return var == o.var && rel == o.rel && literal == o.literal &&
               field == o.field;
    }
    bool operator<(const FactKey& o) const {
        return std::tie(var, rel, literal, field) <
               std::tie(o.var, o.rel, o.literal, o.field);
    }
};

// Reduces a condition to a (key, value) pair: the returned bool is the
// key's value WHEN THE CONDITION IS TRUE. Example: `X != 5` gives
// {(X,EQ,5), false}. On a false edge the caller flips the value. A
// condition that cannot be keyed -> nullopt. `unkeyable`: decls whose
// value can change invisibly (see collectUnkeyableDecls) — never keyed.
//
// `ptrKeyable`: POINTER variables that may additionally be keyed as
// (var EQ 0) — truthiness and null-constant comparisons. Pointer keys
// exist to keep disjuncts SPLIT across the value-joins Clang builds
// for negated short-circuit conditions (the systemd assert shape:
// `if (_unlikely_(!(s || l <= 0)))` merges the s-path and the l-path
// BEFORE the branch, and only a fact difference survives that merge).
// The set is deliberately narrow (collectPtrFactDecls) — keying every
// pointer check would burn the disjunct cap on ordinary guards.
std::optional<std::pair<FactKey, bool>> conditionFact(
    const clang::Expr* cond,
    const std::set<const clang::ValueDecl*>& unkeyable,
    const std::set<const clang::ValueDecl*>& ptrKeyable);

std::optional<std::pair<FactKey, bool>> conditionFact(
    const clang::Expr* cond,
    const std::set<const clang::ValueDecl*>& unkeyable);

// PERMANENT keying bans — decls whose value can change without a
// visible assignment statement: address-taken locals (any call may
// write through the pointer) and assigned non-locals (globals/statics
// mutate through calls too; for the UNASSIGNED global the existing
// deliberate limit applies — see header comment). Plain assignments to
// LOCALS are no longer a ban: facts about them are erased/re-stamped
// flow-sensitively at the assignment statement (applyStmtFacts in
// GuardedDisjuncts.h) — v2b, 2026-07-12.
std::set<const clang::ValueDecl*> collectUnkeyableDecls(
    const clang::FunctionDecl* func);

// Stamping relevance: integer-typed LOCAL decls that appear in a
// keyable condition position somewhere in the function (compared with
// an integer constant, or used as a bare truth value). Only these are
// worth stamping at literal assignments — stamping every `n = 0`
// would burn the disjunct cap for nothing.
std::set<const clang::ValueDecl*> collectFactDecls(
    const clang::FunctionDecl* func);

// Pointer-keying relevance: pointer locals/params that share a
// short-circuit operator with an integer-keyable partner
// (`assert(s || l <= 0)` — s qualifies). See the ptrKeyable note on
// conditionFact for why this set stays narrow.
std::set<const clang::ValueDecl*> collectPtrFactDecls(
    const clang::FunctionDecl* func);

// The decl a statement ASSIGNS (=, compound, ++/--), if the target is
// a plain variable reference. DeclStmt initializations count. Facts
// keyed on it are stale after this statement.
const clang::ValueDecl* assignedDecl(const clang::Stmt* stmt);

// The (decl, value) pair when the statement assigns an integer
// constant to a plain variable: `x = 3`, `x = SOME_ENUM`,
// `int x = 0;`. nullopt for anything else.
std::optional<std::pair<const clang::ValueDecl*, int64_t>>
assignedIntLiteral(const clang::Stmt* stmt);

// TRUE-EDGE-ONLY fact (#87): when `cond` is `X < n` / `n > X` with
// BOTH operands unsigned and `n` a stable keyable var, returns the
// key `(n EQ 0)` — which on the condition's TRUE edge holds FALSE
// (n != 0), because nothing is unsigned-less-than zero. The caller
// applies it ONLY on the true edge; it must never be flipped onto the
// false edge (`X >= n` says nothing about n == 0), which is why it is
// separate from conditionFact. Refutes the `n == 0` disjunct of a
// loop body (`for (i=0; i<n; ++i)`) — the relational-requires escape
// and the file_access null+zero-length loop class.
std::optional<FactKey> unsignedStrictUpperBoundNonzero(
    const clang::Expr* cond,
    const std::set<const clang::ValueDecl*>& unkeyable);

// Public builder for a (var REL literal) fact key — the contract
// layer constructs keys for declared guards without an Expr in hand.
// Same canonicalization as conditionFact (EQ/LT/LE base + unsigned
// zero-identities). nullopt when the form carries no information
// (e.g. `u < 0` for unsigned u).
std::optional<std::pair<FactKey, bool>> compareFact(
    const clang::ValueDecl* var, clang::BinaryOperatorKind opc,
    int64_t literal);

// Whether existing facts contradict `key = wanted`. Exact-key facts
// compare directly; a stamped equality (var EQ a)=true additionally
// ANSWERS any key on the same var by evaluating `a REL lit` — this is
// how `have = 1` (stamped) decides a later `if (have)` (asked as
// (have EQ 0)=false). Unknown -> no contradiction.
bool factsContradict(const std::map<FactKey, bool>& facts,
                     const FactKey& key, bool wanted);

// --- Member fact keying (opt-in scope) ---
//
// DELIBERATE LIMIT, mirroring the global-variable one above: that a
// call may mutate an ESCAPED local struct through a retained alias is
// ignored. The bases admitted by collectMemberFactBases only escape as
// direct call arguments, and member facts are ERASED at every call
// that receives the base's address (the callee legitimately writes
// fields — that is what a parse(&c) is for); a callee STASHING the
// pointer for a later call to mutate through would hide a defect (FN
// direction), the same accepted trade as the keyed-globals limit.

// Local record (struct/union) variables admissible as member-fact
// bases: non-static, non-volatile locals whose address is taken ONLY
// as a direct call argument (any innermost `&c` / `&c.f` use outside
// a call argument position — stored, returned, arithmetic — bans the
// base; so does `volatile`).
std::set<const clang::VarDecl*> collectMemberFactBases(
    const clang::FunctionDecl* func, clang::ASTContext& ctx);

// RAII opt-in for member keys: while a scope object is alive,
// conditionFact keys dot-members of the given bases and the
// applyStmtFacts lifecycle stamps/erases them. Analyses that never
// set a scope see identical behavior to before.
class MemberFactScope {
public:
    explicit MemberFactScope(const std::set<const clang::VarDecl*>* bases);
    ~MemberFactScope();
    MemberFactScope(const MemberFactScope&) = delete;
    MemberFactScope& operator=(const MemberFactScope&) = delete;
};

// The active scope's base set (nullptr when no scope is active).
const std::set<const clang::VarDecl*>* activeMemberFactBases();

// `base.field` (dot access, base a scope-admitted local, field an
// integer-typed FieldDecl) -> {base, field}. nullopt otherwise or
// when no scope is active.
std::optional<std::pair<const clang::VarDecl*, const clang::ValueDecl*>>
memberFactRef(const clang::Expr* expr);

// Member-assignment lifecycle: `c.f = X` / `c.f op= X` / `c.f++` ->
// {base, field, literal-if-plain-int-constant-store}. Drives the
// erase-and-restamp in applyStmtFacts. nullopt when the statement is
// not a store to a scope-admitted dot-member.
struct MemberAssign {
    const clang::VarDecl* base = nullptr;
    const clang::ValueDecl* field = nullptr;
    std::optional<int64_t> literal;  // set only for `c.f = <int const>`
};
std::optional<MemberAssign> assignedMemberFact(const clang::Stmt* stmt);

// Innermost base VarDecl of an address-of argument (`&c`, `&c.f`,
// `&c.arr[i]`) — the erase trigger for call statements. nullptr when
// the expression is not an address-of rooted in a variable.
const clang::VarDecl* addrOfBaseVar(const clang::Expr* expr);

} // namespace codeskeptic

#endif // CODESKEPTIC_PATH_FACTS_H
