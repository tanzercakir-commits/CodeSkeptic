#ifndef CODESKEPTIC_ENGINE_ASSERTGUARDS_H
#define CODESKEPTIC_ENGINE_ASSERTGUARDS_H

// Vanished-assert recovery (AR.3).
//
// THE PROBLEM. A release build defines NDEBUG, so `assert(p != NULL)`
// preprocesses to `((void)0)` and curl's `DEBUGASSERT(p)` to nothing
// at all. The condition never reaches the parser, so it is not in the
// AST, so no CFG edge carries it, so every dereference after it reads
// as unguarded. Measured across the 2026-07-25 scan survey this is one
// FP FAMILY with five independent witnesses — curl (DEBUGASSERT), lua
// (lua_assert), sqlite / raylib / zstd (plain assert) — and the
// adjudicated proof case is zstd 1.5.6 zstd_compress.c:5505:
//
//     cdict = ZSTD_cwksp_reserve_object(&ws, sizeof(ZSTD_CDict));
//     assert(cdict != NULL);        // <- compiled out under NDEBUG
//     ZSTD_cwksp_move(&cdict->workspace, &ws);   // <- flagged
//
// WHAT WAS RULED OUT FIRST (both by measurement, not opinion):
//  - "the engine does not narrow asserts at all" — REFUTED. A LIVE
//    assert already narrows correctly through the ordinary CFG edge
//    (pinned by NullDerefRuleTest.LiveAssertNonNull_NarrowsClean).
//    Only the COMPILED-OUT ones are invisible.
//  - "just scan with assertions enabled" (-DENABLE_DEBUG=ON …) —
//    REFUTED. On curl 8.11.0 that turned 82 null-deref findings into
//    110: the define did silence ~181 sites (the mechanism works) but
//    it also switched on unrelated debug-only code that brought its
//    own noise. A build-define is a dirty switch, not a fix.
//
// WHAT THIS DOES. A PPCallbacks hook watches macro expansions. When an
// assert-like macro expands in a way that DISCARDS its condition, the
// argument's token spelling is parsed in a deliberately narrow set of
// shapes and recorded as a "virtual guard" at that source position.
// The dataflow engine then applies it to the first statement the
// assert dominated, exactly as if the condition had survived to the
// AST as a real guard.
//
// THE HONEST CAVEAT. Under NDEBUG the check does not execute, so this
// is not a soundness fix — it is a deliberate, declared decision to
// treat the author's assert as the invariant they said it was. Every
// serious analyzer makes this call; we make it explicitly and it can
// be turned off with --no-assert-recovery.
//
// WHY IT IS SAFE ANYWAY (the four gates every guard must pass):
//  1. The expansion must genuinely THROW THE CONDITION AWAY — the
//     macro body must not mention its first parameter. A live assert
//     mentions it and is skipped here; the AST already handles that
//     one. So this subsystem can never double-count or contradict the
//     ordinary path. The macro must also take EXACTLY ONE parameter
//     and not be variadic: a multi-argument assert states a RELATION
//     between its arguments, and argument 0 read alone is a different
//     claim — often the opposite one, as in `ASSERT_EQ(p, NULL)`.
//  2. The macro NAME must look like an assertion (case-insensitive
//     "assert", plus --assert-macros for the rest). `UNUSED(p)` also
//     discards its argument and must never mean "p is non-null". A
//     name announcing a NEGATIVE claim is vetoed by spelling — cmocka's
//     assert_null and Unity's TEST_ASSERT_NULL assert that the pointer
//     IS null, and believing one backwards inverts a proven fact. An
//     explicit --assert-macros entry overrides the veto, because there
//     the user supplies the meaning and the spelling stops being
//     evidence about it.
//  3. The argument must match a narrow token shape: `x`, `x != NULL`,
//     `NULL != x`, and `&&`-conjunctions of those. Any other token
//     (parenthesis, `->`, `*`, `!`, `||`, a call) rejects the whole
//     record — a whitelist, not a blacklist.
//  4. Placement must be provably dominating: no label / computed goto
//     / try in the function, no case label in the enclosing block, the
//     macro must sit in a GAP between two statements of that block
//     (not inside one), and the target must be the first CFG element
//     of the next real statement. The target must not be a LOOP: a
//     guard re-fires every time the engine transfers its statement, but
//     an assert written before a loop ran once and dominates ENTRY
//     only, so attaching it to the loop would scrub clean a pointer
//     reassigned inside the body. Anything else drops the guard.
//
// The arity half of gate 1, the negative-name veto in gate 2 and the
// loop rejection in gate 4 were all added AFTER the implementation
// landed, by an adversarial review that read the code for what it
// believed rather than for what it did. Each closed a silent FALSE
// NEGATIVE that the original 33-test battery passed straight through —
// which is the honest measure of how much a green suite proves here.
// They are pinned in section C2 of tests/AssertRecoveryTest.cpp, each
// verified to FAIL on the pre-fix binary.
//
// Deliberately out of scope for v1 (each is a separate, pinned step):
// integer `!= 0` asserts (the div-by-zero twin), field and array
// subjects (`p->q`, `a[i]`), asserts nested inside another macro
// expansion, and the MCP warm-AST path (which has no preprocessor
// hook — see SourceManager::processAllOnWorker).

#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace clang {
class ASTContext;
class CompilerInstance;
class FunctionDecl;
class FieldDecl;
class SourceManager;
class Stmt;
class VarDecl;
} // namespace clang

namespace codeskeptic {

// A recovered guard: "this variable is non-null from here on". A
// one-hop member assertion also keeps the resolved field identity; the
// current null domain consumes the entailed base-pointer fact, while
// field-sensitive domains can consume the narrower subject later.
struct AssertGuard {
    enum class Kind { NonNull };
    Kind kind = Kind::NonNull;
    const clang::VarDecl* var = nullptr;
    const clang::FieldDecl* field = nullptr;
};

// --- Configuration ---

// --no-assert-recovery. Default: enabled.
void setAssertRecoveryEnabled(bool enabled);
bool assertRecoveryEnabled();

// --assert-macros <names>: EXTRA exact macro names to treat as
// assertions, for projects whose macro is not spelled "assert"
// (CHECK, VERIFY, ...). The built-in case-insensitive "assert"
// substring rule already covers assert / ASSERT / DEBUGASSERT /
// lua_assert / Q_ASSERT / SDL_assert / BOOST_ASSERT.
//
// A name listed here bypasses the negative-name veto of gate 2, which
// is what makes a genuine ASSERT_NOT_NULL usable — and equally what
// makes listing a macro that asserts a NEGATIVE (assert_null and
// friends) actively harmful. Do not list one.
void setExtraAssertMacros(std::set<std::string> names);
const std::set<std::string>& extraAssertMacros();

// --negative-assert-macros <names>: exact names that assert a NEGATIVE
// (the pointer IS null/empty/unset). The spelling heuristic vetoes the
// null-ness vocabulary (null, nil, empty, none, absent, missing, ...),
// but that list is inherently incomplete — a framework whose negative
// macro uses none of those words would be believed backwards. This is
// the escape hatch: a declared negative name is force-vetoed and wins
// over --assert-macros on conflict (over-vetoing costs only recall,
// inverting a fact costs correctness).
void setNegativeAssertMacros(std::set<std::string> names);
const std::set<std::string>& negativeAssertMacros();

// True if `name` is treated as an assert-like macro.
bool isAssertMacroName(const std::string& name);

// --- Preprocessor side ---

// Installs the PPCallbacks hook and resets the per-TU record list.
// Called from every FrontendAction's CreateASTConsumer (production and
// the test harness) — it must run BEFORE preprocessing, which is why
// there is no equivalent on the warm-AST path.
void installAssertRecovery(clang::CompilerInstance& ci);

// Number of vanished asserts recorded in the current TU (diagnostics
// and tests; production code goes through AssertGuardCache).
unsigned recordedVanishedAssertCount();

// --- Consumer side ---

// Attachment map for one function: the statement a guard fires on ->
// the guards that fire there.
using AssertGuardMap =
    std::unordered_map<const clang::Stmt*, std::vector<AssertGuard>>;

// Per-function cache of recovered guards, built lazily from the
// records the preprocessor left behind. Empty (and cheap) for every
// function that contains no vanished assert — the overwhelming
// majority.
class AssertGuardCache {
public:
    static AssertGuardCache& instance();

    const AssertGuardMap& get(const clang::FunctionDecl* func,
                              clang::ASTContext& ctx);

    void clear();

private:
    AssertGuardCache() = default;
    std::unordered_map<const clang::FunctionDecl*, AssertGuardMap> cache_;
    AssertGuardMap empty_;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_ENGINE_ASSERTGUARDS_H
