// Vanished-assert recovery (AR.3) — the two-way pin battery.
//
// The subsystem's whole value is that it goes quiet on ONE narrow,
// provable shape. So every test here comes in a pair: what must fall
// silent, and — far more important — what must keep warning. A
// recovery that silences too much is worse than no recovery at all,
// because it silences findings we cannot see it silencing.
//
// The engine detail that makes these tests meaningful: under the test
// harness the macro really does expand away (TestHelper installs the
// PP hook exactly as production does), so these are not simulations —
// the condition is genuinely absent from the AST in every "compiled
// out" case below. The control tests prove it.

#include "TestHelper.h"
#include "engine/AssertGuards.h"
#include "rules/NullDerefRule.h"

#include <gtest/gtest.h>

using namespace codeskeptic;
using namespace codeskeptic::testing;

namespace {

// Recovery is global, process-wide state; a test that changes it must
// put it back or it poisons every test that runs after it.
struct RecoveryScope {
    bool prevEnabled;
    std::set<std::string> prevExtra;
    RecoveryScope()
        : prevEnabled(assertRecoveryEnabled()),
          prevExtra(extraAssertMacros()) {}
    ~RecoveryScope() {
        setAssertRecoveryEnabled(prevEnabled);
        setExtraAssertMacros(prevExtra);
    }
};

// The shared preamble: malloc is the noise source every case below
// builds on, because an unchecked malloc deref is the finding we are
// asking the assert to retire.
const char* kPrelude = R"(
    typedef unsigned long size_t;
    extern void* malloc(size_t);
)";

std::string src(const std::string& body) {
    return std::string(kPrelude) + body;
}

} // namespace

// =====================================================================
// A. THE CONTROL — without any assert, every case below must warn
// =====================================================================

TEST(AssertRecoveryTest, Control_UncheckedMallocWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        int f(void) {
            int* p = (int*)malloc(4);
            return *p;
        }
    )"));
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "null-deref");
}

// =====================================================================
// B. WHAT MUST FALL SILENT — the five ecosystem witnesses
// =====================================================================

// curl's DEBUGASSERT under a release build: the macro body is EMPTY.
// Nothing at all survives to the AST — not even `((void)0)`. This is
// the shape that rules out every token-recovery approach and forces
// PPCallbacks.
TEST(AssertRecoveryTest, CurlShape_EmptyBodyMacro_Silenced) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x)
        int f(void) {
            int* p = (int*)malloc(4);
            DEBUGASSERT(p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// Plain C assert under NDEBUG: the condition is discarded but a
// `((void)0)` expression statement remains.
TEST(AssertRecoveryTest, NdebugShape_VoidZeroBody_Silenced) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            assert(p != (void*)0);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// The two cases above paraphrase libc. These two use the REAL system
// header, so they pin what actually ships: glibc expands NDEBUG's
// assert to `(__ASSERT_VOID_CAST (0))` — a nested macro whose own name
// also matches the "assert" substring rule, with `0` as its argument.
// Both facts have to be survived, and only the real header proves it.
//
// Each carries its own control in the SAME snippet. Without one these
// would pass VACUOUSLY on a box with no system headers: a broken TU
// yields zero findings, which is exactly what a silenced assert looks
// like. The control makes header breakage fail loudly instead.
TEST(AssertRecoveryTest, RealGlibcAssertHeader_NdebugSilenced) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        #define NDEBUG 1
        #include <assert.h>
        #include <stdlib.h>
        int guarded(void) {
            int* p = (int*)malloc(4);
            assert(p != NULL);
            return *p;
        }
        int control(void) {
            int* q = (int*)malloc(4);
            return *q;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "null-deref");
    EXPECT_EQ(results[0].function, "control");
}

TEST(AssertRecoveryTest, RealCassertHeader_NullptrUnderNdebug_Silenced) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        #define NDEBUG 1
        #include <cassert>
        #include <cstdlib>
        int guarded() {
            int* p = static_cast<int*>(std::malloc(4));
            assert(p != nullptr);
            return *p;
        }
        int control() {
            int* q = static_cast<int*>(std::malloc(4));
            return *q;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "null-deref");
    EXPECT_EQ(results[0].function, "control");
}

TEST(AssertRecoveryTest, ReversedComparison_Silenced) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            assert((void*)0 != p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

TEST(AssertRecoveryTest, NullptrSpelling_Silenced) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            assert(p != nullptr);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// lua_assert / Q_ASSERT / SDL_assert: the case-insensitive "assert"
// substring rule covers every real-world spelling with no config.
TEST(AssertRecoveryTest, LuaSpelling_SubstringNameRule_Silenced) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define lua_assert(x) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            lua_assert(p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// A conjunction narrows EVERY subject, not just the first.
TEST(AssertRecoveryTest, Conjunction_NarrowsBothSubjects) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            int* q = (int*)malloc(4);
            assert(p != (void*)0 && q);
            return *p + *q;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// `A && B` entails BOTH conjuncts, so a conjunct we cannot parse is
// dropped on its own rather than poisoning the whole record. This is
// not a corner case — `assert(p != NULL && n > 0)` is how the idiom is
// actually written.
TEST(AssertRecoveryTest, MixedConjunction_KeepsTheUsableHalf) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(int n) {
            int* p = (int*)malloc(4);
            assert(p != (void*)0 && n > 0);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// ...but only when nothing disjoins ABOVE the conjunction. `x || p &&
// q` does NOT prove q, so a top-level `||` vetoes the entire record —
// per-conjunct dropping must not become per-conjunct believing.
TEST(AssertRecoveryTest, Gate3_DisjunctionAboveConjunction_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(int x) {
            int* p = (int*)malloc(4);
            assert(x || p);
            return *p;
        }
    )"));
    EXPECT_GE(results.size(), 1u);
}

// A cast is accepted only when it casts a NULL CONSTANT. `(void*)q`
// is a cast of a variable and proves nothing.
TEST(AssertRecoveryTest, Gate3_CastOfVariable_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            int* q = (int*)malloc(4);
            assert(p != (void*)q);
            return *p;
        }
    )"));
    EXPECT_GE(results.size(), 1u);
}

// The doubly-parenthesized spelling glibc's NULL expands to.
TEST(AssertRecoveryTest, ParenthesizedNullConstant_Silenced) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            assert(p != ((void*)0));
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// The very common switch shape: a BRACED case body. A function-level
// switch ban would have destroyed this; the rule is scoped to the
// innermost enclosing compound precisely so this keeps working.
TEST(AssertRecoveryTest, BracedCaseBody_Silenced) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(int k) {
            int* p = (int*)malloc(4);
            switch (k) {
            case 1: {
                assert(p);
                return *p;
            }
            }
            return 0;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// The assert dominates everything after it in its block, not just the
// next statement.
TEST(AssertRecoveryTest, GuardHoldsForRestOfBlock) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            assert(p);
            int a = *p;
            int b = *p;
            return a + b;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// A DeclStmt target: `int y = *p;` begins at `int`, but the
// dereference is transferred after it. Target selection walks CFG
// element order, not source order, so the guard still lands first.
TEST(AssertRecoveryTest, DeclStmtTarget_Silenced) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            assert(p);
            int y = *p;
            return y;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// =====================================================================
// C. WHAT MUST KEEP WARNING — the gates, one test each
// =====================================================================

// GATE 2 (name). UNUSED(p) also discards its argument. If the name
// rule ever loosens to "any macro that drops its arg", this test is
// what catches it — and the damage would be silent everywhere.
TEST(AssertRecoveryTest, Gate2_UnusedMacroIsNotAnAssert_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define UNUSED(x)
        int f(void) {
            int* p = (int*)malloc(4);
            UNUSED(p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 1u);
}

// GATE 3 (shape). `!p` asserts the OPPOSITE. Reading it as non-null
// would not merely lose a finding — it would record a false fact.
TEST(AssertRecoveryTest, Gate3_NegatedCondition_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            assert(!p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 1u);
}

// GATE 3. `a != b` says the pointers differ, not that either is
// non-null.
TEST(AssertRecoveryTest, Gate3_VarVersusVar_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            int* other = (int*)malloc(4);
            assert(p != other);
            return *p;
        }
    )"));
    EXPECT_GE(results.size(), 1u);
}

// GATE 3. A member subject is v1 out-of-scope. `->` is not in the
// token whitelist, so the record is rejected outright — and crucially
// the rejection is TOTAL: it must not silently degrade into a claim
// about the base pointer `s`.
TEST(AssertRecoveryTest, Gate3_MemberSubject_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        struct S { int* q; };
        int f(void) {
            struct S* s = (struct S*)malloc(8);
            assert(s->q);
            return *s->q;
        }
    )"));
    EXPECT_GE(results.size(), 1u);
}

// GATE 3. A call inside the assert can have side effects and is not a
// nullness claim about anything.
TEST(AssertRecoveryTest, Gate3_CallInsideAssert_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        extern int valid(void*);
        int f(void) {
            int* p = (int*)malloc(4);
            assert(valid(p));
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 1u);
}

// GATE 3. Disjunction: `p || q` proves neither one.
TEST(AssertRecoveryTest, Gate3_Disjunction_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            int* q = (int*)malloc(4);
            assert(p || q);
            return *p;
        }
    )"));
    EXPECT_GE(results.size(), 1u);
}

// GATE 4 (placement). A braceless loop body: the assert runs ZERO
// times when the loop is not entered, so it does not dominate the
// dereference after it.
TEST(AssertRecoveryTest, Gate4_BracelessLoopBody_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(int n) {
            int* p = (int*)malloc(4);
            while (n-- > 0) assert(p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 1u);
}

// GATE 4. A braceless if body: same reasoning, the shape a straddle
// check has to catch.
TEST(AssertRecoveryTest, Gate4_BracelessIfBody_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(int c) {
            int* p = (int*)malloc(4);
            if (c) assert(p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 1u);
}

// GATE 4. A goto can jump PAST the assert into the code it was
// supposed to protect. One label anywhere in the function is enough to
// give up — cheap, and the alternative is a dominance proof.
TEST(AssertRecoveryTest, Gate4_LabelInFunction_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(int c) {
            int* p = (int*)malloc(4);
            if (c) goto skip;
            assert(p);
        skip:
            return *p;
        }
    )"));
    EXPECT_GE(results.size(), 1u);
}

// GATE 4. Switch fallthrough with NO braces: control can enter at
// `case 2` without ever passing the assert.
TEST(AssertRecoveryTest, Gate4_SwitchFallthrough_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(int k) {
            int* p = (int*)malloc(4);
            switch (k) {
            case 1:
                assert(p);
            case 2:
                return *p;
            }
            return 0;
        }
    )"));
    EXPECT_GE(results.size(), 1u);
}

// GATE 4. Two variables share a name in nested scopes: the record
// carries only a SPELLING, so the subject is ambiguous and no claim is
// made.
TEST(AssertRecoveryTest, Gate4_ShadowedName_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(int c) {
            int* p = (int*)malloc(4);
            if (c) {
                int* q = (int*)malloc(4);
                (void)q;
            }
            {
                int* q = (int*)malloc(4);
                assert(q);
                return *q + *p;
            }
        }
    )"));
    // `q` is ambiguous by name, so its guard is dropped and its deref
    // still warns (as does p's).
    EXPECT_GE(results.size(), 1u);
}

// ---------------------------------------------------------------------
// C2. THE THREE THE FIRST BATTERY MISSED
//
// Everything above was written alongside the implementation, and all of
// it passed while the three bugs below were live. An adversarial review
// pass found them by reading the code for what it BELIEVED rather than
// for what it did. Each was a silent false negative — a real finding
// retired by an assert that did not say what the recovery thought it
// said — so each gets a permanent test here, in the section for what
// must keep warning.
// ---------------------------------------------------------------------

// BUG 1 (loop target). A guard is attached to a statement and re-applied
// every time the engine transfers it, but an assert placed BEFORE a loop
// ran once — it dominates loop ENTRY, not each iteration. Attaching it
// to the loop re-asserted the condition on every back edge, so a pointer
// reassigned in the body was scrubbed clean at the top of iteration two
// and its deref went quiet. `p` starts provably non-null so that the
// ONLY thing the assert can be silencing is the loop-carried malloc.
TEST(AssertRecoveryTest, Bug1_AssertBeforeWhile_LoopCarriedDerefStillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x)
        int g;
        int f(int n) {
            int total = 0;
            int* p = &g;
            DEBUGASSERT(p);
            while (n-- > 0) {
                total += *p;
                p = (int*)malloc(4);
            }
            return total;
        }
    )"));
    EXPECT_GE(results.size(), 1u);
}

// BUG 1, the other three loop forms. `while` was how it was found; the
// rejection has to cover every statement that can carry a back edge, or
// the bug simply moves to whichever one was left out. The C++ range-for
// is here because it is the one whose loop variable makes it look least
// like the others.
TEST(AssertRecoveryTest, Bug1_AssertBeforeDoForRangeFor_StillWarn) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x)
        int g;
        struct V { int* begin(); int* end(); };
        int with_do(int n) {
            int total = 0;
            int* p = &g;
            DEBUGASSERT(p);
            do {
                total += *p;
                p = (int*)malloc(4);
            } while (n-- > 0);
            return total;
        }
        int with_for(int n) {
            int total = 0;
            int* p = &g;
            DEBUGASSERT(p);
            for (int i = 0; i < n; ++i) {
                total += *p;
                p = (int*)malloc(4);
            }
            return total;
        }
        int with_range_for(V v) {
            int total = 0;
            int* p = &g;
            DEBUGASSERT(p);
            for (int x : v) {
                total += *p + x;
                p = (int*)malloc(4);
            }
            return total;
        }
    )"));
    EXPECT_GE(results.size(), 3u);
}

// BUG 2 (arity). A multi-argument assert states a RELATION between its
// arguments; argument 0 read alone is a different claim, and here the
// exact opposite one — `ASSERT_EQ(p, NULL)` asserts that p IS null, and
// taking `p` by itself recorded "p is non-null" and retired the true
// finding. gtest's `ASSERT_LT(p, q)` and message-first spellings like
// `ASSERT_MSG(msg, cond)` fail the same way, and all three are picked up
// by the name rule with no opt-in. Only the one-argument form has an
// argument that IS the condition.
TEST(AssertRecoveryTest, Bug2_MultiParamAssertMacros_StillWarn) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define ASSERT_EQ(a, b)
        #define ASSERT_LT(a, b)
        #define ASSERT_MSG(msg, cond)
        int inverted(void) {
            int* p = (int*)malloc(4);
            ASSERT_EQ(p, (void*)0);
            return *p;
        }
        int relational(void) {
            int* p = (int*)malloc(4);
            int* q = (int*)malloc(4);
            ASSERT_LT(p, q);
            return *p;
        }
        int message_first(void) {
            int* p = (int*)malloc(4);
            int* q = (int*)malloc(4);
            ASSERT_MSG(p, q != (void*)0);
            return *p;
        }
    )"));
    EXPECT_GE(results.size(), 3u);
}

// BUG 3 (negative names). The substring rule reads a NAME as evidence of
// a MEANING, and never asked what the assert claimed. cmocka's
// `assert_null`, Unity's `TEST_ASSERT_NULL`, CUnit's `CU_ASSERT_PTR_NULL`
// and Criterion's `cr_assert_null` all assert the pointer IS null.
// Believing one backwards suppressed a *definitely*-null finding — the
// `if (p) return 0;` below makes p null by proof, not by maybe — so this
// was not a lost warning but an inverted fact.
TEST(AssertRecoveryTest, Bug3_NegativeAssertNames_StillWarn) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define assert_null(x)
        #define TEST_ASSERT_FALSE(x)
        int cmocka_shape(void) {
            int* p = (int*)malloc(4);
            if (p) return 0;
            assert_null(p);
            return *p;
        }
        int unity_shape(void) {
            int* q = (int*)malloc(4);
            if (q) return 0;
            TEST_ASSERT_FALSE(q);
            return *q;
        }
    )"));
    EXPECT_GE(results.size(), 2u);
}

// The veto is a guess about SPELLING, so an explicit `--assert-macros`
// declaration overrides it: that is the only way to opt in a genuine
// non-null assert whose name happens to contain a vetoed word, such as
// `ASSERT_NOT_NULL`. The cost is that the same door admits a macro that
// asserts a negative, which is why the docs say not to list one. Pinned
// here so the precedence cannot be reversed by accident.
TEST(AssertRecoveryTest, Bug3_ExplicitDeclarationOverridesTheVeto) {
    NullDerefRule rule;
    RecoveryScope scope;
    setExtraAssertMacros({"ASSERT_NOT_NULL"});
    auto results = runRule(rule, src(R"(
        #define ASSERT_NOT_NULL(x)
        int f(void) {
            int* p = (int*)malloc(4);
            ASSERT_NOT_NULL(p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// =====================================================================
// C3. WHAT THE SECOND REVIEW FOUND — BUG 1 WAS ONLY HALF FIXED
// =====================================================================
//
// The loop rejection above asked "is the next STATEMENT a loop?". But
// the guard is never attached to that statement: it is attached to
// firstElementIn(), the earliest-evaluated CFG element anywhere inside
// it. The check tested one object and the guard landed on another, so
// anything standing between the two reopened the hole — a pragma, or a
// single pair of braces. Every test in section C2 stayed green because
// every one of them writes the loop DIRECTLY after the assert, which is
// the one shape where the two objects coincide.
//
// The rule is now asked of the object it is about: can the target be
// reached from the next statement WITHOUT passing through a loop? A
// target that cannot be located at all is dropped as well — placement
// that cannot be proven is precisely what gate 4 refuses to believe.
//
// In every case below `p` starts provably non-null (`&g`), so the ONLY
// finding recovery can be silencing is the deref of the may-fail malloc
// the body reassigns into it. Each was verified to FAIL on the pre-fix
// binary — i.e. each really does catch the bug it is named after.
// ---------------------------------------------------------------------

// A loop attribute is the realistic form: `#pragma clang loop` above a
// hot loop with an assert above that is ordinary in codecs and
// compression libraries. The pragma wraps the loop in an AttributedStmt,
// so `next` is no longer a loop by class while the target is still the
// loop condition. `_Pragma` is the same shape spelled for macros.
TEST(AssertRecoveryTest, Bug1b_LoopBehindPragma_StillWarns) {
    NullDerefRule rule;
    // Custom raw-string delimiter: the body below contains `)"`, which
    // would close an ordinary R"( ... )" literal in the middle of a
    // _Pragma argument.
    auto results = runRule(rule, src(R"CS(
        #define DEBUGASSERT(x)
        int g;
        int with_pragma(int n) {
            int total = 0;
            int* p = &g;
            DEBUGASSERT(p);
            #pragma clang loop unroll(disable)
            while (n-- > 0) {
                total += *p;
                p = (int*)malloc(4);
            }
            return total;
        }
        int with_underscore_pragma(int n) {
            int total = 0;
            int* p = &g;
            DEBUGASSERT(p);
            _Pragma("clang loop unroll(disable)")
            while (n-- > 0) {
                total += *p;
                p = (int*)malloc(4);
            }
            return total;
        }
    )CS"));
    EXPECT_GE(results.size(), 2u);
}

// One pair of braces was enough. `{ while ... }` makes `next` a
// CompoundStmt, and nesting them changes nothing about where the guard
// lands — the target is still the loop's own condition. The `do` form is
// here because its condition sits at the BOTTOM, so the first element in
// range is a body statement instead, and the rejection has to hold for
// that path too.
TEST(AssertRecoveryTest, Bug1b_LoopBehindBraces_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x)
        int g;
        int braced_while(int n) {
            int total = 0;
            int* p = &g;
            DEBUGASSERT(p);
            {
                while (n-- > 0) {
                    total += *p;
                    p = (int*)malloc(4);
                }
            }
            return total;
        }
        int braced_do(int n) {
            int total = 0;
            int* p = &g;
            DEBUGASSERT(p);
            {
                do {
                    total += *p;
                    p = (int*)malloc(4);
                } while (n-- > 0);
            }
            return total;
        }
        int nested_braces_for(int n) {
            int total = 0;
            int* p = &g;
            DEBUGASSERT(p);
            {
                {
                    for (int i = 0; i < n; ++i) {
                        total += *p;
                        p = (int*)malloc(4);
                    }
                }
            }
            return total;
        }
    )"));
    EXPECT_GE(results.size(), 3u);
}

// The C++ range-for behind braces: its loop variable makes it the form
// least likely to be recognised by a class-based check, and it is the
// one whose first in-range CFG element is the range initialiser rather
// than a condition.
TEST(AssertRecoveryTest, Bug1b_BracedRangeFor_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x)
        int g;
        struct V { int* begin(); int* end(); };
        int braced_range_for(V v) {
            int total = 0;
            int* p = &g;
            DEBUGASSERT(p);
            {
                for (int x : v) {
                    total += *p + x;
                    p = (int*)malloc(4);
                }
            }
            return total;
        }
    )"));
    EXPECT_GE(results.size(), 1u);
}

// The other half of the rule, and the reason it cannot be written as
// "reject any next statement that CONTAINS a loop": here the assert
// genuinely dominates `total += *p`, which runs once, before the loop
// and outside it. Recovery must still fire. Without this pin the
// cheapest fix for the three tests above would quietly delete a whole
// class of legitimate recovery and no test would notice.
TEST(AssertRecoveryTest, Bug1b_StatementBeforeLoopStillRecovers) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x)
        int f(int n) {
            int total = 0;
            int* p = (int*)malloc(4);
            DEBUGASSERT(p);
            {
                total += *p;
                while (n-- > 0) total += n;
            }
            return total;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// =====================================================================
// C4. WHAT SQLITE MEASURED — THE REJECTION IS ABOUT THE VARIABLE
// =====================================================================
//
// The first real-codebase delta (sqlite, 125 TUs) surfaced the other
// half of gate 4. In convertToWithoutRowidTable() the guard for `pPk`
// did not vanish — it MOVED: baseline warned after the join
// (build.c:2536), recovery warned inside the branch (build.c:2468), at
// a deref sitting directly under an assert. Minimal repro (x5.c, 14
// lines): an if/else whose else-branch holds assert, then a loop that
// only READS the pointer, then a deref. The loop rejection fired on
// loop-ness alone and threw the guard away.
//
// The rejection exists because a guard attached inside a loop re-fires
// on the back edge, scrubbing a pointer REASSIGNED in the body. Re-firing
// a fact about a variable the loop never writes is harmless — the fact
// stays true on every iteration. So the question is not "is the target
// in a loop?" but "does that loop write THIS variable?" — asked per
// name, since one assert can cover several.
//
// "Write" is conservative: plain and compound assignment, ++/--,
// address-of, binding to a non-const reference, an unknown-signature
// call taking the variable, any appearance under an asm statement.
// ---------------------------------------------------------------------

// The x5 shape. The loop reads *p and passes p around by value and by
// const reference — none of which can change that p is non-null. The
// guard must survive; every deref here is assert-covered.
// (RED on the pre-fix binary: it warned at the first in-branch deref.)
TEST(AssertRecoveryTest, Sqlite_LoopInBranch_UnwrittenPointer_GuardSurvives) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x)
        void use_by_value(int* q);
        void look(int* const& q);
        int f(int k, int n) {
            int* p; int total = 0;
            if (k > 0) { p = (int*)malloc(4); DEBUGASSERT(p); }
            else {
                p = (int*)malloc(4);
                DEBUGASSERT(p);
                for (int i = 0; i < n; ++i) {
                    total += *p;
                    use_by_value(p);
                    look(p);
                }
                total += *p;
            }
            DEBUGASSERT(p);
            return total + *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// Every way the loop CAN write the pointer, one function each: plain
// reassignment (the `next`-walk class), pointer arithmetic via compound
// assignment, address-of handed to a callee, and binding to a non-const
// reference — the C++ shape that leaves no & in the source. In each the
// first-iteration deref of the may-fail malloc must keep warning: the
// guard would re-fire on the back edge over a pointer the body changes.
TEST(AssertRecoveryTest, Sqlite_LoopWritesThePointer_RejectionHolds) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x)
        void take_addr(int** out);
        void rebind(int*& r);
        int reassigned(int k, int n) {
            int* p; int total = 0;
            if (k > 0) { p = (int*)malloc(4); DEBUGASSERT(p); }
            else {
                p = (int*)malloc(4);
                DEBUGASSERT(p);
                for (int i = 0; i < n; ++i) { total += *p; p = (int*)malloc(4); }
            }
            return total;
        }
        int arithmetic(int n) {
            int* p = (int*)malloc(4);
            DEBUGASSERT(p);
            { for (int i = 0; i < n; ++i) { int t = *p; p += 1; (void)t; } }
            return 0;
        }
        int addr_taken(int n) {
            int* p = (int*)malloc(4);
            DEBUGASSERT(p);
            { for (int i = 0; i < n; ++i) { int t = *p; take_addr(&p); (void)t; } }
            return 0;
        }
        int ref_bound(int n) {
            int* p = (int*)malloc(4);
            DEBUGASSERT(p);
            { for (int i = 0; i < n; ++i) { int t = *p; rebind(p); (void)t; } }
            return 0;
        }
    )"));
    EXPECT_GE(results.size(), 4u);
}

// =====================================================================
// C5. WHAT CURL MEASURED — THE COMPOUND-BODY BLIND SPOT
// =====================================================================
//
// curl's default DEBUGASSERT erases to `do { } while(0)`
// (curl_setup_once.h) and the witness campaign measured the cost:
// recovery silenced ZERO of curl's 82 null-derefs while silencing the
// proven families in sqlite (6) and zstd (1). Cause: a location inside
// a macro body decomposes to the EXPANSION POINT, so the do-while's
// own `{ }` "contains" the expansion offset and innermostCompound
// picks it as the scope — an empty block with no next statement, and
// the record dies unplaced. GLib's G_STMT_START spelling is the same
// shape, which makes this the default idiom of a large part of the C
// ecosystem, not a curl quirk.
//
// The fix is one refusal: a CompoundStmt whose own begin location is a
// macro location cannot be the SCOPE — the scope is a block the assert
// stands IN, which is necessarily written in the file. (An assert
// whose every enclosing block comes from some other macro's expansion
// then finds no scope and is dropped — the standing v1 refusal for
// macro-inside-macro placement, unchanged.)
// ---------------------------------------------------------------------

// The curl shape, verbatim. (RED before the fix: the guard died
// unplaced and the deref warned.)
TEST(AssertRecoveryTest, CompoundBody_DoWhile_RecoversGuard) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x) do { } while(0)
        int f() {
            int* p = (int*)malloc(4);
            DEBUGASSERT(p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// The GLib spelling: the braces arrive through THREE macros. Same
// blind spot, same fix.
TEST(AssertRecoveryTest, CompoundBody_GLibStyle_RecoversGuard) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define G_STMT_START do
        #define G_STMT_END while(0)
        #define custom_assert(expr) G_STMT_START { (void) 0; } G_STMT_END
        int f() {
            int* p = (int*)malloc(4);
            custom_assert(p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// Composition control: the compound BODY must not weaken any other
// gate. Behind a do-while assert, a loop that rebinds the pointer
// still rejects the guard (gate 4, per variable) and the first-
// iteration deref of the may-fail malloc keeps warning.
TEST(AssertRecoveryTest, CompoundBody_LoopStillRejectsRebound) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x) do { } while(0)
        int f(int n) {
            int total = 0;
            int* p = (int*)malloc(4);
            DEBUGASSERT(p);
            while (n-- > 0) { total += *p; p = (int*)malloc(4); }
            return total;
        }
    )"));
    EXPECT_GE(results.size(), 1u);
}

// =====================================================================
// D. NO REGRESSION ON THE LIVE PATH (gate 1)
// =====================================================================

// A LIVE assert mentions its parameter, so the condition reaches the
// AST and the ordinary CFG edge narrows it — pinned by AR.1. The
// recovery must not fire here at all; if it did, it would be applying
// a second, unverified narrowing on top of a correct one.
TEST(AssertRecoveryTest, Gate1_LiveAssertUnchanged_NoDoubleHandling) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        extern void __assert_fail(const char*, const char*, unsigned,
                                  const char*) __attribute__((noreturn));
        #define assert(e) ((e) ? (void)0 : __assert_fail(#e,__FILE__,__LINE__,__func__))
        int f(void) {
            int* p = (int*)malloc(4);
            assert(p != (void*)0);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 0u);
}

// The other half of gate 1: a live assert whose condition is FALSE
// about nullness must not be turned into a non-null claim by the
// recovery path sneaking in behind it.
TEST(AssertRecoveryTest, Gate1_LiveAssertUnrelatedCondition_StillWarns) {
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        extern void __assert_fail(const char*, const char*, unsigned,
                                  const char*) __attribute__((noreturn));
        #define assert(e) ((e) ? (void)0 : __assert_fail(#e,__FILE__,__LINE__,__func__))
        int f(int n) {
            int* p = (int*)malloc(4);
            assert(n > 0);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 1u);
}

// =====================================================================
// E. THE CONFIG SURFACE
// =====================================================================

// --no-assert-recovery. The escape hatch the header promises has to
// actually restore the pre-AR.3 behavior, or the promise is a lie.
TEST(AssertRecoveryTest, Config_RecoveryDisabled_RestoresWarning) {
    RecoveryScope scope;
    setAssertRecoveryEnabled(false);
    NullDerefRule rule;
    auto results = runRule(rule, src(R"(
        #define DEBUGASSERT(x)
        int f(void) {
            int* p = (int*)malloc(4);
            DEBUGASSERT(p);
            return *p;
        }
    )"));
    EXPECT_EQ(results.size(), 1u);
}

// --assert-macros: a project whose macro is not spelled "assert" is
// silent only after opting in.
TEST(AssertRecoveryTest, Config_ExtraMacroName_OptIn) {
    RecoveryScope scope;
    const char* code = R"(
        #define VERIFY(x)
        int f(void) {
            int* p = (int*)malloc(4);
            VERIFY(p);
            return *p;
        }
    )";

    NullDerefRule ruleBefore;
    auto before = runRule(ruleBefore, src(code));
    EXPECT_EQ(before.size(), 1u) << "VERIFY must not be recognized by default";

    setExtraAssertMacros({"VERIFY"});
    NullDerefRule ruleAfter;
    auto after = runRule(ruleAfter, src(code));
    EXPECT_EQ(after.size(), 0u) << "--assert-macros VERIFY must recognize it";
}

TEST(AssertRecoveryTest, Config_NameRuleIsCaseInsensitive) {
    EXPECT_TRUE(isAssertMacroName("assert"));
    EXPECT_TRUE(isAssertMacroName("ASSERT"));
    EXPECT_TRUE(isAssertMacroName("DEBUGASSERT"));
    EXPECT_TRUE(isAssertMacroName("lua_assert"));
    EXPECT_TRUE(isAssertMacroName("Q_ASSERT"));
    EXPECT_TRUE(isAssertMacroName("SDL_assert"));
    EXPECT_TRUE(isAssertMacroName("BOOST_ASSERT"));
    EXPECT_FALSE(isAssertMacroName("UNUSED"));
    EXPECT_FALSE(isAssertMacroName("VERIFY"));
    EXPECT_FALSE(isAssertMacroName("CHECK"));
}

// =====================================================================
// F. THE MECHANISM ITSELF
// =====================================================================

// Direct evidence that the PP hook fires and that gate 1 filters on
// the macro BODY, not on the name: same name, two bodies, two answers.
TEST(AssertRecoveryTest, Mechanism_OnlyDiscardingBodiesAreRecorded) {
    NullDerefRule rule;

    runRule(rule, src(R"(
        #define assert(e) ((void)0)
        int f(void) {
            int* p = (int*)malloc(4);
            assert(p);
            return *p;
        }
    )"));
    EXPECT_GE(recordedVanishedAssertCount(), 1u)
        << "a discarding body must be recorded";

    NullDerefRule rule2;
    runRule(rule2, src(R"(
        extern void __assert_fail(const char*, const char*, unsigned,
                                  const char*) __attribute__((noreturn));
        #define assert(e) ((e) ? (void)0 : __assert_fail(#e,__FILE__,__LINE__,__func__))
        int f(void) {
            int* p = (int*)malloc(4);
            assert(p);
            return *p;
        }
    )"));
    EXPECT_EQ(recordedVanishedAssertCount(), 0u)
        << "a LIVE assert must never be recorded — the AST already has it";
}
