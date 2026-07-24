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
