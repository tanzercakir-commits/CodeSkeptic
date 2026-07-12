#include "TestHelper.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/NullDerefRule.h"
#include "rules/UninitPointerRule_Ex.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// Disjuncts v2b — cross-variable correlation (2026-07-12).
//
// Three mechanisms, each pinned here:
//  1. Per-block edge conditions (engine): the sub-condition a
//     short-circuit block actually evaluated reaches refineOnEdge —
//     `assert(s || l <= 0)` splits the state into disjuncts keyed on
//     (l <= 0) at the assert's join.
//  2. Fact lifecycle (applyStmtFacts): assignments to locals ERASE
//     facts keyed on them (the whole-function keying ban is gone);
//     integer-constant stores STAMP the fresh truth.
//  3. Entailment (factsContradict): a stamped (x EQ a)=true answers
//     any later key on x — `have = 1` decides `if (have)`.

namespace {
constexpr const char* kAssertPrelude = R"(
        [[noreturn]] void die();
        #define myassert(e) ((e) ? (void)0 : die())
)";
} // namespace

// --- The assert(ptr || len-condition) family (systemd, 18 sites) ---

TEST(DisjunctsV2bTest, AssertOrCorrelation_StableLen) {
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kAssertPrelude) + R"(
        int f(const char *s, long l) {
            myassert(s || l <= 0);
            if (l > 0)
                return s[l - 1];
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, AssertOrCorrelation_LenMutatedAfterUse) {
    // The old whole-function mutation ban would have killed the keying
    // because of the l-- AFTER the guarded use. Facts now die at the
    // assignment, not before it.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kAssertPrelude) + R"(
        int f(const char *s, long l) {
            myassert(s || l <= 0);
            int r = 0;
            if (l > 0)
                r = s[l - 1];
            l--;
            return r + (int)l;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, AssertOrCorrelation_SystemdNulstrLoop) {
    // The real strv_parse_nulstr_full shape: the counter is decremented
    // INSIDE the guarded loop, and the dereference happens again after
    // the loop under a fresh l > 0 test.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kAssertPrelude) + R"(
        int f(const char *s, long l) {
            myassert(s || l <= 0);
            while (l > 0 && s[l - 1] == 0)
                l--;
            if (l <= 0)
                return 0;
            return s[l - 1];
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

// --- The flag/status correlation family (rtp2httpd, fprime) ---

TEST(DisjunctsV2bTest, FlagCorrelation_NullDeref) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        char *my_dup(const char *);
        int f(int cond, const char *inp) {
            char *x = 0;
            int have = 0;
            if (cond && inp) {
                x = my_dup(inp);
                have = 1;
            }
            if (have)
                return x[0];
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, FlagCorrelation_EnumStatus) {
    // fprime shape: the status enum and the pointer travel together.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Buf { int size; };
        Buf *acquire();
        int f(int cond) {
            enum Status { ERROR = 0, OK = 1 };
            Buf *b = 0;
            Status st = ERROR;
            if (cond) {
                b = acquire();
                if (b) st = OK;
            }
            if (st == OK)
                return b->size;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, FlagCorrelation_MemoryLeak) {
    // The same correlation through the leak domain: without it, a
    // phantom "allocated but not freed" path survives the second if.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void *malloc(unsigned long);
        void free(void *);
        void f(int cond) {
            void *p = 0;
            int have = 0;
            if (cond) {
                p = malloc(8);
                have = 1;
            }
            if (have)
                free(p);
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, FlagCorrelation_UninitPointer) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        int g;
        int f(int cond) {
            int *p;
            int set = 0;
            if (cond) {
                p = &g;
                set = 1;
            }
            if (set)
                return *p;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

// --- Sharpening and soundness edges ---

TEST(DisjunctsV2bTest, StaleGuard_InfeasibleBranchSilent) {
    // `x = 6` between the guards makes the second `x == 5` branch
    // provably dead — the deref inside it must NOT be reported
    // (constant-propagation sharpening from the stamped fact).
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int *my_alloc();
        int f(int x) {
            int *p = 0;
            if (x == 5)
                p = my_alloc();
            x = 6;
            if (x == 5)
                return *p;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, RebindToSameConstant_KeepsDefiniteError) {
    // Erasure + restamp must not lose the ALWAYS-TAKEN branch: after
    // `x = 0` the second test is true on every path and the definite
    // null deref must keep its error severity.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int f(int c) {
            int *p = 0;
            int x = 0;
            if (c) x = 1;
            x = 0;
            if (x == 0) return *p;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(DisjunctsV2bTest, CompoundAssign_ErasesWithoutStamping) {
    // `x += 1` needs the old value — it must erase (x EQ 5) and stamp
    // nothing; the branch stays possible and the warning stays alive.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int *my_alloc();
        int f(int c) {
            int *p = 0;
            int x = 5;
            if (c) x += 1;
            if (x == 5) return *p;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(DisjunctsV2bTest, GlobalFlag_AssignedLocally_StaysUnkeyed) {
    // A global assigned in the function stays permanently unkeyable:
    // calls can also change it, so flow-erasure would be false
    // comfort. The correlation is NOT built and the conservative
    // warning stays — the documented FP-direction trade-off.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        char *my_dup(const char *);
        void touch();
        int g_have;
        int f(int cond, const char *inp) {
            char *x = 0;
            g_have = 0;
            if (cond && inp) {
                x = my_dup(inp);
                g_have = 1;
            }
            touch();
            if (g_have)
                return x[0];
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(DisjunctsV2bTest, CapOverflow_WidensWithoutCrash) {
    // Five stamped flags exceed kMaxDisjuncts; widening intersects the
    // facts and merges the maps. The correlation may be lost (warning
    // allowed) but the analysis must stay sound and converge.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        char *my_dup(const char *);
        int f(int c1, int c2, int c3, int c4, int c5, const char *inp) {
            char *x = 0;
            int f1 = 0, f2 = 0, f3 = 0, f4 = 0, f5 = 0;
            if (c1) f1 = 1;
            if (c2) f2 = 1;
            if (c3) f3 = 1;
            if (c4) f4 = 1;
            if (c5) { x = my_dup(inp); f5 = 1; }
            if (f5)
                return x[0];
            return 0;
        }
    )");
    // Sound either way; today the f5 disjunct survives widening often
    // enough — accept both outcomes, forbid crashes/false errors.
    for (const auto& d : results)
        EXPECT_EQ(d.severity, Severity::Warning);
}

// --- The systemd assert shape: value-materialized disjunction ---
//
// systemd's own assert is `if (_unlikely_(!(expr))) log_assert_failed(...)`.
// The `!!(!(...))` + __builtin_expect wrappers make Clang materialize
// the || as a VALUE: the operand paths join BEFORE the single branch,
// so the per-leaf edges of a plain `if (a || b)` never exist. Three
// mechanisms together keep the correlation: pointer-nullness facts
// ((s EQ 0) — collectPtrFactDecls gates them to disjunctions with a
// keyable partner) preserve the split across the value-join,
// disjunction elimination applies the surviving operand per disjunct,
// and convergence widening keeps the richer fact traffic terminating.

namespace {
constexpr const char* kSystemdAssertPrelude = R"(
        [[noreturn]] void log_assert_failed(const char*, const char*, int);
        #define _unlikely_(x) (__builtin_expect(!!(x), 0))
        #define myassert(expr)                                          \
            do {                                                        \
                if (_unlikely_(!(expr)))                                \
                    log_assert_failed(#expr, __FILE__, __LINE__);       \
            } while (0)
)";
} // namespace

TEST(DisjunctsV2bTest, SystemdAssertShape_Simple) {
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kSystemdAssertPrelude) + R"(
        int f(const char *s, long l) {
            myassert(s || l <= 0);
            if (l > 0)
                return s[l - 1];
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, SystemdAssertShape_NulstrLoop) {
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kSystemdAssertPrelude) + R"(
        int f(const char *s, long l) {
            myassert(s || l <= 0);
            while (l > 0 && s[l - 1] == 0)
                l--;
            if (l <= 0)
                return 0;
            return s[l - 1];
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, SystemdAssertShape_UnprotectedDerefStillWarns) {
    // The assert only proves s when the l-side is refuted; a deref on
    // a path where l <= 0 held keeps its warning.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kSystemdAssertPrelude) + R"(
        int f(const char *s, long l) {
            myassert(s || l <= 0);
            if (l <= 0)
                return s[0];
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// --- Comparator-ladder case exhaustion (libgit2 cmp functions) ---
//
// `if (!a && !b) ... if (!a && b) ... if (a && !b) ...` — falling
// through all three proves a AND b. Requires BOTH pointers to split
// disjuncts, so collectPtrFactDecls also gates pointer-pointer pairs
// sharing a short-circuit operator (self-guards like `p && p->x` stay
// ungated — the member side is not a bare pointer operand).

TEST(DisjunctsV2bTest, CmpLadder_FallthroughProvesBoth) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct D { const char *path; };
        int cmp(const char *, const char *);
        int f(const D *a, const D *b) {
            if (!a && !b) return 0;
            if (!a && b) return -1;
            if (a && !b) return 1;
            return cmp(a->path, b->path);
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, CmpLadder_ElseIfForm) {
    // The checkout.c shape: else-if chain instead of early returns.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct D { const char *path; };
        int cmp(const char *, const char *);
        int f(const D *a, const D *b) {
            if (!a && !b)
                return 0;
            else if (!a && b)
                return -1;
            else if (a && !b)
                return 1;
            else
                return cmp(a->path, b->path);
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, CmpLadder_SurvivingNullPathStillWarns) {
    // Over-blessing guard: when a b-is-null path SURVIVES to the
    // dereference (the b==0 rung falls through because a was
    // non-null), the gated pointer facts must not silence it. (An
    // INCOMPLETE ladder whose null-evidence paths all return stays
    // silent by design — parameters are Unknown without surviving
    // in-function evidence.)
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct D { int x; };
        int f(const D *a, const D *b) {
            if (b == 0 && a == 0)
                return 0;
            return b->x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// --- Template-parameter facts (llama.cpp ggml rms_norm FP) ---
//
// A non-type template parameter is a compile-time constant — the most
// stable fact key possible. Uninstantiated `if constexpr` reads as a
// runtime branch, so "set under the flag, used under the flag" needs
// the same-condition correlation just like any Juliet flow variant.

TEST(DisjunctsV2bTest, TemplateParam_SameGuardTwice_NoWarning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Tensor { float *data; };
        template <int FUSE>
        float f(Tensor *a, Tensor *b) {
            Tensor *src1 = nullptr;
            if (FUSE == 1) {
                src1 = b;
            }
            float acc = a->data[0];
            if (FUSE == 1) {
                acc += src1->data[0];
            }
            return acc;
        }
        float use(Tensor *a, Tensor *b) {
            return f<0>(a, b) + f<1>(a, b);
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, TemplateParam_DifferentGuards_StillWarns) {
    // Set under FUSE == 1 but used under FUSE != 2 — no correlation,
    // the possible-null dereference must stay reported.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Tensor { float *data; };
        template <int FUSE>
        float f(Tensor *a, Tensor *b) {
            Tensor *src1 = nullptr;
            if (FUSE == 1) {
                src1 = b;
            }
            float acc = a->data[0];
            if (FUSE != 2) {
                acc += src1->data[0];
            }
            return acc;
        }
        float use(Tensor *a, Tensor *b) {
            return f<0>(a, b) + f<1>(a, b);
        }
    )");
    EXPECT_GE(results.size(), 1);
}

// --- Unsigned zero-identities (the NASA fprime PriorityMemQueue FP) ---
//
// For an unsigned counter, `u <= 0` IS `u == 0` and `u > 0` IS
// `u != 0`. Un-canonicalized they split disjuncts on a phantom
// dimension (an "u <= 0 but u != 0" disjunct is unsatisfiable), real
// functions blow the disjunct cap, and the overflow widening erases
// exactly the correlated pointer fact the assert established.

TEST(DisjunctsV2bTest, UnsignedZeroIdentity_FprimeShape) {
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kAssertPrelude) + R"(
        typedef unsigned long FwSizeType;
        struct Cfg { FwSizeType numPriorities; };
        void* alloc_mem(FwSizeType);
        int configure(Cfg *cfgs, FwSizeType num, bool required) {
            myassert((cfgs != nullptr) || (num == 0));
            myassert(!(required && num == 0));
            if (num > 0) {
                void *used = alloc_mem(num);
                myassert(used != nullptr);
            }
            int total = 0;
            if (num > 0) {
                for (FwSizeType i = 0; i < num; ++i)
                    total += (int)cfgs[i].numPriorities;
            }
            return total;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(DisjunctsV2bTest, UnsignedNeverNegative_StillReported) {
    // `u < 0` is never true, so the guarded assignment never happens
    // and the deref IS a null dereference. The canonicalization keys
    // no fact for it (no per-edge information), so the report stays
    // at the conservative maybe-null severity — pruning the
    // impossible branch outright (upgrading this to a definite error)
    // is a possible future sharpening, pinned here as-is.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int *make();
        int f(unsigned n) {
            int *p = 0;
            if (n < 0)
                p = make();
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}
