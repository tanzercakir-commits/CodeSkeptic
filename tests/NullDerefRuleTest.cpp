#include "TestHelper.h"
#include "rules/NullDerefRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// --- Definite null dereference ---

TEST(NullDerefRuleTest, DefiniteNullDeref) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = nullptr;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "null-deref");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_EQ(results[0].function, "f");  // Juliet scoring relies on this
}

TEST(NullDerefRuleTest, ZeroLiteralInit) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = 0;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(NullDerefRuleTest, ArrowDeref) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Node { int data; };
        void f() {
            Node* n = nullptr;
            int x = n->data;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(NullDerefRuleTest, SubscriptDeref) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* a = nullptr;
            int x = a[0];
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(NullDerefRuleTest, AssignNullInsideGuard) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int* p) {
            if (p) {
                p = nullptr;
                int x = *p;
            }
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

// --- Possible null (MaybeNull) ---

TEST(NullDerefRuleTest, MaybeNull_Warning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int v = 1;
            int* p = nullptr;
            if (c) p = &v;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// --- Guards: the old NullPointerRule's FP graveyard ---

TEST(NullDerefRuleTest, TruthinessGuard_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int v = 1;
            int* p = nullptr;
            if (c) p = &v;
            if (p) {
                int x = *p;
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, EarlyReturnGuard_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int v = 1;
            int* p = nullptr;
            if (c) p = &v;
            if (!p) return;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, NotEqualGuard_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = nullptr;
            if (p != nullptr) {
                int x = *p;
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, EqualsNullGuard_DefiniteError) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int* p) {
            if (p == nullptr) {
                int x = *p;
            }
        }
    )");
    // Dereference on the true branch of p == nullptr: definite error
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(NullDerefRuleTest, ShortCircuitAnd_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Node { int data; };
        void f(Node* n) {
            if (n && n->data > 0) {
                int x = n->data;
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, WhileGuard_ErrorAfterLoop) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Node { int data; Node* next; };
        void f(Node* n) {
            while (n) {
                n = n->next;
            }
            int x = n->data;
        }
    )");
    // Inside the loop n is NonNull (clean); on loop exit n is definitely null
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

// --- Conservatism: unknown stays silent ---

TEST(NullDerefRuleTest, ParamUnguarded_Silent) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int* p) {
            int x = *p;
        }
    )");
    // Parameter is Unknown -> no report. This was the old rule's 68-FP trap.
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, AssignAddressOf_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int v = 1;
            int* p = nullptr;
            p = &v;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, AssignNew_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = nullptr;
            p = new int(5);
            int x = *p;
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, OutParamEscape_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void init(int** pp);
        void f() {
            int* p = nullptr;
            init(&p);
            int x = *p;
        }
    )");
    // &p went into a function -> p Unknown -> silent (conservative)
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, LinkedListBuildLoop_WarningNotError) {
    // The cJSON parse_array pattern: cur is assigned on the then-branch
    // in the first iteration and dereferenced on the else-branch in
    // later ones. Since the head/cur correlation is not tracked,
    // MaybeNull (Warning) is honestly reported — but calling it
    // "definitely null" (Error) from the early pre-fixpoint state WAS
    // wrong (engine regression test).
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Node { Node* next; };
        void f(int n) {
            Node* head = nullptr;
            Node* cur = nullptr;
            for (int i = 0; i < n; i++) {
                Node* item = new Node;
                if (head == nullptr) {
                    head = item;
                    cur = item;
                } else {
                    cur->next = item;
                    cur = item;
                }
            }
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);  // NOT Error
}

TEST(NullDerefRuleTest, OpaqueFunctionReturn_Silent) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* make();
        void f() {
            int* p = make();
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- Targeted path sensitivity (GuardedDisjuncts) ---

TEST(NullDerefPathSensitivityTest, CorrelatedGuards_AssignDeref_Clean) {
    // The Juliet int_07/08/09 pattern: assignment and dereference are
    // under the same invariant condition — no "may be null" FP must arise
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int flag;
        void f() {
            int v = 1;
            int* data = nullptr;
            if (flag) data = &v;
            if (flag) { int x = *data; (void)x; }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefPathSensitivityTest, AntiCorrelatedGuards_ErrorStays) {
    // Dereference on the wrong branch: on the flag==0 path data is
    // definitely null
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int flag;
        void f() {
            int v = 1;
            int* data = nullptr;
            if (flag) data = &v;
            if (!flag) { int x = *data; (void)x; }
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(NullDerefPathSensitivityTest, PointerGuardStillWorks_WithFacts) {
    // Int facts work together with pointer nullness refinement:
    // both the flag correlation and the if(p) guard in the same function
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int flag;
        int* make();
        void f() {
            int v = 1;
            int* data = nullptr;
            if (flag) data = &v;
            if (data) { int x = *data; (void)x; }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(NullDerefRuleTest, MultiDeclaration_SecondPointerTracked) {
    // The old "known FN" note turned out invalid: the fine-grained CFG
    // splits a multi-declaration into per-variable synthetic DeclStmts —
    // the second pointer is tracked too. Pinned as a regression test.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f() {
            int *a = nullptr, *b = nullptr;
            int x = *b;
            (void)x; (void)a;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(NullDerefTraceTest, GuardOnlyNull_TraceShowsCondition) {
    // Trace v2: a definite-null coming purely from a guard, with no
    // assignment, used to have NO trace — now the condition point shows
    // up with a "null on this branch" note
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void f(int* p) {
            if (p == 0) {
                int x = *p;
                (void)x;
            }
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
    ASSERT_FALSE(results[0].notes.empty());
    EXPECT_NE(results[0].notes[0].message.find("null on this branch"),
              std::string::npos);
    // The note must point to the condition's line (not the dereference's)
    EXPECT_LT(results[0].notes[0].line, results[0].line);
}

TEST(AbseilFpTest, RawCheckShape_BuiltinExpect_Clean) {
    // The abseil ABSL_RAW_CHECK family: __builtin_expect wraps a
    // negated conjunction and the failure branch TERMINATES (RAW_LOG
    // FATAL ends in a noreturn trap). The short-circuit value blocks
    // inside the call refine "null" facts; without expect-transparency
    // the if-edges could not correct them and the fact leaked into the
    // continue path (8 findings from one check in low_level_alloc.cc).
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void rawlog(const char* m);
        int* getq();
        int f(int* p) {
            if (__builtin_expect(!(p != nullptr && p != getq()), 0)) {
                rawlog("boom");
                __builtin_trap();
            }
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AbseilFpTest, RawCheckShape_NonTerminatingBranch_StillWarns) {
    // The flip side: if the failure branch does NOT terminate, the
    // null path genuinely reaches the dereference — the warning is
    // correct and must stay.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void rawlog(const char* m);
        int* getq();
        int f(int* p) {
            if (__builtin_expect(!(p != nullptr && p != getq()), 0)) {
                rawlog("boom");
            }
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(AbseilFpTest, BuiltinExpect_GuardStillRefines_BothDirections) {
    // Transparency works in the positive direction too: unlikely(!p)
    // early-return leaves p non-null afterwards; and the null branch
    // is still caught when dereferenced inside.
    NullDerefRule rule;
    auto clean = runRule(rule, R"(
        int f(int* p) {
            if (__builtin_expect(p == nullptr, 0)) return -1;
            return *p;
        }
    )");
    EXPECT_EQ(clean.size(), 0);

    auto bad = runRule(rule, R"(
        int f(int* p) {
            if (__builtin_expect(p == nullptr, 0)) {
                return *p;
            }
            return 0;
        }
    )");
    ASSERT_EQ(bad.size(), 1);
    EXPECT_EQ(bad[0].severity, Severity::Error);
}

// --- shadPS4 FP hunt (2026-07-12): call-boundary soundness ---

TEST(ShadPS4FpTest, RefOutParam_InvalidatesNullFact) {
    // The ResolveEpollBinding pattern: `int* p = nullptr; f(id, p);`
    // where f takes `int*&` — the callee may rebind p, so the
    // "definitely null" fact must die at the call.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        bool resolve(int id, int*& out);
        int f(int id) {
            int* p = nullptr;
            if (!resolve(id, p)) {
                return -1;
            }
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ShadPS4FpTest, ValueParam_DefiniteNullStaysReported) {
    // The flip side (and a REAL shadPS4 bug, usb_backend.h): passing a
    // null pointer BY VALUE cannot rebind the caller's variable — the
    // deref after the call is still definitely null.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Desc { int maxPacket; };
        int fill(Desc* d);
        int f() {
            Desc* desc = nullptr;
            int r = fill(desc);
            if (r < 0) { return -1; }
            return desc->maxPacket;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(ShadPS4FpTest, ConstRefParam_DefiniteNullStaysReported) {
    // A const reference cannot rebind the argument either.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void peek(int* const& p);
        int f() {
            int* p = nullptr;
            peek(p);
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(ShadPS4FpTest, DerefInsideAndGuard_StillCaught) {
    // A REAL shadPS4 bug (savedata.cpp): `if (m == nullptr &&
    // m->dirName != nullptr)` — when m IS null the && evaluates
    // m->dirName. The short-circuit true-edge makes it definite.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Mount { const char* dirName; };
        int f(const Mount* mount) {
            if (mount == nullptr && mount->dirName != nullptr) {
                return -1;
            }
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

// --- libgit2 FP hunt (2026-07-12): assignment inside condition ---

TEST(LibGit2FpTest, AssignInCondition_EqNull_Refines) {
    // The dominant libgit2 pattern: `if ((dup = f()) == NULL) return;`
    // — the guard tests the just-assigned value; after it, dup is
    // non-null on the continue path.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g;
        int* f(int c) {
            if (c) return nullptr;
            return &g;
        }
        int use(int c) {
            int* dup;
            if ((dup = f(c)) == nullptr)
                return -1;
            return *dup;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(LibGit2FpTest, AssignInCondition_BangForm_Refines) {
    // The pool.c shape: `if (over || !(page = alloc())) return NULL;`
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Page { int size; };
        Page* alloc(unsigned long n);
        int f(bool over, unsigned long n) {
            Page* page;
            if (over || !(page = alloc(n)))
                return -1;
            return page->size;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(LibGit2FpTest, AssignInCondition_WhileForm_Refines) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Entry { int v; };
        Entry* next();
        int sum() {
            Entry* e;
            int total = 0;
            while ((e = next()) != nullptr) {
                total += e->v;
            }
            return total;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(LibGit2FpTest, AssignInCondition_NullBranchDeref_StillCaught) {
    // The flip side: inside the == NULL branch the variable IS null —
    // a dereference there must stay a definite error.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g;
        int* f(int c) {
            if (c) return nullptr;
            return &g;
        }
        int use(int c) {
            int* p;
            if ((p = f(c)) == nullptr)
                return *p;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

// --- llama.cpp FP hunt (2026-07-12): defensive ternary is not a guard ---

TEST(LlamaFpTest, DefensiveTernary_NoMaybeNullAfterJoin) {
    // The GGML_TENSOR_LOCALS shape: `ne0 = p ? p->x : 0;` — a value
    // selection, not a guard. Its edges carry tautological information
    // ("p is null or non-null"); after the immediate rejoin they must
    // not downgrade Unknown to a reportable MaybeNull.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { long ne[4]; char* data; };
        long f(T* src0) {
            const long ne00 = (src0) ? (src0)->ne[0] : 0;
            return ne00 + (long)*src0->data;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(LlamaFpTest, IfGuard_CheckThenUse_StillWarns) {
    // The flip side: a real statement-level guard keeps refining.
    // Check-then-unguarded-use stays reportable.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        void log_warn();
        int f(T* p) {
            if (p == nullptr) {
                log_warn();
            }
            return p->x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(LlamaFpTest, TernaryArmDeref_NotFlagged) {
    // Inside the arms the variable is Unknown (no refinement) — the
    // true arm's own dereference stays silent, as before.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { long ne[4]; };
        long f(T* p, bool c) {
            long a = c ? 1 : 2;
            long b = (p) ? (p)->ne[1] : 0;
            return a + b;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- Report-flood dedup (2026-07-12): one warning per variable ---

TEST(ReportDedupTest, WarningFlood_CollapsesToOneFinding) {
    // The internal__Foprep shape: one MaybeNull origin, many derefs —
    // ONE report; the rest become "also dereferenced here" notes.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct F { int a; int b; int c; };
        void set_err();
        int f(F* file) {
            if (file == nullptr) {
                set_err();
            }
            int x = file->a;
            int y = file->b;
            int z = file->c;
            return x + y + z;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
    bool hasAlso = false;
    for (const auto& n : results[0].notes)
        if (n.message.find("also dereferenced") != std::string::npos)
            hasAlso = true;
    EXPECT_TRUE(hasAlso);
}

TEST(ReportDedupTest, IndependentVariables_StillTwoFindings) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct F { int a; };
        void warn();
        int f(F* p, F* q) {
            if (p == nullptr) { warn(); }
            if (q == nullptr) { warn(); }
            return p->a + q->a;
        }
    )");
    ASSERT_EQ(results.size(), 2);
}

TEST(ReportDedupTest, DefiniteErrors_KeepPerLineGranularity) {
    // Errors are rare and each site matters — no dedup.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct F { int a; int b; };
        int f() {
            F* p = nullptr;
            int x = p->a;
            int y = p->b;
            return x + y;
        }
    )");
    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_EQ(results[1].severity, Severity::Error);
}

// --- Pointer relational comparison proves validity (systemd FOREACH_ARRAY) ---
//
// C11 6.5.8p5: `p < q` is defined only when both point into (one past)
// the same object; null never does. Evaluating the comparison therefore
// proves both operands non-null — on both edges. systemd's FOREACH_ARRAY
// loop condition `end && i < end` was the dominant scan FP family
// (235 of 302 null findings): the macro's own defensive `i &&` check
// creates the may-be-null evidence, the ternary join keeps it, and the
// loop condition used to refine only `end`.

TEST(ForeachArrayFpTest, ExactMacroShape_NoWarning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct item { int value; };
        int sum(item* items, int n) {
            int total = 0;
            for (__typeof__(items[0])* i = (items), *_end_ = ({
                         __typeof__(n) _m_ = (n);
                         (i && _m_ > 0) ? i + _m_ : nullptr;
                 }); _end_ && i < _end_; i++)
                total += i->value;
            return total;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(ForeachArrayFpTest, OpenCodedShape_NoWarning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct item { int value; };
        int sum(item* items, int n) {
            int total = 0;
            for (item* i = items, *end = (i && n > 0) ? i + n : nullptr;
                 end && i < end; i++)
                total += i->value;
            return total;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(ForeachArrayFpTest, RelationalProvesBothOperands) {
    // The walk reports BOTH sides of `a < b` (variable-on-left
    // normalization used to drop the right side entirely).
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int f(int* a, int* b) {
            if (!a || !b) { }
            if (a < b) return *a + *b;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

TEST(ForeachArrayFpTest, NullLiteralOrdering_DoesNotBless) {
    // Ordering against the null constant carries no validity proof —
    // the definite-null error must survive.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int f(int* p) {
            if (p == nullptr) {
                if (p > (int*)0) return *p;
            }
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(ForeachArrayFpTest, PostLoopDeref_StillWarns) {
    // The proof holds only on paths THROUGH the comparison. The
    // zero-iteration path (end == nullptr short-circuits, `i < end`
    // never evaluated) keeps i possibly-null after the loop.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct item { int value; };
        int f(item* arr, int n) {
            item* i = arr;
            item* end = (i && n > 0) ? i + n : nullptr;
            while (end && i < end) i++;
            return i->value;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// --- #79: assert's ternary must not leak the null disjunct ---
//
// glibc's C++ assert expands to `static_cast<bool>(expr) ? void(0)
// : __assert_fail(...)`. Two transparency requirements meet here:
// the EXPLICIT static_cast<bool> wrapper must be stripped by the
// condition digest (IgnoreParenImpCasts cannot see it), and the
// maybe-null disjunct born on the `&&`'s short-circuit edge must die
// in the noreturn arm instead of sailing into the guarded code (the
// ImGui SetCurrentFont FP family, 2026-07-16). Tests hand-write the
// expansion — runToolOnCode has no system headers.

namespace {
const char* kAssertTernaryPrelude = R"(
        [[noreturn]] void assert_fail(const char*);
        #define MYASSERT(e) \
            (static_cast<bool>(e) ? void(0) : assert_fail(#e))
        struct F { float scale; int loaded() const; };
)";
} // namespace

TEST(AssertTernaryTest, CompoundAssertAfterGuard_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kAssertTernaryPrelude) + R"(
        void f(F* font) {
            if (font != nullptr) {
                MYASSERT(font && font->loaded());
                float s = font->scale;
                (void)s;
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AssertTernaryTest, CompoundAssertNoGuard_Clean) {
    // The assert alone proves font non-null past it.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kAssertTernaryPrelude) + R"(
        void f(F* font) {
            MYASSERT(font && font->loaded());
            float s = font->scale;
            (void)s;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AssertTernaryTest, StaticCastBoolGuard_Clean) {
    // Transparency case 1: explicit conversion TO bool preserves
    // truthiness — the guard must refine through it.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct S { int v; };
        int f(S* p) {
            if (static_cast<bool>(p)) {
                return p->v;
            }
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AssertTernaryTest, AssertOnOtherVar_LeakStaysVisible) {
    // The assert proves only q; a deref of the UNGUARDED p must still
    // report — transparency must not over-suppress.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kAssertTernaryPrelude) + R"(
        void f(F* font, F* other) {
            MYASSERT(other && other->loaded());
            if (font == nullptr) {}
            float s = font->scale;
            (void)s;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

// --- #70: loop-invariant guard correlation at scale ---
//
// A pointer allocated + null-checked only under a flag, dereferenced
// later under the SAME flag, inside a loop whose body carries several
// independent conditions. The disjunct budget (kMaxDisjuncts) cannot
// hold the guard cross-product as explicit path splits; the widening
// correlation miner records "flag != 0 => ptr NonNull" as a
// per-variable implication instead, and the deref guard's assume-edge
// activates it. Clean/dirty pairs pin both directions.

namespace {
constexpr const char* kGuardPrelude = R"(
    extern "C" void* malloc(unsigned long);
    extern "C" void free(void*);
    extern int get(void);
)";
}

TEST(GuardImplicationTest, TgaShape_SingleGuardWithLoopNoise_Clean) {
    // The stb_image TGA loader shape (reduced): palette exists only
    // when `indexed`; the loop's RLE/read-next conditions used to
    // cross-multiply the disjuncts past the cap and the collapse
    // erased the correlation (7 spurious warnings from a 4-pointer
    // variant before the miner existed).
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kGuardPrelude) + R"(
        int f(int indexed, int is_rle, int rgb16, int n) {
            unsigned char *palette = 0;
            int rle_count = 0, read_next = 1, sum = 0, i;
            if (indexed) {
                palette = (unsigned char *)malloc(256);
                if (!palette) return -1;
            }
            for (i = 0; i < n; ++i) {
                if (is_rle) {
                    if (rle_count == 0) { rle_count = get(); read_next = 1; }
                } else {
                    read_next = 1;
                }
                if (read_next) {
                    if (indexed) {
                        sum += palette[i & 255];
                    } else if (rgb16) {
                        sum += get();
                    }
                    read_next = 0;
                }
                --rle_count;
            }
            if (palette) free(palette);
            return sum;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(GuardImplicationTest, FourIndependentGuards_Clean) {
    // 4 independently guarded pointers = 2^4 fact combinations — far
    // past kMaxDisjuncts. Four implications in ONE disjunct instead.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kGuardPrelude) + R"(
        int f(int fa, int fb, int fc, int fd, int n) {
            int *a = 0, *b = 0, *c = 0, *d = 0;
            int i, sum = 0;
            if (fa) { a = (int *)malloc(4); if (!a) return -1; }
            if (fb) { b = (int *)malloc(4); if (!b) return -1; }
            if (fc) { c = (int *)malloc(4); if (!c) return -1; }
            if (fd) { d = (int *)malloc(4); if (!d) return -1; }
            for (i = 0; i < n; ++i) {
                if (fa) sum += a[0];
                if (fb) sum += b[0];
                if (fc) sum += c[0];
                if (fd) sum += d[0];
            }
            free(a); free(b); free(c); free(d);
            return sum;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(GuardImplicationTest, CallInitializedGuardFlag_Clean) {
    // The guard flag is a local initialized from an opaque call (the
    // real TGA header parse), not a parameter — still keyable.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kGuardPrelude) + R"(
        int f(int n) {
            int indexed = get();
            int is_rle = get();
            unsigned char *palette = 0;
            int read_next = 1, sum = 0, i;
            if (indexed) {
                palette = (unsigned char *)malloc(256);
                if (!palette) return -1;
            }
            for (i = 0; i < n; ++i) {
                if (is_rle) { if (get()) sum += get(); }
                else read_next = 1;
                if (read_next) {
                    if (indexed) sum += palette[i & 255];
                    read_next = 0;
                }
            }
            free(palette);
            return sum;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(GuardImplicationTest, WrongGuard_StillWarns) {
    // b is guarded by fb but dereferenced under fa — a REAL bug the
    // miner must not silence (no fact partitions b's nullness on fa).
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kGuardPrelude) + R"(
        int f(int fa, int fb, int n) {
            int *a = 0, *b = 0;
            int i, sum = 0;
            if (fa) { a = (int *)malloc(4); if (!a) return -1; }
            if (fb) { b = (int *)malloc(4); if (!b) return -1; }
            for (i = 0; i < n; ++i) {
                if (get()) sum += get();
                if (get()) sum += get();
                if (get()) sum += get();
                if (fa) sum += b[0];
            }
            free(a); free(b);
            return sum;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(GuardImplicationTest, GuardReassignedInLoop_StillWarns) {
    // The guard variable changes between the check and the deref: the
    // implication is keyed on the assigned decl and must go stale.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kGuardPrelude) + R"(
        int f(int fa, int n) {
            int *a = 0;
            int i, sum = 0;
            if (fa) { a = (int *)malloc(4); if (!a) return -1; }
            for (i = 0; i < n; ++i) {
                if (get()) sum += get();
                if (get()) sum += get();
                if (get()) sum += get();
                fa = get();
                if (fa) sum += a[0];
            }
            free(a);
            return sum;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(GuardImplicationTest, PointerReassignedInLoop_StillWarns) {
    // The pointer itself is nulled on a loop path: any implication on
    // it drops with the assignment.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kGuardPrelude) + R"(
        int f(int fa, int n) {
            int *a = 0;
            int i, sum = 0;
            if (fa) { a = (int *)malloc(4); if (!a) return -1; }
            for (i = 0; i < n; ++i) {
                if (get()) sum += get();
                if (get()) sum += get();
                if (get()) sum += get();
                if (fa) sum += a[0];
                if (get() > 7) a = 0;
            }
            free(a);
            return sum;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(GuardImplicationTest, NoGuardAfterNoise_StillWarns) {
    // Unguarded deref after the same loop noise: nothing to activate.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kGuardPrelude) + R"(
        int f(int fa, int n) {
            int *a = 0;
            int i, sum = 0;
            if (fa) { a = (int *)malloc(4); if (!a) return -1; }
            for (i = 0; i < n; ++i) {
                if (get()) sum += get();
                if (get()) sum += get();
                if (get()) sum += get();
                sum += a[0];
            }
            free(a);
            return sum;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(GuardImplicationTest, UncheckedAllocUnderGuard_Warns) {
    // A maybe-null allocation with NO failure check: the guarded
    // deref is genuinely MaybeNull — the miner has no NonNull group
    // to mine from, so the warning must survive. This shape was
    // silent BEFORE #70 (a measured false negative on the CLI
    // pipeline); the sharper disjuncts now carry the MaybeNull to
    // the deref.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kGuardPrelude) + R"(
        int* mk() {
            if (get()) return nullptr;
            return new int(5);
        }
        int f(int fa) {
            int *a = 0;
            if (fa) a = mk();
            if (fa) return a[0];
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// Static locals initialize once per program, not per call (#86). The
// Godot GDCLASS double-checked lazy-init — `static T *inst = nullptr;
// static bool initialized = false; if (initialized) return *inst;` —
// used to produce a "definitely null" ERROR: the decl-inits were
// modeled as per-call assignment + per-call stamp, so the analysis saw
// a fresh NULL and an infeasible-made-feasible branch on every entry.
// Statics decay to Unknown at their DeclStmt (both the value and the
// fact stamp); mid-call assignments still track.
TEST(StaticLocalTest, DoubleCheckedLazyInit_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern T *make();
        T &get_static() {
            static T *inst = nullptr;
            static bool initialized = false;
            if (initialized) {
                return *inst;
            }
            inst = make();
            initialized = true;
            return *inst;
        }
    )");
    EXPECT_EQ(results.size(), 0);
}

// Control: a PLAIN local initialized null and dereferenced on a
// reachable path keeps its report — the exemption is scoped to static
// storage duration, not to null decl-inits in general.
TEST(StaticLocalTest, PlainLocalNullInit_StillReports) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern int get();
        int f() {
            T *p = 0;
            if (get()) return p->x;
            return 0;
        }
    )");
    ASSERT_GE(results.size(), 1);
}

TEST(GuardImplicationTest, RealTgaLoader_ImplicationWitness_Clean) {
    // The verbatim-shape stbi__tga_load pin (#84, the #70 residual).
    // The reduced tga shapes above pass WITHOUT the implication-
    // witness rule in the miner; this one does not: its prologue
    // tests `indexed` early (comp selection), so by the mid-loop
    // collapses every disjunct that still RECORDS an indexed fact
    // records `indexed == 0` — the indexed-side survives only inside
    // already-mined implications. A miner that demands a fresh
    // explicit recording as its witness discards the implication at
    // every such collapse, and the guarded deref in the pixel loop
    // decays to a spurious "may be null" (stb_image.h:6004, our
    // longest-lived real-world FP). Implication-carrying inputs count
    // as witnesses now; the FP is pinned dead.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kGuardPrelude) + R"(
        extern void skip(int n);
        extern int getn(unsigned char *p, int n);
        extern int get_comp(int bits, int grey, int *rgb16);

        int tga_load(int req_comp) {
            int offset = get();
            int indexed = get();
            int image_type = get();
            int is_rle = 0;
            int palette_start = get();
            int palette_len = get();
            int palette_bits = get();
            int width = get();
            int height = get();
            int bpp = get();
            int comp, rgb16 = 0;
            int inverted = get();
            unsigned char *data;
            unsigned char *palette = 0;
            int i, j;
            unsigned char raw[4] = {0};
            int rle_count = 0, rle_repeating = 0, read_next = 1;

            if (image_type >= 8) { image_type -= 8; is_rle = 1; }
            inverted = 1 - ((inverted >> 5) & 1);

            if (indexed) comp = get_comp(palette_bits, 0, &rgb16);
            else comp = get_comp(bpp, image_type == 3, &rgb16);
            if (!comp) return -1;

            data = (unsigned char *)malloc(width * height * comp);
            if (!data) return -2;
            skip(offset);

            if (!indexed && !is_rle && !rgb16) {
                for (i = 0; i < height; ++i)
                    getn(data + i * width * comp, width * comp);
            } else {
                if (indexed) {
                    if (palette_len == 0) { free(data); return -3; }
                    skip(palette_start);
                    palette = (unsigned char *)malloc(palette_len * comp);
                    if (!palette) { free(data); return -4; }
                    if (rgb16) {
                        unsigned char *pal_entry = palette;
                        for (i = 0; i < palette_len; ++i) {
                            if (get()) pal_entry[0] = 1;
                            pal_entry += comp;
                        }
                    } else if (!getn(palette, palette_len * comp)) {
                        free(data); free(palette); return -5;
                    }
                }
                for (i = 0; i < width * height; ++i) {
                    if (is_rle) {
                        if (rle_count == 0) {
                            int cmd = get();
                            rle_count = 1 + (cmd & 127);
                            rle_repeating = cmd >> 7;
                            read_next = 1;
                        } else if (!rle_repeating) {
                            read_next = 1;
                        }
                    } else {
                        read_next = 1;
                    }
                    if (read_next) {
                        if (indexed) {
                            int pal_idx = (bpp == 8) ? get() : get();
                            if (pal_idx >= palette_len) pal_idx = 0;
                            pal_idx *= comp;
                            for (j = 0; j < comp; ++j)
                                raw[j] = palette[pal_idx + j];
                        } else if (rgb16) {
                            raw[0] = (unsigned char)get();
                        } else {
                            for (j = 0; j < comp; ++j)
                                raw[j] = (unsigned char)get();
                        }
                        read_next = 0;
                    }
                    for (j = 0; j < comp; ++j) data[i * comp + j] = raw[j];
                    --rle_count;
                }
                if (inverted) {
                    for (j = 0; j * 2 < height; ++j) {
                        int index1 = j * width * comp;
                        int index2 = (height - 1 - j) * width * comp;
                        for (i = width * comp; i > 0; --i) {
                            unsigned char temp = data[index1];
                            data[index1] = data[index2];
                            data[index2] = temp;
                            ++index1; ++index2;
                        }
                    }
                }
                if (palette != 0) free(palette);
            }
            if (comp >= 3 && !rgb16) {
                unsigned char *pixel = data;
                for (i = 0; i < width * height; ++i) {
                    unsigned char temp = pixel[0];
                    pixel[0] = pixel[2]; pixel[2] = temp;
                    pixel += comp;
                }
            }
            free(data);
            return req_comp;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}
