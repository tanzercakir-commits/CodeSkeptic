// Interprocedural v1 — function summaries:
//  - Return nullness: unguarded use of a "may return null" function
//    warns; guarded use is clean; a NeverNull chain stays silent.
//  - Parameter effects: free wrappers make double-free/UAF visible;
//    read-only helpers do not hide the leak behind them; storing/opaque
//    calls keep today's conservatism (no regression).
//  - Recursion produces no strong claims (soundness).

#include "TestHelper.h"
#include "engine/FunctionSummary.h"
#include "rules/DivByZeroRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/NullDerefRule.h"

#include <gtest/gtest.h>

#include <fstream>
#include <map>
#include <string>

using namespace codeskeptic;
using namespace codeskeptic::testing;

// ===================================================================
// Return nullness
// ===================================================================

TEST(InterprocNullTest, MaybeNullReturn_UnguardedDeref_Warning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* find(int key) {
            if (key < 0) return nullptr;
            return new int(key);
        }
        int use(int key) {
            int* p = find(key);
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
    // Trace: the source of the possibly-null assignment must be shown
    ASSERT_EQ(results[0].notes.size(), 1u);
    EXPECT_NE(results[0].notes[0].message.find("possibly-null"),
              std::string::npos);
}

TEST(InterprocNullTest, MaybeNullReturn_Guarded_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* find(int key) {
            if (key < 0) return nullptr;
            return new int(key);
        }
        int use(int key) {
            int* p = find(key);
            if (!p) return -1;
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocNullTest, NeverNullChain_Clean) {
    // a() is definitely non-null; b() chains a → b is NeverNull too.
    // The unguarded dereference must stay silent.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* a() { return new int(1); }
        int* b() { return a(); }
        int use() {
            int* p = b();
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocNullTest, MaybeNullChain_TwoLevels_Warning) {
    // May-return-null must leak through the chain: inner may return
    // null → so may outer
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* inner(int k) {
            if (k) return nullptr;
            return new int(1);
        }
        int* outer(int k) { return inner(k); }
        int use(int k) {
            int* p = outer(k);
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(InterprocNullTest, RecursiveReturn_StaysUnknown_Silent) {
    // A recursive function sees its own summary (starts Unknown) —
    // no NeverNull claim can form, but no MaybeNull is invented → silent
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* r(int n) {
            if (n > 0) return r(n - 1);
            return new int(0);
        }
        int use(int n) {
            int* p = r(n);
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocNullTest, VariableReturn_Unknown_Silent) {
    // A path returning a variable is Unknown in v1 — silent (documented limit)
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* pick(int* a, int* b, int c) {
            if (c) return a;
            return b;
        }
        int use(int* a, int* b, int c) {
            int* p = pick(a, b, c);
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// ===================================================================
// Parameter effects
// ===================================================================

TEST(InterprocLeakTest, FreeWrapper_DoubleFree_Error) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void my_free(int* p) { free(p); }
        void f() {
            int* q = (int*)malloc(4);
            my_free(q);
            my_free(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "double-free");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(InterprocLeakTest, GuardedFreeWrapper_StillFrees) {
    // The if (p) free(p) pattern also counts as Frees ("may free")
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void safe_free(int* p) { if (p) free(p); }
        void f() {
            int* q = (int*)malloc(4);
            safe_free(q);
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

TEST(InterprocLeakTest, FreeWrapperChain_TwoLevels) {
    // The w2 → w1 → free chain must be resolved by the fixed-point sweep
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void w1(int* p) { free(p); }
        void w2(int* p) { w1(p); }
        void f() {
            int* q = (int*)malloc(4);
            w2(q);
            w2(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(InterprocLeakTest, ReadOnlyCallee_LeakVisible) {
    // A read-only helper takes no ownership: the leak behind it MUST be
    // visible. (Escaped conservatism used to hide it — new detection.)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int read_value(const int* p) { return *p; }
        void f() {
            int* q = new int(7);
            int x = read_value(q);
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
    EXPECT_NE(results[0].message.find("q"), std::string::npos);
}

TEST(InterprocLeakTest, StoringCallee_NoLeakReport) {
    // A storing call may transfer ownership → Escaped (today's behavior)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int* g_slot = nullptr;
        void keep(int* p) { g_slot = p; }
        void f() {
            int* q = new int(7);
            keep(q);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocLeakTest, AliasingCallee_NowFrees_DoubleFree) {
    // The cJSON_Delete pattern: the parameter is taken into a local
    // cursor and freed. v2 alias tracking: cur is a clean alias of p →
    // delete_list = Frees → the double call is a double-free. (v1 was
    // conservatively silent.)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void delete_list(int* p) {
            int* cur = p;
            free(cur);
        }
        void f() {
            int* q = (int*)malloc(4);
            delete_list(q);
            delete_list(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_EQ(results[0].rule_id, "double-free");
}

// ===================================================================
// Alias tracking (v2)
// ===================================================================

TEST(InterprocAliasTest, CursorLoopWalk_RealCJSONDeleteShape) {
    // The real cJSON_Delete shape: the parameter is reassigned in a
    // loop and freed on every iteration. May-semantics: the first
    // iteration frees the original → Frees → use after the wrapper is
    // a UAF.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        struct Node { struct Node* next; };
        void delete_all(struct Node* item) {
            struct Node* next = nullptr;
            while (item != nullptr) {
                next = item->next;
                free(item);
                item = next;
            }
        }
        void f() {
            Node* list = (Node*)malloc(sizeof(Node));
            list->next = nullptr;
            delete_all(list);
            Node* again = list->next;
            (void)again;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

TEST(InterprocAliasTest, AliasChain_TwoHops_Frees) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void destroy(int* p) {
            int* a = p;
            int* b = a;
            free(b);
        }
        void f() {
            int* q = (int*)malloc(4);
            destroy(q);
            destroy(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(InterprocAliasTest, TaintedAlias_ImpureSource_Conservative) {
    // The alias is fed first from p, then from a tainted source → not
    // trackable → Stores → silent (a false Frees claim would breed FPs)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int* pick();
        void maybe_free(int* p, int c) {
            int* l = p;
            if (c) l = pick();
            free(l);
        }
        void f() {
            int* q = (int*)malloc(4);
            maybe_free(q, 0);
            maybe_free(q, 1);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocAliasTest, MultiParamAlias_Conservative) {
    // The same local is reachable from two parameters at once → cannot
    // be safely bound to either → both are Stores → silent
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void free_one(int* a, int* b, int c) {
            int* l = a;
            if (c) l = b;
            free(l);
        }
        void f() {
            int* q = (int*)malloc(4);
            int* r = (int*)malloc(4);
            free_one(q, r, 0);
            free_one(q, r, 0);
            free(r);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocAliasTest, AliasStoredToGlobal_Stores) {
    // The alias is written to a global → ownership may transfer →
    // Stores → NO leak report on the caller side (a false ReadsOnly FP
    // is prevented)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int* g_slot = nullptr;
        void keep_via_alias(int* p) {
            int* l = p;
            g_slot = l;
        }
        void f() {
            int* q = new int(7);
            keep_via_alias(q);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocAliasTest, AliasReturned_Stores) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int* identity(int* p) {
            int* l = p;
            return l;
        }
        void f() {
            int* q = new int(7);
            int* r = identity(q);
            (void)r;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocAliasTest, AddressTakenAlias_Conservative) {
    // The alias's address is taken → writable from outside → not trackable
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void reseat(int** pp);
        void weird_free(int* p) {
            int* l = p;
            reseat(&l);
            free(l);
        }
        void f() {
            int* q = (int*)malloc(4);
            weird_free(q);
            weird_free(q);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocAliasTest, ReadOnlyThroughAlias_LeakVisible) {
    // Read-only use must stay ReadsOnly through an alias as well:
    // the leak behind it is visible
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int peek(int* p) {
            int* l = p;
            return *l;
        }
        void f() {
            int* q = new int(7);
            int x = peek(q);
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(InterprocLeakTest, ExternalCallee_StillEscapes) {
    // A function with no visible body is Opaque → Escaped → silent (no
    // regression)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void unknown(int* p);
        void f() {
            int* q = new int(7);
            unknown(q);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocLeakTest, MutualRecursionParam_Conservative_Silent) {
    // Mutual recursion: the Opaque start settles at Stores — a strong
    // claim (Frees/ReadsOnly) cannot leak out of the recursion
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void r2(int* p, int n);
        void r1(int* p, int n) { if (n) r2(p, n - 1); }
        void r2(int* p, int n) { if (n) r1(p, n - 1); }
        void f() {
            int* q = new int(7);
            r1(q, 3);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocLeakTest, DeleteWrapper_UAF) {
    // A wrapper containing C++ delete is Frees too
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void destroy(int* p) { delete p; }
        void f() {
            int* q = new int(7);
            destroy(q);
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

// ===================================================================
// Cross-TU summaries (Horizon 2: whole-program mode)
// The callee is defined in ANOTHER file: the summary is harvested in
// pass 1; in pass 2 the rule sees the real summary in the calling file
// instead of Opaque.
// ===================================================================

TEST(CrossTUTest, MaybeNullReturn_AcrossTU_Warning) {
    NullDerefRule rule;
    auto results = runRuleCrossTU(rule, R"(
        int* find(int c) {
            static int v = 1;
            if (c) return &v;
            return 0;
        }
    )", R"(
        int* find(int c);
        void f(int c) {
            int* p = find(c);
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "null-deref");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(CrossTUTest, FreeWrapper_AcrossTU_DoubleFree) {
    MemoryLeakRule_Ex rule;
    auto results = runRuleCrossTU(rule, R"(
        extern "C" void free(void*);
        void my_free(int* p) { free(p); }
    )", R"(
        extern "C" void* malloc(unsigned long);
        void my_free(int* p);
        void f() {
            int* q = (int*)malloc(4);
            my_free(q);
            my_free(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "double-free");
}

TEST(CrossTUTest, ReadsOnlyCallee_AcrossTU_LeakVisible) {
    // A read-only helper in another file no longer HIDES the leak
    // (in single-TU mode it was Opaque -> Escapes -> silent)
    MemoryLeakRule_Ex rule;
    auto results = runRuleCrossTU(rule, R"(
        void use(int* p) { int x = *p; (void)x; }
    )", R"(
        extern "C" void* malloc(unsigned long);
        void use(int* p);
        void f() {
            int* q = (int*)malloc(4);
            use(q);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
}

TEST(CrossTUTest, StaticCallee_NotShared) {
    // The static (file-local) make in the callee TU and the caller TU's
    // extern declaration are DIFFERENT functions — the summary MUST NOT
    // travel. If it did, may-return-null would be claimed instead of
    // NeverNull...
    NullDerefRule rule;
    auto results = runRuleCrossTU(rule, R"(
        static int* make() { return 0; }
        int* unused() { return make(); }
    )", R"(
        int* make();
        void f() {
            int* p = make();
            int x = *p;
            (void)x;
        }
    )");
    // Must stay Opaque -> Unknown -> silent (conservative)
    ASSERT_EQ(results.size(), 0);
}

TEST(CrossTUTest, WithoutHarvest_StaysConservative) {
    // The same calling code in SINGLE-TU mode (no harvest): Opaque ->
    // silent. Control group for the cross-TU gain.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* find(int c);
        void f(int c) {
            int* p = find(c);
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// ===================================================================
// Return-nullness dataflow (v2): `return p;` paths
// Structural evaluation used to leave Unknown; the mini null-flow
// (using our own engine) resolves variable-returning paths
// flow-SENSITIVELY.
// ===================================================================

TEST(ReturnFlowTest, InitNullThenSet_NeverNull_Silent) {
    // FP-killer case: a flow-insensitive "NULL was assigned somewhere"
    // shortcut would wrongly produce MaybeNull here. Flow-sensitive: at
    // the return, p = &g is definitely non-null -> the function is
    // NeverNull -> silent.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g;
        int* get() {
            int* p = 0;
            p = &g;
            return p;
        }
        void f() {
            int* q = get();
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ReturnFlowTest, MaybeNullVarFlow_Warning) {
    // The find() pattern: r stays null on some paths -> MaybeNull ->
    // unguarded dereference warns + trace note
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g;
        int* find(int k) {
            int* r = 0;
            if (k) r = &g;
            return r;
        }
        void f(int k) {
            int* p = find(k);
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
    ASSERT_EQ(results[0].notes.size(), 1u);
    EXPECT_NE(results[0].notes[0].message.find("possibly-null"),
              std::string::npos);
}

TEST(ReturnFlowTest, GuardedFallthrough_NeverNull_Silent) {
    // Early-return guard: after `if (!p) return &fb;` p is definitely
    // non-null (assume-edge) -> both paths NonNull -> NeverNull
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g; int fb;
        int* wrap(int k) {
            int* p = 0;
            if (k) p = &g;
            if (!p) return &fb;
            return p;
        }
        void f(int k) {
            int* q = wrap(k);
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ReturnFlowTest, DefiniteNullVar_Warning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* bad() {
            int* p = 0;
            return p;
        }
        void f() {
            int* q = bad();
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ReturnFlowTest, ParamPassthrough_StaysUnknown_Silent) {
    // Parameter-sensitive summaries are out of v2 scope (documented
    // limit): `return p;` (p a param, never assigned) stays Unknown ->
    // silent
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* id(int* p) { return p; }
        void f(int* a) {
            int* q = id(a);
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ReturnFlowTest, ChainThroughVariable_Warning) {
    // Chain: inner is MaybeNull via variable flow; outer takes it into
    // a variable and returns it -> propagation across sweeps (sweep 2)
    // makes outer MaybeNull too
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int g;
        int* inner(int k) {
            int* r = 0;
            if (k) r = &g;
            return r;
        }
        int* outer(int k) {
            int* t = inner(k);
            return t;
        }
        void f(int k) {
            int* p = outer(k);
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ReturnFlowTest, JulietBadSourceShape_ParamReassignedNull_Warning) {
    // Verbatim Juliet flow-variant source: the parameter is assigned
    // NULL and returned -> MaybeNull -> the caller's unguarded use warns
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        int* badSource(int* data) {
            data = 0;
            return data;
        }
        void f(int* data) {
            data = badSource(data);
            int x = *data;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ReturnFlowTest, CrossTU_VarFlowMaybeNull_Warning) {
    // Variable-flow MaybeNull travels through the cross-TU store too
    NullDerefRule rule;
    auto results = runRuleCrossTU(rule, R"(
        int g;
        int* find(int k) {
            int* r = 0;
            if (k) r = &g;
            return r;
        }
    )", R"(
        int* find(int k);
        void f(int k) {
            int* p = find(k);
            int x = *p;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// ===================================================================
// Summary persistence (Cross-TU v2): saveGlobal / loadGlobal +
// --summary-out / --summary-in end to end.
// Invariants: (1) loading is behaviorally equivalent to harvesting,
// (2) a corrupt file is rejected as a whole — partial data cannot turn
// into a strong claim, (3) conflicting records merge conservatively.
// ===================================================================

#include "analyzer/StaticAnalyzer.h"
#include "config/Config.h"
#include "engine/FunctionSummary.h"

#include <chrono>
#include <filesystem>
#include <fstream>

namespace {

std::string writePersistFile(const std::string& name,
                             const std::string& content) {
    std::string path = ::testing::TempDir() + name;
    std::ofstream file(path);
    file << content;
    return path;
}

std::string readWholeFile(const std::string& path) {
    std::ifstream file(path);
    return {std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()};
}

// Test isolation: the global store is process-lived — every test must
// start clean and leave clean (in a single-process run a leak breaks
// the tests that follow)
struct GlobalStoreGuard {
    GlobalStoreGuard() { SummaryRegistry::instance().clearGlobal(); }
    ~GlobalStoreGuard() { SummaryRegistry::instance().clearGlobal(); }
};

} // anonymous namespace

TEST(SummaryPersistTest, FileFormat_RoundTripDeterministic) {
    GlobalStoreGuard guard;
    const std::string content =
        "codeskeptic-summaries v2\n"
        "alpha/1\tN\tR\tU\n"
        "beta/2\tM\tOF\tM\n"
        "gamma/0\tU\t-\tN\n";
    auto inPath = writePersistFile("sum_roundtrip_in.txt", content);

    auto& registry = SummaryRegistry::instance();
    ASSERT_TRUE(registry.loadGlobal(inPath));
    EXPECT_EQ(registry.globalSize(), 3u);

    auto outPath = ::testing::TempDir() + "sum_roundtrip_out.txt";
    ASSERT_TRUE(registry.saveGlobal(outPath));
    // Format bumps: #69b added the null-condition column (v3), the
    // zero-passthrough slice added zeroFromParam (v4) — save always
    // writes the newest ("-" when absent); loading old versions stays
    // accepted.
    EXPECT_EQ(readWholeFile(outPath),
              "codeskeptic-summaries v5\n"
              "alpha/1\tN\tR\tU\t-\t-\t-\n"
              "beta/2\tM\tOF\tM\t-\t-\t-\n"
              "gamma/0\tU\t-\tN\t-\t-\t-\n");
}

TEST(SummaryPersistTest, OldV1File_AcceptedZeronessUnknown) {
    // A v1 file (3 columns, no zeroness): it loads, zeroness is Unknown
    // — old harvest files keep working in the new version
    GlobalStoreGuard guard;
    auto v1Path = writePersistFile("sum_v1_compat.txt",
        "codeskeptic-summaries v1\n"
        "legacy/1\tN\tR\n");

    auto& registry = SummaryRegistry::instance();
    ASSERT_TRUE(registry.loadGlobal(v1Path));
    EXPECT_EQ(registry.globalSize(), 1u);

    auto outPath = ::testing::TempDir() + "sum_v1_out.txt";
    ASSERT_TRUE(registry.saveGlobal(outPath));
    EXPECT_EQ(readWholeFile(outPath),
              "codeskeptic-summaries v5\nlegacy/1\tN\tR\tU\t-\t-\t-\n");
}

TEST(SummaryPersistTest, ConflictingLoad_MergesConservative) {
    GlobalStoreGuard guard;
    auto pathA = writePersistFile("sum_conflict_a.txt",
        "codeskeptic-summaries v2\n"
        "foo/1\tN\tR\tN\n");
    auto pathB = writePersistFile("sum_conflict_b.txt",
        "codeskeptic-summaries v2\n"
        "foo/1\tM\tF\tM\n");

    auto& registry = SummaryRegistry::instance();
    ASSERT_TRUE(registry.loadGlobal(pathA));
    ASSERT_TRUE(registry.loadGlobal(pathB));
    EXPECT_EQ(registry.globalSize(), 1u);

    // Disagreeing fields fall to the weaker claim: the two return
    // fields N vs M -> U, param R vs F -> O
    auto outPath = ::testing::TempDir() + "sum_conflict_out.txt";
    ASSERT_TRUE(registry.saveGlobal(outPath));
    EXPECT_EQ(readWholeFile(outPath),
              "codeskeptic-summaries v5\nfoo/1\tU\tO\tU\t-\t-\t-\n");
}

TEST(SummaryPersistTest, CorruptFile_RejectedWhole) {
    GlobalStoreGuard guard;
    auto& registry = SummaryRegistry::instance();

    auto good = writePersistFile("sum_good.txt",
        "codeskeptic-summaries v2\n"
        "keep/1\tN\tR\tU\n");
    ASSERT_TRUE(registry.loadGlobal(good));

    // Wrong header: reject
    auto badHeader = writePersistFile("sum_bad_header.txt",
        "some-other-format v9\nfoo/1\tN\tR\n");
    EXPECT_FALSE(registry.loadGlobal(badHeader));

    // Valid header but a corrupt record (unknown effect character):
    // the ENTIRE file is rejected — we don't take the earlier valid
    // line either
    auto badLine = writePersistFile("sum_bad_line.txt",
        "codeskeptic-summaries v2\n"
        "bar/1\tN\tR\tU\n"
        "baz/1\tX\tqq\tU\n");
    EXPECT_FALSE(registry.loadGlobal(badLine));

    // Line with missing fields: reject
    auto badFields = writePersistFile("sum_bad_fields.txt",
        "codeskeptic-summaries v2\n"
        "noeffects/1\tN\n");
    EXPECT_FALSE(registry.loadGlobal(badFields));

    // Line with extra fields: reject (not an unknown future format)
    auto extraFields = writePersistFile("sum_extra_fields.txt",
        "codeskeptic-summaries v2\n"
        "extra/1\tN\tR\tU\tX\n");
    EXPECT_FALSE(registry.loadGlobal(extraFields));

    // The store must be unchanged since the first load
    EXPECT_EQ(registry.globalSize(), 1u);
    auto outPath = ::testing::TempDir() + "sum_untouched_out.txt";
    ASSERT_TRUE(registry.saveGlobal(outPath));
    EXPECT_EQ(readWholeFile(outPath),
              "codeskeptic-summaries v5\nkeep/1\tN\tR\tU\t-\t-\t-\n");
}

TEST(SummaryPersistTest, MissingFile_ReturnsFalse) {
    GlobalStoreGuard guard;
    EXPECT_FALSE(SummaryRegistry::instance().loadGlobal(
        ::testing::TempDir() + "sum_no_such_file.txt"));
    EXPECT_EQ(SummaryRegistry::instance().globalSize(), 0u);
}

TEST(SummaryPersistTest, EndToEnd_SummaryOutThenIn_CrossTUFinding) {
    // The full incremental whole-program story: run 1 harvests summaries
    // from the callee file and writes them to disk; run 2 analyzes ONLY
    // the caller file with the summary file and reports the cross-TU
    // finding. The analyzers' dtor clears the global store — the only
    // thing carrying knowledge into run 2 is the FILE.
    GlobalStoreGuard guard;
    auto calleePath = writePersistFile("sumpersist_callee.cpp", R"(
        int g;
        int* find(int c) {
            if (c) return &g;
            return 0;
        }
    )");
    auto callerPath = writePersistFile("sumpersist_caller.cpp", R"(
        int* find(int c);
        void f(int c) {
            int* p = find(c);
            int x = *p;
            (void)x;
        }
    )");
    auto summaryPath = ::testing::TempDir() + "sumpersist_store.txt";

    {
        Config config;
        config.setSourcePath(calleePath);
        config.setSummaryOut(summaryPath);
        StaticAnalyzer analyzer(std::move(config));
        analyzer.addRule<NullDerefRule>();
        analyzer.run();
    }
    EXPECT_NE(readWholeFile(summaryPath).find("find/1\tM"),
              std::string::npos);

    // Control: the run without summaries is conservative — Opaque, silent
    {
        Config config;
        config.setSourcePath(callerPath);
        StaticAnalyzer analyzer(std::move(config));
        analyzer.addRule<NullDerefRule>();
        analyzer.run();
        EXPECT_EQ(analyzer.diagnostics().size(), 0u);
    }

    // With the summary file: only the caller is analyzed, the finding shows
    {
        Config config;
        config.setSourcePath(callerPath);
        config.setSummaryIn(summaryPath);
        StaticAnalyzer analyzer(std::move(config));
        analyzer.addRule<NullDerefRule>();
        analyzer.run();
        ASSERT_EQ(analyzer.diagnostics().size(), 1u);
        EXPECT_EQ(analyzer.diagnostics()[0].rule_id, "null-deref");
        EXPECT_EQ(analyzer.diagnostics()[0].severity, Severity::Warning);
    }
}

// ===================================================================
// Return zeroness summary (ReturnZeroness): DivByZero now sees across
// functions — the divisor warns even when the `data = 0; return data;`
// source lives in another function/file. The mirror of null: the same
// mini-flow with the zero domain (walkZeroCondition).
// Deliberate limit: the summary is consumed only through the
// ASSIGNMENT path; a direct `x / f()` divisor is not reported (an
// unassigned call result cannot be guarded and would breed a family
// of FPs in real code).
// ===================================================================

TEST(InterprocZeroTest, BadSourceLiteral_UnguardedDiv_Warning) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int badSource() { return 0; }
        int f() {
            int d = badSource();
            return 100 / d;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "div-by-zero");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(InterprocZeroTest, JulietShape_VarFlowSource_Warning) {
    // Juliet CWE369 flow-variant source: the local is 0 first, the
    // return uses that variable — structural evaluation used to leave
    // Unknown, the mini flow derives MaybeZero
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int badSource(int k) {
            int data = 0;
            if (k > 10) data = k;
            return data;
        }
        int f(int k) {
            int d = badSource(k);
            return 100 / d;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(InterprocZeroTest, GuardedUse_Silent) {
    // Even with MaybeZero assigned, the guard refinement yields NonZero
    // at the division point — summary consumption composes with the
    // existing path sensitivity
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int badSource() { return 0; }
        int f() {
            int d = badSource();
            if (d != 0) return 100 / d;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocZeroTest, FlowKilledZero_NeverZero_Silent) {
    // FP-killer: if 0 is assigned inside the source and THEN
    // overwritten, the flow-sensitive summary knows NeverZero — a
    // flow-insensitive "there's a 0 somewhere" shortcut would produce
    // a false warning here
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int source() {
            int d = 0;
            d = 5;
            return d;
        }
        int f() {
            int x = source();
            return 100 / x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocZeroTest, DirectCallDivisor_DocumentedSilent) {
    // Documented limit: an unassigned call result is not reported as a
    // divisor (cannot be guarded; FP-family risk) — the behavior is
    // pinned by this test
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int badSource() { return 0; }
        int f() {
            return 100 / badSource();
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(InterprocZeroTest, TraceNote_MentionsCalleeMayReturnZero) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        int badSource() { return 0; }
        int f() {
            int d = badSource();
            return 100 / d;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    ASSERT_FALSE(results[0].notes.empty());
    EXPECT_NE(results[0].notes[0].message.find("possibly-zero"),
              std::string::npos);
}

TEST(InterprocZeroTest, CrossTU_ZeronessTravels) {
    // Zeroness travels through the cross-TU store too (whole-program /
    // summary-in)
    DivByZeroRule rule;
    auto results = runRuleCrossTU(rule, R"(
        int badSource() { return 0; }
    )", R"(
        int badSource();
        int f() {
            int d = badSource();
            return 100 / d;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(SummaryPersistTest, StaleSummary_WarnsButStillWorks) {
    // Freshness warning: if the source is newer than the summary file,
    // warn on stderr — but analysis does not stop and the summaries are
    // still used (conservative direction: a stale summary does not
    // break correctness, at worst it carries missing/extra claims)
    GlobalStoreGuard guard;
    auto sumPath = writePersistFile("sum_stale.txt",
        "codeskeptic-summaries v2\nfind/1\tM\t-\tU\n");
    auto src = writePersistFile("sum_stale_caller.cpp", R"(
        int* find(int c);
        void f(int c) {
            int* p = find(c);
            int x = *p;
            (void)x;
        }
    )");
    // Stamp the source CLEARLY newer than the summary (no same-second flake)
    namespace fs = std::filesystem;
    fs::last_write_time(src,
        fs::last_write_time(sumPath) + std::chrono::hours(1));

    ::testing::internal::CaptureStderr();
    {
        Config config;
        config.setSourcePath(src);
        config.setSummaryIn(sumPath);
        StaticAnalyzer analyzer(std::move(config));
        analyzer.addRule<NullDerefRule>();
        analyzer.run();
        EXPECT_EQ(analyzer.diagnostics().size(), 1u);  // summary still works
    }
    std::string err = ::testing::internal::GetCapturedStderr();
    EXPECT_NE(err.find("may be stale"), std::string::npos);

    // Control: if the summary is newer than the source, NO warning
    fs::last_write_time(sumPath,
        fs::last_write_time(src) + std::chrono::hours(1));
    ::testing::internal::CaptureStderr();
    {
        Config config;
        config.setSourcePath(src);
        config.setSummaryIn(sumPath);
        StaticAnalyzer analyzer(std::move(config));
        analyzer.addRule<NullDerefRule>();
        analyzer.run();
    }
    err = ::testing::internal::GetCapturedStderr();
    EXPECT_EQ(err.find("may be stale"), std::string::npos);
}

// --- #69b: value-conditioned null-return summaries ---
//
// "Returns null ONLY IF param outside R" + a call-site argument
// provably inside R = no warning. The picojpeg getHuffVal FP: null
// only in the switch default, the caller's masked index provably
// within the cases. Negative controls pin the conservative side.

namespace {
const char* kSwitchTables = R"(
        static unsigned char t0[16], t1[16], t2[16], t3[16];
        static unsigned char* getHuffVal(int idx) {
            switch (idx) {
                case 0: return t0;
                case 1: return t1;
                case 2: return t2;
                case 3: return t3;
                default: return 0;
            }
        }
)";
} // namespace

TEST(ConditionedNullTest, SwitchDefault_MaskedArg_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kSwitchTables) + R"(
        unsigned char use(unsigned char x) {
            int idx = ((x >> 3) & 2) + (x & 1);
            unsigned char* p = getHuffVal(idx);
            return p[0];
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ConditionedNullTest, SwitchDefault_InlineArg_Clean) {
    // The masked expression passed directly, no local.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kSwitchTables) + R"(
        unsigned char use(unsigned char x) {
            unsigned char* p = getHuffVal(x & 3);
            return p[0];
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ConditionedNullTest, SwitchDefault_UnprovableArg_WarningStays) {
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kSwitchTables) + R"(
        unsigned char use(int idx) {
            unsigned char* p = getHuffVal(idx);
            return p[0];
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(ConditionedNullTest, SwitchDefault_OutOfRangeArg_WarningStays) {
    // Provable interval [0,7] is NOT a subset of the cases [0,3].
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kSwitchTables) + R"(
        unsigned char use(unsigned char x) {
            unsigned char* p = getHuffVal(x & 7);
            return p[0];
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(ConditionedNullTest, NonContiguousCases_WarningStays) {
    // Cases {0,1,3}: the hull [0,3] contains 2, which falls to the
    // default — recording the hull would be unsound, so no condition
    // forms and the provable-in-hull argument still warns.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        static unsigned char t0[16];
        static unsigned char* pick(int idx) {
            switch (idx) {
                case 0: return t0;
                case 1: return t0;
                case 3: return t0;
                default: return 0;
            }
        }
        unsigned char use(unsigned char x) {
            unsigned char* p = pick(x & 3);
            return p[0];
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(ConditionedNullTest, CaseFallsThroughToDefault_WarningStays) {
    // `case 1:` falls through into default: an in-range value can
    // reach the null return — the condition must NOT form.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        static unsigned char t0[16];
        static unsigned char* pick(int idx) {
            switch (idx) {
                case 0: return t0;
                case 1: ;
                default: return 0;
            }
        }
        unsigned char use(unsigned char x) {
            unsigned char* p = pick(x & 1);
            return p[0];
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(ConditionedNullTest, IfGuard_ProvableArg_Clean) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        static unsigned char t0[16];
        static unsigned char* pick(int n) {
            if (n > 7) return 0;
            return t0;
        }
        unsigned char use(unsigned char x) {
            int n = x & 3;
            unsigned char* p = pick(n);
            return p[0];
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ConditionedNullTest, MutatedParam_WarningStays) {
    // The guard tests a REASSIGNED param — it no longer speaks about
    // the caller's argument, so the condition must not form.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        static unsigned char t0[16];
        static unsigned char* pick(int n) {
            n = n * 2;
            if (n > 7) return 0;
            return t0;
        }
        unsigned char use(unsigned char x) {
            unsigned char* p = pick(x & 3);
            return p[0];
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(ConditionedNullTest, ArgReassignedLocal_WarningStays) {
    // The caller's local is written twice — no sole definition, its
    // interval is unknown at the call.
    NullDerefRule rule;
    auto results = runRule(rule, std::string(kSwitchTables) + R"(
        unsigned char use(unsigned char x, int flag) {
            int idx = x & 3;
            if (flag) idx = 100;
            unsigned char* p = getHuffVal(idx);
            return p[0];
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(ConditionedNullTest, CrossTU_ConditionTravels) {
    // Whole-program mode: the condition harvested from the callee TU
    // (externally-visible function) suppresses in the caller TU.
    NullDerefRule rule;
    auto results = runRuleCrossTU(rule, R"(
        static unsigned char t0[16], t1[16];
        unsigned char* getHuffVal(int idx) {
            switch (idx) {
                case 0: return t0;
                case 1: return t1;
                default: return 0;
            }
        }
    )", R"(
        unsigned char* getHuffVal(int idx);
        unsigned char use(unsigned char x) {
            unsigned char* p = getHuffVal(x & 1);
            return p[0];
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ConditionedNullTest, V3FileRoundtrip) {
    // Handcrafted v3 line → parse → assert fields; load → save →
    // re-parse → identical condition (serialization both ways).
    const std::string dir = ::testing::TempDir();
    const std::string p1 = dir + "/cs_sum_v3_in.txt";
    const std::string p2 = dir + "/cs_sum_v3_out.txt";
    {
        std::ofstream out(p1);
        out << "codeskeptic-summaries v3\n";
        out << "getHuffVal/1\tM\tR\tU\t0:0:3\n";
        out << "plainMaybe/1\tM\tR\tU\t-\n";
    }
    std::map<std::string, SummaryRegistry::FunctionSummary> parsed;
    ASSERT_TRUE(SummaryRegistry::parseSummaryFile(p1, parsed));
    ASSERT_EQ(parsed.count("getHuffVal/1"), 1u);
    const auto& s = parsed["getHuffVal/1"];
    EXPECT_TRUE(s.hasNullCondition());
    EXPECT_EQ(s.nullCondParam, 0);
    EXPECT_EQ(s.nullCondRange, Interval::range(0, 3));
    EXPECT_FALSE(parsed["plainMaybe/1"].hasNullCondition());

    SummaryRegistry& registry = SummaryRegistry::instance();
    registry.clearGlobal();
    ASSERT_TRUE(registry.loadGlobal(p1));
    ASSERT_TRUE(registry.saveGlobal(p2));
    std::map<std::string, SummaryRegistry::FunctionSummary> reparsed;
    ASSERT_TRUE(SummaryRegistry::parseSummaryFile(p2, reparsed));
    EXPECT_EQ(reparsed["getHuffVal/1"].nullCondParam, 0);
    EXPECT_EQ(reparsed["getHuffVal/1"].nullCondRange, Interval::range(0, 3));
    registry.clearGlobal();
}

// --- v4 persistence: the zero-passthrough column ---

TEST(SummaryPersistTest, V4File_ZeroFromParamParses) {
    GlobalStoreGuard guard;
    const std::string content =
        "codeskeptic-summaries v4\n"
        "id/1\tU\tR\tU\t-\t0\n"
        "plain/1\tU\tR\tU\t-\t-\n";
    auto p = writePersistFile("sum_v4_zf.txt", content);
    std::map<std::string, SummaryRegistry::FunctionSummary> parsed;
    ASSERT_TRUE(SummaryRegistry::parseSummaryFile(p, parsed));
    EXPECT_EQ(parsed["id/1"].zeroFromParam, 0);
    EXPECT_EQ(parsed["plain/1"].zeroFromParam, -1);
}

TEST(SummaryPersistTest, V4File_ZeroFromParamOnNonUnknown_Rejected) {
    // The claim lives only where it is defined (zeroness Unknown);
    // a file pairing it with N/M is corrupt and rejected wholesale.
    GlobalStoreGuard guard;
    const std::string content =
        "codeskeptic-summaries v4\n"
        "bad/1\tU\tR\tN\t-\t0\n";
    auto p = writePersistFile("sum_v4_zf_bad.txt", content);
    std::map<std::string, SummaryRegistry::FunctionSummary> parsed;
    EXPECT_FALSE(SummaryRegistry::parseSummaryFile(p, parsed));
}

TEST(SummaryPersistTest, V3File_NullCondStillParses) {
    // The == 5 -> >= 5 regression trap: v3 files' null-condition column
    // must keep parsing after the v4 bump.
    GlobalStoreGuard guard;
    const std::string content =
        "codeskeptic-summaries v3\n"
        "cond/1\tM\tR\tU\t0:0:3\n";
    auto p = writePersistFile("sum_v3_cond_compat.txt", content);
    std::map<std::string, SummaryRegistry::FunctionSummary> parsed;
    ASSERT_TRUE(SummaryRegistry::parseSummaryFile(p, parsed));
    EXPECT_EQ(parsed["cond/1"].nullCondParam, 0);
}

// --- v5 persistence: the null-passthrough column ---

TEST(SummaryPersistTest, V5File_NullFromParamParses) {
    GlobalStoreGuard guard;
    const std::string content =
        "codeskeptic-summaries v5\n"
        "keep/1\tU\tR\tU\t-\t-\t0\n"
        "plain/1\tU\tR\tU\t-\t-\t-\n";
    auto p = writePersistFile("sum_v5_nf.txt", content);
    std::map<std::string, SummaryRegistry::FunctionSummary> parsed;
    ASSERT_TRUE(SummaryRegistry::parseSummaryFile(p, parsed));
    EXPECT_EQ(parsed["keep/1"].nullFromParam, 0);
    EXPECT_EQ(parsed["plain/1"].nullFromParam, -1);
}

TEST(SummaryPersistTest, V5File_NullFromParamOnNonUnknown_Rejected) {
    GlobalStoreGuard guard;
    const std::string content =
        "codeskeptic-summaries v5\n"
        "bad/1\tN\tR\tU\t-\t-\t0\n";
    auto p = writePersistFile("sum_v5_nf_bad.txt", content);
    std::map<std::string, SummaryRegistry::FunctionSummary> parsed;
    EXPECT_FALSE(SummaryRegistry::parseSummaryFile(p, parsed));
}

TEST(SummaryPersistTest, V4File_ZeroFromParamStillParses) {
    // The >= regression trap, one version later: v4 files' zeroFromParam
    // column must keep parsing after the v5 bump.
    GlobalStoreGuard guard;
    const std::string content =
        "codeskeptic-summaries v4\n"
        "id/1\tU\tR\tU\t-\t0\n";
    auto p = writePersistFile("sum_v4_zf_compat.txt", content);
    std::map<std::string, SummaryRegistry::FunctionSummary> parsed;
    ASSERT_TRUE(SummaryRegistry::parseSummaryFile(p, parsed));
    EXPECT_EQ(parsed["id/1"].zeroFromParam, 0);
}
