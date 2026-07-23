#include "TestHelper.h"
#include "engine/AllocFunctions.h"
#include "rules/MemoryLeakRule_Ex.h"

#include <gtest/gtest.h>

#include <set>
#include <string>

using namespace codeskeptic;
using namespace codeskeptic::testing;

TEST(MemoryLeakRuleExTest, SimpleLeak) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(42);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(MemoryLeakRuleExTest, CorrectUsage_NewDelete) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(42);
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, ConditionalLeak) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int* p = new int(42);
            if (c) delete p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(MemoryLeakRuleExTest, BothBranchesDelete_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f(int c) {
            int* p = new int(42);
            if (c) delete p;
            else delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, ReturnEscape_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        int* create() {
            int* p = new int(42);
            return p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, ReassignmentLeak) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(1);
            p = new int(2);
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(MemoryLeakRuleExTest, MallocFree_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" {
            void* malloc(unsigned long);
            void free(void*);
        }
        void f() {
            int* p = (int*)malloc(sizeof(int));
            free(p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, MallocNoFree_Leak) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" {
            void* malloc(unsigned long);
        }
        void f() {
            int* p = (int*)malloc(sizeof(int));
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(MemoryLeakRuleExTest, FunctionParamEscape_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void consume(int* p);
        void f() {
            int* p = new int(1);
            consume(p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, DoubleFree) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(42);
            delete p;
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_EQ(results[0].rule_id, "double-free");
}

TEST(MemoryLeakRuleExTest, ArrayNewDelete_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int[10];
            delete[] p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, NoAllocation_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int x = 42;
            int* p = &x;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, MultipleVars_OneLeaks) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* a = new int(1);
            int* b = new int(2);
            delete a;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// --- Use-after-free ---

TEST(MemoryLeakRuleExTest, UseAfterFree_Delete) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(1);
            delete p;
            int x = *p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(MemoryLeakRuleExTest, UseAfterFree_CFree_Arrow) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        struct Node { int data; };
        void f() {
            Node* n = (Node*)malloc(sizeof(Node));
            free(n);
            int x = n->data;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

TEST(MemoryLeakRuleExTest, DeleteThenReassignThenUse_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(1);
            delete p;
            p = new int(2);
            int x = *p;
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, UseBeforeFree_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* p = new int(1);
            int x = *p;
            delete p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(MemoryLeakRuleExTest, UseAfterFree_Subscript) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            int* arr = new int[10];
            delete[] arr;
            int x = arr[3];
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

// ===================================================================
// Targeted path sensitivity: correlated guards (PathFacts)
// Root cause of the Juliet FP hunt — paths getting mixed when the same
// invariant condition is tested twice. Solved by the analysis state,
// not the engine (guarded disjuncts).
// ===================================================================

TEST(PathSensitivityTest, CorrelatedGuards_AllocFree_Clean) {
    // Verbatim Juliet goodB2G/goodG2B pattern: source and sink are
    // guarded by the same global condition — no leak
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int globalFive = 5;
        void f() {
            int* data = 0;
            if (globalFive == 5) data = (int*)malloc(4);
            if (globalFive == 5) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(PathSensitivityTest, CorrelatedGuards_Truthiness_Clean) {
    // The if (flag) ... if (flag) ... form (Juliet staticTrue variant)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int flag;
        void f() {
            int* data = 0;
            if (flag) data = (int*)malloc(4);
            if (flag) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(PathSensitivityTest, CorrelatedGuards_NegatedPair_Clean) {
    // if (!flag) alloc; if (!flag) free — negation matches too
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int flag;
        void f() {
            int* data = 0;
            if (!flag) data = (int*)malloc(4);
            if (!flag) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(PathSensitivityTest, AntiCorrelatedGuards_LeakStays) {
    // if (flag) alloc; if (!flag) free — free is on the WRONG branch:
    // the leak is real
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int flag;
        void f() {
            int* data = 0;
            if (flag) data = (int*)malloc(4);
            if (!flag) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(PathSensitivityTest, MutatedBetweenGuards_WarningStays) {
    // The condition variable changes between the two tests: NO
    // correlation is established (not keyed), the conservative warning
    // is kept — if c==5 is true at the first test the alloc happens,
    // the second test is now false, the free is missed
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void f(int c) {
            int* data = 0;
            if (c == 5) data = (int*)malloc(4);
            c = 0;
            if (c == 5) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(PathSensitivityTest, FunctionCallGuard_NotCorrelated) {
    // A function call is NEVER keyed (a rand() correlation would be
    // wrong): two check() calls may give different results → the
    // warning stays
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int check();
        void f() {
            int* data = 0;
            if (check()) data = (int*)malloc(4);
            if (check()) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(PathSensitivityTest, CorrelatedGuards_DoubleFree_NowCaught) {
    // Used to be an FN: the Freed+Allocated mix at the join hid the
    // second free. With disjuncts only the Freed path enters the second
    // if(flag) body → double-free. Also no free at all on the flag==0
    // path → the real exit-leak is reported too (both findings are
    // correct).
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int flag;
        void f() {
            int* data = (int*)malloc(4);
            if (flag) free(data);
            if (flag) free(data);
        }
    )");
    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[0].rule_id, "double-free");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_EQ(results[1].rule_id, "memory-leak");
    EXPECT_EQ(results[1].severity, Severity::Warning);
}

TEST(PathSensitivityTest, CorrelatedGuards_UAF_NowCaught) {
    // Likewise: free and use under the same guard → definite UAF
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        int flag;
        void f() {
            int* data = (int*)malloc(4);
            if (flag) free(data);
            if (flag) { int x = *data; (void)x; }
            free(data);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

TEST(DocumentedLimitTest, CallBetweenCorrelatedGuards_MayMaskLeak) {
    // DELIBERATE TRADE-OFF: a call between the two guards may change
    // the global (a real leak can be hidden — FN direction). Not
    // propagating call effects to globals is the price of staying
    // FP-free on Juliet's printLine-laden patterns. For local/param
    // conditions this risk does NOT exist (a call cannot touch a local
    // whose address does not escape).
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void mayToggle();
        int flag;
        void f() {
            int* data = 0;
            if (flag) data = (int*)malloc(4);
            mayToggle();
            if (flag) free(data);
        }
    )");
    EXPECT_EQ(results.size(), 0);  // documented limit
}

TEST(MemoryLeakRuleExTest, AddrOfArg_Escapes_NoLeak) {
    // sink(&p): the callee may free/reassign p — tracking stops.
    // (Juliet 63x variant: when &data went unseen, a bogus exit-leak
    // was born.)
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" { void* malloc(unsigned long); void free(void*); }
        void sink(int** pp);
        void f() {
            int* p = (int*)malloc(4);
            sink(&p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// ===================================================================
// Abseil FP hunt (2026-07-12): three real-world false-positive
// families found by scanning abseil-cpp (159 files). Each test pins
// the fix; the flip side (real leaks staying visible) is pinned too.
// ===================================================================

TEST(AbseilFpTest, StaticLocalSingleton_NoLeak) {
    // `static T* x = new T;` is the deliberate leak-on-purpose
    // singleton (destruction-order fiasco dodge). Static storage is
    // program-long — not an end-of-function leak.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct M { int v; };
        void f() {
            static M* inst = new M;
            (void)inst;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AbseilFpTest, GlobalAssignedAllocation_NoLeak) {
    // The abseil mutex.cc deadlock_graph pattern: a file-scope global
    // lazily assigned an allocation inside a function.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct G { int v; };
        G* g_graph = nullptr;
        void ensure() {
            if (g_graph == nullptr) g_graph = new G;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AbseilFpTest, MemberAssign_Escapes_NoLeak) {
    // The abseil CrcCordState pattern: a fresh allocation stored into a
    // class member outlives the function — escape, not leak.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct R { int v; };
        struct Holder {
            R* slot;
            void fill() {
                R* copy = new R;
                slot = copy;
            }
        };
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AbseilFpTest, MethodCallReceiver_Escapes_NoLeak) {
    // The abseil CordzInfo pattern: `p->Track()` registers `this` in a
    // global list — the receiver escapes conservatively.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Trk { void track(); };
        void f() {
            Trk* t = new Trk;
            t->track();
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AbseilFpTest, MethodCallReceiver_AfterFree_StillUAF) {
    // The flip side: receiver-escape must not mask use-after-free —
    // the receiver's MemberExpr is checked against the pre-call state.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Trk { void track(); };
        void f() {
            Trk* t = new Trk;
            delete t;
            t->track();
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "use-after-free");
}

TEST(AbseilFpTest, LocalToLocalCopy_LeakStaysVisible) {
    // The flip side of member-assign escape: a plain local-to-local
    // copy is NOT an escape — Juliet's `dataCopy = data;` alias
    // patterns must keep the leak visible.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        void f() {
            int* data = (int*)malloc(4);
            int* dataCopy;
            dataCopy = data;
            (void)dataCopy;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
}

TEST(AbseilFpTest, LocalStructMemberAssign_LeakStaysVisible) {
    // The Juliet guard caught this (CWE401 recall drop): a member of a
    // LOCAL aggregate is still local storage — the allocation stored
    // into it dies with the function. This is a real leak, not an
    // escape (the 66/67 struct-passing families).
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        struct Box { int* ptr; };
        void f() {
            int* data = (int*)malloc(4);
            Box b;
            b.ptr = data;
            (void)b;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
}

TEST(AbseilFpTest, ParamStructMemberAssign_Escapes_NoLeak) {
    // Storing into a caller-owned aggregate escapes for real: the
    // caller can free it after we return.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        struct Box { int* ptr; };
        void f(Box& out) {
            int* data = (int*)malloc(4);
            out.ptr = data;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- shadPS4 FP hunt (2026-07-12): casts and composite arguments ---

TEST(ShadPS4FpTest, VoidCastCallbackArg_Escapes_NoLeak) {
    // The SDL_AddTimer pattern: `(void*)copy` handed to an opaque
    // callback registry. The explicit cast must not hide the variable
    // from the escape analysis.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        typedef unsigned int (*Callback)(void*, unsigned int);
        void addTimer(int ms, Callback cb, void* param);
        unsigned int onTimer(void*, unsigned int);
        void f() {
            int* copy = new int(42);
            addTimer(33, onTimer, (void*)copy);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ShadPS4FpTest, ReinterpretCastThroughOutParam_Escapes_NoLeak) {
    // The usb OpenDevice pattern: `*out = reinterpret_cast<T*>(h);`.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Handle { int fd; };
        int open(void** out) {
            Handle* h = new Handle;
            *out = reinterpret_cast<void*>(h);
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ShadPS4FpTest, MemberOfReferenceBase_Escapes_NoLeak) {
    // The imgui backend pattern: `io.UserData = (void*)bd;` where io
    // is a reference to storage owned elsewhere.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct IO { void* userData; };
        IO& getIO();
        void f() {
            int* bd = new int(1);
            IO& io = getIO();
            io.userData = (void*)bd;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ShadPS4FpTest, AggregateCallArg_Escapes_NoLeak) {
    // The audio3d pattern: the pointer rides inside a composite
    // argument (`push(Data{(unsigned char*)m})`) — the receiving
    // object outlives our view of it.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Data { unsigned char* buf; };
        void push(Data d);
        void f() {
            short* m = new short[64];
            push(Data{reinterpret_cast<unsigned char*>(m)});
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ShadPS4FpTest, DerefArg_LeakStaysVisible) {
    // The flip side: `printInt(*d)` reads the POINTEE — the pointer is
    // not handed over, the leak must stay visible.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void printInt(int v);
        void f() {
            int* d = new int(7);
            printInt(*d);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].message.find("leak"), std::string::npos);
}

TEST(ShadPS4FpTest, CastLocalToLocalCopy_LeakStaysVisible) {
    // The flip side of cast transparency: a cast alias copy between
    // two locals is still a local copy — the alias leak stays visible.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void f() {
            char* data = new char[16];
            void* dataCopy;
            dataCopy = (void*)data;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(ShadPS4FpTest, FreeThroughCast_NoLeak) {
    // `free((void*)p)` is a free of p — cast transparency makes the
    // deallocation visible too.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void free(void*);
        extern "C" void* malloc(unsigned long);
        void f() {
            char* p = (char*)malloc(16);
            free((void*)p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(ShadPS4FpTest, NonConstRefArg_Escapes_NoLeak) {
    // A `T*&` parameter lets the callee reassign or stash the
    // caller's pointer — always an escape.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void take(char*& p);
        void f() {
            char* data = new char[8];
            take(data);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- NASA fprime FP hunt (2026-07-12): placement new ---

TEST(FprimeFpTest, PlacementNew_IsNotAnAllocation) {
    // The AtomicQueue slot-initialization loop: placement new
    // constructs into existing storage — reassigning the cursor
    // pointer across iterations leaks nothing.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Slot { int v; Slot() : v(0) {} };
        void init(void* mem, int n) {
            Slot* slots = static_cast<Slot*>(mem);
            for (int i = 0; i < n; ++i) {
                Slot* slot = new (&slots[i]) Slot();
                slot->v = i;
            }
        }
        void* operator new(unsigned long, void* p) noexcept;
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(FprimeFpTest, PlainNew_StillTracked) {
    // The flip side: ordinary new keeps full leak tracking.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Slot { int v; };
        void f() {
            Slot* s = new Slot();
            s->v = 1;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

// --- Configurable allocators (2026-07-12, the libgit2 lesson) ---

namespace {
// Process-global registries: always cleared on scope exit (the
// single-process test run is what catches leaked state).
class AllocScope {
public:
    AllocScope(std::set<std::string> allocs, std::set<std::string> frees) {
        setAllocFunctionNames(std::move(allocs));
        setFreeFunctionNames(std::move(frees));
    }
    ~AllocScope() {
        setAllocFunctionNames({});
        setFreeFunctionNames({});
    }
};
} // namespace

TEST(AllocFunctionsTest, WrapperLeak_VisibleWhenRegistered) {
    AllocScope scope({"git__malloc"}, {"git__free"});
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* git__malloc(unsigned long);
        void f() {
            char* buf = (char*)git__malloc(64);
            (void)buf;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].message.find("leak"), std::string::npos);
}

TEST(AllocFunctionsTest, WrapperFree_ClosesTheLeak) {
    AllocScope scope({"git__malloc"}, {"git__free"});
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* git__malloc(unsigned long);
        extern "C" void git__free(void*);
        void f() {
            char* buf = (char*)git__malloc(64);
            git__free(buf);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AllocFunctionsTest, WrapperDoubleFree_Caught) {
    AllocScope scope({"git__malloc"}, {"git__free"});
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* git__malloc(unsigned long);
        extern "C" void git__free(void*);
        void f() {
            char* buf = (char*)git__malloc(64);
            git__free(buf);
            git__free(buf);
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(AllocFunctionsTest, Unregistered_WrapperStaysInvisible) {
    // The flip side (and the pre-flag behavior pin): without
    // registration a wrapper allocation is not tracked at all.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* git__malloc(unsigned long);
        void f() {
            char* buf = (char*)git__malloc(64);
            (void)buf;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- Address-of-member escape (libgit2 iterator / fprime font) ---

TEST(AddrOfMemberTest, MemberAddressThroughOutParam_Escapes_NoLeak) {
    // The libgit2 iterator pattern: `*out = &it->parent;` — the caller
    // reaches (and frees) the whole object through the member address.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Parent { int x; };
        struct Iter { Parent parent; int head; };
        int make(Parent** out) {
            Iter* it = new Iter();
            it->head = 1;
            *out = &it->parent;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AddrOfMemberTest, MemberAddressAsCallArg_Escapes_NoLeak) {
    // The fprime font pattern: TrackGeneratedGlyph(&boxed->glyph);
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Glyph { int magic; };
        struct Boxed { Glyph glyph; };
        void track(Glyph* g);
        void f() {
            Boxed* boxed = new Boxed();
            track(&boxed->glyph);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AddrOfMemberTest, MemberAddressIntoLocal_LeakStaysVisible) {
    // The flip side: keeping the member address in a LOCAL alias does
    // not save the object — nothing outlives the function.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Glyph { int magic; };
        struct Boxed { Glyph glyph; };
        void f() {
            Boxed* boxed = new Boxed();
            Glyph* alias;
            alias = &boxed->glyph;
            (void)alias;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

// --- Alias escape propagation (libgit2 realpath copy-then-return) ---

TEST(AliasEscapeTest, CopyThenReturn_NoLeak) {
    // `dup = strdup(s); result = dup; return result;` hands the SAME
    // allocation out — dup escapes through its alias.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" char* strdup(const char*);
        char* f(const char* s, char* result) {
            char* dup = strdup(s);
            result = dup;
            return result;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AliasEscapeTest, CopyNoEscape_LeakStaysVisible) {
    // The flip side (and the Juliet dataCopy pin, re-stated): a local
    // alias that never escapes saves nothing.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" char* strdup(const char*);
        void f(const char* s) {
            char* dup = strdup(s);
            char* copy;
            copy = dup;
            (void)copy;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(AliasEscapeTest, ChainedAssignThroughOutParam_Escapes_NoLeak) {
    // `*out = counts = calloc(...)` — the caller owns the allocation
    // through the out-param (the libgit2 checkout idiom).
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* calloc(unsigned long, unsigned long);
        int f(unsigned long** out) {
            unsigned long* counts = 0;
            *out = counts = (unsigned long*)calloc(4, 8);
            if (!counts) { return -1; }
            counts[0] = 1;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(FprimeFpTest, NothrowNew_IsARealAllocation) {
    // `new (std::nothrow) T` carries a placement ARG but allocates from
    // the heap — only a POINTER-typed placement argument designates
    // caller-provided storage.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        namespace std { struct nothrow_t {}; extern const nothrow_t nothrow; }
        void* operator new(__SIZE_TYPE__, const std::nothrow_t&) noexcept;
        struct T { int v; };
        void f() {
            T* p = new (std::nothrow) T();
            (void)p;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(CarbonFpTest, ArenaPlacementNew_IsNotAnAllocation) {
    // Carbon's MakePlaceholderTemplateArg (call.cpp:108, 280-TU
    // re-hunt #91): `new (ctx.ast_context()) CXXScalarValueInitExpr(...)`
    // draws from an arena the ASTContext owns and frees en masse — the
    // returned node is never individually deleted. A non-pointer,
    // non-nothrow class placement arg designates arena storage.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Arena {};
        void* operator new(unsigned long, Arena&);
        struct Node { int v; };
        Arena& get_arena();
        Node* make() {
            Node* n = new (get_arena()) Node();
            return n;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(CarbonFpTest, ArenaPlacementNew_ByValue_IsNotAnAllocation) {
    // Same idiom with the allocator passed by value rather than
    // reference — still arena storage, still not tracked.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Pool {};
        void* operator new(unsigned long, Pool);
        struct Node { int v; };
        void f(Pool p) {
            Node* n = new (p) Node();
            (void)n;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- Disjuncts v2a (2026-07-12): constant-returning call guards ---

TEST(CallGuardTest, ConstReturningHelper_CorrelatedGuards_Clean) {
    // The Juliet flow-variant shape: alloc and free both guarded by
    // the same constant-returning static helper — the disjunct pairing
    // must recognize the correlation.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        extern "C" void free(void*);
        static int staticReturnsTrue() { return 1; }
        void f() {
            char* data = 0;
            if (staticReturnsTrue()) {
                data = (char*)malloc(16);
            }
            if (staticReturnsTrue()) {
                free(data);
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(CallGuardTest, BodylessExtern_NotKeyed_LeakStaysVisible) {
    // The flip side: rand() has no visible body — two calls may
    // return different values, so the phantom alloc-without-free path
    // is REAL and must stay reported.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        extern "C" void free(void*);
        extern "C" int rand();
        void f() {
            char* data = 0;
            if (rand()) {
                data = (char*)malloc(16);
            }
            if (rand()) {
                free(data);
            }
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(CallGuardTest, StateReadingBody_NotKeyed_LeakStaysVisible) {
    // A helper that reads mutable state is not invariant between the
    // two guards — not keyed, the leak path stays visible.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        extern "C" void free(void*);
        int g_flag;
        static int readsGlobal() { return g_flag; }
        void f() {
            char* data = 0;
            if (readsGlobal()) {
                data = (char*)malloc(16);
            }
            if (readsGlobal()) {
                free(data);
            }
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(AliasEscapeTest, FreedThroughAlias_NoLeak) {
    // The Juliet malloc_realloc good1 shape: the allocation is freed
    // under the alias's name.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        extern "C" void* realloc(void*, unsigned long);
        extern "C" void free(void*);
        void f() {
            int* data = (int*)malloc(400);
            int* tmpData = (int*)realloc(data, 130000);
            if (tmpData != nullptr) {
                data = tmpData;
            }
            free(data);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AliasEscapeTest, AliasReuse_FirstAllocationFN_Documented) {
    // DOCUMENTED accepted FN of the exit-time alias-free check:
    // reusing the alias variable for a SECOND allocation and freeing
    // only that one leaks the first — the flow-insensitive group
    // cannot tell the two apart. This test pins the trade-off; if a
    // future flow-sensitive alias model fixes it, flip the count to 1.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        extern "C" void free(void*);
        void f() {
            char* a = (char*)malloc(8);
            char* b = a;
            b = (char*)malloc(16);
            free(b);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AliasEscapeTest, FreedThroughAlias_UnderGuard_NoLeak) {
    // The flow-variant version of the realloc shape: everything sits
    // inside a keyed guard. The Freed alias lives in a DISJUNCT —
    // flattening would dissolve it (Freed with None = None), so the
    // suppression must check per disjunct.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        extern "C" void* realloc(void*, unsigned long);
        extern "C" void free(void*);
        static int staticFive = 5;
        void f() {
            int* data = 0;
            int* tmpData = 0;
            if (staticFive == 5) {
                data = (int*)malloc(400);
                tmpData = (int*)realloc(data, 130000);
                if (tmpData != nullptr) {
                    data = tmpData;
                }
                free(data);
            }
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(AliasEscapeTest, ExitGuard_DoesNotDiluteFreedAlias) {
    // `if (data == NULL) exit(-1);` — Clang wires the noreturn block
    // straight to the CFG exit; its state must NOT vote there (Freed
    // merged with the dead path's None used to dissolve into None and
    // blind the freed-through-alias check).
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        extern "C" void* realloc(void*, unsigned long);
        extern "C" void free(void*);
        extern "C" [[noreturn]] void exit(int);
        void printLL(long long v);
        void f() {
            long long* data = (long long*)malloc(800);
            if (data == nullptr) { exit(-1); }
            long long* tmpData;
            data[0] = 5;
            printLL(data[0]);
            tmpData = (long long*)realloc(data, 130000);
            if (tmpData != nullptr) {
                data = tmpData;
                data[0] = 10;
            }
            free(data);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- systemd FP hunt (2026-07-12): __attribute__((cleanup)) ---

TEST(CleanupAttrTest, CleanupVar_CannotLeak) {
    // systemd's _cleanup_free_ / GLib's g_autofree: the compiler runs
    // the cleanup function at every scope exit — no leak possible.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        extern "C" void free(void*);
        static inline void freep(void* p) { free(*(void**)p); }
        int f() {
            __attribute__((cleanup(freep))) char* buf = 0;
            buf = (char*)malloc(64);
            if (!buf) { return -1; }
            buf[0] = 1;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(CleanupAttrTest, PlainNeighbor_StillTracked) {
    // The flip side: a cleanup attribute on ONE variable exempts only
    // that variable.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        extern "C" void free(void*);
        static inline void freep(void* p) { free(*(void**)p); }
        int f() {
            __attribute__((cleanup(freep))) char* safe = 0;
            safe = (char*)malloc(8);
            char* leaky = (char*)malloc(8);
            (void)leaky;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

// --- systemd FP hunt round 2 (2026-07-12): macro idioms ---

TEST(SystemdIdiomTest, CompoundLiteralThroughOutParam_Escapes_NoLeak) {
    // iovec_alloc: `*ret = (struct iovec){ .iov_base = buf, ... };`
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        struct iovec { void* iov_base; unsigned long iov_len; };
        int alloc_iov(unsigned long n, iovec* ret) {
            void* buf = malloc(n ? n : 1);
            if (!buf) { return -12; }
            *ret = iovec{ buf, n };
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(SystemdIdiomTest, StatementExprTakePtr_Escapes_NoLeak) {
    // conf-parser: `*ret = TAKE_PTR(cs);` — the RHS statement
    // expression yields the pointer while nulling the source.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" void* malloc(unsigned long);
        struct CS { int line; };
        int make(CS** ret) {
            CS* cs = (CS*)malloc(sizeof(CS));
            if (!cs) { return -12; }
            *ret = ({ CS* t = cs; cs = 0; t; });
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(SystemdIdiomTest, AddressIntoLocalAlias_Escapes_NoLeak) {
    // free_and_replace expansion: `_b = &(p); *_a = *_b; *_b = 0;` —
    // once the address is stored we cannot follow the alias.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" char* strdup(const char*);
        extern "C" void free(void*);
        void replace(char** slot, const char* s) {
            char* p = strdup(s);
            if (!p) { return; }
            char** b = 0;
            b = &p;
            free(*slot);
            *slot = *b;
            *b = 0;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(SystemdIdiomTest, AddressIntoLocalViaInit_Escapes_NoLeak) {
    // The real free_and_replace expansion takes the address in an
    // INIT (`typeof(b)* _b = &(b);`), not an assignment.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern "C" char* strdup(const char*);
        extern "C" void free(void*);
        void replace(char** slot, const char* s) {
            char* t = strdup(s);
            if (!t) { return; }
            char** b = &t;
            free(*slot);
            *slot = *b;
            *b = 0;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

// --- #75: owning-smart-pointer adoption + scope-guard lambda escape ---
//
// Modern C++ hands a raw `new`-ed pointer to an owner it cannot follow
// with the old raw-pointer view. Three real-world FP shapes, cross-
// verified on TensorFlow Lite (std::unique_ptr returns) and JoltPhysics
// (Ref<T> returns, scope-guard lambdas):
//   A. return std::unique_ptr<S>(p);   — std adoption, built-in
//   B. Ref<S> f() { return p; }        — project wrapper, --owning-pointers
//   C. auto g = [&]{ Free(p); };       — closure escape
// The suppression is conservative (Escaped, never a fabricated free):
// a genuine leak beside the adoption, and an unconfigured wrapper, must
// still report.

namespace {
// runToolOnCode has no system headers; the tests declare just enough
// std smart-pointer surface for the type to live in namespace std with
// the recognized name and an adopting constructor.
const std::string kStdSmartPtrs = R"(
namespace std {
  template <class T> class unique_ptr {
   public:
    T* p_;
    explicit unique_ptr(T* p) : p_(p) {}
    ~unique_ptr() { delete p_; }
  };
  template <class T> class shared_ptr {
   public:
    T* p_;
    explicit shared_ptr(T* p) : p_(p) {}
  };
}
struct S { int x; };
)";

// Process-global registry, cleared on scope exit (single-process test
// run is what catches leaked state).
class OwningPtrScope {
public:
    explicit OwningPtrScope(std::set<std::string> names) {
        setOwningPointerNames(std::move(names));
    }
    ~OwningPtrScope() { setOwningPointerNames({}); }
};
} // namespace

TEST(OwningPointerTest, ReturnUniquePtrAdoption_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, kStdSmartPtrs + R"(
        std::unique_ptr<S> make() {
            S* p = new S;
            return std::unique_ptr<S>(p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(OwningPointerTest, ReturnSharedPtrAdoption_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, kStdSmartPtrs + R"(
        std::shared_ptr<S> make() {
            S* p = new S;
            return std::shared_ptr<S>(p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(OwningPointerTest, LocalUniquePtrAdoption_Clean) {
    // Adoption into a LOCAL, not just a return value.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, kStdSmartPtrs + R"(
        void use(std::unique_ptr<S>);
        void f() {
            S* p = new S;
            std::unique_ptr<S> up(p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(OwningPointerTest, GenuineLeakBesideAdoption_Reported) {
    // One pointer is adopted; the other genuinely leaks. Only the leak
    // reports — the suppression is per-variable, not per-function.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, kStdSmartPtrs + R"(
        std::unique_ptr<S> f() {
            S* adopted = new S;
            S* leaked = new S;
            (void)leaked;
            return std::unique_ptr<S>(adopted);
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].message.find("leak"), std::string::npos);
}

TEST(OwningPointerTest, ConfiguredWrapper_ReturnAdoption_Clean) {
    OwningPtrScope scope({"Ref"});
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct S { int x; };
        template <class T> struct Ref { T* ptr; Ref(T* p): ptr(p) {} };
        Ref<S> make() {
            S* p = new S;
            return Ref<S>(p);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(OwningPointerTest, ConfiguredWrapper_ImplicitAdoption_Clean) {
    // `return p;` where the return type's ctor is non-explicit: the
    // implicit CXXConstructExpr adoption must be seen through too.
    OwningPtrScope scope({"Ref"});
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct S { int x; };
        template <class T> struct Ref { T* ptr; Ref(T* p): ptr(p) {} };
        Ref<S> make() {
            S* p = new S;
            return p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(OwningPointerTest, UnconfiguredWrapper_LeakStays) {
    // A same-shaped wrapper NOT on the allow-list may be a non-owning
    // view (it copies/observes, does not free): the leak must stay.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct S { int x; };
        template <class T> struct View { T* ptr; View(T* p): ptr(p) {} };
        View<S> make() {
            S* p = new S;
            return View<S>(p);
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(OwningPointerTest, ScopeGuardLambdaByRef_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct S { int x; };
        void Free(void*);
        void f() {
            S* p = new S;
            auto guard = [&]{ Free(p); };
            guard();
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(OwningPointerTest, ScopeGuardLambdaByValue_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct S { int x; };
        void Free(void*);
        void f() {
            S* p = new S;
            auto guard = [p]{ Free(p); };
            guard();
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(OwningPointerTest, LambdaNotCapturingPtr_LeakStays) {
    // A lambda that does NOT capture the tracked pointer must not
    // silence its leak — the escape is capture-driven, not the mere
    // presence of a closure.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        struct S { int x; };
        void f() {
            S* p = new S;
            (void)p;
            auto g = []{ int x = 0; return x; };
            g();
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

// Real-world regression pin: tensorflow/tensorflow #123387 (still open).
// TFLite rfft2d Rfft2dHelper allocates fft_input_output, then a
// temporary-tensor lookup (TF_LITE_ENSURE_OK) can return early before the
// delete[] — leaking the FFT work buffer on the error path. Conditional
// leak -> Warning. Body reduced from the real function to parseable stubs.
TEST(MemoryLeakRuleExTest, TFLite_123387_Rfft2dWorkBufferLeak_Reports) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        enum TfLiteStatus { kTfLiteOk = 0, kTfLiteError = 1 };
        struct TfLiteContext; struct TfLiteNode; struct TfLiteTensor;
        TfLiteStatus GetTemporarySafe(TfLiteContext*, TfLiteNode*, int, TfLiteTensor**);
        TfLiteStatus Rfft2dHelper(TfLiteContext* context, TfLiteNode* node,
                                  int fft_height, int fft_width) {
            double** fft_input_output = new double*[fft_height];
            for (int i = 0; i < fft_height; ++i) {
                fft_input_output[i] = new double[fft_width + 2];
            }
            TfLiteTensor* fft_integer_working_area;
            if (GetTemporarySafe(context, node, 0, &fft_integer_working_area) != kTfLiteOk)
                return kTfLiteError;
            TfLiteTensor* fft_double_working_area;
            if (GetTemporarySafe(context, node, 1, &fft_double_working_area) != kTfLiteOk)
                return kTfLiteError;
            for (int i = 0; i < fft_height; ++i) { delete[] fft_input_output[i]; }
            delete[] fft_input_output;
            return kTfLiteOk;
        }
    )");
    ASSERT_GE(results.size(), 1u);
    bool found = false;
    for (const auto& d : results) {
        if (d.rule_id == "memory-leak" && d.severity == Severity::Warning) found = true;
    }
    EXPECT_TRUE(found);
}

// --- v0.4: immutable-flag constant propagation (edge pruning) ---
// The Juliet flag-variant goodB2G FP family: alloc guarded by one
// never-written static flag, the free by its complement — the "leaked"
// path cannot execute. ImmutableFlags.h; engine-level, all rules.

TEST(MemoryLeakRuleExTest, ImmutableFlagCorrelation_Clean) {
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern void* malloc(unsigned long);
        extern void free(void*);
        extern void exit(int);
        static int staticTrue = 1;
        static int staticFalse = 0;
        void goodB2G() {
            long* data = 0;
            if (staticTrue) {
                data = (long*)malloc(100 * sizeof(long));
                if (data == 0) { exit(-1); }
            }
            if (staticFalse) {
                /* infeasible: no free here */
            } else {
                free(data);
            }
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(MemoryLeakRuleExTest, ImmutableTrueFlagLeak_StillReports) {
    // The FEASIBLE side must keep reporting — pruning removes only the
    // impossible edge, never the live one.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern void* malloc(unsigned long);
        static int enabled = 1;
        void f() {
            long* p = 0;
            if (enabled) {
                p = (long*)malloc(8);
            }
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
}

TEST(MemoryLeakRuleExTest, MutatedFlag_NotConstantFolded) {
    // The flag is written elsewhere in the TU — folding it would hide
    // a REAL leak. Mutation disqualifies; the leak must be reported.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern void* malloc(unsigned long);
        static int flag = 0;
        void set_flag(void) { flag = 1; }
        void f() {
            long* p = 0;
            if (flag) {
                p = (long*)malloc(8);
            }
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(MemoryLeakRuleExTest, AddressTakenFlag_NotConstantFolded) {
    // &flag escapes — any code could write through the pointer.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern void* malloc(unsigned long);
        static int flag = 0;
        int* leak_the_flag(void) { return &flag; }
        void f() {
            long* p = 0;
            if (flag) {
                p = (long*)malloc(8);
            }
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}

// --- v0.4.2: call-flag folding + flag-copy closure ---

TEST(MemoryLeakRuleExTest, NeverZeroCallFlagCorrelation_Clean) {
    // `if (staticReturnsTrue())`: a visible-body callee whose summary
    // proves NeverZero makes the false edge infeasible — the Juliet
    // variant-08 goodB2G shape. The call's side effects still run;
    // only the impossible successor edge is pruned.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern void* malloc(unsigned long);
        extern void free(void*);
        extern void exit(int);
        static int staticReturnsTrue(void) { return 1; }
        void goodB2G(void) {
            long* data = 0;
            if (staticReturnsTrue()) {
                data = (long*)malloc(100 * sizeof(long));
                if (data == 0) { exit(-1); }
            }
            if (staticReturnsTrue()) {
                free(data);
            }
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(MemoryLeakRuleExTest, MaybeZeroCallFlag_NotFolded) {
    // A callee that CAN return zero must never fold — this leak is
    // real on the zero path.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern void* malloc(unsigned long);
        static int mayReturnZero(int x) { return x > 0 ? 1 : 0; }
        void f(int x) {
            long* p = 0;
            if (mayReturnZero(x)) {
                p = (long*)malloc(8);
            }
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "memory-leak");
}

TEST(MemoryLeakRuleExTest, FlagCopyCorrelation_Clean) {
    // `int flagCopy = staticFalse;` — the copy closure carries the
    // provable value; the leak path behind if(flagCopy) cannot run
    // (the Juliet *_31/_33 flag-copy variants).
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern void* malloc(unsigned long);
        extern void free(void*);
        extern void exit(int);
        static int staticFalse = 0;
        void goodB2G(void) {
            int flagCopy = staticFalse;
            long* d = (long*)malloc(16);
            if (d == 0) { exit(-1); }
            if (flagCopy) {
                /* infeasible: no free */
            } else {
                free(d);
            }
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(MemoryLeakRuleExTest, MutatedFlagCopy_NotFolded) {
    // The copy is reassigned — its value is no longer the flag's;
    // folding would hide this real leak.
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        extern void* malloc(unsigned long);
        static int staticFalse = 0;
        void f(int x) {
            int c = staticFalse;
            if (x) { c = 1; }
            long* p = 0;
            if (c) {
                p = (long*)malloc(8);
            }
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}
