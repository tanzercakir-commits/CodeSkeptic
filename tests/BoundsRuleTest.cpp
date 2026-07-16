#include "TestHelper.h"
#include "rules/BoundsRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// bounds (CWE-125/787), v0: a fixed-size array subscripted by an index
// whose ENTIRE proven range is outside [0, extent). Precision-first —
// only definite out-of-bounds is an Error; partial overlaps stay silent.

// --- Definite out-of-bounds: report ---

TEST(BoundsRuleTest, ConstantIndexPastEnd) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int a[10];
            return a[10];
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "bounds");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, NegativeConstantIndex) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int a[10];
            return a[-1];
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, GuardedIndexProvenPastEnd) {
    // `if (i < 10) return 0;` leaves i ∈ [10,+∞] on the fall-through —
    // every value is out of [0,10).
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f(int i) {
            int a[10];
            if (i < 10) return 0;
            return a[i];
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, ComputedConstantIndexPastEnd) {
    // n = 8 + 8 = 16, proven past a[10].
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int a[10];
            int n = 8 + 8;
            return a[n];
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

// --- In-bounds / unprovable: clean ---

TEST(BoundsRuleTest, ConstantIndexInRange) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f() {
            int a[10];
            return a[9] + a[0];
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, UnknownIndexSilent) {
    // Caller-unknown index → top() → nothing proven (precision-first).
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f(int i) {
            int a[10];
            return a[i];
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, PartialOverlapSilent) {
    // i ∈ [5,15] straddles the bound — some paths in range. v0 does NOT
    // report partial overlaps (loop-counter FP minefield).
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f(int i) {
            int a[10];
            if (i < 5) return 0;
            if (i > 15) return 0;
            return a[i];
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, GuardedIndexInRangeClean) {
    // 0 <= i <= 9 — fully in bounds.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f(int i) {
            int a[10];
            if (i < 0) return 0;
            if (i > 9) return 0;
            return a[i];
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Heap extents: malloc / calloc buffers ---

namespace {
// Inline allocator declarations so the snippets compile in the default
// C++ harness (where malloc's void* needs an explicit cast).
const char* kAlloc =
    "void* malloc(unsigned long);\n"
    "void* calloc(unsigned long, unsigned long);\n"
    "void take(int**);\n";
std::string heap(const std::string& body) { return std::string(kAlloc) + body; }
} // namespace

TEST(BoundsRuleTest, HeapMallocPastEnd) {
    // malloc(10 * sizeof(int)) => 10 elements; a[20] is out of bounds.
    BoundsRule rule;
    auto results = runRule(rule, heap(
        "int f(void){ int* a = (int*)malloc(10 * sizeof(int)); return a[20]; }"));
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "bounds");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, HeapMallocInRangeClean) {
    BoundsRule rule;
    auto results = runRule(rule, heap(
        "int f(void){ int* a = (int*)malloc(10 * sizeof(int)); return a[9]; }"));
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, HeapCharMallocPastEnd) {
    // char buffer: byte size == element count (sizeof(char) == 1).
    BoundsRule rule;
    auto results = runRule(rule, heap(
        "char f(void){ char* s = (char*)malloc(16); return s[50]; }"));
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, HeapCallocPastEnd) {
    // calloc(8, sizeof(int)) => 8 elements; index 8 is one past the end.
    BoundsRule rule;
    auto results = runRule(rule, heap(
        "int f(void){ int* a = (int*)calloc(8, sizeof(int)); return a[8]; }"));
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, HeapCallocInRangeClean) {
    BoundsRule rule;
    auto results = runRule(rule, heap(
        "int f(void){ int* a = (int*)calloc(8, sizeof(int)); return a[3]; }"));
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, HeapReassignedPointerSilent) {
    // a is reassigned after the malloc — the declared extent can no longer
    // be trusted, so the pointer is excluded (sound).
    BoundsRule rule;
    auto results = runRule(rule, heap(
        "int f(int c){ int* a = (int*)malloc(10 * sizeof(int)); "
        "if (c) a = 0; return a[20]; }"));
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, HeapAddressTakenSilent) {
    // &a escapes to a callee that may repoint it — extent dropped.
    BoundsRule rule;
    auto results = runRule(rule, heap(
        "int f(void){ int* a = (int*)malloc(10 * sizeof(int)); "
        "take(&a); return a[20]; }"));
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, HeapVariableSizeSilent) {
    // The size is a caller-unknown parameter — extent unprovable, silent.
    BoundsRule rule;
    auto results = runRule(rule, heap(
        "int f(int n){ int* a = (int*)malloc(n * sizeof(int)); return a[20]; }"));
    EXPECT_EQ(results.size(), 0u);
}

// --- Copy-size overflow: memcpy / memmove / memset ---

namespace {
const char* kCopy =
    "void* memcpy(void*, const void*, unsigned long);\n"
    "void* memset(void*, int, unsigned long);\n"
    "void* malloc(unsigned long);\n";
std::string copy(const std::string& body) { return std::string(kCopy) + body; }
} // namespace

TEST(BoundsRuleTest, MemcpyPastFixedArray) {
    // 50 bytes into a 16-byte buffer.
    BoundsRule rule;
    auto results = runRule(rule, copy(
        "void f(const void* s){ char buf[16]; memcpy(buf, s, 50); }"));
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "bounds");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, MemcpyExactFitClean) {
    BoundsRule rule;
    auto results = runRule(rule, copy(
        "void f(const void* s){ char buf[16]; memcpy(buf, s, 16); }"));
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, MemsetPastIntArray) {
    // int[10] is 40 bytes; memset of 100 overflows.
    BoundsRule rule;
    auto results = runRule(rule, copy(
        "void f(void){ int a[10]; memset(a, 0, 100); }"));
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, MemcpyHeapPastEnd) {
    BoundsRule rule;
    auto results = runRule(rule, copy(
        "void f(const void* s){ char* p = (char*)malloc(16); "
        "memcpy(p, s, 40); }"));
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, MemcpyVariableSizeSilent) {
    BoundsRule rule;
    auto results = runRule(rule, copy(
        "void f(const void* s, unsigned long n){ char buf[16]; "
        "memcpy(buf, s, n); }"));
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, MemcpyInRangeClean) {
    BoundsRule rule;
    auto results = runRule(rule, copy(
        "void f(const void* s){ char buf[64]; memcpy(buf, s, 16); }"));
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, MemcpySizeofOversizedType) {
    // memcpy(buf16, s, sizeof(Big)) with Big = 64 bytes — the classic
    // "sizeof the wrong thing" overflow (Juliet CWE122 shape).
    BoundsRule rule;
    auto results = runRule(rule, copy(
        "struct Big { char x[64]; };\n"
        "void f(const void* s){ char buf[16]; memcpy(buf, s, sizeof(struct Big)); }"));
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, MemcpyCountTimesSizeofOverflow) {
    // 8 * sizeof(int) == 32 bytes into a 16-byte buffer.
    BoundsRule rule;
    auto results = runRule(rule, copy(
        "void f(const void* s){ char buf[16]; memcpy(buf, s, 8 * sizeof(int)); }"));
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, MemcpySizeofSelfClean) {
    // memcpy(buf, s, sizeof(buf)) copies exactly the destination size.
    BoundsRule rule;
    auto results = runRule(rule, copy(
        "void f(const void* s){ char buf[16]; memcpy(buf, s, sizeof(buf)); }"));
    EXPECT_EQ(results.size(), 0u);
}

// --- Struct-member array destinations (b2) ---

TEST(BoundsRuleTest, StructMemberSubscriptPastEnd) {
    // s->buf[20] on a 16-element member array — the extent is a property
    // of the field's type, regardless of the object.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        struct S { char buf[16]; };
        char f(struct S* s){ return s->buf[20]; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, StructMemberSubscriptInRangeClean) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        struct S { char buf[16]; };
        char f(struct S* s){ return s->buf[5]; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, StructMemberByValueSubscript) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        struct T { char buf[8]; };
        char f(struct T t){ return t.buf[9]; }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, MemcpyStructMemberOverflow) {
    // The Juliet CWE122 shape: copy sizeof(the whole struct) into a small
    // member buffer.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        void* memcpy(void*, const void*, unsigned long);
        struct S { char charFirst[16]; void* second; };
        void f(struct S* s, const void* src){
            memcpy(s->charFirst, src, sizeof(struct S));
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, MemcpyStructMemberInRangeClean) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        void* memcpy(void*, const void*, unsigned long);
        struct S { char buf[16]; };
        void f(struct S* s, const void* src){
            memcpy(s->buf, src, sizeof(s->buf));
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Pathological type depth (TFLite hardening) ---
// clang's getTypeInfo recurses once per type-nesting level; a
// metaprogram-generated type can be deep enough to smash the stack
// (TensorFlow Lite's neon_tensor_utils.cc: 104k frames -> SIGSEGV).
// boundedTypeSizeInChars walks the structure under a depth budget
// first: a too-deep type yields "size unknown" and the rule stays
// SILENT (sound) instead of crashing or guessing.

TEST(BoundsRuleTest, PathologicallyDeepTypeStaysSilentNotCrash) {
    // 400 nested array levels (> the 128-depth budget): the definite
    // OOB a[5] would be reportable if the size were computed, but the
    // budget says "unknown" — no crash, no finding.
    std::string code = "typedef int A0[2];\n";
    for (int i = 1; i <= 400; ++i)
        code += "typedef A" + std::to_string(i - 1) + " A" +
                std::to_string(i) + "[2];\n";
    code += "int* f(){ static A400 a; return &a[5][0]";
    for (int i = 0; i < 399; ++i) code += "[0]";
    code += "; }\n";

    BoundsRule rule;
    auto results = runRule(rule, code);
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, ShallowNestedTypeStillReports) {
    // The budget must NOT eat legitimate nesting: 3 levels, definite OOB.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef int A0[2];
        typedef A0 A1[2];
        typedef A1 A2[4];
        int f(){ A2 a; return a[9][0][0]; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

// --- Interprocedural (C3): parameter entry intervals ---

TEST(BoundsRuleTest, StaticHelperOutOfRangeIndexFromCaller) {
    // `at` is static and called only with 20, so i enters as [20,20] —
    // past a[10]. The caller's constant index reaches the bounds check.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        static int at(int i) { int a[10]; return a[i]; }
        int f(void) { return at(20); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, StaticHelperInRangeIndexFromCallerClean) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        static int at(int i) { int a[10]; return a[i]; }
        int f(void) { return at(3); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, PointerParamHasNoExtentSilent) {
    // A pointer parameter has no ConstantArrayType — extent unknown, so
    // even a large constant index proves nothing.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        int f(int* a) {
            return a[1000000];
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}
