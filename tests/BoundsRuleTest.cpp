#include "TestHelper.h"
#include "engine/AllocFunctions.h"
#include "rules/BoundsRule.h"

#include <gtest/gtest.h>

using namespace codeskeptic;
using namespace codeskeptic::testing;

// bounds (CWE-125/787), v0: a fixed-size array subscripted by an index
// whose ENTIRE proven range is outside [0, extent). Precision-first —
// only definite out-of-bounds is an Error; partial overlaps stay silent.

// --- Definite out-of-bounds: report ---

// --- Bitwise / modulo interval modeling (#69a) ---
// `x & c` (c>=0) is provably in [0, c]; `x % c` in [0, |c|-1] when x>=0.
// This lets the bounds rule see through the common mask/modulo indexing
// idioms — both to PROVE safety (stay silent) and to catch an OOB the
// idiom's range makes definite.

TEST(BoundsRuleTest, BitmaskIndexInRangeClean) {
    // idx = src() & 3  ->  [0,3], within a[4]: no finding.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern int src(void);
        int f() { int a[4]; int i = src() & 3; return a[i]; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, BitmaskIndexPlusOffsetOOB) {
    // idx = src() & 7  ->  [0,7]; idx + 4 -> [4,11], all outside a[4].
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern int src(void);
        int g() { int a[4]; int i = src() & 7; return a[i + 4]; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, ModuloIndexInRangeClean) {
    // Non-negative index % 4 -> [0,3]: the canonical safe-indexing idiom.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern int src(void);
        int f() { int a[4]; int n = src() & 15; return a[n % 4]; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, ModuloIndexPlusOffsetOOB) {
    // (n>=0) % 4 -> [0,3]; +10 -> [10,13], outside a[4].
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern int src(void);
        int g() { int a[4]; int n = src() & 255; return a[(n % 4) + 10]; }
    )");
    ASSERT_EQ(results.size(), 1u);
}

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
// __SIZE_TYPE__: snippets are always parsed by clang, which expands it
// to the TARGET's real size_t — `unsigned long` would be a mismatched
// 32-bit type on LLP64 Windows and the extent modeling would not
// engage (missed finding, caught by the windows-native lane).
const char* kAlloc =
    "void* malloc(__SIZE_TYPE__);\n"
    "void* calloc(__SIZE_TYPE__, __SIZE_TYPE__);\n"
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
// __SIZE_TYPE__ for the same LLP64 reason as kAlloc above.
const char* kCopy =
    "void* memcpy(void*, const void*, __SIZE_TYPE__);\n"
    "void* memmove(void*, const void*, __SIZE_TYPE__);\n"
    "void* memset(void*, int, __SIZE_TYPE__);\n"
    "void* malloc(__SIZE_TYPE__);\n";
std::string copy(const std::string& body) { return std::string(kCopy) + body; }
} // namespace

// CS3-CH01-S02-U001: the source has its own read capacity even when
// the destination is large enough (or its capacity is unknown).
TEST(BoundsRuleTest, MemoryCopySourceCapacity) {
    struct Case { const char* name; const char* setup; const char* args; unsigned reports; };
    const Case cases[] = {
        {"large destination small source", "char dst[64]={}, src[4]={};", "dst,src,8", 1},
        {"source exact fit", "char dst[64]={}, src[4]={};", "dst,src,4", 0},
        {"zero length", "char dst[64]={}, src[4]={};", "dst,src,0", 0},
        {"unknown source", "char dst[64]={};", "dst,unknown_src,8", 0},
        {"unknown destination known source", "char src[4]={};", "unknown_dst,src,8", 1},
        {"typed source capacity in bytes", "char dst[64]={}; int src[2]={};", "dst,src,sizeof(src)+1", 1},
        {"typed source exact bytes", "char dst[64]={}; int src[2]={};", "dst,src,sizeof(src)", 0},
        {"string source includes terminator", "char dst[64]={};", "dst,\"abc\",5", 1},
        {"string source exact fit", "char dst[64]={};", "dst,\"abc\",4", 0},
        {"heap source", "char dst[64]={}; char* src=(char*)malloc(4);", "dst,src,8", 1},
        {"member source", "struct S {char data[4];}; S src={}; char dst[64]={};", "dst,src.data,8", 1},
    };
    for (const char* function : {"memcpy", "memmove"}) {
        for (const auto& item : cases) {
            SCOPED_TRACE(function);
            SCOPED_TRACE(item.name);
            BoundsRule rule;
            auto results = runRule(rule, copy(
                std::string("void f(void* unknown_dst,const void* unknown_src){") +
                item.setup + function + "(" + item.args + ");}"));
            EXPECT_EQ(results.size(), item.reports);
            for (const auto& result : results) {
                EXPECT_EQ(result.rule_id, "bounds");
                EXPECT_EQ(result.severity, Severity::Error);
                EXPECT_NE(result.message.find("source"), std::string::npos);
            }
        }
    }
}

TEST(BoundsRuleTest, SourceReadExcludesMemsetAndStrncpy) {
    BoundsRule rule;
    auto results = runRule(rule, copy(R"(
        char* strncpy(char*, const char*, __SIZE_TYPE__);
        void f() {
            char dst[64]={}, src[4]={};
            memset(dst, 0, 8);
            strncpy(dst, src, 8);
        }
    )"));
    EXPECT_TRUE(results.empty());
}

TEST(BoundsRuleTest, SourceReadHeapBytesAndBindingStability) {
    struct Case { const char* body; unsigned reports; };
    const Case cases[] = {
        {"char* src=(char*)malloc(4); src[0]=0; memcpy(dst,src,8);", 1},
        {"char* src=(char*)malloc(4); *src=0; memcpy(dst,src,8);", 1},
        {"int* src=(int*)malloc(6); memcpy(dst,src,6);", 0},
        {"int* src=(int*)malloc(6); memcpy(dst,src,7);", 1},
        {"int* src=(int*)calloc(2,3); memcpy(dst,src,6);", 0},
        {"int* src=(int*)calloc(2,3); memcpy(dst,src,7);", 1},
        {"void* src=malloc(4); memcpy(dst,src,8);", 1},
        {"char* src=(char*)malloc(4); src=large; memcpy(dst,src,8);", 0},
        {"char* src=(char*)malloc(4); char*& alias=src; alias=large; memcpy(dst,src,8);", 0},
        {"char* src=(char*)malloc(4); replace(src); memcpy(dst,src,8);", 0},
        {"char* src=(char*)malloc(4); Replace change(src); memcpy(dst,src,8);", 0},
        {"char* src=(char*)malloc(4); auto change=[&src,&large](){src=large;}; change(); memcpy(dst,src,8);", 0},
        {"char* src=(char*)malloc(4); char** alias=&src; *alias=large; memcpy(dst,src,8);", 0},
        {"char* src=(char*)malloc(n); memcpy(dst,src,8);", 0},
        {"char* src; src=(char*)malloc(4); memcpy(dst,src,8);", 0},
    };
    for (const auto& item : cases) {
        SCOPED_TRACE(item.body);
        BoundsRule rule;
        auto results = runRule(rule, copy(std::string(R"(
            void* calloc(__SIZE_TYPE__, __SIZE_TYPE__);
            void replace(char*&);
            struct Replace { Replace(char*&); };
            void f(__SIZE_TYPE__ n) { char dst[64]={}, large[64]={};
        )") + item.body + "}"));
        EXPECT_EQ(results.size(), item.reports);
        for (const auto& result : results)
            EXPECT_NE(result.message.find("source"), std::string::npos);
    }
}

TEST(BoundsRuleTest, SourceReadRejectsNoncanonicalMemoryFunctions) {
    const char* cases[] = {
        "extern void* memcpy(void*,const void*,unsigned char); void f(){char dst[64],src[4]; memcpy(dst,src,8);}",
        "extern void* memcpy(const void*,const void*,__SIZE_TYPE__); void f(){char dst[64],src[4]; memcpy(dst,src,8);}",
        "extern const void* memcpy(void*,const void*,__SIZE_TYPE__); void f(){char dst[64],src[4]; memcpy(dst,src,8);}",
        "namespace custom {void* memcpy(void*,const void*,__SIZE_TYPE__);} void f(){char dst[64],src[4]; custom::memcpy(dst,src,8);}",
        "struct Custom {void* memcpy(void*,const void*,__SIZE_TYPE__);}; void f(Custom& c){char dst[64],src[4]; c.memcpy(dst,src,8);}",
        "void* memcpy(void* d,const void*,__SIZE_TYPE__){return d;} void f(){char dst[64],src[4]; memcpy(dst,src,8);}",
        "void* malloc(unsigned char); void* memcpy(void*,const void*,__SIZE_TYPE__); void f(){char dst[64]; char* src=(char*)malloc(4); memcpy(dst,src,8);}",
    };
    for (const char* code : cases) {
        SCOPED_TRACE(code);
        BoundsRule rule;
        EXPECT_TRUE(runRule(rule, code).empty());
    }
}

TEST(BoundsRuleTest, SourceReadRejectsUnknownArrayViews) {
    BoundsRule rule;
    auto results = runRule(rule, copy(R"(
        void* calloc(__SIZE_TYPE__, __SIZE_TYPE__);
        void heap_view() {
            char (*src)[4]=(char(*)[4])calloc(2,4);
            char dst[8]; memcpy(dst,*src,8);
        }
        void cast_view() {
            char src[8], dst[8];
            memcpy(dst,*reinterpret_cast<char(*)[4]>(src),8);
        }
        void reference_view(char (&src)[4]) {
            char dst[8]; memcpy(dst,src,8);
        }
    )"));
    EXPECT_TRUE(results.empty());
}

TEST(BoundsRuleTest, SourceReadFlexibleTailAndRealArrayControls) {
    BoundsRule rule;
    auto results = runRule(rule, copy(R"(
        struct Tail {int n; char data[1];};
        struct Middle {char data[1]; int n;};
        struct Fixed {int n; char data[4];};
        void unknown_tail(Tail* src) {char dst[64]; memcpy(dst,src->data,8);}
        void direct_tail() {Tail src; char dst[64]; memcpy(dst,src.data,8);}
        void middle(Middle* src) {char dst[64]; memcpy(dst,src->data,8);}
        void fixed_tail(Fixed* src) {char dst[64]; memcpy(dst,src->data,8);}
    )"));
    ASSERT_EQ(results.size(), 3u);
    for (const auto& result : results) {
        EXPECT_NE(result.function, "unknown_tail");
        EXPECT_NE(result.message.find("source"), std::string::npos);
    }
}

TEST(BoundsRuleTest, SourceReadDefiniteRangeOnly) {
    struct Case { const char* condition; unsigned reports; };
    const Case cases[] = {
        {"if(n>4) return;", 0},
        {"if(n<8 || n>16) return;", 1},
        {"if(n>8) return;", 0},
        {"", 0},
    };
    for (const auto& item : cases) {
        SCOPED_TRACE(item.condition);
        BoundsRule rule;
        auto results = runRule(rule, copy(
            std::string("void f(unsigned n){char dst[64],src[4];") +
            item.condition + "memcpy(dst,src,n);}"));
        EXPECT_EQ(results.size(), item.reports);
        for (const auto& result : results)
            EXPECT_NE(result.message.find("source"), std::string::npos);
    }
}

TEST(BoundsRuleTest, SourceReadDoesNotHideDestinationOrSameLineCalls) {
    BoundsRule rule;
    auto both = runRule(rule, copy(
        "void f(){char dst[2],src[4]; memcpy(dst,src,8);}"));
    ASSERT_EQ(both.size(), 2u);
    EXPECT_EQ(both[0].message.find("source"), std::string::npos);
    EXPECT_NE(both[1].message.find("source"), std::string::npos);
    EXPECT_EQ(both[0].line, both[1].line);

    auto sameLine = runRule(rule, copy(
        "void f(){char dst[64],src[4]; memcpy(dst,src,8); memmove(dst,src,8);}"));
    ASSERT_EQ(sameLine.size(), 2u);
    EXPECT_EQ(sameLine[0].line, sameLine[1].line);
    EXPECT_NE(sameLine[0].column, sameLine[1].column);
}

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
        void* memcpy(void*, const void*, __SIZE_TYPE__);
        struct S { char charFirst[16]; void* second; };
        void f(struct S* s, const void* src){
            memcpy(s->charFirst, src, sizeof(struct S));
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, MemcpyStructMemberInRangeClean) {
    BoundsRule rule;
    // __SIZE_TYPE__ so the rule actually ENGAGES on LLP64 too — with a
    // mismatched size type this clean-test would pass vacuously.
    auto results = runRule(rule, R"(
        void* memcpy(void*, const void*, __SIZE_TYPE__);
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

// --- Unbounded string copy into a fixed buffer (#95, CWE-120) ---

TEST(BoundsRuleTest, StrcpyIntoFixedMember_Warns) {
    // The thesis-corpus miss (hash_djb2): strcpy into a fixed char[N]
    // member with no length check.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern char* strcpy(char*, const char*);
        struct S { char name[16]; };
        void f(struct S* s, const char* in) { strcpy(s->name, in); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "bounds");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(BoundsRuleTest, StrcpyLocalArray_Warns) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern char* strcpy(char*, const char*);
        void f(const char* in) { char buf[8]; strcpy(buf, in); }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, StrcpyFittingLiteral_Clean) {
    // A string literal that provably fits is safe — skipped.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern char* strcpy(char*, const char*);
        void f(void) { char buf[16]; strcpy(buf, "hello"); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, StrcpyIntoHeap_Clean) {
    // A heap destination is NOT a fixed array — excluded (the
    // right-sized malloc+strcpy idiom must not FP).
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern void* malloc(size_t);
        extern char* strcpy(char*, const char*);
        void f(const char* in) { char* p = (char*)malloc(100); strcpy(p, in); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Length-check witness (2026-07-22, the rtp2httpd guarded-copy
// FP family): a strlen(src) measurement in a dominating guard excuses
// the heuristic; anything less keeps firing. ---

TEST(BoundsRuleTest, StrcatStrlenSumGuard_Clean) {
    // Shape A: the canonical guarded append.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern size_t strlen(const char*);
        extern char* strcat(char*, const char*);
        int f(const char* param) {
            char merged[2048];
            merged[0] = 0;
            if (strlen(merged) + strlen(param) < sizeof(merged)) {
                strcat(merged, param);
                return 1;
            }
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, StrcpyPrecheckEarlyReturn_Clean) {
    // Shape B: measure-and-bail before the copy.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern size_t strlen(const char*);
        extern char* strcpy(char*, const char*);
        int f(const char* url) {
            char absolute[4096];
            if (strlen(url) >= sizeof(absolute))
                return -1;
            strcpy(absolute, url);
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, StrcatDstOnlyGuard_Reported) {
    // Measuring the DESTINATION never bounds the source.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern size_t strlen(const char*);
        extern char* strcat(char*, const char*);
        int f(const char* s) {
            char buf[64];
            buf[0] = 0;
            if (strlen(buf) < 60) strcat(buf, s);
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, StrcpyCheckAfterCopy_Reported) {
    // The check must DOMINATE the copy; checking afterwards is theater.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern size_t strlen(const char*);
        extern char* strcpy(char*, const char*);
        int f(const char* s) {
            char buf[64];
            strcpy(buf, s);
            if (strlen(s) >= sizeof(buf)) return -1;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, StrcpyMeasuredThenIgnored_Reported) {
    // A guard whose then-branch does NOT exit leaves the fall-through
    // copy unprotected — measured-then-ignored is a bug, not diligence.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern size_t strlen(const char*);
        extern char* strcpy(char*, const char*);
        extern void log_warn(void);
        int f(const char* s) {
            char buf[64];
            if (strlen(s) >= sizeof(buf)) { log_warn(); }
            strcpy(buf, s);
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, StrcpyOtherVarGuard_Reported) {
    // The measurement must be of the SAME source expression.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern size_t strlen(const char*);
        extern char* strcpy(char*, const char*);
        int f(const char* s, const char* t) {
            char buf[64];
            if (strlen(t) >= sizeof(buf)) return -1;
            strcpy(buf, s);
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}

// --- Untrusted-length copies (docs/untrusted-length.md increment) ---
// memcpy/memmove/memset/strncpy sized by a value that DERIVES from a
// declared untrusted-integer source and whose proven FINITE range can
// exceed the destination capacity -> possible overflow (Warning). The
// range decides: a guard's edge narrows it and silences; an unknown
// (top) length or an underived value never reports.

TEST(BoundsRuleTest, UntrustedLenMemcpy_Warn) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern int atoi(const char*);
        extern void* memcpy(void*, const void*, size_t);
        void f(const char* s, const char* src) {
            char buf[64];
            int n = atoi(s);
            memcpy(buf, src, n);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(BoundsRuleTest, UntrustedLenGuarded_Clean) {
    // The guard's own edge narrows the range below capacity: silent.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern int atoi(const char*);
        extern void* memcpy(void*, const void*, size_t);
        void f(const char* s, const char* src) {
            char buf[64];
            int n = atoi(s);
            if (n < 0 || n > 64) return;
            memcpy(buf, src, n);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, UntrustedLenScanfStrncpy_Warn) {
    // scanf fills n from external text; strncpy writes exactly n bytes.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern int scanf(const char*, ...);
        extern char* strncpy(char*, const char*, size_t);
        void f(const char* src) {
            char buf[32];
            int n;
            if (scanf("%d", &n) != 1) return;
            strncpy(buf, src, n);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(BoundsRuleTest, TrustedOrUnknownLen_Clean) {
    // A trusted constant AND an unknown (underived) parameter length:
    // neither arm may report — provenance alone gates the warning.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern void* memcpy(void*, const void*, size_t);
        void f(const char* src, int m) {
            char buf[64];
            int n = 32;
            memcpy(buf, src, n);
            memcpy(buf, src, m);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, ReassignedAfterUntrusted_Clean) {
    // Plain reassignment recomputes provenance: no stale taint.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern int atoi(const char*);
        extern void* memcpy(void*, const void*, size_t);
        void f(const char* s, const char* src) {
            char buf[64];
            int n = atoi(s);
            n = 16;
            memcpy(buf, src, n);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, UntrustedArithDerived_Warn) {
    // Derivation flows through arithmetic: n*2 is still attacker-sized.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern int atoi(const char*);
        extern void* memcpy(void*, const void*, size_t);
        void f(const char* s, const char* src) {
            char buf[64];
            int n = atoi(s);
            memcpy(buf, src, n * 2);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(BoundsRuleTest, ScanfWidthBound_RangeDecides) {
    // %2d caps the value at 99: fits a 200-byte buffer (silent), can
    // exceed a 50-byte one (warn) — the WIDTH-narrowed range decides,
    // provenance stays untrusted in both.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern int scanf(const char*, ...);
        extern void* memcpy(void*, const void*, size_t);
        void ok(const char* src) {
            char big[200];
            int n;
            if (scanf("%2d", &n) != 1) return;
            memcpy(big, src, n);
        }
        void bad(const char* src) {
            char small[50];
            int n;
            if (scanf("%2d", &n) != 1) return;
            memcpy(small, src, n);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(BoundsRuleTest, StrncpyConstant_DefiniteVsFits) {
    // strncpy joins the sized-copy family: a constant n past capacity
    // is a DEFINITE overflow (strncpy always writes n bytes — it pads),
    // a fitting constant stays silent.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern char* strncpy(char*, const char*, size_t);
        void bad(const char* src) {
            char buf[8];
            strncpy(buf, src, 16);
        }
        void ok(const char* src) {
            char buf[8];
            strncpy(buf, src, 8);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, MemsetUntrustedLen_Warn) {
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern int atoi(const char*);
        extern void* memset(void*, int, size_t);
        void f(const char* s) {
            char buf[16];
            int n = atoi(s);
            memset(buf, 0, n);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(BoundsRuleTest, ConfiguredUntrustedSource_WarnAndRestore) {
    // --untrusted-int-sources read_u16: the project-declared wire-length
    // source drives the possible-overflow arm; an UNLISTED extern stays
    // silent (provenance is opt-in, never guessed).
    setUntrustedIntSourceNames({"read_u16"});
    BoundsRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long size_t;
        extern unsigned short read_u16(void);
        extern int other_len(void);
        extern void* memcpy(void*, const void*, size_t);
        void f(const char* src) {
            char buf[64];
            unsigned short n = read_u16();
            memcpy(buf, src, n);
        }
        void g(const char* src) {
            char buf[64];
            int n = other_len();
            memcpy(buf, src, n);
        }
    )");
    setUntrustedIntSourceNames({});   // restore — process-global registry
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

// --- Multi-hop parameter seeding (F7A.3) ---
// Bounded (or wild) arguments now cross A -> B -> C chains: each
// seeding pass re-evaluates callers with the previous pass's proven
// entry ranges. Every pass is independently sound, so the pass cap is
// a precision knob only.

TEST(BoundsRuleTest, TwoHopParamIndex_DefiniteOOB) {
    // b(9) -> c(j) -> table[k]: [9,9] crosses two hops into a[8].
    BoundsRule rule;
    auto results = runRule(rule, R"(
        static int table[8];
        static int c_leaf(int k) { return table[k]; }
        static int b_mid(int j) { return c_leaf(j); }
        int use(void) { return b_mid(9); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(BoundsRuleTest, TwoHopParamIndex_BoundedClean) {
    // All call chains stay within the extent: silent — and a WILD
    // caller param joins to top, also silent (no guessing).
    BoundsRule rule;
    auto results = runRule(rule, R"(
        static int table[8];
        static int c_leaf(int k) { return table[k]; }
        static int b_mid(int j) { return c_leaf(j); }
        int use(void) { return b_mid(3) + b_mid(0); }
        static int c2(int k) { return table[k]; }
        static int b2(int j) { return c2(j); }
        int use2(int wild) { return b2(wild); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Struct hack / flexible array member (2026-08-01, the libarchive
// v3.8.9 FP) ---
//
// A struct whose LAST member is a `[1]`/`[0]` array, allocated with
// `malloc(sizeof(S) + n)` and written past the declared one element, is
// the pre-C99 flexible-array idiom — legal, ubiquitous, and NOT an
// overflow. The declared extent is not the real extent, so the honest
// answer is "unknown", and this rule's doctrine says unknown stays
// silent. The discriminator is the BASE: reached through a pointer the
// object's real size is unknowable from the type; on a direct object it
// is exactly the declared size and the warning is right.

TEST(BoundsRuleTest, StructHackTailArray_PointerBase_Clean) {
    // The idiom: last member char[1], object from malloc(sizeof+extra).
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern char* strcpy(char*, const char*);
        struct S { int a; char name[1]; };
        void f(struct S* p, const char* in) { strcpy(p->name, in); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, StructHackTailUnion_PointerBase_Clean) {
    // libarchive's exact shape: the tail is a UNION of [1] arrays. The
    // array is not the union's last field (w follows m), so a naive
    // "is this the last member" test misses it — union members all sit
    // at offset 0, so tail-ness belongs to the union field itself.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern char* strcpy(char*, const char*);
        struct S {
            int fd;
            union { char m[1]; int w[1]; } filename;
        };
        void f(struct S* p, const char* in) { strcpy(p->filename.m, in); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(BoundsRuleTest, ZeroLengthTailArray_PointerBase_Clean) {
    // The GNU `[0]` spelling of the same idiom.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern char* strcpy(char*, const char*);
        struct S { int a; char name[0]; };
        void f(struct S* p, const char* in) { strcpy(p->name, in); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Positive controls — the exemption must be narrow. Each of these keeps
// firing, and each fails for a different reason than the others.

TEST(BoundsRuleTest, MiddleMemberArray_PointerBase_StillWarns) {
    // Not the tail: a following member fixes this array's extent at 1,
    // so writing past it corrupts `a`. Still a real overflow.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern char* strcpy(char*, const char*);
        struct S { char name[1]; int a; };
        void f(struct S* p, const char* in) { strcpy(p->name, in); }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, TailArrayDirectObject_StillWarns) {
    // Direct object, not a pointer: sizeof(S) IS the allocation, so the
    // declared 1 element is the real extent. No struct hack possible.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern char* strcpy(char*, const char*);
        struct S { int a; char name[1]; };
        void f(const char* in) { struct S s; strcpy(s.name, in); }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, RealFixedTailArray_PointerBase_StillWarns) {
    // A genuinely sized tail array (char[32]) is a fixed buffer that
    // happens to sit last — not the struct-hack idiom, which is
    // recognisable precisely by its degenerate [0]/[1] extent.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern char* strcpy(char*, const char*);
        struct S { int a; char name[32]; };
        void f(struct S* p, const char* in) { strcpy(p->name, in); }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(BoundsRuleTest, C99FlexibleArrayMember_Clean) {
    // The real C99 spelling `char name[]` is an IncompleteArrayType, so
    // it never had a constant extent to report. Pinned here so the
    // struct-hack work cannot accidentally turn it INTO a finding.
    BoundsRule rule;
    auto results = runRule(rule, R"(
        extern char* strcpy(char*, const char*);
        struct S { int a; char name[]; };
        void f(struct S* p, const char* in) { strcpy(p->name, in); }
    )");
    EXPECT_EQ(results.size(), 0u);
}
