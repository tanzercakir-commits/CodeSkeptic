// Untrusted allocation-size overflow (CWE-131) — acceptance battery,
// docs/PLAN.md section 4. The rule fires only when an UNSIGNED size
// arithmetic with an untrusted operand feeds an allocator and PROVABLY
// wraps its result type. Off unless the provenance flag opts in.
//
// The trophy shape is LVGL's binfont loader: `loca_count` read from a
// font file, `lv_malloc(sizeof(uint32_t) * (loca_count + 1))` — at
// UINT32_MAX the `+ 1` wraps to 0 in uint32 and the fill loop overflows
// the heap. RED-verified against the pre-rule binary (Clean there).

#include "TestHelper.h"
#include "engine/AllocFunctions.h"
#include "rules/AllocSizeOverflowRule.h"

#include <gtest/gtest.h>

using namespace codeskeptic;
using namespace codeskeptic::testing;

namespace {
struct SourceScope {
    explicit SourceScope(std::set<std::string> names) {
        setUntrustedIntSourceNames(std::move(names));
    }
    ~SourceScope() { setUntrustedIntSourceNames({}); }
};
}  // namespace

// The trophy: the LVGL loca_count shape. An untrusted uint32 length
// read through an out-param, `+ 1` in uint32, times a size — the add
// wraps to 0. malloc is the intrinsic sink.
TEST(AllocSizeOverflowRuleTest, LvglLocaCount_OutParamPlusOne_Reports) {
    SourceScope scope({"read_u32"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern int read_u32(uint32_t* out);
        void* f(void) {
            uint32_t loca_count = 0;
            if (!read_u32(&loca_count)) return 0;
            return malloc(sizeof(uint32_t) * (loca_count + 1));
        }
    )");
    ASSERT_GE(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// A return-value untrusted source, direct multiply that wraps its
// uint32 result. calloc's nmemb argument is also a size arg.
TEST(AllocSizeOverflowRuleTest, ReturnValueSource_MultiplyWraps_Reports) {
    SourceScope scope({"packet_count"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern uint32_t packet_count(void);
        void* f(void) {
            uint32_t n = packet_count();
            return malloc(n * 65536u);   /* uint32 * uint32 -> can wrap */
        }
    )");
    ASSERT_GE(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// The fix the finding demands: a bound on the untrusted length narrows
// the interval so the size cannot wrap. Silent.
TEST(AllocSizeOverflowRuleTest, BoundedLength_Silent) {
    SourceScope scope({"read_u32"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern int read_u32(uint32_t* out);
        void* f(void) {
            uint32_t loca_count = 0;
            if (!read_u32(&loca_count)) return 0;
            if (loca_count > 100000u) return 0;
            return malloc(sizeof(uint32_t) * (loca_count + 1));
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Provenance is opt-in: an ordinary unsigned parameter, no declared
// source, is everyday C and stays silent no matter the arithmetic.
TEST(AllocSizeOverflowRuleTest, NoDeclaredSource_Silent) {
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        void* f(uint32_t n) {
            return malloc(sizeof(uint32_t) * (n + 1));
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// The size arithmetic must feed an ALLOCATOR. The same untrusted
// wrapping computation stored in a plain variable is not this rule's
// site (it has no allocator under-sizing story).
TEST(AllocSizeOverflowRuleTest, NotAnAllocatorSink_Silent) {
    SourceScope scope({"read_u32"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        extern int read_u32(uint32_t* out);
        uint32_t f(void) {
            uint32_t n = 0;
            if (!read_u32(&n)) return 0;
            uint32_t total = n * 4096u;   /* not an allocator arg */
            return total;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Signed arithmetic is IntOverflowRule's question, not this one — this
// rule is unsigned-only. A signed untrusted multiply feeding malloc
// (via an implicit widen) must not be reported HERE.
TEST(AllocSizeOverflowRuleTest, SignedArithmetic_NotThisRule) {
    SourceScope scope({"read_int"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern int read_int(void);
        void* f(void) {
            int n = read_int();
            int total = n * 4096;   /* signed: IntOverflowRule's domain */
            return malloc((size_t)total);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// A project allocator wrapper (--alloc-functions) is an allocator sink
// too: the same predicate the sign-conversion rule uses.
TEST(AllocSizeOverflowRuleTest, CustomAllocatorWrapper_Reports) {
    SourceScope scope({"read_u32"});
    setAllocFunctionNames({"lv_malloc"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* lv_malloc(size_t);
        extern int read_u32(uint32_t* out);
        void* f(void) {
            uint32_t loca_count = 0;
            if (!read_u32(&loca_count)) return 0;
            return lv_malloc(sizeof(uint32_t) * (loca_count + 1));
        }
    )");
    setAllocFunctionNames({});
    ASSERT_GE(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// Phase 6.1: a 64-bit allocation-size expression needs operand-corner
// reasoning because the mathematical product does not fit the int64
// interval domain. A declared untrusted size_t and a finite factor are
// sufficient evidence that the upper corner can wrap.
TEST(AllocSizeOverflowRuleTest, SizeT64ConstantMultiply_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            return malloc(sizeof(int) * n);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// CS3-CH01-S01-U002: unsigned 64-bit allocation sums. MAX-offset is
// larger than INT64_MAX: a small-value guard alone does not test this case.
TEST(AllocSizeOverflowRuleTest, SizeT64AdditionConstant_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            return malloc(n + 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionSizeofLeft_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        struct Header { char bytes[16]; };
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            return malloc(sizeof(Header) + n);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionZero_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            return malloc(n + 0);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionExactFitGuard_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            if (n > ((size_t)-1) - 16) return 0;
            return malloc(n + 16);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionInsufficientGuard_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            if (n > ((size_t)-1) - 15) return 0;
            return malloc(n + 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionReversedSizeofGuard_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        struct Header { char bytes[16]; };
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            if (((size_t)-1) - sizeof(Header) < n) return 0;
            return malloc(sizeof(Header) + n);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionNarrowOperand_Silent) {
    SourceScope scope({"read_u32"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern unsigned int read_u32(void);
        void* f(void) {
            unsigned int n = read_u32();
            return malloc((size_t)n + 16);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionUnknownAddend_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        extern size_t runtime_header(void);
        void* f(void) {
            size_t n = read_size();
            return malloc(n + runtime_header());
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionUndeclaredSource_Silent) {
    SourceScope scope({});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) { size_t n = read_size(); return malloc(n + 16); }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionNotAllocator_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern size_t read_size(void);
        size_t f(void) { size_t n = read_size(); return n + 16; }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionGuardThenReassignment_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            if (n > ((size_t)-1) - 16) return 0;
            n = read_size();
            return malloc(n + 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionGuardOnlyOnOneBranch_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(bool check) {
            size_t n = read_size();
            if (check) {
                if (n > ((size_t)-1) - 16) return 0;
            }
            return malloc(n + 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// The canonical checked-multiply guard narrows n to SIZE_MAX / factor.
// Its quotient fits int64 for every factor greater than one, so the
// existing path-sensitive interval state can prove the product safe.
TEST(AllocSizeOverflowRuleTest, SizeT64AdditionGuardEdgesAndMutation) {
    SourceScope scope({"read_size", "read_u32"});
    struct Case { const char* name; const char* body; unsigned reports; };
    const Case cases[] = {
        {"maximum singleton overflows", "if (n != MAX) return 0; return malloc(n + 1);", 1},
        {"exact fit singleton", "if (n != MAX-16) return 0; return malloc(n + 16);", 0},
        {"strict lower edge", "if (n < MAX) return 0; return malloc(n + 1);", 1},
        {"strict upper edge", "if (n >= MAX-15) return 0; return malloc(n + 16);", 0},
        {"negated guard", "if (!(n <= MAX-16)) return 0; return malloc(n + 16);", 0},
        {"or rejection", "if (n > MAX-16 || flag) return 0; return malloc(n + 16);", 0},
        {"and rejection insufficient", "if (n > MAX-16 && flag) return 0; return malloc(n + 16);", 1},
        {"negated conjunction", "if (!(n <= MAX-16 && flag)) return 0; return malloc(n + 16);", 0},
        {"narrowing guard not a wide proof", "if ((unsigned int)n > 15) return 0; return malloc(n + 16);", 1},
        {"signed cast guard not a wide proof", "if ((long long)n > 16) return 0; return malloc(n + 16);", 1},
        {"impossible unsigned edge", "if (n > MAX) return malloc(n + 16); return 0;", 0},
        {"zero plus maximum fits", "if (n != 0) return 0; return malloc(n + MAX);", 0},
        {"one plus maximum overflows", "if (n != 1) return 0; return malloc(n + MAX);", 1},
        {"copied source", "size_t alias=n; return malloc(alias + 16);", 1},
        {"copy after guard", "if (n > MAX-16) return 0; size_t alias=n; return malloc(alias + 16);", 0},
        {"narrow source through alias", "n=read_u32(); return malloc(n + 16);", 0},
        {"small compound update safe", "if (n > 100) return 0; n+=1; return malloc(n + 16);", 0},
        {"wide compound update invalidates", "if (n > MAX-16) return 0; n+=1; return malloc(n + 16);", 1},
        {"pointer alias invalidates old small guard", "size_t* p=&n; if (n>100) return 0; *p=read_size(); return malloc(n+16);", 1},
        {"reference alias invalidates old small guard", "size_t& alias=n; if (n>100) return 0; alias=read_size(); return malloc(n+16);", 1},
        {"conditional reference alias invalidates", "size_t other=0; size_t& alias=flag?n:other; if(n>100) return 0; alias=read_size(); return malloc(n+16);", 1},
        {"guard after alias mutation", "size_t* p=&n; *p=read_size(); if (n>MAX-16) return 0; return malloc(n+16);", 0},
        {"escaped guard survives unrelated store", "size_t* p=&n; if(n>MAX-16) return 0; flag=0; return malloc(n+16);", 0},
        {"escaped guard survives unrelated increment", "size_t* p=&n; if(n>MAX-16) return 0; ++flag; return malloc(n+16);", 0},
        {"escaped guard survives pointer rebinding", "size_t* p=&n; if(n>MAX-16) return 0; p=nullptr; return malloc(n+16);", 0},
        {"guard covers product plus header", "if(n>(MAX-16)/16) return 0; return malloc(n*16+16);", 0},
        {"guard covers product but not header", "if(n>MAX/16) return 0; return malloc(n*16+16);", 1},
        {"guard covers multiply assignment", "if(n>(MAX-16)/16) return 0; n*=16; return malloc(n+16);", 0},
        {"multiply assignment still exceeds header budget", "if(n>MAX/16) return 0; n*=16; return malloc(n+16);", 1},
        {"multiply by zero assignment", "n*=0; return malloc(n+16);", 0},
        {"casted product retains guard", "if(n>(MAX-16)/16) return 0; return malloc((size_t)(n*16)+16);", 0},
        {"guard covers nested addition", "if(n>MAX-32) return 0; return malloc(n+16+16);", 0},
        {"alias mutation invalidates product guard", "size_t* p=&n; if(n>100) return 0; *p=read_size(); return malloc(n*16+16);", 1},
        {"loop may invalidate guard", "if(n>MAX-16) return 0; while(flag) {n=read_size(); flag=0;} return malloc(n+16);", 1},
        {"guard after loop", "while(flag) {n=read_size(); flag=0;} if(n>MAX-16) return 0; return malloc(n+16);", 0},
        // Silent here means unsupported origin, not a proof of safety. The
        // existing provenance policy discards an unknown reference mutation.
        {"unknown reference provenance", "mutate(n); return malloc(n+16);", 0},
        {"indirect unknown reference provenance", "void (*m)(size_t&)=mutate; m(n); return malloc(n+16);", 0},
    };
    for (const auto& item : cases) {
        SCOPED_TRACE(item.name);
        AllocSizeOverflowRule rule;
        auto results = runRule(rule, std::string(R"(
            typedef __SIZE_TYPE__ size_t;
            #define MAX ((size_t)-1)
            extern void* malloc(size_t);
            extern size_t read_size(void);
            extern unsigned int read_u32(void);
            extern void mutate(size_t&);
            void* f(int flag) { size_t n=read_size();
        )") + item.body + "}");
        EXPECT_EQ(results.size(), item.reports);
        for (const auto& result : results)
            EXPECT_EQ(result.rule_id, "alloc-size-overflow");
    }
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionSignedOriginAndWideAliasGuard) {
    SourceScope scope({"read_signed"});
    for (bool guarded : {false, true}) {
        SCOPED_TRACE(guarded);
        AllocSizeOverflowRule rule;
        auto results = runRule(rule, std::string(R"(
            typedef __SIZE_TYPE__ size_t;
            extern void* malloc(size_t);
            extern long long read_signed(void);
            void* f(void) { size_t n=read_signed();
        )") + (guarded ? "if(n>((size_t)-1)-16) return 0;" : "") +
            "return malloc(n+16); }");
        EXPECT_EQ(results.size(), guarded ? 0u : 1u);
    }
}

TEST(AllocSizeOverflowRuleTest, SizeT64AdditionNarrowedSignedResidue) {
    SourceScope scope({"read_signed"});
    for (bool overflowing : {false, true}) {
        SCOPED_TRACE(overflowing);
        AllocSizeOverflowRule rule;
        auto results = runRule(rule, std::string(R"(
            typedef __SIZE_TYPE__ size_t;
            extern void* malloc(size_t);
            extern long long read_signed(void);
            void* f(void) {
                long long raw=read_signed();
                if(raw < -256 || raw > -255) return 0;
                unsigned char narrowed=(unsigned char)raw;
                return malloc((size_t)narrowed +
        )") + (overflowing ? "((size_t)-1)" : "(((size_t)-1)-1)") + "); }");
        EXPECT_EQ(results.size(), overflowing ? 1u : 0u);
    }
}

TEST(AllocSizeOverflowRuleTest, SizeT64DivisionGuard_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            if (n > ((size_t)-1) / 16) return 0;
            return malloc(n * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// A guard for a smaller factor does not prove the actual product safe.
TEST(AllocSizeOverflowRuleTest, SizeT64InsufficientDivisionGuard_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            if (n > ((size_t)-1) / 8) return 0;
            return malloc(n * 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// A second runtime value is not a finite corner witness. Shadowing its
// full unsigned type range would turn ordinary unknowns into reports.
TEST(AllocSizeOverflowRuleTest, SizeT64UnknownFactor_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        extern size_t runtime_factor(void);
        void* f(void) {
            size_t n = read_size();
            size_t factor = runtime_factor();
            return malloc(n * factor);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Widening a 32-bit source before multiplying by 16 is provably safe in
// the 64-bit result type and must not inherit the size_t full-range corner.
TEST(AllocSizeOverflowRuleTest, SizeT64NarrowOperandPromoted_Silent) {
    SourceScope scope({"read_u32"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern uint32_t read_u32(void);
        void* f(void) {
            uint32_t n = read_u32();
            return malloc((size_t)n * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// A stable signed-to-unsigned chain retains its actual signed source range.
// A full-range signed 64-bit source can reach both UINT64_MAX through -1 and
// large positive corners, so multiplication by 16 provably wraps.
TEST(AllocSizeOverflowRuleTest, SizeT64SignedSourceCast_Reports) {
    SourceScope scope({"read_signed"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern long long read_signed(void);
        void* f(void) {
            long long n = read_signed();
            return malloc((size_t)n * 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// Multiplication by one cannot cross the result type's maximum.
TEST(AllocSizeOverflowRuleTest, SizeT64IdentityFactor_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            return malloc(n * 1);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// A non-negative guard alone is not enough, but a factor-aware upper bound
// proves the signed value safe before its unsigned conversion.
TEST(AllocSizeOverflowRuleTest, SizeT64SignedSourceDivisionGuard_Silent) {
    SourceScope scope({"read_signed"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern long long read_signed(void);
        void* f(void) {
            long long n = read_signed();
            if (n < 0) return 0;
            if ((size_t)n > ((size_t)-1) / 16) return 0;
            return malloc((size_t)n * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// The signed origin remains visible through a stable unsigned local alias.
TEST(AllocSizeOverflowRuleTest, SizeT64SignedAlias_Reports) {
    SourceScope scope({"read_signed"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern long long read_signed(void);
        void* f(void) {
            long long raw = read_signed();
            size_t count = (size_t)raw;
            return malloc(count * 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// Once a signed 32-bit source is proven non-negative, widening it to size_t
// cannot make a 64-bit product by 16 wrap. The alias must retain that bound.
TEST(AllocSizeOverflowRuleTest, SizeT64NonNegativeSigned32Alias_Silent) {
    SourceScope scope({"read_signed32"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern int read_signed32(void);
        void* f(void) {
            int raw = read_signed32();
            size_t count = (size_t)raw;
            if (raw < 0) return 0;
            return malloc(count * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Bounds on the unchanged signed source remain valid after a stable alias was
// formed; together they prove the aliased product safe.
TEST(AllocSizeOverflowRuleTest, SizeT64SignedAliasGuarded_Silent) {
    SourceScope scope({"read_signed"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern long long read_signed(void);
        void* f(void) {
            long long raw = read_signed();
            size_t count = (size_t)raw;
            if (raw < 0) return 0;
            if ((size_t)raw > ((size_t)-1) / 16) return 0;
            return malloc(count * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Ignoring the checked-multiply status still feeds the wrapped output to the
// allocator. The finite untrusted corner proves that overflow is reachable.
TEST(AllocSizeOverflowRuleTest, BuiltinMulOverflowIgnored_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            size_t bytes = 0;
            (void)__builtin_mul_overflow(n, (size_t)16, &bytes);
            return malloc(bytes);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// The false edge of the builtin status proves that its output did not wrap.
TEST(AllocSizeOverflowRuleTest, BuiltinMulOverflowDirectCheck_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            size_t bytes = 0;
            if (__builtin_mul_overflow(n, (size_t)16, &bytes)) return 0;
            return malloc(bytes);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Saving the status in a stable local and rejecting true is equivalent to the
// direct checked-multiply guard.
TEST(AllocSizeOverflowRuleTest, BuiltinMulOverflowStatusCheck_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            size_t bytes = 0;
            int overflow = __builtin_mul_overflow(n, (size_t)16, &bytes);
            if (overflow) return 0;
            return malloc(bytes);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Using the builtin output on the true/overflow edge is an under-allocation.
TEST(AllocSizeOverflowRuleTest, BuiltinMulOverflowTrueBranch_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            size_t bytes = 0;
            if (__builtin_mul_overflow(n, (size_t)16, &bytes))
                return malloc(bytes);
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// A runtime factor supplies no finite multiplication witness.
TEST(AllocSizeOverflowRuleTest, BuiltinMulOverflowUnknownFactor_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        extern size_t runtime_factor(void);
        void* f(void) {
            size_t n = read_size();
            size_t bytes = 0;
            (void)__builtin_mul_overflow(n, runtime_factor(), &bytes);
            return malloc(bytes);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// A later plain assignment kills the builtin-output relation.
TEST(AllocSizeOverflowRuleTest, BuiltinMulOverflowOutputReassigned_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            size_t bytes = 0;
            (void)__builtin_mul_overflow(n, (size_t)16, &bytes);
            bytes = 16;
            return malloc(bytes);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Checked arithmetic without an allocator consumer is outside this rule.
TEST(AllocSizeOverflowRuleTest, BuiltinMulOverflowNonAllocator_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern size_t read_size(void);
        size_t f(void) {
            size_t n = read_size();
            size_t bytes = 0;
            (void)__builtin_mul_overflow(n, (size_t)16, &bytes);
            return bytes;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Narrowing the signed source to uint32_t bounds the later size_t corner.
TEST(AllocSizeOverflowRuleTest, NarrowedSignedCornerSmallFactor_Silent) {
    SourceScope scope({"read_signed"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern long long read_signed(void);
        void* f(void) {
            long long raw = read_signed();
            uint32_t narrowed = (uint32_t)raw;
            return malloc((size_t)narrowed * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// The same exact uint32_t residue corner can still prove a 64-bit wrap when
// the constant factor is large enough.
TEST(AllocSizeOverflowRuleTest, NarrowedSignedCornerLargeFactor_Reports) {
    SourceScope scope({"read_signed"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern long long read_signed(void);
        void* f(void) {
            long long raw = read_signed();
            uint32_t narrowed = (uint32_t)raw;
            return malloc((size_t)narrowed * 4294967298ULL);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// A plain assignment chain has no stable single definition in this slice.
TEST(AllocSizeOverflowRuleTest, UnstableSignedAlias_Silent) {
    SourceScope scope({"read_signed"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern long long read_signed(void);
        void* f(void) {
            long long raw = read_signed();
            size_t count = 0;
            count = (size_t)raw;
            return malloc(count * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Comparing a saved status with zero proves the same safe edge as `if (flag)`.
TEST(AllocSizeOverflowRuleTest, BuiltinMulOverflowEqualityCheck_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* f(void) {
            size_t n = read_size();
            size_t bytes = 0;
            int overflow = __builtin_mul_overflow(n, (size_t)16, &bytes);
            if (overflow != 0) return 0;
            return malloc(bytes);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// An unknown callee may rewrite the output, so the exact builtin relation is
// killed before the allocator and cannot support a report.
TEST(AllocSizeOverflowRuleTest, BuiltinMulOverflowOutputEscaped_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        extern void rewrite(size_t* value);
        void* f(void) {
            size_t n = read_size();
            size_t bytes = 0;
            (void)__builtin_mul_overflow(n, (size_t)16, &bytes);
            rewrite(&bytes);
            return malloc(bytes);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// The fixed unsigned-long-long builtin uses the same checked-output contract.
TEST(AllocSizeOverflowRuleTest, BuiltinUnsignedLongLongIgnored_Reports) {
    SourceScope scope({"read_ull"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern unsigned long long read_ull(void);
        void* f(void) {
            unsigned long long n = read_ull();
            unsigned long long bytes = 0;
            (void)__builtin_umulll_overflow(n, 16ULL, &bytes);
            return malloc((size_t)bytes);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// A non-const C++ reference may rewrite the output just like an address escape.
TEST(AllocSizeOverflowRuleTest, BuiltinMulOverflowReferenceEscaped_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        extern void rewrite(size_t& value);
        void* f(void) {
            size_t n = read_size();
            size_t bytes = 0;
            (void)__builtin_mul_overflow(n, (size_t)16, &bytes);
            rewrite(bytes);
            return malloc(bytes);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Phase 6.3: an exact wrapper parameter that reaches an allocator size is
// itself a size sink. The caller-side arithmetic must retain the sink.
TEST(AllocSizeOverflowRuleTest, VisibleAllocatorWrapper_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* alloc_bytes(size_t bytes) { return malloc(bytes); }
        void* f(void) {
            size_t count = read_size();
            return alloc_bytes(count * 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// The existing SCC solver must carry the exact sink through visible wrappers.
TEST(AllocSizeOverflowRuleTest, VisibleAllocatorWrapperChain_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* alloc_bytes(size_t bytes) { return malloc(bytes); }
        void* alloc_chain(size_t bytes) { return alloc_bytes(bytes); }
        void* f(void) {
            size_t count = read_size();
            return alloc_chain(count * 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// Whole-program harvest carries the same exact relation across a TU boundary.
TEST(AllocSizeOverflowRuleTest, CrossTUAllocatorWrapper_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRuleCrossTU(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        void* alloc_bytes(size_t bytes) { return malloc(bytes); }
    )",
                                  R"(
        typedef __SIZE_TYPE__ size_t;
        extern size_t read_size(void);
        void* alloc_bytes(size_t);
        void* f(void) {
            size_t count = read_size();
            return alloc_bytes(count * 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// A declaration without a harvested or visible body grants no sink authority.
TEST(AllocSizeOverflowRuleTest, BodylessAllocatorWrapper_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern size_t read_size(void);
        extern void* opaque_alloc(size_t);
        void* f(void) {
            size_t count = read_size();
            return opaque_alloc(count * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Transforming a parameter before forwarding it is not an exact bounded
// parameter-to-size relation, so callers cannot borrow allocator authority.
TEST(AllocSizeOverflowRuleTest, TransformedAllocatorWrapper_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* adjusted_alloc(size_t bytes) { return malloc(bytes + 1); }
        void* f(void) {
            size_t count = read_size();
            return adjusted_alloc(count * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Pinned allocation replay: LVGL v9.2.2 commit 7f07a129, lines 505-524
// of lv_binfont_loader.c. The real loop indexes glyph_offset with `i`, not
// directly with loca_count, so the allocation report is retained without
// overstating that use as exact same-origin access evidence.
TEST(AllocSizeOverflowRuleTest, LvglPinnedAllocationReplay_Reports) {
    SourceScope scope({"read_u32"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern int read_u32(uint32_t*);
        void load_table(void) {
            uint32_t loca_count = 0;
            if (!read_u32(&loca_count)) return;
            uint32_t* glyph_offset =
                (uint32_t*)malloc(sizeof(uint32_t) * (loca_count + 1));
            for (unsigned i = 0; i < loca_count; ++i)
                glyph_offset[i] = i;
        }
    )",
                           "lv_binfont_loader.c");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_TRUE(results[0].notes.empty());
}
// An unrelated constant access cannot be advertised as count-linked evidence.
TEST(AllocSizeOverflowRuleTest, UnrelatedAccess_HasNoTrace) {
    SourceScope scope({"read_u32"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern int read_u32(uint32_t*);
        void load_table(void) {
            uint32_t loca_count = 0;
            if (!read_u32(&loca_count)) return;
            uint32_t* table =
                (uint32_t*)malloc(sizeof(uint32_t) * (loca_count + 1));
            table[0] = 0;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_TRUE(results[0].notes.empty());
}
// A controlled single function-pointer target carries the exact sink relation.
TEST(AllocSizeOverflowRuleTest, IndirectAllocatorWrapper_Reports) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        typedef void* (*allocator_fn)(size_t);
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* alloc_bytes(size_t bytes) { return malloc(bytes); }
        void* f(void) {
            allocator_fn allocate = alloc_bytes;
            size_t count = read_size();
            return allocate(count * 16);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "alloc-size-overflow");
}

// A closed target set that disagrees on allocator reachability degrades to
// Unknown. The indirect call therefore grants no sink authority.
TEST(AllocSizeOverflowRuleTest, MixedIndirectAllocatorTargets_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        typedef void* (*allocator_fn)(size_t);
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void* alloc_bytes(size_t bytes) { return malloc(bytes); }
        void* inspect_bytes(size_t bytes) { (void)bytes; return 0; }
        void* f(int choose) {
            allocator_fn target = choose ? alloc_bytes : inspect_bytes;
            size_t count = read_size();
            return target(count * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// Cross-TU overloads collide in the persisted qualified-name/arity key. A
// Sink/None disagreement must merge to Unknown instead of a false authority.
TEST(AllocSizeOverflowRuleTest, CrossTUOverloadConflict_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRuleCrossTU(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        void* project_alloc(size_t bytes) { return malloc(bytes); }
        void* project_alloc(unsigned bytes) { (void)bytes; return 0; }
    )",
                                  R"(
        typedef __SIZE_TYPE__ size_t;
        extern size_t read_size(void);
        void* project_alloc(size_t);
        void* f(void) {
            size_t count = read_size();
            return project_alloc(count * 16);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// A bounded memory primitive is access evidence only when its destination is
// the exact allocation binding and its size shares the untrusted origin.
TEST(AllocSizeOverflowRuleTest, MemoryAccessEvidence_HasTrace) {
    SourceScope scope({"read_u32"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern void* memset(void*, int, size_t);
        extern int read_u32(uint32_t*);
        void load_table(void) {
            uint32_t loca_count = 0;
            if (!read_u32(&loca_count)) return;
            uint32_t* table =
                (uint32_t*)malloc(sizeof(uint32_t) * (loca_count + 1));
            memset(table, 0, (size_t)loca_count * sizeof(uint32_t));
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    ASSERT_EQ(results[0].notes.size(), 1u);
    EXPECT_NE(results[0].notes[0].message.find("access"), std::string::npos);
}
// A later access through a reassigned local no longer refers to the allocation
// result, even when its index happens to share the same untrusted origin.
TEST(AllocSizeOverflowRuleTest, ReassignedAllocationBinding_HasNoTrace) {
    SourceScope scope({"read_u32"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int uint32_t;
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern int read_u32(uint32_t*);
        void load_table(uint32_t* replacement) {
            uint32_t loca_count = 0;
            if (!read_u32(&loca_count)) return;
            uint32_t* table =
                (uint32_t*)malloc(sizeof(uint32_t) * (loca_count + 1));
            table = replacement;
            table[loca_count] = 0;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_TRUE(results[0].notes.empty());
}
// A lambda body has its own function summary. Merely constructing a lambda
// must not grant allocator-sink authority to the enclosing function.
TEST(AllocSizeOverflowRuleTest, UninvokedLambdaAllocatorWrapper_Silent) {
    SourceScope scope({"read_size"});
    AllocSizeOverflowRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* malloc(size_t);
        extern size_t read_size(void);
        void inspect(size_t bytes) {
            auto deferred = [bytes]() { return malloc(bytes); };
            (void)deferred;
        }
        void caller(void) {
            size_t count = read_size();
            inspect(count * 16);
        }
    )");
    EXPECT_TRUE(results.empty());
}
