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

// The canonical checked-multiply guard narrows n to SIZE_MAX / factor.
// Its quotient fits int64 for every factor greater than one, so the
// existing path-sensitive interval state can prove the product safe.
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

// Signed-to-unsigned conversion chains belong to the next Phase 6 slice.
// The 64-bit unsigned-corner fallback must not treat a signed source as if
// its declared domain were the full size_t range.
TEST(AllocSizeOverflowRuleTest, SizeT64SignedSourceCast_NotThisSlice_Silent) {
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
    EXPECT_EQ(results.size(), 0u);
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
