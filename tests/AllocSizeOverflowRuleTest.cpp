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
