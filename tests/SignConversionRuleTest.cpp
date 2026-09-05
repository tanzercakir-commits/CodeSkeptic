// Untrusted sign-conversion (CWE-195 neighbourhood) — the acceptance
// battery of docs/PLAN-untrusted-sign.md.
//
// RED baseline, recorded before the rule existed: the four probe
// shapes below (out-param / return-value / obvious int->size_t /
// malloc sink) were scanned against the pre-rule binary with
// --untrusted-int-sources set and every one came back CLEAN — the
// false negative proven on nlohmann/json #3491/#3492 (pre-fix tree
// scanned three ways, all clean; fixed upstream by the `number < 0`
// guard this rule demands).
//
// The provenance doctrine holds throughout: reported ONLY when the
// value derives from a DECLARED untrusted source. An ordinary signed
// local or parameter converting to unsigned is everyday C and stays
// silent no matter its range.

#include "TestHelper.h"
#include "engine/AllocFunctions.h"
#include "rules/SignConversionRule.h"
#include "rules/IntOverflowRule.h"

#include <gtest/gtest.h>

using namespace codeskeptic;
using namespace codeskeptic::testing;

namespace {

// The registry is process-global; every configured test restores it.
struct SourceScope {
    explicit SourceScope(std::set<std::string> names) {
        setUntrustedIntSourceNames(std::move(names));
    }
    ~SourceScope() { setUntrustedIntSourceNames({}); }
};

} // namespace

// --- The trophy: nlohmann #3491/#3492, minimal replica ---------------
// `get_number` fills a signed char through a C++ REFERENCE out-param
// (the 3b extension), the explicit cast converts it to an unsigned
// size. Pre-fix nlohmann had no negativity guard; the conversion of a
// possibly-negative attacker value must report.
TEST(SignConversionRuleTest, Nlohmann_3491_UbjsonSizeValue_Reports) {
    SourceScope scope({"get_number"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        bool get_number(int format, signed char& out);
        unsigned long get_size_value(int format) {
            signed char number = 0;
            if (!get_number(format, number)) return 0;
            return static_cast<unsigned long>(number);
        }
    )");
    ASSERT_GE(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "sign-conversion");
}

// --- Probe shape B: return-value source, explicit C-style cast -------
TEST(SignConversionRuleTest, ReturnValueSource_ExplicitCast_Reports) {
    SourceScope scope({"read_byte"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        int read_byte();
        unsigned long f() {
            int number = read_byte();
            return (unsigned long)number;
        }
    )");
    ASSERT_GE(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "sign-conversion");
}

// --- Probe shape C: intrinsic atoi, IMPLICIT conversion, and the
// upper-bound-only guard that must NOT silence: `n > 100` rejected
// still leaves the whole negative range in n. This is the exact
// guard-shape nlohmann's buggy code had. ---
TEST(SignConversionRuleTest, UpperBoundOnlyGuard_StillReports) {
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        unsigned long f(const char* s) {
            int n = atoi(s);
            if (n > 100) return 0;
            unsigned long size = n;
            return size;
        }
    )");
    ASSERT_GE(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "sign-conversion");
}

// --- Probe shape D, corrected by the thesis corpus: an ALLOCATOR
// argument is NOT this rule's domain. array_from_int.c (ground-truth
// clean) is `n = atoi(argv[1]); calloc(n, ...); if (!p) ...` — a
// negative n makes calloc return NULL, which the null check handles;
// flagging it floods the commonest untrusted-alloc idiom. The
// allocator's NULL-on-over-large contract owns this case (and an
// unchecked result is the null-deref rule's finding). Silent here. ---
TEST(SignConversionRuleTest, AllocatorArgument_NotThisRulesDomain) {
    SourceScope scope({"get_number"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern void* malloc(unsigned long);
        extern void* calloc(unsigned long, unsigned long);
        bool get_number(int format, signed char& out);
        void* via_malloc(int format) {
            signed char number = 0;
            if (!get_number(format, number)) return 0;
            return malloc(static_cast<unsigned long>(number));
        }
        void* via_calloc(int format) {
            signed char number = 0;
            if (!get_number(format, number)) return 0;
            return calloc(static_cast<unsigned long>(number), 4);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- The real harm shape that IS in scope: the converted length used
// for a memory COPY, no allocator NULL net. This is the nlohmann
// danger class — a huge length driving access. ---
TEST(SignConversionRuleTest, LengthUsedForCopy_Reports) {
    SourceScope scope({"get_number"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern void* memcpy(void*, const void*, unsigned long);
        bool get_number(int format, signed char& out);
        void f(int format, char* dst, const char* src) {
            signed char number = 0;
            if (!get_number(format, number)) return;
            unsigned long len = static_cast<unsigned long>(number);
            memcpy(dst, src, len);
        }
    )");
    ASSERT_GE(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "sign-conversion");
}

// --- The guard the fix added: negativity checked -> silent on the
// surviving edge. Both spellings. ---
TEST(SignConversionRuleTest, NegativityGuard_Silent) {
    SourceScope scope({"get_number"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        bool get_number(int format, signed char& out);
        unsigned long guarded_early_return(int format) {
            signed char number = 0;
            if (!get_number(format, number)) return 0;
            if (number < 0) return 0;
            return static_cast<unsigned long>(number);
        }
        unsigned long guarded_positive_branch(const char* s) {
            int n = atoi(s);
            if (n >= 0) return (unsigned long)n;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(SignConversionRuleTest, SafePostCastRangeUse_Silent) {
    // rtp2httpd keepalive body-skip shape: a wrapped negative fails the
    // upper-bound test and the converted value never reaches the sink.
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        void consume(unsigned long);
        void f(const char* text, unsigned long available) {
            unsigned long length = (unsigned long)atoi(text);
            if (length > 0 && length <= available) {
                consume(length);
            }
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(SignConversionRuleTest, PostCastRangeDoesNotCoverLaterUse_Reports) {
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        void consume(unsigned long);
        void f(const char* text, unsigned long available) {
            unsigned long length = (unsigned long)atoi(text);
            if (length > 0 && length <= available) consume(length);
            consume(length);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "sign-conversion");
}

TEST(SignConversionRuleTest, PositiveOnlyPostCastGuard_Reports) {
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        void consume(unsigned long);
        void f(const char* text) {
            unsigned long length = (unsigned long)atoi(text);
            if (length > 0) consume(length);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
}

TEST(SignConversionRuleTest, DisjunctivePostCastGuard_Reports) {
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        void consume(unsigned long);
        void f(const char* text, unsigned long available, int bypass) {
            unsigned long length = (unsigned long)atoi(text);
            if (length <= available || bypass) {
                consume(length);
            }
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "sign-conversion");
}

TEST(SignConversionRuleTest, ArithmeticPostCastBound_Reports) {
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        void consume(unsigned long);
        void f(const char* text, unsigned long available,
               unsigned long slack) {
            unsigned long length = (unsigned long)atoi(text);
            if (length <= available + slack) {
                consume(length);
            }
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "sign-conversion");
}
// --- Unsigned source: no sign to convert, not a site. ---
TEST(SignConversionRuleTest, UnsignedSource_Silent) {
    SourceScope scope({"read_len"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        unsigned read_len();
        unsigned long f() {
            unsigned n = read_len();
            return (unsigned long)n;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Provenance is opt-in, twice over: (a) an unlisted callee's
// out-param taints nothing (the 3b OFF state — byte-for-byte the old
// clobber-to-top behaviour), (b) an ordinary signed parameter is
// everyday C, silent no matter the range. ---
TEST(SignConversionRuleTest, NoDeclaredSource_Silent) {
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        bool get_number(int format, signed char& out);
        unsigned long unlisted_callee(int format) {
            signed char number = 0;
            if (!get_number(format, number)) return 0;
            return static_cast<unsigned long>(number);
        }
        unsigned long plain_parameter(int n) {
            if (n > 100) return 0;
            return (unsigned long)n;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- The IntOverflowRule boundary, stated as a test: an explicit
// SIGNED narrowing (int -> signed char) is that rule's declared
// intent-exemption and must stay OUT of this rule too — the target is
// signed, there is no negative-to-huge story. ---
TEST(SignConversionRuleTest, SignedNarrowing_NotThisRulesQuestion) {
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern int atoi(const char*);
        signed char f(const char* s) {
            int n = atoi(s);
            return (signed char)n;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- The sink-type gate (libarchive v3.8.9 eval, BULGU 2). The rule's
// whole claim is "a negative value reinterpreted as a huge LENGTH".
// A non-size unsigned typedef — mode_t (permission bits), dev_t (a
// device id) — is unsigned but is NOT a length; converting an untrusted
// signed value there is not this rule's story, and the "negative length"
// message misframes it. libarchive set file modes/rdevs from archive
// headers and drew exactly this false positive. The gate is a denylist
// of POSIX identity/permission typedefs (fail-open, deliberately narrow:
// a fail-CLOSED allowlist would also silence uint32_t/uint16_t lengths
// read off the wire — the rule's flagship case). ---
TEST(SignConversionRuleTest, ModeTSink_NotALength_Silent) {
    SourceScope scope({"read_header_field"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned int mode_t;
        extern int read_header_field();
        extern int chmod(const char*, mode_t);
        void apply(const char* path) {
            int raw = read_header_field();
            mode_t m = (mode_t)raw;
            chmod(path, m);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(SignConversionRuleTest, DevTSink_NotALength_Silent) {
    SourceScope scope({"read_header_field"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        typedef unsigned long dev_t;
        extern int read_header_field();
        void f(dev_t* out) {
            int raw = read_header_field();
            *out = (dev_t)raw;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Positive control: the gate must NOT over-silence. A genuine size_t
// typedef sink (the length case) still reports — proving the fix is a
// targeted denylist, not a blanket "any typedef is exempt". ---
TEST(SignConversionRuleTest, SizeTTypedefSink_StillReports) {
    SourceScope scope({"read_header_field"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        typedef __SIZE_TYPE__ size_t;
        extern void* memcpy(void*, const void*, size_t);
        extern int read_header_field();
        void f(char* dst, const char* src) {
            int raw = read_header_field();
            size_t len = (size_t)raw;
            memcpy(dst, src, len);
        }
    )");
    ASSERT_GE(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "sign-conversion");
}

// --- C out-param spelling (`&x`), the scanf-shaped C twin of the
// trophy: a listed source filling through a pointer. ---
TEST(SignConversionRuleTest, PointerOutParam_CShape_Reports) {
    SourceScope scope({"read_len_into"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern int read_len_into(int* out);
        unsigned long f() {
            int n = 0;
            if (!read_len_into(&n)) return 0;
            return (unsigned long)n;
        }
    )");
    ASSERT_GE(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "sign-conversion");
}

TEST(SignConversionRuleTest, NarrowedMemoryLengthAndArrayIndexReportProvenLoss) {
    SignConversionRule rule;
    for (const auto* sink : {"memcpy(dst,src,length);", "memmove(dst,src,length);",
                             "memset(dst,0,length);", "dst[length]=0;", "(void)src[length];"}) {
        SCOPED_TRACE(sink);
        const auto code = std::string(R"(
            extern void* memcpy(void*,const void*,__SIZE_TYPE__);
            extern void* memmove(void*,const void*,__SIZE_TYPE__);
            extern void* memset(void*,int,__SIZE_TYPE__);
            void f(char* dst,const char* src){unsigned wide=70000;unsigned short length=wide;
        )") + sink + "}";
        const auto results = runRule(rule, code);
        ASSERT_EQ(results.size(), 1u);
        EXPECT_EQ(results[0].rule_id, "sign-conversion");
        EXPECT_NE(results[0].message.find("narrowing"), std::string::npos);
    }
}

TEST(SignConversionRuleTest, NarrowingRangeProofAndSafeTypeBoundaries) {
    SignConversionRule rule;
    EXPECT_EQ(runRule(rule, R"(
        void f(char* dst,unsigned n){if(n<300||n>500)return;unsigned char index=n;dst[index]=0;}
    )").size(), 1u);
    EXPECT_EQ(runRule(rule, R"(
        void f(char* dst){int wide=200;signed char index=wide;dst[index]=0;}
    )").size(), 1u);
    EXPECT_TRUE(runRule(rule, R"(
        void exact(char* dst){unsigned wide=255;unsigned char index=wide;dst[index]=0;}
        void guarded(char* dst,unsigned n){if(n>255)return;unsigned char index=n;dst[index]=0;}
        void promoted(char* dst,unsigned char n){unsigned index=n;dst[index]=0;}
        void unknown(char* dst,unsigned n){unsigned char index=n;dst[index]=0;}
        void intentional(char* dst){unsigned wide=70000;unsigned short index=(unsigned short)wide;dst[index]=0;}
        enum E:unsigned {big=70000};
        void enumeration(char* dst){E wide=big;unsigned short index=wide;dst[index]=0;}
        template<class T> void dependent(char* dst,T n){unsigned short index=n;dst[index]=0;}
    )").empty());
}

TEST(SignConversionRuleTest, NarrowingMustReachARecognizedValueSink) {
    SignConversionRule rule;
    EXPECT_TRUE(runRule(rule, R"(
        extern void* malloc(__SIZE_TYPE__);
        void consume(unsigned short);
        void ordinary(){unsigned wide=70000;unsigned short value=wide;consume(value);}
        void* allocation(){unsigned wide=70000;unsigned short length=wide;return malloc(length);}
        void unused(){unsigned wide=70000;unsigned short length=wide;}
        struct User { static void memcpy(void*,const void*,__SIZE_TYPE__); };
        void lookalike(char* dst,const char* src){unsigned wide=70000;unsigned short length=wide;User::memcpy(dst,src,length);}
    )").empty());
}

TEST(SignConversionRuleTest, NarrowingValueCopiesSurviveOnlyTheirOwnAssignments) {
    SignConversionRule rule;
    EXPECT_EQ(runRule(rule, R"(
        void f(char* dst){unsigned wide=70000;unsigned short index=wide;unsigned saved=index;index=0;wide=0;dst[saved]=0;}
    )").size(), 1u);
    EXPECT_TRUE(runRule(rule, R"(
        void overwritten(char* dst){unsigned wide=70000;unsigned short index=wide;index=0;dst[index]=0;}
        void changed(char* dst){unsigned wide=70000;unsigned short index=wide;index+=1;dst[index]=0;}
        void mutate(unsigned short*);
        void escaped(char* dst){unsigned wide=70000;unsigned short index=wide;mutate(&index);dst[index]=0;}
        void mutate_ref(unsigned short&);
        void ref_escaped(char* dst){unsigned wide=70000;unsigned short index=wide;mutate_ref(index);dst[index]=0;}
    )").empty());
}

TEST(SignConversionRuleTest, NarrowingConditionalUsePreservesPossibleLossAndKilledBranches) {
    SignConversionRule rule;
    EXPECT_EQ(runRule(rule, R"(
        void f(char* dst,int use){unsigned wide=70000;unsigned short index=wide;if(use)dst[index]=0;}
    )").size(), 1u);
    EXPECT_TRUE(runRule(rule, R"(
        void f(char* dst,int use){unsigned wide=70000;unsigned short index=wide;if(use)index=0;else return;dst[index]=0;}
    )").empty());
}

TEST(SignConversionRuleTest, NarrowingDoesNotDuplicateExistingArithmeticOrSignReports) {
    class BothRules : public Rule {
    public:
        std::string id() const override { return "both-test-only"; }
        std::string description() const override { return "two production rules"; }
        Severity defaultSeverity() const override { return Severity::Warning; }
        void check(clang::ASTContext& ctx, DiagnosticList& results) override {
            IntOverflowRule arithmetic; arithmetic.check(ctx, results);
            SignConversionRule conversion; conversion.check(ctx, results);
        }
    } both;
    auto arithmetic = runRule(both, R"(
        void f(char* dst){int a=120,b=20;signed char index=a+b;dst[index]=0;}
    )");
    ASSERT_EQ(arithmetic.size(), 1u);
    EXPECT_EQ(arithmetic[0].rule_id, "int-overflow");
    auto sign = runRule(both, R"(
        extern int atoi(const char*);
        void f(char* dst,const char* text){unsigned char index=atoi(text);dst[index]=0;}
    )");
    ASSERT_EQ(sign.size(), 1u);
    EXPECT_EQ(sign[0].rule_id, "sign-conversion");
}

TEST(SignConversionRuleTest, NarrowingNativeCLinkageAndUnreachableSinks) {
    SignConversionRule rule;
    EXPECT_EQ(runRule(rule, R"(
        extern "C" void* memcpy(void*,const void*,__SIZE_TYPE__);
        void f(char* dst,const char* src){unsigned wide=70000;unsigned short length=wide;memcpy(dst,src,length);}
    )").size(), 1u);
    EXPECT_TRUE(runRule(rule, R"(
        void impossible(char* dst){unsigned wide=70000;unsigned short index=wide;if(wide<10)dst[index]=0;}
        void overwrite_proven_branch(char* dst){unsigned wide=70000;unsigned short index=wide;if(wide>10)index=0;dst[index]=0;}
    )").empty());
}

TEST(SignConversionRuleTest, NarrowingWideRepresentableValuesAndExplicitUnknownLimits) {
    SignConversionRule rule;
    EXPECT_EQ(runRule(rule, R"(
        void signed64(char* dst){long long wide=5000000000LL;unsigned index=wide;dst[index]=0;}
        void unsigned64(char* dst){unsigned long long wide=5000000000ULL;unsigned index=wide;dst[index]=0;}
        void literal(char* dst){unsigned short index=70000U;dst[index]=0;}
    )").size(), 3u);
    EXPECT_TRUE(runRule(rule, R"(
        void exact16(char* dst){unsigned wide=65535;unsigned short index=wide;dst[index]=0;}
        void huge64(char* dst){unsigned long long wide=18446744073709551615ULL;unsigned index=wide;dst[index]=0;}
        void huge128(char* dst){__int128 wide=static_cast<__int128>(1)<<100;unsigned index=wide;dst[index]=0;}
        void mixed_join(char* dst,int select){unsigned wide=70000;unsigned short index=0;if(select)index=wide;dst[index]=0;}
        void alias_source(char* dst){unsigned wide=70000;unsigned* p=&wide;*p=0;unsigned short index=wide;dst[index]=0;}
    )").empty());
}

TEST(SignConversionRuleTest, NarrowingVolatileStorageIsNotAStableValueProof) {
    SignConversionRule rule;
    EXPECT_TRUE(runRule(rule, R"(
        void source(char* dst){volatile unsigned wide=70000;unsigned short index=wide;dst[index]=0;}
        void destination(char* dst){unsigned wide=70000;volatile unsigned short index=wide;dst[index]=0;}
    )").empty());
}
