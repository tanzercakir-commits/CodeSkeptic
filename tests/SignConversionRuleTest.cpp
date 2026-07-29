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

// --- Probe shape D: the malloc sink — the conversion feeding an
// allocation size is the same site, reported once. ---
TEST(SignConversionRuleTest, MallocSizeFromOutParam_Reports) {
    SourceScope scope({"get_number"});
    SignConversionRule rule;
    auto results = runRule(rule, R"(
        extern void* malloc(unsigned long);
        bool get_number(int format, signed char& out);
        void* f(int format) {
            signed char number = 0;
            if (!get_number(format, number)) return 0;
            return malloc(static_cast<unsigned long>(number));
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
