#include "TestHelper.h"
#include "core/Capabilities.h"
#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "rules/UninitScalarRule.h"

#include <gtest/gtest.h>

using namespace codeskeptic;
using namespace codeskeptic::testing;

TEST(UninitScalarRuleTest, ActualReads) {
    for (const auto* code : {
        "int f(){int x;return x;}", "int f(){int x;return x+2;}",
        "bool f(){bool x;return x;}", "int f(){int x=x;return x;}",
        "void f(){int x;x+=1;}", "void f(){int x;++x;}",
        "void sink(int);void f(){int x;sink(x);}",
        "int f(){int x;int y;y=x;return y;}",
        "int f(){int x;{int x=1;(void)x;}return x;}",
        "int f(){int x;return static_cast<int>(x);}",
        "int f(int* a){int x;return a[x];}",
        "int f(){int x;return (0,x);}",
        "long f(){long x;return __builtin_expect(x,1);}"}) {
        SCOPED_TRACE(code);
        UninitScalarRule rule;
        auto result = runRule(rule, code);
        ASSERT_EQ(result.size(), 1u);
        EXPECT_EQ(result[0].rule_id, "uninit-scalar");
        EXPECT_EQ(result[0].severity, Severity::Error);
        EXPECT_EQ(result[0].function, "f");
        EXPECT_NE(result[0].message.find("CWE-457"), std::string::npos);
        ASSERT_EQ(result[0].notes.size(), 1u);
        EXPECT_GT(result[0].column, 0u);
    }
}

TEST(UninitScalarRuleTest, InitializationAndNonReadsAreSafe) {
    for (const auto* code : {
        "int f(){int x=1;return x;}", "int f(){int x;x=1;return x;}",
        "bool f(){bool x{};return x;}", "int f(){int x{};return x;}",
        "unsigned long f(){int x;return sizeof(x);}",
        "unsigned long f(){int x;return alignof(decltype(x));}",
        "bool f(){int x;return noexcept(x+1);}",
        "void f(){int x;(void)&x;}",
        "void f(){int x;decltype(x) y; (void)&y;}",
        "int f(){static int x;return x;}",
        "bool f(){thread_local bool x;return x;}",
        "int f(int x){return x;}",
        "int f(){int x;return 1;return x;}",
        "int f(){int x;{return 1;}return x;}",
        "[[noreturn]] void die();int f(){die();int x;return x;}",
        "int f(){int x;(x=1,x=2);return x;}",
        "int f(){int x;{x=2;}return x;}"}) {
        SCOPED_TRACE(code);
        UninitScalarRule rule;
        EXPECT_TRUE(runRule(rule, code).empty());
    }
}

TEST(UninitScalarRuleTest, EscapesAreUnknownNotDefiniteUninitialized) {
    for (const auto* code : {
        "void set(int*);int f(){int x;set(&x);return x;}",
        "void set(int&);int f(){int x;set(x);return x;}",
        "int f(){int x;int& r=x;r=1;return x;}",
        "int f(){int x;int* p=&x;*p=1;return x;}",
        "struct S{S(int&);};int f(){int x;S s(x);return x;}",
        "int f(){int x;static_cast<int&>(x)=1;return x;}",
        "int f(){int x;volatile int& r=x;r=1;return x;}"}) {
        SCOPED_TRACE(code);
        UninitScalarRule rule;
        EXPECT_TRUE(runRule(rule, code).empty());
    }
}

TEST(UninitScalarRuleTest, AddressAndSizeofDoNotInventInitialization) {
    UninitScalarRule rule;
    auto result = runRule(rule, "int f(){int x;(void)sizeof(x);return x;}");
    ASSERT_EQ(result.size(), 1u);
    // Taking an address is deliberately unknown, not an initialization proof.
    // The ordinary scalar assignment model must still catch a different local.
    result = runRule(rule, "int f(){int x;int y;(void)&x;return y;}");
    ASSERT_EQ(result.size(), 1u);
    EXPECT_NE(result[0].message.find("'y'"), std::string::npos);
}

TEST(UninitScalarRuleTest, NonScalarStorageNotClaimed) {
    for (const auto* code : {
        "int* f(){int* x;return x;}", "float f(){float x;return x;}",
        "struct S{int x;};int f(){S s;return s.x;}",
        "int f(){int a[2];return a[0];}",
        "enum E{A};E f(){E x;return x;}",
        "int f(){volatile int x;return x;}"}) {
        SCOPED_TRACE(code);
        UninitScalarRule rule;
        EXPECT_TRUE(runRule(rule, code).empty());
    }
}

TEST(UninitScalarRuleTest, UnsupportedControlDoesNotForgeStraightLineProof) {
    for (const auto* code : {
        "int f(int c){int x;if(c)x=1;else x=2;return x;}",
        "int f(int c){int x;c?(x=1):(x=2);return x;}",
        "int f(int c){int x;c&&(x=1);return x;}",
        "int f(int c){int x;while(c--)x=1;return x;}",
        "void sink(int,int);void f(){int x;sink(x=1,x);}",
        "int f(){int x;return (x=1)+x;}",
        "int f(){int x;auto init=[&](){x=1;};init();return x;}",
        "int f(){int x;asm(\"\" : \"=r\"(x));return x;}"}) {
        SCOPED_TRACE(code);
        UninitScalarRule rule;
        EXPECT_TRUE(runRule(rule, code).empty());
    }
}

TEST(UninitScalarRuleTest, CIntegerAndBoolSurface) {
    UninitScalarRule rule;
    auto result = runRuleWithArgs(rule,
        "int bad(){int x;return x;} _Bool bit(){_Bool b;return b;} "
        "int good(){static int x;return x;}", {"-std=gnu11"}, "scalar.c");
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].rule_id, "uninit-scalar");
    EXPECT_EQ(result[1].rule_id, "uninit-scalar");
}

TEST(UninitScalarRuleTest, NoReturnInsideExpressionStopsLaterReads) {
    for (const auto* code : {
        "[[noreturn]] int die();int f(){int x;return (die(),x);}",
        "[[noreturn]] int die();int f(){int x;x+=die();return 1;}",
        "int f(){int x;__builtin_assume(0);return x;}"}) {
        SCOPED_TRACE(code);
        UninitScalarRule rule;
        EXPECT_TRUE(runRule(rule, code).empty());
    }
}

TEST(UninitScalarRuleTest, CallCannotInitializeBeforeItsValueArgumentsAreRead) {
    for (const auto* code : {
        "void sink(int*,int);void f(){int x;sink(&x,x);}",
        "void sink(int&,int);void f(){int x;sink(x,x);}",
        "void sink(int,int*);void f(){int x;sink(x,&x);}",
        "struct S{S(int&,int);};void f(){int x;S s(x,x);}"}) {
        SCOPED_TRACE(code);
        UninitScalarRule rule;
        auto result = runRule(rule, code);
        ASSERT_EQ(result.size(), 1u);
        EXPECT_EQ(result[0].rule_id, "uninit-scalar");
    }
}

TEST(UninitScalarRuleTest, FiltersAndLanguageRemainEffective) {
    UninitScalarRule rule;
    setFunctionFilter({"good"});
    const auto excluded = runRule(rule, "int bad(){int x;return x;}");
    setFunctionFilter({});
    EXPECT_TRUE(excluded.empty());
    setLineRanges({{10, 12}});
    const auto outside = runRule(rule, "int bad(){int x;return x;}");
    setLineRanges({});
    EXPECT_TRUE(outside.empty());
    const auto oldLang = currentLang();
    setLang(Lang::TR);
    const auto translated = runRule(rule, "int bad(){int x;return x;}");
    setLang(oldLang);
    ASSERT_EQ(translated.size(), 1u);
    EXPECT_NE(translated[0].message.find("başlatılmadan"), std::string::npos);
}

TEST(UninitScalarRuleTest, UnevaluatedBuiltinsAreNotValueReads) {
    for (const auto* code : {
        "int f(){int x;return __builtin_constant_p(x);}",
        "int f(){int x;return __builtin_classify_type(x);}",
        "void f(){int x;__builtin_assume(x);}"}) {
        SCOPED_TRACE(code);
        UninitScalarRule rule;
        EXPECT_TRUE(runRule(rule, code).empty());
    }
    UninitScalarRule rule;
    const auto result = runRule(rule,
        "int f(){int x;(void)__builtin_constant_p(x);return x;}");
    EXPECT_EQ(result.size(), 1u);
    EXPECT_TRUE(runRuleWithArgs(rule, "void f(){int x;__assume(x);}",
                               {"-fms-extensions"}).empty());
    for (const auto* code : {
        "int f(){int x;(void)__builtin_constant_p(x=1);return x;}",
        "int f(){int x;__builtin_assume(x=1);return x;}"}) {
        SCOPED_TRACE(code);
        EXPECT_EQ(runRule(rule, code).size(), 1u);
    }
}
