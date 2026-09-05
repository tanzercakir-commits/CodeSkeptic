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

TEST(UninitScalarRuleTest, SafeControlAndUnsupportedSequencingDoNotForgeProof) {
    for (const auto* code : {
        "int f(int c){int x;if(c)x=1;else x=2;return x;}",
        "int f(int c){int x;c?(x=1):(x=2);return x;}",
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

TEST(UninitScalarRuleTest, DeliberateVoidDiscardDoesNotReadOrInitialize) {
    struct Case { const char* body; unsigned reports; };
    for (const bool cLanguage : {true, false}) {
        for (const bool cfg : {false, true}) {
            for (const auto& test : {
                Case{"(void)x;", 0},
                Case{"(void)(((x)));", 0},
                Case{"LV_UNUSED(x);", 0},
                Case{"LV_UNUSED(((x)));", 0},
                Case{"(void)x;return x;", 1},
                Case{"LV_UNUSED(x);return x;", 1},
                Case{"(void)(x=1);return x;", 0}}) {
                SCOPED_TRACE(cLanguage ? "C11" : "C++17");
                SCOPED_TRACE(cfg ? "CFG" : "straight-line");
                SCOPED_TRACE(test.body);
                const std::string code =
                    std::string("#define LV_UNUSED(x) ((void)x)\nint f(int c){int x;") +
                    (cfg ? "if(c){}" : "") + test.body + "return 0;}";
                UninitScalarRule rule;
                const auto result = runRuleWithArgs(rule, code,
                    {cLanguage ? "-std=gnu11" : "-std=c++17"},
                    cLanguage ? "discard.c" : "discard.cpp");
                EXPECT_EQ(result.size(), test.reports);
                for (const auto& diagnostic : result) {
                    EXPECT_EQ(diagnostic.rule_id, "uninit-scalar");
                    EXPECT_EQ(diagnostic.severity, Severity::Error);
                }
            }
        }
    }
}

TEST(UninitScalarRuleTest, DeliberateVoidDiscardRetainsRealReads) {
    for (const bool cLanguage : {true, false}) {
        for (const bool cfg : {false, true}) {
            for (const auto* body : {
                "(void)(x+1);", "(void)+x;", "(void)(int)x;",
                "(void)(x++);", "(void)(x+=1);", "(void)sink(x);",
                // Never use directReference's comma-RHS peeling to recognize
                // a bare discard: the LHS can contain the actual read.
                "int y=0;(void)(sink(x),y);", "(void)(x?1:2);",
                "volatile int v=0;(void)(v=x);"}) {
                SCOPED_TRACE(cLanguage ? "C11" : "C++17");
                SCOPED_TRACE(cfg ? "CFG" : "straight-line");
                SCOPED_TRACE(body);
                const std::string code = std::string("void sink(int);int f(int c){int x;") +
                    (cfg ? "if(c){}" : "") + body + "return 0;}";
                UninitScalarRule rule;
                const auto result = runRuleWithArgs(rule, code,
                    {cLanguage ? "-std=gnu11" : "-std=c++17"},
                    cLanguage ? "discard.c" : "discard.cpp");
                ASSERT_EQ(result.size(), 1u);
                EXPECT_EQ(result[0].rule_id, "uninit-scalar");
                EXPECT_EQ(result[0].severity, Severity::Error);
            }
        }
    }
}

TEST(UninitScalarRuleTest, DeliberateVoidDiscardKeepsUnsupportedVolatileBoundary) {
    // Volatile arithmetic already invalidates the rule's sequencing proof.
    // Do not silently claim new coverage while fixing ordinary bare discards.
    for (const bool cLanguage : {true, false}) {
        UninitScalarRule rule;
        EXPECT_TRUE(runRuleWithArgs(rule,
            "void f(){int x;volatile int v=0;(void)(v+x);}",
            {cLanguage ? "-std=gnu11" : "-std=c++17"},
            cLanguage ? "discard.c" : "discard.cpp").empty());
    }
}

TEST(UninitScalarRuleTest, DeliberateVoidDiscardPreservesConditionalWritesAndLoops) {
    struct Case { const char* body; unsigned reports; Severity severity; };
    for (const bool cLanguage : {true, false}) {
        for (const auto& test : {
            Case{"(void)(c?(x=1):(x=2));return x;", 0, Severity::Error},
            Case{"(void)(c?(x=1):0);return x;", 1, Severity::Warning},
            Case{"if(c){LV_UNUSED(x);}else{LV_UNUSED(x);}return x;", 1, Severity::Error},
            // Same declaration/discard/assignment ordering as the pinned LVGL
            // blend functions, without importing their dirty source files.
            Case{"int y;LV_UNUSED(x);LV_UNUSED(y);"
                 "for(y=0;y<c;++y){for(x=0;x<c;++x){sink(x+y);}}return 0;",
                 0, Severity::Error}}) {
            SCOPED_TRACE(cLanguage ? "C11" : "C++17");
            SCOPED_TRACE(test.body);
            const std::string code =
                std::string("#define LV_UNUSED(x) ((void)x)\nvoid sink(int);int f(int c){int x;") +
                test.body + "}";
            UninitScalarRule rule;
            const auto result = runRuleWithArgs(rule, code,
                {cLanguage ? "-std=gnu11" : "-std=c++17"},
                cLanguage ? "discard.c" : "discard.cpp");
            EXPECT_EQ(result.size(), test.reports);
            for (const auto& diagnostic : result)
                EXPECT_EQ(diagnostic.severity, test.severity);
        }
    }
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

TEST(UninitScalarRuleTest, ImplicitNoReturnOperationsRespectLifetimeOrder) {
    UninitScalarRule rule;
    const auto result = runRule(rule, R"(
        struct NoReturnCtor { [[noreturn]] NoReturnCtor(); };
        struct NoReturnDtor { NoReturnDtor(); [[noreturn]] ~NoReturnDtor(); };
        struct Normal { Normal(); ~Normal(); };
        int safe_ctor() { NoReturnCtor stop; int x; return x; }
        int safe_dtor_scope() { { NoReturnDtor stop; } int x; return x; }
        int safe_dtor_temporary() { NoReturnDtor{}; int x; return x; }
        int bad_normal_ctor() { Normal normal; int x; return x; }
        int bad_return_before_dtor() { NoReturnDtor stop; int x; return x; }
    )");
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].function, "bad_normal_ctor");
    EXPECT_EQ(result[1].function, "bad_return_before_dtor");
}

TEST(UninitScalarRuleTest, TemporaryCleanupHappensAfterValueEvaluation) {
    const std::string declarations =
        "struct D { D(); [[noreturn]] ~D(); }; D makeD(); ";
    for (const auto* body : {
        "int f(){int x;return (D{},x);}",
        "int f(){int x;int y=(D{},x);return y;}",
        "int f(){const D& guard=D{};int x;return x;}",
        "int f(){const D& guard=(0,D{});int x;return x;}",
        "int f(){const D& guard=makeD();int x;return x;}"}) {
        SCOPED_TRACE(body);
        UninitScalarRule rule;
        EXPECT_EQ(runRule(rule, declarations + body).size(), 1u);
    }
    for (const auto* body : {
        "int f(){{const D& guard=D{};}int x;return x;}",
        "int f(){{const D& guard=(0,D{});}int x;return x;}",
        "int f(){{const D& guard=makeD();}int x;return x;}"}) {
        SCOPED_TRACE(body);
        UninitScalarRule rule;
        EXPECT_TRUE(runRule(rule, declarations + body).empty());
    }
}

TEST(UninitScalarRuleTest, OnlyTheResultTemporaryHasExtendedLifetime) {
    UninitScalarRule rule;
    const auto result = runRule(rule, R"(
        struct D { D(); [[noreturn]] ~D(); };
        struct Normal { Normal(); ~Normal(); };
        int safe() { const D& ref=(D{},D{}); int x; return x; }
        int bad() { const D& ref=(Normal{},D{}); int x; return x; }
    )");
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].function, "bad");
}

TEST(UninitScalarRuleTest, ZeroArraysAndNonOwningBindingsHaveNoDestructorCall) {
    UninitScalarRule rule;
    const auto result = runRule(rule, R"(
        struct D { D(); [[noreturn]] ~D(); };
        struct C { [[noreturn]] C(); };
        D& object();
        int bad_zero_dtor() { {D objects[0];} int x; return x; }
        int bad_zero_ctor() { C objects[0]; int x; return x; }
        int bad_reference() { {D& ref=object();} int x; return x; }
        int safe_nonempty() { {D objects[1];} int x; return x; }
    )");
    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0].function, "bad_zero_dtor");
    EXPECT_EQ(result[1].function, "bad_zero_ctor");
    EXPECT_EQ(result[2].function, "bad_reference");
}

TEST(UninitScalarRuleTest, CFGBranchInitialization) {
    struct Case { const char* code; unsigned count; Severity severity; };
    for (const auto& test : {
        Case{"int f(int c){int x;if(c)x=1;return x;}", 1, Severity::Warning},
        Case{"int f(int c){int x;if(c){}else x=1;return x;}", 1, Severity::Warning},
        Case{"int f(){int x;if(x)return 1;return 0;}", 1, Severity::Error},
        Case{"int f(int c){int x;if(c)x=1;else x=2;return x;}", 0, Severity::Error},
        Case{"int f(int c){int x;if(!c)return 0;x=1;return x;}", 0, Severity::Error},
        Case{"int f(int c,int d){int x;if(c){if(d)x=1;}else x=2;return x;}", 1, Severity::Warning},
        Case{"int f(int c){int x,y;if(c)x=1;else y=1;return x+y;}", 2, Severity::Warning},
        Case{"int f(){if(false){int x;return x;}return 0;}", 0, Severity::Error}}) {
        SCOPED_TRACE(test.code);
        UninitScalarRule rule;
        const auto result = runRule(rule, test.code);
        EXPECT_EQ(result.size(), test.count);
        for (const auto& diagnostic : result) {
            EXPECT_EQ(diagnostic.rule_id, "uninit-scalar");
            EXPECT_EQ(diagnostic.severity, test.severity);
        }
    }
}

TEST(UninitScalarRuleTest, CFGLoopInitializationAndEarlyExits) {
    struct Case { const char* code; unsigned count; Severity severity; };
    for (const auto& test : {
        Case{"int f(int c){int x;while(c--)x=1;return x;}", 1, Severity::Warning},
        Case{"int f(int c){int x;while(1){if(c)break;x=1;break;}return x;}", 1, Severity::Warning},
        Case{"int f(int c){int x;do{x=1;}while(c--);return x;}", 0, Severity::Error},
        Case{"int f(int c){int x;do{if(c)continue;x=1;}while(0);return x;}", 1, Severity::Warning},
        Case{"int f(){int x;while(1){x=1;break;}return x;}", 0, Severity::Error},
        Case{"int f(int c){int x;while(c){return 0;}x=1;return x;}", 0, Severity::Error},
        Case{"void use(int);void f(int c){int x;while(c--){use(x);x=1;}}", 1, Severity::Warning},
        Case{"[[noreturn]]void die();int f(int c){int x;if(c)die();else x=1;return x;}", 0, Severity::Error}}) {
        SCOPED_TRACE(test.code);
        UninitScalarRule rule;
        const auto result = runRule(rule, test.code);
        EXPECT_EQ(result.size(), test.count);
        for (const auto& diagnostic : result) {
            EXPECT_EQ(diagnostic.rule_id, "uninit-scalar");
            EXPECT_EQ(diagnostic.severity, test.severity);
        }
    }
}

TEST(UninitScalarRuleTest, CFGShortCircuitAndArgumentReads) {
    struct Case { const char* code; unsigned count; Severity severity; };
    for (const auto& test : {
        Case{"int f(int c){int x;c&&(x=1);return x;}", 1, Severity::Warning},
        Case{"int f(int c){int x;c||(x=1);return x;}", 1, Severity::Warning},
        Case{"int f(int c){int x;c?(x=1):(x=2);return x;}", 0, Severity::Error},
        Case{"void use(int*,int);void f(int c){int x;if(c)x=1;use(&x,x);}", 1, Severity::Warning},
        Case{"void use(int&,int);void f(int c){int x;if(c)x=1;use(x,x);}", 1, Severity::Warning},
        Case{"void use(int*,int);void f(int c){int x;if(c)x=1;else x=2;use(&x,x);}", 0, Severity::Error},
        Case{"[[noreturn]]void stop(int);void f(int c){int x;if(c)stop(x);}", 1, Severity::Error},
        Case{"int f(int c){int x;if(c)x=1;else __builtin_assume(0);return x;}", 0, Severity::Error},
        Case{"int f(int c){int x;if(c)++x;return 0;}", 1, Severity::Error},
        Case{"void set(int*);int f(int c){int x;if(c)set(&x);return x;}", 0, Severity::Error},
        Case{"void set(int*);int f(int c){int x;if(c)set(&x);x=1;return x;}", 0, Severity::Error},
        Case{"int f(int c){int x;if(c)__builtin_assume(x=1);return x;}", 1, Severity::Error}}) {
        SCOPED_TRACE(test.code);
        UninitScalarRule rule;
        const auto result = runRule(rule, test.code);
        EXPECT_EQ(result.size(), test.count);
        for (const auto& diagnostic : result) EXPECT_EQ(diagnostic.severity, test.severity);
    }
}

TEST(UninitScalarRuleTest, CFGDeclarationLifetimesAndSplitDeclarations) {
    struct Case { const char* code; unsigned count; Severity severity; };
    for (const auto& test : {
        Case{"int f(int c){int x=1,y=x;if(c)y=2;return x+y;}", 0, Severity::Error},
        Case{"int f(int c){int x,y=1;if(c)y=2;return x+y;}", 1, Severity::Error},
        Case{"void use(int);void f(int c){while(c--){int x=x;use(x);}}", 1, Severity::Error},
        Case{"void use(int);void f(int c){while(c--){int x;use(x);x=1;}}", 1, Severity::Error},
        Case{"void use(int);void f(int c){while(c--){int x=1;use(x);}}", 0, Severity::Error},
        Case{"int f(int c){int x=0;while(c--){int x;x=1;}return x;}", 0, Severity::Error},
        Case{"int f(int c){int x;for(int i=0;i<c;++i)x=1;return x;}", 1, Severity::Warning},
        Case{"int f(int c){int x=0;for(int i=0;i<c;++i){if(i)continue;x=1;}return x;}", 0, Severity::Error},
        Case{"int f(){int x;for(;;){x=1;break;}return x;}", 0, Severity::Error}}) {
        SCOPED_TRACE(test.code);
        UninitScalarRule rule;
        const auto result = runRule(rule, test.code);
        EXPECT_EQ(result.size(), test.count);
        for (const auto& diagnostic : result) EXPECT_EQ(diagnostic.severity, test.severity);
    }
}

TEST(UninitScalarRuleTest, CFGBoundariesRemainDeferred) {
    for (const auto* code : {
        "void use(int,int);int f(int c){int x;if(c)use(x=1,x);return x;}",
        "int f(int c){int x;if(c)return (x=1)+x;return 0;}",
        "int f(int c){while(c--){int x=(x=1,x);return x;}return 0;}",
        "struct D{[[noreturn]]~D();};int f(int c){if(c){D stop;int x;return x;}return 0;}",
        "struct D{[[noreturn]]~D();};int f(int c){if(c)D{};int x;return x;}",
        "int f(int c){int x;if(c){auto init=[&](){x=1;};init();}return x;}",
        "int f(int c){int x;if(c)asm(\"\" : \"=r\"(x));return x;}",
        "int f(int c){int x;try{if(c)x=1;}catch(...){x=2;}return x;}"}) {
        SCOPED_TRACE(code);
        UninitScalarRule rule;
        EXPECT_TRUE(runRule(rule, code).empty());
    }
}

TEST(UninitScalarRuleTest, CFGSelectedStorageDoesNotBecomeDefiniteUninitialized) {
    // This unit does not model the identity of a selected lvalue/alias. In
    // particular, ignoring its store must not leave x "definitely" untouched.
    for (const auto* code : {
        "int f(int c){int x,y;(c?x:y)=1;return x;}",
        "int f(int c){int x,y;int& r=c?x:y;r=1;return x;}",
        "void set(int*);int f(int c){int x,y;set(&(c?x:y));return x;}",
        "int f(int c){int x,y;(c?x:y)++;return x;}"}) {
        SCOPED_TRACE(code);
        UninitScalarRule rule;
        EXPECT_TRUE(runRule(rule, code).empty());
    }
}

TEST(UninitScalarRuleTest, CFGIndirectReferenceCallsEscapeAtInvocation) {
    UninitScalarRule rule;
    EXPECT_TRUE(runRule(rule,
        "int f(int c,void(*set)(int&)){int x;if(c)x=1;set(x);return x;}").empty());
    const auto result = runRule(rule,
        "void f(int c,void(*use)(int&,int)){int x;if(c)x=1;use(x,x);}");
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].severity, Severity::Warning);
}
