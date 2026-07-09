#include "TestHelper.h"
#include "core/FunctionFilter.h"
#include "rules/UninitPointerRule_Ex.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

namespace {

// Global filtreyi test sonunda temizleyen RAII bekcisi
struct FilterGuard {
    explicit FilterGuard(std::set<std::string> names) {
        setFunctionFilter(std::move(names));
    }
    ~FilterGuard() { setFunctionFilter({}); }
};

const char* kTwoBuggyFunctions = R"(
    void first() {
        int* a;
        int x = *a;
        (void)x;
    }
    void second() {
        int* b;
        int y = *b;
        (void)y;
    }
)";

} // anonymous namespace

TEST(FunctionFilterTest, EmptyFilter_AnalyzesAll) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, kTwoBuggyFunctions);
    ASSERT_EQ(results.size(), 2);
}

TEST(FunctionFilterTest, FilterSelectsSingleFunction) {
    FilterGuard guard({"second"});
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, kTwoBuggyFunctions);
    ASSERT_EQ(results.size(), 1);
    // Bulgu second() icindeki b degiskenine ait olmali
    EXPECT_NE(results[0].message.find("b"), std::string::npos);
}

TEST(FunctionFilterTest, FilterWithUnknownName_AnalyzesNothing) {
    FilterGuard guard({"no_such_function"});
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, kTwoBuggyFunctions);
    ASSERT_EQ(results.size(), 0);
}

TEST(FunctionFilterTest, QualifiedNameMatchesMethod) {
    FilterGuard guard({"Parser::parse"});
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, R"(
        struct Parser {
            int parse() {
                int* p;
                return *p;
            }
        };
        void other() {
            int* q;
            int x = *q;
            (void)x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].message.find("p"), std::string::npos);
}

// --- Satir araligi filtresi (--lines) ---

namespace {

struct LineGuard {
    explicit LineGuard(LineRanges ranges) {
        setLineRanges(std::move(ranges));
    }
    ~LineGuard() { setLineRanges({}); }
};

// Satir yerlesimi sabit: first() 2-6, second() 7-11
const char* kTwoFunctionsFixedLines =
    "\n"
    "void first() {\n"      // 2
    "    int* a;\n"
    "    int x = *a;\n"
    "    (void)x;\n"
    "}\n"                    // 6
    "void second() {\n"      // 7
    "    int* b;\n"
    "    int y = *b;\n"
    "    (void)y;\n"
    "}\n";                   // 11

} // anonymous namespace

TEST(LineFilterTest, EmptyRanges_AnalyzesAll) {
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, kTwoFunctionsFixedLines);
    ASSERT_EQ(results.size(), 2);
}

TEST(LineFilterTest, RangeSelectsSecondFunction) {
    LineGuard guard({{8, 9}});
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, kTwoFunctionsFixedLines);
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].message.find("b"), std::string::npos);
}

TEST(LineFilterTest, SingleLineOnSignature_Overlaps) {
    // Fonksiyon kapsamiyla tek satirlik kesisme yeterli (imza satiri)
    LineGuard guard({{2, 2}});
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, kTwoFunctionsFixedLines);
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].message.find("a"), std::string::npos);
}

TEST(LineFilterTest, RangeBetweenFunctions_Nothing) {
    LineGuard guard({{100, 200}});
    UninitPointerRule_Ex rule;
    auto results = runRule(rule, kTwoFunctionsFixedLines);
    ASSERT_EQ(results.size(), 0);
}
