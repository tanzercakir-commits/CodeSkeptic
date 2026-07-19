#include "TestHelper.h"

#include "engine/FatalCalls.h"
#include "rules/DivByZeroRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/NullDerefRule.h"

#include <gtest/gtest.h>

using namespace codeskeptic;
using codeskeptic::testing::runRule;

namespace {

// Registers fatal-call names for one test and ALWAYS clears them on
// exit — the registry is process-global, and the single-process test
// run is exactly the mode that catches leaked state.
class FatalScope {
public:
    explicit FatalScope(std::set<std::string> names) {
        setFatalCallNames(std::move(names));
    }
    ~FatalScope() { setFatalCallNames({}); }
};

// The shadPS4 ASSERT shape: the failure handler deliberately lacks
// [[noreturn]] ("sometimes we want to continue after an assert"), so
// the CFG cannot prune the failure path by itself.
constexpr const char* kAssertShape = R"(
    void assert_fail_impl();
    struct S { int x; };
    int f(S* p) {
        if (!p) {
            assert_fail_impl();
        }
        return p->x;
    }
)";

TEST(FatalCallsTest, UnregisteredHandler_PathSurvives_Warns) {
    // Pin of the honest default: without --fatal-asserts the failure
    // path falls through and the dereference IS possibly-null.
    NullDerefRule rule;
    auto results = runRule(rule, kAssertShape);
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(FatalCallsTest, RegisteredHandler_KillsNullPath) {
    FatalScope fatal({"assert_fail_impl"});
    NullDerefRule rule;
    auto results = runRule(rule, kAssertShape);
    ASSERT_EQ(results.size(), 0);
}

TEST(FatalCallsTest, RegisteredHandler_KillsZeroPath) {
    // The shadPS4 ASSERT_MSG(b != 0, ...) shape from
    // constant_propagation_pass.cpp.
    FatalScope fatal({"assert_fail_impl"});
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        void assert_fail_impl();
        unsigned f(unsigned a, unsigned b) {
            if (!(b != 0)) {
                assert_fail_impl();
            }
            return a / b;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(FatalCallsTest, DeadCodeAfterFatalCall_NotReported) {
    // Statements after the fatal call never execute — no reports from
    // dead code (same block AND the whole dead tail of the path).
    FatalScope fatal({"panic"});
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void panic();
        int f(int* p) {
            if (!p) {
                panic();
                return *p;
            }
            return *p;
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(FatalCallsTest, LeakOnFatalPath_NotReported) {
    // A path that dies in a fatal handler never reaches the function
    // exit — the allocation on it is not an end-of-function leak.
    FatalScope fatal({"fatal_error"});
    MemoryLeakRule_Ex rule;
    auto results = runRule(rule, R"(
        void fatal_error();
        extern "C" void* malloc(unsigned long);
        extern "C" void free(void*);
        void f(bool ok) {
            char* d = (char*)malloc(16);
            if (!ok) {
                fatal_error();
            }
            free(d);
        }
    )");
    ASSERT_EQ(results.size(), 0);
}

TEST(FatalCallsTest, OtherCallsUnaffected) {
    // Only registered names kill paths; an ordinary call on the
    // failure branch changes nothing.
    FatalScope fatal({"assert_fail_impl"});
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        void log_error();
        struct S { int x; };
        int f(S* p) {
            if (!p) {
                log_error();
            }
            return p->x;
        }
    )");
    ASSERT_EQ(results.size(), 1);
}

TEST(FatalCallsTest, ScopeCleared_WarningReturns) {
    // The registry must not leak between analyses (MCP server / test
    // process): after clearing, the warning is back.
    {
        FatalScope fatal({"assert_fail_impl"});
        NullDerefRule rule;
        ASSERT_EQ(runRule(rule, kAssertShape).size(), 0);
    }
    NullDerefRule rule;
    ASSERT_EQ(runRule(rule, kAssertShape).size(), 1);
}

} // namespace
