#include "TestHelper.h"
#include "rules/FdResourceRule.h"

#include <gtest/gtest.h>

#include <string>

using namespace codeskeptic;
using namespace codeskeptic::testing;

namespace {

const char* kPosixDecls = R"(
    extern int open(const char*, int, ...);
    extern int openat(int, const char*, int, ...);
    extern int socket(int, int, int);
    extern int dup(int);
    extern int mkstemp(char*);
    extern int close(int);
    extern int shutdown(int, int);
)";

DiagnosticList runFdRule(const std::string& body) {
    FdResourceRule rule;
    return runRule(rule, std::string(kPosixDecls) + body);
}

void expectSingleResourceLeak(const DiagnosticList& results) {
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "resource-leak");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

} // namespace

TEST(FdResourceRuleTest, DirectAcquirersReport) {
    expectSingleResourceLeak(runFdRule(R"(
        void a(const char* p) { int fd = open(p, 0); (void)fd; }
    )"));
    expectSingleResourceLeak(runFdRule(R"(
        void a(int d, const char* p) { int fd = openat(d, p, 0); (void)fd; }
    )"));
    expectSingleResourceLeak(runFdRule(R"(
        void a() { int fd = socket(2, 1, 0); (void)fd; }
    )"));
    expectSingleResourceLeak(runFdRule(R"(
        void a(int source) { int fd = dup(source); (void)fd; }
    )"));
    expectSingleResourceLeak(runFdRule(R"(
        void a() { char n[] = "tmpXXXXXX"; int fd = mkstemp(n); (void)fd; }
    )"));
}

TEST(FdResourceRuleTest, CloseReleasesDescriptor) {
    auto results = runFdRule(R"(
        void f(const char* p) { int fd = open(p, 0); close(fd); }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, ShutdownAloneDoesNotCloseDescriptor) {
    expectSingleResourceLeak(runFdRule(R"(
        void f() { int fd = socket(2, 1, 0); shutdown(fd, 2); }
    )"));
}

TEST(FdResourceRuleTest, ShutdownThenCloseIsClean) {
    auto results = runFdRule(R"(
        void f() { int fd = socket(2, 1, 0); shutdown(fd, 2); close(fd); }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, MinusOneEarlyReturnThenCloseIsClean) {
    auto results = runFdRule(R"(
        int f(const char* p) {
            int fd = open(p, 0);
            if (fd == -1) return -1;
            close(fd);
            return 0;
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, NegativeEarlyReturnThenCloseIsClean) {
    auto results = runFdRule(R"(
        int f(const char* p) {
            int fd = open(p, 0);
            if (fd < 0) return -1;
            close(fd);
            return 0;
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, NonNegativeGuardedCloseIsClean) {
    auto results = runFdRule(R"(
        void f(const char* p) {
            int fd = open(p, 0);
            if (fd >= 0) close(fd);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, FailureReturnDoesNotHideSuccessLeak) {
    expectSingleResourceLeak(runFdRule(R"(
        int f(const char* p) {
            int fd = open(p, 0);
            if (fd == -1) return -1;
            return 0;
        }
    )"));
}

TEST(FdResourceRuleTest, UnrelatedEarlyReturnReports) {
    expectSingleResourceLeak(runFdRule(R"(
        int f(const char* p, int stop) {
            int fd = open(p, 0);
            if (stop) return 1;
            close(fd);
            return 0;
        }
    )"));
}

TEST(FdResourceRuleTest, ConditionalCloseReports) {
    expectSingleResourceLeak(runFdRule(R"(
        void f(const char* p, int release) {
            int fd = open(p, 0);
            if (release) close(fd);
        }
    )"));
}

TEST(FdResourceRuleTest, CleanupLabelClosesEveryPath) {
    auto results = runFdRule(R"(
        int f(const char* p, int stop) {
            int fd = open(p, 0);
            if (fd < 0) return -1;
            if (stop) goto cleanup;
            stop = 1;
        cleanup:
            close(fd);
            return stop;
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, ReturningDescriptorTransfersOwnership) {
    auto results = runFdRule(R"(
        int f(const char* p) { int fd = open(p, 0); return fd; }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, StoringDescriptorGloballyTransfersOwnership) {
    auto results = runFdRule(R"(
        int saved;
        void f(const char* p) { int fd = open(p, 0); saved = fd; }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, CloseThroughLocalCopyIsClean) {
    auto results = runFdRule(R"(
        void f(const char* p) {
            int fd = open(p, 0);
            int alias = fd;
            close(alias);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, DiscardedAcquisitionReports) {
    auto results = runFdRule(R"(
        void f(const char* p) { open(p, 0); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "resource-leak");
    EXPECT_EQ(results[0].severity, Severity::Warning);
    EXPECT_NE(results[0].message.find("discarded"), std::string::npos);
}

TEST(FdResourceRuleTest, NamespacedOpenIsNotPosixAcquisition) {
    auto results = runFdRule(R"(
        namespace vendor { int open(const char*, int); }
        void f(const char* p) { int value = vendor::open(p, 0); (void)value; }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, NamespacedCloseDoesNotReleaseDescriptor) {
    expectSingleResourceLeak(runFdRule(R"(
        namespace vendor { void close(int); }
        void f(const char* p) { int fd = open(p, 0); vendor::close(fd); }
    )"));
}

TEST(FdResourceRuleTest, MethodNamedCloseDoesNotReleaseDescriptor) {
    expectSingleResourceLeak(runFdRule(R"(
        struct Sink { void close(int); };
        void f(const char* p, Sink& sink) {
            int fd = open(p, 0);
            sink.close(fd);
        }
    )"));
}

TEST(FdResourceRuleTest, ReversedMinusOneGuardThenCloseIsClean) {
    auto results = runFdRule(R"(
        int f(const char* p) {
            int fd = open(p, 0);
            if (-1 == fd) return -1;
            close(fd);
            return 0;
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, NotMinusOneGuardedCloseIsClean) {
    auto results = runFdRule(R"(
        void f(const char* p) {
            int fd = open(p, 0);
            if (fd != -1) close(fd);
        }
    )");
    EXPECT_TRUE(results.empty());
}
TEST(FdResourceRuleTest, UnrecognizedIntegerFactoryIsIgnored) {
    auto results = runFdRule(R"(
        extern int make_number();
        void f() { int value = make_number(); (void)value; }
    )");
    EXPECT_TRUE(results.empty());
}
