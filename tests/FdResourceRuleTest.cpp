#include "TestHelper.h"
#include "engine/FunctionSummary.h"
#include "rules/FdResourceRule.h"

#include <gtest/gtest.h>

#include <fstream>
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

struct GlobalStoreGuard {
    GlobalStoreGuard() { SummaryRegistry::instance().clearGlobal(); }
    ~GlobalStoreGuard() { SummaryRegistry::instance().clearGlobal(); }
};

std::string writeModel(const std::string& name,
                       const std::string& content) {
    const std::string path = ::testing::TempDir() + name;
    std::ofstream out(path);
    out << content;
    return path;
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

TEST(FdResourceRuleTest, AcquisitionWrapperAndChainReport) {
    expectSingleResourceLeak(runFdRule(R"(
        int acquire(const char* p) { return open(p, 0); }
        int acquire_chain(const char* p) { return acquire(p); }
        void f(const char* p) {
            int fd = acquire_chain(p);
            (void)fd;
        }
    )"));
}

TEST(FdResourceRuleTest, ClosingWrappedAcquisitionIsClean) {
    auto results = runFdRule(R"(
        int acquire(const char* p) { return open(p, 0); }
        void f(const char* p) {
            int fd = acquire(p);
            close(fd);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, FailureSentinelWrapperStillReportsSuccessLeak) {
    expectSingleResourceLeak(runFdRule(R"(
        int acquire(const char* p, int fail) {
            if (fail) return -1;
            return open(p, 0);
        }
        void f(const char* p, int fail) {
            int fd = acquire(p, fail);
            (void)fd;
        }
    )"));
}

TEST(FdResourceRuleTest, ConsumingWrapperChainClosesDescriptor) {
    auto results = runFdRule(R"(
        void release_fd(int fd) { close(fd); }
        void release_chain(int fd) { release_fd(fd); }
        void f(const char* p) {
            int fd = open(p, 0);
            release_chain(fd);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, ConditionalConsumerDoesNotSuppressLeak) {
    expectSingleResourceLeak(runFdRule(R"(
        void maybe_release(int fd, int release) {
            if (release) close(fd);
        }
        void f(const char* p, int release) {
            int fd = open(p, 0);
            maybe_release(fd, release);
        }
    )"));
}

TEST(FdResourceRuleTest, TransferWrapperEscapesDescriptor) {
    auto results = runFdRule(R"(
        int saved;
        void keep_fd(int fd) { saved = fd; }
        void f(const char* p) {
            int fd = open(p, 0);
            keep_fd(fd);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, ExplicitV10ModelsCreateAndConsumeDescriptors) {
    GlobalStoreGuard guard;
    const std::string model = writeModel(
        "fd_resource_model.csk",
        "codeskeptic-summaries v10\n"
        "vendor_open/0\tU\t-\tU\t-\t-\t-\t-\t-\t-\t-\t-\tO\t-\n"
        "vendor_close/1\tU\tO\tU\t-\t-\t-\t-\tO\tU\tU\tC\tU\t?\n"
        "vendor_keep/1\tU\tO\tU\t-\t-\t-\t-\tO\tU\tU\tT\tU\t?\n");
    ASSERT_TRUE(SummaryRegistry::instance().loadGlobal(model));

    expectSingleResourceLeak(runFdRule(R"(
        extern int vendor_open();
        void f() { int fd = vendor_open(); (void)fd; }
    )"));
    auto results = runFdRule(R"(
        extern void vendor_close(int);
        void f(const char* p) {
            int fd = open(p, 0);
            vendor_close(fd);
        }
    )");
    EXPECT_TRUE(results.empty());
    results = runFdRule(R"(
        extern void vendor_keep(int);
        void f(const char* p) {
            int fd = open(p, 0);
            vendor_keep(fd);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, BorrowedAndUnknownModelsDoNotSuppressLeak) {
    GlobalStoreGuard guard;
    const std::string model = writeModel(
        "fd_non_consuming_model.csk",
        "codeskeptic-summaries v10\n"
        "vendor_borrow/1\tU\tO\tU\t-\t-\t-\t-\tO\tU\tU\tB\tU\t?\n");
    ASSERT_TRUE(SummaryRegistry::instance().loadGlobal(model));

    expectSingleResourceLeak(runFdRule(R"(
        extern void vendor_borrow(int);
        extern void vendor_unknown(int);
        void f(const char* p) {
            int fd = open(p, 0);
            vendor_borrow(fd);
            vendor_unknown(fd);
        }
    )"));
}

TEST(FdResourceRuleTest, ConditionalTransferDoesNotSuppressLeak) {
    expectSingleResourceLeak(runFdRule(R"(
        int saved;
        void maybe_keep(int fd, int keep) {
            if (keep) saved = fd;
        }
        void f(const char* p, int keep) {
            int fd = open(p, 0);
            maybe_keep(fd, keep);
        }
    )"));
}

TEST(FdResourceRuleTest, CrossTUAcquisitionWrapperReports) {
    FdResourceRule rule;
    auto results = runRuleCrossTU(rule, R"(
        extern int open(const char*, int, ...);
        int acquire(const char* p) { return open(p, 0); }
    )", R"(
        int acquire(const char*);
        void f(const char* p) {
            int fd = acquire(p);
            (void)fd;
        }
    )");
    expectSingleResourceLeak(results);
}

TEST(FdResourceRuleTest, CrossTUConsumerWrapperClosesDescriptor) {
    FdResourceRule rule;
    auto results = runRuleCrossTU(rule, R"(
        extern int close(int);
        void release_fd(int fd) { close(fd); }
    )", R"(
        extern int open(const char*, int, ...);
        void release_fd(int);
        void f(const char* p) {
            int fd = open(p, 0);
            release_fd(fd);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, ConflictingModelsDegradeToUnknown) {
    GlobalStoreGuard guard;
    const std::string owned = writeModel(
        "fd_owned_model.csk",
        "codeskeptic-summaries v10\n"
        "vendor_open/0\tU\t-\tU\t-\t-\t-\t-\t-\t-\t-\t-\tO\t-\n");
    const std::string borrowed = writeModel(
        "fd_borrowed_model.csk",
        "codeskeptic-summaries v10\n"
        "vendor_open/0\tU\t-\tU\t-\t-\t-\t-\t-\t-\t-\t-\tB\t-\n");
    ASSERT_TRUE(SummaryRegistry::instance().loadGlobal(owned));
    ASSERT_TRUE(SummaryRegistry::instance().loadGlobal(borrowed));

    auto results = runFdRule(R"(
        extern int vendor_open();
        void f() { int value = vendor_open(); (void)value; }
    )");
    EXPECT_TRUE(results.empty());
}
