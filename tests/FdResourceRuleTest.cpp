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
    struct sockaddr;
    extern int accept(int, struct sockaddr*, unsigned int*);
    extern int accept4(int, struct sockaddr*, unsigned int*, int);
    extern int pipe(int*);
    extern int pipe2(int*, int);
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

TEST(FdResourceRuleTest, PipePairHasTwoIndependentOwnershipObligations) {
    for (const auto* call : {"pipe(fds)", "pipe2(fds,0)"}) {
        SCOPED_TRACE(call);
        const auto prefix = std::string("void f(){int fds[2];") + call + ";";
        const auto both = runFdRule(prefix + "}");
        ASSERT_EQ(both.size(), 2u);
        EXPECT_NE(both[0].message, both[1].message);
        for (const auto& d : both) EXPECT_EQ(d.rule_id, "resource-leak");
        expectSingleResourceLeak(runFdRule(prefix + "close(fds[0]);}"));
        expectSingleResourceLeak(runFdRule(prefix + "close(fds[1]);}"));
        EXPECT_TRUE(runFdRule(prefix + "close(fds[0]);close(fds[1]);}").empty());
    }
}

TEST(FdResourceRuleTest, PipeFailureGuardsDoNotCreateDescriptors) {
    for (const auto* call : {"pipe(fds)", "pipe2(fds,0)"}) {
        SCOPED_TRACE(call);
        for (const auto* condition : {"rc<0", "rc==-1", "rc!=0", "rc", "!(rc==0)"}) {
            SCOPED_TRACE(condition);
            const auto prefix = std::string("void f(){int fds[2];int rc=") + call +
                ";if(" + condition + ")return;";
            EXPECT_TRUE(runFdRule(prefix + "close(fds[0]);close(fds[1]);}").empty());
            EXPECT_EQ(runFdRule(prefix + "}").size(), 2u);
        }
        EXPECT_TRUE(runFdRule(std::string("void f(){int fds[2];if(") + call +
            "==0){close(fds[0]);close(fds[1]);}}").empty());
        EXPECT_TRUE(runFdRule(std::string("void f(){int fds[2];if(!") + call +
            "){close(fds[0]);close(fds[1]);}}").empty());
        EXPECT_EQ(runFdRule(std::string("void f(){int fds[2];int rc=") + call +
            ";rc=-1;if(rc<0)return;close(fds[0]);close(fds[1]);}").size(), 2u);
    }
}

TEST(FdResourceRuleTest, PipeSlotAliasesAndReturnTransferAreIndependent) {
    EXPECT_TRUE(runFdRule(R"(
        int f(){int fds[2];if(pipe(fds)!=0)return -1;
            int read_end=fds[0];close(read_end);return fds[1];}
    )").empty());
    expectSingleResourceLeak(runFdRule(R"(
        int f(){int fds[2];pipe(fds);return fds[1];}
    )"));
    expectSingleResourceLeak(runFdRule(R"(
        void f(){int fds[2];pipe(fds);fds[0]=-1;close(fds[0]);close(fds[1]);}
    )"));
    EXPECT_TRUE(runFdRule(R"(
        void f(){int fds[2];pipe(fds);int saved=fds[0];fds[0]=-1;
            close(saved);close(fds[1]);}
    )").empty());
}

TEST(FdResourceRuleTest, PipeOutputTargetIsNotTheStatusReturn) {
    EXPECT_EQ(runFdRule(R"(
        void f(){int fds[2];int rc=pipe(fds);close(rc);}
    )").size(), 2u);
    EXPECT_EQ(runFdRule(R"(
        int f(){int fds[2];return pipe2(fds,0);}
    )").size(), 2u);
    EXPECT_TRUE(runFdRule(R"(
        int f(int fds[2]){return pipe(fds);}
    )").empty());
    EXPECT_TRUE(runFdRule(R"(
        struct User {int pipe(int*){return 0;}};
        void f(){int fds[2];User u;u.pipe(fds);}
    )").empty());
}

TEST(FdResourceRuleTest, PipeReassignedOutputAndStatusLoseStaleIdentity) {
    for (const auto* mutation : {"++fds[0];", "fds[0]+=1;"}) {
        SCOPED_TRACE(mutation);
        expectSingleResourceLeak(runFdRule(std::string("void f(){int fds[2];pipe(fds);") +
            mutation + "close(fds[0]);close(fds[1]);}"));
    }
    for (const auto* mutation : {"--rc;", "rc-=1;", "change(&rc);"}) {
        SCOPED_TRACE(mutation);
        EXPECT_EQ(runFdRule(std::string("extern void change(int*);void f(){int fds[2];int rc=pipe(fds);") +
            mutation + "if(rc<0)return;close(fds[0]);close(fds[1]);}").size(), 2u);
    }
    EXPECT_TRUE(runFdRule(R"(
        void f(){int fds[2];int rc=pipe(fds);int copy=rc;rc=-1;
            if(copy<0)return;close(fds[0]);close(fds[1]);}
    )").empty());
}

TEST(FdResourceRuleTest, PipeLocalOutputPointerTracksReassignmentAndOffset) {
    for (const auto* move : {"p=fds+1;", "p=&fds[1];", "++p;", "p+=1;"}) {
        SCOPED_TRACE(move);
        EXPECT_TRUE(runFdRule(std::string("void f(){int fds[3];int* p=fds;") + move +
            "if(pipe(p)<0)return;close(fds[1]);close(fds[2]);}").empty());
    }
    EXPECT_TRUE(runFdRule(R"(
        void f(){int a[2],b[2];int* p=a;p=b;if(pipe2(p,0)<0)return;
            close(b[0]);close(b[1]);}
    )").empty());
    EXPECT_EQ(runFdRule(R"(
        void f(){int a[2],b[2];int* p=a;pipe(p);p=b;close(p[0]);close(p[1]);}
    )").size(), 2u);
}

TEST(FdResourceRuleTest, PipeFailedReplacementPreservesPreviousOutputValues) {
    EXPECT_TRUE(runFdRule(R"(
        void f(){int a=open("a",0),b=open("b",0);int fds[2]={a,b};
            if(pipe(fds)<0){close(fds[0]);close(fds[1]);return;}
            close(a);close(b);close(fds[0]);close(fds[1]);}
    )").empty());
    EXPECT_EQ(runFdRule(R"(
        void f(){int fds[2];pipe(fds);pipe2(fds,0);close(fds[0]);close(fds[1]);}
    )").size(), 2u);
}

TEST(FdResourceRuleTest, PipePointerDereferenceAndStoredFailurePredicate) {
    EXPECT_TRUE(runFdRule(R"(
        void f(){int fds[2];pipe(fds);int* p=fds;close(*p);close(p[1]);}
    )").empty());
    EXPECT_TRUE(runFdRule(R"(
        int f(){int fds[2];pipe(fds);close(fds[0]);int saved;return(saved=fds[1]);}
    )").empty());
    for (const auto* setup : {
        "bool failed=pipe(fds)!=0;if(failed)return;",
        "bool failed=pipe(fds);if(failed)return;",
        "bool success=pipe(fds)==0;if(!success)return;"}) {
        SCOPED_TRACE(setup);
        EXPECT_TRUE(runFdRule(std::string("void f(){int fds[2];") + setup +
            "close(fds[0]);close(fds[1]);}").empty());
        EXPECT_EQ(runFdRule(std::string("void f(){int fds[2];") + setup + "}").size(), 2u);
    }
    EXPECT_EQ(runFdRule(R"(
        extern void change(int*);
        void f(){int fds[2];int rc=pipe(fds);int* p=&rc;change(p);
            if(rc<0)return;close(fds[0]);close(fds[1]);}
    )").size(), 2u);
}

TEST(FdResourceRuleTest, PipeStatusConversionsUseTheActualStoredValues) {
    for (const auto* setup : {
        "unsigned short rc=pipe(fds);if(rc==65535)return;",
        "unsigned rc=pipe(fds);if(rc==4294967295U)return;",
        "unsigned long long rc=pipe(fds);if(rc==18446744073709551615ULL)return;",
        "unsigned short rc=pipe(fds);if(rc==static_cast<unsigned short>(-1))return;",
        "bool rc=pipe(fds);if(rc==true)return;"}) {
        SCOPED_TRACE(setup);
        EXPECT_TRUE(runFdRule(std::string("void f(){int fds[2];") + setup +
            "close(fds[0]);close(fds[1]);}").empty());
        EXPECT_EQ(runFdRule(std::string("void f(){int fds[2];") + setup + "}").size(), 2u);
    }
}

TEST(FdResourceRuleTest, PipeSignatureLookalikesDoNotAcquireOutputs) {
    FdResourceRule rule;
    for (const auto* code : {
        "long pipe(int*);void f(){int fds[2];pipe(fds);}",
        "int pipe(void*);void f(){int fds[2];pipe(fds);}",
        "int pipe(const int*);void f(){int fds[2];pipe(fds);}",
        "int pipe(int*,...);void f(){int fds[2];pipe(fds);}",
        "int pipe2(int*,bool);void f(){int fds[2];pipe2(fds,false);}",
        "int pipe(int*){return 0;}void f(){int fds[2];pipe(fds);}",
        "namespace custom{int pipe(int*);}void f(){int fds[2];custom::pipe(fds);}",
        "struct User{static int pipe2(int*,int);};void f(){int fds[2];User::pipe2(fds,0);}"}) {
        SCOPED_TRACE(code);
        EXPECT_TRUE(runRule(rule, code).empty());
    }
}

TEST(FdResourceRuleTest, PipeNativeStatusOverridesOwnedReturnSummaryOnlyForNativeSignature) {
    GlobalStoreGuard guard;
    const std::string model = writeModel("pipe_native_status.csk",
        "codeskeptic-summaries v10\n"
        "pipe/1\tU\tO\tU\t-\t-\t-\t-\tO\tU\tU\tC\tO\t?\n");
    ASSERT_TRUE(SummaryRegistry::instance().loadGlobal(model));
    EXPECT_EQ(runFdRule("void f(){int fds[2];int status=pipe(fds);close(status);}").size(), 2u);
    EXPECT_TRUE(runFdRule("void f(){int fds[2];pipe(fds);close(fds[0]);close(fds[1]);}").empty());
    expectSingleResourceLeak(runFdRule(R"(
        extern int pipe(double*);
        void f(){double values[2];int fd=pipe(values);}
    )"));
    expectSingleResourceLeak(runFdRule(R"(
        void f(){int flags=open("flags",0);int fds[2];pipe2(fds,flags);close(fds[0]);close(fds[1]);}
    )"));
}

TEST(FdResourceRuleTest, PipeIndirectStatusAssignmentInvalidatesOnlyTheWrittenValue) {
    for (const auto* call : {"pipe(fds)", "pipe2(fds,0)"}) {
        SCOPED_TRACE(call);
        const auto prefix = std::string("void f(){int fds[2];int rc=") + call + ";";
        EXPECT_EQ(runFdRule(prefix +
            "int* p=&rc;*p=-1;if(rc<0)return;close(fds[0]);close(fds[1]);}").size(), 2u);
        EXPECT_TRUE(runFdRule(prefix +
            "int saved=rc;int* p=&rc;*p=-1;if(saved<0)return;close(fds[0]);close(fds[1]);}").empty());
    }
}

TEST(FdResourceRuleTest, PipeScalarAliasSpellingsShareOneStorageIdentity) {
    for (const auto* call : {"pipe(fds)", "pipe2(fds,0)"}) {
        SCOPED_TRACE(call);
        const auto prefix = std::string("void f(){int fds[2];int rc=") + call + ";";
        for (const auto* write : {
            "int* p=&rc;*p=-1;", "int* p=&rc;p[0]=-1;", "int* p=&rc;0[p]=-1;",
            "int* p=&rc;*(p+0)=-1;", "int* p=&rc;*(0+p)=-1;", "int* p=&rc;*(&p[0])=-1;",
            "int* p=&rc;*(&*p)=-1;", "int* p=&rc;*((p+1)-1)=-1;",
            "int* p=&rc;++p;--p;*p=-1;", "int* p=&rc;int* q=p;q[0]=-1;",
            "int* p=&rc;p[0]-=1;", "int* p=&rc;--p[0];", "int& alias=rc;alias=-1;",
            "int& alias=rc;--alias;", "int& alias=rc;alias-=1;",
            "int& alias=rc;int* p=&alias;p[0]=-1;"}) {
            SCOPED_TRACE(write);
            EXPECT_EQ(runFdRule(prefix + write +
                "if(rc<0)return;close(fds[0]);close(fds[1]);}").size(), 2u);
            EXPECT_TRUE(runFdRule(prefix + "int saved=rc;" + write +
                "if(saved<0)return;close(fds[0]);close(fds[1]);}").empty());
        }
    }
}

TEST(FdResourceRuleTest, PipeScalarAliasReadsAndMutableCallsUseTheSameValue) {
    for (const auto* call : {"pipe(fds)", "pipe2(fds,0)"}) {
        SCOPED_TRACE(call);
        const auto prefix = std::string("void f(){int fds[2];int rc=") + call + ";int* p=&rc;int& r=rc;";
        for (const auto* value : {"*p", "p[0]", "0[p]", "*(p+0)", "r"}) {
            SCOPED_TRACE(value);
            EXPECT_TRUE(runFdRule(prefix + "if(" + value + "<0)return;close(fds[0]);close(fds[1]);}").empty());
            EXPECT_TRUE(runFdRule(prefix + "int saved=" + value +
                ";rc=-1;if(saved<0)return;close(fds[0]);close(fds[1]);}").empty());
        }
        const std::string declarations = "void mutate(int*);void mutate_ref(int&);void inspect(const int*);void inspect_ref(const int&);";
        for (const auto* write : {"mutate(p+0);", "mutate(&r);", "mutate_ref(r);", "mutate_ref(p[0]);"}) {
            SCOPED_TRACE(write);
            EXPECT_EQ(runFdRule(declarations + prefix + write +
                "if(rc<0)return;close(fds[0]);close(fds[1]);}").size(), 2u);
            EXPECT_TRUE(runFdRule(declarations + prefix + "int saved=rc;" + write +
                "if(saved<0)return;close(fds[0]);close(fds[1]);}").empty());
        }
        EXPECT_TRUE(runFdRule(declarations + prefix +
            "inspect(p+0);inspect_ref(r);if(rc<0)return;close(fds[0]);close(fds[1]);}").empty());
        EXPECT_TRUE(runFdRule(prefix +
            "if(rc<0)return;int& read=fds[0];int& write=fds[1];close(read);close(write);}").empty());
    }
    EXPECT_TRUE(runFdRule("void f(){int fds[2];int* p=&fds[2];p-=2;pipe(p);close(fds[0]);close(fds[1]);}").empty());
    EXPECT_EQ(runFdRule("void f(){int fds[2];int* p=&fds[2];p-=2;pipe(p);}").size(), 2u);
}

TEST(FdResourceRuleTest, PipeFailureRestoresAlreadyAppliedOutputOwnershipEffects) {
    for (const auto* call : {"pipe(fds)", "pipe2(fds,0)"}) {
        SCOPED_TRACE(call);
        const auto prefix = std::string("void f(){int a=open(\"a\",0),b=open(\"b\",0);int fds[2]={a,b};int rc=") + call + ";";
        EXPECT_TRUE(runFdRule(prefix +
            "close(fds[0]);close(fds[1]);if(rc<0)return;close(a);close(b);}").empty());
        const auto missingOld = runFdRule(prefix +
            "close(fds[0]);close(fds[1]);if(rc<0)return;close(a);}");
        expectSingleResourceLeak(missingOld);
        if (!missingOld.empty()) EXPECT_NE(missingOld[0].message.find("'b'"), std::string::npos);
        EXPECT_TRUE(runFdRule(prefix +
            "close(fds[0]);if(rc<0){close(fds[1]);return;}close(a);close(b);close(fds[1]);}").empty());
        expectSingleResourceLeak(runFdRule(prefix +
            "close(fds[0]);if(rc<0)return;close(a);close(b);close(fds[1]);}"));
        EXPECT_EQ(runFdRule(prefix +
            "close(fds[0]);close(fds[1]);if(rc<0)return;}").size(), 2u);
    }
}

TEST(FdResourceRuleTest, AcceptFamilyAcquiresReturnedDescriptors) {
    for (const auto* acquisition : {"accept(listener,0,0)", "accept4(listener,0,0,0)"}) {
        SCOPED_TRACE(acquisition);
        for (const auto* finish : {
            "(void)fd;", "if(fd==-1)return;", "if(fd<0)return;",
            "if(release)close(fd);", "shutdown(fd,2);"}) {
            SCOPED_TRACE(finish);
            expectSingleResourceLeak(runFdRule(
                std::string("void f(int listener,int release){int fd=") + acquisition +
                ";" + finish + "}"));
        }
        const auto discarded = runFdRule(
            std::string("void f(int listener){") + acquisition + ";}");
        expectSingleResourceLeak(discarded);
        if (!discarded.empty()) EXPECT_NE(discarded[0].message.find("discarded"), std::string::npos);
    }
}

TEST(FdResourceRuleTest, AcceptFamilyCloseTransferAndFailurePathsAreClean) {
    for (const auto* acquisition : {"accept(listener,0,0)", "accept4(listener,0,0,0)"}) {
        SCOPED_TRACE(acquisition);
        for (const auto* finish : {
            "close(fd);return 0;", "return fd;", "if(fd==-1)return -1;close(fd);return 0;",
            "if(fd<0)return -1;close(fd);return 0;", "if(fd>=0)close(fd);return 0;",
            "if(-1!=fd)close(fd);return 0;", "int alias=fd;close(alias);return 0;",
            "if(fd==-1)return 7;return fd;"}) {
            SCOPED_TRACE(finish);
            EXPECT_TRUE(runFdRule(
                std::string("int f(int listener){int fd=") + acquisition +
                ";" + finish + "}").empty());
        }
    }
}

TEST(FdResourceRuleTest, AcceptNamedUserMethodsAndNamespacesAreNotPosix) {
    for (const auto* code : {
        "struct S{int accept(int,sockaddr*,unsigned*);};void f(S& s){int x=s.accept(1,0,0);(void)x;}",
        "struct S{static int accept4(int,sockaddr*,unsigned*,int);};void f(){int x=S::accept4(1,0,0,0);(void)x;}",
        "namespace vendor{int accept(int,sockaddr*,unsigned*);}void f(){int x=vendor::accept(1,0,0);(void)x;}",
        "namespace vendor{int accept4(int,sockaddr*,unsigned*,int);}void f(){int x=vendor::accept4(1,0,0,0);(void)x;}"}) {
        SCOPED_TRACE(code);
        EXPECT_TRUE(runFdRule(code).empty());
    }
}

TEST(FdResourceRuleTest, AcceptAssignmentFailureGuardDoesNotCreateResource) {
    for (const auto* acquisition : {"accept(listener,0,0)", "accept4(listener,0,0,0)"}) {
        SCOPED_TRACE(acquisition);
        for (const auto* comparison : {"<0", "==-1", "<=-1"}) {
            SCOPED_TRACE(comparison);
            EXPECT_TRUE(runFdRule(std::string("int f(int listener){int fd;if((fd=") +
                acquisition + ")" + comparison + ")return -1;close(fd);return 0;}").empty());
        }
        EXPECT_TRUE(runFdRule(std::string("int f(int listener){int fd;if(-1==(fd=") +
            acquisition + "))return -1;close(fd);return 0;}").empty());
        expectSingleResourceLeak(runFdRule(std::string("int f(int listener){int fd;if((fd=") +
            acquisition + ")<0)return -1;return 0;}"));
    }
}

TEST(FdResourceRuleTest, AcceptBorrowsListenerAndDescriptorZeroIsValid) {
    for (const auto* acquisition : {"accept(listener,0,0)", "accept4(listener,0,0,0)"}) {
        SCOPED_TRACE(acquisition);
        const auto prefix = std::string("void f(){int listener=socket(2,1,0);int fd=") + acquisition + ";";
        const auto listener = runFdRule(prefix + "close(fd);}");
        expectSingleResourceLeak(listener);
        if (!listener.empty()) EXPECT_NE(listener[0].message.find("listener"), std::string::npos);
        const auto accepted = runFdRule(prefix + "close(listener);}");
        expectSingleResourceLeak(accepted);
        if (!accepted.empty()) EXPECT_NE(accepted[0].message.find("'fd'"), std::string::npos);
        EXPECT_TRUE(runFdRule(prefix + "close(fd);close(listener);}").empty());
        expectSingleResourceLeak(runFdRule(std::string("void f(int listener){int fd=") +
            acquisition + ";if(fd>0)close(fd);}"));
        expectSingleResourceLeak(runFdRule(std::string("void f(int listener){int fd=") +
            acquisition + ";if(!fd)return;close(fd);}"));
    }
}

TEST(FdResourceRuleTest, AcceptConditionalReturnDoesNotHideOtherPathLeak) {
    for (const auto* acquisition : {"accept(listener,0,0)", "accept4(listener,0,0,0)"}) {
        SCOPED_TRACE(acquisition);
        expectSingleResourceLeak(runFdRule(std::string("int f(int listener,int transfer){int fd=") +
            acquisition + ";if(fd<0)return -1;if(transfer)return fd;return 0;}"));
        EXPECT_TRUE(runFdRule(std::string("int f(int listener,int transfer){int fd=") +
            acquisition + ";if(fd<0)return -1;if(transfer)return fd;close(fd);return 0;}").empty());
        EXPECT_TRUE(runFdRule(std::string("int f(int listener){int fd;return (fd=") +
            acquisition + ");}").empty());
        EXPECT_TRUE(runFdRule(std::string("void f(int listener){close(") +
            acquisition + ");}").empty());
    }
}

TEST(FdResourceRuleTest, AcceptSelectedReturnValueTransfersOnItsOwnPath) {
    for (const auto* acquisition : {"accept(listener,0,0)", "accept4(listener,0,0,0)"}) {
        SCOPED_TRACE(acquisition);
        const auto prefix = std::string("int f(int listener,int condition){int fd=") + acquisition + ";";
        for (const auto* finish : {
            "return fd<0 ? -1 : fd;", "return fd>=0 ? fd : -1;", "return (0,fd);",
            "return condition ? fd : fd;", "return (condition?0:1,fd);"}) {
            SCOPED_TRACE(finish);
            EXPECT_TRUE(runFdRule(prefix + finish + "}").empty());
        }
        for (const auto* finish : {
            "return condition ? fd : 0;", "return fd<0 ? fd : -1;", "return (fd,0);"}) {
            SCOPED_TRACE(finish);
            expectSingleResourceLeak(runFdRule(prefix + finish + "}"));
        }
        const auto two = runFdRule(std::string("int f(int listener,int condition){int fd=") +
            acquisition + ";int second=" + acquisition + ";return condition?fd:second;}");
        EXPECT_EQ(two.size(), 2u);
    }
}

TEST(FdResourceRuleTest, AcceptReturnedValueMustPreserveDescriptorRange) {
    for (const auto* code : {
        "int f(int listener){int fd=accept(listener,0,0);return static_cast<int>(fd);}",
        "long f(int listener){int fd=accept(listener,0,0);return fd;}",
        "unsigned f(int listener){int fd=accept(listener,0,0);return fd;}",
        "long f(int listener){int fd=accept(listener,0,0);return static_cast<long>(fd);}"}) {
        SCOPED_TRACE(code);
        EXPECT_TRUE(runFdRule(code).empty());
    }
    for (const auto* code : {
        "bool f(int listener){int fd=accept(listener,0,0);return fd;}",
        "short f(int listener){int fd=accept(listener,0,0);return fd;}",
        "int f(int listener){int fd=accept(listener,0,0);return static_cast<short>(fd);}",
        "int f(int listener,int c){int fd=accept(listener,0,0);return c?static_cast<bool>(fd):fd;}"}) {
        SCOPED_TRACE(code);
        expectSingleResourceLeak(runFdRule(code));
    }
}

TEST(FdResourceRuleTest, AcceptSignatureLookalikesAreNotProducers) {
    for (const auto* code : {
        "int accept(int);void f(){int x=accept(1);(void)x;}",
        "int accept(int,...);void f(){int x=accept(1,0,0);(void)x;}",
        "struct sockaddr;long accept(int,sockaddr*,unsigned*);void f(){long x=accept(1,0,0);(void)x;}",
        "int accept(int,void*,unsigned*);void f(){int x=accept(1,0,0);(void)x;}",
        "struct sockaddr;int accept(int,sockaddr*,bool*);void f(){int x=accept(1,0,0);(void)x;}",
        "struct sockaddr;int accept(int,sockaddr*,unsigned long long*);void f(){int x=accept(1,0,0);(void)x;}",
        "struct sockaddr;int accept(int,const sockaddr*,unsigned*);void f(){int x=accept(1,0,0);(void)x;}",
        "struct sockaddr;int accept(int,sockaddr*,unsigned*){return 5;}void f(){int x=accept(1,0,0);(void)x;}",
        "struct sockaddr;int accept4(int,sockaddr*,unsigned*,bool);void f(){int x=accept4(1,0,0,false);(void)x;}"}) {
        SCOPED_TRACE(code);
        FdResourceRule rule;
        EXPECT_TRUE(runRule(rule, code).empty());
    }
}

TEST(FdResourceRuleTest, AcceptActualSystemHeaderForms) {
    const std::string code = R"(
        #define _GNU_SOURCE 1
        #include <sys/socket.h>
        #include <unistd.h>
        void bad_accept(int listener){int fd=accept(listener,0,0);(void)fd;}
        void bad_accept4(int listener){int fd=accept4(listener,0,0,0);(void)fd;}
        void good_accept(int listener){int fd=accept(listener,0,0);if(fd>=0)close(fd);}
        void good_accept4(int listener){int fd=accept4(listener,0,0,0);if(fd>=0)close(fd);}
        int transfer(int listener){return accept(listener,0,0);}
        int transfer4(int listener){return accept4(listener,0,0,0);}
    )";
    for (const auto& language : {std::pair{"-std=gnu11", "accept.c"},
                                std::pair{"-std=gnu++17", "accept.cpp"}}) {
        SCOPED_TRACE(language.first);
        FdResourceRule rule;
        const auto results = runRuleWithArgs(rule, code, {language.first}, language.second);
        ASSERT_EQ(results.size(), 2u);
        EXPECT_EQ(results[0].function, "bad_accept");
        EXPECT_EQ(results[1].function, "bad_accept4");
    }
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

TEST(FdResourceRuleTest, AcceptWrappersPreserveNativeOwnershipAndClose) {
    for (const auto* acquire : {"accept(listener,0,0)", "accept4(listener,0,0,0)"}) {
        SCOPED_TRACE(acquire);
        auto results = runFdRule(std::string(
            "int inner(int listener){return ") + acquire + ";}"
            "int outer(int listener){return inner(listener);}"
            "void direct(int listener){int fd=" + acquire + ";(void)fd;}"
            "void wrapped(int listener){int fd=outer(listener);(void)fd;}"
            "void good(int listener){int fd=outer(listener);if(fd>=0)close(fd);}");
        ASSERT_EQ(results.size(), 2u);
        EXPECT_EQ(results[0].function, "direct");
        EXPECT_EQ(results[1].function, "wrapped");
    }
}

TEST(FdResourceRuleTest, AcceptWrapperFailureSentinelAndListenerRemainSeparate) {
    for (const auto* acquire : {"accept(listener,0,0)", "accept4(listener,0,0,0)"}) {
        const std::string prefix = std::string(
            "int wrapper(int listener,int fail){if(fail)return -1;return ") + acquire + ";}";
        expectSingleResourceLeak(runFdRule(prefix +
            "void f(int fail){int listener=socket(2,1,0);int fd=wrapper(listener,fail);close(listener);}"));
        expectSingleResourceLeak(runFdRule(prefix +
            "void f(int fail){int listener=socket(2,1,0);int fd=wrapper(listener,fail);if(fd>=0)close(fd);}"));
        EXPECT_TRUE(runFdRule(prefix +
            "void f(int fail){int listener=socket(2,1,0);int fd=wrapper(listener,fail);"
            "if(fd>=0)close(fd);close(listener);}").empty());
    }
}

TEST(FdResourceRuleTest, AcceptWrapperNarrowedNumberIsNotCallerOwned) {
    for (const auto* body : {
            "short wrapper(int listener){return accept(listener,0,0);}",
            "int wrapper(int listener){short n=accept(listener,0,0);return n;}",
            "int wrapper(int listener){return (short)accept(listener,0,0);}"}) {
        SCOPED_TRACE(body);
        auto results = runFdRule(std::string(body) +
            "void caller(int listener){int value=wrapper(listener);(void)value;}");
        // The native descriptor is lost inside wrapper; its narrowed number
        // must not create a second, fictitious ownership obligation in caller.
        ASSERT_EQ(results.size(), 1u);
        EXPECT_EQ(results[0].function, "wrapper");
    }
}

TEST(FdResourceRuleTest, AcceptWrapperRealHeadersInCAndCpp) {
    const std::string code = R"(
        #ifndef _GNU_SOURCE
        #define _GNU_SOURCE
        #endif
        #include <sys/socket.h>
        #include <unistd.h>
        int first(int listener){return accept(listener,0,0);}
        int second(int listener){return accept4(listener,0,0,0);}
        int chain(int listener){return second(listener);}
        void direct(int listener){int fd=accept(listener,0,0);(void)fd;}
        void wrapped(int listener){int fd=first(listener);(void)fd;}
        void nested(int listener){int fd=chain(listener);(void)fd;}
        void good(int listener){int fd=chain(listener);if(fd>=0)close(fd);}
    )";
    for (const auto& language : {std::pair{"-std=gnu11", "accept_wrapper.c"},
                                std::pair{"-std=gnu++17", "accept_wrapper.cpp"}}) {
        SCOPED_TRACE(language.first);
        FdResourceRule rule;
        auto results = runRuleWithArgs(rule, code, {language.first}, language.second);
        ASSERT_EQ(results.size(), 3u);
        EXPECT_EQ(results[0].function, "direct");
        EXPECT_EQ(results[1].function, "wrapped");
        EXPECT_EQ(results[2].function, "nested");
    }
}

TEST(FdResourceRuleTest, AcceptWrapperLookalikesNeverSeedNativeOwnership) {
    const char* cases[] = {
        "int accept(int);int wrapper(int x){return accept(x);}",
        "int accept(int,...);int wrapper(int x){return accept(x,0,0);}",
        "long accept(int,sockaddr*,unsigned*);long wrapper(int x){return accept(x,0,0);}",
        "int accept(int,void*,unsigned*);int wrapper(int x){return accept(x,0,0);}",
        "int accept(int,sockaddr*,unsigned long long*);int wrapper(int x){return accept(x,0,0);}",
        "int accept(int,const sockaddr*,unsigned*);int wrapper(int x){return accept(x,0,0);}",
        "int accept(int,sockaddr*,unsigned*){return 5;}int wrapper(int x){return accept(x,0,0);}",
        "int accept4(int,sockaddr*,unsigned*,bool);int wrapper(int x){return accept4(x,0,0,false);}",
        "namespace vendor{int accept(int,sockaddr*,unsigned*);}int wrapper(int x){return vendor::accept(x,0,0);}",
        "struct S{static int accept(int,sockaddr*,unsigned*);};int wrapper(int x){return S::accept(x,0,0);}",
        "int wrapper(int){return 7;}",
        "int wrapper(int){return -1;}",
    };
    for (const auto* code : cases) {
        SCOPED_TRACE(code);
        FdResourceRule rule;
        EXPECT_TRUE(runRule(rule, std::string("struct sockaddr;") + code +
            "void caller(int listener){int fd=wrapper(listener);(void)fd;}").empty());
    }
}

TEST(FdResourceRuleTest, AcceptWrapperDescriptorPreservingReturns) {
    const char* cases[] = {
        "int wrapper(int l){int n=accept(l,0,0);return static_cast<int>(n);}",
        "long wrapper(int l){int n=accept(l,0,0);return n;}",
        "long wrapper(int l){return static_cast<long>(accept(l,0,0));}",
        "int wrapper(int l){int n=accept(l,0,0);int saved=n;return saved;}",
    };
    for (const auto* code : cases) {
        SCOPED_TRACE(code);
        auto results = runFdRule(std::string(code) +
            "void caller(int listener){int fd=wrapper(listener);(void)fd;}");
        expectSingleResourceLeak(results);
        if (!results.empty()) EXPECT_EQ(results[0].function, "caller");
    }
    // A non-failure borrowed integer alternative prevents a strong Owned
    // summary; -1 alone is the distinguished acquisition failure sentinel.
    EXPECT_TRUE(runFdRule(
        "int wrapper(int l,int c){if(c)return 7;return accept(l,0,0);}"
        "void caller(int l,int c){int value=wrapper(l,c);(void)value;}").empty());
}

TEST(FdResourceRuleTest, AcceptWrapperCrossTUOwnershipAndClose) {
    for (const auto* acquire : {"accept(listener,0,0)", "accept4(listener,0,0,0)"}) {
        for (bool release : {false, true}) {
            SCOPED_TRACE(acquire);
            SCOPED_TRACE(release);
            FdResourceRule rule;
            auto results = runRuleCrossTU(rule, std::string(kPosixDecls) +
                "int inner(int listener){return " + acquire + ";}"
                "int wrapper(int listener){return inner(listener);}",
                std::string("extern int wrapper(int);extern int close(int);"
                    "void caller(int listener){int fd=wrapper(listener);") +
                    (release ? "if(fd>=0)close(fd);}" : "(void)fd;}"));
            EXPECT_EQ(results.size(), release ? 0u : 1u);
        }
    }
}

TEST(FdResourceRuleTest, AcceptDoesNotConsumeWrapperOwnedListener) {
    const std::string body =
        "int wrapper(){int listener=socket(2,1,0);int fd=accept(listener,0,0);"
        "if(fd>=0)close(fd);return listener;}";
    auto leaked = runFdRule(body + "void caller(){int listener=wrapper();(void)listener;}");
    expectSingleResourceLeak(leaked);
    if (!leaked.empty()) EXPECT_EQ(leaked[0].function, "caller");
    EXPECT_TRUE(runFdRule(body + "void caller(){int listener=wrapper();close(listener);}").empty());
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

TEST(FdResourceRuleTest, MemberStoreTransfersDescriptorOwnership) {
    auto results = runFdRule(R"(
        struct Holder { int fd; };
        void f(Holder* holder, const char* p) {
            holder->fd = open(p, 0);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, WrappedMemberStoreTransfersDescriptorOwnership) {
    auto results = runFdRule(R"(
        struct Holder { int fd; };
        int acquire(const char* p) { return open(p, 0); }
        void f(Holder* holder, const char* p) {
            holder->fd = acquire(p);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, OutParameterStoreTransfersDescriptorOwnership) {
    auto results = runFdRule(R"(
        void f(int* output, const char* p) {
            *output = open(p, 0);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, NegativeInputSnapshotProvesReplacementClose) {
    auto results = runFdRule(R"(
        void f(int fd, const char* p) {
            int initial_fd = fd;
            if (fd < 0)
                fd = open(p, 0);
            if (initial_fd != fd)
                close(fd);
        }
    )");
    EXPECT_TRUE(results.empty());
}

TEST(FdResourceRuleTest, ReassignedParameterWithoutCloseStillReports) {
    expectSingleResourceLeak(runFdRule(R"(
        void f(int fd, const char* p) {
            if (fd < 0)
                fd = open(p, 0);
        }
    )"));
}

TEST(FdResourceRuleTest, UnknownSnapshotDoesNotProveReplacementClose) {
    expectSingleResourceLeak(runFdRule(R"(
        void f(int initial_fd, const char* p) {
            int fd = open(p, 0);
            if (initial_fd != fd)
                close(fd);
        }
    )"));
}

TEST(FdResourceRuleTest, ReassignedSnapshotDoesNotProveReplacementClose) {
    expectSingleResourceLeak(runFdRule(R"(
        void f(int fd, const char* p) {
            int initial_fd = fd;
            if (fd < 0)
                fd = open(p, 0);
            initial_fd = fd;
            if (initial_fd != fd)
                close(fd);
        }
    )"));
}

TEST(FdResourceRuleTest, ConditionalReplacementCloseStillReports) {
    expectSingleResourceLeak(runFdRule(R"(
        void f(int fd, const char* p, int release) {
            if (fd < 0)
                fd = open(p, 0);
            if (release)
                close(fd);
        }
    )"));
}

TEST(FdResourceRuleTest, EqualityCleanupMissesSuccessfulReplacement) {
    expectSingleResourceLeak(runFdRule(R"(
        void f(int fd, const char* p) {
            int initial_fd = fd;
            if (fd < 0)
                fd = open(p, 0);
            if (initial_fd == fd)
                close(fd);
        }
    )"));
}
