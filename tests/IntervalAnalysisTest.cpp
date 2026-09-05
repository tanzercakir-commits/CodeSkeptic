#include "engine/IntervalAnalysis.h"

#include "engine/CfgCache.h"
#include "engine/DataflowEngine.h"
#include "engine/AllocFunctions.h"

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Frontend/ASTUnit.h>
#include <clang/Tooling/Tooling.h>
#include <gtest/gtest.h>

#include <string>

// Direct test of IntervalAnalysis (2026-07-14): parse a function, run
// the interval dataflow, and read back the divisor variable's proven
// range at its division. This exercises the numeric transfer,
// guard-refinement, and loop-widening end-to-end through the real
// engine — the analysis is verified in isolation, before any rule
// consumes it.

using namespace clang;
using codeskeptic::Interval;

namespace {

// Collect all integer-typed locals and parameters in a function.
std::set<const VarDecl*> intVars(const FunctionDecl* fn, ASTContext& ctx) {
    struct V : RecursiveASTVisitor<V> {
        std::set<const VarDecl*> vars;
        bool VisitVarDecl(VarDecl* vd) {
            if (vd->getType()->isIntegerType()) vars.insert(vd);
            return true;
        }
    } v;
    v.TraverseDecl(const_cast<FunctionDecl*>(fn));
    for (const auto* p : fn->parameters())
        if (p->getType()->isIntegerType()) v.vars.insert(p);
    return v.vars;
}

// The first integer division/modulo in the body, and its divisor var.
struct DivSite {
    const BinaryOperator* op = nullptr;
    const VarDecl* divisor = nullptr;
};
DivSite findDiv(const FunctionDecl* fn) {
    struct V : RecursiveASTVisitor<V> {
        DivSite site;
        bool VisitBinaryOperator(BinaryOperator* b) {
            if (site.op) return true;
            if (b->getOpcode() != BO_Div && b->getOpcode() != BO_Rem)
                return true;
            const Expr* rhs = b->getRHS()->IgnoreParenImpCasts();
            if (const auto* ref = dyn_cast<DeclRefExpr>(rhs))
                if (const auto* vd = dyn_cast<VarDecl>(ref->getDecl())) {
                    site.op = b;
                    site.divisor = vd;
                }
            return true;
        }
    } v;
    v.TraverseDecl(const_cast<FunctionDecl*>(fn));
    return v.site;
}

struct Result {
    bool found = false;
    bool converged = false;
    Interval divisor;
    bool untrusted = false;
};

class Consumer : public ASTConsumer {
public:
    explicit Consumer(Result& out) : out_(out) {}
    void HandleTranslationUnit(ASTContext& ctx) override {
        // This harness runs the dataflow directly, outside RuleEngine, so
        // it must honor the CfgCache clear contract itself: the cache is
        // keyed by FunctionDecl* and its auto-flush only fires when the
        // ASTContext POINTER changes — a freed context reallocated at the
        // same address would otherwise serve a stale CFG (address reuse,
        // hence order/ASLR-dependent flakiness). Clear before use.
        codeskeptic::CfgCache::instance().clear();
        struct V : RecursiveASTVisitor<V> {
            const FunctionDecl* fn = nullptr;
            bool VisitFunctionDecl(FunctionDecl* f) {
                if (f->hasBody() && f->getName() == "f") fn = f;
                return true;
            }
        } v;
        v.TraverseDecl(ctx.getTranslationUnitDecl());
        if (!v.fn) return;
        DivSite site = findDiv(v.fn);
        if (!site.op) return;
        codeskeptic::IntervalAnalysis analysis(intVars(v.fn, ctx));
        auto dataflow = codeskeptic::runDataflow(v.fn, ctx, analysis);
        out_.converged = dataflow.converged;
        out_.divisor = analysis.intervalAt(site.op, site.divisor);
        if (const auto* origins = analysis.untrustedAt(site.op))
            out_.untrusted = origins->count(site.divisor) != 0;
        out_.found = true;
    }
private:
    Result& out_;
};

class Action : public ASTFrontendAction {
public:
    explicit Action(Result& out) : out_(out) {}
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance&,
                                                   llvm::StringRef) override {
        return std::make_unique<Consumer>(out_);
    }
private:
    Result& out_;
};

// Returns the interval of the divisor at the first division in `f`.
Interval divisorInterval(const std::string& code) {
    Result out;
    clang::tooling::runToolOnCode(std::make_unique<Action>(out), code,
                                  "interval_test.c");
    EXPECT_TRUE(out.found);
    EXPECT_TRUE(out.converged);
    return out.divisor;
}

Interval initializerInterval(const std::string& declaration, bool context, bool size = false) {
    auto ast = clang::tooling::buildASTFromCodeWithArgs(
        "void f(){" + declaration + "}", {"-std=c11"}, "initializer.c");
    EXPECT_NE(ast, nullptr);
    if (!ast) return Interval::top();
    struct Visitor : RecursiveASTVisitor<Visitor> {
        const Expr* init = nullptr;
        bool VisitVarDecl(VarDecl* vd) {
            if (vd->getName() == "n") init = vd->getInit();
            return true;
        }
    } visitor;
    auto& ctx = ast->getASTContext();
    visitor.TraverseDecl(ctx.getTranslationUnitDecl());
    EXPECT_NE(visitor.init, nullptr);
    const codeskeptic::IntervalMap empty;
    return size ? codeskeptic::evalSizeInterval(visitor.init, ctx, empty) :
                  codeskeptic::evalInterval(visitor.init, empty, context ? &ctx : nullptr);
}

struct DestructorElementAnalysis {
    using State = bool;
    static constexpr bool kFollowExceptionalControlFlow = true;
    State initialState() const { return false; }
    State merge(State left, State right) const { return left || right; }
    State transfer(const Stmt*, State state, ASTContext&) const {
        return state;
    }
    State transferElement(const CFGElement& element, State state,
                          ASTContext&) const {
        return state || element.getAs<CFGAutomaticObjDtor>().has_value();
    }
};

struct DestructorResult {
    bool found = false;
    bool converged = false;
    bool reachedExit = false;
};

class DestructorConsumer : public ASTConsumer {
public:
    explicit DestructorConsumer(DestructorResult& out) : out_(out) {}
    void HandleTranslationUnit(ASTContext& ctx) override {
        codeskeptic::CfgCache::instance().clear();
        struct V : RecursiveASTVisitor<V> {
            const FunctionDecl* fn = nullptr;
            bool VisitFunctionDecl(FunctionDecl* f) {
                if (f->hasBody() && f->getName() == "f") fn = f;
                return true;
            }
        } visitor;
        visitor.TraverseDecl(ctx.getTranslationUnitDecl());
        if (!visitor.fn) return;
        DestructorElementAnalysis analysis;
        auto dataflow = codeskeptic::runDataflow(visitor.fn, ctx, analysis);
        out_.found = true;
        out_.converged = dataflow.converged;
        auto exit = dataflow.blockExitStates.find(dataflow.exitBlockID);
        out_.reachedExit = exit != dataflow.blockExitStates.end() &&
                           exit->second;
    }
private:
    DestructorResult& out_;
};

class DestructorAction : public ASTFrontendAction {
public:
    explicit DestructorAction(DestructorResult& out) : out_(out) {}
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance&,
                                                   llvm::StringRef) override {
        return std::make_unique<DestructorConsumer>(out_);
    }
private:
    DestructorResult& out_;
};

} // namespace

TEST(DataflowEngineTest, OptionalElementHookReceivesAutomaticDestructor) {
    DestructorResult out;
    clang::tooling::runToolOnCode(
        std::make_unique<DestructorAction>(out),
        "struct Owner { ~Owner(); }; void f(){ Owner owner; }",
        "destructor_element_test.cpp");
    EXPECT_TRUE(out.found);
    EXPECT_TRUE(out.converged);
    EXPECT_TRUE(out.reachedExit);
}

TEST(DataflowEngineTest, ExceptionalOptInDoesNotInventDisconnectedCleanup) {
    DestructorResult out;
    clang::tooling::runToolOnCode(
        std::make_unique<DestructorAction>(out), R"(
            struct Owner { ~Owner(); };
            void f() {
                try { Owner owner; throw 1; }
                catch (...) {}
            }
        )", "exceptional_destructor_element_test.cpp");
    EXPECT_TRUE(out.found);
    EXPECT_TRUE(out.converged);
    // Clang 20 emits the automatic-dtor block, but it is disconnected from
    // the throw-to-handler edge. The engine must not treat an unreachable
    // cleanup element as evidence on the handler/exit path.
    EXPECT_FALSE(out.reachedExit);
}

TEST(IntervalAnalysisTest, ConstantAssignment) {
    Interval n = divisorInterval("int f(int x){ int n = 5; return x / n; }");
    EXPECT_EQ(n, Interval::constant(5));
    EXPECT_TRUE(n.isKnownNonZero());
}

TEST(IntervalAnalysisTest, UnsignedLiteralAndInitializerChainKeepActualValue) {
    const char* bodies[] = {
        "unsigned n=4294967295U;",
        "unsigned a=4294967295U; unsigned n=a;",
        "unsigned a=4294967295U; long long n=a;",
    };
    for (const char* body : bodies) {
        SCOPED_TRACE(body);
        EXPECT_EQ(divisorInterval(std::string("long long f(){") + body +
                                  "return 10/n;}"),
                  Interval::constant(4294967295LL));
    }
}

TEST(IntervalAnalysisTest, TypedConstantAndCastBoundaries) {
    struct Case { const char* declaration; Interval expected; };
    const Case cases[] = {
        {"int n=2147483647;", Interval::constant(2147483647)},
        {"int n=(-2147483647-1);", Interval::constant(-2147483647LL-1)},
        {"unsigned n=2147483648U;", Interval::constant(2147483648LL)},
        {"long long n=9223372036854775807LL;", Interval::constant(INT64_MAX)},
        {"long long n=(-9223372036854775807LL-1);", Interval::constant(INT64_MIN)},
        {"unsigned long long n=9223372036854775807ULL;", Interval::constant(INT64_MAX)},
        {"unsigned long long n=9223372036854775808ULL;", Interval::top()},
        {"unsigned long long n=18446744073709551615ULL;", Interval::top()},
        {"unsigned n=(unsigned)-1;", Interval::constant(4294967295LL)},
        {"int n=(int)4294967295U;", Interval::constant(-1)},
        {"unsigned long long n=(unsigned long long)-1;", Interval::top()},
        {"__int128 n=(__int128)9223372036854775807LL;", Interval::constant(INT64_MAX)},
        {"__int128 n=(__int128)(-9223372036854775807LL-1);", Interval::constant(INT64_MIN)},
        {"unsigned __int128 n=(unsigned __int128)4294967295U;", Interval::constant(4294967295LL)},
        {"unsigned __int128 n=(unsigned __int128)-1;", Interval::top()},
        {"__int128 n=((__int128)1<<100);", Interval::top()},
        {"unsigned n=(unsigned)(((unsigned __int128)1<<100)+5);", Interval::constant(5)},
        {"unsigned n=-1U;", Interval::constant(4294967295LL)},
        {"unsigned n=-4294967295U;", Interval::constant(1)},
        {"unsigned n=-0U;", Interval::constant(0)},
        {"unsigned long long n=-9223372036854775808ULL;", Interval::top()},
    };
    for (const auto& item : cases) {
        SCOPED_TRACE(item.declaration);
        EXPECT_EQ(divisorInterval(std::string("long long f(){") +
            item.declaration + "return 10/n;}"), item.expected);
    }
}

TEST(IntervalAnalysisTest, TypedUnsignedGuardsPreserveReachableValues) {
    const char* guards[] = {
        "if(n>=4294967295U)return 0;",
        "if(n>=-1)return 0;",
        "if(-1<=n)return 0;",
        "if(!(n < -1))return 0;",
        "if(n>=-1 || n<1)return 0;",
    };
    for (const char* guard : guards) {
        SCOPED_TRACE(guard);
        EXPECT_EQ(divisorInterval(std::string("int f(){unsigned n=8;") +
            guard + "return 10/n;}"), Interval::constant(8));
    }
    // The variable side also undergoes the usual arithmetic conversions.
    // A non-value-preserving comparison must not constrain the signed
    // original to UINT_MAX and invent an unreachable state.
    EXPECT_EQ(divisorInterval("int f(){int n=-1; if(n!=4294967295U)return 0; return 10/n;}"),
              Interval::constant(-1));
    EXPECT_EQ(divisorInterval("int f(){int n=-2; if(n<1U)return 0; return 10/n;}"),
              Interval::constant(-2));
}

TEST(IntervalAnalysisTest, LiteralFallbackAndSizeCastsNeverSignExtendUnsigned) {
    for (bool context : {false, true}) {
        EXPECT_EQ(initializerInterval("unsigned n=4294967295U;", context),
                  Interval::constant(4294967295LL));
        EXPECT_TRUE(initializerInterval("unsigned long long n=18446744073709551615ULL;", context).isTop());
        EXPECT_TRUE(initializerInterval("unsigned long long n=-9223372036854775808ULL;", context).isTop());
    }
    EXPECT_EQ(initializerInterval("__SIZE_TYPE__ n=4294967295U;", true, true),
              Interval::constant(4294967295LL));
    EXPECT_EQ(initializerInterval("__SIZE_TYPE__ n=(unsigned)-1;", true, true),
              Interval::constant(4294967295LL));
    EXPECT_TRUE(initializerInterval("__SIZE_TYPE__ n=-1;", true, true).isTop());
    EXPECT_TRUE(initializerInterval("__SIZE_TYPE__ n=(unsigned long long)-1;", true, true).isTop());
}

TEST(IntervalAnalysisTest, WideGuardBeyondInt64IsUnknownNotUnreachable) {
    EXPECT_TRUE(divisorInterval(
        "long long f(){unsigned long long n=9223372036854775808ULL;"
        "if(n<=9223372036854775807LL)return 0;return 10/n;}").isTop());
    EXPECT_TRUE(divisorInterval(
        "long long f(){__int128 n=((__int128)1<<100);"
        "if(n<=9223372036854775807LL)return 0;return 10/n;}").isTop());
    EXPECT_TRUE(divisorInterval(
        "long long f(){__int128 n=-((__int128)1<<100);"
        "if(n>=(-9223372036854775807LL-1))return 0;return 10/n;}").isTop());
}

TEST(IntervalAnalysisTest, ContextFreeWideBoundaryGuardStaysUnknown) {
    auto ast = clang::tooling::buildASTFromCodeWithArgs(
        "void f(unsigned long long n){if(n>9223372036854775807ULL){}}",
        {"-std=c11"}, "guard.c");
    ASSERT_NE(ast, nullptr);
    struct Visitor : RecursiveASTVisitor<Visitor> {
        const VarDecl* variable = nullptr;
        const Expr* condition = nullptr;
        bool VisitVarDecl(VarDecl* vd) {
            if (vd->getName() == "n") variable = vd;
            return true;
        }
        bool VisitIfStmt(IfStmt* statement) {
            condition = statement->getCond();
            return true;
        }
    } visitor;
    visitor.TraverseDecl(ast->getASTContext().getTranslationUnitDecl());
    ASSERT_NE(visitor.variable, nullptr);
    ASSERT_NE(visitor.condition, nullptr);
    codeskeptic::IntervalMap state{{visitor.variable, Interval::top()}};
    codeskeptic::refineIntervalOnEdge(state, visitor.condition, true, {visitor.variable});
    EXPECT_TRUE(state.at(visitor.variable).isTop());
}

TEST(IntervalAnalysisTest, ArithmeticRange) {
    // n = a + b = 3 + 4 = 7 — a range ZeroState cannot compute.
    Interval n = divisorInterval(
        "int f(int x){ int a = 3; int b = 4; int n = a + b; return x / n; }");
    EXPECT_EQ(n, Interval::constant(7));
    EXPECT_TRUE(n.isKnownNonZero());
}

TEST(IntervalAnalysisTest, BranchJoin) {
    // n ∈ {0} ⊔ {8} = [0,8] — includes 0 (a real maybe-zero).
    Interval n = divisorInterval(
        "int f(int x, int c){ int n = 0; if (c) n = 8; return x / n; }");
    EXPECT_EQ(n, Interval::range(0, 8));
    EXPECT_FALSE(n.isKnownNonZero());
    EXPECT_TRUE(n.contains(0));
}

TEST(IntervalAnalysisTest, GuardRefinesLowerBound) {
    // `if (n <= 1) return;` leaves n ∈ [2,+∞] on the fall-through.
    Interval n = divisorInterval(
        "int f(int x, int n){ if (n <= 1) return 0; return x / n; }");
    EXPECT_TRUE(n.loIsInf() == false && n.lo() == 2);
    EXPECT_TRUE(n.hiIsInf());
    EXPECT_TRUE(n.isKnownNonZero());
}

TEST(IntervalAnalysisTest, GuardRefinesRange) {
    // 3 <= n <= 9.
    Interval n = divisorInterval(
        "int f(int x, int n){ if (n < 3) return 0; if (n > 9) return 0; "
        "return x / n; }");
    EXPECT_EQ(n, Interval::range(3, 9));
    EXPECT_TRUE(n.isKnownNonZero());
}

TEST(IntervalAnalysisTest, UnknownParamIsTop) {
    Interval n = divisorInterval("int f(int x, int n){ return x / n; }");
    EXPECT_TRUE(n.isTop());
    EXPECT_FALSE(n.isKnownNonZero());
}

TEST(IntervalAnalysisTest, DeclaredUint64OutParamOriginIsIndependentOfRange) {
    struct Sources {
        Sources() { codeskeptic::setUntrustedIntSourceNames({"read_size"}); }
        ~Sources() { codeskeptic::setUntrustedIntSourceNames({}); }
    } sources;
    for (bool reference : {false, true}) {
        SCOPED_TRACE(reference ? "C++ reference" : "C pointer");
        const std::string code = std::string("typedef __SIZE_TYPE__ size_t; extern void read_size(size_t") +
            (reference ? "&" : "*") + "); size_t f(size_t x){size_t n=7;read_size(" +
            (reference ? "n" : "&n") + ");return x/n;}";
        Result result;
        ASSERT_TRUE(clang::tooling::runToolOnCode(std::make_unique<Action>(result), code,
            reference ? "origin.cpp" : "origin.c"));
        ASSERT_TRUE(result.found);
        ASSERT_TRUE(result.converged);
        EXPECT_TRUE(result.divisor.isTop());
        EXPECT_TRUE(result.untrusted);
    }
}

TEST(IntervalAnalysisTest, DeclaredUint64SourceGuardAndReplacementAreSeparate) {
    struct Sources {
        Sources() { codeskeptic::setUntrustedIntSourceNames({"read_size"}); }
        ~Sources() { codeskeptic::setUntrustedIntSourceNames({}); }
    } sources;
    struct Case { const char* statements; Interval range; bool origin; };
    const Case cases[] = {
        {"if(n>9)return 0;if(n<3)return 0;", Interval::range(3,9), true},
        {"size_t saved=n;n=0;n=saved;", Interval::top(), true},
        {"n=7;", Interval::constant(7), false},
        {"mutate(n);", Interval::top(), false},
        {"mutate_ptr(&n);", Interval::top(), false},
    };
    for (const auto& item : cases) {
        SCOPED_TRACE(item.statements);
        const std::string code = std::string("typedef __SIZE_TYPE__ size_t;extern void read_size(size_t&);") +
            "extern void mutate(size_t&);extern void mutate_ptr(size_t*);" +
            "size_t f(size_t x){size_t n=7;read_size(n);" + item.statements + "return x/n;}";
        Result result;
        ASSERT_TRUE(clang::tooling::runToolOnCode(std::make_unique<Action>(result), code, "origin.cpp"));
        ASSERT_TRUE(result.found);
        ASSERT_TRUE(result.converged);
        EXPECT_EQ(result.divisor, item.range);
        EXPECT_EQ(result.untrusted, item.origin);
    }
}

TEST(IntervalAnalysisTest, LoopCounterTerminatesViaWidening) {
    // The analysis must CONVERGE (widening) — an unbounded loop counter
    // widens to a range including large values; we only assert it
    // terminated and stays a sound over-approximation containing the
    // reachable values.
    Interval n = divisorInterval(
        "int f(int x){ int n = 1; for (int i = 0; i < 100; i++) n = n + 1; "
        "return x / n; }");
    EXPECT_TRUE(n.contains(1));   // sound: the pre-loop value is included
}
