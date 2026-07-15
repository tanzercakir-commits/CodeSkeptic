#include "engine/IntervalAnalysis.h"

#include "engine/CfgCache.h"
#include "engine/DataflowEngine.h"

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
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
using zerodefect::Interval;

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
    Interval divisor;
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
        zerodefect::CfgCache::instance().clear();
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
        zerodefect::IntervalAnalysis analysis(intVars(v.fn, ctx));
        zerodefect::runDataflow(v.fn, ctx, analysis);
        out_.divisor = analysis.intervalAt(site.op, site.divisor);
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
    return out.divisor;
}

} // namespace

TEST(IntervalAnalysisTest, ConstantAssignment) {
    Interval n = divisorInterval("int f(int x){ int n = 5; return x / n; }");
    EXPECT_EQ(n, Interval::constant(5));
    EXPECT_TRUE(n.isKnownNonZero());
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
