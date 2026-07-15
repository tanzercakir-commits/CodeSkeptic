#include "engine/ParamIntervals.h"

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Tooling/Tooling.h>
#include <gtest/gtest.h>

#include <string>

// ParamIntervals (C3, 2026-07-15): the interprocedural entry-interval
// pass. These tests build the map directly and read back the proven
// entry interval of a named function's first parameter, checking both
// the narrowing (closed static callers) and the soundness gates
// (external linkage, address-taken, mixed callers).

using namespace clang;
using zerodefect::Interval;

namespace {

Interval entryOfFirstParam(const std::string& code, const std::string& fnName) {
    struct V : RecursiveASTVisitor<V> {
        std::string want;
        const FunctionDecl* fn = nullptr;
        bool VisitFunctionDecl(FunctionDecl* f) {
            if (f->hasBody() && f->getName() == want) fn = f;
            return true;
        }
    };
    struct Consumer : ASTConsumer {
        std::string want;
        Interval* out;
        Consumer(std::string w, Interval* o) : want(std::move(w)), out(o) {}
        void HandleTranslationUnit(ASTContext& ctx) override {
            V v; v.want = want;
            v.TraverseDecl(ctx.getTranslationUnitDecl());
            auto map = zerodefect::buildParamIntervals(ctx);
            if (v.fn) *out = zerodefect::paramEntryInterval(map, v.fn, 0);
        }
    };
    struct Action : ASTFrontendAction {
        std::string want;
        Interval* out;
        Action(std::string w, Interval* o) : want(std::move(w)), out(o) {}
        std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance&,
                                                       llvm::StringRef) override {
            return std::make_unique<Consumer>(want, out);
        }
    };
    Interval result = Interval::top();
    clang::tooling::runToolOnCode(std::make_unique<Action>(fnName, &result),
                                  code, "params.c");
    return result;
}

} // namespace

TEST(ParamIntervalsTest, StaticSingleLiteralCallerIsExact) {
    Interval n = entryOfFirstParam(
        "static int g(int n){ return n; } int f(void){ return g(7); }", "g");
    EXPECT_EQ(n, Interval::constant(7));
}

TEST(ParamIntervalsTest, StaticMultipleLiteralCallersJoin) {
    Interval n = entryOfFirstParam(
        "static int g(int n){ return n; } "
        "int f(void){ return g(3) + g(9); }", "g");
    EXPECT_EQ(n, Interval::range(3, 9));
}

TEST(ParamIntervalsTest, MixedUnknownCallerWidensToTop) {
    Interval n = entryOfFirstParam(
        "static int g(int n){ return n; } "
        "int f(int x){ return g(3) + g(x); }", "g");
    EXPECT_TRUE(n.isTop());
}

TEST(ParamIntervalsTest, ExternalFunctionIsTop) {
    // Non-static: callers in other TUs are invisible → unconstrained.
    Interval n = entryOfFirstParam(
        "int g(int n){ return n; } int f(void){ return g(7); }", "g");
    EXPECT_TRUE(n.isTop());
}

TEST(ParamIntervalsTest, AddressTakenIsTop) {
    // g's address escapes → an indirect call could pass anything.
    Interval n = entryOfFirstParam(
        "static int g(int n){ return n; } "
        "int (*fp)(int) = g; "
        "int f(void){ return g(7); }", "g");
    EXPECT_TRUE(n.isTop());
}

TEST(ParamIntervalsTest, UncalledStaticIsTop) {
    Interval n = entryOfFirstParam(
        "static int g(int n){ return n; } int f(void){ return 0; }", "g");
    EXPECT_TRUE(n.isTop());
}

// --- v0.2 (two-pass): caller local dataflow, not just literals ---

TEST(ParamIntervalsTest, BoundedLocalCallerNarrows) {
    // The argument is a LOCAL (k), not a literal — v0.2 reads the caller's
    // interval state at the call, where k is proven [5,5].
    Interval n = entryOfFirstParam(
        "static int g(int n){ return n; } "
        "int f(void){ int k = 5; return g(k); }", "g");
    EXPECT_EQ(n, Interval::constant(5));
}

TEST(ParamIntervalsTest, GuardBoundedCallerNarrows) {
    // x is refined to [0,10] by the caller's guards before the call.
    Interval n = entryOfFirstParam(
        "static int g(int n){ return n; } "
        "int f(int x){ if (x < 0) return 0; if (x > 10) return 0; "
        "return g(x); }", "g");
    EXPECT_EQ(n, Interval::range(0, 10));
}
