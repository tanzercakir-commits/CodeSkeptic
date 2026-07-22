#include "TestHelper.h"

#include "contracts/Sidecar.h"
#include "engine/CfgCache.h"
#include "engine/FunctionSummary.h"
#include "engine/ParamIntervals.h"
#include "source_manager/SourceManager.h"

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Tooling/Tooling.h>

namespace {

class TestASTConsumer : public clang::ASTConsumer {
public:
    TestASTConsumer(codeskeptic::Rule& rule, codeskeptic::DiagnosticList& results)
        : rule_(rule), results_(results) {}

    void HandleTranslationUnit(clang::ASTContext& ctx) override {
        // As RuleEngine::runAll does in production: summaries are built
        // before the rule and cleared when the TU ends (no dangling
        // pointers)
        codeskeptic::SummaryRegistry::instance().rebuild(ctx);
        rule_.check(ctx, results_);
        codeskeptic::SummaryRegistry::instance().clear();
        codeskeptic::CfgCache::instance().clear();
        codeskeptic::ParamIntervalCache::instance().clear();
        codeskeptic::clearSidecarCache();
    }

private:
    codeskeptic::Rule& rule_;
    codeskeptic::DiagnosticList& results_;
};

class TestAction : public clang::ASTFrontendAction {
public:
    TestAction(codeskeptic::Rule& rule, codeskeptic::DiagnosticList& results)
        : rule_(rule), results_(results) {}

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance& /*ci*/,
                      llvm::StringRef /*file*/) override {
        return std::make_unique<TestASTConsumer>(rule_, results_);
    }

private:
    codeskeptic::Rule& rule_;
    codeskeptic::DiagnosticList& results_;
};

// Test counterpart of whole-program pass 1: summary harvesting only
class HarvestASTConsumer : public clang::ASTConsumer {
public:
    void HandleTranslationUnit(clang::ASTContext& ctx) override {
        auto& registry = codeskeptic::SummaryRegistry::instance();
        registry.rebuild(ctx);
        registry.harvestGlobal();
        registry.clear();
        codeskeptic::CfgCache::instance().clear();
    }
};

class HarvestAction : public clang::ASTFrontendAction {
public:
    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance& /*ci*/,
                      llvm::StringRef /*file*/) override {
        return std::make_unique<HarvestASTConsumer>();
    }
};

} // anonymous namespace

namespace codeskeptic {
namespace testing {

// Same platform args as production tooling (resource-dir; macOS SDK
// sysroot) — single source of truth in platformExtraArgs(). Without
// them a snippet's #include <stdlib.h> fails on macOS, the TU breaks,
// and finding-expecting tests fail while clean-expecting ones pass
// vacuously.
static std::vector<std::string> testArgs() {
    std::vector<std::string> args = {"-fparse-all-comments"};
    for (auto& a : platformExtraArgs()) args.push_back(a);
    return args;
}

DiagnosticList runRule(Rule& rule, const std::string& code,
                       const std::string& filename) {
    DiagnosticList results;
    clang::tooling::runToolOnCodeWithArgs(
        std::make_unique<TestAction>(rule, results),
        code,
        testArgs(),
        filename);
    return results;
}

DiagnosticList runRuleCrossTU(Rule& rule, const std::string& calleeTU,
                              const std::string& callerTU) {
    SummaryRegistry::instance().clearGlobal();
    clang::tooling::runToolOnCodeWithArgs(
        std::make_unique<HarvestAction>(), calleeTU,
        testArgs(), "callee_tu.cpp");
    DiagnosticList results;
    clang::tooling::runToolOnCodeWithArgs(
        std::make_unique<TestAction>(rule, results),
        callerTU, testArgs(), "caller_tu.cpp");
    SummaryRegistry::instance().clearGlobal();
    return results;
}

} // namespace testing
} // namespace codeskeptic
