#include "TestHelper.h"

#include "engine/CfgCache.h"
#include "engine/FunctionSummary.h"

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Tooling/Tooling.h>

namespace {

class TestASTConsumer : public clang::ASTConsumer {
public:
    TestASTConsumer(zerodefect::Rule& rule, zerodefect::DiagnosticList& results)
        : rule_(rule), results_(results) {}

    void HandleTranslationUnit(clang::ASTContext& ctx) override {
        // Uretimde RuleEngine::runAll'in yaptigi gibi: ozetler kuraldan
        // once kurulur, TU bitince temizlenir (sarkan pointer olmasin)
        zerodefect::SummaryRegistry::instance().rebuild(ctx);
        rule_.check(ctx, results_);
        zerodefect::SummaryRegistry::instance().clear();
        zerodefect::CfgCache::instance().clear();
    }

private:
    zerodefect::Rule& rule_;
    zerodefect::DiagnosticList& results_;
};

class TestAction : public clang::ASTFrontendAction {
public:
    TestAction(zerodefect::Rule& rule, zerodefect::DiagnosticList& results)
        : rule_(rule), results_(results) {}

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance& /*ci*/,
                      llvm::StringRef /*file*/) override {
        return std::make_unique<TestASTConsumer>(rule_, results_);
    }

private:
    zerodefect::Rule& rule_;
    zerodefect::DiagnosticList& results_;
};

// Whole-program 1. gecisin test karsiligi: yalnizca ozet hasadi
class HarvestASTConsumer : public clang::ASTConsumer {
public:
    void HandleTranslationUnit(clang::ASTContext& ctx) override {
        auto& registry = zerodefect::SummaryRegistry::instance();
        registry.rebuild(ctx);
        registry.harvestGlobal();
        registry.clear();
        zerodefect::CfgCache::instance().clear();
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

namespace zerodefect {
namespace testing {

DiagnosticList runRule(Rule& rule, const std::string& code,
                       const std::string& filename) {
    DiagnosticList results;
    clang::tooling::runToolOnCode(
        std::make_unique<TestAction>(rule, results),
        code,
        filename);
    return results;
}

DiagnosticList runRuleCrossTU(Rule& rule, const std::string& calleeTU,
                              const std::string& callerTU) {
    SummaryRegistry::instance().clearGlobal();
    clang::tooling::runToolOnCode(std::make_unique<HarvestAction>(),
                                  calleeTU, "callee_tu.cpp");
    DiagnosticList results;
    clang::tooling::runToolOnCode(
        std::make_unique<TestAction>(rule, results),
        callerTU, "caller_tu.cpp");
    SummaryRegistry::instance().clearGlobal();
    return results;
}

} // namespace testing
} // namespace zerodefect
