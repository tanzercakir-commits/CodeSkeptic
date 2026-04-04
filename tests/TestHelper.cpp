#include "TestHelper.h"

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
        rule_.check(ctx, results_);
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

} // namespace testing
} // namespace zerodefect
