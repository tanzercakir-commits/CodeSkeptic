#include "rules/UninitPointerRule.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

class UninitPtrCallback : public MatchFinder::MatchCallback {
public:
    explicit UninitPtrCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* var = result.Nodes.getNodeAs<VarDecl>("uninit_ptr");
        if (!var) return;

        const SourceManager& sm = *result.SourceManager;
        SourceLocation loc = var->getLocation();

        if (sm.isInSystemHeader(loc)) return;

        zerodefect::Diagnostic diag;
        diag.severity = zerodefect::Severity::Error;
        diag.file = sm.getFilename(loc).str();
        diag.line = sm.getSpellingLineNumber(loc);
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "uninit-ptr";
        diag.message = "Baslatilmamis pointer: " + var->getNameAsString()
                       + " kullanilmadan once deger atanmali";

        results_.push_back(diag);
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string UninitPointerRule::id() const {
    return "uninit-ptr";
}

std::string UninitPointerRule::description() const {
    return "Baslatilmamis pointer kullanimi";
}

Severity UninitPointerRule::defaultSeverity() const {
    return Severity::Error;
}

void UninitPointerRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    MatchFinder finder;
    UninitPtrCallback callback(results);

    auto matcher = varDecl(
        hasType(pointerType()),
        unless(hasInitializer(anything())),
        unless(parmVarDecl())
    ).bind("uninit_ptr");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
