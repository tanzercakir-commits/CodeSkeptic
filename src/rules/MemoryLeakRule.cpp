#include "rules/MemoryLeakRule.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

class MemLeakCallback : public MatchFinder::MatchCallback {
public:
    explicit MemLeakCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const SourceManager& sm = *result.SourceManager;
        SourceLocation loc;
        std::string message;

        if (const auto* var = result.Nodes.getNodeAs<VarDecl>("raw_new_var")) {
            loc = var->getLocation();
            message = "Raw new kullanimi: " + var->getNameAsString()
                      + " icin smart pointer kullanmayi dusunun";

        } else if (const auto* assign = result.Nodes.getNodeAs<BinaryOperator>("raw_new_assign")) {
            loc = assign->getOperatorLoc();
            std::string name;
            if (const auto* ref = dyn_cast<DeclRefExpr>(assign->getLHS()->IgnoreParenImpCasts())) {
                name = ref->getDecl()->getNameAsString();
            }
            message = "Raw new atamasi: " + name
                      + " icin smart pointer kullanmayi dusunun";

        } else if (const auto* ret = result.Nodes.getNodeAs<ReturnStmt>("raw_new_return")) {
            loc = ret->getReturnLoc();
            message = "Fonksiyondan raw new donusu: smart pointer dondurmeyi dusunun";

        } else {
            return;
        }

        if (sm.isInSystemHeader(loc)) return;

        zerodefect::Diagnostic diag;
        diag.severity = zerodefect::Severity::Warning;
        diag.file = sm.getFilename(loc).str();
        diag.line = sm.getSpellingLineNumber(loc);
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "memory-leak";
        diag.message = message;

        results_.push_back(diag);
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string MemoryLeakRule::id() const {
    return "memory-leak";
}

std::string MemoryLeakRule::description() const {
    return "Raw new kullanimi, smart pointer onerilir";
}

void MemoryLeakRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    MatchFinder finder;
    MemLeakCallback callback(results);

    auto matcher1 = varDecl(
        hasType(pointerType()),
        hasInitializer(
            ignoringParenImpCasts(cxxNewExpr())
        )
    ).bind("raw_new_var");

    auto matcher2 = binaryOperator(
        hasOperatorName("="),
        hasLHS(
            declRefExpr(
                to(varDecl(hasType(pointerType())))
            )
        ),
        hasRHS(
            ignoringParenImpCasts(cxxNewExpr())
        )
    ).bind("raw_new_assign");

    auto matcher3 = returnStmt(
        hasReturnValue(
            ignoringParenImpCasts(cxxNewExpr())
        )
    ).bind("raw_new_return");

    finder.addMatcher(matcher1, &callback);
    finder.addMatcher(matcher2, &callback);
    finder.addMatcher(matcher3, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
