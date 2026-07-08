#include "rules/UninitPointerRule_Ex.h"

#include "core/Messages.h"
#include "engine/DataflowEngine.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <unordered_set>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- PtrState lattice ---

enum class PtrState { Uninit, MaybeInit, Init };

// --- Statement classification ---

enum class StmtEffect { None, Assigns, Dereferences };

StmtEffect classifyStmt(const Stmt* stmt, const VarDecl* targetVar,
                         ASTContext& ctx) {
    auto assignMatcher = findAll(binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(
            declRefExpr(to(varDecl(equalsNode(targetVar))))))
    ));
    auto addrOfMatcher = findAll(unaryOperator(
        hasOperatorName("&"),
        hasUnaryOperand(ignoringParenImpCasts(
            declRefExpr(to(varDecl(equalsNode(targetVar))))))
    ));

    if (!match(assignMatcher, *stmt, ctx).empty())
        return StmtEffect::Assigns;
    if (!match(addrOfMatcher, *stmt, ctx).empty())
        return StmtEffect::Assigns;

    auto derefMatcher = findAll(unaryOperator(
        hasOperatorName("*"),
        hasUnaryOperand(ignoringParenImpCasts(
            declRefExpr(to(varDecl(equalsNode(targetVar))))))
    ));
    auto arrowMatcher = findAll(memberExpr(
        isArrow(),
        hasObjectExpression(ignoringParenImpCasts(
            declRefExpr(to(varDecl(equalsNode(targetVar))))))
    ));
    auto subscriptMatcher = findAll(arraySubscriptExpr(
        hasBase(ignoringParenImpCasts(
            declRefExpr(to(varDecl(equalsNode(targetVar))))))
    ));

    if (!match(derefMatcher, *stmt, ctx).empty())
        return StmtEffect::Dereferences;
    if (!match(arrowMatcher, *stmt, ctx).empty())
        return StmtEffect::Dereferences;
    if (!match(subscriptMatcher, *stmt, ctx).empty())
        return StmtEffect::Dereferences;

    return StmtEffect::None;
}

// --- Analysis struct for DataflowEngine ---

class UninitPtrAnalysis {
public:
    using State = PtrState;

    UninitPtrAnalysis(const VarDecl* targetVar,
                      zerodefect::DiagnosticList& results)
        : targetVar_(targetVar), results_(results) {}

    State initialState() const { return PtrState::Uninit; }

    State merge(const State& a, const State& b) const {
        if (a == b) return a;
        return PtrState::MaybeInit;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& ctx) const {
        StmtEffect effect = classifyStmt(stmt, targetVar_, ctx);
        if (effect == StmtEffect::Assigns)
            return PtrState::Init;
        return in;
    }

    void onStatement(const Stmt* stmt, const State& before,
                     const State& after, ASTContext& ctx) {
        StmtEffect effect = classifyStmt(stmt, targetVar_, ctx);
        if (effect == StmtEffect::Dereferences && before != PtrState::Init) {
            const SourceManager& sm = ctx.getSourceManager();
            SourceLocation loc = stmt->getBeginLoc();
            unsigned line = sm.getSpellingLineNumber(loc);

            if (reportedLines_.insert(line).second) {
                zerodefect::Diagnostic diag;
                diag.severity = zerodefect::Severity::Error;
                diag.file = sm.getFilename(loc).str();
                diag.line = line;
                diag.column = sm.getSpellingColumnNumber(loc);
                diag.rule_id = "uninit-ptr";
                diag.message = zerodefect::msg(
                    zerodefect::MsgId::UninitPtrDeref,
                    targetVar_->getNameAsString());
                results_.push_back(diag);
            }
        }
    }

private:
    const VarDecl* targetVar_;
    zerodefect::DiagnosticList& results_;
    std::unordered_set<unsigned> reportedLines_;
};

// --- Matcher callback ---

class FindUninitPtrCallback : public MatchFinder::MatchCallback {
public:
    explicit FindUninitPtrCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* var = result.Nodes.getNodeAs<VarDecl>("uninit_ptr");
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("enclosing_func");
        if (!var || !func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(var->getLocation())) return;

        UninitPtrAnalysis analysis(var, results_);
        zerodefect::runDataflow(func, *result.Context, analysis);
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string UninitPointerRule_Ex::id() const {
    return "uninit-ptr";
}

std::string UninitPointerRule_Ex::description() const {
    return "CFG-based uninitialized pointer use analysis";
}

Severity UninitPointerRule_Ex::defaultSeverity() const {
    return Severity::Error;
}

void UninitPointerRule_Ex::check(clang::ASTContext& ctx,
                                  DiagnosticList& results) {
    MatchFinder finder;
    FindUninitPtrCallback callback(results);

    auto matcher = varDecl(
        hasType(pointerType()),
        unless(hasInitializer(anything())),
        unless(parmVarDecl()),
        hasAncestor(functionDecl().bind("enclosing_func"))
    ).bind("uninit_ptr");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
