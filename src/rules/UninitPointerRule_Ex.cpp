#include "rules/UninitPointerRule_Ex.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Analysis/CFG.h>

#include <queue>
#include <unordered_map>
#include <unordered_set>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- PtrState lattice ---

enum class PtrState { Uninit, MaybeInit, Init };

PtrState mergeStates(PtrState a, PtrState b) {
    if (a == b) return a;
    return PtrState::MaybeInit;
}

// --- Statement classification ---

enum class StmtEffect { None, Assigns, Dereferences };

StmtEffect classifyStmt(const Stmt* stmt, const VarDecl* targetVar,
                         ASTContext& ctx) {
    // Assignment: p = ... (direct assignment to targetVar)
    auto assignMatcher = findAll(binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(
            declRefExpr(to(varDecl(equalsNode(targetVar))))))
    ));

    // Address-of: &p (out-param pattern — conservative Init)
    auto addrOfMatcher = findAll(unaryOperator(
        hasOperatorName("&"),
        hasUnaryOperand(ignoringParenImpCasts(
            declRefExpr(to(varDecl(equalsNode(targetVar))))))
    ));

    // Check assigns first
    if (!match(assignMatcher, *stmt, ctx).empty())
        return StmtEffect::Assigns;
    if (!match(addrOfMatcher, *stmt, ctx).empty())
        return StmtEffect::Assigns;

    // Dereference: *p
    auto derefMatcher = findAll(unaryOperator(
        hasOperatorName("*"),
        hasUnaryOperand(ignoringParenImpCasts(
            declRefExpr(to(varDecl(equalsNode(targetVar))))))
    ));

    // Arrow: p->member
    auto arrowMatcher = findAll(memberExpr(
        isArrow(),
        hasObjectExpression(ignoringParenImpCasts(
            declRefExpr(to(varDecl(equalsNode(targetVar))))))
    ));

    // Array subscript: p[i]
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

// --- Dataflow analysis ---

void analyzeFunction(const FunctionDecl* funcDecl,
                     const VarDecl* targetVar,
                     ASTContext& ctx,
                     zerodefect::DiagnosticList& results) {
    if (!funcDecl->hasBody()) return;

    CFG::BuildOptions opts;
    std::unique_ptr<CFG> cfg = CFG::buildCFG(
        funcDecl, funcDecl->getBody(), &ctx, opts);
    if (!cfg) return;

    const unsigned numBlocks = cfg->getNumBlockIDs();
    const unsigned maxIterations = numBlocks * 4;

    // Block exit states
    std::unordered_map<unsigned, PtrState> blockExitState;
    std::unordered_set<unsigned> reportedLines;

    // Worklist
    std::queue<const CFGBlock*> worklist;
    worklist.push(&cfg->getEntry());
    unsigned iterations = 0;

    while (!worklist.empty() && iterations < maxIterations) {
        ++iterations;
        const CFGBlock* block = worklist.front();
        worklist.pop();

        // Merge from predecessors
        PtrState entryState = PtrState::Uninit;
        bool hasPreds = false;
        bool firstPred = true;

        for (auto it = block->pred_begin(); it != block->pred_end(); ++it) {
            const CFGBlock* pred = it->getReachableBlock();
            if (!pred) continue;

            auto found = blockExitState.find(pred->getBlockID());
            if (found == blockExitState.end()) continue;

            hasPreds = true;
            if (firstPred) {
                entryState = found->second;
                firstPred = false;
            } else {
                entryState = mergeStates(entryState, found->second);
            }
        }

        // Entry block: no predecessors → Uninit
        if (!hasPreds && block == &cfg->getEntry()) {
            entryState = PtrState::Uninit;
        } else if (!hasPreds) {
            continue; // unreachable block
        }

        // Walk statements in this block
        PtrState currentState = entryState;

        for (const CFGElement& elem : *block) {
            auto cfgStmt = elem.getAs<CFGStmt>();
            if (!cfgStmt) continue;

            const Stmt* stmt = cfgStmt->getStmt();
            if (!stmt) continue;

            StmtEffect effect = classifyStmt(stmt, targetVar, ctx);

            if (effect == StmtEffect::Assigns) {
                currentState = PtrState::Init;
            } else if (effect == StmtEffect::Dereferences &&
                       currentState != PtrState::Init) {
                // Report at dereference location
                const SourceManager& sm = ctx.getSourceManager();
                SourceLocation loc = stmt->getBeginLoc();
                unsigned line = sm.getSpellingLineNumber(loc);

                if (reportedLines.insert(line).second) {
                    zerodefect::Diagnostic diag;
                    diag.severity = zerodefect::Severity::Error;
                    diag.file = sm.getFilename(loc).str();
                    diag.line = line;
                    diag.column = sm.getSpellingColumnNumber(loc);
                    diag.rule_id = "uninit-ptr";
                    diag.message = "Baslatilmamis pointer kullanimi: "
                        + targetVar->getNameAsString()
                        + " dereference noktasinda deger atanmamis olabilir";
                    results.push_back(diag);
                }

                // Continue analysis but don't re-report
                currentState = PtrState::MaybeInit;
            }
        }

        // Update exit state, propagate if changed
        auto [it, inserted] = blockExitState.emplace(
            block->getBlockID(), currentState);

        bool changed = inserted || it->second != currentState;
        if (changed) {
            it->second = currentState;
            for (auto succIt = block->succ_begin();
                 succIt != block->succ_end(); ++succIt) {
                const CFGBlock* succ = succIt->getReachableBlock();
                if (succ) {
                    worklist.push(succ);
                }
            }
        }
    }
}

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

        analyzeFunction(func, var, *result.Context, results_);
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
    return "CFG-tabanli baslatilmamis pointer kullanim analizi";
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
