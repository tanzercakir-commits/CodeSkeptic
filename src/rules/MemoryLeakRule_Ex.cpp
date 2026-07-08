#include "rules/MemoryLeakRule_Ex.h"

#include "core/Messages.h"
#include "engine/DataflowEngine.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <map>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- AllocState lattice ---

enum class AllocState { None, Allocated, Freed, Escaped };

AllocState mergeAllocStates(AllocState a, AllocState b) {
    if (a == b) return a;
    if (a == AllocState::Escaped || b == AllocState::Escaped)
        return AllocState::Escaped;
    if (a == AllocState::None || b == AllocState::None) {
        AllocState other = (a == AllocState::None) ? b : a;
        if (other == AllocState::Allocated) return AllocState::Allocated;
        return AllocState::None;
    }
    return AllocState::Allocated;
}

// --- Statement classification ---

enum class StmtEffect { None, Allocates, Frees, Escapes };

auto allocCallMatcher() {
    return callExpr(callee(functionDecl(
        hasAnyName("malloc", "calloc", "strdup"))));
}

bool isAllocExpr(const Expr* expr, ASTContext& ctx) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    if (isa<CXXNewExpr>(expr)) return true;
    if (const auto* cast = dyn_cast<CastExpr>(expr))
        return isAllocExpr(cast->getSubExpr(), ctx);
    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        if (const auto* callee = call->getDirectCallee()) {
            auto name = callee->getName();
            return name == "malloc" || name == "calloc" ||
                   name == "strdup" || name == "realloc";
        }
    }
    return false;
}

bool refersToVar(const Expr* expr, const VarDecl* targetVar) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return ref->getDecl() == targetVar;
    return false;
}

StmtEffect classifyStmt(const Stmt* stmt, const VarDecl* targetVar,
                         ASTContext& ctx) {
    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (vd == targetVar && vd->hasInit()) {
                    if (isAllocExpr(vd->getInit(), ctx))
                        return StmtEffect::Allocates;
                }
            }
        }
        return StmtEffect::None;
    }
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign) {
            if (refersToVar(binOp->getLHS(), targetVar) &&
                isAllocExpr(binOp->getRHS(), ctx))
                return StmtEffect::Allocates;
        }
    }
    if (const auto* del = dyn_cast<CXXDeleteExpr>(stmt)) {
        if (refersToVar(del->getArgument(), targetVar))
            return StmtEffect::Frees;
    }
    if (const auto* call = dyn_cast<CallExpr>(stmt)) {
        if (const auto* callee = call->getDirectCallee()) {
            if (callee->getName() == "free" && call->getNumArgs() > 0) {
                if (refersToVar(call->getArg(0), targetVar))
                    return StmtEffect::Frees;
            }
        }
        for (unsigned i = 0; i < call->getNumArgs(); ++i) {
            if (refersToVar(call->getArg(i), targetVar))
                return StmtEffect::Escapes;
        }
    }
    if (const auto* ret = dyn_cast<ReturnStmt>(stmt)) {
        if (refersToVar(ret->getRetValue(), targetVar))
            return StmtEffect::Escapes;
    }
    return StmtEffect::None;
}

// --- Collect tracked pointer variables ---

std::vector<const VarDecl*> collectTrackedVars(const FunctionDecl* funcDecl,
                                                ASTContext& ctx) {
    std::set<const VarDecl*> vars;

    auto newInitMatcher = varDecl(
        hasType(pointerType()),
        hasInitializer(ignoringParenImpCasts(cxxNewExpr()))
    ).bind("var");
    auto mallocInitMatcher = varDecl(
        hasType(pointerType()),
        hasInitializer(ignoringParenImpCasts(
            castExpr(hasSourceExpression(ignoringParenImpCasts(
                allocCallMatcher())))))
    ).bind("var");
    auto mallocInitDirect = varDecl(
        hasType(pointerType()),
        hasInitializer(ignoringParenImpCasts(allocCallMatcher()))
    ).bind("var");
    auto newAssignMatcher = binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("var"))))),
        hasRHS(ignoringParenImpCasts(cxxNewExpr()))
    );
    auto mallocAssignMatcher = binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("var"))))),
        hasRHS(ignoringParenImpCasts(
            castExpr(hasSourceExpression(ignoringParenImpCasts(
                allocCallMatcher())))))
    );

    auto declMatchers = {newInitMatcher, mallocInitMatcher, mallocInitDirect};
    for (const auto& m : declMatchers) {
        auto wrapper = functionDecl(equalsNode(funcDecl),
                                     forEachDescendant(m));
        for (const auto& result : match(wrapper, *funcDecl, ctx)) {
            if (const auto* v = result.getNodeAs<VarDecl>("var"))
                vars.insert(v);
        }
    }
    auto assignMatchers = {newAssignMatcher, mallocAssignMatcher};
    for (const auto& m : assignMatchers) {
        for (const auto& result : match(findAll(m), *funcDecl->getBody(), ctx)) {
            if (const auto* v = result.getNodeAs<VarDecl>("var"))
                vars.insert(v);
        }
    }
    return {vars.begin(), vars.end()};
}

// --- Analysis struct for DataflowEngine ---

using VarState = std::map<const VarDecl*, AllocState>;

class MemLeakAnalysis {
public:
    using State = VarState;

    MemLeakAnalysis(const std::vector<const VarDecl*>& trackedVars,
                    zerodefect::DiagnosticList& results)
        : trackedVars_(trackedVars), results_(results) {
        for (const auto* var : trackedVars_)
            initState_[var] = AllocState::None;
    }

    State initialState() const { return initState_; }

    State merge(const State& a, const State& b) const {
        State result = a;
        for (const auto& [var, stateB] : b) {
            auto it = result.find(var);
            if (it == result.end())
                result[var] = stateB;
            else
                it->second = mergeAllocStates(it->second, stateB);
        }
        return result;
    }

    State transfer(const Stmt* stmt, const State& in, ASTContext& ctx) {
        State out = in;
        const SourceManager& sm = ctx.getSourceManager();

        for (const auto* var : trackedVars_) {
            StmtEffect effect = classifyStmt(stmt, var, ctx);

            if (effect == StmtEffect::Allocates) {
                if (out[var] == AllocState::Allocated) {
                    SourceLocation loc = stmt->getBeginLoc();
                    unsigned line = sm.getSpellingLineNumber(loc);
                    if (reported_.emplace(var, line).second) {
                        zerodefect::Diagnostic diag;
                        diag.severity = zerodefect::Severity::Warning;
                        diag.file = sm.getFilename(loc).str();
                        diag.line = line;
                        diag.column = sm.getSpellingColumnNumber(loc);
                        diag.rule_id = "memory-leak";
                        diag.message = zerodefect::msg(
                            zerodefect::MsgId::LeakReassign,
                            var->getNameAsString());
                        results_.push_back(diag);
                    }
                }
                out[var] = AllocState::Allocated;

            } else if (effect == StmtEffect::Frees) {
                if (out[var] == AllocState::Freed) {
                    SourceLocation loc = stmt->getBeginLoc();
                    unsigned line = sm.getSpellingLineNumber(loc);
                    if (reported_.emplace(var, line).second) {
                        zerodefect::Diagnostic diag;
                        diag.severity = zerodefect::Severity::Error;
                        diag.file = sm.getFilename(loc).str();
                        diag.line = line;
                        diag.column = sm.getSpellingColumnNumber(loc);
                        diag.rule_id = "memory-leak";
                        diag.message = zerodefect::msg(
                            zerodefect::MsgId::DoubleFree,
                            var->getNameAsString());
                        results_.push_back(diag);
                    }
                }
                out[var] = AllocState::Freed;

            } else if (effect == StmtEffect::Escapes) {
                out[var] = AllocState::Escaped;
            }
        }
        return out;
    }

    std::set<std::pair<const VarDecl*, unsigned>>& reported() {
        return reported_;
    }

private:
    const std::vector<const VarDecl*>& trackedVars_;
    zerodefect::DiagnosticList& results_;
    VarState initState_;
    std::set<std::pair<const VarDecl*, unsigned>> reported_;
};

// --- Function-level analysis ---

void analyzeFunction(const FunctionDecl* funcDecl,
                     ASTContext& ctx,
                     zerodefect::DiagnosticList& results) {
    if (!funcDecl->hasBody()) return;

    auto trackedVars = collectTrackedVars(funcDecl, ctx);
    if (trackedVars.empty()) return;

    MemLeakAnalysis analysis(trackedVars, results);
    auto dfResult = zerodefect::runDataflow(funcDecl, ctx, analysis);

    // Exit block leak check
    auto exitIt = dfResult.blockExitStates.find(dfResult.exitBlockID);
    if (exitIt == dfResult.blockExitStates.end()) return;

    const SourceManager& sm = ctx.getSourceManager();
    SourceLocation endLoc = funcDecl->getBody()->getEndLoc();

    for (const auto& [var, state] : exitIt->second) {
        if (state == AllocState::Allocated) {
            unsigned line = sm.getSpellingLineNumber(endLoc);
            if (analysis.reported().emplace(var, line).second) {
                zerodefect::Diagnostic diag;
                diag.severity = zerodefect::Severity::Warning;
                diag.file = sm.getFilename(endLoc).str();
                diag.line = line;
                diag.column = sm.getSpellingColumnNumber(endLoc);
                diag.rule_id = "memory-leak";
                diag.message = zerodefect::msg(
                    zerodefect::MsgId::LeakEndOfFunction,
                    var->getNameAsString());
                results.push_back(diag);
            }
        }
    }
}

// --- Matcher callback ---

class FindMemLeakCallback : public MatchFinder::MatchCallback {
public:
    explicit FindMemLeakCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;

        analyzeFunction(func, *result.Context, results_);
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string MemoryLeakRule_Ex::id() const {
    return "memory-leak";
}

std::string MemoryLeakRule_Ex::description() const {
    return "CFG-based memory leak and double-free analysis";
}

void MemoryLeakRule_Ex::check(clang::ASTContext& ctx,
                               DiagnosticList& results) {
    MatchFinder finder;
    FindMemLeakCallback callback(results);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
