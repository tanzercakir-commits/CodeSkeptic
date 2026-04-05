#include "rules/MemoryLeakRule_Ex.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Analysis/CFG.h>

#include <map>
#include <queue>
#include <set>
#include <unordered_map>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- AllocState lattice ---

enum class AllocState { None, Allocated, Freed, Escaped };

AllocState mergeStates(AllocState a, AllocState b) {
    if (a == b) return a;
    if (a == AllocState::Escaped || b == AllocState::Escaped)
        return AllocState::Escaped;
    if (a == AllocState::None || b == AllocState::None) {
        AllocState other = (a == AllocState::None) ? b : a;
        if (other == AllocState::Allocated) return AllocState::Allocated;
        return AllocState::None;
    }
    // Allocated + Freed = Allocated (some paths leak)
    return AllocState::Allocated;
}

// --- Multi-variable state ---

using VarState = std::map<const VarDecl*, AllocState>;

VarState mergeVarStates(const VarState& a, const VarState& b) {
    VarState result = a;
    for (const auto& [var, stateB] : b) {
        auto it = result.find(var);
        if (it == result.end())
            result[var] = stateB;
        else
            it->second = mergeStates(it->second, stateB);
    }
    return result;
}

// --- Statement classification ---

enum class StmtEffect { None, Allocates, Frees, Escapes };

// Alloc function matcher (reusable)
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
    // 1. DeclStmt: int* p = new int / (int*)malloc(...)
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

    // 2. Assignment: p = new int / p = malloc(...)
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign) {
            if (refersToVar(binOp->getLHS(), targetVar) &&
                isAllocExpr(binOp->getRHS(), ctx))
                return StmtEffect::Allocates;
        }
    }

    // For compound expressions, check sub-expressions
    // Walk children for delete/free/escape patterns

    // 3. Frees: delete p / delete[] p
    if (const auto* del = dyn_cast<CXXDeleteExpr>(stmt)) {
        if (refersToVar(del->getArgument(), targetVar))
            return StmtEffect::Frees;
    }

    // 4. Frees via function call: free(p)
    if (const auto* call = dyn_cast<CallExpr>(stmt)) {
        if (const auto* callee = call->getDirectCallee()) {
            if (callee->getName() == "free" && call->getNumArgs() > 0) {
                if (refersToVar(call->getArg(0), targetVar))
                    return StmtEffect::Frees;
            }
        }
        // 5. Escapes: function call with p as argument
        for (unsigned i = 0; i < call->getNumArgs(); ++i) {
            if (refersToVar(call->getArg(i), targetVar))
                return StmtEffect::Escapes;
        }
    }

    // 6. Escapes: return p
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

    // Vars initialized with new
    auto newInitMatcher = varDecl(
        hasType(pointerType()),
        hasInitializer(ignoringParenImpCasts(cxxNewExpr()))
    ).bind("var");

    // Vars initialized with malloc (with cast)
    auto mallocInitMatcher = varDecl(
        hasType(pointerType()),
        hasInitializer(ignoringParenImpCasts(
            castExpr(hasSourceExpression(ignoringParenImpCasts(
                allocCallMatcher())))))
    ).bind("var");

    // Vars initialized with malloc (direct, C mode)
    auto mallocInitDirect = varDecl(
        hasType(pointerType()),
        hasInitializer(ignoringParenImpCasts(allocCallMatcher()))
    ).bind("var");

    // Vars assigned with new
    auto newAssignMatcher = binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("var"))))),
        hasRHS(ignoringParenImpCasts(cxxNewExpr()))
    );

    // Vars assigned with malloc (with cast)
    auto mallocAssignMatcher = binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("var"))))),
        hasRHS(ignoringParenImpCasts(
            castExpr(hasSourceExpression(ignoringParenImpCasts(
                allocCallMatcher())))))
    );

    // Match VarDecl matchers on the FunctionDecl (Decl context)
    auto declMatchers = {newInitMatcher, mallocInitMatcher, mallocInitDirect};
    for (const auto& m : declMatchers) {
        auto wrapper = functionDecl(equalsNode(funcDecl),
                                     forEachDescendant(m));
        for (const auto& result : match(wrapper, *funcDecl, ctx)) {
            if (const auto* v = result.getNodeAs<VarDecl>("var"))
                vars.insert(v);
        }
    }

    // Match assignment matchers on the body (Stmt context)
    auto assignMatchers = {newAssignMatcher, mallocAssignMatcher};
    for (const auto& m : assignMatchers) {
        for (const auto& result : match(findAll(m), *funcDecl->getBody(), ctx)) {
            if (const auto* v = result.getNodeAs<VarDecl>("var"))
                vars.insert(v);
        }
    }

    return {vars.begin(), vars.end()};
}

// --- Core dataflow analysis ---

void analyzeFunction(const FunctionDecl* funcDecl,
                     ASTContext& ctx,
                     zerodefect::DiagnosticList& results) {
    if (!funcDecl->hasBody()) return;

    auto trackedVars = collectTrackedVars(funcDecl, ctx);
    if (trackedVars.empty()) return;

    CFG::BuildOptions opts;
    std::unique_ptr<CFG> cfg = CFG::buildCFG(
        funcDecl, funcDecl->getBody(), &ctx, opts);
    if (!cfg) return;

    const unsigned numBlocks = cfg->getNumBlockIDs();
    const unsigned maxIterations = numBlocks * 4;

    // Initial state: all vars None
    VarState initState;
    for (const auto* var : trackedVars)
        initState[var] = AllocState::None;

    std::unordered_map<unsigned, VarState> blockExitState;
    std::set<std::pair<const VarDecl*, unsigned>> reported;

    std::queue<const CFGBlock*> worklist;
    worklist.push(&cfg->getEntry());
    unsigned iterations = 0;

    while (!worklist.empty() && iterations < maxIterations) {
        ++iterations;
        const CFGBlock* block = worklist.front();
        worklist.pop();

        // Merge from predecessors
        VarState entryState = initState;
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
                entryState = mergeVarStates(entryState, found->second);
            }
        }

        if (!hasPreds && block != &cfg->getEntry())
            continue;

        // Walk statements
        VarState currentState = entryState;
        const SourceManager& sm = ctx.getSourceManager();

        for (const CFGElement& elem : *block) {
            auto cfgStmt = elem.getAs<CFGStmt>();
            if (!cfgStmt) continue;
            const Stmt* stmt = cfgStmt->getStmt();
            if (!stmt) continue;

            for (const auto* var : trackedVars) {
                StmtEffect effect = classifyStmt(stmt, var, ctx);

                if (effect == StmtEffect::Allocates) {
                    // Reassignment leak check
                    if (currentState[var] == AllocState::Allocated) {
                        SourceLocation loc = stmt->getBeginLoc();
                        unsigned line = sm.getSpellingLineNumber(loc);
                        if (reported.emplace(var, line).second) {
                            zerodefect::Diagnostic diag;
                            diag.severity = zerodefect::Severity::Warning;
                            diag.file = sm.getFilename(loc).str();
                            diag.line = line;
                            diag.column = sm.getSpellingColumnNumber(loc);
                            diag.rule_id = "memory-leak";
                            diag.message = "Bellek sizintisi: "
                                + var->getNameAsString()
                                + " yeniden atanmadan once eski bellek serbest birakilmamis";
                            results.push_back(diag);
                        }
                    }
                    currentState[var] = AllocState::Allocated;

                } else if (effect == StmtEffect::Frees) {
                    // Double-free check
                    if (currentState[var] == AllocState::Freed) {
                        SourceLocation loc = stmt->getBeginLoc();
                        unsigned line = sm.getSpellingLineNumber(loc);
                        if (reported.emplace(var, line).second) {
                            zerodefect::Diagnostic diag;
                            diag.severity = zerodefect::Severity::Error;
                            diag.file = sm.getFilename(loc).str();
                            diag.line = line;
                            diag.column = sm.getSpellingColumnNumber(loc);
                            diag.rule_id = "memory-leak";
                            diag.message = "Cift serbest birakma: "
                                + var->getNameAsString()
                                + " zaten serbest birakilmis";
                            results.push_back(diag);
                        }
                    }
                    currentState[var] = AllocState::Freed;

                } else if (effect == StmtEffect::Escapes) {
                    currentState[var] = AllocState::Escaped;
                }
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
                if (succ) worklist.push(succ);
            }
        }
    }

    // Exit block leak check
    auto exitIt = blockExitState.find(cfg->getExit().getBlockID());
    if (exitIt == blockExitState.end()) return;

    const SourceManager& sm = ctx.getSourceManager();
    SourceLocation endLoc = funcDecl->getBody()->getEndLoc();

    for (const auto& [var, state] : exitIt->second) {
        if (state == AllocState::Allocated) {
            unsigned line = sm.getSpellingLineNumber(endLoc);
            if (reported.emplace(var, line).second) {
                zerodefect::Diagnostic diag;
                diag.severity = zerodefect::Severity::Warning;
                diag.file = sm.getFilename(endLoc).str();
                diag.line = line;
                diag.column = sm.getSpellingColumnNumber(endLoc);
                diag.rule_id = "memory-leak";
                diag.message = "Bellek sizintisi: "
                    + var->getNameAsString()
                    + " icin ayrilan bellek serbest birakilmamis olabilir";
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
    return "CFG-tabanli bellek sizintisi ve cift serbest birakma analizi";
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
