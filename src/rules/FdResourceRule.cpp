#include "rules/FdResourceRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CoverageReport.h"
#include "engine/DataflowEngine.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ParentMapContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

using Origin = const CallExpr*;

enum class ResourceLife { None, Open, Closed, Escaped };

ResourceLife mergeLife(ResourceLife a, ResourceLife b) {
    if (a == b) return a;
    if (a == ResourceLife::Escaped || b == ResourceLife::Escaped)
        return ResourceLife::Escaped;
    if (a == ResourceLife::Open || b == ResourceLife::Open)
        return ResourceLife::Open;
    return ResourceLife::None;
}

struct Binding {
    std::set<Origin> origins;
    bool opaque = false;

    bool operator==(const Binding& other) const {
        return origins == other.origins && opaque == other.opaque;
    }
    bool operator!=(const Binding& other) const { return !(*this == other); }
};

struct State {
    std::map<Origin, ResourceLife> resources;
    std::map<const VarDecl*, Binding> bindings;

    bool operator==(const State& other) const {
        return resources == other.resources && bindings == other.bindings;
    }
    bool operator!=(const State& other) const { return !(*this == other); }
};

ResourceLife resourceLife(const State& state, Origin origin) {
    auto it = state.resources.find(origin);
    return it == state.resources.end() ? ResourceLife::None : it->second;
}

State mergeStates(const State& a, const State& b) {
    State out;
    std::set<Origin> origins;
    for (const auto& [origin, life] : a.resources) {
        (void)life;
        origins.insert(origin);
    }
    for (const auto& [origin, life] : b.resources) {
        (void)life;
        origins.insert(origin);
    }
    for (Origin origin : origins)
        out.resources[origin] =
            mergeLife(resourceLife(a, origin), resourceLife(b, origin));

    std::set<const VarDecl*> vars;
    for (const auto& [var, binding] : a.bindings) {
        (void)binding;
        vars.insert(var);
    }
    for (const auto& [var, binding] : b.bindings) {
        (void)binding;
        vars.insert(var);
    }
    for (const VarDecl* var : vars) {
        auto ai = a.bindings.find(var);
        auto bi = b.bindings.find(var);
        if (ai == a.bindings.end()) {
            Binding merged = bi->second;
            merged.opaque = true;
            out.bindings.emplace(var, std::move(merged));
        } else if (bi == b.bindings.end()) {
            Binding merged = ai->second;
            merged.opaque = true;
            out.bindings.emplace(var, std::move(merged));
        } else {
            Binding merged = ai->second;
            merged.origins.insert(bi->second.origins.begin(),
                                  bi->second.origins.end());
            merged.opaque = ai->second.opaque || bi->second.opaque;
            out.bindings.emplace(var, std::move(merged));
        }
    }
    return out;
}

llvm::StringRef calleeName(const CallExpr* call) {
    const FunctionDecl* callee = call ? call->getDirectCallee() : nullptr;
    if (!callee) return {};
    const IdentifierInfo* id = callee->getIdentifier();
    if (!id || isa<CXXMethodDecl>(callee)) return {};
    if (callee->getQualifiedNameAsString() != id->getName().str()) return {};
    return id->getName();
}

bool isAcquireName(llvm::StringRef name) {
    return name == "open" || name == "openat" || name == "socket" ||
           name == "dup" || name == "mkstemp";
}

Origin acquisition(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    const auto* call = dyn_cast<CallExpr>(expr);
    return call && isAcquireName(calleeName(call)) ? call : nullptr;
}

const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    const auto* ref = dyn_cast<DeclRefExpr>(expr);
    return ref ? dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
}

bool isTrackableLocal(const VarDecl* var) {
    return var && var->hasLocalStorage() && !isa<ParmVarDecl>(var) &&
           var->getType()->isIntegerType();
}

Binding bindingFor(const Expr* expr, const State& state) {
    const VarDecl* var = asVar(expr);
    if (!var) return Binding{{}, true};
    auto it = state.bindings.find(var);
    return it == state.bindings.end() ? Binding{{}, true} : it->second;
}

void escape(const Binding& binding, State& state) {
    for (Origin origin : binding.origins)
        state.resources[origin] = ResourceLife::Escaped;
}

void release(const Binding& binding, State& state) {
    if (binding.origins.empty()) return;
    if (binding.opaque || binding.origins.size() != 1) {
        // An imprecise integer binding cannot prove which descriptor a
        // release consumed. Suppress rather than manufacture a leak.
        escape(binding, state);
        return;
    }
    state.resources[*binding.origins.begin()] = ResourceLife::Closed;
}

struct FailureEdge {
    const VarDecl* var = nullptr;
    bool trueBranch = false;
};

std::optional<long long> integerConstant(const Expr* expr) {
    if (!expr) return std::nullopt;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* literal = dyn_cast<IntegerLiteral>(expr))
        return literal->getValue().getSExtValue();
    const auto* unary = dyn_cast<UnaryOperator>(expr);
    if (!unary || unary->getOpcode() != UO_Minus) return std::nullopt;
    const auto* literal = dyn_cast<IntegerLiteral>(
        unary->getSubExpr()->IgnoreParenImpCasts());
    if (!literal) return std::nullopt;
    return -static_cast<long long>(literal->getValue().getZExtValue());
}

BinaryOperatorKind swappedComparison(BinaryOperatorKind op) {
    switch (op) {
        case BO_LT: return BO_GT;
        case BO_LE: return BO_GE;
        case BO_GT: return BO_LT;
        case BO_GE: return BO_LE;
        default: return op;
    }
}

std::optional<FailureEdge> failureEdge(const Expr* condition) {
    if (!condition) return std::nullopt;
    condition = condition->IgnoreParenImpCasts();
    if (const auto* unary = dyn_cast<UnaryOperator>(condition)) {
        if (unary->getOpcode() != UO_LNot) return std::nullopt;
        auto nested = failureEdge(unary->getSubExpr());
        if (nested) nested->trueBranch = !nested->trueBranch;
        return nested;
    }

    const auto* comparison = dyn_cast<BinaryOperator>(condition);
    if (!comparison || !comparison->isComparisonOp()) return std::nullopt;

    const VarDecl* var = asVar(comparison->getLHS());
    auto constant = integerConstant(comparison->getRHS());
    BinaryOperatorKind op = comparison->getOpcode();
    if (!var || !constant) {
        var = asVar(comparison->getRHS());
        constant = integerConstant(comparison->getLHS());
        op = swappedComparison(op);
    }
    if (!var || !constant) return std::nullopt;

    if (op == BO_EQ && *constant == -1) return FailureEdge{var, true};
    if (op == BO_NE && *constant == -1) return FailureEdge{var, false};
    if (op == BO_LT && *constant == 0) return FailureEdge{var, true};
    if (op == BO_GE && *constant == 0) return FailureEdge{var, false};
    if (op == BO_LE && *constant == -1) return FailureEdge{var, true};
    if (op == BO_GT && *constant == -1) return FailureEdge{var, false};
    return std::nullopt;
}

struct ResourceInventory : RecursiveASTVisitor<ResourceInventory> {
    std::vector<Origin> origins;
    std::map<Origin, std::string> names;

    bool VisitCallExpr(CallExpr* call) {
        if (isAcquireName(calleeName(call))) origins.push_back(call);
        return true;
    }

    bool VisitVarDecl(VarDecl* var) {
        if (!var->hasInit()) return true;
        if (Origin origin = acquisition(var->getInit()))
            names.emplace(origin, var->getNameAsString());
        return true;
    }

    bool VisitBinaryOperator(BinaryOperator* assignment) {
        if (assignment->getOpcode() != BO_Assign) return true;
        const VarDecl* var = asVar(assignment->getLHS());
        if (var)
            if (Origin origin = acquisition(assignment->getRHS()))
                names.emplace(origin, var->getNameAsString());
        return true;
    }

    bool TraverseLambdaExpr(LambdaExpr*) { return true; }
};

class FdAnalysis {
public:
    using State = ::State;

    FdAnalysis(std::vector<Origin> origins) : origins_(std::move(origins)) {}

    State initialState() const { return {}; }

    unsigned latticeHeight() const {
        return static_cast<unsigned>(origins_.size()) * 4 + 16;
    }

    State merge(const State& a, const State& b) const {
        return mergeStates(a, b);
    }

    void widen(State&) const {}

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext&) const {
        State out = in;

        if (const auto* declaration = dyn_cast<DeclStmt>(stmt)) {
            for (const Decl* decl : declaration->decls()) {
                const auto* var = dyn_cast<VarDecl>(decl);
                if (!isTrackableLocal(var) || !var->hasInit()) continue;
                if (Origin origin = acquisition(var->getInit())) {
                    out.resources[origin] = ResourceLife::Open;
                    out.bindings[var] = Binding{{origin}, false};
                } else if (const VarDecl* source = asVar(var->getInit())) {
                    auto it = out.bindings.find(source);
                    out.bindings[var] = it == out.bindings.end()
                                            ? Binding{{}, true}
                                            : it->second;
                }
            }
            return out;
        }

        if (const auto* assignment = dyn_cast<BinaryOperator>(stmt)) {
            if (assignment->getOpcode() != BO_Assign) return out;
            const VarDecl* target = asVar(assignment->getLHS());
            if (isTrackableLocal(target)) {
                if (Origin origin = acquisition(assignment->getRHS())) {
                    out.resources[origin] = ResourceLife::Open;
                    out.bindings[target] = Binding{{origin}, false};
                } else {
                    out.bindings[target] = bindingFor(
                        assignment->getRHS(), out);
                }
            } else if (target && !target->hasLocalStorage()) {
                escape(bindingFor(assignment->getRHS(), out), out);
            } else if (!target) {
                escape(bindingFor(assignment->getRHS(), out), out);
            }
            return out;
        }

        if (const auto* ret = dyn_cast<ReturnStmt>(stmt)) {
            if (Origin origin = acquisition(ret->getRetValue())) {
                out.resources[origin] = ResourceLife::Escaped;
            } else {
                escape(bindingFor(ret->getRetValue(), out), out);
            }
            return out;
        }

        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            const llvm::StringRef name = calleeName(call);
            if (name == "close" && call->getNumArgs() >= 1) {
                if (Origin origin = acquisition(call->getArg(0))) {
                    out.resources[origin] = ResourceLife::Closed;
                } else {
                    release(bindingFor(call->getArg(0), out), out);
                }
            } else if (isAcquireName(name)) {
                out.resources[call] = ResourceLife::Open;
            }
            // shutdown intentionally has no ownership effect: POSIX still
            // requires close() to release the descriptor itself.
        }
        return out;
    }

    void refineOnEdge(const Stmt* condition, bool isTrueBranch,
                      State& state, ASTContext&) const {
        const auto* expr = dyn_cast_or_null<Expr>(condition);
        auto failure = failureEdge(expr);
        if (!failure || failure->trueBranch != isTrueBranch) return;
        auto binding = state.bindings.find(failure->var);
        if (binding == state.bindings.end()) return;
        for (Origin origin : binding->second.origins)
            state.resources[origin] = ResourceLife::None;
    }

private:
    std::vector<Origin> origins_;
};

void reportLeaks(const FunctionDecl* function,
                 const ResourceInventory& inventory,
                 const State& exitState,
                 ASTContext& context,
                 codeskeptic::DiagnosticList& results) {
    const SourceManager& sm = context.getSourceManager();
    for (Origin origin : inventory.origins) {
        if (resourceLife(exitState, origin) != ResourceLife::Open) continue;
        const auto name = inventory.names.find(origin);
        const bool discarded = name == inventory.names.end();
        SourceLocation loc = discarded ? origin->getBeginLoc()
                                       : function->getBody()->getEndLoc();
        loc = sm.getExpansionLoc(loc);

        codeskeptic::Diagnostic diag;
        diag.severity = codeskeptic::Severity::Warning;
        diag.file = sm.getFilename(loc).str();
        diag.line = sm.getSpellingLineNumber(loc);
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "resource-leak";
        diag.function = function->getQualifiedNameAsString();
        diag.message = discarded
            ? codeskeptic::msg(codeskeptic::MsgId::OwnedResultDiscarded)
            : codeskeptic::msg(
                  codeskeptic::MsgId::ResourceLeakEndOfFunction,
                  name->second);
        results.push_back(std::move(diag));
    }
}

void analyzeFunction(const FunctionDecl* function,
                     ASTContext& context,
                     codeskeptic::DiagnosticList& results) {
    ResourceInventory inventory;
    inventory.TraverseStmt(const_cast<Stmt*>(function->getBody()));
    if (inventory.origins.empty()) return;

    FdAnalysis analysis(inventory.origins);
    auto dataflow = codeskeptic::runDataflow(function, context, analysis);
    if (!dataflow.converged)
        codeskeptic::CoverageReport::instance().recordDataflowFailure(
            function->getQualifiedNameAsString(), dataflow.failure);

    auto exit = dataflow.blockExitStates.find(dataflow.exitBlockID);
    if (exit == dataflow.blockExitStates.end()) return;
    reportLeaks(function, inventory, exit->second, context, results);
}

class FindFdResourceCallback : public MatchFinder::MatchCallback {
public:
    explicit FindFdResourceCallback(codeskeptic::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* function =
            result.Nodes.getNodeAs<FunctionDecl>("function");
        if (!function || !function->hasBody()) return;
        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(function->getLocation())) return;
        if (!codeskeptic::functionFilterAllows(*function)) return;
        if (!codeskeptic::lineFilterAllows(*function, sm)) return;
        analyzeFunction(function, *result.Context, results_);
    }

private:
    codeskeptic::DiagnosticList& results_;
};

} // namespace

namespace codeskeptic {

std::string FdResourceRule::id() const {
    return "resource-leak";
}

std::string FdResourceRule::description() const {
    return "CFG-based POSIX integer-resource lifecycle analysis";
}

void FdResourceRule::check(clang::ASTContext& context,
                           DiagnosticList& results) {
    MatchFinder finder;
    FindFdResourceCallback callback(results);
    finder.addMatcher(
        functionDecl(isDefinition(), hasBody(anything())).bind("function"),
        &callback);
    finder.matchAST(context);
}

} // namespace codeskeptic
