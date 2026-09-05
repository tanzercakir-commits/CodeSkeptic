#include "rules/FdResourceRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CoverageReport.h"
#include "engine/DataflowEngine.h"
#include "engine/FunctionSummary.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Attr.h>
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

// A precise return transfers ownership only on that exit path. An opaque
// escape is different: it prevents a definite local-ownership claim. Keep
// them distinct so returning on one path cannot hide a leak on another.
enum class ResourceLife { None, Open, Closed, Returned, Escaped };

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
    std::set<const VarDecl*> definitelyNegative;
    std::map<const VarDecl*, const VarDecl*> valueCopies;
    std::map<Origin, std::set<const VarDecl*>> negativeWitnesses;

    bool operator==(const State& other) const {
        return resources == other.resources && bindings == other.bindings &&
               definitelyNegative == other.definitelyNegative &&
               valueCopies == other.valueCopies &&
               negativeWitnesses == other.negativeWitnesses;
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
            for (Origin origin : merged.origins)
                if (resourceLife(a, origin) != ResourceLife::None)
                    merged.opaque = true;
            out.bindings.emplace(var, std::move(merged));
        } else if (bi == b.bindings.end()) {
            Binding merged = ai->second;
            for (Origin origin : merged.origins)
                if (resourceLife(b, origin) != ResourceLife::None)
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

    for (const VarDecl* var : a.definitelyNegative)
        if (b.definitelyNegative.count(var) != 0)
            out.definitelyNegative.insert(var);

    for (const auto& [target, source] : a.valueCopies) {
        auto it = b.valueCopies.find(target);
        if (it != b.valueCopies.end() && it->second == source)
            out.valueCopies.emplace(target, source);
    }

    for (Origin origin : origins) {
        const ResourceLife aLife = resourceLife(a, origin);
        const ResourceLife bLife = resourceLife(b, origin);
        const auto ai = a.negativeWitnesses.find(origin);
        const auto bi = b.negativeWitnesses.find(origin);
        if (aLife == ResourceLife::None) {
            if (bLife != ResourceLife::None &&
                bi != b.negativeWitnesses.end())
                out.negativeWitnesses.emplace(origin, bi->second);
            continue;
        }
        if (bLife == ResourceLife::None) {
            if (ai != a.negativeWitnesses.end())
                out.negativeWitnesses.emplace(origin, ai->second);
            continue;
        }
        if (ai == a.negativeWitnesses.end() ||
            bi == b.negativeWitnesses.end())
            continue;
        std::set<const VarDecl*> common;
        for (const VarDecl* var : ai->second)
            if (bi->second.count(var) != 0) common.insert(var);
        out.negativeWitnesses.emplace(origin, std::move(common));
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

bool isFdIntegerType(QualType type) {
    return !type.isNull() && type->isIntegerType() &&
           !type->isBooleanType();
}

bool isInt(QualType type) {
    return !type.isNull() &&
           type.getCanonicalType()->isSpecificBuiltinType(BuiltinType::Int);
}

bool isSockaddrPointer(QualType type) {
    if (!type->isPointerType()) return false;
    const QualType pointee = type->getPointeeType();
    if (pointee.isConstQualified() || pointee.isVolatileQualified()) return false;
    const auto* record = pointee->getAs<RecordType>();
    return record && record->getDecl()->getQualifiedNameAsString() == "sockaddr";
}

bool isAcceptAddress(QualType type) {
    if (isSockaddrPointer(type)) return true;
    // GNU C libc exposes __SOCKADDR_ARG as a transparent union; C++ exposes
    // sockaddr*. Check the formal type so passing 0/nullptr stays recognized.
    const auto* recordType = type->getAs<RecordType>();
    const auto* record = recordType ? recordType->getDecl()->getDefinition() : nullptr;
    if (!record || !record->isUnion() || !record->hasAttr<TransparentUnionAttr>()) return false;
    for (const auto* field : record->fields())
        if (isSockaddrPointer(field->getType())) return true;
    return false;
}

bool isAcceptCall(const CallExpr* call) {
    const auto name = calleeName(call);
    if (name != "accept" && name != "accept4") return false;
    const auto* callee = call->getDirectCallee();
    const unsigned count = name == "accept" ? 3 : 4;
    if (callee->hasBody() || callee->isVariadic() ||
        callee->getNumParams() != count || call->getNumArgs() != count ||
        !isInt(callee->getReturnType()) || !isInt(callee->getParamDecl(0)->getType()) ||
        (count == 4 && !isInt(callee->getParamDecl(3)->getType())) ||
        !isAcceptAddress(callee->getParamDecl(1)->getType())) return false;
    const QualType length = callee->getParamDecl(2)->getType();
    if (!length->isPointerType()) return false;
    const QualType size = length->getPointeeType();
    // Linux libc's socklen_t is unsigned int, not any unsigned pointee.
    return !size.isConstQualified() && !size.isVolatileQualified() &&
           size.getCanonicalType()->isSpecificBuiltinType(BuiltinType::UInt);
}

bool isAcquisitionCall(const CallExpr* call) {
    if (!call || !isFdIntegerType(call->getType())) return false;
    if (isAcquireName(calleeName(call)) || isAcceptCall(call)) return true;
    const auto* summary =
        codeskeptic::SummaryRegistry::instance().lookup(call);
    return summary &&
           summary->returnOwnership ==
               codeskeptic::SummaryRegistry::ReturnOwnership::Owned;
}

Origin acquisition(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    const auto* call = dyn_cast<CallExpr>(expr);
    return isAcquisitionCall(call) ? call : nullptr;
}

const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    const auto* ref = dyn_cast<DeclRefExpr>(expr);
    return ref ? dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
}

const VarDecl* valueVariable(const Expr* expr) {
    if (const auto* var = asVar(expr)) return var;
    if (!expr) return nullptr;
    const auto* assignment = dyn_cast<BinaryOperator>(expr->IgnoreParenImpCasts());
    // A simple int assignment yields its stored value. Do not treat a
    // compound assignment, arithmetic result or narrowing storage as the FD.
    if (!assignment || assignment->getOpcode() != BO_Assign ||
        !isInt(assignment->getType())) return nullptr;
    return asVar(assignment->getLHS());
}

bool isTrackableLocal(const VarDecl* var) {
    return var && (var->hasLocalStorage() || isa<ParmVarDecl>(var)) &&
           var->getType()->isIntegerType();
}

void forgetValue(const VarDecl* var, State& state) {
    if (!var) return;
    state.definitelyNegative.erase(var);
    state.valueCopies.erase(var);
    for (auto it = state.valueCopies.begin(); it != state.valueCopies.end();) {
        if (it->second == var)
            it = state.valueCopies.erase(it);
        else
            ++it;
    }
    for (auto& [origin, witnesses] : state.negativeWitnesses) {
        (void)origin;
        witnesses.erase(var);
    }
}

void rememberValueCopy(const VarDecl* target, const VarDecl* source,
                       State& state) {
    const bool negative = source &&
        state.definitelyNegative.count(source) != 0;
    forgetValue(target, state);
    if (source && source != target)
        state.valueCopies[target] = source;
    if (negative) state.definitelyNegative.insert(target);
}

void markNegativeEquivalents(const VarDecl* var, State& state) {
    if (!var) return;
    std::set<const VarDecl*> equivalent{var};
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& [target, source] : state.valueCopies) {
            if (equivalent.count(target) == 0 &&
                equivalent.count(source) == 0)
                continue;
            changed |= equivalent.insert(target).second;
            changed |= equivalent.insert(source).second;
        }
    }
    state.definitelyNegative.insert(equivalent.begin(), equivalent.end());
}

void rememberNegativeWitnesses(Origin origin, const VarDecl* target,
                               State& state) {
    std::set<const VarDecl*> witnesses = state.definitelyNegative;
    witnesses.erase(target);
    auto [it, inserted] =
        state.negativeWitnesses.emplace(origin, witnesses);
    if (inserted) return;
    std::set<const VarDecl*> common;
    for (const VarDecl* var : it->second)
        if (witnesses.count(var) != 0) common.insert(var);
    it->second = std::move(common);
}

Binding bindingFor(const Expr* expr, const State& state) {
    const VarDecl* var = valueVariable(expr);
    if (!var) return Binding{{}, true};
    auto it = state.bindings.find(var);
    return it == state.bindings.end() ? Binding{{}, true} : it->second;
}

void escape(const Binding& binding, State& state) {
    for (Origin origin : binding.origins)
        state.resources[origin] = ResourceLife::Escaped;
}

void returnOwnership(const Binding& binding, State& state) {
    if (binding.opaque || binding.origins.size() != 1) {
        escape(binding, state);
        return;
    }
    const Origin origin = *binding.origins.begin();
    // Returning the -1 failure sentinel does not transfer a resource.
    if (resourceLife(state, origin) != ResourceLife::None)
        state.resources[origin] = ResourceLife::Returned;
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

unsigned fdCallParamOffset(const CallExpr* call) {
    if (!isa_and_nonnull<CXXOperatorCallExpr>(call)) return 0;
    const auto* method =
        dyn_cast_or_null<CXXMethodDecl>(call->getDirectCallee());
    return method && !method->isStatic() ? 1u : 0u;
}

void applyOwnershipToExpr(
        const Expr* expr,
        codeskeptic::SummaryRegistry::ParamOwnership ownership,
        State& state) {
    using ParamOwnership =
        codeskeptic::SummaryRegistry::ParamOwnership;
    if (ownership == ParamOwnership::Borrowed ||
        ownership == ParamOwnership::Unknown)
        return;
    if (Origin origin = acquisition(expr)) {
        state.resources[origin] =
            ownership == ParamOwnership::Consumed
                ? ResourceLife::Closed : ResourceLife::Escaped;
        return;
    }
    const Binding binding = bindingFor(expr, state);
    if (ownership == ParamOwnership::Consumed)
        release(binding, state);
    else
        escape(binding, state);
}

void applyModeledCallEffects(const CallExpr* call, State& state) {
    const llvm::StringRef direct = calleeName(call);
    if (isAcquireName(direct) || isAcceptCall(call) || direct == "close" ||
        direct == "shutdown")
        return;
    const auto* summary =
        codeskeptic::SummaryRegistry::instance().lookup(call);
    if (!summary) return;
    const unsigned offset = fdCallParamOffset(call);
    for (unsigned argIndex = offset;
         argIndex < call->getNumArgs(); ++argIndex) {
        const Expr* arg = call->getArg(argIndex);
        if (!isFdIntegerType(arg->getType())) continue;
        applyOwnershipToExpr(
            arg, summary->paramOwnership(argIndex - offset), state);
    }
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

    const VarDecl* var = valueVariable(comparison->getLHS());
    auto constant = integerConstant(comparison->getRHS());
    BinaryOperatorKind op = comparison->getOpcode();
    if (!var || !constant) {
        var = valueVariable(comparison->getRHS());
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

struct EqualityEdge {
    const VarDecl* first = nullptr;
    const VarDecl* second = nullptr;
    bool trueBranch = false;
};

std::optional<EqualityEdge> equalityEdge(const Expr* condition) {
    if (!condition) return std::nullopt;
    condition = condition->IgnoreParenImpCasts();
    if (const auto* unary = dyn_cast<UnaryOperator>(condition)) {
        if (unary->getOpcode() != UO_LNot) return std::nullopt;
        auto nested = equalityEdge(unary->getSubExpr());
        if (nested) nested->trueBranch = !nested->trueBranch;
        return nested;
    }

    const auto* comparison = dyn_cast<BinaryOperator>(condition);
    if (!comparison) return std::nullopt;
    const BinaryOperatorKind op = comparison->getOpcode();
    if (op != BO_EQ && op != BO_NE) return std::nullopt;
    const VarDecl* first = asVar(comparison->getLHS());
    const VarDecl* second = asVar(comparison->getRHS());
    if (!first || !second) return std::nullopt;
    return EqualityEdge{first, second, op == BO_EQ};
}

void discardImpossibleEquality(const VarDecl* resourceVar,
                               const VarDecl* negativeVar,
                               State& state) {
    auto binding = state.bindings.find(resourceVar);
    if (binding == state.bindings.end()) return;
    for (Origin origin : binding->second.origins) {
        const auto witnesses = state.negativeWitnesses.find(origin);
        if (state.definitelyNegative.count(negativeVar) != 0 ||
            (witnesses != state.negativeWitnesses.end() &&
             witnesses->second.count(negativeVar) != 0))
            state.resources[origin] = ResourceLife::None;
    }
}

struct ResourceInventory : RecursiveASTVisitor<ResourceInventory> {
    std::vector<Origin> origins;
    std::map<Origin, std::string> names;
    unsigned integerVariables = 0;

    bool VisitCallExpr(CallExpr* call) {
        if (isAcquisitionCall(call)) origins.push_back(call);
        return true;
    }

    bool VisitVarDecl(VarDecl* var) {
        if (isFdIntegerType(var->getType())) ++integerVariables;
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

    FdAnalysis(std::vector<Origin> origins, unsigned integerVariables)
        : origins_(std::move(origins)),
          integerVariables_(integerVariables) {}

    State initialState() const { return {}; }

    unsigned latticeHeight() const {
        return static_cast<unsigned>(origins_.size()) * 8 +
               integerVariables_ * 4 + 32;
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
                const Expr* init = var->getInit();
                if (Origin origin = acquisition(init)) {
                    rememberNegativeWitnesses(origin, var, out);
                    forgetValue(var, out);
                    out.resources[origin] = ResourceLife::Open;
                    out.bindings[var] = Binding{{origin}, false};
                } else {
                    const Binding binding = bindingFor(init, out);
                    const VarDecl* source = asVar(init);
                    rememberValueCopy(var, source, out);
                    if (const auto constant = integerConstant(init);
                        constant && *constant < 0)
                        out.definitelyNegative.insert(var);
                    out.bindings[var] = binding;
                }
            }
            return out;
        }

        if (const auto* assignment = dyn_cast<BinaryOperator>(stmt)) {
            if (assignment->getOpcode() != BO_Assign) return out;
            const Expr* rhs = assignment->getRHS();
            const VarDecl* target = asVar(assignment->getLHS());
            if (isTrackableLocal(target)) {
                if (Origin origin = acquisition(rhs)) {
                    rememberNegativeWitnesses(origin, target, out);
                    forgetValue(target, out);
                    out.resources[origin] = ResourceLife::Open;
                    out.bindings[target] = Binding{{origin}, false};
                } else {
                    const Binding binding = bindingFor(rhs, out);
                    const VarDecl* source = asVar(rhs);
                    rememberValueCopy(target, source, out);
                    if (const auto constant = integerConstant(rhs);
                        constant && *constant < 0)
                        out.definitelyNegative.insert(target);
                    out.bindings[target] = binding;
                }
            } else if (Origin origin = acquisition(rhs)) {
                out.resources[origin] = ResourceLife::Escaped;
            } else {
                escape(bindingFor(rhs, out), out);
            }
            return out;
        }

        if (const auto* ret = dyn_cast<ReturnStmt>(stmt)) {
            if (Origin origin = acquisition(ret->getRetValue())) {
                out.resources[origin] = ResourceLife::Returned;
            } else {
                returnOwnership(bindingFor(ret->getRetValue(), out), out);
            }
            return out;
        }

        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            const llvm::StringRef name = calleeName(call);
            if (name == "close" && call->getNumArgs() >= 1) {
                applyOwnershipToExpr(
                    call->getArg(0),
                    codeskeptic::SummaryRegistry::ParamOwnership::Consumed,
                    out);
            } else {
                applyModeledCallEffects(call, out);
                if (isAcquisitionCall(call))
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
        if (auto failure = failureEdge(expr);
            failure && failure->trueBranch == isTrueBranch) {
            markNegativeEquivalents(failure->var, state);
            auto binding = state.bindings.find(failure->var);
            if (binding != state.bindings.end())
                for (Origin origin : binding->second.origins)
                    state.resources[origin] = ResourceLife::None;
        }

        if (auto equality = equalityEdge(expr);
            equality && equality->trueBranch == isTrueBranch) {
            discardImpossibleEquality(
                equality->first, equality->second, state);
            discardImpossibleEquality(
                equality->second, equality->first, state);
        }
    }

private:
    std::vector<Origin> origins_;
    unsigned integerVariables_;
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

    FdAnalysis analysis(
        inventory.origins,
        inventory.integerVariables + function->getNumParams());
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
