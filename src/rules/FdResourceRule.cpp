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
#include <functional>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

struct Origin {
    const CallExpr* call = nullptr;
    unsigned output = 0; // 0: returned descriptor; 1/2: pipe read/write output.
    Origin(const CallExpr* value = nullptr, unsigned slot = 0) : call(value), output(slot) {}
    explicit operator bool() const { return call != nullptr; }
    const CallExpr* operator->() const { return call; }
    bool operator==(const Origin& other) const { return call == other.call && output == other.output; }
    bool operator<(const Origin& other) const {
        return call == other.call ? output < other.output : std::less<const CallExpr*>{}(call, other.call);
    }
};

struct Slot {
    const VarDecl* variable = nullptr;
    long long index = -1; // -1 is the scalar variable itself.
    Slot(const VarDecl* var = nullptr, long long element = -1) : variable(var), index(element) {}
    explicit operator bool() const { return variable != nullptr; }
    bool operator==(const Slot& other) const { return variable == other.variable && index == other.index; }
    bool operator<(const Slot& other) const {
        return variable == other.variable ? index < other.index :
            std::less<const VarDecl*>{}(variable, other.variable);
    }
};

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

struct PipeStatus {
    const CallExpr* call = nullptr;
    long long failure = -1;
    long long success = 0;
    explicit operator bool() const { return call != nullptr; }
    bool operator==(const PipeStatus& other) const {
        return call == other.call && failure == other.failure && success == other.success;
    }
};

struct State {
    std::map<Origin, ResourceLife> resources;
    std::map<Slot, Binding> bindings;
    std::map<const VarDecl*, Slot> arrayPointers;
    std::map<const VarDecl*, PipeStatus> pipeStatuses;
    std::map<Origin, Binding> pipePrevious;
    std::set<const VarDecl*> definitelyNegative;
    std::map<const VarDecl*, const VarDecl*> valueCopies;
    std::map<Origin, std::set<const VarDecl*>> negativeWitnesses;

    bool operator==(const State& other) const {
        return resources == other.resources && bindings == other.bindings &&
               definitelyNegative == other.definitelyNegative &&
               valueCopies == other.valueCopies &&
               negativeWitnesses == other.negativeWitnesses &&
               arrayPointers == other.arrayPointers && pipeStatuses == other.pipeStatuses &&
               pipePrevious == other.pipePrevious;
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

    std::set<Slot> vars;
    for (const auto& [var, binding] : a.bindings) {
        (void)binding;
        vars.insert(var);
    }
    for (const auto& [var, binding] : b.bindings) {
        (void)binding;
        vars.insert(var);
    }
    for (Slot var : vars) {
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

    for (const auto& [var, slot] : a.arrayPointers) {
        auto it = b.arrayPointers.find(var);
        if (it != b.arrayPointers.end() && it->second == slot) out.arrayPointers.emplace(var, slot);
    }
    for (const auto& [var, call] : a.pipeStatuses) {
        auto it = b.pipeStatuses.find(var);
        if (it != b.pipeStatuses.end() && it->second == call) out.pipeStatuses.emplace(var, call);
    }
    out.pipePrevious = a.pipePrevious;
    for (const auto& [origin, previous] : b.pipePrevious) {
        auto [it, inserted] = out.pipePrevious.emplace(origin, previous);
        if (!inserted) {
            it->second.origins.insert(previous.origins.begin(), previous.origins.end());
            it->second.opaque |= previous.opaque;
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

bool isPipeCall(const CallExpr* call) {
    const auto name = calleeName(call);
    if (name != "pipe" && name != "pipe2") return false;
    const auto* callee = call->getDirectCallee();
    const unsigned count = name == "pipe" ? 1 : 2;
    if (callee->hasBody() || callee->isVariadic() || callee->getNumParams() != count ||
        call->getNumArgs() != count || !isInt(callee->getReturnType()) ||
        (count == 2 && !isInt(callee->getParamDecl(1)->getType()))) return false;
    const auto target = callee->getParamDecl(0)->getType();
    return target->isPointerType() && isInt(target->getPointeeType()) &&
        !target->getPointeeType().isConstQualified() && !target->getPointeeType().isVolatileQualified();
}

bool isAcquisitionCall(const CallExpr* call) {
    if (!call || !isFdIntegerType(call->getType())) return false;
    if (isPipeCall(call)) return false; // Native pipe returns status, never an owned FD.
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

std::optional<long long> slotOffset(const Expr* expr) {
    if (!expr) return std::nullopt;
    expr = expr->IgnoreParenImpCasts();
    bool negative = false;
    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() != UO_Minus) return std::nullopt;
        negative = true;
        expr = unary->getSubExpr()->IgnoreParenImpCasts();
    }
    const auto* literal = dyn_cast<IntegerLiteral>(expr);
    if (!literal || literal->getValue().getActiveBits() > 63) return std::nullopt;
    const auto value = static_cast<long long>(literal->getValue().getZExtValue());
    return negative ? -value : value;
}

const ConstantArrayType* localFdArray(const VarDecl* var) {
    if (!var || !var->hasLocalStorage()) return nullptr;
    const auto* array = dyn_cast<ConstantArrayType>(var->getType().getCanonicalType().getTypePtr());
    return array && isInt(array->getElementType()) && !array->getElementType().isConstQualified() &&
        !array->getElementType().isVolatileQualified() ? array : nullptr;
}

Slot pointerSlot(const Expr* expr, const State& state, unsigned depth = 0) {
    if (!expr || depth >= 32) return {};
    expr = expr->IgnoreParenImpCasts();
    if (const auto* var = asVar(expr)) {
        if (localFdArray(var)) return {var, 0};
        const auto found = state.arrayPointers.find(var);
        return found == state.arrayPointers.end() ? Slot{} : found->second;
    }
    const Expr* base = nullptr;
    const Expr* offset = nullptr;
    if (const auto* address = dyn_cast<UnaryOperator>(expr);
        address && address->getOpcode() == UO_AddrOf) {
        if (const auto* var = asVar(address->getSubExpr());
            var && var->hasLocalStorage() && isInt(var->getType())) return {var};
        const auto* subscript = dyn_cast<ArraySubscriptExpr>(address->getSubExpr()->IgnoreParenImpCasts());
        if (subscript) { base = subscript->getBase(); offset = subscript->getIdx(); }
    } else if (const auto* add = dyn_cast<BinaryOperator>(expr); add && add->getOpcode() == BO_Add) {
        base = add->getLHS(); offset = add->getRHS();
        if (offset->getType()->isPointerType()) std::swap(base, offset);
    }
    auto amount = slotOffset(offset);
    Slot slot = pointerSlot(base, state, depth + 1);
    if (!slot || !amount || (*amount > 0 && slot.index > std::numeric_limits<long long>::max() - *amount)) return {};
    slot.index += *amount;
    return slot.index >= 0 ? slot : Slot{};
}

Slot valueSlot(const Expr* expr, const State& state) {
    if (const auto* var = valueVariable(expr)) return {var};
    if (!expr) return {};
    expr = expr->IgnoreParenImpCasts();
    if (const auto* assignment = dyn_cast<BinaryOperator>(expr);
        assignment && assignment->getOpcode() == BO_Assign && isInt(assignment->getType()))
        expr = assignment->getLHS()->IgnoreParenImpCasts();
    if (const auto* dereference = dyn_cast<UnaryOperator>(expr);
        dereference && dereference->getOpcode() == UO_Deref) return pointerSlot(dereference->getSubExpr(), state);
    const auto* subscript = dyn_cast<ArraySubscriptExpr>(expr);
    if (!subscript) return {};
    Slot slot = pointerSlot(subscript->getBase(), state);
    const auto offset = slotOffset(subscript->getIdx());
    if (!slot || !offset || (*offset > 0 && slot.index > std::numeric_limits<long long>::max() - *offset)) return {};
    slot.index += *offset;
    const auto* array = localFdArray(slot.variable);
    if (slot.index < 0 || !array || array->getSize().getLimitedValue() <= static_cast<unsigned long long>(slot.index)) return {};
    return slot;
}

std::optional<long long> integerConstant(const Expr* expr);
BinaryOperatorKind swappedComparison(BinaryOperatorKind op);

bool compareStatus(long long value, long long constant, BinaryOperatorKind op, bool unsignedCompare) {
    auto compare = [op](auto a, auto b) {
        switch (op) {
            case BO_EQ: return a == b;
            case BO_NE: return a != b;
            case BO_LT: return a < b;
            case BO_LE: return a <= b;
            case BO_GT: return a > b;
            case BO_GE: return a >= b;
            default: return false;
        }
    };
    return unsignedCompare ? compare(static_cast<unsigned long long>(value), static_cast<unsigned long long>(constant)) :
        compare(value, constant);
}

std::optional<long long> pipeConstant(const Expr* expr, ASTContext& context) {
    Expr::EvalResult result;
    if (!expr || !expr->getType()->isIntegerType() || !expr->EvaluateAsInt(result, context)) return std::nullopt;
    const auto& value = result.Val.getInt();
    if (value.getBitWidth() > 64) return std::nullopt;
    return value.isUnsigned() ? value.zextOrTrunc(64).getSExtValue() : value.sextOrTrunc(64).getSExtValue();
}

PipeStatus pipeStatus(const Expr* expr, const State& state, unsigned depth = 0) {
    if (!expr || depth >= 32) return {};
    expr = expr->IgnoreParens();
    if (const auto* cast = dyn_cast<CastExpr>(expr)) {
        auto status = pipeStatus(cast->getSubExpr(), state, depth + 1);
        if (!status || !cast->getType()->isIntegerType()) return {};
        if (cast->getType()->isBooleanType()) {
            status.failure = status.failure != 0;
            status.success = status.success != 0;
        } else {
            const unsigned width = status.call->getDirectCallee()->getASTContext().getIntWidth(cast->getType());
            if (width > 64) return {};
            auto convert = [&](long long input) {
                const auto bits = llvm::APInt(64, static_cast<unsigned long long>(input)).trunc(width);
                return cast->getType()->isUnsignedIntegerType() ? bits.zextOrTrunc(64).getSExtValue() :
                    bits.sextOrTrunc(64).getSExtValue();
            };
            status.failure = convert(status.failure);
            status.success = convert(status.success);
        }
        return status;
    }
    if (const auto* call = dyn_cast<CallExpr>(expr); isPipeCall(call)) return {call, -1, 0};
    if (const auto* unary = dyn_cast<UnaryOperator>(expr); unary && unary->getOpcode() == UO_LNot) {
        auto status = pipeStatus(unary->getSubExpr(), state, depth + 1);
        status.failure = !status.failure;
        status.success = !status.success;
        return status;
    }
    if (const auto* comparison = dyn_cast<BinaryOperator>(expr); comparison && comparison->isComparisonOp()) {
        auto status = pipeStatus(comparison->getLHS(), state, depth + 1);
        const Expr* constantExpr = comparison->getRHS();
        auto op = comparison->getOpcode();
        if (!status) {
            status = pipeStatus(comparison->getRHS(), state, depth + 1);
            constantExpr = comparison->getLHS();
            op = swappedComparison(op);
        }
        if (!status) return {};
        const auto constant = pipeConstant(constantExpr, status.call->getDirectCallee()->getASTContext());
        if (!constant) return {};
        const bool unsignedCompare = comparison->getLHS()->getType()->isUnsignedIntegerType();
        status.failure = compareStatus(status.failure, *constant, op, unsignedCompare);
        status.success = compareStatus(status.success, *constant, op, unsignedCompare);
        return status;
    }
    const auto found = state.pipeStatuses.find(valueVariable(expr));
    return found == state.pipeStatuses.end() ? PipeStatus{} : found->second;
}

bool isTrackableLocal(const VarDecl* var) {
    return var && (var->hasLocalStorage() || isa<ParmVarDecl>(var)) &&
           var->getType()->isIntegerType();
}

void forgetValue(const VarDecl* var, State& state) {
    if (!var) return;
    state.pipeStatuses.erase(var);
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
    const Slot var = valueSlot(expr, state);
    if (!var) return Binding{{}, true};
    auto it = state.bindings.find(var);
    return it == state.bindings.end() ? Binding{{}, true} : it->second;
}

void acquirePipe(const CallExpr* call, State& state) {
    Slot target = pointerSlot(call->getArg(0), state);
    const auto* array = localFdArray(target.variable);
    const bool local = target && array && target.index >= 0 &&
        array->getSize().getLimitedValue() > static_cast<unsigned long long>(target.index) + 1;
    for (unsigned end = 0; end != 2; ++end) {
        Origin origin{call, end + 1};
        state.resources[origin] = local ? ResourceLife::Open : ResourceLife::Escaped;
        if (!local) continue; // Output already belongs to caller/unknown storage.
        const Slot cell{target.variable, target.index + end};
        const auto old = state.bindings.find(cell);
        state.pipePrevious[origin] = old == state.bindings.end() ? Binding{{}, true} : old->second;
        state.bindings[cell] = Binding{{origin}, false};
    }
}

void pipeFailed(const CallExpr* call, State& state) {
    for (unsigned end = 1; end != 3; ++end) {
        const Origin origin{call, end};
        state.resources[origin] = ResourceLife::None;
        const auto before = state.pipePrevious.find(origin);
        for (auto& [slot, binding] : state.bindings) {
            (void)slot;
            if (!binding.origins.erase(origin)) continue;
            if (before == state.pipePrevious.end()) { binding.opaque = true; continue; }
            binding.origins.insert(before->second.origins.begin(), before->second.origins.end());
            binding.opaque |= before->second.opaque;
        }
    }
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
    if (isAcquireName(direct) || isAcceptCall(call) || isPipeCall(call) || direct == "close" ||
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

std::pair<const CallExpr*, bool> pipeFailureEdge(const Expr* condition, const State& state) {
    const auto status = pipeStatus(condition, state);
    const bool failed = status.failure != 0, success = status.success != 0;
    return status && failed != success ? std::make_pair(status.call, failed) : std::make_pair(nullptr, false);
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
    explicit ResourceInventory(ASTContext& ctx) : context(ctx) {}
    ASTContext& context;
    std::vector<Origin> origins;
    std::map<Origin, std::string> names;
    std::set<const Stmt*> returnedValues;
    unsigned integerVariables = 0;

    bool carriesDescriptor(QualType type) const {
        if (!isFdIntegerType(type) || type->isEnumeralType()) return false;
        // Every successful POSIX fd is a nonnegative int. Only an integer
        // value capable of preserving that entire range can transfer it.
        const unsigned needed = context.getIntWidth(context.IntTy) - 1;
        const unsigned available = context.getIntWidth(type) - (type->isSignedIntegerType() ? 1 : 0);
        return available >= needed;
    }

    void collectReturnedValue(const Expr* expr, unsigned depth = 0) {
        if (!expr || depth >= 128 || !carriesDescriptor(expr->getType())) return;
        if (const auto* paren = dyn_cast<ParenExpr>(expr)) {
            collectReturnedValue(paren->getSubExpr(), depth + 1);
        } else if (const auto* cast = dyn_cast<CastExpr>(expr)) {
            if (cast->getCastKind() == CK_NoOp || cast->getCastKind() == CK_LValueToRValue ||
                cast->getCastKind() == CK_IntegralCast)
                collectReturnedValue(cast->getSubExpr(), depth + 1);
        } else if (const auto* choice = dyn_cast<ConditionalOperator>(expr)) {
            collectReturnedValue(choice->getTrueExpr(), depth + 1);
            collectReturnedValue(choice->getFalseExpr(), depth + 1);
        } else if (const auto* comma = dyn_cast<BinaryOperator>(expr);
                   comma && comma->getOpcode() == BO_Comma) {
            collectReturnedValue(comma->getRHS(), depth + 1);
        } else {
            returnedValues.insert(expr);
        }
    }

    bool VisitReturnStmt(ReturnStmt* ret) {
        collectReturnedValue(ret->getRetValue());
        return true;
    }

    bool VisitCallExpr(CallExpr* call) {
        if (isAcquisitionCall(call)) origins.push_back(call);
        if (isPipeCall(call)) {
            for (unsigned end = 0; end != 2; ++end) {
                const Origin origin{call, end + 1};
                origins.push_back(origin);
                names.emplace(origin, std::string(calleeName(call)) + (end == 0 ? " read end [0]" : " write end [1]"));
            }
        }
        return true;
    }

    bool VisitVarDecl(VarDecl* var) {
        if (isFdIntegerType(var->getType()) || var->getType()->isPointerType() || localFdArray(var)) ++integerVariables;
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

    FdAnalysis(std::vector<Origin> origins, unsigned integerVariables,
               std::set<const Stmt*> returnedValues)
        : origins_(std::move(origins)),
          integerVariables_(integerVariables),
          returnedValues_(std::move(returnedValues)) {}

    State initialState() const { return {}; }

    unsigned latticeHeight() const {
        return static_cast<unsigned>(origins_.size()) * 8 +
               integerVariables_ * 8 + 32;
    }

    State merge(const State& a, const State& b) const {
        return mergeStates(a, b);
    }

    void widen(State&) const {}

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext&) const {
        State out = in;
        auto finish = [&]() {
            // A selected return value executes in its own CFG arm BEFORE
            // the arms join. Transferring at the final ReturnStmt loses that
            // association; escaping both arms there would hide real leaks.
            if (returnedValues_.count(stmt)) {
                const auto* value = dyn_cast<Expr>(stmt);
                if (Origin origin = acquisition(value))
                    out.resources[origin] = ResourceLife::Returned;
                else
                    returnOwnership(bindingFor(value, out), out);
            }
            return out;
        };

        auto mutateValue = [&](const Expr* target, std::optional<long long> delta) {
            if (delta && *delta == 0) return;
            const auto* var = asVar(target);
            if (var && var->getType()->isPointerType()) {
                auto found = out.arrayPointers.find(var);
                if (found == out.arrayPointers.end()) return;
                if (!delta || (*delta > 0 && found->second.index > std::numeric_limits<long long>::max() - *delta) ||
                    (*delta < 0 && found->second.index < -*delta)) out.arrayPointers.erase(found);
                else found->second.index += *delta;
                return;
            }
            const Slot slot = valueSlot(target, out);
            if (!slot) return;
            out.bindings[slot] = Binding{{}, true};
            if (slot.index == -1) forgetValue(slot.variable, out);
        };

        if (const auto* unary = dyn_cast<UnaryOperator>(stmt); unary && unary->isIncrementDecrementOp()) {
            mutateValue(unary->getSubExpr(), unary->isIncrementOp() ? 1 : -1);
            return finish();
        }

        if (const auto* declaration = dyn_cast<DeclStmt>(stmt)) {
            for (const Decl* decl : declaration->decls()) {
                const auto* var = dyn_cast<VarDecl>(decl);
                if (var && var->hasInit() && var->getType()->isPointerType()) {
                    Slot pointer = pointerSlot(var->getInit(), out);
                    if (pointer) out.arrayPointers[var] = pointer;
                    else out.arrayPointers.erase(var);
                    continue;
                }
                if (var && localFdArray(var) && var->hasInit()) {
                    if (const auto* list = dyn_cast<InitListExpr>(var->getInit()->IgnoreParenImpCasts())) {
                        for (unsigned i = 0; i < list->getNumInits(); ++i)
                            out.bindings[Slot{var, i}] = bindingFor(list->getInit(i), out);
                    }
                    continue;
                }
                if (!isTrackableLocal(var) || !var->hasInit()) continue;
                const Expr* init = var->getInit();
                if (Origin origin = acquisition(init)) {
                    rememberNegativeWitnesses(origin, var, out);
                    forgetValue(var, out);
                    out.resources[origin] = ResourceLife::Open;
                    out.bindings[var] = Binding{{origin}, false};
                } else {
                    const Binding binding = bindingFor(init, out);
                    const auto status = pipeStatus(init, out);
                    const VarDecl* source = asVar(init);
                    rememberValueCopy(var, source, out);
                    if (const auto constant = integerConstant(init);
                        constant && *constant < 0)
                        out.definitelyNegative.insert(var);
                    out.bindings[var] = binding;
                    if (status) out.pipeStatuses[var] = status;
                }
            }
            return finish();
        }

        if (const auto* assignment = dyn_cast<BinaryOperator>(stmt)) {
            if (assignment->getOpcode() != BO_Assign) {
                if (assignment->isCompoundAssignmentOp()) {
                    auto delta = slotOffset(assignment->getRHS());
                    if (assignment->getOpcode() == BO_SubAssign && delta) *delta = -*delta;
                    else if (assignment->getOpcode() != BO_AddAssign) delta = std::nullopt;
                    mutateValue(assignment->getLHS(), delta);
                }
                return finish();
            }
            const Expr* rhs = assignment->getRHS();
            const VarDecl* target = asVar(assignment->getLHS());
            const Slot cell = valueSlot(assignment->getLHS(), out);
            if (cell && cell.index >= 0) {
                if (Origin origin = acquisition(rhs)) {
                    out.resources[origin] = ResourceLife::Open;
                    out.bindings[cell] = Binding{{origin}, false};
                } else out.bindings[cell] = bindingFor(rhs, out);
                return finish();
            }
            if (target && target->getType()->isPointerType()) {
                Slot pointer = pointerSlot(rhs, out);
                if (pointer) out.arrayPointers[target] = pointer;
                else out.arrayPointers.erase(target);
                return finish();
            }
            if (isTrackableLocal(target)) {
                if (Origin origin = acquisition(rhs)) {
                    rememberNegativeWitnesses(origin, target, out);
                    forgetValue(target, out);
                    out.resources[origin] = ResourceLife::Open;
                    out.bindings[target] = Binding{{origin}, false};
                } else {
                    const Binding binding = bindingFor(rhs, out);
                    const auto status = pipeStatus(rhs, out);
                    const VarDecl* source = asVar(rhs);
                    rememberValueCopy(target, source, out);
                    if (const auto constant = integerConstant(rhs);
                        constant && *constant < 0)
                        out.definitelyNegative.insert(target);
                    out.bindings[target] = binding;
                    if (status) out.pipeStatuses[target] = status;
                }
            } else if (Origin origin = acquisition(rhs)) {
                out.resources[origin] = ResourceLife::Escaped;
            } else {
                escape(bindingFor(rhs, out), out);
            }
            return finish();
        }

        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            const llvm::StringRef name = calleeName(call);
            if (isPipeCall(call)) {
                acquirePipe(call, out);
            } else if (name == "close" && call->getNumArgs() >= 1) {
                applyOwnershipToExpr(
                    call->getArg(0),
                    codeskeptic::SummaryRegistry::ParamOwnership::Consumed,
                    out);
            } else {
                // A mutable address argument can overwrite a saved pipe status.
                // A later comparison of that variable must not erase ownership
                // acquired before the unrelated call.
                for (const Expr* arg : call->arguments()) {
                    if (!arg->getType()->isPointerType() || arg->getType()->getPointeeType().isConstQualified()) continue;
                    const auto* address = dyn_cast<UnaryOperator>(arg->IgnoreParenImpCasts());
                    if (address && address->getOpcode() == UO_AddrOf) {
                        out.pipeStatuses.erase(asVar(address->getSubExpr()));
                        out.arrayPointers.erase(asVar(address->getSubExpr()));
                    }
                    const Slot pointed = pointerSlot(arg, out);
                    if (pointed && pointed.index == -1) out.pipeStatuses.erase(pointed.variable);
                }
                applyModeledCallEffects(call, out);
                if (isAcquisitionCall(call))
                    out.resources[call] = ResourceLife::Open;
            }
            // shutdown intentionally has no ownership effect: POSIX still
            // requires close() to release the descriptor itself.
        }
        return finish();
    }

    void refineOnEdge(const Stmt* condition, bool isTrueBranch,
                      State& state, ASTContext&) const {
        const auto* expr = dyn_cast_or_null<Expr>(condition);
        const auto pipeFailure = pipeFailureEdge(expr, state);
        if (pipeFailure.first && pipeFailure.second == isTrueBranch)
            pipeFailed(pipeFailure.first, state);
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
    std::set<const Stmt*> returnedValues_;
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
        SourceLocation loc = discarded || origin.output != 0 ? origin->getBeginLoc()
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
    ResourceInventory inventory(context);
    inventory.TraverseStmt(const_cast<Stmt*>(function->getBody()));
    if (inventory.origins.empty()) return;

    FdAnalysis analysis(
        inventory.origins,
        inventory.integerVariables + function->getNumParams(), inventory.returnedValues);
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
