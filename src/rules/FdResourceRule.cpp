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
#include <clang/AST/ExprCXX.h>
#include <clang/AST/ParentMapContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <map>
#include <functional>
#include <initializer_list>
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
    bool operator==(const Origin& other) const {
        return call == other.call && output == other.output;
    }
    bool operator<(const Origin& other) const {
        if (call != other.call) return std::less<const CallExpr*>{}(call, other.call);
        return output < other.output;
    }
};

struct Slot {
    const VarDecl* variable = nullptr;
    long long index = -1; // -1 is the scalar variable itself.
    const FieldDecl* field = nullptr;
    const CallExpr* expression = nullptr; // The current evaluated acquisition value.
    Slot(const VarDecl* var = nullptr, long long element = -1, const FieldDecl* member = nullptr)
        : variable(var), index(element), field(member) {}
    static Slot acquired(const CallExpr* call) { Slot slot; slot.expression = call; return slot; }
    explicit operator bool() const { return variable != nullptr || expression != nullptr; }
    bool operator==(const Slot& other) const {
        return variable == other.variable && index == other.index && field == other.field &&
            expression == other.expression;
    }
    bool operator<(const Slot& other) const {
        if (expression != other.expression) return std::less<const CallExpr*>{}(expression, other.expression);
        if (variable != other.variable) return std::less<const VarDecl*>{}(variable, other.variable);
        return index == other.index ? std::less<const FieldDecl*>{}(field, other.field) : index < other.index;
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

struct DirectoryStream {
    const CallExpr* acquisition = nullptr;
    bool nonnull = false;
    bool operator==(const DirectoryStream& other) const {
        return acquisition == other.acquisition && nonnull == other.nonnull;
    }
};

using HolderSet = std::set<Slot>;
using LiveInstances = std::set<HolderSet>;

// A set describes the proven aliases of ONE possible live instance. Union
// preserves alternatives and simultaneously live instances at loop joins;
// no relative allocation-age alignment is assumed. An empty set is a lost
// instance, never dischargeable by a later unrelated close.
void boundInstances(LiveInstances& instances) {
    // A lost obligation is an absorbing top: permitting new groups beside it
    // would make capped joins order-dependent and allow collapse/regrowth in
    // loops. No later exact holder can discharge that lost instance.
    if (instances.size() > 64 || instances.count(HolderSet{}))
        instances = LiveInstances{HolderSet{}};
}

struct State {
    std::map<Origin, ResourceLife> resources;
    std::map<Slot, Binding> bindings;
    std::map<const VarDecl*, Slot> arrayPointers;
    std::map<const VarDecl*, PipeStatus> pipeStatuses;
    std::map<Origin, Binding> pipePrevious;
    std::set<const VarDecl*> definitelyNegative;
    std::map<const VarDecl*, const VarDecl*> valueCopies;
    std::map<Origin, std::set<const VarDecl*>> negativeWitnesses;
    std::map<const VarDecl*, const FieldDecl*> ownerFields;
    std::map<Slot, DirectoryStream> streams;
    std::set<Origin> managedSites;
    std::map<Origin, LiveInstances> holders;
    // Address/reference exposure can outlive the current value (or occur
    // before acquisition). Such storage is never an authoritative holder.
    std::set<Slot> exposedSlots;

    bool operator==(const State& other) const {
        return resources == other.resources && bindings == other.bindings &&
               definitelyNegative == other.definitelyNegative &&
               valueCopies == other.valueCopies &&
               negativeWitnesses == other.negativeWitnesses &&
               arrayPointers == other.arrayPointers && pipeStatuses == other.pipeStatuses &&
               pipePrevious == other.pipePrevious && ownerFields == other.ownerFields &&
               streams == other.streams && managedSites == other.managedSites && holders == other.holders &&
               exposedSlots == other.exposedSlots;
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

    out.managedSites = a.managedSites;
    out.managedSites.insert(b.managedSites.begin(), b.managedSites.end());
    out.exposedSlots = a.exposedSlots;
    out.exposedSlots.insert(b.exposedSlots.begin(), b.exposedSlots.end());
    for (const auto& [var, field] : a.ownerFields) {
        const auto found = b.ownerFields.find(var);
        if (found != b.ownerFields.end() && found->second == field) out.ownerFields[var] = field;
    }
    for (const auto& [slot, stream] : a.streams) {
        const auto found = b.streams.find(slot);
        if (found != b.streams.end() && found->second.acquisition == stream.acquisition)
            out.streams[slot] = {stream.acquisition, stream.nonnull && found->second.nonnull};
    }
    for (Origin origin : origins) {
        const auto ai = a.holders.find(origin), bi = b.holders.find(origin);
        auto& instances = out.holders[origin];
        if (ai != a.holders.end()) instances.insert(ai->second.begin(), ai->second.end());
        if (bi != b.holders.end()) instances.insert(bi->second.begin(), bi->second.end());
        boundInstances(instances);
        if (out.managedSites.count(origin) && !instances.empty()) out.resources[origin] = ResourceLife::Open;
    }

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

bool isFdIntegerType(QualType type) {
    return !type.isNull() && type->isIntegerType() &&
           !type->isBooleanType();
}

bool isInt(QualType type) {
    return !type.isNull() &&
           type.getCanonicalType()->isSpecificBuiltinType(BuiltinType::Int);
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

// Narrow reporting provenance, not an acquisition/transfer predicate. The
// historical detector also models named/summary-owned integer resources; a
// name alone does not prove that such a resource is a native descriptor.
bool hasNativeDescriptorMetadata(const CallExpr* call) {
    if (!call) return false;
    if (isPipeCall(call)) return true;
    const auto name = calleeName(call);
    if (name == "accept" || name == "accept4")
        return codeskeptic::isNativeFdAcquisition(call); // already signature-checked
    const FunctionDecl* callee = call->getDirectCallee();
    if (name.empty() || callee->hasBody() || !isInt(callee->getReturnType())) return false;
    ASTContext& ctx = callee->getASTContext();
    auto signature = [&](std::initializer_list<QualType> parameters, bool variadic = false) {
        if (callee->isVariadic() != variadic || callee->getNumParams() != parameters.size())
            return false;
        unsigned index = 0;
        for (const QualType type : parameters)
            if (!ctx.hasSameUnqualifiedType(callee->getParamDecl(index++)->getType(), type))
                return false;
        return true;
    };
    const QualType string = ctx.getPointerType(ctx.CharTy.withConst());
    if (name == "open") return signature({string, ctx.IntTy}, true);
    if (name == "openat") return signature({ctx.IntTy, string, ctx.IntTy}, true);
    if (name == "socket") return signature({ctx.IntTy, ctx.IntTy, ctx.IntTy});
    if (name == "dup") return signature({ctx.IntTy});
    if (name == "mkstemp") return signature({ctx.getPointerType(ctx.CharTy)});
    return false;
}

bool isAcquisitionCall(const CallExpr* call) {
    if (!call || !isFdIntegerType(call->getType())) return false;
    if (isPipeCall(call)) return false; // Native pipe returns status, never an owned FD.
    if (codeskeptic::isNativeFdAcquisition(call)) return true;
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

// Pointer addresses use nonnegative offsets, including &scalar at offset 0.
// Binding/status keys instead use -1 for the scalar value. Keep that conversion
// at the dereference boundary so *p, p[0] and *(p+0) name the same storage.
Slot pointedValueSlot(Slot address) {
    if (!address || address.index < 0) return {};
    if (const auto* array = localFdArray(address.variable))
        return array->getSize().getLimitedValue() > static_cast<unsigned long long>(address.index) ? address : Slot{};
    return address.index == 0 && address.variable->hasLocalStorage() &&
        address.variable->getType()->isIntegerType() ? Slot{address.variable} : Slot{};
}

Slot valueSlot(const Expr* expr, const State& state, unsigned depth = 0);

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
    bool subtract = false;
    if (const auto* address = dyn_cast<UnaryOperator>(expr);
        address && address->getOpcode() == UO_AddrOf) {
        const Expr* operand = address->getSubExpr()->IgnoreParenImpCasts();
        if (const auto* dereference = dyn_cast<UnaryOperator>(operand);
            dereference && dereference->getOpcode() == UO_Deref)
            return pointerSlot(dereference->getSubExpr(), state, depth + 1);
        if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(operand)) {
            // Forming a one-past address is valid; reading that slot is not.
            base = subscript->getBase(); offset = subscript->getIdx();
        } else {
            Slot value = valueSlot(operand, state, depth + 1);
            if (!value) return {};
            if (value.index == -1) value.index = 0;
            return pointedValueSlot(value) ? value : Slot{};
        }
    } else if (const auto* add = dyn_cast<BinaryOperator>(expr);
               add && (add->getOpcode() == BO_Add || add->getOpcode() == BO_Sub)) {
        base = add->getLHS(); offset = add->getRHS();
        subtract = add->getOpcode() == BO_Sub;
        if (!subtract && offset->getType()->isPointerType()) std::swap(base, offset);
    }
    auto amount = slotOffset(offset);
    if (amount && subtract) *amount = -*amount;
    Slot slot = pointerSlot(base, state, depth + 1);
    if (!slot || !amount || (*amount > 0 && slot.index > std::numeric_limits<long long>::max() - *amount)) return {};
    slot.index += *amount;
    return slot.index >= 0 ? slot : Slot{};
}

Slot valueSlot(const Expr* expr, const State& state, unsigned depth) {
    if (!expr || depth >= 32) return {};
    if (const auto* var = asVar(expr)) {
        if (!var->getType()->isReferenceType()) return {var};
        const auto found = state.arrayPointers.find(var);
        return found == state.arrayPointers.end() ? Slot{} : pointedValueSlot(found->second);
    }
    expr = expr->IgnoreParenImpCasts();
    if (const auto* member = dyn_cast<MemberExpr>(expr); member && !member->isArrow()) {
        const auto* object = asVar(member->getBase());
        const auto found = state.ownerFields.find(object);
        if (found != state.ownerFields.end() && found->second == member->getMemberDecl())
            return {object, -1, found->second};
        return {};
    }
    if (const auto* assignment = dyn_cast<BinaryOperator>(expr);
        assignment && assignment->getOpcode() == BO_Assign && isInt(assignment->getType()))
        return valueSlot(assignment->getLHS(), state, depth + 1);
    if (const auto* dereference = dyn_cast<UnaryOperator>(expr);
        dereference && dereference->getOpcode() == UO_Deref)
        return pointedValueSlot(pointerSlot(dereference->getSubExpr(), state, depth + 1));
    const auto* subscript = dyn_cast<ArraySubscriptExpr>(expr);
    if (!subscript) return {};
    Slot slot = pointerSlot(subscript->getBase(), state, depth + 1);
    const auto offset = slotOffset(subscript->getIdx());
    if (!slot || !offset || (*offset > 0 && slot.index > std::numeric_limits<long long>::max() - *offset)) return {};
    slot.index += *offset;
    return pointedValueSlot(slot);
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
    const Slot value = valueSlot(expr, state);
    const auto found = state.pipeStatuses.find(value.index == -1 ? value.variable : nullptr);
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

void forgetOwnershipWitness(const VarDecl* var, State& state) {
    // Mere exposure makes ownership witnesses unsafe, but does not mutate a
    // pipe status. Its established const-borrow/alias contract stays separate.
    const auto found = state.pipeStatuses.find(var);
    const auto status = found == state.pipeStatuses.end() ? PipeStatus{} : found->second;
    forgetValue(var, state);
    if (status) state.pipeStatuses[var] = status;
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

bool managed(Origin origin, const State& state) {
    return state.managedSites.count(origin) != 0;
}

Slot holderSlot(const Expr* expression, const State& state, ASTContext& context) {
    while (expression) {
        expression = expression->IgnoreParens();
        const auto* cast = dyn_cast<CastExpr>(expression);
        if (!cast) break;
        const bool preserving = cast->getCastKind() == CK_NoOp ||
            cast->getCastKind() == CK_LValueToRValue ||
            (cast->getCastKind() == CK_IntegralCast &&
             codeskeptic::fdTypePreservesDescriptor(cast->getType(), context) &&
             codeskeptic::fdTypePreservesDescriptor(cast->getSubExpr()->getType(), context));
        if (!preserving) return {};
        expression = cast->getSubExpr();
    }
    if (Origin origin = acquisition(expression)) return Slot::acquired(origin.call);
    return valueSlot(expression, state);
}

void forgetHolder(Slot slot, State& state) {
    if (!slot) return;
    for (auto& [origin, instances] : state.holders) {
        (void)origin;
        LiveInstances changed;
        for (auto aliases : instances) { aliases.erase(slot); changed.insert(std::move(aliases)); }
        boundInstances(changed);
        instances = std::move(changed);
    }
    state.streams.erase(slot);
}

void bindValue(Slot target, const Binding& binding, Slot source, State& state,
               bool fresh = false) {
    if (fresh && binding.origins.size() == 1)
        source = Slot::acquired(binding.origins.begin()->call);
    if (target.variable) {
        const auto type = target.field ? target.field->getType() : target.variable->getType();
        if (!type->isPointerType() && !codeskeptic::fdTypePreservesDescriptor(type, target.variable->getASTContext()))
            source = {};
    }
    for (auto& [origin, instances] : state.holders) {
        (void)origin;
        LiveInstances changed;
        for (auto aliases : instances) {
            const bool copied = source && aliases.count(source);
            aliases.erase(target);
            if (copied && !state.exposedSlots.count(target)) aliases.insert(target);
            changed.insert(std::move(aliases));
        }
        boundInstances(changed);
        instances = std::move(changed);
    }
    state.streams.erase(target);
    state.bindings[target] = binding;
}

void bindExpression(Slot target, const Expr* expression, State& state) {
    if (Origin origin = acquisition(expression))
        bindValue(target, Binding{{origin}, false}, {}, state, true);
    else
        bindValue(target, bindingFor(expression, state), holderSlot(expression, state, target.variable->getASTContext()), state);
}

void disposeHolder(Slot slot, ResourceLife disposition, State& state) {
    if (!slot) return;
    for (auto& [origin, instances] : state.holders) {
        bool consumed = false;
        for (auto it = instances.begin(); it != instances.end();) {
            if (it->count(slot)) { it = instances.erase(it); consumed = true; }
            else ++it;
        }
        boundInstances(instances);
        if (consumed)
            state.resources[origin] = instances.empty() ? disposition : ResourceLife::Open;
    }
}

void acquireInstance(Origin origin, State& state) {
    const Slot value = Slot::acquired(origin.call);
    forgetHolder(value, state); // The previous evaluation is NOT the new value.
    auto& instances = state.holders[origin];
    instances.insert(HolderSet{value});
    boundInstances(instances);
    state.resources[origin] = ResourceLife::Open;
}

void markManaged(Origin origin, State& state) {
    state.managedSites.insert(origin);
    const auto found = state.holders.find(origin);
    if (found != state.holders.end() && !found->second.empty()) state.resources[origin] = ResourceLife::Open;
}

void exposeValue(Slot slot, State& state) {
    if (!slot) return;
    state.exposedSlots.insert(slot);
    forgetHolder(slot, state);
    if (slot.variable && !slot.field && slot.index == -1) forgetOwnershipWitness(slot.variable, state);
}

bool nativeUnary(const CallExpr* call, llvm::StringRef name) {
    const auto* function = call ? call->getDirectCallee() : nullptr;
    return function && calleeName(call) == name && !function->hasBody() &&
        !function->isVariadic() && function->getNumParams() == 1 && call->getNumArgs() == 1;
}

bool nativeClose(const CallExpr* call) {
    return nativeUnary(call, "close") && isInt(call->getDirectCallee()->getReturnType()) &&
        isInt(call->getDirectCallee()->getParamDecl(0)->getType());
}

bool opaqueDirectory(QualType type) {
    if (!type->isPointerType()) return false;
    const auto* record = type->getPointeeType()->getAsRecordDecl();
    return record && !record->getDefinition();
}

bool nativeFdopendir(const CallExpr* call) {
    return nativeUnary(call, "fdopendir") &&
        isInt(call->getDirectCallee()->getParamDecl(0)->getType()) &&
        opaqueDirectory(call->getDirectCallee()->getReturnType());
}

bool nativeClosedir(const CallExpr* call, QualType streamType, ASTContext& context) {
    return nativeUnary(call, "closedir") && isInt(call->getDirectCallee()->getReturnType()) &&
        opaqueDirectory(streamType) && context.hasSameType(
            call->getDirectCallee()->getParamDecl(0)->getType().getUnqualifiedType(),
            streamType.getUnqualifiedType());
}

const Expr* plainExpression(const Expr* expression) {
    if (!expression) return nullptr;
    expression = expression->IgnoreParenImpCasts();
    if (const auto* cleanups = dyn_cast<ExprWithCleanups>(expression))
        return plainExpression(cleanups->getSubExpr());
    return expression;
}

const Stmt* singleStatement(const Stmt* statement) {
    if (const auto* body = dyn_cast_or_null<CompoundStmt>(statement))
        return body->size() == 1 ? singleStatement(*body->body_begin()) : nullptr;
    return statement;
}

bool thisField(const Expr* expression, const FieldDecl* field) {
    const auto* member = dyn_cast_or_null<MemberExpr>(plainExpression(expression));
    return member && member->getMemberDecl() == field &&
        isa<CXXThisExpr>(member->getBase()->IgnoreParenImpCasts());
}

const FieldDecl* cleanupField(const CXXRecordDecl* record, ASTContext& context) {
    if (!record || !record->hasDefinition()) return nullptr;
    record = record->getDefinition();
    if (record->getNumBases() || record->isUnion() || record->field_empty()) return nullptr;
    auto fields = record->field_begin();
    const auto* field = *fields++;
    if (fields != record->field_end() || field->isBitField() ||
        field->getType().isVolatileQualified()) return nullptr;
    const bool descriptor = isInt(field->getType());
    if (!descriptor && !opaqueDirectory(field->getType())) return nullptr;
    const auto* destructor = record->getDestructor();
    if (!destructor || !destructor->hasBody()) return nullptr;
    const Stmt* cleanup = singleStatement(destructor->getBody());
    if (const auto* condition = dyn_cast_or_null<IfStmt>(cleanup)) {
        if (!descriptor || condition->getElse() || condition->getInit() ||
            condition->getConditionVariable()) return nullptr;
        const auto* comparison = dyn_cast<BinaryOperator>(plainExpression(condition->getCond()));
        const auto* zero = comparison ? dyn_cast<IntegerLiteral>(plainExpression(comparison->getRHS())) : nullptr;
        if (!comparison || comparison->getOpcode() != BO_GE || !zero ||
            zero->getValue() != 0 || !thisField(comparison->getLHS(), field)) return nullptr;
        cleanup = singleStatement(condition->getThen());
    }
    const auto* call = dyn_cast_or_null<CallExpr>(cleanup);
    if (!call || !(descriptor ? nativeClose(call) : nativeClosedir(call, field->getType(), context)) ||
        !thisField(call->getArg(0), field)) return nullptr;
    return field;
}

// A value read or a direct field assignment is understood. Object copies,
// address/reference exposure and other mutations are deliberately not proof.
class OwnerExposure : public RecursiveASTVisitor<OwnerExposure> {
public:
    OwnerExposure(const VarDecl* object, const FieldDecl* field, ASTContext& context)
        : object_(object), field_(field), context_(context) {}
    bool safe = true;
    bool VisitDeclRefExpr(DeclRefExpr* reference) {
        if (reference->getDecl() != object_) return true;
        const auto parents = context_.getParents(*reference);
        const auto* member = parents.size() == 1 ? parents[0].get<MemberExpr>() : nullptr;
        if (!member || member->getMemberDecl() != field_ || member->isArrow()) {
            safe = false; return true;
        }
        const Stmt* current = member;
        for (unsigned depth = 0; depth != 16; ++depth) {
            const auto above = context_.getParents(*current);
            if (above.size() != 1) break;
            if (const auto* paren = above[0].get<ParenExpr>()) { current = paren; continue; }
            if (const auto* cast = above[0].get<ImplicitCastExpr>(); cast && cast->getCastKind() == CK_LValueToRValue)
                return true;
            if (const auto* assignment = above[0].get<BinaryOperator>(); assignment &&
                assignment->getOpcode() == BO_Assign && assignment->getLHS() == current)
                return true;
            break;
        }
        safe = false;
        return true;
    }
private:
    const VarDecl* object_;
    const FieldDecl* field_;
    ASTContext& context_;
};

const FieldDecl* localOwnerField(const VarDecl* variable, ASTContext& context) {
    if (!variable || !variable->hasLocalStorage() || !variable->hasInit()) return nullptr;
    const auto* field = cleanupField(variable->getType()->getAsCXXRecordDecl(), context);
    if (!field) return nullptr;
    const auto* function = dyn_cast<FunctionDecl>(variable->getDeclContext());
    if (!function || !function->hasBody()) return nullptr;
    OwnerExposure exposure(variable, field, context);
    exposure.TraverseStmt(function->getBody());
    return exposure.safe ? field : nullptr;
}

const Expr* adoptedValue(const VarDecl* variable, const FieldDecl* field) {
    const auto* expression = plainExpression(variable->getInit());
    if (const auto* construction = dyn_cast_or_null<CXXConstructExpr>(expression)) {
        const auto* constructor = construction->getConstructor();
        const auto* body = dyn_cast_or_null<CompoundStmt>(constructor->getBody());
        if (!isInt(field->getType()) || constructor->isCopyOrMoveConstructor() ||
            constructor->getNumParams() != 1 || construction->getNumArgs() != 1 ||
            constructor->getNumCtorInitializers() != 1 || !body || !body->body_empty()) return nullptr;
        const auto* initializer = *constructor->init_begin();
        const auto* parameter = dyn_cast_or_null<DeclRefExpr>(plainExpression(initializer->getInit()));
        if (!initializer->isMemberInitializer() || initializer->getMember() != field ||
            !parameter || parameter->getDecl() != constructor->getParamDecl(0) ||
            !isInt(constructor->getParamDecl(0)->getType())) return nullptr;
        return construction->getArg(0);
    }
    const auto* list = dyn_cast_or_null<InitListExpr>(expression);
    if (list && opaqueDirectory(field->getType()) && list->getNumInits() == 1)
        return list->getInit(0);
    return nullptr;
}

void bindStream(Slot target, const Expr* expression, State& state) {
    const auto* call = dyn_cast_or_null<CallExpr>(plainExpression(expression));
    if (nativeFdopendir(call)) {
        bindExpression(target, call->getArg(0), state);
        for (Origin origin : state.bindings[target].origins) markManaged(origin, state);
        state.streams[target] = {call, false};
    } else {
        const Slot source = valueSlot(expression, state);
        const auto found = state.streams.find(source);
        const auto stream = found == state.streams.end() ? DirectoryStream{} : found->second;
        bindExpression(target, expression, state);
        if (stream.acquisition) state.streams[target] = stream;
    }
}

void destroyLocalOwner(const VarDecl* variable, State& state) {
    const auto owner = state.ownerFields.find(variable);
    if (owner == state.ownerFields.end()) return;
    const Slot field{owner->first, -1, owner->second};
    const auto stream = state.streams.find(field);
    if (isInt(owner->second->getType()) || (stream != state.streams.end() && stream->second.nonnull))
        disposeHolder(field, ResourceLife::Closed, state);
    forgetHolder(field, state);
    state.ownerFields.erase(variable);
}

bool throwLeavesFunction(const Stmt* statement, ASTContext& context) {
    // Clang may connect an explicit throw directly to EXIT, omitting its
    // automatic destructors. Only a throw with no enclosing handler is proven
    // to leave all currently active locals. A throw caught in this function
    // must NOT release an owner that can subsequently be detached in a catch.
    for (unsigned depth = 0; statement && depth != 128; ++depth) {
        const auto parents = context.getParents(*statement);
        if (parents.size() != 1) return false;
        if (parents[0].get<FunctionDecl>()) return true;
        statement = parents[0].get<Stmt>();
        if (isa_and_nonnull<CXXTryStmt>(statement) || isa_and_nonnull<LambdaExpr>(statement)) return false;
    }
    return false;
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

void escape(const Binding& binding, State& state);
void returnOwnership(const Binding& binding, State& state);
void release(const Binding& binding, State& state);

void pipeFailed(const CallExpr* call, State& state) {
    for (unsigned end = 1; end != 3; ++end) {
        const Origin origin{call, end};
        const auto disposition = resourceLife(state, origin);
        state.resources[origin] = ResourceLife::None;
        const auto before = state.pipePrevious.find(origin);
        // Failure leaves the output values unchanged. Effects performed on
        // those values before checking status therefore consumed/transferred
        // the old descriptors on this edge, not nonexistent new descriptors.
        if (before != state.pipePrevious.end()) {
            if (disposition == ResourceLife::Closed) release(before->second, state);
            else if (disposition == ResourceLife::Returned) returnOwnership(before->second, state);
            else if (disposition == ResourceLife::Escaped) escape(before->second, state);
        }
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
        if (!managed(origin, state)) state.resources[origin] = ResourceLife::Escaped;
}

void returnOwnership(const Binding& binding, State& state) {
    if (binding.opaque || binding.origins.size() != 1) {
        escape(binding, state);
        return;
    }
    const Origin origin = *binding.origins.begin();
    if (managed(origin, state)) return; // Requires a path-conditioned holder proof.
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
    if (!managed(*binding.origins.begin(), state))
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
        if (managed(origin, state)) return; // Exact holder disposition only.
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

bool provesPersistentFdStore(const FunctionDecl* function, ASTContext& context,
                             unsigned depth = 0) {
    if (!function || depth >= 16) return false;
    function = function->getDefinition();
    if (!function || isa<CXXMethodDecl>(function) || function->isVariadic() ||
        function->getNumParams() != 1 || !function->getReturnType()->isVoidType()) return false;
    const auto* parameter = function->getParamDecl(0);
    if (!codeskeptic::fdTypePreservesDescriptor(parameter->getType(), context)) return false;
    const auto* body = dyn_cast<CompoundStmt>(function->getBody());
    if (!body || body->size() != 1) return false;
    const State empty;
    const Stmt* effect = *body->body_begin();
    if (const auto* store = dyn_cast<BinaryOperator>(effect)) {
        if (store->getOpcode() != BO_Assign ||
            !(holderSlot(store->getRHS(), empty, context) == Slot{parameter})) return false;
        const auto* target = asVar(store->getLHS());
        return target && target->hasGlobalStorage() &&
            codeskeptic::fdTypePreservesDescriptor(target->getType(), context);
    }
    const auto* forward = dyn_cast<CallExpr>(effect);
    return forward && forward->getNumArgs() == 1 &&
        holderSlot(forward->getArg(0), empty, context) == Slot{parameter} &&
        provesPersistentFdStore(forward->getDirectCallee(), context, depth + 1);
}

void applyModeledCallEffects(const CallExpr* call, State& state, ASTContext& context) {
    const llvm::StringRef direct = calleeName(call);
    if (codeskeptic::isNativeFdAcquisition(call) || isPipeCall(call) || direct == "close" ||
        direct == "shutdown")
        return;
    const auto* summary =
        codeskeptic::SummaryRegistry::instance().lookup(call);
    if (!summary) return;
    const unsigned offset = fdCallParamOffset(call);
    bool callerStorage = isa<CXXMemberCallExpr>(call) || offset != 0;
    for (const Expr* argument : call->arguments())
        callerStorage |= argument->isGLValue() || argument->getType()->isPointerType() ||
            argument->getType()->isRecordType();
    for (unsigned argIndex = offset;
         argIndex < call->getNumArgs(); ++argIndex) {
        const Expr* arg = call->getArg(argIndex);
        if (!isFdIntegerType(arg->getType())) continue;
        const auto ownership = summary->paramOwnership(argIndex - offset);
        using ParamOwnership = codeskeptic::SummaryRegistry::ParamOwnership;
        // Proven summaries apply to this argument value, not every possible
        // instance at its acquisition site. A transfer on one path must not
        // dominate an outstanding obligation on another as opaque escape does.
        // A stored-value summary does not identify its destination: set(&local,
        // fd) transfers outside the callee, but not outside this caller. Without
        // a destination relation, require a bounded body proof ending at direct
        // persistent storage, including for shadow instances before adoption.
        if (ownership == ParamOwnership::Consumed ||
            (ownership == ParamOwnership::Transferred && !callerStorage &&
             provesPersistentFdStore(call->getDirectCallee(), context)))
            disposeHolder(holderSlot(arg, state, context), ownership == ParamOwnership::Consumed
                ? ResourceLife::Closed : ResourceLife::Returned, state);
        applyOwnershipToExpr(arg, ownership, state);
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
    if (state.definitelyNegative.count(negativeVar) && !state.exposedSlots.count(Slot{negativeVar}))
        disposeHolder(resourceVar, ResourceLife::None, state);
    for (Origin origin : binding->second.origins) {
        if (managed(origin, state)) continue;
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
    std::map<const VarDecl*, const FieldDecl*> owners;
    unsigned integerVariables = 0;

    bool carriesDescriptor(QualType type) const {
        return codeskeptic::fdTypePreservesDescriptor(type, context);
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
        if (isFdIntegerType(var->getType()) || var->getType()->isPointerType() ||
            var->getType()->isRecordType() || localFdArray(var)) ++integerVariables;
        if (const auto* field = localOwnerField(var, context); field && adoptedValue(var, field))
            owners[var] = field;
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
               std::set<const Stmt*> returnedValues,
               std::map<const VarDecl*, const FieldDecl*> owners)
        : origins_(std::move(origins)),
          integerVariables_(integerVariables),
          returnedValues_(std::move(returnedValues)), owners_(std::move(owners)) {}

    State initialState() const { return {}; }

    unsigned latticeHeight() const {
        return static_cast<unsigned>(origins_.size()) * 32 +
               integerVariables_ * 16 + 64;
    }

    State merge(const State& a, const State& b) const {
        return mergeStates(a, b);
    }

    void widen(State&) const {}

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& context) const {
        State out = in;
        // An escaped address may be retained elsewhere, including by an
        // earlier constructor. Do not trust an old negative witness across
        // another call merely because that address is absent from its args.
        if (isa<CallExpr>(stmt) || isa<CXXConstructExpr>(stmt)) {
            for (Slot slot : out.exposedSlots)
                if (slot.variable && !slot.field && slot.index == -1) forgetOwnershipWitness(slot.variable, out);
        }
        auto finish = [&]() {
            // A selected return value executes in its own CFG arm BEFORE
            // the arms join. Transferring at the final ReturnStmt loses that
            // association; escaping both arms there would hide real leaks.
            if (returnedValues_.count(stmt)) {
                const auto* value = dyn_cast<Expr>(stmt);
                if (Origin origin = acquisition(value)) {
                    disposeHolder(Slot::acquired(origin.call), ResourceLife::Returned, out);
                    if (!managed(origin, out)) out.resources[origin] = ResourceLife::Returned;
                }
                else {
                    disposeHolder(holderSlot(value, out, context), ResourceLife::Returned, out);
                    returnOwnership(bindingFor(value, out), out);
                }
            }
            return out;
        };

        auto mutateValue = [&](const Expr* target, std::optional<long long> delta) {
            if (delta && *delta == 0) return;
            const auto* var = asVar(target);
            if (var && var->getType()->isPointerType()) {
                forgetHolder(var, out);
                auto found = out.arrayPointers.find(var);
                if (found == out.arrayPointers.end()) return;
                if (!delta || (*delta > 0 && found->second.index > std::numeric_limits<long long>::max() - *delta) ||
                    (*delta < 0 && found->second.index < -*delta)) out.arrayPointers.erase(found);
                else found->second.index += *delta;
                return;
            }
            const Slot slot = valueSlot(target, out);
            if (!slot) return;
            forgetHolder(slot, out);
            out.bindings[slot] = Binding{{}, true};
            if (slot.index == -1) forgetValue(slot.variable, out);
        };

        if (const auto* unary = dyn_cast<UnaryOperator>(stmt); unary && unary->isIncrementDecrementOp()) {
            mutateValue(unary->getSubExpr(), unary->isIncrementOp() ? 1 : -1);
            return finish();
        }

        if (const auto* address = dyn_cast<UnaryOperator>(stmt); address && address->getOpcode() == UO_AddrOf) {
            const Slot exposed = valueSlot(address->getSubExpr(), out);
            exposeValue(exposed, out);
        }

        if (const auto* cast = dyn_cast<ExplicitCastExpr>(stmt); cast && cast->isGLValue())
            exposeValue(valueSlot(cast->getSubExpr(), out), out);

        if (const auto* construction = dyn_cast<CXXConstructExpr>(stmt)) {
            const auto* constructor = construction->getConstructor();
            for (unsigned i = 0; i < construction->getNumArgs() && i < constructor->getNumParams(); ++i)
                if (constructor->getParamDecl(i)->getType()->isReferenceType())
                    exposeValue(valueSlot(construction->getArg(i), out), out);
        }

        if (const auto* closure = dyn_cast<LambdaExpr>(stmt)) {
            auto initializer = closure->capture_init_begin();
            for (const auto& capture : closure->captures()) {
                if (capture.capturesVariable() && capture.getCaptureKind() == LCK_ByRef) {
                    exposeValue(Slot{dyn_cast<VarDecl>(capture.getCapturedVar())}, out);
                    exposeValue(valueSlot(*initializer, out), out);
                }
                ++initializer;
            }
        }

        if (const auto* assembly = dyn_cast<GCCAsmStmt>(stmt)) {
            for (unsigned i = 0; i < assembly->getNumOutputs(); ++i) {
                const Slot output = valueSlot(assembly->getOutputExpr(i), out);
                forgetHolder(output, out);
                if (output.variable && !output.field && output.index == -1) forgetValue(output.variable, out);
            }
        }

        if (isa<CXXThrowExpr>(stmt) && throwLeavesFunction(stmt, context)) {
            const auto owners = out.ownerFields;
            for (const auto& [variable, field] : owners) {
                (void)field;
                destroyLocalOwner(variable, out);
            }
            return finish();
        }

        if (const auto* declaration = dyn_cast<DeclStmt>(stmt)) {
            for (const Decl* decl : declaration->decls()) {
                const auto* var = dyn_cast<VarDecl>(decl);
                if (!var) continue;
                if (var->hasInit() && var->getType()->isReferenceType())
                    exposeValue(valueSlot(var->getInit(), out), out);
                const auto owner = owners_.find(var);
                if (owner != owners_.end()) {
                    const auto* field = owner->second;
                    out.ownerFields[var] = field;
                    const Slot slot{var, -1, field};
                    const Expr* value = adoptedValue(var, field);
                    if (field->getType()->isPointerType()) bindStream(slot, value, out);
                    else bindExpression(slot, value, out);
                    for (Origin origin : out.bindings[slot].origins) markManaged(origin, out);
                    continue;
                }
                if (var && var->hasInit() && var->getType()->isReferenceType() &&
                    var->getType()->getPointeeType()->isIntegerType()) {
                    Slot value = valueSlot(var->getInit(), out);
                    exposeValue(value, out);
                    if (value.index == -1) value.index = 0;
                    if (pointedValueSlot(value)) out.arrayPointers[var] = value;
                    else out.arrayPointers.erase(var);
                    continue;
                }
                if (var && var->hasInit() && var->getType()->isPointerType()) {
                    bindStream(var, var->getInit(), out);
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
                    bindExpression(var, init, out);
                } else {
                    const Binding binding = bindingFor(init, out);
                    const auto status = pipeStatus(init, out);
                    const VarDecl* source = asVar(init);
                    rememberValueCopy(var, source, out);
                    if (const auto constant = integerConstant(init);
                        constant && *constant < 0)
                        out.definitelyNegative.insert(var);
                    bindValue(var, binding, holderSlot(init, out, context), out);
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
            const Slot cell = valueSlot(assignment->getLHS(), out);
            if (cell.field) {
                if (cell.field->getType()->isPointerType()) bindStream(cell, rhs, out);
                else bindExpression(cell, rhs, out);
                for (Origin origin : out.bindings[cell].origins) markManaged(origin, out);
                return finish();
            }
            const VarDecl* target = cell && cell.index == -1 ? cell.variable : asVar(assignment->getLHS());
            if (cell && cell.index >= 0) {
                if (Origin origin = acquisition(rhs)) {
                    out.resources[origin] = ResourceLife::Open;
                    out.bindings[cell] = Binding{{origin}, false};
                } else out.bindings[cell] = bindingFor(rhs, out);
                return finish();
            }
            if (target && target->getType()->isPointerType()) {
                bindStream(target, rhs, out);
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
                    bindExpression(target, rhs, out);
                } else {
                    const Binding binding = bindingFor(rhs, out);
                    const auto status = pipeStatus(rhs, out);
                    const VarDecl* source = asVar(rhs);
                    rememberValueCopy(target, source, out);
                    if (const auto constant = integerConstant(rhs);
                        constant && *constant < 0)
                        out.definitelyNegative.insert(target);
                    bindValue(target, binding, holderSlot(rhs, out, context), out);
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
                if (nativeClose(call))
                    disposeHolder(holderSlot(call->getArg(0), out, context), ResourceLife::Closed, out);
                applyOwnershipToExpr(
                    call->getArg(0),
                    codeskeptic::SummaryRegistry::ParamOwnership::Consumed,
                    out);
            } else if (nativeFdopendir(call)) {
                const Binding input = acquisition(call->getArg(0)) ?
                    Binding{{acquisition(call->getArg(0))}, false} : bindingFor(call->getArg(0), out);
                for (Origin origin : input.origins) markManaged(origin, out);
            } else if (call->getNumArgs() == 1 && nativeClosedir(call, call->getArg(0)->getType(), context)) {
                const Slot slot = valueSlot(call->getArg(0), out);
                const auto stream = out.streams.find(slot);
                if (stream != out.streams.end() && stream->second.nonnull &&
                    nativeClosedir(call, stream->second.acquisition->getType(), context))
                    disposeHolder(slot, ResourceLife::Closed, out);
            } else {
                // A mutable address argument can overwrite a saved pipe status.
                // A later comparison of that variable must not erase ownership
                // acquired before the unrelated call.
                const auto* callee = call->getDirectCallee();
                for (unsigned i = 0; i < call->getNumArgs(); ++i) {
                    const Expr* arg = call->getArg(i);
                    // Reference arguments remain glvalues after conversion,
                    // including calls through pointers with no direct callee.
                    if (arg->isGLValue()) exposeValue(valueSlot(arg, out), out);
                    if (callee && i < callee->getNumParams()) {
                        const QualType formal = callee->getParamDecl(i)->getType();
                        if (formal->isReferenceType()) {
                            const Slot value = valueSlot(arg, out);
                            exposeValue(value, out);
                            if (!formal->getPointeeType().isConstQualified() && value && value.index == -1)
                                out.pipeStatuses.erase(value.variable);
                        }
                    }
                    if (!arg->getType()->isPointerType() || arg->getType()->getPointeeType().isConstQualified()) continue;
                    const Slot pointed = pointedValueSlot(pointerSlot(arg, out));
                    const auto* address = dyn_cast<UnaryOperator>(arg->IgnoreParenImpCasts());
                    if (address && address->getOpcode() == UO_AddrOf) {
                        const auto* var = asVar(address->getSubExpr());
                        forgetHolder(var, out);
                        out.pipeStatuses.erase(var);
                        // &reference exposes the referent, not a reseatable
                        // pointer variable. Preserve its storage identity.
                        if (var && var->getType()->isPointerType()) out.arrayPointers.erase(var);
                    }
                    if (pointed) forgetHolder(pointed, out);
                    if (pointed && pointed.index == -1) out.pipeStatuses.erase(pointed.variable);
                }
                applyModeledCallEffects(call, out, context);
                if (isAcquisitionCall(call))
                    acquireInstance(call, out);
            }
            // shutdown intentionally has no ownership effect: POSIX still
            // requires close() to release the descriptor itself.
        }
        return finish();
    }

    State transferElement(const CFGElement& element, const State& input, ASTContext&) const {
        const auto destructor = element.getAs<CFGAutomaticObjDtor>();
        if (!destructor) return input;
        State out = input;
        destroyLocalOwner(destructor->getVarDecl(), out);
        return out;
    }

    void refineOnEdge(const Stmt* condition, bool isTrueBranch,
                      State& state, ASTContext& context) const {
        const auto* expr = dyn_cast_or_null<Expr>(condition);
        const Expr* pointer = expr ? expr->IgnoreParenImpCasts() : nullptr;
        bool nonnull = isTrueBranch;
        while (const auto* negate = dyn_cast_or_null<UnaryOperator>(pointer)) {
            if (negate->getOpcode() != UO_LNot) break;
            pointer = negate->getSubExpr()->IgnoreParenImpCasts();
            nonnull = !nonnull;
        }
        if (const auto* comparison = dyn_cast_or_null<BinaryOperator>(pointer)) {
            if (comparison->getOpcode() == BO_EQ || comparison->getOpcode() == BO_NE) {
                const Expr* candidate = comparison->getLHS();
                const Expr* zero = comparison->getRHS();
                if (!candidate->getType()->isPointerType()) std::swap(candidate, zero);
                if (zero->isNullPointerConstant(context, Expr::NPC_ValueDependentIsNotNull)) {
                    pointer = candidate->IgnoreParenImpCasts();
                    if (comparison->getOpcode() == BO_EQ) nonnull = !nonnull;
                }
            }
        }
        const auto directory = state.streams.find(valueSlot(pointer, state));
        if (directory != state.streams.end()) directory->second.nonnull = nonnull;
        const auto pipeFailure = pipeFailureEdge(expr, state);
        if (pipeFailure.first && pipeFailure.second == isTrueBranch)
            pipeFailed(pipeFailure.first, state);
        if (auto failure = failureEdge(expr);
            failure && failure->trueBranch == isTrueBranch) {
            markNegativeEquivalents(failure->var, state);
            disposeHolder(failure->var, ResourceLife::None, state);
            auto binding = state.bindings.find(failure->var);
            if (binding != state.bindings.end())
                for (Origin origin : binding->second.origins)
                    if (!managed(origin, state)) state.resources[origin] = ResourceLife::None;
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
    std::map<const VarDecl*, const FieldDecl*> owners_;
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
        diag.kind = hasNativeDescriptorMetadata(origin.call)
            ? codeskeptic::FindingKind::HandleLeak
            : codeskeptic::FindingKind::GenericResourceLeak;
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
        inventory.integerVariables + function->getNumParams(), inventory.returnedValues, inventory.owners);
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
