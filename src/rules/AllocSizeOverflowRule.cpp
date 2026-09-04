#include "rules/AllocSizeOverflowRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/AllocFunctions.h"
#include "engine/CallRefArgs.h"
#include "engine/CoverageReport.h"
#include "engine/DataflowEngine.h"
#include "engine/FunctionSummary.h"
#include "engine/Interval.h"
#include "engine/IntervalAnalysis.h"
#include "engine/IntervalEval.h"
#include "engine/ParamIntervals.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/AST/Type.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Basic/SourceManager.h>
#include <llvm/ADT/APInt.h>
#include <llvm/ADT/APSInt.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

std::set<const VarDecl*> collectIntVars(const FunctionDecl* fn) {
    struct V : RecursiveASTVisitor<V> {
        std::set<const VarDecl*> vars;
        bool VisitVarDecl(VarDecl* vd) {
            if (vd->getType()->isIntegerType()) vars.insert(vd);
            return true;
        }
    } v;
    v.TraverseStmt(fn->getBody());
    for (const auto* p : fn->parameters())
        if (p->getType()->isIntegerType()) v.vars.insert(p);
    return v.vars;
}

// An unsigned `*`/`+` sitting inside an allocator call's size argument.
// The BinaryOperator is the report site; the untrusted-operand and
// wrap checks run against the dataflow state at analysis time.
struct SizeSite {
    const BinaryOperator* op;
    unsigned bits;  // width of the unsigned result type
    const CallExpr* allocator;
};

struct CheckedSizeSite {
    const CallExpr* allocator;
    const VarDecl* sizeVar;
};

struct SizeInventory {
    std::vector<SizeSite> arithmetic;
    std::vector<CheckedSizeSite> checked;
    bool hasMulOverflow = false;
    bool hasAddOverflow = false;
};

// Does the true (unbounded) result of this unsigned arithmetic PROVABLY
// reach past what the result type can hold? The int64 interval remains the
// primary proof for sub-64 result types.
bool wrapsUnsignedFinite(const codeskeptic::Interval& r, unsigned bits) {
    if (r.isEmpty() || r.isTop()) return false;
    if (bits == 0 || bits >= 64) return false;
    const int64_t umax = (int64_t(1) << bits) - 1;
    return !r.hiIsInf() && r.hi() > umax;
}

// Evaluate a factor exactly in the result type. Runtime values deliberately
// return nullopt: a second unknown operand is not a finite wrap witness.
std::optional<llvm::APInt> constantUnsigned(const Expr* expr, unsigned bits,
                                            ASTContext& ctx) {
    if (!expr || bits == 0) return std::nullopt;
    Expr::EvalResult result;
    if (!expr->EvaluateAsInt(result, ctx)) return std::nullopt;
    const llvm::APSInt& value = result.Val.getInt();
    if (value.isSigned() && value.isNegative()) return std::nullopt;
    return value.zextOrTrunc(bits);
}

// Return the largest reachable value when the existing interval can express
// it. For an unbounded unsigned expression, its declared type maximum is an
// admitted corner only for the untrusted operand; callers enforce that gate.
std::optional<llvm::APInt> unsignedUpperCorner(
    const Expr* expr, const codeskeptic::IntervalMap& state, unsigned bits,
    ASTContext& ctx) {
    const Expr* rangeExpr = expr ? expr->IgnoreParens() : nullptr;
    if (!rangeExpr) return std::nullopt;

    // Recover the real source width through value-preserving unsigned
    // widening casts. The shared evaluator intentionally treats explicit
    // casts conservatively; using the destination width here would turn
    // `(size_t)uint32_value` into a false 64-bit full-range corner.
    while (const auto* cast = llvm::dyn_cast<CastExpr>(rangeExpr)) {
        const CastKind kind = cast->getCastKind();
        const Expr* sub = cast->getSubExpr()->IgnoreParens();
        bool transparent = kind == CK_LValueToRValue || kind == CK_NoOp;
        if (kind == CK_IntegralCast &&
            cast->getType()->isUnsignedIntegerType() &&
            sub->getType()->isUnsignedIntegerType()) {
            transparent = ctx.getIntWidth(cast->getType()) >=
                          ctx.getIntWidth(sub->getType());
        }
        if (!transparent) break;
        rangeExpr = sub;
    }

    codeskeptic::Interval interval =
        codeskeptic::evalInterval(rangeExpr, state, &ctx);
    if (interval.isEmpty()) return std::nullopt;
    if (!interval.hiIsInf()) {
        if (interval.hi() < 0) return std::nullopt;
        return llvm::APInt(bits, static_cast<uint64_t>(interval.hi()));
    }

    QualType type = rangeExpr->getType();
    if (!type->isIntegerType() || !type->isUnsignedIntegerType())
        return std::nullopt;
    const unsigned exprBits = ctx.getIntWidth(type);
    if (exprBits == 0 || exprBits > bits) return std::nullopt;
    return llvm::APInt::getMaxValue(exprBits).zext(bits);
}

const VarDecl* directIntegerVar(const Expr* expr) {
    if (!expr) return nullptr;
    const auto* ref =
        llvm::dyn_cast<DeclRefExpr>(expr->IgnoreParenCasts());
    const auto* var = ref ? llvm::dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
    return var && var->getType()->isIntegerType() ? var : nullptr;
}

const VarDecl* addressedIntegerVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    const auto* unary = llvm::dyn_cast<UnaryOperator>(expr);
    return unary && unary->getOpcode() == UO_AddrOf
               ? directIntegerVar(unary->getSubExpr())
               : nullptr;
}
bool isWritableReferenceArgument(const CallExpr* call, unsigned index) {
    const FunctionDecl* callee = call ? call->getDirectCallee() : nullptr;
    if (!callee || index >= callee->getNumParams()) return false;
    QualType parameter = callee->getParamDecl(index)->getType();
    const auto* reference = parameter->getAs<ReferenceType>();
    return reference && !reference->getPointeeType().isConstQualified();
}

bool isMulOverflowBuiltin(const CallExpr* call) {
    const FunctionDecl* callee = call ? call->getDirectCallee() : nullptr;
    if (!callee || !callee->getBuiltinID()) return false;
    const IdentifierInfo* id = callee ? callee->getIdentifier() : nullptr;
    if (!id) return false;
    const llvm::StringRef name = id->getName();
    return name == "__builtin_mul_overflow" ||
           name == "__builtin_smul_overflow" ||
           name == "__builtin_smull_overflow" ||
           name == "__builtin_smulll_overflow" ||
           name == "__builtin_umul_overflow" ||
           name == "__builtin_umull_overflow" ||
           name == "__builtin_umulll_overflow";
}

bool isAddOverflowBuiltin(const CallExpr* call) {
    const FunctionDecl* callee = call ? call->getDirectCallee() : nullptr;
    if (!callee || !callee->getBuiltinID()) return false;
    const IdentifierInfo* id = callee ? callee->getIdentifier() : nullptr;
    if (!id) return false;
    const llvm::StringRef name = id->getName();
    return name == "__builtin_add_overflow" ||
           name == "__builtin_sadd_overflow" ||
           name == "__builtin_saddl_overflow" ||
           name == "__builtin_saddll_overflow" ||
           name == "__builtin_uadd_overflow" ||
           name == "__builtin_uaddl_overflow" ||
           name == "__builtin_uaddll_overflow";
}

bool isCheckedOverflowBuiltin(const CallExpr* call) {
    return isMulOverflowBuiltin(call) || isAddOverflowBuiltin(call);
}

const VarDecl* checkedOverflowOutput(const CallExpr* call) {
    if (!isCheckedOverflowBuiltin(call) || call->getNumArgs() < 3)
        return nullptr;
    const VarDecl* output = addressedIntegerVar(call->getArg(2));
    return output && output->getType()->isUnsignedIntegerType()
               ? output
               : nullptr;
}

// Stable local definitions are enough to recover the signed source behind
// an unsigned alias. Any later write or address escape makes the value
// relation unsupported and therefore silent.
struct DefinitionIndex {
    std::map<const VarDecl*, const Expr*> initializers;
    std::map<const VarDecl*, std::vector<const Expr*>> writes;
    std::set<const VarDecl*> unstable;

    static DefinitionIndex build(const FunctionDecl* function) {
        DefinitionIndex result;
        struct Visitor : RecursiveASTVisitor<Visitor> {
            DefinitionIndex& index;
            explicit Visitor(DefinitionIndex& out) : index(out) {}

            bool VisitVarDecl(VarDecl* var) {
                if (var->getType()->isIntegerType() && var->hasInit())
                    index.initializers[var] = var->getInit();
                return true;
            }

            bool VisitBinaryOperator(BinaryOperator* op) {
                if (!op->isAssignmentOp()) return true;
                if (const VarDecl* var = directIntegerVar(op->getLHS())) {
                    index.unstable.insert(var);
                    index.writes[var].push_back(op->getRHS());
                }
                return true;
            }

            bool VisitUnaryOperator(UnaryOperator* op) {
                if (op->isIncrementDecrementOp())
                    if (const VarDecl* var =
                            directIntegerVar(op->getSubExpr()))
                        index.unstable.insert(var);
                return true;
            }

            bool VisitCallExpr(CallExpr* call) {
                for (unsigned i = 0; i < call->getNumArgs(); ++i) {
                    const Expr* arg = call->getArg(i);
                    const VarDecl* var = addressedIntegerVar(arg);
                    if (!var && isWritableReferenceArgument(call, i))
                        var = directIntegerVar(arg);
                    if (var) index.unstable.insert(var);
                }
                return true;
            }
        } visitor(result);
        visitor.TraverseStmt(function->getBody());
        return result;
    }

    const Expr* stableInitializer(const VarDecl* var) const {
        if (!var || unstable.count(var)) return nullptr;
        auto found = initializers.find(var);
        return found == initializers.end() ? nullptr : found->second;
    }
};

bool hasSignedUntrustedOrigin(
    const Expr* expr, const std::set<const VarDecl*>& untrusted,
    const DefinitionIndex& definitions,
    std::set<const VarDecl*>& visiting) {
    if (!expr || !codeskeptic::exprDerivesFromUntrusted(expr, untrusted))
        return false;
    expr = expr->IgnoreParens();
    if (const auto* cast = llvm::dyn_cast<CastExpr>(expr))
        return hasSignedUntrustedOrigin(cast->getSubExpr(), untrusted,
                                        definitions, visiting);
    if (const auto* ref = llvm::dyn_cast<DeclRefExpr>(expr)) {
        const auto* var = llvm::dyn_cast<VarDecl>(ref->getDecl());
        if (!var || !untrusted.count(var)) return false;
        if (var->getType()->isSignedIntegerType()) return true;
        if (!visiting.insert(var).second) return false;
        auto init = definitions.initializers.find(var);
        if (init != definitions.initializers.end() &&
            hasSignedUntrustedOrigin(init->second, untrusted, definitions,
                                     visiting))
            return true;
        auto writes = definitions.writes.find(var);
        if (writes != definitions.writes.end())
            for (const Expr* rhs : writes->second)
                if (hasSignedUntrustedOrigin(rhs, untrusted, definitions,
                                             visiting))
                    return true;
        return false;
    }
    if (const auto* call = llvm::dyn_cast<CallExpr>(expr))
        return call->getType()->isSignedIntegerType();
    if (const auto* unary = llvm::dyn_cast<UnaryOperator>(expr))
        return hasSignedUntrustedOrigin(unary->getSubExpr(), untrusted,
                                        definitions, visiting);
    if (const auto* binary = llvm::dyn_cast<BinaryOperator>(expr))
        return hasSignedUntrustedOrigin(binary->getLHS(), untrusted,
                                        definitions, visiting) ||
               hasSignedUntrustedOrigin(binary->getRHS(), untrusted,
                                        definitions, visiting);
    if (const auto* conditional =
            llvm::dyn_cast<ConditionalOperator>(expr))
        return hasSignedUntrustedOrigin(conditional->getTrueExpr(),
                                        untrusted, definitions, visiting) ||
               hasSignedUntrustedOrigin(conditional->getFalseExpr(),
                                        untrusted, definitions, visiting);
    return false;
}

bool hasSignedUntrustedOrigin(
    const Expr* expr, const std::set<const VarDecl*>& untrusted,
    const DefinitionIndex& definitions) {
    std::set<const VarDecl*> visiting;
    return hasSignedUntrustedOrigin(expr, untrusted, definitions, visiting);
}

struct SignedRange {
    codeskeptic::Interval interval;
    unsigned bits;
};

std::optional<SignedRange> stableSignedRange(
    const Expr* expr, const codeskeptic::IntervalMap& state,
    const std::set<const VarDecl*>& untrusted,
    const DefinitionIndex& definitions, ASTContext& ctx) {
    if (!expr) return std::nullopt;
    expr = expr->IgnoreParens();
    if (const auto* cast = llvm::dyn_cast<CastExpr>(expr)) {
        const CastKind kind = cast->getCastKind();
        if (kind == CK_LValueToRValue || kind == CK_NoOp)
            return stableSignedRange(cast->getSubExpr(), state, untrusted,
                                     definitions, ctx);
        if (kind == CK_IntegralCast &&
            cast->getType()->isSignedIntegerType() &&
            cast->getSubExpr()->getType()->isSignedIntegerType() &&
            ctx.getIntWidth(cast->getType()) >=
                ctx.getIntWidth(cast->getSubExpr()->getType()))
            return stableSignedRange(cast->getSubExpr(), state, untrusted,
                                     definitions, ctx);
        return std::nullopt;
    }

    if (!expr->getType()->isSignedIntegerType()) return std::nullopt;
    if (const auto* ref = llvm::dyn_cast<DeclRefExpr>(expr)) {
        const auto* var = llvm::dyn_cast<VarDecl>(ref->getDecl());
        if (!var || !untrusted.count(var) ||
            definitions.unstable.count(var))
            return std::nullopt;
    } else if (!llvm::isa<CallExpr>(expr) ||
               !codeskeptic::exprDerivesFromUntrusted(expr, untrusted)) {
        return std::nullopt;
    }

    codeskeptic::Interval range =
        codeskeptic::evalInterval(expr, state, &ctx);
    if (range.isEmpty() || range.isTop() || range.loIsInf() ||
        range.hiIsInf())
        return std::nullopt;
    const unsigned bits = ctx.getIntWidth(expr->getType());
    if (bits == 0 || bits > 64) return std::nullopt;
    return SignedRange{range, bits};
}

// The maximum residue of every mathematical integer in a finite signed
// interval after conversion modulo 2^bits. The first UINT_MAX residue lies
// exactly (UINT_MAX - loResidue) steps from the lower endpoint.
llvm::APInt signedIntervalUpperModulo(const codeskeptic::Interval& range,
                                      unsigned bits) {
    const llvm::APInt lower64(
        64, static_cast<uint64_t>(range.lo()));
    const llvm::APInt upper64(
        64, static_cast<uint64_t>(range.hi()));
    const llvm::APInt span = upper64.sext(128) - lower64.sext(128);
    // APInt's constructor checks that the input already fits. Narrowing a
    // negative signed endpoint therefore needs an explicit modular truncation.
    const llvm::APInt lowerResidue = lower64.zextOrTrunc(bits);
    const llvm::APInt maximum = llvm::APInt::getMaxValue(bits);
    const llvm::APInt distance = (maximum - lowerResidue).zext(128);
    if (span.uge(distance)) return maximum;
    return lowerResidue + span.trunc(bits);
}

std::optional<llvm::APInt> signedOriginUpperCorner(
    const Expr* expr, const codeskeptic::IntervalMap& state,
    const std::set<const VarDecl*>& untrusted,
    const DefinitionIndex& definitions, unsigned bits, ASTContext& ctx,
    std::set<const VarDecl*>& visiting) {
    if (!expr || bits == 0 || bits > 64) return std::nullopt;
    expr = expr->IgnoreParens();
    const auto adjust = [bits](llvm::APInt value)
        -> std::optional<llvm::APInt> {
        if (value.getBitWidth() > bits) return std::nullopt;
        return value.zext(bits);
    };

    if (const auto* cast = llvm::dyn_cast<CastExpr>(expr)) {
        const CastKind kind = cast->getCastKind();
        const Expr* sub = cast->getSubExpr()->IgnoreParens();
        if (kind == CK_LValueToRValue || kind == CK_NoOp)
            return signedOriginUpperCorner(sub, state, untrusted,
                                           definitions, bits, ctx, visiting);
        if (kind != CK_IntegralCast) return std::nullopt;

        if (cast->getType()->isUnsignedIntegerType()) {
            const unsigned targetBits = ctx.getIntWidth(cast->getType());
            if (targetBits == 0 || targetBits > 64)
                return std::nullopt;
            if (sub->getType()->isSignedIntegerType()) {
                auto signedRange = stableSignedRange(
                    sub, state, untrusted, definitions, ctx);
                if (!signedRange) return std::nullopt;
                return adjust(signedIntervalUpperModulo(
                    signedRange->interval, targetBits));
            }
            if (sub->getType()->isUnsignedIntegerType()) {
                const unsigned sourceBits = ctx.getIntWidth(sub->getType());
                auto source = signedOriginUpperCorner(
                    sub, state, untrusted, definitions, sourceBits, ctx,
                    visiting);
                if (!source || source->getBitWidth() > targetBits)
                    return std::nullopt;
                return adjust(source->zext(targetBits));
            }
        }
        return std::nullopt;
    }

    if (const auto* ref = llvm::dyn_cast<DeclRefExpr>(expr)) {
        const auto* var = llvm::dyn_cast<VarDecl>(ref->getDecl());
        if (!var || !untrusted.count(var) ||
            !var->getType()->isUnsignedIntegerType() ||
            !visiting.insert(var).second)
            return std::nullopt;
        const Expr* init = definitions.stableInitializer(var);
        if (!init) return std::nullopt;
        const unsigned varBits = ctx.getIntWidth(var->getType());
        auto initial = signedOriginUpperCorner(
            init, state, untrusted, definitions, varBits, ctx, visiting);
        if (!initial) return std::nullopt;
        return adjust(*initial);
    }

    if (expr->getType()->isSignedIntegerType()) {
        auto signedRange = stableSignedRange(
            expr, state, untrusted, definitions, ctx);
        if (!signedRange) return std::nullopt;
        return signedIntervalUpperModulo(signedRange->interval, bits);
    }
    return std::nullopt;
}

std::optional<llvm::APInt> signedOriginUpperCorner(
    const Expr* expr, const codeskeptic::IntervalMap& state,
    const std::set<const VarDecl*>& untrusted,
    const DefinitionIndex& definitions, unsigned bits, ASTContext& ctx) {
    std::set<const VarDecl*> visiting;
    return signedOriginUpperCorner(expr, state, untrusted, definitions,
                                   bits, ctx, visiting);
}

bool multiplyCornerExceeds(
    const Expr* lhs, const Expr* rhs, unsigned bits,
    const codeskeptic::IntervalMap& state,
    const std::set<const VarDecl*>& untrusted,
    const DefinitionIndex& definitions, ASTContext& ctx) {
    if (bits == 0 || bits > 64) return false;
    const unsigned wideBits = bits * 2;
    const auto cornerExceeds = [&](const Expr* valueExpr,
                                   const Expr* factorExpr) {
        if (!codeskeptic::exprDerivesFromUntrusted(valueExpr, untrusted))
            return false;
        auto factor = constantUnsigned(factorExpr, bits, ctx);
        if (!factor || factor->ule(llvm::APInt(bits, 1))) return false;

        std::optional<llvm::APInt> upper;
        if (hasSignedUntrustedOrigin(valueExpr, untrusted, definitions))
            upper = signedOriginUpperCorner(
                valueExpr, state, untrusted, definitions, bits, ctx);
        else
            upper = unsignedUpperCorner(valueExpr, state, bits, ctx);
        if (!upper) return false;

        const llvm::APInt product =
            upper->zext(wideBits) * factor->zext(wideBits);
        const llvm::APInt maximum =
            llvm::APInt::getMaxValue(bits).zext(wideBits);
        return product.ugt(maximum);
    };
    return cornerExceeds(lhs, rhs) || cornerExceeds(rhs, lhs);
}

bool wrapsUnsigned64Multiply(
    const BinaryOperator* op, const codeskeptic::IntervalMap& state,
    const std::set<const VarDecl*>& untrusted,
    const DefinitionIndex& definitions, ASTContext& ctx) {
    constexpr unsigned kBits = 64;
    if (!op || op->getOpcode() != BO_Mul ||
        ctx.getIntWidth(op->getType()) != kBits)
        return false;
    return multiplyCornerExceeds(op->getLHS(), op->getRHS(), kBits, state,
                                 untrusted, definitions, ctx);
}

// MAX64-offset cannot be represented by the shared signed interval domain.
// Keep a small unsigned domain local to allocation addition: no changes to
// multiplication, shared provenance, or checked-arithmetic builtin semantics.
class AllocationAddRanges {
    static constexpr uint64_t kMax = std::numeric_limits<uint64_t>::max();
    struct Range {
        uint64_t lo = 0, hi = kMax;
        bool operator==(const Range& other) const {
            return lo == other.lo && hi == other.hi;
        }
    };

public:
    struct State {
        // Absence is the full unsigned range, NOT an unreachable predecessor.
        std::map<const VarDecl*, Range> ranges;
        bool unreachable = false;
        bool operator!=(const State& other) const {
            return unreachable != other.unreachable || ranges != other.ranges;
        }
    };

    explicit AllocationAddRanges(const FunctionDecl* fn) {
        // An alias can write long after it is formed. Every later call or
        // indirect write invalidates bounds for possibly escaped variables.
        // This index carries no initializer/range facts across CFG edges.
        struct Escapes : RecursiveASTVisitor<Escapes> {
            std::set<const VarDecl*>& vars;
            explicit Escapes(std::set<const VarDecl*>& out) : vars(out) {}
            void referenceTargets(const Stmt* stmt) {
                if (!stmt) return;
                if (const auto* ref = llvm::dyn_cast<DeclRefExpr>(stmt))
                    if (auto* var = llvm::dyn_cast<VarDecl>(ref->getDecl());
                        var && var->getType()->isIntegerType())
                        vars.insert(var);
                for (const auto* child : stmt->children()) referenceTargets(child);
            }
            bool VisitUnaryOperator(UnaryOperator* op) {
                if (op->getOpcode() == UO_AddrOf)
                    if (auto* var = directIntegerVar(op->getSubExpr()))
                        vars.insert(var);
                return true;
            }
            bool VisitVarDecl(VarDecl* var) {
                if (var->getType()->isReferenceType() && var->hasInit())
                    referenceTargets(var->getInit());
                return true;
            }
            bool VisitCallExpr(CallExpr* call) {
                codeskeptic::forEachNonConstRefArg(call, [&](const Expr* arg) {
                    referenceTargets(arg);
                });
                return true;
            }
            bool VisitLambdaExpr(LambdaExpr* expr) {
                for (const auto& capture : expr->captures())
                    if (capture.capturesVariable() &&
                        capture.getCaptureKind() == LCK_ByRef)
                        if (auto* var = llvm::dyn_cast<VarDecl>(capture.getCapturedVar()))
                            vars.insert(var);
                return true;
            }
        } visitor(escaped_);
        visitor.TraverseStmt(fn->getBody());
    }

    State initialState() const { return {}; }
    unsigned latticeHeight() const { return 8; }

    State merge(const State& lhs, const State& rhs) const {
        if (lhs.unreachable) return rhs;
        if (rhs.unreachable) return lhs;
        State result;
        for (const auto& [var, range] : lhs.ranges) {
            auto other = rhs.ranges.find(var);
            if (other != rhs.ranges.end())
                put(result, var, {std::min(range.lo, other->second.lo),
                                  std::max(range.hi, other->second.hi)});
        }
        return result;
    }

    State transfer(const Stmt* stmt, const State& input, ASTContext& ctx) const {
        State out = input;
        if (out.unreachable) return out;
        if (const auto* decl = llvm::dyn_cast<DeclStmt>(stmt)) {
            for (const Decl* item : decl->decls()) {
                const auto* var = llvm::dyn_cast<VarDecl>(item);
                if (isWideVar(var, ctx))
                    put(out, var, rangeOf(var->getInit(), out, ctx));
            }
        } else if (const auto* op = llvm::dyn_cast<BinaryOperator>(stmt)) {
            if (op->isAssignmentOp()) {
                Range value;
                if (op->getOpcode() == BO_Assign)
                    value = rangeOf(op->getRHS(), input, ctx);
                else if (op->getOpcode() == BO_AddAssign &&
                         wideVar(op->getLHS(), ctx))
                    value = add(rangeOf(op->getLHS(), input, ctx),
                                rangeOf(op->getRHS(), input, ctx));
                else if (op->getOpcode() == BO_MulAssign &&
                         wideVar(op->getLHS(), ctx))
                    value = multiply(rangeOf(op->getLHS(), input, ctx),
                                     rangeOf(op->getRHS(), input, ctx));
                invalidateWrite(out, op->getLHS());
                if (const auto* var = wideVar(op->getLHS(), ctx))
                    put(out, var, value);
            }
        } else if (const auto* op = llvm::dyn_cast<UnaryOperator>(stmt)) {
            if (op->isIncrementDecrementOp()) {
                const auto* var = wideVar(op->getSubExpr(), ctx);
                const Range value = op->isIncrementOp() && var
                                        ? add(get(input, var), {1, 1}) : Range{};
                invalidateWrite(out, op->getSubExpr());
                if (var) put(out, var, value);
            }
        } else if (llvm::isa<CallExpr>(stmt) || llvm::isa<AsmStmt>(stmt)) {
            invalidateEscapes(out);
        }
        return out;
    }

    void widen(State& state) const {
        // Widening must never turn an unknown/loop-mutated value into a bound.
        state.ranges.clear();
    }

    void refineOnEdge(const Stmt* condition, bool isTrue, State& state,
                      ASTContext& ctx) const {
        if (state.unreachable) return;
        const auto* expr = llvm::dyn_cast_or_null<Expr>(condition);
        if (!expr) return;
        expr = expr->IgnoreParens();
        if (const auto* unary = llvm::dyn_cast<UnaryOperator>(expr)) {
            if (unary->getOpcode() == UO_LNot)
                refineOnEdge(unary->getSubExpr(), !isTrue, state, ctx);
            return;
        }
        const auto* compare = llvm::dyn_cast<BinaryOperator>(expr);
        if (!compare) return;
        auto opcode = compare->getOpcode();
        if ((opcode == BO_LAnd && isTrue) || (opcode == BO_LOr && !isTrue)) {
            refineOnEdge(compare->getLHS(), isTrue, state, ctx);
            refineOnEdge(compare->getRHS(), isTrue, state, ctx);
            return;
        }
        if (!compare->isComparisonOp()) return;
        const VarDecl* var = wideVar(compare->getLHS(), ctx);
        const Expr* constant = compare->getRHS();
        if (!var) {
            var = wideVar(compare->getRHS(), ctx);
            constant = compare->getLHS();
            switch (opcode) {
                case BO_LT: opcode = BO_GT; break;
                case BO_LE: opcode = BO_GE; break;
                case BO_GT: opcode = BO_LT; break;
                case BO_GE: opcode = BO_LE; break;
                default: break;
            }
        }
        // Do not strip narrowing/signed casts: those comparisons do not
        // constrain the original uint64 variable in the same ordering.
        if (!var) return;
        auto limit = constantUnsigned(constant, 64, ctx);
        if (!limit) return;
        if (!isTrue) {
            switch (opcode) {
                case BO_LT: opcode = BO_GE; break;
                case BO_LE: opcode = BO_GT; break;
                case BO_GT: opcode = BO_LE; break;
                case BO_GE: opcode = BO_LT; break;
                case BO_EQ: opcode = BO_NE; break;
                case BO_NE: opcode = BO_EQ; break;
                default: break;
            }
        }
        const uint64_t bound = limit->getZExtValue();
        Range range = get(state, var);
        switch (opcode) {
            case BO_LT:
                if (bound == 0) { makeUnreachable(state); return; }
                range.hi = std::min(range.hi, bound - 1); break;
            case BO_LE: range.hi = std::min(range.hi, bound); break;
            case BO_GT:
                if (bound == kMax) { makeUnreachable(state); return; }
                range.lo = std::max(range.lo, bound + 1); break;
            case BO_GE: range.lo = std::max(range.lo, bound); break;
            case BO_EQ:
                range.lo = std::max(range.lo, bound);
                range.hi = std::min(range.hi, bound); break;
            case BO_NE:
                if (range.lo == bound) {
                    if (bound == kMax) { makeUnreachable(state); return; }
                    ++range.lo;
                }
                if (range.hi == bound) {
                    if (bound == 0) { makeUnreachable(state); return; }
                    --range.hi;
                }
                break;
            default: return;
        }
        if (range.lo > range.hi) makeUnreachable(state);
        else put(state, var, range);
    }

    void onStatement(const Stmt* stmt, const State& before,
                     const State&, ASTContext&) { atStmt_[stmt] = before; }

    bool wraps(const BinaryOperator* op, const codeskeptic::IntervalMap& numeric,
               const std::set<const VarDecl*>& untrusted,
               const DefinitionIndex& definitions, ASTContext& ctx) const {
        auto found = atStmt_.find(op);
        if (found == atStmt_.end() || found->second.unreachable) return false;
        const auto exceeds = [&](const Expr* value, const Expr* offset) {
            if (!codeskeptic::exprDerivesFromUntrusted(value, untrusted))
                return false;
            auto constant = constantUnsigned(offset, 64, ctx);
            if (!constant || constant->isZero()) return false;
            std::optional<llvm::APInt> upper;
            const bool signedOrigin =
                hasSignedUntrustedOrigin(value, untrusted, definitions);
            if (signedOrigin)
                upper = signedOriginUpperCorner(
                    value, numeric, untrusted, definitions, 64, ctx);
            else
                upper = unsignedUpperCorner(value, numeric, 64, ctx);
            const llvm::APInt wideUpper(64, rangeOf(value, found->second, ctx).hi);
            // Preserve bounds for compound operands as well as direct aliases.
            // An aliased write can invalidate the shared numeric bound, even
            // when that stale value occurs inside n*constant or n+constant.
            // The signed-origin model's unsupported cases remain unsupported.
            if (!signedOrigin && referencesEscape(value)) upper = wideUpper;
            else if (upper && wideUpper.ult(*upper)) upper = wideUpper;
            return upper &&
                   (upper->zext(128) + constant->zext(128))
                       .ugt(llvm::APInt::getMaxValue(64).zext(128));
        };
        return exceeds(op->getLHS(), op->getRHS()) ||
               exceeds(op->getRHS(), op->getLHS());
    }

    bool checkedAddOverflows(const CallExpr* call, unsigned outputBits,
                             const codeskeptic::IntervalMap& numeric,
                             const std::set<const VarDecl*>& untrusted,
                             const DefinitionIndex& definitions,
                             ASTContext& ctx) const {
        if (!call || call->getNumArgs() != 3 || outputBits == 0 || outputBits > 64)
            return false;
        auto snapshot = atStmt_.find(call);
        if (snapshot == atStmt_.end() || snapshot->second.unreachable) return false;
        const auto exceeds = [&](const Expr* value, const Expr* offset) {
            if (!codeskeptic::exprDerivesFromUntrusted(value, untrusted)) return false;
            auto constant = mathematicalConstant(offset, ctx);
            if (!constant) return false; // A second unknown is not a finite witness.
            auto input = checkedInputRange(value, snapshot->second, numeric,
                                            untrusted, definitions, ctx);
            if (!input) return false;
            const llvm::APInt lower = input->lo + *constant;
            const llvm::APInt upper = input->hi + *constant;
            const llvm::APInt maximum = llvm::APInt::getMaxValue(outputBits).zext(128);
            // Generic builtin operands retain their signedness/width until
            // AFTER the infinite-precision sum. Do not truncate to outputBits.
            return lower.isNegative() || upper.sgt(maximum);
        };
        return exceeds(call->getArg(0), call->getArg(1)) ||
               exceeds(call->getArg(1), call->getArg(0));
    }

private:
    struct MathematicalRange { llvm::APInt lo, hi; };

    static std::optional<llvm::APInt> mathematicalConstant(const Expr* expr,
                                                           ASTContext& ctx) {
        if (!expr || !expr->getType()->isIntegerType() ||
            ctx.getIntWidth(expr->getType()) > 64) return std::nullopt;
        Expr::EvalResult result;
        if (!expr->EvaluateAsInt(result, ctx) || !result.Val.isInt()) return std::nullopt;
        const llvm::APSInt& value = result.Val.getInt();
        return value.isSigned() ? value.sext(128) : value.zext(128);
    }

    std::optional<MathematicalRange> checkedInputRange(
        const Expr* expr, const State& state, const codeskeptic::IntervalMap& numeric,
        const std::set<const VarDecl*>& untrusted, const DefinitionIndex& definitions,
        ASTContext& ctx, bool requireStable = false, unsigned depth = 0) const {
        if (!expr || depth > 16 || !expr->getType()->isIntegerType()) return std::nullopt;
        const unsigned bits = ctx.getIntWidth(expr->getType());
        if (bits == 0 || bits > 64) return std::nullopt;
        if (auto constant = mathematicalConstant(expr, ctx))
            return MathematicalRange{*constant, *constant};
        expr = expr->IgnoreParens();
        if (const auto* cast = llvm::dyn_cast<CastExpr>(expr)) {
            auto input = checkedInputRange(cast->getSubExpr(), state, numeric,
                untrusted, definitions, ctx, requireStable, depth + 1);
            if (!input) return std::nullopt;
            if (cast->getCastKind() == CK_LValueToRValue || cast->getCastKind() == CK_NoOp)
                return input;
            if (cast->getCastKind() == CK_IntegralToBoolean) {
                const llvm::APInt zero(128, 0), one(128, 1);
                if (input->lo.isZero() && input->hi.isZero())
                    return MathematicalRange{zero, zero};
                if (input->lo.sgt(zero) || input->hi.slt(zero))
                    return MathematicalRange{one, one};
                return MathematicalRange{zero, one};
            }
            if (cast->getCastKind() != CK_IntegralCast) return std::nullopt;
            const bool isUnsigned = cast->getType()->isUnsignedIntegerType();
            const llvm::APInt low = isUnsigned ? input->lo.trunc(bits).zext(128)
                                               : input->lo.trunc(bits).sext(128);
            const llvm::APInt high = isUnsigned ? input->hi.trunc(bits).zext(128)
                                                : input->hi.trunc(bits).sext(128);
            const llvm::APInt span = input->hi - input->lo;
            if (span.ult(llvm::APInt::getMaxValue(bits).zext(128)) && low.sle(high))
                return MathematicalRange{low, high};
            return isUnsigned
                ? MathematicalRange{llvm::APInt(128, 0), llvm::APInt::getMaxValue(bits).zext(128)}
                : MathematicalRange{llvm::APInt::getSignedMinValue(bits).sext(128),
                                    llvm::APInt::getSignedMaxValue(bits).sext(128)};
        }
        if (const auto* ref = llvm::dyn_cast<DeclRefExpr>(expr)) {
            const auto* var = llvm::dyn_cast<VarDecl>(ref->getDecl());
            if (var && requireStable &&
                (definitions.unstable.count(var) || escaped_.count(var))) return std::nullopt;
            if (var && expr->getType()->isUnsignedIntegerType() &&
                hasSignedUntrustedOrigin(expr, untrusted, definitions)) {
                const Expr* init = definitions.stableInitializer(var);
                if (!init) return std::nullopt;
                auto range = checkedInputRange(init, state, numeric, untrusted,
                    definitions, ctx, true, depth + 1);
                if (range) {
                    Range bound = rangeOf(expr, state, ctx);
                    // Narrow unsigned aliases get path guards from the shared
                    // numeric domain; the uint64 sidecar alone cannot retain them.
                    const auto interval = codeskeptic::evalInterval(expr, numeric, &ctx);
                    if (interval.isEmpty()) return std::nullopt;
                    if (!referencesEscape(expr)) {
                        if (!interval.loIsInf() && interval.lo() >= 0)
                            bound.lo = std::max(bound.lo, static_cast<uint64_t>(interval.lo()));
                        if (!interval.hiIsInf() && interval.hi() >= 0)
                            bound.hi = std::min(bound.hi, static_cast<uint64_t>(interval.hi()));
                    }
                    const llvm::APInt low(128, bound.lo), high(128, bound.hi);
                    if (low.sgt(range->lo)) range->lo = low;
                    if (high.slt(range->hi)) range->hi = high;
                    if (range->lo.sgt(range->hi)) return std::nullopt;
                }
                return range;
            }
        }
        const auto interval = codeskeptic::evalInterval(expr, numeric, &ctx);
        if (interval.isEmpty()) return std::nullopt;
        if (expr->getType()->isUnsignedIntegerType()) {
            Range range = rangeOf(expr, state, ctx);
            if (!referencesEscape(expr)) {
                if (!interval.loIsInf() && interval.lo() >= 0)
                    range.lo = std::max(range.lo, static_cast<uint64_t>(interval.lo()));
                if (!interval.hiIsInf() && interval.hi() >= 0)
                    range.hi = std::min(range.hi, static_cast<uint64_t>(interval.hi()));
            }
            if (range.lo > range.hi) return std::nullopt;
            return MathematicalRange{llvm::APInt(128, range.lo), llvm::APInt(128, range.hi)};
        }
        if (referencesEscape(expr) || interval.loIsInf() || interval.hiIsInf())
            return std::nullopt;
        return MathematicalRange{
            llvm::APInt(64, static_cast<uint64_t>(interval.lo())).sext(128),
            llvm::APInt(64, static_cast<uint64_t>(interval.hi())).sext(128)};
    }

    static bool isWideVar(const VarDecl* var, ASTContext& ctx) {
        return var && var->getType()->isUnsignedIntegerType() &&
               !var->getType().isVolatileQualified() &&
               ctx.getIntWidth(var->getType()) == 64;
    }
    static const VarDecl* wideVar(const Expr* expr, ASTContext& ctx) {
        if (!expr) return nullptr;
        expr = expr->IgnoreParens();
        while (const auto* cast = llvm::dyn_cast<CastExpr>(expr)) {
            const Expr* sub = cast->getSubExpr()->IgnoreParens();
            if (!cast->getType()->isUnsignedIntegerType() ||
                !sub->getType()->isUnsignedIntegerType() ||
                ctx.getIntWidth(cast->getType()) != 64 ||
                ctx.getIntWidth(sub->getType()) != 64)
                return nullptr;
            expr = sub;
        }
        const auto* ref = llvm::dyn_cast<DeclRefExpr>(expr);
        const auto* var = ref ? llvm::dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
        return isWideVar(var, ctx) ? var : nullptr;
    }
    static Range get(const State& state, const VarDecl* var) {
        auto it = state.ranges.find(var);
        return it == state.ranges.end() ? Range{} : it->second;
    }
    static void put(State& state, const VarDecl* var, Range range) {
        if (range.lo == 0 && range.hi == kMax) state.ranges.erase(var);
        else state.ranges[var] = range;
    }
    static void makeUnreachable(State& state) {
        state.unreachable = true;
        state.ranges.clear();
    }
    static Range add(Range lhs, Range rhs) {
        const llvm::APInt lo = llvm::APInt(128, lhs.lo) + llvm::APInt(128, rhs.lo);
        const llvm::APInt hi = llvm::APInt(128, lhs.hi) + llvm::APInt(128, rhs.hi);
        // Crossing the modular cut produces two intervals; keep the full
        // range. If both endpoints wrap, their residues are ordered again.
        if (lo.lshr(64) != hi.lshr(64)) return {};
        return {lo.trunc(64).getZExtValue(), hi.trunc(64).getZExtValue()};
    }
    static Range multiply(Range lhs, Range rhs) {
        const llvm::APInt lo = llvm::APInt(128, lhs.lo) * llvm::APInt(128, rhs.lo);
        const llvm::APInt hi = llvm::APInt(128, lhs.hi) * llvm::APInt(128, rhs.hi);
        if (lo.lshr(64) != hi.lshr(64)) return {};
        return {lo.trunc(64).getZExtValue(), hi.trunc(64).getZExtValue()};
    }
    static Range rangeOf(const Expr* expr, const State& state, ASTContext& ctx) {
        if (!expr) return {};
        if (auto constant = constantUnsigned(expr, 64, ctx)) {
            const uint64_t value = constant->getZExtValue();
            return {value, value};
        }
        if (auto* var = wideVar(expr, ctx)) return get(state, var);
        // Preserve the real width through unsigned widening conversions.
        const Expr* source = expr->IgnoreParens();
        while (const auto* cast = llvm::dyn_cast<CastExpr>(source)) {
            const Expr* sub = cast->getSubExpr()->IgnoreParens();
            if (!cast->getType()->isUnsignedIntegerType() ||
                !sub->getType()->isUnsignedIntegerType() ||
                ctx.getIntWidth(sub->getType()) > ctx.getIntWidth(cast->getType()))
                break;
            source = sub;
        }
        if (source != expr->IgnoreParens()) return rangeOf(source, state, ctx);
        if (const auto* op = llvm::dyn_cast<BinaryOperator>(source);
            op && op->getType()->isUnsignedIntegerType() &&
            ctx.getIntWidth(op->getType()) == 64) {
            if (op->getOpcode() == BO_Add)
                return add(rangeOf(op->getLHS(), state, ctx),
                           rangeOf(op->getRHS(), state, ctx));
            if (op->getOpcode() == BO_Mul)
                return multiply(rangeOf(op->getLHS(), state, ctx),
                                rangeOf(op->getRHS(), state, ctx));
        }
        if (source->getType()->isUnsignedIntegerType()) {
            unsigned width = ctx.getIntWidth(source->getType());
            if (width && width < 64)
                return {0, llvm::APInt::getMaxValue(width).getZExtValue()};
        }
        return {};
    }
    void invalidateEscapes(State& state) const {
        for (const auto* var : escaped_) state.ranges.erase(var);
    }
    void invalidateWrite(State& state, const Expr* lhs) const {
        if (const auto* ref = llvm::dyn_cast<DeclRefExpr>(lhs->IgnoreParens())) {
            const auto* var = llvm::dyn_cast<VarDecl>(ref->getDecl());
            if (var && !var->getType()->isReferenceType()) {
                state.ranges.erase(var);
                return; // A direct store cannot write an unrelated escaped n.
            }
        }
        if (const auto* target = directIntegerVar(lhs)) state.ranges.erase(target);
        invalidateEscapes(state);
    }
    bool referencesEscape(const Stmt* stmt) const {
        if (!stmt) return false;
        if (const auto* ref = llvm::dyn_cast<DeclRefExpr>(stmt))
            if (const auto* var = llvm::dyn_cast<VarDecl>(ref->getDecl());
                var && escaped_.count(var)) return true;
        for (const Stmt* child : stmt->children())
            if (referencesEscape(child)) return true;
        return false;
    }
    std::set<const VarDecl*> escaped_;
    std::map<const Stmt*, State> atStmt_;
};

bool isAllocatorSizeArgument(const CallExpr* call, unsigned index) {
    if (!call || index >= call->getNumArgs()) return false;
    if (codeskeptic::isAllocatorCall(call)) return true;

    const auto& registry = codeskeptic::SummaryRegistry::instance();
    if (!registry.stable()) return false;
    const auto* summary = registry.lookup(call);
    return summary &&
           summary->paramAllocatorSize(index) ==
               codeskeptic::SummaryRegistry::ParamAllocatorSize::Sink;
}

SizeInventory collectSizeInventory(const FunctionDecl* fn,
                                   ASTContext& ctx) {
    struct V : RecursiveASTVisitor<V> {
        ASTContext& ctx;
        SizeInventory inventory;
        // Every Expr under a proven allocator-size argument. Recorded on
        // the way down (RAV is pre-order) so nested arithmetic is already
        // known to be a size sub-expression when visited.
        std::map<const Expr*, const CallExpr*> allocArgExprs;
        explicit V(ASTContext& c) : ctx(c) {}

        bool VisitCallExpr(CallExpr* call) {
            if (isMulOverflowBuiltin(call))
                inventory.hasMulOverflow = true;
            if (isAddOverflowBuiltin(call))
                inventory.hasAddOverflow = true;
            for (unsigned i = 0; i < call->getNumArgs(); ++i) {
                if (!isAllocatorSizeArgument(call, i)) continue;
                const Expr* argument = call->getArg(i);
                if (const VarDecl* var = directIntegerVar(argument))
                    inventory.checked.push_back({call, var});
                std::function<void(const Stmt*)> mark =
                    [&](const Stmt* stmt) {
                        if (!stmt) return;
                        if (const auto* expr = llvm::dyn_cast<Expr>(stmt))
                            allocArgExprs[expr] = call;
                        for (const Stmt* child : stmt->children())
                            mark(child);
                    };
                mark(argument);
            }
            return true;
        }

        bool VisitBinaryOperator(BinaryOperator* op) {
            if (op->getOpcode() != BO_Mul && op->getOpcode() != BO_Add)
                return true;
            auto sink = allocArgExprs.find(op);
            if (sink == allocArgExprs.end()) return true;
            QualType type = op->getType();
            if (!type->isIntegerType() ||
                !type->isUnsignedIntegerType())
                return true;
            const unsigned bits = ctx.getIntWidth(type);
            if (bits == 0 || bits > 64) return true;
            inventory.arithmetic.push_back({op, bits, sink->second});
            return true;
        }
    } visitor(ctx);
    visitor.TraverseStmt(fn->getBody());
    return visitor.inventory;
}

// Either operand of the arithmetic derives from a declared untrusted
// source. Reuses the shared provenance predicate over the origin set
// recorded at this program point.
bool hasUntrustedOperand(const BinaryOperator* op,
                         const std::set<const VarDecl*>& untrusted) {
    return codeskeptic::exprDerivesFromUntrusted(op->getLHS(), untrusted) ||
           codeskeptic::exprDerivesFromUntrusted(op->getRHS(), untrusted);
}

// The shared interval engine intentionally treats wrapping casts
// conservatively. For this rule only, an unsigned comparison is equivalent
// to its signed source after a prior edge has proved that source non-negative.
class AllocIntervalAnalysis {
public:
    using State = codeskeptic::IntervalState;

    AllocIntervalAnalysis(
        std::set<const VarDecl*> vars,
        std::map<const VarDecl*, codeskeptic::Interval> seeds)
        : base_(std::move(vars), std::move(seeds)) {}

    State initialState() const { return base_.initialState(); }
    unsigned latticeHeight() const { return base_.latticeHeight(); }
    State merge(const State& lhs, const State& rhs) const {
        return base_.merge(lhs, rhs);
    }
    State transfer(const Stmt* stmt, const State& input,
                   ASTContext& ctx) const {
        return base_.transfer(stmt, input, ctx);
    }
    void widen(State& state) const { base_.widen(state); }

    void refineOnEdge(const Stmt* condition, bool isTrueBranch,
                      State& state, ASTContext& ctx) const {
        base_.refineOnEdge(condition, isTrueBranch, state, ctx);
        const auto* expr = llvm::dyn_cast_or_null<Expr>(condition);
        if (!expr) return;
        expr = expr->IgnoreParenImpCasts();
        const auto* compare = llvm::dyn_cast<BinaryOperator>(expr);
        if (!compare || !compare->isComparisonOp()) return;

        BinaryOperatorKind opcode = compare->getOpcode();
        const VarDecl* var = nonNegativeSignedCast(
            compare->getLHS(), state, ctx);
        const Expr* constant = compare->getRHS();
        if (!var) {
            var = nonNegativeSignedCast(compare->getRHS(), state, ctx);
            constant = compare->getLHS();
            opcode = swapComparison(opcode);
        }
        if (!var) return;
        auto limit = int64Constant(constant, ctx);
        if (!limit) return;
        if (!isTrueBranch) opcode = negateComparison(opcode);

        auto found = state.iv.find(var);
        if (found == state.iv.end()) return;
        switch (opcode) {
            case BO_LT:
                found->second = found->second.constrainLt(*limit);
                break;
            case BO_LE:
                found->second = found->second.constrainLe(*limit);
                break;
            case BO_GT:
                found->second = found->second.constrainGt(*limit);
                break;
            case BO_GE:
                found->second = found->second.constrainGe(*limit);
                break;
            case BO_EQ:
                found->second = found->second.constrainEq(*limit);
                break;
            case BO_NE:
                found->second = found->second.constrainNe(*limit);
                break;
            default:
                break;
        }
    }

    void onStatement(const Stmt* stmt, const State& before,
                     const State&, ASTContext&) {
        atStmt_[stmt] = before;
    }

    const codeskeptic::IntervalMap* stateAt(const Stmt* stmt) const {
        auto found = atStmt_.find(stmt);
        return found == atStmt_.end() ? nullptr : &found->second.iv;
    }

    const std::set<const VarDecl*>* untrustedAt(
        const Stmt* stmt) const {
        auto found = atStmt_.find(stmt);
        return found == atStmt_.end() ? nullptr
                                      : &found->second.untrusted;
    }

private:
    static BinaryOperatorKind swapComparison(BinaryOperatorKind opcode) {
        switch (opcode) {
            case BO_LT: return BO_GT;
            case BO_LE: return BO_GE;
            case BO_GT: return BO_LT;
            case BO_GE: return BO_LE;
            default: return opcode;
        }
    }

    static BinaryOperatorKind negateComparison(BinaryOperatorKind opcode) {
        switch (opcode) {
            case BO_LT: return BO_GE;
            case BO_LE: return BO_GT;
            case BO_GT: return BO_LE;
            case BO_GE: return BO_LT;
            case BO_EQ: return BO_NE;
            case BO_NE: return BO_EQ;
            default: return opcode;
        }
    }

    static std::optional<int64_t> int64Constant(const Expr* expr,
                                                ASTContext& ctx) {
        if (!expr) return std::nullopt;
        Expr::EvalResult result;
        if (!expr->EvaluateAsInt(result, ctx) || !result.Val.isInt())
            return std::nullopt;
        const llvm::APSInt& value = result.Val.getInt();
        if (value.isSigned())
            return value.isSignedIntN(64)
                       ? std::optional<int64_t>(value.getSExtValue())
                       : std::nullopt;
        return value.getActiveBits() <= 63
                   ? std::optional<int64_t>(
                         static_cast<int64_t>(value.getZExtValue()))
                   : std::nullopt;
    }

    static const VarDecl* nonNegativeSignedCast(
        const Expr* expr, const State& state, ASTContext& ctx) {
        if (!expr) return nullptr;
        expr = expr->IgnoreParens();
        const auto* cast = llvm::dyn_cast<CastExpr>(expr);
        if (!cast ||
            (cast->getCastKind() != CK_IntegralCast &&
             cast->getCastKind() != CK_NoOp) ||
            !cast->getType()->isUnsignedIntegerType())
            return nullptr;
        const VarDecl* var = directIntegerVar(cast->getSubExpr());
        if (!var || !var->getType()->isSignedIntegerType() ||
            ctx.getIntWidth(cast->getType()) <
                ctx.getIntWidth(var->getType()))
            return nullptr;
        auto found = state.iv.find(var);
        if (found == state.iv.end() || found->second.isEmpty() ||
            found->second.loIsInf() || found->second.lo() < 0)
            return nullptr;
        return var;
    }

    codeskeptic::IntervalAnalysis base_;
    std::map<const Stmt*, State> atStmt_;
};

// Checked calls own outputs; status variables only identify the matching call
// and polarity. Capture calls at their actual CFG element, never by searching
// an arbitrary enclosing initializer (which may negate/discard the result).
class CheckedArithmeticAnalysis {
public:
    struct Status {
        const CallExpr* call;
        bool trueMeansOverflow;
        bool operator==(const Status& other) const {
            return call == other.call && trueMeansOverflow == other.trueMeansOverflow;
        }
    };
    using Origins = std::map<const CallExpr*, bool>; // true = proved safe
    using Targets = std::set<const VarDecl*>;
    struct State {
        std::map<const VarDecl*, Origins> outputs;
        std::map<const VarDecl*, Status> statuses;
        std::map<const VarDecl*, Targets> aliases;
        Targets escaped;
        bool operator==(const State& other) const {
            return outputs == other.outputs && statuses == other.statuses &&
                   aliases == other.aliases && escaped == other.escaped;
        }
        bool operator!=(const State& other) const { return !(*this == other); }
    };

    State initialState() const { return {}; }
    unsigned latticeHeight() const { return 32; }

    State merge(const State& lhs, const State& rhs) const {
        State result = lhs;
        // An output may originate from a checked call on only one path. Keep
        // that possible origin, with safety required on every path carrying it.
        for (const auto& [var, origins] : rhs.outputs)
            for (const auto& [call, safe] : origins) {
                auto& merged = result.outputs[var];
                auto found = merged.find(call);
                if (found == merged.end()) merged[call] = safe;
                else found->second = found->second && safe;
            }
        result.statuses.clear();
        for (const auto& [var, status] : lhs.statuses) {
            auto found = rhs.statuses.find(var);
            if (found != rhs.statuses.end() && found->second == status)
                result.statuses.emplace(var, status);
        }
        for (const auto& [var, targets] : rhs.aliases)
            result.aliases[var].insert(targets.begin(), targets.end());
        result.escaped.insert(rhs.escaped.begin(), rhs.escaped.end());
        return result;
    }

    State transfer(const Stmt* stmt, const State& input, ASTContext& ctx) const {
        State out = input;
        const auto forget = [&](const VarDecl* var) {
            out.outputs.erase(var);
            out.statuses.erase(var);
        };
        const auto write = [&](const Expr* lhs) {
            Targets targets = writtenTargets(lhs, input);
            if (targets.empty() && !plainStorage(lhs))
                targets = input.escaped;
            for (const auto* var : targets) forget(var);
            return targets;
        };
        const auto bindValue = [&](const VarDecl* var, const Expr* value) {
            if (!var || var->getType().isVolatileQualified()) return;
            if (var->hasGlobalStorage()) out.escaped.insert(var);
            if (auto status = statusFor(value, input, ctx)) out.statuses.emplace(var, *status);
            if (var->getType()->isUnsignedIntegerType())
                if (const auto* origin = copiedOutput(value, input, ctx, var->getType()))
                    out.outputs[var] = *origin;
        };
        const auto bindAlias = [&](const VarDecl* var, Targets targets) {
            if (var->hasGlobalStorage())
                out.escaped.insert(targets.begin(), targets.end());
            out.aliases[var] = std::move(targets);
        };

        if (const auto* call = llvm::dyn_cast<CallExpr>(stmt)) {
            if (isCheckedOverflowBuiltin(call)) {
                // A loop can execute the same AST call again. Old status or
                // copied-output facts must not certify the new invocation.
                for (auto it = out.statuses.begin(); it != out.statuses.end();)
                    if (it->second.call == call) it = out.statuses.erase(it);
                    else ++it;
                for (auto& [var, origins] : out.outputs) origins.erase(call);
                if (const VarDecl* output = checkedOverflowOutput(call)) {
                    forget(output);
                    out.outputs[output] = {{call, false}};
                    if (output->hasGlobalStorage()) out.escaped.insert(output);
                } else if (call->getNumArgs() >= 3) {
                    for (const auto* var : pointedTargets(call->getArg(2), input)) forget(var);
                }
            } else {
                // A callee may retain an escaped pointer/reference and write
                // it on a later call, even after a fresh checked result exists.
                for (const auto* var : input.escaped) forget(var);
                Targets targets;
                for (const Expr* arg : call->arguments()) {
                    auto current = pointedTargets(arg, input);
                    targets.insert(current.begin(), current.end());
                }
                codeskeptic::forEachNonConstRefArg(call, [&](const Expr* arg) {
                    auto current = writtenTargets(arg, input);
                    targets.insert(current.begin(), current.end());
                });
                for (const auto* var : targets) forget(var);
                out.escaped.insert(targets.begin(), targets.end());
            }
        } else if (const auto* decls = llvm::dyn_cast<DeclStmt>(stmt)) {
            for (const Decl* decl : decls->decls()) {
                const auto* var = llvm::dyn_cast<VarDecl>(decl);
                if (!var) continue;
                forget(var);
                if (var->getType()->isPointerType())
                    bindAlias(var, pointedTargets(var->getInit(), input));
                else if (var->getType()->isReferenceType())
                    bindAlias(var, writtenTargets(var->getInit(), input));
                else if (var->hasInit())
                    bindValue(var, var->getInit());
            }
        } else if (const auto* assign = llvm::dyn_cast<BinaryOperator>(stmt);
                   assign && assign->isAssignmentOp()) {
            Targets targets = write(assign->getLHS());
            if (assign->getOpcode() == BO_Assign) {
                if (const auto* var = plainStorage(assign->getLHS());
                    var && var->getType()->isPointerType())
                    bindAlias(var, pointedTargets(assign->getRHS(), input));
                if (targets.size() == 1)
                    bindValue(*targets.begin(), assign->getRHS());
            }
        } else if (const auto* unary = llvm::dyn_cast<UnaryOperator>(stmt);
                   unary && unary->isIncrementDecrementOp()) {
            write(unary->getSubExpr());
        } else if (llvm::isa<AsmStmt>(stmt)) {
            out.outputs.clear();
            out.statuses.clear();
        }
        return out;
    }

    void refineOnEdge(const Stmt* condition, bool isTrue, State& state,
                      ASTContext& ctx) const {
        const auto* expr = llvm::dyn_cast_or_null<Expr>(condition);
        if (!expr) return;
        expr = expr->IgnoreParenImpCasts();
        if (const auto* logic = llvm::dyn_cast<BinaryOperator>(expr);
            logic && ((logic->getOpcode() == BO_LAnd && isTrue) ||
                      (logic->getOpcode() == BO_LOr && !isTrue))) {
            refineOnEdge(logic->getLHS(), isTrue, state, ctx);
            refineOnEdge(logic->getRHS(), isTrue, state, ctx);
            return;
        }
        auto status = statusFor(expr, state, ctx);
        if (!status) return;
        const bool safe = isTrue != status->trueMeansOverflow;
        for (auto& [var, origins] : state.outputs) {
            auto found = origins.find(status->call);
            if (found != origins.end()) found->second = safe;
        }
    }

    void widen(State& state) const {
        state.outputs.clear();
        state.statuses.clear();
        // Alias/escape sets are finite may-facts; forgetting them could make a
        // later aliased write incorrectly preserve a newly created status.
    }
    void onStatement(const Stmt* stmt, const State& before, const State&, ASTContext&) {
        atStmt_[stmt] = before;
    }
    const State* stateAt(const Stmt* stmt) const {
        auto found = atStmt_.find(stmt);
        return found == atStmt_.end() ? nullptr : &found->second;
    }

private:
    static const VarDecl* plainStorage(const Expr* expr) {
        if (!expr) return nullptr;
        const auto* ref = llvm::dyn_cast<DeclRefExpr>(expr->IgnoreParenImpCasts());
        const auto* var = ref ? llvm::dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
        return var && !var->getType()->isReferenceType() ? var : nullptr;
    }
    static Targets writtenTargets(const Expr* expr, const State& state) {
        if (!expr) return {};
        expr = expr->IgnoreParenCasts();
        if (const auto* ref = llvm::dyn_cast<DeclRefExpr>(expr)) {
            const auto* var = llvm::dyn_cast<VarDecl>(ref->getDecl());
            if (!var) return {};
            if (var->getType()->isIntegerType()) return {var};
            auto alias = state.aliases.find(var);
            return var->getType()->isReferenceType() && alias != state.aliases.end()
                       ? alias->second : Targets{};
        }
        if (const auto* op = llvm::dyn_cast<UnaryOperator>(expr);
            op && op->getOpcode() == UO_Deref) return pointedTargets(op->getSubExpr(), state);
        if (const auto* subscript = llvm::dyn_cast<ArraySubscriptExpr>(expr))
            return pointedTargets(subscript->getBase(), state);
        if (const auto* select = llvm::dyn_cast<ConditionalOperator>(expr)) {
            auto result = writtenTargets(select->getTrueExpr(), state);
            auto other = writtenTargets(select->getFalseExpr(), state);
            result.insert(other.begin(), other.end());
            return result;
        }
        return {};
    }
    static Targets pointedTargets(const Expr* expr, const State& state) {
        if (!expr || !expr->getType()->isPointerType()) return {};
        expr = expr->IgnoreParenCasts();
        if (const auto* op = llvm::dyn_cast<UnaryOperator>(expr);
            op && op->getOpcode() == UO_AddrOf) return writtenTargets(op->getSubExpr(), state);
        if (const auto* ref = llvm::dyn_cast<DeclRefExpr>(expr)) {
            const auto* var = llvm::dyn_cast<VarDecl>(ref->getDecl());
            auto alias = state.aliases.find(var);
            return alias == state.aliases.end() ? Targets{} : alias->second;
        }
        if (const auto* select = llvm::dyn_cast<ConditionalOperator>(expr)) {
            auto result = pointedTargets(select->getTrueExpr(), state);
            auto other = pointedTargets(select->getFalseExpr(), state);
            result.insert(other.begin(), other.end());
            return result;
        }
        if (const auto* comma = llvm::dyn_cast<BinaryOperator>(expr);
            comma && comma->getOpcode() == BO_Comma)
            return pointedTargets(comma->getRHS(), state);
        if (const auto* offset = llvm::dyn_cast<BinaryOperator>(expr);
            offset && (offset->getOpcode() == BO_Add || offset->getOpcode() == BO_Sub)) {
            // Keep may-alias targets through pointer offsets, including p+0.
            auto result = pointedTargets(offset->getLHS(), state);
            auto other = pointedTargets(offset->getRHS(), state);
            result.insert(other.begin(), other.end());
            return result;
        }
        return {};
    }
    static const Origins* copiedOutput(const Expr* expr, const State& state,
                                       ASTContext& ctx, QualType destination) {
        if (!expr || !destination->isUnsignedIntegerType()) return nullptr;
        expr = expr->IgnoreParens();
        while (const auto* cast = llvm::dyn_cast<CastExpr>(expr)) {
            const Expr* sub = cast->getSubExpr()->IgnoreParens();
            if (!cast->getType()->isUnsignedIntegerType() ||
                !sub->getType()->isUnsignedIntegerType() ||
                ctx.getIntWidth(cast->getType()) < ctx.getIntWidth(sub->getType()))
                return nullptr;
            expr = sub;
        }
        if (!expr->getType()->isUnsignedIntegerType() ||
            ctx.getIntWidth(destination) < ctx.getIntWidth(expr->getType())) return nullptr;
        const auto targets = writtenTargets(expr, state);
        if (targets.size() != 1) return nullptr;
        auto found = state.outputs.find(*targets.begin());
        return found == state.outputs.end() ? nullptr : &found->second;
    }
    static std::optional<Status> statusFor(const Expr* expr, const State& state,
                                           ASTContext& ctx, unsigned depth = 0) {
        if (!expr || depth > 24) return std::nullopt;
        expr = expr->IgnoreParens();
        if (expr->getType().isVolatileQualified()) return std::nullopt;
        if (const auto* cast = llvm::dyn_cast<CastExpr>(expr)) {
            const auto kind = cast->getCastKind();
            if (kind != CK_LValueToRValue && kind != CK_NoOp &&
                kind != CK_IntegralCast && kind != CK_IntegralToBoolean) return std::nullopt;
            return statusFor(cast->getSubExpr(), state, ctx, depth + 1);
        }
        if (const auto* call = llvm::dyn_cast<CallExpr>(expr);
            call && checkedOverflowOutput(call)) {
            for (const auto& [var, origins] : state.outputs)
                if (origins.count(call)) return Status{call, true};
            return std::nullopt;
        }
        if (llvm::isa<DeclRefExpr>(expr)) {
            auto targets = writtenTargets(expr, state);
            if (targets.size() != 1) return std::nullopt;
            auto found = state.statuses.find(*targets.begin());
            if (found != state.statuses.end()) return found->second;
        }
        if (const auto* unary = llvm::dyn_cast<UnaryOperator>(expr);
            unary && unary->getOpcode() == UO_LNot) {
            auto status = statusFor(unary->getSubExpr(), state, ctx, depth + 1);
            if (status) status->trueMeansOverflow = !status->trueMeansOverflow;
            return status;
        }
        if (const auto* compare = llvm::dyn_cast<BinaryOperator>(expr)) {
            if (compare->getOpcode() == BO_Comma)
                return statusFor(compare->getRHS(), state, ctx, depth + 1);
            if (compare->getOpcode() != BO_EQ && compare->getOpcode() != BO_NE)
                return std::nullopt;
            const auto bit = [&](const Expr* value) -> std::optional<bool> {
                Expr::EvalResult result;
                if (value->EvaluateAsInt(result, ctx) && result.Val.isInt()) {
                    if (result.Val.getInt() == 0) return false;
                    if (result.Val.getInt() == 1) return true;
                }
                return std::nullopt;
            };
            auto constant = bit(compare->getRHS());
            auto status = statusFor(compare->getLHS(), state, ctx, depth + 1);
            if (!constant || !status) {
                constant = bit(compare->getLHS());
                status = statusFor(compare->getRHS(), state, ctx, depth + 1);
            }
            if (constant && status) {
                const bool preserves = (compare->getOpcode() == BO_EQ) == *constant;
                if (!preserves) status->trueMeansOverflow = !status->trueMeansOverflow;
                return status;
            }
        }
        return std::nullopt;
    }
    std::map<const Stmt*, State> atStmt_;
};

const VarDecl* directPointerVar(const Expr* expr) {
    if (!expr) return nullptr;
    const auto* reference =
        llvm::dyn_cast<DeclRefExpr>(expr->IgnoreParenImpCasts());
    const auto* var =
        reference ? llvm::dyn_cast<VarDecl>(reference->getDecl()) : nullptr;
    return var && var->getType()->isPointerType() ? var : nullptr;
}

bool containsStmt(const Stmt* root, const Stmt* target) {
    if (!root || !target) return false;
    if (root == target) return true;
    for (const Stmt* child : root->children())
        if (containsStmt(child, target)) return true;
    return false;
}

const VarDecl* allocationBinding(const FunctionDecl* function,
                                 const CallExpr* allocator) {
    const VarDecl* binding = nullptr;
    bool ambiguous = false;
    struct Visitor : RecursiveASTVisitor<Visitor> {
        const CallExpr* allocator;
        const VarDecl*& binding;
        bool& ambiguous;

        Visitor(const CallExpr* target, const VarDecl*& result,
                bool& hasAmbiguity)
            : allocator(target), binding(result),
              ambiguous(hasAmbiguity) {}

        void record(const VarDecl* candidate) {
            if (!candidate || !candidate->getType()->isPointerType()) return;
            if (binding && binding != candidate)
                ambiguous = true;
            else
                binding = candidate;
        }

        bool VisitVarDecl(VarDecl* var) {
            if (var->hasInit() && containsStmt(var->getInit(), allocator))
                record(var);
            return true;
        }

        bool VisitBinaryOperator(BinaryOperator* op) {
            if (op->getOpcode() == BO_Assign &&
                containsStmt(op->getRHS(), allocator))
                record(directPointerVar(op->getLHS()));
            return true;
        }
    } visitor{allocator, binding, ambiguous};
    visitor.TraverseStmt(const_cast<Stmt*>(function->getBody()));
    return ambiguous ? nullptr : binding;
}

std::set<const VarDecl*> referencedUntrusted(
    const Stmt* root, const std::set<const VarDecl*>& untrusted) {
    std::set<const VarDecl*> found;
    struct Visitor : RecursiveASTVisitor<Visitor> {
        const std::set<const VarDecl*>& untrusted;
        std::set<const VarDecl*>& found;

        Visitor(const std::set<const VarDecl*>& origins,
                std::set<const VarDecl*>& result)
            : untrusted(origins), found(result) {}

        bool VisitDeclRefExpr(DeclRefExpr* reference) {
            const auto* var =
                llvm::dyn_cast<VarDecl>(reference->getDecl());
            if (var && untrusted.count(var)) found.insert(var);
            return true;
        }
    } visitor{untrusted, found};
    if (root) visitor.TraverseStmt(const_cast<Stmt*>(root));
    return found;
}

bool sharesUntrustedOrigin(
    const Stmt* allocation, const Stmt* access,
    const std::set<const VarDecl*>& untrusted) {
    const auto allocationOrigins =
        referencedUntrusted(allocation, untrusted);
    if (allocationOrigins.empty()) return false;
    const auto accessOrigins = referencedUntrusted(access, untrusted);
    for (const VarDecl* origin : allocationOrigins)
        if (accessOrigins.count(origin)) return true;
    return false;
}

bool bindingStableUntil(
    const FunctionDecl* function, const VarDecl* binding,
    const CallExpr* allocator, const Stmt* evidence,
    const SourceManager& sm) {
    if (!function || !binding || !allocator || !evidence) return false;
    const SourceLocation begin =
        sm.getExpansionLoc(allocator->getExprLoc());
    const SourceLocation end =
        sm.getExpansionLoc(evidence->getBeginLoc());
    if (begin.isInvalid() || end.isInvalid() ||
        !sm.isBeforeInTranslationUnit(begin, end))
        return false;

    bool unstable = false;
    struct Visitor : RecursiveASTVisitor<Visitor> {
        const VarDecl* binding;
        const SourceManager& sm;
        SourceLocation begin;
        SourceLocation end;
        bool& unstable;

        Visitor(const VarDecl* tracked, const SourceManager& sourceManager,
                SourceLocation first, SourceLocation last, bool& changed)
            : binding(tracked), sm(sourceManager), begin(first), end(last),
              unstable(changed) {}

        bool between(SourceLocation location) const {
            if (location.isInvalid()) return false;
            const SourceLocation point = sm.getExpansionLoc(location);
            return point.isValid() &&
                   sm.isBeforeInTranslationUnit(begin, point) &&
                   sm.isBeforeInTranslationUnit(point, end);
        }

        bool VisitBinaryOperator(BinaryOperator* op) {
            if (op->isAssignmentOp() &&
                directPointerVar(op->getLHS()) == binding &&
                between(op->getOperatorLoc()))
                unstable = true;
            return !unstable;
        }

        bool VisitUnaryOperator(UnaryOperator* op) {
            const UnaryOperatorKind kind = op->getOpcode();
            const bool changesBinding = op->isIncrementDecrementOp();
            const bool escapesBinding = kind == UO_AddrOf;
            if ((changesBinding || escapesBinding) &&
                directPointerVar(op->getSubExpr()) == binding &&
                between(op->getOperatorLoc()))
                unstable = true;
            return !unstable;
        }
    } visitor{binding, sm, begin, end, unstable};
    visitor.TraverseStmt(const_cast<Stmt*>(function->getBody()));
    return !unstable;
}

std::optional<SourceLocation> findAccessEvidence(
    const FunctionDecl* function, const CallExpr* allocator,
    const Stmt* allocationOrigin,
    const std::set<const VarDecl*>& untrusted, ASTContext& ctx) {
    const VarDecl* binding = allocationBinding(function, allocator);
    if (!binding) return std::nullopt;

    const SourceManager& sm = ctx.getSourceManager();
    SourceLocation best;
    const auto record = [&](const Stmt* evidence, SourceLocation location) {
        if (!evidence || location.isInvalid()) return;
        SourceLocation candidate = sm.getExpansionLoc(location);
        SourceLocation allocation =
            sm.getExpansionLoc(allocator->getExprLoc());
        if (!sm.isBeforeInTranslationUnit(allocation, candidate) ||
            !bindingStableUntil(function, binding, allocator, evidence, sm))
            return;
        if (best.isInvalid() ||
            sm.isBeforeInTranslationUnit(candidate, best))
            best = candidate;
    };

    struct Visitor : RecursiveASTVisitor<Visitor> {
        const VarDecl* binding;
        const Stmt* allocationOrigin;
        const std::set<const VarDecl*>& untrusted;
        std::function<void(const Stmt*, SourceLocation)> record;

        Visitor(
            const VarDecl* allocationBinding, const Stmt* origin,
            const std::set<const VarDecl*>& untrustedOrigins,
            std::function<void(const Stmt*, SourceLocation)> recorder)
            : binding(allocationBinding), allocationOrigin(origin),
              untrusted(untrustedOrigins), record(std::move(recorder)) {}

        bool VisitArraySubscriptExpr(ArraySubscriptExpr* access) {
            if (directPointerVar(access->getBase()) == binding &&
                sharesUntrustedOrigin(
                    allocationOrigin, access->getIdx(), untrusted))
                record(access, access->getExprLoc());
            return true;
        }

        bool VisitCallExpr(CallExpr* call) {
            const FunctionDecl* callee = call->getDirectCallee();
            const IdentifierInfo* id =
                callee ? callee->getIdentifier() : nullptr;
            if (!id || call->getNumArgs() < 3) return true;
            const llvm::StringRef name = id->getName();
            if (name != "memcpy" && name != "memmove" &&
                name != "memset")
                return true;
            if (directPointerVar(call->getArg(0)) == binding &&
                sharesUntrustedOrigin(
                    allocationOrigin, call->getArg(2), untrusted))
                record(call, call->getExprLoc());
            return true;
        }
    } visitor{binding, allocationOrigin, untrusted, record};
    visitor.TraverseStmt(const_cast<Stmt*>(function->getBody()));
    return best.isValid() ? std::optional<SourceLocation>(best)
                          : std::nullopt;
}

void analyzeFunction(const FunctionDecl* fn, ASTContext& ctx,
                     const codeskeptic::ParamIntervalMap& paramMap,
                     codeskeptic::DiagnosticList& results) {
    if (!fn->hasBody()) return;

    SizeInventory inventory = collectSizeInventory(fn, ctx);
    if (inventory.arithmetic.empty() && inventory.checked.empty()) return;
    const DefinitionIndex definitions = DefinitionIndex::build(fn);

    AllocIntervalAnalysis analysis(
        collectIntVars(fn), codeskeptic::paramSeeds(paramMap, fn));
    auto df = codeskeptic::runDataflow(fn, ctx, analysis);
    if (!df.converged)
        codeskeptic::CoverageReport::instance().recordDataflowFailure(
            fn->getQualifiedNameAsString(), df.failure);

    std::optional<AllocationAddRanges> addRanges;
    bool addConverged = false;
    if (inventory.hasAddOverflow ||
        std::any_of(inventory.arithmetic.begin(), inventory.arithmetic.end(),
                    [](const SizeSite& site) {
                        return site.bits == 64 && site.op->getOpcode() == BO_Add;
                    })) {
        addRanges.emplace(fn);
        auto addDf = codeskeptic::runDataflow(fn, ctx, *addRanges);
        addConverged = addDf.converged && df.converged;
        if (!addDf.converged)
            codeskeptic::CoverageReport::instance().recordDataflowFailure(
                fn->getQualifiedNameAsString(), addDf.failure);
    }

    CheckedArithmeticAnalysis checkedAnalysis;
    bool checkedRan = false;
    if ((inventory.hasMulOverflow || inventory.hasAddOverflow) && !inventory.checked.empty()) {
        auto checkedDf =
            codeskeptic::runDataflow(fn, ctx, checkedAnalysis);
        checkedRan = checkedDf.converged && df.converged;
        if (!checkedDf.converged)
            codeskeptic::CoverageReport::instance().recordDataflowFailure(
                fn->getQualifiedNameAsString(), checkedDf.failure);
    }

    const SourceManager& sm = ctx.getSourceManager();
    std::set<unsigned> reportedLines;
    static const std::set<const VarDecl*> kNoUntrusted;
    const auto report = [&](
        SourceLocation source, QualType type, const CallExpr* allocator,
        const Stmt* allocationOrigin,
        const std::set<const VarDecl*>& untrusted) {
        SourceLocation loc = sm.getExpansionLoc(source);
        const unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines.insert(line).second) return;

        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "alloc-size-overflow";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = codeskeptic::Severity::Warning;
        diag.message = codeskeptic::msg(
            codeskeptic::MsgId::AllocSizeOverflow, type.getAsString());
        if (allocator) {
            auto access = findAccessEvidence(
                fn, allocator, allocationOrigin, untrusted, ctx);
            if (access) {
                SourceLocation noteLoc = sm.getExpansionLoc(*access);
                codeskeptic::TraceNote note;
                note.file = sm.getFilename(noteLoc).str();
                note.line = sm.getSpellingLineNumber(noteLoc);
                note.column = sm.getSpellingColumnNumber(noteLoc);
                note.message =
                    "allocation result is accessed with the same "
                    "untrusted length";
                diag.notes.push_back(std::move(note));
            }
        }
        results.push_back(std::move(diag));
    };

    for (const SizeSite& site : inventory.arithmetic) {
        const codeskeptic::IntervalMap* state =
            analysis.stateAt(site.op);
        if (!state) continue;
        const std::set<const VarDecl*>* untrusted =
            analysis.untrustedAt(site.op);
        if (!untrusted) untrusted = &kNoUntrusted;
        if (!hasUntrustedOperand(site.op, *untrusted)) continue;

        codeskeptic::Interval interval =
            codeskeptic::evalInterval(site.op, *state, &ctx);
        bool wraps = wrapsUnsignedFinite(interval, site.bits);
        if (!wraps && site.bits == 64)
            wraps = wrapsUnsigned64Multiply(
                site.op, *state, *untrusted, definitions, ctx);
        if (!wraps && site.bits == 64 && site.op->getOpcode() == BO_Add &&
            addConverged)
            wraps = addRanges->wraps(site.op, *state, *untrusted, definitions, ctx);
        if (!wraps) continue;
        report(site.op->getOperatorLoc(), site.op->getType(),
               site.allocator, site.op, *untrusted);
    }

    if (!checkedRan) return;
    for (const CheckedSizeSite& site : inventory.checked) {
        const CheckedArithmeticAnalysis::State* relationState =
            checkedAnalysis.stateAt(site.allocator);
        if (!relationState) continue;
        auto relation = relationState->outputs.find(site.sizeVar);
        if (relation == relationState->outputs.end()) continue;
        for (const auto& [checked, safe] : relation->second) {
            if (!checked || checked->getNumArgs() < 3 || safe)
                continue;

            const Stmt* keys[3] = {
                checked, checked->getArg(0), checked->getArg(1)};
            const codeskeptic::IntervalMap* state = nullptr;
            const std::set<const VarDecl*>* untrusted = nullptr;
            for (const Stmt* key : keys) {
                if (!state) state = analysis.stateAt(key);
                if (!untrusted) untrusted = analysis.untrustedAt(key);
            }
            if (!state) continue;
            if (!untrusted) untrusted = &kNoUntrusted;

            const VarDecl* originalOutput = checkedOverflowOutput(checked);
            if (!originalOutput) continue;
            QualType resultType = originalOutput->getType();
            if (!resultType->isUnsignedIntegerType()) continue;
            const unsigned bits = ctx.getIntWidth(resultType);
            bool overflow = false;
            if (isMulOverflowBuiltin(checked))
                overflow = multiplyCornerExceeds(checked->getArg(0), checked->getArg(1),
                    bits, *state, *untrusted, definitions, ctx);
            else if (isAddOverflowBuiltin(checked) && addConverged)
                overflow = addRanges->checkedAddOverflows(checked, bits, *state,
                    *untrusted, definitions, ctx);
            if (!overflow) continue;
            report(checked->getExprLoc(), resultType, site.allocator,
                   checked, *untrusted);
        }
    }
}
class AllocSizeOverflowCallback : public MatchFinder::MatchCallback {
public:
    AllocSizeOverflowCallback(const codeskeptic::ParamIntervalMap& paramMap,
                              codeskeptic::DiagnosticList& results)
        : paramMap_(paramMap), results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* fn = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!fn || !fn->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(fn->getLocation())) return;
        if (!codeskeptic::functionFilterAllows(*fn)) return;
        if (!codeskeptic::lineFilterAllows(*fn, sm)) return;

        analyzeFunction(fn, *result.Context, paramMap_, results_);
    }

private:
    const codeskeptic::ParamIntervalMap& paramMap_;
    codeskeptic::DiagnosticList& results_;
};

} // anonymous namespace

namespace codeskeptic {

void AllocSizeOverflowRule::check(clang::ASTContext& ctx,
                                  DiagnosticList& results) {
    const ParamIntervalMap& paramMap = ParamIntervalCache::instance().get(ctx);

    MatchFinder finder;
    AllocSizeOverflowCallback callback(paramMap, results);

    auto matcher =
        functionDecl(isDefinition(), hasBody(anything())).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace codeskeptic
