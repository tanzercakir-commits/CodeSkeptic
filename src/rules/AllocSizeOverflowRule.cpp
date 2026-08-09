#include "rules/AllocSizeOverflowRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/AllocFunctions.h"
#include "engine/CoverageReport.h"
#include "engine/DataflowEngine.h"
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

#include <functional>
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
};

struct CheckedSizeSite {
    const CallExpr* allocator;
    const VarDecl* sizeVar;
};

struct SizeInventory {
    std::vector<SizeSite> arithmetic;
    std::vector<CheckedSizeSite> checked;
    bool hasMulOverflow = false;
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

const CallExpr* findMulOverflowCall(const Stmt* root) {
    const CallExpr* found = nullptr;
    bool ambiguous = false;
    std::function<void(const Stmt*)> visit = [&](const Stmt* stmt) {
        if (!stmt || ambiguous) return;
        if (const auto* call = llvm::dyn_cast<CallExpr>(stmt);
            call && isMulOverflowBuiltin(call)) {
            if (found && found != call)
                ambiguous = true;
            else
                found = call;
        }
        for (const Stmt* child : stmt->children()) visit(child);
    };
    visit(root);
    return ambiguous ? nullptr : found;
}

const VarDecl* mulOverflowOutput(const CallExpr* call) {
    if (!isMulOverflowBuiltin(call) || call->getNumArgs() < 3)
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
    const llvm::APInt lowerResidue(
        bits, static_cast<uint64_t>(range.lo()));
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

SizeInventory collectSizeInventory(const FunctionDecl* fn,
                                   ASTContext& ctx) {
    struct V : RecursiveASTVisitor<V> {
        ASTContext& ctx;
        SizeInventory inventory;
        // Every Expr under an allocator call's arguments. Recorded on
        // the way down (RAV is pre-order) so a nested arithmetic is
        // already known to be a size sub-expression when visited.
        std::set<const Expr*> allocArgExprs;
        explicit V(ASTContext& c) : ctx(c) {}

        bool VisitCallExpr(CallExpr* call) {
            if (isMulOverflowBuiltin(call))
                inventory.hasMulOverflow = true;
            if (!codeskeptic::isAllocatorCall(call)) return true;
            for (const Expr* arg : call->arguments()) {
                if (const VarDecl* var = directIntegerVar(arg))
                    inventory.checked.push_back({call, var});
                std::function<void(const Stmt*)> mark = [&](const Stmt* s) {
                    if (!s) return;
                    if (const auto* e = llvm::dyn_cast<Expr>(s))
                        allocArgExprs.insert(e);
                    for (const Stmt* child : s->children()) mark(child);
                };
                mark(arg);
            }
            return true;
        }

        bool VisitBinaryOperator(BinaryOperator* op) {
            if (op->getOpcode() != BO_Mul && op->getOpcode() != BO_Add)
                return true;
            if (!allocArgExprs.count(op)) return true;
            QualType type = op->getType();
            if (!type->isIntegerType() ||
                !type->isUnsignedIntegerType())
                return true;
            const unsigned bits = ctx.getIntWidth(type);
            if (bits == 0 || bits > 64) return true;
            inventory.arithmetic.push_back({op, bits});
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

// Tracks only the exact relation created by a compiler checked-multiply
// builtin. A no-overflow edge records safety; every redefinition or address
// escape kills the relation. Missing evidence therefore stays silent.
class CheckedMulAnalysis {
public:
    struct State {
        std::map<const VarDecl*, const CallExpr*> outputs;
        std::map<const VarDecl*, const CallExpr*> statuses;
        std::set<const CallExpr*> safe;

        bool operator==(const State& other) const {
            return outputs == other.outputs && statuses == other.statuses &&
                   safe == other.safe;
        }
        bool operator!=(const State& other) const {
            return !(*this == other);
        }
    };

    State initialState() const { return {}; }
    unsigned latticeHeight() const { return 32; }

    State merge(const State& lhs, const State& rhs) const {
        State merged;
        for (const auto& [var, call] : lhs.outputs) {
            auto found = rhs.outputs.find(var);
            if (found != rhs.outputs.end() && found->second == call)
                merged.outputs[var] = call;
        }
        for (const auto& [var, call] : lhs.statuses) {
            auto found = rhs.statuses.find(var);
            if (found != rhs.statuses.end() && found->second == call)
                merged.statuses[var] = call;
        }
        for (const CallExpr* call : lhs.safe)
            if (rhs.safe.count(call)) merged.safe.insert(call);
        return merged;
    }

    State transfer(const Stmt* stmt, const State& input,
                   ASTContext&) const {
        State output = input;
        const auto forget = [&](const VarDecl* var) {
            if (!var) return;
            output.outputs.erase(var);
            output.statuses.erase(var);
        };

        if (const auto* decls = llvm::dyn_cast<DeclStmt>(stmt))
            for (const Decl* decl : decls->decls())
                if (const auto* var = llvm::dyn_cast<VarDecl>(decl))
                    forget(var);
        if (const auto* assign = llvm::dyn_cast<BinaryOperator>(stmt);
            assign && assign->isAssignmentOp())
            forget(directIntegerVar(assign->getLHS()));
        if (const auto* unary = llvm::dyn_cast<UnaryOperator>(stmt);
            unary && unary->isIncrementDecrementOp())
            forget(directIntegerVar(unary->getSubExpr()));

        if (const auto* call = llvm::dyn_cast<CallExpr>(stmt);
            call && !isMulOverflowBuiltin(call)) {
            for (unsigned i = 0; i < call->getNumArgs(); ++i) {
                const Expr* arg = call->getArg(i);
                forget(addressedIntegerVar(arg));
                if (isWritableReferenceArgument(call, i))
                    forget(directIntegerVar(arg));
            }
        }

        const CallExpr* checked = findMulOverflowCall(stmt);
        const VarDecl* result = mulOverflowOutput(checked);
        if (checked && result) {
            output.outputs[result] = checked;
            output.safe.erase(checked);

            if (const auto* decls = llvm::dyn_cast<DeclStmt>(stmt))
                for (const Decl* decl : decls->decls())
                    if (const auto* var = llvm::dyn_cast<VarDecl>(decl);
                        var && var->hasInit() &&
                        findMulOverflowCall(var->getInit()) == checked)
                        output.statuses[var] = checked;
            if (const auto* assign = llvm::dyn_cast<BinaryOperator>(stmt);
                assign && assign->getOpcode() == BO_Assign &&
                findMulOverflowCall(assign->getRHS()) == checked)
                if (const VarDecl* status =
                        directIntegerVar(assign->getLHS()))
                    output.statuses[status] = checked;
        }
        return output;
    }

    void refineOnEdge(const Stmt* condition, bool isTrueBranch,
                      State& state, ASTContext& ctx) const {
        const auto* expr = llvm::dyn_cast_or_null<Expr>(condition);
        if (!expr) return;
        expr = expr->IgnoreParenImpCasts();
        const CallExpr* call = nullptr;
        bool trueMeansOverflow = true;

        if (const auto* direct = llvm::dyn_cast<CallExpr>(expr);
            direct && isMulOverflowBuiltin(direct)) {
            call = direct;
        } else if (const VarDecl* status = directIntegerVar(expr)) {
            auto found = state.statuses.find(status);
            if (found != state.statuses.end()) call = found->second;
        } else if (const auto* compare =
                       llvm::dyn_cast<BinaryOperator>(expr);
                   compare && (compare->getOpcode() == BO_EQ ||
                               compare->getOpcode() == BO_NE)) {
            const auto isZero = [&](const Expr* value) {
                Expr::EvalResult result;
                return value && value->EvaluateAsInt(result, ctx) &&
                       result.Val.isInt() &&
                       result.Val.getInt() == 0;
            };
            const VarDecl* status = nullptr;
            if (isZero(compare->getRHS()))
                status = directIntegerVar(compare->getLHS());
            else if (isZero(compare->getLHS()))
                status = directIntegerVar(compare->getRHS());
            if (status) {
                auto found = state.statuses.find(status);
                if (found != state.statuses.end()) {
                    call = found->second;
                    trueMeansOverflow = compare->getOpcode() == BO_NE;
                }
            }
        }

        if (!call) return;
        const bool overflowEdge = isTrueBranch == trueMeansOverflow;
        if (overflowEdge)
            state.safe.erase(call);
        else
            state.safe.insert(call);
    }

    void widen(State& state) const { state = {}; }

    void onStatement(const Stmt* stmt, const State& before,
                     const State&, ASTContext&) {
        atStmt_[stmt] = before;
    }

    const State* stateAt(const Stmt* stmt) const {
        auto found = atStmt_.find(stmt);
        return found == atStmt_.end() ? nullptr : &found->second;
    }

private:
    std::map<const Stmt*, State> atStmt_;
};

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

    CheckedMulAnalysis checkedAnalysis;
    bool checkedRan = false;
    if (inventory.hasMulOverflow && !inventory.checked.empty()) {
        auto checkedDf =
            codeskeptic::runDataflow(fn, ctx, checkedAnalysis);
        checkedRan = true;
        if (!checkedDf.converged)
            codeskeptic::CoverageReport::instance().recordDataflowFailure(
                fn->getQualifiedNameAsString(), checkedDf.failure);
    }

    const SourceManager& sm = ctx.getSourceManager();
    std::set<unsigned> reportedLines;
    static const std::set<const VarDecl*> kNoUntrusted;
    const auto report = [&](SourceLocation source, QualType type) {
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
        if (!wraps) continue;
        report(site.op->getOperatorLoc(), site.op->getType());
    }

    if (!checkedRan) return;
    for (const CheckedSizeSite& site : inventory.checked) {
        const CheckedMulAnalysis::State* relationState =
            checkedAnalysis.stateAt(site.allocator);
        if (!relationState) continue;
        auto relation = relationState->outputs.find(site.sizeVar);
        if (relation == relationState->outputs.end()) continue;
        const CallExpr* checked = relation->second;
        if (!checked || checked->getNumArgs() < 3 ||
            relationState->safe.count(checked))
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

        QualType resultType = site.sizeVar->getType();
        if (!resultType->isUnsignedIntegerType()) continue;
        const unsigned bits = ctx.getIntWidth(resultType);
        if (!multiplyCornerExceeds(
                checked->getArg(0), checked->getArg(1), bits, *state,
                *untrusted, definitions, ctx))
            continue;
        report(checked->getExprLoc(), resultType);
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
