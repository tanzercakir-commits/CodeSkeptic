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

// Keep this slice on genuinely unsigned provenance. Casts are transparent
// to the shared origin bit, so inspect the visible origin leaves before
// admitting the full 64-bit unsigned corner. Signed/unsigned chains are
// handled by the next Phase 6 slice with their own evidence rules.
bool hasOnlyUnsignedUntrustedOrigins(
    const Expr* expr, const std::set<const VarDecl*>& untrusted) {
    if (!codeskeptic::exprDerivesFromUntrusted(expr, untrusted)) return true;
    expr = expr->IgnoreParenCasts();
    if (const auto* ref = llvm::dyn_cast<DeclRefExpr>(expr)) {
        const auto* var = llvm::dyn_cast<VarDecl>(ref->getDecl());
        return var && untrusted.count(var) > 0 &&
               var->getType()->isUnsignedIntegerType();
    }
    if (const auto* call = llvm::dyn_cast<CallExpr>(expr))
        return call->getType()->isUnsignedIntegerType();
    if (const auto* unary = llvm::dyn_cast<UnaryOperator>(expr))
        return hasOnlyUnsignedUntrustedOrigins(unary->getSubExpr(),
                                               untrusted);
    if (const auto* binary = llvm::dyn_cast<BinaryOperator>(expr))
        return hasOnlyUnsignedUntrustedOrigins(binary->getLHS(), untrusted) &&
               hasOnlyUnsignedUntrustedOrigins(binary->getRHS(), untrusted);
    if (const auto* conditional =
            llvm::dyn_cast<ConditionalOperator>(expr))
        return hasOnlyUnsignedUntrustedOrigins(conditional->getTrueExpr(),
                                               untrusted) &&
               hasOnlyUnsignedUntrustedOrigins(conditional->getFalseExpr(),
                                               untrusted);
    return false;
}

// A 64-bit product cannot be represented by the int64 interval. Widen both
// operand corners to 128 bits and compare the mathematical product with the
// 64-bit result maximum. One side must be a finite constant and the other
// must carry declared untrusted provenance; guards are honored through the
// finite upper bound recorded in the existing path-sensitive state.
bool wrapsUnsigned64Multiply(
    const BinaryOperator* op, const codeskeptic::IntervalMap& state,
    const std::set<const VarDecl*>& untrusted, ASTContext& ctx) {
    constexpr unsigned kBits = 64;
    constexpr unsigned kWideBits = kBits * 2;
    if (!op || op->getOpcode() != BO_Mul ||
        ctx.getIntWidth(op->getType()) != kBits)
        return false;

    const auto cornerExceeds = [&](const Expr* valueExpr,
                                   const Expr* factorExpr) {
        if (!codeskeptic::exprDerivesFromUntrusted(valueExpr, untrusted) ||
            !hasOnlyUnsignedUntrustedOrigins(valueExpr, untrusted))
            return false;
        auto factor = constantUnsigned(factorExpr, kBits, ctx);
        if (!factor || factor->ule(llvm::APInt(kBits, 1))) return false;
        auto upper = unsignedUpperCorner(valueExpr, state, kBits, ctx);
        if (!upper) return false;

        const llvm::APInt product =
            upper->zext(kWideBits) * factor->zext(kWideBits);
        const llvm::APInt maximum =
            llvm::APInt::getMaxValue(kBits).zext(kWideBits);
        return product.ugt(maximum);
    };

    return cornerExceeds(op->getLHS(), op->getRHS()) ||
           cornerExceeds(op->getRHS(), op->getLHS());
}

std::vector<SizeSite> collectSizeSites(const FunctionDecl* fn,
                                       ASTContext& ctx) {
    struct V : RecursiveASTVisitor<V> {
        ASTContext& ctx;
        std::vector<SizeSite> sites;
        // Every Expr under an allocator call's arguments. Recorded on
        // the way down (RAV is pre-order) so a nested arithmetic is
        // already known to be a size sub-expression when visited.
        std::set<const Expr*> allocArgExprs;
        explicit V(ASTContext& c) : ctx(c) {}

        bool VisitCallExpr(CallExpr* call) {
            if (!codeskeptic::isAllocatorCall(call)) return true;
            for (const Expr* arg : call->arguments()) {
                std::function<void(const Stmt*)> mark = [&](const Stmt* s) {
                    if (!s) return;
                    if (const auto* e = llvm::dyn_cast<Expr>(s))
                        allocArgExprs.insert(e);
                    for (const Stmt* c : s->children()) mark(c);
                };
                mark(arg);
            }
            return true;
        }

        bool VisitBinaryOperator(BinaryOperator* op) {
            if (op->getOpcode() != BO_Mul && op->getOpcode() != BO_Add)
                return true;
            if (!allocArgExprs.count(op)) return true;  // not a size arg
            QualType t = op->getType();
            if (!t->isIntegerType() || !t->isUnsignedIntegerType())
                return true;  // signed is IntOverflowRule's question
            unsigned bits = ctx.getIntWidth(t);
            if (bits == 0 || bits > 64) return true;
            sites.push_back({op, bits});
            return true;
        }
    } v(ctx);
    v.TraverseStmt(fn->getBody());
    return v.sites;
}

// Either operand of the arithmetic derives from a declared untrusted
// source. Reuses the shared provenance predicate over the origin set
// recorded at this program point.
bool hasUntrustedOperand(const BinaryOperator* op,
                         const std::set<const VarDecl*>& untrusted) {
    return codeskeptic::exprDerivesFromUntrusted(op->getLHS(), untrusted) ||
           codeskeptic::exprDerivesFromUntrusted(op->getRHS(), untrusted);
}

void analyzeFunction(const FunctionDecl* fn, ASTContext& ctx,
                     const codeskeptic::ParamIntervalMap& paramMap,
                     codeskeptic::DiagnosticList& results) {
    if (!fn->hasBody()) return;

    auto sites = collectSizeSites(fn, ctx);
    if (sites.empty()) return;

    codeskeptic::IntervalAnalysis analysis(
        collectIntVars(fn), codeskeptic::paramSeeds(paramMap, fn));
    auto df = codeskeptic::runDataflow(fn, ctx, analysis);
    if (!df.converged)
        codeskeptic::CoverageReport::instance().recordDataflowFailure(
            fn->getQualifiedNameAsString(), df.failure);

    const SourceManager& sm = ctx.getSourceManager();
    std::set<unsigned> reportedLines;
    static const std::set<const VarDecl*> kNoUntrusted;

    for (const auto& site : sites) {
        const codeskeptic::IntervalMap* st = analysis.stateAt(site.op);
        if (!st) continue;  // unreached / unrecorded
        const std::set<const VarDecl*>* utr =
            analysis.untrustedAt(site.op);
        if (!utr) utr = &kNoUntrusted;

        // Gate: an untrusted operand (provenance, never guessed).
        if (!hasUntrustedOperand(site.op, *utr)) continue;

        // Gate: the size PROVABLY wraps its unsigned result type. The
        // shared interval handles sub-64 arithmetic. For a 64-bit multiply,
        // only a declared untrusted corner plus a finite constant factor is
        // admitted; path guards can narrow that corner back to safety.
        codeskeptic::Interval iv =
            codeskeptic::evalInterval(site.op, *st, &ctx);
        bool wraps = wrapsUnsignedFinite(iv, site.bits);
        if (!wraps && site.bits == 64)
            wraps = wrapsUnsigned64Multiply(site.op, *st, *utr, ctx);
        if (!wraps) continue;

        SourceLocation loc = sm.getExpansionLoc(site.op->getOperatorLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines.insert(line).second) continue;

        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "alloc-size-overflow";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = codeskeptic::Severity::Warning;
        diag.message = codeskeptic::msg(
            codeskeptic::MsgId::AllocSizeOverflow, site.op->getType().getAsString());
        results.push_back(std::move(diag));
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
