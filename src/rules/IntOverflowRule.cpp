#include "rules/IntOverflowRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CoverageReport.h"
#include "engine/DataflowEngine.h"
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

#include <iostream>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// Every integer local and parameter — the interval domain the analysis
// tracks. Reads never mutate a variable's range, so it is enough to seed
// the analysis with the declarations; guards and assignments refine them.
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

// An arithmetic site the rule can prove-and-report (v0.4 recall round:
// grew from "signed sub-64-bit multiplication" to the shapes the
// Juliet FN classification measured addressable — JULIET_FN_CLASS):
//   - signed `*` and `+` at width < 64: the shared Interval dataflow
//     evaluates the result exactly (int64 arithmetic cannot overflow
//     on sub-64 operands) and fitsSignedBits answers the escape query;
//   - the SAME operators at width 64: the int64-based Interval soundly
//     collapses an overflowing result to top(), so the site is proved
//     from the two OPERAND intervals instead — corner arithmetic in
//     __int128 (evalEscapes64 below);
//   - a result implicitly narrowed into a smaller SIGNED type
//     (`char r = d + 1;` — the add happens in int, the wrap happens on
//     the store): the proof runs against the DESTINATION width.
//     Unsigned destinations wrap by definition (not UB) and stay out
//     of scope, as do explicit casts (stated programmer intent).
struct ArithSite {
    const BinaryOperator* op;
    unsigned bits;           // the width the result must fit
    bool narrowing;          // narrowed-store site (message wording + width)
    std::string narrowType;  // destination type name (narrowing only)
};

// The two operands of `*` are the SAME variable (`x * x` — a square).
// KNOWN LIMITATION / honest FN: the safe form of a square bounds the
// operand with `abs(x) < sqrt(TYPE_MAX)` (there is no other way to keep
// x*x inside the type), and that guard rests on `abs` and `sqrt` — a
// call and a floating-point operation the integer-interval refiner
// cannot fold. So a guarded-safe square looks identical to an unguarded
// one (its operand keeps the source's full range either way), and
// reporting it would be a false positive on correct code. We therefore
// stay SILENT on x*x until abs/sqrt guards are modeled — precision over
// recall. A distinct-operand product (`w * h`, `n * k`) is unaffected:
// its natural guard (`w < K`) is a plain constant comparison that DOES
// refine. Measured on Juliet CWE190: every square-op false positive is
// exactly this abs/sqrt-guarded good sink.
bool isSelfSquare(const BinaryOperator* op) {
    auto asVar = [](const Expr* e) -> const ValueDecl* {
        e = e->IgnoreParenImpCasts();
        if (const auto* ref = dyn_cast<DeclRefExpr>(e)) return ref->getDecl();
        return nullptr;
    };
    const ValueDecl* l = asVar(op->getLHS());
    const ValueDecl* r = asVar(op->getRHS());
    return l && l == r;
}

// A growth operator this rule reasons about. `-` belongs to CWE-191
// (underflow) and stays out of scope.
bool isGrowthOp(const BinaryOperator* op) {
    return op->getOpcode() == BO_Mul || op->getOpcode() == BO_Add;
}

bool isReportableOp(const BinaryOperator* op) {
    if (!isGrowthOp(op)) return false;
    QualType t = op->getType();
    if (!t->isIntegerType() || !t->isSignedIntegerType()) return false;
    // abs/sqrt-guarded squares are indistinguishable from unguarded
    // ones at any width — documented FN, precision over recall.
    if (op->getOpcode() == BO_Mul && isSelfSquare(op)) return false;
    return true;
}

std::vector<ArithSite> collectArithSites(const FunctionDecl* fn,
                                         ASTContext& ctx) {
    struct V : RecursiveASTVisitor<V> {
        ASTContext& ctx;
        std::vector<ArithSite> sites;
        explicit V(ASTContext& c) : ctx(c) {}
        bool VisitBinaryOperator(BinaryOperator* op) {
            if (!isReportableOp(op)) return true;
            sites.push_back({op, ctx.getIntWidth(op->getType()),
                             false, {}});
            return true;
        }
        bool VisitImplicitCastExpr(ImplicitCastExpr* ce) {
            if (ce->getCastKind() != CK_IntegralCast) return true;
            // In C++ an explicit (char)(...) materializes as an
            // ImplicitCastExpr marked part_of_explicit_cast — that is
            // stated programmer intent, not an implicit narrowing.
            if (ce->isPartOfExplicitCast()) return true;
            QualType dst = ce->getType();
            // Unsigned narrowing wraps by definition — not UB, silent.
            if (!dst->isSignedIntegerType()) return true;
            const auto* op =
                dyn_cast<BinaryOperator>(ce->getSubExpr()->IgnoreParens());
            if (!op || !isReportableOp(op)) return true;
            unsigned srcBits = ctx.getIntWidth(op->getType());
            unsigned dstBits = ctx.getIntWidth(dst);
            if (dstBits >= srcBits) return true;
            sites.push_back({op, dstBits, true, dst.getAsString()});
            return true;
        }
    } v(ctx);
    v.TraverseStmt(fn->getBody());
    return v.sites;
}

// 64-bit escape proof: both operand intervals fully bounded, corner
// results computed in __int128. Escape iff a corner leaves int64 —
// exactly the case the int64-based Interval must collapse to top().
// Any infinite bound -> not proven -> silent (precision-first).
bool evalEscapes64(const BinaryOperator* op,
                   const codeskeptic::IntervalMap& st, ASTContext& ctx) {
    codeskeptic::Interval l = codeskeptic::evalInterval(op->getLHS(), st, &ctx);
    codeskeptic::Interval r = codeskeptic::evalInterval(op->getRHS(), st, &ctx);
    if (l.isEmpty() || r.isEmpty()) return false;
    if (l.loIsInf() || l.hiIsInf() || r.loIsInf() || r.hiIsInf())
        return false;
    const __int128 corners[4] = {
        op->getOpcode() == BO_Mul
            ? (__int128)l.lo() * r.lo() : (__int128)l.lo() + r.lo(),
        op->getOpcode() == BO_Mul
            ? (__int128)l.lo() * r.hi() : (__int128)l.lo() + r.hi(),
        op->getOpcode() == BO_Mul
            ? (__int128)l.hi() * r.lo() : (__int128)l.hi() + r.lo(),
        op->getOpcode() == BO_Mul
            ? (__int128)l.hi() * r.hi() : (__int128)l.hi() + r.hi(),
    };
    __int128 lo = corners[0], hi = corners[0];
    for (__int128 c : corners) {
        if (c < lo) lo = c;
        if (c > hi) hi = c;
    }
    const __int128 i64min = (__int128)INT64_MIN;
    const __int128 i64max = (__int128)INT64_MAX;
    // Same evidence bar as the sub-64 path: the proven range REACHES
    // beyond the type ("possible overflow", warning) — not necessarily
    // entirely outside it.
    return hi > i64max || lo < i64min;
}

// The sub-64 escape query, with the FINITE-witness bar: an infinite
// endpoint is over-approximation, not evidence. Interval::add keeps
// half-open ranges where mul collapses them to top() — without this
// bar every `if (x > 0) x + k` would be a false positive.
bool escapesSignedFinite(const codeskeptic::Interval& r, unsigned bits) {
    if (r.isEmpty() || r.isTop()) return false;
    const int64_t maxv = ((int64_t)1 << (bits - 1)) - 1;
    const int64_t minv = -maxv - 1;
    if (!r.hiIsInf() && r.hi() > maxv) return true;
    if (!r.loIsInf() && r.lo() < minv) return true;
    return false;
}

void analyzeFunction(const FunctionDecl* fn, ASTContext& ctx,
                     const codeskeptic::ParamIntervalMap& paramMap,
                     codeskeptic::DiagnosticList& results) {
    if (!fn->hasBody()) return;

    auto sites = collectArithSites(fn, ctx);
    if (sites.empty()) return;

    // Run the shared interval dataflow observationally, then read back
    // the proven range at each multiplication. IntervalAnalysis never
    // reports — the report/suppress decision is owned entirely here. The
    // seed map (C3) starts parameters with visible, closed callers at a
    // proven range instead of top() — that is what carries a caller's
    // bounded argument into this function's overflow check.
    codeskeptic::IntervalAnalysis analysis(collectIntVars(fn),
                                          codeskeptic::paramSeeds(paramMap, fn));
    auto df = codeskeptic::runDataflow(fn, ctx, analysis);
    if (!df.converged)
        codeskeptic::CoverageReport::instance().recordNonConvergence(
            fn->getQualifiedNameAsString());

    const SourceManager& sm = ctx.getSourceManager();
    std::set<unsigned> reportedLines;

    for (const auto& site : sites) {
        // The entry interval-state at the operation's own CFG element.
        // Its operands were read (not written) just before, so the
        // variable ranges here are exactly the ones the result uses.
        const codeskeptic::IntervalMap* st = analysis.stateAt(site.op);
        if (!st) continue;  // unreached / not recorded — nothing proven

        bool escapes = false;
        if (site.bits >= 64) {
            // The int64-based Interval collapses an overflowing 64-bit
            // result to top() — prove from the operand corners instead.
            escapes = evalEscapes64(site.op, *st, ctx);
        } else {
            // Report ONLY on a proven finite witness beyond the target
            // width — an unknown operand yields top(), an unbounded
            // side is over-approximation; both stay silent
            // (precision-first: a missed overflow beats a false alarm).
            escapes = escapesSignedFinite(
                codeskeptic::evalInterval(site.op, *st, &ctx), site.bits);
        }
        if (!escapes) continue;

        SourceLocation loc = sm.getExpansionLoc(site.op->getOperatorLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines.insert(line).second) continue;

        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "int-overflow";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = codeskeptic::Severity::Warning;
        if (site.narrowing) {
            // The narrowed DESTINATION carries the claim, not the
            // (wider) arithmetic type.
            diag.message = codeskeptic::msg(
                codeskeptic::MsgId::IntOverflowNarrow, site.narrowType);
        } else {
            diag.message = codeskeptic::msg(
                site.op->getOpcode() == BO_Add
                    ? codeskeptic::MsgId::IntOverflowAdd
                    : codeskeptic::MsgId::IntOverflowMul,
                site.op->getType().getAsString());
        }
        results.push_back(std::move(diag));
    }
}

class IntOverflowCallback : public MatchFinder::MatchCallback {
public:
    IntOverflowCallback(const codeskeptic::ParamIntervalMap& paramMap,
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

void IntOverflowRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    const ParamIntervalMap& paramMap =
        ParamIntervalCache::instance().get(ctx);

    MatchFinder finder;
    IntOverflowCallback callback(paramMap, results);

    auto matcher =
        functionDecl(isDefinition(), hasBody(anything())).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace codeskeptic
