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

// A signed integer multiplication narrower than 64 bits — the only shape
// v0 can prove-and-report. A 64-bit product that overflows int64 inside
// the Interval arithmetic collapses to top() and is silently, soundly
// dropped; an unsigned product wraps by definition (not UB) and is out
// of scope.
struct MulSite {
    const BinaryOperator* op;
    unsigned bits;
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

std::vector<MulSite> collectSignedMuls(const FunctionDecl* fn,
                                       ASTContext& ctx) {
    struct V : RecursiveASTVisitor<V> {
        ASTContext& ctx;
        std::vector<MulSite> muls;
        explicit V(ASTContext& c) : ctx(c) {}
        bool VisitBinaryOperator(BinaryOperator* op) {
            if (op->getOpcode() != BO_Mul) return true;
            QualType t = op->getType();
            if (!t->isIntegerType() || !t->isSignedIntegerType()) return true;
            unsigned bits = ctx.getIntWidth(t);
            if (bits >= 64) return true;  // int64 product is unreportable
            if (isSelfSquare(op)) return true;  // abs/sqrt guard — see above
            muls.push_back({op, bits});
            return true;
        }
    } v(ctx);
    v.TraverseStmt(fn->getBody());
    return v.muls;
}

void analyzeFunction(const FunctionDecl* fn, ASTContext& ctx,
                     const zerodefect::ParamIntervalMap& paramMap,
                     zerodefect::DiagnosticList& results) {
    if (!fn->hasBody()) return;

    auto muls = collectSignedMuls(fn, ctx);
    if (muls.empty()) return;

    // Run the shared interval dataflow observationally, then read back
    // the proven range at each multiplication. IntervalAnalysis never
    // reports — the report/suppress decision is owned entirely here. The
    // seed map (C3) starts parameters with visible, closed callers at a
    // proven range instead of top() — that is what carries a caller's
    // bounded argument into this function's overflow check.
    zerodefect::IntervalAnalysis analysis(collectIntVars(fn),
                                          zerodefect::paramSeeds(paramMap, fn));
    auto df = zerodefect::runDataflow(fn, ctx, analysis);
    if (!df.converged)
        zerodefect::CoverageReport::instance().recordNonConvergence(
            fn->getQualifiedNameAsString());

    const SourceManager& sm = ctx.getSourceManager();
    std::set<unsigned> reportedLines;

    for (const auto& site : muls) {
        // The entry interval-state at the multiplication's own CFG
        // element. Its operands were read (not written) just before, so
        // the variable ranges here are exactly the ones the product uses.
        const zerodefect::IntervalMap* st = analysis.stateAt(site.op);
        if (!st) continue;  // unreached / not recorded — nothing proven

        zerodefect::Interval product =
            zerodefect::evalInterval(site.op, *st, &ctx);

        // Report ONLY when the product's range is fully proven (bounded)
        // AND provably escapes the multiplication's own signed type. An
        // unknown operand yields a top() product → silent (precision-
        // first: a missed overflow beats a false alarm).
        if (product.isEmpty() || product.isTop()) continue;
        if (product.fitsSignedBits(site.bits)) continue;

        SourceLocation loc = sm.getExpansionLoc(site.op->getOperatorLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines.insert(line).second) continue;

        zerodefect::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "int-overflow";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = zerodefect::Severity::Warning;
        diag.message = zerodefect::msg(zerodefect::MsgId::IntOverflowMul,
                                       site.op->getType().getAsString());
        results.push_back(std::move(diag));
    }
}

class IntOverflowCallback : public MatchFinder::MatchCallback {
public:
    IntOverflowCallback(const zerodefect::ParamIntervalMap& paramMap,
                        zerodefect::DiagnosticList& results)
        : paramMap_(paramMap), results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* fn = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!fn || !fn->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(fn->getLocation())) return;
        if (!zerodefect::functionFilterAllows(*fn)) return;
        if (!zerodefect::lineFilterAllows(*fn, sm)) return;

        analyzeFunction(fn, *result.Context, paramMap_, results_);
    }

private:
    const zerodefect::ParamIntervalMap& paramMap_;
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

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

} // namespace zerodefect
