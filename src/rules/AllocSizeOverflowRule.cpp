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

#include <functional>
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
// reach past what the result type can hold? The interval is int64, so a
// sub-64 unsigned type's max is representable and hi() > max witnesses a
// wrap. A 64-bit result cannot be witnessed this way (2^64-1 exceeds
// int64) — deferred, and the site is not collected for it, so this is
// never asked with bits >= 64.
bool wrapsUnsignedFinite(const codeskeptic::Interval& r, unsigned bits) {
    if (r.isEmpty() || r.isTop()) return false;
    if (bits == 0 || bits >= 64) return false;
    const int64_t umax = (int64_t(1) << bits) - 1;
    return !r.hiIsInf() && r.hi() > umax;
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
            if (bits == 0 || bits >= 64) return true;  // v1: sub-64 only
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

        // Gate: the size PROVABLY wraps its unsigned result type. A
        // guard on the untrusted length narrows the interval and this
        // is false; an unknown operand yields top() and is silent.
        codeskeptic::Interval iv =
            codeskeptic::evalInterval(site.op, *st, &ctx);
        if (!wrapsUnsignedFinite(iv, site.bits)) continue;

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
