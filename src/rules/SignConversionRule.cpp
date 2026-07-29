#include "rules/SignConversionRule.h"

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
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/AST/Type.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Basic/SourceManager.h>

#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// Same interval domain as IntOverflowRule: every integer local and
// parameter, seeded by declaration, refined by guards and assignments.
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

// A signed-integer -> unsigned-integer conversion site, implicit or
// explicit. Clang materialises the two spellings differently, and an
// explicit C++ cast can carry its integral conversion in EITHER the
// ExplicitCastExpr itself or an inner ImplicitCastExpr marked
// part_of_explicit_cast — so the collection is asked of both node
// kinds, and the inner part-of-explicit node is always skipped in
// favour of the outer one (visiting both would double-report the same
// conversion).
//
// bool is excluded on the source side by isSignedIntegerType(); enums
// participate through their underlying conversions, which arrive as
// plain integral casts.
struct ConvSite {
    const Expr* cast;      // the conversion expression (report location)
    const Expr* operand;   // the signed value being converted
    std::string srcType;
    std::string dstType;
};

// A call to a heap allocator whose size argument, over-large, is met by
// a NULL return — the intrinsic C family plus any --alloc-functions
// wrapper. The conversion that feeds such an argument is DELIBERATELY
// out of this rule's scope: a negative-turned-huge allocation request
// is caught by the allocator's own contract (calloc even proves the
// nmemb*size overflow) and, when the result is used unchecked, it is
// the null-deref rule's finding, not a sign story. Excluding it is what
// keeps the ubiquitous `n = atoi(argv[1]); p = calloc(n, ...); if (!p)`
// idiom silent — the thesis corpus's array_from_int.c, ground-truth
// clean. The rule's own territory is the NON-allocator use nlohmann
// showed: a length stored/returned/used for access with no NULL net.
bool isAllocatorCallee(const CallExpr* call) {
    const FunctionDecl* fd = call->getDirectCallee();
    if (!fd || !fd->getIdentifier()) return false;
    const std::string n = fd->getName().str();
    static const std::set<std::string> kIntrinsic = {
        "malloc",  "calloc",       "realloc",    "reallocarray",
        "alloca",  "aligned_alloc", "valloc",    "pvalloc",
        "memalign",
    };
    if (kIntrinsic.count(n)) return true;
    const auto& extra = codeskeptic::allocFunctionNames();
    return !extra.empty() && extra.count(n);
}

std::vector<ConvSite> collectConvSites(const FunctionDecl* fn) {
    struct V : RecursiveASTVisitor<V> {
        std::vector<ConvSite> sites;
        // Every Expr under an allocator call's arguments — a size
        // request whose over-large failure mode is a NULL return, not a
        // silent overflow, so its conversion is out of scope here.
        std::set<const Expr*> allocArgExprs;

        // Traverse allocator calls first so allocArgExprs is populated
        // before any contained conversion is considered. RAV visits
        // parents before children, so recording the argument subtree on
        // the way DOWN covers every nested conversion.
        bool VisitCallExpr(CallExpr* call) {
            if (!isAllocatorCallee(call)) return true;
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

        void consider(const Expr* cast, const Expr* operand, QualType dst) {
            if (!operand) return;
            if (allocArgExprs.count(cast)) return;  // allocator size arg
            QualType src = operand->getType();
            if (!dst->isIntegerType() || !dst->isUnsignedIntegerType())
                return;
            if (!src->isIntegerType() || !src->isSignedIntegerType())
                return;
            sites.push_back({cast, operand, src.getAsString(),
                             dst.getAsString()});
        }

        bool VisitImplicitCastExpr(ImplicitCastExpr* ce) {
            if (ce->getCastKind() != CK_IntegralCast) return true;
            // The enclosing explicit cast owns this conversion; it is
            // collected there (VisitExplicitCastExpr), never here.
            if (ce->isPartOfExplicitCast()) return true;
            consider(ce, ce->getSubExpr(), ce->getType());
            return true;
        }

        bool VisitExplicitCastExpr(ExplicitCastExpr* ce) {
            // Asked of the AS-WRITTEN operand: the conversion may live
            // in an inner part-of-explicit implicit cast whose own
            // CastKind the outer node does not repeat.
            consider(ce, ce->getSubExprAsWritten(), ce->getType());
            return true;
        }
    } v;
    v.TraverseStmt(fn->getBody());
    return v.sites;
}

void analyzeFunction(const FunctionDecl* fn, ASTContext& ctx,
                     const codeskeptic::ParamIntervalMap& paramMap,
                     codeskeptic::DiagnosticList& results) {
    if (!fn->hasBody()) return;

    auto sites = collectConvSites(fn);
    if (sites.empty()) return;

    codeskeptic::IntervalAnalysis analysis(
        collectIntVars(fn), codeskeptic::paramSeeds(paramMap, fn));
    auto df = codeskeptic::runDataflow(fn, ctx, analysis);
    if (!df.converged)
        codeskeptic::CoverageReport::instance().recordNonConvergence(
            fn->getQualifiedNameAsString());

    const SourceManager& sm = ctx.getSourceManager();
    std::set<unsigned> reportedLines;
    static const std::set<const VarDecl*> kNoUntrusted;

    for (const auto& site : sites) {
        // The recorded CFG element nearest the conversion: the cast
        // itself when the CFG linearised it, else the operand, else
        // the operand's leaf. No writes separate them, so all three
        // name the same program point.
        const Stmt* keys[3] = {site.cast, site.operand,
                               site.operand->IgnoreParenImpCasts()};
        const codeskeptic::IntervalMap* st = nullptr;
        const std::set<const VarDecl*>* utr = nullptr;
        for (const Stmt* k : keys) {
            if (!st) st = analysis.stateAt(k);
            if (!utr) utr = analysis.untrustedAt(k);
        }
        if (!st) continue;  // unreached / unrecorded — nothing proven
        if (!utr) utr = &kNoUntrusted;

        // Gate 1 — provenance: the value must derive from a declared
        // untrusted source. Opt-in, never guessed: an ordinary signed
        // local or parameter stays silent no matter its range.
        if (!codeskeptic::exprDerivesFromUntrusted(site.operand, *utr))
            continue;

        // Gate 2 — a FINITE negative witness. The untrusted seed is a
        // full finite type range, so an unguarded value shows its
        // type-min here; a dominating non-negativity guard raises the
        // low bound on its own edge and silences. An infinite or
        // unknown bound is over-approximation, not evidence — silent.
        codeskeptic::Interval iv =
            codeskeptic::evalInterval(site.operand, *st, &ctx);
        if (iv.isEmpty() || iv.isTop() || iv.loIsInf()) continue;
        if (iv.lo() >= 0) continue;

        SourceLocation loc = sm.getExpansionLoc(site.cast->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines.insert(line).second) continue;

        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "sign-conversion";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = codeskeptic::Severity::Warning;
        diag.message = codeskeptic::msg(
            codeskeptic::MsgId::SignConversionUntrusted, site.srcType,
            site.dstType);
        results.push_back(std::move(diag));
    }
}

class SignConversionCallback : public MatchFinder::MatchCallback {
public:
    SignConversionCallback(const codeskeptic::ParamIntervalMap& paramMap,
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

void SignConversionRule::check(clang::ASTContext& ctx,
                               DiagnosticList& results) {
    const ParamIntervalMap& paramMap = ParamIntervalCache::instance().get(ctx);

    MatchFinder finder;
    SignConversionCallback callback(paramMap, results);

    auto matcher =
        functionDecl(isDefinition(), hasBody(anything())).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace codeskeptic
