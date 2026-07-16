#include "rules/BoundsRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CoverageReport.h"
#include "engine/DataflowEngine.h"
#include "engine/ExtentMap.h"
#include "engine/IntervalAnalysis.h"
#include "engine/IntervalEval.h"
#include "engine/ParamIntervals.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Basic/SourceManager.h>

#include <iostream>
#include <set>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// Every integer local and parameter — the domain IntervalAnalysis
// tracks, so the subscript index resolves to a proven range.
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

std::vector<const ArraySubscriptExpr*> collectSubscripts(
    const FunctionDecl* fn) {
    struct V : RecursiveASTVisitor<V> {
        std::vector<const ArraySubscriptExpr*> subs;
        bool VisitArraySubscriptExpr(ArraySubscriptExpr* e) {
            subs.push_back(e);
            return true;
        }
    } v;
    v.TraverseStmt(fn->getBody());
    return v.subs;
}

// The fixed byte-copy family: dst is arg 0, byte count is arg 2. All
// write exactly `n` bytes into dst[0 .. n-1], so an `n` past the
// destination's capacity is a definite overflow (CWE-787). strcpy/strcat
// (no explicit size) and strncpy/strncat (append/pad semantics) are out
// of v0 scope.
std::vector<const CallExpr*> collectCopyCalls(const FunctionDecl* fn) {
    struct V : RecursiveASTVisitor<V> {
        std::vector<const CallExpr*> calls;
        bool VisitCallExpr(CallExpr* call) {
            const FunctionDecl* callee = call->getDirectCallee();
            if (!callee || !callee->getIdentifier()) return true;
            const llvm::StringRef n = callee->getName();
            if ((n == "memcpy" || n == "memmove" || n == "memset") &&
                call->getNumArgs() == 3)
                calls.push_back(call);
            return true;
        }
    } v;
    v.TraverseStmt(fn->getBody());
    return v.calls;
}

// Byte size of one element of a buffer variable — the factor that turns
// the ExtentMap's element count into a byte capacity. 0 when unknown
// (including a type too deep for the size budget — see
// boundedTypeSizeInChars).
int64_t destElemSize(const VarDecl* vd, ASTContext& ctx) {
    QualType t = vd->getType();
    if (const auto* arr = ctx.getAsConstantArrayType(t)) {
        return zerodefect::boundedTypeSizeInChars(ctx, arr->getElementType())
            .value_or(0);
    }
    if (t->isPointerType()) {
        QualType p = t->getPointeeType();
        if (!p->isVoidType())
            return zerodefect::boundedTypeSizeInChars(ctx, p).value_or(0);
    }
    return 0;
}

// The proven extent of the buffer that `e` names, as a subscript base or
// a copy destination. Two sources: a variable buffer (fixed array or heap
// pointer) tracked by the ExtentMap, and a FIXED-SIZE ARRAY MEMBER
// (`s->buf` / `s.buf`) — whose extent is a property of the field's type,
// so it holds regardless of the object it belongs to (the real-world
// heap-overflow shape: a small buffer inside a struct). Unprovable →
// {ok = false}.
struct BufExtent {
    zerodefect::Interval elements;  // element count
    int64_t elemBytes = 0;          // byte size of one element
    bool ok = false;
};

BufExtent bufferExtent(const Expr* e, const zerodefect::ExtentMap& extents,
                       ASTContext& ctx) {
    BufExtent r;
    if (!e) return r;
    e = e->IgnoreParenImpCasts();

    if (const auto* ref = dyn_cast<DeclRefExpr>(e)) {
        const auto* vd = dyn_cast<VarDecl>(ref->getDecl());
        if (!vd) return r;
        auto it = extents.find(vd);
        if (it == extents.end()) return r;
        const int64_t es = destElemSize(vd, ctx);
        if (es <= 0) return r;
        r.elements = it->second;
        r.elemBytes = es;
        r.ok = true;
        return r;
    }

    if (const auto* mem = dyn_cast<MemberExpr>(e)) {
        const auto* field = dyn_cast<FieldDecl>(mem->getMemberDecl());
        if (!field) return r;
        const auto* arr = ctx.getAsConstantArrayType(field->getType());
        if (!arr) return r;
        const llvm::APInt& n = arr->getSize();
        if (n.getActiveBits() > 63) return r;
        auto elemBytes =
            zerodefect::boundedTypeSizeInChars(ctx, arr->getElementType());
        if (!elemBytes || *elemBytes <= 0) return r;
        r.elements =
            zerodefect::Interval::constant(static_cast<int64_t>(n.getZExtValue()));
        r.elemBytes = *elemBytes;
        r.ok = true;
        return r;
    }
    return r;
}

void analyzeFunction(const FunctionDecl* fn, ASTContext& ctx,
                     const zerodefect::ParamIntervalMap& paramMap,
                     zerodefect::DiagnosticList& results) {
    if (!fn->hasBody()) return;

    // Variable-buffer extents (fixed arrays + heap pointers). Member-array
    // extents are derived at the access site (bufferExtent), so an empty
    // map does not mean there is nothing to check.
    zerodefect::ExtentMap extents = zerodefect::buildExtentMap(fn, ctx);

    auto subs = collectSubscripts(fn);
    auto copies = collectCopyCalls(fn);
    if (subs.empty() && copies.empty()) return;

    // Seed parameters with visible, closed callers (C3) at their proven
    // entry range, so a caller's bounded index argument reaches the check.
    zerodefect::IntervalAnalysis analysis(collectIntVars(fn),
                                          zerodefect::paramSeeds(paramMap, fn));
    auto df = zerodefect::runDataflow(fn, ctx, analysis);
    if (!df.converged)
        zerodefect::CoverageReport::instance().recordNonConvergence(
            fn->getQualifiedNameAsString());

    const SourceManager& sm = ctx.getSourceManager();
    std::set<unsigned> reportedLines;

    for (const auto* sub : subs) {
        BufExtent be = bufferExtent(sub->getBase(), extents, ctx);
        if (!be.ok) continue;
        const zerodefect::Interval& extent = be.elements;

        const zerodefect::IntervalMap* st = analysis.stateAt(sub);
        if (!st) continue;  // not recorded — nothing proven
        zerodefect::Interval idx = zerodefect::evalInterval(sub->getIdx(), *st);
        if (idx.isEmpty()) continue;  // unreachable

        // Definite out-of-bounds: the ENTIRE proven index range is out.
        //  - high: every value reaches past the largest possible extent
        //    (idx.lo >= extent.hi); needs a finite extent upper bound.
        //  - low: every value is negative (idx.hi < 0); extent-independent.
        const bool definiteHigh = !idx.loIsInf() && !extent.hiIsInf() &&
                                  idx.lo() >= extent.hi();
        const bool definiteLow = !idx.hiIsInf() && idx.hi() < 0;
        if (!definiteHigh && !definiteLow) continue;

        SourceLocation loc = sm.getExpansionLoc(sub->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines.insert(line).second) continue;

        int64_t e;
        std::string extentStr =
            extent.isSingleton(&e) ? std::to_string(e) : extent.toString();

        zerodefect::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "bounds";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = zerodefect::Severity::Error;
        diag.message = zerodefect::msg(zerodefect::MsgId::BoundsArrayDefinite,
                                       idx.toString(), extentStr);
        results.push_back(std::move(diag));
    }

    // Copy-size overflow: memcpy/memmove/memset(dst, ..., n) writes n
    // bytes into dst. When dst has a proven byte capacity and n's proven
    // minimum exceeds even the largest possible capacity, it definitely
    // overflows (CWE-787). Byte capacity = element count (ExtentMap) *
    // element size.
    const zerodefect::IntervalMap emptyState;
    for (const auto* call : copies) {
        BufExtent be = bufferExtent(call->getArg(0), extents, ctx);
        if (!be.ok) continue;
        zerodefect::Interval capacity = zerodefect::Interval::mul(
            be.elements, zerodefect::Interval::constant(be.elemBytes));
        if (capacity.hiIsInf()) continue;  // unbounded capacity — prove nothing

        const zerodefect::IntervalMap* st = analysis.stateAt(call);
        zerodefect::Interval sz = zerodefect::evalSizeInterval(
            call->getArg(2), ctx, st ? *st : emptyState);
        // Definite overflow: every byte count exceeds the capacity.
        if (sz.isEmpty() || sz.loIsInf() || sz.lo() <= capacity.hi()) continue;

        SourceLocation loc = sm.getExpansionLoc(call->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines.insert(line).second) continue;

        zerodefect::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "bounds";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = zerodefect::Severity::Error;
        diag.message = zerodefect::msg(zerodefect::MsgId::BoundsCopyOverflow,
                                       sz.toString(),
                                       std::to_string(capacity.hi()));
        results.push_back(std::move(diag));
    }
}

class BoundsCallback : public MatchFinder::MatchCallback {
public:
    BoundsCallback(const zerodefect::ParamIntervalMap& paramMap,
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

void BoundsRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    const ParamIntervalMap& paramMap =
        ParamIntervalCache::instance().get(ctx);

    MatchFinder finder;
    BoundsCallback callback(paramMap, results);

    auto matcher =
        functionDecl(isDefinition(), hasBody(anything())).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
