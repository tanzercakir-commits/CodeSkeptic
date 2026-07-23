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

// The UNBOUNDED string-copy family: functions with NO length argument,
// so the amount written is `strlen(src)+1` (strcpy/stpcpy), an append
// (strcat), or a whole line (gets) — intrinsically unbounded, a
// property of the FUNCTION, not of any caller (the #94 lesson: key on
// intrinsic signals, never caller-dependent ones). Copied into a
// fixed-size destination with no length check, this is the textbook
// CWE-120 that every linter and MISRA bans. The thesis-v2 corpus miss
// (hash_djb2's `strcpy(n->key, key)` into `char key[32]`).
struct StrCopyCall {
    const CallExpr* call;
    unsigned destArg;   // which argument is the destination buffer
    bool hasSource;     // false for gets (no source to prove-fits)
    unsigned srcArg;
};

std::vector<StrCopyCall> collectStrCopyCalls(const FunctionDecl* fn) {
    struct V : RecursiveASTVisitor<V> {
        std::vector<StrCopyCall> calls;
        bool VisitCallExpr(CallExpr* call) {
            const FunctionDecl* callee = call->getDirectCallee();
            if (!callee || !callee->getIdentifier()) return true;
            const llvm::StringRef n = callee->getName();
            const unsigned na = call->getNumArgs();
            if ((n == "strcpy" || n == "strcat" || n == "stpcpy") && na == 2)
                calls.push_back({call, 0, true, 1});
            else if (n == "gets" && na == 1)
                calls.push_back({call, 0, false, 0});
            return true;
        }
    } v;
    v.TraverseStmt(fn->getBody());
    return v.calls;
}

// Is the destination a genuinely FIXED-SIZE array — a local/global
// `char[N]` or a struct/union array member? v1 restricts the unbounded
// string-copy warning to these (the intrinsic "fixed buffer" signal,
// and every thesis-corpus case). A heap pointer is excluded: the
// idiomatic `p = malloc(strlen(s)+1); strcpy(p, s)` is exactly
// right-sized and its extent is symbolic anyway, but a `malloc(CONST)`
// heap block would false-positive on the "programmer sized it
// correctly" case far more often than a stack/struct array.
bool destIsFixedArray(const Expr* e, ASTContext& ctx) {
    if (!e) return false;
    e = e->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(e)) {
        const auto* vd = dyn_cast<VarDecl>(ref->getDecl());
        return vd && ctx.getAsConstantArrayType(vd->getType()) != nullptr;
    }
    if (const auto* mem = dyn_cast<MemberExpr>(e)) {
        const auto* field = dyn_cast<FieldDecl>(mem->getMemberDecl());
        return field && ctx.getAsConstantArrayType(field->getType()) != nullptr;
    }
    return false;
}

// A string-literal source whose length (incl. NUL) provably fits the
// destination capacity — the safe `strcpy(buf32, "hi")` case, skipped.
bool literalFits(const Expr* src, int64_t capacityBytes) {
    const auto* lit =
        dyn_cast<clang::StringLiteral>(src->IgnoreParenImpCasts());
    if (!lit) return false;
    // byte length including the terminating NUL
    return static_cast<int64_t>(lit->getByteLength()) + 1 <= capacityBytes;
}

// --- Length-check witness for the unbounded-copy heuristic (2026-07-22,
// the rtp2httpd service.c / http_proxy_rewrite.c FP family) ---
//
// The CWE-120 message claims "the source length is not checked", so the
// rule must actually LOOK for the check. The two idioms that guard
// virtually every deliberate strcpy/strcat in real C:
//
//   A) the copy sits INSIDE a branch whose condition measures the
//      source:      if (strlen(dst) + strlen(src) < sizeof(dst))
//                       strcat(dst, src);
//   B) an EARLIER statement in an enclosing block is an if whose
//      then-branch unconditionally exits and whose condition measures
//      the source:  if (strlen(src) >= sizeof(dst)) return -1;
//                   ...
//                   strcpy(dst, src);
//
// The witness is deliberately about MEASUREMENT, not about proving the
// comparison arithmetically: a strlen/strnlen of the SAME source
// expression inside such a dominating guard is evidence of length
// diligence, and this heuristic's job is flagging OBLIVIOUSLY
// unbounded copies. Measuring only the DESTINATION does not count
// (`if (strlen(dst) < 100) strcat(dst, src)` never bounds src), a
// check AFTER the copy does not count (shape B looks only at earlier
// siblings), and a measured-then-ignored guard does not count (shape A
// requires the copy INSIDE the guarded branch). gets() has no source
// and is never excused.

// Same-source comparison for the witness: identical variable, or the
// same member chain over identical variables (`s->buf`, `c.name`).
bool sameSourceExpr(const Expr* a, const Expr* b) {
    if (!a || !b) return false;
    a = a->IgnoreParenImpCasts();
    b = b->IgnoreParenImpCasts();
    if (const auto* ra = dyn_cast<DeclRefExpr>(a)) {
        const auto* rb = dyn_cast<DeclRefExpr>(b);
        return rb && ra->getDecl()->getCanonicalDecl() ==
                         rb->getDecl()->getCanonicalDecl();
    }
    if (const auto* ma = dyn_cast<MemberExpr>(a)) {
        const auto* mb = dyn_cast<MemberExpr>(b);
        return mb && ma->getMemberDecl() == mb->getMemberDecl() &&
               sameSourceExpr(ma->getBase(), mb->getBase());
    }
    return false;
}

// Does `e` contain a strlen/strnlen call whose measured argument is
// the copy's source expression?
bool mentionsStrlenOfSrc(const Expr* e, const Expr* src) {
    if (!e) return false;
    struct V : RecursiveASTVisitor<V> {
        const Expr* src;
        bool found = false;
        explicit V(const Expr* s) : src(s) {}
        bool VisitCallExpr(CallExpr* call) {
            const FunctionDecl* fd = call->getDirectCallee();
            if (!fd || !fd->getIdentifier()) return true;
            const llvm::StringRef n = fd->getName();
            if ((n == "strlen" || n == "strnlen") &&
                call->getNumArgs() >= 1 &&
                sameSourceExpr(call->getArg(0), src)) {
                found = true;
                return false;  // stop
            }
            return true;
        }
    } v(src);
    v.TraverseStmt(const_cast<Expr*>(const_cast<Expr*>(e)));
    return v.found;
}

// The last effective statement of a branch, unwrapping one compound.
const Stmt* lastStmtOf(const Stmt* s) {
    if (!s) return nullptr;
    if (const auto* comp = dyn_cast<CompoundStmt>(s))
        return comp->body_empty() ? nullptr : comp->body_back();
    return s;
}

// Unconditional-exit test for shape B's then-branch: the branch's
// final statement leaves the surrounding flow (return/goto/break/
// continue). This is what makes the guard's FALSE edge dominate the
// copy that follows the if.
bool branchExits(const Stmt* s) {
    const Stmt* last = lastStmtOf(s);
    return last && (isa<ReturnStmt>(last) || isa<GotoStmt>(last) ||
                    isa<BreakStmt>(last) || isa<ContinueStmt>(last));
}

bool hasLengthCheckWitness(const CallExpr* copyCall, const Expr* src,
                           ASTContext& ctx) {
    using DynNode = clang::DynTypedNode;
    DynNode node = DynNode::create(*copyCall);
    const Stmt* childStmt = copyCall;

    // Walk up the tree. At every IfStmt whose then/else contains us,
    // test shape A; at every CompoundStmt, test shape B against the
    // earlier siblings of the statement we came from.
    for (unsigned depth = 0; depth < 64; ++depth) {
        auto parents = ctx.getParents(node);
        if (parents.empty()) return false;
        const Stmt* parent = parents[0].get<Stmt>();
        if (!parent) {
            // Function boundary (or non-stmt parent): stop.
            return false;
        }
        if (const auto* ifs = dyn_cast<IfStmt>(parent)) {
            const bool inThen = ifs->getThen() == childStmt;
            const bool inElse = ifs->getElse() == childStmt;
            if ((inThen || inElse) &&
                mentionsStrlenOfSrc(ifs->getCond(), src))
                return true;  // shape A
        }
        if (const auto* comp = dyn_cast<CompoundStmt>(parent)) {
            for (const Stmt* sib : comp->body()) {
                if (sib == childStmt) break;  // only EARLIER siblings
                const auto* sibIf = dyn_cast<IfStmt>(sib);
                if (!sibIf || !branchExits(sibIf->getThen())) continue;
                if (mentionsStrlenOfSrc(sibIf->getCond(), src))
                    return true;  // shape B
            }
        }
        childStmt = parent;
        node = DynNode::create(*parent);
    }
    return false;
}

// Byte size of one element of a buffer variable — the factor that turns
// the ExtentMap's element count into a byte capacity. 0 when unknown
// (including a type too deep for the size budget — see
// boundedTypeSizeInChars).
int64_t destElemSize(const VarDecl* vd, ASTContext& ctx) {
    QualType t = vd->getType();
    if (const auto* arr = ctx.getAsConstantArrayType(t)) {
        return codeskeptic::boundedTypeSizeInChars(ctx, arr->getElementType())
            .value_or(0);
    }
    if (t->isPointerType()) {
        QualType p = t->getPointeeType();
        if (!p->isVoidType())
            return codeskeptic::boundedTypeSizeInChars(ctx, p).value_or(0);
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
    codeskeptic::Interval elements;  // element count
    int64_t elemBytes = 0;          // byte size of one element
    bool ok = false;
};

BufExtent bufferExtent(const Expr* e, const codeskeptic::ExtentMap& extents,
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
            codeskeptic::boundedTypeSizeInChars(ctx, arr->getElementType());
        if (!elemBytes || *elemBytes <= 0) return r;
        r.elements =
            codeskeptic::Interval::constant(static_cast<int64_t>(n.getZExtValue()));
        r.elemBytes = *elemBytes;
        r.ok = true;
        return r;
    }
    return r;
}

void analyzeFunction(const FunctionDecl* fn, ASTContext& ctx,
                     const codeskeptic::ParamIntervalMap& paramMap,
                     codeskeptic::DiagnosticList& results) {
    if (!fn->hasBody()) return;

    // Variable-buffer extents (fixed arrays + heap pointers). Member-array
    // extents are derived at the access site (bufferExtent), so an empty
    // map does not mean there is nothing to check.
    codeskeptic::ExtentMap extents = codeskeptic::buildExtentMap(fn, ctx);

    auto subs = collectSubscripts(fn);
    auto copies = collectCopyCalls(fn);
    auto strcopies = collectStrCopyCalls(fn);
    if (subs.empty() && copies.empty() && strcopies.empty()) return;

    // Seed parameters with visible, closed callers (C3) at their proven
    // entry range, so a caller's bounded index argument reaches the check.
    codeskeptic::IntervalAnalysis analysis(collectIntVars(fn),
                                          codeskeptic::paramSeeds(paramMap, fn));
    auto df = codeskeptic::runDataflow(fn, ctx, analysis);
    if (!df.converged)
        codeskeptic::CoverageReport::instance().recordNonConvergence(
            fn->getQualifiedNameAsString());

    const SourceManager& sm = ctx.getSourceManager();
    std::set<unsigned> reportedLines;

    for (const auto* sub : subs) {
        BufExtent be = bufferExtent(sub->getBase(), extents, ctx);
        if (!be.ok) continue;
        const codeskeptic::Interval& extent = be.elements;

        const codeskeptic::IntervalMap* st = analysis.stateAt(sub);
        if (!st) continue;  // not recorded — nothing proven
        codeskeptic::Interval idx = codeskeptic::evalInterval(sub->getIdx(), *st);
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

        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "bounds";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = codeskeptic::Severity::Error;
        diag.message = codeskeptic::msg(codeskeptic::MsgId::BoundsArrayDefinite,
                                       idx.toString(), extentStr);
        results.push_back(std::move(diag));
    }

    // Copy-size overflow: memcpy/memmove/memset(dst, ..., n) writes n
    // bytes into dst. When dst has a proven byte capacity and n's proven
    // minimum exceeds even the largest possible capacity, it definitely
    // overflows (CWE-787). Byte capacity = element count (ExtentMap) *
    // element size.
    const codeskeptic::IntervalMap emptyState;
    for (const auto* call : copies) {
        BufExtent be = bufferExtent(call->getArg(0), extents, ctx);
        if (!be.ok) continue;
        codeskeptic::Interval capacity = codeskeptic::Interval::mul(
            be.elements, codeskeptic::Interval::constant(be.elemBytes));
        if (capacity.hiIsInf()) continue;  // unbounded capacity — prove nothing

        const codeskeptic::IntervalMap* st = analysis.stateAt(call);
        codeskeptic::Interval sz = codeskeptic::evalSizeInterval(
            call->getArg(2), ctx, st ? *st : emptyState);
        // Definite overflow: every byte count exceeds the capacity.
        if (sz.isEmpty() || sz.loIsInf() || sz.lo() <= capacity.hi()) continue;

        SourceLocation loc = sm.getExpansionLoc(call->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines.insert(line).second) continue;

        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "bounds";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = codeskeptic::Severity::Error;
        diag.message = codeskeptic::msg(codeskeptic::MsgId::BoundsCopyOverflow,
                                       sz.toString(),
                                       std::to_string(capacity.hi()));
        results.push_back(std::move(diag));
    }

    // Unbounded string copy (#95, CWE-120): strcpy/strcat/stpcpy/gets
    // into a fixed-size destination. No length argument means the write
    // is bounded only by the SOURCE's length, which the code does not
    // check — a latent overflow. Recall move mirroring #92/#94: the
    // unboundedness is intrinsic to the function, so keying on it stays
    // precise. Skip a string-literal source that provably fits.
    for (const auto& sc : strcopies) {
        const Expr* dest = sc.call->getArg(sc.destArg);
        if (!destIsFixedArray(dest, ctx)) continue;  // fixed buffers only
        BufExtent be = bufferExtent(dest, extents, ctx);
        if (!be.ok) continue;
        codeskeptic::Interval capacity = codeskeptic::Interval::mul(
            be.elements, codeskeptic::Interval::constant(be.elemBytes));
        if (capacity.hiIsInf()) continue;  // unbounded dest — prove nothing
        if (sc.hasSource &&
            literalFits(sc.call->getArg(sc.srcArg), capacity.hi()))
            continue;  // `strcpy(buf32, "hi")` — provably safe
        if (sc.hasSource &&
            hasLengthCheckWitness(sc.call, sc.call->getArg(sc.srcArg), ctx))
            continue;  // guarded by a strlen(src) check — not oblivious

        SourceLocation loc = sm.getExpansionLoc(sc.call->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines.insert(line).second) continue;

        const FunctionDecl* callee = sc.call->getDirectCallee();
        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "bounds";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = codeskeptic::Severity::Warning;
        diag.message = codeskeptic::msg(
            codeskeptic::MsgId::BoundsUnboundedStrCopy,
            callee->getNameAsString(), std::to_string(capacity.hi()));
        results.push_back(std::move(diag));
    }
}

class BoundsCallback : public MatchFinder::MatchCallback {
public:
    BoundsCallback(const codeskeptic::ParamIntervalMap& paramMap,
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

} // namespace codeskeptic
