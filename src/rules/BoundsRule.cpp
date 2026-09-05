#include "rules/BoundsRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CallRefArgs.h"
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

#include <algorithm>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// Warning evidence is separate from the full converted size. A signed
// external count converted to size_t may include values beyond int64 (top),
// but its finite nonnegative source subset still proves the existing possible
// destination-overflow warning. Never use this subset for a definite error,
// a source read, or an allocation/buffer capacity.
codeskeptic::Interval copyWarningRange(const Expr* expr, ASTContext& ctx,
                                      const codeskeptic::IntervalMap& state,
                                      const codeskeptic::Interval& full) {
    using codeskeptic::Interval;
    if (!full.isEmpty() && !full.hiIsInf()) return full;
    const auto* cast = dyn_cast<ImplicitCastExpr>(expr->IgnoreParens());
    if (!cast || cast->getCastKind() != CK_IntegralCast) return Interval::bottom();
    const QualType from = cast->getSubExpr()->getType(), to = cast->getType();
    if (!from->isSignedIntegerType() || !to->isUnsignedIntegerType())
        return Interval::bottom();
    const unsigned width = ctx.getIntWidth(from);
    if (!width || width > 64 || ctx.getIntWidth(to) < width)
        return Interval::bottom();
    const auto source = codeskeptic::evalSizeInterval(cast->getSubExpr(), ctx, state);
    if (source.isEmpty() || source.loIsInf() || source.hiIsInf())
        return Interval::bottom();
    // Mathematical arithmetic can exceed its signed result type; that part
    // is not a defined source value and cannot be a conversion witness.
    const int64_t high = width == 64 ? INT64_MAX : (int64_t(1) << (width - 1)) - 1;
    return Interval::meet(source, Interval::range(0, high));
}

std::string copyWarningRangeText(const codeskeptic::Interval& full,
                                 const codeskeptic::Interval& warning) {
    if (full == warning) return full.toString();
    return full.toString() + (codeskeptic::currentLang() == codeskeptic::Lang::TR
        ? " (negatif olmayan kaynak alt kumesi " : " (nonnegative source subset ") +
        warning.toString() + ")";
}

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
// write exactly `n` bytes into dst[0 .. n-1] — memcpy/memmove/memset by
// contract, and strncpy too (it PADS with NULs up to n), so an `n` past
// the destination's capacity is a definite overflow (CWE-787). strcat
// and strncat (append semantics — the write also depends on the
// existing content) stay out of scope.
std::vector<const CallExpr*> collectCopyCalls(const FunctionDecl* fn) {
    struct V : RecursiveASTVisitor<V> {
        std::vector<const CallExpr*> calls;
        bool VisitCallExpr(CallExpr* call) {
            const FunctionDecl* callee = call->getDirectCallee();
            if (!callee || !callee->getIdentifier()) return true;
            const llvm::StringRef n = callee->getName();
            if ((n == "memcpy" || n == "memmove" || n == "memset" ||
                 n == "strncpy") &&
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
// Is `f` the final field declared in `rd`?
bool isLastFieldOf(const FieldDecl* f, const RecordDecl* rd) {
    const FieldDecl* last = nullptr;
    for (const auto* fd : rd->fields()) last = fd;
    return last == f;
}

// The struct-hack / flexible-array-member tail (2026-08-01, the
// libarchive v3.8.9 false positive).
//
// `struct S { ...; char name[1]; }` allocated as
// `malloc(sizeof(S) + n)` and written past the declared element is the
// pre-C99 spelling of a flexible array member — legal and everywhere in
// C. The declared extent is then NOT the object's extent, so the type
// says nothing about capacity and the honest answer is "unknown", which
// this analyzer keeps silent by doctrine.
//
// Three conditions, all necessary, deliberately narrow:
//   * a DEGENERATE extent — `[0]` or `[1]`. A real `char name[32]` is a
//     fixed buffer that merely happens to sit last; only the degenerate
//     spelling identifies the idiom.
//   * TAIL position in every record the member is nested in. A middle
//     member is pinned by the field that follows it, so its extent is
//     real. Union members are exempt from the position test and only
//     from it: they all sit at offset 0, so tail-ness is a property of
//     the union FIELD in its enclosing struct (libarchive's shape —
//     `union { char m[1]; wchar_t w[1]; }` where the array is not the
//     union's last field).
//   * a POINTER base. Reached through `p->`, the object's real size is
//     unknowable from the type — the allocation decides it. On a direct
//     object, `sizeof(S)` IS the allocation and the declared extent is
//     exact, so the warning stays.
//
// The real C99 `char name[]` needs no handling here: an
// IncompleteArrayType never had a constant extent to report.
bool isFlexibleTailMember(const MemberExpr* mem, ASTContext& ctx) {
    const auto* field = dyn_cast<FieldDecl>(mem->getMemberDecl());
    if (!field) return false;
    const auto* arr = ctx.getAsConstantArrayType(field->getType());
    if (!arr || arr->getSize().ugt(1)) return false;  // degenerate only

    bool pointerBase = false;
    for (const MemberExpr* cur = mem; cur;) {
        const auto* f = dyn_cast<FieldDecl>(cur->getMemberDecl());
        if (!f) return false;
        const RecordDecl* rd = f->getParent();
        if (!rd) return false;
        if (!rd->isUnion() && !isLastFieldOf(f, rd)) return false;

        if (cur->isArrow()) pointerBase = true;
        const Expr* base = cur->getBase()->IgnoreParenImpCasts();
        if (const auto* deref = dyn_cast<UnaryOperator>(base))
            if (deref->getOpcode() == UO_Deref) pointerBase = true;
        cur = dyn_cast<MemberExpr>(base);
    }
    return pointerBase;
}

bool destIsFixedArray(const Expr* e, ASTContext& ctx) {
    if (!e) return false;
    e = e->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(e)) {
        const auto* vd = dyn_cast<VarDecl>(ref->getDecl());
        return vd && ctx.getAsConstantArrayType(vd->getType()) != nullptr;
    }
    if (const auto* mem = dyn_cast<MemberExpr>(e)) {
        const auto* field = dyn_cast<FieldDecl>(mem->getMemberDecl());
        if (!field || !ctx.getAsConstantArrayType(field->getType()))
            return false;
        return !isFlexibleTailMember(mem, ctx);
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

// New source-read semantics must not be inferred from a user's same-named
// method, namespace function, definition or incompatible declaration.
bool isGlobalMemoryFunction(const CallExpr* call, llvm::StringRef name,
                            unsigned arity, ASTContext& ctx,
                            QualType returnType = QualType()) {
    const FunctionDecl* callee = call ? call->getDirectCallee() : nullptr;
    if (!callee || !callee->getIdentifier() || callee->getName() != name ||
        call->getNumArgs() != arity || callee->getNumParams() != arity ||
        callee->isVariadic() || callee->hasBody() ||
        !callee->getDeclContext()->getRedeclContext()->isTranslationUnit() ||
        !ctx.hasSameType(callee->getReturnType().getUnqualifiedType(),
                         returnType.isNull() ? ctx.VoidPtrTy : returnType))
        return false;
    return true;
}

bool isSourceCopy(const CallExpr* call, ASTContext& ctx) {
    if (!isGlobalMemoryFunction(call, "memcpy", 3, ctx) &&
        !isGlobalMemoryFunction(call, "memmove", 3, ctx)) return false;
    const auto* callee = call->getDirectCallee();
    return ctx.hasSameType(callee->getParamDecl(0)->getType().getUnqualifiedType(),
                           ctx.VoidPtrTy) &&
           ctx.hasSameType(callee->getParamDecl(1)->getType().getUnqualifiedType(),
                           ctx.getPointerType(ctx.VoidTy.withConst())) &&
           ctx.hasSameType(callee->getParamDecl(2)->getType().getUnqualifiedType(),
                           ctx.getSizeType());
}

bool isDestinationCopy(const CallExpr* call, ASTContext& ctx) {
    if (isSourceCopy(call, ctx)) return true;
    const auto* callee = call->getDirectCallee();
    const auto matches = [&](unsigned index, QualType type) {
        return ctx.hasSameType(callee->getParamDecl(index)->getType().getUnqualifiedType(), type);
    };
    if (isGlobalMemoryFunction(call, "memset", 3, ctx))
        return matches(0, ctx.VoidPtrTy) && matches(1, ctx.IntTy) && matches(2, ctx.getSizeType());
    const QualType chars = ctx.getPointerType(ctx.CharTy);
    if (isGlobalMemoryFunction(call, "strncpy", 3, ctx, chars))
        return matches(0, chars) && matches(1, ctx.getPointerType(ctx.CharTy.withConst())) &&
               matches(2, ctx.getSizeType());
    return false;
}

// A rule-local sole-binding guard for pointers and integer offset constants.
// The element ExtentMap is unchanged: copy slices need raw allocation BYTES,
// including a partial final element, and reject reference/capture mutations.
struct SourceBindings : RecursiveASTVisitor<SourceBindings> {
    std::set<const VarDecl*> unstable;
    bool hasAssembly = false;

    void invalidate(const Expr* expr) {
        if (!expr) return;
        expr = expr->IgnoreParenCasts();
        // Invalidate the binding being written/escaped, not every pointer used
        // to locate it: src[0]=0 and *src=0 only change the allocation's contents.
        if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) {
            if (const auto* var = dyn_cast<VarDecl>(ref->getDecl());
                var && (var->getType().getNonReferenceType()->isPointerType() ||
                        var->getType().getNonReferenceType()->isIntegralOrEnumerationType()))
                unstable.insert(var);
        } else if (const auto* choice = dyn_cast<ConditionalOperator>(expr)) {
            invalidate(choice->getTrueExpr());
            invalidate(choice->getFalseExpr());
        } else if (const auto* comma = dyn_cast<BinaryOperator>(expr);
                   comma && comma->getOpcode() == BO_Comma) {
            invalidate(comma->getRHS());
        }
    }
    bool VisitVarDecl(VarDecl* var) {
        if (var->getType()->isReferenceType()) invalidate(var->getInit());
        return true;
    }
    bool VisitBinaryOperator(BinaryOperator* op) {
        if (op->isAssignmentOp()) invalidate(op->getLHS());
        return true;
    }
    bool VisitUnaryOperator(UnaryOperator* op) {
        if (op->getOpcode() == UO_AddrOf || op->isIncrementDecrementOp())
            invalidate(op->getSubExpr());
        return true;
    }
    bool VisitCallExpr(CallExpr* call) {
        codeskeptic::forEachNonConstRefArg(call, [&](const Expr* arg) { invalidate(arg); });
        return true;
    }
    bool VisitCXXConstructExpr(CXXConstructExpr* call) {
        const auto* constructor = call->getConstructor();
        for (unsigned i = 0; constructor && i < constructor->getNumParams() &&
                             i < call->getNumArgs(); ++i) {
            const QualType type = constructor->getParamDecl(i)->getType();
            if (type->isReferenceType() && !type.getNonReferenceType().isConstQualified())
                invalidate(call->getArg(i));
        }
        return true;
    }
    bool VisitLambdaExpr(LambdaExpr* lambda) {
        for (const auto& capture : lambda->captures())
            if (capture.capturesVariable() && capture.getCaptureKind() == LCK_ByRef)
                if (const auto* var = dyn_cast<VarDecl>(capture.getCapturedVar()))
                    unstable.insert(var);
        return true;
    }
    bool VisitAsmStmt(AsmStmt*) { hasAssembly = true; return true; }
};

codeskeptic::Interval sourceByteCapacity(const Expr* source,
                                        const SourceBindings& bindings,
                                        ASTContext& ctx) {
    using codeskeptic::Interval;
    if (!source) return Interval::top();
    source = source->IgnoreParenCasts();
    // Actual declared array storage and literals carry byte sizes. An array
    // expression created by dereferencing/casting a pointer is only a view,
    // not proof of an allocation upper bound; reference parameters are unknown.
    if (ctx.getAsConstantArrayType(source->getType())) {
        if (const auto* member = dyn_cast<MemberExpr>(source)) {
            if (!isa<FieldDecl>(member->getMemberDecl()) ||
                isFlexibleTailMember(member, ctx)) return Interval::top();
        } else if (const auto* ref = dyn_cast<DeclRefExpr>(source)) {
            const auto* var = dyn_cast<VarDecl>(ref->getDecl());
            if (!var || !ctx.getAsConstantArrayType(var->getType()))
                return Interval::top();
        } else if (!isa<clang::StringLiteral>(source)) {
            return Interval::top();
        }
        if (const auto bytes = codeskeptic::boundedTypeSizeInChars(ctx, source->getType()))
            return Interval::constant(*bytes);
        return Interval::top();
    }
    const auto* ref = dyn_cast<DeclRefExpr>(source);
    const auto* var = ref ? dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
    if (!var || !var->getType()->isPointerType() || !var->hasInit() ||
        var->hasGlobalStorage() || bindings.hasAssembly || bindings.unstable.count(var))
        return Interval::top();
    const auto* alloc = dyn_cast<CallExpr>(var->getInit()->IgnoreParenCasts());
    if (!alloc) return Interval::top();
    const codeskeptic::IntervalMap empty;
    Interval bytes = Interval::top();
    if (isGlobalMemoryFunction(alloc, "malloc", 1, ctx) &&
        ctx.hasSameType(alloc->getDirectCallee()->getParamDecl(0)->getType().getUnqualifiedType(),
                        ctx.getSizeType()))
        bytes = codeskeptic::evalSizeInterval(alloc->getArg(0), ctx, empty);
    else if (isGlobalMemoryFunction(alloc, "calloc", 2, ctx) &&
             ctx.hasSameType(alloc->getDirectCallee()->getParamDecl(0)->getType().getUnqualifiedType(),
                             ctx.getSizeType()) &&
             ctx.hasSameType(alloc->getDirectCallee()->getParamDecl(1)->getType().getUnqualifiedType(),
                             ctx.getSizeType()))
        bytes = Interval::mul(codeskeptic::evalSizeInterval(alloc->getArg(0), ctx, empty),
                              codeskeptic::evalSizeInterval(alloc->getArg(1), ctx, empty));
    return bytes.isEmpty() || bytes.loIsInf() || bytes.lo() < 0 ? Interval::top() : bytes;
}

// Offset constants must not inherit a lossy shared numeric snapshot (notably
// unsigned literal -> local -> wider local). Prove executed sole-initializer
// chains and preserve each operation/cast's actual type. Unsupported or
// int64-unrepresentable intermediate values remain unknown, never truncated.
class CopyOffsetEvaluator {
    const SourceBindings& bindings_;
    const std::set<const VarDecl*>& initialized_;
    ASTContext& ctx_;
    std::set<const VarDecl*> active_;
    unsigned budget_ = 128;

    static std::optional<int64_t> bounded(const llvm::APInt& value, bool sign) {
        if (sign) {
            if (!value.isSignedIntN(64)) return std::nullopt;
            return value.sextOrTrunc(64).getSExtValue();
        }
        if (value.getActiveBits() > 63) return std::nullopt;
        return static_cast<int64_t>(value.zextOrTrunc(64).getZExtValue());
    }
public:
    CopyOffsetEvaluator(const SourceBindings& bindings,
                        const std::set<const VarDecl*>& initialized, ASTContext& ctx)
        : bindings_(bindings), initialized_(initialized), ctx_(ctx) {}

    std::optional<int64_t> evaluate(const Expr* expr, unsigned depth = 0) {
        if (!expr || !budget_ || depth >= 32) return std::nullopt;
        --budget_;
        expr = expr->IgnoreParens();
        if (expr->isValueDependent() || expr->isTypeDependent() ||
            !expr->getType()->isIntegralOrEnumerationType() || expr->HasSideEffects(ctx_))
            return std::nullopt;
        if (const auto* constant = dyn_cast<ConstantExpr>(expr))
            return evaluate(constant->getSubExpr(), depth + 1);
        const auto recurse = [&](const Expr* child) { return evaluate(child, depth + 1); };
        if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) {
            if (const auto* var = dyn_cast<VarDecl>(ref->getDecl())) {
                if (!var->hasInit() || var->hasGlobalStorage() || var->getType()->isReferenceType() ||
                    var->getType().isVolatileQualified() || bindings_.hasAssembly ||
                    bindings_.unstable.count(var) || !initialized_.count(var) ||
                    !active_.insert(var).second) return std::nullopt;
                const auto value = recurse(var->getInit());
                active_.erase(var);
                return value;
            }
        }
        const unsigned width = ctx_.getIntWidth(expr->getType());
        const bool sign = expr->getType()->isSignedIntegerOrEnumerationType();
        if (!width || width > 128) return std::nullopt;
        if (const auto* cast = dyn_cast<CastExpr>(expr)) {
            const auto value = recurse(cast->getSubExpr());
            if (!value) return std::nullopt;
            if (cast->getCastKind() == CK_IntegralToBoolean) return *value != 0;
            if (cast->getCastKind() != CK_LValueToRValue && cast->getCastKind() != CK_NoOp &&
                cast->getCastKind() != CK_IntegralCast) return std::nullopt;
            return bounded(llvm::APInt(64, static_cast<uint64_t>(*value)).sextOrTrunc(width), sign);
        }
        if (const auto* op = dyn_cast<UnaryOperator>(expr)) {
            const auto value = recurse(op->getSubExpr());
            if (!value) return std::nullopt;
            if (op->getOpcode() == UO_Plus) return value;
            if (op->getOpcode() == UO_LNot) return *value == 0;
            if (op->getOpcode() != UO_Minus) return std::nullopt;
            const llvm::APInt operand = llvm::APInt(64, static_cast<uint64_t>(*value)).sextOrTrunc(width);
            bool overflow = false;
            const auto result = sign ? llvm::APInt(width, 0).ssub_ov(operand, overflow)
                                     : -operand;
            return overflow ? std::nullopt : bounded(result, sign);
        }
        if (const auto* op = dyn_cast<BinaryOperator>(expr)) {
            const auto left = recurse(op->getLHS()), right = recurse(op->getRHS());
            if (!left || !right) return std::nullopt;
            const auto a = llvm::APInt(64, static_cast<uint64_t>(*left)).sextOrTrunc(width);
            const auto b = llvm::APInt(64, static_cast<uint64_t>(*right)).sextOrTrunc(width);
            bool overflow = false;
            llvm::APInt result(width, 0);
            switch (op->getOpcode()) {
            case BO_Add: result = sign ? a.sadd_ov(b, overflow) : a + b; break;
            case BO_Sub: result = sign ? a.ssub_ov(b, overflow) : a - b; break;
            case BO_Mul: result = sign ? a.smul_ov(b, overflow) : a * b; break;
            case BO_And: result = a & b; break;
            case BO_Or: result = a | b; break;
            case BO_Xor: result = a ^ b; break;
            case BO_Shl:
                if (*right < 0 || static_cast<uint64_t>(*right) >= width ||
                    (sign && (*left < 0 || a.getActiveBits() + *right >= width)))
                    return std::nullopt;
                result = a.shl(static_cast<unsigned>(*right));
                break;
            case BO_Shr:
                if (*right < 0 || static_cast<uint64_t>(*right) >= width) return std::nullopt;
                result = sign ? a.ashr(static_cast<unsigned>(*right))
                              : a.lshr(static_cast<unsigned>(*right));
                break;
            default: return std::nullopt;
            }
            return overflow ? std::nullopt : bounded(result, sign);
        }
        if (const auto* size = dyn_cast<UnaryExprOrTypeTraitExpr>(expr)) {
            if (size->getKind() != UETT_SizeOf) return std::nullopt;
            return codeskeptic::boundedTypeSizeInChars(ctx_, size->getTypeOfArgument());
        }
        if (!isa<IntegerLiteral>(expr) && !isa<CharacterLiteral>(expr) &&
            !isa<CXXBoolLiteralExpr>(expr) && !isa<DeclRefExpr>(expr)) return std::nullopt;
        Expr::EvalResult result;
        if (!expr->EvaluateAsInt(result, ctx_) || !result.Val.isInt()) return std::nullopt;
        const auto& value = result.Val.getInt();
        return bounded(value, value.isSigned());
    }
};

struct CopySlice {
    codeskeptic::Interval bytes;  // root storage's raw allocation bytes
    int64_t offset = 0;          // byte displacement, not element count
    bool hasOffset = false;
};

CopySlice copySlice(const Expr* expr, const SourceBindings& bindings,
                    const std::set<const VarDecl*>& initialized, ASTContext& ctx,
                    unsigned depth = 0) {
    using codeskeptic::Interval;
    if (!expr || depth >= 32) return {};
    expr = expr->IgnoreParens();
    if (const auto* cast = dyn_cast<CastExpr>(expr)) {
        // Only address-preserving casts; derived-base adjustments and
        // integer/pointer round trips do not establish a root storage address.
        const CastKind kind = cast->getCastKind();
        if (cast->getType()->isPointerType() &&
            (kind == CK_ArrayToPointerDecay || kind == CK_BitCast ||
             kind == CK_NoOp || kind == CK_LValueToRValue))
            return copySlice(cast->getSubExpr(), bindings, initialized, ctx, depth + 1);
        return {};
    }
    const Expr* base = nullptr;
    const Expr* index = nullptr;
    bool subtract = false;
    if (const auto* op = dyn_cast<BinaryOperator>(expr)) {
        if ((op->getOpcode() == BO_Add || op->getOpcode() == BO_Sub) &&
            op->getLHS()->getType()->isPointerType()) {
            base = op->getLHS(); index = op->getRHS();
            subtract = op->getOpcode() == BO_Sub;
        } else if (op->getOpcode() == BO_Add && op->getRHS()->getType()->isPointerType()) {
            base = op->getRHS(); index = op->getLHS();
        }
    } else if (const auto* address = dyn_cast<UnaryOperator>(expr);
               address && address->getOpcode() == UO_AddrOf) {
        const Expr* operand = address->getSubExpr()->IgnoreParens();
        if (const auto* sub = dyn_cast<ArraySubscriptExpr>(operand)) {
            base = sub->getBase(); index = sub->getIdx();
        } else if (operand->getType()->isArrayType()) {
            return copySlice(operand, bindings, initialized, ctx, depth + 1);
        }
    }
    if (base && index) {
        CopySlice result = copySlice(base, bindings, initialized, ctx, depth + 1);
        result.hasOffset = true;
        const auto offset = CopyOffsetEvaluator(bindings, initialized, ctx).evaluate(index);
        const QualType element = base->getType()->getPointeeType();
        const auto scale = element.isNull() || element->isVoidType()
            ? std::nullopt : codeskeptic::boundedTypeSizeInChars(ctx, element);
        if (!offset || !scale || *scale <= 0) return {Interval::top(), 0, true};
        const auto delta = Interval::mul(Interval::constant(*offset), Interval::constant(*scale));
        const auto combined = subtract ? Interval::sub(Interval::constant(result.offset), delta)
                                       : Interval::add(Interval::constant(result.offset), delta);
        if (!combined.isSingleton(&result.offset)) return {Interval::top(), 0, true};
        return result;
    }
    const auto* ref = dyn_cast<DeclRefExpr>(expr);
    const auto* var = ref ? dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
    if (var && var->getType()->isPointerType() && !initialized.count(var)) return {};
    const auto capacity = sourceByteCapacity(expr, bindings, ctx);
    if (!capacity.isEmpty() && !capacity.hiIsInf()) return {capacity, 0, false};
    // Bounded stable aliases may name an offset expression. A changed or
    // escaped pointer anywhere in the chain cannot contribute stale capacity.
    if (var && var->getType()->isPointerType() && var->hasInit() &&
        !var->hasGlobalStorage() && !bindings.hasAssembly && !bindings.unstable.count(var))
        return copySlice(var->getInit(), bindings, initialized, ctx, depth + 1);
    return {};
}

// Taking &array[N] forms the legal one-past pointer; it does not read element
// N. A plain array[N] read and an address strictly beyond N remain distinct.
bool isAddressOperand(const ArraySubscriptExpr* sub, ASTContext& ctx) {
    auto node = DynTypedNode::create(*sub);
    for (unsigned depth = 0; depth < 32; ++depth) {
        const auto parents = ctx.getParents(node);
        if (parents.size() != 1) return false;
        if (const auto* paren = parents[0].get<ParenExpr>()) {
            node = DynTypedNode::create(*paren);
            continue;
        }
        const auto* op = parents[0].get<UnaryOperator>();
        return op && op->getOpcode() == UO_AddrOf;
    }
    return false;
}

// Keep infeasibility explicit for the new source model. A constant copy size
// does not inherit an unrelated variable's empty interval. Nor can a later
// assignment or loop widening make a contradictory path executable again.
// This adapter also governs new offset destinations; the legacy direct
// destination analysis is unchanged.
class SourceReadAnalysis : public codeskeptic::IntervalAnalysis {
    using Base = codeskeptic::IntervalAnalysis;
    std::map<const Stmt*, std::set<const VarDecl*>> initializedAt_;
public:
    using Base::Base;
    struct State {
        codeskeptic::IntervalState numeric;
        bool feasible = true;
        std::set<const VarDecl*> initialized;
        bool operator==(const State& other) const {
            return feasible == other.feasible && (!feasible ||
                (numeric == other.numeric && initialized == other.initialized));
        }
        bool operator!=(const State& other) const { return !(*this == other); }
    };
    static State checked(codeskeptic::IntervalState numeric,
                         std::set<const VarDecl*> initialized = {}) {
        const bool feasible = std::none_of(numeric.iv.begin(), numeric.iv.end(),
            [](const auto& entry) { return entry.second.isEmpty(); });
        return {std::move(numeric), feasible, std::move(initialized)};
    }
    State initialState() const { return checked(Base::initialState()); }
    State merge(const State& a, const State& b) const {
        if (!a.feasible) return b;
        if (!b.feasible) return a;
        std::set<const VarDecl*> initialized;
        for (const auto* var : a.initialized)
            if (b.initialized.count(var)) initialized.insert(var);
        return checked(Base::merge(a.numeric, b.numeric), std::move(initialized));
    }
    State transfer(const Stmt* stmt, const State& in, ASTContext& ctx) const {
        if (!in.feasible) return in;
        State out = checked(Base::transfer(stmt, in.numeric, ctx), in.initialized);
        if (const auto* declarations = dyn_cast<DeclStmt>(stmt))
            for (const auto* declaration : declarations->decls())
                if (const auto* var = dyn_cast<VarDecl>(declaration); var && var->hasInit())
                    out.initialized.insert(var);
        return out;
    }
    void refineOnEdge(const Stmt* cond, bool truth, State& state, ASTContext& ctx) const {
        if (!state.feasible) return;
        Base::refineOnEdge(cond, truth, state.numeric, ctx);
        state = checked(std::move(state.numeric), std::move(state.initialized));
    }
    void widen(State& state) const {
        if (state.feasible) Base::widen(state.numeric);
    }
    void onStatement(const Stmt* stmt, const State& before, const State& after,
                     ASTContext& ctx) {
        if (before.feasible) {
            Base::onStatement(stmt, before.numeric, after.numeric, ctx);
            initializedAt_[stmt] = before.initialized;
        }
    }
    const std::set<const VarDecl*>* initializedAt(const Stmt* stmt) const {
        const auto found = initializedAt_.find(stmt);
        return found == initializedAt_.end() ? nullptr : &found->second;
    }
};

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
        codeskeptic::CoverageReport::instance().recordDataflowFailure(
            fn->getQualifiedNameAsString(), df.failure);

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
            (isAddressOperand(sub, ctx) ? idx.lo() > extent.hi() : idx.lo() >= extent.hi());
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

    // Copy-size overflow: memcpy/memmove/memset/strncpy(dst, ..., n)
    // writes n bytes into dst. When dst has a proven byte capacity:
    //  - DEFINITE (CWE-787, error): n's proven minimum exceeds even the
    //    largest possible capacity — every execution overflows.
    //  - POSSIBLE-UNTRUSTED (CWE-120, warning): n DERIVES from a
    //    declared untrusted-integer source (atoi/strtol/scanf or
    //    --untrusted-int-sources) and its proven FINITE range reaches
    //    past the capacity. The range is attacker-chosen by the source
    //    contract, so reachability is by construction — this is the
    //    docs/untrusted-length.md increment. A guard (`if (n <= cap)`)
    //    narrows the range on its own edge and silences it; an unknown
    //    (top) length without a finite, conversion-preserved nonnegative
    //    source subset stays silent — provenance alone never reports.
    // Byte capacity = element count (ExtentMap) * element size.
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
        if (sz.isEmpty()) continue;  // unreachable

        const bool definite =
            !sz.loIsInf() && sz.lo() > capacity.hi();
        const auto warningRange = copyWarningRange(call->getArg(2), ctx,
                                                   st ? *st : emptyState, sz);
        bool possibleUntrusted = false;
        if (!definite && !warningRange.isEmpty() && !warningRange.hiIsInf() &&
            warningRange.hi() > capacity.hi()) {
            const auto* un = analysis.untrustedAt(call);
            possibleUntrusted =
                un && codeskeptic::exprDerivesFromUntrusted(call->getArg(2),
                                                            *un);
        }
        if (!definite && !possibleUntrusted) continue;

        SourceLocation loc = sm.getExpansionLoc(call->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines.insert(line).second) continue;

        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "bounds";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = definite ? codeskeptic::Severity::Error
                                 : codeskeptic::Severity::Warning;
        diag.message =
            definite ? codeskeptic::msg(codeskeptic::MsgId::BoundsCopyOverflow,
                                        sz.toString(),
                                        std::to_string(capacity.hi()))
                     : codeskeptic::msg(
                           codeskeptic::MsgId::BoundsCopyUntrustedLen,
                           copyWarningRangeText(sz, warningRange), std::to_string(capacity.hi()));
        results.push_back(std::move(diag));
    }

    // Byte slices share checked offset/alias semantics, but source and
    // destination diagnostics remain independent. Direct destinations above
    // retain their existing model; this pass adds offset destinations only.
    if (df.converged && std::any_of(copies.begin(), copies.end(),
                                  [&](const CallExpr* call) { return isDestinationCopy(call, ctx); })) {
        SourceReadAnalysis sourceAnalysis(collectIntVars(fn),
                                          codeskeptic::paramSeeds(paramMap, fn));
        const auto sourceDf = codeskeptic::runDataflow(fn, ctx, sourceAnalysis);
        if (!sourceDf.converged)
            codeskeptic::CoverageReport::instance().recordDataflowFailure(
                fn->getQualifiedNameAsString(), sourceDf.failure);
        SourceBindings bindings;
        bindings.TraverseStmt(fn->getBody());
        for (const auto* call : copies) {
            if (!sourceDf.converged || !isDestinationCopy(call, ctx)) continue;
            const auto* state = sourceAnalysis.stateAt(call);
            const auto* initialized = sourceAnalysis.initializedAt(call);
            if (!state || !initialized) continue;
            const auto size = codeskeptic::evalSizeInterval(call->getArg(2), ctx, *state);
            if (size.isEmpty()) continue;
            const auto warningRange = copyWarningRange(call->getArg(2), ctx, *state, size);
            const auto report = [&](unsigned argument, bool source) {
                const auto slice = copySlice(call->getArg(argument), bindings, *initialized, ctx);
                if ((!source && !slice.hasOffset) || slice.bytes.isEmpty() || slice.bytes.hiIsInf())
                    return;
                const bool beforeStart = slice.offset < 0;
                const int64_t remaining = beforeStart || slice.offset > slice.bytes.hi()
                    ? 0 : slice.bytes.hi() - slice.offset;
                const bool definite = !size.loIsInf() && size.lo() > remaining;
                const auto* origins = sourceAnalysis.untrustedAt(call);
                const bool possible = !source && !definite && !warningRange.isEmpty() &&
                    !warningRange.hiIsInf() && warningRange.hi() > remaining && origins &&
                    codeskeptic::exprDerivesFromUntrusted(call->getArg(2), *origins);
                if (!definite && !possible) return;
                const SourceLocation loc = sm.getExpansionLoc(call->getBeginLoc());
                codeskeptic::Diagnostic diag;
                diag.file = sm.getFilename(loc).str();
                diag.line = sm.getSpellingLineNumber(loc);
                diag.column = sm.getSpellingColumnNumber(loc);
                diag.rule_id = "bounds";
                diag.function = fn->getQualifiedNameAsString();
                diag.severity = definite ? codeskeptic::Severity::Error : codeskeptic::Severity::Warning;
                if (beforeStart) {
                    diag.message = codeskeptic::currentLang() == codeskeptic::Lang::TR
                        ? std::string(source ? "kaynak (CWE-125)" : "hedef (CWE-787)") + " pointer tampon baslangicindan once; " +
                          size.toString() + " baytlik kopya sinir disina erisebilir"
                        : std::string(source ? "source (CWE-125)" : "destination (CWE-787)") + " pointer is before its buffer; " +
                          size.toString() + " byte copy can access outside the buffer";
                } else if (!source) {
                    diag.message = codeskeptic::msg(definite ? codeskeptic::MsgId::BoundsCopyOverflow
                                                            : codeskeptic::MsgId::BoundsCopyUntrustedLen,
                                                    definite ? size.toString() : copyWarningRangeText(size, warningRange),
                                                    std::to_string(remaining));
                } else {
                    diag.message = codeskeptic::currentLang() == codeskeptic::Lang::TR
                        ? "kaynak tampon siniri disinda okuma (CWE-125): " + size.toString() +
                          " baytlik kopya, kaynagin " + std::to_string(remaining) + " baytlik kapasitesini asiyor"
                        : "source buffer over-read (CWE-125): copy size " + size.toString() +
                          " exceeds the source's capacity of " + std::to_string(remaining) + " byte(s)";
                }
                results.push_back(std::move(diag));
            };
            report(0, false);
            if (isSourceCopy(call, ctx)) report(1, true);
        }
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
