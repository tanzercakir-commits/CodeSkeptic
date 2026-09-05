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
#include <limits>
#include <map>
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

// A conversion feeding a heap allocator's size argument is DELIBERATELY
// out of this rule's scope: a negative-turned-huge allocation request
// is caught by the allocator's own contract (calloc even proves the
// nmemb*size overflow) and, when the result is used unchecked, it is
// the null-deref rule's finding, not a sign story. Excluding it is what
// keeps the ubiquitous `n = atoi(argv[1]); p = calloc(n, ...); if (!p)`
// idiom silent — the thesis corpus's array_from_int.c, ground-truth
// clean. The rule's own territory is the NON-allocator use nlohmann
// showed: a length stored/returned/used for access with no NULL net.
// The allocator predicate is shared (engine/AllocFunctions.h) with
// AllocSizeOverflowRule, which owns the opposite half.

// The rule's claim is "a negative value reinterpreted as a huge LENGTH".
// Some unsigned typedefs are NOT lengths — mode_t (permission bits),
// dev_t (a device id), uid_t/gid_t (identities). An untrusted signed
// value converting into one of these is a real conversion but not THIS
// rule's story, and the "negative length" message misframes it
// (libarchive v3.8.9 eval, BULGU 2: file modes/rdevs set from archive
// headers). This is a DENYLIST, not an allowlist, on purpose: a
// fail-closed "only size_t-family fires" gate would also silence the
// uintN_t lengths read straight off the wire — the rule's flagship case.
// So raw builtins, size_t, and the exact-width unsigned types all keep
// firing; only these named identity/permission typedefs are exempt. The
// whole typedef chain is walked because glibc spells dev_t as __dev_t.
bool isNonSizeUnsignedSink(QualType dst) {
    static const std::set<std::string> kNonSize = {
        "mode_t",   "dev_t",   "uid_t",   "gid_t",   "ino_t",   "nlink_t",
        "__mode_t", "__dev_t", "__uid_t", "__gid_t", "__ino_t", "__nlink_t",
    };
    for (QualType t = dst;;) {
        const auto* tt = t->getAs<TypedefType>();
        if (!tt) return false;
        if (kNonSize.count(tt->getDecl()->getName().str())) return true;
        t = tt->getDecl()->getUnderlyingType();
    }
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

        void consider(const Expr* cast, const Expr* operand, QualType dst) {
            if (!operand) return;
            if (allocArgExprs.count(cast)) return;  // allocator size arg
            QualType src = operand->getType();
            if (!dst->isIntegerType() || !dst->isUnsignedIntegerType())
                return;
            if (!src->isIntegerType() || !src->isSignedIntegerType())
                return;
            if (isNonSizeUnsignedSink(dst)) return;  // not a length sink
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

bool subtreeContains(const Stmt* root, const Stmt* needle) {
    if (!root) return false;
    if (root == needle) return true;
    for (const Stmt* child : root->children())
        if (subtreeContains(child, needle)) return true;
    return false;
}

const VarDecl* directVar(const Expr* expr) {
    if (!expr) return nullptr;
    const auto* ref =
        dyn_cast<DeclRefExpr>(expr->IgnoreParenImpCasts());
    return ref ? dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
}

// A post-cast bound must be a distinct integer variable (remaining buffer
// length, packet size, ...). Constants and arithmetic expressions are
// intentionally excluded: either can admit wrapped negatives without a
// separately proven range.
bool independentIntegerBound(const Expr* expr, const VarDecl* converted) {
    const VarDecl* bound = directVar(expr);
    return bound && bound != converted &&
           bound->getType()->isIntegerType();
}

bool hasIndependentUpperBound(const Expr* cond, const VarDecl* converted) {
    if (!cond) return false;
    const Expr* stripped = cond->IgnoreParenImpCasts();
    if (const auto* bin = dyn_cast<BinaryOperator>(stripped)) {
        // A true conjunction entails both operands; a disjunction does
        // not entail either one and must never suppress the finding.
        if (bin->getOpcode() == BO_LAnd)
            return hasIndependentUpperBound(bin->getLHS(), converted) ||
                   hasIndependentUpperBound(bin->getRHS(), converted);
        const VarDecl* lhs = directVar(bin->getLHS());
        const VarDecl* rhs = directVar(bin->getRHS());
        if ((bin->getOpcode() == BO_LE || bin->getOpcode() == BO_LT) &&
            lhs == converted &&
            independentIntegerBound(bin->getRHS(), converted))
            return true;
        if ((bin->getOpcode() == BO_GE || bin->getOpcode() == BO_GT) &&
            rhs == converted &&
            independentIntegerBound(bin->getLHS(), converted))
            return true;
    }
    return false;
}

// Precision proof for the rtp2httpd body-skip idiom. The conversion must
// initialize a dedicated unsigned local; every read of that local must
// occur either in a qualifying range condition or in its true branch.
// A later/outside/else use keeps the finding.
bool allPostCastUsesRangeGuarded(const FunctionDecl* fn,
                                const ConvSite& site) {
    struct DestinationVisitor : RecursiveASTVisitor<DestinationVisitor> {
        const Expr* cast = nullptr;
        std::set<const VarDecl*> matches;
        bool VisitVarDecl(VarDecl* vd) {
            if (vd->hasInit() && vd->getType()->isUnsignedIntegerType() &&
                subtreeContains(vd->getInit(), cast))
                matches.insert(vd);
            return true;
        }
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    } destination;
    destination.cast = site.cast;
    destination.TraverseStmt(const_cast<Stmt*>(fn->getBody()));
    if (destination.matches.size() != 1) return false;
    const VarDecl* converted = *destination.matches.begin();

    struct UseVisitor : RecursiveASTVisitor<UseVisitor> {
        const VarDecl* converted = nullptr;
        std::vector<const DeclRefExpr*> uses;
        std::vector<const IfStmt*> guards;
        bool VisitDeclRefExpr(DeclRefExpr* ref) {
            if (ref->getDecl() == converted) uses.push_back(ref);
            return true;
        }
        bool VisitIfStmt(IfStmt* stmt) {
            if (hasIndependentUpperBound(stmt->getCond(), converted))
                guards.push_back(stmt);
            return true;
        }
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    } use;
    use.converted = converted;
    use.TraverseStmt(const_cast<Stmt*>(fn->getBody()));
    if (use.uses.empty() || use.guards.empty()) return false;

    bool consumedInTrueBranch = false;
    for (const DeclRefExpr* ref : use.uses) {
        bool covered = false;
        for (const IfStmt* guard : use.guards) {
            if (subtreeContains(guard->getCond(), ref)) {
                covered = true;
                break;
            }
            if (subtreeContains(guard->getThen(), ref)) {
                covered = true;
                consumedInTrueBranch = true;
                break;
            }
        }
        if (!covered) return false;
    }
    return consumedInTrueBranch;
}

struct NarrowingProof {
    const Expr* operand;
    codeskeptic::Interval range;
};
using NarrowingProofs = std::map<const Expr*, NarrowingProof>;

bool hasNarrowingCandidate(const FunctionDecl* fn, ASTContext& ctx) {
    struct V : RecursiveASTVisitor<V> {
        ASTContext& ctx;
        bool found = false;
        explicit V(ASTContext& c) : ctx(c) {}
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
        bool VisitImplicitCastExpr(ImplicitCastExpr* cast) {
            const auto src = cast->getSubExpr()->getType(), dst = cast->getType();
            found = cast->getCastKind() == CK_IntegralCast && !cast->isPartOfExplicitCast() &&
                !cast->isTypeDependent() && src->isIntegerType() && dst->isIntegerType() &&
                ctx.getIntWidth(dst) < ctx.getIntWidth(src);
            return !found;
        }
    } visitor(ctx);
    visitor.TraverseStmt(const_cast<Stmt*>(fn->getBody()));
    return visitor.found;
}

// This extension owns only implicit scalar/literal narrowing reaching a
// recognized length/index sink. Signed arithmetic remains IntOverflowRule's
// responsibility; explicit casts, enums, bool and unrepresentable facts are
// deliberately not interpreted as a new loss proof.
NarrowingProofs collectNarrowingProofs(const FunctionDecl* fn, ASTContext& ctx,
                                     const codeskeptic::IntervalAnalysis& analysis) {
    struct V : RecursiveASTVisitor<V> {
        ASTContext& ctx;
        const codeskeptic::IntervalAnalysis& analysis;
        NarrowingProofs proofs;
        V(ASTContext& c, const codeskeptic::IntervalAnalysis& a) : ctx(c), analysis(a) {}
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
        bool VisitImplicitCastExpr(ImplicitCastExpr* cast) {
            if (cast->getCastKind() != CK_IntegralCast || cast->isPartOfExplicitCast() ||
                cast->isTypeDependent() || cast->isValueDependent()) return true;
            const Expr* operand = cast->getSubExpr();
            const QualType src = operand->getType(), dst = cast->getType();
            if (!src->isIntegerType() || !dst->isIntegerType() || src->isEnumeralType() ||
                dst->isEnumeralType() || src->isBooleanType() || dst->isBooleanType() ||
                isNonSizeUnsignedSink(dst)) return true;
            const unsigned srcBits = ctx.getIntWidth(src), dstBits = ctx.getIntWidth(dst);
            if (srcBits > 64 || dstBits >= srcBits || dstBits == 0) return true;
            const Expr* value = operand->IgnoreParenImpCasts();
            if (!isa<DeclRefExpr>(value) && !isa<IntegerLiteral>(value)) return true;
            if (const auto* var = directVar(value); var && var->getType().isVolatileQualified()) return true;
            const codeskeptic::IntervalMap* state = analysis.stateAt(cast);
            if (!state) state = analysis.stateAt(operand);
            if (!state) state = analysis.stateAt(value);
            if (!state) return true;
            auto range = codeskeptic::evalInterval(operand, *state, &ctx);
            // Interpret literal bits using the actual AST signedness. The
            // shared signed interval domain cannot represent large uint64s.
            if (const auto* literal = dyn_cast<IntegerLiteral>(value)) {
                const auto& bits = literal->getValue();
                if (src->isUnsignedIntegerType()) {
                    if (bits.getActiveBits() > 63) return true;
                    range = codeskeptic::Interval::constant(static_cast<int64_t>(bits.getZExtValue()));
                } else range = codeskeptic::Interval::constant(bits.getSExtValue());
            }
            if (range.isEmpty() || range.loIsInf() || range.hiIsInf()) return true;
            if (src->isUnsignedIntegerType() && range.lo() < 0) return true;
            if (src->isSignedIntegerType() && !range.fitsSignedBits(srcBits)) return true;
            if (src->isUnsignedIntegerType() && srcBits < 64 &&
                static_cast<uint64_t>(range.hi()) >= (uint64_t{1} << srcBits)) return true;
            const int64_t minimum = dst->isUnsignedIntegerType() ? 0 : -(int64_t{1} << (dstBits - 1));
            const int64_t maximum = dst->isUnsignedIntegerType() ?
                static_cast<int64_t>((uint64_t{1} << dstBits) - 1) : (int64_t{1} << (dstBits - 1)) - 1;
            if (range.lo() >= minimum && range.hi() <= maximum) return true;
            // Existing negative-to-unsigned reports keep their own proof and
            // post-cast guard policy, without a second report for the same cast.
            const auto* untrusted = analysis.untrustedAt(cast);
            if (!untrusted) untrusted = analysis.untrustedAt(operand);
            if (!untrusted) untrusted = analysis.untrustedAt(value);
            if (src->isSignedIntegerType() && dst->isUnsignedIntegerType() && range.lo() < 0 &&
                untrusted && codeskeptic::exprDerivesFromUntrusted(operand, *untrusted)) return true;
            proofs.emplace(cast, NarrowingProof{operand, range});
            return true;
        }
    } visitor(ctx, analysis);
    visitor.TraverseStmt(const_cast<Stmt*>(fn->getBody()));
    return visitor.proofs;
}

// A small finite origin lattice, separate from numeric ranges: replacing the
// original source cannot rewrite the value already stored in a narrow local.
// Address/reference-exposed locals are conservatively outside this direct-value
// subset. No pointer-alias or interprocedural length propagation is claimed.
class NarrowingFlow {
public:
    using Origins = std::set<const Expr*>;
    using State = std::map<const VarDecl*, Origins>;
    NarrowingFlow(const NarrowingProofs& proofs, const FunctionDecl* fn,
                  const codeskeptic::IntervalAnalysis& analysis) : proofs_(proofs), analysis_(analysis) {
        struct Escapes : RecursiveASTVisitor<Escapes> {
            std::set<const VarDecl*> vars;
            bool TraverseLambdaExpr(LambdaExpr*) { return true; }
            bool VisitUnaryOperator(UnaryOperator* op) {
                if (op->getOpcode() == UO_AddrOf)
                    if (const auto* var = directVar(op->getSubExpr())) vars.insert(var);
                return true;
            }
            bool VisitVarDecl(VarDecl* var) {
                if (var->getType()->isReferenceType() && var->hasInit())
                    if (const auto* target = directVar(var->getInit())) vars.insert(target);
                return true;
            }
            bool VisitCallExpr(CallExpr* call) {
                const auto* fn = call->getDirectCallee();
                if (!fn) return true;
                for (unsigned i = 0; i < call->getNumArgs() && i < fn->getNumParams(); ++i)
                    if (fn->getParamDecl(i)->getType()->isReferenceType())
                        if (const auto* var = directVar(call->getArg(i))) vars.insert(var);
                return true;
            }
        } escapes;
        escapes.TraverseStmt(const_cast<Stmt*>(fn->getBody()));
        excluded_ = std::move(escapes.vars);
        variables_ = collectIntVars(fn).size();
    }
    State initialState() const { return {}; }
    unsigned latticeHeight() const { return static_cast<unsigned>((proofs_.size() + 1) * (variables_ + 1) + 4); }
    State merge(const State& a, const State& b) const {
        // A mixed/unknown join is not a proof that this exact stored value
        // reaches the sink. Retain only the origins common to both paths.
        State out;
        for (const auto& [var, origins] : a) {
            const auto other = b.find(var);
            if (other == b.end()) continue;
            for (const Expr* origin : origins)
                if (other->second.count(origin)) out[var].insert(origin);
        }
        return out;
    }
    Origins origins(const Expr* expr, const State& state, unsigned depth = 0) const {
        if (!expr || depth >= 32) return {};
        expr = expr->IgnoreParens();
        if (const auto proof = proofs_.find(expr); proof != proofs_.end())
            return excluded_.count(directVar(proof->second.operand)) ? Origins{} : Origins{expr};
        if (const auto* cast = dyn_cast<ImplicitCastExpr>(expr)) {
            if (cast->getCastKind() == CK_LValueToRValue || cast->getCastKind() == CK_NoOp ||
                (cast->getCastKind() == CK_IntegralCast &&
                 cast->getType()->isIntegerType() && cast->getSubExpr()->getType()->isIntegerType()))
                return origins(cast->getSubExpr(), state, depth + 1);
            return {};
        }
        const auto found = state.find(directVar(expr));
        return found == state.end() ? Origins{} : found->second;
    }
    State transfer(const Stmt* stmt, const State& before, ASTContext&) const {
        State after = before;
        auto assign = [&](const VarDecl* var, const Expr* value) {
            if (!var || !var->hasLocalStorage() || !var->getType()->isIntegerType() ||
                var->getType().isVolatileQualified() || excluded_.count(var)) return;
            auto sources = origins(value, after);
            if (sources.empty()) after.erase(var);
            else after[var] = std::move(sources);
        };
        if (const auto* decl = dyn_cast<DeclStmt>(stmt)) {
            for (const auto* item : decl->decls())
                if (const auto* var = dyn_cast<VarDecl>(item)) assign(var, var->getInit());
        } else if (const auto* assignment = dyn_cast<BinaryOperator>(stmt); assignment && assignment->isAssignmentOp()) {
            assign(directVar(assignment->getLHS()), assignment->getOpcode() == BO_Assign ? assignment->getRHS() : nullptr);
        } else if (const auto* unary = dyn_cast<UnaryOperator>(stmt); unary && unary->isIncrementDecrementOp()) {
            assign(directVar(unary->getSubExpr()), nullptr);
        }
        return after;
    }
    void onStatement(const Stmt* stmt, const State& before, const State&, ASTContext& ctx) {
        const auto* numeric = analysis_.stateAt(stmt);
        if (!numeric) return;
        for (const auto& [var, range] : *numeric) {
            (void)var;
            if (range.isEmpty()) return; // no reachable valuation at this sink
        }
        const Expr* value = nullptr;
        if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(stmt)) value = subscript->getIdx();
        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            const auto* callee = call->getDirectCallee();
            if (callee && !isa<CXXMethodDecl>(callee) && callee->getDeclContext()->getRedeclContext()->isTranslationUnit() &&
                !callee->hasBody() && !callee->isVariadic() && callee->getNumParams() == 3 && call->getNumArgs() == 3) {
                const auto name = callee->getNameAsString();
                const auto first = callee->getParamDecl(0)->getType();
                const auto second = callee->getParamDecl(1)->getType();
                const auto size = callee->getParamDecl(2)->getType();
                const bool memory = name == "memcpy" || name == "memmove";
                if ((memory || name == "memset") && first->isVoidPointerType() &&
                    (memory ? second->isVoidPointerType() : second->isSpecificBuiltinType(BuiltinType::Int)) &&
                    callee->getReturnType()->isVoidPointerType() && ctx.hasSameType(size, ctx.getSizeType()))
                    value = call->getArg(2);
            }
        }
        auto found = origins(value, before);
        consumed.insert(found.begin(), found.end());
    }
    Origins consumed;
private:
    const NarrowingProofs& proofs_;
    const codeskeptic::IntervalAnalysis& analysis_;
    std::set<const VarDecl*> excluded_;
    size_t variables_ = 0;
};

void analyzeFunction(const FunctionDecl* fn, ASTContext& ctx,
                     const codeskeptic::ParamIntervalMap& paramMap,
                     codeskeptic::DiagnosticList& results) {
    if (!fn->hasBody()) return;

    auto sites = collectConvSites(fn);
    if (sites.empty() && !hasNarrowingCandidate(fn, ctx)) return;

    codeskeptic::IntervalAnalysis analysis(
        collectIntVars(fn), codeskeptic::paramSeeds(paramMap, fn));
    auto df = codeskeptic::runDataflow(fn, ctx, analysis);
    if (!df.converged)
        codeskeptic::CoverageReport::instance().recordDataflowFailure(
            fn->getQualifiedNameAsString(), df.failure);

    if (df.converged) {
        const auto proofs = collectNarrowingProofs(fn, ctx, analysis);
        if (!proofs.empty()) {
            NarrowingFlow flow(proofs, fn, analysis);
            const auto propagation = codeskeptic::runDataflow(fn, ctx, flow);
            if (!propagation.converged)
                codeskeptic::CoverageReport::instance().recordDataflowFailure(fn->getQualifiedNameAsString(), propagation.failure);
            else for (const Expr* cast : flow.consumed) {
                const auto& proof = proofs.at(cast);
                const auto& sm = ctx.getSourceManager();
                const auto loc = sm.getExpansionLoc(cast->getBeginLoc());
                codeskeptic::Diagnostic diag;
                diag.file = sm.getFilename(loc).str();
                diag.line = sm.getSpellingLineNumber(loc);
                diag.column = sm.getSpellingColumnNumber(loc);
                diag.rule_id = "sign-conversion";
                diag.function = fn->getQualifiedNameAsString();
                diag.severity = codeskeptic::Severity::Warning;
                diag.message = "Lossy implicit narrowing from '" + proof.operand->getType().getAsString() +
                    "' to '" + cast->getType().getAsString() + "': proven source range " + proof.range.toString() +
                    " exceeds the destination range and reaches a length/index sink (CWE-681)";
                results.push_back(std::move(diag));
            }
        }
    }

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

        // A wrapped value that is used only behind an independent
        // post-cast capacity check cannot reach the sink on the bad
        // path. Any use outside that true branch remains reportable.
        if (allPostCastUsesRangeGuarded(fn, site)) continue;

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
