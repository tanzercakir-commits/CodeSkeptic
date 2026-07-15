#include "engine/ParamIntervals.h"

#include "engine/IntervalEval.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>

#include <set>

using namespace clang;

namespace zerodefect {

namespace {

// One TU walk: collects internal-linkage function definitions, the
// direct-callee DeclRefExprs (call positions), every function-valued
// DeclRefExpr (to detect address-taken), and every call site.
struct TuVisitor : RecursiveASTVisitor<TuVisitor> {
    // Candidate functions (canonical): internal linkage + has body.
    std::set<const FunctionDecl*> candidates;
    // Functions whose address is taken (canonical) — used as a value
    // somewhere other than a direct call callee.
    std::set<const FunctionDecl*> addressTaken;
    // DeclRefExprs that ARE a call's direct callee (so referencing the
    // function there is NOT taking its address).
    std::set<const Expr*> calleeRefs;
    // Call sites: (callee canonical, the call expr).
    std::vector<std::pair<const FunctionDecl*, const CallExpr*>> calls;

    static const FunctionDecl* canonicalCandidate(const FunctionDecl* fn) {
        if (!fn) return nullptr;
        fn = fn->getCanonicalDecl();
        // Internal linkage: cannot be called from another TU, so every
        // caller is visible here. External functions stay unconstrained.
        if (fn->isExternallyVisible()) return nullptr;
        return fn;
    }

    bool VisitFunctionDecl(FunctionDecl* fn) {
        if (fn->isThisDeclarationADefinition() && fn->hasBody())
            if (const auto* c = canonicalCandidate(fn)) candidates.insert(c);
        return true;
    }

    bool VisitCallExpr(CallExpr* call) {
        if (const auto* callee = call->getDirectCallee()) {
            if (const auto* c = canonicalCandidate(callee))
                calls.emplace_back(c, call);
            // The callee reference is a call, not an address-of.
            if (const auto* ref =
                    dyn_cast<DeclRefExpr>(call->getCallee()->IgnoreParenImpCasts()))
                calleeRefs.insert(ref);
        }
        return true;
    }

    bool VisitDeclRefExpr(DeclRefExpr* ref) {
        const auto* fn = dyn_cast<FunctionDecl>(ref->getDecl());
        if (!fn) return true;
        const auto* c = canonicalCandidate(fn);
        if (!c) return true;
        // A reference to the function that is NOT a direct-call callee
        // means its address escapes — an indirect call could reach it
        // with arguments we never see.
        if (!calleeRefs.count(ref)) addressTaken.insert(c);
        return true;
    }
};

} // namespace

ParamIntervalMap buildParamIntervals(ASTContext& ctx) {
    TuVisitor v;
    v.TraverseDecl(ctx.getTranslationUnitDecl());

    ParamIntervalMap map;
    const IntervalMap empty;  // v0: only literals/constants evaluate bounded

    // Seed every tracked function's parameters to bottom() (⊥); each call
    // site joins in an argument interval, and any parameter left ⊥ (no
    // constraining call) or widened by an unknown argument ends at top().
    for (const auto* fn : v.candidates) {
        if (v.addressTaken.count(fn)) continue;  // address escapes -> top
        map[fn] = std::vector<Interval>(fn->getNumParams(), Interval::bottom());
    }

    for (const auto& [callee, call] : v.calls) {
        auto it = map.find(callee);
        if (it == map.end()) continue;  // address-taken or not a candidate
        std::vector<Interval>& entry = it->second;
        const unsigned nArgs = call->getNumArgs();
        for (unsigned i = 0; i < entry.size(); ++i) {
            // A parameter this call does not cover (fewer args / variadic
            // / default) could hold its default/unknown value -> top().
            Interval argIv = (i < nArgs)
                                 ? evalInterval(call->getArg(i), empty)
                                 : Interval::top();
            entry[i] = Interval::join(entry[i], argIv);
        }
    }

    // A parameter never constrained by a call site stays ⊥ after the
    // join loop; lift it to top() — uncalled here means unconstrained.
    for (auto& [fn, entry] : map)
        for (Interval& iv : entry)
            if (iv.isEmpty()) iv = Interval::top();

    return map;
}

Interval paramEntryInterval(const ParamIntervalMap& map,
                            const FunctionDecl* fn, unsigned index) {
    if (!fn) return Interval::top();
    auto it = map.find(fn->getCanonicalDecl());
    if (it == map.end() || index >= it->second.size())
        return Interval::top();
    return it->second[index];
}

std::map<const VarDecl*, Interval> paramSeeds(const ParamIntervalMap& map,
                                              const FunctionDecl* fn) {
    std::map<const VarDecl*, Interval> seeds;
    if (!fn) return seeds;
    for (unsigned i = 0; i < fn->getNumParams(); ++i) {
        Interval iv = paramEntryInterval(map, fn, i);
        if (!iv.isTop() && !iv.isEmpty())
            seeds[fn->getParamDecl(i)] = iv;
    }
    return seeds;
}

} // namespace zerodefect
