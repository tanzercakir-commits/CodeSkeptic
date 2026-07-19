#include "engine/ParamIntervals.h"

#include "engine/DataflowEngine.h"
#include "engine/IntervalAnalysis.h"
#include "engine/IntervalEval.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>

#include <set>
#include <vector>

using namespace clang;

namespace codeskeptic {

namespace {

const FunctionDecl* candidate(const FunctionDecl* fn) {
    if (!fn) return nullptr;
    fn = fn->getCanonicalDecl();
    // Internal linkage: cannot be called from another TU, so every caller
    // is visible here. External functions stay unconstrained (top).
    if (fn->isExternallyVisible()) return nullptr;
    return fn;
}

// One TU walk: candidate definitions, address-taken candidates, and the
// call-callee references (so a function reference at a call is NOT counted
// as taking the address).
struct TuVisitor : RecursiveASTVisitor<TuVisitor> {
    std::set<const FunctionDecl*> candidates;
    std::set<const FunctionDecl*> addressTaken;
    std::set<const Expr*> calleeRefs;

    bool VisitFunctionDecl(FunctionDecl* fn) {
        if (fn->isThisDeclarationADefinition() && fn->hasBody())
            if (const auto* c = candidate(fn)) candidates.insert(c);
        return true;
    }
    bool VisitCallExpr(CallExpr* call) {
        if (call->getDirectCallee())
            if (const auto* ref = dyn_cast<DeclRefExpr>(
                    call->getCallee()->IgnoreParenImpCasts()))
                calleeRefs.insert(ref);
        return true;
    }
    bool VisitDeclRefExpr(DeclRefExpr* ref) {
        if (const auto* fn = dyn_cast<FunctionDecl>(ref->getDecl()))
            if (const auto* c = candidate(fn))
                if (!calleeRefs.count(ref)) addressTaken.insert(c);
        return true;
    }
};

// Integer locals + parameters of a function (the IntervalAnalysis domain).
std::set<const VarDecl*> intVars(const FunctionDecl* fn) {
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

// Calls to a candidate callee inside one function body.
std::vector<const CallExpr*> callsToCandidates(
    const FunctionDecl* fn, const std::set<const FunctionDecl*>& tracked) {
    struct V : RecursiveASTVisitor<V> {
        const std::set<const FunctionDecl*>* tracked;
        std::vector<const CallExpr*> calls;
        bool VisitCallExpr(CallExpr* call) {
            if (const auto* c = candidate(call->getDirectCallee()))
                if (tracked->count(c)) calls.push_back(call);
            return true;
        }
    } v;
    v.tracked = &tracked;
    v.TraverseStmt(fn->getBody());
    return v.calls;
}

} // namespace

ParamIntervalMap buildParamIntervals(ASTContext& ctx) {
    TuVisitor v;
    v.TraverseDecl(ctx.getTranslationUnitDecl());

    // Tracked = candidate (internal linkage, has body) and address never
    // taken. Its parameters start at bottom(); each call site joins in an
    // argument interval.
    std::set<const FunctionDecl*> tracked;
    ParamIntervalMap map;
    for (const auto* fn : v.candidates) {
        if (v.addressTaken.count(fn)) continue;
        tracked.insert(fn);
        map[fn] = std::vector<Interval>(fn->getNumParams(), Interval::bottom());
    }
    if (tracked.empty()) return map;

    // Pass 1: over every function that calls a tracked callee, run the
    // interval dataflow (parameters = top, no seeding — so there is no
    // fixpoint and no optimistic recursion) and evaluate each call's
    // arguments in the CALLER's local state at that call site.
    struct FnCollector : RecursiveASTVisitor<FnCollector> {
        std::vector<const FunctionDecl*> fns;
        bool VisitFunctionDecl(FunctionDecl* fn) {
            if (fn->isThisDeclarationADefinition() && fn->hasBody())
                fns.push_back(fn);
            return true;
        }
    } fc;
    fc.TraverseDecl(ctx.getTranslationUnitDecl());

    for (const auto* caller : fc.fns) {
        auto calls = callsToCandidates(caller, tracked);
        if (calls.empty()) continue;

        IntervalAnalysis analysis(intVars(caller));
        runDataflow(caller, ctx, analysis);

        const IntervalMap empty;
        for (const auto* call : calls) {
            const FunctionDecl* callee = candidate(call->getDirectCallee());
            auto it = map.find(callee);
            if (it == map.end()) continue;
            std::vector<Interval>& entry = it->second;
            // The caller's interval state at this call site refines a
            // VARIABLE argument to its proven range. When the call is not
            // a recorded CFG element (fine-grained CFG shape varies by
            // libclang version), fall back to an empty state: a literal or
            // constant argument still evaluates exactly, a variable widens
            // to top() (sound). Evaluating with an empty state is the v0
            // behaviour, so a missing call state can only LOSE precision,
            // never soundness — and it keeps the result deterministic
            // across toolchains.
            const IntervalMap* st = analysis.stateAt(call);
            const IntervalMap& state = st ? *st : empty;
            const unsigned nArgs = call->getNumArgs();
            for (unsigned i = 0; i < entry.size(); ++i) {
                // A parameter this call does not cover (variadic / default
                // / fewer args) holds an unknown value.
                Interval argIv = (i < nArgs)
                                     ? evalInterval(call->getArg(i), state)
                                     : Interval::top();
                entry[i] = Interval::join(entry[i], argIv);
            }
        }
    }

    // A parameter never constrained by a call site stays bottom(); lift it
    // to top() — uncalled here means unconstrained.
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

ParamIntervalCache& ParamIntervalCache::instance() {
    static ParamIntervalCache cache;
    return cache;
}

const ParamIntervalMap& ParamIntervalCache::get(ASTContext& ctx) {
    if (!built_) {
        map_ = buildParamIntervals(ctx);
        built_ = true;
    }
    return map_;
}

void ParamIntervalCache::clear() {
    map_.clear();
    built_ = false;
}

} // namespace codeskeptic
