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

// One seeding pass: recompute every tracked callee's parameter joins
// from scratch, evaluating each call's arguments in the CALLER's local
// state — with the caller's OWN parameters seeded from `prev` (empty on
// the first pass = the original single-pass behaviour).
//
// SOUNDNESS BY INDUCTION (the multi-hop upgrade's core argument): if
// `prev` over-approximates every actual entry value, then evaluating
// arguments under `prev` over-approximates every actual argument, so
// the recomputed map is sound too. The all-top pass-0 is trivially
// sound; therefore EVERY pass is independently sound — recursion and
// cycles included — and capping the iteration at any pass keeps a
// correct result (cycles simply stabilise at top instead of narrowing).
ParamIntervalMap runSeedingPass(ASTContext& ctx,
                                const std::set<const FunctionDecl*>& tracked,
                                const std::vector<const FunctionDecl*>& fns,
                                const ParamIntervalMap& prev) {
    ParamIntervalMap map;
    for (const auto* fn : tracked)
        map[fn] = std::vector<Interval>(fn->getNumParams(), Interval::bottom());

    for (const auto* caller : fns) {
        auto calls = callsToCandidates(caller, tracked);
        if (calls.empty()) continue;

        IntervalAnalysis analysis(intVars(caller), paramSeeds(prev, caller));
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

ParamIntervalMap buildParamIntervals(ASTContext& ctx) {
    TuVisitor v;
    v.TraverseDecl(ctx.getTranslationUnitDecl());

    // Tracked = candidate (internal linkage, has body) and address never
    // taken.
    std::set<const FunctionDecl*> tracked;
    for (const auto* fn : v.candidates)
        if (!v.addressTaken.count(fn)) tracked.insert(fn);
    if (tracked.empty()) return {};

    struct FnCollector : RecursiveASTVisitor<FnCollector> {
        std::vector<const FunctionDecl*> fns;
        bool VisitFunctionDecl(FunctionDecl* fn) {
            if (fn->isThisDeclarationADefinition() && fn->hasBody())
                fns.push_back(fn);
            return true;
        }
    } fc;
    fc.TraverseDecl(ctx.getTranslationUnitDecl());

    // Multi-hop seeding (F7A.3): iterate the pass so a bounded caller
    // parameter reaches through A -> B -> C chains. Each pass is
    // independently sound (see runSeedingPass), so the cap is a pure
    // precision knob, not a correctness one; 3 passes cover the chains
    // real code has, and early-exit fires when a pass changes nothing.
    constexpr unsigned kMaxSeedingPasses = 3;
    ParamIntervalMap map;  // pass 0: empty = all params top
    for (unsigned pass = 0; pass < kMaxSeedingPasses; ++pass) {
        ParamIntervalMap next = runSeedingPass(ctx, tracked, fc.fns, map);
        if (next == map) break;
        map = std::move(next);
    }
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
