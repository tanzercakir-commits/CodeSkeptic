#include "rules/MemoryLeakRule_Ex.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/AllocFunctions.h"
#include "engine/CallRefArgs.h"
#include "engine/DataflowEngine.h"
#include "engine/FunctionSummary.h"
#include "engine/ConditionWalk.h"
#include "engine/GuardedDisjuncts.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <algorithm>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- AllocState lattice ---

enum class AllocState { None, Allocated, Freed, Escaped };

AllocState mergeAllocStates(AllocState a, AllocState b) {
    if (a == b) return a;
    if (a == AllocState::Escaped || b == AllocState::Escaped)
        return AllocState::Escaped;
    if (a == AllocState::None || b == AllocState::None) {
        AllocState other = (a == AllocState::None) ? b : a;
        if (other == AllocState::Allocated) return AllocState::Allocated;
        return AllocState::None;
    }
    return AllocState::Allocated;
}

// --- Statement classification ---

enum class StmtEffect { None, Allocates, Frees, Escapes };

// getName() is invalid on operator overloads — safe access
llvm::StringRef calleeName(const FunctionDecl* callee) {
    if (!callee) return {};
    if (const auto* id = callee->getIdentifier()) return id->getName();
    return {};
}

bool isAllocExpr(const Expr* expr, ASTContext& ctx) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    // Placement new constructs into EXISTING storage — no allocation
    // happens and nothing is leakable (the NASA fprime AtomicQueue
    // slot-initialization loop, `new (&m_slots[i]) Slot()`).
    if (const auto* newExpr = dyn_cast<CXXNewExpr>(expr))
        return newExpr->getNumPlacementArgs() == 0;
    if (const auto* cast = dyn_cast<CastExpr>(expr))
        return isAllocExpr(cast->getSubExpr(), ctx);
    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        auto name = calleeName(call->getDirectCallee());
        if (name == "malloc" || name == "calloc" ||
            name == "strdup" || name == "realloc")
            return true;
        // Project wrappers registered via --alloc-functions
        // (git__malloc, zmalloc, ...) — without them the whole
        // leak/double-free/UAF domain is blind in wrapper-heavy
        // codebases.
        return !name.empty() &&
               zerodefect::allocFunctionNames().count(name.str()) != 0;
    }
    return false;
}

const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    // Explicit casts included: `(void*)copy` handed to a callback
    // registry and `reinterpret_cast<T*>(handle)` stored through an
    // out-param are still uses of the SAME pointer (shadPS4
    // SDL_AddTimer / OpenDevice FP families) — IgnoreParenImpCasts
    // alone hid the variable from the escape analysis.
    expr = expr->IgnoreParenCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// `&var->member`, `&var.member`, `&var` (chained members/subscripts
// included): taking the address of an object or of one of its members
// keeps the WHOLE object reachable through the handed-out pointer —
// the object escapes wherever that address escapes. The libgit2
// iterator pattern (`*out = &it->parent;` — the caller later frees
// through the parent pointer) and the fprime font pattern
// (`*glyph_out = &boxed->glyph;`) are both this shape.
const VarDecl* addrOfMemberBase(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenCasts();
    const auto* unary = dyn_cast<UnaryOperator>(expr);
    if (!unary || unary->getOpcode() != UO_AddrOf) return nullptr;
    const Expr* inner = unary->getSubExpr()->IgnoreParenCasts();
    while (true) {
        if (const auto* member = dyn_cast<MemberExpr>(inner))
            inner = member->getBase()->IgnoreParenCasts();
        else if (const auto* sub = dyn_cast<ArraySubscriptExpr>(inner))
            inner = sub->getBase()->IgnoreParenCasts();
        else
            break;
    }
    if (const auto* ref = dyn_cast<DeclRefExpr>(inner))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// Dereference detection (for use-after-free). Since the CFG is
// fine-grained, looking only at the top node is enough.
const VarDecl* derefTarget(const Stmt* stmt) {
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
        if (unary->getOpcode() == UO_Deref)
            return asVar(unary->getSubExpr());
        return nullptr;
    }
    if (const auto* member = dyn_cast<MemberExpr>(stmt)) {
        if (member->isArrow())
            return asVar(member->getBase());
        return nullptr;
    }
    if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(stmt))
        return asVar(subscript->getBase());
    return nullptr;
}

// If the same variable appears in multiple call positions the most
// conservative wins: Escapes > Frees > ReadsOnly.
struct VarCallEffect { bool escapes = false; bool frees = false; };

// Marks every tracked variable referenced anywhere inside a composite
// call argument as escaping (aggregate initializers, constructor
// arguments wrapping the pointer). Bare-variable arguments are handled
// separately with summary-driven precision.
void collectNestedTrackedRefs(const Stmt* stmt,
                              const std::set<const VarDecl*>& tracked,
                              std::map<const VarDecl*, VarCallEffect>& byVar) {
    if (!stmt) return;
    if (const auto* ref = dyn_cast<DeclRefExpr>(stmt)) {
        if (const auto* var = dyn_cast<VarDecl>(ref->getDecl()))
            if (tracked.count(var)) byVar[var].escapes = true;
        return;
    }
    // Do not descend through a dereference: `f(*data)` / `f(data->x)`
    // reads the POINTEE — the pointer itself is not handed over, the
    // leak must stay visible (Juliet print-the-value sinks).
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt))
        if (unary->getOpcode() == UO_Deref) return;
    if (const auto* member = dyn_cast<MemberExpr>(stmt))
        if (member->isArrow()) return;
    if (isa<ArraySubscriptExpr>(stmt)) return;
    // Nested calls are their own fine-grained CFG elements and get the
    // summary-driven treatment there — descending would override a
    // ReadsOnly verdict with a blanket escape.
    if (isa<CallExpr>(stmt)) return;
    for (const Stmt* child : stmt->children())
        collectNestedTrackedRefs(child, tracked, byVar);
}

// Top-node Effect pattern (as in UninitPtr): the expression is
// classified ONCE and itself reports the effects on the tracked
// variables it touches — no per-variable rescanning. In the
// fine-grained CFG each element comes with its own top node, so no
// nested search is needed.
using StmtEffects = std::vector<std::pair<const VarDecl*, StmtEffect>>;

StmtEffects classifyStmtEffects(const Stmt* stmt,
                                const std::set<const VarDecl*>& tracked,
                                ASTContext& ctx) {
    StmtEffects effects;

    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (tracked.count(vd) && vd->hasInit() &&
                    isAllocExpr(vd->getInit(), ctx))
                    effects.emplace_back(vd, StmtEffect::Allocates);
            }
        }
        return effects;
    }
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign) {
            const VarDecl* lhs = asVar(binOp->getLHS());
            if (lhs && tracked.count(lhs) &&
                isAllocExpr(binOp->getRHS(), ctx))
                effects.emplace_back(lhs, StmtEffect::Allocates);

            // Storing a tracked pointer into something that outlives the
            // local scope is an escape: a `this` member (`slot_ = copy;`,
            // the abseil CrcCordState pattern), a global/static, a
            // param-reachable or deref/array target. Deliberately NOT
            // escapes (Juliet guard taught this, 2026-07-12):
            //  - a plain LOCAL-to-local copy (`dataCopy = data;` alias
            //    leaks must stay visible on the original), and
            //  - a member of a LOCAL aggregate (`myStruct.ptr = data;` —
            //    the aggregate itself dies at function end, the leak is
            //    real; the Juliet 66/67 struct-passing families).
            const VarDecl* rhsVar = asVar(binOp->getRHS());
            if (!rhsVar)
                rhsVar = addrOfMemberBase(binOp->getRHS());
            if (!rhsVar) {
                // Chained assignment: `*out = counts = git__calloc(...)`
                // stores the same value the inner assignment gave to
                // `counts` — the escape applies to that variable (the
                // libgit2 checkout out-param idiom).
                const Expr* rhs = binOp->getRHS()->IgnoreParenCasts();
                if (const auto* inner = dyn_cast<BinaryOperator>(rhs))
                    if (inner->getOpcode() == BO_Assign)
                        rhsVar = asVar(inner->getLHS());
            }
            if (rhsVar && tracked.count(rhsVar) && rhsVar != lhs) {
                const Expr* lhsExpr = binOp->getLHS()->IgnoreParenImpCasts();
                bool escapes;
                if (lhs) {
                    escapes = !lhs->hasLocalStorage();  // global/static
                } else if (const auto* member =
                               dyn_cast<MemberExpr>(lhsExpr)) {
                    if (member->isArrow()) {
                        escapes = true;  // pointee may live anywhere
                    } else {
                        const VarDecl* base = asVar(member->getBase());
                        // local (non-param) aggregate: stays local;
                        // param/global/this/complex base: escapes.
                        // A reference base refers to storage owned
                        // elsewhere (`ImGuiIO& io = GetIO();
                        // io.UserData = bd;` — shadPS4 imgui backends),
                        // so it escapes too.
                        escapes = !(base && base->hasLocalStorage() &&
                                    !isa<ParmVarDecl>(base) &&
                                    !base->getType()->isReferenceType());
                    }
                } else {
                    escapes = true;  // *p = q, arr[i] = q, this-member...
                }
                if (escapes)
                    effects.emplace_back(rhsVar, StmtEffect::Escapes);
            }
        }
        return effects;
    }
    if (const auto* del = dyn_cast<CXXDeleteExpr>(stmt)) {
        const VarDecl* var = asVar(del->getArgument());
        if (var && tracked.count(var))
            effects.emplace_back(var, StmtEffect::Frees);
        return effects;
    }
    if (const auto* call = dyn_cast<CallExpr>(stmt)) {
        const FunctionDecl* callee = call->getDirectCallee();
        const llvm::StringRef name = calleeName(callee);
        const bool isFreeByName =
            name == "free" ||
            (!name.empty() &&
             zerodefect::freeFunctionNames().count(name.str()) != 0);
        const auto* summary =
            zerodefect::SummaryRegistry::instance().lookup(callee);
        using PE = zerodefect::SummaryRegistry::ParamEffect;

        // &var is always Escapes (the callee may reassign/free it).
        std::map<const VarDecl*, VarCallEffect> byVar;

        // Method call: `p->Track()` may stash `this` anywhere (observer/
        // registry registration — the abseil CordzInfo pattern). The
        // receiver escapes conservatively. Use-after-free stays intact:
        // the receiver's MemberExpr is its own (earlier) CFG element and
        // is checked against the pre-call state.
        if (const auto* memberCall = dyn_cast<CXXMemberCallExpr>(call)) {
            if (const VarDecl* recv =
                    asVar(memberCall->getImplicitObjectArgument()))
                if (tracked.count(recv)) byVar[recv].escapes = true;
        }

        // An argument bound to a NON-CONST reference parameter
        // (`T*& handle`) lets the callee reassign or stash the
        // caller's pointer — always an escape, whatever the summary
        // says about by-value semantics.
        zerodefect::forEachNonConstRefArg(call, [&](const Expr* refArg) {
            const VarDecl* var = asVar(refArg);
            if (var && tracked.count(var)) byVar[var].escapes = true;
        });

        for (unsigned i = 0; i < call->getNumArgs(); ++i) {
            const Expr* arg = call->getArg(i);
            if (const auto* unary = dyn_cast<UnaryOperator>(
                    arg->IgnoreParenImpCasts())) {
                if (unary->getOpcode() == UO_AddrOf) {
                    // &var AND &var->member both hand out a way to
                    // reach (and free) the object.
                    const VarDecl* var = addrOfMemberBase(arg);
                    if (var && tracked.count(var))
                        byVar[var].escapes = true;
                }
                continue;
            }
            const VarDecl* var = asVar(arg);
            if (!var || !tracked.count(var)) {
                // The pointer may sit INSIDE a composite argument:
                // `push_back(AudioData{.buf = cast(mix_s16), ...})`
                // (shadPS4 audio3d). Any tracked variable referenced
                // anywhere within the argument subtree escapes —
                // the receiving object outlives our view of it.
                // Bare-variable args keep the summary-driven logic
                // below, so Juliet's `printLine(data)` sinks are
                // unaffected.
                collectNestedTrackedRefs(arg, tracked, byVar);
                continue;
            }
            if (isFreeByName && i == 0) {
                byVar[var].frees = true;
                continue;
            }
            PE effect = summary ? summary->paramEffect(i) : PE::Opaque;
            switch (effect) {
                case PE::Stores:
                case PE::Opaque:    byVar[var].escapes = true; break;
                case PE::Frees:     byVar[var].frees = true; break;
                case PE::ReadsOnly: byVar[var]; break;  // become visible, no effect
            }
        }
        for (const auto& [var, e] : byVar) {
            if (e.escapes)
                effects.emplace_back(var, StmtEffect::Escapes);
            else if (e.frees)
                effects.emplace_back(var, StmtEffect::Frees);
            // ReadsOnly-only: no effect (the leak stays visible)
        }
        return effects;
    }
    if (const auto* ret = dyn_cast<ReturnStmt>(stmt)) {
        const VarDecl* var = asVar(ret->getRetValue());
        if (!var)
            var = addrOfMemberBase(ret->getRetValue());
        if (var && tracked.count(var))
            effects.emplace_back(var, StmtEffect::Escapes);
    }
    return effects;
}

// --- Collect tracked pointer variables ---

std::vector<const VarDecl*> collectTrackedVars(const FunctionDecl* funcDecl,
                                                ASTContext& ctx) {
    std::set<const VarDecl*> vars;

    // The matchers only pre-select CANDIDATES (pointer var initialized /
    // assigned from any expression); the real allocation test is
    // isAllocExpr — one place that knows the built-in names, the
    // --alloc-functions registry, casts and the placement-new
    // exemption. The old per-name matcher list silently missed realloc
    // and could never see registered wrappers.
    auto candidateInit = varDecl(
        hasType(pointerType()),
        hasInitializer(expr())
    ).bind("var");
    auto candidateAssign = binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("var")))))
    ).bind("assign");

    // Only automatic-storage locals are tracked. A static local or a
    // global assigned an allocation is NOT an end-of-function leak: its
    // lifetime is program-long and the "leak on purpose" singleton
    // (`static Mutex* mu = new Mutex;` — deliberate Google style to
    // dodge destruction-order fiasco) is idiomatic real-world code.
    auto trackable = [](const VarDecl* v) { return v->hasLocalStorage(); };

    auto wrapper = functionDecl(equalsNode(funcDecl),
                                 forEachDescendant(candidateInit));
    for (const auto& result : match(wrapper, *funcDecl, ctx)) {
        const auto* v = result.getNodeAs<VarDecl>("var");
        if (v && trackable(v) && v->hasInit() &&
            isAllocExpr(v->getInit(), ctx))
            vars.insert(v);
    }
    for (const auto& result :
         match(findAll(candidateAssign), *funcDecl->getBody(), ctx)) {
        const auto* v = result.getNodeAs<VarDecl>("var");
        const auto* assign = result.getNodeAs<BinaryOperator>("assign");
        if (v && assign && trackable(v) &&
            isAllocExpr(assign->getRHS(), ctx))
            vars.insert(v);
    }
    return {vars.begin(), vars.end()};
}

// Flow-insensitive alias groups over direct local-to-local pointer
// copies (`b = a;` / `T* b = a;` between tracked locals). Used ONLY to
// propagate ESCAPES (see transfer): once one alias is handed out, the
// allocation is reachable by the caller regardless of which name we
// first saw it under.
std::map<const VarDecl*, std::vector<const VarDecl*>> collectAliasGroups(
        const FunctionDecl* funcDecl, ASTContext& ctx,
        const std::set<const VarDecl*>& tracked) {
    std::map<const VarDecl*, const VarDecl*> parent;  // union-find
    std::function<const VarDecl*(const VarDecl*)> find =
        [&](const VarDecl* v) -> const VarDecl* {
        auto it = parent.find(v);
        if (it == parent.end() || it->second == v) return v;
        return parent[v] = find(it->second);
    };
    auto unite = [&](const VarDecl* a, const VarDecl* b) {
        // Register both nodes: the group materialization below walks
        // the parent map's keys, so roots must appear there too.
        parent.emplace(a, a);
        parent.emplace(b, b);
        const VarDecl* ra = find(a);
        const VarDecl* rb = find(b);
        if (ra != rb) parent[ra] = rb;
    };

    auto copyAssign = binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("lhs"))))),
        hasRHS(ignoringParenCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("rhs"))))));
    for (const auto& result :
         match(findAll(copyAssign), *funcDecl->getBody(), ctx)) {
        const auto* l = result.getNodeAs<VarDecl>("lhs");
        const auto* r = result.getNodeAs<VarDecl>("rhs");
        if (l && r && l != r && l->hasLocalStorage() &&
            (tracked.count(l) || tracked.count(r)))
            unite(l, r);
    }
    auto copyInit = varDecl(
        hasType(pointerType()),
        hasInitializer(ignoringParenCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("rhs")))))).bind("lhs");
    auto wrapper = functionDecl(equalsNode(funcDecl),
                                 forEachDescendant(copyInit));
    for (const auto& result : match(wrapper, *funcDecl, ctx)) {
        const auto* l = result.getNodeAs<VarDecl>("lhs");
        const auto* r = result.getNodeAs<VarDecl>("rhs");
        if (l && r && l != r && l->hasLocalStorage() &&
            (tracked.count(l) || tracked.count(r)))
            unite(l, r);
    }

    // Materialize: for each var, its group members (self excluded)
    std::map<const VarDecl*, std::vector<const VarDecl*>> byRoot;
    for (const auto& [v, _] : parent) byRoot[find(v)].push_back(v);
    std::map<const VarDecl*, std::vector<const VarDecl*>> groups;
    for (const auto& [root, members] : byRoot) {
        if (members.size() < 2) continue;
        for (const VarDecl* v : members) {
            auto& list = groups[v];
            for (const VarDecl* other : members)
                if (other != v) list.push_back(other);
        }
    }
    return groups;
}

// --- Branch condition refinement (assume edges) ---

using VarState = std::map<const VarDecl*, AllocState>;

// On an edge known to be null there is no "allocation": the malloc/new
// failure path is NOT a leak (p = malloc; if (!p) return;).
// The walk comes from the shared skeleton (engine/ConditionWalk.h); this
// domain only cares about the null edge and ignores non-null knowledge.
void applyNullCondition(const Expr* cond, bool isTrue, VarState& state) {
    zerodefect::walkNullCondition(
        cond, isTrue, [&](const VarDecl* var, bool isNull) {
            if (!isNull) return;
            auto it = state.find(var);
            if (it != state.end() && it->second == AllocState::Allocated)
                it->second = AllocState::None;
        });
}

// --- Guarded disjuncts (targeted path sensitivity) ---
//
// The Juliet FP hunt (2026-07-10) showed a single root cause: when the
// same invariant condition is tested twice ("if(g==5) alloc; ... if(g==5)
// free;"), paths get mixed at the join and a phantom "path that allocates
// but never frees" is born. The shared machinery is in
// engine/GuardedDisjuncts.h — here it is only instantiated with the
// AllocState merger.

using DisjunctState = zerodefect::GuardedState<VarState>;

VarState flattenState(const DisjunctState& state) {
    return zerodefect::flattenGuarded(state, mergeAllocStates);
}

// --- Analysis struct for DataflowEngine ---

class MemLeakAnalysis {
public:
    using State = DisjunctState;

    MemLeakAnalysis(const std::vector<const VarDecl*>& trackedVars,
                    std::set<const ValueDecl*> mutatedDecls,
                    std::string funcName,
                    std::map<const VarDecl*, std::vector<const VarDecl*>>
                        aliasGroups,
                    zerodefect::DiagnosticList& results)
        : trackedVars_(trackedVars),
          trackedSet_(trackedVars.begin(), trackedVars.end()),
          mutated_(std::move(mutatedDecls)),
          aliasGroups_(std::move(aliasGroups)),
          funcName_(std::move(funcName)), results_(results) {
        zerodefect::Guarded<VarState> init;
        for (const auto* var : trackedVars_)
            init.vars[var] = AllocState::None;
        initState_.push_back(std::move(init));
    }

    State initialState() const { return initState_; }

    // The per-variable AllocState chain makes at most 3 transitions;
    // the number of disjuncts multiplies the height (each disjunct can
    // rise independently)
    unsigned latticeHeight() const {
        return (static_cast<unsigned>(trackedVars_.size()) * 3 + 1) *
                   static_cast<unsigned>(zerodefect::kMaxDisjuncts) + 4;
    }

    State merge(const State& a, const State& b) const {
        return zerodefect::mergeGuarded(a, b, mergeAllocStates);
    }

    // Pure state transition — produces no reports. Reporting lives in
    // onStatement, the post-fixpoint pass (an engine guarantee).
    State transfer(const Stmt* stmt, const State& in, ASTContext& ctx) const {
        // Effects are state-independent: classify once, apply to every disjunct
        StmtEffects effects = classifyStmtEffects(stmt, trackedSet_, ctx);
        if (effects.empty()) return in;

        State out = in;
        for (auto& d : out) {
            for (const auto& [var, effect] : effects) {
                switch (effect) {
                    case StmtEffect::Allocates:
                        d.vars[var] = AllocState::Allocated; break;
                    case StmtEffect::Frees:
                        d.vars[var] = AllocState::Freed; break;
                    case StmtEffect::Escapes: {
                        // An escape travels through local aliases:
                        // `dup = git__strdup(s); result = dup;
                        // return result;` hands the SAME allocation
                        // out, so dup escapes too (the libgit2
                        // realpath copy-then-return shape). Escape is
                        // the safe direction to propagate — it only
                        // silences reports. Frees stay per-variable:
                        // flow-insensitive groups would fabricate
                        // double-frees for `b = a; b = other;
                        // free(b); free(a)`.
                        d.vars[var] = AllocState::Escaped;
                        auto group = aliasGroups_.find(var);
                        if (group != aliasGroups_.end())
                            for (const VarDecl* member : group->second)
                                d.vars[member] = AllocState::Escaped;
                        break;
                    }
                    case StmtEffect::None: break;
                }
            }
        }
        return out;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        const auto* condExpr = dyn_cast<Expr>(cond);
        zerodefect::refineGuardedFacts(state, condExpr, isTrueBranch,
                                       mutated_, mergeAllocStates);
        for (auto& d : state)
            applyNullCondition(condExpr, isTrueBranch, d.vars);
    }

    // Post-fixpoint reporting: reassignment leak, double free and
    // use-after-free are produced here.
    void onStatement(const Stmt* stmt, const State& beforeDisjuncts,
                     const State& afterDisjuncts, ASTContext& ctx) {
        // Reporting works on today's single-state view; the payoff of
        // path sensitivity is that disjuncts dropped by refineOnEdge
        // never enter this merge at all.
        VarState before = flattenState(beforeDisjuncts);
        VarState after = flattenState(afterDisjuncts);
        // Dataflow trace: record state-changing events (alloc/free).
        // Notes are attached to the report at the END of the run — the
        // reporting pass's block order is not source order.
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState == AllocState::Allocated)
                recordEvent(stmt, var, ctx,
                            zerodefect::MsgId::TraceAllocatedHere);
            else if (afterState == AllocState::Freed)
                recordEvent(stmt, var, ctx,
                            zerodefect::MsgId::TraceFreedHere);
        }

        for (const auto& [var, effect] :
             classifyStmtEffects(stmt, trackedSet_, ctx)) {
            auto it = before.find(var);
            if (it == before.end()) continue;

            if (effect == StmtEffect::Allocates &&
                it->second == AllocState::Allocated) {
                report(stmt, var, ctx, zerodefect::Severity::Warning,
                       "memory-leak", zerodefect::MsgId::LeakReassign);
            } else if (effect == StmtEffect::Frees &&
                       it->second == AllocState::Freed) {
                // Under its own identity, like UAF: so the CWE415 mapping
                // and the --disable-rule taxonomy can tell the finding
                // kinds apart
                report(stmt, var, ctx, zerodefect::Severity::Error,
                       "double-free", zerodefect::MsgId::DoubleFree);
            }
        }

        // Dereference of a pointer in the Freed state: use-after-free
        if (const VarDecl* var = derefTarget(stmt)) {
            auto it = before.find(var);
            if (it != before.end() && it->second == AllocState::Freed) {
                report(stmt, var, ctx, zerodefect::Severity::Error,
                       "use-after-free", zerodefect::MsgId::UseAfterFree);
            }
        }
    }

    std::set<std::pair<const VarDecl*, unsigned>>& reported() {
        return reported_;
    }

    // After the run finishes: attach the accumulated event notes to reports
    void attachTraces() {
        for (const auto& [index, var] : noteTargets_) {
            auto it = events_.find(var);
            if (it == events_.end()) continue;
            auto notes = it->second;
            std::sort(notes.begin(), notes.end());
            if (notes.size() > 6) notes.resize(6);
            results_[index].notes = std::move(notes);
        }
        noteTargets_.clear();
    }

    // For external reports (exit-block leak): target registration + event access
    void registerNoteTarget(size_t resultIndex, const VarDecl* var) {
        noteTargets_.emplace_back(resultIndex, var);
    }

private:
    std::map<const VarDecl*, std::vector<zerodefect::TraceNote>> events_;
    std::vector<std::pair<size_t, const VarDecl*>> noteTargets_;

    void recordEvent(const Stmt* stmt, const VarDecl* var, ASTContext& ctx,
                     zerodefect::MsgId msgId) {
        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        zerodefect::TraceNote note;
        note.file = sm.getFilename(loc).str();
        note.line = sm.getSpellingLineNumber(loc);
        note.column = sm.getSpellingColumnNumber(loc);
        note.message = zerodefect::msg(msgId, var->getNameAsString());

        auto& list = events_[var];
        for (const auto& existing : list)
            if (existing.line == note.line &&
                existing.message == note.message)
                return;
        list.push_back(std::move(note));
    }

    void report(const Stmt* stmt, const VarDecl* var, ASTContext& ctx,
                zerodefect::Severity severity, const char* ruleId,
                zerodefect::MsgId msgId) {
        const SourceManager& sm = ctx.getSourceManager();
        // Findings inside macros are bound to the use site (expansion);
        // otherwise the file name can end up empty (scratch buffer)
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reported_.emplace(var, line).second) return;

        zerodefect::Diagnostic diag;
        diag.severity = severity;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = ruleId;
        diag.function = funcName_;
        diag.message = zerodefect::msg(msgId, var->getNameAsString());
        results_.push_back(diag);
        noteTargets_.emplace_back(results_.size() - 1, var);
    }

    const std::vector<const VarDecl*>& trackedVars_;
    std::set<const VarDecl*> trackedSet_;
    std::set<const ValueDecl*> mutated_;
    std::map<const VarDecl*, std::vector<const VarDecl*>> aliasGroups_;
    std::string funcName_;
    zerodefect::DiagnosticList& results_;
    State initState_;
    std::set<std::pair<const VarDecl*, unsigned>> reported_;
};

// --- Function-level analysis ---

void analyzeFunction(const FunctionDecl* funcDecl,
                     ASTContext& ctx,
                     zerodefect::DiagnosticList& results) {
    if (!funcDecl->hasBody()) return;

    auto trackedVars = collectTrackedVars(funcDecl, ctx);
    if (trackedVars.empty()) return;

    std::set<const VarDecl*> trackedSet(trackedVars.begin(),
                                        trackedVars.end());
    auto aliasGroups = collectAliasGroups(funcDecl, ctx, trackedSet);
    // Alias-connected variables join the tracked set: their state
    // starts None (they never produce leak reports of their own), but
    // an escape THROUGH them (`result = dup; return result;`) must be
    // visible so it can propagate to the allocation they alias.
    for (const auto& [var, members] : aliasGroups) {
        (void)members;
        if (trackedSet.insert(var).second) trackedVars.push_back(var);
    }
    MemLeakAnalysis analysis(
        trackedVars, zerodefect::collectMutatedDecls(funcDecl),
        funcDecl->getQualifiedNameAsString(),
        std::move(aliasGroups), results);
    auto dfResult = zerodefect::runDataflow(funcDecl, ctx, analysis);
    if (!dfResult.converged)
        std::cerr << zerodefect::msg(zerodefect::MsgId::AnalysisNotConverged,
                                     funcDecl->getQualifiedNameAsString())
                  << "\n";

    // Exit block leak check
    auto exitIt = dfResult.blockExitStates.find(dfResult.exitBlockID);
    if (exitIt == dfResult.blockExitStates.end()) return;

    const SourceManager& sm = ctx.getSourceManager();
    SourceLocation endLoc = funcDecl->getBody()->getEndLoc();

    const VarState exitVars = flattenState(exitIt->second);
    for (const auto& [var, state] : exitVars) {
        if (state == AllocState::Allocated) {
            unsigned line = sm.getSpellingLineNumber(endLoc);
            if (analysis.reported().emplace(var, line).second) {
                zerodefect::Diagnostic diag;
                diag.severity = zerodefect::Severity::Warning;
                diag.file = sm.getFilename(endLoc).str();
                diag.line = line;
                diag.column = sm.getSpellingColumnNumber(endLoc);
                diag.rule_id = "memory-leak";
                diag.function = funcDecl->getQualifiedNameAsString();
                diag.message = zerodefect::msg(
                    zerodefect::MsgId::LeakEndOfFunction,
                    var->getNameAsString());
                results.push_back(diag);
                analysis.registerNoteTarget(results.size() - 1, var);
            }
        }
    }

    analysis.attachTraces();
}

// --- Matcher callback ---

class FindMemLeakCallback : public MatchFinder::MatchCallback {
public:
    explicit FindMemLeakCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;
        if (!zerodefect::functionFilterAllows(*func)) return;
        if (!zerodefect::lineFilterAllows(*func, sm)) return;

        analyzeFunction(func, *result.Context, results_);
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string MemoryLeakRule_Ex::id() const {
    return "memory-leak";
}

std::string MemoryLeakRule_Ex::description() const {
    return "CFG-based memory leak, double-free and use-after-free analysis";
}

void MemoryLeakRule_Ex::check(clang::ASTContext& ctx,
                               DiagnosticList& results) {
    MatchFinder finder;
    FindMemLeakCallback callback(results);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
