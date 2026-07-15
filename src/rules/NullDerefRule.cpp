#include "rules/NullDerefRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CoverageReport.h"
#include "engine/DataflowEngine.h"
#include "engine/FunctionSummary.h"
#include "engine/CallRefArgs.h"
#include "engine/ConditionWalk.h"
#include "engine/GuardedDisjuncts.h"
#include "contracts/ContractInfo.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- NullState lattice ---
//
// Unknown : no information (parameter, opaque function return)
// Null    : definitely null on all paths
// NonNull : definitely not null on all paths
// MaybeNull: null on at least one path (reportable signal)

enum class NullState { Unknown, Null, NonNull, MaybeNull };

NullState mergeNullStates(NullState a, NullState b) {
    if (a == b) return a;
    // Null knowledge on any path is preserved; only NonNull + Unknown
    // decays to no knowledge (same shape as the DivByZero merge)
    bool anyNullInfo = a == NullState::Null || a == NullState::MaybeNull ||
                       b == NullState::Null || b == NullState::MaybeNull;
    return anyNullInfo ? NullState::MaybeNull : NullState::Unknown;
}

// --- Expression null-ness evaluation ---

const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

NullState evaluateNullness(const Expr* expr) {
    if (!expr) return NullState::Unknown;
    // Strip explicit casts too: (int*)0, (Node*)nullptr
    expr = expr->IgnoreParenCasts();

    if (isa<CXXNullPtrLiteralExpr>(expr)) return NullState::Null;
    if (isa<GNUNullExpr>(expr)) return NullState::Null;
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0 ? NullState::Null : NullState::NonNull;

    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() == UO_AddrOf) return NullState::NonNull;
    }
    if (isa<CXXNewExpr>(expr)) return NullState::NonNull;
    if (isa<StringLiteral>(expr)) return NullState::NonNull;
    if (isa<CXXThisExpr>(expr)) return NullState::NonNull;

    // Interprocedural: the null-ness of a call's return comes from the
    // function summary. A "may return null" summary produces MaybeNull —
    // an unguarded dereference becomes a warning; guarded use stays
    // clean via the assume-edge.
    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        using RN = zerodefect::SummaryRegistry::ReturnNullness;
        const auto* summary =
            zerodefect::SummaryRegistry::instance().lookup(
                call->getDirectCallee());
        if (summary) {
            if (summary->returnNullness == RN::NeverNull)
                return NullState::NonNull;
            if (summary->returnNullness == RN::MaybeNull)
                return NullState::MaybeNull;
        }
        return NullState::Unknown;
    }

    return NullState::Unknown;
}

// --- Statement classification ---

enum class EffectKind { None, Assign, AssignUnknown, Deref };

struct Effect {
    const VarDecl* var = nullptr;
    EffectKind kind = EffectKind::None;
    NullState value = NullState::Unknown;  // only for Assign
};

Effect classifyStmt(const Stmt* stmt) {
    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        // In a multi-declaration the first pointer init is taken; the
        // rest start Unknown (conservative). Rare case, noted in the todo.
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (vd->getType()->isPointerType() && vd->hasInit())
                    return {vd, EffectKind::Assign,
                            evaluateNullness(vd->getInit())};
            }
        }
        return {};
    }
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign)
            if (const auto* var = asVar(binOp->getLHS()))
                return {var, EffectKind::Assign,
                        evaluateNullness(binOp->getRHS())};
        return {};
    }
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
        // If &p goes to a function, p may have been assigned a value
        if (unary->getOpcode() == UO_AddrOf)
            if (const auto* var = asVar(unary->getSubExpr()))
                return {var, EffectKind::AssignUnknown};
        if (unary->getOpcode() == UO_Deref)
            if (const auto* var = asVar(unary->getSubExpr()))
                return {var, EffectKind::Deref};
        return {};
    }
    if (const auto* member = dyn_cast<MemberExpr>(stmt)) {
        if (member->isArrow())
            if (const auto* var = asVar(member->getBase()))
                return {var, EffectKind::Deref};
        return {};
    }
    if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(stmt)) {
        if (const auto* var = asVar(subscript->getBase()))
            return {var, EffectKind::Deref};
        return {};
    }
    return {};
}

// --- Branch condition refinement (assume edges) ---

using NullVarState = std::map<const VarDecl*, NullState>;

void setIfTracked(NullVarState& state, const VarDecl* var, NullState value) {
    if (!var) return;
    auto it = state.find(var);
    if (it != state.end()) it->second = value;
}

// Via the shared walk skeleton (engine/ConditionWalk.h): `if (p)`,
// `!p`, `p ==/!= nullptr/NULL/0`, && / || short-circuiting.
void applyCondition(const Expr* cond, bool isTrue, NullVarState& state) {
    zerodefect::walkNullCondition(
        cond, isTrue, [&](const VarDecl* var, bool isNull) {
            setIfTracked(state, var,
                         isNull ? NullState::Null : NullState::NonNull);
        });
}

// --- Collect tracked pointer variables ---

std::vector<const VarDecl*> collectTrackedVars(const FunctionDecl* funcDecl,
                                                ASTContext& ctx) {
    std::set<const VarDecl*> vars;

    // All pointer local variables and parameters appearing in the
    // function. Parameters start Unknown — no assumption is made about
    // the caller.
    auto ptrVarMatcher = varDecl(hasType(pointerType())).bind("var");
    auto wrapper = functionDecl(equalsNode(funcDecl),
                                 forEachDescendant(ptrVarMatcher));
    for (const auto& result : match(wrapper, *funcDecl, ctx)) {
        if (const auto* v = result.getNodeAs<VarDecl>("var"))
            vars.insert(v);
    }
    for (const auto* param : funcDecl->parameters()) {
        if (param->getType()->isPointerType())
            vars.insert(param);
    }
    return {vars.begin(), vars.end()};
}

// Whether any call in the body targets a callee with an enforced
// non-null requires clause (CONTRACTS.md Round C). A function with no
// pointer variables of its own still needs the dataflow pass then —
// `g() { f(NULL); }` is exactly the call-site violation the contract
// exists to catch.
bool hasNonNullContractCalls(const FunctionDecl* funcDecl, ASTContext& ctx) {
    auto callMatcher = callExpr().bind("call");
    for (const auto& result :
         match(findAll(callMatcher), *funcDecl->getBody(), ctx)) {
        const auto* call = result.getNodeAs<CallExpr>("call");
        if (!call) continue;
        const FunctionDecl* callee = call->getDirectCallee();
        if (!callee) continue;
        auto parsed = zerodefect::allContractClausesForDecl(callee, ctx);
        if (parsed.clauses.empty()) continue;
        auto req = zerodefect::analyzeRequires(parsed, callee);
        for (const auto& info : req.enforced)
            if (info.kind != zerodefect::RequiresInfo::Kind::NonZeroParam)
                return true;
    }
    return false;
}

// --- Analysis struct for DataflowEngine ---

class NullDerefAnalysis {
public:
    // Guarded disjuncts (targeted path sensitivity): the Juliet
    // int_07/08/09 pattern — `if(staticTrue) data = alloc; ...
    // if(staticTrue) *data;` — produced a false "may be null" under
    // correlation-free analysis. The shared machinery is in
    // engine/GuardedDisjuncts.h; the pointer nullness refinement
    // (applyCondition) is additionally applied per disjunct.
    using State = zerodefect::GuardedState<NullVarState>;

    NullDerefAnalysis(const std::vector<const VarDecl*>& trackedVars,
                      std::set<const ValueDecl*> unkeyableDecls,
                      std::set<const ValueDecl*> stampableDecls,
                      std::set<const ValueDecl*> ptrFactDecls,
                      std::string funcName,
                      zerodefect::DiagnosticList& results)
        : mutated_(std::move(unkeyableDecls)),
          stampable_(std::move(stampableDecls)),
          ptrFacts_(std::move(ptrFactDecls)),
          funcName_(std::move(funcName)), results_(results) {
        zerodefect::Guarded<NullVarState> init;
        for (const auto* var : trackedVars)
            init.vars[var] = NullState::Unknown;
        initState_.push_back(std::move(init));
    }

    State initialState() const { return initState_; }

    // Callee-side contract seeding (CONTRACTS.md Round C): a declared
    // `requires p != null` carries the proof burden — p starts NonNull
    // inside the body (callers are checked at every visible call
    // site). The relational form seeds a SPLIT initial state: the
    // escape-condition disjunct leaves p unconstrained, the other
    // pins it NonNull.
    void seedRequires(const FunctionDecl* func,
                      const std::vector<zerodefect::RequiresInfo>& infos) {
        for (const auto& info : infos) {
            if (info.paramIndex >= func->getNumParams()) continue;
            const ParmVarDecl* p = func->getParamDecl(info.paramIndex);
            if (info.kind == zerodefect::RequiresInfo::Kind::NonNullParam) {
                for (auto& d : initState_) setIfTracked(d.vars, p,
                                                        NullState::NonNull);
            } else if (info.kind ==
                       zerodefect::RequiresInfo::Kind::NonNullUnlessCond) {
                if (info.condParamIndex >= func->getNumParams()) continue;
                const ParmVarDecl* c =
                    func->getParamDecl(info.condParamIndex);
                if (mutated_.count(c)) continue;  // unkeyable: no seed
                auto fact = zerodefect::compareFact(
                    c, zerodefect::toBinaryOp(info.condOp),
                    info.condLiteral);
                if (!fact) continue;
                State next;
                for (auto& d : initState_) {
                    auto escape = d;             // cond TRUE: p free
                    escape.facts[fact->first] = fact->second;
                    auto pinned = d;             // cond FALSE: p NonNull
                    pinned.facts[fact->first] = !fact->second;
                    setIfTracked(pinned.vars, p, NullState::NonNull);
                    next.push_back(std::move(escape));
                    next.push_back(std::move(pinned));
                }
                initState_ = std::move(next);
                zerodefect::normalizeGuarded(initState_, mergeNullStates);
            }
        }
    }

    // Guarded postconditions of THIS function (CONTRACTS.md Round D):
    // `ensures return != null if <g>` — checked per disjunct at every
    // return statement (checkGuardedEnsures).
    void setGuardedEnsures(std::vector<zerodefect::GuardedEnsuresInfo> v) {
        guardedEnsures_ = std::move(v);
    }

    // The per-variable NullState chain makes at most 3 transitions;
    // the number of disjuncts multiplies the height
    unsigned latticeHeight() const {
        return (static_cast<unsigned>(initState_.front().vars.size()) * 3 +
                1) * static_cast<unsigned>(zerodefect::kMaxDisjuncts) + 4 + factBudget();
    }

    // Fact records add lattice climbs the var-state formula above
    // never counted (v2b); bounded so pathological functions do not
    // explode the iteration cap.
    unsigned factBudget() const {
        auto n = static_cast<unsigned>(stampable_.size());
        return (n > 16 ? 16u : n) * 2 *
               static_cast<unsigned>(zerodefect::kMaxDisjuncts);
    }

    // Engine convergence hook: collapse the disjuncts when a block is
    // revisited beyond any monotone explanation (see DataflowEngine).
    void widen(State& s) const { zerodefect::widenGuarded(s, mergeNullStates); }

    State merge(const State& a, const State& b) const {
        return zerodefect::mergeGuarded(a, b, mergeNullStates);
    }

    State transfer(const Stmt* stmt, const State& inRaw,
                   ASTContext& /*ctx*/) const {
        // Fact lifecycle first (v2b): assignments to locals erase the
        // facts keyed on them; integer-constant stores stamp the new
        // truth. Domain logic below then reads the fact-current state.
        State in = inRaw;
        zerodefect::applyStmtFacts(in, stmt, stampable_, ptrFacts_,
                                   mergeNullStates);

        // A tracked pointer passed by non-const reference is an
        // out-param: the callee may rebind it, so its fact drops to
        // Unknown. There is no AddrOf node to see — only the parameter
        // type reveals it (the shadPS4 ResolveEpollBinding FP family:
        // `int* p = nullptr; f(id, p); *p` is NOT a definite null
        // deref when f takes `int*&`).
        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            State out = in;
            bool changed = false;
            zerodefect::forEachNonConstRefArg(call, [&](const Expr* arg) {
                const VarDecl* var = asVar(arg);
                if (!var) return;
                for (auto& d : out) {
                    auto it = d.vars.find(var);
                    if (it == d.vars.end()) continue;
                    it->second = NullState::Unknown;
                    changed = true;
                }
            });
            return changed ? out : in;
        }

        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Assign &&
            effect.kind != EffectKind::AssignUnknown)
            return in;

        State out = in;
        for (auto& d : out) {
            auto it = d.vars.find(effect.var);
            if (it == d.vars.end()) continue;  // not tracked
            it->second = (effect.kind == EffectKind::Assign)
                             ? effect.value
                             : NullState::Unknown;
        }
        return out;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        const auto* condExpr = dyn_cast<Expr>(cond);
        zerodefect::refineGuardedFactsWith(
            state, condExpr, isTrueBranch, mutated_, ptrFacts_,
            mergeNullStates,
            // Domain refuter for disjunction elimination: an operand
            // whose REQUIRED nullness contradicts this disjunct's var
            // state cannot have held here (walkNullCondition yields
            // the operand's necessary conditions).
            [](const zerodefect::Guarded<NullVarState>& d, const Expr* e,
               bool wanted) {
                bool refuted = false;
                zerodefect::walkNullCondition(
                    e, wanted, [&](const VarDecl* var, bool isNull) {
                        auto it = d.vars.find(var);
                        if (it == d.vars.end()) return;
                        if (isNull && it->second == NullState::NonNull)
                            refuted = true;
                        if (!isNull && it->second == NullState::Null)
                            refuted = true;
                    });
                return refuted;
            },
            // Per-disjunct var refinement of every leaf this disjunct
            // is known to satisfy (including survivors of an
            // eliminated disjunction — whole-state applyCondition
            // never sees those).
            [](zerodefect::Guarded<NullVarState>& d, const Expr* leaf,
               bool leafTrue) { applyCondition(leaf, leafTrue, d.vars); });
    }

    // Caller-side contract check (CONTRACTS.md Round C): every
    // visible call into a function with a declared `requires` on a
    // pointer parameter is checked against the caller's own nullness
    // state. Null literal / definitely-null argument -> error
    // (warning for zd:ai); possibly-null -> warning. The relational
    // escape is honored when the condition argument is an integer
    // literal; a non-literal escape stays conservative (silent).
    void checkCallContracts(const CallExpr* call, const State& before,
                            ASTContext& ctx) {
        const FunctionDecl* callee = call->getDirectCallee();
        if (!callee) return;
        auto parsed = zerodefect::allContractClausesForDecl(callee, ctx);
        if (parsed.clauses.empty()) return;
        auto req = zerodefect::analyzeRequires(parsed, callee);
        if (req.enforced.empty()) return;

        NullVarState flat =
            zerodefect::flattenGuarded(before, mergeNullStates);

        for (const auto& info : req.enforced) {
            if (info.kind == zerodefect::RequiresInfo::Kind::NonZeroParam)
                continue;  // DivByZero owns the zero domain
            if (info.paramIndex >= call->getNumArgs()) continue;
            const Expr* arg = call->getArg(info.paramIndex);

            if (info.kind ==
                zerodefect::RequiresInfo::Kind::NonNullUnlessCond) {
                if (info.condParamIndex >= call->getNumArgs()) continue;
                auto lit = zerodefect::intLiteralArg(
                    call->getArg(info.condParamIndex));
                if (!lit) continue;  // non-literal escape: conservative
                if (zerodefect::evalCmp(*lit, info.condOp,
                                        info.condLiteral))
                    continue;  // escape holds, contract satisfied
            }

            bool definite = false;
            bool maybe = false;
            if (zerodefect::isNullPointerArg(arg)) {
                definite = true;
            } else if (const VarDecl* var = asVar(arg)) {
                auto it = flat.find(var);
                if (it != flat.end()) {
                    definite = (it->second == NullState::Null);
                    maybe = (it->second == NullState::MaybeNull);
                }
            }
            if (!definite && !maybe) continue;

            const SourceManager& sm = ctx.getSourceManager();
            SourceLocation loc = sm.getExpansionLoc(call->getBeginLoc());
            const unsigned line = sm.getSpellingLineNumber(loc);
            if (!reportedContracts_.emplace(line, info.text).second)
                continue;

            zerodefect::Diagnostic diag;
            diag.file = sm.getFilename(loc).str();
            diag.line = line;
            diag.column = sm.getSpellingColumnNumber(loc);
            diag.rule_id = "contract";
            diag.severity = (definite && !info.machineProposed)
                                ? zerodefect::Severity::Error
                                : zerodefect::Severity::Warning;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::ContractViolated, info.text);
            diag.function = funcName_;
            results_.push_back(std::move(diag));
            // Violation trace (Round D): why is the argument null?
            if (const VarDecl* var = asVar(arg))
                noteTargets_.emplace_back(results_.size() - 1, var);
        }
    }

    // Guarded postcondition check (CONTRACTS.md Round D): at a return
    // statement, every disjunct that does not REFUTE the guard must
    // satisfy the postcondition. A disjunct that PROVES the guard and
    // returns definite null is a violation (error for bare zd:); null
    // under an undecided guard, or possibly-null, is a warning —
    // evidence-per-path, the same ladder as everywhere else.
    void checkGuardedEnsures(const ReturnStmt* ret, const State& before,
                             ASTContext& ctx) {
        if (guardedEnsures_.empty()) return;
        const Expr* val = ret->getRetValue();
        if (!val) return;
        const NullState literal = evaluateNullness(val);
        const VarDecl* var = asVar(val);
        if (literal == NullState::Unknown && !var) return;

        for (const auto& info : guardedEnsures_) {
            bool definite = false;
            bool maybe = false;
            for (const auto& d : before) {
                // Guard provably false on this path: exempt.
                if (zerodefect::factsContradict(d.facts, info.guardKey,
                                                info.guardWanted))
                    continue;
                bool guardProven = zerodefect::factsContradict(
                    d.facts, info.guardKey, !info.guardWanted);
                NullState v = literal;
                if (v == NullState::Unknown) {
                    auto it = d.vars.find(var);
                    if (it == d.vars.end()) continue;
                    v = it->second;
                }
                if (v == NullState::Null)
                    (guardProven ? definite : maybe) = true;
                else if (v == NullState::MaybeNull)
                    maybe = true;
            }
            if (!definite && !maybe) continue;

            const SourceManager& sm = ctx.getSourceManager();
            SourceLocation loc = sm.getExpansionLoc(ret->getBeginLoc());
            const unsigned line = sm.getSpellingLineNumber(loc);
            if (!reportedContracts_.emplace(line, info.text).second)
                continue;

            zerodefect::Diagnostic diag;
            diag.file = sm.getFilename(loc).str();
            diag.line = line;
            diag.column = sm.getSpellingColumnNumber(loc);
            diag.rule_id = "contract";
            diag.severity = (definite && !info.machineProposed)
                                ? zerodefect::Severity::Error
                                : zerodefect::Severity::Warning;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::ContractViolated, info.text);
            diag.function = funcName_;
            results_.push_back(std::move(diag));
            if (var)
                noteTargets_.emplace_back(results_.size() - 1, var);
        }
    }

    // Guard trace (Trace v2): during the reporting pass, if the edge
    // refinement made a variable DEFINITELY null, a trace note is added
    // at the condition point — the "why null" question for the
    // `if (p == 0) { *p }` finding now has an answer (null coming purely
    // from a guard, with no assignment, used to be traceless).
    void onEdgeRefined(const Stmt* cond, bool /*isTrueBranch*/,
                       const State& beforeDisjuncts,
                       const State& afterDisjuncts, ASTContext& ctx) {
        NullVarState before =
            zerodefect::flattenGuarded(beforeDisjuncts, mergeNullStates);
        NullVarState after =
            zerodefect::flattenGuarded(afterDisjuncts, mergeNullStates);
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState == NullState::Null)
                recordEvent(cond, var, ctx,
                            zerodefect::MsgId::TraceAssumedNullHere);
        }
    }

    void onStatement(const Stmt* stmt, const State& beforeDisjuncts,
                     const State& afterDisjuncts, ASTContext& ctx) {
        if (const auto* call = dyn_cast<CallExpr>(stmt))
            checkCallContracts(call, beforeDisjuncts, ctx);
        if (const auto* ret = dyn_cast<ReturnStmt>(stmt))
            checkGuardedEnsures(ret, beforeDisjuncts, ctx);

        NullVarState before =
            zerodefect::flattenGuarded(beforeDisjuncts, mergeNullStates);
        NullVarState after =
            zerodefect::flattenGuarded(afterDisjuncts, mergeNullStates);
        // Dataflow trace: record transitions to null / possibly-null
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState == NullState::Null)
                recordEvent(stmt, var, ctx,
                            zerodefect::MsgId::TraceAssignedNullHere);
            else if (afterState == NullState::MaybeNull)
                recordEvent(stmt, var, ctx,
                            zerodefect::MsgId::TraceAssignedMaybeNullHere);
        }

        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Deref) return;

        auto it = before.find(effect.var);
        if (it == before.end()) return;
        if (it->second != NullState::Null &&
            it->second != NullState::MaybeNull)
            return;

        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reported_.emplace(effect.var, line).second) return;

        const bool definite = (it->second == NullState::Null);

        // Report-flood dedup (warnings only): one MaybeNull origin can
        // reach dozens of dereferences (shadPS4 internal__Foprep: a
        // single missing return produced 25 identical warnings). The
        // FIRST dereference carries the report; the rest become "also
        // dereferenced here" trace notes on it. Definite (error)
        // reports keep per-line granularity — they are rare and each
        // site matters.
        if (!definite) {
            auto first = firstWarnIndex_.find(effect.var);
            if (first != firstWarnIndex_.end()) {
                zerodefect::TraceNote note;
                note.file = sm.getFilename(loc).str();
                note.line = line;
                note.column = sm.getSpellingColumnNumber(loc);
                note.message = zerodefect::msg(
                    zerodefect::MsgId::TraceAlsoDerefHere,
                    effect.var->getNameAsString());
                alsoDerefs_[effect.var].push_back(std::move(note));
                return;
            }
        }

        zerodefect::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "null-deref";
        diag.function = funcName_;
        if (definite) {
            diag.severity = zerodefect::Severity::Error;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::NullDerefDefinite,
                effect.var->getNameAsString());
        } else {
            diag.severity = zerodefect::Severity::Warning;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::NullDerefMaybe,
                effect.var->getNameAsString());
        }
        results_.push_back(diag);
        if (!definite)
            firstWarnIndex_[effect.var] = results_.size() - 1;
        noteTargets_.emplace_back(results_.size() - 1, effect.var);
    }

    // After the run finishes: attach the null-assignment traces to
    // reports, then the deduplicated "also dereferenced here" sites.
    void attachTraces() {
        for (const auto& [index, var] : noteTargets_) {
            std::vector<zerodefect::TraceNote> notes;
            auto it = events_.find(var);
            if (it != events_.end()) {
                notes = it->second;
                std::sort(notes.begin(), notes.end());
                if (notes.size() > 6) notes.resize(6);
            }
            auto also = alsoDerefs_.find(var);
            if (also != alsoDerefs_.end()) {
                auto extra = also->second;
                std::sort(extra.begin(), extra.end());
                for (auto& n : extra) {
                    if (notes.size() >= 10) break;
                    notes.push_back(std::move(n));
                }
            }
            if (!notes.empty()) results_[index].notes = std::move(notes);
        }
        noteTargets_.clear();
        firstWarnIndex_.clear();
        alsoDerefs_.clear();
    }

private:
    void recordEvent(const Stmt* stmt, const VarDecl* var,
                     ASTContext& ctx, zerodefect::MsgId msgId) {
        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        zerodefect::TraceNote note;
        note.file = sm.getFilename(loc).str();
        note.line = sm.getSpellingLineNumber(loc);
        note.column = sm.getSpellingColumnNumber(loc);
        note.message = zerodefect::msg(msgId, var->getNameAsString());

        auto& list = events_[var];
        for (const auto& existing : list)
            if (existing.line == note.line) return;
        list.push_back(std::move(note));
    }

    std::set<const ValueDecl*> mutated_;
    std::set<const ValueDecl*> stampable_;
    std::set<const ValueDecl*> ptrFacts_;
    std::string funcName_;
    zerodefect::DiagnosticList& results_;
    State initState_;
    std::set<std::pair<const VarDecl*, unsigned>> reported_;
    std::map<const VarDecl*, std::vector<zerodefect::TraceNote>> events_;
    std::vector<std::pair<size_t, const VarDecl*>> noteTargets_;
    std::map<const VarDecl*, size_t> firstWarnIndex_;
    std::map<const VarDecl*, std::vector<zerodefect::TraceNote>> alsoDerefs_;
    std::set<std::pair<unsigned, std::string>> reportedContracts_;
    std::vector<zerodefect::GuardedEnsuresInfo> guardedEnsures_;
};

// --- Matcher callback ---

class NullDerefCallback : public MatchFinder::MatchCallback {
public:
    explicit NullDerefCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;
        if (!zerodefect::functionFilterAllows(*func)) return;
        if (!zerodefect::lineFilterAllows(*func, sm)) return;

        auto parsed = zerodefect::allContractClausesForDecl(func, *result.Context);
        auto guardedEnsures =
            zerodefect::analyzeNullEnsuresGuards(parsed, func);

        auto trackedVars = collectTrackedVars(func, *result.Context);
        // A function with no pointer variables still needs the pass
        // when a contract must be checked in it: a call into a
        // contracted callee, or its own guarded postcondition
        // (`return NULL;` needs no variable).
        if (trackedVars.empty() && guardedEnsures.enforced.empty() &&
            !hasNonNullContractCalls(func, *result.Context))
            return;

        NullDerefAnalysis analysis(
            trackedVars, zerodefect::collectUnkeyableDecls(func),
            zerodefect::collectFactDecls(func),
            zerodefect::collectPtrFactDecls(func),
            func->getQualifiedNameAsString(), results_);
        if (!parsed.clauses.empty()) {
            auto req = zerodefect::analyzeRequires(parsed, func);
            if (!req.enforced.empty())
                analysis.seedRequires(func, req.enforced);
            if (!guardedEnsures.enforced.empty())
                analysis.setGuardedEnsures(
                    std::move(guardedEnsures.enforced));
        }
        auto df = zerodefect::runDataflow(func, *result.Context, analysis);
        if (!df.converged)
            zerodefect::CoverageReport::instance().recordNonConvergence(
                func->getQualifiedNameAsString());
        analysis.attachTraces();
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string NullDerefRule::id() const {
    return "null-deref";
}

std::string NullDerefRule::description() const {
    return "CFG-based null pointer dereference analysis with branch "
           "condition refinement";
}

Severity NullDerefRule::defaultSeverity() const {
    return Severity::Error;
}

void NullDerefRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    MatchFinder finder;
    NullDerefCallback callback(results);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
