#ifndef CODESKEPTIC_DATAFLOW_ENGINE_H
#define CODESKEPTIC_DATAFLOW_ENGINE_H

#include "engine/CfgCache.h"
#include "engine/ConditionWalk.h"
#include "engine/FatalCalls.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/Analysis/CFG.h>

#include <queue>
#include <type_traits>
#include <unordered_map>

namespace codeskeptic {

template <typename Analysis>
struct DataflowResult {
    using State = typename Analysis::State;
    std::unordered_map<unsigned, State> blockExitStates;
    bool converged = false;
    unsigned exitBlockID = 0;
};

namespace detail {

template <typename A, typename = void>
struct HasOnStatement : std::false_type {};

template <typename A>
struct HasOnStatement<A, std::void_t<decltype(
    std::declval<A>().onStatement(
        std::declval<const clang::Stmt*>(),
        std::declval<const typename A::State&>(),
        std::declval<const typename A::State&>(),
        std::declval<clang::ASTContext&>()))>> : std::true_type {};

template <typename A, typename = void>
struct HasLatticeHeight : std::false_type {};

template <typename A>
struct HasLatticeHeight<A, std::void_t<decltype(
    std::declval<const A&>().latticeHeight())>> : std::true_type {};

template <typename A, typename = void>
struct HasRefineOnEdge : std::false_type {};

template <typename A>
struct HasRefineOnEdge<A, std::void_t<decltype(
    std::declval<A>().refineOnEdge(
        std::declval<const clang::Stmt*>(),
        bool{},
        std::declval<typename A::State&>(),
        std::declval<clang::ASTContext&>()))>> : std::true_type {};

template <typename A, typename = void>
struct HasWiden : std::false_type {};

template <typename A>
struct HasWiden<A, std::void_t<decltype(
    std::declval<const A&>().widen(
        std::declval<typename A::State&>()))>> : std::true_type {};

template <typename A, typename = void>
struct HasOnEdgeRefined : std::false_type {};

template <typename A>
struct HasOnEdgeRefined<A, std::void_t<decltype(
    std::declval<A>().onEdgeRefined(
        std::declval<const clang::Stmt*>(),
        bool{},
        std::declval<const typename A::State&>(),
        std::declval<const typename A::State&>(),
        std::declval<clang::ASTContext&>()))>> : std::true_type {};

// The condition actually EVALUATED in this block, with its edge
// polarity. For a short-circuit tree (`if (s || l <= 0)`,
// `if (_unlikely_(!(s || l <= 0)))` — the systemd assert), Clang
// gives the final decision block a terminator of the WHOLE
// IfStmt/ternary; getTerminatorCondition() then returns the full
// tree, which no domain can use: the true edge of an || says nothing
// about either operand alone, so both the nullness walk and
// conditionFact went home empty-handed (2026-07-12).
//
// The wrappers between a branch decision and the condition TREE it
// actually tests carry only polarity: `!` flips, `__builtin_expect`
// and the comma operator pass through. The tree itself (including
// `&&`/`||` structure) is handed to the analysis — walkCondition
// decomposes conjunctions structurally, and the disjunction-aware
// per-disjunct refinement (GuardedDisjuncts) handles the branches a
// walk cannot decide. Clang materializes negated short-circuit
// conditions as VALUES (`if (!!(!(s || l <= 0)))` — the systemd
// assert): the operand paths merge BEFORE the single branch, so the
// per-leaf edges seen in plain `if (a || b)` CFGs do not exist there
// — whoever consumes the condition must reason about the whole tree
// per disjunct.
struct EdgeCondition {
    const clang::Stmt* leaf = nullptr;
    bool flip = false;
};

inline EdgeCondition edgeCondition(const clang::CFGBlock* block) {
    EdgeCondition out;
    out.leaf = block->getTerminatorCondition();
    const auto* e = llvm::dyn_cast_or_null<clang::Expr>(out.leaf);
    while (e) {
        e = e->IgnoreParenImpCasts();
        // `static_cast<bool>(...)` (glibc's C++ assert) is another
        // polarity-free wrapper — see stripBoolPreservingCasts.
        {
            const clang::Expr* stripped = stripBoolPreservingCasts(e);
            if (stripped != e) { e = stripped; continue; }
        }
        if (const auto* call = llvm::dyn_cast<clang::CallExpr>(e)) {
            const clang::FunctionDecl* callee = call->getDirectCallee();
            const clang::IdentifierInfo* id =
                callee ? callee->getIdentifier() : nullptr;
            if (id && (id->getName() == "__builtin_expect" ||
                       id->getName() ==
                           "__builtin_expect_with_probability") &&
                call->getNumArgs() >= 1) {
                e = call->getArg(0);
                continue;
            }
            break;
        }
        if (const auto* un = llvm::dyn_cast<clang::UnaryOperator>(e)) {
            if (un->getOpcode() == clang::UO_LNot) {
                out.flip = !out.flip;
                e = un->getSubExpr();
                continue;
            }
            break;
        }
        if (const auto* bo = llvm::dyn_cast<clang::BinaryOperator>(e)) {
            if (bo->getOpcode() == clang::BO_Comma) {
                e = bo->getRHS();
                continue;
            }
        }
        break;
    }
    if (e) out.leaf = e;
    return out;
}

} // namespace detail

template <typename Analysis>
DataflowResult<Analysis> runDataflow(
        const clang::FunctionDecl* func,
        clang::ASTContext& ctx,
        Analysis& analysis) {
    using State = typename Analysis::State;
    DataflowResult<Analysis> result;

    if (!func || !func->hasBody()) return result;

    // CFG comes from the shared cache (built once per function; build
    // options — including setAllAlwaysAdd — live in CfgCache)
    clang::CFG* cfg = CfgCache::instance().get(func, ctx);
    if (!cfg) return result;

    const unsigned numBlocks = cfg->getNumBlockIDs();

    // A monotone transfer + finite lattice guarantees convergence; the
    // cap is only a safety fuse. If the analysis reports its lattice
    // height, the cap scales with it (each block can climb at most
    // height times), otherwise the old default is used.
    unsigned latticeHeight = 4;
    if constexpr (detail::HasLatticeHeight<Analysis>::value)
        latticeHeight = analysis.latticeHeight();
    const unsigned maxIterations = numBlocks * (latticeHeight + 2);

    auto& blockExitState = result.blockExitStates;

    // Computes the block entry state from the predecessors' exit
    // states (including assume-edge refinement). The same logic serves
    // both the worklist phase and the reporting pass. `reporting` is
    // true only in the reporting pass: if the analysis provides
    // onEdgeRefined, it is invoked on edges where refinement ACTUALLY
    // changed the state — this is how guard traces are born. It is not
    // invoked in phase 1 (that would emit spurious events from early
    // state; the same fixpoint rule as onStatement).
    auto computeEntryState = [&](const clang::CFGBlock* block,
                                 bool& hasPreds, bool reporting) -> State {
        State entryState = analysis.initialState();
        hasPreds = false;
        bool firstPred = true;

        // Value-selection rewind. A ternary refines its ARMS (`z ?
        // 100/z : 0` — z is NonZero inside the true arm), but the facts
        // it contributes are tautological ONCE THE ARMS REJOIN: "p is
        // null or non-null" must not downgrade the pre-ternary state to
        // a reportable MaybeNull for the rest of the function (the
        // GGML_TENSOR_LOCALS defensive-macro shape, `ne0 = p ? p->x :
        // 0`, produced ~90% of llama.cpp's findings). Detection: the
        // join's two predecessors are the two arms of one
        // ConditionalOperator diamond and each arm's exit equals the
        // PURE refinement of the condition block's exit — the arms
        // changed nothing themselves — so the join re-enters with the
        // condition block's state. An arm with a real effect (an
        // assignment) fails the equality and merges normally.
        if constexpr (detail::HasRefineOnEdge<Analysis>::value) {
            if (block->pred_size() == 2) {
                auto predIt = block->pred_begin();
                const clang::CFGBlock* arm1 = predIt->getReachableBlock();
                ++predIt;
                const clang::CFGBlock* arm2 = predIt->getReachableBlock();
                if (arm1 && arm2 && arm1 != arm2 &&
                    arm1->pred_size() == 1 && arm2->pred_size() == 1) {
                    const clang::CFGBlock* g1 =
                        arm1->pred_begin()->getReachableBlock();
                    const clang::CFGBlock* g2 =
                        arm2->pred_begin()->getReachableBlock();
                    const clang::Stmt* term =
                        g1 ? g1->getTerminatorStmt() : nullptr;
                    if (g1 && g1 == g2 && term &&
                        (llvm::isa<clang::ConditionalOperator>(term) ||
                         llvm::isa<clang::BinaryConditionalOperator>(term))) {
                        auto gExit = blockExitState.find(g1->getBlockID());
                        auto e1 = blockExitState.find(arm1->getBlockID());
                        auto e2 = blockExitState.find(arm2->getBlockID());
                        // Same per-block leaf condition the arms' entry
                        // refinement used — the exit-equality test
                        // below compares like with like.
                        detail::EdgeCondition cond = detail::edgeCondition(g1);
                        if (cond.leaf && gExit != blockExitState.end() &&
                            e1 != blockExitState.end() &&
                            e2 != blockExitState.end()) {
                            const clang::CFGBlock* trueSucc =
                                g1->succ_begin()->getReachableBlock();
                            State rTrue = gExit->second;
                            analysis.refineOnEdge(cond.leaf, !cond.flip,
                                                  rTrue, ctx);
                            State rFalse = gExit->second;
                            analysis.refineOnEdge(cond.leaf, cond.flip,
                                                  rFalse, ctx);
                            const State& trueExit =
                                (arm1 == trueSucc) ? e1->second : e2->second;
                            const State& falseExit =
                                (arm1 == trueSucc) ? e2->second : e1->second;
                            if (!(trueExit != rTrue) &&
                                !(falseExit != rFalse)) {
                                hasPreds = true;
                                return gExit->second;
                            }
                        }
                    }
                }
            }
        }

        for (auto it = block->pred_begin(); it != block->pred_end(); ++it) {
            const clang::CFGBlock* pred = it->getReachableBlock();
            if (!pred) continue;

            auto found = blockExitState.find(pred->getBlockID());
            if (found == blockExitState.end()) continue;

            State predState = found->second;

            // Assume edge: on a conditional terminator with two
            // successors (if/while/for), the state is refined per the
            // true/false edge. succ[0] = true, succ[1] = false (Clang
            // CFG convention).
            if constexpr (detail::HasRefineOnEdge<Analysis>::value) {
                if (pred->succ_size() == 2) {
                    detail::EdgeCondition cond = detail::edgeCondition(pred);
                    if (cond.leaf) {
                        auto succIt = pred->succ_begin();
                        const clang::CFGBlock* trueSucc =
                            succIt->getReachableBlock();
                        ++succIt;
                        const clang::CFGBlock* falseSucc =
                            succIt->getReachableBlock();
                        if (trueSucc != falseSucc &&
                            (block == trueSucc || block == falseSucc)) {
                            const bool edgeIsTrue =
                                (block == trueSucc) != cond.flip;
                            if constexpr (
                                detail::HasOnEdgeRefined<Analysis>::value) {
                                if (reporting) {
                                    State beforeRefine = predState;
                                    analysis.refineOnEdge(cond.leaf,
                                                          edgeIsTrue,
                                                          predState, ctx);
                                    if (predState != beforeRefine)
                                        analysis.onEdgeRefined(
                                            cond.leaf, edgeIsTrue,
                                            beforeRefine, predState, ctx);
                                } else {
                                    analysis.refineOnEdge(cond.leaf,
                                                          edgeIsTrue,
                                                          predState, ctx);
                                }
                            } else {
                                (void)reporting;
                                analysis.refineOnEdge(cond.leaf, edgeIsTrue,
                                                      predState, ctx);
                            }
                        }
                    }
                }
            }

            hasPreds = true;
            if (firstPred) {
                entryState = predState;
                firstPred = false;
            } else {
                entryState = analysis.merge(entryState, predState);
            }
        }
        return entryState;
    };

    // --- Phase 1: fixpoint iteration ---
    // In this phase ONLY transfer runs; onStatement is NOT called.
    // Reporting from early (not yet converged) states leads to wrong
    // severity: e.g. on the first visit of a do-while body, before the
    // back-edge state exists, we might claim "definitely null".
    std::queue<const clang::CFGBlock*> worklist;
    worklist.push(&cfg->getEntry());
    unsigned iterations = 0;

    // Convergence widening. The guarded-disjunct domain is not a clean
    // lattice: facts are recorded, ERASED (assignments), and disjuncts
    // are DROPPED (contradictions) — transfer is not monotone, and
    // real code does oscillate (rtp2httpd's parser functions cycled
    // forever; an 8x iteration budget changed nothing, 2026-07-12).
    // The classical fix, WITH time memory: once a block has been
    // visited more often than any monotone climb could explain, its
    // entry is joined with the previous widened entry and collapsed to
    // a single disjunct (analysis-provided upper approximation). Facts
    // that flip between visits disagree in the join and are erased by
    // the collapse; var states only climb their finite lattice — the
    // sequence stabilizes. Memoryless widening is NOT enough: a
    // single-disjunct state can still alternate fact VALUES across
    // visits (merge_query_strings kept cycling until the join-with-
    // previous was added).
    std::vector<unsigned> visitCounts(numBlocks, 0);
    std::map<unsigned, State> widenMemory;
    const unsigned widenAfter = latticeHeight + 2;

    while (!worklist.empty() && iterations < maxIterations) {
        ++iterations;
        const clang::CFGBlock* block = worklist.front();
        worklist.pop();

        bool hasPreds = false;
        State entryState = computeEntryState(block, hasPreds,
                                             /*reporting=*/false);
        if (!hasPreds && block != &cfg->getEntry()) continue;

        if constexpr (detail::HasWiden<Analysis>::value) {
            const unsigned id = block->getBlockID();
            if (++visitCounts[id] > widenAfter) {
                auto mem = widenMemory.find(id);
                if (mem != widenMemory.end())
                    entryState = analysis.merge(mem->second, entryState);
                analysis.widen(entryState);
                widenMemory[id] = entryState;
            }
        }

        State currentState = entryState;
        bool pathKilled = false;
        for (const clang::CFGElement& elem : *block) {
            auto cfgStmt = elem.getAs<clang::CFGStmt>();
            if (!cfgStmt) continue;
            const clang::Stmt* stmt = cfgStmt->getStmt();
            if (!stmt) continue;
            // A registered fatal call (--fatal-asserts) ends the path
            // here: the block's exit state is never recorded, so
            // successors treat this edge like one from an unreachable
            // predecessor. Elements after the call are dead code.
            if (isFatalCall(stmt)) { pathKilled = true; break; }
            currentState = analysis.transfer(stmt, currentState, ctx);
        }
        // Real [[noreturn]] calls (exit, abort, __assert_fail) get the
        // same treatment as registered fatal calls: Clang wires such
        // blocks straight to the CFG exit, and letting their state
        // merge there DILUTES facts on the live paths — `if (!p)
        // exit(-1);` fed a None into the exit block that dissolved a
        // later Freed (Freed ⊔ None = None) and blinded the
        // freed-through-alias check (the Juliet malloc_realloc family).
        // The process dies on this path; it must not vote on
        // end-of-function state.
        if (pathKilled || block->hasNoReturnElement()) continue;

        // Update exit state, propagate if changed
        auto [it, inserted] = blockExitState.emplace(
            block->getBlockID(), currentState);

        bool changed = inserted || it->second != currentState;
        if (changed) {
            it->second = currentState;
            for (auto succIt = block->succ_begin();
                 succIt != block->succ_end(); ++succIt) {
                const clang::CFGBlock* succ = succIt->getReachableBlock();
                if (succ) worklist.push(succ);
            }
        }
    }

    result.converged = (iterations < maxIterations);
    result.exitBlockID = cfg->getExit().getBlockID();

    // --- Phase 2: reporting pass ---
    // Each block's entry state is recomputed from the converged exit
    // states and the elements are walked once more, calling onStatement.
    // This way reports always reflect the state at the fixpoint.
    if constexpr (detail::HasOnStatement<Analysis>::value) {
        for (const clang::CFGBlock* block : *cfg) {
            if (!block) continue;

            bool hasPreds = false;
            State entryState = computeEntryState(block, hasPreds,
                                                 /*reporting=*/true);
            if (!hasPreds && block != &cfg->getEntry()) continue;

            State currentState = entryState;
            for (const clang::CFGElement& elem : *block) {
                auto cfgStmt = elem.getAs<clang::CFGStmt>();
                if (!cfgStmt) continue;
                const clang::Stmt* stmt = cfgStmt->getStmt();
                if (!stmt) continue;
                // Same cut as phase 1: nothing after a fatal call
                // executes, so nothing there is reported either.
                if (isFatalCall(stmt)) break;

                State before = currentState;
                currentState = analysis.transfer(stmt, currentState, ctx);
                analysis.onStatement(stmt, before, currentState, ctx);
            }
        }
    }

    return result;
}

} // namespace codeskeptic

#endif // CODESKEPTIC_DATAFLOW_ENGINE_H
