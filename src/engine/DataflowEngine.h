#ifndef ZERODEFECT_DATAFLOW_ENGINE_H
#define ZERODEFECT_DATAFLOW_ENGINE_H

#include "engine/CfgCache.h"
#include "engine/FatalCalls.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/Analysis/CFG.h>

#include <queue>
#include <type_traits>
#include <unordered_map>

namespace zerodefect {

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
struct HasOnEdgeRefined : std::false_type {};

template <typename A>
struct HasOnEdgeRefined<A, std::void_t<decltype(
    std::declval<A>().onEdgeRefined(
        std::declval<const clang::Stmt*>(),
        bool{},
        std::declval<const typename A::State&>(),
        std::declval<const typename A::State&>(),
        std::declval<clang::ASTContext&>()))>> : std::true_type {};

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
                        const clang::Stmt* cond = g1->getTerminatorCondition();
                        if (cond && gExit != blockExitState.end() &&
                            e1 != blockExitState.end() &&
                            e2 != blockExitState.end()) {
                            const clang::CFGBlock* trueSucc =
                                g1->succ_begin()->getReachableBlock();
                            State rTrue = gExit->second;
                            analysis.refineOnEdge(cond, true, rTrue, ctx);
                            State rFalse = gExit->second;
                            analysis.refineOnEdge(cond, false, rFalse, ctx);
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
                    if (const clang::Stmt* cond =
                            pred->getTerminatorCondition()) {
                        auto succIt = pred->succ_begin();
                        const clang::CFGBlock* trueSucc =
                            succIt->getReachableBlock();
                        ++succIt;
                        const clang::CFGBlock* falseSucc =
                            succIt->getReachableBlock();
                        if (trueSucc != falseSucc &&
                            (block == trueSucc || block == falseSucc)) {
                            const bool edgeIsTrue = (block == trueSucc);
                            if constexpr (
                                detail::HasOnEdgeRefined<Analysis>::value) {
                                if (reporting) {
                                    State beforeRefine = predState;
                                    analysis.refineOnEdge(cond, edgeIsTrue,
                                                          predState, ctx);
                                    if (predState != beforeRefine)
                                        analysis.onEdgeRefined(
                                            cond, edgeIsTrue, beforeRefine,
                                            predState, ctx);
                                } else {
                                    analysis.refineOnEdge(cond, edgeIsTrue,
                                                          predState, ctx);
                                }
                            } else {
                                (void)reporting;
                                analysis.refineOnEdge(cond, edgeIsTrue,
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

    while (!worklist.empty() && iterations < maxIterations) {
        ++iterations;
        const clang::CFGBlock* block = worklist.front();
        worklist.pop();

        bool hasPreds = false;
        State entryState = computeEntryState(block, hasPreds,
                                             /*reporting=*/false);
        if (!hasPreds && block != &cfg->getEntry()) continue;

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
        if (pathKilled) continue;

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

} // namespace zerodefect

#endif // ZERODEFECT_DATAFLOW_ENGINE_H
