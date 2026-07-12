#ifndef ZERODEFECT_DATAFLOW_ENGINE_H
#define ZERODEFECT_DATAFLOW_ENGINE_H

#include "engine/CfgCache.h"
#include "engine/FatalCalls.h"

#include <clang/AST/ASTContext.h>
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
