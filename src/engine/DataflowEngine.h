#ifndef ZERODEFECT_DATAFLOW_ENGINE_H
#define ZERODEFECT_DATAFLOW_ENGINE_H

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

} // namespace detail

template <typename Analysis>
DataflowResult<Analysis> runDataflow(
        const clang::FunctionDecl* func,
        clang::ASTContext& ctx,
        Analysis& analysis) {
    using State = typename Analysis::State;
    DataflowResult<Analysis> result;

    if (!func || !func->hasBody()) return result;

    clang::CFG::BuildOptions opts;
    std::unique_ptr<clang::CFG> cfg = clang::CFG::buildCFG(
        func, func->getBody(), &ctx, opts);
    if (!cfg) return result;

    const unsigned numBlocks = cfg->getNumBlockIDs();
    const unsigned maxIterations = numBlocks * 4;

    auto& blockExitState = result.blockExitStates;

    std::queue<const clang::CFGBlock*> worklist;
    worklist.push(&cfg->getEntry());
    unsigned iterations = 0;

    while (!worklist.empty() && iterations < maxIterations) {
        ++iterations;
        const clang::CFGBlock* block = worklist.front();
        worklist.pop();

        // Merge from predecessors
        State entryState = analysis.initialState();
        bool hasPreds = false;
        bool firstPred = true;

        for (auto it = block->pred_begin(); it != block->pred_end(); ++it) {
            const clang::CFGBlock* pred = it->getReachableBlock();
            if (!pred) continue;

            auto found = blockExitState.find(pred->getBlockID());
            if (found == blockExitState.end()) continue;

            hasPreds = true;
            if (firstPred) {
                entryState = found->second;
                firstPred = false;
            } else {
                entryState = analysis.merge(entryState, found->second);
            }
        }

        if (!hasPreds && block != &cfg->getEntry()) continue;

        // Walk statements
        State currentState = entryState;

        for (const clang::CFGElement& elem : *block) {
            auto cfgStmt = elem.getAs<clang::CFGStmt>();
            if (!cfgStmt) continue;
            const clang::Stmt* stmt = cfgStmt->getStmt();
            if (!stmt) continue;

            State before = currentState;
            currentState = analysis.transfer(stmt, currentState, ctx);

            if constexpr (detail::HasOnStatement<Analysis>::value) {
                analysis.onStatement(stmt, before, currentState, ctx);
            }
        }

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
    return result;
}

} // namespace zerodefect

#endif // ZERODEFECT_DATAFLOW_ENGINE_H
