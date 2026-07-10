#ifndef ZERODEFECT_DATAFLOW_ENGINE_H
#define ZERODEFECT_DATAFLOW_ENGINE_H

#include "engine/CfgCache.h"

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

    // CFG paylasimli onbellekten (fonksiyon basina bir insa; kurulum
    // secenekleri — setAllAlwaysAdd dahil — CfgCache'te yasar)
    clang::CFG* cfg = CfgCache::instance().get(func, ctx);
    if (!cfg) return result;

    const unsigned numBlocks = cfg->getNumBlockIDs();

    // Monoton transfer + sonlu lattice ile sabitleme garantidir; tavan
    // yalnizca guvenlik sigortasi. Analiz lattice yuksekligini bildirirse
    // tavan ona gore olceklenir (blok basina en fazla yukseklik kadar
    // yukselis olabilir), bildirmezse eski varsayilan kullanilir.
    unsigned latticeHeight = 4;
    if constexpr (detail::HasLatticeHeight<Analysis>::value)
        latticeHeight = analysis.latticeHeight();
    const unsigned maxIterations = numBlocks * (latticeHeight + 2);

    auto& blockExitState = result.blockExitStates;

    // Predecessor exit state'lerinden blok giris state'ini hesaplar
    // (assume-edge iyilestirmesi dahil). Hem worklist fazinda hem
    // raporlama gecisinde ayni mantik kullanilir. `reporting` yalnizca
    // raporlama gecisinde true'dur: analiz onEdgeRefined sagliyorsa,
    // iyilestirmenin state'i GERCEKTEN degistirdigi kenarlarda cagrilir
    // — guard izleri boyle dogar. Faz 1'de cagrilmaz (erken state'le
    // sahte olay uretirdi; onStatement'in fixpoint kuralinin aynisi).
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

            // Assume edge: iki ardilli kosullu terminator'da (if/while/for)
            // true/false kenarina gore state iyilestirilir. succ[0] = true,
            // succ[1] = false (Clang CFG konvansiyonu).
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

    // --- Faz 1: fixpoint iterasyonu ---
    // Bu fazda YALNIZCA transfer calisir; onStatement CAGRILMAZ.
    // Erken (henuz sabitlenmemis) state'lerle rapor uretmek yanlis
    // severity'ye yol acar: ornegin do-while govdesinin ilk ziyaretinde
    // back-edge state'i henuz yokken "kesinlikle null" denebilir.
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
        for (const clang::CFGElement& elem : *block) {
            auto cfgStmt = elem.getAs<clang::CFGStmt>();
            if (!cfgStmt) continue;
            const clang::Stmt* stmt = cfgStmt->getStmt();
            if (!stmt) continue;
            currentState = analysis.transfer(stmt, currentState, ctx);
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

    // --- Faz 2: raporlama gecisi ---
    // Sabitlenmis exit state'lerden her blogun giris state'i yeniden
    // hesaplanir ve elemanlar bir kez daha yurunerek onStatement cagrilir.
    // Boylece raporlar her zaman fixpoint'teki state'i yansitir.
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
