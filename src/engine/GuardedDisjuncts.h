#ifndef ZERODEFECT_GUARDED_DISJUNCTS_H
#define ZERODEFECT_GUARDED_DISJUNCTS_H

// Guard'li disjunkt state'i: hedefli yol duyarliliginin veri yapisi.
//
// Bir analiz state'i tek birlesik VarMap yerine az sayida
// (kosul-gercekleri, VarMap) cifti olarak tutulur. refineOnEdge ayni
// kosulu ikinci kez gordugunde celisen disjunkti dusurur — boylece
// "if(g==5) uret; ... if(g==5) tuket;" kalibindaki hayalet yollar
// (uretilip tuketilmeyen) hic dogmaz. Juliet FP avinin kok cozumu;
// once MemoryLeakRule'da dogrulandi, uc kuralin ortak bileseni oldu.
//
// Motor sozlesmesiyle uyum: State = std::vector<Guarded<VarMap>>
// operator== ile karsilastirilir; normalizeGuarded kanonik sira ve
// tavan (widening) uygular — motorun "state degisti mi" testi kararli
// kalir. Tavan asiminda tek disjunkta genisletilir: ortak gercekler
// kesisir, VarMap'ler birlesir (klasik birlesik analize geri dusus).
//
// VarMap gereksinimleri: std::map<K, V>; V icin cagiran bir
// mergeVal(V, V) -> V birlestiricisi saglar.

#include "engine/PathFacts.h"

#include <clang/AST/Expr.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <set>
#include <vector>

namespace zerodefect {

template <typename VarMap>
struct Guarded {
    std::map<FactKey, bool> facts;
    VarMap vars;

    bool operator==(const Guarded& o) const {
        return facts == o.facts && vars == o.vars;
    }
    bool operator!=(const Guarded& o) const { return !(*this == o); }
    bool operator<(const Guarded& o) const {
        if (facts != o.facts) return facts < o.facts;
        return vars < o.vars;
    }
};

template <typename VarMap>
using GuardedState = std::vector<Guarded<VarMap>>;

// Disjunkt tavani. Kucuk tutulur: hedef genel yol duyarliligi degil,
// korelasyonlu guard kalibi. Asiminda widening bugunku (birlesik)
// davranisa geri duser — dogruluk kaybi yok, keskinlik kaybi var.
constexpr std::size_t kMaxDisjuncts = 4;

template <typename VarMap, typename MergeVal>
void mergeVarMaps(VarMap& into, const VarMap& from, MergeVal mergeVal) {
    for (const auto& [var, s] : from) {
        auto it = into.find(var);
        if (it == into.end())
            into.emplace(var, s);
        else
            it->second = mergeVal(it->second, s);
    }
}

// Kanonik form: sirali; ayni-facts disjunktlar birlesik; tavan asiminda
// genisletilmis. Motorun != karsilastirmasi icin sira kararliligi sart.
template <typename VarMap, typename MergeVal>
void normalizeGuarded(GuardedState<VarMap>& state, MergeVal mergeVal) {
    std::sort(state.begin(), state.end());
    GuardedState<VarMap> merged;
    for (auto& d : state) {
        if (!merged.empty() && merged.back().facts == d.facts)
            mergeVarMaps(merged.back().vars, d.vars, mergeVal);
        else
            merged.push_back(std::move(d));
    }
    state = std::move(merged);

    if (state.size() > kMaxDisjuncts) {
        Guarded<VarMap> widened = std::move(state.front());
        for (std::size_t i = 1; i < state.size(); ++i) {
            for (auto it = widened.facts.begin();
                 it != widened.facts.end();) {
                auto found = state[i].facts.find(it->first);
                if (found == state[i].facts.end() ||
                    found->second != it->second)
                    it = widened.facts.erase(it);
                else
                    ++it;
            }
            mergeVarMaps(widened.vars, state[i].vars, mergeVal);
        }
        state.clear();
        state.push_back(std::move(widened));
    }
}

template <typename VarMap, typename MergeVal>
GuardedState<VarMap> mergeGuarded(const GuardedState<VarMap>& a,
                                  const GuardedState<VarMap>& b,
                                  MergeVal mergeVal) {
    GuardedState<VarMap> result = a;
    result.insert(result.end(), b.begin(), b.end());
    normalizeGuarded(result, mergeVal);
    return result;
}

// Raporlama gorunumu: tum disjunktlarin pointwise birlesimi — tek-state
// analizin birebir karsiligi. Raporlama mantiklari degismeden calisir;
// yol duyarliliginin kazanci, dusurulen disjunktlarin bu birlesime hic
// girmemesidir.
template <typename VarMap, typename MergeVal>
VarMap flattenGuarded(const GuardedState<VarMap>& state, MergeVal mergeVal) {
    VarMap out;
    for (const auto& d : state) mergeVarMaps(out, d.vars, mergeVal);
    return out;
}

// Kosul anahtarlanabiliyorsa: celisen disjunktlar bu kenarda olanaksizdir
// (dusurulur), kalanlara gercek islenir. Anahtarlanamayan kosul no-op.
// Tum disjunktlar duserse state bosalir = kenar olanaksiz (dogru semantik:
// o kenardan hicbir rapor dogmaz).
template <typename VarMap, typename MergeVal>
void refineGuardedFacts(GuardedState<VarMap>& state,
                        const clang::Expr* cond, bool isTrueBranch,
                        const std::set<const clang::ValueDecl*>& mutated,
                        MergeVal mergeVal) {
    auto fact = conditionFact(cond, mutated);
    if (!fact) return;

    const bool value = isTrueBranch ? fact->second : !fact->second;
    GuardedState<VarMap> kept;
    for (auto& d : state) {
        auto it = d.facts.find(fact->first);
        if (it != d.facts.end() && it->second != value) continue;
        d.facts[fact->first] = value;
        kept.push_back(std::move(d));
    }
    state = std::move(kept);
    normalizeGuarded(state, mergeVal);
}

} // namespace zerodefect

#endif // ZERODEFECT_GUARDED_DISJUNCTS_H
