#ifndef ZERODEFECT_PATH_FACTS_H
#define ZERODEFECT_PATH_FACTS_H

// Hedefli yol duyarliligi icin kosul-gercekleri (path facts).
//
// Motivasyon (Juliet FP avi, 2026-07-10): analizler ayni degismez
// kosulun iki kez test edildigi kaliplarda korelasyon kuramiyordu:
//
//   if (globalFive == 5) data = malloc(...);   // kaynak
//   if (globalFive == 5) free(data);           // lavabo — AYNI kosul
//
// Ilk if'in join'inde {Allocated, None} karisir; ikinci if'te "alloc
// olup free olmayan yol" hayaleti dogar. Cozum: kosullar kanonik bir
// anahtara indirgenir (FactKey) ve analiz state'i az sayida "guard'li
// disjunkt" halinde tutulur; ayni anahtar ikinci kez gorulunce celisen
// disjunkt dusurulur.
//
// BILINCLI SINIRLAR (precision-first):
//  - Yalnizca DeclRef degisken vs tamsayi-sabit karsilastirmalari
//    anahtarlanir (fonksiyon cagrilari ASLA — rand() korelasyonu yanlis
//    olur).
//  - Fonksiyon icinde atanan / adresi alinan degiskenler anahtarlanmaz.
//  - Cagrilarin globalleri degistirebilecegi ihmal edilir: iki korelasyonlu
//    guard arasindaki bir cagri globali degistirirse gercek bir kusur
//    gizlenebilir (FN yonu). FP'siz kalmak icin kabul edilen taviz —
//    testte dokumante edilir.

#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/OperationKinds.h>

#include <cstdint>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

namespace zerodefect {

// Kanonik kosul anahtari: "var REL literal". REL yalnizca EQ/LT/LE —
// NE/GT/GE deger tersleme ile bunlara indirgenir (X!=5 ≡ !(X==5)).
struct FactKey {
    const clang::ValueDecl* var = nullptr;
    clang::BinaryOperatorKind rel = clang::BO_EQ;  // BO_EQ | BO_LT | BO_LE
    int64_t literal = 0;

    bool operator==(const FactKey& o) const {
        return var == o.var && rel == o.rel && literal == o.literal;
    }
    bool operator<(const FactKey& o) const {
        return std::tie(var, rel, literal) <
               std::tie(o.var, o.rel, o.literal);
    }
};

// Kosulu (anahtar, deger) ciftine indirger: dondurulen bool, KOSUL DOGRU
// oldugunda anahtarin degeridir. Ornek: `X != 5` icin {(X,EQ,5), false}.
// Kenar yanlissa cagiran degeri tersler. Anahtarlanamayan kosul -> nullopt.
// `mutated`: fonksiyon icinde atanan/adresi alinan decl'ler (anahtar disi).
std::optional<std::pair<FactKey, bool>> conditionFact(
    const clang::Expr* cond,
    const std::set<const clang::ValueDecl*>& mutated);

// Govdede atanan, ++/-- uygulanan veya adresi alinan decl'leri toplar.
// Bu decl'lere dayali kosullar iki test arasinda degisebilir — anahtarlanmaz.
std::set<const clang::ValueDecl*> collectMutatedDecls(
    const clang::FunctionDecl* func);

} // namespace zerodefect

#endif // ZERODEFECT_PATH_FACTS_H
