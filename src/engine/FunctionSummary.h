#ifndef ZERODEFECT_FUNCTION_SUMMARY_H
#define ZERODEFECT_FUNCTION_SUMMARY_H

#include <map>
#include <string>
#include <vector>

namespace clang {
class ASTContext;
class FunctionDecl;
}

namespace zerodefect {

// Interprosedurel analiz v1: TU-yerel fonksiyon ozetleri.
//
// Iki bilgi cikarilir:
//  1. Donus nullness'i — fonksiyon pointer donduruyorsa, donus degeri
//     hicbir yolda null olamaz mi (NeverNull), bazi yollarda null
//     olabilir mi (MaybeNull), yoksa bilinmiyor mu (Unknown)?
//  2. Parametre etkileri — govde parametreyi free mi ediyor (Frees),
//     yalnizca okuyor mu (ReadsOnly), saklıyor/kaciriyor mu (Stores)?
//     Govdesi gorunmeyen fonksiyonlar Opaque'tir.
//
// Kapsam ve guvenlik sinirlari (v1):
//  - Yalnizca ayni TU'da GOVDESI gorunen fonksiyonlar ozetlenir;
//    disaridakiler Opaque kalir (cagiran taraf muhafazakar davranir).
//  - Alias'lara kor: parametrenin BASKA BIR SEYE atanmasi (yerel dahil)
//    Stores sayilir — cJSON_Delete'in `q = p; free(q)` kalibi bilerek
//    Escaped'de birakilir (v2: alias izleme).
//  - Donus nullness'i literal/new/&x/string ve cagri zinciriyle sinirli;
//    degisken donduren yollar Unknown'a duser.
//
// Yakinsam: ozetler sabit sayida tarama ile (<= kMaxSweeps) sifirdan
// yeniden hesaplanir; degisiklik kalmayinca durulur. Rekursif fonksiyon
// kendi onceki ozetini gorur — Unknown/Opaque baslangic, NeverNull ve
// ReadsOnly/Frees gibi guclu iddialarin rekursiyonla sizmasini onler
// (yanlis yonde iyimserlik yok).
class SummaryRegistry {
public:
    enum class ReturnNullness { Unknown, NeverNull, MaybeNull };
    enum class ParamEffect { Opaque, ReadsOnly, Frees, Stores };

    struct FunctionSummary {
        ReturnNullness returnNullness = ReturnNullness::Unknown;
        std::vector<ParamEffect> params;

        ParamEffect paramEffect(unsigned index) const {
            if (index >= params.size()) return ParamEffect::Opaque;
            return params[index];
        }
    };

    static SummaryRegistry& instance();

    // TU basina bir kez: tum govdeli fonksiyonlarin ozetlerini hesaplar.
    // FunctionDecl* anahtarlari TU'ya ozgudur — her cagri onceki tabloyu
    // TAMAMEN temizler (sarkan pointer olmasin).
    void rebuild(clang::ASTContext& ctx);

    // Ozet yoksa nullptr doner. Once TU-yerel tablo, sonra cross-TU
    // deposu (yalnizca harici baglantili fonksiyonlar) denenir.
    const FunctionSummary* lookup(const clang::FunctionDecl* func) const;

    // --- Cross-TU katmani (Ufuk 2: whole-program modu) ---
    //
    // Anahtar: nitelikli ad + "/" + parametre sayisi. Yalnizca HARICI
    // baglantili fonksiyonlar depolanir/aranir — static (dosya-yerel)
    // fonksiyonlar TU disindan cagrilamaz ve Juliet gibi korpuslarda
    // ayni adla her dosyada bulunur; onlari anahtarlamak yanlis
    // eslesme uretirdi. C++ overload'lari ayni anahtara dusebilir:
    // cakismada alanlar muhafazakar birlesir (returnNullness -> Unknown,
    // param -> Opaque) — belirsizlik her zaman kaybeder, yanlis guclu
    // iddia dogamaz.

    // TU-yerel tablodaki harici-baglantili ozetleri depoya katar
    // (whole-program 1. gecisinde TU basina bir kez cagrilir).
    void harvestGlobal();

    // Depodan arama; yalnizca harici-baglantili decl'ler icin.
    const FunctionSummary* lookupGlobal(
        const clang::FunctionDecl* func) const;

    void clear();
    void clearGlobal();
    size_t size() const { return summaries_.size(); }
    size_t globalSize() const { return globalStore_.size(); }

private:
    std::map<const clang::FunctionDecl*, FunctionSummary> summaries_;
    std::map<std::string, FunctionSummary> globalStore_;
};

} // namespace zerodefect

#endif // ZERODEFECT_FUNCTION_SUMMARY_H
