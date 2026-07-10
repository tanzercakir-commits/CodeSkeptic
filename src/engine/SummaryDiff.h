#ifndef ZERODEFECT_SUMMARY_DIFF_H
#define ZERODEFECT_SUMMARY_DIFF_H

#include "engine/FunctionSummary.h"

#include <iosfwd>
#include <map>
#include <string>
#include <vector>

namespace zerodefect {

// Ozet-diff (semantik regresyon sinyalinin cekirdegi): iki hasat
// arasinda fonksiyon SOZLESMELERI nasil degisti?
//
//  WEAKENED     guclu bir iddia kayboldu ya da degisti (NeverNull /
//               NeverZero dustu; ReadsOnly/Frees param iddiasi baskasina
//               dondu). Bu iddiaya yaslanan CAGIRANLAR yeniden
//               incelenmeli — CI kapisi: cikis kodu 1.
//  STRENGTHENED yeni guclu iddia kazanildi (bilgi; risk yok).
//  CHANGED      yon icermeyen degisim (Unknown <-> Maybe* gibi) —
//               bulgu kumesi oynayabilir ama sozlesme riski yok.
//  ADDED /      anahtar (nitelikli ad + arite) yeni dosyada girdi /
//  REMOVED      cikti. Imza degisikligi ayni fonksiyonu REMOVED+ADDED
//               olarak gosterir (anahtar ariteyi icerir — bilerek:
//               arite degisimi zaten tum cagiranlari kirar).
enum class ChangeKind { Added, Removed, Weakened, Strengthened, Changed };

struct SummaryChange {
    ChangeKind kind;
    std::string key;
    std::string detail;  // alan farklari, insan-okur ("rn: N -> M" gibi)
};

struct SummaryDiffResult {
    // Siralama: once Weakened (en onemli), sonra digerleri anahtar sirali
    std::vector<SummaryChange> changes;
    size_t weakened = 0;
    size_t strengthened = 0;
    size_t changed = 0;
    size_t added = 0;
    size_t removed = 0;
};

using SummaryMap =
    std::map<std::string, SummaryRegistry::FunctionSummary>;

SummaryDiffResult diffSummaries(const SummaryMap& oldMap,
                                const SummaryMap& newMap);

// Iki dosyayi ayristirir, diff'i `out`a yazar (makine-greplenebilir
// "SUMMARY_DIFF <KIND> <key> <detail>" satirlari + ozet). Cikis kodu:
// 0 = zayiflama yok, 1 = WEAKENED var (CI kapisi), 2 = dosya okunamadi.
int reportSummaryDiff(const std::string& oldPath,
                      const std::string& newPath, std::ostream& out);

} // namespace zerodefect

#endif // ZERODEFECT_SUMMARY_DIFF_H
