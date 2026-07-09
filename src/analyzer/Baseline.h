#ifndef ZERODEFECT_BASELINE_H
#define ZERODEFECT_BASELINE_H

#include "core/Diagnostic.h"

#include <set>
#include <string>

namespace zerodefect {

// Baseline: mevcut bulgulari dosyaya dondurur, sonraki kosularda
// yalnizca YENI bulgular raporlanir. Eski koda kademeli adaptasyonun
// standart yolu.
//
// Format: satir basina bir anahtar — rule_id|file|line|message
// Not: satir numarasi anahtara dahil oldugu icin kod kaydiginda baseline
// tazelenmeli (bilinen v1 sinirlamasi, dokumante).
class Baseline {
public:
    // Bulgulari baseline dosyasina yazar. Basari durumunu dondurur.
    static bool write(const std::string& path,
                      const DiagnosticList& diagnostics);

    // Baseline dosyasini yukler. Dosya yoksa bos baseline (hata degil).
    bool load(const std::string& path);

    // Baseline'da kayitli bulgulari listeden cikarir, cikarilan sayiyi
    // dondurur.
    size_t filter(DiagnosticList& diagnostics) const;

    static std::string key(const Diagnostic& diag);

private:
    std::set<std::string> keys_;
};

} // namespace zerodefect

#endif // ZERODEFECT_BASELINE_H
