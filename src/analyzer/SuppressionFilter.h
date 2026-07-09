#ifndef ZERODEFECT_SUPPRESSION_FILTER_H
#define ZERODEFECT_SUPPRESSION_FILTER_H

#include "core/Diagnostic.h"

#include <map>
#include <string>
#include <vector>

namespace zerodefect {

// Kaynak koddaki bastirma yorumlarini uygular:
//   // zerodefect-disable-line              -> o satirdaki tum bulgular
//   // zerodefect-disable-line rule1,rule2  -> o satirda yalnizca bu kurallar
//   // zerodefect-disable-next-line [...]   -> bir sonraki satir icin ayni
// Kural listesi bosluk veya virgulle ayrilabilir.
class SuppressionFilter {
public:
    // Bastirilan bulgulari listeden cikarir, cikarilan sayiyi dondurur.
    size_t filter(DiagnosticList& diagnostics);

    // Tek bir bulgunun bastirilip bastirilmadigini soyler (test edilebilir).
    bool isSuppressed(const Diagnostic& diag);

private:
    const std::vector<std::string>* linesFor(const std::string& path);

    std::map<std::string, std::vector<std::string>> file_cache_;
};

// Yorum metni verilen kurali bastiriyor mu? (markerdan sonra kural listesi
// yoksa tum kurallar bastirilir) — birim test icin disari acik.
bool markerSuppressesRule(const std::string& line_text,
                          const std::string& marker,
                          const std::string& rule_id);

} // namespace zerodefect

#endif // ZERODEFECT_SUPPRESSION_FILTER_H
