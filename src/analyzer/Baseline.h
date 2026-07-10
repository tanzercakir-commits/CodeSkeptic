#ifndef ZERODEFECT_BASELINE_H
#define ZERODEFECT_BASELINE_H

#include "core/Diagnostic.h"

#include <map>
#include <string>

namespace zerodefect {

// Baseline: mevcut bulgulari dosyaya dondurur, sonraki kosularda
// yalnizca YENI bulgular raporlanir. Eski koda kademeli adaptasyonun
// standart yolu.
//
// v2 anahtari SATIR-BAGIMSIZ: satir numarasi yerine bulgu satirinin
// kirpilmis METIN iceriginin hash'i (FNV-1a 64 — platformlar arasi
// sabit; std::hash garanti vermez). Ustune kod eklenip bulgu kaydiginca
// anahtar degismez; satirin KENDISI degisirse bulgu yeniden gorunur —
// bu bir ozellik (degisen satir yeniden gozden gecirilmeli).
//
// Ayni anahtarli birden fazla bulgu SAYIYLA izlenir (multiset
// semantigi): iki ayri fonksiyondaki ozdes `delete p;` satirlarinin
// birini baseline'a almak digerini gizlemez.
//
// Format: "# zerodefect-baseline v2" basligi + satir basina bir anahtar
// (rule_id|file|satir-hash|message; tekrarlar korunur). Basliksiz eski
// v1 dosyalari (rule_id|file|line|message) yuklemede taninir ve eski
// anlamiyla eslesmeye devam eder — baseline tazelenince v2'ye gecilir.
class Baseline {
public:
    // Bulgulari baseline dosyasina yazar (v2 format). Basari durumu.
    static bool write(const std::string& path,
                      const DiagnosticList& diagnostics);

    // Baseline dosyasini yukler. Dosya yoksa bos baseline (hata degil).
    bool load(const std::string& path);

    // Baseline'da kayitli bulgulari listeden cikarir, cikarilan sayiyi
    // dondurur. Anahtar basina kayit SAYISI kadar bulgu bastirilir.
    size_t filter(DiagnosticList& diagnostics) const;

    // v1: satir numarali eski anahtar (yalniz eski dosya uyumu icin)
    static std::string keyV1(const Diagnostic& diag);
    // v2: satir-icerigi hash'li anahtar (diag.file diskten okunur)
    static std::string keyV2(const Diagnostic& diag);

private:
    std::map<std::string, int> counts_;
};

} // namespace zerodefect

#endif // ZERODEFECT_BASELINE_H
