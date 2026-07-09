#include "core/Messages.h"

namespace zerodefect {

namespace {

Lang g_lang = Lang::EN;

struct MsgEntry {
    const char* en;
    const char* tr;
};

// MsgId enum sirasiyla birebir ayni sirada olmali.
const MsgEntry kMessages[] = {
    // UninitPtrDeref
    {"Use of uninitialized pointer: '{0}' may not be assigned at this dereference",
     "Baslatilmamis pointer kullanimi: {0} dereference noktasinda deger atanmamis olabilir"},
    // LeakReassign
    {"Memory leak: '{0}' is reassigned without freeing the previous allocation",
     "Bellek sizintisi: {0} yeniden atanmadan once eski bellek serbest birakilmamis"},
    // LeakEndOfFunction
    {"Memory leak: allocation stored in '{0}' may not be freed",
     "Bellek sizintisi: {0} icin ayrilan bellek serbest birakilmamis olabilir"},
    // DoubleFree
    {"Double free: '{0}' has already been freed",
     "Cift serbest birakma: {0} zaten serbest birakilmis"},
    // UseAfterFree
    {"Use after free: '{0}' is dereferenced after being freed",
     "Serbest birakildiktan sonra kullanim: {0} free edildikten sonra dereference ediliyor"},
    // DivByZeroLiteral
    {"Division by zero: division by a constant zero",
     "Sifira bolme: sabit sifir ile bolme islemi"},
    // DivByZeroDefinite
    {"Division by zero: '{0}' is definitely zero",
     "Sifira bolme: {0} kesinlikle sifir"},
    // DivByZeroMaybe
    {"Possible division by zero: '{0}' may be zero on some paths",
     "Sifira bolme riski: {0} bazi kod yollarinda sifir olabilir"},
    // AnalysisStarting
    {"[ZeroDefect] Analysis starting... ({0} files, {1} rules)",
     "[ZeroDefect] Analiz basliyor... ({0} dosya, {1} kural)"},
    // NoFilesToAnalyze
    {"[ZeroDefect] No files to analyze.",
     "[ZeroDefect] Analiz edilecek dosya yok."},
    // NoRulesRegistered
    {"[ZeroDefect] No rules registered.",
     "[ZeroDefect] Kayitli kural yok."},
    // CleanNoIssues
    {"ZeroDefect: Clean! No issues found.",
     "ZeroDefect: Temiz! Sorun bulunamadi."},
    // FindingsCount
    {"ZeroDefect: {0} finding(s)",
     "ZeroDefect: {0} bulgu"},
    // SuppressedCount
    {"[ZeroDefect] {0} finding(s) suppressed by source comments",
     "[ZeroDefect] {0} bulgu kaynak yorumlariyla bastirildi"},
    // BaselineWritten
    {"[ZeroDefect] {0} finding(s) recorded to baseline: {1}",
     "[ZeroDefect] {0} bulgu baseline dosyasina kaydedildi: {1}"},
    // BaselineFiltered
    {"[ZeroDefect] {0} known finding(s) filtered by baseline",
     "[ZeroDefect] {0} bilinen bulgu baseline ile filtrelendi"},
    // CompileDbNotFound
    {"[ZeroDefect] compile_commands.json not found: {0}\n"
     "[ZeroDefect] Fallback: continuing with -std=c++17.",
     "[ZeroDefect] compile_commands.json bulunamadi: {0}\n"
     "[ZeroDefect] Fallback: -std=c++17 ile devam ediliyor."},
    // OutputFileOpenError
    {"[ZeroDefect] Cannot open output file: {0}",
     "[ZeroDefect] Cikti dosyasi acilamadi: {0}"},
    // FileNotFound
    {"[ZeroDefect] File not found: {0}",
     "[ZeroDefect] Dosya bulunamadi: {0}"},
    // DirNotFound
    {"[ZeroDefect] Directory not found: {0}",
     "[ZeroDefect] Dizin bulunamadi: {0}"},
    // DirScanError
    {"[ZeroDefect] Directory scan error: {0}",
     "[ZeroDefect] Dizin tarama hatasi: {0}"},
    // UsageError
    {"Error: no source path given.\n"
     "Usage: zerodefect <source_path> [options]\n"
     "See: zerodefect --help",
     "Hata: Kaynak dizin belirtilmedi.\n"
     "Kullanim: zerodefect <kaynak_yolu> [secenekler]\n"
     "Detay icin: zerodefect --help"},
};

void substitute(std::string& text, const std::string& placeholder,
                const std::string& value) {
    for (auto pos = text.find(placeholder); pos != std::string::npos;
         pos = text.find(placeholder, pos + value.size())) {
        text.replace(pos, placeholder.size(), value);
    }
}

} // anonymous namespace

void setLang(Lang lang) { g_lang = lang; }

Lang currentLang() { return g_lang; }

Lang parseLang(const std::string& value) {
    return value == "tr" ? Lang::TR : Lang::EN;
}

std::string msg(MsgId id, const std::string& a0, const std::string& a1) {
    const MsgEntry& entry = kMessages[static_cast<int>(id)];
    std::string text = (g_lang == Lang::TR) ? entry.tr : entry.en;
    substitute(text, "{0}", a0);
    substitute(text, "{1}", a1);
    return text;
}

} // namespace zerodefect
