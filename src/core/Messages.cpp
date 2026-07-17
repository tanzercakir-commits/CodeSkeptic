#include "core/Messages.h"

namespace zerodefect {

namespace {

Lang g_lang = Lang::EN;

struct MsgEntry {
    const char* en;
    const char* tr;
};

// Must be in exactly the same order as the MsgId enum.
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
    // NullDerefDefinite
    {"Null pointer dereference: '{0}' is definitely null",
     "Null pointer dereference: {0} kesinlikle null"},
    // NullDerefMaybe
    {"Possible null dereference: '{0}' may be null on some paths",
     "Olasi null dereference: {0} bazi kod yollarinda null olabilir"},
    // TraceAllocatedHere
    {"'{0}' allocated here",
     "{0} burada ayrildi"},
    // TraceFreedHere
    {"'{0}' freed here",
     "{0} burada serbest birakildi"},
    // TraceAssignedNullHere
    {"'{0}' assigned null here",
     "{0} burada null atandi"},
    // TraceAssignedMaybeNullHere
    {"'{0}' assigned a possibly-null value here (callee may return null)",
     "{0} burada null olabilecek bir deger atandi (cagrilan null donebilir)"},
    // TraceAssignedZeroHere
    {"'{0}' assigned zero here",
     "{0} burada sifir atandi"},
    // TraceDeclaredHere
    {"'{0}' declared without an initializer here",
     "{0} burada baslangic degeri olmadan bildirildi"},
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
    // ReportPathsFiltered
    {"[ZeroDefect] {0} finding(s) outside --report-paths filtered",
     "[ZeroDefect] {0} bulgu --report-paths disinda kaldigi icin filtrelendi"},
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
    // WholeProgramPass
    {"[ZeroDefect] Whole-program pass: collecting summaries from {0} file(s)...",
     "[ZeroDefect] Tum-program gecisi: {0} dosyadan ozetler toplaniyor..."},
    // AnalysisNotConverged
    {"[ZeroDefect] warning: dataflow did not converge in '{0}' "
     "(iteration cap hit); findings in this function may be incomplete",
     "[ZeroDefect] uyari: '{0}' icinde dataflow yakinsamadi (iterasyon "
     "tavani); bu fonksiyondaki bulgular eksik olabilir"},
    // SummariesLoaded
    {"[ZeroDefect] {0} function summaries loaded from {1}",
     "[ZeroDefect] {0} fonksiyon ozeti yuklendi: {1}"},
    // SummariesSaved
    {"[ZeroDefect] {0} function summaries saved to {1}",
     "[ZeroDefect] {0} fonksiyon ozeti kaydedildi: {1}"},
    // SummaryLoadError
    {"[ZeroDefect] warning: could not load summaries from {0} "
     "(missing or malformed file); continuing without them",
     "[ZeroDefect] uyari: ozetler yuklenemedi: {0} (dosya yok ya da "
     "bozuk); ozetsiz devam ediliyor"},
    // SummarySaveError
    {"[ZeroDefect] warning: could not save summaries to {0}",
     "[ZeroDefect] uyari: ozetler kaydedilemedi: {0}"},
    // TraceAssignedMaybeZeroHere
    {"'{0}' assigned a possibly-zero value here (callee may return zero)",
     "{0} burada sifir olabilecek bir deger atandi (cagrilan sifir donebilir)"},
    // TraceAssumedNullHere
    {"'{0}' is null on this branch (per this condition)",
     "{0} bu dalda null (buradaki kosula gore)"},
    // TraceAssumedZeroHere
    {"'{0}' is zero on this branch (per this condition)",
     "{0} bu dalda sifir (buradaki kosula gore)"},
    // SummaryStaleWarning
    {"[ZeroDefect] warning: summary file {0} is older than {1} — "
     "summaries may be stale; re-run --summary-out to refresh",
     "[ZeroDefect] uyari: ozet dosyasi {0}, {1} dosyasindan eski — "
     "ozetler bayat olabilir; --summary-out ile tazeleyin"},
    // TraceAlsoDerefHere
    {"'{0}' is also dereferenced here (same origin)",
     "{0} burada da dereference ediliyor (ayni kaynak)"},
    // ContractViolated
    {"contract violated: '{0}'",
     "sozlesme ihlal edildi: '{0}'"},
    // ContractGuardCrash
    {"null argument for '{0}' violates {1}'s own entry assert (line {2}); "
     "in builds where the assert is compiled out this call crashes",
     "'{0}' icin null arguman, {1} fonksiyonunun kendi giris assert'ini "
     "ihlal ediyor (satir {2}); assert'in derlenmedigi build'lerde bu "
     "cagri coker"},
    // ContractGuardRejected
    {"null argument for '{0}': {1}'s own entry guard (line {2}) will "
     "always refuse this call - it can never do its work",
     "'{0}' icin null arguman: {1} fonksiyonunun kendi giris guard'i "
     "(satir {2}) bu cagriyi her zaman reddedecek - cagri isini asla "
     "yapamaz"},
    // ContractSyntaxError
    {"invalid contract syntax: '{0}'",
     "gecersiz sozlesme sozdizimi: '{0}'"},
    // ContractUnsupported
    {"contract is outside the v1 checkable subset (not checked): '{0}'",
     "sozlesme v1 dogrulanabilir alt kumesinin disinda (kontrol edilmedi): '{0}'"},
    // ContractUnverified
    {"contract could not be verified yet (engine limit): '{0}'",
     "sozlesme henuz dogrulanamadi (motor siniri): '{0}'"},
    // PolicyAbsolutePath
    {"policy 'no-absolute-paths': hard-coded absolute path {0}",
     "'no-absolute-paths' politikasi: sabit kodlanmis mutlak yol {0}"},
    // PolicyUnknownName
    {"unknown policy name: '{0}'",
     "bilinmeyen politika adi: '{0}'"},
    // IntOverflowMul
    {"possible integer overflow: this multiplication can exceed '{0}'",
     "olasi tamsayi tasmasi: bu carpma '{0}' sinirini asabilir"},
    // BoundsArrayDefinite
    {"out-of-bounds array access: proven index range {0} lies outside the "
     "array bound [0, {1})",
     "dizi sinirlari disinda erisim: ispatlanan indeks araligi {0}, dizi "
     "siniri [0, {1}) disinda"},
    // CoverageIncomplete
    {"[ZeroDefect] analysis coverage: {0} function(s) hit the iteration cap "
     "and were not fully analyzed; their findings may be incomplete:",
     "[ZeroDefect] analiz kapsami: {0} fonksiyon iterasyon tavanina takildi "
     "ve tam analiz edilemedi; bu fonksiyonlardaki bulgular eksik olabilir:"},
    // BrokenTuSkipped
    {"[ZeroDefect] {0} translation unit(s) failed to COMPILE and were "
     "skipped - findings from an error-recovery AST are unreliable. Fix "
     "the include paths/flags, or pass --analyze-broken-tus to analyze "
     "anyway:",
     "[ZeroDefect] {0} ceviri birimi DERLENEMEDI ve atlandi - hata "
     "kurtarmali AST'den gelen bulgular guvenilmezdir. Include yollarini/"
     "bayraklari duzeltin ya da yine de analiz icin --analyze-broken-tus "
     "verin:"},
    // AssumptionNonNullParam
    {"inferred assumption: parameter '{0}' is assumed non-null "
     "(dereferenced, never checked); this precondition is undeclared "
     "(consider a contract: requires {0} != null)",
     "cikarilan varsayim: '{0}' parametresi null-degil kabul ediliyor "
     "(dereference ediliyor, hic kontrol edilmiyor); bu onkosul "
     "bildirilmemis (sozlesme onerisi: requires {0} != null)"},
    // BoundsCopyOverflow
    {"buffer overflow: copy size {0} exceeds the destination's capacity of "
     "{1} byte(s)",
     "tampon tasmasi: {0} baytlik kopya, hedefin {1} baytlik kapasitesini "
     "asiyor"},
    // BoundsUnboundedStrCopy
    {"possible buffer overflow: {0} copies an unbounded amount into a "
     "fixed {1}-byte buffer; the source length is not checked (use a "
     "bounded copy or verify it fits)",
     "olasi tampon tasmasi: {0} sabit {1} baytlik tampona sinirsiz miktar "
     "kopyaliyor; kaynak uzunlugu kontrol edilmiyor (sinirli kopya kullanin "
     "veya sigdigini dogrulayin)"},
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

std::string msg(MsgId id, const std::string& a0, const std::string& a1,
                const std::string& a2) {
    const MsgEntry& entry = kMessages[static_cast<int>(id)];
    std::string text = (g_lang == Lang::TR) ? entry.tr : entry.en;
    substitute(text, "{0}", a0);
    substitute(text, "{1}", a1);
    substitute(text, "{2}", a2);
    return text;
}

} // namespace zerodefect
