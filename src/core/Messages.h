#ifndef ZERODEFECT_MESSAGES_H
#define ZERODEFECT_MESSAGES_H

#include <string>

namespace zerodefect {

enum class Lang { EN, TR };

void setLang(Lang lang);
Lang currentLang();
Lang parseLang(const std::string& value);

enum class MsgId {
    // Tani mesajlari
    UninitPtrDeref,       // {0} = degisken adi
    LeakReassign,         // {0} = degisken adi
    LeakEndOfFunction,    // {0} = degisken adi
    DoubleFree,           // {0} = degisken adi
    UseAfterFree,         // {0} = degisken adi
    DivByZeroLiteral,
    DivByZeroDefinite,    // {0} = degisken adi
    DivByZeroMaybe,       // {0} = degisken adi
    NullDerefDefinite,    // {0} = degisken adi
    NullDerefMaybe,       // {0} = degisken adi

    // Dataflow izi adimlari
    TraceAllocatedHere,   // {0} = degisken adi
    TraceFreedHere,       // {0} = degisken adi
    TraceAssignedNullHere,// {0} = degisken adi
    TraceAssignedMaybeNullHere, // {0} = degisken adi (ozet: null donebilir)
    TraceAssignedZeroHere,// {0} = degisken adi
    TraceDeclaredHere,    // {0} = degisken adi

    // CLI / calisma zamani
    AnalysisStarting,     // {0} = dosya sayisi, {1} = kural sayisi
    NoFilesToAnalyze,
    NoRulesRegistered,
    CleanNoIssues,
    FindingsCount,        // {0} = bulgu sayisi
    SuppressedCount,      // {0} = bastirilan bulgu sayisi
    BaselineWritten,      // {0} = bulgu sayisi, {1} = dosya yolu
    BaselineFiltered,     // {0} = baseline ile eslesen bulgu sayisi
    CompileDbNotFound,    // {0} = hata mesaji
    OutputFileOpenError,  // {0} = yol
    FileNotFound,         // {0} = yol
    DirNotFound,          // {0} = yol
    DirScanError,         // {0} = hata mesaji
    UsageError,
    WholeProgramPass,     // {0} = dosya sayisi
    AnalysisNotConverged, // {0} = fonksiyon adi
    SummariesLoaded,      // {0} = ozet sayisi, {1} = dosya yolu
    SummariesSaved,       // {0} = ozet sayisi, {1} = dosya yolu
    SummaryLoadError,     // {0} = dosya yolu
    SummarySaveError,     // {0} = dosya yolu
    TraceAssignedMaybeZeroHere, // {0} = degisken adi (ozet: 0 donebilir)
    TraceAssumedNullHere,       // {0} = degisken adi (guard: bu dalda null)
    TraceAssumedZeroHere,       // {0} = degisken adi (guard: bu dalda sifir)
    SummaryStaleWarning,        // {0} = ozet dosyasi, {1} = yeni kaynak
};

// {0} ve {1} yer tutucularini argumanlarla degistirir.
std::string msg(MsgId id, const std::string& a0 = "",
                const std::string& a1 = "");

} // namespace zerodefect

#endif // ZERODEFECT_MESSAGES_H
