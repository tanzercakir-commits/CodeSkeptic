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
    DivByZeroLiteral,
    DivByZeroDefinite,    // {0} = degisken adi
    DivByZeroMaybe,       // {0} = degisken adi

    // CLI / calisma zamani
    AnalysisStarting,     // {0} = dosya sayisi, {1} = kural sayisi
    NoFilesToAnalyze,
    NoRulesRegistered,
    CleanNoIssues,
    FindingsCount,        // {0} = bulgu sayisi
    CompileDbNotFound,    // {0} = hata mesaji
    FileNotFound,         // {0} = yol
    DirNotFound,          // {0} = yol
    DirScanError,         // {0} = hata mesaji
    UsageError,
};

// {0} ve {1} yer tutucularini argumanlarla degistirir.
std::string msg(MsgId id, const std::string& a0 = "",
                const std::string& a1 = "");

} // namespace zerodefect

#endif // ZERODEFECT_MESSAGES_H
