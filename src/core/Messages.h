#ifndef ZERODEFECT_MESSAGES_H
#define ZERODEFECT_MESSAGES_H

#include <string>

namespace zerodefect {

enum class Lang { EN, TR };

void setLang(Lang lang);
Lang currentLang();
Lang parseLang(const std::string& value);

enum class MsgId {
    // Diagnostic messages
    UninitPtrDeref,       // {0} = variable name
    LeakReassign,         // {0} = variable name
    LeakEndOfFunction,    // {0} = variable name
    DoubleFree,           // {0} = variable name
    UseAfterFree,         // {0} = variable name
    DivByZeroLiteral,
    DivByZeroDefinite,    // {0} = variable name
    DivByZeroMaybe,       // {0} = variable name
    NullDerefDefinite,    // {0} = variable name
    NullDerefMaybe,       // {0} = variable name

    // Dataflow trace steps
    TraceAllocatedHere,   // {0} = variable name
    TraceFreedHere,       // {0} = variable name
    TraceAssignedNullHere,// {0} = variable name
    TraceAssignedMaybeNullHere, // {0} = variable name (summary: may return null)
    TraceAssignedZeroHere,// {0} = variable name
    TraceDeclaredHere,    // {0} = variable name

    // CLI / runtime
    AnalysisStarting,     // {0} = file count, {1} = rule count
    NoFilesToAnalyze,
    NoRulesRegistered,
    CleanNoIssues,
    FindingsCount,        // {0} = finding count
    SuppressedCount,      // {0} = suppressed finding count
    BaselineWritten,      // {0} = finding count, {1} = file path
    BaselineFiltered,     // {0} = count of findings matching the baseline
    CompileDbNotFound,    // {0} = error message
    OutputFileOpenError,  // {0} = path
    FileNotFound,         // {0} = path
    DirNotFound,          // {0} = path
    DirScanError,         // {0} = error message
    UsageError,
    WholeProgramPass,     // {0} = file count
    AnalysisNotConverged, // {0} = function name
    SummariesLoaded,      // {0} = summary count, {1} = file path
    SummariesSaved,       // {0} = summary count, {1} = file path
    SummaryLoadError,     // {0} = file path
    SummarySaveError,     // {0} = file path
    TraceAssignedMaybeZeroHere, // {0} = variable name (summary: may return 0)
    TraceAssumedNullHere,       // {0} = variable name (guard: null on this branch)
    TraceAssumedZeroHere,       // {0} = variable name (guard: zero on this branch)
    SummaryStaleWarning,        // {0} = summary file, {1} = newer source
};

// Replaces the {0} and {1} placeholders with the arguments.
std::string msg(MsgId id, const std::string& a0 = "",
                const std::string& a1 = "");

} // namespace zerodefect

#endif // ZERODEFECT_MESSAGES_H
