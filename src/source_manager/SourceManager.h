#ifndef CODESKEPTIC_SOURCE_MANAGER_H
#define CODESKEPTIC_SOURCE_MANAGER_H

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clang {
class ASTContext;
namespace tooling {
class CompilationDatabase;
}
}

namespace codeskeptic {

using ASTCallback = std::function<void(clang::ASTContext&)>;

// The platform-specific compile arguments every analysis invocation
// needs (resource-dir; on macOS the SDK sysroot and system include
// paths). Single source of truth: production tooling (ClangTool
// adjusters) and the unit-test harness (runToolOnCodeWithArgs) must
// compile snippets IDENTICALLY — a test TU that silently fails to
// find <stdlib.h> reports zero findings and passes vacuously.
std::vector<std::string> platformExtraArgs();

// Exact in-memory entry point used by both the production file wrapper and
// deterministic fuzzing. Parsing remains Clang's JSON compilation-database
// grammar; CodeSkeptic does not maintain a second interpretation.
bool validateCompilationDatabaseText(const std::string& text,
                                     std::string& error);

struct TranslationUnitExecution {
    std::string canonical_path;
    std::string working_directory;
    std::vector<std::string> command_line;
    std::string output;
    std::string compile_command_sha256;
    std::size_t command_ordinal = 0;
};

// Stable identity of the exact command the isolated worker will execute.
// The worker recomputes this value before parsing so a request cannot bind a
// receipt to one command while analyzing another.
std::string translationUnitCommandSha256(
    const TranslationUnitExecution& execution);

class SourceManager {
public:
    explicit SourceManager(const std::string& build_path);
    ~SourceManager();

    void addSourceFile(const std::string& path);
    void scanDirectory(const std::string& dir_path);
    int processAll(ASTCallback callback);

    // A missing compile_commands.json intentionally selects the extension-
    // aware fallback. Once the file exists, parse/read failure is invalid
    // input and must make the product verdict unavailable instead of silently
    // broadening analysis under synthesized flags.
    bool compilationDatabaseValid() const { return comp_db_valid_; }
    const std::string& compilationDatabaseError() const {
        return comp_db_error_;
    }

    // Warm AST cache (MCP server / long-lived process): parsed TUs are
    // kept for the PROCESS lifetime, so subsequent calls do not pay the
    // parse cost. The key is path+build-path; if the fingerprint
    // (mtime+size) does not match, it is rebuilt — a STALE AST IS NEVER
    // SERVED. Stays off in one-shot CLI runs (memory: we do not want to
    // keep all ASTs alive during a large directory scan).
    void enableWarmCache(bool enabled) { warm_cache_ = enabled; }

    // Test/diagnostics: cache counters and reset (process-lifetime store)
    static unsigned warmCacheHits();
    static unsigned warmCacheMisses();
    static void clearWarmCache();

    // Broken-TU guard (#86): TUs whose parse ended with an uncompilable
    // error are always recorded. They are skipped by default; the explicit
    // recovery opt-in may run rules over them, but never erases the broken
    // evidence or restores a project verdict.
    static void setAnalyzeBrokenTUs(bool allow);
    static bool analyzeBrokenTUs();
    static void recordBrokenTU(const std::string& file);
    static const std::vector<std::string>& brokenTUs();
    static void clearBrokenTUs();
    // Attempted-TU count for THIS run, published as a static so the
    // decoupled console reporter can detect the nothing-was-analyzed
    // case (set by StaticAnalyzer::run before processing).
    static void setAttemptedTUCount(size_t n);
    static size_t attemptedTUCount();

    size_t fileCount() const;
    // Exact number of explicitly requested/discovered TU identities before
    // missing paths are filtered from the ClangTool input list.
    size_t requestedFileCount() const;
    const std::vector<std::string>& files() const;
    std::vector<TranslationUnitExecution> executionUnits() const;

private:
    // The body of processAll, run on a large-stack worker thread (deep
    // metaprogram-generated types overflow a default stack — see the
    // comment in processAll).
    int processAllOnWorker(ASTCallback callback);

    std::string build_path_;
    // Every explicit/discovered request, including missing paths. Resource
    // coordination needs an exact failure receipt even when ClangTool cannot
    // be started for that entry.
    std::vector<std::string> requested_files_;
    std::vector<std::string> source_files_;
    size_t requested_file_count_ = 0;
    std::unique_ptr<clang::tooling::CompilationDatabase> comp_db_;
    bool comp_db_valid_ = true;
    std::string comp_db_error_;
    bool warm_cache_ = false;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_SOURCE_MANAGER_H
