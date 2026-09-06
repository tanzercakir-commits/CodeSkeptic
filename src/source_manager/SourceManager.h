#ifndef CODESKEPTIC_SOURCE_MANAGER_H
#define CODESKEPTIC_SOURCE_MANAGER_H

#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "core/Messages.h"
#include "core/AnalysisResult.h"
#include "source_manager/InputIdentity.h"

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

class SourceManager {
public:
    explicit SourceManager(const std::string& build_path);
    SourceManager(const std::string& build_path,
                  std::unique_ptr<clang::tooling::CompilationDatabase> database,
                  bool synthetic_single_file);
    ~SourceManager();

    bool addSourceFile(const std::string& path, InputError* error = nullptr);
    bool scanDirectory(const std::string& dir_path, InputError* error = nullptr);
    int processAll(ASTCallback callback);

    // Warm AST cache (MCP server / long-lived process): parsed TUs are
    // kept for the PROCESS lifetime, so subsequent calls do not pay the
    // parse cost. The key includes path, build-path and loaded compile
    // commands plus observed source/header bytes and filesystem lookups.
    // Unknown or volatile input mechanisms bypass reuse. Stays off in
    // one-shot CLI runs (memory: we do not want to
    // keep all ASTs alive during a large directory scan).
    void enableWarmCache(bool enabled) { warm_cache_ = enabled; }

    // Bind actual per-command observations to the caller's frozen request.
    // Empty context disables witness production for ordinary cold analysis.
    void recordInputs(std::string context) { input_context_ = std::move(context); }
    const InputIdentity& inputIdentity() const { return input_identity_; }

    // Test/diagnostics: cache counters and reset (process-lifetime store)
    static unsigned warmCacheHits();
    static unsigned warmCacheMisses();
    static void clearWarmCache();

    // Broken-TU guard (#86): TUs whose parse ended with an
    // uncompilable error are skipped by default — error recovery eats
    // initializers and declarations, and rules would report
    // confidently about code that does not exist. The skip list is
    // process-global for the run (mirrors the warm-cache counters);
    // StaticAnalyzer surfaces it as an honest coverage note.
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
    const std::vector<std::string>& files() const;
    const std::vector<SourceCoverage>& coverage() const { return coverage_; }

private:
    // The body of processAll, run on a large-stack worker thread (deep
    // metaprogram-generated types overflow a default stack — see the
    // comment in processAll).
    int processAllOnWorker(ASTCallback callback);

    std::string build_path_;
    std::vector<std::string> source_files_;
    std::vector<SourceCoverage> coverage_;
    std::unique_ptr<clang::tooling::CompilationDatabase> comp_db_;
    bool warm_cache_ = false;
    std::string input_context_;
    InputIdentity input_identity_;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_SOURCE_MANAGER_H
