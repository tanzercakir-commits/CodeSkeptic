#ifndef ZERODEFECT_SOURCE_MANAGER_H
#define ZERODEFECT_SOURCE_MANAGER_H

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

namespace zerodefect {

using ASTCallback = std::function<void(clang::ASTContext&)>;

class SourceManager {
public:
    explicit SourceManager(const std::string& build_path);
    ~SourceManager();

    void addSourceFile(const std::string& path);
    void scanDirectory(const std::string& dir_path);
    int processAll(ASTCallback callback);

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

    size_t fileCount() const;
    const std::vector<std::string>& files() const;

private:
    // The body of processAll, run on a large-stack worker thread (deep
    // metaprogram-generated types overflow a default stack — see the
    // comment in processAll).
    int processAllOnWorker(ASTCallback callback);

    std::string build_path_;
    std::vector<std::string> source_files_;
    std::unique_ptr<clang::tooling::CompilationDatabase> comp_db_;
    bool warm_cache_ = false;
};

} // namespace zerodefect

#endif // ZERODEFECT_SOURCE_MANAGER_H
