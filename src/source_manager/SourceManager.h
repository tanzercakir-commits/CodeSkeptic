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

    // Sicak AST onbellegi (MCP server / uzun omurlu surec): parse
    // edilmis TU'lar SUREC omurlu tutulur, sonraki cagrilar parse
    // maliyeti odemez. Anahtar yol+build-path; parmak izi (mtime+boyut)
    // uyusmazsa yeniden kurulur — BAYAT AST ASLA SERVIS EDILMEZ.
    // CLI tek-atim kosularinda kapali kalir (bellek: buyuk dizin
    // taramasinda tum AST'leri canli tutmak istemeyiz).
    void enableWarmCache(bool enabled) { warm_cache_ = enabled; }

    // Test/teshis: onbellek sayaclari ve sifirlama (surec-omurlu depo)
    static unsigned warmCacheHits();
    static unsigned warmCacheMisses();
    static void clearWarmCache();

    size_t fileCount() const;
    const std::vector<std::string>& files() const;

private:
    std::string build_path_;
    std::vector<std::string> source_files_;
    std::unique_ptr<clang::tooling::CompilationDatabase> comp_db_;
    bool warm_cache_ = false;
};

} // namespace zerodefect

#endif // ZERODEFECT_SOURCE_MANAGER_H
