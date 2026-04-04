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

    size_t fileCount() const;
    const std::vector<std::string>& files() const;

private:
    std::string build_path_;
    std::vector<std::string> source_files_;
    std::unique_ptr<clang::tooling::CompilationDatabase> comp_db_;
};

} // namespace zerodefect

#endif // ZERODEFECT_SOURCE_MANAGER_H
