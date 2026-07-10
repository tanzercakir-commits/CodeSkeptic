#include "source_manager/SourceManager.h"

#include "core/Messages.h"

#include <filesystem>
#include <iostream>
#include <map>

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/Frontend/ASTUnit.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/Tooling.h>

namespace fs = std::filesystem;

namespace {

class ZeroDefectASTConsumer : public clang::ASTConsumer {
public:
    explicit ZeroDefectASTConsumer(zerodefect::ASTCallback callback)
        : callback_(std::move(callback)) {}

    void HandleTranslationUnit(clang::ASTContext& ctx) override {
        callback_(ctx);
    }

private:
    zerodefect::ASTCallback callback_;
};

class ZeroDefectAction : public clang::ASTFrontendAction {
public:
    explicit ZeroDefectAction(zerodefect::ASTCallback callback)
        : callback_(std::move(callback)) {}

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance& /*ci*/,
                      llvm::StringRef /*file*/) override {
        return std::make_unique<ZeroDefectASTConsumer>(callback_);
    }

private:
    zerodefect::ASTCallback callback_;
};

class ZeroDefectActionFactory
    : public clang::tooling::FrontendActionFactory {
public:
    explicit ZeroDefectActionFactory(zerodefect::ASTCallback callback)
        : callback_(std::move(callback)) {}

    std::unique_ptr<clang::FrontendAction> create() override {
        return std::make_unique<ZeroDefectAction>(callback_);
    }

private:
    zerodefect::ASTCallback callback_;
};

} // anonymous namespace

namespace zerodefect {

SourceManager::SourceManager(const std::string& build_path)
    : build_path_(build_path) {
    std::string error_msg;
    comp_db_ = clang::tooling::CompilationDatabase::loadFromDirectory(
        build_path_, error_msg);

    if (!comp_db_) {
        std::cerr << msg(MsgId::CompileDbNotFound, error_msg) << "\n";
        comp_db_ = std::make_unique<clang::tooling::FixedCompilationDatabase>(
            ".", std::vector<std::string>{"-std=c++17"});
    }
}

SourceManager::~SourceManager() = default;

void SourceManager::addSourceFile(const std::string& path) {
    auto abs = fs::absolute(path);
    if (!fs::exists(abs)) {
        std::cerr << msg(MsgId::FileNotFound, abs.string()) << "\n";
        return;
    }
    source_files_.push_back(abs.string());
}

void SourceManager::scanDirectory(const std::string& dir_path) {
    if (!fs::is_directory(dir_path)) {
        std::cerr << msg(MsgId::DirNotFound, dir_path) << "\n";
        return;
    }

    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir_path)) {
            if (!entry.is_regular_file()) continue;

            auto ext = entry.path().extension().string();
            if (ext == ".c" || ext == ".cpp" || ext == ".cc" || ext == ".cxx") {
                source_files_.push_back(entry.path().string());
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << msg(MsgId::DirScanError, e.what()) << "\n";
    }
}

namespace {

void applyPlatformAdjusters(clang::tooling::ClangTool& tool) {
#ifdef __APPLE__
    // macOS: SDK headers come via isysroot; extra system paths are needed.
    // On Linux, prepending these paths breaks GCC libstdc++'s include_next
    // chain (stdlib.h not found) — resource-dir is sufficient there.
    tool.appendArgumentsAdjuster(
        clang::tooling::getInsertArgumentAdjuster(
            {"-isystem", "/usr/include",
             "-isystem", "/usr/local/include"},
            clang::tooling::ArgumentInsertPosition::BEGIN));
#endif

#ifdef CLANG_RESOURCE_DIR
    tool.appendArgumentsAdjuster(
        clang::tooling::getInsertArgumentAdjuster(
            {"-resource-dir", CLANG_RESOURCE_DIR},
            clang::tooling::ArgumentInsertPosition::BEGIN));
#endif

#ifdef MACOS_SDK_PATH
    tool.appendArgumentsAdjuster(
        clang::tooling::getInsertArgumentAdjuster(
            {"-isysroot", MACOS_SDK_PATH},
            clang::tooling::ArgumentInsertPosition::BEGIN));
#endif
}

// --- Process-lifetime warm AST cache ---
//
// Deliberate global state (not the OPPOSITE of the filter-leak lesson,
// but its complement): here cross-call persistence IS the feature, and
// correctness is protected by a content-derived key — path+build-path
// key, mtime+size fingerprint. If the fingerprint does not match, the
// entry is rebuilt; there is no path by which a stale AST could be
// served.
struct CachedAst {
    std::string fingerprint;
    std::unique_ptr<clang::ASTUnit> unit;
};

std::map<std::string, CachedAst>& astCache() {
    static std::map<std::string, CachedAst> cache;
    return cache;
}
unsigned g_warmHits = 0;
unsigned g_warmMisses = 0;

// Simple memory ceiling: not worth LRU complexity — flush everything on
// overflow (in MCP usage the file count is small, rarely triggered)
constexpr size_t kMaxCachedAsts = 16;

std::string fingerprintOf(const std::string& path) {
    std::error_code ec;
    auto size = fs::file_size(path, ec);
    if (ec) return {};
    auto mtime = fs::last_write_time(path, ec);
    if (ec) return {};
    return std::to_string(size) + ":" +
           std::to_string(mtime.time_since_epoch().count());
}

} // anonymous namespace

unsigned SourceManager::warmCacheHits() { return g_warmHits; }
unsigned SourceManager::warmCacheMisses() { return g_warmMisses; }
void SourceManager::clearWarmCache() {
    astCache().clear();
    g_warmHits = 0;
    g_warmMisses = 0;
}

int SourceManager::processAll(ASTCallback callback) {
    if (source_files_.empty()) return 0;

    if (warm_cache_) {
        bool anyFailed = false;
        for (const auto& file : source_files_) {
            const std::string key = file + "|" + build_path_;
            const std::string fp = fingerprintOf(file);

            auto it = astCache().find(key);
            if (!fp.empty() && it != astCache().end() &&
                it->second.fingerprint == fp && it->second.unit) {
                ++g_warmHits;
                callback(it->second.unit->getASTContext());
                continue;
            }

            ++g_warmMisses;
            clang::tooling::ClangTool tool(*comp_db_, {file});
            applyPlatformAdjusters(tool);
            std::vector<std::unique_ptr<clang::ASTUnit>> units;
            tool.buildASTs(units);
            if (units.empty() || !units[0]) {
                anyFailed = true;
                continue;
            }
            callback(units[0]->getASTContext());

            if (astCache().size() >= kMaxCachedAsts) astCache().clear();
            astCache()[key] = {fp, std::move(units[0])};
        }
        return anyFailed ? 1 : 0;
    }

    clang::tooling::ClangTool tool(*comp_db_, source_files_);
    applyPlatformAdjusters(tool);

    ZeroDefectActionFactory factory(callback);
    return tool.run(&factory);
}

size_t SourceManager::fileCount() const {
    return source_files_.size();
}

const std::vector<std::string>& SourceManager::files() const {
    return source_files_;
}

} // namespace zerodefect
