#include "source_manager/SourceManager.h"

#include "core/Messages.h"

#include <filesystem>
#include <iostream>

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
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

int SourceManager::processAll(ASTCallback callback) {
    if (source_files_.empty()) return 0;

    clang::tooling::ClangTool tool(*comp_db_, source_files_);

#ifdef __APPLE__
    // macOS: SDK header'lari isysroot ile gelir; ek sistem path'leri gerekli.
    // Linux'ta bu path'leri one eklemek GCC libstdc++'in include_next
    // zincirini kirar (stdlib.h bulunamaz) — resource-dir orada yeterli.
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
