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
#include <llvm/Support/thread.h>

namespace fs = std::filesystem;

namespace {

// Broken-TU guard (#86). An AST built through error recovery is not
// the program: after a failed include or a hard type error, clang
// drops initializers, whole declarations, and types — and every rule
// then reasons CONFIDENTLY about code that does not exist. Measured
// on Godot: 176 TUs analyzed with a missing generated header produced
// 298 uninit-ptr ERRORS, all artifacts ("declared without an
// initializer" on declarations whose initializers the recovery had
// eaten). A TU that did not compile is SKIPPED and honestly counted;
// --analyze-broken-tus restores the old behavior for consumers who
// accept the risk (AI-generated code that never compiled at all).
bool tuIsBroken(clang::ASTContext& ctx) {
    return ctx.getDiagnostics().hasUncompilableErrorOccurred();
}

std::string mainFileOf(clang::ASTContext& ctx) {
    const clang::SourceManager& sm = ctx.getSourceManager();
    if (auto ref = sm.getFileEntryRefForID(sm.getMainFileID()))
        return ref->getName().str();
    return "<unknown>";
}

class CodeSkepticASTConsumer : public clang::ASTConsumer {
public:
    explicit CodeSkepticASTConsumer(codeskeptic::ASTCallback callback)
        : callback_(std::move(callback)) {}

    void HandleTranslationUnit(clang::ASTContext& ctx) override {
        if (!codeskeptic::SourceManager::analyzeBrokenTUs() &&
            tuIsBroken(ctx)) {
            codeskeptic::SourceManager::recordBrokenTU(mainFileOf(ctx));
            return;
        }
        callback_(ctx);
    }

private:
    codeskeptic::ASTCallback callback_;
};

class CodeSkepticAction : public clang::ASTFrontendAction {
public:
    explicit CodeSkepticAction(codeskeptic::ASTCallback callback)
        : callback_(std::move(callback)) {}

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance& /*ci*/,
                      llvm::StringRef /*file*/) override {
        return std::make_unique<CodeSkepticASTConsumer>(callback_);
    }

private:
    codeskeptic::ASTCallback callback_;
};

class CodeSkepticActionFactory
    : public clang::tooling::FrontendActionFactory {
public:
    explicit CodeSkepticActionFactory(codeskeptic::ASTCallback callback)
        : callback_(std::move(callback)) {}

    std::unique_ptr<clang::FrontendAction> create() override {
        return std::make_unique<CodeSkepticAction>(callback_);
    }

private:
    codeskeptic::ASTCallback callback_;
};

// Fallback compilation database (no compile_commands.json found):
// one synthesized command per file, with the standard chosen by the
// file's EXTENSION. A single fixed `-std=c++17` for everything is
// wrong for C sources — clang rejects `-std=c++17` on a `.c` file, the
// TU fails to compile, and the broken-TU guard silently SKIPS it,
// returning a false "clean". That path is exactly the MCP-for-AI use
// case: an assistant hands the server a bare `.c` snippet with no
// build DB and must get real findings, not a skip. `.c` → gnu11 (so
// strdup/strcasecmp and other POSIX/GNU decls a first-draft file uses
// are visible); everything else → c++17.
class ExtensionAwareCompilationDatabase
    : public clang::tooling::CompilationDatabase {
public:
    std::vector<clang::tooling::CompileCommand> getCompileCommands(
        llvm::StringRef file) const override {
        llvm::StringRef ext = file.rsplit('.').second;
        const bool isC = ext == "c";
        std::vector<std::string> cmd = {isC ? "clang" : "clang++"};
        if (isC) {
            cmd.push_back("-x");
            cmd.push_back("c");
            cmd.push_back("-std=gnu11");
        } else {
            cmd.push_back("-std=c++17");
        }
        cmd.push_back("-fsyntax-only");
        cmd.push_back(file.str());
        return {clang::tooling::CompileCommand(
            ".", file.str(), std::move(cmd), "")};
    }
};

} // anonymous namespace

namespace codeskeptic {

SourceManager::SourceManager(const std::string& build_path)
    : build_path_(build_path) {
    std::string error_msg;
    comp_db_ = clang::tooling::CompilationDatabase::loadFromDirectory(
        build_path_, error_msg);

    if (!comp_db_) {
        std::cerr << msg(MsgId::CompileDbNotFound, error_msg) << "\n";
        comp_db_ = std::make_unique<ExtensionAwareCompilationDatabase>();
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
    // Contracts live in ordinary line comments; without this flag the
    // AST keeps only doc-comments and getRawCommentForDeclNoCache
    // returns nothing for `// cs:` blocks (CONTRACTS.md).
    tool.appendArgumentsAdjuster(
        clang::tooling::getInsertArgumentAdjuster(
            {"-fparse-all-comments"},
            clang::tooling::ArgumentInsertPosition::BEGIN));
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
    // The whole per-TU pipeline (parse + rules) runs on a worker thread
    // with a LARGE stack. Clang type queries recurse per nesting level
    // of the type, and metaprogram-generated types in real code go deep
    // enough to smash a default 8MB stack (TensorFlow Lite's
    // neon_tensor_utils.cc: getTypeInfoImpl 104k frames deep =
    // SIGSEGV). 64MB gives an ~8x margin over the worst type observed;
    // rule-side queries are additionally budget-capped (IntervalEval's
    // boundedTypeSizeInChars), so this guard is for the paths we do NOT
    // control. Sequential (one thread at a time) — the engine's global
    // caches see no concurrency.
    int result = 0;
    llvm::thread worker(
        std::optional<unsigned>(64u << 20),
        [this, &result, cb = std::move(callback)]() mutable {
            result = processAllOnWorker(std::move(cb));
        });
    worker.join();
    return result;
}

int SourceManager::processAllOnWorker(ASTCallback callback) {
    if (source_files_.empty()) return 0;

    if (warm_cache_) {
        bool anyFailed = false;
        for (const auto& file : source_files_) {
            const std::string key = file + "|" + build_path_;
            const std::string fp = fingerprintOf(file);

            // The broken-TU guard applies to both cache paths — a
            // cached AST keeps its DiagnosticsEngine, so the check is
            // identical (see CodeSkepticASTConsumer).
            auto guardedCall = [&](clang::ASTContext& ctx) {
                if (!analyzeBrokenTUs() && tuIsBroken(ctx)) {
                    recordBrokenTU(mainFileOf(ctx));
                    return;
                }
                callback(ctx);
            };

            auto it = astCache().find(key);
            if (!fp.empty() && it != astCache().end() &&
                it->second.fingerprint == fp && it->second.unit) {
                ++g_warmHits;
                guardedCall(it->second.unit->getASTContext());
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
            guardedCall(units[0]->getASTContext());

            if (astCache().size() >= kMaxCachedAsts) astCache().clear();
            astCache()[key] = {fp, std::move(units[0])};
        }
        return anyFailed ? 1 : 0;
    }

    clang::tooling::ClangTool tool(*comp_db_, source_files_);
    applyPlatformAdjusters(tool);

    CodeSkepticActionFactory factory(callback);
    return tool.run(&factory);
}

namespace {
bool g_analyzeBrokenTUs = false;
std::vector<std::string>& brokenList() {
    static std::vector<std::string> list;
    return list;
}
} // anonymous namespace

void SourceManager::setAnalyzeBrokenTUs(bool allow) {
    g_analyzeBrokenTUs = allow;
}
bool SourceManager::analyzeBrokenTUs() { return g_analyzeBrokenTUs; }
void SourceManager::recordBrokenTU(const std::string& file) {
    brokenList().push_back(file);
}
const std::vector<std::string>& SourceManager::brokenTUs() {
    return brokenList();
}
void SourceManager::clearBrokenTUs() { brokenList().clear(); }

size_t SourceManager::fileCount() const {
    return source_files_.size();
}

const std::vector<std::string>& SourceManager::files() const {
    return source_files_;
}

} // namespace codeskeptic
