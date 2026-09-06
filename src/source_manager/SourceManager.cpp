#include "source_manager/SourceManager.h"

#include "core/Messages.h"
#include "engine/AssertGuards.h"
#include "source_manager/ResourceDir.h"

#include <filesystem>
#include <exception>
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
    // Honor the compilation command's diagnostic policy too: -Werror can
    // reject an AST without an "uncompilable" parse error. Do not run rules
    // or harvest summaries from a rejected compilation unless the caller
    // explicitly accepts recovery. Ordinary warnings are not errors.
    return ctx.getDiagnostics().hasErrorOccurred();
}

class CodeSkepticASTConsumer : public clang::ASTConsumer {
public:
    explicit CodeSkepticASTConsumer(codeskeptic::ASTCallback callback)
        : callback_(std::move(callback)) {}

    void HandleTranslationUnit(clang::ASTContext& ctx) override {
        // SourceManager wraps this callback with the requested source and
        // compile-variant identity, including the broken-AST guard.
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
    CreateASTConsumer(clang::CompilerInstance& ci,
                      llvm::StringRef /*file*/) override {
        // AR.3: the vanished-assert recorder is a PPCallbacks hook, so
        // it must be installed HERE, before preprocessing. The warm-AST
        // path (processAllOnWorker) never reaches this point and is
        // therefore inert — AssertGuardCache's SourceManager fence
        // makes that a no-op rather than a stale-pointer read.
        codeskeptic::installAssertRecovery(ci);
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

std::vector<std::string> platformExtraArgs() {
    std::vector<std::string> args;
#ifdef __APPLE__
    // macOS: SDK headers come via isysroot; extra system paths are
    // needed. On Linux, prepending these paths breaks GCC libstdc++'s
    // include_next chain (stdlib.h not found) — resource-dir is
    // sufficient there.
    args.insert(args.end(), {"-isystem", "/usr/include",
                             "-isystem", "/usr/local/include"});
#endif

    // Relocatable resource-dir (v0.4): release tarballs ship the
    // intrinsic headers next to the binary, so the path is resolved at
    // runtime — env override -> exe-relative lib/clang/<ver> -> the
    // baked build-machine path (ResourceDir.cpp) — instead of trusting
    // a build-time absolute path that does not exist on user machines.
    const std::string& resource_dir = resourceDir();
    if (!resource_dir.empty()) {
        args.insert(args.end(), {"-resource-dir", resource_dir});
    }

#ifdef __APPLE__
    // Runtime-resolved SDK sysroot (v0.4.5): SDKROOT env -> xcrun
    // probe -> baked build-machine path — the resource-dir treatment
    // applied to -isysroot. Empty -> no flag; a hopeless TU then
    // fails LOUDLY (exit-2 policy) instead of "Clean!".
    const std::string& sdk = macSdkPath();
    if (!sdk.empty()) args.insert(args.end(), {"-isysroot", sdk});
#endif
    return args;
}

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

SourceManager::SourceManager(
    const std::string& build_path,
    std::unique_ptr<clang::tooling::CompilationDatabase> database,
    bool synthetic_single_file)
    : build_path_(build_path), comp_db_(std::move(database)) {
    if (synthetic_single_file)
        comp_db_ = std::make_unique<ExtensionAwareCompilationDatabase>();
}

bool SourceManager::addSourceFile(const std::string& path, InputError* error) {
    auto fail = [&](const char* reason, const char* message) {
        InputError failure{reason, "path", message};
        if (error) *error = failure;
        reportInputError(failure);
        return false;
    };
    if (path.empty() || path.find('\0') != std::string::npos)
        return fail("invalid_path", "Expected a non-empty source path without NUL");
    try {
        const auto abs = fs::absolute(path);
        if (!fs::is_regular_file(abs))
            return fail("invalid_target", "Source target is not a regular file");
        const auto ext = abs.extension().string();
        if (ext != ".c" && ext != ".cpp" && ext != ".cc" && ext != ".cxx")
            return fail("invalid_target", "Unsupported source extension");
        const auto identity = fs::weakly_canonical(abs).string();
        if (std::find(source_files_.begin(), source_files_.end(), identity) ==
            source_files_.end()) source_files_.push_back(identity);
    } catch (const fs::filesystem_error&) {
        return fail("read_error", "Cannot inspect source target");
    }
    if (error) *error = {};
    return true;
}

bool SourceManager::scanDirectory(const std::string& dir_path, InputError* error) {
    auto fail = [&](const char* reason, const char* message) {
        InputError failure{reason, "path", message};
        if (error) *error = failure;
        reportInputError(failure);
        return false;
    };
    if (dir_path.empty() || dir_path.find('\0') != std::string::npos)
        return fail("invalid_path", "Expected a non-empty directory path without NUL");
    auto staged = source_files_;
    try {
        if (!fs::is_directory(dir_path))
            return fail("invalid_target", "Target is not a directory");
        for (const auto& entry : fs::recursive_directory_iterator(dir_path)) {
            if (!entry.is_regular_file()) continue;

            auto ext = entry.path().extension().string();
            if (ext == ".c" || ext == ".cpp" || ext == ".cc" || ext == ".cxx") {
                const auto identity = fs::weakly_canonical(entry.path()).string();
                if (std::find(staged.begin(), staged.end(), identity) == staged.end())
                    staged.push_back(identity);
            }
        }
    } catch (const fs::filesystem_error&) {
        return fail("read_error", "Directory traversal failed");
    }
    source_files_ = std::move(staged);
    if (error) *error = {};
    return true;
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

    // Platform args shared with the test harness (single source of
    // truth — see platformExtraArgs below).
    auto extra = codeskeptic::platformExtraArgs();
    if (!extra.empty()) {
        tool.appendArgumentsAdjuster(
            clang::tooling::getInsertArgumentAdjuster(
                extra, clang::tooling::ArgumentInsertPosition::BEGIN));
    }
}

// --- Process-lifetime warm AST cache ---
//
// Deliberate global state (not the OPPOSITE of the filter-leak lesson,
// but its complement): here cross-call persistence IS the feature, and
// the key includes the loaded compile commands and paths, with a source
// mtime+size freshness fingerprint. Changed commands/source metadata rebuild
// the AST; transitive header/environment tracking is outside this cache model.
struct CachedAst {
    std::string fingerprint;
    std::unique_ptr<clang::ASTUnit> unit;
    int frontend_result = 0;
};

// ClangTool's aggregate result cannot identify which of a source's compile
// variants failed before producing an AST. Execute each frozen recipe once.
class SingleCommandDatabase : public clang::tooling::CompilationDatabase {
public:
    explicit SingleCommandDatabase(clang::tooling::CompileCommand command)
        : command_(std::move(command)) {}
    std::vector<clang::tooling::CompileCommand>
    getCompileCommands(llvm::StringRef) const override { return {command_}; }
private:
    clang::tooling::CompileCommand command_;
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
    // Explicit casts: on Apple libc++ file_time_type's rep is __int128,
    // which has no std::to_string overload (ambiguous-call error). The
    // narrowing is harmless — this is a cache fingerprint, not a
    // timestamp.
    return std::to_string(static_cast<unsigned long long>(size)) + ":" +
           std::to_string(static_cast<long long>(
               mtime.time_since_epoch().count()));
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
    std::exception_ptr failure;
    llvm::thread worker(
        std::optional<unsigned>(64u << 20),
        [this, &result, &failure, cb = std::move(callback)]() mutable {
            try {
                result = processAllOnWorker(std::move(cb));
            } catch (...) {
                failure = std::current_exception();
            }
        });
    worker.join();
    // join synchronizes both result and exception ownership. The request's
    // analyzer can now unwind/clean its caches on the calling thread instead
    // of an uncaught exception terminating the long-lived MCP process.
    if (failure) std::rethrow_exception(failure);
    return result;
}

int SourceManager::processAllOnWorker(ASTCallback callback) {
    coverage_.clear();
    for (const auto& file : source_files_) coverage_.push_back(SourceCoverage{file});
    bool anyFailed = false;
    for (auto& source : coverage_) {
        const auto& file = source.file;
        if (!comp_db_) {
            source.reason = "compilation_database_unavailable";
            anyFailed = true;
            continue;
        }
        const auto commands = comp_db_->getCompileCommands(file);
        source.commands = commands.size();
        if (commands.empty()) {
            source.reason = "missing_compile_command";
            anyFailed = true;
            continue;
        }
        for (const auto& command : commands) {
            bool visited = false, completed = false, broken = false;
            auto guardedCall = [&](clang::ASTContext& ctx) {
                visited = true;
                broken = broken || tuIsBroken(ctx);
                if (tuIsBroken(ctx) && !analyzeBrokenTUs()) {
                    recordBrokenTU(file);
                    return;
                }
                callback(ctx);
                completed = true;
            };
            int frontendResult = 0;
            SingleCommandDatabase database(command);
            // Retain the existing one-command warm-cache boundary. Multiple
            // variants always execute normally; none is silently discarded.
            if (warm_cache_ && commands.size() == 1) {
                // Length-prefix fields prevent delimiter collisions. Retain
                // the existing source mtime/size cache freshness model.
                std::string key;
                auto bind = [&](const std::string& field) {
                    key += std::to_string(field.size()) + ":" + field;
                };
                bind(file);
                bind(build_path_);
                bind(std::to_string(commands.size()));
                bind(command.Directory);
                bind(command.Filename);
                bind(command.Output);
                bind(std::to_string(command.CommandLine.size()));
                for (const auto& argument : command.CommandLine) bind(argument);
                for (const auto& argument : platformExtraArgs()) bind(argument);
                const std::string fp = fingerprintOf(file);
                auto it = astCache().find(key);
                if (!fp.empty() && it != astCache().end() &&
                    it->second.fingerprint == fp && it->second.unit) {
                    ++g_warmHits;
                    frontendResult = it->second.frontend_result;
                    guardedCall(it->second.unit->getASTContext());
                } else {
                    ++g_warmMisses;
                    clang::tooling::ClangTool tool(database, {file});
                    applyPlatformAdjusters(tool);
                    std::vector<std::unique_ptr<clang::ASTUnit>> units;
                    frontendResult = tool.buildASTs(units);
                    if (!units.empty() && units[0]) {
                        guardedCall(units[0]->getASTContext());
                        if (astCache().size() >= kMaxCachedAsts) astCache().clear();
                        astCache()[key] = {fp, std::move(units[0]), frontendResult};
                    }
                }
            } else {
                clang::tooling::ClangTool tool(database, {file});
                applyPlatformAdjusters(tool);
                CodeSkepticActionFactory factory(guardedCall);
                frontendResult = tool.run(&factory);
            }
            if (!visited || (!broken && frontendResult != 0)) {
                ++source.failed_commands;
                source.reason = frontendResult != 0 ? "frontend_failed"
                                                     : "ast_not_produced";
            } else if (broken && !analyzeBrokenTUs()) {
                ++source.skipped_commands;
            } else if (completed) {
                ++source.analyzed_commands;
                if (broken) ++source.recovery_commands;
            } else {
                ++source.failed_commands;
                source.reason = "analysis_not_completed";
            }
        }
        if (source.failed_commands > 0) {
            source.status = SourceStatus::Failed;
            anyFailed = true;
        } else if (source.skipped_commands > 0) {
            source.status = SourceStatus::Skipped;
            source.reason = "broken_translation_unit";
            anyFailed = true;
        } else {
            source.status = SourceStatus::Analyzed;
            source.reason = source.recovery_commands > 0 ? "error_recovery_ast"
                                                        : "analyzed";
        }
    }
    return anyFailed ? 1 : 0;
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
    // Deduplicated: summary-inference prepasses re-parse TUs, so the
    // same broken file can be recorded once per sweep — which made
    // brokenTUCount() overshoot fileCount() and spuriously trip the
    // all-TUs-broken exit-2 policy on PARTIALLY broken inputs
    // (order-dependent, caught while testing the v0.4.5 policy).
    auto& list = brokenList();
    for (const auto& f : list)
        if (f == file) return;
    list.push_back(file);
}
const std::vector<std::string>& SourceManager::brokenTUs() {
    return brokenList();
}
void SourceManager::clearBrokenTUs() { brokenList().clear(); }

namespace { size_t g_attempted_tus = 0; }
void SourceManager::setAttemptedTUCount(size_t n) { g_attempted_tus = n; }
size_t SourceManager::attemptedTUCount() { return g_attempted_tus; }

size_t SourceManager::fileCount() const {
    return source_files_.size();
}

const std::vector<std::string>& SourceManager::files() const {
    return source_files_;
}

} // namespace codeskeptic
