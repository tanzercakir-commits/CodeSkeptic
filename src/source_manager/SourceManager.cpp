#include "source_manager/SourceManager.h"

#include "core/Messages.h"
#include "engine/AssertGuards.h"
#include "source_manager/ResourceDir.h"

#include <filesystem>
#include <exception>
#include <iostream>
#include <map>
#include <stdexcept>

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/Frontend/ASTUnit.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Lex/PreprocessorOptions.h>
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

void callInCompilerDirectory(clang::ASTContext& context, const fs::path& directory,
                             const codeskeptic::ASTCallback& callback) {
    // ClangTool restores cwd before a retained-AST callback. Native consumers
    // (sidecars and baseline function binding) must see the same directory as
    // the AST's real FileManager VFS. The production AST pipeline is serialized;
    // this does not promise concurrent-library-call safety.
    auto& virtual_fs = context.getSourceManager().getFileManager().getVirtualFileSystem();
    const auto native_before = fs::current_path();
    const auto virtual_before = virtual_fs.getCurrentWorkingDirectory();
    if (!virtual_before) throw std::runtime_error("cannot read compiler working directory");
    std::exception_ptr failure;
    try {
        fs::current_path(directory);
        if (virtual_fs.setCurrentWorkingDirectory(directory.string()))
            throw std::runtime_error("cannot set compiler working directory");
        callback(context);
    } catch (...) { failure = std::current_exception(); }
    const auto virtual_error = virtual_fs.setCurrentWorkingDirectory(*virtual_before);
    std::error_code native_error;
    fs::current_path(native_before, native_error);
    if (virtual_error || native_error) throw std::runtime_error("cannot restore compiler working directory");
    if (failure) std::rethrow_exception(failure);
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
        // Both fresh and retained-AST construction must install these hooks
        // before preprocessing; an AST alone cannot reconstruct discarded macros.
        codeskeptic::installAssertRecovery(ci);
        codeskeptic::observeCompilerInputs(ci);
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

class RetainedAstAction : public clang::tooling::ToolAction {
public:
    explicit RetainedAstAction(codeskeptic::ASTCallback callback) : fallback_(std::move(callback)) {}
    bool runInvocation(std::shared_ptr<clang::CompilerInvocation> invocation,
        clang::FileManager* files,
        std::shared_ptr<clang::PCHContainerOperations> pch,
        clang::DiagnosticConsumer* consumer) override {
        const auto& inputs = invocation->getFrontendOpts().Inputs;
        const auto& preprocessor = invocation->getPreprocessorOpts();
        const bool supported = inputs.size() == 1 && inputs.front().isFile() &&
            inputs.front().getFile() != "-" &&
            inputs.front().getKind().getFormat() == clang::InputKind::Source &&
            (inputs.front().getKind().getLanguage() == clang::Language::C ||
             inputs.front().getKind().getLanguage() == clang::Language::CXX) &&
            !inputs.front().getKind().isPreprocessed() && !inputs.front().getKind().isHeader() &&
            !inputs.front().getKind().isHeaderUnit() && preprocessor.ImplicitPCHInclude.empty() &&
            preprocessor.ChainedIncludes.empty() && preprocessor.PCHThroughHeader.empty();
        if (!supported) {
            codeskeptic::refuseInputReuse("unsupported_frontend_input");
            CodeSkepticActionFactory factory(fallback_);
            return factory.runInvocation(std::move(invocation), files, std::move(pch), consumer);
        }
        auto diagnostics = clang::CompilerInstance::createDiagnostics(
            files->getVirtualFileSystem(), &invocation->getDiagnosticOpts(), consumer, false);
        if (!diagnostics) return false;
        auto candidate = clang::ASTUnit::create(invocation, diagnostics,
            clang::CaptureDiagsKind::None, false);
        candidate->getFileManager().setVirtualFileSystem(files->getVirtualFileSystemPtr());
        // The persistent consumer must not retain references to the caller's
        // stack. Rules run once after loading, while fresh PP state is valid.
        CodeSkepticAction action([](clang::ASTContext&) {});
        auto* loaded = clang::ASTUnit::LoadFromCompilerInvocationAction(
            invocation, pch, diagnostics, &action, candidate.get(), true, {},
            false, clang::CaptureDiagsKind::None, 0, false, false);
        if (!loaded) return false;
        const bool success = diagnostics->getClient()->getNumErrors() == 0;
        unit = std::move(candidate);
        return success;
    }
    std::unique_ptr<clang::ASTUnit> unit;
private:
    codeskeptic::ASTCallback fallback_;
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
// the key binds the recipe and PP settings, and the witness binds the actual
// input bytes plus positive/negative filesystem observations. Unsupported or
// volatile inputs still parse normally but cannot populate the store.
struct CachedAst {
    InputIdentity identity;
    std::unique_ptr<clang::ASTUnit> unit;
    int frontend_result = 0;
    std::function<InputIdentity()> snapshot;
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
    input_identity_ = {};
    if (!input_context_.empty()) {
        input_identity_.reusable = true;
        input_identity_.reason.clear();
        input_identity_.context = input_context_;
        input_identity_.environment = inputEnvironmentIdentity();
    }
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
            const auto command_directory = fs::absolute(command.Directory);
            bool visited = false, completed = false, broken = false;
            std::exception_ptr callback_failure;
            auto guardedCall = [&](clang::ASTContext& ctx) {
                if (callback_failure) return;
                visited = true;
                broken = broken || tuIsBroken(ctx);
                if (tuIsBroken(ctx) && !analyzeBrokenTUs()) {
                    recordBrokenTU(file);
                    return;
                }
                try { callInCompilerDirectory(ctx, command_directory, callback); }
                catch (...) {
                    // Finish Clang's action normally so it restores its own
                    // working directory and unwinds frontend ownership before
                    // the exception crosses the public SourceManager boundary.
                    callback_failure = std::current_exception();
                    return;
                }
                completed = true;
            };
            int frontendResult = 0;
            SingleCommandDatabase database(command);
            std::string key;
            auto bind = [&](const std::string& field) {
                key += std::to_string(field.size()) + ":" + field;
            };
            bind(file); bind(build_path_); bind(fs::current_path().string());
            bind(command.Directory); bind(command.Filename); bind(command.Output);
            bind(std::to_string(command.CommandLine.size()));
            for (const auto& argument : command.CommandLine) bind(argument);
            for (const auto& argument : platformExtraArgs()) bind(argument);
            bind(assertRecoveryEnabled() ? "asserts-on" : "asserts-off");
            bind(std::to_string(extraAssertMacros().size()));
            for (const auto& name : extraAssertMacros()) bind(name);
            bind(std::to_string(negativeAssertMacros().size()));
            for (const auto& name : negativeAssertMacros()) bind(name);
            key = inputDigest(key);
            const bool supported = cacheableCommand(command.CommandLine);
            std::unique_ptr<InputRecording> recording;
            if (warm_cache_ || !input_context_.empty()) {
                recording = std::make_unique<InputRecording>(key);
                if (!supported) recording->refuse("unsupported_compiler_arguments");
            }
            auto filesystem = recording ? recording->filesystem() : llvm::vfs::getRealFileSystem();
            InputIdentity command_identity;
            // Retain the existing one-command warm-cache boundary. Multiple
            // variants always execute normally; none is silently discarded.
            if (warm_cache_ && commands.size() == 1 && supported) {
                auto it = astCache().find(key);
                if (it != astCache().end() && it->second.unit && it->second.identity.matchesCurrent()) {
                    ++g_warmHits;
                    frontendResult = it->second.frontend_result;
                    guardedCall(it->second.unit->getASTContext());
                    command_identity = it->second.snapshot();
                    command_identity.append(recording->finish());
                    it->second.identity = command_identity;
                } else {
                    ++g_warmMisses;
                    if (it != astCache().end()) astCache().erase(it);
                    clang::tooling::ClangTool tool(database, {file},
                        std::make_shared<clang::PCHContainerOperations>(), filesystem);
                    applyPlatformAdjusters(tool);
                    RetainedAstAction builder(guardedCall);
                    frontendResult = tool.run(&builder);
                    if (builder.unit) {
                        guardedCall(builder.unit->getASTContext());
                        command_identity = recording->finish();
                        // Assert records are globally owned by the most recently
                        // parsed SourceManager, not by ASTUnit. Only a zero-record
                        // AST is independent of that volatile external ownership.
                        if (!callback_failure && recordedVanishedAssertCount() == 0 && command_identity.hasBuffer(file) &&
                            command_identity.matchesCurrent()) {
                            if (astCache().size() >= kMaxCachedAsts) astCache().clear();
                            astCache()[key] = {command_identity, std::move(builder.unit), frontendResult,
                                              recording->snapshotter()};
                        }
                    }
                }
            } else {
                if (warm_cache_ && commands.size() == 1) ++g_warmMisses;
                clang::tooling::ClangTool tool(database, {file},
                    std::make_shared<clang::PCHContainerOperations>(), filesystem);
                applyPlatformAdjusters(tool);
                CodeSkepticActionFactory factory(guardedCall);
                frontendResult = tool.run(&factory);
                if (recording) command_identity = recording->finish();
            }
            if (callback_failure) std::rethrow_exception(callback_failure);
            if (!input_context_.empty()) input_identity_.append(command_identity);
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
