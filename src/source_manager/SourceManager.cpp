#include "source_manager/SourceManager.h"

#include "core/Messages.h"
#include "engine/AssertGuards.h"
#include "source_manager/ResourceDir.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Lex/PPCallbacks.h>
#include <clang/Lex/Preprocessor.h>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Support/SHA256.h>
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
// eaten). A TU that did not compile is always honestly counted;
// --analyze-broken-tus may collect non-verdict evidence from the recovered
// AST for consumers investigating AI-generated code that never compiled.
bool tuIsBroken(clang::ASTContext& ctx) {
    return ctx.getDiagnostics().hasUncompilableErrorOccurred();
}

std::string mainFileOf(clang::ASTContext& ctx) {
    const clang::SourceManager& sm = ctx.getSourceManager();
    if (auto ref = sm.getFileEntryRefForID(sm.getMainFileID()))
        return ref->getName().str();
    return "<unknown>";
}

std::string canonicalIdentity(const std::string& path) {
    std::error_code ec;
    fs::path canonical = fs::weakly_canonical(path, ec);
    if (ec) {
        ec.clear();
        canonical = fs::absolute(path, ec);
    }
    return (ec ? fs::path(path) : canonical).lexically_normal().string();
}

std::string lexicalIdentity(const std::string& path) {
    std::error_code ec;
    fs::path lexical(path);
    if (lexical.is_relative()) lexical = fs::absolute(lexical, ec);
    return (ec ? fs::path(path) : lexical).lexically_normal().string();
}

std::vector<std::string>& dependencyList() {
    static std::vector<std::string> files;
    return files;
}

bool& volatilePreprocessorBuiltinSeen() {
    static bool seen = false;
    return seen;
}

class VolatilePreprocessorCallbacks : public clang::PPCallbacks {
public:
    void MacroExpands(const clang::Token& name_token,
                      const clang::MacroDefinition&,
                      clang::SourceRange,
                      const clang::MacroArgs*) override {
        const auto* identifier = name_token.getIdentifierInfo();
        if (!identifier) return;
        const auto name = identifier->getName();
        if (name == "__DATE__" || name == "__TIME__" ||
            name == "__TIMESTAMP__")
            volatilePreprocessorBuiltinSeen() = true;
    }
};

void recordDependencyFiles(clang::ASTContext& ctx) {
    auto& files = dependencyList();
    const auto& source = ctx.getSourceManager();
    for (auto it = source.fileinfo_begin(); it != source.fileinfo_end(); ++it) {
        const std::string path = it->first.getName().str();
        // Sidecar lookup intentionally uses Clang's lexical file spelling.
        // Preserve it as evidence in addition to the resolved file identity,
        // otherwise alias.h -> real.h could read alias.h.csk while only
        // real.h.csk was bound to the checkpoint.
        files.push_back(lexicalIdentity(path));
        files.push_back(canonicalIdentity(path));
    }
    std::sort(files.begin(), files.end());
    files.erase(std::unique(files.begin(), files.end()), files.end());
}

void appendLengthPrefixed(std::ostringstream& out,
                          const std::string& value) {
    out << value.size() << ':' << value << '\n';
}

std::string serializedCommand(
    const clang::tooling::CompileCommand& command) {
    std::ostringstream out;
    appendLengthPrefixed(out, command.Directory);
    appendLengthPrefixed(out, command.Filename);
    appendLengthPrefixed(out, command.Output);
    out << command.CommandLine.size() << '\n';
    for (const auto& argument : command.CommandLine)
        appendLengthPrefixed(out, argument);
    return out.str();
}

std::string sha256(const std::string& value) {
    llvm::SHA256 hasher;
    hasher.update(llvm::StringRef(value));
    const auto digest = hasher.final();
    return llvm::toHex(llvm::ArrayRef<std::uint8_t>(digest), true);
}

std::string serializedExecution(
    const codeskeptic::TranslationUnitExecution& execution) {
    std::ostringstream out;
    appendLengthPrefixed(out, execution.working_directory);
    appendLengthPrefixed(out, execution.canonical_path);
    appendLengthPrefixed(out, execution.output);
    out << execution.command_line.size() << '\n';
    for (const auto& argument : execution.command_line)
        appendLengthPrefixed(out, argument);
    return out.str();
}

class CodeSkepticASTConsumer : public clang::ASTConsumer {
public:
    explicit CodeSkepticASTConsumer(codeskeptic::ASTCallback callback)
        : callback_(std::move(callback)) {}

    void HandleTranslationUnit(clang::ASTContext& ctx) override {
        recordDependencyFiles(ctx);
        if (tuIsBroken(ctx)) {
            codeskeptic::SourceManager::recordBrokenTU(mainFileOf(ctx));
            if (!codeskeptic::SourceManager::analyzeBrokenTUs()) return;
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
    CreateASTConsumer(clang::CompilerInstance& ci,
                      llvm::StringRef /*file*/) override {
        ci.getPreprocessor().addPPCallbacks(
            std::make_unique<VolatilePreprocessorCallbacks>());
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

std::string translationUnitCommandSha256(
    const TranslationUnitExecution& execution) {
    return sha256(serializedExecution(execution));
}

namespace {

std::unique_ptr<clang::tooling::CompilationDatabase>
loadCompilationDatabaseText(const std::string& text, std::string& error) {
    if (text.find('\0') != std::string::npos) {
        error = "embedded NUL byte";
        return nullptr;
    }
    auto database = clang::tooling::JSONCompilationDatabase::loadFromBuffer(
        llvm::StringRef(text.data(), text.size()), error,
        clang::tooling::JSONCommandLineSyntax::AutoDetect);
    if (!database) return nullptr;
    for (const auto& command : database->getAllCompileCommands()) {
        if (command.Directory.find('\0') != std::string::npos ||
            command.Filename.find('\0') != std::string::npos ||
            command.Output.find('\0') != std::string::npos)
            error = "embedded NUL byte in compilation command";
        for (const auto& argument : command.CommandLine)
            if (argument.find('\0') != std::string::npos)
                error = "embedded NUL byte in compilation command";
        if (!error.empty()) return nullptr;
    }
    return database;
}

} // anonymous namespace

bool validateCompilationDatabaseText(const std::string& text,
                                     std::string& error) {
    std::string parsed_error;
    auto database = loadCompilationDatabaseText(text, parsed_error);
    if (!database) {
        error = std::move(parsed_error);
        return false;
    }
    error.clear();
    return true;
}

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
    std::error_code database_ec;
    const fs::path database_path =
        fs::path(build_path_) / "compile_commands.json";
    const fs::file_status entry_status =
        fs::symlink_status(database_path, database_ec);
    const bool database_missing =
        database_ec == std::errc::no_such_file_or_directory &&
        entry_status.type() == fs::file_type::not_found;
    if (database_missing) database_ec.clear();
    if (database_ec) {
        comp_db_valid_ = false;
        comp_db_error_ = database_ec.message();
        std::cerr << msg(MsgId::CompileDbInvalid, comp_db_error_) << "\n";
        return;
    }
    const bool database_entry_exists =
        entry_status.type() != fs::file_type::not_found;

    std::string error_msg;
    if (database_entry_exists) {
        const fs::file_status resolved_status =
            fs::status(database_path, database_ec);
        if (database_ec || !fs::is_regular_file(resolved_status)) {
            comp_db_valid_ = false;
            comp_db_error_ = database_ec
                ? database_ec.message()
                : "path is not a regular file";
            std::cerr << msg(MsgId::CompileDbInvalid, comp_db_error_) << "\n";
            return;
        }
        std::ifstream input(database_path, std::ios::binary);
        if (!input.is_open()) {
            comp_db_valid_ = false;
            comp_db_error_ = "cannot read " + database_path.string();
            std::cerr << msg(MsgId::CompileDbInvalid, comp_db_error_) << "\n";
            return;
        }
        std::string content(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
        if (input.bad()) {
            comp_db_valid_ = false;
            comp_db_error_ = "failed while reading " + database_path.string();
            std::cerr << msg(MsgId::CompileDbInvalid, comp_db_error_) << "\n";
            return;
        }
        comp_db_ = loadCompilationDatabaseText(content, error_msg);
        if (!comp_db_) {
            comp_db_valid_ = false;
            comp_db_error_ = error_msg.empty()
                ? "parser rejected the existing database"
                : error_msg;
            std::cerr << msg(MsgId::CompileDbInvalid, comp_db_error_) << "\n";
        }
        return;
    }

    comp_db_ = clang::tooling::CompilationDatabase::loadFromDirectory(
        build_path_, error_msg);

    if (!comp_db_) {
        std::cerr << msg(MsgId::CompileDbNotFound, error_msg) << "\n";
        comp_db_ = std::make_unique<ExtensionAwareCompilationDatabase>();
    }
}

SourceManager::~SourceManager() = default;

void SourceManager::addSourceFile(const std::string& path) {
    ++requested_file_count_;
    auto abs = fs::absolute(path);
    requested_files_.push_back(abs.lexically_normal().string());
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
                ++requested_file_count_;
                requested_files_.push_back(
                    fs::absolute(entry.path()).lexically_normal().string());
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

    // Platform args shared with the test harness (single source of
    // truth — see platformExtraArgs below).
    auto extra = codeskeptic::platformExtraArgs();
    if (!extra.empty()) {
        tool.appendArgumentsAdjuster(
            clang::tooling::getInsertArgumentAdjuster(
                extra, clang::tooling::ArgumentInsertPosition::BEGIN));
    }
}

unsigned g_warmHits = 0;
unsigned g_warmMisses = 0;

} // anonymous namespace

unsigned SourceManager::warmCacheHits() { return g_warmHits; }
unsigned SourceManager::warmCacheMisses() { return g_warmMisses; }
void SourceManager::clearWarmCache() {
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
    if (!comp_db_) return 1;

    // The compatibility switch records reparses but deliberately shares the
    // exact normal ClangTool path. That preserves every compile command for a
    // source while ensuring an unverifiable process-lifetime AST is never
    // served.
    if (warm_cache_) g_warmMisses += source_files_.size();

    clang::tooling::ClangTool tool(*comp_db_, source_files_);
    applyPlatformAdjusters(tool);

    CodeSkepticActionFactory factory(callback);
    const int result = tool.run(&factory);
    if (warm_cache_ && result != 0) {
        for (const auto& file : source_files_) {
            if (comp_db_->getCompileCommands(file).empty())
                recordBrokenTU(file);
        }
    }
    return result;
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
const std::vector<std::string>& SourceManager::dependencyFiles() {
    return dependencyList();
}
bool SourceManager::volatilePreprocessorBuiltinExpanded() {
    return volatilePreprocessorBuiltinSeen();
}
void SourceManager::clearDependencyFiles() {
    dependencyList().clear();
    volatilePreprocessorBuiltinSeen() = false;
}

namespace { size_t g_attempted_tus = 0; }
void SourceManager::setAttemptedTUCount(size_t n) { g_attempted_tus = n; }
size_t SourceManager::attemptedTUCount() { return g_attempted_tus; }

size_t SourceManager::fileCount() const {
    return source_files_.size();
}

size_t SourceManager::requestedFileCount() const {
    return requested_file_count_;
}

const std::vector<std::string>& SourceManager::files() const {
    return source_files_;
}

std::vector<TranslationUnitExecution> SourceManager::executionUnits() const {
    std::vector<TranslationUnitExecution> units;
    if (!comp_db_) return units;

    std::vector<std::string> files = requested_files_;
    std::sort(files.begin(), files.end(), [](const std::string& lhs,
                                             const std::string& rhs) {
        return canonicalIdentity(lhs) < canonicalIdentity(rhs);
    });
    for (const auto& file : files) {
        auto commands = comp_db_->getCompileCommands(file);
        std::sort(commands.begin(), commands.end(),
                  [](const clang::tooling::CompileCommand& lhs,
                     const clang::tooling::CompileCommand& rhs) {
                      return serializedCommand(lhs) < serializedCommand(rhs);
                  });
        if (commands.empty()) {
            units.push_back(TranslationUnitExecution{
                canonicalIdentity(file), {}, {}, {}, {}, 0});
            continue;
        }
        for (std::size_t ordinal = 0; ordinal < commands.size(); ++ordinal) {
            const auto& command = commands[ordinal];
            TranslationUnitExecution execution{
                canonicalIdentity(file), command.Directory,
                command.CommandLine, command.Output, {}, ordinal};
            execution.compile_command_sha256 =
                translationUnitCommandSha256(execution);
            units.push_back(std::move(execution));
        }
    }
    return units;
}

} // namespace codeskeptic
