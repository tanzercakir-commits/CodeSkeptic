#include "source_manager/CompilationDatabaseDiscovery.h"

#include "config/Config.h"

#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Driver/Options.h>
#include <llvm/Option/ArgList.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/VirtualFileSystem.h>

#include <algorithm>
#include <filesystem>
#include <map>
#include <ostream>
#include <set>

namespace codeskeptic {
namespace {
namespace fs = std::filesystem;

fs::path normalized(const fs::path& path) {
    return fs::weakly_canonical(fs::absolute(path));
}

bool supportedSource(const fs::path& path) {
    const auto ext = path.extension().string();
    return ext == ".c" || ext == ".cpp" || ext == ".cc" || ext == ".cxx";
}

class ResolvedCompilationDatabase final : public clang::tooling::CompilationDatabase {
public:
    explicit ResolvedCompilationDatabase(std::vector<clang::tooling::CompileCommand> commands) {
        for (auto& command : commands) entries_[command.Filename].push_back(std::move(command));
    }
    std::vector<clang::tooling::CompileCommand> getCompileCommands(llvm::StringRef file) const override {
        const auto found = entries_.find(file.str());
        return found == entries_.end() ? std::vector<clang::tooling::CompileCommand>{} : found->second;
    }
    std::vector<std::string> getAllFiles() const override {
        std::vector<std::string> result;
        for (const auto& entry : entries_) result.push_back(entry.first);
        return result;
    }
    std::vector<clang::tooling::CompileCommand> getAllCompileCommands() const override {
        std::vector<clang::tooling::CompileCommand> result;
        for (const auto& entry : entries_) result.insert(result.end(), entry.second.begin(), entry.second.end());
        return result;
    }
private:
    std::map<std::string, std::vector<clang::tooling::CompileCommand>> entries_;
};

bool commandTargetsDeclaredFile(const clang::tooling::CompileCommand& command) {
    if (command.CommandLine.empty()) return false;
    const auto compiler = fs::path(command.CommandLine.front()).filename().string();
    bool clMode = compiler == "cl" || compiler == "cl.exe" ||
                  compiler == "clang-cl" || compiler == "clang-cl.exe";
    std::vector<const char*> arguments;
    for (std::size_t i = 1; i < command.CommandLine.size(); ++i) {
        const auto& argument = command.CommandLine[i];
        if (argument == "--driver-mode=cl") clMode = true;
        // Unexpanded (e.g. missing) response files cannot hide actual inputs.
        if (!argument.empty() && argument.front() == '@') return false;
        arguments.push_back(argument.c_str());
    }
    unsigned missingIndex = 0, missingCount = 0;
    const auto visibility = clang::driver::options::ClangOption |
        (clMode ? clang::driver::options::CLOption : 0);
    const auto parsed = clang::driver::getDriverOptTable().ParseArgs(
        arguments, missingIndex, missingCount, llvm::opt::Visibility(visibility));
    if (missingCount != 0) return false;
    const auto inputs = parsed.getAllArgValues(clang::driver::options::OPT_INPUT);
    if (inputs.size() != 1) return false;
    fs::path working = command.Directory;
    // The driver resolves relative inputs after its last working-directory
    // override, not necessarily against the database's directory field.
    if (const auto* override = parsed.getLastArg(clang::driver::options::OPT_working_directory)) {
        fs::path selected(override->getValue());
        if (selected.empty()) return false;
        working = selected.is_absolute() ? selected : working / selected;
    }
    fs::path input(inputs.front());
    if (input.is_relative()) input = working / input;
    return normalized(input) == fs::path(command.Filename);
}

// Search only conventional build locations on the requested source's ancestry.
// CWD is not an independent search root. A nested .git (file or directory) is
// a fence; without one, the nearest build-system marker is the project fence.
void addSearchRoots(const fs::path& anchor, std::set<fs::path>& roots) {
    std::vector<fs::path> ancestors;
    fs::path buildRoot;
    fs::path cursor = anchor;
    bool repositoryFound = false;
    for (unsigned depth = 0; depth < 8; ++depth) {
        ancestors.push_back(cursor);
        if (fs::exists(cursor / ".git")) {
            repositoryFound = true;
            break;
        }
        if (buildRoot.empty() &&
            (fs::exists(cursor / "CMakeLists.txt") ||
             fs::exists(cursor / "meson.build") || fs::exists(cursor / "Makefile")))
            buildRoot = cursor;
        if (cursor == cursor.parent_path()) break;
        cursor = cursor.parent_path();
    }
    const fs::path boundary = repositoryFound ? ancestors.back() :
                                  (buildRoot.empty() ? anchor : buildRoot);
    for (const auto& root : ancestors) {
        roots.insert(root);
        if (root == boundary) break;
    }
}

std::unique_ptr<clang::tooling::CompilationDatabase> loadExactJson(
    const fs::path& path, std::string& error) {
    // Directory loading accepts compile_flags.txt and inferred commands. It
    // must not rescue a broken or non-covering compile_commands.json.
    constexpr std::uintmax_t maximumBytes = 128u * 1024u * 1024u;
    if (!fs::is_regular_file(path) || fs::file_size(path) > maximumBytes) {
        error = "database is not a regular file within the 128 MiB input limit";
        return nullptr;
    }
    auto buffer = llvm::MemoryBuffer::getFile(path.string());
    if (!buffer) {
        error = "cannot read compile_commands.json";
        return nullptr;
    }
    auto parsed = llvm::json::parse((*buffer)->getBuffer());
    if (!parsed) {
        error = "malformed compile_commands.json: " + llvm::toString(parsed.takeError());
        return nullptr;
    }
    auto* array = parsed->getAsArray();
    if (!array || array->empty()) {
        error = "compile_commands.json must be a nonempty JSON array";
        return nullptr;
    }
    for (auto& value : *array) {
        auto* object = value.getAsObject();
        if (!object) {
            error = "database entries must be objects";
            return nullptr;
        }
        const auto directory = object->getString("directory");
        const auto file = object->getString("file");
        if (!directory || directory->empty() || !file || file->empty() ||
            directory->contains('\0') || file->contains('\0')) {
            error = "database entries require nonempty directory and file strings";
            return nullptr;
        }
        if (auto* arguments = object->get("arguments")) {
            auto* items = arguments->getAsArray();
            if (!items || items->empty() ||
                !(*items)[0].getAsString() || (*items)[0].getAsString()->empty() ||
                !std::all_of(items->begin(), items->end(), [](const auto& argument) {
                    const auto text = argument.getAsString();
                    return text && !text->contains('\0');
                })) {
                error = "arguments must be a nonempty string array with a compiler";
                return nullptr;
            }
        } else {
            const auto command = object->getString("command");
            if (!command || command->empty() || command->contains('\0')) {
                error = "database entry requires arguments or a command string";
                return nullptr;
            }
        }
        if (object->get("output") && !object->getString("output")) {
            error = "database output must be a string";
            return nullptr;
        }
        fs::path working(directory->str());
        if (working.is_relative()) working = path.parent_path() / working;
        working = normalized(working);
        fs::path input(file->str());
        if (input.is_relative()) input = working / input;
        const auto canonicalInput = normalized(input).string();
        const auto canonicalDirectory = working.string();
        // Even UTF-8 database strings may resolve through a symlink to a raw
        // byte pathname. Do not construct an invalid LLVM JSON string from it.
        if (!llvm::json::isUTF8(canonicalInput) || !llvm::json::isUTF8(canonicalDirectory)) {
            error = "resolved compilation input path is not UTF-8";
            return nullptr;
        }
        // Normalize the actual loaded commands, not just the doctor's labels.
        (*object)["directory"] = canonicalDirectory;
        (*object)["file"] = canonicalInput;
    }
    auto database = clang::tooling::JSONCompilationDatabase::loadFromBuffer(
        llvm::formatv("{0}", *parsed).str(), error,
        clang::tooling::JSONCommandLineSyntax::AutoDetect);
    if (!database) return nullptr;
    auto expanded = clang::tooling::expandResponseFiles(
        clang::tooling::inferTargetAndDriverMode(std::move(database)),
        llvm::vfs::getRealFileSystem());
    auto commands = expanded->getAllCompileCommands();
    for (const auto& command : commands) {
        if (!commandTargetsDeclaredFile(command)) {
            error = "compile command must target exactly its declared file (check arguments/response files): " + command.Filename;
            return nullptr;
        }
    }
    // Freeze expanded commands once. Response-file edits between resolution,
    // cache-key construction and execution must not change the selected recipe.
    return std::make_unique<ResolvedCompilationDatabase>(std::move(commands));
}

// Freeze known requested identities independently of database readiness. In
// particular, an invalid later file-list member must not erase earlier ones.
std::string unresolvedIdentity(const fs::path& path) {
    // Reporting fallback only, never a path accepted for compilation. ELOOP
    // and permission failures prevent canonicalization but not recording the
    // exact requested location as failed evidence.
    std::error_code error;
    auto absolute = fs::absolute(path, error);
    return (error ? path : absolute).lexically_normal().string();
}

bool collectRequestedSources(const Config& config, const fs::path& source,
                             const fs::path& database,
                             std::vector<std::string>& files,
                             std::string& reason) {
    std::set<std::string> requested;
    auto problem = [&](const std::string& text) {
        if (reason.empty()) reason = text;
    };
    bool sourceIsDirectory = false;
    try {
        if (!source.empty()) {
            sourceIsDirectory = fs::is_directory(source);
            if (sourceIsDirectory) {
                for (auto it = fs::recursive_directory_iterator(normalized(source));
                     it != fs::recursive_directory_iterator(); ++it) {
                    if (it->is_directory() &&
                        (it->path().filename() == ".git" ||
                         (!database.empty() && it->path().filename() == "CMakeFiles" &&
                          normalized(it->path().parent_path()) == database.parent_path() &&
                          fs::is_regular_file(database.parent_path() / "CMakeCache.txt")))) {
                        it.disable_recursion_pending();
                        continue;
                    }
                    if (it->is_regular_file() && supportedSource(it->path()))
                        requested.insert(normalized(it->path()).string());
                }
            } else {
                requested.insert(normalized(source).string());
                if (!fs::is_regular_file(source) || !supportedSource(source))
                    problem("source is not a supported C/C++ file or directory");
            }
        }
    } catch (const fs::filesystem_error& error) {
        if (!source.empty() && !sourceIsDirectory)
            requested.insert(unresolvedIdentity(source));
        problem("cannot inspect requested scope: " + std::string(error.what()));
    }
    for (const auto& file : config.sourceFiles()) {
        fs::path path(file);
        try {
            // Preserve discovery's existing CWD-first/build-relative policy.
            if (!fs::exists(path) && path.is_relative() && !database.empty())
                path = database.parent_path() / path;
            requested.insert(normalized(path).string());
            if (!fs::is_regular_file(path) || !supportedSource(path))
                problem("listed source is missing or unsupported: " + file);
        } catch (const fs::filesystem_error& error) {
            requested.insert(unresolvedIdentity(path));
            problem("cannot inspect listed source: " + std::string(error.what()));
        }
    }
    files.assign(requested.begin(), requested.end());
    for (const auto& file : files) {
        if (!llvm::json::isUTF8(file))
            problem("requested source path is not UTF-8");
    }
    return reason.empty();
}

} // namespace

CompilationDatabaseSelection discoverCompilationDatabase(const Config& config) {
    CompilationDatabaseSelection result;
    try {
        fs::path source = config.sourcePath();
        if (source.empty() && config.sourceFiles().empty() &&
            !config.fileListSpecified() && config.doctor()) source = ".";
        result.source = source.empty() ? "file-list" : normalized(source).string();
        auto fail = [&](std::string reason) {
            std::string inputReason;
            collectRequestedSources(config, source, result.database,
                                    result.files, inputReason);
            result.reason = std::move(reason);
            return std::move(result);
        };
        if (config.fileListSpecified() && config.sourceFiles().empty()) {
            return fail("explicit file list is empty");
        }
        if ((!source.empty() && !fs::exists(source)) ||
            (source.empty() && config.sourceFiles().empty())) {
            return fail("no existing source input was requested");
        }
        std::set<fs::path> candidates;
        if (config.buildPathSpecified()) {
            result.selection = "explicit";
            if (config.buildPath().empty()) {
                return fail("explicit build path is empty");
            }
            const fs::path specified = normalized(config.buildPath());
            const fs::path database = specified.filename() == "compile_commands.json" ?
                                          specified : specified / "compile_commands.json";
            result.database = database.string();
            candidates.insert(database);
        } else {
            result.selection = "automatic";
            std::set<fs::path> roots;
            if (!source.empty()) {
                const fs::path absolute = normalized(source);
                addSearchRoots(fs::is_directory(absolute) ? absolute : absolute.parent_path(), roots);
            }
            for (const auto& file : config.sourceFiles()) {
                if (!fs::is_regular_file(file)) {
                    return fail("listed source does not exist: " + file);
                }
                addSearchRoots(normalized(file).parent_path(), roots);
            }
            if (roots.size() > 128) {
                return fail("automatic discovery exceeds 128 source roots; select --build-path");
            }
            for (const auto& root : roots) {
                for (const char* location : {"", "build", "Build", "build-debug", "build-release",
                                             "cmake-build-debug", "cmake-build-release", "out/build"}) {
                    const fs::path candidate = root / location / "compile_commands.json";
                    // Include a dangling link or directory as an invalid candidate;
                    // it must not silently turn a configured project into fallback.
                    if (fs::exists(candidate) || fs::is_symlink(candidate))
                        candidates.insert(normalized(candidate));
                }
            }
        }
        for (const auto& path : candidates) result.candidates.push_back(path.string());
        if (candidates.size() > 1) {
            return fail("ambiguous compilation databases; select --build-path explicitly");
        }
        if (candidates.empty()) {
            if (!source.empty() && fs::is_regular_file(source) && supportedSource(source) &&
                config.sourceFiles().empty() && !config.fileListSpecified()) {
                result.synthetic = true;
                result.ready = true;
                result.files.push_back(normalized(source).string());
                result.selection = "direct-single-file";
                if (!llvm::json::isUTF8(result.files.front())) {
                    result.ready = false;
                    result.reason = "requested source path is not UTF-8";
                }
                return result;
            }
            return fail("no compile_commands.json found; project/file-list analysis requires a database");
        }
        const fs::path database = *candidates.begin();
        result.database = database.string();
        if (!collectRequestedSources(config, source, database, result.files, result.reason))
            return result;
        result.commands = loadExactJson(database, result.reason);
        if (!result.commands) return result;
        const auto allCommands = result.commands->getAllCompileCommands();
        result.entries = allCommands.size();
        const std::set<std::string> requested(result.files.begin(), result.files.end());
        if (requested.empty()) {
            result.reason = "no supported source files in requested scope";
            return result;
        }
        std::set<std::string> covered;
        for (const auto& command : allCommands) {
            if (!requested.count(command.Filename)) continue;
            if (!fs::is_directory(command.Directory)) {
                result.reason = "compile command working directory does not exist: " + command.Directory;
                return result;
            }
            covered.insert(command.Filename);
            ++result.matching_entries;
        }
        for (const auto& file : requested) {
            if (!covered.count(file)) {
                result.reason = "database has no exact compile command for requested source: " + file;
                return result;
            }
        }
        result.ready = true;
    } catch (const fs::filesystem_error& error) {
        result.ready = false;
        result.reason = "cannot inspect compilation inputs: " + std::string(error.what());
        std::string inputReason;
        collectRequestedSources(config, config.sourcePath(), result.database,
                                result.files, inputReason);
    }
    return result;
}

void writeCompilationDoctor(const CompilationDatabaseSelection& result, std::ostream& output) {
    // Human-readable labels must not corrupt a UTF-8 stderr/stdout stream.
    // The analysis coverage separately retains each failed path byte-for-byte.
    auto display = [](const std::string& text) {
        return llvm::json::isUTF8(text) ? text : llvm::json::fixUTF8(text);
    };
    output << "[CodeSkeptic] compilation doctor\n"
           << "status: " << (result.ready ? "ready" : "unavailable") << "\n"
           << "source: " << display(result.source) << "\n";
    if (result.ready) {
        output << "mode: " << (result.synthetic ? "synthetic-single-file" : "compilation-database") << "\n"
               << "selection: " << result.selection << "\n"
               << "database: " << (result.synthetic ? "none" : display(result.database)) << "\n"
               << "entries: " << result.entries << "\n"
               << "matching-entries: " << result.matching_entries << "\n"
               << "source-files: " << result.files.size() << "\n";
        if (result.synthetic)
            output << "standard: " << (fs::path(result.files.front()).extension() == ".c" ? "gnu11" : "c++17") << "\n";
        output << "next: run analysis with the same source and build-path options; doctor does not compile or prove correctness\n";
    } else {
        output << "reason: " << display(result.reason) << "\n";
        if (!result.database.empty()) output << "database: " << display(result.database) << "\n";
        for (std::size_t i = 0; i < result.candidates.size(); ++i)
            output << "candidate[" << i << "]: " << display(result.candidates[i]) << "\n";
        output << "next: generate a valid compile_commands.json for this project and select its directory with --build-path; for CMake enable CMAKE_EXPORT_COMPILE_COMMANDS\n";
    }
}
} // namespace codeskeptic
