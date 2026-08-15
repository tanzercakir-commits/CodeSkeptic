#include "analyzer/WorkerRuntime.h"

#include "analyzer/DefaultRules.h"
#include "analyzer/StaticAnalyzer.h"
#include "analyzer/WorkerProtocol.h"
#include "config/Config.h"
#include "engine/CfgCache.h"
#include "engine/FunctionSummary.h"
#include "source_manager/SourceManager.h"

#include <clang/AST/ASTContext.h>
#include <clang/Basic/Version.h>
#include <clang/Basic/SourceManager.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Support/Allocator.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/StringSaver.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <new>
#include <set>
#include <vector>

namespace codeskeptic {

namespace json = llvm::json;

namespace {

constexpr int kMemoryLimitExitCode = 86;
constexpr int kProtocolFailureExitCode = 70;
constexpr int kResponseFailureExitCode = 71;
constexpr std::uintmax_t kMaxDependencyBytes = 16ull << 30;
constexpr std::uintmax_t kMaxResponseFileBytes = 64ull << 20;
constexpr unsigned kMaxResponseFileDepth = 16;

std::string hashText(const std::string& text) {
    const auto digest = llvm::SHA256::hash(
        llvm::ArrayRef<std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    return llvm::toHex(digest, true);
}

bool containsVolatilePreprocessorMarker(llvm::StringRef text) {
    for (const char* marker : {"__DATE__", "__TIME__", "__TIMESTAMP__"}) {
        if (text.contains(marker)) return true;
    }
    return false;
}

std::string hashRegularFile(const std::string& path, std::string& error,
                            bool* volatile_preprocessor_input = nullptr) {
    std::error_code ec;
    const auto status = std::filesystem::status(path, ec);
    if (ec || !std::filesystem::is_regular_file(status)) {
        error = "dependency is not a regular file: " + path;
        return {};
    }
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > kMaxDependencyBytes) {
        error = "dependency exceeds size limit: " + path;
        return {};
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "cannot read dependency: " + path;
        return {};
    }
    llvm::SHA256 hasher;
    std::vector<char> buffer(64u << 10);
    std::string overlap;
    if (volatile_preprocessor_input) *volatile_preprocessor_input = false;
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            hasher.update(llvm::ArrayRef<std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(buffer.data()),
                static_cast<std::size_t>(count)));
            if (volatile_preprocessor_input &&
                !*volatile_preprocessor_input) {
                std::string window = overlap;
                window.append(buffer.data(), static_cast<std::size_t>(count));
                if (containsVolatilePreprocessorMarker(window))
                    *volatile_preprocessor_input = true;
                constexpr std::size_t kOverlapBytes = 16;
                overlap = window.substr(
                    window.size() > kOverlapBytes
                        ? window.size() - kOverlapBytes
                        : 0);
            }
        }
    }
    if (input.bad()) {
        error = "failed while reading dependency: " + path;
        return {};
    }
    const auto digest = hasher.final();
    return llvm::toHex(llvm::ArrayRef<std::uint8_t>(digest), true);
}

std::string toolchainIdentitySha256() {
    std::string identity = clang::getClangFullVersion();
    identity += '\n';
    identity += CODESKEPTIC_VERSION;
    identity += '\n';
    for (const auto& argument : platformExtraArgs()) {
        identity += std::to_string(argument.size()) + ":" + argument + "\n";
    }
    return hashText(identity);
}

std::string canonicalCommandInput(const std::string& path,
                                  const std::filesystem::path& working_dir,
                                  std::string& error) {
    if (path.empty()) {
        error = "compile-command dependency path is empty";
        return {};
    }
    std::filesystem::path candidate(path);
    if (candidate.is_relative()) candidate = working_dir / candidate;
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(candidate, ec);
    if (ec) {
        ec.clear();
        canonical = std::filesystem::absolute(candidate, ec);
    }
    if (ec) {
        error = "cannot canonicalize compile-command dependency: " + path;
        return {};
    }
    return canonical.lexically_normal().string();
}

bool evidenceForPath(const std::string& path, DependencyEvidence& evidence,
                     std::string& error,
                     bool* volatile_preprocessor_input = nullptr) {
    evidence = {};
    evidence.canonical_path = path;
    evidence.content_sha256 =
        hashRegularFile(path, error, volatile_preprocessor_input);
    if (evidence.content_sha256.empty()) return false;

    const std::string sidecar = path + ".csk";
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(sidecar, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
        error = "cannot inspect dependency sidecar: " + sidecar;
        return false;
    }
    evidence.sidecar_exists =
        !ec && status.type() != std::filesystem::file_type::not_found;
    if (evidence.sidecar_exists) {
        evidence.sidecar_sha256 = hashRegularFile(sidecar, error);
        if (evidence.sidecar_sha256.empty()) return false;
    }
    return true;
}

bool readResponseFile(const std::string& path, std::string& contents,
                      std::string& error) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > kMaxResponseFileBytes) {
        error = "response-file dependency exceeds size limit: " + path;
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "cannot read response-file dependency: " + path;
        return false;
    }
    contents.assign(std::istreambuf_iterator<char>(input),
                    std::istreambuf_iterator<char>());
    if (input.bad()) {
        error = "failed while reading response-file dependency: " + path;
        return false;
    }
    return true;
}

using EvidenceMap = std::map<std::string, DependencyEvidence>;

bool addCommandInput(const std::string& value,
                     const std::filesystem::path& working_dir,
                     EvidenceMap& inputs, std::string& error) {
    const std::string canonical =
        canonicalCommandInput(value, working_dir, error);
    if (canonical.empty()) return false;
    if (inputs.count(canonical)) return true;
    DependencyEvidence evidence;
    if (!evidenceForPath(canonical, evidence, error)) return false;
    inputs.emplace(canonical, std::move(evidence));
    return true;
}

bool collectCommandArguments(const std::vector<std::string>& arguments,
                             const std::filesystem::path& working_dir,
                             EvidenceMap& inputs,
                             std::set<std::string>& active_responses,
                             unsigned depth, bool& volatile_input,
                             std::string& error);

bool addResponseFile(const std::string& value,
                     const std::filesystem::path& working_dir,
                     EvidenceMap& inputs,
                     std::set<std::string>& active_responses,
                     unsigned depth, bool& volatile_input,
                     std::string& error) {
    if (depth > kMaxResponseFileDepth) {
        error = "response-file dependency nesting exceeds limit";
        return false;
    }
    const std::string canonical =
        canonicalCommandInput(value, working_dir, error);
    if (canonical.empty()) return false;
    if (active_responses.count(canonical)) {
        error = "response-file dependency cycle: " + canonical;
        return false;
    }
    if (inputs.count(canonical)) return true;

    DependencyEvidence evidence;
    if (!evidenceForPath(canonical, evidence, error)) return false;
    std::string contents;
    if (!readResponseFile(canonical, contents, error)) return false;
    if (containsVolatilePreprocessorMarker(contents)) volatile_input = true;
    inputs.emplace(canonical, std::move(evidence));
    active_responses.insert(canonical);

    llvm::BumpPtrAllocator allocator;
    llvm::StringSaver saver(allocator);
    llvm::SmallVector<const char*, 32> tokens;
#ifdef _WIN32
    llvm::cl::TokenizeWindowsCommandLine(contents, saver, tokens);
#else
    llvm::cl::TokenizeGNUCommandLine(contents, saver, tokens);
#endif
    std::vector<std::string> nested;
    nested.reserve(tokens.size());
    for (const char* token : tokens) {
        if (token) nested.emplace_back(token);
    }
    const bool accepted = collectCommandArguments(
        nested, working_dir, inputs, active_responses, depth + 1,
        volatile_input, error);
    active_responses.erase(canonical);
    return accepted;
}

std::string moduleFilePath(std::string value) {
    const auto separator = value.rfind('=');
    if (separator != std::string::npos)
        value.erase(0, separator + 1);
    return value;
}

bool collectCommandArguments(const std::vector<std::string>& arguments,
                             const std::filesystem::path& working_dir,
                             EvidenceMap& inputs,
                             std::set<std::string>& active_responses,
                             unsigned depth, bool& volatile_input,
                             std::string& error) {
    static const std::set<std::string> separate_file_options = {
        "-include-pch", "-fmodule-file", "-fmodule-map-file",
        "-ivfsoverlay",
    };
    static const std::vector<std::string> joined_file_options = {
        "-include-pch=", "-fmodule-file=", "-fmodule-map-file=",
        "-ivfsoverlay=",
    };
    for (std::size_t i = 0; i < arguments.size(); ++i) {
        const auto& argument = arguments[i];
        if (containsVolatilePreprocessorMarker(argument))
            volatile_input = true;
        if (argument.size() > 1 && argument.front() == '@') {
            if (!addResponseFile(argument.substr(1), working_dir, inputs,
                                 active_responses, depth, volatile_input,
                                 error))
                return false;
            continue;
        }
        if (separate_file_options.count(argument)) {
            if (++i >= arguments.size()) {
                error = "compile-command file option lacks a value: " +
                        argument;
                return false;
            }
            std::string value = arguments[i];
            if (argument == "-fmodule-file")
                value = moduleFilePath(std::move(value));
            if (!addCommandInput(value, working_dir, inputs, error))
                return false;
            continue;
        }
        for (const auto& prefix : joined_file_options) {
            if (argument.rfind(prefix, 0) != 0) continue;
            std::string value = argument.substr(prefix.size());
            if (prefix == "-fmodule-file=")
                value = moduleFilePath(std::move(value));
            if (!addCommandInput(value, working_dir, inputs, error))
                return false;
            break;
        }
    }
    return true;
}

bool expandResponseArguments(const std::vector<std::string>& arguments,
                             const std::filesystem::path& working_dir,
                             std::set<std::string>& active_responses,
                             unsigned depth,
                             std::vector<std::string>& expanded,
                             std::string& error) {
    if (depth > kMaxResponseFileDepth) {
        error = "response-file dependency nesting exceeds limit";
        return false;
    }
    for (const auto& argument : arguments) {
        if (argument.size() <= 1 || argument.front() != '@') {
            expanded.push_back(argument);
            continue;
        }
        const std::string canonical = canonicalCommandInput(
            argument.substr(1), working_dir, error);
        if (canonical.empty()) return false;
        if (!active_responses.insert(canonical).second) {
            error = "response-file dependency cycle: " + canonical;
            return false;
        }
        std::string contents;
        if (!readResponseFile(canonical, contents, error)) {
            active_responses.erase(canonical);
            return false;
        }
        llvm::BumpPtrAllocator allocator;
        llvm::StringSaver saver(allocator);
        llvm::SmallVector<const char*, 32> tokens;
#ifdef _WIN32
        llvm::cl::TokenizeWindowsCommandLine(contents, saver, tokens);
#else
        llvm::cl::TokenizeGNUCommandLine(contents, saver, tokens);
#endif
        std::vector<std::string> nested;
        nested.reserve(tokens.size());
        for (const char* token : tokens) {
            if (token) nested.emplace_back(token);
        }
        const bool accepted = expandResponseArguments(
            nested, working_dir, active_responses, depth + 1,
            expanded, error);
        active_responses.erase(canonical);
        if (!accepted) return false;
    }
    return true;
}

bool buildDependencyManifest(const TranslationUnitExecution& unit,
                             DependencyManifest& manifest,
                             std::string& error) {
    manifest = {};
    manifest.toolchain_identity_sha256 = toolchainIdentitySha256();
    if (SourceManager::volatilePreprocessorBuiltinExpanded())
        manifest.cacheable = false;
    EvidenceMap files;
    for (const auto& path : SourceManager::dependencyFiles()) {
        if (files.count(path)) continue;
        DependencyEvidence evidence;
        bool volatile_input = false;
        if (!evidenceForPath(path, evidence, error, &volatile_input))
            return false;
        if (volatile_input) manifest.cacheable = false;
        files.emplace(path, std::move(evidence));
    }
    std::vector<DependencyEvidence> command_inputs;
    bool volatile_command_input = false;
    if (!collectCompileCommandDependencyEvidence(unit, command_inputs,
                                                 error,
                                                 &volatile_command_input))
        return false;
    if (volatile_command_input) manifest.cacheable = false;
    for (auto& evidence : command_inputs)
        files.emplace(evidence.canonical_path, std::move(evidence));
    if (files.empty()) {
        error = "worker parse produced no dependency evidence";
        return false;
    }
    for (auto& [path, evidence] : files)
        manifest.files.push_back(std::move(evidence));
    manifest.sha256 = dependencyManifestSha256(manifest);
    return true;
}

bool containsForbiddenControl(const std::vector<std::string>& args,
                              std::string& error) {
    static const std::set<std::string> forbidden = {
        "--source", "--build-path", "--json", "--sarif", "--html",
        "--baseline", "--write-baseline", "--files", "--serve",
        "--whole-program", "--summary-out", "--summary-diff",
        "--tu-timeout-seconds", "--tu-memory-mib", "--checkpoint-dir",
        "--help",
        "--version", "--capabilities",
    };
    for (const auto& argument : args) {
        if (forbidden.count(argument)) {
            error = "worker request contains parent-only option: " + argument;
            return true;
        }
    }
    return false;
}

bool writeCompilationDatabase(const std::filesystem::path& path,
                              const TranslationUnitExecution& unit,
                              std::string& error) {
    std::vector<std::string> expanded_arguments;
    std::set<std::string> active_responses;
    if (!expandResponseArguments(
            unit.command_line, unit.working_directory, active_responses, 0,
            expanded_arguments, error))
        return false;
    json::Array arguments;
    for (const auto& argument : expanded_arguments)
        arguments.push_back(argument);
    json::Array commands;
    commands.push_back(json::Object{
        {"directory", unit.working_directory},
        {"arguments", std::move(arguments)},
        {"file", unit.canonical_path},
        {"output", unit.output},
    });
    std::string text;
    llvm::raw_string_ostream stream(text);
    stream << json::Value(std::move(commands));
    stream.flush();
    text.push_back('\n');
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "cannot create exact worker compilation database";
        return false;
    }
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    output.flush();
    if (!output.good()) {
        error = "cannot write exact worker compilation database";
        return false;
    }
    return true;
}

bool parseWorkerConfig(const WorkerRequest& request,
                       const std::filesystem::path& root,
                       Config& config, std::string& error) {
    if (containsForbiddenControl(request.config_arguments, error)) return false;
    std::vector<std::string> storage{"codeskeptic-worker"};
    storage.insert(storage.end(), request.config_arguments.begin(),
                   request.config_arguments.end());
    storage.insert(storage.end(), {
        "--source", request.unit.canonical_path,
        "--build-path", root.string(),
        "--json", (root / "worker-analysis.json").string(),
    });
    if (!request.summary_fragment_path.empty()) {
        storage.push_back("--summary-out");
        storage.push_back(request.summary_fragment_path);
    }
    std::vector<char*> argv;
    argv.reserve(storage.size());
    for (auto& value : storage) argv.push_back(value.data());
    if (!config.parseArgs(static_cast<int>(argv.size()), argv.data())) {
        error = "worker request contains invalid analysis configuration";
        return false;
    }
    return true;
}

AnalysisResult harvestSummaries(const Config& config,
                                const std::string& summary_path) {
    AnalysisResult result;
    result.attempted_tus = 1;
    result.analyze_broken_tus = config.analyzeBrokenTUs();
    result.accept_partial_coverage = config.acceptPartialCoverage();

    // Constructing the environment applies the exact filters/models used by
    // analysis. Its own SourceManager is intentionally not run; the harvest
    // below owns the single exact command and saves before the environment's
    // destructor clears process-global summary state.
    StaticAnalyzer environment(config);
    SourceManager source(config.buildPath());
    source.addSourceFile(config.sourcePath());
    if (!source.compilationDatabaseValid()) {
        result.compile_database_failed = true;
        return result;
    }
    SourceManager::clearBrokenTUs();
    SourceManager::setAnalyzeBrokenTUs(config.analyzeBrokenTUs());
    SourceManager::setAttemptedTUCount(1);
    const int tool_result = source.processAll([&result](clang::ASTContext& ctx) {
        ++result.analyzed_tus;
        auto& registry = SummaryRegistry::instance();
        registry.rebuild(ctx);
        registry.harvestGlobal();
        registry.clear();
        CfgCache::instance().clear();
    });
    result.broken_tus = SourceManager::brokenTUs().size();
    if (tool_result != 0 && result.broken_tus == 0) result.tool_failed = true;
    if (!summary_path.empty() &&
        !SummaryRegistry::instance().saveGlobal(summary_path))
        result.summary_save_failed = true;
    return result;
}

AnalysisResult probeDependencies(const Config& config) {
    AnalysisResult result;
    result.attempted_tus = 1;
    result.analyze_broken_tus = config.analyzeBrokenTUs();
    result.accept_partial_coverage = config.acceptPartialCoverage();
    StaticAnalyzer environment(config);
    SourceManager source(config.buildPath());
    source.addSourceFile(config.sourcePath());
    if (!source.compilationDatabaseValid()) {
        result.compile_database_failed = true;
        return result;
    }
    SourceManager::clearBrokenTUs();
    SourceManager::setAnalyzeBrokenTUs(config.analyzeBrokenTUs());
    SourceManager::setAttemptedTUCount(1);
    const int tool_result = source.processAll(
        [&result](clang::ASTContext&) { ++result.analyzed_tus; });
    result.broken_tus = SourceManager::brokenTUs().size();
    if (tool_result != 0 && result.broken_tus == 0) result.tool_failed = true;
    return result;
}

} // anonymous namespace

bool collectCompileCommandDependencyEvidence(
    const TranslationUnitExecution& unit,
    std::vector<DependencyEvidence>& evidence, std::string& error,
    bool* volatile_preprocessor_input) {
    evidence.clear();
    error.clear();
    EvidenceMap inputs;
    std::set<std::string> active_responses;
    bool volatile_input = false;
    std::filesystem::path working_dir(unit.working_directory);
    if (working_dir.empty()) working_dir = std::filesystem::current_path();
    if (!collectCommandArguments(unit.command_line, working_dir, inputs,
                                 active_responses, 0, volatile_input, error))
        return false;
    evidence.reserve(inputs.size());
    for (auto& [path, item] : inputs)
        evidence.push_back(std::move(item));
    if (volatile_preprocessor_input)
        *volatile_preprocessor_input = volatile_input;
    return true;
}

int runTranslationUnitWorker(const std::string& request_path) {
    try {
        WorkerRequest request;
        std::string error;
        if (!readWorkerRequest(request_path, request, error)) {
            std::cerr << "[CodeSkeptic worker] " << error << "\n";
            return kProtocolFailureExitCode;
        }
        if (translationUnitCommandSha256(request.unit) !=
            request.unit.compile_command_sha256) {
            std::cerr << "[CodeSkeptic worker] compile-command identity drift\n";
            return kProtocolFailureExitCode;
        }
        const std::filesystem::path root =
            std::filesystem::path(request_path).parent_path();
        if (root.empty() ||
            !writeCompilationDatabase(root / "compile_commands.json",
                                      request.unit, error)) {
            std::cerr << "[CodeSkeptic worker] " << error << "\n";
            return kProtocolFailureExitCode;
        }
        Config config;
        if (!parseWorkerConfig(request, root, config, error)) {
            std::cerr << "[CodeSkeptic worker] " << error << "\n";
            return kProtocolFailureExitCode;
        }

        WorkerResponse response;
        response.request_id = request.request_id;
        response.canonical_path = request.unit.canonical_path;
        response.compile_command_sha256 =
            request.unit.compile_command_sha256;
        response.command_ordinal = request.unit.command_ordinal;
        response.phase = request.phase;

        SourceManager::clearDependencyFiles();

        if (request.phase == TranslationUnitPhase::DependencyProbe) {
            response.analysis = probeDependencies(config);
        } else if (request.phase == TranslationUnitPhase::SummaryHarvest) {
            response.analysis = harvestSummaries(
                config, request.summary_fragment_path);
        } else {
            StaticAnalyzer analyzer(std::move(config));
            registerDefaultRules(analyzer);
            response.analysis = analyzer.run();
            response.diagnostics = analyzer.diagnostics();
        }

        if (!response.analysis.hasHardFailure() &&
            !response.analysis.hasIncompleteEvidence() &&
            !buildDependencyManifest(request.unit, response.dependency_manifest,
                                     error)) {
            response.analysis.tool_failed = true;
            std::cerr << "[CodeSkeptic worker] " << error << "\n";
            error.clear();
        }

        if (!request.summary_fragment_path.empty() &&
            !response.analysis.summary_save_failed) {
            response.summary_fragment_sha256 =
                sha256File(request.summary_fragment_path, error);
            if (response.summary_fragment_sha256.empty()) {
                response.analysis.summary_save_failed = true;
                error.clear();
            }
        }
        if (!writeWorkerResponse(request.response_path, response, error)) {
            std::cerr << "[CodeSkeptic worker] " << error << "\n";
            return kResponseFailureExitCode;
        }
        return 0;
    } catch (const std::bad_alloc&) {
        return kMemoryLimitExitCode;
    } catch (const std::exception& exception) {
        std::cerr << "[CodeSkeptic worker] unhandled exception: "
                  << exception.what() << "\n";
        return kProtocolFailureExitCode;
    } catch (...) {
        std::cerr << "[CodeSkeptic worker] unknown unhandled exception\n";
        return kProtocolFailureExitCode;
    }
}

} // namespace codeskeptic
