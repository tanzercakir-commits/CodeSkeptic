#include "analyzer/WorkerRuntime.h"

#include "analyzer/DefaultRules.h"
#include "analyzer/StaticAnalyzer.h"
#include "analyzer/WorkerProtocol.h"
#include "config/Config.h"
#include "engine/CfgCache.h"
#include "engine/FunctionSummary.h"
#include "source_manager/SourceManager.h"

#include <clang/AST/ASTContext.h>
#include <clang/Basic/SourceManager.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <new>
#include <set>
#include <vector>

namespace codeskeptic {

namespace json = llvm::json;

namespace {

constexpr int kMemoryLimitExitCode = 86;
constexpr int kProtocolFailureExitCode = 70;
constexpr int kResponseFailureExitCode = 71;

bool containsForbiddenControl(const std::vector<std::string>& args,
                              std::string& error) {
    static const std::set<std::string> forbidden = {
        "--source", "--build-path", "--json", "--sarif", "--html",
        "--baseline", "--write-baseline", "--files", "--serve",
        "--whole-program", "--summary-out", "--summary-diff",
        "--tu-timeout-seconds", "--tu-memory-mib", "--help",
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
    json::Array arguments;
    for (const auto& argument : unit.command_line)
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

} // anonymous namespace

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

        if (request.phase == TranslationUnitPhase::SummaryHarvest) {
            response.analysis = harvestSummaries(
                config, request.summary_fragment_path);
        } else {
            StaticAnalyzer analyzer(std::move(config));
            registerDefaultRules(analyzer);
            response.analysis = analyzer.run();
            response.diagnostics = analyzer.diagnostics();
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
