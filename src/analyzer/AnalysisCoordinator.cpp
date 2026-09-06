#include "analyzer/AnalysisCoordinator.h"
#include "analyzer/AnalysisState.h"
#include "analyzer/BuiltinRules.h"
#include "core/Capabilities.h"
#include "core/FindingFingerprint.h"
#include "engine/CfgCache.h"
#include "engine/FunctionSummary.h"
#include "engine/RuleEngine.h"
#include "source_manager/SourceManager.h"
#include <llvm/ADT/SmallString.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Program.h>
#include <array>
#include <filesystem>
#include <iostream>
#include <optional>
#include <set>
#include <stdexcept>

namespace codeskeptic {
namespace {

std::string& configuredExecutable() {
    static std::string executable;
    return executable;
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        llvm::SmallString<256> directory;
        const auto error = llvm::sys::fs::createUniqueDirectory("codeskeptic-worker", directory);
        if (error) throw std::runtime_error("cannot create worker directory: " + error.message());
        path_ = directory.str().str();
    }
    ~TemporaryDirectory() {
        // Only the exact, newly created directory owned by this operation.
        // The synchronous launcher has reaped its child before destruction.
        std::error_code error;
        std::filesystem::remove_all(path_, error);
        if (error) std::cerr << "[CodeSkeptic] worker cleanup failed: " << error.message() << '\n';
    }
    std::string file(const char* name) const {
        return (std::filesystem::path(path_) / name).string();
    }
    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
private:
    std::string path_;
};

class FrozenWorkerDatabase : public clang::tooling::CompilationDatabase {
public:
    explicit FrozenWorkerDatabase(const WorkerRequest& request)
        : source_(request.source), commands_(request.commands) {}
    std::vector<clang::tooling::CompileCommand> getCompileCommands(llvm::StringRef file) const override {
        return file == source_ ? commands_ : std::vector<clang::tooling::CompileCommand>{};
    }
    std::vector<std::string> getAllFiles() const override { return {source_}; }
    std::vector<clang::tooling::CompileCommand> getAllCompileCommands() const override { return commands_; }
private:
    std::string source_;
    std::vector<clang::tooling::CompileCommand> commands_;
};

void check(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}

Config decodeAnalysisArguments(const WorkerRequest& request) {
    static const std::set<std::string> pairs = {
        "--lang", "--function", "--lines", "--fatal-asserts", "--assert-macros",
        "--negative-assert-macros", "--alloc-functions", "--free-functions",
        "--allocator-pairs", "--owning-pointers", "--untrusted-int-sources", "--policy",
    };
    static const std::set<std::string> flags = {
        "--assumptions", "--analyze-broken-tus", "--no-assert-recovery",
    };
    for (std::size_t i = 0; i < request.arguments.size(); ++i) {
        const auto& argument = request.arguments[i];
        if (flags.count(argument)) continue;
        check(pairs.count(argument) && i + 1 < request.arguments.size(), "invalid worker analysis option");
        ++i;
        check(request.arguments[i].find('\0') == std::string::npos, "NUL in worker analysis option");
    }
    std::vector<std::string> storage{"codeskeptic-worker"};
    storage.insert(storage.end(), request.arguments.begin(), request.arguments.end());
    std::vector<char*> arguments;
    for (auto& value : storage) arguments.push_back(value.data());
    Config config;
    check(config.parseArgs(static_cast<int>(arguments.size()), arguments.data()), "invalid resolved worker settings");
    return config;
}

} // namespace

void setWorkerExecutable(std::string executable) { configuredExecutable() = std::move(executable); }
const std::string& workerExecutable() { return configuredExecutable(); }

std::vector<std::string> workerAnalysisArguments(const Config& config) {
    std::vector<std::string> arguments{"--lang", config.lang()};
    auto names = [&](const char* option, const std::set<std::string>& values) {
        for (const auto& value : values) { arguments.emplace_back(option); arguments.push_back(value); }
    };
    names("--function", config.functions());
    names("--fatal-asserts", config.fatalAsserts());
    names("--assert-macros", config.assertMacros());
    names("--negative-assert-macros", config.negativeAssertMacros());
    names("--alloc-functions", config.allocFunctions());
    names("--free-functions", config.freeFunctions());
    names("--owning-pointers", config.owningPointers());
    names("--untrusted-int-sources", config.untrustedIntSources());
    names("--policy", config.policies());
    for (const auto& pair : config.allocatorPairs()) {
        for (const auto& free : pair.second) {
            arguments.emplace_back("--allocator-pairs");
            arguments.push_back(pair.first + "=" + free);
        }
    }
    for (const auto& range : config.lines()) {
        arguments.emplace_back("--lines");
        arguments.push_back(std::to_string(range.first) + "-" + std::to_string(range.second));
    }
    if (!config.assertRecovery()) arguments.emplace_back("--no-assert-recovery");
    if (config.analyzeBrokenTUs()) arguments.emplace_back("--analyze-broken-tus");
    if (config.assumptions()) arguments.emplace_back("--assumptions");
    return arguments;
}

bool exportWorkerSummaries(std::string& bytes, std::string& error) {
    try {
        TemporaryDirectory directory;
        const auto path = directory.file("summaries.txt");
        check(SummaryRegistry::instance().saveGlobal(path), "cannot export worker summaries");
        std::string candidate;
        check(readWorkerPacket(path, candidate, error), error);
        check(candidate.size() <= kWorkerFieldLimit, "worker summary exceeds transfer limit");
        std::map<std::string, SummaryRegistry::FunctionSummary> parsed;
        check(SummaryRegistry::parseSummaryFile(path, parsed), "exported worker summaries fail validation");
        check(parsed.size() == SummaryRegistry::instance().globalSize(), "worker summary export lost records");
        bytes = std::move(candidate);
        error.clear();
        return true;
    } catch (const std::exception& failure) {
        error = failure.what();
        return false;
    }
}

bool importWorkerSummaries(const std::string& bytes, std::string& error) {
    try {
        check(bytes.size() <= kWorkerFieldLimit, "worker summary exceeds transfer limit");
        TemporaryDirectory directory;
        const auto path = directory.file("summaries.txt");
        check(writeWorkerPacket(path, bytes, error), error);
        check(SummaryRegistry::instance().loadGlobal(path), "invalid worker summary snapshot");
        error.clear();
        return true;
    } catch (const std::exception& failure) {
        error = failure.what();
        return false;
    }
}

WorkerExecution executeAnalysisWorker(const std::string& executable, const WorkerRequest& request,
    const WorkerLimits& limits, const ResourceCancellation* cancellation) {
    WorkerExecution execution;
    execution.reason = "worker_transport_failed";
    try {
        check(!executable.empty(), "worker executable is not configured");
        check(validWorkerLimits(limits) && request.memory_mb == limits.memory_mb,
              "worker launch/request resource limit mismatch");
        const auto packet = encodeWorkerRequest(request);
        const auto digest = workerRequestDigest(packet);
        TemporaryDirectory directory;
        const auto input = directory.file("request.bin");
        const auto output = directory.file("response.bin");
        const auto stdout_path = directory.file("stdout.txt");
        const auto stderr_path = directory.file("stderr.txt");
        check(writeWorkerPacket(input, packet, execution.detail), execution.detail);
        const std::vector<std::string> arguments{executable, "--codeskeptic-worker-v1", input, output};
        const std::array<std::string, 3> redirects{{"", stdout_path, stderr_path}};
        const auto process = runResourceWorker(executable, arguments, redirects, limits, cancellation);
        switch (process.stop) {
        case ResourceStop::LaunchFailed: execution.reason = "worker_launch_failed"; break;
        case ResourceStop::Timeout: execution.reason = "worker_timeout"; break;
        case ResourceStop::Cancelled: execution.reason = "worker_cancelled"; break;
        case ResourceStop::Crashed: execution.reason = "worker_crashed"; break;
        case ResourceStop::SupervisionFailed: execution.reason = "worker_supervision_failed"; break;
        case ResourceStop::Exited:
            execution.reason = process.exit_code == 90 ? "worker_memory_limit_unavailable" :
                               process.exit_code == 91 ? "worker_memory_exhausted" : "worker_exit_nonzero";
            break;
        }
        execution.detail = process.detail;
        std::string diagnostic_text, read_error;
        const bool stderr_ok = readWorkerPacket(stderr_path, diagnostic_text, read_error);
        if (stderr_ok) execution.detail += diagnostic_text;
        if (process.stop != ResourceStop::Exited || process.exit_code != 0) {
            // Keep the actual timeout/cancellation/abnormal-exit classification
            // even when the interrupted process did not finish its stderr file.
            if (!stderr_ok) execution.detail += read_error;
            return execution;
        }
        execution.reason = "worker_result_invalid";
        check(stderr_ok, read_error);
        std::string acknowledgement;
        check(readWorkerPacket(output + ".limits", acknowledgement, read_error), read_error);
        check(acknowledgement == "codeskeptic-worker-memory/v1 " + std::to_string(request.memory_mb) + "\n",
              "worker did not acknowledge its memory limit");
        std::string stdout_text, response_packet;
        check(readWorkerPacket(stdout_path, stdout_text, read_error), read_error);
        check(stdout_text.empty(), "unexpected worker stdout");
        check(readWorkerPacket(output, response_packet, read_error), read_error);
        check(decodeWorkerResponse(response_packet, request, digest, execution.response, read_error), read_error);
        execution.valid = true;
        execution.reason.clear();
        return execution;
    } catch (const std::exception& failure) {
        execution.detail += failure.what();
        return execution;
    }
}

int runAnalysisWorker(const std::string& request_path, const std::string& response_path) {
    struct Cleanup { ~Cleanup() { clearAnalysisState(); } } cleanup;
    WorkerMemoryLimit memory_limit;
    bool memory_ready = false;
    try {
        check(!std::filesystem::exists(std::filesystem::symlink_status(response_path)),
              "worker output already exists");
        std::string packet, error;
        check(readWorkerPacket(request_path, packet, error), error);
        WorkerRequest request;
        check(decodeWorkerRequest(packet, request, error), error);
        if (!memory_limit.apply(request.memory_mb, error)) {
            std::cerr << "[CodeSkeptic] worker memory setup failed: " << error << '\n';
            return 90;
        }
        memory_ready = true;
        check(!std::filesystem::exists(std::filesystem::symlink_status(response_path + ".limits")),
              "worker limit acknowledgement already exists");
        check(writeWorkerPacket(response_path + ".limits",
              "codeskeptic-worker-memory/v1 " + std::to_string(request.memory_mb) + "\n", error), error);
        Config config = decodeAnalysisArguments(request);
        initializeAnalysisState(config);
        check(importWorkerSummaries(request.global_summaries, error), error);
        RuleEngine engine;
        for (const auto& producer : request.producers)
            check(addBuiltinRule(engine, producer), "worker cannot reconstruct custom producer: " + producer);
        const std::set<std::string> selected(request.selected_families.begin(), request.selected_families.end());
        for (const auto& family : selected) {
            const auto* capability = findRuleCapability(family);
            check(capability && capability->id == family, "unknown worker finding family");
        }
        engine.setDiagnosticSelector([&](const std::string& id) {
            const auto* capability = findRuleCapability(id);
            return !capability || selected.count(std::string(capability->id)) != 0;
        });
        check(request.phase == WorkerPhase::Harvest || engine.enabledRuleCount() > 0,
              "worker has no enabled producers");
        engine.enableGlobalHarvest(request.harvest);
        auto database = std::make_unique<FrozenWorkerDatabase>(request);
        // Even synthetic requests carry their already-frozen complete command.
        // Passing true here would replace it with a newly inferred database.
        SourceManager source(request.build_directory, std::move(database), false);
        check(source.addSourceFile(request.source), "worker source is unavailable");
        SourceManager::setAnalyzeBrokenTUs(config.analyzeBrokenTUs());
        SourceManager::clearBrokenTUs();
        SourceManager::setAttemptedTUCount(1);
        WorkerResponse response;
        response.request_digest = workerRequestDigest(packet);
        response.ordinal = request.ordinal;
        response.phase = request.phase;
        source.processAll([&](clang::ASTContext& context) {
            if (request.phase == WorkerPhase::Harvest) {
                auto& registry = SummaryRegistry::instance();
                registry.rebuild(context);
                registry.harvestGlobal();
                registry.clear();
                CfgCache::instance().clear();
            } else {
                auto diagnostics = engine.runAll(context);
                bindBaselineFunctions(context, diagnostics);
                response.diagnostics.insert(response.diagnostics.end(), diagnostics.begin(), diagnostics.end());
            }
        });
        check(source.coverage().size() == 1, "worker did not account for its source");
        response.coverage = source.coverage().front();
        response.gaps = CoverageReport::instance().entries();
        check(exportWorkerSummaries(response.global_summaries, error), error);
        check(writeWorkerPacket(response_path, encodeWorkerResponse(response), error), error);
        return 0; // Transport succeeded; source coverage may still describe failure.
    } catch (const std::bad_alloc&) {
        std::cerr << "[CodeSkeptic] worker allocation failed\n";
        return memory_ready ? 91 : 2;
    } catch (const std::exception& failure) {
        std::cerr << "[CodeSkeptic] worker failed: " << failure.what() << '\n';
        return 2;
    }
}

} // namespace codeskeptic
