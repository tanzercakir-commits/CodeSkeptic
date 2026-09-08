#include "analyzer/StaticAnalyzer.h"
#include "analyzer/AnalysisState.h"
#include "analyzer/AnalysisCoordinator.h"
#include "analyzer/CheckpointTime.h"
#include "source_manager/CompilationDatabaseDiscovery.h"

#include "analyzer/Baseline.h"
#include "analyzer/SuppressionFilter.h"
#include "core/Capabilities.h"
#include "core/FindingFingerprint.h"
#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "contracts/Policy.h"
#include "contracts/Sidecar.h"
#include "engine/AllocFunctions.h"
#include "engine/AssertGuards.h"
#include "engine/AssumptionMode.h"
#include "engine/CfgCache.h"
#include "engine/CoverageReport.h"
#include "engine/FatalCalls.h"
#include "engine/FunctionSummary.h"
#include "engine/ImmutableFlags.h"
#include "engine/ParamIntervals.h"
#include "reporter/ConsoleReporter.h"
#include "reporter/HtmlReporter.h"
#include "reporter/JsonReporter.h"
#include "reporter/SarifReporter.h"
#include "reporter/Coverage.h"
#include "reporter/ReportContract.h"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <set>
#include <stdexcept>
#include "source_manager/InputIdentity.h"

namespace codeskeptic {

namespace {

void setFindingCounts(AnalysisResult& result,
                      const DiagnosticList& diagnostics) {
    result.findings = diagnostics.size();
    result.report_only_findings = static_cast<std::size_t>(std::count_if(
        diagnostics.begin(), diagnostics.end(), [](const Diagnostic& diag) {
            return !findingBlocksVerdict(diag.rule_id);
        }));
}

void checkpointRequire(bool condition, const std::string& reason) {
    if (!condition) throw std::runtime_error(reason);
}
void checkpointField(std::string& bytes, const std::string& value) {
    constexpr auto limit = kWorkerPacketLimit - 80;
    checkpointRequire(value.size() <= limit - 4 && bytes.size() <= limit - 4 - value.size(), "checkpoint_capacity");
    const auto size = static_cast<std::uint32_t>(value.size());
    for (unsigned i = 0; i < 4; ++i) bytes += static_cast<char>((size >> (8 * i)) & 255);
    bytes += value;
}
class CheckpointReader {
public:
    explicit CheckpointReader(const std::string& bytes) : bytes_(bytes) {
        checkpointRequire(bytes.size() <= kWorkerPacketLimit - 80, "checkpoint_capacity");
    }
    std::string field() {
        checkpointRequire(bytes_.size() - at_ >= 4, "checkpoint_truncated");
        std::uint32_t size = 0;
        for (unsigned i = 0; i < 4; ++i)
            size |= std::uint32_t(static_cast<unsigned char>(bytes_[at_++])) << (8 * i);
        checkpointRequire(size <= bytes_.size() - at_, "checkpoint_truncated");
        auto result = bytes_.substr(at_, size); at_ += size;
        return result;
    }
    std::size_t count(std::size_t maximum) {
        const auto value = field();
        checkpointRequire(!value.empty() && value.size() <= 5 &&
                          value.find_first_not_of("0123456789") == std::string::npos &&
                          (value.size() == 1 || value.front() != '0'), "checkpoint_count_invalid");
        const auto count = static_cast<std::size_t>(std::stoul(value));
        checkpointRequire(count <= maximum, "checkpoint_count_invalid");
        return count;
    }
    void finish() { checkpointRequire(at_ == bytes_.size(), "checkpoint_trailing_data"); }
private:
    const std::string& bytes_;
    std::size_t at_ = 0;
};

std::string checkpointParentIdentity(const Config& config, const std::vector<WorkerRequest>& requests,
                                     const std::string& database, const std::function<bool()>& cancelled) {
    std::string identity;
    checkpointField(identity, config.checkpointSettings());
    checkpointField(identity, std::filesystem::current_path().string());
    checkpointField(identity, inputEnvironmentIdentity());
    std::size_t consumed = 0;
    auto file = [&](const std::string& path, const std::string* expected = nullptr) {
        checkpointRequire(!cancelled(), "checkpoint_cancelled");
        const auto canonical = std::filesystem::weakly_canonical(path).string();
        checkpointField(identity, path); checkpointField(identity, canonical);
        const auto status = std::filesystem::symlink_status(path);
        if (!std::filesystem::exists(status)) {
            checkpointRequire(expected && *expected == "absent", "checkpoint_input_missing");
            checkpointField(identity, "absent");
            return;
        }
        std::string bytes, error;
        checkpointRequire(std::filesystem::is_regular_file(status) && readWorkerPacket(path, bytes, error),
                          "checkpoint_input_unreadable: " + path);
        checkpointRequire(bytes.size() <= kInputBufferLimit && consumed <= kInputTotalBufferLimit - bytes.size(),
                          "checkpoint_input_capacity");
        consumed += bytes.size();
        const auto digest = inputDigest(bytes);
        checkpointRequire(!expected || *expected == digest, "checkpoint_config_changed");
        checkpointField(identity, digest);
        checkpointField(identity, checkpointTickIdentity(std::filesystem::last_write_time(path).time_since_epoch().count()));
    };
    for (const auto& input : config.configurationInputs()) file(input.first, &input.second);
    if (!database.empty()) file(database);
    for (const auto& path : config.modelFiles()) file(path);
    if (!config.summaryIn().empty()) {
        file(config.summaryIn());
        for (const auto& request : requests)
            checkpointField(identity, checkpointTickIdentity(std::filesystem::last_write_time(request.source).time_since_epoch().count()));
    }
    if (config.writeBaselinePath().empty() && !config.baselinePath().empty()) file(config.baselinePath());
    for (const auto& path : config.reportPaths()) {
        std::error_code error;
        const auto canonical = std::filesystem::weakly_canonical(path, error);
        checkpointField(identity, (error ? std::filesystem::path(path) : canonical).lexically_normal().string());
    }
    for (const auto& output : {config.jsonOutputPath(), config.sarifOutputPath(), config.htmlOutputPath(),
                               config.summaryOut(), config.writeBaselinePath()})
        if (!output.empty()) checkpointField(identity, std::filesystem::weakly_canonical(output).string());
    return inputDigest(identity);
}

} // namespace

// A manifest stores a complete input inventory plus a prefix of successfully
// qualified workers. There is deliberately no persisted "run DONE" flag: all
// parent filters, output writes and verdict checks run again after replay.
class RunCheckpoint {
    struct Record { std::string request, response; };
public:
    RunCheckpoint(const Config& config, std::string executable,
                  const std::vector<WorkerRequest>& requests, std::vector<std::string> producers,
                  std::string parent_identity, std::string database)
        : config_(config), executable_(std::move(executable)), requests_(requests),
          producers_(std::move(producers)), parent_identity_(std::move(parent_identity)), database_(std::move(database)),
          store_(config.checkpointDirectory(), config.checkpointBytes()) {}

    bool prepare(const std::string& summaries) {
        try {
            checkpointRequire(!executable_.empty() && !requests_.empty() &&
                              requests_.size() <= config_.checkpointUnits(), "checkpoint_unit_capacity");
            checkpointRequire(!config_.analysisCache() && !config_.serve() && !config_.doctor() &&
                              config_.summaryDiffOld().empty(), "checkpoint_mode_conflict");
            tool_identity_ = workerExecutableIdentity(executable_, cancellation());
            checkpointRequire(!tool_identity_.empty(), "checkpoint_tool_unavailable");
            std::string identity;
            checkpointField(identity, parent_identity_); checkpointField(identity, tool_identity_);
            for (const auto& frozen : requests_) {
                auto request = makeRequest(frozen.ordinal, WorkerPhase::Snapshot, summaries);
                checkpointField(identity, encodeWorkerRequest(request));
            }
            identity_ = inputDigest(identity);
            std::string payload;
            const bool opened = store_.open(config_.resumeCheckpoint(), payload, cancellation());
            checkpointRequire(opened, "checkpoint_" + store_.state());
            if (config_.resumeCheckpoint()) {
                decode(payload, summaries);
                validateInputs(); // All pending and completed inputs before any replay.
                for (const auto& record : snapshots_) {
                    WorkerRequest request; std::string error;
                    checkpointRequire(decodeWorkerRequest(record.request, request, error), "checkpoint_request_invalid");
                    const auto execution = executeAnalysisWorker(executable_, request, config_.workerLimits(),
                        config_.resourceCancellation(), nullptr, &record.response, true);
                    checkpointRequire(execution.valid && execution.cache_hit, "checkpoint_snapshot_rejected: " + execution.reason + execution.detail);
                }
            } else {
                for (const auto& frozen : requests_) {
                    const auto request = makeRequest(frozen.ordinal, WorkerPhase::Snapshot, summaries);
                    const auto execution = executeAnalysisWorker(executable_, request, config_.workerLimits(),
                        config_.resourceCancellation(), nullptr, nullptr, true);
                    checkpointRequire(execution.valid && execution.detail.empty() && reusableWorkerResponse(request, execution.response),
                                      "checkpoint_snapshot_unavailable: " + execution.reason + execution.detail);
                    snapshots_.push_back({encodeWorkerRequest(request), encodeWorkerResponse(execution.response)});
                    encode(); // Refuse total capacity before collecting another TU.
                }
                validateInputs();
                persist();
            }
            validateInputs();
            std::cerr << "[CodeSkeptic] checkpoint: ready units=" << requests_.size()
                      << " saved_workers=" << completed_.size() << '\n';
            return true;
        } catch (const std::exception& failure) { fail(failure.what()); return false; }
    }

    WorkerExecution execute(const WorkerRequest& request) {
        WorkerExecution execution;
        execution.reason = "checkpoint_not_processed";
        if (failed_) return execution;
        try {
            validateInputs();
            const auto expected = makeRequest(position_ % requests_.size(),
                config_.wholeProgram() && position_ < requests_.size() ? WorkerPhase::Harvest : WorkerPhase::Analyze,
                request.global_summaries);
            const auto packet = encodeWorkerRequest(request);
            checkpointRequire(position_ < requests_.size() * (config_.wholeProgram() ? 2 : 1) &&
                              packet == encodeWorkerRequest(expected), "checkpoint_worker_order_changed");
            const bool replay = position_ < completed_.size();
            if (replay) checkpointRequire(packet == completed_[position_].request, "checkpoint_incoming_state_changed");
            execution = executeAnalysisWorker(executable_, request, config_.workerLimits(), config_.resourceCancellation(),
                nullptr, replay ? &completed_[position_].response : nullptr, true);
            checkpointRequire(execution.valid && execution.detail.empty() && reusableWorkerResponse(request, execution.response),
                              "checkpoint_worker_incomplete: " + execution.reason + execution.detail);
            WorkerResponse snapshot; std::string error;
            const auto& inventory = snapshots_[request.ordinal];
            WorkerRequest snapshot_request;
            checkpointRequire(decodeWorkerRequest(inventory.request, snapshot_request, error) &&
                decodeWorkerResponse(inventory.response, snapshot_request, workerRequestDigest(inventory.request), snapshot, error) &&
                snapshot.runtime_digest == execution.response.runtime_digest, "checkpoint_runtime_changed");
            validateInputs();
            if (!replay) {
                completed_.push_back({packet, encodeWorkerResponse(execution.response)});
                persist();
            }
            ++position_;
            std::cerr << "[CodeSkeptic] checkpoint: " << (replay ? "replayed" : "saved")
                      << " worker=" << position_ << '/' << requests_.size() * (config_.wholeProgram() ? 2 : 1) << '\n';
            return execution;
        } catch (const std::exception& failure) {
            fail(failure.what()); execution.valid = false; execution.cache_hit = false;
            execution.reason = "checkpoint_rejected"; return execution;
        }
    }
    bool finish() {
        if (failed_) return false;
        try {
            checkpointRequire(position_ == requests_.size() * (config_.wholeProgram() ? 2 : 1), "checkpoint_missing_workers");
            validateInputs(); return true;
        } catch (const std::exception& failure) { fail(failure.what()); return false; }
    }
private:
    std::function<bool()> cancellation() const {
        return [this] { return workerSignalCancellationRequested() ||
            (config_.resourceCancellation() && config_.resourceCancellation()->requested()); };
    }
    WorkerRequest makeRequest(std::size_t ordinal, WorkerPhase phase, const std::string& summaries) const {
        auto request = requests_.at(ordinal);
        request.phase = phase; request.record_inputs = true; request.producers = producers_;
        request.harvest = phase != WorkerPhase::Snapshot && !config_.summaryOut().empty();
        request.global_summaries = summaries;
        return request;
    }
    void validateInputs() const {
        checkpointRequire(checkpointParentIdentity(config_, requests_, database_, cancellation()) == parent_identity_, "checkpoint_parent_input_changed");
        checkpointRequire(workerExecutableIdentity(executable_, cancellation()) == tool_identity_, "checkpoint_tool_changed");
        std::set<std::string> inputs;
        if (!database_.empty()) inputs.insert(database_);
        for (const auto& request : requests_) inputs.insert(request.source);
        for (const auto& entry : config_.configurationInputs()) inputs.insert(entry.first);
        inputs.insert(config_.modelFiles().begin(), config_.modelFiles().end());
        if (!config_.summaryIn().empty()) inputs.insert(config_.summaryIn());
        if (config_.writeBaselinePath().empty() && !config_.baselinePath().empty()) inputs.insert(config_.baselinePath());
        for (const auto* records : {&snapshots_, &completed_}) for (const auto& record : *records) {
            WorkerRequest request; WorkerResponse response; InputIdentity input; std::string error;
            checkpointRequire(decodeWorkerRequest(record.request, request, error) &&
                decodeWorkerResponse(record.response, request, workerRequestDigest(record.request), response, error) &&
                reusableWorkerResponse(request, response) && decodeInputIdentity(response.input_witness, input) &&
                input.matchesCurrent(cancellation()), "checkpoint_source_input_changed");
            for (const auto& observation : input.observations)
                if (observation.kind != InputObservationKind::Frontend) inputs.insert(observation.path);
        }
        std::vector<std::string> prior_outputs;
        for (const auto& output : {config_.jsonOutputPath(), config_.sarifOutputPath(), config_.htmlOutputPath(),
                                   config_.summaryOut(), config_.writeBaselinePath()}) {
            if (output.empty()) continue;
            const auto canonical = std::filesystem::weakly_canonical(output);
            for (const auto& prior : prior_outputs) {
                std::error_code error;
                const bool alias = std::filesystem::equivalent(prior, output, error);
                checkpointRequire(std::filesystem::weakly_canonical(prior) != canonical && (error || !alias),
                                  "checkpoint_output_aliases_output");
            }
            prior_outputs.push_back(output);
            for (const auto& input : inputs) {
                std::error_code error;
                const auto target = std::filesystem::weakly_canonical(input, error);
                checkpointRequire(error || target != canonical, "checkpoint_output_aliases_input");
                error.clear();
                const bool alias = std::filesystem::equivalent(input, output, error);
                checkpointRequire(error || !alias, "checkpoint_output_aliases_input");
            }
            const auto root = std::filesystem::path(config_.checkpointDirectory()).lexically_normal();
            const auto mismatch = std::mismatch(root.begin(), root.end(), canonical.begin(), canonical.end());
            checkpointRequire(mismatch.first != root.end(), "checkpoint_output_aliases_storage");
        }
    }
    std::string encode() const {
        std::string bytes;
        checkpointField(bytes, "codeskeptic-run-checkpoint/v1"); checkpointField(bytes, identity_);
        for (const auto* records : {&snapshots_, &completed_}) {
            checkpointField(bytes, std::to_string(records->size()));
            for (const auto& record : *records) { checkpointField(bytes, record.request); checkpointField(bytes, record.response); }
        }
        return bytes;
    }
    void decode(const std::string& bytes, const std::string& summaries) {
        CheckpointReader reader(bytes);
        checkpointRequire(reader.field() == "codeskeptic-run-checkpoint/v1" && reader.field() == identity_, "checkpoint_run_identity_changed");
        std::vector<Record> snapshots, completed;
        const auto snapshot_count = reader.count(config_.checkpointUnits());
        checkpointRequire(snapshot_count == requests_.size(), "checkpoint_snapshot_missing");
        for (std::size_t i = 0; i < snapshot_count; ++i) {
            Record record{reader.field(), reader.field()};
            checkpointRequire(record.request == encodeWorkerRequest(makeRequest(i, WorkerPhase::Snapshot, summaries)), "checkpoint_snapshot_request_changed");
            snapshots.push_back(std::move(record));
        }
        const auto count = reader.count(requests_.size() * (config_.wholeProgram() ? 2 : 1));
        for (std::size_t i = 0; i < count; ++i) {
            Record record{reader.field(), reader.field()};
            WorkerRequest request; std::string error;
            checkpointRequire(decodeWorkerRequest(record.request, request, error), "checkpoint_completed_request_invalid");
            const auto expected = makeRequest(i % requests_.size(), config_.wholeProgram() && i < requests_.size() ?
                WorkerPhase::Harvest : WorkerPhase::Analyze, request.global_summaries);
            checkpointRequire(record.request == encodeWorkerRequest(expected), "checkpoint_completed_order_invalid");
            completed.push_back(std::move(record));
        }
        reader.finish();
        snapshots_ = std::move(snapshots); completed_ = std::move(completed);
    }
    void persist() {
        const auto saved = store_.save(encode(), cancellation());
        checkpointRequire(saved == DiskWriteResult::Committed, "checkpoint_" + store_.state());
    }
    void fail(const std::string& reason) {
        failed_ = true;
        std::cerr << "[CodeSkeptic] checkpoint rejected: " << reason << '\n';
    }
    const Config& config_;
    const std::string executable_;
    const std::vector<WorkerRequest>& requests_;
    const std::vector<std::string> producers_;
    const std::string parent_identity_;
    const std::string database_;
    CheckpointStore store_;
    std::string identity_, tool_identity_;
    std::vector<Record> snapshots_, completed_;
    std::size_t position_ = 0;
    bool failed_ = false;
};

void clearAnalysisState() {
    setFunctionFilter({});
    setLineRanges({});
    setFatalCallNames({});
    setAssertRecoveryEnabled(true);
    setExtraAssertMacros({});
    setNegativeAssertMacros({});
    setAllocFunctionNames({});
    setFreeFunctionNames({});
    setAllocatorPairs({});
    setOwningPointerNames({});
    setUntrustedIntSourceNames({});
    setAssumptionMode(false);
    SummaryRegistry::instance().clearGlobal();
    // A rule exception skips RuleEngine's normal per-TU cleanup. Clear local
    // pointer-keyed stores too, before a later request sees a different AST.
    SummaryRegistry::instance().clear();
    ParamIntervalCache::instance().clear();
    ImmutableFlagCache::instance().clear();
    CfgCache::instance().clear();
    AssertGuardCache::instance().clear();
    CoverageReport::instance().clear();
}

void initializeAnalysisState(const Config& config) {
    setLang(parseLang(config.lang()));
    setFunctionFilter(config.functions());
    setLineRanges(config.lines());
    setFatalCallNames(config.fatalAsserts());
    setAssertRecoveryEnabled(config.assertRecovery());
    setExtraAssertMacros(config.assertMacros());
    setNegativeAssertMacros(config.negativeAssertMacros());
    setAllocFunctionNames(config.allocFunctions());
    setFreeFunctionNames(config.freeFunctions());
    setAllocatorPairs(config.allocatorPairs());
    setOwningPointerNames(config.owningPointers());
    setUntrustedIntSourceNames(config.untrustedIntSources());
    setProfilePolicies(config.policies());
    setAssumptionMode(config.assumptions());
    clearSidecarCache();
    CoverageReport::instance().clear();
}

std::size_t StaticAnalyzer::totalTUs() const {
    return source_mgr_ ? source_mgr_->fileCount() : 0;
}

std::size_t StaticAnalyzer::brokenTUCount() const {
    return SourceManager::brokenTUs().size();
}


StaticAnalyzer::StaticAnalyzer(Config config)
    try : config_(std::move(config)) {
    // Sidecar contracts are cached per file path for the process
    // lifetime; a new analyzer run re-reads them (the MCP server
    // lives long — an edited .csk must be seen).
    // Coverage gaps belong to a single run; a long-lived process (the
    // MCP server) must not inherit the previous run's non-convergence.
    initializeAnalysisState(config_);

    auto selection = discoverCompilationDatabase(config_);
    compilation_input_ready_ = selection.ready;
    compilation_database_ = selection.database;
    writeCompilationDoctor(selection, std::cerr);
    const auto buildDirectory = selection.database.empty() ? "." :
        std::filesystem::path(selection.database).parent_path().string();
    worker_executable_ = workerExecutable();
    if (!worker_executable_.empty() && selection.ready) {
        // Discovery already freezes canonical, sorted files and expanded command
        // variants. Capture them before moving the database, not after a second
        // lookup in a child with a potentially changed project configuration.
        for (const auto& file : selection.files) {
            WorkerRequest request;
            request.ordinal = static_cast<std::uint32_t>(worker_requests_.size());
            request.source = file;
            request.build_directory = buildDirectory;
            request.synthetic = selection.synthetic;
            if (selection.synthetic) {
                // The no-database selection intentionally owns no DB object.
                // Freeze the existing documented single-file GNU11/C++17
                // recipe here; the child must not rediscover or replace it.
                const bool is_c = std::filesystem::path(file).extension() == ".c";
                std::vector<std::string> arguments = is_c
                    ? std::vector<std::string>{"clang", "-x", "c", "-std=gnu11"}
                    : std::vector<std::string>{"clang++", "-std=c++17"};
                arguments.insert(arguments.end(), {"-fsyntax-only", file});
                request.commands.emplace_back(".", file, std::move(arguments), "");
            } else {
                request.commands = selection.commands->getCompileCommands(file);
            }
            request.arguments = workerAnalysisArguments(config_);
            request.memory_mb = config_.workerLimits().memory_mb;
            for (const auto& family : ruleCapabilities()) {
                const std::string id(family.id);
                if ((id != "assumption" || config_.assumptions()) && config_.isRuleEnabled(id))
                    request.selected_families.push_back(id);
            }
            worker_requests_.push_back(std::move(request));
        }
    }
    source_mgr_ = std::make_unique<SourceManager>(
        buildDirectory, std::move(selection.commands), selection.synthetic);
    if (config_.warmCache()) source_mgr_->enableWarmCache(true);
    for (const auto& file : selection.files) {
        SourceCoverage source{file};
        source.reason = selection.ready ? "not_processed"
                                        : "compilation_input_unavailable";
        if (!llvm::json::isUTF8(file)) {
            source.reason = "source_path_not_utf8";
            compilation_input_ready_ = false;
        } else if (!selection.ready) {
            std::error_code error;
            if (!std::filesystem::is_regular_file(file, error))
                source.reason = error ? "source_identity_unavailable" : "source_unavailable";
        }
        requested_sources_.push_back(std::move(source));
        if (selection.ready && llvm::json::isUTF8(file) && !source_mgr_->addSourceFile(file)) {
            requested_sources_.back().reason = "source_unavailable";
            compilation_input_ready_ = false;
        }
    }

    if (config_.outputFormat() == "json") {
        reporter_ = std::make_unique<JsonReporter>(config_.jsonOutputPath());
    } else if (config_.outputFormat() == "sarif") {
        reporter_ = std::make_unique<SarifReporter>(config_.sarifOutputPath());
    } else if (config_.outputFormat() == "html") {
        reporter_ = std::make_unique<HtmlReporter>(config_.htmlOutputPath());
    } else {
        reporter_ = std::make_unique<ConsoleReporter>();
    }
} catch (...) {
    // A failed constructor has no destructor. Its published request globals
    // need the same cleanup as a completed or exceptionally unwound analyzer.
    clearAnalysisState();
    throw;
}

StaticAnalyzer::~StaticAnalyzer() {
    // Keep global filter state bounded by this analysis's lifetime: in
    // a long-lived process (MCP server) a filtered run must not
    // silently prune later ones. (In tests the same leak broke 11 of
    // InterproceduralTest's tests — ctest's per-process isolation had
    // been hiding it.)
    clearAnalysisState();
}

std::vector<SourceCoverage> StaticAnalyzer::processIsolated(bool prepass) {
    std::vector<SourceCoverage> coverage;
    for (const auto& frozen : worker_requests_) {
        WorkerRequest request = frozen;
        request.phase = prepass ? WorkerPhase::Harvest : WorkerPhase::Analyze;
        request.harvest = !config_.summaryOut().empty();
        request.producers = engine_.ruleIds();
        request.record_inputs = config_.analysisCache() || checkpoint_ != nullptr;
        SourceCoverage failed{request.source};
        failed.commands = failed.failed_commands = request.commands.size();
        failed.reason = "worker_summary_export_failed";
        std::string error;
        const bool stopping = workerSignalCancellationRequested() ||
            (config_.resourceCancellation() && config_.resourceCancellation()->requested());
        if (!stopping && !exportWorkerSummaries(request.global_summaries, error)) {
            std::cerr << "[CodeSkeptic] worker summary export failed: " << error << '\n';
            coverage.push_back(std::move(failed));
            continue;
        }
        auto execution = checkpoint_ ? checkpoint_->execute(request) :
            executeAnalysisWorker(worker_executable_, request, config_.workerLimits(),
                                  config_.resourceCancellation(), disk_cache_.get());
        if (!execution.detail.empty()) std::cerr << execution.detail << '\n';
        if (!execution.valid) {
            failed.reason = execution.reason;
            std::cerr << "[CodeSkeptic] " << execution.reason << ": " << request.source << '\n';
            coverage.push_back(std::move(failed));
            continue;
        }
        // The response has been fully decoded and bound to this exact request.
        // Import its rolling state before allowing another source to consume it.
        if (!importWorkerSummaries(execution.response.global_summaries, error)) {
            failed.reason = "worker_summary_import_failed";
            std::cerr << "[CodeSkeptic] worker summary import failed: " << error << '\n';
            coverage.push_back(std::move(failed));
            continue;
        }
        auto& response = execution.response;
        if (response.coverage.skipped_commands > 0)
            SourceManager::recordBrokenTU(request.source);
        for (const auto& gap : response.gaps) {
            if (gap.gap == CoverageGap::CfgUnavailable)
                CoverageReport::instance().recordCfgUnavailable(gap.function);
            else CoverageReport::instance().recordNonConvergence(gap.function);
        }
        diagnostics_.insert(diagnostics_.end(), response.diagnostics.begin(), response.diagnostics.end());
        coverage.push_back(std::move(response.coverage));
    }
    return coverage;
}

AnalysisResult StaticAnalyzer::run() {
    checkpoint_.reset();
    disk_cache_.reset();
    if (config_.analysisCache() && !config_.analysisCacheDirectory().empty())
        disk_cache_ = std::make_unique<DiskEvidenceStore>(config_.analysisCacheDirectory(),
            config_.analysisCacheBytes(), config_.analysisCacheEntries());
    // Parent-only advisory on every return/exception. Never writes worker
    // stdout or execution.detail and never changes report/exit semantics.
    struct StorageSummary {
        DiskEvidenceStore* store;
        ~StorageSummary() {
            if (!store) return;
            const auto s = store->status();
            std::cerr << "[CodeSkeptic] disk-cache: state=" << s.state
                      << " candidates=" << s.candidates << " hits=" << s.hits
                      << " writes=" << s.writes << " evictions=" << s.evictions
                      << " recovered=" << s.recovered << " rejected=" << s.rejected
                      << " errors=" << s.errors << " capacity=" << s.capacity
                      << " busy=" << s.busy << " bytes=" << s.bytes << " entries=" << s.entries << '\n';
        }
    } storage_summary{disk_cache_.get()};
    diagnostics_.clear();
    AnalysisResult result;
    result.sources = requested_sources_;
    result.reconcileSources();
    result.analyze_broken_tus = config_.analyzeBrokenTUs();
    result.accept_partial_coverage = config_.acceptPartialCoverage();
    CoverageReport::instance().clear();
    SourceManager::setAnalyzeBrokenTUs(config_.analyzeBrokenTUs());
    SourceManager::clearBrokenTUs();
    SourceManager::setAttemptedTUCount(result.attempted_tus);
    auto finishReport = [&] {
        if (!reporter_->report(diagnostics_, &result)) result.report_write_failed = true;
        writeCoverageConsole(std::cerr, result);
        return result;
    };
    auto rejectCheckpoint = [&](const std::string& reason) {
        diagnostics_.clear();
        result.tool_failed = true;
        for (auto& source : result.sources) {
            source.status = SourceStatus::Failed; source.reason = "checkpoint_rejected";
            source.commands = std::max<std::size_t>(1, source.commands);
            source.failed_commands = source.commands;
            source.analyzed_commands = source.skipped_commands = source.recovery_commands = 0;
        }
        result.reconcileSources();
        std::cerr << "[CodeSkeptic] checkpoint rejected: " << reason << '\n';
        // Rejection must not open a report/baseline/summary path: it may alias
        // precisely the input whose invalidation caused the refusal.
        writeCoverageConsole(std::cerr, result);
        return result;
    };
    const bool checkpoint_requested = !config_.checkpointDirectory().empty() || config_.resumeCheckpoint();

    if (!compilation_input_ready_) {
        result.tool_failed = true;
        if (checkpoint_requested) return rejectCheckpoint("checkpoint_compilation_input_unavailable");
        return finishReport();
    }

    if (source_mgr_->fileCount() == 0) {
        // Analyzing nothing must not look like a clean pass: a mistyped
        // path or a relative-path file list would otherwise print
        // "Clean!" with exit 0.
        std::cerr << msg(MsgId::NoFilesToAnalyze) << "\n";
        result.no_inputs = true;
        if (checkpoint_requested) return rejectCheckpoint("checkpoint_no_inputs");
        return finishReport();
    }

    if (engine_.ruleCount() == 0) {
        std::cerr << msg(MsgId::NoRulesRegistered) << "\n";
        result.no_rules = true;
        for (auto& source : result.sources) source.reason = "no_rules";
        if (checkpoint_requested) return rejectCheckpoint("checkpoint_no_rules");
        return finishReport();
    }

    engine_.setDiagnosticSelector([this](const std::string& id) {
        // The assumption producer is always registered, but has no effective
        // work without its explicit opt-in. Keep that existing behavior.
        return (id != "assumption" || config_.assumptions()) &&
               config_.isRuleEnabled(id);
    });

    // Registered-but-disabled is still "no analysis". Without this
    // post-configuration check, disabling every rule produced a false
    // clean verdict because runAll simply had nothing to execute.
    if (engine_.enabledRuleCount() == 0) {
        std::cerr << msg(MsgId::NoRulesRegistered) << "\n";
        result.no_rules = true;
        for (auto& source : result.sources) source.reason = "no_rules";
        if (checkpoint_requested) return rejectCheckpoint("checkpoint_no_enabled_rules");
        return finishReport();
    }

    std::cerr << msg(MsgId::AnalysisStarting,
                     std::to_string(source_mgr_->fileCount()),
                     std::to_string(engine_.enabledRuleCount())) << "\n";

    std::string checkpoint_parent;
    if (!config_.checkpointDirectory().empty() || config_.resumeCheckpoint()) {
        try {
            checkpointRequire(!config_.checkpointDirectory().empty() && !worker_executable_.empty(), "checkpoint_requires_isolated_cli");
            checkpoint_parent = checkpointParentIdentity(config_, worker_requests_, compilation_database_, [&] {
                return workerSignalCancellationRequested() ||
                    (config_.resourceCancellation() && config_.resourceCancellation()->requested());
            });
        } catch (const std::exception& error) { return rejectCheckpoint(error.what()); }
    }

    // Opt-in library models are declarative specifications in the existing
    // strict summary format. Load them before harvested summaries so every
    // source of knowledge shares the same conservative merge operation.
    // Unlike --summary-in, models do not represent a source snapshot and
    // therefore have no freshness relationship to analyzed files.
    if (!config_.modelFiles().empty()) {
        auto& registry = SummaryRegistry::instance();
        for (const auto& path : config_.modelFiles()) {
            if (registry.loadGlobal(path)) {
                std::cerr << msg(MsgId::SummariesLoaded,
                                 std::to_string(registry.globalSize()),
                                 path) << "\n";
            } else {
                result.summary_load_failed = true;
                std::cerr << msg(MsgId::SummaryLoadError, path) << "\n";
            }
        }
    }

    // Load saved summaries (Cross-TU v2): a previous run's harvest is
    // merged into the store — a single file is analyzed with
    // whole-project knowledge. A load failure does NOT stop the
    // analysis, but it does not pass silently either: a summary-less
    // run yields fewer findings, and the user must know that.
    if (!config_.summaryIn().empty()) {
        auto& registry = SummaryRegistry::instance();
        if (registry.loadGlobal(config_.summaryIn())) {
            std::cerr << msg(MsgId::SummariesLoaded,
                             std::to_string(registry.globalSize()),
                             config_.summaryIn()) << "\n";
            // Freshness: if an analyzed source is NEWER than the
            // summary file, summaries may be stale for that file — the
            // analysis does not stop (conservative direction: a stale
            // summary carries at most missing/extra claims, correctness
            // is not at stake) but the user must know to refresh.
            // Warning only, and once, not per file.
            std::error_code ec;
            auto summaryTime = std::filesystem::last_write_time(
                config_.summaryIn(), ec);
            if (!ec) {
                for (const auto& file : source_mgr_->files()) {
                    std::error_code fec;
                    auto srcTime =
                        std::filesystem::last_write_time(file, fec);
                    if (!fec && srcTime > summaryTime) {
                        result.summary_stale = true;
                        std::cerr << msg(MsgId::SummaryStaleWarning,
                                         config_.summaryIn(), file) << "\n";
                        break;
                    }
                }
            }
        } else {
            result.summary_load_failed = true;
            std::cerr << msg(MsgId::SummaryLoadError, config_.summaryIn())
                      << "\n";
        }
    }

    if (!checkpoint_parent.empty()) {
        if (result.summary_load_failed) return rejectCheckpoint("checkpoint_initial_summary_unavailable");
        std::string summaries, error;
        if (!exportWorkerSummaries(summaries, error)) return rejectCheckpoint(error);
        checkpoint_ = std::make_unique<RunCheckpoint>(config_, worker_executable_, worker_requests_,
                                                     engine_.ruleIds(), checkpoint_parent, compilation_database_);
        if (!checkpoint_->prepare(summaries)) return rejectCheckpoint("checkpoint_prepare_failed");
    }

    // Whole-program mode (Horizon 2): pass 1 collects summaries of
    // externally-linked functions from all TUs; rules in pass 2 see the
    // real summary instead of Opaque at cross-file calls. The cost is a
    // second parse — deliberate, enabled by flag.
    std::vector<SourceCoverage> prepassCoverage;
    if (config_.wholeProgram()) {
        std::cerr << msg(MsgId::WholeProgramPass,
                         std::to_string(source_mgr_->fileCount())) << "\n";
        if (!worker_executable_.empty()) {
            prepassCoverage = processIsolated(true);
        } else {
            source_mgr_->processAll([](clang::ASTContext& ctx) {
                auto& registry = SummaryRegistry::instance();
                registry.rebuild(ctx);
                registry.harvestGlobal();
                registry.clear();
                CfgCache::instance().clear();
            });
            prepassCoverage = source_mgr_->coverage();
        }
    }

    // --summary-out: harvest from the per-TU local table runAll builds —
    // the store gets filled without paying whole-program's second-parse
    // cost (in whole-program mode the second harvest merges with
    // equivalent values, harmless)
    if (!config_.summaryOut().empty()) engine_.enableGlobalHarvest(true);

    SourceManager::clearBrokenTUs();

    if (!worker_executable_.empty()) {
        result.sources = processIsolated(false);
    } else {
        source_mgr_->processAll([this](clang::ASTContext& ctx) {
            auto findings = engine_.runAll(ctx);
            bindBaselineFunctions(ctx, findings);
            diagnostics_.insert(diagnostics_.end(), findings.begin(), findings.end());
        });
        result.sources = source_mgr_->coverage();
    }
    // Both passes use the same frozen source ordering. A later successful
    // parse cannot erase missing summary evidence from the required prepass.
    for (std::size_t i = 0; i < prepassCoverage.size(); ++i) {
        result.sources[i].prepass_status = prepassCoverage[i].statusName();
        result.sources[i].prepass_reason = prepassCoverage[i].reason;
        result.sources[i].prepass_recovery_commands = prepassCoverage[i].recovery_commands;
        if (prepassCoverage[i].status == SourceStatus::Failed &&
            result.sources[i].status != SourceStatus::Failed) {
            result.sources[i].status = SourceStatus::Failed;
            result.sources[i].reason = "summary_prepass_failed";
        } else if (prepassCoverage[i].status == SourceStatus::Skipped &&
                   result.sources[i].status == SourceStatus::Analyzed) {
            result.sources[i].status = SourceStatus::Skipped;
            result.sources[i].reason = "summary_prepass_skipped";
        }
    }
    result.reconcileSources();
    result.tool_failed = result.failed_tus > 0;
    if (checkpoint_ && !checkpoint_->finish()) return rejectCheckpoint("checkpoint_incomplete_or_changed");

    // Broken-TU guard (#86): honest coverage note for every skipped TU.
    if (!SourceManager::brokenTUs().empty()) {
        std::cerr << msg(MsgId::BrokenTuSkipped,
                         std::to_string(SourceManager::brokenTUs().size()))
                  << "\n";
        for (const auto& file : SourceManager::brokenTUs())
            std::cerr << "  - " << file << "\n";
    }

    // Coverage: surface concrete functions whose CFG could not be built or
    // whose dataflow could not reach a fixpoint. "No warning" in these is
    // NOT "proven safe" — one honest summary, deduplicated across rules.
    const auto& coverage = CoverageReport::instance();
    result.incomplete_functions = coverage.incompleteCount();
    if (coverage.incompleteCount() > 0) {
        std::cerr << msg(MsgId::CoverageIncomplete,
                         std::to_string(coverage.incompleteCount())) << "\n";
        for (const auto& entry : coverage.entries()) {
            const char* reason =
                entry.gap == CoverageGap::CfgUnavailable
                    ? "CFG unavailable"
                    : "iteration limit";
            std::cerr << "  - " << entry.function << " (" << reason
                      << ")\n";
        }
    }

    if (!config_.summaryOut().empty()) {
        auto& registry = SummaryRegistry::instance();
        if (registry.saveGlobal(config_.summaryOut())) {
            std::cerr << msg(MsgId::SummariesSaved,
                             std::to_string(registry.globalSize()),
                             config_.summaryOut()) << "\n";
        } else {
            result.summary_save_failed = true;
            std::cerr << msg(MsgId::SummarySaveError, config_.summaryOut())
                      << "\n";
        }
    }

    // The same file may arrive under different paths (e.g. "tests/../x.c"
    // in the compile DB) — canonical path for deduplication and
    // baseline keys
    for (auto& diag : diagnostics_) {
        if (diag.file.empty()) continue;
        std::error_code ec;
        auto canonical = std::filesystem::weakly_canonical(diag.file, ec);
        if (!ec) diag.file = canonical.string();
    }

    // Report-path filter: findings OUTSIDE the given prefixes are
    // dropped (dependency headers pulled into the TU — 15 of the
    // Carbon scan's 16 findings were in LLVM headers, not the target).
    // Runs on canonical paths, so the prefixes are canonicalized the
    // same way; a prefix that fails to canonicalize (not on disk) is
    // used as written.
    if (!config_.reportPaths().empty()) {
        std::vector<std::filesystem::path> prefixes;
        for (const auto& p : config_.reportPaths()) {
            std::error_code ec;
            auto canonical = std::filesystem::weakly_canonical(p, ec);
            auto prefix = (ec ? std::filesystem::path(p) : canonical).lexically_normal();
            // A trailing separator is not a filename component. Keep roots.
            if (prefix.has_relative_path() && prefix.filename().empty())
                prefix = prefix.parent_path();
            prefixes.push_back(std::move(prefix));
        }
        auto outside = [&](const Diagnostic& d) {
            const std::filesystem::path path(d.file);
            for (const auto& prefix : prefixes) {
                if (prefix.empty()) continue;
                const auto mismatch = std::mismatch(prefix.begin(), prefix.end(),
                                                    path.begin(), path.end());
                if (mismatch.first == prefix.end())
                    return false;
            }
            return true;
        };
        size_t before = diagnostics_.size();
        diagnostics_.erase(
            std::remove_if(diagnostics_.begin(), diagnostics_.end(), outside),
            diagnostics_.end());
        size_t dropped = before - diagnostics_.size();
        if (dropped > 0) {
            std::cerr << msg(MsgId::ReportPathsFiltered,
                             std::to_string(dropped)) << "\n";
        }
    }

    SuppressionFilter suppression;
    size_t suppressed = suppression.filter(diagnostics_);
    result.suppressions = suppression.takeRecords();
    if (suppressed > 0) {
        std::cerr << msg(MsgId::SuppressedCount, std::to_string(suppressed))
                  << "\n";
    }

    // Assign once, after paths and suppressions are canonical, so every
    // reporter and integration observes exactly the same stable identity.
    assignFindingFingerprints(diagnostics_);

    // Record mode: findings are written to the baseline, no reporting,
    // exit clean (for producing a baseline in CI)
    if (!config_.writeBaselinePath().empty()) {
        result.baseline_version = 3;
        const auto written = Baseline::write(config_.writeBaselinePath(), diagnostics_, &result.baseline_unbound);
        // Record-only mode intentionally has no normal report file. Preserve
        // the suppression decision trail in its machine-readable stderr record.
        std::cerr << "[CodeSkeptic] suppressions: ";
        writeSuppressionAuditJson(std::cerr, result);
        std::cerr << "\n[CodeSkeptic] baseline: version=3 unbound_records=" << result.baseline_unbound << "\n";
        if (written) {
            std::cerr << msg(MsgId::BaselineWritten,
                             std::to_string(diagnostics_.size()),
                             config_.writeBaselinePath()) << "\n";
            setFindingCounts(result, diagnostics_);
            result.baseline_recorded = true;
            writeCoverageConsole(std::cerr, result);
            return result;
        }
        setFindingCounts(result, diagnostics_);
        result.baseline_write_failed = true;
        std::cerr << msg(MsgId::OutputFileOpenError,
                         config_.writeBaselinePath()) << "\n";
        writeCoverageConsole(std::cerr, result);
        return result;
    }

    if (!config_.baselinePath().empty()) {
        Baseline baseline;
        if (!baseline.load(config_.baselinePath())) {
            result.baseline_load_failed = true;
            std::cerr << msg(MsgId::OutputFileOpenError,
                             config_.baselinePath()) << "\n";
        }
        size_t matched = baseline.filter(diagnostics_);
        result.baseline_version = baseline.version();
        result.baseline_legacy_identity = baseline.legacy();
        result.baseline_unbound = baseline.unboundRecords();
        result.baseline_matched = matched;
        if (baseline.legacy())
            std::cerr << "[CodeSkeptic] baseline: legacy-weak-identity v" << baseline.version()
                      << "; refresh to v3 for function/signature/severity identity\n";
        if (matched > 0) {
            std::cerr << msg(MsgId::BaselineFiltered,
                             std::to_string(matched)) << "\n";
        }
    }

    auto severity_below = [this](const Diagnostic& d) {
        return d.severity < config_.minSeverity();
    };
    diagnostics_.erase(
        std::remove_if(diagnostics_.begin(), diagnostics_.end(), severity_below),
        diagnostics_.end());

    std::sort(diagnostics_.begin(), diagnostics_.end());

    // Functions defined in headers are analyzed in multiple TUs; the
    // same finding arrives once per TU — deduplicate, retaining independently
    // proven subtype evidence from every equivalent compilation variant.
    // The finding equivalence key and survivor count remain unchanged.
    auto output = diagnostics_.begin();
    for (auto input = diagnostics_.begin(); input != diagnostics_.end(); ++input) {
        if (output != diagnostics_.begin() && *(output - 1) == *input) {
            if ((output - 1)->baseline_function != input->baseline_function ||
                (output - 1)->function != input->function)
                (output - 1)->baseline_function.clear();
            mergeFindingMetadata(*(output - 1), *input);
        } else {
            if (output != input) *output = std::move(*input);
            ++output;
        }
    }
    diagnostics_.erase(output, diagnostics_.end());

    setFindingCounts(result, diagnostics_);
    return finishReport();
}

} // namespace codeskeptic
