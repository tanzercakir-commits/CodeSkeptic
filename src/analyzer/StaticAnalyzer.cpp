#include "analyzer/StaticAnalyzer.h"

#include "analyzer/AnalysisCoordinator.h"
#include "analyzer/Baseline.h"
#include "analyzer/SuppressionFilter.h"
#include "analyzer/WorkerProtocol.h"
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
#include "reporter/ConsoleReporter.h"
#include "reporter/HtmlReporter.h"
#include "reporter/JsonReporter.h"
#include "reporter/SarifReporter.h"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <clang/AST/ASTContext.h>
#include <clang/Basic/SourceManager.h>
#include <llvm/ADT/SmallString.h>
#include <llvm/Support/FileSystem.h>
#include <string>
#include <unordered_set>

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

std::string sourceIdentity(const std::string& path) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path normalized = fs::weakly_canonical(path, ec);
    if (ec) {
        ec.clear();
        normalized = fs::absolute(path, ec);
    }
    return (ec ? fs::path(path) : normalized).lexically_normal().string();
}

class TemporaryDirectory {
public:
    TemporaryDirectory() = default;
    explicit TemporaryDirectory(std::filesystem::path path)
        : path_(std::move(path)) {}
    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
    TemporaryDirectory(TemporaryDirectory&& other) noexcept
        : path_(std::move(other.path_)) {
        other.path_.clear();
    }
    TemporaryDirectory& operator=(TemporaryDirectory&& other) noexcept {
        if (this == &other) return *this;
        if (!path_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
        path_ = std::move(other.path_);
        other.path_.clear();
        return *this;
    }
    ~TemporaryDirectory() {
        if (path_.empty()) return;
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

bool createTemporaryDirectory(const char* prefix, TemporaryDirectory& result,
                              std::string& error) {
    llvm::SmallString<256> path;
    if (const std::error_code ec =
            llvm::sys::fs::createUniqueDirectory(prefix, path)) {
        error = ec.message();
        return false;
    }
    result = TemporaryDirectory(std::filesystem::path(path.str().str()));
    return true;
}

UnitExecutionResult failedWorkerOutcome(const std::string& error) {
    UnitExecutionResult outcome;
    outcome.resource.status = ResourceRunStatus::Crashed;
    outcome.resource.error = error;
    outcome.analysis.attempted_tus = 1;
    outcome.analysis.tool_failed = true;
    return outcome;
}

UnitExecutionResult missingWorkerOutcome() {
    UnitExecutionResult outcome;
    outcome.resource.status = ResourceRunStatus::Completed;
    outcome.resource.exit_code = 0;
    outcome.analysis.attempted_tus = 1;
    outcome.analysis.no_inputs = true;
    return outcome;
}

UnitExecutionResult executeIsolatedWorker(
    const Config& config,
    const std::vector<std::string>& rule_ids,
    const TranslationUnitExecution& unit,
    TranslationUnitPhase phase,
    const std::string& summary_override,
    bool replace_configured_summaries,
    bool produce_summary_fragment) {
    std::error_code source_error;
    if (!std::filesystem::is_regular_file(unit.canonical_path,
                                          source_error)) {
        if (source_error &&
            source_error != std::errc::no_such_file_or_directory)
            return failedWorkerOutcome(
                "cannot inspect requested translation unit: " +
                source_error.message());
        return missingWorkerOutcome();
    }
    if (unit.command_line.empty() || unit.compile_command_sha256.empty()) {
        return failedWorkerOutcome("missing or inconsistent compile command");
    }
    if (translationUnitCommandSha256(unit) != unit.compile_command_sha256)
        return failedWorkerOutcome("missing or inconsistent compile command");

    TemporaryDirectory temporary;
    std::string error;
    if (!createTemporaryDirectory("codeskeptic-tu-worker", temporary, error))
        return failedWorkerOutcome("cannot create worker directory: " + error);

    WorkerRequest request;
    request.request_id =
        temporary.path().filename().string() + ":" +
        translationUnitPhaseName(phase) + ":" +
        unit.compile_command_sha256 + ":" +
        std::to_string(unit.command_ordinal);
    request.unit = unit;
    request.phase = phase;
    request.config_arguments = config.workerArguments(
        rule_ids, summary_override, replace_configured_summaries);
    request.response_path = (temporary.path() / "response.json").string();
    if (produce_summary_fragment)
        request.summary_fragment_path =
            (temporary.path() / "summary.csk").string();
    const std::string request_path =
        (temporary.path() / "request.json").string();
    if (!writeWorkerRequest(request_path, request, error))
        return failedWorkerOutcome("cannot write worker request: " + error);

    UnitExecutionResult outcome;
    outcome.resource = ResourceSupervisor::run(
        config.workerProgram(), {"--internal-tu-worker", request_path},
        ResourceLimits{config.tuTimeoutSeconds(), config.tuMemoryMiB()});
    if (outcome.resource.status != ResourceRunStatus::Completed) return outcome;
    if (outcome.resource.exit_code != 0) {
        outcome.resource.status = ResourceRunStatus::Crashed;
        if (outcome.resource.error.empty())
            outcome.resource.error = "worker exited without a valid response";
        return outcome;
    }

    WorkerResponse response;
    if (!readWorkerResponse(request.response_path, request, response, error)) {
        outcome.resource.status = ResourceRunStatus::Crashed;
        outcome.resource.error = "invalid worker response: " + error;
        return outcome;
    }
    outcome.analysis = std::move(response.analysis);
    outcome.diagnostics = std::move(response.diagnostics);

    if (!request.summary_fragment_path.empty() &&
        !outcome.analysis.summary_save_failed) {
        const std::string actual =
            sha256File(request.summary_fragment_path, error);
        if (actual.empty() || actual != response.summary_fragment_sha256) {
            outcome.analysis.tool_failed = true;
            outcome.resource.error = "summary fragment checksum mismatch";
        } else if (!SummaryRegistry::instance().loadGlobal(
                       request.summary_fragment_path)) {
            outcome.analysis.summary_load_failed = true;
            outcome.resource.error = "summary fragment parser rejected worker output";
        }
    }
    return outcome;
}

} // namespace

std::size_t StaticAnalyzer::totalTUs() const {
    return source_mgr_ ? source_mgr_->requestedFileCount() : 0;
}

std::size_t StaticAnalyzer::brokenTUCount() const {
    return SourceManager::brokenTUs().size();
}


StaticAnalyzer::StaticAnalyzer(Config config)
    : config_(std::move(config)) {
    setLang(parseLang(config_.lang()));
    setFunctionFilter(config_.functions());
    setLineRanges(config_.lines());
    setFatalCallNames(config_.fatalAsserts());
    setAssertRecoveryEnabled(config_.assertRecovery());
    setExtraAssertMacros(config_.assertMacros());
    setNegativeAssertMacros(config_.negativeAssertMacros());
    setAllocFunctionNames(config_.allocFunctions());
    setFreeFunctionNames(config_.freeFunctions());
    setAllocatorPairs(config_.allocatorPairs());
    setOwningPointerNames(config_.owningPointers());
    setUntrustedIntSourceNames(config_.untrustedIntSources());
    setProfilePolicies(config_.policies());
    setAssumptionMode(config_.assumptions());
    // Sidecar contracts are cached per file path for the process
    // lifetime; a new analyzer run re-reads them (the MCP server
    // lives long — an edited .csk must be seen).
    clearSidecarCache();
    // Coverage gaps belong to a single run; a long-lived process (the
    // MCP server) must not inherit the previous run's non-convergence.
    CoverageReport::instance().clear();

    source_mgr_ = std::make_unique<SourceManager>(config_.buildPath());
    if (config_.warmCache()) source_mgr_->enableWarmCache(true);

    if (!config_.sourcePath().empty()) {
        if (std::filesystem::is_directory(config_.sourcePath())) {
            source_mgr_->scanDirectory(config_.sourcePath());
        } else {
            source_mgr_->addSourceFile(config_.sourcePath());
        }
    }
    for (const auto& file : config_.sourceFiles()) {
        // Meson compile DBs carry build-dir-relative paths
        // (`../src/foo.c`). An entry that does not exist as given is
        // retried relative to --build-path before being reported —
        // without this, a meson-driven file list silently analyzed
        // NOTHING (the systemd lesson, 2026-07-12).
        namespace fs = std::filesystem;
        if (!fs::exists(file) && fs::path(file).is_relative()) {
            fs::path viaBuild = fs::path(config_.buildPath()) / file;
            if (fs::exists(viaBuild)) {
                source_mgr_->addSourceFile(
                    fs::weakly_canonical(viaBuild).string());
                continue;
            }
        }
        source_mgr_->addSourceFile(file);
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
}

StaticAnalyzer::~StaticAnalyzer() {
    // Keep global filter state bounded by this analysis's lifetime: in
    // a long-lived process (MCP server) a filtered run must not
    // silently prune later ones. (In tests the same leak broke 11 of
    // InterproceduralTest's tests — ctest's per-process isolation had
    // been hiding it.)
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
    // Same rationale for the cross-TU summary store: one run's
    // summaries must not leak into the next (the MCP server runs many
    // analyses in the same process)
    SummaryRegistry::instance().clearGlobal();
    CfgCache::instance().clear();
    AssertGuardCache::instance().clear();
    CoverageReport::instance().clear();
}

AnalysisResult StaticAnalyzer::run() {
    if (!config_.workerProgram().empty()) return runBudgeted();
    return runDirect();
}

AnalysisResult StaticAnalyzer::runBudgeted() {
    diagnostics_.clear();
    AnalysisResult seed;
    seed.analyze_broken_tus = config_.analyzeBrokenTUs();
    seed.accept_partial_coverage = config_.acceptPartialCoverage();

    if (!source_mgr_->compilationDatabaseValid()) {
        seed.compile_database_failed = true;
        return seed;
    }
    const auto units = source_mgr_->executionUnits();
    seed.attempted_tus = units.size();
    if (units.empty()) {
        std::cerr << msg(MsgId::NoFilesToAnalyze) << "\n";
        seed.no_inputs = true;
        return seed;
    }
    if (engine_.ruleCount() == 0) {
        std::cerr << msg(MsgId::NoRulesRegistered) << "\n";
        seed.no_rules = true;
        return seed;
    }
    const auto rule_ids = engine_.ruleIds();
    for (const auto& rule_id : rule_ids) {
        if (!config_.isRuleEnabled(rule_id))
            engine_.enableRule(rule_id, false);
    }
    if (engine_.enabledRuleCount() == 0) {
        std::cerr << msg(MsgId::NoRulesRegistered) << "\n";
        seed.no_rules = true;
        return seed;
    }

    std::cerr << msg(MsgId::AnalysisStarting,
                     std::to_string(units.size()),
                     std::to_string(engine_.enabledRuleCount())) << "\n";

    // Parent owns the authoritative merged summary state. Child workers load
    // the same configured inputs for ordinary per-TU analysis; whole-program
    // mode instead consumes one parent-merged harvest after every prepass
    // receipt has completed.
    auto& registry = SummaryRegistry::instance();
    registry.clearGlobal();
    for (const auto& path : config_.modelFiles()) {
        if (!registry.loadGlobal(path)) {
            seed.summary_load_failed = true;
            std::cerr << msg(MsgId::SummaryLoadError, path) << "\n";
        }
    }
    if (!config_.summaryIn().empty()) {
        if (!registry.loadGlobal(config_.summaryIn())) {
            seed.summary_load_failed = true;
            std::cerr << msg(MsgId::SummaryLoadError, config_.summaryIn())
                      << "\n";
        } else {
            std::error_code ec;
            const auto summary_time = std::filesystem::last_write_time(
                config_.summaryIn(), ec);
            if (!ec) {
                for (const auto& file : source_mgr_->files()) {
                    std::error_code source_ec;
                    const auto source_time =
                        std::filesystem::last_write_time(file, source_ec);
                    if (!source_ec && source_time > summary_time) {
                        seed.summary_stale = true;
                        std::cerr << msg(MsgId::SummaryStaleWarning,
                                         config_.summaryIn(), file) << "\n";
                        break;
                    }
                }
            }
        }
    }

    TemporaryDirectory run_directory;
    std::string directory_error;
    if (!createTemporaryDirectory("codeskeptic-tu-run", run_directory,
                                  directory_error)) {
        seed.tool_failed = true;
        return seed;
    }
    const std::string merged_summary =
        (run_directory.path() / "merged-summary.csk").string();
    bool merged_summary_ready = false;
    bool merged_summary_failed = false;

    const UnitExecutor executor =
        [this, &rule_ids, &merged_summary, &merged_summary_ready,
         &merged_summary_failed](const TranslationUnitExecution& unit,
                                 TranslationUnitPhase phase) {
            if (config_.wholeProgram() &&
                phase == TranslationUnitPhase::Analysis &&
                !merged_summary_ready) {
                merged_summary_ready = true;
                if (!SummaryRegistry::instance().saveGlobal(merged_summary))
                    merged_summary_failed = true;
            }
            if (merged_summary_failed)
                return failedWorkerOutcome(
                    "cannot materialize merged whole-program summary");

            const bool harvest =
                phase == TranslationUnitPhase::SummaryHarvest;
            const bool replace_summaries = config_.wholeProgram();
            const std::string summary_override =
                replace_summaries && !harvest ? merged_summary : std::string{};
            const bool produce_fragment =
                harvest || (!config_.summaryOut().empty() &&
                            !config_.wholeProgram());
            return executeIsolatedWorker(
                config_, rule_ids, unit, phase, summary_override,
                replace_summaries, produce_fragment);
        };

    if (config_.wholeProgram()) {
        std::cerr << msg(MsgId::WholeProgramPass,
                         std::to_string(source_mgr_->fileCount())) << "\n";
    }

    auto coordinated = AnalysisCoordinator::run(
        units,
        ResourceLimits{config_.tuTimeoutSeconds(), config_.tuMemoryMiB()},
        config_.wholeProgram(), executor);
    AnalysisResult result = std::move(coordinated.analysis);
    result.analyze_broken_tus = config_.analyzeBrokenTUs();
    result.accept_partial_coverage = config_.acceptPartialCoverage();
    result.summary_load_failed =
        result.summary_load_failed || seed.summary_load_failed;
    result.summary_stale = result.summary_stale || seed.summary_stale;
    result.tool_failed = result.tool_failed || seed.tool_failed;
    diagnostics_ = std::move(coordinated.diagnostics);
    for (const auto& receipt : result.tu_receipts) {
        if (receipt.status == TranslationUnitStatus::Completed) continue;
        std::cerr << "[CodeSkeptic] translation unit "
                  << translationUnitStatusName(receipt.status) << ": "
                  << receipt.canonical_path << " (command_sha256="
                  << receipt.compile_command_sha256 << ", ordinal="
                  << receipt.command_ordinal << ", phase=" << receipt.phase
                  << ")\n";
    }

    if (!config_.summaryOut().empty()) {
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
    return finalizeResult(std::move(result));
}

AnalysisResult StaticAnalyzer::runDirect() {
    diagnostics_.clear();
    AnalysisResult result;
    result.attempted_tus = source_mgr_->requestedFileCount();
    result.analyze_broken_tus = config_.analyzeBrokenTUs();
    result.accept_partial_coverage = config_.acceptPartialCoverage();

    if (!source_mgr_->compilationDatabaseValid()) {
        result.compile_database_failed = true;
        return result;
    }

    if (source_mgr_->fileCount() == 0) {
        // Analyzing nothing must not look like a clean pass: a mistyped
        // path or a relative-path file list would otherwise print
        // "Clean!" with exit 0.
        std::cerr << msg(MsgId::NoFilesToAnalyze) << "\n";
        result.no_inputs = true;
        return result;
    }

    if (engine_.ruleCount() == 0) {
        std::cerr << msg(MsgId::NoRulesRegistered) << "\n";
        result.no_rules = true;
        return result;
    }

    for (const auto& rule_id : engine_.ruleIds()) {
        if (!config_.isRuleEnabled(rule_id)) {
            engine_.enableRule(rule_id, false);
        }
    }

    // Registered-but-disabled is still "no analysis". Without this
    // post-configuration check, disabling every rule produced a false
    // clean verdict because runAll simply had nothing to execute.
    if (engine_.enabledRuleCount() == 0) {
        std::cerr << msg(MsgId::NoRulesRegistered) << "\n";
        result.no_rules = true;
        return result;
    }

    std::cerr << msg(MsgId::AnalysisStarting,
                     std::to_string(source_mgr_->requestedFileCount()),
                     std::to_string(engine_.enabledRuleCount())) << "\n";

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

    SourceManager::setAnalyzeBrokenTUs(config_.analyzeBrokenTUs());
    SourceManager::clearBrokenTUs();
    SourceManager::setAttemptedTUCount(result.attempted_tus);

    // Whole-program mode (Horizon 2): pass 1 collects summaries of
    // externally-linked functions from all TUs; rules in pass 2 see the
    // real summary instead of Opaque at cross-file calls. The cost is a
    // second parse — deliberate, enabled by flag.
    int whole_program_result = 0;
    if (config_.wholeProgram()) {
        std::cerr << msg(MsgId::WholeProgramPass,
                         std::to_string(source_mgr_->fileCount())) << "\n";
        whole_program_result = source_mgr_->processAll([](clang::ASTContext& ctx) {
            auto& registry = SummaryRegistry::instance();
            registry.rebuild(ctx);
            registry.harvestGlobal();
            registry.clear();
            CfgCache::instance().clear();
        });
    }

    // --summary-out: harvest from the per-TU local table runAll builds —
    // the store gets filled without paying whole-program's second-parse
    // cost (in whole-program mode the second harvest merges with
    // equivalent values, harmless)
    if (!config_.summaryOut().empty()) engine_.enableGlobalHarvest(true);

    std::unordered_set<std::string> analyzed_files;
    const int analysis_result = source_mgr_->processAll(
        [this, &result, &analyzed_files](clang::ASTContext& ctx) {
        const auto& source_manager = ctx.getSourceManager();
        const auto main_file = source_manager.getMainFileID();
        const auto main_path = source_manager
                                   .getFilename(source_manager.getLocForStartOfFile(main_file))
                                   .str();
        if (analyzed_files.insert(sourceIdentity(main_path)).second) {
            ++result.analyzed_tus;
        }
        auto findings = engine_.runAll(ctx);
        diagnostics_.insert(diagnostics_.end(), findings.begin(), findings.end());
    });

    // Broken-TU guard (#86): honest coverage note for every skipped TU.
    if (!SourceManager::brokenTUs().empty()) {
        std::cerr << msg(MsgId::BrokenTuSkipped,
                         std::to_string(SourceManager::brokenTUs().size()))
                  << "\n";
        for (const auto& file : SourceManager::brokenTUs())
            std::cerr << "  - " << file << "\n";
    }
    result.broken_tus = SourceManager::brokenTUs().size();
    std::unordered_set<std::string> broken_files;
    for (const auto& file : SourceManager::brokenTUs())
        broken_files.insert(sourceIdentity(file));
    std::vector<std::string> unaccounted_files;
    for (const auto& file : source_mgr_->files()) {
        const std::string identity = sourceIdentity(file);
        if (!analyzed_files.count(identity) && !broken_files.count(identity))
            unaccounted_files.push_back(file);
    }
    const std::size_t accounted_tus = std::min(
        result.attempted_tus, result.analyzed_tus + result.broken_tus);
    const std::size_t unaccounted_tus = result.attempted_tus - accounted_tus;
    if (unaccounted_tus > 0) {
        std::cerr << msg(MsgId::RequestedTuUnaccounted,
                         std::to_string(unaccounted_tus)) << "\n";
        for (const auto& file : unaccounted_files)
            std::cerr << "  - " << file << "\n";
    }
    // ClangTool returns non-zero for ordinary compile diagnostics as well as
    // driver failures. Broken TUs are already accounted explicitly; only an
    // unaccounted failure is a separate hard tool failure unless the caller
    // explicitly accepted a verdict over the translation units that did run.
    const bool tool_returned_failure =
        whole_program_result != 0 || analysis_result != 0;
    if (tool_returned_failure &&
        (result.broken_tus == 0 ||
         result.analyzed_tus + result.broken_tus < result.attempted_tus))
        result.tool_failed = true;

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

    return finalizeResult(std::move(result));
}

AnalysisResult StaticAnalyzer::finalizeResult(AnalysisResult result) {
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
        std::vector<std::string> prefixes;
        for (const auto& p : config_.reportPaths()) {
            std::error_code ec;
            auto canonical = std::filesystem::weakly_canonical(p, ec);
            prefixes.push_back(ec ? p : canonical.string());
        }
        auto outside = [&](const Diagnostic& d) {
            for (const auto& prefix : prefixes)
                if (d.file.compare(0, prefix.size(), prefix) == 0)
                    return false;
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
        if (Baseline::write(config_.writeBaselinePath(), diagnostics_)) {
            std::cerr << msg(MsgId::BaselineWritten,
                             std::to_string(diagnostics_.size()),
                             config_.writeBaselinePath()) << "\n";
            setFindingCounts(result, diagnostics_);
            result.baseline_recorded = true;
            return result;
        }
        setFindingCounts(result, diagnostics_);
        result.baseline_write_failed = true;
        std::cerr << msg(MsgId::OutputFileOpenError,
                         config_.writeBaselinePath()) << "\n";
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
    // same finding arrives once per TU — deduplicate.
    diagnostics_.erase(
        std::unique(diagnostics_.begin(), diagnostics_.end()),
        diagnostics_.end());

    setFindingCounts(result, diagnostics_);
    if (!reporter_->report(diagnostics_, &result))
        result.report_write_failed = true;

    return result;
}

} // namespace codeskeptic
