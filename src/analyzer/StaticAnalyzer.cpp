#include "analyzer/StaticAnalyzer.h"
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

#include <algorithm>
#include <filesystem>
#include <iostream>

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

} // namespace

std::size_t StaticAnalyzer::totalTUs() const {
    return source_mgr_ ? source_mgr_->fileCount() : 0;
}

std::size_t StaticAnalyzer::brokenTUCount() const {
    return SourceManager::brokenTUs().size();
}


StaticAnalyzer::StaticAnalyzer(Config config)
    try : config_(std::move(config)) {
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

    auto selection = discoverCompilationDatabase(config_);
    compilation_input_ready_ = selection.ready;
    writeCompilationDoctor(selection, std::cerr);
    const auto buildDirectory = selection.database.empty() ? "." :
        std::filesystem::path(selection.database).parent_path().string();
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

AnalysisResult StaticAnalyzer::run() {
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

    if (!compilation_input_ready_) {
        result.tool_failed = true;
        return finishReport();
    }

    if (source_mgr_->fileCount() == 0) {
        // Analyzing nothing must not look like a clean pass: a mistyped
        // path or a relative-path file list would otherwise print
        // "Clean!" with exit 0.
        std::cerr << msg(MsgId::NoFilesToAnalyze) << "\n";
        result.no_inputs = true;
        return finishReport();
    }

    if (engine_.ruleCount() == 0) {
        std::cerr << msg(MsgId::NoRulesRegistered) << "\n";
        result.no_rules = true;
        for (auto& source : result.sources) source.reason = "no_rules";
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
        return finishReport();
    }

    std::cerr << msg(MsgId::AnalysisStarting,
                     std::to_string(source_mgr_->fileCount()),
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

    // Whole-program mode (Horizon 2): pass 1 collects summaries of
    // externally-linked functions from all TUs; rules in pass 2 see the
    // real summary instead of Opaque at cross-file calls. The cost is a
    // second parse — deliberate, enabled by flag.
    std::vector<SourceCoverage> prepassCoverage;
    if (config_.wholeProgram()) {
        std::cerr << msg(MsgId::WholeProgramPass,
                         std::to_string(source_mgr_->fileCount())) << "\n";
        source_mgr_->processAll([](clang::ASTContext& ctx) {
            auto& registry = SummaryRegistry::instance();
            registry.rebuild(ctx);
            registry.harvestGlobal();
            registry.clear();
            CfgCache::instance().clear();
        });
        prepassCoverage = source_mgr_->coverage();
    }

    // --summary-out: harvest from the per-TU local table runAll builds —
    // the store gets filled without paying whole-program's second-parse
    // cost (in whole-program mode the second harvest merges with
    // equivalent values, harmless)
    if (!config_.summaryOut().empty()) engine_.enableGlobalHarvest(true);

    SourceManager::clearBrokenTUs();

    source_mgr_->processAll([this](clang::ASTContext& ctx) {
        auto findings = engine_.runAll(ctx);
        diagnostics_.insert(diagnostics_.end(), findings.begin(), findings.end());
    });
    result.sources = source_mgr_->coverage();
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
