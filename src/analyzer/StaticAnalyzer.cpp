#include "analyzer/StaticAnalyzer.h"

#include "analyzer/Baseline.h"
#include "analyzer/SuppressionFilter.h"
#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "contracts/Policy.h"
#include "contracts/Sidecar.h"
#include "engine/AllocFunctions.h"
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

namespace zerodefect {

StaticAnalyzer::StaticAnalyzer(Config config)
    : config_(std::move(config)) {
    setLang(parseLang(config_.lang()));
    setFunctionFilter(config_.functions());
    setLineRanges(config_.lines());
    setFatalCallNames(config_.fatalAsserts());
    setAllocFunctionNames(config_.allocFunctions());
    setFreeFunctionNames(config_.freeFunctions());
    setOwningPointerNames(config_.owningPointers());
    setProfilePolicies(config_.policies());
    setAssumptionMode(config_.assumptions());
    // Sidecar contracts are cached per file path for the process
    // lifetime; a new analyzer run re-reads them (the MCP server
    // lives long — an edited .zdc must be seen).
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
    setAllocFunctionNames({});
    setFreeFunctionNames({});
    setOwningPointerNames({});
    setAssumptionMode(false);
    // Same rationale for the cross-TU summary store: one run's
    // summaries must not leak into the next (the MCP server runs many
    // analyses in the same process)
    SummaryRegistry::instance().clearGlobal();
    CfgCache::instance().clear();
    CoverageReport::instance().clear();
}

int StaticAnalyzer::run() {
    diagnostics_.clear();

    if (source_mgr_->fileCount() == 0) {
        // Analyzing nothing must not look like a clean pass: a mistyped
        // path or a relative-path file list would otherwise print
        // "Clean!" with exit 0.
        std::cerr << msg(MsgId::NoFilesToAnalyze) << "\n";
        return 2;
    }

    if (engine_.ruleCount() == 0) {
        std::cerr << msg(MsgId::NoRulesRegistered) << "\n";
        return 0;
    }

    for (const auto& rule_id : engine_.ruleIds()) {
        if (!config_.isRuleEnabled(rule_id)) {
            engine_.enableRule(rule_id, false);
        }
    }

    std::cerr << msg(MsgId::AnalysisStarting,
                     std::to_string(source_mgr_->fileCount()),
                     std::to_string(engine_.ruleCount())) << "\n";

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
                        std::cerr << msg(MsgId::SummaryStaleWarning,
                                         config_.summaryIn(), file) << "\n";
                        break;
                    }
                }
            }
        } else {
            std::cerr << msg(MsgId::SummaryLoadError, config_.summaryIn())
                      << "\n";
        }
    }

    // Whole-program mode (Horizon 2): pass 1 collects summaries of
    // externally-linked functions from all TUs; rules in pass 2 see the
    // real summary instead of Opaque at cross-file calls. The cost is a
    // second parse — deliberate, enabled by flag.
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
    }

    // --summary-out: harvest from the per-TU local table runAll builds —
    // the store gets filled without paying whole-program's second-parse
    // cost (in whole-program mode the second harvest merges with
    // equivalent values, harmless)
    if (!config_.summaryOut().empty()) engine_.enableGlobalHarvest(true);

    source_mgr_->processAll([this](clang::ASTContext& ctx) {
        auto findings = engine_.runAll(ctx);
        diagnostics_.insert(diagnostics_.end(), findings.begin(), findings.end());
    });

    // Coverage: surface the functions the dataflow could not drive to a
    // fixpoint (iteration cap). "No warning" in these is NOT "proven
    // safe" — one honest summary, deduplicated across all rules, instead
    // of six scattered per-rule stderr lines.
    const auto& coverage = CoverageReport::instance();
    if (coverage.incompleteCount() > 0) {
        std::cerr << msg(MsgId::CoverageIncomplete,
                         std::to_string(coverage.incompleteCount())) << "\n";
        for (const auto& entry : coverage.entries())
            std::cerr << "  - " << entry.function << "\n";
    }

    if (!config_.summaryOut().empty()) {
        auto& registry = SummaryRegistry::instance();
        if (registry.saveGlobal(config_.summaryOut())) {
            std::cerr << msg(MsgId::SummariesSaved,
                             std::to_string(registry.globalSize()),
                             config_.summaryOut()) << "\n";
        } else {
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

    SuppressionFilter suppression;
    size_t suppressed = suppression.filter(diagnostics_);
    if (suppressed > 0) {
        std::cerr << msg(MsgId::SuppressedCount, std::to_string(suppressed))
                  << "\n";
    }

    // Record mode: findings are written to the baseline, no reporting,
    // exit clean (for producing a baseline in CI)
    if (!config_.writeBaselinePath().empty()) {
        if (Baseline::write(config_.writeBaselinePath(), diagnostics_)) {
            std::cerr << msg(MsgId::BaselineWritten,
                             std::to_string(diagnostics_.size()),
                             config_.writeBaselinePath()) << "\n";
            return 0;
        }
        std::cerr << msg(MsgId::OutputFileOpenError,
                         config_.writeBaselinePath()) << "\n";
        return 0;
    }

    if (!config_.baselinePath().empty()) {
        Baseline baseline;
        baseline.load(config_.baselinePath());
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

    reporter_->report(diagnostics_);

    return static_cast<int>(diagnostics_.size());
}

} // namespace zerodefect
