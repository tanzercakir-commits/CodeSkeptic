#include "analyzer/AnalysisCoordinator.h"

#include "core/Capabilities.h"

#include <algorithm>

namespace codeskeptic {

namespace {

TranslationUnitStatus receiptStatus(const UnitExecutionResult& outcome) {
    switch (outcome.resource.status) {
        case ResourceRunStatus::TimedOut:
            return TranslationUnitStatus::TimedOut;
        case ResourceRunStatus::MemoryExceeded:
            return TranslationUnitStatus::MemoryExceeded;
        case ResourceRunStatus::Crashed:
        case ResourceRunStatus::LaunchFailed:
            return TranslationUnitStatus::WorkerFailed;
        case ResourceRunStatus::Completed:
            break;
    }
    if (outcome.analysis.broken_tus > 0)
        return TranslationUnitStatus::Broken;
    if (outcome.analysis.no_inputs)
        return TranslationUnitStatus::Missing;
    if (outcome.analysis.hasHardFailure())
        return TranslationUnitStatus::WorkerFailed;
    if (outcome.analysis.hasIncompleteEvidence())
        return TranslationUnitStatus::Broken;
    return TranslationUnitStatus::Completed;
}

void mergeWorkerEvidence(AnalysisResult& target,
                         const AnalysisResult& worker) {
    target.broken_tus += worker.broken_tus;
    target.incomplete_functions += worker.incomplete_functions;
    // A single-TU worker reports no_inputs for an exact missing requested
    // path. The project still had inputs; its missing receipt plus aggregate
    // coverage makes the verdict incomplete. Zero aggregate analysis remains
    // a hard failure through AnalysisResult::hasHardFailure.
    target.no_rules = target.no_rules || worker.no_rules;
    target.compile_database_failed =
        target.compile_database_failed || worker.compile_database_failed;
    target.tool_failed = target.tool_failed || worker.tool_failed;
    target.summary_load_failed =
        target.summary_load_failed || worker.summary_load_failed;
    target.summary_stale = target.summary_stale || worker.summary_stale;
    target.summary_save_failed =
        target.summary_save_failed || worker.summary_save_failed;
    target.baseline_load_failed =
        target.baseline_load_failed || worker.baseline_load_failed;
    target.baseline_write_failed =
        target.baseline_write_failed || worker.baseline_write_failed;
    target.report_write_failed =
        target.report_write_failed || worker.report_write_failed;
}

void mergeWorkerAnalysis(AnalysisResult& target,
                         const AnalysisResult& worker) {
    target.analyzed_tus += worker.analyzed_tus;
    mergeWorkerEvidence(target, worker);
}

TranslationUnitReceipt makeReceipt(
    const TranslationUnitExecution& unit,
    TranslationUnitPhase phase,
    const UnitExecutionResult& outcome,
    ResourceLimits limits) {
    return TranslationUnitReceipt{
        unit.canonical_path,
        unit.compile_command_sha256,
        unit.command_ordinal,
        translationUnitPhaseName(phase),
        receiptStatus(outcome),
        outcome.resource.duration_ms,
        outcome.resource.peak_memory_kib,
        limits.timeout_seconds,
        limits.memory_mib,
        outcome.origin,
        outcome.checkpoint_key_sha256,
        outcome.payload_sha256,
    };
}

void recomputeFindingCounts(CoordinatedAnalysisResult& result) {
    std::sort(result.diagnostics.begin(), result.diagnostics.end());
    result.diagnostics.erase(
        std::unique(result.diagnostics.begin(), result.diagnostics.end()),
        result.diagnostics.end());
    result.analysis.findings = result.diagnostics.size();
    result.analysis.report_only_findings =
        static_cast<std::size_t>(std::count_if(
            result.diagnostics.begin(), result.diagnostics.end(),
            [](const Diagnostic& diagnostic) {
                return !findingBlocksVerdict(diagnostic.rule_id);
            }));
}

} // anonymous namespace

const char* translationUnitPhaseName(TranslationUnitPhase phase) {
    switch (phase) {
        case TranslationUnitPhase::DependencyProbe:
            return "dependency-probe";
        case TranslationUnitPhase::SummaryHarvest:
            return "summary-harvest";
        case TranslationUnitPhase::Analysis:
            return "analysis";
    }
    return "analysis";
}

CoordinatedAnalysisResult AnalysisCoordinator::run(
    const std::vector<TranslationUnitExecution>& units,
    ResourceLimits limits,
    bool whole_program,
    const UnitExecutor& executor) {
    CoordinatedAnalysisResult result;
    result.analysis.attempted_tus = units.size();

    if (whole_program) {
        bool harvest_complete = true;
        AnalysisResult harvest_evidence;
        for (const auto& unit : units) {
            UnitExecutionResult outcome =
                executor(unit, TranslationUnitPhase::SummaryHarvest);
            const auto receipt = makeReceipt(
                unit, TranslationUnitPhase::SummaryHarvest, outcome, limits);
            if (receipt.status != TranslationUnitStatus::Completed)
                harvest_complete = false;
            result.analysis.tu_receipts.push_back(receipt);
            if (outcome.resource.status == ResourceRunStatus::Completed)
                mergeWorkerEvidence(harvest_evidence, outcome.analysis);
        }
        if (!harvest_complete) {
            mergeWorkerEvidence(result.analysis, harvest_evidence);
            recomputeFindingCounts(result);
            return result;
        }
    }

    for (const auto& unit : units) {
        UnitExecutionResult outcome =
            executor(unit, TranslationUnitPhase::Analysis);
        result.analysis.tu_receipts.push_back(
            makeReceipt(unit, TranslationUnitPhase::Analysis, outcome,
                        limits));
        if (outcome.resource.status != ResourceRunStatus::Completed)
            continue;
        mergeWorkerAnalysis(result.analysis, outcome.analysis);
        result.diagnostics.insert(result.diagnostics.end(),
                                  outcome.diagnostics.begin(),
                                  outcome.diagnostics.end());
    }
    recomputeFindingCounts(result);
    return result;
}

} // namespace codeskeptic
