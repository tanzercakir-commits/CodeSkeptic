#ifndef CODESKEPTIC_ANALYSIS_RESULT_H
#define CODESKEPTIC_ANALYSIS_RESULT_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace codeskeptic {

// One verdict contract for every frontend (CLI, MCP, integrations).
// Findings and analysis integrity are deliberately separate: zero findings
// is only a clean verdict when the requested evidence was produced.
enum class AnalysisStatus {
    Clean,
    Findings,
    ReportOnly,
    Recorded,
    Incomplete,
    Failed,
};

enum class TranslationUnitStatus {
    Completed,
    Broken,
    Missing,
    TimedOut,
    MemoryExceeded,
    WorkerFailed,
};

inline const char* translationUnitStatusName(TranslationUnitStatus status) {
    switch (status) {
        case TranslationUnitStatus::Completed: return "completed";
        case TranslationUnitStatus::Broken: return "broken";
        case TranslationUnitStatus::Missing: return "missing";
        case TranslationUnitStatus::TimedOut: return "timed-out";
        case TranslationUnitStatus::MemoryExceeded: return "memory-exceeded";
        case TranslationUnitStatus::WorkerFailed: return "worker-failed";
    }
    return "worker-failed";
}

struct TranslationUnitReceipt {
    std::string canonical_path;
    std::string compile_command_sha256;
    std::size_t command_ordinal = 0;
    std::string phase;
    TranslationUnitStatus status = TranslationUnitStatus::WorkerFailed;
    std::uint64_t duration_ms = 0;
    std::uint64_t peak_memory_kib = 0;
    unsigned timeout_seconds = 0;
    unsigned memory_mib = 0;
};

struct AnalysisResult {
    std::size_t attempted_tus = 0;
    std::size_t analyzed_tus = 0;
    std::size_t broken_tus = 0;
    std::size_t incomplete_functions = 0;
    // `findings` is the complete visible result set. Experimental families
    // remain measurable but are report-only; only the remainder gates the
    // process verdict. Existing callers that set only `findings` retain the
    // historical all-findings-block behavior.
    std::size_t findings = 0;
    std::size_t report_only_findings = 0;
    std::vector<TranslationUnitReceipt> tu_receipts;

    // These flags can request additional diagnostic evidence, but they never
    // turn a broken or skipped requested TU into a trustworthy verdict.
    bool analyze_broken_tus = false;
    bool accept_partial_coverage = false;
    bool no_inputs = false;
    bool no_rules = false;
    bool compile_database_failed = false;
    bool tool_failed = false;
    bool summary_load_failed = false;
    bool summary_stale = false;
    bool summary_save_failed = false;
    bool baseline_load_failed = false;
    bool baseline_write_failed = false;
    bool baseline_recorded = false;
    bool report_write_failed = false;

    bool hasHardFailure() const {
        const bool nothing_analyzed =
            attempted_tus > 0 && analyzed_tus == 0;
        return no_inputs || no_rules || compile_database_failed ||
               tool_failed || nothing_analyzed ||
               hasResourceFailure() ||
               summary_save_failed || baseline_load_failed ||
               baseline_write_failed || report_write_failed;
    }

    bool hasResourceFailure() const {
        return std::any_of(
            tu_receipts.begin(), tu_receipts.end(),
            [](const TranslationUnitReceipt& receipt) {
                return receipt.status == TranslationUnitStatus::TimedOut ||
                       receipt.status ==
                           TranslationUnitStatus::MemoryExceeded ||
                       receipt.status ==
                           TranslationUnitStatus::WorkerFailed;
            });
    }

    std::size_t completedReceiptCount() const {
        return static_cast<std::size_t>(std::count_if(
            tu_receipts.begin(), tu_receipts.end(),
            [](const TranslationUnitReceipt& receipt) {
                return receipt.status == TranslationUnitStatus::Completed;
            }));
    }

    bool hasIncompleteEvidence() const {
        const bool partial_tu_coverage = broken_tus > 0;
        const bool unaccounted_tus =
            analyzed_tus + broken_tus < attempted_tus;
        const bool incomplete_receipt = std::any_of(
            tu_receipts.begin(), tu_receipts.end(),
            [](const TranslationUnitReceipt& receipt) {
                return receipt.status == TranslationUnitStatus::Broken ||
                       receipt.status == TranslationUnitStatus::Missing;
            });
        return partial_tu_coverage || unaccounted_tus || incomplete_receipt ||
               incomplete_functions > 0 ||
               summary_load_failed || summary_stale;
    }

    bool complete() const {
        return !hasHardFailure() && !hasIncompleteEvidence();
    }

    std::size_t blockingFindings() const {
        return findings - std::min(findings, report_only_findings);
    }

    AnalysisStatus status() const {
        if (hasHardFailure()) return AnalysisStatus::Failed;
        if (hasIncompleteEvidence()) return AnalysisStatus::Incomplete;
        if (baseline_recorded) return AnalysisStatus::Recorded;
        if (blockingFindings() > 0) return AnalysisStatus::Findings;
        return findings > 0 ? AnalysisStatus::ReportOnly
                            : AnalysisStatus::Clean;
    }

    // Stable process contract:
    //   0 complete + no blocking findings (clean, report-only, or baseline)
    //   1 complete + supported findings
    //   2 no trustworthy verdict (input, coverage, evidence, or I/O failure)
    int exitCode() const {
        if (!complete()) return 2;
        if (baseline_recorded) return 0;
        return blockingFindings() > 0 ? 1 : 0;
    }

    const char* statusName() const {
        switch (status()) {
            case AnalysisStatus::Clean: return "clean";
            case AnalysisStatus::Findings: return "findings";
            case AnalysisStatus::ReportOnly: return "report-only";
            case AnalysisStatus::Recorded: return "recorded";
            case AnalysisStatus::Incomplete: return "incomplete";
            case AnalysisStatus::Failed: return "failed";
        }
        return "failed";
    }
};

} // namespace codeskeptic

#endif // CODESKEPTIC_ANALYSIS_RESULT_H
