#ifndef CODESKEPTIC_ANALYSIS_RESULT_H
#define CODESKEPTIC_ANALYSIS_RESULT_H

#include "core/Diagnostic.h"
#include <algorithm>
#include <cstddef>
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
    PartialAccepted,
    RecoveryAccepted,
    Incomplete,
    Failed,
};

enum class SourceStatus { Analyzed, Skipped, Failed };

// An applied decision, retained after the finding leaves the visible list.
// Legacy comments have no supplied rationale: never invent one for the owner.
struct SuppressionRecord {
    Diagnostic finding{};
    unsigned marker_line = 0;
    unsigned target_line = 0;
    std::string marker;
    std::vector<std::string> rules;
    std::string reason;
    bool has_reason = false;
    std::size_t occurrences = 1;
};

// One canonical requested source, irrespective of the number of compile
// variants or AST callbacks. A failed/skipped variant dominates success.
struct SourceCoverage {
    std::string file;
    SourceStatus status = SourceStatus::Failed;
    std::string reason = "not_processed";
    std::size_t commands = 0;
    std::size_t analyzed_commands = 0;
    std::size_t skipped_commands = 0;
    std::size_t failed_commands = 0;
    std::size_t recovery_commands = 0;
    std::string prepass_status = "not_requested";
    std::string prepass_reason;
    std::size_t prepass_recovery_commands = 0;

    const char* statusName() const {
        switch (status) {
            case SourceStatus::Analyzed: return "analyzed";
            case SourceStatus::Skipped: return "skipped";
            case SourceStatus::Failed: return "failed";
        }
        return "failed";
    }
};

struct AnalysisResult {
    std::vector<SuppressionRecord> suppressions;
    unsigned baseline_version = 0;
    bool baseline_legacy_identity = false;
    std::size_t baseline_matched = 0;
    std::size_t baseline_unbound = 0;
    std::size_t attempted_tus = 0;
    std::size_t analyzed_tus = 0;
    std::size_t broken_tus = 0;
    std::size_t failed_tus = 0;
    std::size_t recovery_tus = 0;
    std::vector<SourceCoverage> sources;
    std::size_t incomplete_functions = 0;
    // `findings` is the complete visible result set. Experimental families
    // remain measurable but are report-only; only the remainder gates the
    // process verdict. Existing callers that set only `findings` retain the
    // historical all-findings-block behavior.
    std::size_t findings = 0;
    std::size_t report_only_findings = 0;

    bool analyze_broken_tus = false;
    bool accept_partial_coverage = false;
    bool no_inputs = false;
    bool no_rules = false;
    bool tool_failed = false;
    bool summary_load_failed = false;
    bool summary_stale = false;
    bool summary_save_failed = false;
    bool baseline_load_failed = false;
    bool baseline_write_failed = false;
    bool baseline_recorded = false;
    bool report_write_failed = false;

    void reconcileSources() {
        attempted_tus = sources.size();
        analyzed_tus = broken_tus = failed_tus = recovery_tus = 0;
        for (const auto& source : sources) {
            switch (source.status) {
                case SourceStatus::Analyzed: ++analyzed_tus; break;
                case SourceStatus::Skipped: ++broken_tus; break;
                case SourceStatus::Failed: ++failed_tus; break;
            }
            if (source.recovery_commands > 0 || source.prepass_recovery_commands > 0)
                ++recovery_tus;
        }
    }

    bool hasHardFailure() const {
        const bool nothing_analyzed =
            attempted_tus > 0 && analyzed_tus == 0 && !analyze_broken_tus;
        const bool impossible_counts = analyzed_tus > attempted_tus ||
            broken_tus > attempted_tus - std::min(attempted_tus, analyzed_tus);
        return no_inputs || no_rules || tool_failed || failed_tus > 0 ||
               impossible_counts || nothing_analyzed ||
               summary_save_failed || baseline_load_failed ||
               baseline_write_failed || report_write_failed;
    }

    bool hasIncompleteEvidence() const {
        const bool partial_tu_coverage =
            broken_tus > 0 && !analyze_broken_tus &&
            !accept_partial_coverage;
        const bool unaccounted_tus =
            analyzed_tus < attempted_tus &&
            broken_tus < attempted_tus - analyzed_tus;
        return partial_tu_coverage || unaccounted_tus ||
               incomplete_functions > 0 ||
               summary_load_failed || summary_stale;
    }

    bool complete() const {
        return !hasHardFailure() && !hasIncompleteEvidence();
    }

    // Explicit opt-ins may accept a subset/recovery verdict, but never make
    // its underlying coverage fully trustworthy. Keep that distinction visible.
    bool coverageComplete() const {
        return complete() && attempted_tus > 0 &&
               analyzed_tus == attempted_tus && broken_tus == 0 &&
               failed_tus == 0 && recovery_tus == 0;
    }

    std::size_t blockingFindings() const {
        return findings - std::min(findings, report_only_findings);
    }

    AnalysisStatus status() const {
        if (hasHardFailure()) return AnalysisStatus::Failed;
        if (hasIncompleteEvidence()) return AnalysisStatus::Incomplete;
        if (broken_tus > 0) return AnalysisStatus::PartialAccepted;
        if (recovery_tus > 0) return AnalysisStatus::RecoveryAccepted;
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
            case AnalysisStatus::PartialAccepted: return "partial-accepted";
            case AnalysisStatus::RecoveryAccepted: return "recovery-accepted";
            case AnalysisStatus::Incomplete: return "incomplete";
            case AnalysisStatus::Failed: return "failed";
        }
        return "failed";
    }
};

} // namespace codeskeptic

#endif // CODESKEPTIC_ANALYSIS_RESULT_H
