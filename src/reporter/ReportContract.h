#ifndef CODESKEPTIC_REPORTER_REPORT_CONTRACT_H
#define CODESKEPTIC_REPORTER_REPORT_CONTRACT_H

#include "core/Capabilities.h"
#include "core/Diagnostic.h"
#include "core/FindingFingerprint.h"
#include "reporter/ReportEncoding.h"

namespace codeskeptic {

// Independent of the native SARIF 2.1.0 and source-coverage/v1 envelopes.
inline constexpr const char* reportSchema = "codeskeptic-report/v1";

inline void writeReportEvidenceJson(std::ostream& out, const AnalysisResult& result) {
    out << "{ \"no_inputs\": " << (result.no_inputs ? "true" : "false")
        << ", \"no_rules\": " << (result.no_rules ? "true" : "false")
        << ", \"tool_failed\": " << (result.tool_failed ? "true" : "false")
        << ", \"summary_load_failed\": " << (result.summary_load_failed ? "true" : "false")
        << ", \"summary_stale\": " << (result.summary_stale ? "true" : "false")
        << ", \"summary_save_failed\": " << (result.summary_save_failed ? "true" : "false")
        << ", \"baseline_load_failed\": " << (result.baseline_load_failed ? "true" : "false")
        << ", \"baseline_write_failed\": " << (result.baseline_write_failed ? "true" : "false")
        << ", \"baseline_recorded\": " << (result.baseline_recorded ? "true" : "false")
        << ", \"report_write_failed\": " << (result.report_write_failed ? "true" : "false") << " }";
}

// Console already receives one authoritative source-coverage record from the
// analyzer. SARIF has its native invocation coverage property. Neither repeats it.
inline void writeReportRunFields(std::ostream& out, std::size_t total,
                                 const AnalysisResult* result, bool includeCoverage) {
    out << "\"tool\": \"CodeSkeptic\", \"tool_version\": \"" << escapeJson(toolVersion())
        << "\", \"schema\": \"" << reportSchema << "\", \"status\": \""
        << (result ? result->statusName() : "not-recorded") << "\", \"complete\": ";
    if (result) out << (result->complete() ? "true" : "false");
    else out << "null";
    out << ", \"exit_code\": ";
    if (result) out << result->exitCode();
    else out << "null";
    out << ", \"evidence\": ";
    if (result) writeReportEvidenceJson(out, *result);
    else out << "null";
    out << ", \"finding_counts\": ";
    if (result) {
        out << "{ \"total\": " << result->findings
            << ", \"blocking\": " << result->blockingFindings()
            << ", \"report_only\": " << result->report_only_findings << " }";
    } else out << "null";
    out << ", \"total\": " << total;
    if (includeCoverage) {
        out << ", \"coverage\": ";
        if (result) writeCoverageJson(out, *result);
        else out << "null";
    }
}

inline void writeReportRunJson(std::ostream& out, std::size_t total,
                               const AnalysisResult* result, bool includeCoverage = false) {
    out << "{ ";
    writeReportRunFields(out, total, result, includeCoverage);
    out << " }";
}

inline void writeReportFindingJson(std::ostream& out, const Diagnostic& diag) {
    const auto* capability = findRuleCapability(diag.rule_id);
    out << "{ \"severity\": \"" << diag.severityToString()
        << "\", \"rule_id\": \"" << escapeJson(diag.rule_id) << "\", \"rule_metadata\": ";
    writeFindingMetadataJson(out, diag);
    out << ", \"capability_tier\": \""
        << (capability ? capabilityTierName(capability->tier) : "unclassified")
        << "\", \"blocks_verdict\": " << (findingBlocksVerdict(diag.rule_id) ? "true" : "false")
        << ", \"fingerprint\": \""
        << escapeJson(diag.fingerprint.empty() ? findingFingerprint(diag) : diag.fingerprint)
        << "\", \"file\": \"" << escapeJson(coveragePathIdentity(diag.file))
        << "\", \"line\": " << diag.line << ", \"column\": " << diag.column
        << ", \"function\": \"" << escapeJson(diag.function)
        << "\", \"message\": \"" << escapeJson(diag.message) << "\", \"notes\": [";
    for (std::size_t index = 0; index < diag.notes.size(); ++index) {
        const auto& note = diag.notes[index];
        if (index) out << ", ";
        out << "{ \"file\": \"" << escapeJson(coveragePathIdentity(note.file))
            << "\", \"line\": " << note.line << ", \"column\": " << note.column
            << ", \"message\": \"" << escapeJson(note.message) << "\" }";
    }
    out << "] }";
}

inline void writeReportJson(std::ostream& out, const DiagnosticList& diagnostics,
                            const AnalysisResult* result) {
    out << "{\n  ";
    writeReportRunFields(out, diagnostics.size(), result, true);
    out << ",\n  \"diagnostics\": [";
    for (std::size_t index = 0; index < diagnostics.size(); ++index) {
        if (index) out << ',';
        out << "\n    ";
        writeReportFindingJson(out, diagnostics[index]);
    }
    out << "\n  ]\n}\n";
}

} // namespace codeskeptic
#endif
