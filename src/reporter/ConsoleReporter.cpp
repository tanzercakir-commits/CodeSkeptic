#include "source_manager/SourceManager.h"
#include "reporter/ConsoleReporter.h"

#include "core/Messages.h"
#include "reporter/ReportContract.h"

#include <iostream>

namespace codeskeptic {

bool ConsoleReporter::report(const DiagnosticList& diagnostics,
                             const AnalysisResult* result) {
    // Stable, single-line records accompany the readable presentation. Strings
    // are escaped so user text cannot forge another record or terminal control.
    std::cerr << "[CodeSkeptic] report: ";
    writeReportRunJson(std::cerr, diagnostics.size(), result);
    std::cerr << '\n';
    if (diagnostics.empty()) {
        // Suppressed when NOTHING was actually analyzed (every TU
        // broken): printing "Clean!" a line above the exit-2 failure
        // message would be a contradiction (v0.4.5 fail-loud policy).
        if (result && result->complete() && result->broken_tus == 0 &&
                      result->recovery_tus == 0)
            std::cerr << msg(MsgId::CleanNoIssues) << "\n";
        else if (result && result->complete())
            std::cerr << "[CodeSkeptic] " << result->statusName()
                      << ": no findings in accepted evidence; not a full clean analysis.\n";
        return true;
    }

    std::cerr << msg(MsgId::FindingsCount,
                     std::to_string(diagnostics.size())) << "\n";
    if (result && result->report_only_findings > 0) {
        std::cerr << "[CodeSkeptic] Verdict gate: "
                  << result->blockingFindings() << " blocking, "
                  << result->report_only_findings
                  << " experimental report-only finding(s).\n";
    }
    std::cerr << "----------------------------------------\n";

    for (const auto& diag : diagnostics) {
        std::cerr << escapeJson(coveragePathIdentity(diag.file)) << ':' << diag.line << ':' << diag.column
                  << " [" << diag.severityToString() << "] "
                  << escapeJson(diag.rule_id) << ": " << escapeJson(diag.message) << "\n";
        std::cerr << "    CWE:";
        const auto ids = findingCweIds(diag);
        if (ids.empty()) std::cerr << " no classified mapping";
        for (int id : ids) std::cerr << " CWE-" << id;
        std::cerr << '\n';
        for (const auto& note : diag.notes) {
            std::cerr << "    -> " << escapeJson(coveragePathIdentity(note.file)) << ":" << note.line
                      << ":" << note.column << " " << escapeJson(note.message) << "\n";
        }
        std::cerr << "[CodeSkeptic] finding: ";
        writeReportFindingJson(std::cerr, diag);
        std::cerr << '\n';
    }

    std::cerr << "----------------------------------------\n";
    return true;
}

std::string ConsoleReporter::format() const {
    return "console";
}

} // namespace codeskeptic
