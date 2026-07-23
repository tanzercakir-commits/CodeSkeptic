#include "source_manager/SourceManager.h"
#include "reporter/ConsoleReporter.h"

#include "core/Messages.h"

#include <iostream>

namespace codeskeptic {

void ConsoleReporter::report(const DiagnosticList& diagnostics) {
    if (diagnostics.empty()) {
        // Suppressed when NOTHING was actually analyzed (every TU
        // broken): printing "Clean!" a line above the exit-2 failure
        // message would be a contradiction (v0.4.5 fail-loud policy).
        const std::size_t total = SourceManager::attemptedTUCount();
        const std::size_t broken = SourceManager::brokenTUs().size();
        if (!(total > 0 && broken >= total &&
              !SourceManager::analyzeBrokenTUs()))
            std::cerr << msg(MsgId::CleanNoIssues) << "\n";
        return;
    }

    std::cerr << msg(MsgId::FindingsCount,
                     std::to_string(diagnostics.size())) << "\n";
    std::cerr << "----------------------------------------\n";

    for (const auto& diag : diagnostics) {
        std::cerr << diag.location()
                  << " [" << diag.severityToString() << "] "
                  << diag.rule_id << ": " << diag.message << "\n";
        for (const auto& note : diag.notes) {
            std::cerr << "    -> " << note.file << ":" << note.line
                      << ":" << note.column << " " << note.message << "\n";
        }
    }

    std::cerr << "----------------------------------------\n";
}

std::string ConsoleReporter::format() const {
    return "console";
}

} // namespace codeskeptic
