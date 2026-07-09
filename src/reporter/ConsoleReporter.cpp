#include "reporter/ConsoleReporter.h"

#include "core/Messages.h"

#include <iostream>

namespace zerodefect {

void ConsoleReporter::report(const DiagnosticList& diagnostics) {
    if (diagnostics.empty()) {
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

} // namespace zerodefect
