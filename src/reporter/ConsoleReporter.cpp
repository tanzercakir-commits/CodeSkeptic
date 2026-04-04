#include "reporter/ConsoleReporter.h"

#include <iostream>

namespace zerodefect {

void ConsoleReporter::report(const DiagnosticList& diagnostics) {
    if (diagnostics.empty()) {
        std::cerr << "ZeroDefect: Temiz! Sorun bulunamadi.\n";
        return;
    }

    std::cerr << "ZeroDefect: " << diagnostics.size() << " bulgu\n";
    std::cerr << "----------------------------------------\n";

    for (const auto& diag : diagnostics) {
        std::cerr << diag.location()
                  << " [" << diag.severityToString() << "] "
                  << diag.rule_id << ": " << diag.message << "\n";
    }

    std::cerr << "----------------------------------------\n";
}

std::string ConsoleReporter::format() const {
    return "console";
}

} // namespace zerodefect
