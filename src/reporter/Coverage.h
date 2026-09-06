#ifndef CODESKEPTIC_REPORTER_COVERAGE_H
#define CODESKEPTIC_REPORTER_COVERAGE_H

#include "core/AnalysisResult.h"
#include <ostream>

namespace codeskeptic {

inline void writeCoverageString(std::ostream& out, const std::string& value) {
    static constexpr char hex[] = "0123456789abcdef";
    out << '"';
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') out << '\\' << static_cast<char>(c);
        else if (c < 0x20) out << "\\u00" << hex[c >> 4] << hex[c & 15];
        else out << static_cast<char>(c);
    }
    out << '"';
}

// JSON, SARIF and the CLI consume one representation, not independently
// reconstructed counters. Legacy attempted/analyzed/broken keys stay available.
inline void writeCoverageJson(std::ostream& out, const AnalysisResult& result) {
    std::size_t commands = 0, analyzed = 0, skipped = 0, failed = 0;
    for (const auto& source : result.sources) {
        commands += source.commands;
        analyzed += source.analyzed_commands;
        skipped += source.skipped_commands;
        failed += source.failed_commands;
    }
    out << "{ \"attempted_tus\": " << result.attempted_tus
        << ", \"analyzed_tus\": " << result.analyzed_tus
        << ", \"broken_tus\": " << result.broken_tus
        << ", \"skipped_tus\": " << result.broken_tus
        << ", \"failed_tus\": " << result.failed_tus
        << ", \"recovery_tus\": " << result.recovery_tus
        << ", \"schema\": \"codeskeptic-source-coverage/v1\""
        << ", \"attempted_commands\": " << commands
        << ", \"analyzed_commands\": " << analyzed
        << ", \"skipped_commands\": " << skipped
        << ", \"failed_commands\": " << failed
        << ", \"incomplete_functions\": " << result.incomplete_functions
        << ", \"complete\": " << (result.coverageComplete() ? "true" : "false")
        << ", \"accept_partial_coverage\": "
        << (result.accept_partial_coverage ? "true" : "false")
        << ", \"analyze_broken_tus\": "
        << (result.analyze_broken_tus ? "true" : "false")
        << ", \"sources\": [";
    bool first = true;
    for (const auto& source : result.sources) {
        if (!first) out << ", ";
        first = false;
        out << "{ \"file\": ";
        writeCoverageString(out, source.file);
        out << ", \"status\": \"" << source.statusName() << "\", \"reason\": ";
        writeCoverageString(out, source.reason);
        out << ", \"commands\": " << source.commands
            << ", \"analyzed_commands\": " << source.analyzed_commands
            << ", \"skipped_commands\": " << source.skipped_commands
            << ", \"failed_commands\": " << source.failed_commands
            << ", \"recovery_commands\": " << source.recovery_commands
            << ", \"prepass\": { \"status\": ";
        writeCoverageString(out, source.prepass_status);
        out << ", \"reason\": ";
        writeCoverageString(out, source.prepass_reason);
        out << ", \"recovery_commands\": " << source.prepass_recovery_commands << " } }";
    }
    out << "] }";
}

inline void writeCoverageConsole(std::ostream& out, const AnalysisResult& result) {
    out << "[CodeSkeptic] source coverage: ";
    writeCoverageJson(out, result);
    out << '\n';
}

} // namespace codeskeptic
#endif
