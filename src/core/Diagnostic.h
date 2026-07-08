#ifndef ZERODEFECT_DIAGNOSTIC_H
#define ZERODEFECT_DIAGNOSTIC_H

#include <string>
#include <vector>

namespace zerodefect {

enum class Severity {
    Info,
    Warning,
    Error
};

struct Diagnostic {
    Severity severity;
    std::string file;
    unsigned line;
    unsigned column;
    std::string rule_id;
    std::string message;

    std::string severityToString() const {
        switch (severity) {
            case Severity::Info:    return "info";
            case Severity::Warning: return "warning";
            case Severity::Error:   return "error";
        }
        return "unknown";
    }

    std::string location() const {
        return file + ":" + std::to_string(line) + ":" + std::to_string(column);
    }

    bool operator<(const Diagnostic& other) const {
        if (severity != other.severity)
            return severity > other.severity;
        if (file != other.file)
            return file < other.file;
        if (line != other.line)
            return line < other.line;
        // Kalan alanlar: deterministik sira + esit kayitlarin bitisik
        // gelmesi (std::unique ile tekillestirme icin sart)
        if (column != other.column)
            return column < other.column;
        if (rule_id != other.rule_id)
            return rule_id < other.rule_id;
        return message < other.message;
    }

    bool operator==(const Diagnostic& other) const {
        return severity == other.severity && file == other.file &&
               line == other.line && column == other.column &&
               rule_id == other.rule_id && message == other.message;
    }
};

using DiagnosticList = std::vector<Diagnostic>;

} // namespace zerodefect

#endif // ZERODEFECT_DIAGNOSTIC_H
