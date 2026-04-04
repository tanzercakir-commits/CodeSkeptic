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
        return line < other.line;
    }
};

using DiagnosticList = std::vector<Diagnostic>;

} // namespace zerodefect

#endif // ZERODEFECT_DIAGNOSTIC_H
