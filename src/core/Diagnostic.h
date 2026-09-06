#ifndef CODESKEPTIC_DIAGNOSTIC_H
#define CODESKEPTIC_DIAGNOSTIC_H

#include <string>
#include <vector>

namespace codeskeptic {

enum class Severity {
    Info,
    Warning,
    Error
};

// Producer-owned semantics, independent of translated message text. Reporting
// metadata does not participate in finding identity or deduplication.
enum class FindingKind {
    Unspecified,
    ArithmeticUpper,
    ArithmeticLower,
    ArithmeticBoth,
    NarrowingUpper,
    NarrowingLower,
    NarrowingBoth,
    BoundsRead,
    BoundsWrite,
    BoundsReadWrite,
    BoundsAddress,
    BoundsUnboundedCopy,
    SignedToUnsigned,
    LossyConversion,
    MemoryDoubleRelease,
    ResourceDoubleRelease,
    MemoryUseAfterRelease,
    ResourceUseAfterRelease,
    MemoryLeak,
    HandleLeak,
    GenericResourceLeak,
};

// Dataflow trace step attached to a finding: the chain of events that
// leads to the error (e.g. "p allocated here", "p freed here"). The
// answer to "why?" for both human and LLM consumers.
struct TraceNote {
    std::string file;
    unsigned line = 0;
    unsigned column = 0;
    std::string message;

    bool operator<(const TraceNote& other) const {
        if (file != other.file) return file < other.file;
        if (line != other.line) return line < other.line;
        return column < other.column;
    }
};

struct Diagnostic {
    Severity severity;
    std::string file;
    unsigned line;
    unsigned column;
    std::string rule_id;
    std::string message;
    std::string function;          // function the finding occurs in
    std::vector<TraceNote> notes;  // function and notes excluded from ordering
    // csf1 semantic identity, assigned after path canonicalization and before
    // reporting. Excluded from ordering/equality so presentation metadata
    // cannot change finding deduplication.
    std::string fingerprint;
    FindingKind kind = FindingKind::Unspecified;
    // Equivalent findings from different compilation commands can carry
    // different proven subtypes. Retain their union without changing the
    // existing finding key, count or source fingerprint.
    std::vector<FindingKind> additional_kinds;
    // Baseline-only, AST-proven function signature (csb-fn1). Empty means
    // ownership could not be bound safely, NOT a wildcard. Not a finding key.
    std::string baseline_function;

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
        // Remaining fields: deterministic order + equal records must be
        // adjacent (required for deduplication via std::unique)
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

} // namespace codeskeptic

#endif // CODESKEPTIC_DIAGNOSTIC_H
