#ifndef CODESKEPTIC_BASELINE_H
#define CODESKEPTIC_BASELINE_H

#include "core/Diagnostic.h"

#include <map>
#include <string>

namespace codeskeptic {

// Baseline: freezes the current findings into a file; subsequent runs
// report ONLY NEW findings. The standard path for gradual adoption on
// legacy code.
//
// The v2 key is LINE-INDEPENDENT: instead of the line number it uses a
// hash of the trimmed TEXT content of the finding's line (FNV-1a 64 —
// stable across platforms; std::hash gives no such guarantee). When
// code is added above and the finding shifts, the key does not change;
// if the line ITSELF changes, the finding reappears — that is a
// feature (a changed line should be re-reviewed).
//
// Multiple findings with the same key are tracked by COUNT (multiset
// semantics): baselining one of two identical `delete p;` lines in two
// different functions does not hide the other.
//
// Format: "# codeskeptic-baseline v2" header + one key per line
// (rule_id|file|line-hash|message; duplicates preserved). Headerless
// old v1 files (rule_id|file|line|message) are recognized on load and
// keep matching with their old meaning — refreshing the baseline
// migrates to v2.
class Baseline {
public:
    // Writes findings to the baseline file (v2 format). Returns success.
    static bool write(const std::string& path,
                      const DiagnosticList& diagnostics);

    // Loads the baseline file. A missing file means an empty baseline
    // (not an error).
    bool load(const std::string& path);

    // Removes findings recorded in the baseline from the list, returns
    // the number removed. Per key, as many findings are suppressed as
    // there are recorded entries.
    size_t filter(DiagnosticList& diagnostics) const;

    // v1: old line-number key (only for legacy file compatibility)
    static std::string keyV1(const Diagnostic& diag);
    // v2: line-content-hash key (diag.file is read from disk)
    static std::string keyV2(const Diagnostic& diag);

private:
    std::map<std::string, int> counts_;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_BASELINE_H
