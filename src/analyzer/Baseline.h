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
// v3 binds rule, full path, function name and AST-proven signature, severity,
// indentation-relative column, trimmed source line and message. Hex fields
// preserve delimiters/control bytes without hashing away identity. Line shifts
// remain stable. Equivalent TU callbacks consume ONE logical finding budget.
// Unbound findings are explicitly recorded but can never suppress a finding.
// Valid v1/v2 files keep their original weak matching semantics, disclosed by
// version()/legacy(); no mixed-format or malformed file is partially accepted.
class Baseline {
public:
    // Writes v3. Optional count exposes findings without sufficient identity.
    static bool write(const std::string& path,
                      const DiagnosticList& diagnostics,
                      std::size_t* unbound = nullptr);

    // Missing, malformed or unreadable files fail; failed load clears state.
    bool load(const std::string& path);

    // Removes findings recorded in the baseline from the list, returns
    // the number removed. Per key, as many findings are suppressed as
    // there are recorded entries.
    size_t filter(DiagnosticList& diagnostics) const;

    // v1: old line-number key (only for legacy file compatibility)
    static std::string keyV1(const Diagnostic& diag);
    // v2: line-content-hash key (diag.file is read from disk)
    static std::string keyV2(const Diagnostic& diag);
    // Empty means unbound, never a wildcard. Public csf1 remains unchanged.
    static std::string keyV3(const Diagnostic& diag);
    unsigned version() const { return version_; }
    bool legacy() const { return version_ == 1 || version_ == 2; }
    std::size_t unboundRecords() const { return unbound_; }

private:
    std::map<std::string, std::size_t> counts_;
    unsigned version_ = 0;
    std::size_t unbound_ = 0;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_BASELINE_H
