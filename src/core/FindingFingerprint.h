#ifndef CODESKEPTIC_FINDING_FINGERPRINT_H
#define CODESKEPTIC_FINDING_FINGERPRINT_H

#include "core/Diagnostic.h"

#include <map>
#include <string>
#include <vector>

namespace codeskeptic {

// Stable semantic finding identity (schema csf1). The checkout root and source
// line number are deliberately excluded: the identity follows the same
// finding across machines, harmless line shifts, severity changes, and message
// wording changes. A short path tail, function, rule, and normalized source
// statement identify the semantic site; duplicate sites retain multiset counts
// in measurement receipts.
class FindingFingerprintContext {
public:
  std::string fingerprint(const Diagnostic &diagnostic);

private:
  std::map<std::string, std::vector<std::string>> source_lines_;
};

std::string findingFingerprint(const Diagnostic &diagnostic);
void assignFindingFingerprints(DiagnosticList &diagnostics);

} // namespace codeskeptic

#endif // CODESKEPTIC_FINDING_FINGERPRINT_H
