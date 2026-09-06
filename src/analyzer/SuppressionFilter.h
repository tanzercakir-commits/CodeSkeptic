#ifndef CODESKEPTIC_SUPPRESSION_FILTER_H
#define CODESKEPTIC_SUPPRESSION_FILTER_H

#include "core/Diagnostic.h"
#include "core/AnalysisResult.h"

#include <map>
#include <string>
#include <vector>
#include <utility>

namespace codeskeptic {

// Applies suppression comments found in the source code:
//   // codeskeptic-disable-line              -> all findings on that line
//   // codeskeptic-disable-line rule1,rule2  -> only these rules on that line
//   // codeskeptic-disable-next-line [...]   -> same, for the next line
// The rule list may be separated by spaces or commas.
// A supplied rationale follows `-- reason` or the legacy `(reason)` syntax.
// Only actual comment tokens are directives; quoted text is never executable.
class SuppressionFilter {
public:
    // Removes suppressed findings from the list, returns the number removed.
    size_t filter(DiagnosticList& diagnostics);

    // Tells whether a single finding is suppressed (testable).
    bool isSuppressed(const Diagnostic& diag);

    const std::vector<SuppressionRecord>& records() const { return records_; }
    std::vector<SuppressionRecord> takeRecords() { return std::move(records_); }

private:
    const SuppressionRecord* directiveFor(const Diagnostic& diag);

    std::map<std::string, std::vector<SuppressionRecord>> file_cache_;
    std::vector<SuppressionRecord> records_;
};

// Does the comment text suppress the given rule? (if no rule list follows
// the marker, all rules are suppressed) — exposed for unit testing.
bool markerSuppressesRule(const std::string& line_text,
                          const std::string& marker,
                          const std::string& rule_id);

} // namespace codeskeptic

#endif // CODESKEPTIC_SUPPRESSION_FILTER_H
