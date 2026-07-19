#ifndef CODESKEPTIC_SUPPRESSION_FILTER_H
#define CODESKEPTIC_SUPPRESSION_FILTER_H

#include "core/Diagnostic.h"

#include <map>
#include <string>
#include <vector>

namespace codeskeptic {

// Applies suppression comments found in the source code:
//   // codeskeptic-disable-line              -> all findings on that line
//   // codeskeptic-disable-line rule1,rule2  -> only these rules on that line
//   // codeskeptic-disable-next-line [...]   -> same, for the next line
// The rule list may be separated by spaces or commas.
class SuppressionFilter {
public:
    // Removes suppressed findings from the list, returns the number removed.
    size_t filter(DiagnosticList& diagnostics);

    // Tells whether a single finding is suppressed (testable).
    bool isSuppressed(const Diagnostic& diag);

private:
    const std::vector<std::string>* linesFor(const std::string& path);

    std::map<std::string, std::vector<std::string>> file_cache_;
};

// Does the comment text suppress the given rule? (if no rule list follows
// the marker, all rules are suppressed) — exposed for unit testing.
bool markerSuppressesRule(const std::string& line_text,
                          const std::string& marker,
                          const std::string& rule_id);

} // namespace codeskeptic

#endif // CODESKEPTIC_SUPPRESSION_FILTER_H
