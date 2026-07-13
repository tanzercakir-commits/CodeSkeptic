#ifndef ZERODEFECT_SUMMARY_DIFF_H
#define ZERODEFECT_SUMMARY_DIFF_H

#include "engine/FunctionSummary.h"

#include <iosfwd>
#include <map>
#include <string>
#include <vector>

namespace zerodefect {

// Summary-diff (the core of the semantic regression signal): how did
// function CONTRACTS change between two harvests?
//
//  WEAKENED     a strong claim was lost or changed (NeverNull /
//               NeverZero dropped; a ReadsOnly/Frees param claim
//               turned into something else). CALLERS leaning on that
//               claim must be re-examined — CI gate: exit code 1.
//  STRENGTHENED a new strong claim was gained (informational; no risk).
//  CHANGED      a directionless change (like Unknown <-> Maybe*) —
//               the finding set may shift but no contract risk.
//  ADDED /      the key (qualified name + arity) entered / left in
//  REMOVED      the new file. A signature change shows the same
//               function as REMOVED+ADDED (the key includes arity —
//               deliberately: an arity change breaks all callers
//               anyway).
enum class ChangeKind { Added, Removed, Weakened, Strengthened, Changed };

struct SummaryChange {
    ChangeKind kind;
    std::string key;
    std::string detail;  // field diffs, human-readable ("rn: N -> M" etc.)
};

struct SummaryDiffResult {
    // Ordering: Weakened first (most important), then the rest by key
    std::vector<SummaryChange> changes;
    size_t weakened = 0;
    size_t strengthened = 0;
    size_t changed = 0;
    size_t added = 0;
    size_t removed = 0;
};

using SummaryMap =
    std::map<std::string, SummaryRegistry::FunctionSummary>;

SummaryDiffResult diffSummaries(const SummaryMap& oldMap,
                                const SummaryMap& newMap);

// Parses the two files, writes the diff to `out` (machine-greppable
// "SUMMARY_DIFF <KIND> <key> <detail>" lines + a summary). Exit code:
// 0 = no weakening, 1 = has WEAKENED (CI gate), 2 = file unreadable.
// gateWeakened=false (--gate warn, CONTRACTS.md §5): WEAKENED is
// still fully reported but exits 0 — the adoption ramp for projects
// not ready to break CI on inferred-contract drift. Unreadable files
// stay exit 2 regardless: a gate that can't read its input must
// never look green.
int reportSummaryDiff(const std::string& oldPath,
                      const std::string& newPath, std::ostream& out,
                      bool gateWeakened = true);

} // namespace zerodefect

#endif // ZERODEFECT_SUMMARY_DIFF_H
