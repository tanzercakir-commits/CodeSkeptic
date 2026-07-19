#ifndef CODESKEPTIC_COVERAGE_REPORT_H
#define CODESKEPTIC_COVERAGE_REPORT_H

// CoverageReport (2026-07-15): the first step toward the "assurance
// engine" stance — an analyzer must not let "no warning" be read as
// "proven safe". Where the dataflow could NOT be driven to a fixpoint
// (the per-function iteration cap was hit), findings in that function
// are INCOMPLETE, not a clean bill. This process-global accumulator
// collects those gaps so the run can surface them as one honest
// coverage summary instead of six scattered per-rule stderr lines
// (every rule re-reported the same non-converged function).
//
// v0 tracks a single gap kind — non-convergence — because that is the
// one incompleteness signal the engine already produces. Opaque
// external calls and unsupported constructs are later gap kinds; the
// enum leaves room. Cleared per analysis run (StaticAnalyzer ctor/dtor),
// exactly like the other global engine state, so a long-lived process
// (the MCP server) never leaks one run's gaps into the next.

#include <cstddef>
#include <set>
#include <string>
#include <vector>

namespace codeskeptic {

enum class CoverageGap {
    NonConvergence,   // dataflow hit the iteration cap; findings incomplete
};

struct CoverageEntry {
    std::string function;
    CoverageGap gap;
};

class CoverageReport {
public:
    static CoverageReport& instance();

    // Record that `function`'s dataflow did not converge. Deduplicated:
    // the six rules each analyze the same function, but the coverage gap
    // belongs to the function, not the rule — so only the first report
    // per function is kept.
    void recordNonConvergence(const std::string& function);

    const std::vector<CoverageEntry>& entries() const { return entries_; }
    // Number of distinct functions with any coverage gap.
    std::size_t incompleteCount() const { return entries_.size(); }

    void clear();

private:
    std::vector<CoverageEntry> entries_;
    std::set<std::string> seen_;   // dedup key: function name
};

} // namespace codeskeptic

#endif // CODESKEPTIC_COVERAGE_REPORT_H
