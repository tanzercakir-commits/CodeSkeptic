#include "engine/CoverageReport.h"

#include "engine/DataflowEngine.h"

namespace codeskeptic {

CoverageReport& CoverageReport::instance() {
    static CoverageReport report;
    return report;
}

void CoverageReport::recordNonConvergence(const std::string& function) {
    if (!seen_.insert(function).second) return;  // one gap per function
    entries_.push_back({function, CoverageGap::NonConvergence});
}

void CoverageReport::recordCfgUnavailable(const std::string& function) {
    if (!seen_.insert(function).second) return;  // one gap per function
    entries_.push_back({function, CoverageGap::CfgUnavailable});
}

void CoverageReport::recordDataflowFailure(const std::string& function,
                                           DataflowFailure failure) {
    if (failure == DataflowFailure::CfgUnavailable)
        recordCfgUnavailable(function);
    else if (failure == DataflowFailure::IterationLimit)
        recordNonConvergence(function);
}

void CoverageReport::clear() {
    entries_.clear();
    seen_.clear();
}

} // namespace codeskeptic
