#include "engine/CoverageReport.h"

namespace codeskeptic {

CoverageReport& CoverageReport::instance() {
    static CoverageReport report;
    return report;
}

void CoverageReport::recordNonConvergence(const std::string& function) {
    if (!seen_.insert(function).second) return;  // one gap per function
    entries_.push_back({function, CoverageGap::NonConvergence});
}

void CoverageReport::clear() {
    entries_.clear();
    seen_.clear();
}

} // namespace codeskeptic
