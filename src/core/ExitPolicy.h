#ifndef CODESKEPTIC_EXIT_POLICY_H
#define CODESKEPTIC_EXIT_POLICY_H

#include <cstddef>

namespace codeskeptic {

// Process exit code policy (v0.4.5, the fail-loud half of the first
// external hardware evaluation's P1):
//   0 — analysis ran, no supported/blocking findings
//   1 — analysis ran, supported/blocking findings reported
//   2 — no trustworthy verdict: no inputs or any requested translation
//       unit was broken or skipped. Error-recovery and partial-coverage
//       opt-ins may collect evidence, but cannot manufacture a verdict.
inline int analysisExitCode(int blocking_findings, std::size_t total_tus,
                            std::size_t broken_tus,
                            bool analyze_broken_tus) {
    (void)analyze_broken_tus;
    if (total_tus == 0 || broken_tus > 0)
        return 2;
    return blocking_findings > 0 ? 1 : 0;
}

} // namespace codeskeptic

#endif // CODESKEPTIC_EXIT_POLICY_H
