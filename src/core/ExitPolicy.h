#ifndef CODESKEPTIC_EXIT_POLICY_H
#define CODESKEPTIC_EXIT_POLICY_H

#include <cstddef>

namespace codeskeptic {

// Process exit code policy (v0.4.5, the fail-loud half of the first
// external hardware evaluation's P1):
//   0 — analysis ran, no findings
//   1 — analysis ran, findings reported
//   2 — no trustworthy verdict: no inputs or any requested translation
//       unit was skipped (unless --analyze-broken-tus explicitly accepts
//       error-recovery ASTs). Partial coverage is evidence, not a verdict.
inline int analysisExitCode(int findings, std::size_t total_tus,
                            std::size_t broken_tus,
                            bool analyze_broken_tus) {
    if (total_tus == 0 || (broken_tus > 0 && !analyze_broken_tus))
        return 2;
    return findings > 0 ? 1 : 0;
}

} // namespace codeskeptic

#endif // CODESKEPTIC_EXIT_POLICY_H
