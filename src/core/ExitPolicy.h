#ifndef CODESKEPTIC_EXIT_POLICY_H
#define CODESKEPTIC_EXIT_POLICY_H

#include <cstddef>

namespace codeskeptic {

// Process exit code policy (v0.4.5, the fail-loud half of the first
// external hardware evaluation's P1):
//   0 — analysis ran, no findings
//   1 — analysis ran, findings reported
//   2 — NOTHING was analyzed: every attempted translation unit failed
//       to compile (and --analyze-broken-tus was not given). The old
//       behavior — "Clean! No issues found." + exit 0 — is the worst
//       possible failure mode for an analyzer in CI: a green tick with
//       zero coverage. Partial breakage keeps the honest per-TU
//       warning and the findings-based code: some coverage is not NO
//       coverage, and corpus/real-world flows depend on that.
inline int analysisExitCode(int findings, std::size_t total_tus,
                            std::size_t broken_tus,
                            bool analyze_broken_tus) {
    if (total_tus > 0 && broken_tus >= total_tus && !analyze_broken_tus)
        return 2;
    return findings > 0 ? 1 : 0;
}

} // namespace codeskeptic

#endif // CODESKEPTIC_EXIT_POLICY_H
