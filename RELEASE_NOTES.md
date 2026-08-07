# CodeSkeptic v0.4.8 — fail-closed verdict integrity

v0.4.8 makes one promise precise across every interface: a clean result is
published only when CodeSkeptic produced a complete, trustworthy verdict.
Findings and analyzer failure are no longer two spellings of the same
non-zero exit, and integrations can no longer turn missing analysis into a
green “0 findings” result.

## One verdict contract

CLI, MCP and report writers now consume the same `AnalysisResult` evidence:
translation units attempted, analyzed and broken; incomplete dataflow
functions; whole-program summary freshness/load failures; and artifact I/O.

- **Exit 0 — complete and clean.** Every requested unit and analysis
  obligation completed, every requested artifact was written, and no finding
  survived filtering.
- **Exit 1 — complete with findings.** The verdict is trustworthy and the
  reported findings are the result.
- **Exit 2 — verdict unavailable.** Broken or skipped requested units,
  incomplete dataflow, a stale/missing requested summary, report-write
  failure, or no enabled detection rule cannot masquerade as clean.

`--accept-partial-coverage` remains an explicit corpus-maintenance escape
hatch. It does not erase attempted/analyzed/broken evidence and never permits
unreliable error-recovery ASTs to be analyzed.

Dataflow coverage now distinguishes a real iteration limit from a function
whose CFG cannot be built. Dependent templates without concrete control flow
are deferred to their concrete instantiations instead of being mislabeled as
non-convergent. The worklist keeps one pending entry per block and determines
completion from remaining work, closing duplicate-scheduling and exact-budget
false failures.

## Every output tells the same truth

- JSON and SARIF carry status, completeness, exit-code and coverage evidence.
- HTML cannot display “Clean!” when the verdict is incomplete or absent.
- Failed JSON, SARIF, HTML and baseline writes make the verdict unavailable.
- MCP `analyze` returns status/completeness/coverage evidence and uses tool
  error only for unavailable verdicts; ordinary findings remain a successful
  tool call.
- MCP rejects unknown or wrongly typed arguments instead of ignoring them.

## Strict configuration and honest identity

Configuration is whitespace-aware and fail-loud. Unknown CLI flags, missing
values, invalid severity/language/line scopes, malformed config lines and
unknown keys now return exit 2. This also fixes shipped idiom profiles whose
documented `key = value` form previously retained whitespace in the key.
`--help` remains successful even beside an invalid project configuration.

An exact `v0.4.8` tag reports `0.4.8`. Any other checkout reports the next
development identity with its source commit (and `.dirty` when applicable),
so a post-release build cannot claim to be the old binary. The dependency-free
`--capabilities --json` surface publishes version, rules, outputs, modes and
the verdict contract for wrappers and agents. Windows builds also normalize
the native Clang resource path before compiling it in, so the development
fallback cannot be corrupted by C++ backslash escapes.

## GitHub Action hardening

The composite Action validates gate, SARIF-upload, output-path and version
inputs before download or analysis. User values cross into shell through
environment variables. `extra-args` supports shell-style quoting and
environment expansion as data, but never evaluates command substitution,
globbing or shell syntax; malformed quoting fails with exit 2. Report-only
keeps findings green by design, but an unavailable verdict is always red.

## Verification receipts

- The Windows suite passed **848/848** in both parallel and serial modes. A
  dedicated regression proves the configured Clang resource directory carries
  intrinsic headers; packaged-zip rehearsal and relocation smoke passed with
  the build LLVM hidden.
- The Action argument parser passed **5/5** tests on Windows and Linux.
- The thesis gate held at **0 false positives on nine clean programs** and
  **9/9 addressable in-scope bugs caught**. Pinned cJSON/tinyxml2 counts held.
- The fail-closed real-world replay completed libgit2 v1.9.0 at **167/167
  translation units, 34 findings, exit 1**, and rtp2httpd
  `a7a1e568d46ee3176f8a3e94e0f88f131ebd444e` at **38/38, 6 findings,
  exit 1**. rtp2httpd triage partitions those six into four actionable
  findings and two context false positives. The canonical executable ledger
  is `scripts/realworld_expected.txt`; method and immutable receipt are in
  `docs/benchmarks.md`.
- The TFLite FFT work-buffer leak preserved by
  `MemoryLeakRuleExTest.TFLite_123387_Rfft2dWorkBufferLeak_Reports` was fixed
  upstream: TensorFlow issue #123387 closed with merged PR #123994, commit
  `68a7e5821cbb2beb76eeebbbbdffda85a418b254`.

No detection rule was removed and no quality floor was relaxed. Automation
that previously treated every non-zero result as “findings” should now branch
on 0/1/2 explicitly; that incompatibility is the safety fix.
