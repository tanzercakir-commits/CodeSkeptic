# Unreleased CWE restart — bounded candidate dossier

## Second-act status — targets, not a release claim

The owner-approved [CH08–CH14 plan](docs/PRODUCT_COMPLETION_PLAN.md) continues the
same FIFO with 51 additional tasks; the old 46 local-completion records remain
unchanged. Its [G1–G8 completion contract](docs/product-quality-contract.md)
requires actual wider quality, one-source signed native artifacts and an
authorized public release verified from consumer downloads. No such result,
new installed rule, promotion, version or tag is claimed by this documentation.
The local-only delivery boundary below is the historical CH07 contract, **not**
a fallback that can close the second act. Separate exact tag/signing/publication
approval remains mandatory; main is unchanged.

## Historical first-act candidate

This is an unsigned, unpublished development candidate dossier, not v0.4.8,
a new version/tag, or one rebuilt same-source cross-platform release. The
[acceptance matrix](docs/release-checklist.md#candidate-acceptance-matrix)
binds each accepted workflow to its actual source/artifact and independent
PASS evidence. A later documentation or FIFO commit never relabels a binary.

- Linux x86_64: `a23cf319264847c752a4fdc55ce2f3cadb196f78`,
  `0.4.9-dev+ga23cf3192648`; real offline/non-root relocation, C/C++ first
  scans, all four output formats, and local container/Action parity qualified.
- Windows x86_64 and macOS arm64:
  `e83b641be32665740e8637cbb1368346e82ea471`,
  `0.4.9-dev+ge83b641be326`; actual hosted native test/package/first-scan
  jobs passed. Linux CI and ordinary Windows CI on that source also passed;
  this does not create a new Linux archive. Exact package/executable hashes,
  runner dependencies and skipped assertions are recorded in the matrix's
  linked native profile. Skips are unexecuted coverage, not passes.
- Triage, output/model validation, bounded CWE qualification and project
  measurements keep their own exact component-source receipts. Seven supported
  and five experimental CWE-family sample sets passed their bounded checks;
  experimental rules remain report-only. These are not all-CWE coverage,
  general precision/recall guarantees or low-noise qualification for every project.

Known limits include false positives and incomplete cJSON coverage in the
recorded real-project sample, narrow GoogleTest/tinyxml2 scopes, platform SDK/
host-library prerequisites, and different native memory-cap semantics.
Publisher signing, notarization/Gatekeeper download-install, native SBOMs,
hosted execution of the new local Action scenario, public distribution and
main integration are not qualified by this dossier. Broader publication needs
its own exact-candidate authorization and missing evidence; nothing here
authorizes it or converts a historical failed run into success.

## Local delivery decision

The authorized result is the local, unsigned candidate dossier, not a new
public release or a main merge. The accepted dossier is
`3012eabce97586e53362569a3f2ce61808f1a85f`, independently reviewed with canonical
receipt SHA-256 `53eef36bee4a52bb8f74de73147e99852db7a355b9dc68035ebddd45bfb2e293`
and actually finalized by ledger commit
`c588b9312dccbe761a866994e2989d6acbc3a50a`. The
[local handoff record](docs/release-checklist.md#authorized-local-delivery--ch07-s01-u002)
locates the source, unchanged artifacts, raw evidence and preserved archives.

Final program closure is recorded only by the final task's independent review,
real ledger POP and successful transition guard: all 46 task records in
PROGRESS, terminal TODO with no remaining FRONT, and protected main unchanged.
This paragraph does not substitute for that transition or predeclare a prepared
POP complete. No required public action is being deferred under a DONE label:
public release, signing/notarization and main integration are outside this
explicitly local delivery and still need separate authority/qualification.

## Unsigned Linux artifact provenance

The qualified Linux x86_64 tarball can now carry an unsigned CycloneDX 1.6
inventory and checksum-bound provenance sidecars. Source and generator revisions
are separate; native version/schema records, bundled files, dpkg package versions
and license notices are reconciled before publication of the sidecars. Original
artifacts are not repacked or relabeled. The Release workflow includes Linux
sidecars in draft assets and final checksum verification; this branch does not
itself publish a release.

The inventory explicitly leaves static source dependencies and target-host
library versions unresolved. Distribution notices are preserved, not asserted to
be a legal license classification. Recorded build recipes are not a signature,
SLSA attestation, independent producer proof or byte-identical rebuild guarantee.
See `docs/release-checklist.md` for the exact profile and evidence requirements.
Windows/macOS now have separately measured candidate profiles; the Linux
sidecars do not claim inventory/provenance coverage for those native packages.

The following notes describe the historical release, not a new release claim.

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
