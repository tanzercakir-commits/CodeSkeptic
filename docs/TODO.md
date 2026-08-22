# CodeSkeptic — TODO (generated open work)

> Generated from the fixed work-item catalog in `docs/PLAN.md` and
> protected-main completion trailers by `progress_status.py`. Do not
> edit this file by hand. A phase branch cannot close a work item.

## Repository state

<!-- cs:state-begin -->
```
base          = 7dfd375
in_flight     = phase-cache-checkpoint-correctness phase-determinism-exclusive-cgroup-authority phase-determinism-exclusive-cgroup-authority-v2 phase-determinism-performance-qualification phase-frontend-cfg-stress phase-per-tu-resource-budgets phase-realworld-release-candidate-factory phase-robustness-input-validation phase-upstream-validation phase-v1-field-validation-policy
verified_main = 7dfd375
progress      = sha256:1b6edc7f100977936a6d77b2c3f357f67e42e975dcb1ba8d0faa0b40571cabdb
```
<!-- cs:state-end -->

## Open work

### CS-P08-03 — Phase 8: Release-candidate qualification promotion

Boundary: Promote the retained Phase 8.3 qualification only when protected main contains the immutable three-project qualification contract and its complete hosted evidence.

Dependencies: none.

Acceptance gates:
- llama.cpp, TensorFlow Lite, and shadPS4 identities, admitted translation units, toolchains, verdicts, and checksummed receipts match the retained qualification contract.
- Every requested surface is complete with zero broken translation units and zero incomplete functions; unavailable attempts remain explicitly unavailable.
- The qualifying implementation, focused contracts, full regression, and hosted aggregate are reachable from protected main.

### CS-P08-04 — Phase 8: Release-candidate factory promotion

Boundary: Promote the retained Phase 8.4 factory only when protected main contains the nine-shard three-project campaign and its accepted aggregate receipt.

Dependencies: `CS-P08-03`.

Acceptance gates:
- The release-candidate tier plans exactly three repetitions for each of the three qualified projects from one analyzer artifact.
- All nine checksummed receipts reproduce the qualified identities and semantics with zero broken units or incomplete functions.
- The accepted aggregate identity, checksum, tests, and workflow implementation are reachable from protected main.

### CS-P09-01 — Phase 9: Accepted-fix and project target

Boundary: Preserve the incomplete Phase 9 ledger and close it only after at least ten fixes across five independent projects are accepted under the frozen Gate A/B/C contract; no active external target research or upstream action occurs during the product program.

Dependencies: `CS-P08-04`.

Acceptance gates:
- The append-only validator proves at least ten accepted fixes across at least five independent projects, including merged-change ancestry and every required Gate A/B/C field.
- Rejected, duplicate, stale, non-triggerable, and false-positive records remain durable and never count toward completion.
- Any remaining candidate review or upstream action occurs only in the owner-controlled end-of-program review with target-specific authorization.

### CS-P10-01 — Phase 10: Targeted-scope input validation

Boundary: Function and line scopes fail closed across CLI, project config, and MCP; invalid values never widen analysis and every rejected update preserves prior state atomically.

Dependencies: none.

Acceptance gates:
- Empty and delimiter-only function values are rejected on CLI, config, and MCP surfaces.
- Invalid line ranges preserve all previously accepted line state byte-for-byte.
- Focused Config/MCP tests, direct single-process suite, full CTest, and negative CLI replay pass.

### CS-P10-02 — Phase 10: Structured input fuzzing

Boundary: Build deterministic fuzz targets for project configuration, compile-database, strict text summary/model, and MCP JSON-RPC input parsers without expanding analyzer semantics.

Dependencies: `CS-P10-01`.

Acceptance gates:
- Each named input surface has a bounded reproducible fuzz target and retained seed corpus.
- Malformed input fails closed with no crash, hang, partial state commit, or silent scope expansion.
- CI smoke fuzzing and a documented extended local campaign pass with checksummed receipts.

### CS-P10-03 — Phase 10: Sanitizer runtime matrix

Boundary: Exercise the production analyzer and fuzz targets under ASAN and UBSAN, and under TSAN only when parallel execution exists.

Dependencies: `CS-P10-02`.

Acceptance gates:
- ASAN and UBSAN build, focused parser corpus, complete unit suite, and representative analyzer runs are clean.
- TSAN is either clean on a proven parallel surface or recorded as not applicable with executable evidence that execution is serial.
- Sanitizer options, toolchain identity, commands, exits, and logs are retained.

### CS-P10-04 — Phase 10: Frontend and CFG stress matrix

Boundary: Stress broken AST recovery, templates, macros, pathological CFGs, and incomplete translation units while preserving explicit verdict availability.

Dependencies: `CS-P10-03`.

Acceptance gates:
- Broken or skipped requested translation units make the verdict unavailable and return exit 2.
- Template, macro, malformed-source, and high-complexity CFG fixtures terminate deterministically without crash or fabricated clean verdict.
- Stress corpus identities and expected outcomes are machine-checked in CI.

### CS-P10-05 — Phase 10: Per-TU resource budgets

Boundary: Enforce explicit per-translation-unit timeout and memory budgets with deterministic cancellation and honest partial-run reporting.

Dependencies: `CS-P10-04`.

Acceptance gates:
- Timeout and memory exhaustion are independently triggerable, bounded, and return exit 2 without a clean verdict.
- Budget failures identify the exact translation unit and preserve completed-unit receipts without promoting a project verdict.
- Default and configurable budgets have regression tests on CLI, config, and MCP entry paths.

### CS-P10-06 — Phase 10: Cache correctness and resumable checkpoints

Boundary: Prove cache identity, invalidation, corruption handling, and resumable campaign checkpoints against exact analyzer inputs and outputs.

Dependencies: `CS-P10-05`.

Acceptance gates:
- Source, compile-command, configuration, rule-set, and analyzer-version changes invalidate every affected cache entry.
- Corrupt or incompatible cache/checkpoint data fails closed and cannot manufacture a verdict.
- Interrupted campaigns resume without duplicate or omitted requested translation units and reproduce cold-run fingerprints.

### CS-P10-07 — Phase 10: Determinism and performance budgets

Boundary: Freeze representative performance baselines and semantic fingerprints for unit, real-repository, and release-candidate workloads.

Dependencies: `CS-P10-06`.

Acceptance gates:
- Ten of ten identical runs produce identical semantic fingerprints for every gated workload.
- No unexplained wall-time, CPU, or peak-memory regression exceeds 10 percent against the pinned baseline.
- Every measurement records toolchain, hardware class, inputs, repetitions, statistics, and raw checksummed receipts.

### CS-P10-08 — Phase 10: Cumulative quality-floor audit

Boundary: Re-prove v1 default-rule quality and requested-TU truthfulness before the long stability campaign.

Dependencies: `CS-P10-07`.

Acceptance gates:
- Every analyzable requested translation unit is processed; otherwise the run returns exit 2 and no project verdict.
- No default rule precision is below 0.85, total default precision is at least 0.90, and lower-precision rules remain experimental.
- Addressable default recall is at least 0.70 and the clean corpus has zero false positives.

### CS-P10-09 — Phase 10: Seventy-two-hour stability gate

Boundary: Run the qualified release-candidate matrix continuously for 72 hours using resource budgets, checkpoints, deterministic fingerprints, and sanitizer-supported diagnostics.

Dependencies: `CS-P10-08`.

Acceptance gates:
- The full 72-hour window completes without analyzer crash or hang.
- No unexplained performance regression above 10 percent or semantic fingerprint drift occurs.
- All requested-unit coverage, restart, resource, and checksummed campaign receipts validate.

### CS-P11-01 — Phase 11: Stable JSON and SARIF contracts

Boundary: Freeze versioned JSON and SARIF output contracts with explicit compatibility, deprecation, and migration policy.

Dependencies: `CS-P10-09`.

Acceptance gates:
- Canonical schemas, golden outputs, deterministic ordering, and consumer validation pass across supported platforms.
- Every allowed additive change and every forbidden breaking change is executable in compatibility tests.
- Migration and deprecation windows are documented and schema versions are emitted by the product.

### CS-P11-02 — Phase 11: Baseline v2 lifecycle

Boundary: Ship Baseline v2 entries with stable identity, suppression reason, owner-neutral expiry, migration, and deterministic multiset consumption.

Dependencies: `CS-P11-01`.

Acceptance gates:
- Reason and expiry are schema-validated and expired suppressions fail visibly without hiding findings.
- Baseline v1 migration is deterministic, lossless for supported entries, and rejects malformed or ambiguous data.
- Line movement, duplicates, path normalization, and package/source parity tests pass.

### CS-P11-03 — Phase 11: Governance and maintenance policy

Boundary: Complete security policy, contribution and issue templates, public roadmap, dependency policy, troubleshooting, and supported-use documentation.

Dependencies: `CS-P11-02`.

Acceptance gates:
- All governance artifacts are present, internally linked, version-consistent, and checked by docs CI.
- Supported, experimental, and out-of-scope capabilities match the executable registry.
- Disclosure, dependency update, deprecation, and troubleshooting procedures name owners by role and measurable response windows.

### CS-P11-04 — Phase 11: SBOM provenance and signing

Boundary: Produce verifiable software bills of materials, build provenance, checksums, and signatures for every distribution channel.

Dependencies: `CS-P11-03`.

Acceptance gates:
- SBOMs cover direct and packaged runtime dependencies and validate against the release artifact.
- Provenance binds source revision, workflow identity, toolchain, inputs, and artifact digest.
- Signature verification, tamper rejection, key-rotation procedure, and offline verification are tested.

### CS-P11-05 — Phase 11: Offline installation and operation

Boundary: Make documented source and packaged installation, analysis, schema validation, baseline use, and signature verification work without network access.

Dependencies: `CS-P11-04`.

Acceptance gates:
- A clean offline environment installs each supported artifact using only retained inputs.
- Representative CLI and report-only workflows complete without network fallback or undeclared downloads.
- Missing offline prerequisites fail with actionable diagnostics and no partial success claim.

### CS-P11-06 — Phase 11: Distribution verdict parity

Boundary: Prove source builds and every supported package produce identical verdicts for identical inputs and configuration.

Dependencies: `CS-P11-05`.

Acceptance gates:
- Source, archive, container, action, and supported platform packages emit identical semantic fingerprints.
- Version, rule registry, JSON/SARIF schema, Baseline v2, exit code, and requested-TU behavior are identical.
- Parity is reproduced from clean environments with checksummed artifacts and no undeclared network dependency.

### CS-P12-01 — Phase 12: External qualification protocol

Boundary: Freeze a privacy-conscious, coverage-based, reproducible qualification protocol for three independent external projects before any campaign begins.

Dependencies: `CS-P11-06`.

Acceptance gates:
- Project selection, immutable inputs, scenario matrix, requested-TU coverage, triage, suppression, incident, and withdrawal procedures are fixed before measurement.
- Each project exercises full scan, deterministic repeat, cache/resume, bounded resource-failure, JSON/SARIF, baseline, and supported-package parity paths under one checksummed protocol.
- Campaign receipts contain only approved product measurements; no external write or maintainer contact occurs without target-specific owner authorization.

### CS-P12-02 — Phase 12: First external project qualification

Boundary: Complete the frozen qualification matrix on the first independent external project without using elapsed time as a substitute for coverage.

Dependencies: `CS-P12-01`.

Acceptance gates:
- Every predeclared scenario has valid coverage, semantic fingerprint, crash/hang, performance, triage, suppression, and distribution-parity receipts.
- Unavailable, interrupted, or rejected scenarios are retained and rerun under the frozen protocol rather than silently counted green.
- The project-level qualification report is repeatable from immutable inputs and independently auditable.

### CS-P12-03 — Phase 12: Second external project qualification

Boundary: Complete the same frozen qualification matrix on a second independent external project without using elapsed time as a substitute for coverage.

Dependencies: `CS-P12-01`.

Acceptance gates:
- Every predeclared scenario has valid coverage, semantic fingerprint, crash/hang, performance, triage, suppression, and distribution-parity receipts.
- Unavailable, interrupted, or rejected scenarios are retained and rerun under the frozen protocol rather than silently counted green.
- The project-level qualification report is repeatable from immutable inputs and independently auditable.

### CS-P12-04 — Phase 12: Third external project qualification

Boundary: Complete the same frozen qualification matrix on a third independent external project without using elapsed time as a substitute for coverage.

Dependencies: `CS-P12-01`.

Acceptance gates:
- Every predeclared scenario has valid coverage, semantic fingerprint, crash/hang, performance, triage, suppression, and distribution-parity receipts.
- Unavailable, interrupted, or rejected scenarios are retained and rerun under the frozen protocol rather than silently counted green.
- The project-level qualification report is repeatable from immutable inputs and independently auditable.

### CS-P12-05 — Phase 12: Qualification triage and suppression audit

Boundary: Aggregate all three qualification campaigns without hiding rejected findings, unavailable scenarios, suppression costs, or project-specific limitations.

Dependencies: `CS-P12-02`, `CS-P12-03`, `CS-P12-04`.

Acceptance gates:
- At least 200 findings are human-triaged with reproducible classification and suppression outcomes.
- Precision, recall proxies, time-to-triage, suppression expiry, unavailable-scenario, and performance measures are reported per project and in aggregate.
- All three campaigns satisfy the frozen coverage matrix and retain a complete checksummed audit trail.

### CS-P12-06 — Phase 12: Evidence-gated optional blocking

Boundary: Permit project-scoped opt-in blocking only for supported default rules whose three-project qualification evidence satisfies every frozen quality and reliability gate.

Dependencies: `CS-P12-05`.

Acceptance gates:
- Blocking eligibility is revoked on a blocking false positive, unavailable scenario, semantic drift, crash, hang, or unexplained budget regression.
- Blocking remains opt-in, project-scoped, reversible, and defaults to report-only.
- Positive, revocation, and rollback paths are end-to-end tested before any project enables blocking.

### CS-P12-07 — Phase 12: CLI and schema freeze

Boundary: Freeze v1 CLI, exit codes, configuration, MCP surface, JSON/SARIF, Baseline v2, and compatibility policy against breaking changes.

Dependencies: `CS-P12-06`.

Acceptance gates:
- Golden discovery, help, schema, configuration, MCP, and exit-code contracts pass on every supported platform.
- Breaking-change fixtures fail CI and additive changes require explicit version-policy evidence.
- Package and source artifacts expose the identical frozen contract.

### CS-P12-08 — Phase 12: v1.0 checklist support policy and final audit

Boundary: Close v1.0 only after a requirement-by-requirement audit proves every cumulative product, quality, distribution, qualification, governance, and support gate.

Dependencies: `CS-P09-01`, `CS-P12-07`.

Acceptance gates:
- The v1 checklist maps every Phase 10–12 item to authoritative commands, artifacts, measurements, and independent review evidence.
- Cumulative gates prove deterministic 10-of-10 fingerprints, quality floors, zero clean-corpus false positives, 200 triaged findings, five projects and ten accepted fixes, 72-hour stability, distribution parity, and three independent external qualification campaigns.
- Support versions, platforms, response windows, deprecation policy, known limitations, rollback, and release procedure are published with no blocking audit finding.
