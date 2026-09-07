# CWE qualification results

## 1. Supported families — CS3-CH05-S01-U002

Measured source: `b284b613313a7cef7a6d1dcfcca60b0dcba37b11`, tree
`ac8ae5e3a7bedfbdf5baed4f94de9f1547f29e2f`, on 2026-09-07.
Binary version: `0.4.9-dev+gb284b613313a`.
Analyzer SHA-256:
`f8c650f65a1065233a31a67d3a97ceacb3c5d1864fde55b31475f8689fe370b1`.
Test executable SHA-256:
`1f8bf5bd67fb3a097217a48776351c041f2d4e0346064cec01580512c9986b87`.

The later future-plan amendment and this results document do not change the
qualified source, test, runner or input bytes. They are not a new binary build
or a claim that the tests ran at the documentation commit. The final independent
review must check that exact non-executable transition and the retained evidence.
Completion belongs to the queue's review/POP record, not this document alone.

### 1.1 Frozen isolated-rule regression profile

The [protocol](quality_protocol.md) and [catalog](../tests/cwe_corpus/catalog.json)
were frozen before measurement. Catalog SHA-256:
`814266dd620c46f33b170a732623cb25cb3ed5a949038c59fe6659c6bae6a46c`;
regression inventory SHA-256:
`799484c95b33b9f0692e10d3e1e7a965e145df015c1dc3f27f54c153897955e9`.
All 52 source fixtures and 124 protected test/build/runner inputs remain unchanged.

Only the seven already-supported families were selected for this measurement:
25 source files, comprising 12 buggy, 12 safe and one unknown. Each real CLI
invocation disables the other public families, uses an explicit C++17 compile
command and frozen untrusted-source names, and disables analysis-cache reuse.
Private working directories prevent project configuration loading; source-local
inputs remain bound by the closed catalog. Baseline and suppression audits are
empty. All 25 reports have complete one-source/one-command analysis.

| Family | Buggy | Safe | Unknown | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| memory-leak | 1 | 1 | 0 | 1 | 0 | 0 |
| double-free | 1 | 1 | 0 | 1 | 0 | 0 |
| use-after-free | 1 | 1 | 0 | 1 | 0 | 0 |
| resource-leak | 5 | 5 | 0 | 6 | 0 | 0 |
| div-by-zero | 1 | 1 | 0 | 1 | 0 | 0 |
| null-deref | 1 | 1 | 0 | 1 | 0 | 0 |
| int-overflow | 2 | 2 | 1 | 2 | 0 | 0 |

Precision and addressable recall are 1.000 for each family **in this small
regression sample only**. This is not a market-representative accuracy estimate,
proof of all-CWE coverage or grounds to hide the broader limitations below.
The unknown integer operand is observed but not scored as clean or FN. The other
27 frozen fixtures, including experimental unknown/unsupported cases, belong to
U003; no measurement or promotion is claimed for them here.

The pipe case intentionally contributes two TP findings on the same source
line with the same coarse `csf1` fingerprint. They are distinct read/write-end
leaks, not duplicates to discard. Exact rule/function multiplicity is retained;
identical repeated diagnostic records are rejected.

A separate complete, clean probe verifies the analyzer's actual embedded
Clang major 20, Linux x86_64, C++17 and 64-bit pointer/size type. It is not added
to fixture metrics. Build and scans used the already-cached rootless image
`25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5`,
with no network, two CPUs, 6 GiB memory, 256 PIDs and 1 GiB temporary space.
Cases have 20-second deadlines and an overall bounded measurement loop.

### 1.2 Full Linux regression suite

Fresh discovery and execution were bound to the same build: **1,582 CTest tests
passed**, followed by **1,567 single-process C++ tests passed**, and **44 Python
catalog/measurement tests passed**. Counts refer to their distinct execution
lanes, not independent quality samples to add to the fixture denominator.
CTest took 291.01 seconds; the single-process suite took 407.217 seconds.
The fragile real header/cache-hit check also passed before the full suites.

Measurement regressions cover malformed/partial reports, wrong source or full
revision, altered fixture bytes, missing/extra finding multiplicity, shared-line
fingerprints, unknown classification, output preservation and process failure.
The first implementation's three review findings and intermediate failed tests
remain recorded; they were corrected before these product measurements.

### 1.3 Inherited external gates — separate denominators

Fresh checksummed Juliet inputs contain 9,677 retained files. All selected
analysis TUs and their whole-program prepasses completed; each profile includes
one additional `io.c` support TU excluded from scoring. Original group-based
400-file sampling and every existing floor were retained.

| Juliet family | Scored files | Rule TP | Rule FP | Rule precision | Rule hit rate | All-rule FP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-476 | 400 | 140 | 0 | 1.000 | 0.347 | 55 |
| CWE-401 | 399 | 103 | 14 | 0.880 | 0.248 | 14 |
| CWE-415 | 400 | 119 | 0 | 1.000 | 0.297 | 34 |
| CWE-416 | 399 | 212 | 0 | 1.000 | 0.531 | 371 |
| CWE-369 | 399 | 43 | 0 | 1.000 | 0.108 | 0 |
| CWE-190 | 401 | 23 | 0 | 1.000 | 0.057 | 0 |

All six score guards passed without pin changes. Hit rate is the inherited
file-based metric, not the addressable recall of the isolated seed catalog.
Good/bad function-name scoring, split-flow cases and out-of-scope variants have
the evaluator's existing limitations. Other-family noise is shown rather than
filtered away; notably this is **not** a zero-FP claim for all Juliet findings.

The first wrapper failed after the six successful scans because its filename
glob counted both six reports and six new execution receipts as reports.
The failure remains exit 1. Corrected post-validation checks the exact twelve
filenames, each actual analyzer exit, source/command/prepass completeness,
verdict consistency and unchanged raw bytes; it re-evaluates the original floors
without rerunning or rewriting the analyses. That separate validation passed.

Four fresh real-world profiles retained all 497 frozen input hashes, exact
semantic finding multisets, coverage and whole-program summary bytes:

| Input/profile | Findings | Analyzed / requested TUs | Skipped TUs |
| --- | ---: | ---: | ---: |
| cJSON plain | 54 | 34 / 76 | 42 |
| cJSON whole-program | 57 | 34 / 76 | 42 |
| tinyxml2 plain | 9 | 3 / 3 | 0 |
| tinyxml2 whole-program | 12 | 3 / 3 | 0 |

cJSON's historical broken-TU slice remains explicitly partial; it is not a
full-project clean verdict. No new finding or silent loss appeared in these
comparisons. The blind thesis corpus passed all 24 file floors: nine clean
files with zero FP; nine of fifteen buggy files detected, eleven findings.
The remaining six are the preserved documented out-of-scope misses, not new
successes. Seven stress profiles passed their expectations; the deliberate
compiler-depth rejection remains incomplete exit 2, not a clean analysis.

### 1.4 Hosted status and remaining gates

These are fresh **local Linux qualification** results, not a release or current
Windows PASS. The earlier catalog ledger `c395903204be674a1474f4e0ba2db92d08cde9f0`
had successful Linux, Juliet and FIFO hosted runs, but Windows run
`34098971513` failed in the single-process survivor/resource-failure test.
Its 300 ms worker deadline also timed out one expected survivor; the report
correctly remained incomplete with exit 2. The cause within startup/analysis/
scheduling is not proven. Build and isolated CTest passed on that run.

The independently reviewed future task **CS3-CH05-S02-U001** owns this retained
failure, controlled timing diagnosis and fresh Windows suite/package gates.
Production budgets, the separate 150 ms kill/reap test, survivor assertions and
quality floors must remain intact. Nothing here waives the failed Windows gate
or claims Windows support requalification before that work. Experimental-family
decisions, targeted sanitizer/fuzz work, performance and packaging remain FIFO
tasks. Protected main remains unchanged; no merge, tag or release is claimed.

### 1.5 Evidence and reproduction

Local evidence lives under the user-state `codeskeptic/cwe-restart-evidence/`
directory, in `CS3-CH05-S01-U002/b284b613313a7cef7a6d1dcfcca60b0dcba37b11/`.
It retains discovery, commands, real exits, raw reports, hashes and failures.
The supported result JSON SHA-256 is
`8164e22a98e22332bcfd7dda07b6cd4d3ee3f4b84677d83c9b52386a06f5400d`.
The independent review binds the required Linux, relevant-corpus and queue
evidence separately; a successful input-integrity check alone is not quality.

On a clean checkout with its matching compiled development binary, use
`python3 -B scripts/cwe_quality.py check` and then `run --binary <binary>
--revision <full-checkout-SHA> --out <new-absolute-directory>` on the same script.
The output parent must already exist; existing output is never overwritten.
The runner supports only the measured supported lane at this checkpoint.
Full-suite and inherited gates are still required separately. No expectation
refresh, skip-to-clean conversion, automatic promotion or hidden download exists.

## 2. Experimental families — CS3-CH05-S01-U003

Measured source: `157724b079803c2fbe28d1de8e2c1032eb8f703f`, tree
`5faf560bcb25876ce1a97aea245084a5319ad65b`, on 2026-09-07.
Version: `0.4.9-dev+g157724b07980`.
Analyzer SHA-256:
`f0fa65be72441fb5b5ecd62ad3e932daa1cfdd7e2378b96c309a65c400fef246`.
Test executable SHA-256:
`67a4fe5e2059b933c20445bf8669f721039a63f71dcd0d59d23bddd3ac5a1764`.
The subsequent four-document results/scope update does not rebuild or relabel
these artifacts. Its exact transition must be independently checked before POP.

### 2.1 Complete frozen tier, not selected passing rules

The runner now accepts `--tier experimental`; its default remains `supported`.
It selects the entire frozen tier before execution, never an arbitrary family
or result-dependent subset. All original 52 fixtures, their expectations, the
catalog/inventory digests in section 1.1 and 124 protected inputs are unchanged.
The frontend/ABI probe, isolated compile commands, configuration/source identity,
disabled analysis cache and bounded offline environment are the same profile.

All 27 experimental cases completed: 12 buggy, 10 safe, two unknown and three
unsupported. Every experimental invocation returned exit 0, including the twelve
true findings; each finding remained experimental and nonblocking. The evaluator
scores actual diagnostics, not exit 0 as an absence of bugs.

| Family | Buggy | Safe | Unknown | Unsupported | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| uninit-ptr | 1 | 1 | 0 | 0 | 1 | 0 | 0 |
| uninit-scalar | 2 | 2 | 1 | 1 | 2 | 0 | 0 |
| bounds | 3 | 3 | 1 | 0 | 3 | 0 | 0 |
| sign-conversion | 2 | 2 | 0 | 1 | 2 | 0 | 0 |
| alloc-size-overflow | 4 | 2 | 0 | 1 | 4 | 0 | 0 |

Per-family precision and addressable recall are 1.000 **only within these small
seeded samples**; each family's deterministic safe FP count is zero. They exceed
the numerical 0.90/0.70 promotion thresholds for this profile, but do not supply
independent family-wide precision evidence. No pooled average or source-test
assertion count is used to enlarge those denominators.

The five predeclared boundary rows all completed with zero diagnostics and raw
status `clean`/exit 0. Their measurement metrics remain null, not TN or FN:

| Case ID | Frozen role | Interpretation of silence |
| --- | --- | --- |
| uninit-scalar-unknown-external-write | unknown | Opaque write does not prove initialization or a defect. |
| uninit-scalar-unsupported-float | unsupported | The known float initialization defect is outside the integer/bool subset, not safe. |
| bounds-unknown-extent | unknown | Missing capacity is not an in-bounds proof. |
| sign-conversion-unsupported-explicit-narrowing | unsupported | Explicit narrowing is not the new implicit-narrowing subset. |
| alloc-size-overflow-unknown-addend | unsupported | The frozen model does not establish arbitrary runtime addend overflow. |

### 2.2 Source-regression and real-project evidence stay separate

Fresh Linux execution passed **1,582 CTest tests** (291.40 seconds), **1,567
single-process C++ tests** (407.775 seconds) and **48 Python measurement tests**.
Discovery and actual executed/passed test identities match one-to-one, with no
skipped test credited as a pass. The real header/cache-hit check passed before
the suites. New measurement tests cover complete experimental selection,
report-only TP scoring, rejected blocking verdicts and invalid tier subsets.

The additional log-identity audit initially missed five genuine GTest PASS
markers prefixed by non-newline stderr in the merged output. Its failed audit
is retained. Corrected parsing matches exact test identities/time suffixes and
all discovered/run/pass multiplicities; it does not edit the original logs or
rerun/relabel a failed product test. The separate corrected audit passed.

The complete source suite retains harder boundaries beyond the isolated seeds:

| Family | Additional executed source-regression boundary evidence |
| --- | --- |
| uninit-ptr | `UninitPointerRuleExTest.cpp`: guaranteed versus bypassed/zero-trip loop assignment, correlated versus anti-correlated guards, reference-output versus value arguments, static/thread-local versus automatic storage. Its two isolated fixtures have no separate unknown/unsupported row; these source tests do not enter that denominator. |
| uninit-scalar | `UninitScalarRuleTest.cpp`: CFG branches, loops/early exits, short-circuit reads, escapes, selected-storage aliases and deferred sequencing/EH boundaries. |
| bounds | `BoundsRuleTest.cpp`: copy source/destination extents, constant offsets, casts and aliases; unknown extents and unsupported signatures do not acquire capacity proofs. |
| sign-conversion | `SignConversionRuleTest.cpp`: narrowing fit/loss, source snapshots/mutation and the retained nlohmann/json-shaped regression; not universal explicit-cast or unknown-range analysis. |
| alloc-size-overflow | `AllocSizeOverflowRuleTest.cpp`: uint64 guards, checked-add status/output identity, mutation/alias boundaries and the retained LVGL replay shape; not complete taint tracking or all allocators. |

The separate supported rerun retained 25 cases, 13 TP, zero FP/FN and its one
unscored unknown. Four fresh real-world profiles retained all 497 input hashes,
exact semantic finding multisets, coverage and whole-program summary bytes:
cJSON plain/whole 54/57 findings and tinyxml2 plain/whole 9/12. cJSON remains the
explicitly partial historical 34 analyzed/76 requested TU slice, with 42 skipped
and zero failed; tinyxml2 is 3/3. This is no claim of full clean-project precision.

Section 1's Juliet, thesis and stress observations retain their original b284
revision and binary: they were **not rerun in U003**. Production C++, registry,
build configuration, original tests, frozen inputs and inherited gate bytes
are unchanged from that qualified source. The only non-ledger/results changes
since b284 are this isolated-tier selector and its Python tests. Their historical
limitations and failures remain visible; those observations are not substituted
for U003's fresh required suite and corpus executions. In particular, Juliet's
six selected CWEs are not independent precision samples for these five families;
cross-family noise, repeated real-project copies or thesis aggregates cannot
be converted into such a sample.

### 2.3 Support decision

**Retain all five families as experimental, enabled and report-only.** No
feature is removed from delivery, no expected finding or floor is weakened and
no quality gate is disabled. All seven supported families retain their prior
blocking behavior. The new features remain usable; experimental is an explicit
evidence/tier limitation, not a silent deletion or deferred implementation.

The contract requires independent precision evidence before promotion. These
source-derived seeds and existing regression replicas are not that sample,
even though every scored case passed. No unprovided minimum sample size is
invented. A later promotion needs prospectively frozen, independently classified
evidence for the declared subset, the existing precision/recall and zero-safe-FP
floors, relevant regression/hosted gates and an authorized FIFO task. Nothing
here asserts industrial certification, all-CWE coverage or market accuracy.

The original scalar capability evidence string describes its historical first
straight-line checkpoint. Current documented behavior includes tested CFG joins;
the registry bytes are deliberately not silently re-frozen or treated as a new
precision result. All tier flags remain identical. The known c395 Windows failure
is still unresolved and owned by S02-U001; no current hosted Windows success,
sanitizer/performance acceptance, package/release or main integration is claimed.

### 2.4 Evidence and reproduction

Fresh evidence: user-state `codeskeptic/cwe-restart-evidence/CS3-CH05-S01-U003/`
under exact measured source `157724b079803c2fbe28d1de8e2c1032eb8f703f`.
Experimental results SHA-256:
`87d4a143139242a0e541bc4261e39e9d54fa7b81dbc1cdbf01d2521f7fa5cd1a`;
separate supported results SHA-256:
`5bd99902143f3726f6cb30252f453c3c2fbc9fa69aee0e9a1a6652fb96e66825`.
Raw per-case reports, compile commands, actual exit/timing records, discovery,
full logs and the failed/corrected log audit remain separate evidence.

On a clean matching build, run `python3 -B scripts/cwe_quality.py run --binary
<binary> --revision <full-checkout-SHA> --out <new-absolute-directory> --tier
experimental`; use a different fresh directory for `--tier supported`.
The parent must exist. Neither command refreshes expectations, promotes a family
or replaces the full suite, independent audit and exact-head FIFO POP.
