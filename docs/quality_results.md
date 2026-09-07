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
