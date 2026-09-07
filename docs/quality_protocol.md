# CWE qualification protocol

## 1. Freeze inputs before measurement

`tests/cwe_corpus/catalog.json` v1 was selected from source contracts at
`005b1264618dcf84aa20a5685efd9c03a26bd67f`, before running this new catalog.
It contains 52 explicitly identified fixtures for all 12 CWE-bearing diagnostic
families: 24 buggy, 22 safe, 3 unknown and 3 unsupported. Every source has a
SHA-256, semantic rationale, source-regression origin, compiler flags, declared
untrusted sources and expected rule/function multiplicity. Family CWE sets are
not per-finding labels or claims of every variant of that CWE.

Profile: Linux x86_64, Clang 20, C++17, one explicit compile command per fixture.
The profile fixes `size_t` at 64 bits. A later runner must verify that target,
not silently reuse these expectations on a 32-bit or differently configured
target. These sources are analyzed, never executed. No network acquisition is
needed. C/native Windows behavior remains in the separate full source and
hosted lanes; this small profile does not replace them.

This unit freezes inputs and checks their integrity. It does **not** claim a
precision/recall measurement, rule promotion, release or current-catalog PASS.
The measurement runner and actual supported/experimental decisions belong to
the next FIFO units, CS3-CH05-S01-U002 and U003.

## 2. Three mandatory evidence lanes, separate denominators

1. **Isolated rule fixtures.** Enable only the declared diagnostic family by
   explicitly disabling the other public families; retain the exact configured
   source names and normal verdict behavior. Assert complete single-TU analysis,
   exact source identity, no recovery/failure flags, real process exit and exact
   rule/function multiplicity. Do not filter unexpected findings after execution.
   A `resource-leak` pipe fixture deliberately expects two findings, not one.
2. **Entire source regression suite.** `regression_inventory.json` binds all
   96 pre-existing test-tree files, including helper sources and CMake registration.
   None of the new core tests is dropped for being hard or not easily extracted
   from a table-driven C++ test. Run the full Linux CTest **and** single-process
   suite in U002/U003. Bind discovery and executed test identities, source/binary
   digests, actual failures and skips. Declaration/file counts are not executed
   test counts and never enter the isolated-fixture precision denominator.
3. **Inherited external gates.** Preserve checksummed Juliet, thesis, real-world
   corpus/checkpoint profiles, stress cases and actual hosted gates. Existing
   source selection, pins, precision/recall floors, clean-corpus zero-FP guards
   and adjudications remain independent requirements. Passing the small fixture
   catalog cannot compensate for any failure in these lanes.

The inventory also binds 28 registry/build/runner/pin/workflow inputs (124 total),
including the adjudications and transitive measurement/comparison helpers.
This is a source-integrity snapshot, not proof they executed. In particular,
`RegressionCheckpointTest.py` and `WorkflowPolicyTest.py` are not ordinary CTest
entries: execute their documented workflow checks separately when that profile
is required. `test_first_scan.sh` is another explicit runner. A missing, skipped
or conditionally inactive gate is never labeled as an executed PASS.

Shared-core attribution includes interval/disjunct/summary/interprocedural and
CFG tests; source/config/coverage/false-clean boundaries; worker/budget/cache/
checkpoint lifecycles; report/identity/filter/baseline tests and qualification
automation. Full-tree binding deliberately retains all of them, not just files
with `Rule` in the name. Hard RAII alias, checked-add status/output and mutation
regressions remain mandatory even when the small profile uses simpler examples.

## 3. Interpret observations without manufacturing clean results

- `buggy`: an addressable seeded defect. Missing the expected diagnostic is an
  FN, never an unsupported relabel after the run. Extra target findings count
  against precision; exact multiplicity mismatches remain visible.
- `safe`: safe for the named rule/subset, not a global safety certificate.
  Any target diagnostic is an FP. Deterministic safe fixtures require zero FP.
- `unknown`: source/caller/side-effect evidence does not establish safe or buggy.
  Store actual results and completeness separately; do not score as TN or FN.
- `unsupported`: a source-defined limitation selected before measurement, not
  an excuse for a newly observed miss. Some are known defects (for example an
  uninitialized float); preserve that fact in the rationale. Record outputs,
  but do not add these to clean or addressable-recall counts.

`expected_diagnostics: null` is mandatory for the last two roles; `[]` means a
real safe expectation and is rejected for those boundary rows. Crashes, timeouts,
OOMs, invalid/missing reports and incomplete TUs are infrastructure/coverage
failures, not FN/TN observations. Unmeasured metrics are null, not 0% or 100%.

Report TP/FP/FN and raw denominators **per rule**. Do not micro-average easy
families to hide a failing family; do not mix source-unit assertions, repeated
runs or inherited benchmark samples into this catalog's denominator. New-family
promotion requires the PLAN's precision >=90%, addressable recall >=70%, zero
deterministic-safe FP and any stricter existing floor. Small seeded fixtures are
regression evidence, not an independent market-representative precision sample.
Unknown/unsupported counts and limitations must appear beside scored results.

## 4. Integrity checks and changes

Run before qualification and again before accepting its result:

```bash
python3 -B scripts/cwe_quality.py check
python3 -B tests/cwe_corpus/test_catalog.py
```

The check rejects missing/extra fixture sources, duplicate identities, changed
fixture or protected input bytes, missing positive/negative pairs, omitted rules,
scope/tier drift, symlinks, traversal and malformed JSON. It performs no analyzer
run and emits `quality_measured: false`. This is procedural integrity under
review and Git history, not malicious-root-resistant attestation.

Never regenerate expected outputs from an analyzer report. No automatic refresh
command exists. Necessary additions/corrections belong to the active authorized
FIFO unit or a reviewed future plan amendment: retain the old catalog in Git,
record the reason and old/new digests, classify changed rows independently and
freeze the successor before a fresh measurement. Existing failures remain
failures; no silent removal, threshold reduction or retroactive success.
