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

The check closes the whole corpus file set (declared .cpp sources plus the two
JSON catalogs and its Python test). Unlisted .cc/.cxx/.c files, headers or other
files are rejected rather than silently excluded as out-of-profile. Use `-B`
so generated bytecode does not enter that source namespace.
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

## 5. CH06 native-filesystem prerequisite successor — 2026-09-08

Actual macOS arm64 run `34222316673`, source
`a3c3c60acc187dce76bc0f24be8a56185c886cce`, could not create the invalid-byte
filenames needed by four compilation-input tests: Darwin returned `EILSEQ`
before analyzer execution. The retained failed artifact `10054475612` has
SHA-256 `f0952996639e18cabd3a474e0dadba332073c12c45d3678552be45f2c173dd34`.
That run remains failed, including its separate worker-memory setup failures.

The current FRONT's independently applied scope edge `46b7db6` admitted the
necessary prerequisite correction, not an acceptance or policy rewrite.
At candidate `0fc8ebe849ba26c0ef5afa0fc9913d3c12cd9ee6`, read-only verifier
`/root/gtest_measurement_verifier` independently classified the exact change
and recomputed the successor digests below before this prospective freeze.
All four original bodies/assertions remain byte-identical except for an added
prerequisite call. Only measured Darwin `EILSEQ` from exclusively creating an
owned probe permits an explicit SKIP; Linux and all other errors remain blocking.
Those filesystem assertions are **unexecuted**, not passed, on such a filesystem.

Two additional controls execute real CLI rejection without creating a file:
distinct invalid POSIX argv paths (including an invalid parent) must retain
encoded identity, exit 2, failed coverage and refusal of partial/recovery flags
across JSON/SARIF/console/HTML; a valid UTF-8 missing path must not be mislabeled
as invalid encoding. These complement rather than replace the directory and
canonical-symlink cases, which continue to require an actual compatible
filesystem. Windows retains its existing POSIX-only exclusions.

| Bound input | Previous SHA-256 | Successor SHA-256 |
|---|---|---|
| `tests/CompilationDatabaseCliTest.py` | `7cb7bf40058443262cc6012ea3e25b55dc50b6ccc78052debce1a5ee9b426984` | `becbc2719da069b8763b9c15848aa210611595e0d66bd7902c36290e43d0fe6a` |
| `regression_inventory.json` | `2d39b4f324b151f012585e50c175af3f2186c4d1b3ba3dc4868d7c1228425c75` | `2d1de674463568b8d9fc7927c1d7d2b4e2b295bc9cb4fbcb63410d5876e69060` |
| `catalog.json` | `4ed2c19615b70b41fa41413ba4269b20ab84000103fa2517964e7c02a69ac048` | `ae87d17d8894cebacf4f56eb5a1fdc0c03249aad9ea4011f8087745d53ba0594` |

Only this single inventory row and its catalog digest link change. The old
inputs remain in Git; all other 123 rows, all 52 CWE cases/expected findings,
selection base, registry, floors, previous measurements and completed contracts
remain unchanged. No expectations were derived from analyzer output.

The proposed six-test Linux check passed without skips using the explicitly
older `9040852` executable; it is not new-candidate or native macOS evidence.
The 47 offline harness checks also passed. Fresh native execution, explicit
skip accounting, all applicable source/hosted gates and independent applied-
freeze review remain required. Darwin memory diagnostics preserve the existing
cap and fail-closed behavior; this record does not approve a larger or redefined
memory budget, claim that issue fixed, or qualify the whole platform unit.

## 6. Owner-authorized macOS memory contract — 2026-09-08

After the preceding diagnostics-only work, the owner explicitly authorized a
prospective macOS memory-contract redesign, preserving Linux/Windows behavior.
This later decision does not rewrite section 5, the earlier reviewed boundary,
or any failed campaign. Applied scope edge `a1b1997` adds only the four necessary
implementation/documentation/test paths; independent review confirmed unchanged
acceptance, T3 budget/checks, FIFO, completed records and main.

The new contract is documented in [usage.md](usage.md): one startup Mach virtual
size snapshot plus checked MiB allowance, fixed as a finite absolute RLIMIT_AS
ceiling no greater than inherited finite limits, with exact soft/hard readback.
No repeated baseline, upward retry, RSS substitution or unlimited fallback.
Existing mappings and later unmapping carry the explicit limitations documented
there. Arithmetic/OS-sequence checks are synthetic, not native qualification.

The additive Darwin resource tests retain every original body/assertion,
including the actual 128 MiB touched-allocation rejection. New child controls
require the same 192 MiB anonymous/private read-write mapping to succeed before
lowering limits, then fail with ENOMEM after installing the cap while an 8 MiB
volatile-touched positive mapping remains live. The large control is unmapped
without physical-page touching; missing control or unexpected success fails,
never skips. Separate inherited-soft/hard cases and unchanged-parent checks
exercise the actual native API. They cannot turn the prior setup failure into
allocation-denial evidence without a fresh successful native run.

Only the necessary protected resource-test input and its digest links may gain
a separately independently classified prospective successor. All other inputs,
52 CWE cases, expectations, floors and historical results remain unchanged.
Native package scans, full hosted gates and exact-head independent review remain
required; source reasoning or local tests alone do not qualify macOS.
