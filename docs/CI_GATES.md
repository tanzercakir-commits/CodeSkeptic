# CI gates for the main-based CWE restart

## What is connected

CS3-CH01-S07-U001 adds push selection for `agent/cs3-*` without changing main,
opening a PR, or relying on a workflow_dispatch registration on the default
branch. This document describes wiring, **not hosted qualification**.

| Event / changed paths | Linux `build-and-test` | Windows `windows-native` | Juliet |
| --- | --- | --- | --- |
| Agent push: `src/**` or `tests/**` | Yes | Yes | Yes |
| Agent push: `ci/regression-checkpoint.json` | Yes | Yes | Yes |
| Agent push: docs only | Yes | Yes | No |
| Unrelated branch or tag push | No new selection | No new selection | No new selection |
| Existing main / phase push, PR, Juliet manual / schedule | Existing behavior | Existing behavior | Existing behavior; checkpoint path also selects phase pushes |

Juliet retains its other explicit source/tool/workflow path filters. Its PR
paths remain unchanged; draft PRs still skip its job. Branch and path filters
both have to match. `agent/cs3-*` does not match nested suffixes such as
`agent/cs3-x/nested`; branch matching is case-sensitive. See GitHub's
[workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

## Existing quality floors stay in force

The original Linux build, CTest, single-process tests, real CLI smoke, zero-finding
self-scan, cJSON/tinyxml2 corpus and frozen thesis floor remain unchanged.
Windows retains its native build/tests, SDK-discovery probe, package rehearsals
and relocation smoke. Juliet retains its pins, limits, classifier self-test,
quality dashboard, scheduled deep corpus and existing artifact upload. Neither
experimental capability tiers nor baseline counts are lowered by this wiring.

`build-and-test` keeps its existing name. Hosted rulesets, required checks and
permissions are not changed. Existing write permissions remain for legacy lanes;
the agent guard is a workflow control, not a token-level security boundary.

## Ordinary agent artifacts, no legacy ref writes

All six existing Git diagnostic/status writers are excluded when `github.ref`
starts with `refs/heads/agent/cs3-`, including manual Juliet runs on that ref.
Each retains its original `failure()` or `always()` predicate for other refs.
The `startsWith` expression is case-insensitive, unlike the push branch glob;
see GitHub's [expression reference](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions).
Legacy PR runs use `refs/pull/.../merge` and retain their old behavior. No new
`refs/status` or `refs/ci-logs` publication is performed by agent-ref runs.

Linux and Windows add agent-only diagnostic snapshots and normal Actions
artifacts on success or failure (best effort on cancellation). These contain:

- Event SHA, observed checkout SHA if available, workflow SHA, run ID/attempt,
  job identity and preceding named-step outcomes/conclusions, never step outputs.
- At most the final 64 KiB of each of four explicitly named CTest/configuration/
  probe logs. Missing or symlinked logs are marked unavailable, not fabricated.
- An explicit diagnostics-only label. A snapshot is taken before collection/
  upload finish; it is **not** the final job verdict, a PASS receipt, or complete
  test/campaign output. Consult the actual Actions job conclusion and full logs.

The collector does not rerun tests, upload the workspace recursively, or reuse
an existing snapshot directory. Uploads use a run/attempt-specific name,
14-day retention and `if-no-files-found: error`. Upload runs only after successful
collection, so a rejected stale/symlink target cannot be uploaded after failure.
Juliet uses its preserved
quality dashboard artifact. Infrastructure failure or cancellation can still
prevent artifact creation; missing evidence cannot establish success.

## Local validation and later hosted qualification

Run `python3 -B tests/WorkflowPolicyTest.py` with PyYAML installed. The new Linux
agent lane installs the distribution `python3-yaml` package on the hosted runner
and runs this command with `/usr/bin/python3`; no installation on the owner's
computer is performed by the workflow change.

The test reads real YAML, rejects duplicate keys, exercises event/path/ref
positives and negatives, and executes both actual embedded Python collectors
in temporary fixtures. A canonical parsed-YAML digest anchored to verified POP
`67ae9204218176e003b56fe8f9553f9cb991d008` checks that removing only the named
additions reconstructs the entire former workflow contract. It is an accidental
drift guard, not a signature or a full GitHub event interpreter. Future intentional
workflow changes must update this test through the declared FIFO scope/review.

Separately validate all three files with actionlint. For this unit, actionlint
1.7.12 was fetched explicitly from its official release into a temporary directory,
with the archive checked against the official release asset/checksum digests.
The command is `actionlint -shellcheck= -pyflakes= .github/workflows/ci.yml
.github/workflows/windows.yml .github/workflows/juliet.yml` (one shell command).
ShellCheck/Pyflakes companions are not installed and are explicitly disabled;
do not claim their checks passed. Also run `python3 -B scripts/project_queue.py check`.

## Explicit same-input base/head checkpoint (S07-U002)

S07-U002 delivered `ci/regression-checkpoint.json` **disabled**, with wiring
and local evidence rather than a successful hosted campaign. S07-U003 owns its
activation and qualification (current candidate status below). The request pins the full base SHA, the same
input SHA, the canonical real-world manifest digest and the only supported
profile, `nightly-weekend-three-repeats`. The head and workflow SHA must both
equal the actual push event SHA; run ID, attempt, repository and agent ref come
from Actions, not from a freely chosen receipt field.

Both measurement and real-world workflows now have an additive push lane for
`agent/cs3-*`, filtered to that request file. The cheap `checkpoint-plan` job
requires an enabled request with a **new request_id in the final candidate
commit**, compared with its first parent. Inherited requests on new branches
and ordinary ledger commits do not launch a heavy campaign, even if a broad
new-branch push path comparison includes the old request. A disabled request
also selects no heavy jobs. A malformed request fails closed. Do not push a
request buried below a later ledger commit and expect that later SHA to qualify.
Existing PR measurement and scheduled/manual real-world jobs remain intact.

`scripts/run_regression_checkpoint.py` has `plan`, `build`, `measure`, `shard`
and `aggregate` modes. It creates fresh workspaces under `RUNNER_TEMP`, builds
the exact versions and calls the existing measurement and real-world runners.
It does not install tools, implicitly fetch a missing base commit, or reuse
cached campaign receipts. Hosted jobs explicitly install their dependencies;
the existing real-world runner fetches the manifest-pinned upstream projects.
There is no corresponding installation on the owner's computer.

Both analyzers use one common exact-base checkout. All its regular tracked
files are hashed and matched against the pinned Git objects, including the
thesis fixtures, source tree, manifest and copied project profiles. Dirty or
ignored extra inputs are rejected, and the identity is checked again after
execution. Measurement uses the same compilation database and source paths
for both binaries and binds the database bytes. The complete input checkout
must stay outside generated build/output directories.

The real-world profile contains eight pinned projects and three repetitions
for **each** analyzer: 48 independent side/project/repetition shards, with at
most six running concurrently. The two analyzers are built once per side and
shared as digest-bound artifacts. Each shard keeps the existing project timeout;
base and head are not squeezed sequentially into one shard's time limit. Four
existing aggregates validate base/nightly, base/weekend, head/nightly and
head/weekend with exact pins and three-repeat determinism. V1 uses the original
pins for both sides; V2 can use the independently adjudicated head expectations
described below. The original base manifest and inputs remain unchanged.

### What actually blocks acceptance

Measurement retains the existing comparator and frozen CLEAN/BUG floors. The
wrapper additionally requires exact cases and source identities, complete base
and head coverage, consistent counts and no unavailable/incomplete results.
Measurement timing, RSS and fingerprint differences are informational; they
cannot excuse a failed quality floor. Some frozen BUG cases intentionally have
a zero minimum: the checkpoint does not silently change those expectations.

Real-world findings, fingerprint digest, exit classification, TU-list digest
and all coverage fields remain **exact blocking pins**, not informational
measurement deltas. Every raw analyzer report, TU list, accepted receipt and
receipt checksum is revalidated. Missing projects/repetitions, substituted
binaries, resumed receipts and failed/skipped/cancelled jobs cannot qualify.
No pin, baseline, quality floor or hosted protection is lowered here.

### Owner-approved exact semantic adjudication (policy checkpoint)

The first actual candidate `695839b6f99d8c47113482d163eb5d6aca697617`
passed Linux, Windows, Juliet and measurement, but its real-world run failed.
Abseil lost exactly one old false positive: `csf1-46954827fe18f69a` at pinned
`demangle.cc:524`, the legal formation of `&buf[20]` for a20-element array.
The subsequent write decrements the pointer first. The existing one-past test
retains detection of actual out-of-bounds reads. All158 TUs and the other11
findings are preserved across the three head repetitions. LVGL separately
added four uninit-scalar reports at `LV_UNUSED` casts; these require their own
diagnosis/correction and are not accepted by the Abseil decision.

After that evidence, the owner explicitly approved a narrow acceptance-policy
revision. It permits independently classified, source/regression-backed exact
head semantic deltas while preserving the original base manifest and pins.
This section records authorization, **not hosted qualification or PASS**.
The separately scoped V2 producer/verifier implements the exact distinction
below. Its candidate still requires independent review and fresh hosted results.

The required implementation must identify any head-effective manifest separately
from the unchanged baseline, preserve every input/recipe/coverage/timeout pin,
and validate exact added/removed fingerprint multiplicities against actual base
reports in all three repetitions. No count tolerance, general suppression or
unexplained difference is permitted. A reviewed delta must identify the project,
pinned revision, original expectations, specific classification and source/test
evidence. A false positive must not be restored merely to make CI green.

The original failed run and receipts remain failed and preserved. Only a fresh
successful exact-head campaign with the same48-shard profile and independent
raw-evidence audit may complete U003. This authorization does not change main,
hosted protections, experimental tiers, existing quality floors or FIFO order.

### V2 candidate control data, not modified campaign inputs

The V2 request adds `adjudications_sha256`, the exact byte SHA-256 of the
canonical JSON+LF file `ci/regression-adjudications.json`. V1 remains unchanged
and cannot activate that sidecar. The current record classifies only the one
Abseil removal above; LVGL has no allowance. Each adjudicated project binds its
revision, the entire original expectation object and sorted full baseline
fingerprint list, preserving duplicate occurrences. Each added/removed
occurrence binds classification, rationale, pinned-source path/digest/line,
regression commit/test and distinct implementer/verifier evidence references.

The derived head manifest changes only `findings` and `fingerprint_sha256` for
listed projects. Exit classification cannot change under this policy. No other
recipe, source, coverage, resource, timeout or campaign field may change. Every
head shard uses the separately named effective **whole-manifest** digest, even
for unchanged projects; every base shard still uses the original digest.
Artifacts continue binding the original immutable input identity. The result
reports `original_base_manifest_sha256`, `effective_head_manifest_sha256` and
`adjudications_sha256` separately. It never relabels the effective expectations
as original inputs or rehabilitates an unavailable old receipt.

Plan validation rejects malformed control data before any build. Shards execute
against their side's expectations from the outset. Aggregation revalidates raw
reports/receipts and requires the exact classified base/head Counter difference
for repetitions1,2 and3, with zero unexplained changes in all other projects.
Excessive removal, duplicate/cancelling records, wrong revisions, bool/float pin
substitutions, no-op changes and unbound evidence files are rejected.

Reviewer identities and source/evidence digests are procedural review records,
not signatures or a runtime proof that a classification is true. The independent
candidate reviewer must inspect the referenced source, regression and retained
raw evidence. The current Abseil classification review inspected raw base1 and
head1/2/3; it does not claim inspection of the old raw base2/3 or campaign success.
Fresh qualification still requires all48 raw shards.

### LVGL deliberate-unused precision boundary

The four added LVGL reports came from `LV_UNUSED(x/y)`, defined as `((void)x)`.
The narrow correction treats only a C-style void cast of a bare nonvolatile
automatic integer/bool local, possibly parenthesized, as an intentional unused
marker. It follows the precision convention in Clang's
[uninitialized-value classifier](https://clang.llvm.org/doxygen/UninitializedValues_8cpp_source.html),
not a claim that all C void expressions are unevaluated or ISO-C-safe.
No initialization or escape is inferred. Arithmetic, intermediate explicit
casts, call arguments, increments and comma-LHS reads are still evaluated by
the existing rule. Straight-line and CFG C11/C++17 tests protect these boundaries
and the later real read after a bare discard. Unsupported volatile arithmetic
remains outside the existing sequencing model; this fix claims no new coverage
there. The original LVGL count16 and fingerprint pins stay unchanged.

### Evidence collection and independent validation

Each artifact envelope binds the configuration digest, full input identity,
source/binary identity and workflow/run/attempt context to exact file hashes.
The measurement artifact includes both measurements, recomputed JSON/Markdown
comparison, binary build bindings and the shared compilation database. The
real-world run produces two binary, 48 raw shard and one aggregate artifacts.
Artifact names contain lane, run ID and attempt; aggregate downloads keep
identities separate rather than merging files with duplicate names.

After a run finishes, the primary obtains the following **directly from GitHub**:

- Run metadata from `repos/{owner}/{repo}/actions/runs/{run_id}`.
- That exact attempt's jobs from
  `repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs`.
- The complete artifact catalog from
  `repos/{owner}/{repo}/actions/runs/{run_id}/artifacts`.
- Each selected artifact's ZIP from
  `repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip`, saved as
  `{artifact_id}.zip` in a dedicated archive directory.

Fetch all pages and combine their arrays while preserving `total_count`; a
partial page is rejected. Independently construct `context.json` with exact
`head_sha`, `workflow_sha`, decimal-string `run_id`/`run_attempt`, `repository`,
`ref` and `lane`. Use the candidate's request JSON and a fresh detached checkout
of its pinned base as `--inputs-root`. Then, once per lane:

```bash
python3 -B scripts/verify_regression_checkpoint.py \
  --config ci/regression-checkpoint.json --context /evidence/context.json \
  --inputs-root /checkouts/exact-base --run-json /evidence/run.json \
  --jobs-json /evidence/jobs.json --catalog-json /evidence/artifacts.json \
  --archives /evidence/archives --output /evidence/validated.json
```

For a V2 candidate, also supply
`--adjudications ci/regression-adjudications.json` in **both** lanes. The file
must match the candidate's bound canonical bytes. Missing or mismatched data
fails; a V1 invocation rejects an adjudication argument. The validation output
also records this source-file digest.

The output must not already exist. The verifier makes no network requests and
executes no downloaded binary. It requires actual completed/successful run and
checkpoint job records from the same attempt, exact expected artifact IDs,
unexpired catalog records and GitHub's archive SHA-256/byte size before safe
extraction. It rejects duplicate/traversing/symlink ZIP entries, corrupt or
oversized archives and any envelope/raw-evidence mismatch. It recomputes the
result instead of trusting an aggregate's own PASS. Downloads are capped at
2 GiB per archive and 8 GiB total; extracted data has the same size limits.

Use a complete workflow rerun, not a partial failed-jobs rerun: successful jobs
or artifacts inherited from an older attempt cannot satisfy a new attempt's
complete identity set. Cancelled or incomplete runs are not usable evidence.

These checks are integrity and consistency checks, **not a cryptographic
attestation of an honest producer**. A fabricated but internally consistent API
JSON fixture is not GitHub evidence. The caller and independent verifier must
check the actual remote repository/run/attempt and preserve the fetched records
and archive digests. The result's provenance explicitly states this boundary.

### Local checks versus hosted qualification

Run `python3 -B tests/RegressionCheckpointTest.py` (PyYAML required for its real
workflow checks), existing measurement/real-world/workflow policy tests and
actionlint on both changed workflows. The checkpoint test guards the entire
parsed legacy workflow against verified POP `4a1626f4f809bb4261993b277bead6395719974b`
after removing only the declared additive lane changes. Synthetic manifests and
receipts are test fixtures only, never substitutes for the real pinned corpus.

The actual CLI slice is explicit:
`CODESKEPTIC_CHECKPOINT_BINARY=/absolute/codeskeptic python3 -B tests/RegressionCheckpointTest.py RealCliSliceTest`.
It runs the real binary twice against one small fixed input set and validates
the generated measurement artifact; using the same binary twice tests the
pipeline, not a new-version quality claim. Without the environment variable,
this test is explicitly skipped, not claimed as a successful CLI check. S07-U002
also requires its stated T2 Linux suite, queue and independent exact-head review.

S07-U003 separately requires actual same-head Linux, Windows, Juliet,
measurement and all 48 real-world shards. Until those receipts exist, local
tests and a green Project FIFO job establish neither hosted product correctness
nor release readiness. Main integration remains a separate owner-authorized
action; neither checkpoint activation nor a PASS grants merge authority.

## Current qualification candidate (S07-U003)

The first request, `hosted-qualification-001-20260905`, is now enabled in the
candidate. Its base and common inputs remain the unchanged main commit
`7dfd37596414c9512316093ff4fb6b039673f55f`; the eight-project manifest and quality
pins are unchanged. Enabling this request locally is **not** a hosted result.
Only the primary may push its exact clean head after independent publication
precheck; that precheck is not the task's final PASS or permission to POP.

Earlier feature head `4a1626f4f809bb4261993b277bead6395719974b` actually passed
Juliet (run `33974498005`) and FIFO (`33974498013`), but failed Linux self-scan
(`33974497998`) and two native Windows tests (`33974497981`). These failures
were retained and diagnosed before activating this first full profile:

- The two accept tests used GNU/Linux headers unconditionally on Windows.
  Their real Linux header assertions remain explicitly Linux-qualified, while
  shared portable POSIX declaration bodies now exercise the same direct/wrapped
  leak, close and transfer behavior in both C and C++ on every host. This is not
  WinSock support or a blanket test disable. Actual Windows success is still
  required; a Linux fixture probe cannot establish it.
- The complete local baseline self-scan analyzed all 49 TUs and reported one
  possible null dereference in `FdAnalysis::transfer`. `isTrackableLocal` already
  rejects null, so the caller was safe; an early null `continue` makes that
  existing condition explicit without a suppression or analyzer-rule change.
  A narrow scan of the changed file with the same analyzer is now complete and
  clean. Declaration-kind tests preserve resource behavior around non-variable
  typedef, enum and record declarations.

Both necessary file additions passed independent scope and applied-transition
reviews before editing. Acceptance, FIFO, completed records, existing quality
gates and source pins remain unchanged. Full current-head hosted Linux,
Windows, Juliet, measurement and 48-shard evidence remains **pending** until
the actual run/job/artifact records pass independent validation. Earlier SHA
results and local preparation cannot fill any missing current-head result.
