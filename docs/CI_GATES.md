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

The next unit, S07-U002, adds exact base/head checkpoint execution and evidence
validation. S07-U003 then requires actual same-head Linux, Windows, Juliet,
measurement and eight-project repeated base/head real-world qualification.
Until those receipts exist, local tests and a green Project FIFO job establish
neither hosted product correctness nor release readiness. Main integration
remains a separate owner-authorized action.
