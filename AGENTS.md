# CodeSkeptic — active working agreement

This main-based CWE restart supersedes the retired phase/book editions, under
the owner's 2026-09-05 authorization. Historical instructions are reference,
not executable authority. Never merge into or write directly to main.

## Start every unit

1. Read INVARIANTS.md, docs/QUEUE_GUIDE.md, the active PLAN section and the full
   first task in docs/TODO.md; inspect recent PROGRESS and BOOK decisions.
2. Inspect branch, exact HEAD, working diff and the declared task scope.
3. Run `python3 -B scripts/project_queue.py check` before editing.
4. Work only on FRONT, on `agent/<lowercase-task-id>-<slug>`. The one bootstrap
   uses `governance/cwe-product-restart`. Never mix two tasks in one diff.

The primary is the implementer. A unit is not done after writing code or seeing
green tests: obtain independent exact-head PASS, prepare the POP, commit its
three ledger files and validate the transition. Then create the next branch
from that verified ledger commit. No separate human permission is needed for
each ordinary local unit; the owner has authorized this queue's local work.

## Scope and proportional testing

Use the task's Outcome, Acceptance, Scope and test budget. A pre-existing bug
needs a reproduced RED, then a focused fix and GREEN, including safe negatives.
New detection rules start experimental/report-only; do not lower existing
quality floors, change pins to hide regressions, or claim all-CWE coverage.
T0: Python/docs governance checks. T1: focused component plus real CLI smoke.
T2: Linux suite and relevant corpus/sanitizer slice. T3: stated release profile.
Do not run unrelated heavy suites repeatedly. No sudo or hidden downloads.

Fixes necessary for the current outcome and inside its scope belong to that
unit. Other discoveries are proposed future tasks through the controlled plan
amendment, not worked on immediately. A blocked front stays blocked: never
skip it or weaken its acceptance to obtain PASS. No old wholesale merges or
copies: donor behavior must be re-understood, narrowly reimplemented and tested.

## Delegation boundary

Before each assignment name the one allowed repository/worktree, branch and
exact verification SHA, role, owned files or read-only question, checks and
stop point. Tell every agent that others may work concurrently and that their
changes must not be reverted or absorbed outside the assigned scope.

The primary implements and integrates. Helpers may edit only explicitly owned
files in their isolated assigned workspace. Independent verifiers are strictly
read-only and inspect the actual contract, diff, checks and negative evidence.
They must not edit, switch/create branches, commit, finalize, push, open or
comment on PRs, trigger workflows or act on another project. Neither helpers
nor verifiers may spawn further agents without a separately bounded primary
assignment. Only the primary may perform an owner-authorized remote action.
Material findings block completion; any changed head invalidates prior PASS.

## Preservation and publication

Main remains unchanged. Former local branches live in archive refs and a
verified bundle (docs/RESTART.md); they are not active work. Never delete those
archives or remote branches implicitly. A ready verified feature branch may be
pushed fast-forward under the owner's standing authorization. Never force-push,
merge main, tag/release, or change hosted protections without explicit authority.
Local progress is not hosted CI success or a published release.

Read MASTER_PROMPT.md for unattended execution and evidence handoff.
