# Unattended execution

Read AGENTS.md and the current FIFO contract, not old chat commands. Continue
one task at a time while its local prerequisites and authority exist. Do not
wait for another approval at each ordinary local unit. Do not manufacture a
PASS or ask for permission merely because a focused regression found a bug.

Implementer sequence: check → task branch → RED where applicable → narrow fix →
budgeted GREEN → clean implementation commit → independent read-only audit →
canonical receipt → finalize → ledger-only commit → transition guard → next.
The primary alone performs those Git and ledger writes. Keep receipts and
bounded logs outside the worktree under a durable user-state directory; use
temporary paths for experiments, not the only copy of completion evidence.

Reviewers inspect requirements and files themselves. A summary is not proof.
Return either material findings or the exact canonical JSON receipt described
in docs/QUEUE_GUIDE.md. Distinct run identities are procedural accountability,
not cryptographic authentication. Changes require a fresh exact-head review.

Keep short user updates. Report task ID, outcome, evidence and next front,
not giant logs. If a tool/build fails, diagnose within scope and retry only with
a reason; avoid endless identical test runs or unbounded cache growth.

Stop for missing new authority (main merge, signing identity, release, destructive
external cleanup), unrelated user changes that cannot be preserved, exhausted
disk, or a front contract that cannot be met. Preserve the branch, report the
specific blocker and sound the requested notification if available. A notification
attempt is not a guarantee that the user heard it. Never ask for sudo passwords.
