# Invariants — CWE restart

1. Main starts and stays at `7dfd37596414c9512316093ff4fb6b039673f55f`
   unless the owner explicitly authorizes a later main integration.
2. All executable work is the first complete task block in docs/TODO.md.
   BOOK.json owns the transactional state; PLAN/TODO/PROGRESS are exact checked
   views, not independently maintained queues.
3. `reverse(PROGRESS task IDs) + remaining catalog IDs == PLAN task IDs`.
   TODO exposes exactly the remaining tasks of the active chapter. The next
   chapter opens only when that inner queue is empty. No skipped or reused ID.
4. Completion pops exactly one front and pushes exactly one newest progress
   record. Its full contract and independent review remain preserved forever.
5. Front and completed contracts cannot be changed by ordinary amendments.
   Future contracts can be clarified and new work appended with a reason and
   old-plan digest. Existing active chapter tasks cannot be jumped.
6. A review binds the clean implementation SHA, task, branch, full contract,
   distinct implementer/verifier identities and every required check's evidence.
   PASS with zero material findings is required. This shared-user procedure is
   not a cryptographic signature or proof of an honest external producer.
7. A caught write failure restores all managed bytes. After host/process loss,
   the journal blocks further work until recovery. Never claim multi-file writes
   are physically atomic; commit and transition guard complete the transaction.
8. Governance self-check checks state consistency, not product correctness or
   malicious-root resistance. Independent review and transition guards are also
   mandatory. Local evidence never proves GitHub publication or a full release.
9. No task may silently weaken tests, quality floors, scope or acceptance.
   A failure is recorded as failure; a blocked task is not DONE.
10. No subordinate has GitHub/PR/merge authority. Primary-only integration,
    read-only independent audit and explicit protected-main approval remain.
