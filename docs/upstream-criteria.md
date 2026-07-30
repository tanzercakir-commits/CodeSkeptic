# Upstream Reporting Criteria

Every candidate finding runs through this before any report is filed.
Precision-first applies to reporting doubly: one bad upstream report
costs more reputation than ten unreported true bugs. Precedent that
passed: tensorflow/tensorflow#123387 (TFLite rfft2d leak — mechanism
hand-verified, path real, no duplicate, HEAD affected; fixed by a
community PR). Precedent that was correctly killed by the checklist:
zlib untgz (2026-07-30 — defect real in the 1.3.1 tarball, but
upstream had DELETED contrib/untgz entirely; reporting a bug in
removed code would have cost credibility for nothing).

## Gate A — defect certainty (ALL FOUR required; miss one → no report)

1. **Mechanism proven by reading source.** Tool output alone is never
   enough; the claim must survive a human read of the actual code
   (macro expansions checked, cleanup paths traced).
2. **Trigger path is real.** Reachable input or call chain — not
   test-only, not dead, not behind a config no one builds.
3. **No duplicate.** Issue tracker AND commit history searched; a fix
   already landed or in flight kills the report.
4. **Current HEAD still affected.** Pinned-version findings must be
   re-verified on upstream's development head — the code may have been
   fixed OR REMOVED (the untgz lesson).

## Gate B — report value (defect certainty is not sufficiency)

5. **Is the code maintained?** contrib/, examples/, vendored copies
   and "as-is" directories rate LOW even when the defect is real —
   check the project's own README/contrib disclaimers.
6. **Does the severity carry a report alone?** A trivial
   missing-null-check does not travel by itself; bundle only same-root
   cases, never pad.
7. **Right channel.** If there is security impact, SECURITY.md's
   process outranks the public tracker. Otherwise follow
   CONTRIBUTING.md's shape.

## Gate C — presentation standard (only after A and B pass)

8. Reproduction first: file:line, the minimal flow, and an honest
   statement of how it was found (static dataflow analysis of <tree>).
9. One issue = one defect.
10. Fix suggestions stay modest and match the maintainers' style;
    the report's job is the proof, not the patch.

## Ledger

| Candidate | Gate A | Gate B | Outcome |
|---|---|---|---|
| TFLite rfft2d/irfft2d leak (#123387) | 4/4 | pass | reported; community PR open |
| zlib untgz strcpy (1.3.1) | failed 4 (code deleted at HEAD) | — | no report |
| zlib untgz strdup (1.3.1) | failed 4 (same) | — | no report |
