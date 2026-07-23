# CodeSkeptic v0.4.3 — the real-world FP round

v0.4.2 put the thesis axis under CI guard and shipped an on-demand
real-world scan lane. This release is what that lane was FOR: the
first scans reproduced the analyzer's stable core exactly — and
surfaced 37 false positives on libgit2 and rtp2httpd. Every one was
adjudicated against upstream source, reduced to a reproducer, and
fixed at a root cause. Six roots, four engine rounds, zero
suppression lists.

## The numbers (CI-verified on pinned versions)

- **libgit2 v1.9.0** (201 files): 61 → **34** — exactly the
  documented stable core (23 triaged null-derefs + the 11 confirmed
  OOM-path leaks reported upstream). The 27-finding hashmap-macro
  family is gone.
- **rtp2httpd** (39 files): 12 → **0**.
- Unchanged and green throughout: all Juliet per-CWE floors, the
  real-world corpus pins (cJSON 53 / tinyxml2 9 / abseil 4 /
  Catch2 0), the frozen thesis-corpus gate (0 FP, 9/9 in-scope), and
  the self-scan. 683 unit tests (was 661) — every fix pinned in both
  directions.

## Engine — six root causes

- **Correlation-miner entailment**: the disjunct-collapse miner
  matched facts by exact key, blind to stamped equalities on other
  literals (`(j EQ 1)=true` neither excluded the `j == 0` disjunct
  nor witnessed the consumable implication). Compatibility, witness
  and activation now run through stamp entailment — the khash
  `j`-flag/pointer correlation survives the collapse.
- **Member fact keys**: `if (c.has_x) produce; ... if (c.has_x)
  consume;` on a local struct's field had no correlation support at
  all. Dot-members join the fact domain (conditions, literal-store
  stamps, erasure at `&c`-receiving calls), with a documented
  deliberate limit mirroring the keyed-globals trade.
- **Implication payloads**: mined guard implications can now promise
  "guarded absence of null-info" (Unknown), not just NonNull — the
  out-param-factory-under-a-guard shape survives disjunct-cap
  collapses.
- **Out-param success contracts**: `rc = getaddrinfo(..., &res)`
  with `rc == 0` guarantees a non-null result (POSIX); the call
  splits success/failure disjuncts so the caller's own error check
  proves the happy path — and an UNCHECKED rc keeps the failure
  side reportable. Curated: getaddrinfo, posix_memalign.
- **Miner slot discipline**: implications never key on the pointer's
  own nullness (a tautology that burned the slot), and the
  anti-vacuity witness runs strict-then-loose, accepting a
  complement-deciding disjunct for compound contracts
  (`if (!p && len > 0) return;`) only when the strict pass mines
  nothing — so nothing previously mined can be shadowed.
- **scanf field widths + strlen-guard witness**: `%2d` now seeds
  [-9, 99] instead of a full int range that manufactured overflow
  "witnesses" (conversion/argument pairing handles `%*d`), and the
  CWE-120 unbounded-copy heuristic finally checks the claim in its
  own message — a dominating `strlen(src)` guard suppresses it,
  while dst-only, after-the-fact and other-variable measurements
  still fire.

## Everything else

The onboarding surface is unchanged and re-validated by this
release's clean-container smokes: binaries for Linux x86_64 and
macOS arm64, the Docker image on ghcr.io, the report-only GitHub
Action, idiom profiles, and the layered docs. Full history:
`docs/devlog/changelog.md` (2026-07-22).
