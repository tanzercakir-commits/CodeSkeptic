# CodeSkeptic v0.4.2 — the mission-axis gate

v0.4.1 closed addressable Juliet recall slices one root cause at a
time. v0.4.2 finishes that round across call boundaries — and, the
reason this project exists, it puts the **thesis axis** under CI
guard: a frozen, blind-generated AI first-draft corpus that every PR
must now pass with zero false positives.

## The thesis gate (new — gates every PR)

- 24 small C programs written by generator subagents **blind to
  CodeSkeptic's rules** — first-draft everyday/systems C,
  self-annotated, frozen verbatim in `tests/thesis_corpus/`.
  Regenerating them would break the blindness that makes the number
  meaningful, so they never change.
- An **adjudicated manifest** is the scored truth, not the raw
  annotations — a first-draft author's self-labels are noisy. One file
  the generator called clean actually dereferences two unchecked
  mallocs; CodeSkeptic flags it and is correct. Every such call is
  documented in the manifest.
- Current state, now pinned in CI: **0 false positives across the 9
  genuinely-clean programs; 9/9 in-scope memory-safety/overflow bugs
  caught.** Out-of-scope misses (float division, pure logic errors)
  are pinned at 0 as documented misses — if a future rule catches one,
  its pin moves up, Juliet-floor style. `scripts/run_thesis.sh`, wired
  as a `ci.yml` step; `docs/benchmarks.md` now tracks all three gated
  axes.

## Engine

- **div-by-zero goes interprocedural** (recall 0.098 → 0.108 @
  precision 1.000): zeroness now crosses call boundaries for
  fully-visible internal callees (internal linkage, address never
  taken — the ParamIntervals discipline). A parameter is seeded
  zero-able only when some call site *provably* passes a zero-able
  value; Unknown never seeds, so externally-callable and escaping
  functions behave exactly as before. CWE-369 recall floor ratcheted
  0.085 → 0.095.
- **Call-flag and flag-copy folding** (leak FP family, round 2):
  immutable-flag constant propagation now also folds branch conditions
  that are *calls* to functions with a stable never-zero return
  summary, and local copies of immutable flags join the closure
  (`int c = staticFalse; if (c) …` is provably dead). Mutated flags,
  address-taken flags, and maybe-zero callees are never folded — both
  directions pinned by unit tests.

## Infrastructure

- **Real-world scan lane** (`.github/workflows/realworld.yml`):
  pushing a `realworld-scan` branch builds the analyzer and runs full
  scans of libgit2 v1.9.0 (project allocators via profile flags),
  rtp2httpd, and a deep abseil pass, publishing per-project
  `REALWORLD_RESULT` counts and complete logs to a git-readable ref —
  release-scale validation on demand.
- **Draft-release janitor** (`housekeeping.yml`): orphaned draft
  releases left behind by retried release runs are pruned
  automatically after every successful Release.

## Everything else

The onboarding surface is unchanged and re-validated by this release's
clean-container smokes: binaries for Linux x86_64 and macOS arm64 (no
LLVM install needed), the Docker image on ghcr.io, the
report-only-by-default GitHub Action, idiom profiles, and the layered
docs. 661 unit tests. Full plan and status: `docs/PLAN-v0.4.md`.
