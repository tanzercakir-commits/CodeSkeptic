# CodeSkeptic v0.4.1 — the measured-recall round

v0.4.0 fixed the front door (relocatable binaries, Docker, the
report-only Action, a README a stranger can use in five minutes).
v0.4.1 is the engine round that followed, worked entirely from
measurement: every missed Juliet case is now *classified*
(by-design silence vs addressable gap), and the addressable slices
were closed one root cause at a time — each improvement locked by a
ratcheted CI floor, precision-first bar intact.

## Engine

- **int-overflow coverage** (recall 0.010 → 0.052 @ precision 1.000):
  signed `+` joins `*`; 64-bit sites are proved from operand intervals
  via `__int128` corner arithmetic; results implicitly narrowed into a
  smaller signed type (`char r = d + 1` — the add happens in `int`,
  the wrap on the store) are checked against the destination width.
  Unsigned destinations (defined wrap) and explicit casts (stated
  intent) stay silent; `INT64_MAX`-boundary literals became modelable
  (an off-by-one in the interval evaluator's significant-bits guard).
- **div-by-zero copy flow** (recall 0.093 → 0.098 @ precision 1.000):
  zeroness now flows through var-to-var copies — `int copy = data;`
  no longer launders an untrusted divisor, and the copy step shows up
  in the finding's dataflow trace.
- **Immutable-flag constant propagation** (engine-wide): assume edges
  that contradict the provable value of a never-written file-static
  flag are infeasible and contribute no state. The Juliet
  flag-correlation FP family died at the root — memory-leak precision
  0.684 → 0.714 with cross-rule noise down on three other CWEs at
  once. Mutated or address-taken flags are never folded (folding
  would hide real leaks; pinned tests enforce both directions).

## Measurement infrastructure

- `JULIET_FN_CLASS` — every missed case bucketed by variant family
  (float / opaque / baseline / flow / multifile / cpp), published with
  full benchmark output to a git-readable ref on every run. Recall
  numbers now carry their honest denominator: 66% of div-by-zero's
  misses are deliberate silences, not gaps.
- Floors ratcheted in `scripts/juliet_expected.txt` with rationale:
  CWE-190 recall 0.005 → 0.040, CWE-369 0.03 → 0.085, CWE-401
  precision 0.66 → 0.68.

## Everything else

The v0.4.0 onboarding surface is unchanged and re-validated by this
release's own clean-container smokes: binaries for Linux x86_64 and
macOS arm64 (no LLVM install needed), the Docker image, the
report-only-by-default GitHub Action, idiom profiles, and the
layered docs. Full plan and status: `docs/PLAN-v0.4.md`.
