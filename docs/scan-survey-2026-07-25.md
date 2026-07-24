# Real-World Scan Survey — 2026-07-25 (11 targets, one afternoon)

A breadth sweep across hobby code, libraries, an OS, graphics
engines and compression — run on the realworld-scan CI lane, each
with the processed/broken honesty counts. The value was the
learning, not the finding counts. Two false-cleans were correctly
distrusted before they could mislead.

## Results

| Target | Scope | Findings | Coverage | Verdict |
|---|---|---:|---|---|
| Fourier-Series | 24 files | 0 | broken=1 | clean (friend's own code) |
| TeXRender | 36 files | 0 | clean | clean (friend's own code) |
| raylib-modern (friend) | 229 files | 20 | broken=1 | all in VENDORED glfw/raylib tools |
| box2d 3.0.0 | 35 files | **0** | broken=0 | **genuinely clean** (pure-C physics) |
| libexpat 2.6.4 | full lib | **0** | broken=0 | **genuinely clean** (see README trophy) |
| zlib 1.3.1 | 64 files | 12 | broken=1 | mixed; triage pending |
| lua 5.4.7 | 40 files | 36 | broken=1 | **assert-family FP** (all null-deref) |
| sqlite 3.47 | 1 giant TU | 132 | broken=0, 184s | **assert-family FP** (69+ null-deref) |
| raylib 5.5 src | 53 files | 177 | broken=1 | vendored + assert-family FP |
| LVGL 9.2.2 | 361 files | 47 | broken=0 | triage pending (full coverage) |
| zstd 1.5.6 | 75 files | 5 | broken=0 | **assert-family FP, adjudicated** |
| mbedTLS / stb_image | — | — | false-clean | generated header / driver did not compile |

## The headline finding: an ecosystem-wide assert-nonnull FP family

Across FIVE independently-audited C codebases the dominant "finding"
is the same false positive: a pointer assigned from a can-return-null
call, then `assert(ptr)`, then dereferenced. The engine does not yet
treat `assert(cond)` as narrowing `cond` true on the fall-through
edge, so every deref after the assert reads as unchecked.

Adjudicated proof (zstd 1.5.6, `zstd_compress.c:5505`):

```c
cdict = ZSTD_cwksp_reserve_object(&ws, sizeof(ZSTD_CDict)); /* may be NULL */
assert(cdict != NULL);                                       /* the invariant */
ZSTD_cwksp_move(&cdict->workspace, &ws);                     /* flagged deref */
```

Witnesses: curl (`DEBUGASSERT`), lua (`lua_assert`, 36/36 findings),
sqlite (`assert`, 69+), raylib (`assert`), zstd (`assert`, proven).

### Loop-closure bonus

The zstd `cdict` site was FIRST seen in ReactOS's vendored (old)
zstd copy, then re-confirmed in current upstream v1.5.6
(`ZSTD_LOOP=recurs_upstream`) — a finding seen in one place and
independently reproduced in another, current source. It turned out
FP, but the reproduction pipeline is exactly what a real upstream
report would ride on.

## Recommendation: assert-refinement is the next engine round's #1

Model `assert(cond)` as a guard that refines `cond` true on the
fall-through edge — distinct from `--fatal-asserts` (which kills the
path on abort); this one uses the RELEASE-time invariant the assert
documents (`assert(x)` then relying on x is UB if false, so treating
x as true is sound-by-contract).

- **Impact**: every real C codebase uses assert; this single feature
  collapses the hundreds of FPs seen across all five witnesses at
  once (lua 36→~0, sqlite's null bulk, most of curl's 83).
- **Risk**: LOW — the refineOnEdge guard machinery already exists;
  wiring an assert call into it as a condition is narrow.
- **Priority**: precision-first. This should precede the Phase 7A
  recall slices — higher impact, lower risk, five ready repros.

## Genuine wins recorded

- **box2d 3.0.0**: 0 findings, full coverage — a precision data point
  from a maths-heavy physics engine.
- **libexpat 2.6.4**: 0 findings — already in the README trophy table.

## Parked for later triage (real coverage, not yet adjudicated)

zlib (12), LVGL (47 — full 361-file coverage), raylib-src's non-
vendored remainder. All behind the assert-refinement round: much of
each is likely the same family, so triage AFTER that feature lands
will be far smaller.
