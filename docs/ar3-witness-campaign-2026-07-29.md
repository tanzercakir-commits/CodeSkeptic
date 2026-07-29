# AR.3 Witness Campaign — 2026-07-29 (the promised measurement)

PLAN-assert.md's landing promise: "curl'ün gerçek assert-ailesi (~181
konum) AR.3 landing'inde ölçülür." This campaign measures the
assert-recovery delta (`--no-assert-recovery` vs default) on the scan
survey's witnesses, with the per-variable gate-4 binary (9c12db7),
replicating each witness's ORIGINAL lane recipe exactly — same
version, same build mode, same invocation, same counting grep. Every
baseline below reproduced its historical number before the delta was
read; a replication that cannot hit the old number is not a
measurement.

## Results

| Witness | recipe replicated | off | on | silenced | added |
|---|---|---:|---:|---:|---:|
| sqlite (125 TU src) | local delta rig (63 hit) | 63 | 57 | **6** | 0 |
| zstd 1.5.6 lib | probe-graphics job (5 hit) | 5 | 4 | **1** | 0 |
| curl 8.11.0 lib | ar2-curl job (82 hit) | 82 | 82 | **0** | 0 |
| lua 5.4.7 no-db | probe-lessons job (36/40/1 hit) | 36 | 36 | **0** | 0 |
| raylib | not measured | — | — | — | — |

Zero additions anywhere. The three zero/nonzero splits each have a
verified cause, and two of them correct earlier records:

## sqlite — the family is real and the gate now fits it

Six eliminations, every one hand-verified against the source, zero
relocations (the blanket-rejection relocation build.c:2536→2468 is
gone), zero additions. Detailed in changelog 2026-07-29.

## zstd — the adjudicated proof-case, closed by the engine

The ONE silenced finding is exactly the survey's adjudicated FP
(`zstd_compress.c:5507`, `cdict` from `ZSTD_cwksp_reserve_object`,
`assert(cdict != NULL)` between assignment and deref). The site that
was proven-FP by hand in the survey is now silenced by the machinery
that reads the same assert. zstd's erased assert body is a plain
`((void)0)` — the shape AR.3's gate 1 was built for.

## curl — FINDING 3, no longer a review note but a measured cost

curl's default `DEBUGASSERT` erases to `do { } while(0)`
(curl_setup_once.h:296). A compound-statement body currently produces
ZERO guards (the innermostCompound placement walk resolves the macro's
own body as the scope), so recovery silences NOTHING: 82 = 82. The
~181-location family that the AR.2 probe proved real (sites that fell
silent when assertions were compiled IN) is unreachable by AR.3 until
compound bodies are handled. One witness, eighty-two findings of
measured cost — this is the next recall lever, ahead of everything
else in the assert line.

## lua — an attribution corrected, honestly

The survey recorded "lua 36/36 assert-family". Replicating the exact
lane run (36 findings, 40 processed, 1 broken — numbers hit) and then
sampling sites shows otherwise: `lauxlib.c:485` derefs
`lua_touserdata()`'s result with NO assert anywhere near;
`lgc.c:1195`'s nearest assert (`lua_assert(isold(curr))`) asserts a
property of a DIFFERENT variable than the flagged `next`. These are
the accessor-nullability / assumption class, not the
assign-assert-deref shape. AR.3 silencing zero of them is CORRECT
behavior, and the survey's headline count for this witness was
misattributed. The ecosystem FP-family claim stands on curl (proved by
the AR.2 on/off probe), sqlite and zstd — not on lua.

## raylib — declared, not measured

The survey's raylib findings are dominated by vendored code and were
already parked for triage; a recovery delta on top of unresolved
vendor noise would measure nothing attributable. Skipped, stated.

## What this changes in the plan

1. **Compound-body recovery (FINDING 3) is promoted to the top of the
   assert line** — measured 82-finding cost on curl alone, and the
   same `do{}while(0)`/`G_STMT_START` shape is the default in GLib and
   much of the C ecosystem.
2. The scan-survey's lua row should be read as accessor-nullability,
   not assert-family (correction recorded here; the survey doc itself
   is a dated artifact and stays as written).
3. Suite note: changelog 2026-07-29 says "774 -> 778"; the correct
   chain is 772 (AR.3) -> 776 (review pins) -> 778 (per-variable
   pins).
