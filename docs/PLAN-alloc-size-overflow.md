# PLAN — Untrusted allocation-size overflow (binfont hunt result)

> 2026-07-30. The LVGL binfont untrusted-length hunt (docs/
> scan-triage-2026-07-30.md) came up EMPTY — and the empty result is
> the finding. It is a SCOPE GAP, not clean code, and it names the next
> rule. Self-contained brief for a future session.

## The hunt, honestly

Declared `lv_fs_read` / `read_label` as `--untrusted-int-sources` and
re-scanned LVGL src: 47 = 47, zero new int-overflow / sign-conversion /
bounds findings. But the code is not clean. `lv_binfont_loader.c`:

```c
uint32_t loca_count;                                   // from the font FILE
lv_fs_read(fp, &loca_count, sizeof(uint32_t), NULL);   // NO guard
uint32_t* glyph_offset = lv_malloc(sizeof(uint32_t) * (loca_count + 1));
for (unsigned i = 0; i < loca_count; ++i)
    glyph_offset[i] = offset;                          // OOB if the size wrapped
```

`loca_count = 0xFFFFFFFF` -> `loca_count + 1` wraps to 0 in uint32 ->
`lv_malloc(0)` -> the fill loop of 0xFFFFFFFF entries overflows the
heap. Attacker-reachable through a crafted .bin font. A second site at
line 337: `lv_malloc(loca_count * sizeof(lv_font_fmt_txt_glyph_dsc_t))`
— same shape. Present at LVGL HEAD (33d45e3), no upper-bound guard —
so unlike the untgz candidate, this one PASSES upstream gate A/4, and
it is core src (gate B/5 maintained).

## Why every existing rule misses it — by design

- **IntOverflowRule**: signed only (`!isSignedIntegerType() -> return`).
  `size_t * uint32_t` is unsigned; unsigned wrap is defined behaviour,
  correctly out of its UB scope. This is THE reason the multiply is
  invisible.
- **sign-conversion**: needs a signed->unsigned conversion; loca_count
  is already unsigned. And it EXCLUDES allocator arguments (last
  session's precision fix) — so an allocation size is doubly out.
- **bounds**: fixed-extent copies, not a dynamic lv_malloc extent
  written in a count loop.

The gap is exactly the nlohmann lesson one level over: there an
untrusted SIGNED value became a huge unsigned length (sign-conversion);
here an untrusted UNSIGNED value wraps a computed allocation size.

## The rule candidate: alloc-size-overflow (CWE-131 / CWE-190-unsigned)

Report an UNSIGNED arithmetic (`*` or `+`) that (all required,
precision-first):

1. has an operand of declared untrusted provenance (the existing
   untrusted-int-source model, returns AND out-params — 3b),
2. is (transitively) the size argument to an allocator (the intrinsic
   family + --alloc-functions — REUSE isAllocatorCallee from
   SignConversionRule, now shared),
3. can PROVABLY wrap: the proven interval of the result, computed in
   unbounded integers, exceeds the unsigned type's max (the finite-
   witness discipline, mirror of escapesSignedFinite for the unsigned
   modulus).

Precision anchors:
- a guard (`if (loca_count > LIMIT) return`) narrows the interval and
  silences — same edge-refinement the other rules ride;
- unknown (non-untrusted) size stays silent — provenance opt-in;
- the allocator EXCLUSION that sign-conversion added is INVERTED here:
  this rule's whole point is the allocator sink. The two rules partition
  the space cleanly — sign-conversion owns non-allocator length use,
  alloc-size-overflow owns the allocator sink.

Honest scope note: the HARM is the subsequent write loop over the
pre-wrap count, which this rule does not prove — it reports the
size computation, sink-aware, on provenance + wrap. That is the
defensible v1 (the write-loop link is interprocedural-ish; later).

## Acceptance tests (RED-first)

- `n = read_u32(); malloc(sizeof(T) * (n + 1))` with n untrusted ->
  REPORT (RED on today's binary);
- same with `if (n < 1000)` guard -> silent;
- signed operand -> that is IntOverflowRule's job, not here;
- non-untrusted n -> silent (provenance);
- the LVGL binfont trophy replica (loca_count shape) -> REPORT.

## Then — and only then — the LVGL question

If the rule lands and flags binfont, it becomes an upstream CANDIDATE,
run through docs/upstream-criteria.md:
- gate A/1 mechanism: proven by reading (done above);
- gate A/2 trigger: crafted .bin font, reachable — plausible, confirm;
- gate A/3 DUPLICATE: **font parsers attract CVEs — search LVGL issues,
  advisories and CVE db BEFORE any report. Not yet done.**
- gate A/4 HEAD: affected (confirmed, 33d45e3);
- gate B/7 channel: memory-safety in a "1M+ device" GUI lib -> LVGL
  SECURITY.md / private disclosure, NOT the public tracker.

Do not file anything until the duplicate search and the rule both
exist. This doc is the trail.

## Execution

- Branch: `phase-alloc-size-overflow` from main.
- New rule file mirrors SignConversionRule's shape; lift
  isAllocatorCallee into a shared header (engine/AllocFunctions or a
  small AllocatorSinks.h) so both rules use one definition.
- Off by default (needs the provenance flag), like sign-conversion.
- Local gates before push: suite + thesis + corpus (the discipline).
