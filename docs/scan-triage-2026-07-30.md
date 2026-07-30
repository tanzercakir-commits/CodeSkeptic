# Parked Triage Closed — zlib + LVGL (2026-07-30)

The scan survey (2026-07-25) parked two targets "behind the
assert-refinement round: much of each is likely the same family, so
triage AFTER that feature lands will be far smaller." The round landed
(AR.3 + gate-4 per-variable + compound-body, all in main). This closes
the parked item, with the prediction tested honestly: it held for one
target and not the other.

Binary: main @ 3ae3ecb. Both scans replicate the survey lane recipes
exactly (LVGL hit 47/47 broken=0 verbatim; zlib's tree hit its
broken=1).

## zlib 1.3.1 — 12 -> 7, and the core is CLEAN

| | survey | now (off) | now (on) |
|---|---:|---:|---:|
| findings | 12 | 7 | 7 |

Recovery delta is zero (zlib's findings are not assert-family); the
12 -> 7 shrink came from the engine precision work landed since the
survey. The headline: **all 7 sit in contrib/ and examples/ — the
15-file core library scans clean.**

Triage of the 7:

| Site | Verdict |
|---|---|
| untgz.c:136 `strcpy(buffer, arcname)` | **REAL** — argv flows into a fixed static 1024-byte buffer unbounded (TGZfname <- argv[arg], line 638). Classic overflow in a contrib tool. |
| untgz.c:338 `buffer[len-1]` | **REAL (minor)** — `buffer = strdup(newdir)` with no null check, deref'd unconditionally. |
| untgz.c:259 `item->fname` | **FP, config-solved and PROVEN** — `error()` prints and exit(1)s but is not noreturn-annotated; `--fatal-asserts error` silences it (re-scan: 7 -> 6, site gone). The documented custom-fatal-handler lever. |
| pufftest.c:105 `(unsigned)atoi(...)` | **Technically right, low value** — sign-conversion's first wild firing (intrinsic atoi path, no flag needed). atoi overflow can go negative -> huge unsigned skip; but it is a test harness's CLI arg. Watch item: if the intrinsic-default ever storms on a bigger target, consider gating intrinsics behind the flag as well. One firing on all of zlib+LVGL is not a storm. |
| gzappend.c:439 `out` | **Probable-real (example code)** — the file's own header history notes malloc-check gaps. Not deep-verified. |
| gzjoin.c:374 `in` / zran.c:236 `index` | **NOT verified** — allocation sites carry checks nearby; whether the flagged paths dodge them was not established. Recorded as unadjudicated, not claimed either way. |

## LVGL 9.2.2 — 47 = 47, the parked prediction did NOT hold here

| | survey | now (off) | now (on) |
|---|---:|---:|---:|
| findings | 47 | 47 | 47 |

Recovery has zero effect: LVGL's findings are not the vanished-assert
family (its LV_ASSERT macros do not erase into the recovered shapes).
The survey's "will shrink after assert-refinement" guess was wrong for
this target — recorded as such.

Cluster classification (44 null-deref, 2 div-by-zero, 1 leak):

- **Unchecked lv_malloc + immediate deref** (draw/lv_draw_rect.c and
  friends): `bg_dsc = lv_malloc(...)` then `bg_dsc->base = ...` with no
  check; task pointers from lv_draw_add_task deref'd likewise. Honest
  "may" warnings of the TFLite accessor-nullability/assumption class.
  Embedded convention treats alloc failure as fatal-anyway; the right
  consumer-side treatment is a contract on lv_malloc (cs: ensures) or
  a baseline — the same conclusion the TFLite hunt reached. Not
  upstream-report material.
- **Accessor-nullability** (core/lv_obj_tree.c `parent->spec_attr->...`,
  disp->screens): fields whose null-safety rests on tree invariants the
  code elsewhere DOES check through accessors. Assumption-class.
- **div-by-zero x2** (buttonmatrix `/ unit_cnt`): denominator derives
  from summed button widths; provable-nonzero only through
  get_button_width's contract. Honest "may".
- **binfont_loader cluster (6) — the one lead worth a future pass**:
  lv_binfont_loader.c PARSES an external binary font file — untrusted
  input by nature, lengths and offsets read off the file drive
  allocations and derefs. This is exactly the territory of
  `--untrusted-int-sources` + the new sign-conversion rule (declare the
  fs-read fill functions as sources). Parked as its own candidate hunt,
  scoped and named, not started.

## Disposition

- zlib: two real contrib findings could be upstreamed (untgz strcpy,
  untgz strdup) — user's call; core-clean is a trophy-table candidate.
- LVGL: no per-finding follow-up; the class-level answer is
  contract/baseline, plus the binfont untrusted-length hunt as a
  separate future item.
- Parked-triage item: CLOSED.
