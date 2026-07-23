# Untrusted-length sources (`--untrusted-int-sources`)

## What this is

The intrinsic-source recipe (v0.3): `atoi`/`strtol`/`scanf` deliver a value
the caller did not choose, so a downstream multiply or copy into a fixed
extent is a defect unless a guard refines it. **Protocol and parser code has
its own such sources** — a length or count field decoded off the wire (a
received USB descriptor, a packet header, a file-format field). Those
function names are project-specific, so they are **configuration, not code**:

```
codeskeptic src/ --untrusted-int-sources read_u16,packet_len,tud_cdc_read
```

The listed functions' **return** is then treated as a full-range untrusted
integer — the exact discipline already applied to `atoi`. A downstream
`n * k` that can escape the type is reported (CWE-190), while a guard
(`if (n <= LIMIT)`) refines it and stays silent.

## Reversibility / safety

- **Default is empty.** With no `--untrusted-int-sources`, the engine is
  byte-for-byte the previous behavior — every unit test and every NIST
  Juliet floor is unchanged. The feature only turns on when a project opts
  in, per project.
- It reuses the existing interval / overflow machinery — no new heuristic
  that could invent false positives on code that never asked for it.
- Re-hunt receipt: the full tinyusb device stack (24 TUs) scanned **clean**
  both without and with the flag on plausible sources — no new false
  positives.

## The bounds connection (landed, v0.4 F7 round)

The biggest USB/protocol attack surface is `memcpy(fixed_buf, src, len)`
where `len` is the untrusted length. The source mechanism now feeds the
**bounds** rule too: when a sized copy's length (memcpy/memmove/memset/
strncpy) *derives* from a declared untrusted source — the atoi/strtol
family, scanf-filled outputs, or this flag's functions — and its proven
FINITE range reaches past the destination's capacity, CodeSkeptic
reports a **possible buffer overflow (CWE-120)** warning. Reachability
is by construction: the source contract says the input picks the value.

The proof doctrine holds on both sides of the line:

- a guard (`if (len <= sizeof(buf))`) narrows the range on its own edge
  and silences the warning;
- an UNKNOWN length (no declared source) never reports — provenance is
  opt-in, never guessed, so ordinary size parameters stay silent;
- a `%2d`-style width-bounded scanf value keeps its narrowed range: it
  warns only against a destination it can actually exceed.

Validated by pinned unit tests (guard / reassignment / width / config /
unknown negatives), the Juliet floors and corpus pins in CI, and
real-world re-scans (libgit2, rtp2httpd) holding their documented
counts.
