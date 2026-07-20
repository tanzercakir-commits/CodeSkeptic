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

## What it does *not* do yet (the honest limit)

The biggest USB/protocol attack surface is `memcpy(fixed_buf, src, len)`
where `len` is the untrusted length. Today the source mechanism feeds the
**int-overflow** rule (length arithmetic), but the **bounds** rule still
requires a *proven* whole-range overflow, and a full-range length includes
safe values — so an unguarded copy sized by an untrusted length is not yet
flagged.

Making the bounds rule emit a **possible-overflow warning** when a copy's
size is an untrusted-source-derived (full-range) value that can exceed the
destination is the natural next step. It is deliberately a **separate
increment**: it can shift CWE-120/125 precision, so it must be validated
against the Juliet floors in CI (which gate the merge) before it lands —
the ratchet, not a judgment call. This document is the design placeholder
for that work.
