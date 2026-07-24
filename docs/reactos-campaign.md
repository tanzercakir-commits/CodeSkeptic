# ReactOS Scan Campaign — status: PARKED (recipe documented)

Ten CI rounds (2026-07-25, `probe-reactos` history on the
realworld-scan lane) established exactly how far a plain GitHub
runner gets toward analyzing ReactOS, and where the wall is.

## What WORKS (proven, keep)

1. **Configure without a full OS build**: `cmake -G Ninja
   -DCMAKE_TOOLCHAIN_FILE=toolchain-clang.cmake -DARCH=i386
   -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
   -DCMAKE_DISABLE_PRECOMPILE_HEADERS=ON` on ubuntu-24.04 with
   `clang lld gcc-mingw-w64-i686 ninja flex bison` — ~10 s, emits a
   **9160-entry compile db**. The clang toolchain still assembles
   with mingw gcc, so BOTH toolchains must be installed.
2. **Generated SDK headers**: `ninja xdk psdk ntstatus bugcodes`
   materializes `winnt.h` and friends (seconds, host-side).
3. **Idiom profile**: `profiles/reactos.conf` (Ex*Pool* +
   RtlAllocateHeap/RtlFreeHeap families).
4. **Diagnostics discipline** (hard-won): tee every stage, publish
   per-file (git add is atomic across pathspecs — one missing name
   stages nothing), `set -o pipefail` explicitly (Actions' default
   `bash -e` has no pipefail; a failing cmake vanished into tee).

## The wall (why parked)

The mingw-w64 sysroot headers that `winnt.h` pulls in transitively
use **GCC MMX intrinsics** (`__builtin_ia32_*`, `_mm_*` inlines).
Clang 19+ removed those builtins (MMX re-implemented via SSE), so a
modern-clang front-end cannot parse the header chain: masking
mmintrin.h kills the `__m64` type winnt.h itself needs; shimming the
type still leaves header-inlined `_mm_*` CALLS undeclared. This is a
toolchain-version mismatch, not an analyzer defect.

## Resumption paths (in preference order)

1. **ReactOS's own CI container** — their pinned clang parses their
   headers by construction; run codeskeptic inside it (hand-run
   campaign, RosBE docker image).
2. Runner with clang <= 18 for the TARGET parse (our LibTooling
   front-end is clang 20; would need a second, older clang purely to
   validate flags — or a full _mm_* stub shim, ~40 functions).
3. Scan only subtrees that avoid the mingw intrinsics chain (boot/,
   some drivers compiled freestanding) — unmeasured.

## Yield so far

Two findings in `drivers/filesystems/btrfs/zstd` (VENDORED upstream
zstd, old version): a maybe-null `cdict` deref (zstd_compress.c:3431)
and a null-then-deref `lastHashed` (zstd_ldm.c:293). Not
ReactOS-authored code — check against current upstream zstd before
any report; likely long since fixed or FP-adjudicable there. Recorded
here so the two data points survive.
