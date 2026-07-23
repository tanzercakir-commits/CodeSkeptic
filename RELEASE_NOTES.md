# CodeSkeptic v0.4.6 — the first external evaluation's P1, fixed

v0.4.5 shipped the first native Windows binary. This release fixes
the P1 that the first external evaluation (the maintainer's macOS
hardware, a separate AI toolchain driving the docs/evaluate.md
protocol) found in the darwin binaries — including the v0.4.5 one:
the worst failure mode a static analyzer can have.

## The P1: baked SDK path -> silent "Clean!" with zero coverage

Darwin release binaries carried the CI runner's versioned Xcode
sysroot (`/Applications/Xcode_15.4.app/...`) baked at build time. On
machines without that exact path — almost all of them — the
no-compile-db quickstart failed to find `stdlib.h`, skipped the TU,
and reported **"Clean! No issues found." with exit 0**: a green tick
with nothing analyzed. Both suggested fix layers are in:

- **Runtime SDK resolution** (`resolveMacSdkPath`, mirroring the v0.4
  resource-dir treatment): `SDKROOT` env (honored verbatim — explicit
  intent fails loudly, never silently second-guessed) -> one cached
  `xcrun --show-sdk-path` probe -> the baked path only while it
  exists. Unit-tested for the full resolution order.
- **Fail-loud exit policy**: when EVERY attempted translation unit
  fails to compile (and `--analyze-broken-tus` is not given), the exit
  code is now **2** with an ANALYSIS FAILED message — never a clean
  report. Partial breakage keeps the honest per-TU warning and
  findings-based exit codes. The GitHub Action already propagates
  exit > 1 as a job failure, in report-only mode too. The macOS
  release smoke now proves the loud path (`SDKROOT=/nonexistent`
  must exit 2).

## Also in this release

- A second positional source path is now a loud usage error (it used
  to be silently ignored — pass a directory or `--files`).
- Broken-TU records are deduplicated across summary-inference
  re-parses (they could overcount and spuriously trip the new exit-2
  policy).
- Exit codes documented in docs/usage.md.

No analysis-engine changes — Juliet floors, corpus pins, the thesis
gate and the new Windows lanes ride along unchanged.
