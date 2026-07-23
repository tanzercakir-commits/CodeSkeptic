# CodeSkeptic v0.4.5 — the first external evaluation's P1, fixed

An external evaluation on real user hardware (macOS arm64, a separate
AI toolchain driving the docs/evaluate.md protocol) validated the
whole surface — source build with LLVM 22, 683/683 tests, 7/8
deliberate bugs caught with the 8th correctly identified as a
documented by-design silence, checksums, relocation, compile-db
parity — and found one P1: the worst failure mode a static analyzer
can have.

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
- Exit codes documented in docs/usage.md: 0 clean, 1 findings,
  2 nothing-analyzed/usage failure modes explained.

695 tests (was 683). No analysis-engine changes — Juliet floors,
corpus pins and the thesis gate ride along unchanged.
