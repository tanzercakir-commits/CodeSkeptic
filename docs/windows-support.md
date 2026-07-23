# Windows support — status and remaining work

> **Working paths today**: native MSVC build from source (Tier 1,
> below), WSL2, or Docker — see the
> [README's Windows section](../README.md#windows-native-build-from-source-or-wsl2docker),
> including the honest `#ifdef _WIN32` caveat on the WSL2/Docker paths.

Status: **Tier 1 + Tier 2 landed** (phase7-windows-native +
phase8-windows-sdk, 2026-07-23). The native MSVC build compiles, links,
and runs the full 682-test unit suite green on `windows-latest` on every
push, and plain-terminal directory mode is guarded by its own CI step —
the item-6 ratchet ([windows.yml](../.github/workflows/windows.yml))
holds both from here on. Tier 2 turned out to need measurement, not
code (see item 3). Packaging landed with v0.4.5: a prebuilt
`codeskeptic-windows-x86_64.zip` ships from the release lane, with a
per-push packaging rehearsal + relocation smoke in windows.yml. The
per-item notes below record what landed and what each gap turned out
to be in practice.

## Starting point: the core is already portable

- **No POSIX process/syscall use.** A scan for `fork`/`exec*`/`popen`/
  `pipe`/`dup2`/`mkstemp`/`opendir`/`unistd.h`/`sys/*.h` across `src/` finds
  only analyzer *rule strings* (function names the tool detects), never a
  real call. The tool does not shell out or spawn.
- **C++17 `std::filesystem` everywhere** for path/dir/time work
  (`StaticAnalyzer.cpp`, `SourceManager.cpp`, `Sidecar.cpp`) — portable.
- **Separators already handled where it matters:** `HtmlReporter.cpp:75`
  splits on `"/\\"`; the `no-absolute-paths` policy already recognizes both
  `C:\` and `/` (`Policy.cpp:31-37`).

So this is a targeted port, not a rewrite.

## Requirements

### 1. Windows LLVM/Clang development package (external dependency — the gate) — LANDED
`src/CMakeLists.txt` links `clangTooling, clangFrontend, clangAST,
clangBasic, clangSerialization, clangDriver, clangParse, clangSema,
clangAnalysis, clangEdit, clangLex, clangASTMatchers, LLVMSupport`. The ABI
must match the build: MSVC-built LLVM for an MSVC build.

**What landed:** the official
`clang+llvm-20.1.8-x86_64-pc-windows-msvc.tar.xz` release tarball carries
everything (headers, static libs, `lib/cmake/{llvm,clang}`);
`find_package(LLVM/Clang CONFIG)` finds it via `-DCMAKE_PREFIX_PATH`. One
papercut, patched in CI: the tarball's `LLVMExports.cmake` hard-codes the
absolute `diaguids.lib` path of the machine that *built* LLVM — the
windows.yml "Patch LLVM exports" step rewrites it to the runner's real
DIA SDK (idempotent, survives caching). Note the package is a static-CRT
(`/MT`) build and its config propagates that to the whole tree.

### 2. MSVC compiler/toolchain guards (small, certain) — LANDED
- `-fno-rtti` → `/GR-` under MSVC; `/bigobj` on the core library (PUBLIC,
  the Clang-header-heavy test TUs need it too) — `src/CMakeLists.txt`.
- Found in practice, beyond the original list: the `-Wl,-rpath` link
  options had to be gated off Windows; googletest needed
  `gtest_force_shared_crt` (CRT-model match); `__builtin_*_overflow` has
  no MSVC equivalent — replaced by the exported `checkedAdd64/Sub64/Mul64`
  helpers (`src/engine/Interval.h`, verified equivalent to the builtins
  over the int64 edge matrix + 40M random pairs), which also retired the
  `__int128` corner arithmetic in `IntOverflowRule.cpp` (a GCC/Clang
  extension MSVC lacks).
- LLP64 discipline in *test fixtures*: analyzed snippets must spell size
  types as `__SIZE_TYPE__` and 64-bit intent as `long long` (`long` is 32
  bits on Windows), and paths spliced into hand-built JSON must be
  forward-slash (`generic_string()`). The windows lane now enforces all
  of this.

### 3. System-header discovery for the *analyzed* code (the real functional gap) — LANDED (by measurement, not code)
The plan assumed a Windows branch in `SourceManager.cpp` (mirroring the
`#ifdef __APPLE__` isysroot logic) would have to discover MSVC + SDK
include paths. **Measured on CI: unnecessary.** Clang's MSVC toolchain
driver carries its own discovery — `INCLUDE` env when present (Developer
Prompt), otherwise VS via COM setup-API/registry and the Windows SDK via
registry. Two probe rounds on `windows-latest` proved it: with the entire
28-variable vcvars family stripped from the environment (plain-terminal
simulation), the freshly built exe still resolved `#include <stdio.h>` in
analyzed code, in plain point-at-a-directory mode, and reported the
planted bounds/null-deref/leak findings with exit 1. That behavior is now
pinned by a hard windows.yml step ("Directory mode without a Developer
Prompt") — if a future LLVM upgrade regresses it, the lane goes red and
the vswhere-style fallback becomes real work again.

Inherent requirement (not a gap): an MSVC toolset + Windows SDK must be
installed on the machine — there is nothing to discover otherwise. A
user-supplied `compile_commands.json` bypasses discovery entirely, on
every platform.

### 4. SARIF absolute-path detection (small correctness bug) — LANDED
`SarifReporter.cpp` used to classify a path as absolute only when
`path[0] == '/'`, mis-classifying Windows `C:\...` paths and emitting
`file://` URIs GitHub Code Scanning cannot ingest. Fixed (earlier, in the
v0.4.2 packaging round): drive-letter (`X:\` / `X:/`) and UNC (`\\`)
prefixes are absolute (`isWindowsAbsolute`, pinned by SarifReporterTest).

### 5. MCP stdio binary mode (robustness) — LANDED
`server/McpServer.cpp` frames JSON-RPC line-by-line
(`std::getline(std::cin, ...)` / `std::cout << ... << "\n"`). On Windows,
text-mode stdio would leave a trailing `\r` on each read line and expand
`\n` to `\r\n` on write. `runMcpServer` now sets binary mode
(`_setmode(_fileno(stdin/stdout), _O_BINARY)`) on Windows *and* strips a
trailing `\r` on every platform (CRLF-framing clients).

### 6. CI guard (the ratchet — without it, Windows support silently rots) — LANDED
[windows.yml](../.github/workflows/windows.yml): a `windows-latest` job on
every push — cached official LLVM tarball, `vcvars64` env exported (cl.exe
*and* `INCLUDE` for the analyzed snippets), full ctest + the same
single-process rerun as the Linux lane + a native-binary smoke (exit-code-1
contract), status/diagnostics mirrored to `refs/status` / `refs/ci-logs`.
No third-party actions (trust-chain rule). The auxiliary harness stays
**bash + python** by design (`run_juliet.sh`, `run_corpus.sh`,
`review_diff.sh`, ...) and runs on the Linux/macOS lanes only; the ctest
`ReviewDiffFlow` entry is accordingly POSIX-gated in `tests/CMakeLists.txt`.
The 682 C++ unit tests are the portable floor and all run on Windows.

## Effort tiers

- **Tier 1 — "builds and runs with a `compile_commands.json` (or from a
  Developer Prompt)":** items 1 + 2 + 4 + 5 + 6. **DONE** — landed as
  phase7-windows-native with the ratchet guarding it.
- **Tier 2 — "point-at-a-directory" parity anywhere:** item 3. **DONE** —
  closed by measurement (phase8-windows-sdk): the clang driver's own
  VS/SDK discovery covers it; guarded by the no-dev-prompt CI step
  instead of new code. What the plan called "the largest single piece"
  cost two probe rounds and zero engine lines.
- **Packaging — DONE** (v0.4.5, phase9-windows-package):
  `package_release.sh` runs under Git Bash on the runner with a small
  Windows branch (zip via 7z, `codeskeptic.exe`, `cygpath` for the
  resource dir, no lib bundling — the static-CRT build links only
  Windows system DLLs). Release lane: build → 682 tests → version/tag
  check → package → relocation smoke (C:\llvm renamed away + vcvars
  family stripped: the zip must carry itself) → draft upload; combined
  `sha256sums.txt` covers Linux + macOS + Windows. The same package +
  smoke also runs on every push (windows.yml rehearsal) so packaging
  breaks at push time, not tag time.

## Invariants
Everything landed behind the item-6 CI floor with every existing unit test
and NIST Juliet floor green — Windows support was added *on top of* the
invariants, never by relaxing them. That includes the checked-arithmetic
rewrite (`Interval.h` helpers) proving behavior-identity with the GCC/Clang
builtins before replacing them.
