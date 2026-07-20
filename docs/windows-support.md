# Windows support — requirements (plan, not yet implemented)

Status: **plan only.** No Windows code has been written. This document
records, with file:line evidence, exactly what a Windows port needs, so the
work can be scoped and gated (the ratchet) before any code moves. The core
engine is already portable; the gaps are a small, bounded set.

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

### 1. Windows LLVM/Clang development package (external dependency — the gate)
`src/CMakeLists.txt:78-99` links `clangTooling, clangFrontend, clangAST,
clangBasic, clangSerialization, clangDriver, clangParse, clangSema,
clangAnalysis, clangEdit, clangLex, clangASTMatchers, LLVMSupport`. Windows
needs these dev libraries: an official LLVM Windows release, `vcpkg install
llvm[clang,tools]`, or Chocolatey. The ABI must match the build: MSVC-built
LLVM for an MSVC build. `find_package(LLVM/Clang CONFIG)` (CMakeLists.txt:14-15)
is already portable; pass `-DCMAKE_PREFIX_PATH=<llvm-windows-install>`.

### 2. MSVC compiler-flag guards (small, certain)
- `src/CMakeLists.txt:89` emits `-fno-rtti` — GCC/Clang syntax. Under MSVC
  it must be `/GR-`. Guard with `if(MSVC) ... else() ... endif()`.
- The large number of Clang TUs tends to overflow MSVC's object section
  limit; `/bigobj` is likely required on the core library.

### 3. System-header discovery for the *analyzed* code (the real functional gap)
`SourceManager.cpp:180-203` has an `#ifdef __APPLE__` branch (adds
`-isystem /usr/include`, isysroot) and relies on the Clang resource dir on
Linux — but **no Windows branch.** To parse a target's `#include <stdio.h>`
on Windows, the driver needs the MSVC + Windows SDK include paths (normally
from the `INCLUDE` env set by `vcvarsall`, or discovered via `vswhere`),
typically with `-fms-compatibility -fms-extensions`.

**Important mitigation:** if the user supplies a real `compile_commands.json`
(from their own MSVC/clang build), include paths come from there and this is
largely bypassed. Only the "point at a directory" convenience mode — the
synthesized `-fsyntax-only` command in `SourceManager.cpp:116` — strictly
needs Windows SDK discovery. This is why the effort tiers below split on it.

### 4. SARIF absolute-path detection (small correctness bug)
`SarifReporter.cpp:39` classifies a path as absolute only when
`path[0] == '/'`. On Windows an absolute path is `C:\...`, so it is
mis-classified as relative and the emitted `file://` URI is wrong — which
breaks GitHub Code Scanning ingest for Windows paths. Fix: also treat a
drive-letter (`X:\` / `X:/`) and UNC (`\\`) prefix as absolute. (Console/
HTML/JSON reporters are unaffected.)

### 5. MCP stdio binary mode (robustness)
`server/McpServer.cpp:272-276` frames JSON-RPC line-by-line
(`std::getline(std::cin, ...)` / `std::cout << ... << "\n"`). On Windows,
text-mode stdio leaves a trailing `\r` on each read line and expands `\n` to
`\r\n` on write. Newline-delimited JSON clients usually tolerate this, but
to be safe set binary mode (`_setmode(_fileno(stdin/stdout), _O_BINARY)`) or
strip a trailing `\r`.

### 6. CI guard (the ratchet — without it, Windows support silently rots)
The 620 unit tests are C++/ctest and portable (GoogleTest builds on
Windows). The auxiliary harness, however, is **bash + python**
(`scripts/*.sh`: `run_juliet.sh`, `run_corpus.sh`, `analyze_diff.sh`,
`review_diff.sh`, `test_review_diff.sh`); these need Git-Bash/WSL on Windows.
The only thing that keeps a Windows port *real* is a `windows-latest` GitHub
Actions job (LLVM via choco/vcpkg) that builds and runs ctest. Without that
floor, the first later change breaks Windows and no one notices.

## Effort tiers (recommended sequencing)

- **Tier 1 — "builds and runs with a `compile_commands.json`":** items 1 + 2
  + 4. Small, bounded, testable; yields an honest "works on Windows (with a
  compile DB)" claim. Add the item-6 CI job in the same increment so the
  claim is guarded.
- **Tier 2 — "point-at-a-directory" parity:** item 3 (Windows SDK header
  discovery). Windows-specific and brittle; the largest single piece.
- **Always:** items 5 + 6 (robustness + guard).

## Non-goals for now
No code changes are made by this document. Any implementation must land
behind the item-6 CI floor and keep every existing unit test and NIST Juliet
floor green — Windows support is added *on top of* the invariants, never by
relaxing them.
