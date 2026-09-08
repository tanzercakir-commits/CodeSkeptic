# Windows support — status and remaining work

## Current platform artifact gate — CH06-S02-U002

The current restart's unsigned Windows x86_64 and macOS arm64 candidate packages
were actually qualified at source
`e83b641be32665740e8637cbb1368346e82ea471`, version
`0.4.9-dev+ge83b641be326`. Native run
[`34243269691`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34243269691)
attempt 1 and ordinary Windows run
[`34243269775`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34243269775)
attempt 1 finished successfully. Independent read-only audits reconciled actual
raw tests/scans, source and runner records, downloaded catalog/ZIP hashes, and
packaged executable bytes. [Exact artifact identities](release-checklist.md#hosted-native-measurement--2026-09-08)
are separate from this later documentation checkpoint and historical releases.
The ordinary Windows artifact remains diagnostic-only, not a retained package.

The candidate-only jobs in [release.yml](../.github/workflows/release.yml) now
build **Windows x86_64** and **macOS arm64** packages without creating a tag,
release, PR or Git ref. Their token is read-only, checkout credentials are not
persisted, and legacy release writers are tag-only. The frozen Windows workflow
and all existing quality floors stay unchanged. The measured promise is this
bounded actual-runner profile; adding jobs or passing synthetic tests alone
does not qualify another source, OS version or architecture.

Each native job runs the full CTest and single-process suites, assembles one
versioned archive, then hides its known build LLVM installation temporarily.
The recorded packaged executable runs outside checkout/build paths with a fresh
home and without developer-prompt, SDKROOT or dynamic-loader override variables.
UTF-8 paths and explicit compilation databases exercise both C and C++ across
clean (0), supported null-dereference finding (1), and missing-header/unavailable
(2) cases. Source/fixture/archive/executable hashes, native version/capabilities,
commands, raw outputs, JSON coverage and verdicts are retained together. A timeout
or failure retains failure evidence; it is never converted into PASS. The caller
restores LLVM in a finally/exit handler, and the final job must also succeed.

This is an actual-runner promise, not every Windows/macOS version or architecture:
Windows needs the host MSVC toolset and Windows SDK; macOS needs Apple developer
headers/CLT and any remaining dependencies recorded in the package. Toolchain
setup may download the explicit LLVM 20 packages (Windows cache miss or Homebrew
on macOS). The helper makes no downloads. Its **artifact first-scan mode** does
not run a compiler; its separate **build-stage `--ctest-accounting` mode** invokes
the unchanged registered Python tests and may run their corpus compiler. The
latter retains the full original CTest log plus a named compilation-input repeat
using the registered interpreter, binary, working directory and compiler, and
the same build-step temporary environment. `CAPTURED` is not an independent
test/skip verdict. This is a controlled trusted-build test, not an OS sandbox
or a signing service.
There is no publisher signature, notarization, Gatekeeper download-install test,
or macOS/Windows SBOM claim. Native Windows is not interchangeable with the
Linux preprocessor view in WSL2/Docker; those Windows-host routes are not measured
by this new native profile.

Qualification archives use
`native-<target>-<full-source-sha>-<run-id>-<attempt>` with 14-day retention.
The uploaded helper `result.json` is not by itself independent or final hosted
evidence: reconcile it with the exact run, completed jobs/steps, artifact catalog
and downloaded archive digest. A missing runner, artifact, signer or authority
stays an explicit limitation/blocker; do not infer release or main-integration
permission from feature-branch synchronization.

### Actual tests and unexecuted platform coverage

The source above was measured on Windows Server 2025 `10.0.26100`, AMD64, runner
image `20260824.214.3`, and Darwin `23.6.0`, arm64, image `20260831.0302.1`.
The Windows artifact helper used Python 3.12.10; the registered CTest Python
was 3.14.7. macOS used Python 3.14.7. These are observed runners, not immutable
image pins or an all-version support promise. macOS still needs Apple CLT and
the host Homebrew zstd dependency listed in `DEPENDENCIES.txt`; Windows needs
host MSVC/Windows SDK discovery. The build LLVM installation was hidden during
the six packaged scans and restored before final successful job completion.

| Actual evidence | Windows native and ordinary, independently counted | macOS native |
|---|---|---|
| CTest processes | 1,525 passed + 1 skipped / 1,526 | 1,540 passed / 1,540 |
| Separate single-process C++ | 1,519 passed + 1 skipped / 1,520 | 1,525 passed / 1,525 |
| Python unittest inside CTest | 105 passed + 16 skipped / 121 | 203 passed + 4 skipped / 207 |
| Separate named compilation-input repeat | 48 passed + 6 skipped / 54 (native only) | 50 passed + 4 skipped / 54 |
| StressMatrixCorpus | 7 expected outcomes | 7 expected outcomes |

Do not add the repeated 54 tests to the original Python total, or count a CTest
wrapper as all of its inner assertions passing. The ordinary diagnostic
`LastTest.log` is truncated to 64 KiB, but its tail actually contains all six
Python helper blocks; those results were independently counted, not inferred
from the native run. The native jobs retain the complete original CTest log.
Stress depth-limit evidence remains exit 2/incomplete, not a clean result.

All skips below are **unexecuted assertions**, never PASS:

- Windows C++: `SourceManagerTargetTest.FailedDirectoryScanNeverPublishesTraversedPrefix`;
  the runner cannot enforce its unreadable-directory fixture.
- Both platforms' four compilation-input filesystem cases:
  `test_mixed_source_encodings_preserve_every_requested_identity`,
  `test_non_utf8_canonical_symlink_target_is_reported_and_mcp_recovers`,
  `test_non_utf8_source_identity_cannot_corrupt_coverage_json`, and
  `test_unrequested_database_symlink_with_non_utf8_target_fails_without_crash`.
  Windows lacks the POSIX byte-path prerequisite; macOS actually returned
  `EILSEQ` when creating the owned non-UTF8 fixture. The macOS no-file raw-byte
  rejection and valid-UTF8 missing-path controls did execute successfully.
- Windows compilation-input extras:
  `test_corpus_rejects_non_utf8_response_values_without_output` and
  `test_non_utf8_requested_paths_are_rejected_without_creating_files`, which
  require raw POSIX byte paths/arguments.
- Windows stress harness: `test_real_matrix_timeout_is_incomplete_and_next_case_runs`
  and `test_real_signal_and_timeout_child_group_cleanup`, requiring a POSIX
  executable shebang or owned process-group/signal behavior.
- Windows review-input helpers: `test_quoted_command_rename_preserves_literal_macro_value`
  and `test_real_alias_remaps_to_base_without_repairing_wrong_input`, requiring
  POSIX shell quoting or a real POSIX directory alias.
- Windows `ReviewFlowInputTest` class, all six POSIX-flow cases:
  `test_generated_headers_and_multiple_variants_work_on_both_sides`,
  `test_rename_preserves_build_cwd_and_generated_headers`,
  `test_missing_generated_header_is_not_clean_even_with_warn_gate`,
  `test_missing_database_is_not_clean_even_with_warn_gate`,
  `test_malformed_and_wrong_input_commands_are_not_repaired`, and
  `test_added_source_has_a_real_head_command_and_no_base_counterpart`.

Windows' original 128 MiB touched-allocation regression passed. macOS also passed
that unchanged regression and all three new kernel-enforcement scenarios:
the same 192 MiB mapping succeeds before lowering the limit, then is refused
with `ENOMEM` while a touched 8 MiB positive mapping remains live. Finite exact
readback, tighter inherited limits and unchanged parent limits are asserted.
This qualifies the [snapshot-based Darwin contract](usage.md), not RSS, heap,
committed memory, cumulative allocations or preexisting mappings.

### Measured failures and the bounded SDK comparison

The first candidate run `34217016638` at
`b459d99feddd8e94a4252312ca03dc247500bbf9` failed on both native platforms.
Windows passed build/full tests/package and the C intrinsic-header clean scan,
but its C finding scan could not find `stdio.h` in the isolated child environment
(exit 2, no analyzed translation unit). macOS failed to compile the file-clock
timestamp conversion. Later source fixes and fresh successful native executions
do not change either old failure into a qualified result.

A temporary Windows pre-build comparison reuses only that exact retained package
(artifact `10052976442`, full outer and nested SHA-256 pinned in the helper).
It preserves the archived C finding source and command semantics, recording the
original and rebased database digests. With build LLVM hidden, both arms use the
same binary, inputs, working directory, fresh HOME/TMP and system-only PATH.
Arm B adds only `ProgramFiles`, `ProgramFiles(x86)`, `ProgramW6432`, `SystemDrive`;
developer variables, SDK overrides and credentials remain excluded. Arm A must
reproduce the missing-stdio failure, and B must yield complete supported findings.
Otherwise the experiment fails explicitly before the expensive Windows rebuild.
This tests the sufficiency of the locator set on that runner, not which member
is necessary, nor every machine's SDK discovery.

The comparison has a separate `codeskeptic-windows-sdk-diagnostic/v1` record,
distinguishing current helper source from the historical executable source.
It never emits a platform qualification PASS. Only after that observation may
the fresh candidate use the explicit OS-locator profile, still requiring all six
unchanged C/C++ scans and full tests. The frozen no-developer-prompt Windows guard
remains separate and unchanged. Missing/expired historical input is an explicit
diagnostic failure; this temporary wiring must not become a permanent release
dependency.

That temporary experiment subsequently ran and was independently checked in
job `102065286527`, run `34227551813`, at source
`bdba538d9517665470badfe1b9e3cd6ac5291921`. The pinned historical A/B reproduced
exit 2 without the four OS locators and complete findings/exit 1 with them.
The fresh Windows package separately passed all six scans and full tests;
outer artifact `10057354923` has SHA-256
`c11a3efb3140aac9904210dd44db29b5f447f781c207b51589cd51010dc689d5`.
The ordinary frozen Windows lane `34227551814` also succeeded. The overall
native run still failed because macOS could not install its former absolute
MiB address-space cap; no all-platform completion is claimed.

With the diagnostic evidence retained, the candidate workflow no longer repeats
that historical download/A/B or requests its Actions-read permission. The
diagnostic helper and old failures remain available in history; current SDK
discovery, six scan fixtures and full qualification gates are unchanged.
The owner subsequently approved the macOS-only snapshot-based memory contract
in [usage.md](usage.md). Its actual enforcement passed in the new measured
profile above; the earlier absolute-cap failure remains failed. The intermediate
`c4fd06b` native run passed its jobs but lacked complete inner-Python accounting;
that evidence gap was closed only by the retained full/named `e83b641` outputs,
not by assuming zero skips or reclassifying the older campaign.

## Historical support foundation

The following landed/working statements describe earlier editions and their
historical CI. They are preserved as context, not as current artifact receipts.

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

## Earlier restart checkpoint and Unicode paths

The dated landed results below describe historical revisions, not automatic
qualification of the current restart. At `d98354a`, the native MSVC build passed
after the source-specific conforming-preprocessor fix, but CTest failed and
the later smoke, SDK and relocation gates were skipped. A later candidate must
pass those actual gates before this restart is qualified.

The native CLI and development corpus helper embed `src/windows_utf8.manifest`, requesting a UTF-8
process code page before the CRT constructs `argv`. This is intended to preserve Unicode
filenames across argument, narrow filesystem and report-output boundaries;
calling `setlocale` inside `main` cannot recover characters already replaced
at startup. No elevated execution level or machine-wide locale change is
requested. Tests decode the CLI's UTF-8 output explicitly rather than using
the test runner's locale.

Microsoft supports this process setting from **Windows 10 version 1903 onward**.
The qualification host is Windows Server 2025. The manifest does not establish
Unicode correctness on older Windows versions, which would require explicit
encoding conversions and their own evidence. Native Unicode input/directory/
output round trips and package relocation remain required candidate evidence;
adding the manifest alone is not a successful runtime qualification.
See [Microsoft's process-code-page documentation](https://learn.microsoft.com/en-us/windows/apps/design/globalizing/use-utf8-code-page).

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
The original plan assumed a Windows branch in `SourceManager.cpp` (mirroring the
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
Prompt"). The CH02 strict-input restart now gives that directory probe an
explicit minimal `compile_commands.json`: the same C source, `gnu11`, and
no SDK/include-path flags. It still strips the same environment, requires the
same null-dereference finding and exit 1, and executes no compiler. This changes
the old database-free directory interface, not the SDK-discovery quality floor.
If a future LLVM upgrade regresses header discovery, the lane goes red and
the vswhere-style fallback becomes real work again.

Inherent requirement (not a gap): an MSVC toolset + Windows SDK must be
installed on the machine — there is nothing to discover otherwise. A
user-supplied `compile_commands.json` establishes source commands; SDK discovery
can still be needed when those commands do not provide system-header paths.
Directory scans require that database; only a direct isolated source file with
no discovered database has explicitly announced synthetic single-file mode.
Windows smoke and relocated-package checks therefore use isolated source copies
outside the repository's unrelated build database, preserving their original
source bytes, findings, exit checks and hidden-LLVM/plain-terminal conditions.
These CH02 fixture changes still require a fresh native hosted run; prior
Windows results certify the prior candidate, not the new implementation.

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
- **Tier 2 — SDK discovery without a Developer Prompt:** item 3 was closed by
  measurement (phase8-windows-sdk), using the clang driver's VS/SDK discovery.
  The current directory interface requires an explicit compilation database;
  the no-dev-prompt gate keeps the same SDK and finding conditions without
  returning to silently inferred directory commands.
- **Packaging — DONE** (v0.4.5, phase9-windows-package):
  `package_release.sh` runs under Git Bash on the runner with a small
  Windows branch (zip via 7z, falling back to PowerShell
  `Compress-Archive` on machines without 7-Zip — flagged by the first
  external Windows evaluation and CI-proven by a 7-Zip-masked
  rehearsal; `codeskeptic.exe`, `cygpath` for the resource dir, no lib
  bundling — the static-CRT build links only Windows system DLLs). Release lane: build → 682 tests → version/tag
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
