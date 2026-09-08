# Your first scan on a real codebase

## A small, reproducible C and C++ project

Start with an installed `codeskeptic` on `PATH`, Python 3, CMake, Ninja and
working C/C++ compilers. The marked recipes were qualified locally on Linux
with source `a23cf319264847c752a4fdc55ce2f3cadb196f78`, binary
`0.4.9-dev+ga23cf3192648`, SHA-256
`5272baff931cae3dbd21c51409dd129a607df983a69e851b3f6cf57e5e845677`.
The 12 passing FirstScan tests include real C/C++ workflows plus static/mock
negative controls; they are not 12 independent end-to-end scans. This proof
uses a byte-identical local installation, not archive extraction or a hosted
GitHub job. Separate package-isolation and native-platform evidence is in the
[candidate acceptance matrix](release-checklist.md#candidate-acceptance-matrix).

For an already-built development binary, an **unprivileged local installation**
can be made on the same machine. Set `CODESKEPTIC_BUILT_BINARY` to its absolute
path and `CODESKEPTIC_LOCAL_PREFIX` to a **new, empty prefix you own**. This copy
still needs the build environment's LLVM shared libraries and Clang resource
headers; it is not a replacement for the separate release-packaging checks.

<!-- first-scan:install -->
```bash
set -eu
test ! -e "$CODESKEPTIC_LOCAL_PREFIX"
install -d "$CODESKEPTIC_LOCAL_PREFIX/bin"
install -m 755 "$CODESKEPTIC_BUILT_BINARY" "$CODESKEPTIC_LOCAL_PREFIX/bin/codeskeptic"
export PATH="$CODESKEPTIC_LOCAL_PREFIX/bin:$PATH"
codeskeptic --version
```

Create a new project directory (including `src`, `include` and `ci`
subdirectories), and save these four files. No fixture executable needs to run.

`CMakeLists.txt`:

<!-- first-scan:cmake-file -->
```cmake
cmake_minimum_required(VERSION 3.20)
project(FirstScan LANGUAGES C CXX)
add_library(example OBJECT src/answer.c src/answer.cpp)
target_include_directories(example PRIVATE include)
target_compile_definitions(example PRIVATE FIRST_SCAN_VALUE=42)
set_target_properties(example PROPERTIES C_STANDARD 11 CXX_STANDARD 17)
```

`include/fixture.h`:

<!-- first-scan:header-file -->
```c
#ifndef FIRST_SCAN_VALUE
#error Configure this project to supply FIRST_SCAN_VALUE
#endif
```

`src/answer.c`:

<!-- first-scan:c-file -->
```c
#include "fixture.h"
#include <stddef.h>
int c_answer(void) { return FIRST_SCAN_VALUE + (int)sizeof(size_t); }
```

`src/answer.cpp`:

<!-- first-scan:cpp-file -->
```cpp
#include "fixture.h"
#include <stddef.h>
int cpp_answer() { return FIRST_SCAN_VALUE + static_cast<int>(sizeof(size_t)); }
```

From this project's root, generate the real include/define settings and scan:

<!-- first-scan:configure -->
```bash
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

If compiler discovery fails, select installed compilers with `CC` and `CXX`
before configuring a fresh build directory. Install missing dependencies through
your normal environment setup; the analyzer does not download them.

<!-- first-scan:doctor -->
```bash
codeskeptic --doctor --source src --build-path build
```

<!-- first-scan:scan -->
```bash
codeskeptic --source src --build-path build --json findings.json
```

These safe fixtures should return `0`: doctor says `status: ready`, and the
JSON report says `schema: codeskeptic-report/v1`, `complete: true`, with both
source files analyzed and `coverage.complete: true`. Check those fields, not
just an empty findings list. A supported finding returns `1`; invalid input,
incomplete analysis or an output failure returns `2` and must not be accepted.
These tiny examples prove the commands work, not coverage of every CWE.

**Missing compilation inputs:** before configuration, the doctor command above
returns `2`, `status: unavailable`, and `reason` / `next` guidance. Run the
configure command, then rerun the same doctor and scan commands. If a source
has no command, add it to your CMake target and regenerate the database. If
headers/defines are missing, fix the target's include paths/definitions and
regenerate; `status: ready` alone does not prove a source can be parsed.
Do not use partial-coverage/recovery options to make this walkthrough pass.

For adoption CI, save and run the [checked report-only recipe](integrations.md#local-report-only-ci).
It accepts complete finding reports without disguising them as clean, and
rejects missing inputs, stale output directories and incomplete evidence.

The repository's direct T1 check, `bash scripts/test_first_scan.sh <binary>`,
installs a temporary local copy and executes the marked recipes above and
below on both languages, with negative controls. It performs no download,
GitHub write or release commissioning.

## First establish the compilation inputs

Run the input doctor before interpreting findings:

```sh
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
codeskeptic --doctor --source src --build-path build
codeskeptic --source src --build-path build --json findings.json
```

The first command is an example **you** run to configure your project; the
doctor never runs CMake, a compiler, commands from the database, or analysis.
`status: ready` means the requested files have usable compilation-command
entries, not that those files compile or are free of defects. Actual analysis
still checks parse/analysis coverage and can return exit 2.

Doctor output lists the selected database, explicit/automatic selection,
entry counts and requested source count. Normal analysis reports the same
selection on stderr and consumes the already-loaded database from the same
resolver. `--doctor` uses text output, not `--json`, `--sarif` or `--html`.
Without a source or file-list argument it examines the current directory.

Without `--build-path`, discovery searches the requested source's directory
and bounded project ancestry, not an unrelated working directory. It checks
`compile_commands.json` and the conventional `build`, `Build`, `build-debug`,
`build-release`, `cmake-build-debug`, `cmake-build-release`, and `out/build`
locations. A nested `.git` file/directory fences ancestry; without Git, the
nearest CMake/Meson/Makefile project marker does. Search is bounded to eight
ancestor levels and 128 distinct roots; unusual layouts need an explicit path.
Symlink aliases to the same database are deduplicated.

Two databases are an error, even if only one appears to cover the file. Select
one with `--build-path`; an explicit CLI or `build_path` configuration value is
authoritative, so an invalid explicit path never falls back to another database.
Missing, malformed, empty or non-covering databases return exit 2 with `reason`
and `next` guidance. `compile_flags.txt` cannot rescue malformed JSON. Relative
command directories are resolved relative to the database, not the process CWD.

Directory requests retain supported C/C++ source files in the requested tree.
Only `.git` metadata and the selected CMake build's generated `CMakeFiles`
internals are excluded from recursion; a database inside `src` cannot hide it.
An unmapped source is an error, not silently omitted or compiled with inferred
flags. Use `--source` for a narrower tree or `--files` for an explicit list.
Existing CWD-relative listed files take precedence; a missing relative entry may
be resolved against the selected build directory. Empty/missing lists cannot
turn into a broad scan.

The declared database `file` must match the command's actual input; unrelated
source substitution is rejected. Response files are expanded and the selected
commands frozen before analysis, without executing them. Warm-cache keys include
compile commands, so changing flags invalidates cached ASTs; multiple command
variants run uncached so no second configuration is lost.

A direct, existing single `.c`, `.cpp`, `.cc` or `.cxx` file can still be analyzed
without a database: both doctor and analysis explicitly announce
`mode: synthetic-single-file` (`gnu11` for C, `c++17` for C++). This convenience
does not reconstruct a project's defines, include paths or toolchain. It is
not available to rescue invalid or ambiguous discovered/explicit databases,
directory scans, or file-list requests.

## Then interpret findings

The first run on a mature C/C++ project surfaces a few well-known
families of findings. This is the map: recognise the family, apply the
lever. Verified allocator/assert contracts refine analysis assumptions;
baselines and suppression comments instead accept or hide selected findings.
Those are review decisions, not proof that the source is safe. Keep their
reason and audit evidence visible.

## Start here: baseline

Adopting CodeSkeptic on an existing project? Snapshot today's findings
and gate only what's NEW, so you get PR-gating without triaging history
up front:

<!-- first-scan:baseline -->
```bash
codeskeptic src/ --build-path build --write-baseline .codeskeptic-baseline
codeskeptic src/ --build-path build --baseline .codeskeptic-baseline
```

Review the initial findings before recording that acceptance. This is versioned
text, not JSON. Record mode returns `0` only with acceptable analysis evidence;
it writes the baseline, not an ordinary JSON/SARIF report. New, changed or
unbound findings can still block on the second command; input/evidence failures
remain `2`. See the [v3 identity and legacy limits](usage.md#baseline-workflow).

## The families and their levers

| You see a lot of… | It is this class | Do this |
|---|---|---|
| `null-deref` right after `assert(p)` | assert-family | Usually already silent — the engine recovers `assert` even when `NDEBUG` compiled it out. Custom spelling? `--assert-macros CHECK_PTR`. A macro that asserts a pointer IS null (`assert_null`)? `--negative-assert-macros`. |
| `null-deref` after a custom abort — `error()`, `panic()`, `Fatal()` | a fatal handler not marked `noreturn` | `--fatal-asserts error,panic` — tells the engine that path really does terminate. |
| `null-deref` on accessor results — `obj->get(id)->field` | accessor-nullability (the "assumption" class) | Honest **may** warnings: the accessor's summary says it can return null. Put a contract on it (`cs: ensures` — see CONTRACTS.md), or baseline. |
| `null-deref` after an unchecked `malloc`, used immediately | the embedded "alloc failure is fatal anyway" convention | A contract on your allocator (`cs: ensures` non-null), or baseline. |
| leak / double-free findings are **zero** on a wrapper-heavy codebase | the leak domain is blind to your wrappers | `--alloc-functions git__malloc,zmalloc --free-functions git__free` — turns the whole leak/UAF domain on. |
| a field-subject assert — `DEBUGASSERT(data->conn)` — doesn't silence its deref | a known v1 gap (member-subject recovery) | Baseline for now; the plain-variable and custom-abort cases above cover most of it. |

## Opt-in rules (silent unless you ask)

Some rules need you to declare your project's untrusted inputs — they
report nothing until you do:

```
# parsers: enables sign-conversion (CWE-195) + alloc-size-overflow
# (CWE-131) on lengths/counts read off the wire or a file
codeskeptic src/ --build-path build \
  --untrusted-int-sources read_u16,packet_len,tud_cdc_read
```

Provenance is never guessed — an ordinary length parameter stays silent;
only a value you declared untrusted, that can wrap or go negative into a
size, is reported.

## Reading a finding before deciding it's noise

- **Every finding carries a trace.** Follow it — allocated here, may be
  null here, dereferenced here — before calling it a false positive.
- **Severity tells you the claim.** `[error]` = definite on some path;
  `[warning]` = may. An honest "may" on an accessor is not the tool
  guessing — it is the tool declining to assume.
- **Want the shipped-build view instead?** `--no-assert-recovery`
  reports the code exactly as the `NDEBUG` build runs it, with no
  recovered assumptions at all.

## The short version

Establish full compilation coverage first, inspect findings, then introduce
reviewed contracts or recorded acceptance decisions. Report-only CI must keep
analysis failures red even when supported findings are temporarily non-blocking.
