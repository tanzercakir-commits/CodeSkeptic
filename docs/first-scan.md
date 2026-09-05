# Your first scan on a real codebase

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
lever. **Every lever below is precision — a fact you hand the analyzer,
not a mute button.** You are refining the proof, never hiding output;
that is why the findings that remain stay trustworthy.

## Start here: baseline

Adopting CodeSkeptic on an existing project? Snapshot today's findings
and gate only what's NEW, so you get PR-gating without triaging history
up front:

```
codeskeptic src/ --build-path build --baseline .codeskeptic-baseline.json
```

This is the single most important first move. Tune the families below
second — with a baseline in place, none of them block you meanwhile.
(Details: docs/usage.md#baseline-workflow.)

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

Baseline first, tune second. Each lever states a fact the compiler
already relies on — that a handler aborts, that a pointer is non-null,
that a wrapper allocates. You are not silencing the analyzer; you are
finishing the proof it started.
