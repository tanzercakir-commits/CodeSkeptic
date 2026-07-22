# CodeSkeptic

[![CI](https://github.com/tanzercakir-commits/CodeSkeptic/actions/workflows/ci.yml/badge.svg)](https://github.com/tanzercakir-commits/CodeSkeptic/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/tanzercakir-commits/CodeSkeptic?color=blue)](https://github.com/tanzercakir-commits/CodeSkeptic/releases)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg?logo=cplusplus)](https://en.cppreference.com/w/cpp/17)
![Built on Clang LibTooling](https://img.shields.io/badge/Clang-LibTooling-262D3A.svg?logo=llvm)
[![Platform: Linux | macOS](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](docs/windows-support.md)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/tanzercakir-commits/CodeSkeptic/pulls)

> **Everyone generates. CodeSkeptic verifies.**

Real C/C++ bugs, deterministic dataflow traces, low-noise PR gating.

CodeSkeptic is a precision-first static analyzer built on Clang
LibTooling. It performs CFG-based forward dataflow analysis — not just
AST pattern matching — so it can reason about *paths*: what a pointer's
state is at a dereference, whether an allocation is freed on every
path, whether a divisor can be zero on the path that reaches a
division. It only speaks when the dataflow proves something, and every
finding carries the trace that proves it.

The long-term goal is a fast, embeddable **semantic verification layer
for AI-assisted development**: an analyzer that sits inside the
code-generation loop, re-checking each edit in milliseconds and
returning machine-readable findings with dataflow traces.

## Quickstart

Linux (Ubuntu 24.04) — four commands from clone to first report:

```bash
sudo apt-get update && sudo apt-get install -y llvm-20-dev libclang-20-dev libzstd-dev zlib1g-dev ninja-build
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/usr/lib/llvm-20
cmake --build build
./build/src/codeskeptic docs/demo.c
```

That last command flags what the compiler waves through on
[`docs/demo.c`](docs/demo.c) — an unchecked `getenv`, an `atoi` result
multiplied past `int`, a work buffer leaked on an error path — none of
it caught by `gcc -O2 -Wall -Wextra -Woverflow`. Findings look like:

```
demo.cpp:4:13 [error] use-after-free: Use after free: 'p' is dereferenced after being freed
    -> demo.cpp:2:5 'p' allocated here
    -> demo.cpp:3:5 'p' freed here
demo.cpp:9:12 [warning] div-by-zero: Possible division by zero: 'z' may be zero on some paths
    -> demo.cpp:7:5 'z' assigned zero here
```

macOS (Homebrew): `brew install llvm cmake ninja`, then the same
`cmake` + build steps (LLVM is found automatically). Requires CMake ≥
3.20, a C++17 compiler, LLVM/Clang dev libraries (tested with LLVM 18
and 20). Windows is [planned, not yet implemented](docs/windows-support.md).

On a real project, point it at your compilation database and get an
offline HTML report with clickable dataflow traces:

```bash
codeskeptic src/ --build-path build --report-paths $PWD/src --html report.html
```

![CodeSkeptic's HTML report on a first-draft file](docs/img/report.png)

![A finding's dataflow trace](docs/img/trace.png)

Next steps: the full [usage reference](docs/usage.md) ·
[evaluate it on *your* code in about an hour](docs/evaluate.md) ·
[CI, editor & agent integrations](docs/integrations.md).

## Proven on real code

Synthetic benchmarks reward pattern coverage; real codebases punish
every false positive. Each project below was built with its own build
system, analyzed from its compilation database, and every surviving
finding was triaged by hand. All numbers are from one analyzer build
(2026-07-12); the "initial" column is what the same scan reported when
the project was first tried, before the false-positive families it
exposed were fixed.

| Project | Scope | Initial → now | Hand-verified real bugs |
|---------|-------|--------------:|------------------------|
| [systemd](https://github.com/systemd/systemd) | 494 files (basic/core/shared) | 414 → **53** | 3 deliberate leak-shaped idioms, documented |
| [shadPS4](https://github.com/shadps4-emu/shadPS4) | 377 files | 209 → **22** | **3 reported upstream — 2 merged ([#4702](https://github.com/shadps4-emu/shadPS4/pull/4702), [#4703](https://github.com/shadps4-emu/shadPS4/pull/4703))** |
| [libgit2](https://github.com/libgit2/libgit2) | 168 files | 149 → **44** | **11 confirmed OOM-path leaks** (one issue class, report drafted) |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) | full build | 511 → **25** | triage in progress |
| [rtp2httpd](https://github.com/stackia/rtp2httpd) | 27k lines | 4 → **3** | **1 confirmed NULL-contract bug**, report drafted |
| [NASA fprime](https://github.com/nasa/fprime) | 216 files | 10 → **0** | clean (with `--fatal-asserts SwAssert` declaring F´'s assert handler) |
| [abseil-cpp](https://github.com/abseil/abseil-cpp) | LTS tag | 12 → **4** | — |
| [Catch2](https://github.com/catchorg/Catch2) | full build | **0** | clean |

The two merged shadPS4 fixes are the canonical
looks-right-reads-wrong bugs this project exists to catch: a null
check with `&&` where it needed `||`, so the guard fell through and
dereferenced the very pointer it had just checked
([#4703](https://github.com/shadps4-emu/shadPS4/pull/4703)), and an
`ENOMEM` path that fell through without a `return`, dereferencing the
null `FILE*` on the next line
([#4702](https://github.com/shadps4-emu/shadPS4/pull/4702)). Real
bugs, found from a compilation database, accepted by the people who
own the code. How these numbers are kept honest — idiom configuration
and the FP-family process — is in
[docs/benchmarks.md](docs/benchmarks.md#reading-the-real-world-scan-numbers).

## What it won't catch

CodeSkeptic is precision-first, and the price of precision is recall.
Read its silence accordingly:

- **A clean run is not a safety proof.** Unknown values stay silent by
  design; bugs that need reasoning the engine doesn't have (deep
  aliasing, concurrency, arbitrary arithmetic) are not reported.
- **Recall is bounded and measured.** On Juliet, recall ranges from
  0.501 (use-after-free) down to 0.010 (integer overflow, a documented
  known false negative family) — the numbers, and why, are in
  [docs/benchmarks.md](docs/benchmarks.md).
- **`memory-leak` is the one noisy rule** (Juliet precision 0.716 vs
  1.000 for the others) and the current improvement target. Evaluate
  it separately ([how](docs/evaluate.md)).
- Checked bug classes only: the [rules below](#rules) — not style, not
  concurrency, not undefined behavior at large.

## Use it alongside, not instead

Keep your existing net. CodeSkeptic replaces none of it — it adds a
low-noise, trace-backed layer that is strongest exactly where the
others are weakest: gating *new* changes (human or AI-generated).

| Keep using | It gives you | CodeSkeptic adds |
|------------|--------------|------------------|
| Compiler warnings (`-Wall -Wextra`) | Cheap, universal checks | Path-sensitive bugs warnings can't see |
| Sanitizers (ASan/UBSan/TSan) | Runtime proof on executed paths | Static coverage of paths tests never run |
| clang analyzer / gcc `-fanalyzer` | Broad heuristic coverage | Deterministic traces, low-noise PR delta gating ([coverage differs both ways](docs/comparison.md)) |
| CodeQL & co. | Query breadth, security taxonomies | Millisecond re-checks inside an edit loop |
| Fuzzing & tests | Ground truth on real executions | A verdict *before* the code runs |

## Rules

| Rule | ID | Detects |
|------|----|---------|
| Uninitialized pointer | `uninit-ptr` | Dereference of a pointer that may be unassigned on some path (CFG dataflow) |
| Memory leak | `memory-leak` | Leaks at function exit and reassignment leaks, `malloc`/`calloc`/`strdup`/`free` and `new`/`delete` (CFG dataflow with escape analysis) |
| Double free | `double-free` | Freeing a pointer already in freed state (shares the memory-leak dataflow) |
| Use after free | `use-after-free` | Dereference (`*p`, `p->`, `p[i]`) of a pointer in freed state (shares the memory-leak dataflow) |
| Division by zero | `div-by-zero` | Definite and possible integer division/modulo by zero, with **branch-condition refinement** — `if (z != 0)` guards are understood, so guarded divisions don't produce false positives |
| Null dereference | `null-deref` | Definite and possible dereference of null pointers; tracks `nullptr`/`NULL`/`0` flow with branch-condition refinement (`if (p)`, `if (!p) return`, `p != nullptr`, short-circuit `&&`/`\|\|`); unknown values stay silent, so unguarded parameters don't spam warnings |
| Array/heap bounds | `bounds` | Out-of-bounds access proven whole-range, and copies (`memcpy`/`memmove`/`memset`, `strcpy`/`strcat`/`gets`) past a fixed-size destination (CWE-125/787/120), on an interval + extent lattice |
| Integer overflow | `int-overflow` | Signed multiplication whose proven operand ranges escape the type (CWE-190), including an untrusted source (`int n = atoi(s); n * k`) |
| Contract verification | `contract` | Violations of declared `// cs:` contracts (preconditions, postconditions, ownership effects) — checked by the same dataflow that infers summaries |
| Policy enforcement | `policy` | `cs:policy` pattern prohibitions; v1 ships `no-absolute-paths` (hard-coded absolute path literals) |

The machinery behind the table — intrinsic-source recall, targeted
path-sensitivity, interprocedural function summaries — is described in
[docs/engine.md](docs/engine.md).

## The numbers

Two axes, tracked separately ([full methodology](docs/benchmarks.md)):

- **Mature code (NIST Juliet 1.3):** rule precision **1.000** on five
  of six rules (memory-leak 0.716); recall 0.501 / 0.352 / 0.241 /
  0.195 / 0.095 / 0.010 by CWE — lower bounds, with the honest
  reasons (floating-point variants, opaque sources, one known macro
  family) documented.
- **First-draft code (blind 24-program AI corpus — the mission axis):**
  combined recall **0.625 at precision 1.000**, zero false positives
  including on 9 deliberately-clean programs.

Every number is reproducible with one script, and CI enforces pinned
per-CWE floors, pinned real-world finding counts, and a self-scan
dogfood gate on every PR — the floors only move together with a
deliberate, explained rule change.

**Cheaper AI review, measured:** if you already loop an LLM over your
diffs, CodeSkeptic's findings-instead-of-raw-code input is **O(bugs),
not O(lines)** — 6–59× fewer tokens on real-sized files (no saving
below ~50 lines; measurement, method and limits in
[docs/token-ablation.md](docs/token-ablation.md)).

## In your loop

- **CI gate / PR review:** `scripts/review_diff.sh` analyzes base and
  head, reports the **delta** with traces, and exits on the evidence
  ladder (new definite findings gate; `--gate warn` for report-only
  adoption — recommended for week one). SARIF uploads to GitHub code
  scanning; VS Code renders traces via the SARIF Viewer.
  [docs/integrations.md](docs/integrations.md)
- **Agents (MCP):** `codeskeptic --serve` exposes an `analyze` tool
  over stdio — findings with traces as structured JSON, scoped to the
  functions just edited. [docs/integrations.md](docs/integrations.md#mcp-server-agent-integration)
- **Incremental:** `--function`/`--lines` re-check one function in
  milliseconds; `--summary-in` keeps whole-project knowledge in
  single-file runs. [docs/usage.md](docs/usage.md#incremental-analysis)
- **Semantic regression gate:** deterministic function summaries diff
  as *contracts* — `NeverNull → MaybeNull` is a `WEAKENED` verdict
  that fails CI before callers break.
  [docs/integrations.md](docs/integrations.md#semantic-regression-gate-summary-diff)
- **Baselines & suppression:** adopt on a legacy codebase without
  fixing history first. [docs/usage.md](docs/usage.md#baseline-workflow)

## Contracts (`cs:`)

Rules infer what a function does; contracts pin what it is *supposed*
to do — declared as structured comments, checked by the same dataflow:

```c
// cs: requires p != null
// cs: ensures return != null if n != 0
// cs: owns(cfg)
char *find_config(struct Cfg *cfg, const char *p, int n);
```

When AI-generated (or human) code later breaks the promise, the diff
between declared and actual behavior is a finding at the exact line
that broke it. Violated contracts are errors (that friction is the
point); `cs:ai` marks machine-proposed contracts that warn instead;
sidecar files cover third-party code you can't annotate. Full grammar,
checkable subset and failure semantics: [CONTRACTS.md](CONTRACTS.md).

## Documentation map

- [docs/usage.md](docs/usage.md) — CLI reference, config, suppression, baselines, incremental
- [docs/evaluate.md](docs/evaluate.md) — evaluate on your own code in ~1 hour
- [docs/integrations.md](docs/integrations.md) — CI gates, PR review, MCP, SARIF/VS Code
- [docs/benchmarks.md](docs/benchmarks.md) — Juliet + AI-corpus methodology, guards
- [docs/comparison.md](docs/comparison.md) — vs mainstream tools, honest positioning
- [docs/engine.md](docs/engine.md) — architecture and analysis machinery
- [docs/token-ablation.md](docs/token-ablation.md) — the 6–59× token measurement
- [CONTRACTS.md](CONTRACTS.md) — the `cs:` contract language
- [ROADMAP.md](ROADMAP.md) — current state and near-term plan ([full devlog](docs/devlog/))

## License

Apache License 2.0 — see [LICENSE](LICENSE).
