# ZeroDefect

[![CI](https://github.com/tanzercakir-commits/ZeroDefect/actions/workflows/ci.yml/badge.svg)](https://github.com/tanzercakir-commits/ZeroDefect/actions/workflows/ci.yml)

A C/C++ static analyzer built on Clang LibTooling, with a reusable
dataflow-analysis engine at its core. ZeroDefect performs CFG-based
forward dataflow analysis — not just AST pattern matching — so it can
reason about *paths*: what a pointer's state is at a dereference, whether
an allocation is freed on every path, whether a divisor can be zero on
the path that reaches a division.

The long-term goal is a fast, embeddable **semantic verification layer for
AI-assisted development**: an analyzer designed to sit inside the
code-generation loop, re-checking each edit in milliseconds and returning
machine-readable findings with dataflow traces.

## Rules

| Rule | ID | Detects |
|------|----|---------|
| Uninitialized pointer | `uninit-ptr` | Dereference of a pointer that may be unassigned on some path (CFG dataflow) |
| Memory leak / double free | `memory-leak` | Leaks at function exit, reassignment leaks, double free, `malloc`/`calloc`/`strdup`/`free` and `new`/`delete` (CFG dataflow with escape analysis) |
| Division by zero | `div-by-zero` | Definite and possible integer division/modulo by zero, with **branch-condition refinement** — `if (z != 0)` guards are understood, so guarded divisions don't produce false positives |

Example:

```
$ zerodefect demo.cpp
ZeroDefect: 4 finding(s)
----------------------------------------
demo.cpp:14:5 [error] memory-leak: Double free: 'q' has already been freed
demo.cpp:18:12 [error] uninit-ptr: Use of uninitialized pointer: 'r' may not be assigned at this dereference
demo.cpp:9:5 [warning] memory-leak: Memory leak: 'p' is reassigned without freeing the previous allocation
demo.cpp:10:1 [warning] memory-leak: Memory leak: allocation stored in 'p' may not be freed
----------------------------------------
```

## Architecture

```
StaticAnalyzer (facade)
 ├─ SourceManager   — LibTooling wrapper: compile_commands.json, AST production
 ├─ RuleEngine      — rule registry, enable/disable, runAll
 │   └─ Rule (abstract) → UninitPointerRule_Ex, MemoryLeakRule_Ex, DivByZeroRule
 │        └─ DataflowEngine — generic worklist solver over the Clang CFG:
 │             Analysis = { State, initialState, merge, transfer,
 │                          onStatement?, refineOnEdge? (assume edges) }
 ├─ Reporter        — ConsoleReporter, JsonReporter
 └─ Config          — CLI args + .zerodefect.conf
```

Writing a new flow-sensitive rule means defining a lattice (`State`), a
`transfer` function, and optionally `refineOnEdge` to sharpen state along
branch edges. The engine handles CFG construction, the worklist, and
predecessor merges.

## Building

Requires CMake ≥ 3.20, a C++17 compiler, and LLVM/Clang development
libraries (tested with LLVM 18).

### Linux (Ubuntu 24.04)

```bash
sudo apt-get install -y llvm-18-dev libclang-18-dev libzstd-dev zlib1g-dev ninja-build
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/usr/lib/llvm-18
cmake --build build
ctest --test-dir build        # 52 tests
```

### macOS (Homebrew)

```bash
brew install llvm cmake ninja
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

## Usage

```bash
zerodefect <source_path> [options]

  --source <path>        Directory/file to analyze
  --build-path <path>    compile_commands.json directory
  --json <file>          JSON output file
  --sarif <file>         SARIF 2.1.0 output file (GitHub code scanning)
  --severity <level>     Minimum severity (info/warning/error)
  --disable-rule <id>    Disable a rule
  --lang <en|tr>         Diagnostic message language (default: en)
```

Options can also be set in a `.zerodefect.conf` file (`key=value` lines:
`source_path`, `build_path`, `output_format`, `json_output`,
`sarif_output`, `min_severity`, `enable_rule`, `disable_rule`, `lang`).

### Suppressing findings

Individual findings can be suppressed with source comments:

```cpp
int x = 1 / z;  // zerodefect-disable-line
int y = 1 / w;  // zerodefect-disable-line div-by-zero

// zerodefect-disable-next-line memory-leak
p = new int(7);
```

A bare marker suppresses every rule on that line; a comma- or
space-separated rule list limits it to those rules. The count of
suppressed findings is reported on stderr.

Exit code is `1` when findings are reported, `0` when clean — suitable
for CI gates.

## Roadmap

See [`analiz-2026-07.md`](analiz-2026-07.md) (Turkish) for the full
assessment and phased roadmap: SARIF output, suppression/baseline
support, benchmark-driven precision measurement, incremental analysis,
and MCP-server mode for agent integration.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
