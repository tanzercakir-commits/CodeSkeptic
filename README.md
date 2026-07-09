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
| Use after free | `use-after-free` | Dereference (`*p`, `p->`, `p[i]`) of a pointer in freed state (shares the memory-leak dataflow) |
| Division by zero | `div-by-zero` | Definite and possible integer division/modulo by zero, with **branch-condition refinement** — `if (z != 0)` guards are understood, so guarded divisions don't produce false positives |
| Null dereference | `null-deref` | Definite and possible dereference of null pointers; tracks `nullptr`/`NULL`/`0` flow with branch-condition refinement (`if (p)`, `if (!p) return`, `p != nullptr`, short-circuit `&&`/`\|\|`); unknown values stay silent, so unguarded parameters don't spam warnings |

**Interprocedural (v1):** functions with visible bodies are summarized
before rules run — return nullness (a `find()`-style function that can
return null makes unguarded dereferences of its result a warning, with
a trace note) and parameter effects (free-wrappers count as frees, so
double-free/use-after-free through wrappers is caught; read-only
helpers no longer hide leaks behind them). Recursion-safe fixpoint;
external and aliasing callees stay conservative. |

Example:

```
$ zerodefect demo.cpp
ZeroDefect: 2 finding(s)
----------------------------------------
demo.cpp:4:13 [error] use-after-free: Use after free: 'p' is dereferenced after being freed
    -> demo.cpp:2:5 'p' allocated here
    -> demo.cpp:3:5 'p' freed here
demo.cpp:9:12 [warning] div-by-zero: Possible division by zero: 'z' may be zero on some paths
    -> demo.cpp:7:5 'z' assigned zero here
----------------------------------------
```

Findings carry **dataflow traces** — the chain of events that leads to
the bug. Traces appear indented on the console, as a `notes` array in
JSON output, and as `relatedLocations` in SARIF (rendered by GitHub
code scanning).

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
  --baseline <file>      Suppress findings recorded in the baseline
  --write-baseline <file> Record current findings as the baseline
  --function <names>     Analyze only these functions (comma list,
                         plain or qualified names; repeatable)
  --lines <N-M,K>        Analyze only functions overlapping these line
                         ranges of the analyzed file
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

### Baseline workflow

Adopting the analyzer on an existing codebase without fixing every
legacy finding first:

```bash
zerodefect src/ --write-baseline .zerodefect-baseline   # record & exit clean
zerodefect src/ --baseline .zerodefect-baseline         # only NEW findings fail
```

Baseline keys include the line number, so refresh the baseline after
large refactors (known v1 limitation).

### Incremental analysis

For edit-check loops (agents, IDEs, pre-commit hooks) analyze only what
changed:

```bash
# re-check just the function you edited (milliseconds)
zerodefect src/parser.cpp --function Parser::parse

# analyze only the functions actually touched since a git ref:
# the script extracts changed line ranges from diff hunks and passes
# --lines per file, so untouched functions are skipped entirely
scripts/analyze_diff.sh build/src/zerodefect origin/main --severity error
```

### MCP server (agent integration)

`zerodefect --serve` runs an MCP (Model Context Protocol) server over
stdio, exposing an `analyze` tool that returns findings — with dataflow
traces — as structured JSON. Agents like Claude Code can call it after
every edit. Register it in `.mcp.json`:

```json
{
  "mcpServers": {
    "zerodefect": {
      "command": "/path/to/zerodefect",
      "args": ["--serve"]
    }
  }
}
```

The `analyze` tool accepts `path` plus optional `build_path`,
`functions` and `lines` — so an agent can scope the re-check to exactly
the functions it just edited.

Exit code is `1` when findings are reported, `0` when clean — suitable
for CI gates.

## Roadmap

See [`analiz-2026-07.md`](analiz-2026-07.md) (Turkish) for the full
assessment and phased roadmap: SARIF output, suppression/baseline
support, benchmark-driven precision measurement, incremental analysis,
and MCP-server mode for agent integration.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
