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
| Memory leak | `memory-leak` | Leaks at function exit and reassignment leaks, `malloc`/`calloc`/`strdup`/`free` and `new`/`delete` (CFG dataflow with escape analysis) |
| Double free | `double-free` | Freeing a pointer already in freed state (shares the memory-leak dataflow) |
| Use after free | `use-after-free` | Dereference (`*p`, `p->`, `p[i]`) of a pointer in freed state (shares the memory-leak dataflow) |
| Division by zero | `div-by-zero` | Definite and possible integer division/modulo by zero, with **branch-condition refinement** — `if (z != 0)` guards are understood, so guarded divisions don't produce false positives |
| Null dereference | `null-deref` | Definite and possible dereference of null pointers; tracks `nullptr`/`NULL`/`0` flow with branch-condition refinement (`if (p)`, `if (!p) return`, `p != nullptr`, short-circuit `&&`/`\|\|`); unknown values stay silent, so unguarded parameters don't spam warnings |

**Targeted path-sensitivity:** the memory rules keep a small set of
guarded states instead of one merged state, keyed by conditions on
variables that provably don't change (`if (mode == 5) p = malloc(...);
… if (mode == 5) free(p);` is clean — the two guards are correlated,
so the "allocated but never freed" path is infeasible). Function-call
conditions are never keyed (two `check()` calls may differ), mutated
variables are never keyed, and the disjunct budget degrades gracefully
to the classic merged analysis.

**Interprocedural (v1):** functions with visible bodies are summarized
before rules run — return nullness (a `find()`-style function that can
return null makes unguarded dereferences of its result a warning, with
a trace note), return zeroness (a callee that can return zero makes an
unguarded division by the assigned result a warning — the classic
`data = badSource(); 100 / data` split across functions or files) and
parameter effects (free-wrappers count as frees, so double-free/
use-after-free through wrappers is caught; read-only helpers no longer
hide leaks behind them). Recursion-safe fixpoint; external and aliasing
callees stay conservative. |

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

## Benchmark (NIST Juliet C/C++ 1.3)

Weekly CI runs the analyzer against the [NIST Juliet test
suite](https://samate.nist.gov/SARD/test-suites/112): 400 files per
CWE, sampled evenly across all variant families. A finding in a
function whose name contains `bad` counts as a true positive; in a
`good` function, a false positive. **Rule-matched** columns count only
the rule that targets the CWE under test — that is the precision of
the rule itself. The **all-findings** column includes every rule's
output on the same files (cross-rule noise; tracked separately as
FP-hunting material).

| CWE | Target rule | Rule precision | Recall | Case F1 |
|-----|-------------|---------------:|-------:|--------:|
| CWE-416 Use After Free | `use-after-free` | **1.000** (174 TP / 0 FP) | 0.436 | **0.607** |
| CWE-476 NULL Pointer Dereference | `null-deref` | **1.000** (139 TP / 0 FP) | 0.347 | **0.516** |
| CWE-415 Double Free | `double-free` | **1.000** (88 TP / 0 FP) | 0.220 | 0.361 |
| CWE-401 Memory Leak | `memory-leak` | 0.653 (case-level) | 0.246 | 0.357 |
| CWE-369 Divide by Zero | `div-by-zero` | **1.000** (21 TP / 0 FP) | 0.053 | 0.100 |

The journey these numbers took (all on 2026-07-10): targeted
path-sensitivity cut false positives across rules (memory-leak
92 → 61, uninit-ptr 178 → 84, cross-file null-deref noise 241 → 129)
and *surfaced previously missed true positives* — correlated-guard
double frees and use-after-frees (+107 TP combined) were false
negatives under merged-path analysis. Cross-TU summaries
(`--whole-program`) then connected source/sink flows split across
files (double-free +9 TP, leak +5 TP, with variant-group sampling so
a/b file pairs stay together). Return-zeroness summaries lifted
divide-by-zero across function boundaries (18 → 21 TP at precision
1.000 in the PR sample; the `data = badSource(); 100 / data` pattern
dominates CWE-369 and its source is almost never in the same
function). A caveat on cross-rule findings: Juliet
`good` functions are only guaranteed free of the *tested* CWE — e.g. a
CWE-416 good function may genuinely leak, so a `memory-leak` finding
there is counted against us while possibly being correct. The
rule-matched columns are the sound metric.

Beyond precision/hit-rate, the harness reports **case-level F1** (each
file is a case: a matched finding in a `bad` function is a case-TP, in
a `good` function a case-FP, a silent bad file an FN) and a second
operating point restricted to `error`-severity findings. There is
deliberately **no ROC curve**: the analyzer is evidence-based and
binary, not probabilistic — with no sweepable threshold, an AUC from a
two-point "curve" would be misleading. A **score guard**
(`scripts/juliet_expected.txt`) pins per-CWE precision/hit-rate floors;
any code PR that drops below them fails CI.

Notes on reading these numbers honestly:

- **Zero false positives on four of five rules** reflects the design
  choice that unknown values stay silent — the analyzer only speaks
  when the dataflow proves something.
- **Hit rates are lower bounds.** Many Juliet defects flow through
  source/sink call chains and class variants; intraprocedural analysis
  plus v1 summaries catches the local and wrapper-based portion.
  CWE-369's low rate is by design: most Juliet variants there use
  floating-point division (defined behavior in IEEE 754 — deliberately
  not reported) or opaque sources (`rand()`, sockets) that an honest
  analyzer cannot call zero.
- **`memory-leak` is the one noisy rule** (also the bulk of the
  cross-rule noise on other CWEs' files) and is the current
  improvement target.

Results are from the 2026-07-09 run; grep `JULIET_RESULT` in the
weekly workflow logs for current numbers.

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
  --html <file>          Self-contained HTML report: summary cards double
                         as filters, dataflow traces open with embedded
                         source context, dark/light theme — works offline
  --severity <level>     Minimum severity (info/warning/error)
  --disable-rule <id>    Disable a rule
  --baseline <file>      Suppress findings recorded in the baseline
  --write-baseline <file> Record current findings as the baseline
  --function <names>     Analyze only these functions (comma list,
                         plain or qualified names; repeatable)
  --lines <N-M,K>        Analyze only functions overlapping these line
                         ranges of the analyzed file
  --whole-program        Two-pass mode: collect function summaries
                         across all files first, then analyze
  --summary-out <file>   Save harvested cross-file summaries to a file
  --summary-in <file>    Load summaries saved earlier (incremental
                         whole-program: single-file analysis with
                         whole-project knowledge)
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

Baseline keys are **line-independent**: instead of the line number they
hash the (whitespace-trimmed) text of the finding's source line, so
adding or removing code elsewhere in the file does not invalidate the
baseline. If the flagged line itself changes, the finding resurfaces as
new — deliberately, since a changed line deserves a fresh look.
Identical findings on identical lines are tracked by count, so
baselining one occurrence never hides a second one. Old (v1,
line-numbered) baseline files keep working with their original meaning;
rewrite with `--write-baseline` to migrate.

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

Cross-file knowledge survives incremental runs via summary files:

```bash
# once (or nightly): harvest function summaries from the whole project
zerodefect src/ --summary-out .zerodefect-summaries

# then: analyze just the changed file WITH whole-project knowledge —
# e.g. a callee in another file that may return null is still known
zerodefect src/parser.cpp --summary-in .zerodefect-summaries

# analyze_diff.sh forwards extra options, so the diff loop composes:
scripts/analyze_diff.sh build/src/zerodefect origin/main \
    --summary-in .zerodefect-summaries --severity error
```

The MCP `analyze` tool accepts the same file via its optional
`summaries` argument, so agent loops get cross-file knowledge too.

Stale or malformed summary files are rejected whole (analysis continues
without them, conservatively); conflicting entries merge toward the
weaker claim, so a wrong strong claim cannot enter through the file.

### Semantic regression gate (summary diff)

Summary files are deterministic, so two harvests can be compared as
*contracts*:

```bash
zerodefect src/ --summary-out before.txt     # e.g. on main
# ... apply the change ...
zerodefect src/ --summary-out after.txt
zerodefect --summary-diff before.txt after.txt
```

```
SUMMARY_DIFF WEAKENED find/1 returnNullness: NeverNull -> MaybeNull
[ZeroDefect] 1 weakened, 0 strengthened, 0 changed, 0 added, 0 removed
[ZeroDefect] weakened contracts: callers relying on them must be re-checked
```

`WEAKENED` means a strong claim callers may rely on was lost — a
function that could never return null now can, a callee that used to
be read-only now stores its argument. The exit code is `1` in that
case, so the diff doubles as a CI gate: *this change silently altered
function contracts; the callers deserve a look*. Gained claims report
as `STRENGTHENED` (informational), directionless drifts as `CHANGED`,
and signature changes appear as `REMOVED`+`ADDED` (the key includes
arity — an arity change breaks callers anyway).

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

### Editor & code-scanning integration (via SARIF)

The SARIF 2.1.0 output works today with standard tooling — no plugin of
our own required:

**VS Code.** Install the
[SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
extension (Microsoft), then:

```bash
zerodefect src/ --sarif findings.sarif
code findings.sarif   # or: open via the SARIF Viewer panel
```

Findings appear in a results panel; clicking one jumps to the source
line, and ZeroDefect's dataflow traces show up as *related locations*
(the allocation/free/null-assignment chain behind each finding is
navigable step by step).

**GitHub code scanning.** Upload the same file from CI and findings
appear in the repository's Security tab and as PR annotations:

```yaml
- run: build/src/zerodefect src/ --sarif findings.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: findings.sarif
```

(`|| true` because ZeroDefect exits 1 on findings; code scanning does
its own gating.)

For a shareable, tool-free view of the same findings, use `--html` —
one self-contained file with filters and source-context traces.

## Roadmap

See [`analiz-2026-07.md`](analiz-2026-07.md) (Turkish) for the full
assessment and phased roadmap: SARIF output, suppression/baseline
support, benchmark-driven precision measurement, incremental analysis,
and MCP-server mode for agent integration.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
