# The analysis engine

What actually runs when CodeSkeptic analyzes a translation unit — the
architecture, and the three capabilities behind the rule table.

## Architecture

```
StaticAnalyzer (facade)
 ├─ SourceManager   — LibTooling wrapper: compile_commands.json, AST production
 ├─ RuleEngine      — rule registry, enable/disable, runAll
 │   └─ Rule (abstract) → UninitPointerRule_Ex, MemoryLeakRule_Ex, DivByZeroRule
 │        └─ DataflowEngine — generic worklist solver over the Clang CFG:
 │             Analysis = { State, initialState, merge, transfer,
 │                          onStatement?, refineOnEdge? (assume edges) }
 ├─ Reporter        — ConsoleReporter, JsonReporter, SarifReporter, HtmlReporter
 └─ Config          — CLI args + .codeskeptic.conf
```

Writing a new flow-sensitive rule means defining a lattice (`State`), a
`transfer` function, and optionally `refineOnEdge` to sharpen state along
branch edges. The engine handles CFG construction, the worklist, and
predecessor merges. A fuller box diagram lives in
[`architecture.txt`](../architecture.txt).

## Intrinsic-source recall (v0.3)

The rules recognize the library calls whose *contract* makes a defect
intrinsic — `malloc`/`calloc`/`getenv`/`fopen` may return null,
`atoi`/`strtol`/`scanf` deliver unbounded untrusted values,
`strcpy`/`strchr` have no bound / dereference their argument. Keying on
the callee's contract (never on caller data) turns the everyday
first-draft shapes an AI writes — `p = malloc(n); *p`, `x / atoi(s)`,
`int n = atoi(s); n * k`, `strchr(getenv(x), ':')` — into findings,
while a downstream guard refines the state and stays silent. On a blind
24-program AI corpus this lifted combined recall from ~0 (on the
non-alloc classes) to **0.625 at precision 1.000** (zero false
positives, including on 9 deliberately-clean programs).

## Targeted path-sensitivity

The memory rules keep a small set of guarded states instead of one
merged state, keyed by conditions on variables that provably don't
change (`if (mode == 5) p = malloc(...); … if (mode == 5) free(p);` is
clean — the two guards are correlated, so the "allocated but never
freed" path is infeasible). Function-call conditions are never keyed
(two `check()` calls may differ), mutated variables are never keyed,
and the disjunct budget degrades gracefully to the classic merged
analysis.

## Interprocedural analysis (v1)

Functions with visible bodies are summarized before rules run — return
nullness (a `find()`-style function that can return null makes
unguarded dereferences of its result a warning, with a trace note),
return zeroness (a callee that can return zero makes an unguarded
division by the assigned result a warning — the classic
`data = badSource(); 100 / data` split across functions or files) and
parameter effects (free-wrappers count as frees, so double-free/
use-after-free through wrappers is caught; read-only helpers no longer
hide leaks behind them). Recursion-safe fixpoint; external and aliasing
callees stay conservative.

Summaries are deterministic and serializable (`--summary-out` /
`--summary-in`), which is what makes the
[semantic regression gate](integrations.md#semantic-regression-gate-summary-diff)
and incremental whole-program analysis possible.
