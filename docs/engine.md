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

## Interprocedural analysis (v2)

Functions with visible bodies are summarized before rules run — return
nullness (a `find()`-style function that can return null makes
unguarded dereferences of its result a warning, with a trace note),
return zeroness (a callee that can return zero makes an unguarded
division by the assigned result a warning — the classic
`data = badSource(); 100 / data` split across functions or files) and
parameter effects (free-wrappers count as frees, so double-free/
use-after-free through wrappers is caught; read-only helpers no longer
hide leaks behind them). Visible direct calls form a call graph whose
strongly connected components are solved callee-first. Acyclic wrappers are
evaluated once after their dependencies; recursive components iterate
synchronously from conservative summaries to a fixed point. External,
indirect and aliasing callees stay conservative.

The v2 schema also records exact pointer return identity: a relation is
published only when every reachable return aliases the same pointer
parameter's entry object. Local copies and direct call chains preserve it;
mixed sources, mutation and exposed write channels lose it conservatively.
This identity relation is independent from null correspondence.

Parameter contracts now cross translation-unit boundaries too. Leading
assert/abort and complain-then-return guards become exact non-null entry
preconditions with their crash/reject consequence preserved. On normal
return, direct `T**` and `T*&` output slots carry an exact Null/NonNull
postcondition only when every reachable path agrees; partial writes,
conflicting paths, rebinding and untracked aliases fall back to Unknown.
Callers consume both relations, including direct chains and `operator()`
calls.

Side effects and ownership are separate summary axes. For every pointer-like
parameter, the access relation records no access, read, write, or read+write;
the ownership relation records borrowed, consumed, transferred, or unknown.
Direct dereference/member/subscript uses, clean local aliases, direct call
chains and non-static `operator()` calls compose through the SCC solver. Fresh
heap/resource returns and their wrapper chains are Owned; parameter/global
aliases are Borrowed; mixed, opaque, capture, and conflicting flows remain
Unknown. MemoryLeak consumes the ownership relations, and ContractRule now
verifies `owns`, `borrows`, and `returns owned` against the same facts.

Summary format v9 persists the access (`O/R/W/B/U`), parameter ownership
(`B/C/T/U`), and return ownership (`B/O/U`) fields alongside the v8
pre/postcondition vectors. Readers still accept v1-v8 files; old parameter
effects are conservatively upgraded for ownership behavior.

Summaries are deterministic and serializable (`--summary-out` /
`--summary-in`), which is what makes the
[semantic regression gate](integrations.md#semantic-regression-gate-summary-diff)
and incremental whole-program analysis possible.
