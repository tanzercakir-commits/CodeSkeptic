# ZeroDefect v0.1.0

First public release. ZeroDefect is a C/C++ static analyzer built on
Clang LibTooling, designed for the age of AI-generated code: every
finding comes with a **dataflow trace** — the chain of events that leads
to the bug — so both humans and coding agents can act on it without
guessing.

## What it detects

| Check | rule id | Juliet precision* |
|-------|---------|-------------------|
| Use after free | `use-after-free` | 1.000 |
| Double free | `double-free` | 1.000 |
| Null pointer dereference | `null-deref` | 1.000 |
| Division by zero | `div-by-zero` | 1.000 |
| Memory leak | `memory-leak` | 0.653 |
| Uninitialized pointer use | `uninit-ptr` | — |

\* rule-matched, case-level precision on the NIST Juliet 1.3 benchmark
(400-file strided samples; full methodology and honest limitations in
the README's Benchmark section).

## Highlights

- **Flow-, path- (targeted) and context-sensitive dataflow engine**:
  fixpoint iteration with assume-edge refinement, guarded disjuncts for
  correlated branches, two-phase reporting (findings only from converged
  state), per-function CFG cache.
- **Interprocedural analysis**: function summaries (return nullness,
  return zeroness, parameter effects with alias tracking) with a
  recursion-safe fixpoint; `--whole-program` connects flows across
  files.
- **Incremental by design**: `--function` / `--lines` scoping, a
  diff-driven script, and summary files (`--summary-out` /
  `--summary-in`) that give single-file analysis whole-project
  knowledge.
- **Semantic regression gate**: `--summary-diff old new` classifies
  contract changes between two harvests; a WEAKENED contract (e.g.
  NeverNull → MaybeNull) exits 1 — CI can block changes that silently
  alter function contracts.
- **Agent integration**: `--serve` runs an MCP server exposing an
  `analyze` tool with structured findings and traces; a process-lifetime
  warm AST cache makes repeat calls ~6x faster.
- **Reports people actually read**: self-contained HTML report (filters,
  source-context traces, dark/light), SARIF 2.1.0 (VS Code SARIF
  Viewer, GitHub code scanning), JSON, console with traces.
- **Adoption tools**: line-independent baselines (refactors don't
  invalidate them), suppression comments, severity filtering, English
  or Turkish diagnostics (`--lang tr`).

## Confirmed in the wild

The analyzer has already found a real bug that the upstream maintainers
fixed: shadPS4's `internal__Foprep` set `ENOMEM` on file-table
exhaustion but fell through without a `return`, dereferencing the null
`FILE*` on the next line. The one-line fix — a `return nullptr;` after
the error is set — was merged
([shadps4-emu/shadPS4#4702](https://github.com/shadps4-emu/shadPS4/pull/4702)).
Two more findings from the same scan are reported upstream. See the
README's Real-world scans section for the full table (systemd, Redis,
libgit2, llama.cpp, NASA fprime, abseil, Catch2).

## Quality gates behind this release

- 228 unit/integration tests, run both under ctest isolation and as a
  single process (the latter catches global-state leaks).
- Real-world corpus guard (cJSON, tinyxml2) with pinned finding counts.
- NIST Juliet score guard with per-CWE precision/hit-rate floors — any
  PR that drops below them fails CI.

## Known limitations (deliberate, documented)

- Evidence-based and conservative: opaque callees, escaped pointers and
  unknown values stay silent rather than guessing (precision over
  recall; the hit-rate numbers in the README reflect this).
- Analysis is per translation unit unless `--whole-program` or summary
  files are used.
- See the README's Benchmark section and `todo.md` for the full list.
