# ZeroDefect v0.2.0

The quantitative release. v0.1 tracked only SYMBOLIC state (null?
freed? zero?); v0.2 adds NUMERIC reasoning — intervals, sizes, bounds —
and builds the first market-facing layer on top of it: a diff-native
PR review that judges the change, not the backlog.

## New detection: the spatial/numeric class

| Check | rule id | Class |
|-------|---------|-------|
| Out-of-bounds array access (proven whole-range) | `bounds` | CWE-125/787 |
| Copy past destination (`memcpy`/`memmove`/`memset`) | `bounds` | CWE-787/122 |
| Signed multiply overflow (incl. `malloc(a*b)`) | `int-overflow` | CWE-190 |

Built on a new interval lattice and dataflow: fixed-array extents,
heap extents (`malloc`/`calloc` with sole-definition discipline),
sizeof-aware size evaluation, fixed-size ARRAY MEMBERS of structs
(`s->buf` — the real-world heap-overflow shape), and interprocedural
parameter entry intervals over closed call graphs. Same soundness
posture as everything else: only a whole-range proof reports as error.

## Diff-native PR review

`scripts/review_diff.sh <binary> <base-ref>` analyzes the changed
files at BOTH revisions and reports the delta: new findings (traces
included, changed lines marked), fixed findings, contract
WEAKENED/STRENGTHENED changes, and a coverage-honesty section. Gate =
the evidence ladder: new definite findings and weakened contracts
fail; "may" findings inform (`--strict` to gate). The ASSUMPTION DELTA
is on by default — a new inferred, unchecked precondition is exactly
the CWE-476 shape reviews exist to catch: in the field trial it
pinpointed cJSON's #991 null dereference as a single finding, with
zero noise across a 116-commit history range.

## Three-valued honesty, operationalized

- Coverage report: functions the dataflow could not drive to a
  fixpoint are LISTED — "no warning" there is "not checked".
- `--assumptions`: the inferred-contract report ("parameter p is
  assumed non-null — dereferenced, never checked").
- Evidence-ladder severity everywhere, now including `uninit-ptr`:
  proven-on-all-paths = error; possible = warning. An imprecision can
  no longer masquerade as a proof.

## Hardened at scale

A full TensorFlow Lite scan (285 TUs) drove the hardening: a
metaprogram-generated type 104k stack frames deep crashed the analyzer
— fixed with a 64MB analysis worker plus structural budgets on every
type-size query (pathological type = honest "unknown", never a crash
or a guess). A test-order determinism bug (CFG cache address reuse)
was found and fixed; shuffle-stability is now a standing referee.

## Confirmed in the wild (new this release)

- cJSON's vendored Unity example ships a deliberate off-by-one
  (`NumbersToFind[9]` on a 9-element array behind a brace-less `if`);
  the bounds rule proves `i in [9, +inf)` on loop exit and flags it.
- TensorFlow Lite `rfft2d`/`irfft2d` leak their FFT work buffer on
  temporary-tensor lookup failure — hand-verified and reported
  upstream ([tensorflow#123387](https://github.com/tensorflow/tensorflow/issues/123387)).
- Precision field test: sixteen fresh, zero-dependency codecs/parsers
  (~2 MB — stb, dr_libs, lz4, cgltf, picojpeg, …) scanned with the
  spatial/numeric rules: zero findings, zero false positives, with a
  canary proving the rules were exercised, not skipped.

## Quality gates behind this release

- 507 unit/integration tests (v0.1: 228), run under ctest isolation,
  as a single process, and under 12 gtest-shuffle seeds (order
  dependence is a failure).
- An end-to-end hermetic git fixture pins the PR-review semantics
  (shift-immunity, rename silence, gate ladder) and is mutation-tested.
- Real-world corpus pins and NIST Juliet per-CWE floors gate CI as
  before.

---

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

The analyzer has already found real bugs that the upstream maintainers
fixed and merged — two, from the shadPS4 emulator:

- a `sceSaveDataMount/Mount2` guard that used `&&` where it needed
  `||` and dereferenced the pointer it had just null-checked
  ([shadps4-emu/shadPS4#4703](https://github.com/shadps4-emu/shadPS4/pull/4703)) —
  the canonical looks-right-reads-wrong bug;
- `internal__Foprep` setting `ENOMEM` on file-table exhaustion but
  falling through without a `return` and dereferencing the null
  `FILE*`
  ([#4702](https://github.com/shadps4-emu/shadPS4/pull/4702)).

A third finding from the same scan is reported upstream. See the
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
