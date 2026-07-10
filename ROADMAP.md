# ZeroDefect — Assessment & Roadmap (2026-07)

This document is a technical analysis of the project made with an
independent eye, its positioning within the industry, and the roadmap
proposed for what lies ahead. Every "verified" statement in here was
confirmed during this analysis by actually building and running on Linux
(Ubuntu 24.04, LLVM 18.1.3).

---

## 1. Assessment

### 1.1 Verified state

| Topic | Result |
|-------|--------|
| Linux build | Successful — `cmake -DCMAKE_PREFIX_PATH=/usr/lib/llvm-18` + `llvm-18-dev libclang-18-dev libzstd-dev` |
| Test suite | **41/41 passed** (0.79 s) — verified outside macOS for the first time |
| Smoke test | uninit-ptr, reassignment leak, exit-block leak, double-free correctly caught; exit code correct (1 when there are findings) |
| Guarded division (parameter) | `if (z != 0) return 100/z;` — NO false positive (because the parameter stays Unknown) |

### 1.2 The project's real level

The project is not "a linter with three rules"; it is **the core of a
general-purpose dataflow analysis framework**. The critical architectural
decisions were made correctly:

- **DataflowEngine** (template, duck-typed Analysis, worklist + merge):
  this abstraction is exactly what turns a pile of rules into an analysis
  framework. The conceptual core of the Clang Static Analyzer is the same.
  Writing a new rule has come down to the level of "define a lattice +
  write a transfer".
- The layered architecture (SourceManager → RuleEngine → Rules → Reporter)
  is clean, dependencies are one-directional, testability is high.
- The honest limitation list in `todo.md` (known FPs/FNs) is a rare and
  very valuable engineering habit.
- The reflex of validating against a real-world corpus (cJSON, tinyxml2)
  is right.

### 1.3 New problems found in this analysis

**(a) Header resolution failure on Linux — verified.**
The unconditional `-isystem /usr/include` addition in
`SourceManager::processAll`, a side effect of the fix made for macOS,
breaks GCC libstdc++'s `#include_next <stdlib.h>` chain on Linux:

```
/usr/include/c++/13/cstdlib:79:15: fatal error: 'stdlib.h' file not found
```

Once `/usr/include` is prepended to the include search order,
`include_next` has nowhere left to go. On Linux `-resource-dir` is already
sufficient; `/usr/include` should either not be added at all or be
conditional on the platform. Because the analysis continues with a partial
AST, findings silently go missing (the double-free in the demo file was
missed for this reason) — **silent incomplete analysis means a wrong
"clean" report**; this is the most critical fix before a public release.

**(b) DataflowEngine's fixed iteration ceiling.**
`maxIterations = numBlocks * 4` is not a theoretical fixpoint guarantee.
With a monotone transfer + a finite-height lattice, convergence is already
guaranteed; the ceiling should only be a safety fuse. Right now, if the
ceiling is hit, `converged=false` is set but **the results are still
used** and nobody is warned — in loop-heavy functions there is a risk of
reporting with incomplete state. Make the ceiling `numBlocks × lattice
height`, and if it is exceeded, report that function as "could not be
analyzed".

**(c) Architectural inconsistency across rules.**
MemoryLeakRule_Ex uses the right pattern: all variables in a single
product lattice (`map<VarDecl*, AllocState>`), a single dataflow run,
fast `dyn_cast`-based classify. UninitPointerRule_Ex, however, runs a
separate CFG + separate run per variable + 5-6 ASTMatchers per
statement — O(variables × statements × matchers). Consolidating both onto
the same pattern (product lattice + dyn_cast) gains both speed and code
simplicity.

**(d) Unknown's absorbing behavior in the DivByZero lattice.**
Because `merge(Zero, Unknown) = Unknown`, the following case silently
slips through (verified):

```cpp
int d = 0;
if (z > 0) d = z;
return 100 / d;   // on the z <= 0 path d == 0 — NO report
```

Deliberate conservatism to avoid FPs, but `Zero + Unknown = MaybeZero`
(at least at Info level) would be a more accurate signal. This should be
handled together with guard analysis (below).

**(e) Cross-TU duplicate finding risk.**
Diagnostics are collected per TU and merged; if a function defined in a
header is analyzed in multiple TUs, the same finding is reported N times.
There is sorting but no deduplication — global dedup over
`(file, line, rule_id)` is needed.

### 1.4 Gaps for a public release

- **README is 12 bytes** — the project has no storefront.
- **No LICENSE** — a repo without a license is legally "all rights
  reserved"; nobody can use it or contribute. (Suggestion: Apache-2.0 —
  the patent clause matters for analysis tools.)
- **No CI** — the "41/41 passing" claim exists only locally. A GitHub
  Actions matrix with Ubuntu + LLVM 18 is a one-day job (the recipe was
  verified in this analysis).
- **Diagnostic messages are Turkish only** and clipped to ASCII
  ("sizintisi"). If public is the target, English by default + `--lang tr`
  is the right balance.
- **No SARIF output** — GitHub code scanning and all modern CI
  integration speak SARIF; a custom JSON format is an integration wall.
- **No suppression mechanism** (`// NOLINT`-style + a baseline file) —
  the precondition of gradual adoption on a real project.

---

## 2. Industry Positioning — "Don't let similar projects discourage us"

The honest table:

| Tool | Approach | Strength | Weakness |
|------|----------|----------|----------|
| clang-tidy | AST patterns | Ecosystem, speed | No flow analysis in most checks |
| Clang Static Analyzer | Symbolic execution, path-sensitive | Depth | Slow, hard to extend, intra-TU |
| Infer (Meta) | Separation logic, interprocedural | **Diff-aware mode** | Heavy, OCaml, maintenance declined |
| CodeQL | Datalog queries | Expressive power | Batch/CI-scale, takes minutes |
| cppcheck | Its own parser | Easy installation | No Clang AST, limited depth |

The critical observation: **none of these tools was designed for the
workflow "an agent is writing the code, and someone inside the loop needs
to verify the semantics."** Trying to beat CSA at path-sensitivity is a
20-person-year war and unnecessary; the gap is not in the engine, it is
in the **position within the workflow**.

The pain you voiced — "we said it's done, and a bug showed up again" —
is the industry's most expensive problem right now: as the production
cost of code drops to zero, its **verification cost** has become the
bottleneck. ZeroDefect's thesis sits exactly in that gap:

1. **In-loop gate:** the moment an LLM changes a function, a tool that —
   within milliseconds — analyzes only that function (and its callers)
   and returns the finding **together with its dataflow trace** (which
   path the faulty value came from) in a machine-readable format. The
   trace is precisely the explanation the LLM needs to correct itself.
   CSA/CodeQL cannot get down to that speed; clang-tidy cannot get up to
   that depth.

2. **Contract layer (intent verification):** general UB hunting finds
   "universal" bugs, but your problem is **intent** semantics. A
   lightweight annotation language (ownership, nonnull, ranges) → the LLM
   produces the code AND the contract → ZeroDefect verifies the code
   against the contract. This is what directly targets the "semantic
   debugging" gap.

3. **Diff-aware semantic regression:** on every change, compare function
   summaries (nullability, ownership, may-be-zero) before/after; if a
   property callers rely on has silently changed, raise an alarm. This
   was Infer's killer feature at Meta; nobody in the open ecosystem does
   it well. "We said it's done, then it broke" is exactly a semantic
   regression problem.

The discipline that finished an LALR parser from scratch in two years is
the right profile for this work: analysis frameworks are the same class
of deep infrastructure craft — there is no shortcut, but each layer
accumulates on top of the next, and the competitors' inertia (heavy,
general-purpose, out-of-loop) is our agility.

---

## 3. Roadmap

### Phase 0 — Public preparation (low effort, high visibility)
- [ ] Linux header resolution fix (§1.3a) — **first task; it is producing silent incomplete analysis**
- [ ] README (English: what, why, architecture diagram, sample output, build recipe)
- [ ] LICENSE (Apache-2.0 suggested)
- [ ] GitHub Actions CI: Ubuntu 24.04 + LLVM 18, build + ctest
- [ ] Diagnostic messages English by default, `--lang tr` option
- [ ] Cross-TU finding deduplication (§1.3e)

### Phase 1 — Deepening the analysis core
- [ ] **Branch-condition refinement (assume edges):** apply the CFG
      terminator condition to the state on the true/false successor edges
      (`if (p) → p NonNull`, `if (z != 0) → z NonZero`). On its own it
      kills the biggest FP class and solves the known guard FP in
      DivByZero. **The technical step with the highest value/effort
      ratio.**
- [ ] Move UninitPointerRule to the product lattice + dyn_cast pattern (§1.3c)
- [ ] Per-function CFG cache (single build, shared by all rules)
- [ ] Tie the iteration ceiling to the lattice height; report a function
      that does not converge (§1.3b)
- [ ] Revisit the `Zero + Unknown` merge decision together with guard analysis (§1.3d)

### Phase 2 — Real-world usability
- [ ] SARIF reporter (free integration with GitHub code scanning)
- [ ] `// zerodefect-disable-line <rule>` suppression + a baseline file
- [ ] Measurement infrastructure: precision/recall numbers with the NIST
      Juliet test suite — "let's state our claim with numbers". Make the
      cJSON/tinyxml2 runs a regression test in CI.
- [ ] New rules (the framework now makes them cheap): use-after-free (the
      Freed state already exists, add a dereference check), null-deref
      (meaningful after assume edges), overflow-prone loop bounds

### Phase 3 — AI loop integration (the vision differentiator)
- [ ] Incremental mode: analysis of a single function / changed functions
      (from the diff)
- [ ] Add dataflow traces to findings: "p, allocated at line 12 → if-false
      path at 15 → freed again at 19" — the explanation format the LLM
      will consume
- [ ] MCP server / JSON-RPC mode: a persistent process that Claude Code
      and similar agents call after every edit (the AST cache stays warm)
- [ ] Diff-aware semantic summary comparison (§2.3)

### Phase 4 — Research horizon
- [ ] Interprocedural analysis with function summaries
      (ownership/nullability summaries — turns Escaped conservatism into
      real transfer knowledge)
- [ ] Lightweight contract/annotation language + verifier (§2.2)
- [ ] Gradual transition to path-sensitivity (at first only in guarded
      regions)

### Rationale for the ordering
Phase 0 builds trust (a state that can go public), Phase 1 takes the tool
past the "not a toy" threshold (without guard analysis the signal/noise
ratio holds on no real project), Phase 2 brings measurability and
adoption, and Phase 3 takes the seat nobody is sitting in. A note against
the temptation to pull Phase 3 forward: putting a tool with no traces and
high FPs into the loop misleads the LLM too — core quality (Phase 1) is
the precondition of the vision.

---

## 4. The Linux build recipe used in this analysis

```bash
apt-get install -y llvm-18-dev libclang-18-dev libzstd-dev zlib1g-dev
cmake -B build -G Ninja -DCMAKE_PREFIX_PATH=/usr/lib/llvm-18 -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build          # 41/41
```

Note: without `libzstd-dev`, LLVM 18's CMake exports cannot find the
`zstd::libzstd_shared` target and blow up at the configure stage. This
recipe can be used as the basis when the CI workflow is written; the
Homebrew `CMAKE_PREFIX_PATH` default should be restricted to the `APPLE`
condition only.
