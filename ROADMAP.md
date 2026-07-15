# ZeroDefect — Assessment & Roadmap (updated 2026-07-13)

This document tracks the project's verified state, its positioning, and
the decisions that remain. The previous revision (2026-07) described a
pre-public prototype; almost everything it planned has since shipped.
History lives in `changelog.md`; the maintenance backlog lives in
`todo.md`. This file is for STRATEGY: what is true today, and which
forks in the road are still open.

---

## 1. Verified state (2026-07-13)

| Topic | Result |
|-------|--------|
| Test suite | **334/334** in both modes (ctest AND single-process — the second catches global-state leaks) |
| CI | Ubuntu 24.04 + LLVM 18: build + tests + smoke + corpus on every PR; Juliet benchmark on every code PR; weekly deep run |
| Score guards | Three independent referees gate every merge: the test suite, per-CWE Juliet precision/recall floors (`scripts/juliet_expected.txt`), and corpus finding-count pins (`scripts/corpus_expected.txt`). Deliberate rule changes must move the floors IN THE SAME PR with written rationale. |
| Juliet (NIST) | CWE-476/415/416/369 at rule precision **1.000**; CWE-416 recall 0.501, CWE-476 0.352; CWE-401 case precision 0.716 |
| Real-world scans | Eight codebases measured on one analyzer build (see README table): systemd 414→53, shadPS4 209→22, libgit2 149→38, llama.cpp 511→23, fprime 10→**0**, Catch2 0, Redis first scan 80 (idioms not yet learned) |
| Upstream reports | 3 shadPS4 issues FILED (confirmed real bugs); libgit2 (11 verified OOM-path leaks), rtp2httpd and Redis NULL-contract drafts delivered, awaiting filing |
| Non-convergence | 0 on systemd/libgit2/rtp2httpd/fprime after engine convergence widening (llama residue: 4 nlohmann header templates, documented) |

Everything in the previous roadmap's Phases 0–3 — and most of Phase 4 —
has shipped: the dataflow engine with targeted path sensitivity,
5 rules, interprocedural summaries (intra- and cross-TU, on-disk),
summary-diff as a semantic-regression CI gate, SARIF/HTML/JSON
reporting with dataflow traces, suppression + baseline, incremental
analysis (function/line-scoped, diff-driven), an MCP server with
per-call idiom parameters, and configurable project idioms
(allocators, fatal asserts, cleanup attributes).

## 2. What the analysis core is now

The engine is a worklist dataflow framework (duck-typed Analysis over
Clang CFGs) with **targeted path sensitivity**: analysis states are
small sets of guarded disjuncts (condition-facts × variable states,
cap 4) rather than one merged state. The fact machinery (v2, 2026-07-12)
carries:

- canonical condition keys (var/enum/template-param vs integer
  constant, constant-returning callees, gated pointer-nullness keys),
- a flow-sensitive fact lifecycle (assignments erase, constant stores
  stamp, stamped equalities entail answers to later keys),
- disjunction elimination for value-materialized short-circuit
  conditions (the systemd assert shape),
- unsigned zero-identities (`u <= 0` ≡ `u == 0`),
- engine-level convergence widening with time memory (the domain is
  deliberately non-monotone; real code oscillates without it).

Each mechanism exists because a real codebase demonstrated the need,
and each is pinned by tests plus the three referees. This
evidence-first loop — scan, triage every finding by hand, turn each
false-positive family into an engine feature with a pin — is the
project's actual method, and it has held up across eight codebases.

## 3. Positioning (updated)

The 2026-07 analysis identified three differentiators for the "an
agent writes the code, someone in the loop verifies the semantics"
workflow. Status:

1. **In-loop gate — SHIPPED.** MCP server with warm AST cache,
   function/line-scoped incremental analysis in milliseconds, findings
   with machine-readable dataflow traces (the explanation an LLM needs
   to fix its own bug).
2. **Diff-aware semantic regression — SHIPPED (v1).** Function
   summaries (nullability, zeroness, parameter effects) are compared
   as contracts; a WEAKENED verdict is a CI-failing event
   (`--summary-diff`).
3. **Contract layer (intent verification) — OPEN.** The remaining
   differentiator, and the largest open decision below.

The competitive observation stands: clang-tidy cannot reach this
depth, CSA/CodeQL cannot reach this speed/position, Infer is
unmaintained. What has CHANGED since the first analysis: the engine
is no longer the risk item — eight real-world scans and the guard
infrastructure are evidence the core holds. The remaining risk is
PRODUCT, not engine: the contract language and the distribution
story.

## 4. Open architectural decisions

Three forks require a human decision. Everything else in the backlog
is maintenance.

### 4.A Contract language (intent verification) — the keystone

Everything shipped so far hunts UNIVERSAL bugs (null, leaks, UB). The
founding pain — "we said it was done, and it crashed anyway" — is
about INTENT: the code does not do what it was supposed to do. The
plan: a lightweight annotation language (ownership, nullability,
ranges, relations between parameters); the LLM emits code AND
contract; ZeroDefect verifies one against the other, deterministically.

Design questions that need co-design (user + assistant, max effort):
- **Surface syntax**: attributes (`[[zd::nonnull]]`), structured
  comments (`// @zd: returns nonnull unless n == 0`), or a sidecar
  file? Trade-off: attributes are toolable but invasive; comments are
  adoptable on any codebase including C89; sidecars never touch
  upstream code (works for scanning third-party projects).
- **Semantic scope of v1**: the existing summary machinery already
  infers return-nullness, zeroness and parameter effects — v1
  contracts should be CHECKABLE BY THE EXISTING ENGINE (declare what
  we can already verify), then grow with the engine. The
  `assert(p || n == 0)` conditional-contract shape from systemd/fprime
  is the natural first relational form.
- **Failure semantics**: is a contract violation an error (code is
  wrong) or a contract-diff event (intent changed — summary-diff
  semantics)? Probably both, distinguished by who authored the
  contract.
- **LLM ergonomics**: the contract must be cheap for a model to emit
  correctly next to the code it writes, and the violation message must
  be self-repair fuel (trace + violated clause).

### 4.B Engine philosophy: evolve vs rewrite

Question: keep evolving targeted path sensitivity, or rewrite as a
single-pass path-sensitive (symbolic) engine à la CSA?

Evidence gathered 2026-07-12 favors EVOLUTION: the disjunct machinery
absorbed five major mechanisms in one day without destabilizing
(334 tests, floors RAISED twice); the measured cost knee is the
disjunct cap (cap 8 = ~2.7× systemd scan time for −2 findings), and
the identified lever is smarter (fact-prioritized) widening, not a
bigger engine. A symbolic rewrite would buy generality we have not
yet needed, at the cost of the speed that makes the in-loop position
possible, plus months of re-validation of everything the referees
currently pin.

**Recommendation: evolve.** Revisit ONLY if the contract language
(4.A) demands relational reasoning (e.g. `len(buf) >= n` arithmetic
between variables) that provably cannot be hosted in the fact
machinery. Decision should therefore FOLLOW 4.A, not precede it.

### 4.C Distribution & idiom profiles

How does the tool actually enter someone's AI loop? Candidate
surfaces, not mutually exclusive: CLI (exists), MCP server (exists),
GitHub Action + code-scanning via SARIF (exists as output, not as a
packaged action), VS Code extension (evaluated, deferred), pre-built
binaries vs build-from-source.

The scan campaign produced a second product insight: **idioms are
configuration** — every codebase needed its own allocator/assert/
cleanup vocabulary before the analysis saw the code the way the
project means it. That configuration is shippable: per-project
"idiom profiles" (a `zerodefect.conf` for systemd, redis, libgit2,
...) maintained in-repo, doubling as documentation of what the
analyzer understands. Decision needed on packaging priority order
once the repo is public.

## 5. Near-term plan (week of 2026-07-13)

- **Thu**: GitHub settings session (user + assistant), v0.1.0 tag +
  Release (notes ready), user files the libgit2 / rtp2httpd / Redis
  upstream reports (drafts delivered).
- **Fri**: public flip (user), contract-language co-design session
  (4.A, max effort).
- Rolling maintenance from `todo.md` (fstab-util correlation loss,
  llama header-template non-convergence residue, ternary-value FN,
  Redis idiom round 2) — each is an ordinary PR round guarded by the
  three referees.

## 6. "Ideal analyzer" spec — adopted vs parked (2026-07-15)

A 30-section design spec for the *ideal* AI-era C/C++ analyzer was
reviewed (source: user-supplied `ideal_statik_cpp_kod_analizcisi`). Its
core thesis — **produce proof / counterexample / "unknown", never a bare
warning; "no warning" ≠ "correct"** — is already this project's operating
discipline (soundness invariant, precision-first). The spec is a VISION,
explicitly not a feature checklist (its own §29); treating it as a to-do
list would spread us too thin to be sound anywhere. Decision: adopt its
*philosophy*, execute its Phase-1 list (which matches our roadmap), pull
two high-leverage AI-era items early, and DECLARE what we will not chase.

**Adopted early (uniquely enabled by our Clang/LibTooling base):**
- **Three-valued output + coverage report** (spec §1/§21.9/§27) — say
  "proven / counterexample / unknown-because-X", and surface what was
  *not* analyzed soundly. Task #62. No mainstream tool does this.
- **Hallucinated-symbol detection** (spec §20.4) — nonexistent
  header/API/overload/signature, made-up flag/env/config/error-code.
  The front-end already resolves symbols; this is near-free and a real
  AI-era wedge. Task #63.
- **Assumption-extraction** (spec §20.2, the doc's own #1 idea) — infer
  the implicit contract a function relies on and ask "where is this
  verified?". Natural extension of Contracts v1. Task #64 (medium-term,
  research-heavy, FP-risk — calibrate).

**Parked deliberately — NOT "can't", but "not where a Clang-AST tool can
be sound":**
- Binary analysis / source-binary verification / ABI matrix (spec §13,
  §23.6) — needs a separate DWARF/disassembler stack; different product.
- Concurrency model checking / thread-interleaving counterexamples
  (spec §11, §23.4) — needs a model checker; our whole architecture is
  per-function flow-sensitive dataflow, not interleaving exploration.
  The single hardest domain in the spec. Hard defer.
- Supply-chain / SBOM / dependency risk (spec §19) — a dependency-graph +
  registry-query tool (OpenSSF Scorecard territory), not C/C++ semantics.
- Full symbolic execution + SMT (spec §23.3) — where true concrete
  counterexamples come from (KLEE/CBMC), a multi-year effort; we
  approximate with abstract interpretation and say "unknown" honestly
  rather than overpromise "proven".

**Honesty guardrail (from the spec's own warning):** the "proven" verdict
may only ever be stamped where we are genuinely sound — otherwise we
become the "convincing but wrong" artifact the spec critiques. Executable
specs stay the aspirational apex, but the tool must deliver value at ZERO
spec (find real bugs today) and reward those who add contracts with
deeper proofs — never require a spec to be useful.

### Numeric capability — progress (the quantitative foundation)
The engine's lattices were all SYMBOLIC (null?/freed?/zero?); none
QUANTITATIVE. The interval sub-project closes that: `Interval` value type
(#57, merged), `IntervalAnalysis` dataflow (#58, merged), int-overflow
rule as the first consumer (#60/PR #70, merged 2026-07-15). Next: extent
map + bounds rule (#61) — the OOB / heap-overflow class, targeting the
shadPS4 #4712 heap-overflow shape and Juliet CWE121/122/124/126.

## 7. Build recipe (unchanged since 2026-07)

```bash
apt-get install -y llvm-18-dev libclang-18-dev libzstd-dev zlib1g-dev
cmake -B build -G Ninja -DCMAKE_PREFIX_PATH=/usr/lib/llvm-18 -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build          # 334/334
./build/tests/zerodefect_tests  # single-process mode, same 334
```
