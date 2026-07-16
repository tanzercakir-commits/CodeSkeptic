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
  *not* analyzed soundly. Task #62 — SHIPPED (coverage report, PR #72).
- **Assumption-extraction** (spec §20.2, the doc's own #1 idea) — infer
  the implicit contract a function relies on and ask "where is this
  verified?". Natural extension of Contracts v1. Task #64 (medium-term,
  research-heavy, FP-risk — calibrate).

Note (2026-07-15): **Hallucinated-symbol detection** (spec §20.4) was
initially adopted but MOVED TO PARKED after a feasibility probe (see
below) — my earlier "near-free" claim was wrong.

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
- **Hallucinated / nonexistent-symbol detection** (spec §20.4) — parked
  after a feasibility probe (2026-07-15). Evidence: in C11+ a call to an
  undeclared function is a compile ERROR (`-Wimplicit-function-
  declaration`), and every §20.4 shape (nonexistent header / function /
  overload / signature / enum) is likewise a hard compile error. Since
  we analyze the AST of code that already COMPILES (compile_commands.json),
  the compiler has already rejected these before they reach us — our
  value-add is zero. The residue splits two ways, neither a clean
  static-AST v0: (a) symbols that COMPILE but are semantically wrong
  (old-version / wrong-platform / wrong-library same-name, made-up
  env-var / error-code) need a VERSIONED, dated knowledge base (spec
  §20.5 says so explicitly) — a data problem, like supply-chain; (b) the
  one genuine cross-TU niche — "declared in a project header, called, but
  defined in no TU" — is irreducibly FP-prone (libc and third-party libs
  are declared-not-defined-in-our-TUs yet link fine), so it violates
  precision-first without heavy opt-in gating. Honest reclassification:
  a knowledge-base problem, not a static-AST one. (My initial "near-free
  wedge" claim was wrong; corrected here rather than shipped as a
  compiler echo or an FP generator.)

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

## 6.5 Real-world spatial-rule validation (2026-07-16)

After landing the bounds rule's deepenings — heap extents (#76),
copy-size overflow (#77), sizeof-aware sizes (#78), fixed-size array
MEMBERS as buffers (#79) — the spatial rules were hunted on SIXTEEN
FRESH, zero-dependency, buffer-heavy translation units (perfect compile
DB, no build deps), the canonical CWE-125/787 domain — "AI writes a
parser/codec":
  - image/media: qoi, qoa, pl_mpeg, stb_vorbis, stb_image, stb_truetype,
    picojpeg, nanosvg;
  - parsers: cgltf, jsmn, parson, microtar;
  - compression: lz4, fastlz, heatshrink, dr_flac.
(~2 MB of decoder/parser code total.)

- **Spatial/bounds + int-overflow rules: 0 findings, 0 false positives.**
  Correct: a sound bounds rule fires only on a WHOLE-RANGE definite OOB,
  which shipping decoders do not contain. A definite-OOB + struct-member-
  copy CANARY appended to the stb_vorbis TU was caught (index [20,20]
  outside [0,8); copy [116,116] > 16-byte member), proving the rules were
  EXERCISED, not silently skipped. Precision confirmed on the most
  FP-hostile input class (heavy fixed arrays, memcpy, sizeof, bit math).
- **Null-deref rule: 2 findings, both FALSE POSITIVES** — the mature
  null-deref rule, orthogonal to the new spatial work. Two distinct
  precision mechanisms, both well-understood, neither a soundness bug:
    1. stb_image TGA (`tga_palette`): DISJUNCT-BUDGET EXHAUSTION. The
       basic loop-invariant-guard shape (one guard, one pointer) is
       handled correctly — a minimal repro is silent. The FP needs SCALE:
       with >=4 independently-guarded pointers (`kMaxDisjuncts = 4`), the
       binary-guard product exceeds the budget, `widenGuarded` collapses
       ALL correlations, and every guarded pointer turns into a spurious
       "may be null" (confirmed: a 4-pointer repro yields 7 FPs). The
       real fix is a per-variable guard representation so INDEPENDENT
       guards don't multiply into a cross-product — a disjunct-model
       redesign, not a constant bump (raising kMaxDisjuncts trades perf
       and risks the disjuncts-v2a/v2b-tuned Juliet floors). The
       path-sensitivity scaling wall Coverity/CSA also hit.
    2. picojpeg (`pHuffVal`): `getHuffVal(idx)` returns null only in its
       default case (idx ∉ {0,1,2,3}); the caller's `idx =
       ((x>>3)&2)+(x&1)` provably ∈ {0,1,2,3}, so the null path is
       infeasible — but the interval evaluator returns top() for bitwise
       `&`/`>>`, so the argument's in-range value is not proven, and the
       "callee-may-return-null" summary fires. Two cheap sound levers
       exist (model `x & c → [0,c]` for constant mask c≥0; value-condition
       the null-return summary on the argument interval), tracked as
       future precision work.

  (shadPS4 was the original target; its full compile DB — 42 submodules +
  Vulkan/Qt/SDL — is infeasible in the sandbox, so the hunt used zero-dep
  codecs instead.)

## 6.6 (c1) Diff-native semantic PR review — v0 shipped (2026-07-16)

The market-facing composition layer over the validated engine:
`scripts/review_diff.sh <bin> <base-ref>` analyzes the changed files at
base (temporary git worktree + head compile commands remapped by
`review_report.py remap-db`) and at head, and emits a markdown review of
the DELTA: new findings (traces included, changed lines marked), fixed
findings, contract WEAKENED/STRENGTHENED/ADDED/REMOVED via
--summary-diff, and a coverage-honesty section. Gate = evidence ladder:
new definite findings + weakened contracts fail; new "may" warnings
report-only (--strict to gate; --gate warn to never fail the exit).

Design decisions (peer-grounded): delta computed OUTSIDE the C++ core —
zero risk to analyzer semantics and the Juliet floors (which cannot be
measured in this sandbox); the finding key is a faithful Python port of
Baseline v2 (same FNV-1a, same trimming, multiset consume) with the one
deliberate difference that the file component is repo-RELATIVE (absolute
canonical paths can never match across two checkouts) plus a rename map
(git --find-renames), so refactor PRs stay quiet. Whole changed files
are analyzed (not just hunks — analyze_diff.sh keeps that fast path), so
a change whose consequence lands elsewhere in the same file is caught.

Verification: hermetic end-to-end fixture (ctest `ReviewDiffFlow`,
scripts/test_review_diff.sh) pins the semantics — introduce/fix/weaken
verdict with exact REVIEW_RESULT counts, shift-immunity, pure-rename
silence, self-review cleanliness, and the full gate ladder
(default/--strict/--gate warn). MUTATION-tested: disabling the rename
map or the content-hash key each turns the suite red.

Known v0 limits (stated in README): header-only changes analyze no TU
(listed in the coverage section instead of silently ignored); deleted
files' base-only findings are not counted as fixed; cross-FILE
consequences of a change need --summary-in/whole-program (v0.5
candidate: auto-harvest summaries for the review pair). MCP `review`
tool and GitHub Action packaging are follow-ups.

## 6.7 (c1) trial on real upstream history — cJSON (2026-07-16)

The review flow was trialed on REAL external history: five recent cJSON
security/bug fixes (type confusion #1006, CWE-476 null deref #991,
stack-depth #984, wrong index check #957, wrong counter increment),
each reviewed in BOTH directions — the fix as a PR (forward) and the
buggy parent as a PR against the fixed base (reverse = "would we have
caught the bug at review time?").

Mechanics: 12 single-commit reviews at 0-2 s each, a 116-commit /
14-TU range review in 2 s, zero crashes, zero false gate-failures in
the forward (fix) direction. The flow holds up on a real repo with a
cmake compile DB.

**Key discovery — assumptions x delta.** The reverse review of the
CWE-476 fix (#991) with `-- --assumptions` forwarded caught the
vulnerability EXACTLY: one single new finding, "parameter 'object' is
assumed non-null (dereferenced, never checked)" at the right
function/line. The assumption engine (task #64) was parked as
high-volume by nature; the review DELTA bounds that volume to the
change — the pairing dissolves the adoption problem and is the
strongest catch-a-real-CVE-shape story the tool has. v0.5: make
assumption-delta a first-class review option.

Honest gap map from the same five (reverse direction, default rules):
1/5 caught (the CWE-476, via assumptions). Missed and why: type
confusion (needs a type-tag domain we do not model), recursion-depth
DoS (stack-depth domain), wrong-check and wrong-counter logic bugs
(spec-dependent — invisible to any analyzer without a contract to
check against). Recorded as rule-roadmap input, not spun.

v0.5 wart list from the trial: test/example-path findings dominate
range reviews (7 of 8 warnings in tests/ + readme_examples.c) — add a
path-exclude filter; the "New findings (N error, M warning)" label
says "warning" for info-severity items (cosmetic); consider assumption
delta on-by-default in review mode.

**v0.5 shipped (2026-07-16):** all three warts closed — assumption
delta ON BY DEFAULT in review mode (`--no-assumptions` opts out; the
default was decided from data: 0 new assumption findings across the
116-commit cJSON range vs. the exact CWE-476 catch in the targeted
case), `--exclude <glob>` skips changed files VISIBLY (listed in the
coverage section), and the findings label counts by true severity.
`--summary-in` composition and a GitHub Actions gate example
documented in README. The MCP `review` tool was consciously deferred:
it would force git+python orchestration into the C++ server, breaking
the zero-C++-risk layering — agents can run review_diff.sh directly.
Fixture grew to 7 phases (assumption catch + exclude, with a
no-exclude control).

## 6.8 TensorFlow Lite stress hunt (2026-07-16)

Scale test on the biggest tractable target: TensorFlow Lite via its
official CMake build (configure-only compile DB — full TF is
Bazel-locked). 285 TUs of production template-heavy C++ (kernels,
delegates, control flow), plus third-party headers pulled in by them
(Eigen, protobuf, abseil).

**Crash found and fixed (the hunt's biggest win, PR #82):**
neon_tensor_utils.cc drove getTypeInfoImpl 104,611 frames deep through
our own bufferExtent size query — SIGSEGV. Fixed with two layers:
64MB analysis worker thread (paths we don't control) +
boundedTypeSizeInChars structural budget (rule-side queries answer
"unknown" for pathological types — relax-only, no false findings
possible). The crashing TU now analyzes in 2.1s; the full 285-TU scan
completed with ZERO crashes (~25 min, sequential).

**Scan results: 106 findings, triaged by cluster:**
- **uninit-ptr, 24 errors — a NEW characterized FP class** (21 in
  TFLite's resize_bilinear.h, 3 in protobuf arena_impl.h): the pointer
  is assigned inside a CONSTANT-TRIP-COUNT loop (`for (c = 0; c < 8;
  ++c)`) that provably executes, and used after it; the engine keeps a
  loop-skip path alive that is infeasible for constant bounds. An
  ERROR-severity FP class — worst kind under our discipline. Targeted
  fix candidate: the uninit rule consuming IntervalAnalysis loop-entry
  facts (guaranteed first iteration when lo(init) < lo(bound)).
  Tracked as task #74.
- **null-deref, 71 warnings**: overwhelmingly the accessor-nullability
  shape (`subgraph->tensor(...)` may return null per its summary;
  deref follows). Honest "may" claims at warning severity; TFLite
  mediates these with TF_LITE_ENSURE macros (not noreturn), so
  assert-opacity flags (--fatal-asserts) would clear most — the
  shadPS4 round-2 lesson applies unchanged.
- **memory-leak, 10 warnings**: early-return error paths in kernels
  (rfft2d/irfft2d `fft_input_output`, interpreter
  `affine_quantization`) — the libgit2-class candidate set; each needs
  hand verification before any upstream report.
- **div-by-zero, 1 error — analyzer CORRECT, library deliberate**:
  Eigen's raise_div_by_zero divides by zero ON PURPOSE (volatile, to
  force SIGFPE); the "definitely zero" proof is exactly right, and the
  finding is the showcase for suppression comments / third-party path
  filtering, not a bug on either side.

Honest coverage: 67 of 285 TUs failed to PARSE (configure-only DB —
flatbuffer schema headers are generated at build time and absent);
those TUs are reported as errors by the tool and simply not analyzed,
never silently counted as clean. 12 functions hit the iteration cap
(abseil str_format internals) and are listed by the coverage report.

## 6.9 uninit-ptr precision: the constant-loop FP class (2026-07-16)

The TFLite hunt's 24 ERROR-severity uninit FPs (task #74) fixed with a
two-part change confined to UninitPointerRule_Ex (zero engine changes):

1. **Structural must-assign proof (suppression-only).** A pointer
   assigned unconditionally inside a constant-trip-count loop IS
   assigned when a later sibling runs, but the dataflow loses that
   proof at scale: the zero-trip path's infeasibility lives in a
   literal-stamped disjunct that the kMaxDisjuncts collapse erases in a
   large function. Rather than grow the disjunct budget (re-measured
   2026-07-16: k=8 only moves the cliff and multiplies scan time; a
   similarity-clustering collapse also failed to save the exact
   disjunct), the proof is re-established at report time the way Java's
   definite-assignment (JLS 16) reasons — structurally and
   conservatively: function free of goto/label/switch; a
   `for (i = A; i </<= B; …)` with integer literals A < B; body has a
   top-level `p = …` and NO break/continue/return/goto; the deref is a
   later sibling of that loop. Every clause is necessary; anything
   unproven keeps its report. (Investigated first as an engine widening
   fix — the raw pop-count trigger, then selective disjunct collapse —
   both reverted: the structural check is tighter and carries zero
   regression risk to other rules.)

2. **Evidence-ladder severity.** The rule previously reported EVERY
   finding as Error, including maybe-uninitialized (assigned on some
   path). That made every imprecision a false PROOF — the worst defect
   our own spec names. Now: unassigned on ALL paths = Error;
   unassigned on SOME path = Warning. This is the general defense —
   any future uninit imprecision degrades to a warning, never a false
   error — and aligns the rule with null-deref/div-by-zero.

Verification: resize_bilinear.cc 21 → 0; genuine all-paths uninit still
Error; four new unit tests pin the suppression boundary (break /
variable-bound / conditional-assign all STILL warn) + the severity
split. Referees: ctest 508/508, single-process 507/507, 12 shuffle
seeds 0 failures, corpus on-pin (cjson 53, tinyxml2 9). No Juliet floor
covers uninit-ptr, so the measured CWEs are unaffected by construction.

## 6.10 TFLite harvest to value (2026-07-16)

The 106-finding scan converted into outcomes; full rescan with the
#82+#83 binary: **106 -> 85 findings, uninit-ptr 24 -> 3** (the 21
resize_bilinear FPs gone; 3 protobuf arena_impl.h residuals remain —
out-param-under-short-circuit shape, third-party header, 1 error + 2
warnings under the new ladder — a separate look someday).

**Leak triage (10 candidates): 2 REAL, hand-verified** —
rfft2d.cc/irfft2d.cc leak the FFT work buffer on TF_LITE_ENSURE_OK
early returns (macro verified as `return s;`; delete[] only at the
end; no upstream duplicate found). Upstream issue text prepared and
handed to the user (session GitHub scope cannot post outside the
project repo). The 8 FPs fall into 4 mechanisms: unique_ptr-adoption
escape (x2) and lambda-capture escape (x3) — both cheap leak-rule
levers, task #75; aggregate-return escape (x1) and pointer-arithmetic
ownership (Eigen aligned malloc, x2) — harder residuals.

**Null-deref cluster (71): honest self-correction of §6.8.** Sampling
falsified the TF_LITE_ENSURE-opacity guess: these sites have NO check
at all — control-flow kernels (while/if/case) dereference
`subgraph->tensor(...)` bare, with null-safety resting on the
graph-validity invariant. So they are honest "may" warnings of exactly
the ASSUMPTION class; the right consumer-side treatment is a contract
on `tensor()` (zd: ensures) or a baseline — not fatal-asserts. That
our own assumption engine names precisely this gap is a coherence
data point for the AI-era thesis.

## 6.11 Bitwise/modulo interval modeling — #69a (2026-07-16)

The picojpeg null-deref FP (task #69) needs two independent pieces: (a)
proving a bitwise-masked argument is in range, and (b) a
value-conditioned null-return summary. Split accordingly. #69a lands
piece (a) as a self-contained, sound, low-risk win in IntervalEval:

  - `x & c` (constant c >= 0) -> [0, c] for ANY x (masked sign bit ->
    non-negative, result <= c); both-non-negative operands -> [0,
    min(hi)];
  - `x % c` (constant c != 0) -> [-(|c|-1), |c|-1], tightened to
    [0, |c|-1] when x is known non-negative.

Independent value on the VALIDATED spatial rules (not the null FP): the
bounds rule now sees through the mask/modulo indexing idioms both to
prove safety AND to catch an OOB the idiom's range makes definite
(e.g. `a[(src()&7) + 4]` -> index [4,11], definite OOB). Four bounds
unit tests pin it. IntervalEval also feeds DivByZeroRule (CWE369
floor), but every new interval is zero-CONTAINING, so it can never
prove a divisor non-zero and never kill a true finding; Juliet
triggered in this PR to gate it regardless. Referees: ctest 512/512,
12 shuffle seeds, corpus on-pin.

#69b (value-conditioned null-return summary + coupling interval
reasoning into NullDerefRule to actually clear the picojpeg FP) is the
cross-cutting, CWE476-floor-touching, locally-unmeasurable half — kept
separate and deferred to an explicit decision.

## 6.12 JoltPhysics hunt (2026-07-16)

The cleanest big target yet: JoltPhysics (jrouwe/JoltPhysics) is a
self-contained CMake C++17 physics engine — NO submodules, NO exotic
deps (unlike shadPS4's 42 submodules and TF's Bazel). 143 TUs of
SIMD/template-heavy real code, compile DB generated in one configure
step. Two setup traps, both solved and worth recording for future
CMake targets: (1) the DB defaulted to GCC and carried
`-Wno-stringop-overflow`, which clang rejects under `-Werror`
(`-DCMAKE_CXX_COMPILER=clang++`); (2) Jolt uses PCH, and a
configure-only tree has no `.pch` (`-DCMAKE_DISABLE_PRECOMPILE_HEADERS=ON`).
Custom allocators registered via `--alloc-functions Allocate,
AlignedAllocate,Reallocate --free-functions Free,AlignedFree`.

Results: 143 TUs, ZERO parse failures, 34 findings.
- **Spatial/numeric rules (bounds, int-overflow, uninit): 0 findings,
  0 FP** on 143 TUs of real SIMD/array physics code. Fifth independent
  precision confirmation of the v0.2 numeric class.
- **Leak rule: 31 findings, ALL false positives**, in exactly three
  modern-C++ ownership-escape mechanisms — hand-verified:
    * `return raw;` into a `Ref<T>` / `unique_ptr<T>` return type — the
      pointer is adopted by the smart handle at the return (17: every
      `*Constraint::GetConstraintSettings`, DebugRenderer batches);
    * a scope-guard macro frees it — `JPH_SCOPE_EXIT([&]{ Free(p); })`
      (~6: StaticCompoundShape stack, HeightFieldShape
      normals/material_remap_table, …), a captured-lambda free the rule
      does not trace;
    * ownership handed to a member field, freed later in `Reset()`/dtor
      (IslandBuilder temp arrays) — an interprocedural free.
- **null-deref: 3 findings = the assumption class** (BodyManager
  `TryGetBody(id)` dereferenced without a check where the id is a
  known-valid loop element; CharacterVirtual `deepest_contact`). Honest
  "may" warnings, same shape as the TFLite accessor-nullability cluster.

**Cross-codebase confirmation for task #75.** The dominant leak-FP class
here (smart-pointer-return adoption + scope-guard-lambda free) is the
SAME two mechanisms characterized on TFLite (unique_ptr adoption +
Eigen's `[ctx]{delete ctx;}`). Two independent mature C++ engines,
identical FP mechanisms — #75 is not a niche lever, it is THE modern-C++
leak-precision fix, and this hunt promotes it from "cheap" to
"highest-value leak-rule work." A third class surfaced worth adding:
RAII scope-guard macros (JPH_SCOPE_EXIT / absl::Cleanup / defer-style)
modeled as frees of their captured pointer.

No real bug (Jolt is determinism-tested, heavily used); the value is the
precision proof and the sharpened #75 case. Its clean build also makes
it a strong candidate for the deep corpus tier.

## 7. Build recipe (unchanged since 2026-07)

```bash
apt-get install -y llvm-18-dev libclang-18-dev libzstd-dev zlib1g-dev
cmake -B build -G Ninja -DCMAKE_PREFIX_PATH=/usr/lib/llvm-18 -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build          # 334/334
./build/tests/zerodefect_tests  # single-process mode, same 334
```
