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

## 6.13 Leak-rule ownership-escape FP fix (#75, 2026-07-16)

Fixed the modern-C++ leak-FP class characterized on TFLite + Jolt. The
leak rule tracked raw pointers but could not follow ownership when it
left the raw-pointer view; three shapes reported false positives on
idiomatic C++. All are now modeled as an ESCAPE (conservative — silences
the leak, never fabricates a free/UAF):

- **Owning-smart-pointer adoption.** `return std::unique_ptr<S>(p);`,
  `std::shared_ptr<S>(p)`, and adoption into a local (`unique_ptr<S>
  up(p);`) transfer ownership to the wrapper. `std::unique_ptr` /
  `shared_ptr` / `auto_ptr` are recognized built-in; project wrappers
  (Jolt `Ref<T>`, WebKit `RefPtr<T>`, Chromium `scoped_refptr<T>`) via a
  new `--owning-pointers` name allow-list. Deliberately an allow-list,
  not a blanket "constructed-from-a-pointer" rule: non-adopting views
  (`span`, `string_view`) and copying wrappers (`std::string(char*)`
  copies the bytes — the raw pointer still leaks) must NOT be silenced.
- **Scope-guard / closure capture.** A tracked pointer captured by a
  lambda (`[&]{ Free(p); }`, `[p]{...}`) escapes: the closure body is a
  separate function we do not analyze and may free/store/transfer it
  (JPH_SCOPE_EXIT, absl::Cleanup, Eigen `[ctx]{delete ctx;}`). Same
  escaped-on-opaque-call posture, applied to closures.

Implementation: `adoptedRawPointer` (peels ExprWithCleanups /
MaterializeTemporary / CXXBindTemporary / CXXFunctionalCast down to the
owning CXXConstructExpr) and `collectLambdaCaptures`, wired into
`classifyStmtEffects` ahead of the raw dyn_casts so they fire uniformly
for return-value, DeclStmt-init and bare-construct CFG elements. Pure
suppression, so no CWE401 Juliet floor risk (Juliet is C — no smart
pointers, no lambdas); the change still CI-gates Juliet via `src/**`.
Guards: 10 new unit tests (adoption cleared, genuine-leak-beside-adoption
still reported, unconfigured wrapper still reported, lambda-not-capturing
still reported). The ownership-to-MEMBER-freed-in-dtor shape (Reset/dtor)
is deferred — it needs member-lifetime modeling and is a smaller FP
source than these two.

## 6.14 #75 live validation: Jolt re-scan + ImGui hunt (2026-07-16)

**Jolt re-scan (the #75 receipt).** Same 143 TUs, same flags plus
`--owning-pointers Ref,RefConst`: **31 leak findings → 8**. The 23 that
died are exactly the two fixed mechanisms (17 smart-pointer-return
adoptions + 6 scope-guard lambdas — 100% of their instances); the 8
that remain are all the deliberately deferred third class (ownership
handed to a member, freed in `Reset()`/dtor: IslandBuilder temp arrays,
AABBTree codec arena allocators). null-deref (3) and spatial (0)
unchanged — the suppression touched nothing else.

**ImGui hunt (ocornut/imgui, 4 core TUs, imgui_demo excluded).**
Trivial compile DB (no build system needed), allocator wrappers via
`--alloc-functions MemAlloc --free-functions MemFree`. Results:
0 parse errors, ~7s. **Leak: 0 findings — and a canary proved the
domain was exercised**, not blind (an injected MemAlloc-without-free
TU reported; its paired-free control stayed silent — the libgit2
lesson, operationalized). Spatial/numeric: 0 findings (sixth
independent precision confirmation). null-deref: 17 (18 with
`--whole-program`, which correctly connected one extra cross-TU
caller), ALL warning-severity "may" findings. Triage:

- **7 = the `GetFontBaked` cluster**, one root cause: the function
  syntactically `return NULL`s, but only on the
  locked-atlas + dynamic-font-size path, straight after
  `IM_ASSERT(!atlas->Locked && ...)` fires — assert-opacity plus a
  value-conditioned null return. Exactly the #69b shape (needs
  null-return summaries conditioned on values); not upstream-reportable
  (the assert documents the invariant).
- **≥1 = a NEW analyzer FP, minimally reproduced** (see below).
- Rest = the known correlation classes: `EndTable` guards through a
  derived variable (`g.CurrentTable` non-null implies `temp_data`
  non-null), `InputTextEx` refinement lost across ~380 lines of
  branches — the #70 family, honest "may" warnings.

**New FP mechanism found: `assert(A && B)` leaks the null disjunct.**
Minimal repro (scratchpad fp78/guard3.cpp): after `if (font != NULL)`,
a standard `assert(font && font->IsLoaded())` between the guard and
the dereference RE-INTRODUCES a maybe-null disjunct on `font`
(ImGui's `SetCurrentFont` — every IM_ASSERT is this macro). Narrowed
precisely: `assert(font)` alone is fine, `assert(font->IsLoaded())`
is fine, and the SAME compound condition as an
`if (!(A && B)) __builtin_abort();` statement is fine — the bug is
specific to the `&&` short-circuit INSIDE assert's ternary expansion
(`cond ? void(0) : __assert_fail(...)`): the null-refined short-circuit
edge is not killed by the noreturn false-arm. Standard assert with a
compound pointer condition is ubiquitous → high-value engine fix,
CWE476-gated (next task).

**FIXED (#79, same day):** shared `stripBoolPreservingCasts` at all
three condition-digest points (edgeCondition, walkCondition,
refineDisjunctCondition), TYPE-based (casts to bool + pure no-ops
only) — a CastKind-based first attempt was caught wrongly "proving"
`x == 0` from `!(char)x` (Clang hides the narrowing in a
part_of_explicit_cast child) and is pinned as a negative test.
Receipt: ImGui 18 → 14 warnings, zero new; all four killed are the
IM_ASSERT-compound shape.

## 6.15 Carbon-lang hunt (2026-07-16) — the Bazel mountain, climbed sideways

User-assigned stretch target: carbon-language/carbon-lang (Google's C++
successor toolchain; modern C++20, Bazel-ONLY build, LLVM pinned to
top-of-tree). The hardest compile-DB story to date, solved WITHOUT
running Bazel — three layers, all reusable for future Bazel targets:

1. **Version-matched dependency headers.** System LLVM-18 headers
   failed everywhere (llvm::support, ConstantLog2, ArrayRef API drift).
   Fetched llvm-project at Carbon's exact pinned commit
   (MODULE.bazel git_override), CMake **configure-only** with
   clang+clang-tools-extra enabled, then built ONLY the tablegen
   header targets (`intrinsics_gen`, `Attributes.inc`,
   `clang-tablegen-targets` — 487 actions, no library build).
2. **Bazel-generated files reproduced by hand.** `llvm_tools.def` from
   a faithful Python port of its `llvm_tools.bzl` rule (30 entries;
   consumer parses clean); clangd `Features.inc` synthesized.
3. **Include-order fixes:** `-include variant` (Carbon relies on a
   transitive include our flag set doesn't produce), clangd/lld
   include roots.

Parse coverage: 95 → 207 → **218/286 TUs (76%)**. The honest ceiling:
**63 TUs (check/sem_ir/lower — the semantic core) use an in-class
member-variable-template explicit specialization (`kind_switch.h`)
that the clang-18 parser rejects** — needs clang ≥19. Concrete,
measured motivation for an LLVM-19/20 upgrade task. 5 singletons
(gmock, Bazel runfiles, …) not worth chasing.

Scan: 218 TUs, 19m38s, `--fatal-asserts CheckFailImpl` (CARBON_CHECK's
fail fn is [[noreturn]] only under NDEBUG — the shadPS4 lever, exactly
as designed). **Zero analyzer errors/crashes** on the heaviest
template code we've ever parsed. 16 findings, all warning severity:

- **15 are in LLVM/clang HEADERS, not Carbon code** (Casting.h `isa`
  family, MathExtras.h divide helpers — documented caller-contract
  preconditions). Product insight: findings in DEPENDENCY headers
  should be filterable (`--report-paths <root>`-style); today the only
  tool is post-hoc JSON filtering. Task candidate.
- **1 is in Carbon proper, hand-verified REAL:**
  `toolchain/check/cpp/export.cpp` `ExportClassToCpp` —
  `ExportNameScopeToCpp` returns nullptr on its
  non-identifier-package-name TODO path (`Context::TODO` returns bool,
  diagnose-and-continue), the SIBLING caller checks
  (`if (!decl_context) continue;`), but ExportClassToCpp passes the
  result unchecked into `CXXRecordDecl::Create`,
  `isa<CXXRecordDecl>(decl_context)` (asserting) and
  `decl_context->addHiddenDecl(...)`. The compiler emits the TODO
  diagnostic, then crashes instead of continuing — the shadPS4 #4703
  shape (contract honored in one caller, forgotten in the other).
  **Reported upstream:
  [carbon-lang#7523](https://github.com/carbon-language/carbon-lang/issues/7523)**
  (2026-07-16, user-filed via prefilled toolchain-bug template).

Coverage honesty: the leak domain produced 0 findings here without a
canary (Carbon allocates via ASTContext arenas — little raw new); the
domain was canary-proven live on ImGui the same day with this binary.

## 6.16 Recall study: Carbon's open toolchain bugs vs our rules (2026-07-16)

User-proposed methodology inversion: every hunt so far measured
PRECISION (are our findings real?); this study measures REAL-WORLD
RECALL — take the known open bugs and ask "why didn't WE find them?"
Corpus: 33 of the 36 open `label:toolchain` issues (3 uncollected —
pagination summarizer losses; noted honestly).

**Classification.** 25/33 are out-of-domain by construction: language
semantics (#7159 negative floats, #7064 const-eval, #6991/#6913/#5750
generics), feature requests (#6717/#6680/#6655), infra/perf/UX
(#5223/#5037/#4944/#3054...). No memory-safety analyzer — ours, CSA,
Infer, Coverity — targets these. The remaining 8 are CRASHES, our
domain candidates. Verdicts:

| Issue | Mechanism | Location | Verdict |
|---|---|---|---|
| #7371 | CHECK `const_id.is_concrete()` | lower/function_context.cpp:190 | invariant violation, behind parse ceiling |
| #6862 | CHECK `const_id.is_concrete()` | lower/function_context.cpp:187 | same family |
| #6905 | FATAL "missing constant value" | lower/handle_call.cpp:551 | same family |
| #6553 | FATAL "missing constant value" | lower/handle_call.cpp:492 | same family |
| #7162 | CHECK `poisoning_loc_id.has_value()` | check/name_lookup.cpp:703 | invariant violation |
| #7160 | crash, no stack (var binding) | check/? | unattributable, likely CHECK |
| #6500 | impl-selection logic error | check | out-of-domain (semantics) |
| #7157 | SIGSEGV, **no stack** | ? | the ONE possibly-in-domain crash; indeterminate without attribution |

**The finding of the study: 7 of 8 real-world crashes are
CARBON_CHECK/FATAL failures** — Carbon's own runtime invariants
catching semantic states that specific LANGUAGE INPUTS drive the
compiler into. Statically proving "input X makes `const_id`
non-concrete at this CHECK" requires modeling Carbon's own language
semantics — out of scope for ANY general-purpose analyzer; these bugs
are found by fuzzing and users, not by dataflow. They also cluster in
`lower/` — behind our clang-19 parse ceiling regardless.

**Three consequences:**
1. **The niches are complementary, not competing.** Users report
   input-TRIGGERED invariant violations; we find LATENT contract bugs
   on paths no input has exercised yet — our #7523 (unchecked null
   return, sibling caller checks) is exactly the class absent from all
   33 user reports. Zero overlap = zero redundancy.
2. **The parse ceiling is the binding constraint on recall,** not rule
   sensitivity: the crash cluster lives in lower/ + check/, mostly in
   the 63 unparseable TUs. LLVM-19/20 upgrade remains the recall lever
   for this codebase.
3. **CHECK invariants ARE contracts** — enforced far from where they
   are established. An analyzer that ingests CHECK conditions as
   callee preconditions and asks "which caller can violate this?" is
   the growth path past memory safety — direct evidence for the
   contract-layer direction (§4.A), from the largest C++ project we
   have touched.

**Ground-truth extension (closed+fixed issues).** Fixed bugs beat open
ones for recall measurement: the fix commit tells you exactly which
line was wrong. Probe case #7142 (closed 2026-06): a real SIGSEGV —
Carbon-function-returning-pointer called from C++ — whose fix (PR
carbon-lang#7359) added NO null check; it refactored object LIFECYCLE
(a stale reference through `MultiplexExternalSemaSource` after
`CarbonExternalASTSource` was removed early). Classification: temporal
memory safety — our UAF rule's domain in SPIRIT, but cross-object
registry lifetime is beyond the per-variable heap-state abstraction;
today we honestly go silent when a pointer ESCAPES, and this class
requires FOLLOWING the escapee. Recorded as the measured target for
any future escape-tracking work.

**Standing methodology going forward** (user-proposed, adopted): every
hunt gains a recall half — alongside "scan and triage our findings,"
also "triage the target's known bugs (open AND closed+fixed) and
attribute every in-domain miss to parse coverage, abstraction, or rule
gap." Even one attributable miss is a measured engine task; a hit on a
pre-fix revision is a recall pin candidate for CI.

## 6.17 #69b value-conditioned null-return summaries (2026-07-16)

The picojpeg FP (`getHuffVal(pHuffVal, idx)` at readDHTMarker:542) had
survived every engine improvement because it needs an INTERPROCEDURAL
value argument: the callee returns null only in its switch DEFAULT,
and every caller's index expression provably lands in a case. Three
pieces, each individually reusable:

1. **Conditioned summary** (`nullCondParam`/`nullCondRange`): harvest
   "null ONLY IF param outside R" from switch-default and
   if-comparison guards. Strict harvest discipline — exactly one
   structurally-null return, contiguous case constants, param never
   mutated, `switchHasNoFallthrough` (flat-body scan; goto/continue
   bail). `stripBoolPreservingCasts` (#79's helper) reused in the
   comparison-guard matcher — the shared-skeleton bet paying off.
2. **Sole-definition intervals for integers**: the heap extents'
   sole-def discipline applied to locals. Declaration-init OR the
   uninitialized-then-single-assignment C idiom both qualify;
   any second write, ++/--, or address-taken disqualifies (absent =
   consumers prove nothing — sound).
3. **Value-based narrowing fit**: `evalInterval` with ASTContext
   passes a narrowing IntegralCast through when the operand interval
   fits the destination range. CastKind-blindness was the last
   soundness-preserving gap; value-based is the correct fix (the #79
   lesson — kinds lie, types and values don't).

Development shape worth recording: the reduced repro passed while REAL
picojpeg still fired, three times, and each gap was found by diffing
real source against the repro — `return t0;` array-decay in vstateOf,
the declare-then-assign idiom, the uint8 narrowing. The receipt
discipline (re-scan the ORIGINAL corpus, not the repro) is what
converted "tests pass" into "the FP is dead": **picojpeg 1 → 0**.

Honest non-result: ImGui stays 14 → 14. The GetFontBaked cluster
hinges on opaque `ImFontAtlasBakedAdd` — a MaybeNull with no body to
harvest a condition from. Different mechanism, different task.

Disk format v3 (condition column), version-strict parsing, merge drops
conditions on cross-TU disagreement. Gate: CWE476 Juliet floor.

## 6.18 #70 guard-implication mining (2026-07-16) — the cross-product wall, half torn down

The stb_image `tga_palette` FP's mechanism (§ scan of 2026-07-15) was
DISJUNCT-BUDGET EXHAUSTION: ≥4 independently guarded pointers need
2^4 disjuncts to keep every guard correlation as an explicit path
split; `kMaxDisjuncts = 4` forces `widenGuarded` to collapse, and the
collapse erased ALL correlations. The fix is the ROADMAP's own
prescription — a per-variable guard representation:

1. **Mined implications.** At every collapse point (cap-overflow in
   joins AND the engine's convergence widening) a miner scans the
   pre-collapse disjuncts: if every disjunct compatible with fact F=v
   knows pointer p NonNull, the collapsed value carries
   `F=v ⟹ p NonNull`. Linear: N guards = N implications in one
   disjunct. An assume-edge that records F=v activates the
   implication; assignment to p or to F's variable drops it.
2. **Fact-aware meets.** Same-facts disjunct merges combine values
   UNDER the shared fact map (`GuardedOps.meetVal`): an implication
   whose condition the shared facts CONTRADICT holds vacuously and
   survives the meet. Without this, one fact-blind drop re-merged
   into every later join — measured on the tga loader: 13 seed drops
   cascaded into ~1300, leaving no implication alive anywhere.

Receipts: the 4-pointer scale repro 5→0; every reduced tga shape
(single guard + RLE/read-next noise, call-initialized flag,
assignment-derived flag) clean; all five negative controls still
warn; a measured FALSE NEGATIVE fixed for free (`if (fa) a = alloc();
if (fa) a[0]` with no failure check now warns — sharper disjuncts
carry the MaybeNull); 551/551 tests; no perf cost (stb corpus 1.8 s →
1.3 s).

**Honest residual, precisely diagnosed:** the verbatim
`stbi__tga_load` still yields its warning (stb corpus 1→1 vs main).
Bisection receipts: deleting the POST-deref inverted-swap loop
silences it, and so does merely RENAMING that loop's reused `i`/`j`
counters — the report depends on iteration order, not on the value
domain. Root: ACCUMULATIVE widening (`widenMemory` joins each visit's
entry with the previous widened entry) mixes iterates; an
early-iteration state that lost the implication before it matured
keeps re-entering every later collapse, and the miner cannot
re-derive it once a MaybeNull-without-implication copy sits in the
group. This is a known cost of widening-without-narrowing. Two
candidate levers, both out of #70's scope, recorded as the next
engine task: a NARROWING (descending) pass after the widened
fixpoint, or provenance-carrying implications (valid-from-block +
dominance check at activation).

## 6.19 #84 implication witness (2026-07-16) — the residual, dead by ablation

The #70 residual (verbatim `stbi__tga_load` still warning) fell to a
diagnose-then-ablate session worth recording for its METHOD as much as
its fix.

**Two principled ideas failed first, with receipts.** The 6.18 hunch —
"accumulative widening mixes immature iterates; add a narrowing pass"
— was implemented (descending re-propagation of the plain flow
equations from the widened fixpoint, budgeted, wholesale fallback) and
measured: the descent STABILIZED IN ONE SWEEP with the FP intact. The
widened solution was self-consistent — temporal blending, once folded
in, satisfies the very equations a narrowing pass re-checks. A
two-stage widening (memoryless collapse first, accumulative join only
as escalation) also changed nothing. Both were REMOVED from the
branch: the discipline is that a mechanism ships with a receipt or
not at all.

**The actual chain, pinned by disjunct-level tracing** (env-gated
dumps at every collapse, phase- and block-stamped): the miner's
non-vacuousness gate demanded an EXPLICIT `key=wanted` recording among
the collapse inputs. In the tga loader the prologue tests `indexed`
early (comp selection), so by the mid-loop collapses every disjunct
still carrying an explicit indexed fact carried `indexed == 0` — the
indexed-SIDE existed only inside already-mined implications. The gate
refused the witness, the implication died at every such collapse
(1585 of 1591), and the guarded deref decayed to MaybeNull.

**Fix: an implication-carrying input IS a witness** — proof a real
partition mined it upstream; preserving it is not vacuous. One
condition in the miner. Ablation matrix over three candidate fixes
(refinement-keeps-implication, leaf-level domain-refuter drop,
witness): witness alone is NECESSARY AND SUFFICIENT for the receipt;
the other two moved nothing and were dropped from the diff. Both
remain honest candidates: the leaf-refute drop kills a real phantom
(a `{flag==0, palette Null}` disjunct surviving a `palette != NULL`
true edge as `{flag==0, NonNull}` — path-empty hybrid), but with no
measured receipt it stays out per the same discipline.

**Receipts**: verbatim stbi__tga_load standalone 1 → 0; stb corpus
tu_image.c 1 → 0 (stb_image.h:6004, our longest-lived real-world FP,
dead); tu_resize.c 2 → 2 (last_decoded/info — a different, pre-#70
class, untouched); all 8 #70 negative controls still warn; the full
trimmed loader is pinned as a regression test that FAILS without the
witness clause (verified against the pre-fix binary). 552/552 ctest,
12/12 shuffle seeds.

Measurement honesty note: multi-file positional invocations analyze
only the FIRST file (the "stb corpus 1→1" line in PR #90 was
first-file-only). Per-TU scans are the honest form; recorded here so
future receipts don't repeat the mistake.

## 6.20 #85 LLVM 20 (2026-07-17) — the recall lever, pulled

The 6.16 recall study's binding constraint is gone. The upgrade cost
NOTHING in source (LibTooling surface identical 18→20; the whole
project built as-is on the first try) and bought the exact door the
study pointed at:

- **Carbon: 218/286 → 280/286 TUs parse** (same include set, same
  probe, clang-18 vs clang-20 side by side). All 63 TUs of the
  "constexpr data member" ceiling — the `check/` + `lower/` semantic
  core where 7 of 8 real-world crashes clustered — now parse. The 6
  stragglers are Bazel-generated-header gaps, not language level.
- `toolchain/check/call.cpp` (previously unparseable) analyzes
  end-to-end; its 11 findings are all dependency-header noise, i.e.
  --report-paths input — the Carbon re-hunt over the opened core is
  now a straight scan job, queued behind the Godot hunt.

Juliet floors were tuned on the 18 frontend; the PR's gate run on the
20 frontend is the real referee for the bump (local ctest — including
the corpus pins — passed unchanged, which is the strong prior).

## 6.21 #86 Godot hunt, round 1 (2026-07-17) — two engine deliverables before the first real finding

The hunt's opening hours produced tool work, exactly as the libgit2
and shadPS4 hunts did:

1. **Static-local model** (GDCLASS DCL flood): decl-inits of static
   locals are once-per-program; modeling them per-call fabricated
   "definitely null" at thousands of macro expansion sites.
2. **Broken-TU guard**: the first scan ran against TUs missing
   Godot's build-generated headers — clang error recovery silently ate
   initializers, and 298 of 311 findings were confident nonsense from
   ASTs of code that does not exist. TUs that fail to compile are now
   skipped and honestly listed. This guard matters beyond hunts: the
   AI-generated-code mission analyzes exactly the kind of code that
   often does not compile, and "unreliable AST" must be a stated
   coverage gap, not a silent precision leak. (Field note recorded:
   scons compiledb produces the DB without building — the .gen.h
   fixpoint loop in the scratchpad builds the 6 needed headers in
   seconds.)

Round-1 scan state: 176 core/ TUs, 0 broken, 18 findings. Standing
candidates: gdextension.cpp sibling-evidence null contract (report
candidate), convex_hull.cpp cluster (deep verify + recall tie-in:
upstream has convex-hull crash reports), file_access.cpp null+zero-
length loop (measured FP class: var-vs-var loop bound with the
zero-length fact already recorded — conditionFact keys var-vs-CONST
only). Recall half not started.

## 6.22 #86 Godot hunt, round 2 (2026-07-17) — deep-verify + recall cross-check, honest negatives

Round 2 hand-verified the 18 round-1 findings and ran the recall half.
The result is a clean pair of documented NEGATIVES — no upstream
report — which is itself the deliverable: precision held, and the one
recall opportunity was attributed, not hand-waved.

**gdextension.cpp (3 findings) — non-report, implicit contract.**
`p_object->_get_extension_instance()` after an `is_static() ? nullptr
: p_object->...` — the author's OWN `p_object && p_object->is_...`
placeholder guard proves p_object is considered nullable, then the
non-static path dereferences it unguarded. But the NATIVE MethodBind
siblings (method_bind.h:224/260) have the identical shape: the engine-
wide invariant is `p_object != null unless is_static()` — a relational
precondition callers satisfy, not a bug. Documented as §4.A contract-
layer evidence (this is literally `requires p_object != null unless
is_static()`), not filed.

**convex_hull.cpp (9 findings) — all FP, disjunct-budget exhaustion.**
Hand-traced every one. Two correlation shapes the #70 miner does not
capture, both inside `merge()`/`merge_projection()` — 235-line internal
geometric routines with 10+ interacting pointer locals that blow past
kMaxDisjuncts = 4 (the tga_palette scale wall, pre-miner):
  1. constant-trip-count loop, first iteration assigns: `for (side=0;
     side<=1) if (side==0) { v00=v0; v10=v1; }` then `v00->next` — the
     side==0 body always runs, but the loop join re-enters with
     v00=null. (The NullDeref cousin of #74's resize_bilinear.)
  2. integer-encodes-nullness: `cmp = !min0 ? 1 : (!min1 ? -1 : cmp())`
     then `if (cmp>=0) min1->x` — cmp>=0 with min1 null gives cmp=-1,
     excluded, so min1 is non-null there; the correlation runs through
     a derived integer the disjunct facts do not key.
Minimal reductions of BOTH come out clean — our engine handles the
simple shapes; the FPs need the full context. Not fixed this round:
one giant internal file, and the right lever is a larger engine task
than the finding density justifies. Recorded as a measured target.

**Correction (2026-07-17, deeper diagnosis).** The "disjunct-budget
exhaustion" attribution above was WRONG, and disproving it is the
lesson: raising `kMaxDisjuncts` 4 → 16 left all 9 findings unchanged.
It is not scale — it is three distinct correlation-shape gaps, pinned
by disjunct tracing at the deref sites:
  1. **v00/v10 (2)** — loop-first-iteration definite assignment. At the
     `v00->next` deref the state is a SINGLE disjunct `{side<=1=false,
     v00=MaybeNull}`: the loop provably ran (`for(side=0;side<=1)`, so
     `if(side==0)` fires on trip 0 and assigns), but the "did trip 0
     run" distinction is gone. This is #74's class one level harder —
     the must-assign sits under `if(loopvar==initliteral)`, not
     top-level, AND the loop body's `break`/`continue` target INNER
     `while` loops (they never bypass the assignment), which #74's
     coarse `hasEarlyExit` cannot tell apart. A sound fix needs
     loop-precise break/continue targeting + first-trip if-guard
     reasoning, ported to NullDeref.
  2. **min0/min1/pending… (5)** — integer-encodes-nullness through a
     `cmp` ternary, plus linked-list edge invariants.
  3. **face_edge/first_face_edge (2)** — linked-list traversal
     invariants; likely beyond a sound per-variable abstraction (CSA/
     Infer would struggle too).
Verdict: three specialized sound mechanisms for 9 FPs in one internal
geometry file — the round's own "lever > density" call holds, now with
the budget hypothesis retired. Deferred by decision (2026-07-17) in
favor of the contract-language work (§4.A); kept as a measured target,
the tractable slice being (1).

**Recall cross-check — NEGATIVE, attributed.** Two open convex crashes
exist upstream and live in this exact file's call graph: #60337
(`ConvexPolygonShape.get_debug_mesh` → find_max_angle:1168 assertion
`p_ccw ? t.dot(p_s)<0 : t.dot(p_s)>0`) and #60357 (`create_convex_
shape` → vhacd voxelize OOB). BOTH are NaN/INF-float-driven
assertion/OOB failures found by the Qarminer fuzzer — value-domain
float reasoning we do not do, and CHECK/assert-invariant violations
driven by specific inputs. This is the SAME conclusion as the Carbon
recall study (§6.16): the real-world crashes are input-triggered
invariant violations (fuzzer + user territory), orthogonal to the
latent contract bugs a dataflow analyzer finds. Our 9 findings share
the file but not the mechanism — no overlap, honest miss, filed under
the standing "float value-domain + input-driven CHECK" gap.

**Round verdict.** Precision held on the largest C++ codebase touched
(0 real findings survived, but 0 false reports filed); the two engine
deliverables were round 1 (static-local, broken-TU guard); recall
produced a clean attributed miss. The hunt's honest yield is the
broken-TU guard — a precision mechanism the whole project now carries.

## 6.23 #89 Guard-as-contract v1 (2026-07-17) — the code's own guard becomes a checked contract

**The §4.A increment, demonstration-driven.** Three real-world evidence
points converged on one shape (Carbon's CARBON_CHECK preconditions
§6.16, Godot's `ERR_FAIL_COND_V(!p_object && ..., ...)` placeholder
guard §6.22, and `FileAccess::store_buffer`'s
`ERR_FAIL_COND_V(!p_src && p_length > 0, false)` §6.21–22): a
function's OWN entry guard is a precondition the code already enforces
at runtime — but only locally. #89 lifts it into a checkable contract
and asks the interprocedural question no compiler asks: **which caller
violates the callee's own rule?** No annotation, no sidecar — the
guard IS the contract.

**Two user design decisions shaped v1 (2026-07-17).**
1. **Severity by consequence class**, not by confidence alone. The
   guard's KIND tells you what a violation DOES:
   - `Crash` (assert ternary, or an if-guard that aborts/throws): the
     check vanishes in NDEBUG builds or kills the process — a
     violating call crashes or is UB. Definite violation → **error**.
   - `Rejected` (if-guard that returns): the check is always compiled
     in; the callee refuses and the call silently does nothing — a
     logic bug (the caller believes work happened), not a crash.
     Definite violation → **warning** ("this call will always be
     refused").
2. **No overlap with compiler warnings.** v1 deliberately takes only
   the compiler-silent slice: null-pointer preconditions. Narrowing /
   int64→int32 argument mismatches are `-Wconversion` territory and
   are EXCLUDED — we do not add to warning chaos the compiler already
   covers. Extension beyond this slice waits on the user's verdict
   ("beğenilirse geliştiririz").

**v1 recognizer** (`src/contracts/GuardContracts.{h,cpp}`): scan the
LEADING statements of a body (DeclStmts tolerated between guards; the
first real statement ends the entry region — a guard below other work
proves nothing about entry). Two shapes: `if (<p is null>) <branch
that provably does not fall through>` (the ERR_FAIL expansion — a
CompoundStmt is decided by its LAST statement, matching
`{ print; return v; }`) and the glibc assert ternary
(`cond ? void(0) : __assert_fail(...)`). One parameter per condition;
a compound condition (`!p && n > 0`) is structurally detected and
SKIPPED — walkNullCondition's `&&`-decomposition makes it look like a
clean single hit, and accepting it would fabricate an unconditional
requires the code does not enforce (the store_buffer lesson: that
guard does NOT fire for p==null when n==0). Relational lifting is
v-next.

**Caller-side wiring** (NullDerefRule): memoized per-callee inference;
a param covered by a DECLARED contract is skipped (the author's clause
wins — no double report); DEFINITE violations only (literal
null/nullptr argument, or a flat-state Null variable) — zero
possible-violation noise in v1; callers with no pointer locals of
their own still wake the pass. Messages carry the callee name and the
guard's line so the report reads as "violates X's own entry assert
(line N)".

**Receipts.**
- End-to-end 4-scenario TU: `crash_callee(nullptr)` → ERROR
  (assert-guard, "in builds where the assert is compiled out this
  call crashes"); `reject_callee(nullptr)` → WARNING ("will always
  refuse this call"); declared-contract param single-reports; clean
  calls silent.
- 8 new pins (assert/if-return severities, definite-null variable,
  maybe-null NOT reported, compound guard NOT lifted, non-entry guard
  ignored, declared-contract precedence, no-pointer-locals caller
  wake). 574/574 ctest, 5/5 shuffle seeds; tga + picojpeg receipts
  0/0 unchanged.
- **Godot noise check: 0 new findings** across the 6 hunted core
  files (file_access, input, worker_thread_pool, image, convex_hull,
  resource_loader). Honest reading: mature in-tree callers do not
  violate their own guards — the yield of this feature is for
  AI-GENERATED callers of guarded APIs, the project's mission target;
  its in-tree value is that it costs nothing (zero noise).

**The cJSON lesson (first CI run, corpus referee).** The initial
if-return arm accepted ANY non-fallthrough return branch — and the
cJSON corpus pin jumped 53 → 88. All 35 extras were the same class:
silent early returns on null-TOLERANT APIs. `cJSON_IsInvalid(NULL)`
→ false is the documented answer to a legitimate question;
`cJSON_InitHooks(NULL)` MEANS "reset allocators to defaults" — the
null branch does the function's work. Their callers (the library's
own tests) pass null deliberately. The correction: **refusal evidence
requires the guard to COMPLAIN before returning** — an
expression-statement call (error report) before the terminal return,
exactly the ERR_FAIL expansion (`{ _err_print_error(...); return
ret; }`) that motivated the Rejected class — or to die. Bare returns
and work-then-return infer nothing; a branch whose only call is
inside the return value (`return make_default();`) is alternative
work, not a complaint. The corpus pin stays at 53: the feature
narrowed to fit the evidence, the referee floor did not move. This is
the ablation discipline working as designed — the corpus caught in
one CI run an FP class the 6-file Godot noise check could not see
(Godot's guards all complain; C null-tolerant-API style does not).

**v-next menu (awaiting the "beğenilirse" verdict):** possible-
violation warnings (maybe-null args), relational/compound guard
lifting (`!p && n > 0` → `requires p != null unless n == 0`, reusing
the declared-contract relational machinery), cross-TU transport via
the summary store, configurable guard-macro names.

## 6.24 #91 Carbon re-hunt + CHECK transparency (2026-07-17) — the §6.16 opacity gap, easy half closed

**Setup.** LLVM 20 re-opened Carbon: 280/286 TUs parse (was 218 at
#80; the 6 fails are generated-file/env). Motivation: demonstrate
guard-as-contract (#89) on the corpus whose CARBON_CHECK idiom
motivated §4.A, and re-measure precision with the season's fixes.

**The probe-driven chain.** A hand probe (`CARBON_CHECK(n != nullptr)`
callee + `nullptr` caller) failed to fire, and peeling the onion
produced four distinct findings:
1. **CheckCondition opacity** — CARBON_CHECK wraps every condition in
   an exact-identity function (`return condition;`, exists only for
   constant-condition diagnosis). Fix: identity-call transparency in
   walkCondition (condwalk_detail::identityCallArg) — same class as
   __builtin_expect, proven by body instead of trusted by name. This
   is engine-wide: assume-edges AND the guard recognizer see through.
2. **`true && (cond)`** — literal-true conjunct peel in the
   recognizer (walk handles && natively; the peel is for the
   compound-bail).
3. **Conditional [[noreturn]]** — CheckFail is noreturn only under
   NDEBUG; every build's body is a single call to noreturn
   CheckFailFormat. Fix: transitive noreturn (visible body provably
   aborts, depth-capped). HONEST LIMIT: in the debug parse the chain
   ends at a declaration-only maybe-returning impl — Carbon's
   non-fatal-checks debug flag makes "may return" CORRECT there; the
   scan answer is -DNDEBUG (shipped semantics), not a recognizer
   guess.
4. **Dedup key lacked the callee** — same-line calls to different
   guarded callees collapsed to one report.

**Ablation receipts (280 TU).** Baseline (merged #89 binary) 7
findings → new binary, same flags: identical 7 (transparency adds
zero noise) → -DNDEBUG: **4** — the three `CARBON_CHECK(ptr)` FPs
(import.cpp:746, facet_type.cpp:393, lower/type.cpp:712) die exactly
as predicted, nothing else moves. Findings identical across all three
scans before the fix landed — parse-mode-stable.

**Survivor triage (4).**
- `export.cpp:169` — **TP-quality**: ExportNameScopeToCpp has an
  explicit `return nullptr;` TODO path (keyword package names);
  caller CHECKs the sibling identifier_info but dereferences
  decl_context unguarded. Alive since #80; both parse modes agree.
- `eval.cpp:2811`, `import_ref.cpp:2548` — the KNOWN
  flag-encodes-nullness correlation gap (evaluation_mode/thunk-state
  set iff pointer set; §6.22 convex_hull family). Honest FPs, class
  on file.
- `call.cpp:108` — NEW leak FP class: **placement `new (arena) T`
  treated as an owning allocation**. ASTContext-arena nodes are never
  individually freed. FIXED (#91b): placement-new detection now treats
  a non-pointer, non-`std::nothrow` class placement arg as arena
  storage; Carbon 4 → 3.
- In-tree guard-as-contract violations: **0** (same honest zero as
  Godot — mature code doesn't pass literal null into its own guarded
  APIs; the feature's yield is AI-generated callers).

**Tool-side lessons banked.** `--` fixed-database flags are silently
dropped (scans must use a compile DB; backlog); the multi-file
positional mode only analyzes the first file (known); one unreproduced
single-run anomaly (a crash-class finding absent once, 240/240
deterministic since) noted for watch.

## 7. Build recipe (unchanged since 2026-07)

```bash
apt-get install -y llvm-18-dev libclang-18-dev libzstd-dev zlib1g-dev
cmake -B build -G Ninja -DCMAKE_PREFIX_PATH=/usr/lib/llvm-18 -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build          # 334/334
./build/tests/zerodefect_tests  # single-process mode, same 334
```
