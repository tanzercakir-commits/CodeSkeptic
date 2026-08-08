# Benchmarks & measurement methodology

Every number CodeSkeptic publishes is reproducible from this repository
with one command — the same scripts CI runs. If you don't want to take
our word for it (you shouldn't), run them:

```bash
bash scripts/run_juliet.sh ./build/src/codeskeptic juliet-work 400   # Juliet suite
bash scripts/run_corpus.sh ./build/src/codeskeptic corpus-work      # real-world corpus
python3 scripts/token_ablation.py                                    # token measurement
```

## Two axes, deliberately separate

Precision on **mature code** and recall on **first-draft code** are
different axes; optimizing one silently starves the other (we learned
this the hard way — see the devlog). CodeSkeptic tracks both:

- **NIST Juliet 1.3** (synthetic, mature-code shapes) — per-CWE
  precision/recall with pinned CI floors.
- **The thesis corpus** (24 first-draft programs by rule-blind
  generators, frozen in `tests/thesis_corpus/`, adjudicated manifest)
  — the mission axis, gating every PR: **0 FP across 9 genuinely-clean
  programs, 9/9 in-scope bugs caught**; out-of-scope misses pinned and
  documented (`scripts/run_thesis.sh`).
- **Real-world corpus** (cJSON, tinyxml2, weekly abseil) — pinned
  finding counts; deviation = semantic regression.

## PR measurement laboratory

Every pull request runs `.github/workflows/measurement.yml` against the exact
PR base SHA and head SHA. Both analyzers are built independently, then the
same head-owned harness measures three deliberately separate corpora:

- `clean`: the nine adjudicated clean thesis programs; any new finding is a
  false-positive regression and fails the gate;
- `defective`: the fifteen adjudicated defective thesis programs; caught-case
  recall and each case's minimum finding floor may not drop;
- `real-repository`: CodeSkeptic's own `src/` tree, analyzed from its real
  compilation database with the product's self-scan policy enabled.

The machine receipts record findings and per-rule counts, attempted/analyzed/
broken TUs, incomplete functions, wall time, peak RSS where the platform
provides GNU `time`, and stable finding fingerprints. `compare_measurements.py`
publishes quality, performance, coverage and fingerprint deltas in the PR job
summary and uploads the exact base/head/delta JSON plus Markdown for 14 days.
Unavailable analysis, broken TUs, lost TU coverage, a clean-corpus finding
increase, or a defective-corpus recall/floor loss fails closed. Runtime and
memory deltas are visible evidence in Phase 2, not noisy threshold gates;
Phase 10 owns the measured performance budgets.

Each finding has a `csf1-` semantic site identity. Schema `csf1` hashes the
rule ID, the last three normalized path components, function name, and source
statement with formatting whitespace removed outside literals. Checkout root,
line/column, severity and message wording are excluded, so a harmless line
shift or presentation change does not manufacture a new finding. It is an
identity key rather than a security hash; duplicate sites are retained as
multiset counts. The C++ implementation and an independent Python oracle must
agree on every head finding before a receipt is accepted.

The Juliet lane separately emits a six-rule precision/recall/F1 dashboard.
Every false negative is partitioned into exactly one product-decision class:
`addressable` (`baseline`, `other`), `model_gap` (`multifile`, `flow`, `cpp`),
or `out_of_scope` (`float`, `opaque`). The detailed `JULIET_FN_CLASS` rows stay
available for engine work; `JULIET_MISS_CLASS` is the complete three-way
product view. `scripts/measurement_baseline.json` binds dashboard deltas to an
exact analyzer tree, workflow run and sample limit.

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
| CWE-416 Use After Free | `use-after-free` | **1.000** (198 TP / 0 FP) | 0.496 | **0.663** |
| CWE-476 NULL Pointer Dereference | `null-deref` | **1.000** (140 TP / 0 FP) | 0.347 | **0.516** |
| CWE-415 Double Free | `double-free` | **1.000** (97 TP / 0 FP) | 0.242 | 0.390 |
| CWE-401 Memory Leak | `memory-leak` | 0.714 (case-level) | 0.193 | 0.306 |
| CWE-369 Divide by Zero | `div-by-zero` | **1.000** (43 TP / 0 FP) | 0.108 | 0.195 |
| CWE-190 Integer Overflow | `int-overflow` | **1.000** (21 TP / 0 FP*) | 0.052 | 0.100 |

<sub>* The CWE-190 rand-source family reaches the sink through a
bit-shuffle macro the interval evaluator cannot fold — a documented
known false negative — so the sampled recall stays deliberately
conservative while precision is perfect.</sub>

**Where the misses live — the FN classification.** Every missed case
is bucketed by its variant name (`JULIET_FN_CLASS` in the CI output;
`scripts/juliet_eval.py`), so the recall numbers carry their honest
denominator. Reading div-by-zero as an example: of 360 missed cases,
158 are floating-point variants (IEEE 754 division is defined
behavior — deliberately silent) and 81 are opaque sources (`rand()`,
sockets — an honest analyzer cannot call them zero); the remaining
~120 addressable misses are dominated by flow-through-calls variants,
the next recall target. CWE-190's map is similar: 179 opaque
rand-family cases by design, the rest addressable and shrinking (the
v0.4 round covered `+`, 64-bit and narrowing-store shapes: recall
0.010 → 0.052 at precision 1.000).

The journey these numbers took: targeted path-sensitivity
(2026-07-10) cut false positives across rules (memory-leak 92 → 61,
uninit-ptr 178 → 84, cross-file null-deref noise 241 → 129) and
*surfaced previously missed true positives* — correlated-guard double
frees and use-after-frees (+107 TP combined) were false negatives
under merged-path analysis. Cross-TU summaries (`--whole-program`)
connected source/sink flows split across files. Guarded disjuncts v2
(2026-07-12) added call-condition keys, a flow-sensitive fact
lifecycle with constant stamping and entailment, disjunction
elimination for value-materialized asserts, and engine-level
convergence widening. The v0.4 recall round (2026-07-22) worked from
the FN classification: int-overflow grew from signed 32-bit `*` to
`+`, 64-bit corner proofs and narrowing stores (0.010 → 0.052);
div-by-zero zeroness now flows through var-to-var copies and, for
fully-visible internal callees, across call boundaries
(0.093 → 0.108); and immutable-flag constant propagation prunes
provably-dead branches engine-wide — the goodB2G flag-correlation FP
family died (leak precision 0.684 → 0.714 on the 400-file sample,
cross-rule noise down on three other CWEs at once). A caveat on
cross-rule findings: Juliet
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

Results are from the 2026-07-22 run (v0.4.1, 400 files/CWE); grep
`JULIET_RESULT` in the workflow logs for current numbers. Every
improvement is locked by a ratcheted floor in
`scripts/juliet_expected.txt` (CWE-190 recall 0.005 → 0.040, CWE-369
0.03 → 0.095, CWE-401 precision 0.66 → 0.68) — the guard file's
comments carry each move's rationale.

## Current-engine real-world replay ledger

The canonical executable expectations live in
[`scripts/realworld_expected.txt`](../scripts/realworld_expected.txt).
The real-world workflow reads that file for project revisions, translation-unit
surfaces, finding counts and exit codes; those values are not duplicated in
workflow shell. A deliberate semantic change therefore updates one ledger in
the same reviewed change, while an unexplained surface/count/verdict drift is
red.

The current receipt was measured on 2026-08-07 UTC with analyzer tree
[`d47d11422542551e2f4f7b571e07d6d917c32885`](https://github.com/tanzercakir-commits/CodeSkeptic/commit/d47d11422542551e2f4f7b571e07d6d917c32885)
in [workflow run 31199842703](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/31199842703).
CI mirrored `results.txt` and bounded tail logs to
`refs/ci-logs/d47d11422542551e2f4f7b571e07d6d917c32885/realworld`; its immutable
evidence commit is
[`2d03342268a523c33bafa22ddb3c97d5834be4d4`](https://github.com/tanzercakir-commits/CodeSkeptic/commit/2d03342268a523c33bafa22ddb3c97d5834be4d4).

| Project | Exact input revision | Built TU verdict | Findings | Completed triage claim |
|---|---|---:|---:|---|
| libgit2 (`v1.9.0`) | `338e6fb681369ff0537719095e22ce9dc602dbf0` | 167/167, exit 1 | 34 | 11 confirmed OOM-path leaks; no full 34-finding partition claimed here |
| rtp2httpd | `a7a1e568d46ee3176f8a3e94e0f88f131ebd444e` | 38/38, exit 1 | 6 | 4 actionable findings + 2 context false positives |

Exit 1 is material evidence here: under the fail-closed contract it means a
complete verdict with findings, whereas any broken requested TU or unavailable
analysis would be exit 2. Historical table numbers remain historical and are
never substituted for this current-engine replay.

## Reading the real-world scan numbers

The [real-world scan table in the README](../README.md#proven-on-real-code)
tracks eight projects, each built with its own build system and analyzed
from its compilation database, every surviving finding triaged by hand.
Two things make those numbers move:

- **Idiom support is configuration, not code**: project allocators
  (`--alloc-functions git__malloc,... --free-functions git__free`),
  fatal assert macros (`--fatal-asserts assert_fail_impl`), and
  cleanup attributes (`_cleanup_free_`, `g_autofree`) are recognized
  so the analysis sees the code the way the project means it.
- **Every false-positive family became an engine feature with a
  pinned test**: the v0.4.3 round alone turned 37 real-world FPs into
  six engine roots (miner entailment, member fact keys, implication
  payloads, out-param success contracts, miner slot discipline, scanf
  widths + strlen-guard witness — changelog 2026-07-22);
  pointer-relational validity (systemd's
  `FOREACH_ARRAY`, 235 findings from one root cause),
  cross-variable correlation (flag/status guards, `assert(p || len
  <= 0)` contracts), value-selection rewind (llama's defensive
  ternary macros), escape analysis for macro idioms (`TAKE_PTR`,
  `free_and_replace`, compound literals). The remaining findings per
  project are classified and documented — nothing is hidden behind a
  suppression list.

## Guards that keep the numbers honest

- `scripts/juliet_expected.txt` — per-CWE precision/recall floors; a
  code PR that drops below any floor fails CI. Floors are only moved
  in the same PR as a deliberate rule change, with the rationale in
  the commit message.
- `scripts/corpus_expected.txt` — pinned real-world finding counts
  (10%+2 tolerance); a drop = silent finding loss, a rise = FP
  explosion.
- **Self-scan (dogfood gate)** — the analyzer analyzes its own sources
  on every PR; any finding fails CI.
- The token measurement (`scripts/token_ablation.py`) calls no model
  and is deterministic — method and limits in
  [token-ablation.md](token-ablation.md).
