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
- **A blind AI corpus** (24 programs, generated at first-draft quality
  by a model with no knowledge of our rules, bugs self-annotated) —
  the mission axis: combined recall **0.625 at precision 1.000**,
  including zero false positives on 9 deliberately-clean programs.
- **Real-world corpus** (cJSON, tinyxml2, weekly abseil) — pinned
  finding counts; deviation = semantic regression.

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
| CWE-416 Use After Free | `use-after-free` | **1.000** (200 TP / 0 FP) | 0.501 | **0.668** |
| CWE-476 NULL Pointer Dereference | `null-deref` | **1.000** (141 TP / 0 FP) | 0.352 | **0.521** |
| CWE-415 Double Free | `double-free` | **1.000** (95 TP / 0 FP) | 0.241 | 0.388 |
| CWE-401 Memory Leak | `memory-leak` | 0.716 (case-level) | 0.195 | 0.306 |
| CWE-369 Divide by Zero | `div-by-zero` | **1.000** (38 TP / 0 FP) | 0.095 | 0.174 |
| CWE-190 Integer Overflow | `int-overflow` | **1.000** (42 TP / 0 FP*) | 0.010 | 0.020 |

<sub>* CWE-190 precision measured over the full 3080-file corpus (42 TP,
0 FP); the recall figure is the CI-sampled rate. The rand-source family
reaches the sink through a bit-shuffle macro the interval evaluator
cannot fold — a documented known false negative — so the sampled recall
is deliberately low while precision is perfect.</sub>

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
convergence widening — CWE-416 recall rose 0.436 → 0.501 and CWE-401
precision 0.653 → 0.716 in the same step that removed hundreds of
real-world false positives. A caveat on cross-rule findings: Juliet
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

Results are from the 2026-07-18 run (v0.3); grep `JULIET_RESULT` in the
weekly workflow logs for current numbers. The v0.3 recall series added a
sixth per-CWE floor (CWE-190) and raised div-by-zero recall via untrusted
sources — all six floors hold rprecision 1.000 with zero regressions.

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
  pinned test**: pointer-relational validity (systemd's
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
