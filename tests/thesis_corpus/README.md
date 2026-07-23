# Thesis corpus — the mission-axis gate

CodeSkeptic's mission is catching the bugs an AI writes on a first
pass. Juliet measures mature-code precision; the real-world corpus
measures FP-resistance on production code. This corpus measures the
third axis, the one the project exists for: **do we catch first-draft
bugs without crying wolf?**

## How it was built (blindness integrity)

24 small C programs, written in two batches by generator subagents
that were **blind to CodeSkeptic's rules** — they were asked to write
everyday / systems C at first-draft quality and to self-annotate their
own bugs (`// GROUND_TRUTH_BUG: …`) or mark a file `// GROUND_TRUTH_CLEAN`.
No static analyzer was in the loop during generation, and the prompt
never named a bug category. The files are frozen **verbatim** here;
regenerating them would break the blindness that makes the number
meaningful.

## The manifest is the adjudicated truth

`thesis_expected.txt` is what CI scores against — not the raw
annotations, because a first-draft author's self-labels are noisy (the
same way the devlog's first thesis run was re-scored). One file the
generator called CLEAN, `matrix_row_copy.c`, actually dereferences two
unchecked mallocs; CodeSkeptic flags it and is **correct** — the
analyzer being more careful than the author is the whole point. Every
such call is documented in the manifest's comments.

## What it gates

- **Precision (hard):** the 9 genuinely-clean programs must produce
  **zero** findings. One false alarm turns CI red.
- **Recall (floor):** each buggy program must keep producing at least
  its pinned number of findings; a drop is a recall regression. An
  increase means a new detection — bump the pin in the same PR (the
  Juliet-floor discipline).

Current state: **0 false positives across 9 clean programs; 9/9
in-scope memory-safety/overflow bugs caught.** The 6 remaining buggy
files carry out-of-scope defects (floating-point division, pure logic
errors, possible-not-definite out-of-bounds, a scanf format-string
bug) and are pinned at 0 as documented misses — if a future rule
catches one, its pin moves up.

Run it locally: `bash scripts/run_thesis.sh ./build/src/codeskeptic`.
