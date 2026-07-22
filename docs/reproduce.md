# Reproduce our numbers

Every figure CodeSkeptic publishes comes from a script in this
repository — the same ones CI runs. Don't take the tables on faith;
run them. All commands assume a built tree
([README quickstart](../README.md#quickstart)).

## Juliet benchmark (the per-CWE precision/recall table)

```bash
bash scripts/run_juliet.sh ./build/src/codeskeptic juliet-work 400
```

Downloads NIST Juliet C/C++ 1.3 (cached in `juliet-work/`), samples
400 files per CWE evenly across variant families, and prints one
greppable `JULIET_RESULT` line per CWE — the exact numbers in
[benchmarks.md](benchmarks.md). Scoring: `scripts/juliet_eval.py`
(a finding in a `bad` function = TP, in a `good` function = FP).
Pass `0` instead of `400` for the unlimited run (the weekly CI cron
uses 1600). The pinned floors CI enforces are in
`scripts/juliet_expected.txt` — with the history of every floor move
and its rationale in the comments.

## Real-world corpus (pinned finding counts)

```bash
bash scripts/run_corpus.sh ./build/src/codeskeptic corpus-work
CORPUS_DEEP=1 bash scripts/run_corpus.sh ./build/src/codeskeptic corpus-work  # + abseil
```

Fetches pinned versions of cJSON and tinyxml2 (deep mode adds abseil),
builds their real compilation databases, analyzes, and checks the
finding counts against `scripts/corpus_expected.txt` (10%+2 tolerance;
a drop = silent finding loss, a rise = FP explosion).

## Token-ablation measurement (the 6–59× table)

```bash
python3 scripts/token_ablation.py
```

Deterministic, no model is called — it measures the input-token
footprint of "whole file" vs "CodeSkeptic findings" on the same
sources. Method, honest caveats (no saving under ~50 lines) and the
full table: [token-ablation.md](token-ablation.md).

## Tool comparison (the demo.c table)

```bash
./build/src/codeskeptic docs/demo.c
gcc -O2 -Wall -Wextra -Woverflow -fanalyzer -c docs/demo.c -o /dev/null
clang --analyze docs/demo.c
```

Same three-bug files ([comparison.md](comparison.md)); reproduced
there with gcc 13.3 / clang 18.1. Versions matter — analyzer coverage
shifts between releases, which is part of the point.

## Real-world scan table

The [scan table](../README.md#proven-on-real-code) requires building
each project (its own build system) and analyzing from its
compilation database with its [idiom profile](../profiles/) — hours,
not minutes, and finding counts drift as upstreams move. The
reproducible essence: pick one project, use its profile, triage each
finding by its dataflow trace. `docs/evaluate.md` turns that into a
one-hour protocol for *your* codebase — which is the measurement that
should actually convince you.

## What the guards mean

CI enforces all of this on every code PR: Juliet floors
(`juliet_expected.txt`), corpus pins (`corpus_expected.txt`), a
self-scan dogfood gate (the analyzer must be clean on its own source,
`no-absolute-paths` policy active), and the quickstart doc-test (the
README install block runs verbatim on a clean runner). Floors and pins
move only in the same PR as a deliberate rule change, with the
rationale in the commit message.
