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

The CI replay is `.github/workflows/realworld.yml`. Its daily cron selects the
pinned `nightly` tier, its distinct weekly cron selects `weekend`, and either
tier is available through `workflow_dispatch`. Nightly builds independent
libgit2, rtp2httpd, Abseil, and libarchive shards; weekend builds systemd,
curl, Redis, and LVGL shards. CodeSkeptic is built once for the campaign. Each
project is checked out at an immutable commit, configured through its real
build system, and analyzed from an exact source list derived from
`compile_commands.json` plus only explicitly admitted fallback files. Exit 2,
timeout, broken/incomplete/skipped coverage, TU drift, receipt tampering, a
missing repetition, or semantic disagreement is a failure.

`attempted_tus` is the exact requested source-list size. `analyzed_tus` is the
analyzer execution count and can be larger only when an admitted mode such as
`--whole-program` performs additional executions. It must never be smaller
than `attempted_tus`; both values are pinned per project, while any broken TU
or incomplete function remains an unavailable verdict.

The single executable authority is
[`scripts/realworld_manifest.json`](../scripts/realworld_manifest.json); the
legacy `realworld_expected.txt` path is only a compatibility pointer. Validate
and inspect the deterministic matrix without cloning any project:

```bash
python3 scripts/check_realworld_ledger.py
python3 scripts/run_realworld_campaign.py plan --tier nightly
python3 scripts/run_realworld_campaign.py plan --tier weekend
```

One shard can be reproduced with the same built Linux analyzer:

```bash
python3 scripts/run_realworld_campaign.py run \
  --project libgit2 --repetition 1 \
  --analyzer ./build/src/codeskeptic \
  --workspace realworld-work \
  --output receipts/libgit2/repeat-1/receipt.json \
  --checkpoint checkpoints/libgit2/repeat-1/receipt.json
```

After all three receipts for every project exist, run the separate referee:

```bash
python3 scripts/run_realworld_campaign.py aggregate \
  --tier nightly --receipts receipts \
  --output aggregate/receipt.json
```

Use `--tier weekend` with the same aggregate command after the twelve weekend
receipts exist. Phase 8.2 local qualification accepted all twelve with manifest
SHA-256
`88e7dbe8d46b88bd95e88b83106096953e90fed425b39a68d68225a78279a255`
and aggregate receipt SHA-256
`9bbc429187d5059d0f292677420ff79c7d2755bc001deb5e80addb109f68e498`.

Receipts and their `.sha256` sidecars are uploaded per shard even when the
verdict is unavailable; the aggregate receipt is a distinct artifact. Current
immutable receipts and the interpretation contract are recorded in
[benchmarks.md](benchmarks.md#current-engine-real-world-replay-ledger).
The first accepted hosted factory evidence is GitHub workflow run
[`31370373875`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/31370373875);
its aggregate receipt SHA-256 is
`08f8fe075e2dba92c8706c9028026d46cbb6b5148913d113146c1b64ffd559f6`.

## What the guards mean

CI enforces all of this on every code PR: Juliet floors
(`juliet_expected.txt`), corpus pins (`corpus_expected.txt`), a
self-scan dogfood gate (the analyzer must be clean on its own source,
`no-absolute-paths` policy active), and the quickstart doc-test (the
README install block runs verbatim on a clean runner). Floors and pins
move only in the same PR as a deliberate rule change, with the
rationale in the commit message.
