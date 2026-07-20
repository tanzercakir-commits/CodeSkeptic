# Does CodeSkeptic cut tokens in an AI review loop?

Short answer: **on real-sized files, yes — a lot, and the saving grows with
file size.** On tiny files, no. Here's the measurement, including where it
does *not* help.

## The idea

An LLM asked to find bugs in raw C/C++ must ingest **every line** and reason
over the paths between them. CodeSkeptic reads the code as *computation*
(outside the token budget) and returns a compact, deterministic findings
list with a trace. So its output is **O(bugs), not O(lines)** — and for any
file bigger than a screenful, an agent that calls CodeSkeptic processes far
fewer tokens to know where the memory-safety bugs are.

![Tokens to locate the bugs — baseline grows with lines, CodeSkeptic stays flat](img/token-ablation.png)

## The measurement

`scripts/token_ablation.py` is deterministic and reproducible — **no model is
called**. It measures the *input-token footprint* of two conditions on the
same source:

- **baseline** — the whole file is handed to the model ("find the bugs").
- **assisted** — CodeSkeptic's findings are handed to the model instead
  (`detect` = findings only; `fix` = findings + a few lines of context per
  finding to patch it).

The scaling series holds the 3-bug set constant while clean helper code grows:

| input        | LOC  | bugs | baseline | detect | fix | detect× | fix× |
|--------------|-----:|-----:|---------:|-------:|----:|--------:|-----:|
| demo.c       |   15 |    3 |      176 |    205 | 408 |    0.9× | 0.4× |
| custom.c     |   20 |    2 |      174 |    152 | 251 |    1.1× | 0.7× |
| scaling k=0  |   18 |    3 |      154 |    205 | 331 |    0.8× | 0.5× |
| scaling k=10 |   77 |    3 |      450 |    205 | 341 |    2.2× | 1.3× |
| scaling k=40 |  257 |    3 |    1 342 |    205 | 341 |    6.5× | 3.9× |
| scaling k=120|  737 |    3 |    3 725 |    205 | 341 |   18.2× |10.9× |
| scaling k=400| 2417 |    3 |   12 090 |    205 | 341 |   59.0× |35.5× |

<sub>Offline token estimate (the reduction ratio is tokenizer-insensitive; the
harness uses tiktoken's real BPE when it can reach the vocab). Reproduce with
`python3 scripts/token_ablation.py`.</sub>

## Reading it — honestly

- **CodeSkeptic's output is flat.** `detect` ≈ 205 and `fix` ≈ 341 tokens
  whether the file is 18 or 2 417 lines — it scales with the number of bugs,
  not the file. The baseline scales linearly with lines (154 → 12 090).
- **On tiny files there is no saving — even a small cost** (0.4–1.1×). On a
  15-line toy, wrapping a finding in JSON + trace + context costs as much as
  the source. No free lunch, and we don't pretend otherwise.
- **The crossover is ~50–80 lines.** Real files are hundreds to thousands of
  lines, whole modules, multi-file PRs — the regime where the saving is
  6–59× and *growing*. That is where AI review actually happens.
- **It compounds at repo scale.** Reviewing 50 files LLM-only means ingesting
  all 50; CodeSkeptic scans them as computation and returns one short list.

## Cheaper *and* more reliable

The baseline path is also probabilistic: it hallucinates and misses, so some
of those tokens are spent on false leads and re-checking. CodeSkeptic's
findings are deterministic and carry a verifiable trace. Usually cheaper
means worse — here cheaper means **more reliable at the same time**, because
the hard part (sound, path-sensitive bug-finding) moved off the token budget.

## Limits

- This measures **input/context tokens** only. Output tokens and *accuracy*
  (did the model find the bug, did it hallucinate) need a live model —
  `scripts/token_ablation_live.py` does that with your own API key.
- CodeSkeptic covers the defect **classes it detects** (memory safety, etc.),
  not everything a reviewer comments on (design, naming). It is a
  **complement**: the LLM still does the broad review; CodeSkeptic makes the
  safety-critical part cheap and sound.
