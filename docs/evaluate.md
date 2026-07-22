# Evaluate CodeSkeptic on your own code — in about an hour

Benchmarks are our numbers, on our corpora. The only measurement that
should convince you is **precision on your codebase**. This is the
controlled, ~one-hour experiment we recommend before wiring CodeSkeptic
into anything that can block a merge.

## 0. Prerequisites

A Linux or macOS machine with LLVM/Clang development libraries (the
[README quickstart](../README.md#quickstart) is the 4-command build),
and a real `compile_commands.json` for your project
(`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`, or `bear -- make`).

## 1. Pick a real slice, not a toy

Choose **10–30 translation units** you know well — a module with real
pointer work, ideally one with some history of memory bugs. Use your
real compilation database; don't hand-craft flags:

```bash
./codeskeptic path/to/module --build-path build \
    --report-paths $PWD/path/to/module --html report.html
```

`--report-paths` keeps dependency headers out of the report; the
analysis itself is unaffected.

## 2. Evaluate memory-leak separately

`memory-leak` is our noisiest rule (Juliet precision 0.716 vs 1.000 for
the other five — [benchmarks.md](benchmarks.md) doesn't hide this).
Score it on its own so one rule's noise doesn't color your read of the
others:

```bash
# everything except the leak family (--disable-rule is repeatable):
./codeskeptic path/to/module --build-path build --disable-rule memory-leak

# then the leak rule's own pass, scored separately:
./codeskeptic path/to/module --build-path build \
    --disable-rule uninit-ptr --disable-rule null-deref \
    --disable-rule div-by-zero --disable-rule bounds \
    --disable-rule int-overflow --disable-rule contract
```

## 3. Verify every finding by its trace — not by vibes

Each finding carries a dataflow trace (the allocation/free/null
assignment chain). Open the HTML report and walk each trace by hand:
the trace either shows a real path or it doesn't. That
verifiability is the product; use it.

## 4. Teach it your project's idioms before judging the noise

Most real-world false positives come from unrecognized project
vocabulary, and that is configuration, not code:

```bash
./codeskeptic ... \
    --alloc-functions my_malloc,pool_alloc \
    --free-functions my_free \
    --fatal-asserts my_assert_fail \
    --owning-pointers RefPtr
```

See the [usage reference](usage.md) for the full list. Worked example
profiles from the projects we scan (systemd, libgit2, …) are landing in
a `profiles/` directory as part of the v0.4 round.

## 5. Compare against your existing tools

Run the same slice through what you already have — `clang --analyze`,
`gcc -fanalyzer`, cppcheck — and compare per finding. Expect overlap
and disagreement both ways ([comparison.md](comparison.md) shows the
pattern); the question is what CodeSkeptic adds *on top*, with a trace.

## 6. Report-only first. Do not gate CI in week one.

Collect reports before you block anything: upload SARIF with `|| true`
(code scanning does its own gating), or use `--gate warn` on the
diff/summary gates so verdicts print without failing the job. Let a
week of PRs accumulate evidence.

## 7. The decision rule

If, out of your first ~10 findings, **7–8 hand-verify as meaningful**
(real bugs, or true statements about assumptions your code makes), wire
in the next layer: the diff-native
[PR review](integrations.md#pr-review-diff-native) or the
[MCP server](integrations.md#mcp-server-agent-integration) for your AI
coding loop — still `--gate warn` until it earns `error`. If they
don't, file an issue with a trace: every false-positive family we've
closed became an engine feature with a pinned test, and yours will too.

## What a "finding" of *no findings* means

Nothing. CodeSkeptic is precision-first; silence is not a safety proof
(see [What it won't catch](../README.md#what-it-wont-catch)). Keep your
sanitizers, fuzzing, and tests exactly where they are.
