# Contributing to CodeSkeptic

Thanks for looking under the hood. This project runs on a small number
of hard rules that keep a precision-first analyzer honest; knowing them
up front makes every contribution smoother.

## Build & test

The [README quickstart](README.md#quickstart) is the 4-command build
(Linux; macOS via Homebrew `llvm@20`). Then:

```bash
ctest --test-dir build --output-on-failure   # unit tests (googletest)
./build/tests/codeskeptic_tests              # same suite, single process
                                             # (catches global-state leakage)
```

Writing a new flow-sensitive rule = a lattice (`State`), a `transfer`
function, and optionally `refineOnEdge` — see
[docs/engine.md](docs/engine.md). Test snippets compile with the same
platform arguments as production (`platformExtraArgs()`), so what a
test sees is what the CLI sees.

## The three referees (please don't fight them)

Every code PR must satisfy, in CI:

1. **Juliet floors** (`scripts/juliet_expected.txt`) — per-CWE
   precision/recall must not drop below the pinned values.
2. **Corpus pins** (`scripts/corpus_expected.txt`) — finding counts on
   pinned cJSON/tinyxml2 (weekly: abseil) within 10%+2; a drop is
   silent finding loss, a rise is an FP explosion.
3. **Self-scan dogfood gate** — the analyzer must be clean on its own
   sources with the `no-absolute-paths` policy active.

A floor/pin may move **only in the same PR** as a deliberate rule
change, with the rationale in the commit message — that history is the
project's measurement conscience (read `juliet_expected.txt`'s
comments to see it in action).

## False positives are contributions

The engine's precision was built one FP family at a time: every
false-positive family reported against a real codebase became an
engine feature with a pinned regression test (pointer-relational
validity, cross-variable correlation, escape-analysis idioms, …).
If CodeSkeptic flags your code wrongly:

1. Open an issue with the **dataflow trace** (console output or SARIF
   `relatedLocations`) and a minimal snippet if you can extract one.
2. If the cause is project vocabulary (custom allocators, fatal
   asserts, owning pointers), try an [idiom profile](profiles/) first —
   that may be the whole fix, and a new profile is itself a welcome PR.

## Starter tasks

Genuinely approachable entry points, no dataflow expertise required:

- **A new idiom profile** for a codebase you know (`profiles/*.conf`,
  format-checked by `scripts/check_profiles.sh`).
- **Juliet FN classification** — extend `scripts/juliet_eval.py` to
  label missed cases (float-division / opaque-source / addressable);
  the groundwork of the next recall round (docs/PLAN-v0.4.md, Phase 2).
- **Docs**: a gap you hit during onboarding is a gap the next person
  hits — the README budget guard (`scripts/check_readme.sh`) will keep
  you honest about where the fix belongs.

## Style notes

C++17, no RTTI (matches LLVM), 4-space indent, comments explain *why*
(the codebase's comment culture is deliberate — read a rule file
before writing one). Diagnostic messages live in `core/Messages.*`
(en/tr). License: Apache-2.0; by contributing you agree your work is
released under it.
