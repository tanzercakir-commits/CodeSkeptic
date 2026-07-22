# Integrations: CI gates, editors, agents

How CodeSkeptic plugs into a PR pipeline, an editor, and an AI coding
loop. Adoption advice up front, learned the honest way: **run
report-only for the first week** (`--gate warn`, or upload SARIF without
failing the job) and let the findings earn the right to block your CI —
see [evaluate.md](evaluate.md).

## Semantic regression gate (summary diff)

Summary files are deterministic, so two harvests can be compared as
*contracts*:

```bash
codeskeptic src/ --summary-out before.txt     # e.g. on main
# ... apply the change ...
codeskeptic src/ --summary-out after.txt
codeskeptic --summary-diff before.txt after.txt
```

```
SUMMARY_DIFF WEAKENED find/1 returnNullness: NeverNull -> MaybeNull
[CodeSkeptic] 1 weakened, 0 strengthened, 0 changed, 0 added, 0 removed
[CodeSkeptic] weakened contracts: callers relying on them must be re-checked
```

`WEAKENED` means a strong claim callers may rely on was lost — a
function that could never return null now can, a callee that used to
be read-only now stores its argument. The exit code is `1` in that
case, so the diff doubles as a CI gate: *this change silently altered
function contracts; the callers deserve a look*. Gained claims report
as `STRENGTHENED` (informational), directionless drifts as `CHANGED`,
and signature changes appear as `REMOVED`+`ADDED` (the key includes
arity — an arity change breaks callers anyway).

The gate is configurable for adoption: `--gate warn` (or
`summary_diff_gate = warn` in `.codeskeptic.conf`) keeps the full
report but exits `0`, so a project can watch its contract drift
before letting it break CI. The default stays `error` — and an
unreadable summary file is exit `2` regardless: a gate that cannot
read its input never looks green.

## PR review (diff-native)

`review_diff.sh` turns the analyzer into a PR reviewer: it analyzes the
changed files at BOTH the base revision (in a temporary git worktree,
reusing the head compile commands) and the working tree, and reports the
**delta** — what this change did, not what the codebase already had:

```bash
# in CI, after checking out the PR head:
scripts/review_diff.sh build/src/codeskeptic origin/main --out review.md
```

The markdown review contains:

* **New findings** — introduced by the change, with dataflow traces;
  findings and trace steps that sit on changed lines are marked. A
  finding that merely *shifted* (code added above it) does not
  resurface: matching uses the baseline's line-content keys, and pure
  renames are mapped old→new, so refactor PRs stay quiet.
* **New assumptions** — on by default in review mode: a new inferred,
  unchecked precondition ("parameter `p` is assumed non-null —
  dereferenced, never checked") is exactly the CWE-476 shape reviews
  exist to catch; in the field trial it pinpointed cJSON's #991 null
  dereference as one single finding, and produced zero noise across a
  116-commit history range (the delta bounds the assumption engine's
  volume). Info severity — it informs, and gates only under
  `--strict`. Opt out with `--no-assumptions`.
* **Fixed findings** — present at base, gone at head.
* **Contract changes** — the summary diff of both sides' inferred
  contracts; `WEAKENED` entries gate.
* **Coverage** — what was *not* analyzed and why (headers, deleted
  files, `--exclude` matches, iteration-cap functions). "No warning"
  in an unanalyzed file means *not checked*, and the review says so.

Real-world diffs are noisy in predictable places — test and vendor
directories exercise null paths on purpose. `--exclude 'tests/*'`
(repeatable) skips those changed files *visibly*: they are listed in
the coverage section, never silently dropped.

The exit code is the verdict, on the same evidence ladder as the rules
themselves: **new definite findings (error) and weakened contracts
gate; new "may" findings (warning) are reported but do not** — pass
`--strict` to gate them too, or `--gate warn` to always exit `0` while
still printing the failing verdict (adoption ramp). The last line is
machine-greppable for CI dashboards:

```
REVIEW_RESULT new_errors=1 new_warnings=0 fixed=1 weakened=1 gate=fail
```

Both analyzer runs receive identical settings (arguments after `--` are
forwarded to both — `--alloc-functions`, `--fatal-asserts`, or
`--summary-in .codeskeptic-summaries` to review with whole-project
knowledge, …); a delta between two differently-configured runs would
not be a delta. Known limits, stated rather than hidden: a header-only
change analyzes no TU (it is listed in the coverage section), and
deleted files' base-only findings are not counted as fixed.

A minimal GitHub Actions gate:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }        # the review needs the base commit
- name: Build codeskeptic          # or download a release binary
  run: cmake -B build -G Ninja && cmake --build build
- name: Review the PR diff
  run: |
    scripts/review_diff.sh build/src/codeskeptic \
      "origin/${{ github.base_ref }}" --build-path build \
      --exclude 'tests/*' --out review.md
```

## MCP server (agent integration)

`codeskeptic --serve` runs an MCP (Model Context Protocol) server over
stdio, exposing an `analyze` tool that returns findings — with dataflow
traces — as structured JSON. Agents like Claude Code can call it after
every edit. Register it in `.mcp.json`:

```json
{
  "mcpServers": {
    "codeskeptic": {
      "command": "/path/to/codeskeptic",
      "args": ["--serve"]
    }
  }
}
```

Calling the analyzer is also **cheaper than asking the model to reason
over the raw code** — O(bugs), not O(lines), so an agent spends 6–59×
fewer tokens to locate the memory-safety bugs on a real-sized file, and
gets a deterministic answer with a trace. See
[token-ablation.md](token-ablation.md) for the measurement and honest
caveats.

The `analyze` tool accepts `path` plus optional `build_path`,
`functions` and `lines` — so an agent can scope the re-check to exactly
the functions it just edited — and the project-idiom parameters
(`fatal_asserts`, `alloc_functions`, `free_functions`) so the analysis
sees custom assert handlers and allocator wrappers the same way the
CLI flags do. Idiom registrations are per-call: nothing leaks into the
next request of the long-lived server process.

Exit code is `1` when findings are reported, `0` when clean — suitable
for CI gates.

## Editor & code-scanning integration (via SARIF)

The SARIF 2.1.0 output works today with standard tooling — no plugin of
our own required:

**VS Code.** Install the
[SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
extension (Microsoft), then:

```bash
codeskeptic src/ --sarif findings.sarif
code findings.sarif   # or: open via the SARIF Viewer panel
```

Findings appear in a results panel; clicking one jumps to the source
line, and CodeSkeptic's dataflow traces show up as *related locations*
(the allocation/free/null-assignment chain behind each finding is
navigable step by step).

**GitHub code scanning.** Upload the same file from CI and findings
appear in the repository's Security tab and as PR annotations. A complete
workflow — build CodeSkeptic, generate your project's compilation
database, analyze, upload:

```yaml
# .github/workflows/codeskeptic.yml
name: CodeSkeptic
on: [push, pull_request]

permissions:
  contents: read
  security-events: write        # required to upload SARIF to code scanning

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build CodeSkeptic
        run: |
          sudo apt-get update
          sudo apt-get install -y llvm-18-dev libclang-18-dev cmake
          cmake -B cs-build -DCMAKE_BUILD_TYPE=Release
          cmake --build cs-build -j

      - name: Generate your project's compile_commands.json
        run: cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

      - name: Analyze -> SARIF
        run: ./cs-build/src/codeskeptic . --build-path build --sarif codeskeptic.sarif || true

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: codeskeptic.sarif
```

(`|| true` because CodeSkeptic exits 1 on findings; code scanning does
its own gating — this is the report-only mode that first-week adoption
should use.)

For a shareable, tool-free view of the same findings, use `--html` —
one self-contained file with filters and source-context traces.
