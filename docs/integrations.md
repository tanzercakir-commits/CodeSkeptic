# Integrations: CI gates, editors, agents

How CodeSkeptic plugs into a PR pipeline, an editor, and an AI coding
loop. Start adoption with complete findings visible but non-blocking; keep
input, analysis and artifact failures blocking. Ordinary scans do not have a
`--gate warn` mode: that flag belongs to summary diff (and the review script's
own gate). Use the locally tested recipe below; see [evaluate.md](evaluate.md)
for the broader evaluation process.

## Local report-only CI

First run the [small C/C++ project](first-scan.md). Save this block as
`ci/report_only.py` in that example project. It uses only Python's standard
library and an installed `codeskeptic` on `PATH`. This deliberately narrow
recipe scans a source-only `src` tree (`.c`, `.cpp`, `.cc`, `.cxx`), with the
generated build directory **outside** it. Review that intended source set for
your own project; it is not a universal build-system adapter.

The output directory must be new: reusing an old report is not evidence that
this run worked. A complete supported-finding verdict stays `1` in the artifact
while this adoption wrapper exits `0`. Experimental-only CLI reports already
exit `0`. Missing/malformed reports, missing intended files, incomplete coverage,
launch failures, timeouts and exit `2` remain wrapper failures. This example's
300-second analysis budget can be changed deliberately for larger projects.

<!-- first-scan:report-only-file -->
```python
import json
from pathlib import Path
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    try:
        require(len(sys.argv) == 4, "usage: report_only.py <source-dir> <build-dir> <new-output-dir>")
        source, build, output = map(Path, sys.argv[1:])
        source = source.resolve(strict=True)
        require(source.is_dir(), "choose a source-only directory")
        expected = {str(p.resolve()) for p in source.rglob("*")
                    if p.is_file() and p.suffix in {".c", ".cpp", ".cc", ".cxx"}}
        require(bool(expected), "no intended C/C++ sources")
        output.mkdir()  # Refuse an existing directory, including stale reports.
        artifact = output / "codeskeptic.sarif"
        result = subprocess.run(
            ["codeskeptic", "--source", str(source), "--build-path", str(build),
             "--sarif", str(artifact)], timeout=300, check=False)
        require(result.returncode in (0, 1), "analysis failed: exit " + str(result.returncode))
        data = json.loads(artifact.read_text(encoding="utf-8"))
        require(data["version"] == "2.1.0" and len(data["runs"]) == 1, "invalid SARIF run")
        run = data["runs"][0]
        report = run["properties"]["codeskeptic/report"]
        require(report["schema"] == "codeskeptic-report/v1", "unsupported report schema")
        require(report["tool"] == "CodeSkeptic" and report["complete"] is True,
                "analysis evidence incomplete")
        require(type(report["exit_code"]) is int and report["exit_code"] == result.returncode,
                "process/report exit mismatch")
        require(report["status"] in ("clean", "report-only", "findings"), "unexpected verdict")
        require(len(run["invocations"]) == 1, "missing invocation")
        invocation = run["invocations"][0]
        properties = invocation["properties"]
        require(invocation["executionSuccessful"] is True
                and properties["codeskeptic/exitCode"] == result.returncode
                and properties["codeskeptic/status"] == report["status"], "invocation mismatch")
        coverage = properties["codeskeptic/coverage"]
        require(coverage["schema"] == "codeskeptic-source-coverage/v1"
                and coverage["complete"] is True, "source coverage incomplete")
        require(coverage["accept_partial_coverage"] is False
                and coverage["analyze_broken_tus"] is False, "partial/recovery opt-in not allowed")
        require(coverage["attempted_tus"] == coverage["analyzed_tus"] == len(expected),
                "intended source count mismatch")
        require(all(coverage[key] == 0 for key in (
            "broken_tus", "skipped_tus", "failed_tus", "recovery_tus", "incomplete_functions",
            "skipped_commands", "failed_commands")), "failed or incomplete coverage")
        rows = coverage["sources"]
        require(len(rows) == len(expected) and {row["file"] for row in rows} == expected,
                "intended source identity mismatch")
        for row in rows:
            require(row["status"] == "analyzed"
                    and row["commands"] == row["analyzed_commands"] > 0
                    and row["skipped_commands"] == row["failed_commands"] == row["recovery_commands"] == 0
                    and row["prepass"]["recovery_commands"] == 0, "incomplete source command")
        counts = report["finding_counts"]
        require(all(type(counts[key]) is int and counts[key] >= 0
                    for key in ("total", "blocking", "report_only")), "invalid finding counts")
        require(counts["total"] == counts["blocking"] + counts["report_only"]
                == report["total"] == len(run["results"]), "finding count mismatch")
        require((counts["blocking"] > 0) == (result.returncode == 1), "finding verdict mismatch")
        require(report["status"] == ("findings" if counts["blocking"] else
                                     "report-only" if counts["total"] else "clean"), "status mismatch")
        print("REPORT_ONLY_OK analyzer_exit=" + str(result.returncode)
              + " sources=" + str(len(expected)) + " artifact=" + str(artifact))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.TimeoutExpired) as error:
        print("REPORT_ONLY_FAILED: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
```

<!-- first-scan:report-only-run -->
```bash
python3 ci/report_only.py src build scan-artifacts
```

For another run, choose a new output directory. Keep the SARIF findings and
original analyzer verdict for review; `REPORT_ONLY_OK` means acceptable
execution/coverage, **not** “no defects.” The recipe adds no baseline, rule
disabling, suppression or reduced quality floor. It assumes a trusted installed
analyzer and trusted project configuration; it does not attest a malicious
producer or establish all-CWE coverage.

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
be read-only now stores its argument. Losing or changing an exact pointee
access, parameter-ownership, return-ownership, return-alias, or output
postcondition claim is also a weakening. Adding a possible field write,
replacing an exact field set with unknown, or changing to an incomparable
set is likewise WEAKENED; removing possible writes is STRENGTHENED.
Preconditions use the caller-compatibility direction: adding a new non-null obligation, or changing
rejection into crash, is WEAKENED; removing/softening it is STRENGTHENED. The
exit code is `1` for a weakening,
so the diff doubles as a CI gate: *this change silently altered function
contracts; the callers deserve a look*. Other gained claims report as
`STRENGTHENED` (informational), directionless drifts as `CHANGED`, and
signature changes appear as `REMOVED`+`ADDED` (the key includes
arity — an arity change breaks callers anyway).

The gate is configurable for adoption: `--gate warn` (or
`summary_diff_gate = warn` in `.codeskeptic.conf`) keeps the full
report but exits `0`, so a project can watch its contract drift
before letting it break CI. The default stays `error` — and an
unreadable summary file is exit `2` regardless: a gate that cannot
read its input never looks green.

## Opt-in library models in CI

A repository can version reviewed declarations for body-less platform or
vendor functions and load them on every analysis:

```bash
codeskeptic src/ --model-file models/platform.csk \
    --model-file models/vendor.csk
```

The flag is repeatable and is forwarded normally when placed after `--` in
the diff/review scripts. Model files use the same deterministic strict schema
as `--summary-out`, so `--summary-diff old.csk new.csk` can review their
semantic drift. Key collisions across models, harvested summaries, and the
current run merge conservatively; ordering is not an override mechanism.

Treat model changes like source changes. A strong declaration is a reviewed
assumption and can remove a finding; it is not proof that the library
implementation satisfies the row. CI should pin the files in the repository,
show their semantic diff, and require human review before accepting generated
or AI-proposed changes. CodeSkeptic never promotes a proposal into a model or
accepted contract automatically.

A missing or malformed requested model sets the ordinary
`summary_load_failed` evidence bit and exits `2`, even if the remaining
analysis produced diagnostics. Model files have no source timestamp check
because they are declarations rather than harvested snapshots. There are no
built-in models or implicit library-name semantics.

## Repository PR measurement

CodeSkeptic's own `measurement.yml` is the product-quality companion to the
per-change review. It builds the exact `pull_request.base.sha` and
`pull_request.head.sha`, runs the same clean, defective and real-repository
corpora on each, and publishes four independent delta axes: finding quality,
runtime/peak RAM, analyzed/broken TU coverage, and semantic fingerprint
additions/removals. The job fails closed when evidence is unavailable, clean
noise grows, defective caught-case recall falls, or coverage regresses.
Performance remains visible but ungated until a measured budget is adopted.

The workflow uploads the base, head and comparison JSON receipts plus its
Markdown summary. Juliet's companion artifact adds the per-rule
precision/recall/F1 table and the complete addressable/model-gap/out-of-scope
miss partition. See
[benchmarks.md](benchmarks.md#pr-measurement-laboratory) for the schemas and
reproduction contract.

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
  resurface when its strong v3 function-bound identity matches; pure
  renames are mapped old→new. Changed ownership, signatures, severity or
  message are not silently accepted by weaker line-content matching.
* **New assumptions** — on by default in review mode: a new inferred,
  unchecked precondition ("parameter `p` is assumed non-null —
  dereferenced, never checked") is exactly the CWE-476 shape reviews
  exist to catch; in the field trial it pinpointed cJSON's #991 null
  dereference as one single finding, and produced zero noise across a
  116-commit history range (the delta bounds the assumption engine's
  volume). It is experimental/report-only, so it informs even under
  `--strict`. Opt out with `--no-assumptions`.
* **Fixed findings** — supported by the complete comparison evidence, not merely
  hidden at head. Applied suppressions retain an audit section and cannot be
  claimed as fixes; baseline-filtered input that consumed findings cannot
  establish the full delta. Ambiguous ownership stays conservative.
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
themselves: **new supported definite findings (error) and weakened contracts
gate; new supported "may" findings (warning) are reported but do not** —
pass `--strict` to gate supported warnings too. Experimental findings are
always report-only, including under `--strict`. Use `--gate warn` to
exit `0` for a complete supported failing verdict (adoption ramp), not for
missing or invalid evidence: those failures remain `2`. The last line is
machine-greppable for CI dashboards:

```
REVIEW_RESULT new_errors=1 new_warnings=0 fixed=1 weakened=1 gate=fail
```

Both analyzer runs receive identical settings (arguments after `--` are
forwarded to both — `--allocator-pairs`, `--alloc-functions`,
`--fatal-asserts`, or
`--summary-in .codeskeptic-summaries` to review with whole-project
knowledge, …); a delta between two differently-configured runs would
not be a delta. Loaded summaries also compose through a controlled automatic
local function-pointer target when that target set is closed. Unresolved
indirect dispatch remains conservative. Known limits are stated rather than
hidden: a header-only change analyzes no TU (it is listed in the coverage
section), and deleted files' base-only findings are not counted as fixed.

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
(`fatal_asserts`, `alloc_functions`, `free_functions`, `allocator_pairs`) so
the analysis sees custom assert handlers and allocator wrappers the same way
the CLI flags do. `allocator_pairs` uses comma-separated
`allocator=deallocator` entries and rejects malformed values atomically. Idiom
registrations are per-call: nothing leaks into the next request of the
long-lived server process.

The MCP payload exposes the same verdict contract as the CLI: `0` means
complete evidence with no supported/blocking findings (experimental findings
may still be returned report-only), `1` means complete with supported
findings, and `2` means the requested evidence was not sufficient for a
trustworthy verdict. It publishes total, blocking and report-only counts;
only verdict-unavailable sets `isError`.

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

**GitHub code scanning.** After local qualification, a repository with code
scanning enabled and appropriate permissions can upload the checked SARIF.
The following is an integration fragment, **not a commissioned workflow or
release test**. It assumes checkout, an installed matching development binary,
Python/CMake/Ninja/compilers, and the saved recipe above. Add these steps only
through your repository's normal review and CI authorization process:

```yaml
- name: Generate the example project's compilation inputs
  run: cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
- name: Analyze with checked report-only acceptance
  run: python3 ci/report_only.py src build scan-artifacts
- uses: github/codeql-action/upload-sarif@v3
  if: success()
  with:
    sarif_file: scan-artifacts/codeskeptic.sarif
```

The job requires `contents: read` and `security-events: write` as permitted by
the hosting repository. Do not add blanket shell success or `continue-on-error`
to the analysis step: it would also hide infrastructure and coverage failures.
No hosted upload is required by the local first-scan test.

For a shareable, tool-free view of the same findings, use `--html` —
one self-contained file with filters and source-context traces.

The packaged composite Action accepts `extra-args` with shell-style quoting.
Environment references such as `$GITHUB_WORKSPACE/src` are expanded, while
command substitutions and glob patterns remain literal data and are never
executed by a shell.

## Qualified artifact integration profiles

The current composite Action expects the native `codeskeptic-report/v1` and
`codeskeptic-source-coverage/v1` contracts; older releases are not automatically
compatible. Pin a reviewed Action revision and a matching qualified artifact.
Local `artifact-path` plus its required `artifact-sha256` installs without any
download; do not combine these inputs with `version`. A checksum verifies byte
integrity, not the producer's authenticity: packages are trusted executable code.
Extraction is bounded and rejects traversal, links, special files and ambiguous
paths. Installation uses a fresh directory and checks the actual binary version.

Alternatively, `version` selects a release tag or explicitly floating `latest`.
An omitted version only derives from a release-tag Action ref; branch/SHA/local
refs never silently float. Downloading is restricted to the public project
repository with isolated acquisition credentials/configuration. Analyzer
processes receive a minimal environment without runner tokens. This native
execution is **not an OS sandbox**: use trusted binaries/project configuration
on an appropriately isolated runner. Checkout/download traffic is distinct from
uploading source-containing reports.

`upload-sarif` defaults to `false`; enabling it requires explicit consumer intent
and that job's `security-events: write` permission. Ordinary analysis requires
no repository write permission. Use a **new** `sarif` destination each run.
Missing, malformed, stale or contradictory reports and timeouts fail both gates.
Valid incomplete reports are retained with exit `2`. Explicit partial/recovery
options preserve CLI semantics, never falsely claim full coverage. `gate: error`
preserves the process exit; `report-only` maps valid supported findings to step
exit `0` while retaining raw `exit-code: 1` and unchanged SARIF. `sarif-valid`
means fresh validated publication, not absence of defects or complete coverage.
The analysis timeout is configurable with `timeout-seconds` (1–3600, default300).

`Dockerfile` separates the explicit `artifact-runtime` target from the final
default source-backed release rebuild. Both runtime images default to nonroot
UID/GID65532. The artifact profile consumes a previously verified package and a
caller-pinned cached base; it does not install packages or invent target SDKs.
The default networked rebuild retains its version override and is **not**
qualified by testing the offline target. `.dockerignore` defaults to excluding
context, with authored build/package inputs explicitly admitted. The helper
below additionally stages only the verified package and exact recipe into a
fresh minimal context, never the working checkout. Historical release source
contexts have their own context policy and are outside this claim.

Use a trusted Linux x86_64 package, Python, new output paths, and a working
rootless Podman with a cached compatible Linux amd64 base for the second step:

```bash
python3 -B scripts/action_local_smoke.py \
  --artifact /absolute/package.tar.gz --sha256 <exact-artifact-sha256> \
  --out /absolute/new-local-evidence
python3 -B scripts/action_container.py \
  --artifact /absolute/package.tar.gz --sha256 <exact-artifact-sha256> \
  --base-image <exact-cached-image-id> \
  --local-evidence /absolute/new-local-evidence --out /absolute/new-container-evidence
```

The container profile forbids pulls and build/run network, uses read-only root
and source mounts, drops capabilities, disables new privileges and checks the
nonroot caller identity. Only a new report bind is writable, plus restricted
1GiB temporary storage. Limits are two CPUs, 6GiB RAM/12GiB RAM+swap, 256 PIDs,
and a 120-second outer process wait. Created/terminal runtime settings and actual
binary hash/version are recorded. Cleanup removes only invocation-owned exact
container IDs; local image/context/evidence remain inspectable. Intrinsic-header
fixtures do not establish arbitrary target-header or platform support.

Actual local CLI/composite shell-step qualification passed 13 scans using the
U001 `0.4.9-dev+ga23cf3192648` package. Independent review confirmed six complete
SARIF comparisons and preserved raw report-only verdicts. This is not a hosted
Action run. The rootless/offline artifact profile subsequently passed six real
container scans with full CLI/Action/SARIF parity, measured binary hash/version,
created/terminal isolation checks and exact owned-container cleanup. The cached
base was Ubuntu24.04.4 amd64 (image ID
`045183670ef29ce21bc22a8d4f62511ce472679ca8fc9774f04181f7f383ca62`).
The first attempt failed before analysis because `/work` was absent under the
read-only profile; its failed records remain preserved. The corrected profile
uses the package directory already created by `COPY`.
The self-test workflow separates offline feature-push tests from successful
Release/explicit-manual asset checks, uses read-only repository permissions and
does not write status refs. A workflow edit is not successful hosted execution
or permission to publish a release.
