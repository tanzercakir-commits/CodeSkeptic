# Usage reference

The complete CLI surface, configuration file, suppression comments, and
the baseline/incremental workflows. For a five-minute start, see the
[README quickstart](../README.md#quickstart); to evaluate CodeSkeptic on
your own project, follow [evaluate.md](evaluate.md).

## CLI options

```
codeskeptic <source_path> [options]

  --source <path>        Directory/file to analyze
  --build-path <path>    compile_commands.json directory
  --json <file>          JSON output file
  --sarif <file>         SARIF 2.1.0 output file (GitHub code scanning)
  --html <file>          Self-contained HTML report: summary cards double
                         as filters, dataflow traces open with embedded
                         source context, dark/light theme — works offline
  --severity <level>     Minimum severity (info/warning/error)
  --disable-rule <id>    Disable a rule
  --baseline <file>      Suppress findings recorded in the baseline
  --write-baseline <file> Record current findings as the baseline
  --function <names>     Analyze only these functions (comma list,
                         plain or qualified names; repeatable)
  --lines <N-M,K>        Analyze only functions overlapping these line
                         ranges of the analyzed file
  --fatal-asserts <names> Treat these functions as never returning
                         (comma list). For projects whose assert-failure
                         handler deliberately lacks [[noreturn]]: kills
                         the failure path so guarded code stops warning
                         (e.g. --fatal-asserts assert_fail_impl)
  --assert-macros <names> Also treat these macros as assertions (comma
                         list). Macro names containing "assert" (any
                         case) are recognised automatically; use this
                         for project spellings that do not
                         (e.g. --assert-macros CHECK_PTR,REQUIRE).
                         Only single-argument macros are recovered. A
                         name listed here also overrides the veto on
                         negative-sounding names, so list ASSERT_NOT_NULL
                         if you have one -- but never a macro that
                         asserts a NEGATIVE (cmocka's assert_null and
                         friends): it would be believed backwards.
                         Every recognised macro -- listed or automatic --
                         must TERMINATE on failure. A log-and-continue
                         "soft assert" compiled out by NDEBUG is
                         indistinguishable from a real one (the erased
                         body leaves only the name to judge by), and
                         believing it hides real findings behind a
                         check that never stopped anything
  --negative-assert-macros <names> Macro names that assert a pointer IS
                         null/empty/unset (comma list). A vanished assert
                         leaves only its NAME to judge direction by, so a
                         built-in null-ness vocabulary (null, nil, false,
                         zero, not, fail, none, empty, absent, missing,
                         unset) is vetoed automatically -- a negative
                         macro using one of those words is never believed
                         as non-null. That list cannot be complete;
                         RESIDUAL FAILS-OPEN: a negative macro whose name
                         uses none of those words (say ASSERT_CLEARED)
                         would be believed backwards, silencing a
                         definitely-null finding. List such a name here to
                         veto it. A negative declaration wins over
                         --assert-macros on conflict -- over-vetoing costs
                         only recall, inverting a fact costs correctness
  --no-assert-recovery   Disable vanished-assert recovery. By default,
                         an assertion compiled out by NDEBUG (its
                         condition never reaches the parser) is
                         recovered from the preprocessor and its
                         null-check believed. This flag reports the
                         code exactly as the shipped build sees it
  --alloc-functions <names> Treat these functions as heap allocators
                         (comma list). Extends leak/double-free/UAF
                         analysis to project wrappers
                         (e.g. --alloc-functions git__malloc,zmalloc)
  --free-functions <names> Treat these functions as deallocators
                         (their first argument is freed)
  --owning-pointers <names> Treat these class templates as owning smart
                         pointers (comma list). A raw pointer adopted by
                         constructing one is no longer leaked;
                         std::unique_ptr/shared_ptr are built in
                         (e.g. --owning-pointers Ref,RefPtr,scoped_refptr)
  --untrusted-int-sources <names> Treat these functions' return as a
                         full-range untrusted integer (comma list), the
                         same discipline as atoi/strtol. For protocol/parser
                         length fields read off the wire, so downstream
                         length arithmetic that can overflow is reported
                         (e.g. --untrusted-int-sources read_u16,packet_len)
  --report-paths <paths> Report only findings under these path prefixes
                         (comma list). Filters out findings in dependency
                         headers pulled into your TUs; analysis itself is
                         unaffected (e.g. --report-paths $PWD/src)
  --whole-program        Two-pass mode: collect function summaries
                         across all files first, then analyze
  --summary-out <file>   Save harvested cross-file summaries to a file
  --summary-in <file>    Load summaries saved earlier (incremental
                         whole-program: single-file analysis with
                         whole-project knowledge)
  --lang <en|tr>         Diagnostic message language (default: en)
  --capabilities [--json] Print the tiered product scope and exit
```

The verdict contract is stable: `0` means complete evidence with no blocking
findings (it may include experimental report-only findings), `1` means a
complete analysis with supported findings, and `2` means no trustworthy
verdict was produced (invalid input/config, incomplete coverage/evidence,
or an output artifact could not be written). Integrations must never turn
`2` green. The tier matrix is the [capability contract](capabilities.md).

JSON, SARIF and HTML artifacts carry that same status and exit code together
with translation-unit/dataflow coverage. An empty HTML findings list says
“Clean” only when the evidence is complete; an unavailable verdict stays
visibly unavailable.

Every finding also carries the same stable semantic fingerprint. JSON and MCP
use the `fingerprint` field, SARIF uses
`partialFingerprints["codeskeptic/v1"]`, and HTML displays the value and stores
it in `data-fingerprint`. The current `csf1-<16 lowercase hex digits>` schema
tracks a rule at a normalized source statement across checkout roots, harmless
line shifts, formatting-only edits, severity changes and message rewrites. It
is a site identity, not a cryptographic digest; consumers must retain counts
when identical sites occur more than once. The exact schema and PR comparison
contract are documented in [benchmarks.md](benchmarks.md#pr-measurement-laboratory).

Machine-readable capability discovery does not start an analysis:

```bash
codeskeptic --capabilities --json
```

**Environment:** `CODESKEPTIC_RESOURCE_DIR` overrides the Clang
resource directory (intrinsic headers). Normally unnecessary — release
tarballs bundle the headers next to the binary (`lib/clang/<N>/include`,
found automatically), and source builds bake the build machine's path.
Set it only when analyzing with a resource dir in a non-standard place.

## Configuration file

Options can also be set in a `.codeskeptic.conf` file (`key=value` lines;
whitespace around `=` is accepted, while unknown keys and invalid values
fail with exit `2`):
`source_path`, `build_path`, `output_format`, `json_output`,
`sarif_output`, `min_severity`, `enable_rule`, `disable_rule`, `lang`,
`function`, `fatal_asserts`, `assert_macros`, `assert_recovery`,
`alloc_functions`, `free_functions`).

Project idioms are configuration, not code: allocator wrappers, fatal
assert handlers and owning smart pointers belong in the project's conf
file so the analysis sees the code the way the project means it.

## Suppressing findings

Individual findings can be suppressed with source comments:

```cpp
int x = 1 / z;  // codeskeptic-disable-line
int y = 1 / w;  // codeskeptic-disable-line div-by-zero

// codeskeptic-disable-next-line memory-leak
p = new int(7);
```

A bare marker suppresses every rule on that line; a comma- or
space-separated rule list limits it to those rules. The count of
suppressed findings is reported on stderr.

## Baseline workflow

Adopting the analyzer on an existing codebase without fixing every
legacy finding first:

```bash
codeskeptic src/ --write-baseline .codeskeptic-baseline   # record & exit clean
codeskeptic src/ --baseline .codeskeptic-baseline         # only NEW findings fail
```

Baseline keys are **line-independent**: instead of the line number they
hash the (whitespace-trimmed) text of the finding's source line, so
adding or removing code elsewhere in the file does not invalidate the
baseline. If the flagged line itself changes, the finding resurfaces as
new — deliberately, since a changed line deserves a fresh look.
Identical findings on identical lines are tracked by count, so
baselining one occurrence never hides a second one. Old (v1,
line-numbered) baseline files keep working with their original meaning;
rewrite with `--write-baseline` to migrate.

## Incremental analysis

For edit-check loops (agents, IDEs, pre-commit hooks) analyze only what
changed:

```bash
# re-check just the function you edited (milliseconds)
codeskeptic src/parser.cpp --function Parser::parse

# analyze only the functions actually touched since a git ref:
# the script extracts changed line ranges from diff hunks and passes
# --lines per file, so untouched functions are skipped entirely
scripts/analyze_diff.sh build/src/codeskeptic origin/main --severity error
```

Cross-file knowledge survives incremental runs via summary files:

```bash
# once (or nightly): harvest function summaries from the whole project
codeskeptic src/ --summary-out .codeskeptic-summaries

# then: analyze just the changed file WITH whole-project knowledge —
# e.g. a callee in another file that may return null is still known
codeskeptic src/parser.cpp --summary-in .codeskeptic-summaries

# analyze_diff.sh forwards extra options, so the diff loop composes:
scripts/analyze_diff.sh build/src/codeskeptic origin/main \
    --summary-in .codeskeptic-summaries --severity error
```

The MCP `analyze` tool accepts the same file via its optional
`summaries` argument, so agent loops get cross-file knowledge too
(see [integrations.md](integrations.md#mcp-server-agent-integration)).

Stale or malformed summary files are rejected whole (analysis continues
without them, conservatively); conflicting entries merge toward the
weaker claim, so a wrong strong claim cannot enter through the file.
The current v9 format includes exact pointer return-alias identity, inferred
non-null parameter preconditions (crash versus rejected-call consequence),
exact Null/NonNull normal-return effects for `T**`/`T*&` output slots,
pointee access (`none/read/write/read+write`), parameter ownership
(`borrowed/consumed/transferred`), and non-null return ownership
(`borrowed/owned`). Readers remain backward compatible with v1-v8 files;
version-specific field counts, codes, and parameter-vector lengths are
strict, so a newer column under an older header or a truncated vector is
rejected rather than guessed.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Complete analysis; no supported/blocking findings (experimental findings may be report-only), or baseline recorded successfully. |
| 1 | Complete analysis; at least one supported/blocking finding was reported. |
| 2 | **Verdict unavailable** — invalid CLI/config, no inputs, skipped TUs, incomplete dataflow/summary evidence, or artifact I/O failure. |

A partially broken run fails closed with `2`. A deliberately scoped adoption
harness may pass `--accept-partial-coverage` to restore a findings-based exit
over the analyzed subset; attempted/analyzed/broken counts and warnings remain
visible. This is different from `--analyze-broken-tus`, which runs rules over
Clang's error-recovery AST and accepts that additional reliability risk.
