# Capability contract

This is the human-readable counterpart of `codeskeptic --capabilities
--json`. Schema v2 keeps the v1 name arrays and adds tiered
`rule_capabilities`, so existing discovery consumers do not lose fields. The
runtime registry in `src/core/RuleCapabilities.def` is the single source of
truth; CI rejects drift in this document or the README.

## Tiers and verdicts

- `supported`: enabled by default, protected by a measured quality gate,
  and its findings block a complete analysis with exit 1.
- `experimental`: still measured and fully reported, but its findings are
  report-only and cannot make an otherwise complete analysis fail.
- `out-of-scope`: deliberately absent from the v1 product scope.

Exit 0 means complete evidence with no blocking findings; it can contain
experimental report-only findings. Exit 1 means at least one supported
finding. Exit 2 still means no trustworthy verdict and can never be relaxed.
JSON, SARIF, HTML and MCP expose total, blocking and report-only counts.

## Product surfaces

| Group | Capability | ID | Tier |
|---|---|---|---|
| Language | C | `c` | supported |
| Language | C++ | `cpp` | supported |
| Frontend | CLI | `cli` | supported |
| Frontend | MCP | `mcp` | supported |
| Output | console | `console` | supported |
| Output | JSON | `json` | supported |
| Output | SARIF 2.1.0 | `sarif-2.1.0` | supported |
| Output | HTML | `html` | supported |
| Mode | baseline | `baseline` | supported |
| Mode | function scope | `function-scope` | supported |
| Mode | line scope | `line-scope` | supported |
| Mode | whole-program | `whole-program` | experimental |
| Mode | incremental summaries | `incremental-summaries` | experimental |
| Non-goal | Injection/taint analysis | `injection-taint` | out-of-scope |
| Non-goal | Race detection | `race-detection` | out-of-scope |
| Non-goal | Automatic fixes | `automatic-fixes` | out-of-scope |
| Non-goal | IDE product | `ide` | out-of-scope |
| Non-goal | Cloud dashboard | `cloud-dashboard` | out-of-scope |

## Finding rules

“Default” describes ordinary CLI registration. `assumption` additionally
requires `--assumptions`; configuration-dependent rules remain loaded but
stay silent until their source/contract/policy signal exists.

| Rule | ID | Tier | Default | Quality gate | Verdict |
|---|---|---|:---:|:---:|---|
| Uninitialized pointer | `uninit-ptr` | experimental | on | no | report-only |
| Uninitialized scalar | `uninit-scalar` | experimental | on | no | report-only |
| Memory leak | `memory-leak` | supported | on | yes | blocking |
| Double free | `double-free` | supported | on | yes | blocking |
| Use after free | `use-after-free` | supported | on | yes | blocking |
| Resource leak (`FILE*`/`DIR*`/POSIX fd) | `resource-leak` | supported | on | yes | blocking |
| Division by zero | `div-by-zero` | supported | on | yes | blocking |
| Null dereference | `null-deref` | supported | on | yes | blocking |
| Array/heap bounds | `bounds` | experimental | on | no | report-only |
| Integer overflow/underflow | `int-overflow` | supported | on | yes | blocking |
| Sign conversion | `sign-conversion` | experimental | on | no | report-only |
| Allocation-size overflow | `alloc-size-overflow` | experimental | on | no | report-only |
| Inferred assumption | `assumption` | experimental | off | no | report-only |
| Contract verification | `contract` | experimental | on | no | report-only |
| Policy enforcement | `policy` | experimental | on | no | report-only |

`uninit-scalar` currently handles straight-line automatic integer/bool value
reads, including compound updates. Initializers, assignment-first, ordinary
`sizeof`/`alignof`/`noexcept`, address-taking and zero-initialized static/thread-local
storage do not invent uninitialized reads. Address/reference escapes become
unknown, not proven initialized. Volatile locals, enums, aggregates, heap storage,
branch/loop merges, exception flow and unsupported/unspecified expression sequencing
are outside this first unit; such functions do not acquire a straight-line proof.
`uninit-ptr` remains the separate pointer-dereference rule. Neither rule claims
complete CWE-457 coverage or a measured precision tier for the new scalar subset.

The supported evidence is the pinned Juliet precision gate: double-free
1.000 (101 TP / 0 FP), use-after-free 1.000 (212 / 0), div-by-zero 1.000
(43 / 0), null-deref 1.000 (140 / 0), and int-overflow 1.000 (23 / 0).
Phase 3 promoted `memory-leak` after it reached 0.860 precision (80 TP /
13 FP), above its 0.85 product gate. Phase 5 promoted `resource-leak` after
the pinned libarchive v3.8.9 clean run removed all 12 manually adjudicated
false reports and a separate load-bearing mutation run produced exactly
3 TP / 0 FP: precision 1.000 at the 0.90 gate. Families without an
independent precision sample remain experimental.

Heap, `FILE*`, and `DIR*` findings come from the `memory-leak` engine
pass; POSIX integer-descriptor findings come from the separate
`resource-leak` rule. `--disable-rule memory-leak` disables the pointer
pass, while `--disable-rule resource-leak` disables the descriptor pass.
Verdict tiers are decided from each emitted finding ID.
`contract-syntax` and `contract-unsupported` are internal diagnostics, not
separate selectable rules; both inherit the experimental `contract` tier.

### CWE metadata

These are possible mappings for each family, not a claim that every finding
has every listed weakness. The registry preserves all existing maturity and
verdict flags. JSON `rule_metadata.cwes` and SARIF
`properties["codeskeptic/ruleMetadata"].cwes` contain the selected finding
mapping; CLI discovery lists `potential_cwes`. Each numeric entry includes
its explanation and canonical MITRE definition link. No CWE is invented for
assumptions, contracts or project policy.

<!-- CWE-METADATA-BEGIN -->
| Rule ID | Potential CWE IDs | Description |
|---|---|---|
| `uninit-ptr` | CWE-824 | Dereference of an uninitialized pointer |
| `uninit-scalar` | CWE-457 | Read of an uninitialized automatic scalar |
| `memory-leak` | CWE-401 | Owned allocated memory is not released |
| `double-free` | CWE-415, CWE-675 | Repeated release of memory or a resource |
| `use-after-free` | CWE-416, CWE-672 | Use of memory or a resource after release |
| `resource-leak` | CWE-775 | File stream, directory handle or descriptor left unclosed |
| `div-by-zero` | CWE-369 | Division or remainder with a zero divisor |
| `null-deref` | CWE-476 | Dereference of a null pointer |
| `bounds` | CWE-120, CWE-125, CWE-787, CWE-823 | Out-of-range memory access, pointer offset or unchecked copy |
| `int-overflow` | CWE-190, CWE-191, CWE-681 | Signed arithmetic or destination conversion exceeds its range |
| `sign-conversion` | CWE-195, CWE-681 | Negative-to-unsigned or lossy narrowing conversion reaches a sink |
| `alloc-size-overflow` | CWE-131 | Unsigned size calculation can under-allocate a buffer |
| `assumption` | none | Report of an inferred analysis assumption |
| `contract` | none | Declared contract violation or contract-processing limitation |
| `policy` | none | Configured project policy violation |
<!-- CWE-METADATA-END -->

The producer's typed kind, never the translated message, selects the mapping.
Reads use CWE-125, writes CWE-787, read-modify-write both; invalid address-only
offsets use CWE-823. Unchecked string copies use CWE-120, but `memset` remains
a write. Signed arithmetic upper/lower excursions use CWE-190/CWE-191;
lossy destination narrowing uses CWE-681. If a multi-CWE family has no proven
subtype, `cwe_mapping` is `unclassified` with an empty selected CWE list;
it does not inherit the family set. `not-applicable` identifies project-only
rules. Unknown rules retain their existing fail-closed verdict behavior.

The rule help URI points to the published capability overview; per-CWE links
point directly to MITRE. This branch's new metadata documentation is not a
claim that the branch has been merged into the published default branch.

### Arithmetic direction and baseline compatibility


The stable `int-overflow` family distinguishes a result above the arithmetic
type's maximum from one below its minimum; addition, subtraction and
multiplication can each cross either limit. When bounded interval witnesses
reach both limits, the message describes both possibilities. Implicit signed
narrowing instead names the narrower destination and describes conversion
range loss, not overflow of the wider arithmetic type. Unknown ranges do not
gain a new detection merely from this metadata distinction.

Corrected direction messages can make old baseline entries stop matching:
the existing baseline formats include diagnostic message text in their keys.
Review resurfacing findings before refreshing a baseline; do not treat this
presentation correction as evidence of a newly introduced source defect.
The public rule ID, source-comment suppression and `csf1` source fingerprints
are unchanged. This is not a claim of message-independent baseline matching.

## Explicit non-goals

The v1 scope excludes injection/taint analysis, race detection, automatic
fixes, an IDE product, and a cloud dashboard. These are published as
`injection-taint`, `race-detection`, `automatic-fixes`, `ide`, and
`cloud-dashboard` in capability JSON. CWE count is explicitly not a success
metric; measured precision, recall, coverage and reproducibility are.
