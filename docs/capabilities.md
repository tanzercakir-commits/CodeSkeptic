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
| Memory leak | `memory-leak` | experimental | on | no | report-only |
| Double free | `double-free` | supported | on | yes | blocking |
| Use after free | `use-after-free` | supported | on | yes | blocking |
| Resource leak (`FILE*`/`DIR*`) | `resource-leak` | experimental | on | no | report-only |
| Division by zero | `div-by-zero` | supported | on | yes | blocking |
| Null dereference | `null-deref` | supported | on | yes | blocking |
| Array/heap bounds | `bounds` | experimental | on | no | report-only |
| Integer overflow/underflow | `int-overflow` | supported | on | yes | blocking |
| Sign conversion | `sign-conversion` | experimental | on | no | report-only |
| Allocation-size overflow | `alloc-size-overflow` | experimental | on | no | report-only |
| Inferred assumption | `assumption` | experimental | off | no | report-only |
| Contract verification | `contract` | experimental | on | no | report-only |
| Policy enforcement | `policy` | experimental | on | no | report-only |

The supported evidence is the pinned Juliet precision gate: double-free
1.000 (97 TP / 0 FP), use-after-free 1.000 (198 / 0), div-by-zero 1.000
(43 / 0), null-deref 1.000 (140 / 0), and int-overflow 1.000 (21 / 0).
`memory-leak` remains experimental at 0.714 precision until Phase 3 reaches
at least 0.85. Families without an independent precision sample remain
experimental even when other clean-corpus tests cover them.

The four heap/resource finding IDs share the `memory-leak` engine pass.
`--disable-rule memory-leak` disables that pass; their verdict tiers are
still decided independently from each emitted finding ID.
`contract-syntax` and `contract-unsupported` are internal diagnostics, not
separate selectable rules; both inherit the experimental `contract` tier.

## Explicit non-goals

The v1 scope excludes injection/taint analysis, race detection, automatic
fixes, an IDE product, and a cloud dashboard. These are published as
`injection-taint`, `race-detection`, `automatic-fixes`, `ide`, and
`cloud-dashboard` in capability JSON. CWE count is explicitly not a success
metric; measured precision, recall, coverage and reproducibility are.
