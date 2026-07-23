# CodeSkeptic — Roadmap (curated)

Updated 2026-07-22. This is the short, current view. The complete
engineering journal this summary is distilled from — every hunt,
false-positive family, ablation and design decision since day one —
lives in [`docs/devlog/`](docs/devlog/) (ROADMAP-full.md, changelog.md).

## 1. Where the project stands (v0.3)

- Eight rule families plus contract verification and policy
  enforcement, all CFG-dataflow based, with dataflow traces on every
  finding ([docs/engine.md](docs/engine.md)).
- Interprocedural v1: deterministic function summaries (nullness,
  zeroness, parameter effects), cross-TU via `--whole-program`,
  serializable for incremental runs and semantic summary-diff gating.
- Measured on three gated axes: Juliet (six pinned per-CWE CI
  floors), the real-world corpus (pinned counts), and the frozen
  blind first-draft thesis corpus (0 FP / 9-of-9 in-scope, gating
  every PR) — [docs/benchmarks.md](docs/benchmarks.md).
- Proven in the wild: systemd/shadPS4/libgit2/llama.cpp scans triaged
  by hand; two findings fixed and merged upstream by shadPS4
  maintainers; three more reports drafted (libgit2 ×11, rtp2httpd,
  Redis).
- Distribution surfaces working today: CLI, MCP server, SARIF (code
  scanning + VS Code), HTML reports, diff-native PR review script.

## 2. Positioning

A precision-first *complementary* layer, not a replacement for
compiler warnings, sanitizers, broad analyzers, fuzzing or tests
([docs/comparison.md](docs/comparison.md)). The mission surface is the
AI coding loop: millisecond re-checks of just-edited functions, with
deterministic, trace-backed verdicts an agent can act on.

## 3. Current round — v0.4 "critique response" (week of 2026-07-22) — SHIPPED

An external reviewer's assessment was verified point by point and
turned into a phased plan with tests, guards and definition-of-done
per phase — the working plan is committed at
[docs/PLAN-v0.4.md](docs/PLAN-v0.4.md) (in Turkish; phases summarized):

- **Phase 0 — first five minutes:** README re-architecture (quickstart
  up top, honest-limits and use-alongside sections, deep content
  layered into docs/), this document, and a docs CI guard.
- **Phase 1 — frictionless install:** release binaries (Linux x86_64,
  macOS arm64), a Docker image on ghcr.io, and a packaged GitHub
  Action with report-only default gating.
- **Phase 2 — rule quality:** memory-leak FP taxonomy toward ≥0.80
  precision; div-by-zero / int-overflow FN classification
  (addressable vs by-design) and the addressable slice closed; the
  blind-corpus thesis test wired into CI as a standing recall gate.
- **Phase 3 — ecosystem proof:** the drafted upstream reports filed;
  `docs/reproduce.md`; per-project idiom `profiles/`; CONTRIBUTING and
  good-first-issues.
- **Phase 4 — Windows, staged honestly:** the SARIF drive-letter/UNC
  absolute-path fix landed early; Tier 1 (MSVC build + full test
  suite, `windows-latest` ratchet, phase7-windows-native) and Tier 2
  (plain-terminal directory mode, closed by measurement and guarded,
  phase8-windows-sdk) are done — [status](docs/windows-support.md).
  Prebuilt Windows binary remains open.

## 4. Open architectural decisions

- **4.A Contract language (the keystone):** how far the `cs:` grammar
  grows (temporal/typestate properties are designed and deliberately
  parked — see TYPESTATE_FEASIBILITY.md); adoption semantics stay
  "tools propose (`cs:ai`), humans adopt".
- **4.B Engine philosophy — evolve vs rewrite:** the worklist engine
  keeps evolving (guarded disjuncts, implication mining); a
  from-scratch symbolic core is explicitly not planned while each
  precision/recall step still lands as an ordinary guarded PR.
- **4.C Distribution & idiom profiles:** packaging order resolved by
  the v0.4 round (binary + Docker + Action first); per-project idiom
  profiles ship as configuration in `profiles/`.

## 5. After v0.4 (unordered backlog)

Windows prebuilt binary + packaging (per [docs/windows-support.md](docs/windows-support.md)) ·
remaining real-world FP families (fstab-util correlation, llama
header-template convergence residue, ternary-value FN) · Redis idiom
round 2 · whole-program global-flow tracking for the Juliet 44/45
static-global families · VS Code extension (evaluated, deferred) ·
Homebrew tap if demand shows.
