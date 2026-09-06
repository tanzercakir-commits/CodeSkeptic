# Bounded frontend / CFG corpus

Run `python3 -B scripts/run_stress_matrix.py <codeskeptic-binary> --out <new-report.json>`.
No network, corpus download, system headers or external project is needed.
Every case receives one exact temporary compilation command and a fresh report.

- `templates.cpp`: 32-level constexpr instantiation, dependent type/member names,
  and safe/seeded null-dereference variants.
- `macros.cpp`: nested expansion, 16 guarded paths, safe/seeded division variants.
- `high_cfg.cpp`: 64 switch arms, loop back-edge, nested branches and early exits;
  safe/seeded null-dereference variants.
- The template input is also compiled with an intentionally low depth limit of
  16. The same input succeeds with the normal limit. The low-limit case must
  return exit 2, the exact `broken_translation_unit` source reason, incomplete
  coverage and the compiler's depth diagnostic, not a crash or clean verdict.

The default per-case deadline is 10 seconds. A timeout is external runner
evidence, not a JSON AnalysisResult allegedly emitted by a killed analyzer.
The report separates `qualification_passed` from `coverage_complete`: expected
compiler-limit rejection can pass qualification but must remain incomplete.
Timeouts, crashes, malformed reports, wrong source/command counters and missing
expected findings fail qualification. The contract tests include real sleeping,
failing and signalled subprocesses; POSIX timeout cleanup covers the owned group.

This is a small repeatable qualification profile, not exhaustive frontend/CWE
coverage or the product worker/resource-budget system planned in CH04.
