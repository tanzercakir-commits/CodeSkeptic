# ZeroDefect — Progress Status

## Completed Components

| Component | Files | Status |
|-----------|-------|--------|
| Diagnostic | `src/core/Diagnostic.h` | Done (operator== + total ordering) |
| Rule | `src/core/Rule.h` | Done |
| Messages (i18n) | `src/core/Messages.h`, `.cpp` | Done (EN default, `--lang tr`) |
| SourceManager | `src/source_manager/SourceManager.h`, `.cpp` | Done (Linux header fix + warm AST cache, MCP path) |
| RuleEngine | `src/engine/RuleEngine.h`, `.cpp` | Done |
| DataflowEngine | `src/engine/DataflowEngine.h` | Done (template + assume edges + latticeHeight + fine-grained CFG + two-phase reporting) |
| PathFacts | `src/engine/PathFacts.h`, `.cpp` | Done (condition→canonical key; mutation visitor) |
| GuardedDisjuncts | `src/engine/GuardedDisjuncts.h` | Done (guarded disjunct template — used by 3 rules) |
| FunctionSummary | `src/engine/FunctionSummary.h`, `.cpp` | Done (TU-local + cross-TU store; --whole-program; write/load to disk) |
| Reporter (abstract) | `src/reporter/Reporter.h` | Done |
| ConsoleReporter | `src/reporter/ConsoleReporter.h`, `.cpp` | Done |
| JsonReporter | `src/reporter/JsonReporter.h`, `.cpp` | Done |
| SarifReporter | `src/reporter/SarifReporter.h`, `.cpp` | Done (SARIF 2.1.0) |
| HtmlReporter | `src/reporter/HtmlReporter.h`, `.cpp` | Done (single file; filters + source-context traces) |
| SuppressionFilter | `src/analyzer/SuppressionFilter.h`, `.cpp` | Done (disable-line / next-line) |
| Baseline | `src/analyzer/Baseline.h`, `.cpp` | Done (v2: line-independent content-hash key; v1 compatible) |
| Config | `src/config/Config.h`, `.cpp` | Done (including `--lang`) |
| StaticAnalyzer | `src/analyzer/StaticAnalyzer.h`, `.cpp` | Done (cross-TU dedup) |
| UninitPointerRule_Ex | `src/rules/UninitPointerRule_Ex.h`, `.cpp` | Done (product lattice + guarded disjuncts) |
| MemoryLeakRule_Ex | `src/rules/MemoryLeakRule_Ex.h`, `.cpp` | Done (leak + double-free + UAF; disjuncts + Effect pattern + summary consumption) |
| DivByZeroRule | `src/rules/DivByZeroRule.h`, `.cpp` | Done (literal + CFG + guard analysis) |
| NullDerefRule | `src/rules/NullDerefRule.h`, `.cpp` | Done (NullState + assume edges + disjuncts + return-nullness summary) |
| main.cpp | `src/main.cpp` | Done (4 rules registered, 5 rule_ids) |
| CMake build system | `CMakeLists.txt`, `src/CMakeLists.txt` | Done (Linux + macOS) |
| CfgCache | `src/engine/CfgCache.h`, `.cpp` | Done (one CFG per function; TU-end cleanup + ctx-change safety) |
| SummaryDiff | `src/engine/SummaryDiff.h`, `.cpp` | Done (--summary-diff; WEAKENED = exit 1 CI gate) |
| CallRefArgs | `src/engine/CallRefArgs.h` | Done (non-const ref args invalidate facts; all four rules) |
| FatalCalls | `src/engine/FatalCalls.h`, `.cpp` | Done (--fatal-asserts; engine-level path kill) |
| AllocFunctions | `src/engine/AllocFunctions.h`, `.cpp` | Done (--alloc-functions/--free-functions) |
| GTest infrastructure | `tests/` | Done (300/300; ctest + single-process) |
| CI | `.github/workflows/ci.yml` | Done (build + test + smoke + corpus) |
| Corpus script | `scripts/run_corpus.sh` | Done (cJSON v1.7.18 + tinyxml2 10.0.0) |
| Juliet benchmark | `scripts/run_juliet.sh`, `juliet_eval.py`, `juliet.yml` | Full integration: F1 + score guard; runs on every code PR (drafts excluded); numbers in the README |
| README / LICENSE | `README.md`, `LICENSE` | Done (EN, Apache-2.0) |
| Assessment / roadmap | `ROADMAP.md` | Done |

## Open Issues

None. (See `todo.md` for known analysis limitations.)

## Directory Layout

```
ZeroDefect/
├── CMakeLists.txt
├── README.md
├── LICENSE
├── architecture.txt
├── ROADMAP.md
├── progress.md
├── todo.md
├── changelog.md
├── .github/workflows/ci.yml
├── src/
│   ├── CMakeLists.txt
│   ├── main.cpp
│   ├── analyzer/
│   │   ├── StaticAnalyzer.h
│   │   └── StaticAnalyzer.cpp
│   ├── config/
│   │   ├── Config.h
│   │   └── Config.cpp
│   ├── core/
│   │   ├── Diagnostic.h          (header-only)
│   │   ├── Messages.h/.cpp       (i18n: EN/TR message table)
│   │   └── Rule.h                (header-only)
│   ├── engine/
│   │   ├── DataflowEngine.h      (template, header-only)
│   │   ├── RuleEngine.h
│   │   └── RuleEngine.cpp
│   ├── reporter/
│   │   ├── Reporter.h            (abstract)
│   │   ├── ConsoleReporter.h/.cpp
│   │   └── JsonReporter.h/.cpp
│   ├── rules/
│   │   ├── UninitPointerRule_Ex.h/.cpp  (CFG dataflow)
│   │   ├── MemoryLeakRule_Ex.h/.cpp     (CFG dataflow)
│   │   └── DivByZeroRule.h/.cpp         (literal + CFG dataflow)
│   └── source_manager/
│       ├── SourceManager.h
│       └── SourceManager.cpp
├── tests/
│   ├── CMakeLists.txt
│   ├── TestHelper.h/.cpp
│   ├── DiagnosticTest.cpp          (6 tests: 4 + dedup + i18n)
│   ├── UninitPointerRuleExTest.cpp (14 tests)
│   ├── MemoryLeakRuleExTest.cpp    (13 tests)
│   └── DivByZeroRuleTest.cpp       (19 tests: 10 + 9 guard)
├── test_projects/
│   ├── cJSON/                      (C test project)
│   └── tinyxml2/                   (C++ test project)
```
