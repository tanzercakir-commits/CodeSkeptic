# ZeroDefect — To-Dos and Notes

## 📅 Tomorrow's plan (prepared for the 2026-07-10 session)

Suggested order — each item is an independent PR round:

1. **Juliet number analysis + weak-CWE rule improvement.** Start from
   PR #16's representative numbers (added/to be added to the README).
   Focus wherever mapped precision is lowest:
   - CWE415/416 good-function FPs: which FPs do the typical patterns of
     the Juliet good variants (goodB2G/goodG2B call chains) produce?
     Pick two or three sample files via the `function` field in
     `findings_*.json`, extract the pattern, apply a test-first fix to
     the rule.
   - CWE369: after strided sampling the int variants will become
     visible; conservative silence is correct for rand()/fgets-sourced
     flows (Unknown), `data=0` local flows should be caught.
2. **Pin corpus finding counts** (small round): an expected-finding-count
   file + tolerance; the corpus CI step goes red on deviation. An early
   catcher of semantic regressions.
3. **Move MemLeak's transfer to the top-node Effect pattern** (medium
   round): the pattern already in UninitPtr; the per-variable classify
   loop goes away, the MemLeak Juliet run speeds up too.
4. If time remains: a shared condition-walk helper (NullDeref +
   DivByZero applyCondition deduplication) — no behavior change, tests
   must stay unchanged.

Open user decisions (the 4 items in the roadmap artifact):
public v0.1 timing (my suggestion: after the Juliet numbers are in the
README), contract language syntax (co-design before Horizon 3),
Juliet's CI weight, project name check.

## Upcoming Tasks (roadmap: ROADMAP.md)

### Phase 1 leftovers
- [x] Per-function CFG cache (engine/CfgCache: memoized store keyed by
      FunctionDecl*; explicit cleanup at TU end + automatic flush on ctx
      change; build options in one place). 6+ builds per function → 1.
      (A single-pass engine redesign is a separate horizon — if needed.)
- [x] converged=false is now visible on stderr (AnalysisNotConverged,
      in 4 rules; i18n'd)
- [x] MemoryLeakRule moved to the top-node Effect pattern
      (classifyStmtEffects: an expression is classified once)

### Phase 2 leftovers
- [x] NIST Juliet measurement infrastructure (weekly workflow +
      juliet_eval; real numbers into the README after the first run)
- [x] First real Juliet run done (PR #14) — numbers and analysis in the
      changelog (2026-07-09 entry)
- [x] **Juliet measurement accuracy round**: strided sampling + mapped
      precision (`rprecision`) + double-free rule_id — see the
      2026-07-10 changelog entry. Bonus: a global filter leak was found
      in the single-process run and fixed (~StaticAnalyzer RAII;
      single-process test step added to CI).
- [ ] Representative numbers (from this PR's Juliet CI run) to be added
      to the README as a benchmark section
- [ ] Examine the CWE415/416 good-function FPs (real size becomes clear
      after mapped precision); interprocedural source/sink flow for the
      CWE401 file hit rate (known v1 limit)
- [x] Pin corpus finding counts (corpus_expected.txt: cjson 111,
      tinyxml2 9; 10%+2 tolerance; deviation = red = semantic regression)
- [x] Baseline v2: line-independent key (FNV-1a hash of the line
      content; multiset counter — identical findings tracked one by one;
      v1 files backward compatible)

### Rule improvement notes
- [ ] Juliet 44/45 families ("data passed via static global"): known FN
      after the escape refinement — storing an allocation into a
      global/static suppresses the local leak report by design.
      Catching it needs whole-program global-flow tracking (the summary
      infrastructure is the natural host).
- [x] **Abseil FP hunt (2026-07-12)**: scanned abseil-cpp (159 files,
      tag 20260526.0) — 40 findings triaged into 3 FP families, all
      fixed with FP-killer tests: (1) `__builtin_expect` transparency in
      walkCondition (ABSL_RAW_CHECK / likely-unlikely macros), (2)
      static/global storage exempt from end-of-function leak (the
      leak-on-purpose singleton idiom), (3) member-assign and
      method-receiver escapes. 40 → 12 findings; the remaining 12 are
      invariant-checked or genuinely-suspicious cases. abseil added to
      the corpus guard (deep/weekly, pin 12).
- [x] **shadPS4 FP hunt round 1 (2026-07-12)**: scanned shadPS4 (377
      src/ files, 209 findings). Fixed the call-boundary soundness
      family across all four rules (engine/CallRefArgs.h): a variable
      passed by NON-CONST REFERENCE must lose its dataflow fact — there
      is no AddrOf node to see, only the parameter type reveals the
      out-param. Also: explicit-cast transparency in MemoryLeak's
      escape analysis (`(void*)copy` callback args,
      `reinterpret_cast` out-params), member-of-reference-base
      assignments, composite call arguments (aggregate initializers
      wrapping the pointer), and DivByZero's missing `f(&z)`
      invalidation.
- [x] **Assert-opacity flood — `--fatal-asserts` (2026-07-12)**:
      configurable fatal-call list; engine kills dataflow paths at
      calls to registered names (empty by default — per-project
      opt-in). shadPS4's ~170-finding ASSERT flood collapses with
      `--fatal-asserts assert_fail_impl`. 7 FatalCallsTest pins.
- [ ] Address-of-member escape (found in shadPS4 round 2 triage):
      `TrackGeneratedGlyph(&boxed->glyph); *out = &boxed->glyph;` —
      handing out a member's address keeps the whole object reachable;
      the leak report on `boxed` (font.cpp:1718) is an FP. Rule:
      AddrOf of a MemberExpr whose base is tracked -> base escapes.
- [ ] **Report-flood dedup**: one root cause should not produce 25
      reports (shadPS4 internal__Foprep: a single missing return -> 25
      warnings on the same variable). Candidate: report only the FIRST
      deref per (variable, fact-origin) pair; later derefs become trace
      notes on the first finding.
- [x] **shadPS4 true positives REPORTED UPSTREAM (2026-07-12)** — the
      analyzer's first public real-world validation: (1) savedata.cpp
      sceSaveDataMount/Mount2 `&&`-vs-`||` null-check →
      shadps4-emu/shadPS4#4696; (2) usb_backend.h GetMaxPacketSize
      by-value nullptr desc (memcpy into null) →
      shadps4-emu/shadPS4#4697; (3) libc_internal_io.cpp
      internal__Foprep missing return after ENOMEM →
      shadps4-emu/shadPS4#4698. If maintainers answer "PR welcome",
      the three fix diffs are ready to draft (one-to-three-liners).
- ~~NullDeref multi-declaration FN~~ — invalidated by experiment: the
  fine-grained CFG splits a multi-declaration per variable, the second
  pointer is tracked too (pinned with regression tests, 2026-07-10).
- ~~Shared condition walk~~ — done (engine/ConditionWalk.h):
  walkCondition (generic skeleton: !, &&/||, variable-on-left
  normalization) + walkNullCondition (pointer-null domain). Four
  clients: NullDeref, MemLeak, FunctionSummary (null), DivByZero (zero,
  generic skeleton).

### Phase 3 (AI loop)
- [x] Incremental analysis primitive: --function filter + analyze_diff.sh
- [x] Incremental v2: --lines ranges + hunk parsing (fully automatic
      "analyze only the touched functions" loop)
- [x] Dataflow traces on findings (TraceNote; console/JSON/SARIF
      relatedLocations)
- [x] MCP server mode (--serve; initialize / tools/list / tools/call
      analyze)
- [x] Trace v2: guard/refine events in traces (onEdgeRefined engine
      hook — only in the reporting pass, only on state-changing edges;
      NullDeref "null on this branch", DivByZero "zero on this branch"
      notes)
- [x] MCP v2: AST/compilation cache in the warm process
      (path+build-path key, size+mtime fingerprint — a stale AST is
      never served; enabled only on the MCP path, off in the CLI; ~6x
      speed on repeat calls)

### UI — practicality + visuals
- [x] **HTML report**: `--html rapor.html` — a single, self-contained
      file; summary cards = filters (severity/rule), text filtering,
      traces with source context (`<details>`), dark/light theme
      automatic. Source lines are embedded at generation time — the
      report is portable.
- [x] **Editor integration doc**: SARIF guide in the README — VS Code
      SARIF Viewer (traces navigable as related locations) + GitHub
      code scanning upload-sarif YAML example. (A screenshot could not
      be captured from this environment — the user can add one if
      desired.)
- [ ] **Trend panel**: a static page (GitHub Pages) processing the
      weekly JULIET_RESULT/CORPUS_RESULT lines — F1/precision time
      series. The visual face of the score guard.
- [ ] (Evaluation) VS Code extension: live analysis via MCP/--serve +
      inline squiggles. Highest impact, highest cost — decide with
      feedback from the HTML report + SARIF experience.

### Phase 4 (research horizon)
- [x] Interprocedural v1: function summaries (return nullness +
      parameter effects; fixed-point scan, recursion-safe)
- [x] Interprocedural v2: alias tracking (copy graph + taint
      propagation; cursor-style destructors are Frees;
      dirty/multi-source/address-taken locals conservative)
- [x] Return-nullness dataflow: `return p;` paths resolved
      flow-sensitively with a mini null-flow (runDataflow client); param
      passthrough stays Unknown (a parameter-sensitive summary is a
      separate horizon)
- [x] Cross-TU summaries v1 (--whole-program two-pass mode; name+arity
      key, external linkage only, conservative merge on collision)
- [x] Cross-TU v2: write/load summaries to disk
      (--summary-out/--summary-in; versioned line format, corrupt file
      rejected wholesale, conservative merge on conflict; harvest in the
      rules pass — no second parse)
- [x] Cross-TU v3 endpoints: analyze_diff.sh --summary-in (extra-arg
      forwarding already existed, documented); `summaries` argument on
      the MCP analyze tool
- [x] Summary file staleness check (source mtime > summary mtime →
      stderr warning; analysis does not stop, summaries are still used)
- [ ] Juliet 61-family validation of return-flow: the weekly deep run
      (cron limit=1600) should show it in the trend; check the first
      cron result
- [x] Int return zeroness summary (ReturnZeroness; DivByZero consumes it
      via the assignment path — a direct `x/f()` divisor deliberately
      not reported; summary file format v2, v1 backward compatible)
- [x] Summary-diff v1 (--summary-diff old new): contract change report —
      WEAKENED (loss of a strong claim → callers affected, exit 1 = CI
      gate) / STRENGTHENED / CHANGED / ADDED / REMOVED. The core of the
      semantic regression signal; contract LANGUAGE design is separate
      (a co-design session with the user).
- [ ] Summary cache v2: in incremental mode only the changed function is
      refreshed (built on top of the diff)

## Completed Tasks

- [x] Core architecture (Diagnostic, Rule, SourceManager, RuleEngine, Reporter, Config, StaticAnalyzer)
- [x] UninitPointerRule_Ex (CFG dataflow, 14 tests)
- [x] MemoryLeakRule_Ex (CFG dataflow, leak + double-free + escape, 13 tests)
- [x] DivByZeroRule (literal + CFG dataflow, 10 tests)
- [x] DataflowEngine template (shared worklist infrastructure, SFINAE onStatement)
- [x] string.h warning fix (resource-dir + isysroot + isystem)
- [x] GTest infrastructure (41/41 tests)
- [x] Assessment + roadmap document (ROADMAP.md)
- [x] Linux header resolution fix (isystem macOS-only)
- [x] CMake portability (Homebrew prefix APPLE-only)
- [x] Cross-TU finding deduplication (operator== + std::unique)
- [x] i18n: EN default + --lang tr (core/Messages)
- [x] Assume edges: DataflowEngine refineOnEdge + DivByZero guard analysis (9 tests)
- [x] DivByZero merge fix (Zero + Unknown = MaybeZero)
- [x] GitHub Actions CI (Ubuntu 24.04 + LLVM 18)
- [x] README (EN) + LICENSE (Apache-2.0)
- [x] GTest 52/52
- [x] CFG granularity: setAllAlwaysAdd (subexpressions as elements — CSA parity)
- [x] UninitPointerRule product lattice + top-node dyn_cast (single run)
- [x] Iteration ceiling tied to lattice height (latticeHeight hook)
- [x] SARIF 2.1.0 reporter (--sarif, sarif_output=)
- [x] Suppression comments (disable-line / disable-next-line, rule list)
- [x] Use-after-free detection (MemLeak Freed state + dereference)
- [x] Baseline support (--write-baseline / --baseline)
- [x] NullDerefRule (NullState lattice + assume edges, 16 tests)
- [x] GTest 92/92
- [x] Real-world corpus in CI (cJSON + tinyxml2, scripts/run_corpus.sh)
- [x] Engine: post-fixpoint reporting pass (early-state severity bug)
- [x] Path canonicalization + macro expansion loc (corpus findings)
- [x] Best/worst-case stress suite (17 tests; documented FNs included)
- [x] MemLeak null-aware refineOnEdge (malloc-failure FP)
- [x] DivByZero onStatement top-node classification (ternary FP)
- [x] GTest 110/110

## Technical Notes (Keep in Mind)

### Severity enum order dependency
The severity filter in `StaticAnalyzer::run()` (`d.severity < config_.minSeverity()`) depends on the enum order: `Info=0, Warning=1, Error=2`. If a new level is inserted in between, both the enum in `core/Diagnostic.h` and this comparison must be updated.

### processAll callback — move safety
The `SourceManager::processAll` callback is taken by copy (not move). It can be called more than once.

### FixedCompilationDatabase working directory
Set to `"."` in the fallback case (not `build_path_`).

### JSON string escaping
`JsonReporter` writes JSON by hand. The `escapeJson` helper handles `"`, `\`, `\n`, `\r`, `\t`. Could migrate to nlohmann/json later.

### LLVM RTTI compatibility
LLVM is built with `-fno-rtti`. There is an `LLVM_ENABLE_RTTI` check in CMake.

### CMake C language requirement
The `project()` line must say `LANGUAGES C CXX` — LLVM's `check_include_file` macro requires C.

### StaticAnalyzer sourcePath — file vs directory
Checked with `is_directory`: `scanDirectory` for a directory, `addSourceFile` for a file.

### DataflowEngine — Analysis duck typing
The Analysis class must provide `State`, `initialState()`, `merge()`, `transfer()`. `onStatement()`, `refineOnEdge()` and `latticeHeight()` are optional (via SFINAE `if constexpr`). `DataflowResult` contains `exitBlockID` — no CFG rebuild is needed for the exit block check.

### Engine contract — transfer is pure, reporting happens at fixpoint
`transfer()` must be PURE (only returns state, produces no side effects) — it is called many times during the worklist phase. Reporting is done inside `onStatement()`; the engine calls it only in the reporting pass AFTER the fixpoint. Producing reports from early state yields wrong severity (the cJSON parse_array case, 2026-07-09).

### CFG granularity — setAllAlwaysAdd
The engine builds the CFG with `setAllAlwaysAdd`: subexpressions are separate elements in evaluation order (as in DumpCFG). Analyses must look ONLY at each element's top node; a findAll/descendant search is both unnecessary and double-triggers (the same expression appears both as its own element and inside the parent statement's element — that is why the report dedups exist).

### Assume edges — edge convention
On a two-successor terminator (if/while/for), `succ[0]` = the true branch, `succ[1]` = the false branch (Clang CFG convention). `refineOnEdge` is called only when `succ_size() == 2` and `trueSucc != falseSucc`; it is not called on multi-successor terminators such as switch. Refinement is applied on a copy of the predecessor's exit state, before the merge.

### UninitPointerRule_Ex — known limitations

**SOLVED (2026-07): CFG cache / classify cost.** Now a single CFG + a single dataflow run per function (product lattice); classify is top-node `dyn_cast`, O(1) per element. With `setAllAlwaysAdd` subexpressions are their own elements, so no nested search is needed.

**Compound expression false negative:** `*p = (p = &x, 42)` — evaluation order with the comma operator is problematic. Rare.

### MemoryLeakRule_Ex — known limitations

**Conditional double-free missed:** `if(c) delete p; delete p;` — merge `Freed + Allocated = Allocated`, the second delete is not caught. Requires path-sensitive analysis. (Pinned as a test: `DocumentedLimitTest.ConditionalDoubleFree_KnownFN`)

**Null-awareness EXISTS (2026-07):** the `p = malloc(); if (!p) return;` path is no longer a leak — refineOnEdge turns Allocated → None on the null edge.

**realloc's dual nature missing:** with `q = realloc(p, n)` the old p is invalid — we cannot catch it.

**Conservative escape:** `foo(p)` → Escaped. False negative if it does not take ownership. Needs an annotation system.

### DivByZeroRule — known limitations

**Guard analysis EXISTS (2026-07):** `if (z != 0) { x = 1/z; }` is now clean; `if (z == 0) 1/z` is a definite error. Supported patterns: `z`, `!z`, `==`/`!=` (zero and non-zero constant), `>`/`<`/`>=`/`<=` with a zero constant (mirrored forms included), `&&` true branch, `||` false branch. Unsupported: variable-variable comparison (`z != y`), conditions containing arithmetic.

**No expression-level constant folding:** cannot catch `a / (b - b)`. Only IntegerLiteral and simple variable tracking.

**Float division excluded:** in IEEE 754 `1.0/0.0 = inf`, not UB. Deliberate decision.

**Compound assignment not tracked:** expressions like `z -= z` do not even produce AssignsUnknown (not BO_Assign) — the state keeps the old value. Rare but wrong in direction: `CompoundAssignOperator` support could be added later.

### string.h / header resolution — solution
Via `ClangTool::appendArgumentsAdjuster()`: `-resource-dir` (all platforms), `-isysroot` + `-isystem /usr/include` (macOS only — `#ifdef __APPLE__`). On Linux, prepending `/usr/include` breaks the GCC libstdc++ `include_next` chain (stdlib.h cannot be found); resource-dir is sufficient there. The macOS SDK path is found with `xcrun --show-sdk-path`, the Clang resource dir with `clang -print-resource-dir` in CMake.
