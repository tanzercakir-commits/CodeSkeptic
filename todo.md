# ZeroDefect — To-Dos and Notes

## 📅 2026-07-10 session plan (ARCHIVED — all four items shipped that week)

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
- [x] Representative numbers added to the README as a benchmark
      section (2026-07-12 round, with the real-world scan table)
- [ ] Examine the CWE415/416 good-function FPs (real size becomes clear
      after mapped precision); interprocedural source/sink flow for the
      CWE401 file hit rate (known v1 limit)
- [x] Pin corpus finding counts (corpus_expected.txt: cjson 111,
      tinyxml2 9; 10%+2 tolerance; deviation = red = semantic regression)
- [x] Baseline v2: line-independent key (FNV-1a hash of the line
      content; multiset counter — identical findings tracked one by one;
      v1 files backward compatible)

### Contracts (CONTRACTS.md; v1 COMPLETE — Rounds B/C/D/E shipped 2026-07-13)
- [x] Round C: `requires p != null` / `requires n != 0` — callee-side
      seeding (contract carries the proof burden) + caller-side
      violation checks at every visible call site (NullDeref owns the
      null domain, DivByZero the zero domain; the shared recognizer is
      contracts/ContractInfo). Relational requires
      (`p != null || n <= 0`) seeds a split initial state via fact
      keys and honors literal escape arguments at call sites.
      Residual (noted in CONTRACTS.md §7): non-literal escape
      arguments stay conservative (silent); caller-side state for the
      escape param could refine that in a later round.
- [x] Round D: guarded ensures (`ensures return != null if g`)
      per-disjunct return checking (guard keyability decided in
      ContractInfo, shared with ContractRule — no silent hole);
      `owns/borrows` vs param-effect summaries (ReadsOnly violates
      owns, Frees violates borrows; Stores/Opaque explicitly
      unverified); violation traces attached to contract findings.
      Residuals: `returns owned` needs a return-ownership summary
      (stays contract-unsupported); zero-domain guarded ensures
      (`ensures return != 0 if g`) needs disjuncts in DivByZero
      (stays contract-unsupported).
- [x] Round E: `zd:policy` engine with `no-absolute-paths` first
      (the Ruledsl homage — shipped); `.zdc` sidecar loading
      (anchored entries only, /arity overload disambiguation,
      malformed lines = contract-syntax); profile-level policies
      (conf `policy =` + `--policy`); README contracts section.
- [ ] Contracts post-v1 residuals: caller-side consumption of
      declared ensures (contracted callee's return as
      NonNull/MaybeNull per guard); unverified reporting for sidecar
      clauses on bodyless declarations; whole-program sidecar anchor
      coverage check (typo'd anchors); zero-domain guarded ensures;
      `returns owned` (needs return-ownership summary).

### Rule improvement notes
- [x] **FOREACH_ARRAY family — resolved via pointer-relational
      validity, NOT join surgery (2026-07-12)**: full classification
      showed the family was 235 of systemd's 302 null-derefs (the
      "110+" undercount had matched only iterators literally named
      `i`; the macro's first argument is the user-chosen name, and
      FOREACH_ELEMENT expands to FOREACH_ARRAY). The fix that shipped
      is one rule, not engine surgery: C11 6.5.8p5 makes `p < q`
      defined only when both operands point into the same object, so
      EVALUATING a pointer-pointer relational comparison proves both
      sides non-null on both edges (`end && i < end` now proves `i`,
      not just `end`). walkCondition additionally reports BOTH sides
      of a comparison (variable-on-left normalization used to drop
      the right side). Null-literal orderings excluded. 5 pin tests.
- [x] **Disjuncts v2b — cross-variable correlation (2026-07-12, max
      session)**: five mechanisms shipped together. (1) Fact
      LIFECYCLE: the whole-function mutation ban became flow-time —
      assignments to locals ERASE the facts keyed on them
      (applyStmtFacts, called from all three GuardedState rules);
      address-taken decls and assigned globals stay permanently
      unkeyable. (2) STAMPING: integer-constant stores on
      condition-relevant locals record (var EQ lit)=true — paths that
      assigned different constants stay separate disjuncts at joins
      (the flag/status family: rtp2httpd, fprime). Enum constants
      count as literals. (3) ENTAILMENT: factsContradict answers any
      key on a var from a stamped equality ((x EQ 6)=true refutes
      (x EQ 5)); gives constant-propagation sharpening for free.
      (4) DISJUNCTION ELIMINATION with pointer facts: systemd's own
      assert (`if (_unlikely_(!(expr))) log_assert_failed(...)`)
      materializes `s || l <= 0` as a VALUE — Clang joins the operand
      paths BEFORE the branch, so only a fact difference survives the
      merge. Narrowly-gated pointer-nullness facts
      (collectPtrFactDecls: pointers sharing a short-circuit operator
      with a keyable partner) keep the split; per-disjunct
      refineDisjunctCondition applies the surviving operand to the
      disjunct that refutes the other one (fact-based + domain
      refuter). (5) CONVERGENCE WIDENING in the engine: the domain is
      not monotone (erase/drop), and real code oscillates
      (rtp2httpd's parsers cycled at 8x budget); after latticeHeight+2
      visits a block's entry is joined with the previous widened entry
      and collapsed to one disjunct — unstable facts die in the
      intersection, var states only climb. Memoryless widening was NOT
      enough (fact VALUES flip across visits). systemd non-convergence
      warnings 17 -> 0 while scan time halved.
- [ ] **Short-circuit condition-tree joins (general principle,
      urgency dropped after the relational fix + v2b)**: a join of
      multiple SAME-DIRECTION edges of one short-circuit condition
      tree is tautological — it should merge to refine(entry, C, dir),
      like the simple-diamond value-selection rewind but N-pred. No
      longer carries a known FP family; revisit if a scan surfaces
      one. Effort: max (engine surgery).
- [ ] **Ternary value FN (found while building the FOREACH repro,
      2026-07-12)**: `q = (p && flag) ? p : NULL; q->value;` is NOT
      reported — the ternary RESULT's nullness never reaches the
      assigned variable (q stays Unknown). The analyzer currently
      warns on the benign twin of this pattern (deref of the CONDITION
      variable, now fixed) while missing the buggy one. Needs
      value-level join at ConditionalOperator: q = join of arm
      nullness. Candidate for the v2b design session.
- [ ] **rtp2httpd TP for upstream** (verified 2026-07-12):
      configuration.c:1342-1358 — `if (arg && arg[0] == '/')` admits
      arg may be NULL; the next block dereferences `arg[0]`
      unconditionally. Draft ready (rtp2httpd_upstream_report.md);
      user files it Thursday together with libgit2 + Redis.
- [x] **--files UX hardening — done (2026-07-12)**: non-absolute
      entries retried against --build-path; zero analyzable files is
      exit 2, not a clean pass.
- [x] **--files papercut — fixed (2026-07-13)**: a missing list file
      is now its own error ("--files list not found: <path>", exit 1)
      instead of the generic usage message. (Had cost 20 minutes of
      scan-diff confusion on systemd.)
- [x] fprime residual — SOLVED (2026-07-12 night): unsigned
      zero-identity canonicalization (u<=0 IS u==0); fprime is CLEAN
      with --fatal-asserts SwAssert. README row updated 2026-07-13
      (10 -> 0, flag documented).
- [ ] fstab-util.c:261 (+1 from the unsigned round): flag/pointer
      correlation lost — direction conservative. Diagnosis narrowed
      (2026-07-13, single-file rerun still exactly 1 warning): the
      shape is `found`-flag / `x`-pointer correlation through
      STRV_FOREACH/NULSTR_FOREACH; the function body has NO direct
      unsigned-vs-0 comparison, so the lost key lives in a macro
      expansion or in the `u > 0 -> NE` rewrite weakening a stamped
      fact (EQ-false answers less than LE-false: it loses the
      sign half). Full root-cause needs a conditionFact debug-print
      build over this file — engine-v2 queue, not worth it for one
      conservative warning now.
- [x] **Redis null round 2 — CLASSIFIED, no engine change
      (2026-07-13)**: fresh scan on the contracts-complete build is
      byte-stable (80 findings, 66 null warnings; contracts added
      zero noise). Site-by-site families:
      (a) quicklist (12): defensive guards INSIDE utility macros
      (quicklistDecompressNode's `if ((_n) && ...)`) vs function-top
      length invariants — an attempted "macro-born null evidence is
      not caller evidence" rule was REVERTED: the
      SystemdAssertShape_UnprotectedDerefStillWarns pin proved it
      lexically indistinguishable from caller-authored assert
      predicates (`myassert(s || l <= 0)`) — both expand to
      body-authored tests over arg-spelled variables; discrimination
      needs macro-behavior awareness (engine v2 input, ROADMAP §4.B).
      Plus _quicklistListpackMerge keep/nokeep: if/else-if with no
      else, invariant carried by lpMerge's postcondition — locally a
      genuinely suspicious shape; contract material only when "one of
      two outputs is null" becomes expressible.
      (b) redis-cli (11): lazy arrays correlated with heap-field loop
      bounds (`types = NULL` until `keys->elements > 0`; the deref
      loop is bounded by the SAME field) — value correlation on heap
      fields, beyond v1 keying.
      (c) t_stream (8): flag/pointer correlation where the flag is a
      HEAP pointer (`if (groups) consumer = ...; ... if (groups)
      consumer->...`) — ptrKeyable is deliberately narrow
      (short-circuit partners only); widening it re-opens the
      disjunct-budget tradeoff measured at kMaxDisjuncts.
      (d) rax (5) + tail: conditional allocation under size
      computations, same correlation class.
      CONCLUSION: no lexical idiom flags left in redis — the residue
      measures exactly the engine-v2 features (value correlation,
      macro-behavior summaries, wider pointer keying). Feed into the
      ROADMAP §4.B evolve-vs-rewrite decision.
- [x] **tmux scan — two precision fixes shipped, one engine-v2
      note (2026-07-13)**. tmux (mature C) clean of real bugs; the
      triage produced two near-term FIXES (both landed test-first):
      (1) static/thread-local pointers no longer flagged uninit (C
      zero-inits them; screen_print/buf); (2) DivByZero refinement
      generalized to any zero-excluding bound `var <op> c`, c>=0
      (layout_spread_cell `if (n <= 1) return;`). Remaining tmux
      residue: `tty_add_features`/`tf` — pointer assigned in a loop
      bounded by `nitems()` (compile-time array size > 0); the
      analyzer walks the impossible zero-iteration path. Needs
      value-range knowledge that the loop runs >= 1 time (engine-v2,
      same family as bounded-loop reasoning). Also a scan-hygiene
      note: scanning a whole source dir pulls in non-compiled
      platform/compat files (tmux compat/setenv.c: undeclared
      `environ` under fallback flags → error-recovery AST → phantom
      uninit). Prefer restricting real-world scans to files present
      in the compile DB.
- [ ] **Passthrough / identity nullness — engine-v2 summary
      extension (minimal real-world repro from Kyty, 2026-07-13)**.
      Kyty (PS4 emulator) scanned clean of real bugs, but its JSON
      parser gave two twin FPs (JsonReader parse_array:118,
      parse_object:171) tracing to ONE limitation:

          static const char32_t* skip(const char32_t* in) {
              if (in == nullptr) return nullptr;   // only null path
              while (*in && Char::IsSpace(*in)) in++;
              return in;                           // null IFF in null
          }
          // caller: value points at '[' (guaranteed by a prior deref)
          value = skip(value + 1);   // value+1 provably non-null
          if (*value == U']') ...    // FP: value flagged MaybeNull

      Root cause: ReturnNullness is {Unknown, NeverNull, MaybeNull} —
      it cannot say "returns null IFF parameter N is null", so
      skip()'s `return nullptr` path poisons every call result to
      MaybeNull regardless of the argument. Fix direction (EVOLVE,
      not rewrite): add a conditional summary point
      (e.g. ReturnNullness::NullIffParam(n)) inferred when every
      null-return is dominated by a `param == null` check and the
      non-null return is the (possibly offset) param; consumed at
      call sites by forwarding the argument's own nullness. Clean,
      bounded, and it retires a whole FP family (skip/trim/advance
      helpers are everywhere). Kyty took no upstream report — no real
      bug, and reporting an FP would burn credibility.
- [ ] llama.cpp non-convergence residue (2026-07-12): 72 warnings but
      only 4 UNIQUE functions — all nlohmann/json.hpp header templates
      (get_unchecked/get_checked/get_and_create/contains), re-counted
      in every TU that includes the header. Down from 86 pre-widening.
      Heavy recursive-template CFGs; candidates for a per-function
      block-count bailout or a header-dedup on the warning itself.
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
- [x] **Correlated guards across variables — SHIPPED as disjuncts
      v2b + unsigned identities + relational requires (2026-07-12/13)**:
      the `FW_ASSERT(ptr != nullptr || count == 0)` family died —
      fprime is 0 findings with --fatal-asserts SwAssert; the same
      correlation is now also DECLARABLE as a contract
      (`requires p != null || n <= 0`, Round C).
      ALSO needed: canonical keys for CALL conditions
      (staticReturnsTrue()/False() — the Juliet realloc-family FPs,
      ~24 findings, measured 2026-07-12): PathFacts only keys
      variable conditions today. ALSO: pointer-identity correlation
      (libgit2 blame_git small-buffer optimization: alloc under
      `n >= bufsize`, free under `ptr != stackbuf` — semantically the
      same condition, syntactically unrelatable today).
- [x] **Configurable allocators — done (2026-07-12)**:
      --alloc-functions/--free-functions + three escape refinements
      (address-of-member, alias escape propagation, chained
      assignment). libgit2 leak domain: 0 -> 31 -> 15 findings; the
      merge.c multi-allocation OOM-path leak verified REAL by hand.
- [x] **libgit2 leak findings hand-verified (2026-07-12)**: 15 findings
      = 11 TP across 8 sites (all the GIT_ERROR_CHECK_ALLOC
      early-return class), 2 FP (blame_git small-buffer pointer
      identity -> disjuncts-v2 note; remote.c loop-free pattern),
      2 unclear (filebuf, remote detail) excluded from the report.
      Single class-issue drafted (libgit2_upstream_report.md, sent to
      user) — one issue for the pattern, 8 permalinked sites, per
      libgit2 convention. User files it.
- [x] **Report-flood dedup — shipped (2026-07-12)**: one report per
      (variable, function) for warning-severity null-derefs; later
      sites attach as "also dereferenced here" trace notes.
- [ ] libgit2 remaining null-deref triage — numbers refreshed
      2026-07-13: current total is 44 findings (was 149 initially);
      the 11 confirmed OOM-path leaks are drafted for upstream. The
      remaining null warnings cluster around hashmap macro-generated
      code (GIT_HASHMAP_OID_SETUP) and GIT_ERROR_CHECK_ALLOC
      interplay — post-public round, likely the same macro-behavior
      family as redis quicklist.
- [x] Address-of-member escape — done (2026-07-12, with the
      configurable-allocators round): AddrOf of member/self escapes
      the base at assignment/call/return sites; fprime font.cpp FP
      and the libgit2 iterator family both die.
- [x] **Report-flood dedup** (duplicate of the entry above — same
      mechanism shipped 2026-07-12; shadPS4 internal__Foprep's 25x
      flood collapses to 1 finding + trace notes).
- [x] **shadPS4 true positives REPORTED UPSTREAM (2026-07-12)** — the
      analyzer's first public real-world validation: (1) savedata.cpp
      sceSaveDataMount/Mount2 `&&`-vs-`||` null-check →
      shadps4-emu/shadPS4#4696; (2) usb_backend.h GetMaxPacketSize
      by-value nullptr desc (memcpy into null) →
      shadps4-emu/shadPS4#4697; (3) libc_internal_io.cpp
      internal__Foprep missing return after ENOMEM →
      shadps4-emu/shadPS4#4698. **TWO MERGED 2026-07-13**: #4698 fixed
      via PR #4702 (`return nullptr;` after the ENOMEM set); #4696
      (sceSaveDataMount &&-vs-|| null-check) fixed via PR #4703 — the
      canonical looks-right-reads-wrong bug. Both exactly the traces'
      shapes. #4697 (usb_backend GetMaxPacketSize) still open. Proof
      captured in README, RELEASE_NOTES, and both v0.1.0 drafts.
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
