# CodeSkeptic — Changelog

## 2026-08-23 — Phase 10.9 scope-bound endurance policy (in progress)

- With explicit owner approval, replaced the arbitrary 72-hour v1.0 blocker
  with an exact risk-based endurance contract: one cold and one warm round,
  each running three repetitions of llama.cpp, TensorFlow Lite, and shadPS4,
  for 18 retained real-world analyses in total. Elapsed time remains recorded
  evidence but cannot replace or extend the fixed scenario inventory.
- Kept every substantive gate: pre/post 10-of-10 determinism, the 10 percent
  performance ceiling, semantic and requested-unit-plan stability, complete
  requested-TU coverage, sanitizer authority, RSS/FD/time budgets, zero live
  process-group descendants, checkpoint/restart behavior, fault injection,
  immutable offline inputs, and checksummed receipts. Longer soak runs remain
  available as non-blocking post-v1 field observation.
- Versioned the complete work catalog to schema 3 without adding, removing,
  reordering, closing, or weakening any task dependency. The status guard pins
  previous full PLAN/catalog SHA-256 values
  `8f9ae5587063e86862f49dd68497c4c69a2cd244d28128ffb12876199883d6ef` /
  `1eb6055330dd0f0b3f7ef0eaf80c074870587278ea05b624fb4840ae3ba44d11`
  and new values
  `990a23767127679b21e57742b2252055016d3373d32943b3de6ccce30099f369` /
  `09fa55fceeae80aec56d261f143b9ff7fc85d82c37cd3f9efc668eeceb737a7b`.
  It accepts the revision only on descendants of policy checkpoint
  `0fbe212971abb6599e372b715a4cb662344c2eb0`; arbitrary PLAN edits and
  phase-branch completion claims remain rejected.
- Hardened every campaign command boundary around exact PID/start-time and
  all-thread ownership, Linux subreaper `ECHILD` convergence, bounded live
  stdout/stderr, and setup-failure cleanup. Real-kernel fixtures cover a main
  thread exiting while a worker remains live; unrelated host processes are
  never inferred from a global PID delta.
- Added bounded local-Git exact-head reads and offline mirror production:
  workflow blobs are type/size checked before capture and remain live-capped,
  while mirror/shard writers use per-file limits, observed aggregate budgets,
  quiescence-before-release emergency reserves, and identity-bound rollback.
  The portable statvfs guard is explicitly recovery-oriented detection, not a
  hard aggregate filesystem quota.
- Gave staging-command cleanup its own bounded grace period after an execution
  deadline. A timed-out process is still rejected immediately, but SIGKILL
  cleanup can now observe kernel quiescence instead of falsely reporting a
  surviving process on the first scheduler tick after the deadline.
- Closed every offline real-world shard subprocess over a fixed executable
  path and authority-declared compiler pair, disabled ambient compiler caches,
  and placed HOME, TMP, and XDG state inside the identity-bound shard budget.
  Checkout, configure, build, target-closure discovery, and analyzer execution
  now share that environment; hostile host compiler, launcher, proxy, and
  cache variables are covered by both unit and real adapter regressions.
- Separated historical P10-08 quality evidence from the fresh P10-09 source
  gate. Historical verification may skip only equality with the descendant
  worktree: ancestry, the recorded revision manifest, authority scripts,
  mutation manifest, capability registry, raw evidence, bundles, and receipt
  are still re-derived. Fresh verification remains exact-current by default.
- Narrowed the upstream-manifest AST contract to the single translation-unit
  count/hash guard it is intended to protect, so unrelated mirror-submodule
  digest checks cannot satisfy or multiply that assertion.
- Versioned the staging lifecycle to v2 and removed its last hand-authored
  runtime input. `configure` now derives every fixed-path authority hash from
  exact staged bytes and atomically publishes the canonical config pair; a
  partial write, collision, stale receipt, malformed repository identity, or
  post-publication drift removes only the producer-owned inode and fails closed.
- Removed large sealed-bundle and private VFS work from ambient `TMPDIR`.
  The command-line seal, verify, and install actions now require an explicit
  empty, mode-0700, caller-owned disk root, enforce a size-derived free-space
  budget plus cleanup reserve, and identity-bind both publication and removal.
  This prevents the pinned multi-gigabyte archive from exhausting the host's
  tmpfs and remains reliable across `sudo` environment filtering.
- Removed the hand-authored hosted gate selection from the authority path. The
  capture now deterministically selects attempt-one successful runs and their
  exact check suites from complete provider API snapshots, prefers `push` over
  `workflow_dispatch` and then the lowest run ID, and re-derives the same
  selection offline. The capture retains the complete check-suite inventory
  and rejects the boundary where GitHub's filtered workflow-run or commit
  check-run APIs become ambiguous at 1,000 results. A legacy `--selection` is
  accepted only when its canonical bytes exactly match that provider-derived
  result.
- Made hosted capture and sealing publication interruption-safe. Random private
  staging directories and published outputs are inode-bound; a signal, parent
  fsync failure, or post-publication verification error removes only the exact
  producer-owned tree, while a concurrent or substituted foreign output is
  preserved and reported.
- Closed the remaining cleanup and success-return races with descriptor-relative
  atomic quarantine. Cleanup pins the original inode, moves it to a random
  sibling before deletion, restores any mismatched node without replacement,
  preserves restore collisions, and refuses multiply-linked regular files.
  Staging, hosted capture, and hosted sealing also recheck the published inode
  after the durable parent sync instead of reporting success over a concurrent
  replacement.
- Removed the last network dependency from test and sanitizer configuration by
  retaining the official GoogleTest `v1.14.0` archive, its license, upstream
  tag identity, and exact SHA-256 in the source authority. CMake now accepts
  only those local checksum-pinned bytes; source, sanitizer, determinism, and
  staging manifests all bind the new `third_party` inventory.
- Split prepared-tree creation from machine-specific authority production.
  Staging now leaves sanitizer and release destinations absent, while a
  create-new provisioner builds them in the pinned networkless image and asks
  separate containers to re-derive each result. Fsynced operation and
  publication journals recover interrupted work, bind complete source/build
  inventories, bound runtime-identity probes, and verify invocation-owned
  containers before cleanup. Rollback now rechecks the complete recorded tree;
  ambiguous ownership is preserved fail-closed, while failed producer logs are
  sealed as read-only, checksummed rejection evidence before owned scratch
  state is removed.
- Versioned runtime, session, establishment, and final receipts to schema 3.
  The exact release-candidate receipt is now part of configuration and session
  identity, is semantically re-derived before execution, is copied into the
  establishment record, and must remain byte- and directory-identical through
  final evidence verification.
- Reconciled the generated TODO state against a clean protected-remote branch
  inventory and made the new campaign-interruption tests honor their actual
  platform boundary. Linux still exercises the real subreaper, procfs, and
  `renameat2` cleanup contracts; macOS and Windows retain the portable command,
  environment, and error-reporting checks without passing or failing for an
  unrelated Linux prerequisite.
- Made the staging module's `fcntl` dependency explicit at the lifecycle-lock
  boundary. Non-POSIX hosts can now load and compare the portable source
  manifest contract, while any attempt to acquire the Linux authority lock is
  still rejected immediately with a controlled fail-closed error.
- Made low-level stability-manifest hashing request Windows binary mode, so
  retained archives have the same exact digest as the sanitizer and
  determinism authorities instead of being exposed to CRT text translation.
- Made the interrupted-campaign recovery-path assertion compare the native
  rendered path. Windows now verifies its actual separator convention while
  preserving the same retained recovery-workspace contract.

## 2026-08-22 — Phase 10.8 cumulative quality-floor audit (in progress)

- Added a fail-closed cumulative receipt for the exact seven supported default
  rules. Acceptance requires at least `85%` precision for every rule, `90%`
  micro precision, `70%` addressable recall, all nine clean-corpus cases with
  zero findings, and both missing/broken requested-TU negatives returning
  unavailable exit `2` without a project verdict.
- Pinned the official Juliet 1.3 archive and sampled source manifest, the exact
  libarchive revision and Linux translation-unit surface, three source-level
  resource-leak mutations, analyzer capability registry, scripts, raw files,
  and all 18 rule/clean/requested-TU evidence bundles. Stale, mixed, partial,
  symlinked, duplicated, or inconsistently re-hashed/resealed derived layers
  are rejected.
- Added an exact LLVM 20 Release/Ninja analyzer-build authority in the retained
  Phase 10 image. It binds the self-contained detached source checkout,
  toolchain, CMake cache and compile database, analyzer, logs, Podman/image
  identity, and a re-derived operator record; linked worktrees, replacement
  refs, grafts, alternates, shallow/partial repositories, external Git config,
  and ambient Git authority are not admitted.
- The public quality-floor operator verifies that build authority before any
  output is created, runs only inside the same pinned no-network/read-only
  image, retains a separate campaign execution authority, independently
  verifies staged output in a second container, and publishes by same-filesystem
  atomic promotion. Resource receipts bind each logical libarchive source to
  both admitted compile commands in both whole-program phases instead of
  collapsing them to a unique path set. A failed container surfaces only its
  bounded, escaped final diagnostic while the private workspace is still
  removed.
- Hardened the real-world corpus gate after a live cJSON/tinyxml2 run exposed
  a false green: the outer requested-surface banner was followed by nested
  one-file banners, producing a multiline arithmetic operand that skipped the
  coverage and finding-pin checks while Bash still returned success. The gate
  now consumes only the deterministic top-level banner and a behavioral
  contract proves exact `23/23` and `2/2` coverage while rejecting missing or
  mismatched aggregate surfaces.
- The exact-head authoritative campaign at source checkpoint
  `837fd0d37aec528a01df13b155c45f40b9ab6f89` and build-authority seal
  `31b991324f4dc01ff59033f6c8aee39f3b31de24adfdda47e5540ea9dfdfcbbb`
  passed both producer and independent verifier paths. Micro precision is
  `643/657`, addressable recall is `638/898`, every rule exceeds its precision
  floor, all `9/9` clean cases have zero findings, and both requested-TU
  unavailable negatives passed.
- Retained the exact 167-file package under
  `docs/evidence/phase10/quality/2026-08-22-linux-x86_64`. Its accepted receipt
  SHA-256 is
  `9aacf249426db439810439bc7d3f56a5f2b54adbec70248544b104eb9938554c`;
  the sibling external manifest SHA-256 is
  `517ddc1c1acc629430ff49338a5e7ee723ab4eedf16c439756d39c077ad52b2c`.
  This evidence checkpoint does not close `CS-P10-08` and does not change
  protected-main status.

## 2026-08-22 — Phase 10.7 accepted confirmation (branch checkpoint)

- The first complete V7 confirmation produced all ten repetitions for the
  unit, real-repository, and release-candidate workloads, with every retained
  inner and batch environment decision valid. All three semantic hashes match
  the pinned baseline and the largest positive performance delta is `0.76%`,
  below the `10%` gate. The sealed run nevertheless rejected at the final gate
  because Linux reported `16425545728` memory bytes while the calibration boot
  reported `16425553920`, an `8192`-byte difference on the same machine,
  kernel, CPU partition, uclamp policy, and toolchain.
- Profile matching now retains the exact observed `memory_bytes` in evidence
  but tolerates at most `1 MiB` of Linux boot-page accounting movement. Every
  other OS, hardware, affinity, cgroup, uclamp, and toolchain field remains
  exact, and a memory-capacity drift beyond that narrow bound is rejected.
- Baseline authority and required profile compatibility are now checked before
  release-candidate preparation, idle waiting, or any measured workload. A
  missing or materially incompatible profile therefore fails closed before an
  expensive run instead of after the full confirmation matrix.
- The original Attempt21 receipt remains an immutable rejected artifact; it is
  not rewritten retroactively. Its raw observations recompute to zero gate
  failures under the corrected policy and provide a regression oracle. The
  verifier retains only the narrow legacy rejection shape caused by a nonzero,
  in-tolerance memory delta; a fresh accepted confirmation is still required
  to close `CS-P10-07`.
- Re-anchored the retained frontend/CFG stress receipt on feature base
  `88e369b21675e64e0a92842b0ce22f0c8148745e` and the exact 388-file source
  manifest after the confirmation evidence contract extended the inventory.
  All nine cases passed twice with unchanged stable semantic projections; the
  refreshed 37-file bundle and its external checksum manifest verify
  independently. The receipt SHA-256 is
  `5e2d13f4b5bf21b9289ee0fe3dde4ac659fd8e0a623f67bd93f4e9b737fa40a5`.
- Completed a fresh independent V7 confirmation against feature revision
  `88e369b21675e64e0a92842b0ce22f0c8148745e`. Unit, real-repository, and
  release-candidate workloads each produced ten identical semantic
  fingerprints; the required performance gate passed with no regressions.
  The accepted receipt retains 631 raw artifacts and has SHA-256
  `a7d8409199a22a2896d8486e2e7d95674ba254bdb9c6df84da9746f2a3c096f9`.
- The headless controller and independent receipt verifier both exited `0`,
  cleanup succeeded, and the coredump inventory remained unchanged. The
  immutable guided result nevertheless recorded exit `2`: its outer wrapper
  incorrectly required DrKonqi's accepted-connection counter to reset to zero
  even though the already-tested controller contract permits either the
  preserved journal value or a zero reset. A focused RED/GREEN regression
  corrected that orchestration-only rule; the corrected operator passed
  `65/65` checks and root-staging emulation. The accepted measurement matrix
  therefore does not require another physical run.
- Retained the complete confirmation, host receipts, immutable Attempt23
  wrapper, and Attempt24 erratum under
  `docs/evidence/phase10/determinism/confirmations/2026-08-22-fedora44-i5-1235u-exclusive-pcores-kernel-6-19-10`.
  A self-excluded 678-entry manifest binds the bundle and an executable
  repository contract revalidates every retained byte, receipt invariant,
  10/10 workload cardinality, and the guided-wrapper distinction. This
  satisfies the three `CS-P10-07` technical gates on the feature branch;
  protected-main status automation remains unchanged until an authorized
  integration occurs.

## 2026-08-20 — Phase 12 coverage-based v1 qualification policy (in progress)

- Replaced the proposed three consecutive 30-day pre-v1 pilots with three
  independent, coverage-based external-project qualification campaigns. Each
  campaign must execute the same predeclared scenario matrix from immutable
  inputs and retain checksummed coverage, semantic-fingerprint, crash/hang,
  performance, triage, suppression, baseline, JSON/SARIF, cache/resume,
  resource-failure, and distribution-parity evidence. Elapsed time cannot
  substitute for a missing scenario or rejected receipt.
- Kept the measurable product gates intact: deterministic 10-of-10 results,
  precision/recall floors, zero clean-corpus false positives, 200 human-triaged
  findings, the upstream project/fix ledger, 72-hour stability, sanitizer and
  platform coverage, distribution parity, packaging, SBOM/provenance,
  signatures, and offline operation remain v1.0 requirements.
- Moved three 30-day report-only pilots to a post-v1 field-observation program.
  They may run in parallel, do not block v1.0, and cannot rewrite its evidence;
  successful completion may support a later `field-proven` or
  `enterprise-readiness` claim. No external write or maintainer contact is
  authorized by this policy revision.
- Versioned the work catalog as schema 2. The status guard admits this policy
  change only as the exact successor of authority commit
  `338be9c4db73f55b08b57b6b482d7d1045b55137`, with pinned full-PLAN and catalog
  SHA-256 values, the complete unchanged task-ID set, regression coverage, and
  an independently audited change. Arbitrary PLAN edits still fail closed.
  `CS-P12-01` through `CS-P12-08` remain open; this policy checkpoint closes no
  task and does not change protected `main`.

## 2026-08-19 — Phase 10.7 kernel-bound determinism authority (in progress)

- Advanced the determinism authority to coordinated V7 schemas that bind the
  exact operating-system kernel, retain the failure-causing batch environment,
  and reject earlier V6/V5 authority formats instead of silently interpreting
  them under the new contract. The performance authority requires an exclusive
  cgroup-v2 P-core partition, disjoint controller CPUs, exact effective and
  exclusive cpusets, local/ancestor/system uclamp `1024`, recursive empty and
  unfrozen cgroup state, cgroup-owned CPU accounting, thermal/throttle/OOM
  counters, and a checksummed fixed idle preflight. Runtime global pressure is
  retained as observation; predeclared idle gates remain fail-closed.
- Established the initial kernel-bound profile
  `fedora44-i5-1235u-exclusive-pcores-0-3` on
  `Linux 6.19.10-300.fc44.x86_64`, using measurement CPUs `0-3` and controller
  CPUs `4-11`. The bound source is revision
  `4bd5e0bc8bafac6ac1b000e4107b3c6cfee11cdf`, with `386` files and source
  manifest SHA-256
  `1e1b565ef7637231bdc366eca64bd3bd8326ee25eaeca332be785fc3f451aa46`;
  the analyzer SHA-256 is
  `2fdca181e7c881de7a20472c78cf807e0b1f1b984747e9d860eb2119af049562`.
- The retained calibration at
  `docs/evidence/phase10/determinism/calibrations/2026-08-19-fedora44-i5-1235u-exclusive-pcores-kernel-6-19-10`
  contains a 634-file evidence tree with a self-excluded 633-entry manifest.
  Its receipt SHA-256 is
  `6d616524b39696c1bd574ba021f6ea890c08c2def7e6f0210a4d77b1ed5d2b01`,
  its manifest SHA-256 is
  `34289524bcd07de5fd81f96b407d7849b2ebe615737d1ba06f88f84b5fbb699a`,
  and the generated V7 baseline SHA-256 is
  `5b8517de98074944b055949c0d17ade4525522a65b174ca359f1853ebe36b7b6`.
  All three workloads completed ten outer repetitions; the unit workload also
  retained ten inner invocations per repetition, for 120 measured invocations
  and 631 raw artifacts. Median wall/CPU/RSS values were
  `6040 ms / 5230 ms / 88138 KiB` for unit,
  `209215 ms / 208030 ms / 1304776 KiB` for the real repository, and
  `30925 ms / 30785 ms / 370686 KiB` for the release candidate.
- Every retained inner and batch environment decision is valid, with no
  violations, thermal-throttle delta, cgroup throttling, or OOM event. The
  same-run establishment receipt passed semantic and performance gates with no
  regression, and independent pinned-image, no-network verification recomputed
  the calibration, baseline provenance, accepted receipt, workload statistics,
  and artifact inventory. That establishment is a self-check over the
  calibration samples, not the still-required independent confirmation.
- The headless controller restored the network, unit states, process affinity,
  masks, and cgroup authority with payload exit `0`. A later interactive sudo
  prompt timed out while reopening the graphical target; the graphical session
  was restored separately after all measurements and therefore does not affect
  the calibration authority. The confirmation operator must harden this final
  credential/GUI handoff before use. Independent confirmation, refreshed stress
  evidence, full regression suites, exact-head hosted CI, and final independent
  audit remain required; this checkpoint does not close `CS-P10-07` or write
  protected `main`.

## 2026-08-15 — Phase 10.6 cache correctness and resume checkpoint (in progress)

- Replaced the legacy timestamp/size AST shortcut with a parent-owned,
  process-isolated unit evidence store. Exact keys bind the analyzer binary and
  protocol, canonical source and compile-command ordinal, resolved source,
  header, response/PCH/module/VFS and sibling-sidecar contents, semantic
  configuration and enabled rules, ordered model/summary inputs, resource
  limits, and analysis phase. Volatile date/time preprocessor inputs execute
  normally without persistence, including definitions supplied directly or
  through recursive response files. A Clang preprocessor callback observes
  actual builtin expansion, so token-paste and macro indirection cannot evade
  that boundary; isolated workers also expand nested `@response` arguments
  under the same depth and size limits used by their evidence collector.
  Lexical dependency aliases and resolved targets are both bound so
  symlink-addressed `.csk` sidecars invalidate.
- Added strict checksummed manifests and content-addressed unit payloads with
  atomic publication, bounded parsers, symlink rejection, exact planned-phase
  cardinality, and analyzer-identity checks before, during, and after a run.
  Different valid keys are ordinary misses; a corrupt expected entry or an
  incompatible explicitly selected checkpoint makes evidence unavailable with
  exit `2` and cannot manufacture a clean verdict. A pre-created empty
  checkpoint directory is initialized safely, while an existing manifest with
  a missing or non-directory entry store is rejected. Manifest staging is
  opened create-new without following symlinks; a regular file left by an
  interrupted pre-rename write is recovered, while non-regular staging state
  remains fail-closed and cannot truncate an external target.
  Content-addressed entry staging likewise recovers only a real stale
  directory. Analyzer file-id/change-time drift forces a full executable
  SHA-256 comparison at lookup and completed-manifest publication, so a
  same-size/restored-mtime mutation cannot pollute a later run.
- Partitioned a configured long-lived MCP checkpoint root into deterministic
  analyzer/configuration/translation-unit-plan namespaces. Sequential A, A, B,
  A requests now prove executed, checkpoint, executed, checkpoint origins
  without treating B as an incompatible explicit checkpoint or allowing a
  request to choose the storage path.
- Whole-program harvest fragments are persisted per exact unit, canonically
  remerged, and bind every analysis-phase key through the merged-summary
  digest. A dependency probe brackets every cache hit to reject TOCTOU drift;
  source/header shadowing, sidecars, compile commands, models, summaries,
  configuration, rules, and analyzer changes all have production-path
  invalidation regressions. Probe, cache-hit verification, and cache-miss
  execution share one absolute per-TU/phase wall-clock deadline, so enabling a
  checkpoint cannot multiply the configured timeout; receipts measure the
  complete logical pipeline. Parent-side input hashing, cache parsing, and
  publication receive that same deadline, and a timed-out store rolls back
  its completed manifest instead of leaving a reusable timed-out entry.
- Interrupted production-worker analysis now preserves completed units and
  resumes the same unchanged inputs without duplicate or omitted command,
  ordinal, or phase identities. Resumed coverage, diagnostics, and semantic
  fingerprints match a cold run while receipts separately report `executed`
  and `checkpoint` origins. A prior accepted shard receipt validates resume
  identity but never short-circuits checkout/build or substitutes its old
  verdict: the current compile database is regenerated and every unit is
  revalidated through the exact-key store. The real-world shard referee
  validates the exact requested-path projection, every compile-command ordinal
  and whole-program phase, and cross-repetition plan digest; it refuses
  malformed, partial, or incompatible checkpoint evidence. Immutable Phase 8
  receipts use one
  explicit legacy validator because their historical schema predates plans;
  current checkpoints and aggregation keep the strict default.
- Split hosted checkpoint restore and save operations so an unavailable shard
  still publishes its verified per-TU subset under an immutable run-attempt
  key. A later rerun restores only from the exact commit, manifest, project,
  and repetition prefix; workflow contracts pin the ordering and failure-path
  save condition. Campaign receipt/checksum staging uses create-new,
  no-follow writes; checksum-first publication from an empty pair makes either
  regular crash orphan recoverable through the per-TU store, while symlink or
  other non-regular state remains fail-closed.
- Made the accepted-shard revalidation regression portable to macOS by
  canonicalizing its temporary analyzer fixture before command matching.
  macOS exposes the same temporary directory through `/var` and
  `/private/var`; the production campaign path was already canonical and the
  fixture now tests that path instead of rejecting a valid analyzer invocation.
- Removed a long-diff race from the offline changelog guard. Its `pipefail`
  pipeline previously let `grep -q` close early and turn the producer's
  `SIGPIPE` into a false "changelog missing" result; direct here-string
  matching preserves the exact file-list checks without a producer process.
- Reconciled the first exact-head hosted run without weakening any gate.
  Clang VFS spellings such as `/include/c++/...` now bind the existing physical
  standard-library file while preserving lexical symlink identity for sidecar
  lookup, so the real NIST Juliet suite no longer loses dependency evidence.
  Windows checkpoint namespaces use a 128-bit directory prefix while their
  manifests still compare every full SHA-256 identity and fail closed on a
  prefix collision; native JSON fixtures no longer embed unescaped backslashes.
  A repository-wide LF checkout rule, with the existing binary/evidence
  exceptions retained, makes source-manifest bytes identical across Linux,
  macOS, and Windows rather than accepting line-ending drift.
- Exact-source local qualification passes `1280/1280` direct C++ tests,
  `1297/1297` repository-aware CTest entries, the selected six hosted-regression
  cases, `52/52` status-automation cases, `25/25` real-world campaign cases,
  and `21/21` upstream-evidence compatibility cases. The bound source manifest
  contains `380` files with SHA-256
  `a902a872bfccbb1dc47335811987db1d085cb8d4e3d8e8a1c4eb1b485e374c0e`;
  the independent source-stage audit passed.
- Retained the exact-source frontend stress replay at
  `docs/evidence/phase10/stress/2026-08-15-cache-linux-x86_64`: all nine
  cases passed two deterministic repetitions with zero timeout/crash in
  `695` ms. Its receipt SHA-256 is
  `0e4eaeb4f9e0f6b3ef45690b010feb7a08e0f25e65cd64ad60dd6f161182e780`;
  the 37-entry tree manifest SHA-256 is
  `3c033f5497ae9b941f3ce42ed9885e5a40b7cbadcaefda79bc473763ac654870`.
- Retained independent ASAN and UBSAN trees at
  `docs/evidence/phase10/sanitizers/2026-08-15-cache-linux-x86_64`.
  Each passed all ten runtime gates, `1297/1297` CTest entries,
  `1280/1280` direct C++ tests, representative analyzer/MCP paths, and four
  fuzz targets against the same source manifest. ASAN completed in `159640`
  ms with receipt SHA-256
  `3d2854032b17171b11a59b2119f839745d8cb32280e7e72754da1378aabf0072`;
  UBSAN completed in `1319390` ms with receipt SHA-256
  `fea1f76331ecff018bc7a5f12cf272684513e3e5e83b7b68164452d88545a5e1`.
  Both verify-only passes and the materialized `13/13` sanitizer contract
  succeeded without skips; the `6/6` stress contract also passed without a
  skip, and the 40-entry tree manifest SHA-256 is
  `05bf6c88351f5bb4a350f07e0b60b65a44617e3c168d1a0a53fd9f83d1c90145`.
  The fresh independent final evidence audit passed. Commit/push and exact-head
  hosted CI remain pending; this checkpoint does not close `CS-P10-06` or
  write protected `main`.

## 2026-08-15 — Phase 10.5 per-TU resource budgets locally complete

- Replaced in-process multi-TU execution with an exact-command coordinator and
  one OS-isolated worker process per requested translation unit. Worker
  requests bind canonical file, compile-command SHA-256, command ordinal,
  configuration, rules, summaries, and output identity; strict response
  parsing rejects count, identity, finding, and completion-marker drift before
  aggregation.
- Added explicit defaults of 300 seconds and 4096 MiB per TU, bounded CLI and
  configuration parsing, inherited and per-request MCP overrides, and durable
  JSON resource receipts. Timeout, memory exhaustion, launch/protocol failure,
  missing input, and broken input identify the exact TU, preserve completed
  receipts, keep later independent units observable, and make the project
  verdict unavailable with exit `2`.
- Added post-exec start/completion handshakes so the supervisor measures the
  worker image rather than a transient spawning parent. Linux uses monotonic
  `VmHWM`, Windows uses `PeakWorkingSetSize`, and Darwin resets and samples a
  monotonic physical-footprint interval. Unexpected worker exit, failed
  sampling/handshake, timeout, or memory excess is fail-closed and the exact
  child is terminated and reaped. Every post-ready sample remains mandatory
  until the completion marker is observed; a deterministic injected sampling
  failure now proves `Crashed`, exit `-2`, and no verdict instead of permitting
  a final unmeasured poll.
- Added production-path regressions for whole-program summaries, distinct
  compile commands, missing/broken inputs, timeout and memory failure,
  summary/model merging, failed JSON/SARIF/HTML/baseline artifacts, CLI/config,
  and MCP. Restored the whole-program activation marker on the budgeted parent
  path after the retained-matrix contract caught its absence; the production
  worker regression now pins that evidence without changing receipt or verdict
  semantics. The current Linux Clang 20 source passes `1237/1237` direct C++
  tests and `1254/1254` CTest entries.
- Added a contract-pinned `resource-budget-macos` PR/push lane using native
  macOS 14 and Homebrew LLVM 20. Its first hosted build exposed Homebrew
  Clang receiving an SDK `/usr/include` without the matching `-isysroot`;
  Apple sysroot discovery and imported SDK-include cleanup now apply to every
  Apple build while preserving a caller-supplied sysroot. The same hosted head
  exposed Win32 `max` macro expansion at the supervisor peak calculation and
  an `/MD` worker-control library linked into its `/MT` probe. `NOMINMAX` is
  now defined before `windows.h`, and the worker-control target is created
  only after LLVM selects the MSVC CRT model for the downstream target
  graph. The next native macOS compile reached the supervisor and exposed the
  Darwin `getpid()` call without its declaring header; the Apple branch now
  includes `<unistd.h>`. The Windows build then completed and exposed an
  assertion that compared the canonical long spelling of `%TEMP%` with its
  `RUNNER~1` spelling; the missing-request regression now compares the same
  `weakly_canonical` identity used by production. The workflow contract is
  `6/6`. The final
  sanitizer and stress source manifests agree on 377 files with digest
  `91f7080aba5a7f01b980a2f0d5f42ddce88332530a7801fbb7854a4bcdea8db7`.
- Refreshed the retained stress matrix after the final supervisor regression
  changed the bound source bytes. It accepts `9/9` cases and `18/18`
  executions in `679` ms; receipt SHA-256 is
  `56490a70c7ea950e07a5445a665893037ba8dd58934abaf03909dc95f3e14690`,
  and the 37-entry outer manifest SHA-256 is
  `92625c37d7a4ffc41a43b68467f465247b062a4d34faf2d9adc5f7e2a9b881f9`.
  Its verifier, `StressMatrixContract` `4/4`, and all manifest entries pass.
- Retained final Linux x86_64 ASAN and UBSAN trees bind those exact source
  bytes. Both pass all ten runtime gates, `1254/1254` CTest entries,
  `1237/1237` direct C++ tests, representative clean/finding/invalid/
  whole-program and sequential MCP paths, and four fuzz smoke targets. ASAN
  completed in `317125` ms with receipt SHA-256
  `95819a673a0192dd852a809cbd3281f37be9f163d8f79e882ecb32f09a89989c`;
  UBSAN completed in `289051` ms with receipt SHA-256
  `ec7c21382ce3db8ce75cfecec7004d48eda4329c623c046fac5f69b084d215a1`.
  The 40-entry outer manifest SHA-256 is
  `3c7e4e9cba518d7aa7973bbb52ce5022ea917604d296ba67b1fc3ce958e81153`;
  both retained verifier modes pass and `SanitizerContract` is `13/13` with
  no skips.
- Independent read-only pre-evidence, narrow lifecycle, and final evidence
  audits found no material blocker after independently rechecking the full
  normal suite, receipt/build/source bindings, and both outer manifests.
  `CS-P10-05` remains open pending hosted Linux, Windows, and native macOS
  gates. No protected-main write or merge is performed here.

## 2026-08-15 — Phase 10.4 frontend and CFG stress matrix locally complete

- Made verdict availability unconditional over the requested translation-unit
  set. Missing paths are counted before filtering, broken ASTs remain recorded
  even when recovery analysis is requested, whole-program prepass failures are
  preserved, warm-cache AST failures name the exact TU, and neither
  `--accept-partial-coverage` nor `--analyze-broken-tus` can manufacture exit
  `0`/`1` from broken or skipped requested input. Recovery findings remain
  available as explicitly non-verdict evidence.
- Added a checksum-bound production CLI matrix with nine fixed cases covering
  templates, dependent templates, nested macros, malformed templates/source,
  a 64-way CFG, mixed clean/broken input, recovered broken ASTs, and a missing
  requested TU. Every case runs twice with a 30-second crash/hang tripwire and
  machine-checks process/report exit, status, completeness, exact TU coverage,
  seeded findings, clean twins, and stable semantic hashes. The malformed
  template now forces instantiation, so both ordinary Clang and Windows'
  MSVC-compatible delayed-template-parsing mode diagnose the same production
  input. The retained Linux x86_64 run accepted `9/9` cases and `18/18`
  executions with zero timeout or crash in `327` ms. Its receipt SHA-256 is
  `3be46ec3f1f517025d448e8df8927f554b75cab3908bdd87aec988b6be75ea4e`;
  the 37-entry outer manifest SHA-256 is
  `d7316415a05fc875a4e345d4150d5428dfd2cba2d20dc3b2a83a351cc1023a61`.
- Replaced the permissive real-world source-tree scan with each pinned
  project's exact compile-database surface. cJSON is now `23/23` analyzed,
  zero broken, zero missing, and 48 findings; tinyxml2 is `2/2`, zero broken,
  zero missing, and 9 findings. The harness rejects any requested/enumerated
  mismatch or incomplete TU before comparing finding pins.
- Refreshed the retained ASAN and UBSAN matrices for the final P10.4 source
  bytes. Both bind the same 358-file source manifest
  `a452bb75b509d7d0091c74a591a2ea231d5219bce219d0d181e1609987f275ef`,
  pass all ten runtime gates, `1208/1208` CTest entries, `1192/1192` direct
  C++ tests, and four fuzz smoke targets. ASAN completed in `66135` ms with
  receipt SHA-256
  `d91a04340f69104d0c3ed1414d2f5947f9be1fd54bc549109bc6f4987ab46308`;
  UBSAN completed in `40754` ms with receipt SHA-256
  `c92c8af369e68101e7625cb56fe0c8696aa1e5e1dce3b46e64d9818d156d41fb`;
  their 40-entry outer manifest is
  `e40eb2a67435c59f2e6f08cc4d808dc7d1b2549eb1de491e22656154c5ff7f85`.
  Both receipt verifiers pass and `SanitizerContract` is `13/13` with no
  skips. Evidence directories are excluded from source manifests to prevent
  later phase receipts from creating cross-matrix hash cycles.
- Independent read-only final pre-push review found no blocking correctness
  issue after rechecking the Windows RED/GREEN path, receipt bindings, and
  retained manifests. `CS-P10-04` remains open pending hosted Windows and all
  other CI gates; this work stays on `phase-frontend-cfg-stress` and does not
  write to or merge protected `main`.

## 2026-08-14 — Phase 10.3 sanitizer matrix locally complete

- Closed the three failures exposed by PR #142 CI. ASAN now disables only
  explicit user poisoning, which avoids the instrumented-header/uninstrumented
  system-Clang DSO mismatch while leak detection, heap redzones, and the
  crashing runtime tripwire remain active. Explicit partial-coverage requests
  now accept translation units omitted from the compile database without
  weakening the default fail-closed verdict. Corpus coverage now reports those
  omissions instead of counting them as analyzed: cJSON recorded 76 enumerated,
  53 missing compile commands, and 23 analyzed units; tinyxml2 recorded 3, 1,
  and 2 respectively. A request that analyzes zero units remains a hard
  failure with exit `2`, including when both partial-coverage and broken-TU
  opt-ins are set. Windows pins PLAN, generated TODO/PROGRESS, and shell files
  to LF, selects Git Bash instead of the WSL launcher for the offline docs
  guard, and checks out full history so protected-main anchor and merge-base
  checks have their required objects. The offline guard now records the real
  native Git subprocess path through Trace2 and disallows non-file transports,
  so Windows exercises `git.exe` without an extension-resolution shim while
  still failing closed before a network fallback. Synthetic Git repositories
  disable automatic GC and maintenance, preventing detached background writes
  from racing temporary directory cleanup on hosted runners.
- Bounded sanitizer build parallelism at two jobs after a four-job local run
  caused system-wide resource pressure on a 16 GiB workstation. The final
  runs used Ubuntu Clang 20.1.2 and bound 352 source files with manifest
  `ff9be05aa0e3512b49a0a3f431f2a4e32118735010253a2657694c2cfbe77a1d`.
- Retained accepted Linux x86_64 ASAN and UBSAN trees under
  `docs/evidence/phase10/sanitizers/2026-08-14-linux-x86_64`. Each profile
  passed all ten runtime gates, `1202/1202` CTest entries, `1187/1187` direct
  C++ tests, all representative analyzer/MCP checks, and all four fuzz smoke
  targets. ASAN completed in `64061` ms with receipt SHA-256
  `2d1ea036028e059975d6af9e580a19ca19e495ced86658b228fe9ebb4745102a`;
  UBSAN completed in `42769` ms with receipt SHA-256
  `ed7256c83c321c795032af5e6864613dd8207822600bc083e6e696f385296edb`.
- The external manifest pins every retained receipt and log; its SHA-256 is
  `2dc144770a4a70cf381dd1e339676b4ed3dd40db326973989288e86febf2cf4e`.
  Both receipts pass independent verifier mode, all manifest entries pass
  `sha256sum -c`, and the sanitizer contract is `13/13` with no skips. The
  focused serial-worker gate records TSAN as not applicable with one joined
  worker and `max_active=1`.
- `CS-P10-03` now meets its local acceptance gates on
  `phase-robustness-input-validation`. Generated `docs/TODO.md` and
  `docs/PROGRESS.md` remain unchanged and the task remains open in
  protected-main authority until an authorized merge records the closing
  transition; this work does not write to or merge `main`.

## 2026-08-13 — Phase 10.3 sanitizer matrix checkpoint (in progress)

- Added one CMake sanitizer profile boundary shared by the production core,
  CLI, unit tests, and four parser fuzz targets. AddressSanitizer and
  UndefinedBehaviorSanitizer carry compile and link instrumentation; UBSAN is
  non-recovering. Dedicated runtime tripwires prove that the selected runtime
  is active instead of treating compiler flags as sufficient evidence.
- Added a bounded matrix runner for complete CTest and direct single-process
  suites, focused serial-worker evidence, clean/finding/invalid/whole-program
  analyzer verdicts, two ordered MCP requests, and the four-target fuzz smoke
  campaign. The serial worker proves `max_active=1`, one joined worker thread,
  so TSAN is recorded as not applicable while production analysis remains
  sequential.
- Hardened the evidence boundary before retention: receipt output may not
  overlap either build tree; current product, test, script, workflow, PLAN,
  generated lifecycle, fuzz, and documentation inputs are source-bound while
  bytecode and the receipt's own hash-cycle outputs are excluded. Host
  sanitizer options are removed before each run; ASAN explicitly enables leak
  detection and pins LSan's failure exit, while UBSAN uses its exact retained
  environment.
- Pre-retention probes completed both ASAN and UBSAN matrices with `1200/1200`
  CTest entries, `1185/1185` direct C++ tests, active runtime tripwires, all
  analyzer/MCP gates, and four parser fuzz targets. Those temporary receipts
  predate the final manifest/environment hardening and are deliberately not
  promotion evidence.
- Checkpoint verification is `11/11` review-path tests and `26/26` combined
  fuzz/sanitizer contract tests; four sanitizer contract cases are expectedly
  skipped until retained receipts exist. The docs lifecycle guard, Python and
  shell syntax checks, and `git diff --check` are clean. The independent
  read-only reviewer found no remaining source-level blocker.
- Remaining before `CS-P10-03` local completion: rerun both complete matrices
  against the final source bytes, retain and externally checksum the two
  receipts and logs, make all receipt contract cases execute without skips,
  then run final regression/CI gates. This checkpoint carries no protected-main
  task-closing trailer and does not consume generated TODO work.

## 2026-08-13 — Phase 10.2 structured parser fuzzing

- Corrected the fixed PLAN boundary to the four input parsers that actually
  exist: project configuration, Clang's compilation database, CodeSkeptic's
  strict versioned text summary/model, and MCP JSON-RPC. SARIF remains an
  output reporter rather than an invented input format, and no analyzer-rule
  semantics were added.
- Added exact in-memory production parser entry points and four dedicated
  libFuzzer targets. Config parsing now commits the complete object only after
  a valid file; summary/model parsing commits a complete map only after a
  valid strict record set; MCP validation never starts analysis or filesystem
  discovery; compilation-database validation continues to use Clang's own
  parser rather than a second JSON grammar.
- Made existing-but-unusable config and compilation-database inputs fail
  closed, including malformed data, dangling links, and non-regular entries;
  a genuinely absent optional config or compile database retains its prior
  optional/fallback behavior. An invalid requested compilation database makes
  the verdict unavailable with exit `2` before analysis starts.
- Tightened the summary/model schema so `qualified-name/arity` is canonical,
  arity agrees with every parameter vector, and null-condition,
  zero-passthrough, null-passthrough, and return-alias indices are canonical,
  representable, and within arity. Tightened MCP envelopes to require
  `jsonrpc: "2.0"`, a string method, and a valid JSON-RPC id kind.
- Added a dedicated Clang/libFuzzer CMake mode, macOS/Homebrew include-order
  repair, nine checksummed seeds, fixed target/seed/budget mapping, 64 KiB
  input cap, five-second per-input timeout, 2 GiB RSS ceiling, per-target wall
  timeout, mutable temporary corpora, and a separate CI smoke job that retains
  its receipt.
- The documented extended campaign ran all four targets for exactly `10,000`
  inputs each with seeds `1001..1004`: all exits were `0`, no timeout or crash
  artifact occurred, and receipt verification re-bound each current binary,
  exact terminal run evidence, logs, corpus, campaign, toolchain, source bytes,
  and budgets. The canonical receipt SHA-256 is
  `e2c556426b2d076c8f1b113597e5721bc6b11844d7191d1008389654847ae3b7`;
  the external evidence manifest pins it and all four logs.
- RED evidence included malformed compilation-database fallback to a false
  clean exit, partial config mutation, invalid summary arity/index acceptance,
  invalid MCP envelopes, non-regular input paths, mutable/escaping campaign
  paths, unbounded budget drift, and coordinated receipt/log rewrites. The
  strict compile-database gate also exposed fail-open assumptions in the
  diff-review fixture: base worktree path aliases, absolute and relative Git
  renames, and a newly added TU without an explicit compile command. The
  remapper now preserves POSIX/Windows path, case, quote, escape, build-path,
  and directory-relative semantics, while the fixture explicitly lists every
  analyzed TU.
- GREEN is `17/17` focused production tests, `13/13` fuzz-contract tests,
  `47/47` offline lifecycle/path tests, the verified `4 x 10,000` campaign,
  `1184/1184` direct single-process C++ tests, and the final `1198/1198`
  complete CTest package. Receipt verification, the docs lifecycle guard,
  Python/shell syntax checks, and `git diff --check` are also clean. A
  separate salt-read-only review found no remaining blocker in this slice.
- This is local implementation evidence for `CS-P10-02`, not protected-main
  completion authority. `docs/TODO.md` therefore remains generator-owned and
  keeps the task open until an authorized protected-main completion trailer is
  observed.

## 2026-08-13 — PLAN-driven automatic TODO and PROGRESS lifecycle

- Corrected the previous partial automation: `docs/PLAN.md` now contains the
  fixed 26-item catalog: the protected-main-unclosed Phase 8.3, 8.4, and 9
  obligations plus the Phase 10–12 program. `docs/TODO.md` is rendered entirely
  from its still-open items and `docs/PROGRESS.md` remains a generated,
  append-only protected-main ledger. Neither generated file is hand-edited.
- Made only exact `Closes-CodeSkeptic-Task: CS-Pxx-yy` entries parsed from the
  real final Git trailer block on first-parent protected-main commits completion
  authority. A lookalike line in message prose, phase-branch trailer, local
  test output, changelog prose, or AI statement cannot remove work from TODO.
  Unknown, malformed, duplicate, dependency-invalid, or repeatedly closed task
  identities fail closed.
- Made status synchronization reject direct `main` use and made the PLAN
  catalog immutable once protected main contains the migration. Before that
  merge, the exact 26 IDs and catalog SHA-256 are pinned to protected-main
  `7dfd375`; deleting PROGRESS cannot invoke normal bootstrap, and CI rejects
  non-`phase-*` PR heads instead of skipping the generated-state gate.
- Preserved the existing legacy PROGRESS prefix byte-for-byte and activated a
  closure-only v2 ledger. Ordinary reconciliation commits are omitted, so one
  trailer-free reconciliation after the final task closure can produce an
  empty TODO and current ledger without an infinite self-recording chain.
- RED was five focused failures proving prose could spoof a closure, deleted
  history could bootstrap shorter, a non-phase PR bypassed the guard, Phase
  8/9 obligations disappeared, and final reconciliation was non-terminating.
  GREEN is `36/36` status/path tests, including byte-pinned migration, raw-byte
  protected-main/legacy ledger and PLAN equality, host-config- and Unicode-
  separator-independent raw trailer parsing, old-ref mature-bootstrap
  rejection, pair-write
  interruption and deterministic recovery, final reconciliation, manual drift,
  malformed history, cross-commit duplicate closure, first-parent-only
  authority plus reverse-parent anchor rejection, dependencies, and branch
  authority.
- Removed the obsolete duplicate Phase 9 qualification summaries from TODO's
  evidence validator. The authoritative retained manifest, three checksummed
  receipts per project, frozen candidate snapshot, and unique changelog
  summary remain cross-checked; all `21/21` candidate-evidence tests and the
  complete docs lifecycle guard pass.
- Final local verification is `57/57` combined status/path and candidate-
  evidence Python tests, `36/36` focused Config/MCP/docs CTest entries,
  `1170/1170` direct single-process C++ tests, and `1183/1183` complete CTest
  entries in `163.39 s`. The real phase branch passes the docs gate; a
  simulated `feature-docs-bypass` head fails it with exit `1`; Python syntax
  and `git diff --check` are clean.
- The first real sync on `phase-robustness-input-validation` generated all 26
  open tasks, froze the legacy ledger at its `7dfd375` v2 anchor, and appended
  zero task receipts because protected main remains at that commit. Therefore
  the locally GREEN `CS-P10-01` implementation correctly
  remains open until a later authorized merge commit carries its exact trailer.

## 2026-08-13 — Phase 10.1 targeted scopes fail closed

- Rejected empty and delimiter-only function scopes consistently across the
  CLI, project config, and MCP input surfaces. A malformed targeted request can
  no longer collapse into the empty-filter meaning of “analyze all functions.”
- Made function- and line-scope updates atomic: a rejected value leaves the
  previously accepted scope unchanged, while valid repeated plain and
  qualified function names remain cumulative.
- Recorded RED first across Config and MCP tests plus an independent binary
  replay. GREEN is three focused tests, `34/34` Config/MCP tests,
  `1170/1170` direct single-process C++ tests, and `1183/1183` CTest entries
  including Python and end-to-end workflow contracts. The invalid CLI replay
  exits `2` before analysis starts; independent review found no blocking issue.
- This completes the local implementation evidence for `CS-P10-01` only; it
  does not authoritatively close the task before protected main contains its
  exact completion trailer. Fuzzing, resource budgets, the 72-hour
  stability/performance gate, and Phases 11–12 remain open.

## 2026-08-13 — Upstream candidates moved to end-of-program batch review

- Replaced per-candidate owner prompts with uninterrupted internal collection.
  Every candidate dossier retains the trigger path, CWE, current-head proof,
  duplicate search, severity, and proposed issue text.
- Prohibited upstream issues, PRs, comments, forks, and maintainer contact
  during the active product program. The complete candidate set is presented
  once at program completion; only owner-selected targets may proceed after
  target-specific approval.
- Preserved issue-first reporting, separate approval for direct PRs, showcase
  eligibility after maintainer confirmation or acceptance, and explicit owner
  approval before the complete program's final `main` merge.

## 2026-08-13 — Owner-controlled upstream reporting restored

- Corrected the over-broad execution-authority wording: continuous authority
  remains for CodeSkeptic push, PR, intermediate merge, and release/tag work,
  but no longer claims to cover any upstream action.
- Made target-specific owner approval mandatory before upstream issues, PRs,
  comments, forks, or maintainer contact. The default reporting route is now
  issue-first; a direct PR requires separate approval. Maintainer-confirmed or
  accepted issues may enter the public showcase, while the accepted-fix ledger
  still counts only merged fixes.
- Required owner notice and explicit go-ahead before the final `main` merge
  after the complete product program.
- Closed rtp2httpd PR #709 and libgit2 PR #7345 unmerged at the owner's request.
  The former remains internal candidate evidence; the latter is also retained
  as unproven because its description and changed path did not match and the
  reported state correlation was not demonstrated as triggerable. Neither PR
  changes the Phase 9 ledger (`3/10` fixes across `2/5` projects).

## 2026-08-13 — Phase 9 documentation structure recovery

- Moved all eleven canonical current-head qualification summaries into the
  Phase 9 evidence slice instead of leaving them after the file-discipline
  footer or inside the recovered-program roadmap.
- Restored the uninterrupted Phase 9 roadmap item, removed duplicate scratch
  notes, and consolidated the two pending upstream submissions under the
  measured `3/10` fixes across `2/5` projects state.
- This recovery changes no retained receipt, manifest, candidate identity,
  analyzer result, accepted-fix ledger entry, product code, or quality floor.

## 2026-08-13 — Phase 9 distinct candidate coverage

- Phase 9 current-head qualification: lvgl qualified with 3/3 accepted repetitions at 470/470 translation units, with 0 broken units, 0 incomplete functions, and 13 stable findings. The live-head manifest, Kconfig profile, LLVM19 recipe, and three fresh raw receipts are retained and cross-checked automatically. This does not change the accepted upstream ledger.
- Phase 9 current-head qualification: llama-cpp qualified with 3/3 accepted repetitions at 201/201 translation units, with 0 broken units, 0 incomplete functions, and 41 stable findings. The live-head manifest, LLVM19 recipe, and three fresh raw receipts are retained and cross-checked automatically. This does not change the accepted upstream ledger.
- Preserved separate attempted and analyzed translation-unit counts across retained snapshots, manifests, receipts, and canonical document summaries; recipes that expand whole-program analysis are no longer forced into a false equal-count model.
- Added exact numeric-boundary checks so the canonical TODO and changelog summaries reject prefixed, suffixed, or otherwise drifted coverage counts.
- Phase 9 current-head qualification: shadPS4 qualified with 3/3 accepted repetitions at 385/385 translation units, with 0 broken units, 0 incomplete functions, and 65 stable findings. The retained manifest, three raw receipts, checksums, analyzer identity, source identity, and semantic summary are now enforced together. This does not change the accepted upstream ledger of 3 fixes across 2 projects.
- Phase 9 current-head qualification: libarchive qualified with 3/3 accepted repetitions at 132/132 translation units, with 0 broken units, 0 incomplete functions, and 36 stable findings. The retained manifest and three fresh raw receipts are bound to the live default-branch head and the current LLVM19 analyzer. This does not change the accepted upstream ledger of 3 fixes across 2 projects.
- Phase 9 current-head qualification: rtp2httpd qualified with 3/3 accepted repetitions at 38/38 translation units, with 0 broken units, 0 incomplete functions, and 24 stable findings. The retained manifest and three fresh raw receipts bind the unchanged live head to the current LLVM19 analyzer. This does not change the accepted upstream ledger of 3 fixes across 2 projects.

## 2026-08-12 — Phase 9 first current-head execution

- Fixed two shared-runner defects exposed by a project recipe without Ninja target closure: the optional command output is initialized as text, and target filtering runs only when target evidence exists.
- Added structural regression coverage for both the default and target-restricted paths; existing release-candidate behavior remains pinned.
- Ran current rtp2httpd head `e49df993ca2629bb116a29a87ce2afff24d97ef7` locally with an isolated Fedora LLVM 19 runtime: accepted `38/38`, broken 0, incomplete 0, findings 24.
- Compared against the accepted Phase 8 receipt: all 19 unique fingerprints are unchanged, with zero additions and zero removals. The result remains discovery evidence until individual candidates pass Gates A, B, and C.

## 2026-08-12 — Phase 9 frozen current-head candidate batch

- Counted 260 findings across seven projects from accepted, checksummed Phase 8 receipts and froze the first low-drift current-head batch for rtp2httpd, llama.cpp, and libgit2.
- Added a deterministic materializer that reuses qualified recipes while replacing only immutable project revisions; repository drift, unknown or duplicate projects, malformed dates, and malformed commit identities fail closed.
- Preserved the three-repeat campaign invariant and produced a planner-accepted nine-shard matrix. The batch is discovery-only and cannot bypass Gates A, B, or C.
- Passed 4 candidate-manifest tests, 10 ledger tests, Python syntax, JSON/YAML parsing, and diff checks.

## 2026-08-12 — Phase 9 append-only validation ledger

- Added a schema-checked Phase 9 ledger with the three reverified accepted records and the fixed `10` fixes / `5` projects target.
- Added a fail-closed validator for all accepted Gate A/B/C evidence, merged identities, current default-branch ancestry records, unique IDs, and durable non-accepted classifications.
- Added an optional previous-ledger comparison that permits only an unchanged prefix plus appended records; mutation, deletion, and reordering are rejected. A dedicated PR job compares the proposed ledger with the target tree.
- Passed 10 focused tests, Python syntax, JSON parsing, document automation, and diff checks. Gate C supports general report/fix references without assuming one hosting platform, and recorded dates have checked ISO forms. The measured completion gate correctly remains incomplete at `3/10` and `2/5`.

## 2026-08-12 — Phase 9 upstream validation boundary

- Locked Phase 9 to PLAN section 6 Gates A, B, and C on current default-branch heads, with a hard completion target of ten accepted fixes across five independent projects.
- Reverified three existing accepted fixes across two projects: shadPS4 PRs `#4702` and `#4703` remain in current `main`, and TensorFlow PR `#123994` remains in current `master`.
- Established the measured RED baseline at `3/10` fixes and `2/5` projects; rejected, duplicate, stale, non-triggerable, and false-positive candidates remain durable non-counting evidence.
- Restricted the first implementation slice to a schema-checked append-only ledger and fail-closed validator before any new candidate is reported.

## 2026-08-12 — Phase 8.4 release-candidate factory qualified

- Hosted run `31536531313` at `21278b2e561c76aabc0fbca6c72c911eb341c62a` accepted all nine checksummed receipts and the aggregate receipt after a failed-only rerun recovered one pre-project checkout interruption.
- All three repetitions are identical per project: llama.cpp `200/200` with 40 findings, ShadPS4 `382/382` with 66 findings, and TensorFlow Lite `241` requested / `245` analyzed with 73 findings.
- All nine receipts use one analyzer identity; broken TUs, incomplete functions, and failure entries total zero. The aggregate is accepted and its checksum verifies.
- The accepted aggregate is uniquely pinned to artifact ID `9123466154`, artifact digest `sha256:4fe8b5450c497aff60a33f815f4ec4d4d8c3f34bb1b0994a1e98e2683520295c`, and receipt SHA-256 `684b868c9ec86da57b279c3bc5db81482ec8578990649e7aefef5767f84dfbf5`; same-name artifact ID `9121649494` is unavailable evidence.
- Phase 8.4 is qualified; partial receipts from attempts 1–8 remain classified as unavailable evidence.

## 2026-08-11 — Phase 8.4 hosted dual-toolchain correction

- Run `31525147338` showed that replacing the shard compiler with `clang-19` broke the immutable candidate recipes, which explicitly configure their source builds with `clang-20`.
- Phase 8.4 hosted factory attempt 3 (`31525916462`, head `6f0453b741aee8a6f09489915cb6476b48a6c7ee`) confirmed both compiler packages were available and exposed a deterministic target-selection mismatch: TensorFlow Lite repeated 269 units rather than the qualified 241. The 28 additions were exclusively non-target tools, profiling, Python, and example units. Cancelled the unwinnable run, moved the proven Phase 8.3 Ninja target-closure filter into the shared campaign runner, and verified against the downloaded artifact that it restores the exact 241/241 relative identity set. Hosted rerun remains pending.
- Phase 8.4 hosted factory attempt 4 (`31528519780`, head `4bc34a99338d9df0ba7ad045315d6eb0ce2b7cd3`) reached the new target-closure integration. All Llama commands exited 0, after which each repetition exposed the same `file_list` versus `files` wiring error. Cancelled the run, corrected the binding to transform the existing `files` and `relative_files` pair, and passed syntax, 23 focused tests, structural binding verification, and diff checks before the next rerun.
- Phase 8.4 hosted factory attempt 5 (`31529684488`, head `43d40d136731d753f9da7625940d08d154d638e2`) proved the target-closure binding with three identical accepted Llama receipts: 200/200, broken 0, incomplete 0, findings 40. Shad configure failed identically in all three repetitions because `mold`, present in the qualified Phase 8.3 image, was absent from the factory image. Restored `mold` only in the release-candidate package step and added a regression assertion; TensorFlow repetitions from the attempt continue in parallel.
- Phase 8.4 hosted factory attempt 6 (`31531567925`, head `b1b8d83e9cd7d66a5f83f81388aa54f9f8bc603a`) exposed a package-array wiring error: every shard tried to execute `mold` before the install command because the token sat outside the Bash array expression. Moved it inside the release-only package array and strengthened both the tier-selection and linker regression assertions; all 17 factory tests pass.
- Phase 8.4 hosted factory attempt 7 (`31532850193`, head `4fb651d38c83713492abe7d21b7c52975c48a751`) confirmed the corrected package array and accepted all three Llama receipts. Shad moved beyond the linker probe, then exposed the remaining environment delta: the qualified X11, Wayland, audio, input, and OpenGL development packages were absent. Copied the complete Phase 8.3 Shad package set into the release-only array, changed the regression to verify the full required subset, passed 17 factory tests, and cancelled the unwinnable run.
- Phase 8.4 hosted factory attempt 8 (`31534556897`, head `703dfa16fff0ffc7d5549e0a3170b0d5c9d6cfff`) accepted all Llama repeats and moved Shad through configure into compilation. The build then failed with exit 127 at CMake's missing `clang-scan-deps` launcher. Restored the exact Phase 8.3 `clang-tools-19` package, pinned it in the release-only dependency subset, passed 17 factory tests, and cancelled the unwinnable run.
- Cancelled the invalid run after TensorFlow Lite configure receipts proved the missing executable; no partial result was admitted.
- Release-candidate shards now install both `clang-20` for candidate builds and `clang-19` for analyzer resources; nightly and weekend shards remain unchanged.
- Updated the workflow contract to pin the two-package release behavior.

## 2026-08-11 — Phase 8.4 hosted shard toolchain correction

- Run `31523815926` proved the plan and shared LLVM 19 analyzer stages, then produced unavailable llama.cpp receipts with `199` broken TUs because shard images lacked the matching Clang resource headers.
- Cancelled the invalid run; its partial artifacts remain classified as unavailable and are not promotion evidence.
- Added tier-aware shard packages: release-candidate jobs install `clang-19`, while nightly and weekend jobs retain `clang-20` and their existing expectations.
- Extended the workflow contract test to pin both analyzer-build and shard-runtime toolchain selection.

## 2026-08-11 — Phase 8.4 factory promotion implementation and local qualification

- Promoted the three exact Phase 8.3 recipes into an 11-project manifest and added a manual 72-hour release-candidate campaign with three repetitions per project.
- Extended factory checkout identity with pinned recursive submodule count and checksum evidence; ShadPS4 requires the qualified 53-entry identity before build.
- Extended the shared-analyzer workflow to select LLVM 19 for the release-candidate tier, retain LLVM 20 for existing tiers, and preserve aggregate equality across all three receipts.
- Verified RED `2` to GREEN `0` with a nine-shard plan, both campaign contract suites, an LLVM 19 Release build at `100/100`, and full CTest at `1177/1177`; the later accepted hosted aggregation is recorded above.

## 2026-08-11 — Phase 8.4 release-candidate factory boundary

- Locked promotion to the three exact Phase 8.3 candidate recipes and their immutable coverage and fingerprint expectations.
- Required a manual 72-hour campaign with three repetitions per project, one shared analyzer artifact, and aggregate equality across all receipts.
- Required ShadPS4's recursive 53-entry submodule identity to match its qualified checksum before the build begins.
- Recorded the pre-implementation RED: boundary head `0759dca` rejects the absent release-candidate tier with exit `2`; GREEN requires a nine-shard plan and hosted aggregation.

## 2026-08-11 — Phase 8.3 exact qualification closed

- Rebased the release-candidate factory onto the fixed-width summary guard and aligned the shared analyzer build with LLVM 19.
- Closed hosted run `31515185143` at head `ecec77a8b02bb2ffdbf62d4deff936bbcaf65ff6` using one immutable analyzer artifact across all candidates.
- Qualified llama.cpp at `200/200` executions with 40 findings, TensorFlow Lite at `241` requested and `245` admitted executions with 73 findings, and ShadPS4 at `382/382` with 66 findings.
- Every receipt reports zero broken translation units, zero incomplete functions, and a findings-only semantic exit.

## 2026-08-11 — Fixed-width summary guard

- Limited zero-passthrough width reasoning to fixed builtin integer types.
- Kept dependent, enum, incomplete, and other uncertain-width types conservative.
- Added a regression case from the real template pattern that exposed the invalid width query.
- Verified the focused regression and full local suites with LLVM 20 and LLVM 19; the exact Shad candidate completed 382/382 translation units with LLVM 19.

## 2026-08-11 — Phase 8.3 production-target qualification correction

Rebased the observational release-candidate lane onto protected-main commit
`7dfd37596414c9512316093ff4fb6b039673f55f`, which contains the GCC14
immutable-flag correction from PR #139. The qualification contract now requires
translation units to belong both to the real compile database and to the named
Ninja production target's command closure. RED-first tests exclude
configured-only sources, dependency sources, malformed closures, and paths
outside the pinned source tree.

This corrects the TensorFlow Lite surface without accepting expectations. Its
505-step hosted build configured 269 unique project source paths, but ten were
not members of the production library target and required generated or Python
binding headers absent from that build. The exact `tensorflow-lite` target is
241 unique translation units with digest
`2dd69e73c882f6a3ea17a63349500db7d350eb1d3aaa5a8a47f06a716f5fed5f`.
A full local observation completed with coverage fields 241 attempted, 245
analyzed, zero broken, and zero incomplete functions, plus 73 supported
blocking findings and normal exit 1. Its fingerprint digest is
`6cf30f16db0a5eb2537e6178a30087a0385b7dfdb1ff5f61d9bb2815a765a81a`
and report SHA-256 is
`717f15b1dab63648e5864c85db0994bdf1d1648a7bf6631cf11563babbf152fb`.

The first shadPS4 hosted build showed that Clang 20 with GCC 14's default
libstdc++ is not a valid recipe for the pinned sources. A narrow disposable
Ubuntu probe established only that libc++ 20 exposes the required C++23
`std::jthread` and `std::stop_token` surface (`_LIBCPP_VERSION=200100`). The
complete libc++ rerun reached step 2,181 of 2,452 and then disproved that recipe
because the packaged library does not expose `std::chrono::current_zone()`.
The immutable upstream production workflow is the stronger recipe authority:
Ubuntu 24.04, Clang 19 with the default libstdc++, and mold. RED-first contract
assertions now pin those shadPS4 compiler and linker choices, preserve its
upstream-enabled Discord/updater surface, and enable Release IPO; llama.cpp
and TensorFlow Lite remain on Clang 20. The first production-shaped rerun
configured successfully and reached step 433 of 2,554, where CMake's C++23
dependency scan invoked the absent `clang-scan-deps-19` binary and stopped with
exit 127. The matching `clang-tools-19` package is now pinned instead of
disabling IPO or narrowing the production surface. The corrected hosted run
then completed all 2,554 build steps and exposed an observer-only parsing
defect: CMake's Clang dependency-scanner form places its source path before
`-c`. A RED-first regression preserves that real command shape. Target closure
selection now matches command tokens position-independently against the
already validated compile-database surface, while ambiguous matches and an
empty intersection still fail closed. The three-candidate hosted rerun remains
the referee; no canonical expectation, production factory membership, or
accepted contract intent changed. No C++ production function changed, so the
contract-first shadow counts are all zero.

## 2026-08-11 — GCC14 immutable-flag evaluator hardening and local qualification

Phase 8.3 hosted qualification completed the pinned TensorFlow Lite surface's
505-step build and selected 269 production translation units, but the analyzer
crashed on `tensorflow/lite/core/acceleration/configuration/delegate_registry.cc`.
Clang 20 with GCC 14 libstdc++ reproduces the failure on that single TU with
exit 139. GDB traced more than 838,000 recursive frames through Clang constant
evaluation to `edgeInfeasibleByFlags`; instrumentation identified a non-flag
member equality in libstdc++ 14 `bits/unicode.h` as the last evaluated
expression. A standalone five-line C++20 `<format>` source also returns exit
139, separating the product bug from TFLite and the qualification factory.

The immutable-flag engine promises to evaluate the constant side of only a
known `flag ==/!= constant` comparison. The existing implementation violated
that boundary by calling `EvaluateAsInt` on one side of every equality before
proving the other side was an immutable flag. RED is pinned by the focused
`ImmutableFlagsTest.FormatHeaderEqualityDoesNotEvaluateNonFlagOperands`, which
crashes the unmodified GCC14 test process with exit 139. This branch is limited
to gating that evaluation behind flag recognition, preserving both operand
orders and equality operators, the focused test-helper wiring, and required
documentation automation. PR #138 remains qualification-only; no campaign
recipe or expected result changes here.

The implementation now performs flag recognition before any constant
evaluation. It tries both operand directions only through that gate, retaining
`==` and `!=` pruning without sending unrelated standard-library expressions
to Clang's evaluator. The standalone `<format>` regression is GREEN in 614 ms,
an explicit four-shape equality/inequality regression is GREEN, and the related
immutable-flag behavior set is 14/14 GREEN. The full CTest suite is 1175/1175
GREEN and the direct single-process suite is 1166/1166 GREEN. Self-scan is
clean and complete at 48/48 TUs; its JSON receipt SHA-256 is
`53ddcd60f2fee8cbf6d7538c61bdbcec162ea2cba43562bee3911aefa941cc47`.
The frozen thesis gate remains `clean_fp=0`, `bug_caught=9/15`, and 11 total
findings. The real-corpus referee remains exactly on its pins: cJSON 54
findings (76 enumerated, 35 analyzed, 41 explicitly accepted broken fixtures)
and tinyxml2 9 findings (3/3 analyzed).

Analyzer SHA-256
`2ad4991268a3a9921e9d8095b1f0cd1767893701427627425a624460da9bd0a2`
then completed the exact GCC14 TFLite TU with 1/1 analyzed, zero broken TUs,
zero incomplete functions, and one supported blocking `memory-leak` finding
at `TfLiteTensorVariantRealloc` (`csf1-a845db511c25bcc3`). Exit 1 is the normal
findings verdict, not a tool failure. The complete JSON receipt SHA-256 is
`fce1be0c540059ebd2f4b7c10a8abaf428677de48b308ac0cb7185717dfc1187`.

Contract-first shadow completion considered the one materially changed
production function, `edgeInfeasibleByFlags`: proposals 0, eligible 0,
rejected 0, unsupported 1. Conditional evaluator call order over Clang AST
state is outside the current contract grammar and referee, so no proof-bearing
annotation was invented. No candidate requires later human review and no
`cs: ai` proposal became accepted intent. Executable RED/GREEN fixtures remain
the authority for this boundary.

## 2026-08-10 — Phase 8.2 weekend factory implementation and qualification

The canonical factory now has separate, non-overlapping nightly and weekend
tiers. Its weekend manifest pins systemd, curl, Redis, and LVGL to the exact
commits, real build recipes, source identities, coverage, findings, verdicts,
and fingerprint digests in the locked boundary. The validator admits Meson
only as configure `setup` or build `compile -C` with strictly shaped options
and targets. Bear is admitted only around native Make with the fixed compile-
database output/source prefix, `-j{jobs}`, and simple variable assignments.
Option-shaped Meson targets, alternative Bear/Make structures, shell control,
and every other command remain rejected.

The workflow selects the existing nightly tier from its daily cron and the
weekend tier from one distinct weekly cron or explicit dispatch. Unknown tiers
fail before matrix execution. Required Meson, Bear, gperf, capability, and
mount development packages are installed without changing any ordinary PR
gate or the existing per-shard time ceilings.

RED first recorded four factory gaps across canonical membership, weekend
window bounds, command shapes, and workflow orchestration. The implementation
closes all four; 14/14 Python contract tests, the executable manifest ledger,
bytecode compilation, YAML parsing, whitespace checks, and the full 1166/1166
CTest suite pass. The first Redis runner probe also exposed the separately
recorded preliminary digest assumption before implementation acceptance.

One Linux analyzer SHA-256
`e5f2031e0da767f636450e702b6487134256fd7da8bb03f3d5fd3eda888d562c`
then produced twelve accepted receipts. Three independent repetitions agree
for systemd at 390 requested / 815 analyzed and 0 findings, curl at 169/169
and 59, Redis at 103/206 and 0, and LVGL at 311/311 and 16. Every shard has
zero broken TUs and zero incomplete functions. The aggregate manifest SHA-256
is `88e7dbe8d46b88bd95e88b83106096953e90fed425b39a68d68225a78279a255`;
the checksummed aggregate receipt SHA-256 is
`9bbc429187d5059d0f292677420ff79c7d2755bc001deb5e80addb109f68e498`.

GitHub workflow run
[`31381555374`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/31381555374)
independently rebuilt analyzer SHA-256
`52f8520234e350ced20678a4f6356b0e96da3da6aa4d19be4e1f78046af54861`
and accepted all twelve weekend shards. Its project semantic digests exactly
match the local aggregate and its checksummed aggregate receipt SHA-256 is
`e781fbffa80f44b41a5bc97585c9385d950c5e6e8338d1bacf43c2a7fe111ec9`.
Separate nightly regression run
[`31382838369`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/31382838369)
used the same hosted analyzer, accepted all twelve original shards without
finding/fingerprint drift, and produced aggregate receipt SHA-256
`2954b90c3fba14d6d76bab985949428bc6cd091a466cf321970ddbf160a478ce`.
All ordinary PR checks are green and PR #137 has no review threads. Protected-
main delivery later completed at squash commit
`488377ad06f6d516faf57e902703208a2c0ddbcc`.

No C++ function changed, so contract-first shadow dogfood is not applicable:
functions considered 0, proposals 0, eligible 0, rejected 0, unsupported 0.
No proposal exposed a problem; the independent runner exposed the pre-hash
assumption. No candidate contract requires human review, no `cs: ai` proposal
became accepted intent, and native owned-memory semantics remain deferred to
executable A7 fixtures.

## 2026-08-10 — Phase 8.2 pre-implementation boundary correction

The first official Redis runner probe reproduced the same sorted 103-file
surface but rejected the preliminary digest. Direct comparison proved the
file lists identical; the preliminary PowerShell normalizer/hash calculation
was the incorrect authority. The runner's canonical
`translation_unit_digest` is
`289cde3a18f71ccdcf3fd3b317a232e57514c14690b8d67f8551af261bcff844`.
It supersedes only the Redis SHA literal in the boundary below. Implementation
changes were uncommitted and acceptance was paused before this correction;
the project pin, recipe, source roots, 103-file count, file set, and every
other boundary remain unchanged. Official curl, LVGL, and systemd probes
reproduced their locked TU identities.

## 2026-08-10 — Phase 8.2 weekend factory boundary

Protected main contains Phase 8.1 through PR #136 at
`3b1714e1e9e3997ab63507837c3a177c1bdefab1`, tree
`0293f291d2a4a7876eaa734e6b23dd0a82779377`. The branch-opening status sync
mechanically appended that merge to PROGRESS and regenerated TODO's state
block before new implementation work.

The separately locked weekend tier consists of systemd v256.17 at
`009adf6c0e435376c80fbc11675d581e0a94d350`, curl 8.11.0 at
`b1ef0e1a01c0bb6ee5367bd9c186a603bde3615a`, Redis 7.4.2 at
`a0a6f23d997b024689ba157916837f493a593a34`, and LVGL 9.2.2 at
`7f07a129e8d77f4984fff8e623fd5be18ff42e74`. Exact minimal-build source
identities measured before implementation are systemd 390
(`5a65361ff67a6bc1dca48d0da5aee60ead0f1a061084492684e2c1cb7313823c`),
curl 169
(`213f0c1cb75de379b16ade4d0ab7cc8e701ced13a51fc822060db1f95ec92a01`),
Redis 103
(`3b01da3958fa65529f859ca097ef6e471a8ec45f9976c31d833311559588aa1b`),
and LVGL 311
(`30a090f5cdffb81f3b2184b5cd537d4ac85fff23acf3cdccecdb9ec13af00e50`).
Historical measurements from other revisions or build configurations are not
interchangeable with these identities.

The implementation may add only strict Meson setup/compile and Bear-wrapped
native-Make command shapes to the existing token-array runner. It will add an
exact 2,880-minute, three-repeat weekend manifest tier and a distinct weekly
Actions selection while preserving the nightly tier and every existing
fail-closed receipt rule. Finding and fingerprint expectations must be
measured with the current analyzer and repeated three times; they are not
inferred from historical documentation.

The exact file set is `.github/workflows/realworld.yml`,
`scripts/realworld_manifest.json`, `scripts/run_realworld_campaign.py`,
`tests/RealworldCampaignTest.py`, `docs/benchmarks.md`, `docs/reproduce.md`,
`docs/TODO.md`, `docs/PROGRESS.md`, and this changelog. No C++, grammar,
accepted intent, capability, profile, schema, release, quality-floor, nightly
project, or ordinary PR gate change is admitted. RED-first tests are the
implementation referee and this pre-implementation boundary will not change.

Contract-first shadow dogfood is not applicable because no C++ function is
created or materially changed. Functions considered 0; proposals 0; eligible
0; rejected 0; unsupported 0. No proposal exposed a problem, no candidate
contract requires human review, and no `cs: ai` proposal can become accepted
intent. Native owned-memory semantics remain deferred to executable A7
fixtures.

## 2026-08-10 — Phase 8.1 factory implementation and local qualification

The nightly factory now has one structured authority for four immutable
projects and twelve independent shards. The validator reserves obvious
placeholder SHA-256 values, admits only controlled token-array recipes, and
rejects mutable revisions, unsafe paths, unavailable verdicts, partial
coverage, or unbounded campaign inputs. Shards check out and build the exact
project, hash the sorted requested TU identity, run one analyzer under time
and memory bounds, and write a receipt plus checksum even when evidence is
unavailable. Exact-identity checkpoints are optimization only. The separate
aggregate referee requires three accepted, checksum-valid, semantically
identical receipts per project and one valid analyzer digest across the whole
campaign. It recomputes semantic structure and fingerprint identities rather
than trusting a checksummed payload, and early shard or aggregate failures
still publish checksummed unavailable evidence. The 355-minute scan-job bound
leaves a 25-minute evidence-publication margin above the 330-minute project
limit while remaining below GitHub's six-hour ceiling.

RED-first qualification exposed one factory assumption: libarchive requests
132 exact source files but `--whole-program` deliberately produces 255
analysis executions. Requiring analyzed executions to equal requested files
rejected complete evidence. The corrected contract still requires the exact
requested count, permits only an analysis count at least that large, pins the
exact project-specific value in the manifest, and continues to require zero
broken TUs and zero incomplete functions. The new regression test proves both
the 2-request/3-execution case and rejection of under-coverage.

Historical-to-current finding drift was classified before updating the
manifest. libgit2 moved 34 to 39 by closing three prior reports and adding
eight findings under the later ownership/lifetime engine. rtp2httpd retains
its four historical findings and adds 17 memory-leak plus three promoted
resource-leak reports. Abseil moves 4 to 12 under the later interprocedural and
ownership/lifetime engine. libarchive moves 35 to 38, from 17 memory-leak and
18 null-deref to 19 of each. Project revisions, build recipes, and requested
source identities remain immutable; these are classified analyzer-semantic
changes, not silently accepted upstream drift.

The local Linux aggregate accepted all twelve receipts with analyzer SHA-256
`e5f2031e0da767f636450e702b6487134256fd7da8bb03f3d5fd3eda888d562c`
and manifest SHA-256
`f8cae660758d1df9aeb0c931fa4a13028ffe8dd18d3645b12f220d601b765c36`.
Per-project results are libgit2 167/167 and 39 findings, rtp2httpd 38/38 and
24, Abseil 158/158 and 12, and libarchive 132 requested / 255 analyzed and 38;
all have zero broken TUs, zero incomplete functions, exit 1, and identical
fingerprint identities across three repetitions. Remote publication evidence
was then independently reproduced by GitHub workflow run
[`31370373875`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/31370373875)
at commit `856cdc73a4ce245eb70cdf73da2c35fcd02545e7`: plan, one analyzer
build, all twelve shards, and the aggregate referee passed. The hosted
campaign-wide analyzer SHA-256 is
`146e6761107acfaf7fd6a1057a420e7abadcdb2de77bc66b09d3e3af5933e4f3` and
the checksummed aggregate receipt SHA-256 is
`08f8fe075e2dba92c8706c9028026d46cbb6b5148913d113146c1b64ffd559f6`.
Protected-main delivery later completed through PR #136 at squash commit
`3b1714e1e9e3997ab63507837c3a177c1bdefab1`.

Local release gates are green: the deterministic factory suite passes 12/12,
the full NMake/CTest suite passes 1166/1166, the direct C++ suite passes
1164/1164, capability/profile/documentation/corpus/thesis/self-scan gates pass,
and the bounded 400-case-per-CWE Juliet campaign retains every published
recall and false-positive floor. Python bytecode compilation, workflow YAML
parsing, and whitespace validation also pass.

No product C++ function changed, so contract-first shadow dogfood is not
applicable. Functions considered 0; proposals 0; eligible 0; rejected 0;
unsupported 0. No proposal exposed an implementation or assumption problem;
there are no candidate contracts requiring later human review, and no
`cs: ai` proposal became accepted intent. Native owned-memory semantics remain
deferred to executable A7 fixtures.

## 2026-08-10 — Phase 8.1 deterministic real-repository factory boundary

Protected main contains the progress/review automation maintenance through PR
#135 at `e146a434f17e61813cceb175ea8791c9065a1b38`, tree
`fc719f17f30e32bac49d80dac5f80b4002e9f32b`. Running the documented sync on
the new Phase 8 branch appended that protected-main transition to PROGRESS and
regenerated TODO automatically, proving the owner-requested workflow before
new product work began.

The first Phase 8 boundary is the nightly core real-repository factory for
libgit2, rtp2httpd, Abseil, and libarchive. A canonical manifest will bind each
project to an immutable commit, controlled build recipe, exact translation-
unit count and digest, expected coverage/finding/verdict tuple, timeout, and
three independent repetitions. A validator/planner, single-shard runner, and
separate aggregate referee will keep input eligibility, execution evidence,
and deterministic acceptance distinct. Coverage gaps, unavailable verdicts,
stale checkpoints, tampered receipts, missing repetitions, or semantic drift
must fail closed with exit 2. Each shard keeps its own artifact; checksummed
checkpoints are reusable only when every project/analyzer/manifest/recipe/TU
identity matches.

The Actions lane will build the analyzer once, fan out project-by-repetition
shards, upload evidence even on failure, and aggregate independently. The
nightly campaign may occupy a 12-hour aggregate window, but no hosted shard
claims a duration beyond the platform job ceiling. Existing PR unit, CTest,
cJSON, tinyxml2, self-scan, and Juliet work receives an explicit 30-minute job
ceiling. Weekend and release-candidate tiers are deliberately excluded until
their own pins and measured expectations are locked.

The exact file set is `.github/workflows/ci.yml`,
`.github/workflows/juliet.yml`, `.github/workflows/realworld.yml`,
`scripts/realworld_manifest.json`, `scripts/run_realworld_campaign.py`,
`scripts/check_realworld_ledger.py`, `scripts/realworld_expected.txt`,
`tests/RealworldCampaignTest.py`, `tests/RealworldLedgerTest.py`,
`tests/CMakeLists.txt`, `docs/benchmarks.md`, `docs/reproduce.md`,
`docs/TODO.md`, `docs/PROGRESS.md`, and this changelog. No product C++,
contract grammar, capability, profile, schema, release, or quality-floor
change is admitted. The contract is separate from implementation and will not
change during this slice.

Contract-first shadow dogfood is not applicable: no C++ function is created or
materially changed. Functions considered 0; proposals 0; eligible 0; rejected
0; unsupported 0. No proposal exposed a problem, there are no candidate
contracts for later human review, and no `cs: ai` proposal can become accepted
intent. Native owned-memory semantics remain deferred to executable A7
fixtures.

The former external development note was no longer present at its original
desktop path. Its recovered Phase 8–12 program is now recorded as the durable
queue in `docs/TODO.md`: real-repository factory, upstream validation,
robustness/performance, distribution/governance, and external beta/v1.0. This
does not alter the fixed `docs/PLAN.md` or create a forbidden parallel plan;
Phase 8.1 was the next active slice at recovery time. It and Phase 8.2 are now
delivered through protected main; Phase 8.3 and Phase 8.4 are qualified on the
still-open PR #138 branch.

## 2026-08-10 — Verified progress and Windows review maintenance boundary

Phase 7 is merged through protected-main PR #134 at
`47b03f4076f246c38a81fbc834693bed0f98ccc4`, tree
`d21f47b802f5a824626501d39425e98fb6509142`. The separate owner-requested
automation boundary is now locked before implementation.

The progress authority is git, not prose. A new append-only
`docs/PROGRESS.md` ledger may record a transition as `MERGED` only when its
commit is reachable from `origin/main`. Phase branches, local receipts, AI
statements, and changelog text remain non-authoritative. A single status tool
will append newly observed protected-main commits and regenerate TODO's marked
state view; its read-only mode will fail on stale, malformed, rewritten, or
non-ancestor progress and on a mismatched TODO block. Missing git facts fail
closed in CI. The changelog remains the detailed rationale/evidence record.

The same maintenance slice owns two Windows defects measured by the Phase 7
strict diff referee. Compile-command remapping recognized forward slashes but
not native backslashes, so base sources included head headers. After that was
corrected temporarily, dependency paths from an older build tree were wrongly
remapped into the base worktree. Finally, native relative paths failed to
match Git's slash-separated changed-file list, yielding a contradictory
coverage section. Permanent separator-tolerant source remapping, build-path
protection, and slash-normalized relative paths are required, with synthetic
Windows regressions plus the existing end-to-end review flow as referees.

The exact file set is `docs/PROGRESS.md`, `docs/TODO.md`, this changelog,
`CONTRIBUTING.md`, `scripts/progress_status.py`,
`scripts/check_docs_sync.sh`, `scripts/review_report.py`,
`tests/StatusAutomationTest.py`, and `tests/CMakeLists.txt`. No product C++,
grammar, capability, workflow, profile, release, or floor changes are allowed.
Contract-first shadow dogfood is not applicable because no C++ function is
created or materially changed: functions considered 0; proposals 0; eligible
0; rejected 0; unsupported 0. Candidate contracts requiring later human
review: none. No `cs: ai` proposal can become accepted intent. This contract
will not change during implementation.

Implementation receipt (branch verification, not completion authority): the
new status tool bootstraps PROGRESS at protected-main Phase 7 and derives all
MERGED commit/tree evidence from git. It atomically updates only the generated
TODO state block, while read-only mode rejects a stale main cursor, a missing
cursor, manual rewrites, non-ancestor history, and TODO mismatches. The five
focused automation tests pass. Direct C++ tests pass 1164/1164 and CTest passes
1165/1165 with `StatusAutomationContract`; the existing end-to-end diff-review
fixture passes. A real strict `3aa85f9`-to-working-tree replay covers all 12
changed C/C++ sources, reaches all fixpoints, and reports
`new_errors=0`, `new_warnings=0`, `fixed=0`, `weakened=0`, `gate=pass`; native
path normalization no longer lists those sources as unanalyzed. The remote
docs gate resolves protected main at `47b03f4`, records only
`phase-progress-automation` as in flight, and passes the capability and
real-world-ledger checks. Product C++ and its quality floors are unchanged.
The maintenance transition remains merge-pending until protected main
contains it; no branch receipt is rendered as MERGED.

## 2026-08-10 — Phase 7 strict-review correction boundary

The corrected Windows base/head semantic diff review passes its blocking and
contract gates, but reports two new experimental assumption findings:
`collectReallocSites` and `collectOwnerRawResultSites` dereference their
internal `FunctionDecl*` parameters without a local null boundary. Quality
policy treats these report-only findings as review work rather than leaving
them behind.

The locked correction is deliberately narrower than the existing Phase 7.5
boundary. A null function returns an empty site map; every non-null path keeps
its current behavior. No allocator-family, alias, owner, cleanup, summary, or
native pointer authority changes. The exact file set is
`src/rules/MemoryLeakRule_Ex.cpp`, `docs/TODO.md`, and this changelog.
Contract-first shadow pre-screen considered the two helpers: proposals 0,
eligible 0, rejected 0, unsupported 2 because native pointer nullability is
outside the current verifier. Candidate contracts requiring human review:
none. No `cs: ai` proposal can become accepted intent. The contract is locked
before implementation and will not change during the correction.

Both helpers now return an empty site map for a null function, with every
non-null path unchanged. The corrected strict base/head semantic review covers
all 12 changed C/C++ translation units and passes with `new_errors=0`,
`new_warnings=0`, `weakened=0`; every analyzed function reaches a fixpoint.
Direct and CTest suites remain 1164/1164. Self-scan is clean and complete at
48/48 TUs, frozen thesis remains `clean_fp=0`, `bug_caught=9/15`, 11 findings,
and corpus remains cJSON 54 (76 enumerated, 35 analyzed, 41 accepted broken
fixtures) and tinyxml2 9 (3/3). Capability output remains schema 2 / rules 14 /
supported 7 / out-of-scope 5, and ActionArgs remains 5/5. The final Windows
product SHA-256 is
`25e0a566990dedabf959a5c770079b362f5d462ae7af177cc81a8b2a9e9c120d`.

The review also exposed two Windows-only harness defects: backslash paths in
compile commands were not remapped to the base worktree, and native relative
paths did not match Git's slash-separated coverage paths. Temporary
referee-only corrections made the receipt trustworthy; the repository fix is
queued in the separately declared documentation/automation maintenance
follow-up rather than widening the completed Phase 7.5 implementation.

## 2026-08-10 — Phase 7.5 conservative exceptional ownership

Phase 7 now has an explicit, measured exceptional-ownership boundary. CFG
cache keys include implicit-destructor and EH-edge options, and the shared
dataflow engine exposes a compile-time analysis opt-in while leaving all
default consumers unchanged. Clang 20 may emit an automatic-owner destructor
block for a throw without connecting that block to the throw-to-handler path.
CodeSkeptic therefore refuses to treat the orphan element as release evidence.

An explicit `throw` degrades only allocations with a live exact standard
smart owner to escape/unknown. This prevents a disconnected cleanup block from
manufacturing a leak, UAF, or double-free. Raw allocations with no owner and
allocations deliberately left live by `release()` remain leak-reportable;
unreachable throws preserve normal destructor evidence. Summary and member
boundaries remain unchanged and are now pinned: compatible cross-TU
`Consumed` summaries can still prove UAF, `Transferred` cannot invent release,
local member storage keeps a real leak visible, and global member storage
escapes. No member, heap, or whole-project pointer identity was invented.

The first compile RED proved that the cache lacked an EH option key. After
plumbing, 7 of 12 semantic fixtures passed and 5 failed. CFG inspection then
showed that the destructor block had no predecessor; the proposed exceptional
release expectation was therefore ineligible under the locked contract. The
conservative throw transition closed all five without granting false
authority. Two precision fixtures pinned unreachable and conditional throws.
The final Phase 7.5 matrix is 16/16, and direct and CTest suites pass 1164/1164.

Interface gates remain schema 2 / rules 14 / supported 7 / out-of-scope 5 and
ActionArgs 5/5. Frozen thesis is `clean_fp=0`, `bug_caught=9/15`, 11 findings;
self-scan is clean and complete at 48/48 TUs. Corpus remains cJSON 54 findings
(76 enumerated, 35 analyzed, 41 accepted broken fixtures) and tinyxml2 9
findings (3/3). The full unchanged 400-file/CWE Juliet replay passes every
floor: CWE476 140/0, CWE401 105/15 (precision 0.875), CWE415 119/0, CWE416
212/0, CWE369 43/0, and CWE190 23/0. The tested Windows product SHA-256 is
`25e0a566990dedabf959a5c770079b362f5d462ae7af177cc81a8b2a9e9c120d`.

Contract-first shadow completion considered `CfgCache::get`, `runDataflow`,
the exceptional-CFG opt-in trait, `classifyStmtEffects`,
`MemLeakAnalysis::transferElement`, `MemLeakAnalysis::onCFGElement`,
`analyzeFunction`, `collectReallocSites`, and `collectOwnerRawResultSites`:
proposals 0, eligible 0, rejected 0, unsupported 9. No proposal was eligible.
Independent RED, CFG inspection, and strict diff review exposed the API gap,
the disconnected-cleanup assumption problem, and two internal null-boundary
assumptions. Candidate contracts requiring later human review: none. No
`cs: ai` proposal became accepted intent, and native memory-verification
parity remains deferred to executable A7 fixtures. The locked eleven-file
boundary was preserved.

## 2026-08-10 — Phase 7.5 exceptional cleanup and transfer boundary

Phase 7.4 is sealed in commit `21277325e73b513d3da4d949fcd093ce23082078`
with tree `b2921225f8a90d8aac2c8898496d6174f23fb9a8`, published in draft
PR #134, and locally gated. The final Phase 7 slice is restricted to explicit
exceptional cleanup for the exact automatic local standard owners already
admitted in Phase 7.4, plus regression pins for the existing summary and
member-transfer boundaries.

The pre-implementation audit found that ownership summaries already separate
`Owned`, `Borrowed`, `Consumed`, and `Transferred`. Memory lifetime consumes
exact `Consumed` releases for compatible legacy allocations, keeps owned
returns caller-owned, preserves borrowed visibility, and conservatively
escapes transfers whose destination lifetime is outside the caller. Direct
member/global stores likewise already separate local non-escape controls from
outliving storage. No new summary schema or native member identity is needed
or justified without executable A7 fixtures.

The remaining executable gap is CFG construction: Phase 7.4 requests implicit
automatic destructors but does not request exception-handling edges. The
locked contract in `docs/TODO.md` admits cleanup only when an opt-in Clang CFG
emits the existing `CFGAutomaticObjDtor` on an exceptional path. Last-owner
release may then support UAF or double-free evidence. Owners outside the
unwound scope, prior `release`, absent destructor evidence, temporary and
constructor-failure cleanup, rethrow/catch ownership, coroutine cleanup, and
interprocedural exception propagation remain non-authoritative.

The exceptional CFG is separately keyed from ordinary and normal-dtor graphs,
and only an explicitly opting-in analysis receives it. The exact file boundary
is `src/engine/CfgCache.h`, `src/engine/CfgCache.cpp`,
`src/engine/DataflowEngine.h`, `src/rules/MemoryLeakRule_Ex.cpp`,
`tests/CfgCacheTest.cpp`, `tests/IntervalAnalysisTest.cpp`,
`tests/MemoryLeakRuleExTest.cpp`, `tests/InterproceduralTest.cpp`,
`docs/usage.md`, `docs/TODO.md`, and this changelog. Summary persistence,
grammar, capabilities, configuration, model authority, profiles, and quality
floors remain unchanged.

Contract-first shadow pre-screen considered `CfgCache::get`, `runDataflow`,
the exceptional-CFG opt-in trait, `classifyStmtEffects`,
`MemLeakAnalysis::transferElement`, `MemLeakAnalysis::onCFGElement`, and
`analyzeFunction`: proposals 0, eligible 0, rejected 0, unsupported 7. The
current verifier cannot prove template dispatch, Clang EH identity, or native
pointer/ownership/heap lifetime. Candidate contracts requiring later human
review: none. No `cs: ai` proposal became accepted intent. Clang-backed RED
fixtures are the implementation referee; native memory-verification parity
remains deferred to executable A7 fixtures, and this record will not change
during Phase 7.5.

## 2026-08-10 — Phase 7.4 exact local standard smart-owner lifetimes

CodeSkeptic now carries exact per-disjunct owner identity for direct automatic
local `std::unique_ptr`, `std::shared_ptr`, and legacy `std::auto_ptr` objects.
Compatible raw adoption, captured `get`/`release` aliases, reset, standard
copy/move construction and assignment, destination replacement, and normal
last-owner destruction update the existing allocation lifetime. This makes
released allocations leak-reportable and supports UAF or double-free evidence
after an exact reset, raw release, or automatic destructor.

The shared CFG cache separately keys ordinary and implicit-destructor graphs.
Only analyses declaring the optional CFG-element hook request the latter;
statement-only consumers retain their original path. Configured project owner
wrappers preserve adoption-only escape behavior. Custom deleters, exact custom
allocator families, aliasing constructors, incompatible pointees, fields,
owner exposure/references/lambdas, unknown methods or calls, conflicts, and
indirect targets remain conservative and cannot manufacture release evidence.
Exceptional cleanup remains Phase 7.5 work.

The compile RED first established the missing option-keyed CFG API. After the
engine hook was added, 10 of 17 initial semantic owner cases stayed RED. The
owner-lifetime implementation closed them. Precision review then found three
false authorities—owner address exposure, writable owner references, and a
shared aliasing constructor—and conservative escape closed all three. A
custom-deleter template with a single constructor argument exposed one final
false authority; admitting only the implicit/default deleter shape closed it.
The lambda-capture control was already conservative. The final Phase 7.4 plus
legacy owner regression matrix passes 41/41, and direct and CTest suites pass
1148/1148.

Interface gates remain schema 2 / rules 14 / supported 7 / out-of-scope 5 and
ActionArgs 5/5. Frozen thesis is `clean_fp=0`, `bug_caught=9/15`, 11 findings;
self-scan is clean and complete at 48/48 TUs. Corpus remains cJSON 54 findings
(76 enumerated, 35 analyzed, 41 accepted broken fixtures) and tinyxml2 9
findings (3/3). The unchanged 400-file/CWE Juliet replay passes every floor:
CWE476 140/0, CWE401 105/15 (precision 0.875), CWE415 119/0, CWE416 212/0,
CWE369 43/0, and CWE190 23/0. The tested Windows product SHA-256 is
`19875c442be7e3f6bed6e50eba1f29374b685bc19275757a2c6370be7b9fd3d6`.

Contract-first shadow completion considered `CfgCache::get`, `runDataflow`,
`standardOwnerKind`, `ownerOperation`, `applyOwnerOperation`,
`MemoryFlow::transferElement`, and `MemoryFlow::onCFGElement`: proposals 0,
eligible 0, rejected 0, unsupported 7. Current verifier semantics cannot prove
the template/CFG dispatch, Clang identity, native alias, ownership, or heap
lifetime authority involved, so no proposal was eligible. Independent RED and
precision fixtures exposed and closed the implementation/assumption problems.
Candidate contracts requiring later human review: none. No `cs: ai` proposal
became accepted intent, and native owned-memory parity remains deferred to
executable A7 fixtures. The locked ten-file boundary was preserved.

## 2026-08-10 — Phase 7.4 RAII lifetime boundary and contract record

Phase 7.3 is sealed in commit `3aeb20e6926544056e3382f77e761c7a3f203479`
and published in draft PR #134. The next independently measurable slice is
restricted to exact local standard smart-owner lifetimes; allocator-family
semantics and the prior raw alias/realloc slices are not reopened.

The pre-implementation audit confirmed that the existing smart-pointer helper
only converts a tracked raw allocation to `Escaped` at construction. It
suppresses known adoption false positives but carries no owner identity and
cannot model `release`, `reset`, copy/move, last-owner destruction, UAF, or
double-free. The shared dataflow engine also deliberately visits only
`CFGStmt`, so Clang automatic-object destructor elements are currently absent
from every analysis transition.

The locked contract is recorded separately in `docs/TODO.md`. Direct automatic
local `std::unique_ptr`, `std::shared_ptr`, and `std::auto_ptr` objects may hold
an exact per-disjunct raw allocation relation. Compatible direct construction,
`reset`, `release`, `get`, standard copy/move, replacement, normal scope exit,
and return cleanup update that relation. Exclusive owners transfer; shared
copies retain a set; only the last exact reset/destructor proves release.
Captured release/get results may form exact local raw aliases. Proven release
may support later UAF/double-free, while a released live allocation remains
leak-reportable.

Custom allocator families never inherit an implicit deleter match. Custom
deleters, conversions, aliasing constructors, fields/heap owners, exposure,
references, lambdas, indirect/ambiguous targets, lookalikes, unsupported
methods, and conflicts remain non-authoritative. Configured project wrappers
retain their existing conservative adoption escape and must still be named by
`--owning-pointers`; unconfigured wrappers and non-owning views do not suppress
raw leaks. Exceptional cleanup remains Phase 7.5 work.

Only an analysis exposing the optional CFG-element hook requests a separately
cached implicit-destructor CFG; statement-only consumers retain the existing
cache key and path. The exact file boundary is `src/engine/CfgCache.h`,
`src/engine/CfgCache.cpp`, `src/engine/DataflowEngine.h`,
`src/rules/MemoryLeakRule_Ex.cpp`, `tests/CfgCacheTest.cpp`,
`tests/IntervalAnalysisTest.cpp`, `tests/MemoryLeakRuleExTest.cpp`,
`docs/usage.md`, `docs/TODO.md`, and this changelog. Configuration,
allocator-pair syntax, contract grammar, capabilities, accepted model
channels, summary schema, profiles, and quality floors remain unchanged.

Contract-first shadow pre-screen considered `CfgCache::get`, `runDataflow`,
`standardOwnerKind`, `ownerOperation`, `applyOwnerOperation`,
`MemoryFlow::transferElement`, and `MemoryFlow::onCFGElement`. Current verifier
semantics cannot prove template/CFG event dispatch, Clang declaration
identity, native pointer aliasing, smart ownership, or heap lifetime, so
dogfood is not applicable: proposals 0, eligible 0, rejected 0, unsupported 7.
Candidate contracts requiring later human review: none. No proof-bearing
contract was invented and no `cs: ai` proposal became accepted intent.
Executable A7 RED fixtures and ordinary tests are the referee; this contract
record will not change during Phase 7.4.

## 2026-08-09 — Phase 7.3 exact custom allocator families

CodeSkeptic now accepts atomic, fail-closed custom allocation families through
CLI `--allocator-pairs`, project `allocator_pairs`, and MCP
`allocator_pairs`. Direct non-instance paired allocators carry an exact family
per guarded disjunct. Only an admitted argument-zero deallocator closes that
family and enables UAF or double-free evidence. Qualified configuration matches
the exact qualified declaration; unqualified configuration retains identifier
compatibility. Duplicate pairs are idempotent, an allocator may admit multiple
deallocators, and each analyzer/MCP call clears the pair registry afterward.

Mismatched paired or legacy frees, `delete`, and built-in `realloc` do not
close an exact custom family, so a live allocation remains leak-reportable.
Conflicting paths and summary-only, indirect, ambiguous, method-receiver, or
otherwise non-exact release evidence cannot manufacture family authority;
release-shaped uncertainty escapes conservatively. Explicitly paired wrapper
names are the only wrapper authority. Legacy independent allocation/free lists
remain family-agnostic, and summary schema, grammar, capabilities, profiles,
and all quality floors are unchanged.

The initial compile RED established the absent configuration API. After
configuration, registry, and MCP plumbing, 8 of 14 focused cases passed and 6
semantic cases remained RED: mismatched-family leak retention, no fabricated
UAF/double-free after mismatch, qualified matching, built-in free/delete
mismatch, conflicting families, and MCP behavior. The first semantic
implementation closed all 14. Precision review added six cases and exposed a
second RED: a paired source passed to built-in `realloc` produced two leaks
instead of the required single old-allocation leak. Preserving the direct
source owner before binding invalidation closed it. The final allocator-family
matrix is 20/20; direct and CTest suites pass 1117/1117.

Interface and documentation gates pass: `CapabilitiesCliTest.py` reports
schema 2, rules 14, supported 7, and out-of-scope 5; `ActionArgsTest.py` is
5/5; docs sync, 8/8 profiles, README 315/315, and capability sync are green.
Frozen thesis remains `clean_fp=0`, `bug_caught=9/15`, 11 findings, and the
self-scan is clean and complete at 48/48 translation units. Corpus results are
cJSON 54 findings (76 enumerated, 35 analyzed, 41 explicitly accepted broken
fixtures) and tinyxml2 9 findings (3/3 analyzed).

The full unchanged 400-file/CWE Juliet replay passes every floor. Rule-matched
results are CWE476 140/0 (precision 1.000, hit rate 0.347), CWE401 105/15
(precision 0.875, hit rate 0.253), CWE415 119/0 (precision 1.000, hit rate
0.297), CWE416 212/0 (precision 1.000, hit rate 0.531), CWE369 43/0 (precision
1.000, hit rate 0.108), and CWE190 23/0 (precision 1.000, hit rate 0.057). The
tested Windows product SHA-256 is
`db1f7ba8eea153edaec1b9e4e77df191d77eb1f56a12e199b2494cd8de13fc68`.

Contract-first shadow completion considered `Config::addAllocatorPairs`,
`setAllocatorPairs`, `pairedAllocatorFamily`, `isPairedDeallocatorCall`,
`matchesAllocatorFamily`, `allocationFamilyOf`, and `releaseAuthority`:
proposals 0, eligible 0, rejected 0, unsupported 7. Their semantics depend on
string/container parsing, Clang declaration identity, and native pointer/heap
lifetime outside the current verifier. No proposal exposed a problem because
none was eligible; independent RED and precision-review tests exposed and
closed the implementation and assumption problems above. Candidate contracts
requiring later human review: none. No `cs: ai` proposal became accepted
intent, and native owned-memory parity remains deferred to executable A7
fixtures. The exact locked file set was preserved.

## 2026-08-09 — Phase 7.3 allocator-family boundary and contract record

Phase 7.2 is sealed in commit `a242b3c` and published in draft PR #134. The
next independently measurable slice is restricted to opt-in exact custom
allocator/deallocator families; the prior alias and realloc slices are not
reopened.

The locked pre-implementation contract is recorded separately in
`docs/TODO.md`. New CLI, config, and MCP input uses comma-separated
`allocator=deallocator` entries. Parsing is atomic and fail-closed; duplicate
pairs are idempotent and one allocator may admit multiple exact deallocators.
Qualified spellings match qualified direct non-instance callees, while
unqualified spellings preserve the existing identifier convention. Paired
names automatically join allocation and release recognition.

Each direct paired allocation carries its exact family per disjunct. Only an
admitted direct argument-zero deallocator proves release and enables later UAF
or double-free evidence. A mismatched paired/legacy deallocator, `delete`, or
built-in `realloc` cannot close that allocation, so a live allocation remains a
leak. Conflicting family paths degrade to unknown. Summary-only ownership,
summary-only consumption, unresolved or ambiguous indirect calls, instance
methods, non-variable arguments, and unknown targets cannot create exact
family authority; release-shaped uncertainty escapes instead of fabricating a
release or leak. A wrapper receives authority only by explicit pairing. Legacy
independent allocator/free lists retain their family-agnostic behavior, and
all pair state is cleared between analyzer/MCP calls.

The exact file boundary is `src/config/Config.h`, `src/config/Config.cpp`,
`src/engine/AllocFunctions.h`, `src/engine/AllocFunctions.cpp`,
`src/analyzer/StaticAnalyzer.cpp`, `src/server/McpServer.cpp`,
`src/rules/MemoryLeakRule_Ex.cpp`, `tests/ConfigTest.cpp`,
`tests/McpServerTest.cpp`, `tests/MemoryLeakRuleExTest.cpp`, `docs/usage.md`,
`docs/integrations.md`, `docs/TODO.md`, and this changelog. Contract grammar,
capability tiers, accepted model channels, summary schema, profiles, and
quality floors remain unchanged.

Contract-first shadow pre-screen considered `Config::addAllocatorPairs`,
`setAllocatorPairs`, `pairedAllocatorFamily`, `isPairedDeallocatorCall`,
`matchesAllocatorFamily`, `allocationFamilyOf`, and `releaseAuthority`.
String/container parsing, Clang declaration identity, and native pointer/heap
lifetime are unsupported by the current verifier, so dogfood is not
applicable: proposals 0, eligible 0, rejected 0, unsupported 7. Candidate
contracts requiring later human review: none. No proof-bearing contract was
invented and no `cs: ai` proposal became accepted intent. Executable A7 RED
fixtures and ordinary tests are the referee; this contract record will not
change during Phase 7.3.

## 2026-08-09 — Phase 7.2 realloc outcome lifetimes

The memory-lifetime analysis now records an exact pending source/result
relation for direct global-C or `std` `realloc`/`reallocarray` calls with local,
same-pointer-type identities and proven nonzero requests. A proven null result
preserves the original allocation; a proven non-null result transfers the
lifetime to the result and invalidates the old owner. Proven-nonzero direct
overwrite reports the possible failure-path leak, null input remains ordinary
allocation, and `reallocarray` requires both multiplicands to be nonzero.

Zero or unknown sizes, indirect and custom calls, methods and other namespaces,
type-changing results, address exposure, and conflicting relations remain
non-authoritative. They cannot manufacture release, transfer, UAF,
double-free, or overwrite-leak evidence. Reassignment and exposure invalidate
only the pending relation, while unresolved result/source alternatives are
deduplicated at exit.

Initial RED recorded four implementation gaps after one other-namespace test
was corrected because its original leak expectation contradicted the existing
generic escape semantics. The first full suite then exposed a Systemd
copy-before-null regression: realloc invalidation had accidentally erased a
normal pointer-value copy binding. Preserving that binding closed the
regression. Precision review added an exact-result-alias guard RED; resolving
the guard to its binding owner closed it. The final Phase 7.2 matrix has 20
cases, the focused realloc/alias/Systemd replay is 24/24, and both the direct
and CTest suites pass 1097/1097.

The final 400-file/CWE Juliet replay passes every unchanged floor. Rule-matched
results are CWE476 140/0 (precision 1.000, hit rate 0.347), CWE401 105/15
(precision 0.875, hit rate 0.253), CWE415 119/0 (precision 1.000, hit rate
0.297), CWE416 212/0 (precision 1.000, hit rate 0.531), CWE369 43/0 (precision
1.000, hit rate 0.108), and CWE190 23/0 (precision 1.000, hit rate 0.057).
Compared with the sealed Phase 7.1 baseline, realloc modeling adds 13 CWE401
true positives and two false positives while holding precision above its 0.85
floor; no quality floor changed.

Final local gates are frozen thesis `clean_fp=0`, `bug_caught=9/15`, 11
findings; clean and complete 48/48-TU self-scan; cJSON 54 findings (76
enumerated, 35 analyzed, 41 explicitly accepted broken fixtures); and tinyxml2
9 findings (3/3 analyzed). The tested Windows product SHA-256 is
`4ccb8e52a53e1af0905830c2889bb9ffc1467960c17a44cf4ac8e76c423c656d`. The exact
slice file set remains `src/rules/MemoryLeakRule_Ex.cpp`,
`tests/MemoryLeakRuleExTest.cpp`, `docs/TODO.md`, and this changelog. Shared
dataflow/guard engines, allocator registries, contract grammar, capability
tiers, configuration, summary schemas, accepted model channels, and Juliet
floors are unchanged.

Contract-first shadow completion considered `reallocSite`, `reallocUpdates`,
`collectReallocSites`, `invalidateReallocRelations`, `provesNonZero`,
`provesNonZeroRequest`, and `applyNullCondition`. Their composite authority
depends on native pointer identity and heap lifetime semantics that the current
verifier cannot prove, so dogfood was not applicable: proposals 0, eligible 0,
rejected 0, unsupported 7. No proposal exposed a problem because none was
eligible. Independent RED, full-suite, and precision-review tests exposed the
implementation and assumption problems above; all are closed. Candidate
contracts requiring later human review: none. No `cs: ai` proposal became
accepted intent, and native owned-memory verification parity remains deferred
to executable A7 fixtures.

## 2026-08-09 — Phase 7.2 realloc boundary and contract record

Phase 7.1 is sealed in commit `1475adb8754c75174ef4057d62a1f8b5c543a605`
with tree `5aac1b25da279bed85ab60332152020c7ba74e24`. The next independently
measurable slice is restricted to exact `realloc`/`reallocarray`
success/failure lifetime behavior; the prior slice is not reopened.

The locked pre-implementation contract is recorded separately from production
code in `docs/TODO.md`. Only direct global-C or `std` calls with exact local,
same-pointer-type result/source identities may create a pending realloc
relation. For a proven nonzero request, null preserves the original allocation
and non-null transfers its lifetime to the result. Proven-nonzero direct
overwrite reports the possible failure leak; null input remains ordinary
allocation. `reallocarray` requires both size operands to be proven nonzero
and preserves the source on overflow failure. Zero or unknown sizes, indirect
or custom calls, methods and other namespaces, type changes, exposure, and
conflicts cannot create release, transfer, UAF, double-free, or overwrite-leak
evidence. Alternative unresolved result/source outcomes produce at most one
exit leak unless later evidence separates them.

The exact file boundary is `src/rules/MemoryLeakRule_Ex.cpp`,
`tests/MemoryLeakRuleExTest.cpp`, `docs/TODO.md`, and this changelog. Shared
engines, allocator registries, contract grammar, capability tiers,
configuration, summary schemas, accepted model channels, and quality floors
remain unchanged. Contract-first shadow review considered seven critical
semantic decisions. All depend on native pointer/heap lifetime semantics that
the current verifier does not support, so dogfood is not applicable: proposals
0, eligible 0, rejected 0, unsupported 7. Candidate contracts requiring later
human review: none. No proof-bearing contract was invented and no `cs: ai`
proposal became accepted intent. Executable A7 RED fixtures and ordinary tests
are the referee; this contract record will not change during Phase 7.2.

## 2026-08-09 — Phase 7.1 exact local alias lifetime

The memory-lifetime analysis now carries an exact must-binding beside each
allocation state in every guarded disjunct. A release through an unchanged
local pointer copy updates the allocation owner, so later access or release
through the owner, the alias, or a transitive exact alias reports UAF or
double-free with the original allocation/free trace. Null failure edges refine
the owner, conflicting bindings merge to unknown, and exit leaks no longer use
flow-insensitive group suppression. Reusing an alias for a second allocation
therefore exposes the first allocation leak instead of preserving the old
accepted FN.

Local pointer references and pointer value copies have separate binding
semantics. `T*& ref = owner` stays attached to the pointer variable when
`owner` later receives an allocation; `T* copy = owner` preserves only the
value present at the copy. Direct reassignment and allocation overwrite only
the affected binding. Address exposure, writable-reference calls,
cast-changing copies, conflicting paths, fields, heap aliases, and unknown
relations remain non-authoritative and cannot manufacture UAF/double-free
evidence. A narrow same-source, proven-non-null compatibility bridge preserves
the existing Juliet realloc good shapes; complete realloc success/failure,
zero-size, null-input, and overwrite semantics remain owned by Phase 7.2.

RED was recorded before implementation: six of the initial eight alias cases
failed while both precision controls passed. Null-guard, address-exposure, and
writable-reference controls were independently RED. The first full suite then
found the Systemd copy-before-null escape regression. Precision review added
cast-changing, reference-before-allocation, copy-before-allocation, and
reference-storage-reassignment controls. The final Phase 7.1 matrix is 15/15;
the adjacent local-reference and Systemd controls make the focused replay
17/17.

The first 400-file/CWE Juliet replay was deliberately kept red: CWE401 reached
92 TP / 17 FP, precision 0.844, below the unchanged 0.85 floor. All four added
FPs were variant-33 good sinks where a local `T*&` was incorrectly invalidated
when its bound pointer variable received the allocation. Distinguishing
reference-to-variable bindings from pointer-value copies removed exactly those
four FPs without losing a TP. Final rule-matched results are CWE401 92/13
(precision 0.876, hit rate 0.223), CWE415 119/0 (precision 1.000, hit rate
0.297), and CWE416 212/0 (precision 1.000, hit rate 0.531). The unaffected
rule-matched receipts are CWE476 140/0 (hit rate 0.347), CWE369 43/0 (0.108),
and CWE190 23/0 (0.057). Every existing floor passes and no floor changed.

Final local gates are direct suite 1077/1077, CTest 1077/1077, frozen thesis
`clean_fp=0` and `bug_caught=9/15` with 11 findings, clean and complete 48/48-TU
self-scan, cJSON 54 findings (76 enumerated, 35 analyzed, 41 explicitly
accepted broken fixtures), and tinyxml2 9 findings (3/3 analyzed). The tested
Windows product SHA-256 is
`2a0a43114832761ea60617bc553393f4b6b7b15fd64cd5bcbdc0e0659f9ad197`. The exact
slice file set remains `src/rules/MemoryLeakRule_Ex.cpp`,
`tests/MemoryLeakRuleExTest.cpp`, `docs/TODO.md`, and this changelog. Shared
dataflow/guard engines, contract grammar, capability tiers, configuration,
summary schemas, accepted model channels, and Juliet floors are unchanged.

Contract-first shadow completion considered the six critical binding, merge,
root-resolution, release, dereference, and exit semantic units. Native pointer
identity, reference storage, alias, and heap lifetime remain unsupported by the
current verifier, so dogfood was not applicable: proposals 0, eligible 0,
rejected 0, unsupported 6. No proposal exposed a problem because none was
eligible. Independent RED tests, the Systemd full-suite regression, and the
Juliet floor exposed the implementation and assumption problems above; all are
closed. Candidate contracts requiring later human review: none. No `cs: ai`
proposal became accepted intent, and native owned-memory verification parity
remains deferred to executable A7 fixtures.

## 2026-08-09 — Phase 7.1 exact-alias boundary and contract record

Phase 6 merged through fully green PR #133 as squash commit
`3aa85f9ed773c2473683e5a41593208e8945a0d9`; its tree
`12f62243ba39b3b7b49369f843f33af640619efb` exactly matches the gated branch
head. Both feature-branch refs were removed after that equality check.

The pre-implementation lifetime audit passed the existing 68-test focused
memory/alias/path/custom-owner matrix and identified the first Phase 7 gap:
local pointer copies are collected into whole-function alias components.
Those components can suppress an exit leak through any member's free, but
they deliberately cannot carry a free into UAF or double-free reporting and
cannot invalidate a reused alias. The accepted
`AliasReuse_FirstAllocationFN_Documented` fixture pins the resulting missed
leak.

The locked slice contract is recorded separately from production code in
`docs/TODO.md`: only unchanged, exact, local pointer bindings within one
guarded disjunct may transfer lifetime evidence; reassignment invalidates the
overwritten binding, and conflicting/non-local/address-exposed/field/heap or
unknown aliases cannot create a finding. The exact file boundary is
`src/rules/MemoryLeakRule_Ex.cpp`, `tests/MemoryLeakRuleExTest.cpp`,
`docs/TODO.md`, and this changelog. Shared engines, contract grammar,
capability tiers, configuration, summary schemas, and accepted model channels
remain outside the slice.

Contract-first shadow review considered the six critical binding,
root-resolution, merge, release, dereference, and exit decisions. All depend
on native pointer identity, alias, and heap-lifetime semantics unsupported by
the current verifier, so dogfood is not applicable: proposals 0, eligible 0,
rejected 0, unsupported 6. No proof-bearing contract was invented and no
`cs: ai` proposal became accepted intent. Executable A7 fixtures are the
referee; this pre-implementation contract record will not change during the
slice.

## 2026-08-09 — Phase 6.3 interprocedural allocator sinks and access evidence

Function summaries now carry a versioned, exact integer-parameter-to-allocator-
size relation. Only unchanged visible parameters that reach a direct or proven
summary sink become authoritative; SCC chains, controlled indirect target sets,
cross-TU harvest/reload, strict persistence, and conservative conflict merges
all use the same relation. Summary schema v11 encodes `Unknown`, `None`, and
`Sink` as `?`, `O`, and `S`; v10 and older inputs upgrade to non-authoritative
`Unknown`. Losing a proven sink is a weakening in summary diff, while gaining
one is strengthening. Bodyless, transformed, conflicting, incomplete indirect,
legacy-unknown, and uninvoked-lambda flows remain silent.

The allocation rule consumes only a stable proven `Sink`. An optional trace note
is attached after the existing finite wrap proof only when the allocation call
has an exact local pointer binding, that binding remains unchanged and does not
escape by address before the access, and an exact array index or supported
`memcpy`/`memmove`/`memset` length shares the same declared-untrusted origin.
Absence of this evidence never suppresses or creates the allocation finding.
Precision review found and closed two additional RED cases: a pointer reassigned
before access incorrectly received a note, and an uninvoked lambda body leaked
sink authority into its enclosing function.

The real-repository replay pins LVGL v9.2.2 tag object
`c98ab243621a2a948674da5339c15da88832f928`, peeled commit
`7f07a129e8d77f4984fff8e623fd5be18ff42e74`. Using LVGL's generated
`compile_commands.json`, `lv_fs_read` as the declared untrusted source, and
`lv_malloc` as the configured allocator, the exact
`src/font/lv_binfont_loader.c` scan reports one experimental finding at
line 511, column 72. It intentionally carries no access note: the real direct
index is `glyph_offset[i]`, not the same `loca_count` expression, and
`lv_fs_read` is outside the admitted bounded-memory primitive set. A separate
controlled `memset` fixture proves the supported same-origin trace path.

RED was recorded before production implementation: 8 of the initial 11 focused
cases failed exactly for the new positive summary/persistence/diff paths; three
precision controls passed. The two review cases above were then independently
RED before correction. The final focused matrix is 51/51. Exact product CLI
receipts are one report for the unsafe visible wrapper, zero for its dominating-
division-guard twin, and one report plus one access note for the controlled
bounded-memory fixture. `tests/CapabilitiesCliTest.py` now explicitly locks
`alloc-size-overflow` as default-enabled, experimental, not quality-gated, and
non-blocking; schema 2 still publishes 14 rules with seven supported. The tested
binary SHA-256 is
`c5c73f49750d12ae1a24cbe96c8120425fbcd79a35505063b6a3a721f9c6d8dc`.

Final local gates are direct suite 1063/1063, CTest 1063/1063, frozen thesis
`clean_fp=0` and `bug_caught=9/15` with 11 total findings, clean and complete
48/48-TU self-scan with zero findings/broken/incomplete units, cJSON 54 findings
(76 enumerated, 35 analyzed, 41 explicitly accepted broken fixtures), and
tinyxml2 9 findings (3/3 analyzed). The exact slice file set is
`src/engine/FunctionSummary.{h,cpp}`, `src/engine/SummaryDiff.cpp`,
`src/rules/AllocSizeOverflowRule.{h,cpp}`,
`tests/AllocSizeOverflowRuleTest.cpp`, `tests/InterproceduralTest.cpp`,
`tests/SummaryDiffTest.cpp`, `tests/CapabilitiesCliTest.py`, `docs/TODO.md`, and
this changelog. `PLAN.md`, the shared interval engine, contract grammar,
capability registry/tier, configuration, and accepted model channels are
unchanged.

Contract-first shadow audit considered 42 new or materially changed production
functions: the allocator-size summary accessor, exact-param extraction,
collection visitor and integration, equality/merge/persistence/parser paths;
summary-diff naming/classification; allocator argument and inventory visitors;
exact allocation-binding, origin, stability, and access-evidence visitors; and
`analyzeFunction`. Two minimal proposals were produced:
`allocatorSizeToChar: ensures return != 0` and
`computeParamAllocatorSizes::Visitor::TraverseLambdaExpr: ensures return != 0`.
The Windows pre-screen reported the modified file clean, but both independent
Linux CI self-scans classified the proposals as `contract-unsupported`. Under
the shadow eligibility rule, unsupported evidence is not eligible: both marker
lines were removed. Final counts are eligible 0, rejected 2, unsupported 40;
no candidate remains for human review. The proposals exposed a cross-platform
verifier eligibility gap, not an implementation or assumption problem.
Independent RED tests and pinned-source review exposed the binding-
reassignment, lambda-isolation, and LVGL access-evidence premise issues above;
all are closed. No `cs:ai` proposal became marker-free accepted intent. No
native pointer, heap, alias, ownership, or lifetime contract semantics were
added; owned-memory verification remains deferred to executable A7 fixtures.

## 2026-08-09 — Phase 6.2 checked allocation arithmetic

The allocation-size rule now preserves an exact reachable upper corner
through stable local signed-to-unsigned cast and alias chains, including
narrowing conversions. It also recognizes the Clang/GCC
`__builtin_*mul*_overflow` family when the direct output variable reaches an
allocator. A proven no-overflow edge is silent; an ignored result or proven
overflow edge reports only when the same finite-corner proof establishes
wrap. Reassignment, address escape, writable-reference escape, unknown
factors, non-allocator use, and unproven relations remain silent.

RED was recorded before implementation: 5 of 25 focused cases failed exactly
for the signed direct and alias paths and the ignored and overflow-edge
builtin paths. Review corrected one fixture premise: an unguarded signed
32-bit value can be negative and therefore can convert to `UINT64_MAX`; the
safe fixture now proves non-negativity. The Clang AST also exposed an outer
`NoOp` cast around the integral cast, which required a local, path-sensitive
normalization rather than a shared interval-engine change. Writable-reference
escape coverage closed the final stale-relation risk. The focused precision
matrix is 32/32.

The exact CLI smoke emits one experimental/report-only
`alloc-size-overflow` diagnostic for each unsafe signed-cast and checked-
builtin fixture and zero for each guarded twin; all exit 0. The tested binary
SHA-256 is
`7638041d48e2a8aff2dc00569b614ae2e5cc99a7b33b8e612751ba229fa81ec7`.
Final local gates are direct suite 1044/1044, CTest 1044/1044, frozen thesis
`clean_fp=0` and `bug_caught=9/15` with 11 total findings, clean 48/48-TU
self-scan, cJSON 54 findings (76 enumerated, 35 analyzed, 41 explicitly
accepted broken fixtures), and tinyxml2 9 findings (3/3 analyzed). The exact
slice file set is `src/rules/AllocSizeOverflowRule.{h,cpp}`,
`tests/AllocSizeOverflowRuleTest.cpp`, `docs/TODO.md`, and this changelog.
The shared interval engine, `SignConversionRule`, contract grammar,
capability registry/tier, configuration, and accepted models are unchanged.

Contract-first shadow audit considered 50 new or materially changed
production functions. The groups were direct/addressed-variable and builtin
recognizers; `DefinitionIndex` construction, visitor callbacks, and signed-
origin/range/corner proofs; size inventory collection; the rule-local
`AllocIntervalAnalysis` adapter; `CheckedMulAnalysis` state, transfer, edge,
widening, and observation methods; and `analyzeFunction`. Dogfood was not
applicable because every candidate depends on Clang AST/type/CFG identity,
APInt/APSInt or interval/container lattice state, or analyzer class context
beyond the current deterministic contract referee. Counts: proposals 0,
eligible 0, rejected 0, unsupported 50. No proposal exposed an implementation
or assumption problem. Independent tests and AST review exposed the signed-
32-bit fixture premise, cast normalization, and writable-reference
invalidation issues above; all are closed. Candidate contracts requiring
later human review: none. No `cs: ai` proposal became accepted intent. No
native pointer, heap, alias, ownership, or lifetime verification semantics
were added; those claims remain deferred to executable A7 fixtures.

## 2026-08-09 — Phase 6.1 exact 64-bit allocation-size corner proof

The allocation-size rule now proves 64-bit unsigned multiplication wraps
without widening the shared int64 interval domain. At an allocator size sink,
one operand must carry declared untrusted unsigned provenance and the other
must be an exactly evaluated constant greater than one. The untrusted upper
corner and factor are widened to 128 bits before comparison with `UINT64_MAX`.
A dominating `SIZE_MAX / factor` guard narrows the existing path state and
silences the report. Runtime factors, ordinary inputs, signed provenance,
value-preserving 32-to-64-bit promotions, and identity multiplication remain
silent unless their own finite evidence proves a wrap.

RED was recorded before implementation: 2 of 12 focused cases failed exactly
for the unguarded 64-bit product and an insufficient division guard, while the
canonical safe guard, unknown-factor control, and existing seven cases held.
Precision review then caught a promoted `uint32_t` false positive at 11/12 and
a signed-source scope leak at 12/13; recovering value-preserving source width
and requiring unsigned origin leaves closed both. Six pre-existing fixtures
also used a target-dependent `unsigned long` size type; replacing it with
Clang's `__SIZE_TYPE__` made the tests express the host target truth instead of
passing alongside parse diagnostics. The final focused matrix is 14/14.

The exact CLI smoke emits one experimental/report-only
`alloc-size-overflow` diagnostic for `sizeof(int) * read_size()` and zero for
its dominating division-guard twin; both exit 0. Final local gates are direct
suite 1026/1026, CTest 1026/1026, frozen thesis `clean_fp=0` and
`bug_caught=9/15` with 11 total findings, clean 48/48-TU self-scan, cJSON 54
findings (76 enumerated, 35 analyzed, 41 explicitly accepted broken fixtures),
tinyxml2 9 findings (3/3 analyzed), and docs-sync clean. The exact slice file
set is `src/rules/AllocSizeOverflowRule.{h,cpp}`,
`tests/AllocSizeOverflowRuleTest.cpp`, `docs/TODO.md`, and this changelog.
`PLAN.md`, the interval engine, contract grammar, capability tier,
configuration, and accepted models are unchanged.

Contract-first shadow audit considered six new or materially changed
production functions: `constantUnsigned`, `unsignedUpperCorner`,
`hasOnlyUnsignedUntrustedOrigins`, `wrapsUnsigned64Multiply`,
`collectSizeSites::V::VisitBinaryOperator`, and `analyzeFunction`. Dogfood was
not applicable because every candidate depends on Clang AST/type identity,
APInt/APSInt, interval/container state, or allocator-sink analyzer context
beyond the current deterministic contract referee. Counts: proposals 0,
eligible 0, rejected 0, unsupported 6. No proposal exposed an implementation
or assumption problem; the independent RED and precision tests exposed the
two false-positive assumptions and the stale fixture type above, all closed.
Candidate contracts requiring later human review: none. No `cs: ai` proposal
became accepted intent. No pointer, heap, alias, ownership, or lifetime
verification semantics were added; native memory claims remain deferred to
executable A7 fixtures.

## 2026-08-09 — Phase 5.3 capability CLI contract sync

The full GitHub Actions run correctly rejected the promoted capability because
the end-to-end CLI fixture still pinned six supported rules. The Phase 5.3 file
boundary was explicitly expanded to include `tests/CapabilitiesCliTest.py`;
its exact supported set and receipt now cover all seven supported rules. This
fixture-only correction changes no production code or accepted specification.

## 2026-08-08 — Phase 5.3 pinned libarchive validation and promotion

Phase 5 closed against the pinned libarchive v3.8.9 tag object
`f1f785cc218bb05876c54680f10d3d4e54575ea2`, peeled commit
`27cbc7827172698143e440801fc0ba39ccb4f1f5`. The exact library surface is
132 C files: 123 have compile-database entries and nine platform files use
the controlled fallback, producing 255 analysis executions in whole-program
mode. Both the clean and mutation runs are complete with zero broken
translation units and zero incomplete functions.

The first clean scan produced 47 findings: 17 `memory-leak`, 18
`null-deref`, and 12 `resource-leak`. Every descriptor finding was manually
triaged against the source and was false: one caller-owned negative-input
replacement, two output stores, four struct/member ownership stores, one
streaming parser state store, one saved-directory transfer, two writer-state
stores, and one registered-close-callback store. This exposed two concrete
analysis assumptions: non-local stores were not treated as responsibility
transfer, and the path-correlated relation between an incoming negative
descriptor snapshot and its successful replacement was not retained.

RED was recorded before implementation: exactly three of 39 focused tests
failed for member transfer, output-parameter transfer, and the negative
snapshot cleanup. The dataflow now marks direct and wrapped non-local
acquisition stores as escaped responsibility, tracks reassigned integer
parameters without claiming ownership of the incoming value, and preserves
only path-common negative witnesses. Reassignment invalidates stale copies
and witnesses; conditional or equality cleanup without proof still reports.
The final focused matrix is 42/42, including wrapper/member transfer and a
reassigned-snapshot precision control.

The final clean scan with binary SHA-256
`5f59aa44c94b68e3d6b8d96f3974baac48b87b907a49bb4c2b6affced2c37aaa`
contains 35 findings: the unchanged 17 `memory-leak` and 18 `null-deref`
findings, with zero `resource-leak`. It completed in 36.39 seconds at
102292 KiB peak RSS. The clean checkout has no tracked source changes.

A separate worktree at the same peeled commit contains exactly three
load-bearing close mutations: the replacement descriptor cleanup in
`archive_read_disk_entry_from_file`, the write-disk fixup-loop cleanup, and
the internal descriptor cleanup in `set_fflags_platform`. The scan contains
38 findings: the same 17 memory and 18 null findings plus exactly three
blocking `resource-leak` findings at the seeded sites, with no extra
descriptor report. It completed in 32.66 seconds at 103404 KiB peak RSS.
Measured descriptor precision is 3 / (3 + 0) = 1.000 and mutation recall is
3/3, above the Phase 5 precision gate of 0.90.

`resource-leak` is therefore promoted to supported, quality-gated, and
blocking in the central registry. README and the capability contract now
cover both `FILE*`/`DIR*` and POSIX `open`/`openat`/`socket`/`dup`/`mkstemp`
descriptors, including visible wrappers and reviewed v10 models. The
capability JSON publishes the promoted tier. CLI smoke reports one blocking
descriptor finding with exit 1 for the leaking fixture and stays clean with
exit 0 for its closed twin.

Final local gates are focused capability/descriptor 45/45, direct suite
1019/1019, CTest 1019/1019, frozen thesis `clean_fp=0` and
`bug_caught=9/15` with 11 total findings, clean 48/48-TU self-scan, cJSON 54
findings (76 attempted, 35 analyzed, 41 explicitly accepted broken
fixtures), and tinyxml2 9 findings (3/3 analyzed). The exact Phase 5.3 file
set is `src/rules/FdResourceRule.cpp`, `tests/FdResourceRuleTest.cpp`,
`src/core/RuleCapabilities.def`, `tests/CapabilitiesTest.cpp`,
`tests/MemoryLeakRuleExTest.cpp`, `README.md`, `docs/capabilities.md`,
`tests/CapabilitiesCliTest.py`, `docs/TODO.md`, and this changelog; `PLAN.md`
remains unchanged.

Contract-first shadow audit considered 15 new or materially changed
production functions: `State::operator==`, `mergeStates`,
`isTrackableLocal`, `forgetValue`, `rememberValueCopy`,
`markNegativeEquivalents`, `rememberNegativeWitnesses`, `equalityEdge`,
`discardImpossibleEquality`, `ResourceInventory::VisitVarDecl`, the
`FdAnalysis` constructor, `FdAnalysis::latticeHeight`,
`FdAnalysis::transfer`, `FdAnalysis::refineOnEdge`, and `analyzeFunction`.
Dogfood was not applicable because every candidate depends on Clang AST/CFG
identity, container/lattice state, class members, or resource-ownership
lifetime beyond the current deterministic contract referee. Counts:
proposals 0, eligible 0, rejected 0, unsupported 15. No proposal exposed an
implementation or assumption problem; the independent libarchive scan
exposed the two problems above and both are closed. Candidate contracts
requiring later human review: none. No `cs: ai` proposal became accepted
intent. No native pointer, heap, alias, ownership, or lifetime verification
semantics were added; those claims remain deferred to executable A7 fixtures.

## 2026-08-08 — Phase 5.2 descriptor wrappers and explicit models

Phase 5 now propagates POSIX descriptor ownership through visible wrappers
and the existing strict v10 model channel. The shared SCC summary solver
infers `Owned` for non-boolean integer returns only when every non-`-1`
return path originates at global `open`, `openat`, `socket`, `dup`, or
`mkstemp`, or at a wrapper with the same proven relation. It infers
`Consumed` or `Transferred` for integer parameters only when every normal
exit agrees that the descriptor reaches `close` or non-local storage.
Conditional, conflicting, opaque, and ambiguous flows remain `Unknown`;
ordinary integer returns do not acquire a borrowed-resource claim.

`FdResourceRule` consumes those same relations for local, cross-TU, and
controlled summary calls. `Owned` results become acquisition origins;
`Consumed` closes an exact origin and `Transferred` escapes it. `Borrowed`
and `Unknown` never suppress a leak. Exact global POSIX primitives retain
their built-in meaning, so `shutdown` still borrows and same-named namespace
functions or methods gain no implicit authority. Bodyless vendor APIs can
opt in through reviewed v10 `--model-file` rows for acquire, consume, or
transfer. Duplicate model/harvest rows use the existing conservative join;
a disagreement falls to `Unknown` instead of allowing the last file to win.
No header/API, configuration, grammar, ContractRule, default model, or native
pointer/heap/alias/lifetime claim was added.

RED was recorded before implementation: 5 of 29 focused cases failed exactly
on acquisition chains, `-1`-neutral acquisition wrappers, consuming wrappers,
transfer wrappers, and explicit model acquire/consume. GREEN plus precision
review expanded the matrix to 33/33 with consumer chains, conditional
consume/transfer negatives, cross-TU acquire/consume, explicit model transfer,
Borrowed/Unknown non-suppression, and conflicting-model degradation. The
summary/model/contract regression selection passed 129/129. The exact Windows
binary and CTest both passed 1010/1010.

The production CLI smoke emitted exactly two experimental/report-only
`resource-leak` diagnostics for the deliberately leaking visible and modeled
wrappers, while wrapper/model close and transfer twins stayed clean; exit was
0. The frozen thesis receipt remains `clean_fp=0`, `bug_caught=9/15`, and
`total_findings=11`. Self-scan is clean and complete across 48/48 translation
units with zero broken TUs and zero incomplete functions. Corpus pins remain
cJSON 54 findings (76 enumerated, 41 explicitly accepted broken, 35 analyzed)
and tinyxml2 9 findings (3/3 analyzed).

Contract-first shadow audit considered 46 new or materially changed C++
functions: 35 summary-domain functions/methods including `summarizeFunction`,
eight FD-rule functions/methods, and three explicit test helpers. Dogfood was
not applicable because every candidate depends on Clang `QualType`/AST/CFG
identity, enum lattice relations, containers, call-summary registry state,
filesystem streams, or analyzer lifetime beyond the current deterministic
contract referee. Counts: proposals 0, eligible 0, rejected 0, unsupported
46. No proposal exposed an implementation or assumption problem; the
independent RED suite exposed the planned feature gap, and precision review
removed a potential ordinary-integer Borrowed overclaim. Candidate contracts
requiring later human review: none. No `cs: ai` proposal became accepted
intent.

## 2026-08-08 — Phase 5.1 direct POSIX descriptor lifecycle

CWE-775 now has a separate integer-resource dataflow rule instead of being
forced through the pointer-oriented MemoryLeak lattice. The rule recognizes
only global POSIX `open`, `openat`, `socket`, `dup`, and `mkstemp` calls as
owned acquisitions and `close` as release. A global namespace check prevents
same-named C++ namespace functions and methods from acquiring or releasing a
descriptor accidentally. `shutdown` deliberately does not release ownership:
POSIX still requires `close` to dispose of the descriptor.

Each acquisition site carries an independent lifecycle and local integer
bindings carry its origin. Exact local copies can release or transfer the
same origin; return and global/reachable stores transfer responsibility.
Ambiguous integer bindings degrade toward escape rather than manufacturing a
leak. The `-1` failure sentinel is refined for `==`, `!=`, `< 0`, `>= 0`,
`<= -1`, `> -1`, reversed comparisons, and logical negation. Branches, early
returns, conditional cleanup, and cleanup labels therefore preserve a leak
whenever any success path remains open while dropping the failed-acquisition
path. Discarded acquisitions report at the call site. Wrapper propagation and
custom resource models remain explicitly outside this first slice.

The initial RED receipt was 6/16 failing test cases; the combined direct-
acquirer case contained five independently checked opener failures. After the
first GREEN pass, a precision review added three more RED cases showing that
`vendor::open`, `vendor::close`, and `Sink::close` were incorrectly classified
by unqualified name. The global-function constraint closed all three. The
focused matrix is now 21/21 and pins direct acquisition/release, shutdown,
sentinel branches, early returns, conditional and label cleanup, return/global
transfer, local aliases, discarded results, namespace/method collisions, and
an unrecognized integer factory.

The exact Windows binary passed 998/998 tests both in the direct single-process
run and through CTest. End-to-end CLI smoke produced exactly one experimental,
report-only `resource-leak` with exit 0 for an unclosed `open`, and a clean exit
0 for the guarded-and-closed twin. The frozen thesis gate remains
`clean_fp=0`, `bug_caught=9/15`, and `total_findings=11`. The self-scan is
clean and complete across 48/48 translation units (the new rule adds one),
with zero broken TUs and zero incomplete functions. Corpus pins remain cJSON
54 findings (76 attempted, 35 analyzed, 41 explicitly accepted broken
fixtures) and tinyxml2 9 findings (3/3).

Contract-first shadow audit considered 40 materially changed or created source
functions. Production functions were `mergeLife`, both `Binding` comparisons,
both `State` comparisons, `resourceLife`, `mergeStates`, `calleeName`,
`isAcquireName`, `acquisition`, `asVar`, `isTrackableLocal`, `bindingFor`,
`escape`, `release`, `integerConstant`, `swappedComparison`, `failureEdge`,
the four `ResourceInventory` visitor methods, the `FdAnalysis` constructor and
six analysis methods, `reportLeaks`, `analyzeFunction`, the callback
constructor/run pair, and the three `FdResourceRule` methods. The two explicit
test helpers plus the `main` and MCP registration functions complete the
count; GoogleTest macro-generated bodies are not source-level contract
targets.

Dogfood was not applicable. The current referee can adjudicate selected
zero/null/ownership summaries, but not enum-to-enum lattice relations,
`StringRef`, containers, optional/set state, Clang AST identity, CFG
transitions, diagnostic side effects, or analyzer lifetime. Counts: proposals
0, eligible 0, rejected 0, unsupported 40. The independent RED suite exposed
the planned implementation gap, and the later precision RED exposed the
namespace/method assumption problem; no proposal exposed a separate problem.
Candidate contracts requiring later human review: none. No `cs: ai` proposal
became accepted intent.

## 2026-08-08 — Phase 4.7 opt-in library model files

Body-less platform and vendor functions can now participate in the existing
interprocedural analysis through repeatable `--model-file <file>` CLI
arguments or `model_file = <file>` configuration entries. A model is the
existing strict summary file, loaded before `--summary-in`; this slice adds
no grammar, file format, accepted relation, built-in model, or implicit
library-name semantics.

Every model and harvested summary enters the same global registry. Duplicate
keys merge through the existing conservative relation-by-relation join, so
file order cannot override a disagreement with a stronger claim. Models are
declarative specifications rather than source snapshots and deliberately skip
the source-freshness check. Missing, unreadable, empty-path, or malformed
inputs fail closed through the existing `summary_load_failed` evidence and
exit 2; strict parsing remains atomic, so a rejected file contributes no
partial rows.

The RED receipt was four failures: the CLI/config surface rejected the new
repeatable option and three end-to-end model cases could not load. GREEN pins
direct and controlled local function-pointer consumption of model-provided
nullness, zeroness, return ownership, and non-null entry preconditions. The
fixture reports exactly two findings on each of those four relations.
Additional negatives cover empty/missing paths, malformed v10, a model older
than the analyzed source without a stale warning, conflicting model files,
and a model/harvested-summary collision degrading to Unknown. The focused
config, persistence, function-pointer, and model matrix is 42/42.

Both the direct single-process binary and CTest passed 977/977 tests. The
frozen thesis gate remains `clean_fp=0`, `bug_caught=9/15`, and
`total_findings=11`. The self-scan is clean with complete evidence across
47/47 translation units, zero broken TUs, and zero incomplete functions. The
historical corpus lane remains cJSON 54 findings (76 attempted, 35 analyzed,
41 explicitly accepted broken fixtures) and tinyxml2 9 findings (3/3); exact
diagnostic-site multisets have zero additions and zero removals versus Phase
4.6. The documentation sync gate is green.

Models are documented as reviewed, trusted assumptions that can suppress a
finding when wrong, not verifier-produced proof. They must be versioned and
human-reviewed; CodeSkeptic does not promote generated or AI-proposed text
into a model or accepted contract automatically. Native pointer, heap, alias,
ownership, and lifetime verification remain outside this slice and await the
upstream A7 executable semantics.

Contract-first shadow audit considered `Config::loadFromFile`,
`Config::parseArgs`, `Config::modelFiles`, and `StaticAnalyzer::run`.
Dogfood was not applicable: all four new or materially changed functions
depend on `std::string`/`std::vector`, reference lifetime, filesystem
streams, registry state, or analyzer/AST lifecycle semantics the current
verifier cannot express and check. Counts: proposals 0, eligible 0, rejected
0, unsupported 4. No proposal exposed an
implementation or assumption problem; the independent RED tests exposed only
the planned feature gap. Candidate contracts requiring later human review:
none. No `cs: ai` proposal became accepted intent.

## 2026-08-08 — Phase 4.6 controlled function-pointer targets

Interprocedural v2 now resolves a deliberately bounded indirect-call class:
automatic local raw function-pointer variables whose initializer and every
visible assignment form a closed set of function addresses. Clean local
pointer aliases and conditional target choices join into a flow-insensitive
may-target union. Each resolved target becomes a call-graph edge, so
callee-first SCC solving and cross-TU persisted summaries compose through the
indirect call.

Target summaries are joined relation by relation. Nullness and zeroness keep
their may-value information, pointee access unions read/write bits, exact field
writes union their may-write sets, and identity, ownership, pre/postcondition,
and legacy effect claims retain strength only when every target agrees. The
call consumers now cover null/zero returns and passthrough, return ownership,
borrow/consume effects, field-sensitive invalidation, output postconditions,
non-null guard preconditions, and constant-return branch pruning.

The resolver fails closed for any unknown source, address exposure, mutable
reference rebinding, by-reference lambda capture, volatile or non-local
storage, function-pointer parameter, GNU inline-assembly output, or any MS
inline assembly. Member-function pointers and global/table dispatch remain
unresolved. The feature is call-target summary composition only; it does not
claim native pointer, heap, ownership, lifetime, or alias-verification parity.

RED receipts first showed absent summary composition and downstream null,
zero, leak, precondition, postcondition, field, and mixed-target behavior. A
later soundness audit added two more RED cases: GNU asm could mutate the target
without invalidating the set, and an indirect zero-passthrough relation was not
consumed because its prototype width was unavailable. Both now pass via
fail-closed asm handling and width-checked callee-expression prototypes. The
focused function-pointer matrix is 15/15, and the affected interprocedural
matrix is 120/120.

The exact Windows binary passed 971/971 tests. The frozen thesis gate remains
`clean_fp=0`, `bug_caught=9/15`, and `total_findings=11`. The self-scan is
complete and clean across 47/47 translation units with zero broken TU. The
historical corpus lane remains cJSON 54 findings (76 attempted, 35 analyzed,
41 explicitly accepted broken fixtures) and tinyxml2 9 findings (3/3); the
diagnostic-site multisets have zero additions and zero removals versus Phase
4.5.

Contract-first shadow audit after the workflow was adopted considered
`MutationCollector::VisitGCCAsmStmt`,
`MutationCollector::VisitMSAsmStmt`, `unwrapZeroPassthrough`, and
`NullDerefAnalysis::checkGuardContracts`. All four depend on Clang AST
pointers, function-pointer target identity, alias/mutation channels, or
dataflow state that the current contract verifier cannot prove. Counts:
proposals 0, eligible 0, rejected 0, unsupported 4. No proposal exposed an
implementation or assumption problem; the independent soundness REDs exposed
two implementation gaps and both were closed. Candidate contracts requiring
later human review: none. No `cs: ai` proposal became accepted intent.

## 2026-08-08 — Phase 4.5 field-sensitive effect summaries

Interprocedural v2 now records the exact set of one-hop record fields that
may be written through each pointer or reference parameter. Direct
arrow/dot stores, `(*p).field`, clean pointer aliases, field addresses and
references, returned aliases, record-reference parameters, and direct call
chains compose through the call-graph SCC fixed point. Whole-object writes,
non-const member calls, opaque/indirect calls, captures, ambiguous aliases,
and escaped whole-record references remain conservative. Const member calls
write only their declared `mutable` fields; rvalue-record references retain
the same exact caller binding as lvalue-record references.

NullDeref consumes the relation for its member-keyed guard implications.
Passing `&c`, or `c` to a non-const record reference, invalidates only the
exact fields a visible/persisted callee may write. Sibling-field and
read-only calls preserve correlation. Unknown effects, `&c.field`,
whole-object writes, and direct non-const calls on `c` still invalidate
conservatively; direct const calls invalidate only `mutable` fields. The same
rules cover calls used as initializers rather than only standalone call
statements.

Summary format v10 adds a strict field-write vector: `?` is unknown, `!` is
the exact empty set, and comma-separated identifiers are the deterministic
may-write set. Readers accept v1-v9 conservatively; v10 segment counts,
identifiers, duplicates, delimiters, and row widths are rejected strictly
when malformed. Cross-TU collisions union exact may-write sets and fall to
unknown if either side is unknown. Summary-diff classifies added writes,
unknown loss, and incomparable sets as WEAKENED; removed writes are
STRENGTHENED.

RED receipts covered a sibling-field false invalidation and the soundness
boundaries for guard writes, `(*p).field`, address/reference aliases,
returned field/record aliases, record-reference whole-object assignment,
non-const versus const methods, and persistence/cross-TU composition. The
final focused matrix is 87/87. The full Windows suite grew from 922 to
956 tests and is 956/956 green.

The exact historical corpus lane is unchanged at cJSON 54
(76 attempted, 35 analyzed, 41 explicitly accepted broken fixtures) and
tinyxml2 9 (3/3). Primary finding-site deltas against Phase 4.4 are zero
for both corpora.
## 2026-08-08 — Phase 4.4 call-graph SCC fixed point

Visible same-translation-unit direct calls now form an explicit call graph.
Tarjan strongly connected components are emitted callee-first, so acyclic
wrappers are summarized once after their dependencies regardless of source
order or chain depth. Recursive components are seeded conservatively and
recomputed synchronously to an exact fixed point; a bounded safety guard
falls back to the first conservative round if a future summary relation ever
fails to converge. Indirect calls remain conservative until the controlled
function-pointer slice.

The RED receipt was an eight-level owned-return wrapper that the legacy five
global sweeps could not carry to its caller. GREEN covers deep ownership,
nullness, borrowed-access and persisted write-access chains, plus nullable
facts inside a mutually recursive component. Existing recursion soundness
tests continue to reject invented strong claims.

The final Windows suite is 922/922. The exact historical corpus lane stayed
cJSON 54 (35/76 TUs analyzed, 41 explicitly accepted broken fixtures) and
tinyxml2 9 (3/3), with no finding-count or verdict-tier change.

## 2026-08-08 — Phase 4.3 side effects and ownership transfer

Interprocedural v2 now keeps pointee access and ownership on independent
axes. Pointer-like parameters carry an exact access relation
(`None/Reads/Writes/ReadsWrites`) and an ownership result
(`Borrowed/Consumed/Transferred`); opaque, captured, aliased-conflict, and
consume-plus-transfer flows remain Unknown. Direct dereference, member and
subscript uses compose through clean aliases, call chains, and non-static
`operator()` calls.

Pointer returns independently record `Owned` or `Borrowed` when every
reachable non-null path agrees. Ordinary heap allocation, configured
allocators, FILE*/DIR* acquisitions, and wrapper chains produce Owned;
parameter/global aliases produce Borrowed. Placement-new exemptions are
shared with MemoryLeak instead of duplicated. MemoryLeak now tracks owned
wrapper results, including a standalone discarded result, and no longer
treats a returned borrowed alias as ownership escape. Direct discarded
FILE*/DIR* acquisitions retain the `resource-leak` classification.
ContractRule verifies `owns`, `borrows`, and `returns owned` against the same
relations; unknown evidence stays explicitly unverified.

Summary format v9 adds fixed-width access (`O/R/W/B/U`), parameter ownership
(`B/C/T/U`), and return ownership (`B/O/U`) fields. Readers retain v1-v8
compatibility, upgrading legacy parameter effects conservatively; v9 width,
vector lengths, and codes are strict. Conservative key merges drop
disagreement to Unknown, and summary-diff treats loss/change of an exact
relation as WEAKENED.

RED was captured before implementation: owned allocation wrappers were
invisible to caller leak tracking, borrowed return aliases hid leaks,
`returns owned` stayed unverified, and persisted summaries had no access or
ownership columns (five expected failures across the focused fixture). The
first GREEN pass covered 59 persistence, compatibility, contract, cross-TU,
alias, ownership, and summary-diff tests.

The final Windows suite is 917/917. The exact historical local corpus lane
stayed cJSON 54 (35/76 TUs analyzed, 41 explicitly accepted broken fixtures)
and tinyxml2 9 (3/3), with no uncontrolled finding increase. A separate
Windows Ninja probe generated a different tinyxml2 compilation database with
`TINYXML2_DEBUG` enabled and therefore a different 54-finding nullness
surface; that result is retained as an environment observation, not
misreported as a delta against the 9-finding pin.

## 2026-08-08 — Phase 4.2 parameter precondition/postcondition summaries

Interprocedural v2 now persists and consumes two parameter relations across
translation-unit boundaries. A callee's exact leading non-null guard becomes
an entry precondition while preserving its observable consequence: an
assert/abort violation is an error, and a complain-then-return rejection is a
warning. Exact normal-return Null/NonNull effects are harvested for direct
`T**` and `T*&` output slots. Every reachable path must agree; partial writes,
conflicting values, pointer rebinding, copied/member aliases, lambda capture
and opaque forwarding degrade to Unknown.

The relations compose through direct calls, non-static `operator()` calls and
the existing bounded summary sweep. NullDeref applies exact output effects
after conservative out-parameter invalidation, so a proven NonNull result
cleans the next dereference and a proven Null result produces the existing
definite error. Body-less callers also wake for persisted preconditions.

Summary format v8 adds fixed-width precondition (`O/C/R`) and postcondition
(`U/0/N`) vectors. Readers retain v1-v7 compatibility; v8 row width, vector
lengths and codes are strict, and an older header carrying v8 columns is
rejected wholesale. Conservative key collisions keep either relation only on
exact agreement. Summary diff uses caller compatibility for preconditions
(new obligation or reject-to-crash is WEAKENED) and guarantee strength for
postconditions (loss/change is WEAKENED, gain is STRENGTHENED).

RED was captured before implementation: the cross-TU guard test returned zero
diagnostics instead of one, and the Phase 4.1 executable still emitted v7
summaries with no parameter-relation fields for the same fixture. After
implementation, all focused inference, persistence, cross-TU,
chain/operator, alias/path and summary-diff tests passed; the full Windows
suite is 899/899. The pinned local corpus stayed exactly at cJSON 54 and
tinyxml2 9, with no finding-count rise.

## 2026-08-08 — Phase 4.1 exact pointer return-alias summaries

Interprocedural v2 now harvests an independent, strong relation stating that
every reachable return denotes the entry object of one exact pointer
parameter. The analysis is flow-sensitive across local copies, direct
assignment and CFG joins; direct call chains and non-static operator() calls
compose through the prior fixpoint sweep. Mixed sources, pointer arithmetic,
dynamic casts, address exposure, compound mutation and non-const reference
write channels conservatively drop the relation. It is intentionally separate
from null passthrough: null correspondence does not imply object identity.

The deterministic summary format is v7 with a trailing return-alias parameter
column. Readers still accept v1-v6; an old header carrying a v7 column is
rejected wholesale. Conservative cross-TU/key-collision merges retain the
relation only on exact agreement. Summary diff treats gaining the relation as
STRENGTHENED, and losing or changing its source parameter as WEAKENED.

The required RED receipt was captured before implementation: the exact
harvest test failed every alias assertion and the v7 round-trip file was
rejected. After implementation, the 30/30 focused return-alias, persistence
and summary-diff tests and the full 881/881 Windows suite passed, including
assignment, path merge, reference escape, address exposure, ternary and
operator-call boundaries. The pre-existing v1-v6 compatibility matrix remains
covered.
Final local gates passed 881/881 CTest cases and the documentation/capability/
real-world-ledger sync check. The dogfood scan was clean across 47/47
translation units with zero findings and no broken TU. The frozen thesis gate
held at clean_fp=0, bug_caught=9/15 and total_findings=11. The pinned
open-source corpus remained exactly cJSON 54 findings (35/76 analyzed, 41
known broken fixtures accepted explicitly) and tinyxml2 9 findings (3/3
analyzed), so this relation produced no uncontrolled finding-count increase.


## 2026-08-08 — Phase 3 precision-debt implementation

Phase 3 replaces two rtp2httpd context false positives with explicit
proof inputs and narrow engine reasoning. Recovered assertions now accept an
honestly resolved one-hop member subject such as `DEBUGASSERT(data->conn)`,
preserve its field identity, and refine only the asserted base. The
`parse_bind_cmd` precondition is carried by a revision-pinned sidecar contract
pack whose `getopt_long` required-argument invariant is documented and copied
into the exact real-world replay; it is not a baseline or suppression.

The sign-conversion rule recognizes the rtp2httpd post-cast capacity idiom
only when one dedicated unsigned local is consumed exclusively under a direct
independent-variable upper bound. Disjunctions, arithmetic bounds, positive-
only checks, else/outside uses and later uses remain reportable. Bidirectional
regression tests pin those limits.

Memory-leak ownership now constructs transitive local pointer/reference alias
components before filtering them to tracked owners, covering Juliet shadow and
`T*&` variants without hiding the no-free control. Cross-TU summaries add an
exact `AlwaysZero` state so support helpers such as `globalReturnsFalse()` can
prune impossible leak paths. The disk format is v6, older v1-v5 files remain
accepted, and v5 rejects the new encoding rather than misreading it.

The authoritative Juliet run
[`31252090247`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/31252090247)
on analyzer tree `125a915a458e108b631d48b1dfdd92cd49089c6b` kept all 80
memory-leak TPs while cutting rule-matched FPs from 32 to 13:
precision **0.714 → 0.860**, recall 0.193 and case F1 0.315. The 0.85
product threshold is now the pinned CI floor; `memory-leak` is promoted to
supported, quality-gated and blocking. The independently unmeasured
`resource-leak` finding remains experimental/report-only.

Adding the shared support TU also exposed exact constant-return helper truth:
double-free reached 101 TP / 0 FP (recall 0.253), use-after-free 212 / 0
(0.531), and integer-overflow 23 / 0 (0.057); all gains have ratcheted floors.
The immutable Juliet evidence commit is `20626193c6e29d3b00721cad117d2ff6f4b53ad5`.

The pinned rtp2httpd replay
[`31252131673`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/31252131673)
analyzed 38/38 TUs, exit 1, and reported exactly four findings: the same four
actionable findings from the completed triage and zero context false
positives. libgit2 stayed 34 across 167/167 TUs, the canonical ledger matched,
and the run passed. Immutable evidence is `f8e39ce49c40893859f6079f57c423df1b654166`.

Local verification passed all 875 tests both through CTest and in one process,
the dogfood scan was clean across 47/47 TUs, and corpus pins stayed cJSON 54 /
tinyxml2 9. The thesis gate stayed `clean_fp=0`, `bug_caught=9/15`; profile,
capability, documentation and real-world-ledger integrity checks passed.

## 2026-08-08 — Phase 2 measurement laboratory

Every pull request now receives an exact base-to-head measurement rather than
a collection of unrelated green checks. `measurement.yml` builds the analyzer
at `pull_request.base.sha` and `pull_request.head.sha`, then uses one head-owned
harness to measure the clean thesis cases, defective thesis cases and the real
CodeSkeptic source tree separately. The receipts record duration, GNU-time
peak RSS where available, attempted/analyzed/broken TU coverage, complete or
unavailable runs, findings, per-rule counts and semantic fingerprint
multisets. The Markdown/JSON comparison exposes all four requested delta axes.
It fails closed on unavailable or broken analysis, TU coverage loss, added
clean-corpus findings, defective caught-case loss, or an adjudicated case-floor
violation. Performance deltas are evidence only in this phase; threshold
budgets remain Phase 10 work.

Findings now carry a stable `csf1` semantic site identity through JSON, SARIF,
HTML and MCP. The payload combines rule ID, a portable three-component path
tail, function and a formatting-normalized source statement; checkout root,
line/column, severity and message text do not perturb it. Duplicate sites are
preserved as multiset counts. C++ tests pin root/line/format and presentation
stability plus semantic changes, while the measurement harness independently
recomputes each head fingerprint in Python and rejects any parity mismatch.
Reporter and verdict-integrity regressions prove the value survives every
structured surface without changing diagnostic ordering or blocking policy.

Juliet false negatives now retain their detailed flow-family buckets and also
form an exhaustive product-decision partition: addressable, engine/model gap,
or intentionally out of scope. A versioned baseline binds the six current
rule-matched precision/recall/F1 rows and miss counts to analyzer tree
`7decb6b09ac2ee3c09a03bb37eebf17df71e97d5`, workflow run `31242561307` and
the 400-file sample. The Juliet workflow publishes the per-rule delta table,
three-way miss counts, runtime and peak RSS as both job summary and bounded
artifacts; an incomplete partition or missing dashboard fails instead of
silently degrading to prose.

Local Phase 2 receipts used the Windows analyzer against all three corpora:
9 clean cases, 15 defective cases and one real-repository scan produced
71/71 analyzed TUs with zero broken TUs, and every emitted fingerprint matched
the independent oracle. Five schema/delta tests, two workflow-contract tests,
the Juliet classifier self-test, workflow YAML parsing and the focused 50-test
reporter/fingerprint/verdict set passed before the full suite. The final MSVC
binary then passed all 860 tests both parallel and serial. The canonical thesis
gate stayed at zero clean false positives, 9/15 caught defective cases and 11
findings; pinned cJSON/tinyxml2 corpus counts stayed at 54/9 with no crash.

The first draft-PR push also exercised the new Juliet dashboard fail-closed:
all six score and miss rows were correct, but the parser treated the human
completion sentence containing the words `JULIET_RESULT lines` as a seventh
machine row and rejected it. Machine-row patterns are now start-anchored, with
a regression containing that exact prose line. No score, miss classification,
floor or artifact requirement changed.

## 2026-08-08 — Phase 1 product-scope contract

The capability surface is now a versioned runtime contract instead of a flat
list. `--capabilities --json` schema v2 classifies languages, frontends,
outputs, modes, all fourteen public finding families, and five explicit v1
non-goals as `supported`, `experimental`, or `out-of-scope`. The single
rule registry records default activation, quality-gate status, verdict
behavior and evidence. The v1 name-enumeration arrays, including `rules`,
remain available under their original keys; richer rule objects are additive
under `rule_capabilities`. Supported rules are exactly the five
Juliet-measured
families at 1.000 precision: double-free, use-after-free, div-by-zero,
null-deref and int-overflow. Memory-leak stays experimental at 0.714 until
the Phase 3 >=0.85 gate; every family without an independent precision
sample is likewise labeled experimental rather than promoted on breadth.

The tier is enforced, not merely documented. Experimental findings remain in
console, JSON, SARIF, HTML and MCP output but are report-only; only supported
findings contribute exit 1. Reports publish total, blocking and report-only
counts plus per-finding tier/blocking metadata. Exit 2 remains fail-closed for
incomplete evidence. Unknown future diagnostic IDs conservatively block until
classified, while the internal `contract-syntax` diagnostic inherits the
experimental contract tier. README, usage/integration docs, PLAN and the new
capability reference use the same semantics. A CI sync guard parses the
runtime registry and rejects any rule ID/tier/verdict drift in both public
tables, and it enforces supported/default/quality/blocking plus
experimental/report-only invariants. Injection/taint, race detection,
automatic fixes, an IDE product and a cloud dashboard are explicit non-goals;
CWE count is explicitly not a success metric.

CI exit-1 smokes now plant supported use-after-free/null-deref witnesses rather
than experimental memory-leak/bounds-only witnesses. The canonical real-world
ledger needs no pin relaxation: the stored libgit2 replay contains supported
null-deref findings alongside its experimental leaks, and rtp2httpd contains
two supported null-deref findings alongside four experimental sign-conversion
findings, so both complete scans still honestly exit 1.
The thesis runner also emits native compile-database paths under MSYS and
normalizes CRLF manifests, making its pinned precision/recall gate reproducible
from Git Bash as well as Linux CI.

## 2026-08-08 — v0.4.8 release smoke contract repair

The first v0.4.8 tag run (`31231137919`) proved that the macOS build, all
851 tests, tag/version check and relocatable package were sound, but its final
negative smoke assertion had drifted behind the fail-closed verdict contract.
With `SDKROOT=/nonexistent/sdk`, the packaged CLI correctly returned exit 2
and printed `VERDICT UNAVAILABLE`; the workflow still searched for the retired
`ANALYSIS FAILED` phrase and therefore failed after the product checks passed.
The Linux lane, including its two clean-container relocation smokes, passed.
Windows likewise passed build, all tests, version, package, relocation and
draft-upload checks; publish was correctly skipped because macOS was red.
The parallel Linux/Windows upload steps also exposed a second release-only
race: each could create a draft, leaving two v0.4.8 drafts (one carried all
four uploaded aliases; the other was empty). A serial `prepare` job now owns
the single draft before any platform starts, while the three platform jobs
only upload to it. The workflow contract pins one create command and all three
dependency edges, preventing incomplete or orphaned release state on retries.

The first retag retry (`31232746706`) then failed closed in three seconds,
before any platform job started: the deliberately checkout-free `prepare` job
gave `gh` neither a Git repository nor an explicit repository context. Its log
reported `fatal: not a git repository`. `GH_REPO` is now bound to
`github.repository`, and the release-workflow contract requires that binding;
the same command can create the draft without an unnecessary checkout.

The next exact-main tag run (`31233391177`) then passed prepare, macOS,
Linux, Windows and publish; the public v0.4.8 release and all six archive
aliases were valid. Action self-test, real WSL2 smoke and housekeeping also
passed. The green downstream Docker run (`31233885015`) nevertheless exposed
an identity error in its publish log: it built the default-branch checkout,
whose honest development identity was `0.4.9-dev`, stripped that suffix and
pushed the image as future tag `v0.4.9` instead of release tag `v0.4.8`.

Release-triggered Docker now checks out the Release run's exact `head_sha`,
passes its `head_branch` tag through an explicit CMake version override, and
refuses to publish unless the image-reported version equals that tag. Phase
branch pushes remain build+smoke-only; the old commit-message publish escape
hatch was removed because it had no trustworthy release identity. A manual
`workflow_dispatch` republish requires a published release tag, checks out that
same tag and reuses the identical version/equality gates; it cannot publish an
arbitrary phase commit. A new `DockerWorkflowContract` regression pins the
source SHA, override, public-release check and pushed tag. No analyzer or image
payload behavior changed.

The first guarded manual republish (`31235061132`) checked out `v0.4.8`, built
the image and passed the fresh-image analysis smoke, then stopped before either
registry push. Its log showed why: the immutable v0.4.8 source contains the
CMake override but its historical Dockerfile predates the `ARG` that forwards
that override, so the image honestly reported `0.4.9-dev`; the tag-equality
gate rejected it. Release rebuilds now keep the workflow revision's Dockerfile
as the trusted recipe while using the immutable release checkout as the build
context. This preserves exact source identity and also lets recipe-only release
repairs rebuild older tags. A regression requires the two checkouts and their
separate recipe/context roles.

PR #124 merged that repair as `a4fc98f6`. The single guarded republish
(`31236205846`) then passed both checkouts, built `0.4.8`, packaged
`codeskeptic-v0.4.8-linux-x86_64.tar.gz`, found the expected three demo
findings and published both `v0.4.8` and `latest` at
`sha256:039b10d81dbceb6cd8d16c93c4e640b84febc55e02365b0537e78652f90e9f56`.
The remaining registry repair is intentionally narrower than a tag-name
delete: a one-shot Actions step requires exactly one matching package version,
digest `sha256:03b346e66f1b292a5c2a1ddd1b5cb9190d21899077b6d646eee115f320d6197c`,
and exactly the sole tag `v0.4.9`; any ambiguity fails without deleting. It
also re-lists the package and requires both the digest and tag to be absent.
The step is removed after its deletion receipt is recorded.

The first cleanup dispatch (`31237082007`) was superseded before publication
by the single concurrency winner (`31237090369`). That run again passed exact
source build, smoke and publish, producing the correct `0.4.8` image at the new
digest `sha256:bc6994d7f6e0fdcbfedf38813b36c7e663a4aae0eb25194161d8b74fbc2d0fb0`,
then failed closed before deletion. Container rebuilds are not byte-for-byte
reproducible, so pinning the previous *good* digest was not a stable protection.
The guard now derives exactly one current version carrying both `v0.4.8` and
`latest`, requires that digest to differ from the stale digest, and requires
that same dynamically bound digest and both tags after deletion. The stale
target itself remains fixed by its exact digest and sole tag.

PR #126 merged the dynamic-current guard as `eecbcfea`. The final single
dispatch (`31237949505`) passed exact checkout, built and packaged identity
`0.4.8`, reproduced the three-finding smoke, and published both `v0.4.8` and
`latest` at
`sha256:8c39cb9602e8a60d410687b7fdecf04f2910d2fe854bdce6e66ea5349f4d5b14`.
The cleanup step then passed every precondition, deleted only stale digest
`sha256:03b346e66f1b292a5c2a1ddd1b5cb9190d21899077b6d646eee115f320d6197c`
with its sole `v0.4.9` tag, re-listed zero stale matches, and proved the same
current digest still carried both release tags. Its one-shot deletion code is
now removed; a permanent workflow contract requires it to remain absent.

Release run `31233391177` published one checksum manifest plus generic and
versioned aliases for all three platforms (seven assets total). GitHub's asset
digests and the downloaded manifest agreed exactly: macOS aliases
`sha256:24e269cd73f6bf83748532b8005fc73e78d60ed1caadffef51f8342a89c0f7d0`,
Linux aliases
`sha256:2ad28e773d134edb9d4b21e68b050c3942c07b5304fd225a1fbb0e08a508427c`,
Windows aliases
`sha256:f16ee1cf5f4068f5fd3f47d33af0cb55488cd85b497497c7106519d4963f5964`,
and the checksum asset
`sha256:913e763bc95b49815de3c23599b08cf11957b0e841be3fa1e7a7b3cb62093175`.
Packaged Action self-test `31233885003`, real WSL2 smoke `31233885002`,
and release housekeeping `31233885009` all passed before the final Docker
receipt `31237949505`.

This closes Phase 0: verdict-integrity PR #119 is on `main`; the v0.4.8
macOS, Linux and Windows packages passed tests, version, packaging and
relocation smokes; the public release, Action, real WSL2 and Docker paths all
carry the fail-closed contract; and the accidental future GHCR identity is
gone. Phase 1 starts from this evidence boundary.

A new `ReleaseWorkflowContract` regression first reproduced that mismatch.
The release workflow now requires both exit 2 and the canonical
`VERDICT UNAVAILABLE` marker in the unpacked macOS package. The regression is
registered in CTest on Linux/macOS, so future wording drift fails before the
release smoke rather than invalidating an otherwise correct tag candidate.
No product behavior, analysis threshold or quality gate was weakened.

## 2026-08-07 — v0.4.8 truth sync: one verdict, one replay ledger

Verdict-integrity PR #119 merged to `main` as squash commit `dd089708` after
all required Linux, Windows, documentation, Juliet and package-relocation
checks passed. The merge used the user's explicitly approved one-time
administrator bypass; this work did not modify the repository ruleset. The
truth-sync change was then rebased onto that exact `main` commit, whose Git
tree matches the reviewed PR head `4db8205` byte for byte.

On 2026-08-08 the user replaced the per-operation approval lock with standing
authorization through completion of the product program. Push, draft/ready
PR, merge, release/tag and necessary upstream actions no longer pause for a
second approval. The protocol still requires exact target/head verification,
green mandatory gates, protected `main`, and unchanged quality floors; the
authorization is not a gate bypass.

Prepared the v0.4.8 release identity and rewrote the release notes around the
contract the candidate actually ships: exit 0 is complete+clean, exit 1 is
complete+findings, and exit 2 is verdict unavailable across CLI, reports, MCP
and the Action. README, evaluation instructions and Action examples now pin
v0.4.8 together.

The current libgit2/rtp2httpd replay no longer has expected revisions, TU
surfaces and result counts copied into workflow shell. The executable source of
truth is `scripts/realworld_expected.txt`; `realworld.yml` validates it, fetches
both projects by full commit SHA and consumes its expectations. The human
ledger in `docs/benchmarks.md` binds those rows to analyzer tree `d47d114`,
workflow run 31199842703, evidence ref
`refs/ci-logs/d47d11422542551e2f4f7b571e07d6d917c32885/realworld` and evidence
commit `2d03342268a523c33bafa22ddb3c97d5834be4d4`.
`check_realworld_ledger.py` is also part of the required docs-sync gate: it
rejects missing/duplicate projects, non-SHA inputs, exit-2 pseudo-results,
result/exit contradictions and incomplete or dishonest triage partitions.
Six Python regressions pin those rejection paths plus the canonical success.

The final Windows rehearsal exposed a release-path bug before tagging: Clang's
native `C:\llvm\...` resource path was passed into a quoted C++ definition
without normalization, so sequences such as `\l` and `\c` corrupted the baked
development fallback. A new configured-resource regression first failed with
an empty path. CMake now emits portable forward slashes; the same regression
passes and the path-escape compiler warnings are gone.

Local truth-sync gates: CMake identified the untagged dirty checkout as
`0.4.9-dev+gaa403171dd86.dirty`; all **848/848** Windows tests passed both
parallel and serial; the canonical ledger and its six validator regressions
passed locally. The parent PR's Action argument tests were already green at
5/5. README and the remaining docs-sync guards passed. A final build with the
release override made both `--version` and `--capabilities --json` report
`0.4.8`, then produced the 14 MB
`codeskeptic-v0.4.8-windows-x86_64.zip`. Its extracted tree carried
`lib/clang/20/include/stddef.h`. With `C:\llvm` hidden, the packaged executable
reproduced three demo findings with exit 1, while a missing input produced the
required verdict-unavailable marker and exit 2.

Upstream truth was stale too. TensorFlow issue #123387 is closed and PR #123994
merged on 2026-08-07 as
`68a7e5821cbb2beb76eeebbbbdffda85a418b254`; PLAN/TODO, README proof and the
pinned regression-test comment now say so. No analyzer behavior or quality
floor changed in this truth-sync slice.

## 2026-08-07 — verdict integrity: zero findings is no longer enough

CLI, MCP and report artifacts now share one `AnalysisResult` contract.
The result records attempted/analyzed/broken translation units, incomplete
dataflow functions, summary freshness/load failures and artifact I/O. Exit
codes are deliberately narrow: 0 is complete+clean, 1 is complete+findings,
and 2 means a trustworthy verdict was not produced. Partial broken-TU
coverage, a stale or missing requested summary, a failed ClangTool run, and
failed JSON/SARIF/HTML/baseline writes can therefore never look clean.
The existing corpus harness explicitly opts into `--accept-partial-coverage`
for its intentionally broad tree pins; ordinary CLI, MCP and Action use stays
fail-closed. The override preserves the attempted/analyzed/broken evidence and
does not analyze unreliable error-recovery ASTs.

Dataflow coverage now distinguishes an iteration limit from a concrete
function whose CFG could not be built. A dependent function-template pattern
that has no concrete control flow is deferred to the AST's concrete
instantiations instead of being mislabeled as an iteration-cap failure; those
instantiations are still analyzed normally. The worklist also keeps only one
pending entry per CFG block and derives convergence from whether work remains,
so duplicate fan-in scheduling and an exactly-drained iteration budget cannot
manufacture an incomplete verdict.

MCP's `analyze` result publishes `status`, `complete`, `exit_code`, coverage
and evidence fields, and sets `isError` only when the verdict is unavailable;
ordinary findings remain a successful tool call. Unknown or wrongly typed MCP
arguments are rejected instead of ignored.

Configuration is now strict and whitespace-aware. This also fixes the shipped
idiom profiles: their documented `key = value` form previously retained the
space in the key and silently ignored every setting. Unknown CLI flags,
missing option values, invalid severity/language/line scopes, malformed config
lines and unknown config keys now fail loudly. `--help` is successful control
flow and remains available even beside a broken project config.

Development builds no longer claim the last release's identity. An exact
`v<project-version>` tag reports the final version; other checkouts report the
next patch as `-dev+g<commit>` (and `.dirty` when applicable). A dependency-free
`--capabilities --json` surface publishes version, rules, outputs, modes and the
verdict contract for wrappers and AI agents.

The composite GitHub Action validates `gate`, `upload-sarif`, output path and
version inputs before downloading or analyzing. User-provided values are passed
through environment variables rather than interpolated into shell source;
`extra-args` is split as data without evaluating command substitutions. An
invalid gate can no longer fall through to a green report-only run.

The final integrity audit closed four ways integrations could still overstate
their result. Action `extra-args` now preserves quoted paths and expands
environment variables such as `$GITHUB_WORKSPACE` without executing shell
syntax. Disabling every registered rule is verdict-unavailable rather than
clean. JSON and SARIF publish the same exit-code evidence as CLI/MCP, while an
incomplete empty HTML report can no longer display the contradictory “Clean!”
banner.

The first real-world replay proved why the verdict distinction matters. The
old lane swallowed analyzer exit 2, counted only emitted diagnostics and
reported success even though 16 libgit2 TUs and 3 rtp2httpd TUs had failed to
compile. The lane now builds both projects, analyzes only the translation units
in their real compilation databases, and pins both that surface and the result:
libgit2 v1.9.0 is complete at 167 TUs / 34 findings; rtp2httpd at the recorded
campaign revision `a7a1e568` is complete at 38 TUs / 6 findings. Any unavailable
verdict, surface drift or count drift is red.

The rtp2httpd zero in the historical table belonged to the 2026-07 engine, not
the current rule set. Re-triage of the six current findings found four
actionable reports across three roots (unchecked allocation, two verbosity
range sites and negative RTSP Content-Length arithmetic) and two context FPs
(the required-argument getopt contract and a cast followed by a bounding
check). README now shows the historical and current measurements separately
instead of letting a stale zero look contemporary.

## 2026-08-01 — corpus: name the surface the pinned count belongs to

The libarchive round ended by asking "132/132 of what?" and answering it
with a measurement. The same question had never been put to our own
corpus, where the CI log had been printing the answer's premise all
along: cjson's pinned 54 comes from a run that also skips 41
translation units it cannot compile.

Measured and classified rather than assumed, on both axes. Coverage:
enumerated 76, broken 41, analysed 35; all 41 broken sit under
tests/unity/ — the vendored framework's own suite, its expectdata
samples and runner generators, none of which the corpus build compiles
— and zero outside tests/, so no part of cjson proper is silently
absent. That half matched the expectation.

The other half did not, and is the honest headline: of the 54 findings,
only 4 are in the cJSON library itself (cJSON.c 3, cJSON_Utils.c 1).
47 sit in cjson's OWN test suite (misc_tests.c 18, cjson_add.c 10,
minify_tests.c 5, …) and 3 in Unity's tutorial ProductionCode.c — the
deliberate off-by-one. So the pin is ~87% a tripwire over test code:
real C, deliberately unguarded idioms, exactly where a null-deref FP
family would first surface — legitimate for a regression tripwire, but
a reader of "cjson 54" would naturally assume the analyzer found 54
things in cJSON, and it found 4. A cjson movement should be read
accordingly: far more likely a test-idiom family than a library-scan
change. An expectation that is never checked is just a belief — this
one was half right.

run_corpus.sh now prints CORPUS_COVERAGE per project (enumerated,
broken, analysed), so the surface is readable from any run instead of
requiring an investigation: cjson enumerated=76 broken=41 analysed=35,
tinyxml2 enumerated=3 broken=0 analysed=3.

Also restores the executable bit on check_docs_sync.sh and
run_corpus.sh, dropped when they were edited over a UNC path from
Windows. Harmless in practice — every caller says `bash scripts/...`,
in all three workflows — but their own `Usage: scripts/run_corpus.sh`
headers had stopped being true, and a header that lies is the same
defect as a pin that lies.

Footnote worth keeping: check 6's first live run failed this very
branch, and correctly. main had moved to 138b222 and the branch opened
without anyone re-running --fix, so the block still read
`base = bc50462 / uçuşta = phase-state-guard`. Ten seconds, red. That
is the same staleness that previously sat unnoticed for five commits,
and the guard caught its own author with it on the first attempt —
which is the only kind of evidence that a mechanism built against
forgetting actually works.

## 2026-08-01 — guards: the record can no longer drift from reality

Two silent drifts surfaced by accident in one session, both of the same
shape — a document asserting a fact that had stopped being true, with
nothing able to notice. TODO's state block read `main = 3ae3ecb` for
five commits while listing two long-since-merged branches as in flight.
The cjson pin read 53 from 895c813 onward while every measurement read
54, the 10%+2 tolerance quietly absorbing the gap. Neither was being
looked for; both were found because someone opened the file for an
unrelated reason.

The existing guard could not have caught either: checks 1-5 verify
presence and name/version consistency — things derivable from the tree
itself — never whether a stated fact still matches the world.

Check 6 closes the first. The two facts in TODO's state block (the main
commit the work sits on; the phase branches actually in flight) are
derivable, so they are GENERATED into a marked region and verified
against git, not remembered. `--fix` regenerates them. The pairing is
deliberate: a guard alone catches forgetting but does not undo it, and a
generator alone drifts whenever nobody runs it. Enforced on phase*
branches, where the refresh belongs — on main the block records the
round that just merged and has nothing left to prove. Everything else
in TODO (priorities, open user decisions) is judgment and is never
touched; generating that would be fabricating a record rather than
keeping one.

Writing the check taught it something. The first draft defined "in
flight" as any phase-* branch present on the remote — which would have
listed phase-docs-combined and phase-housekeeping, both long merged and
merely undeleted, manufacturing exactly the false record the check
exists to kill. In flight now means UNMERGED (not an ancestor of
origin/main).

The pin drift gets a different instrument, because prose-parsing a
changelog for the last measured number is fragile and the information
already exists where it is produced. run_corpus.sh now prints
`PIN_DRIFT expected=N measured=M` whenever the two differ inside the
tolerance band. Loud, not fatal: legitimate movement should be
re-centred deliberately in a commit that says why, and a pin one below
the true level is worse than a wrong number — a real -1 lands on it and
reads as "unchanged".

Negative-tested, both: stale base, a merged branch listed as in flight,
and a deleted marker block each turn the guard red (exit 1), the
regenerated block is green; the pin line appears at 53-vs-54 and is
absent when the pin is on the measurement. No src/ change — suite,
thesis, corpus and self-scan unaffected and re-run clean.

And then CI produced the sharpest finding of the round, by being read
instead of trusted. The lane was green, so check 6 looked delivered;
the log said otherwise:

    note: changelog-freshness check skipped (no shared base)
    note: state-block check skipped (git could not resolve a base)

actions/checkout defaults to depth 1. With no history there is no
merge-base with main, so check 3 has been skipping since it was written
(c8ca617) and check 6 would have shipped stubbed out — a guard that had
never once executed in the place it exists to guard, reporting success
the whole time. This is the same defect as the two it was written to
catch, one level up: a green signal that asserts something untrue, and
nothing able to notice.

Fixed on both sides. The lane now checks out with fetch-depth: 0 so a
base exists. More importantly the guard no longer treats an
unresolvable base as a soft skip when GITHUB_ACTIONS is set — under CI
that condition is a broken guard, not a benign one, and it now fails.
Local shallow clones keep the soft skip. Negative-tested by cloning
--depth 1 and running the guard both with and without GITHUB_ACTIONS:
exit 1 under CI, green and skipping without it.

One silent path was still left after that, and the same standard
applies to it: on success check 6 printed nothing, so a pass could not
be distinguished in the log from a check that never ran — which is
exactly how this guard reported success from a shallow checkout for
days. It now affirms what it did (`state-block verified: base = …`) and
says so explicitly when it does not apply (`n/a on 'main'`). A green
lane should never be the only evidence that a check happened.

## 2026-08-01 — bounds: struct-hack / flexible-array tail exemption (BULGU 1)

The second fix out of the libarchive v3.8.9 evaluation — the one its
receipt named first.

The unbounded-copy arm (CWE-120) read a struct member's declared
`char name[1]` as a one-byte destination and reported
`strcpy(p->name, src)` as a possible overflow. That is the pre-C99
flexible-array idiom: the object comes from `malloc(sizeof(S) + n)`, so
the declared extent is not the object's extent. libarchive sizes it
deliberately — `calloc(1, sizeof(*mine) + wcslen(wfilename) *
MB_LEN_MAX)` in archive_read_open_filename.c — and the copy fits by
construction. The type says nothing about capacity there, and an
unknown extent is precisely what this analyzer keeps silent by
doctrine; reporting it was the doctrine breaking, not merely noise.

isFlexibleTailMember() exempts a member on three conditions, each
necessary:

  * DEGENERATE extent — `[0]` or `[1]` only. A real `char name[32]` is
    a fixed buffer that happens to sit last, and keeps warning.
  * TAIL position in every record it nests in. A middle member is
    pinned by the field that follows it, so its extent is real. Unions
    are exempt from the position test and from nothing else: their
    members all sit at offset 0, so tail-ness belongs to the union
    FIELD in its enclosing struct. That is libarchive's shape — the
    array is not even the union's last member, so a naive last-field
    test would have missed the very case that prompted this.
  * a POINTER base. Through `p->` the allocation decides the size, not
    the type; on a direct object `sizeof(S)` IS the allocation, the
    declared extent is exact, and the warning stands.

The real C99 `char name[]` needed no work — an IncompleteArrayType
never carried a constant extent — and a pinned probe now proves this
change cannot turn it INTO a finding.

RED-first, with positive controls outnumbering the exemption 4 to 3:
StructHackTailArray / StructHackTailUnion / ZeroLengthTailArray report
against the pre-fix binary and go silent after; MiddleMemberArray,
TailArrayDirectObject, RealFixedTailArray and C99FlexibleArrayMember
pass before AND after, each failing the exemption for a different
reason. Suite 815 -> 822, thesis clean_fp=0 with recall floors held,
corpus unmoved (cjson 54 / tinyxml2 9 — the gate silenced nothing
there), self-scan clean. bounds carries CWE-125/787/120 and has no
Juliet floor; only the CWE-120 arm narrows.

Post-merge confirmation (def46ac binary, libarchive v3.8.9, same
target/command as the BULGU 2 receipt): untrusted 14 -> 13, baseline
12 -> 11, and the entire delta is one line — the
archive_read_open_filename.c:222 struct-hack FP — with nothing added;
null-deref 11 and int-overflow 2 unmoved. The pre-registered prediction
(13, that single line, no collateral) is what this measured. Surface
named, since these receipts carry two denominators: the directory walk
enumerates 487 .c (132 library + 355 test); the 355 test files have no
compile command (tests disabled) and are skipped; the 610 "processing"
lines are not files — 123 library files hold two compile-DB entries
each (shared + static). Of the 132 library TUs, 123 come from the DB
and 9 are platform files absent from the Linux build (4 ACL backends —
the Linux one included, libacl being unavailable on the rig — and 5
Windows-only), analysed with fallback flags and effectively empty
behind their guards. "132/132, broken=0" is true of the library scope;
the load-bearing surface is 123.

## 2026-08-01 — sign-conversion: non-size unsigned typedef sink gate (BULGU 2)

Fix drawn from the first foreign-machine evaluation.

libarchive v3.8.9 measurement receipt (independent WSL host, no repo
files written): 132/132 TU parsed, broken=0, ~22s. Finding ladder held
its shape across the config axis — baseline 12 -> --untrusted-int-sources
19 -> --no-assert-recovery 12 — i.e. the untrusted rules are the only
thing the flag turns on, and assert-recovery accounts for exactly the
baseline delta. Three precision notes came back (BULGU 1 bounds
struct-hack FP, BULGU 2 below, BULGU 3 CWE-775 int-fd precondition).

BULGU 2 fixed here: the sign-conversion rule (CWE-195, opt-in) reported
an untrusted signed value converting into a mode_t / dev_t as a "possible
negative length". Those types are unsigned but are NOT lengths —
permission bits, a device id — so the message misframed a conversion
that is not this rule's story (libarchive sets file modes/rdevs from
archive headers). Added isNonSizeUnsignedSink(): a conversion whose
destination typedef chain names a POSIX identity/permission type
(mode_t, dev_t, uid_t, gid_t, ino_t, nlink_t + the glibc __ spellings)
is exempt. Deliberately a DENYLIST, not an allowlist: a fail-closed
"only size_t-family fires" gate would also silence the uintN_t lengths
read straight off the wire — the rule's flagship case — so raw builtins,
size_t and the exact-width unsigned types all keep firing. RED-first:
ModeTSink / DevTSink probes reported against the pre-fix binary and go
silent after; SizeTTypedefSink positive-control proves the gate is
targeted, not a blanket typedef exemption. Full suite 814/814, thesis
clean_fp=0 recall floors held, self-scan clean. Corpus (cjson 54 /
tinyxml2 9) is invariant by construction — it runs without
--untrusted-int-sources, so sign-conversion emits nothing there — and CI
confirms empirically. The rule is off-by-default and not Juliet-floored;
this only narrows it.

Post-merge confirmation (5dae941 binary, libarchive v3.8.9, same
target/command): 19 -> 14, the full delta the intended class —
sign-conversion 5 -> 0 at exactly tar.c:1348 (mode_t) +
1852/1854/3085/3087 (dev_t), zero collateral, no new findings. This
measures the gate's targeting, not the flagship-preserved claim
(libarchive had no size_t/uint32_t sink to begin with — that claim
rests on the RED tests).

Scope notes, for the record: 2 of the 11 baseline null-derefs were
sampled, 9 remain untriaged; and the lzma/bz2/openssl/acl-xattr filter
layers were outside the scan (missing dev headers on the rig: lzma.h,
bzlib.h, openssl/evp.h, sys/acl.h, attr/xattr.h), so "clean" here means
within-scope, not absolute.

## 2026-07-30 — docs: README rule table synced + two consistency guards

An external review flagged the gap the doc-hygiene guard had left open:
the README Rules table listed the old rule set while main had shipped
resource-leak, sign-conversion, alloc-size-overflow and the CWE-191
underflow expansion. Closed both the drift and the door.

- README Rules table: added resource-leak (CWE-404), sign-conversion
  (CWE-195), alloc-size-overflow (CWE-131), assumption; int-overflow
  row now names CWE-191 subtraction underflow. Budget raised 300 -> 315
  for the real rule-count growth (not prose).
- evaluate.md Docker tag v0.4.5 -> v0.4.7 (drift from README).
- check_docs_sync.sh gains two mechanical guards, both negative-tested:
  (4) every finding rule_id the code emits must appear in README
  (skip-list for non-detection diagnostic ids); (5) version pins in
  README + evaluate.md must match the canonical CMakeLists version, so
  a release bumps the install docs in the same commit. The registry
  <-> README drift and the version drift can no longer recur silently.

## 2026-07-30 — docs: first-scan triage guide (adoption)

New docs/first-scan.md, the adoption-critical guide missing until now:
what a first run on a mature codebase surfaces and the exact lever for
each family — baseline first; assert-family -> --assert-macros/
--negative-assert-macros; custom abort -> --fatal-asserts;
accessor-nullability -> contracts/baseline; wrapper-blind leak domain
-> --alloc-functions; opt-in provenance -> --untrusted-int-sources. The
framing is precision, not suppression: every lever states a fact the
analyzer couldn't see, so the surviving findings stay trustworthy.
Linked from README "Next steps" (budget held at 298/300).

## 2026-07-30 — tinyusb untrusted-length receipt (out-param model), re-measured clean

The sign-conversion round's out-param seeding (a declared untrusted
source taints integer out-params, not just returns) was a real behaviour
change; the untrusted-length.md receipt (tinyusb, "scanned clean with
and without the flag on plausible sources") predated it and was flagged
as not-re-measured. Now measured: full tinyusb src (77 .c files) under
the alloc-size binary, three modes — assert-recovery off, flag off, flag
on (--untrusted-int-sources read_u16,packet_len,tud_cdc_read,tu_u16) —
ALL 0 findings, 0 resource/sign/alloc-size. The out-param model
introduced no false positives on the device stack; the receipt holds
under the new engine. Honest note: the survey cited 24 TUs, this run
saw 77 .c (the fallback per-extension DB compiles a wider set); either
way, clean.

## 2026-07-30 — CI: doc-hygiene guard automates the working agreement

scripts/check_docs_sync.sh, wired into the required build-and-test lane,
enforces mechanically what used to rest on memory: the canonical trio
(PLAN.md / TODO.md / changelog.md) exists, NO scattered per-feature
PLAN-*.md briefs are added (the no-scatter decision, now a CI gate), and
a src/ change ships with a changelog entry (best-effort against the
merge base; skipped gracefully when no base). A miss blocks merge.

## 2026-07-30 — CWE-404: resource leak (fopen/opendir), built-in

A FILE*/DIR* left un-closed is a resource leak, and a FILE* is a
pointer — so the leak rule's ownership machinery already tracked it the
moment `--alloc-functions fopen --free-functions fclose` was set. This
makes the common resource pairs BUILT-IN (fopen/freopen/fdopen/tmpfile
acquire, opendir/fdopendir; fclose/closedir release) so the CWE-404
case is caught out of the box, no config. The report classifies by the
ACQUIRING name — robust across libc FILE typedefs — as a distinct
`resource-leak` finding, so a leaked handle is not mislabelled a heap
`memory-leak` (CWE-401). Ownership escape (return, struct store) rides
the same logic that keeps returned malloc clean, so a FILE* handed back
to the caller is silent.

Raw-fd openers (open/openat/socket/accept) return an int the
pointer-based leak domain cannot track; CWE-775 strict is deferred to
an integer-resource model (documented, not silently dropped). RED/GREEN
proven; 5 tests (fopen leak, fopen closed, opendir leak, returned-escape
clean, heap-still-memory-leak regression). Suite 806 -> 811, thesis
clean_fp=0, corpus unchanged (cjson 54, tinyxml2 9, zero new resource
findings — real code closes its files).

## 2026-07-30 — CWE-191: signed subtraction underflow, folded into IntOverflowRule

The roadmap parked `-` as "CWE-191, out of scope." It turned out to be
one predicate away: `escapesSignedFinite` already tested BOTH bounds
(`hi > max` for overflow, `lo < min` for underflow), so underflow
detection was latent — the only thing keeping subtraction out was
`isGrowthOp` admitting just `*` and `+`. Admitting `-` (renamed
`isArithOp`) turns it on with no new engine: same interval dataflow,
same finite-witness bar, same guard refinement.

Signed subtraction whose proven range provably leaves the type (either
direction — `a - b` below INT_MIN, or minus-a-negative above INT_MAX,
both UB) now reports with a subtraction-specific message. `x - x` is
skipped (provably 0). Unsigned subtraction stays out (its wrap is
defined, a different non-UB story). Guards refine and silence; unknown
operands stay top() and silent.

RED/GREEN proven (-2e9 - 2e9 = -4e9: pre-change Clean -> reports). 5
tests (underflow, in-range, guarded, unknown, unsigned-excluded). Suite
801 -> 806, thesis clean_fp=0, corpus unchanged (cjson 54, tinyxml2 9),
Juliet floors held (CI). CWE-190 and CWE-191 now share one rule and one
proof discipline.

## 2026-07-30 — alloc-size-overflow rule (CWE-131), the binfont hunt's answer

The LVGL binfont hunt named a scope gap; this is the rule. An untrusted
length wraps an UNSIGNED allocation-size computation before the
allocator sees it: `lv_malloc(sizeof(uint32_t) * (loca_count + 1))` with
loca_count from a font file — at 0xFFFFFFFF the `+ 1` wraps to 0 in
uint32, lv_malloc(0) hands back a tiny buffer, the fill loop overflows
the heap. Every existing rule missed it by design (IntOverflow is
signed-only, sign-conversion needs a cast and EXCLUDES allocator args,
bounds is fixed-extent) — the nlohmann lesson one level over.

The rule fires only when an unsigned `*`/`+` (a) feeds an allocator's
size argument, (b) has an operand of declared untrusted provenance, and
(c) provably reaches past its unsigned result type's max (a finite
interval witness). A bound on the length narrows the interval and
silences on its edge; an ordinary unsigned parameter with no declared
source stays silent (provenance opt-in). It INVERTS sign-conversion's
allocator exclusion — the allocator sink is precisely this rule's
target — so the two partition the allocator-size space cleanly; the
shared `isAllocatorCall` predicate (lifted to engine/AllocFunctions.h)
keeps them in lockstep. v1 scope: sub-64-bit result types, where the
int64 interval can witness the wrap; 64-bit size_t multiply needs the
operand-corner proof and is deferred (documented, not dropped).

RED/GREEN proven on the loca_count shape (pre-rule Clean -> reports at
the `+ 1`). 7 tests (trophy out-param, return-value multiply, the bound
that silences, provenance/non-allocator/signed negatives, custom
wrapper). Off by default. Suite 794 -> 801, thesis clean_fp=0, corpus
unchanged. The LVGL sites are now upstream candidates pending the
duplicate/CVE search and SECURITY.md channel (PLAN.md section 6) — NOT
yet filed.

## 2026-07-30 — FINDING 2: the negative-name veto failed open

AR.3 gate 2 vetoes a recovered assert whose NAME announces the pointer
is null (cmocka's assert_null &c), because a vanished assert leaves only
its name to judge direction by and believing a negative one backwards
INVERTS a proven fact — silences a definitely-null finding. The veto
was a five-word denylist (null/false/zero/not/fail) and failed OPEN:
assert_nil, ASSERT_EMPTY, assert_missing use none of those words, so
they were recovered as positive non-null assertions and their derefs
went silent. Proven RED/GREEN on a probe: the pre-fix binary reports
Clean on `if (p) return 0; assert_nil(p); return *p;`, the fixed one
warns.

Two-part close, both safe-by-construction (over-vetoing costs only
recall — an over-vetoed positive is merely not recovered; inverting a
fact costs correctness):
- the denylist is widened to the null-ness VOCABULARY (adds nil, none,
  empty, absent, missing, unset; "nil" distinct from "null"). Short
  fragments that collide with innocent names ("no", "err") are
  deliberately left out;
- `--negative-assert-macros` is the escape hatch for the residual
  fails-open — a negative macro whose name uses no vocabulary word
  (ASSERT_CLEARED) is declared and force-vetoed, winning over
  --assert-macros on conflict. usage.md documents the residual openly.

No positive-path regression: DEBUGASSERT/lua_assert still recover (unit
pin), and real-world recovery is unchanged — curl re-scan 76 = 76 (its
DEBUGASSERT carries no vocabulary word). Suite 791 -> 794, thesis
clean_fp=0, corpus unchanged (cjson 54, tinyxml2 9).

## 2026-07-30 — sign-conversion rule: untrusted signed → unsigned length

The nlohmann campaign's proven false negative closed. #3491/#3492 —
`get_ubjson_size_value` converts an attacker-chosen `std::int8_t` to a
`std::size_t` with no negativity guard, so a negative wraps to a huge
length and the read walks off the buffer. CodeSkeptic missed it
pre-fix (scanned three ways, clean); the cause was diagnosed by
source-reading as a SCOPE gap, not a tuning miss — IntOverflowRule
excludes the pattern twice on purpose (explicit-cast = stated intent,
unsigned-wrap = defined), both correct for ITS question and unchanged.

New rule `sign-conversion` (CWE-195 neighbourhood, off unless the
provenance flag opts in) asks a different question of the same
expression: does an UNTRUSTED signed value reach an unsigned integer
type while provably able to be negative? Gates: declared untrusted
provenance (never guessed), a finite negative witness in the proven
interval, so a dominating `x >= 0` / `x < 0` guard silences on its
edge while an upper-bound-only guard (`if (x > 100)`) does NOT — the
negative range survives it, which was nlohmann's exact shape.

Precision boundary, caught by the thesis gate before merge: an
ALLOCATOR argument is out of scope. `n = atoi(argv[1]); calloc(n, ...);
if (!p) ...` (the corpus's array_from_int.c, ground-truth clean) is the
commonest untrusted-alloc idiom — a negative n makes calloc return
NULL, handled by the check; the allocator's NULL-on-over-large contract
owns this case, and an unchecked result is the null-deref rule's
finding. The rule's territory is the NON-allocator use nlohmann showed:
a length stored/returned/copied with no NULL net. The malloc/calloc
intrinsics plus --alloc-functions wrappers are excluded; the nlohmann
sites (a store to a reference param) are untouched.

Plus the out-param half of the untrusted-source model (3b): a declared
`--untrusted-int-sources` function now taints its integer out-params
(C++ reference and C `&x` pointer), not only its return —
nlohmann's `get_number(format, number)` delivers the value through a
reference, which the return-only model let arrive trusted.

Retro-detection, both directions on the real trees:
- pre-fix (`6a739205`), unit-bjdata.cpp, `--untrusted-int-sources
  get_number`: **4 findings**, exactly the `i`/`I`/`l`/`L` signed
  cases at `result = static_cast<std::size_t>(number)`; the unsigned
  `U` case correctly silent;
- fixed (`93c9e0c7`), same scan: **0** — the upstream `if (number < 0)`
  guards silence on their edge, the machinery agreeing with the human
  fix.

Default unchanged (flag empty): sqlite re-scan 57 = 57, zero
sign-conversion without the flag; corpus (cjson 54, tinyxml2 9) and
thesis (clean_fp=0, bug 9/15) at their pinned levels. 10 new tests
(`SignConversionRuleTest`: the trophy, return-value and out-param
sources, the upper-bound-only guard that must still report, the
allocator-argument and signed-narrowing boundaries, guard/unsigned/
provenance negatives), suite 781 -> 791. NOT re-measured this round:
the tinyusb untrusted-length receipt (out-param seeding is new; the
flag is opt-in so default projects are untouched, but a project using
both the flag and out-param sources could see new — genuine, by the
doctrine — findings). Rule registered in main.cpp and McpServer.cpp.

## 2026-07-29 — AR.3 placement: the compound-body blind spot (curl's find)

The witness campaign (docs/ar3-witness-campaign-2026-07-29.md) measured
recovery silencing 6 of sqlite's findings and zstd's adjudicated
proof-case — and ZERO of curl's 82. Cause, not guess: curl's default
`DEBUGASSERT` erases to `do { } while(0)`, a location inside a macro
body decomposes to the expansion point, so the macro's own `{ }` won
the innermostCompound walk as deepest container — an empty scope with
no next statement, and every record died unplaced. GLib's
`G_STMT_START` is the same shape, which made this the default idiom of
a large part of the C ecosystem, not a curl quirk.

One refusal fixes it: a CompoundStmt whose own begin location is a
macro location cannot be the SCOPE — the block an assert stands in is
necessarily written in the file. An assert whose every enclosing block
comes from some other macro's expansion still finds no scope and is
dropped, the standing v1 refusal for macro-inside-macro placement.

Re-measured with exact lane recipes: curl 82 -> 76 null-deref, six
silenced (conncache's `DEBUGASSERT(cpool)`, splay's
`DEBUGASSERT(t)`/`(x)` — covering asserts verified at each), zero
added; the 76 that remain are dominated by field-subject asserts
(`DEBUGASSERT(data->conn)`), which are the declared v1 grammar
boundary, not a placement failure. No movement anywhere else: sqlite
57, zstd 4, lua 36, probe matrix identical. Three pins (do-while
shape, GLib shape, loop-rebind composition); suite 778 -> 781.

## 2026-07-29 — AR.3 gate 4, asked twice more precisely (sqlite's find)

The first real-codebase delta measurement for assert recovery — sqlite,
125 TUs, run independently on two machines with identical results —
showed gate 4's loop rejection doing something no unit test had asked
about: not REMOVING a finding but MOVING it. In
`convertToWithoutRowidTable()` the baseline warned after the join
(build.c:2536) and recovery warned inside the branch (build.c:2468) —
same function, same `pPk`, a deref sitting directly under an assert.
Minimal repro is 14 lines: if/else, assert in the else-branch, a loop
that only READS the pointer, then a deref. Six-variant ablation
isolated the trigger (loop inside a conditional branch; neither alone)
and `--no-assert-recovery` pinned the mechanism to recovery itself.

Two commits close it, each asking gate 4's question of a more precise
object:

- **Target, not class** (796c90e): the rejection tested whether the
  statement after the assert IS a loop, but the guard lands on
  `firstElementIn()` INSIDE it — so a `#pragma clang loop`
  (AttributedStmt) or one pair of braces reopened the exact false
  negative the rejection exists to prevent. Rejection now walks to the
  target. Four pins, each verified RED on the pre-fix binary.
- **Variable, not loop** (9c12db7): re-firing a guard on the back edge
  is only unsound when the body can REBIND the pointer; re-asserting
  an unwritten variable re-states a true fact. The gate now locates
  the target's outermost enclosing loop and rejects PER NAME, only
  when that loop writes the variable — write detection deliberately
  conservative (assignment, `++/--`, address-of, non-const-ref
  binding, unseeable signatures, asm).

Measured on sqlite, same tree, three binaries: baseline 63 findings,
blanket rejection 59 (5 silenced + the relocation), per-variable
**57 — six eliminations, zero relocations, zero additions**. The sixth
(select.c:6976, `pList->a` in a for-init directly under
`assert( pList!=0 )`, loop never writes `pList`) was invisible to the
relocation analysis — blanket rejection had produced the same line as
baseline there — and was hand-verified against the source. nlohmann
parity: the known single finding, identical before and after. Suite
774 -> 778, all six CI lanes green.

Also documented (usage.md): a recognised assert macro must TERMINATE
on failure. A log-and-continue soft assert erased by NDEBUG leaves
only its name to judge by — the erased body is structurally invisible
— and believing it hides real findings. Found by a second independent
route (a non-terminating `SOFT_ASSERT` probe) converging with the
review's name-based-trust finding.

## 2026-07-25 — AR.3: recovering the assert the compiler threw away

The ecosystem FP family that five independent audits kept producing
has an engine answer now. Under NDEBUG an assert's condition never
reaches the parser — curl's DEBUGASSERT expands to NOTHING, glibc's
assert to `(__ASSERT_VOID_CAST (0))` — so there is no AST node to
narrow and no amount of dataflow work can find one. New subsystem
`src/engine/AssertGuards.{h,cpp}` intercepts the expansion itself via
`PPCallbacks::MacroExpands`, parses the argument tokens, and records a
"virtual guard" that `DataflowEngine` applies to the following
statement (`applyAssertGuard`, an optional SFINAE hook alongside the
existing `refineOnEdge`/`widen` family; NullDerefRule implements it).
Different work from `--fatal-asserts`, which makes VISIBLE calls
noreturn — this recovers INVISIBLE macros. The two compose.

Four gates, all of which must pass before anything is recorded: the
macro body must genuinely DISCARD its argument (if the body uses it,
the condition is already in the AST and AR.1's live path handles it —
double-handling is structurally impossible, not merely avoided); the
name must look like an assertion ("assert" substring, case-insensitive,
plus `--assert-macros` for project spellings); the token shape must
match a deliberately narrow null-constant grammar (`x`, `x != NULL`,
`NULL != x`, conjunctions — with a top-level `||` vetoing the whole
record, since `p || q && r` does not prove `r`); and the placement
must provably dominate (braceless if/while bodies, switch fallthrough,
goto/labels and shadowed names are all refused). Every NULL spelling
accepted — `NULL`, `nullptr`, `0`, `(void*)0`, `((void*)0)` — is a
null pointer constant by the language rules, so collapsing them adds
no assumption; `(int)0` and `(void*)q` are rejected.

Stated plainly, because it matters: this is NOT a soundness fix. The
shipped NDEBUG build really does not run that check. It is a
deliberate, declared decision to treat the author's assert as the
invariant they said it was — `--no-assert-recovery` turns it off and
reports the code exactly as the shipped build sees it. On by default.

38 new tests (`tests/AssertRecoveryTest.cpp`), suite 734 -> 772, zero
regressions; thesis gate and self-scan unchanged. Two of the tests use
the REAL `<assert.h>`/`<cassert>` under NDEBUG rather than a paraphrase
of them, each with an in-snippet control so a box without system
headers fails loudly instead of passing vacuously on a broken TU.

Two bugs found and fixed by the battery, both real rather than test
artifacts. Null-constant casts were rejected outright, which would
have missed every `assert(p != (void*)0)` in real C — replaced the
flat token whitelist with a recursive grammar. And the straddle check
could never fire: a location inside a macro body decomposes to the
macro's EXPANSION POINT, so an enclosing `if`'s end offset lands at
the macro's BEGIN, never past its end — `if (c) assert(p); return *p;`
was being silently believed. Rewritten as a three-way containment
classification.

Then three more, and these are the ones worth reading. With all 33
tests green, an adversarial review pass over the landed code — reading
it for what it BELIEVED rather than for what it did — found three
silent false negatives, each retiring a real finding on the strength of
an assert that did not say what the recovery thought it said. A guard
attached to a loop re-fired on every back edge, so `assert(p); while
(...) { use(*p); p = malloc(4); }` scrubbed the pointer clean at the
top of iteration two and the loop-carried deref of a may-fail malloc
went quiet — an assert before a loop dominates ENTRY, once, not each
iteration. Multi-parameter macros had only argument 0 parsed, so
`ASSERT_EQ(p, NULL)` — which asserts that p IS null — was recorded as
"p is non-null"; gtest's `ASSERT_LT(p, q)` and message-first spellings
like `ASSERT_MSG(msg, cond)` failed identically, all three recognised
with no opt-in. Worst of the three, the "assert" substring rule never
asked what the assert CLAIMED: cmocka's `assert_null`, Unity's
`TEST_ASSERT_NULL`, CUnit's `CU_ASSERT_PTR_NULL` all assert the pointer
IS null, and believing one backwards suppressed a *definitely*-null
finding — an inverted proof, not a lost maybe.

Closed by three new sub-gates: loop statements are refused as guard
targets, the macro must take exactly one non-variadic parameter, and a
name announcing a negative claim is vetoed by spelling (an explicit
`--assert-macros` entry still overrides the veto, which is how a real
`ASSERT_NOT_NULL` stays usable and why listing a negative one is
documented as harmful). All three cost some recovery value and buy
soundness, which is the trade this project takes every time.

The lesson is the one worth keeping: 33 green tests written alongside
an implementation prove that the implementation does what its author
was already thinking about. They say nothing about the assumption
nobody wrote down. The three regression tests now in section C2 of
`AssertRecoveryTest.cpp` were each verified to FAIL on the pre-fix
binary before being kept — a test that passes on the buggy build is
not a regression test.

## 2026-07-25 — AR.2 measured: the assert-define doctrine is a dirty switch

The scan survey proposed enabling a project's assert define as the
cheap fix for the assert-nonnull FP family. Measured on curl
(off-vs-on probe e9b5c3f) and REFUTED as a clean fix: assertions off
= 82 null-derefs, assertions on (-DENABLE_DEBUG=ON) = 110 - it went
UP. The site diff explains why: ~181 sites DID go silent when asserts
were enabled (the narrowing mechanism works, the family is real), but
DEBUGBUILD also switched on unrelated debug-only code (curl's multi.c
block) that added more findings than it removed. So the mechanism is
right but the delivery is wrong - telling users to compile with the
debug define changes semantics and adds noise. This makes AR.3 (the
PPCallbacks vanished-assert recovery that reads the compiled-out
assert's condition WITHOUT enabling the debug build) REQUIRED, not
optional - promoted from a maybe to the one clean path, by
measurement not guess. docs/PLAN-assert.md updated.

## 2026-07-25 — Assert-refinement plan: the hypothesis CORRECTED by measurement

The survey's "engine doesn't narrow asserts" hypothesis was tested
before planning — and REFUTED: a live glibc assert already narrows
correctly (noreturn false-edge + refineOnEdge; pinned experiment in
docs/PLAN-assert.md). The real gap is asserts COMPILED OUT by default
(zstd DEBUGLEVEL, lua LUAI_ASSERT, curl DEBUGBUILD, sqlite
SQLITE_DEBUG) - the invariant never reaches the AST. The plan
therefore leads with measurement: AR.1 pins today's correct live
behavior, AR.2 establishes the assertion-enabled-scan doctrine and
RE-MEASURES all five witnesses (config work, ~3%, no fresh quota
needed), and only AR.2's collapse numbers decide between AR.3 (a new
PPCallbacks vanished-assert recovery subsystem, medium) and Phase
7A.2. Plan-by-evidence, not plan-by-guess.

## 2026-07-25 — Scan survey: 11 targets, and an ecosystem-wide FP family

A breadth sweep (hobby code, libraries, an OS earlier, graphics
engines, compression) surfaced one dominant lesson, documented in
docs/scan-survey-2026-07-25.md: across FIVE independently-audited C
codebases (curl, lua, sqlite, raylib, zstd) the top "finding" is the
same false positive — a pointer from a may-return-null call, then
`assert(ptr)`, then dereferenced, with the engine not treating the
assert as narrowing the pointer non-null. Adjudicated on zstd 1.5.6
(zstd_compress.c:5505, the site first seen in ReactOS's vendored copy
and re-confirmed upstream — loop closed). Recommendation on record:
model assert(cond) as a fall-through refinement (distinct from
--fatal-asserts) as the NEXT engine round's #1, precision-first,
ahead of the Phase 7A recall slices — low risk, five ready repros,
collapses hundreds of FPs at once. Genuine wins banked: box2d 3.0.0
and libexpat 2.6.4 both genuinely clean (libexpat in the README
trophy table). Two false-cleans (mbedTLS generated header, stb_image
driver) correctly distrusted via the processed/broken counts.

## 2026-07-25 — New targets: libexpat clean, curl parked for triage

Two plain-CMake C targets scanned on the realworld lane, both with
real coverage (broken=0, verified via the processed/broken counts the
ReactOS campaign taught us to print). **libexpat 2.6.4**: 0 findings
across its ~5-file core — a hardened XML parser came back clean and
the v0.4.7 untrusted-length→bounds arm produced no false positive on
its length-field code; recorded in the README trophy table.
**curl 8.11.0**: 86 findings over 170 clean TUs (83 null-deref +
3 unbounded-strcpy). Not triaged — curl is heavily audited, so 83
null-derefs is an FP FAMILY (libgit2 149→34 shape), leading suspect
the DEBUGASSERT macro the engine does not yet know establishes
non-null. Parked with the full hypothesis, the 3 strcpy real-candidate
sites, and the resumption recipe in docs/curl-campaign.md — an FP-hunt
round reserved for fresh quota + max, not started at 84% used.

## 2026-07-25 — ReactOS campaign: ten rounds, parked at the MMX wall

An OS-scale target probed end to end on plain CI runners. Proven:
ReactOS configures WITHOUT a full build (10 s, 9160-entry compile
db; clang toolchain still needs mingw gcc for ASM), generated SDK
headers materialize via `ninja xdk psdk`, PCH disabled at configure.
Walled: the mingw sysroot headers use GCC MMX builtins that clang
19+ removed — masking the header kills the __m64 type winnt.h needs,
shimming the type leaves header-inlined _mm_* calls undeclared. A
toolchain-version mismatch, not an analyzer defect; resumption paths
(ReactOS's own CI container first) in docs/reactos-campaign.md, plus
profiles/reactos.conf and two vendored-zstd findings recorded.
Process lessons banked: git add's cross-pathspec atomicity can
swallow diagnostics; Actions' default bash has NO pipefail — both
now written into the lane. The 0-findings runs were correctly
distrusted twice (false-clean via wrong-compiler db, then via
missing PCH) — reading the logs, not the exit code, is the product's
own doctrine applied to its harness.

## 2026-07-24 — F7A.3: multi-hop parameter seeding (intervals + zeroness)

Both C3 seeding passes (ParamIntervals, param-zeroness) were
deliberately single-shot — "no fixpoint, no optimistic recursion". The
multi-hop upgrade keeps that caution but gains the chains: the pass is
ITERATED (cap 3, early exit on stabilization), each round re-analyzing
callers from scratch with THEIR params seeded from the previous
round. Soundness is by induction, not by monotonicity: pass-0
(all-top / empty) trivially over-approximates, and any pass computed
under a sound predecessor is sound itself — recursion and cycles
included, they simply stabilize at top instead of narrowing. So the
cap is a precision knob, never a correctness one. On the zeroness
side the evidence chain stays proof-backed at every hop (a pass-k
MaybeZero exists only because pass-(k-1) PROVED the caller's param
possibly zero) — MaybeZero is still never manufactured from Unknown.

Measured shapes: b(9) -> c(j) -> table[k] is now a definite OOB
through two hops; scanf'd d -> a -> b -> 100/y warns through two
hops; a guard at the middle hop silences; wild callers stay silent.
733/733 tests (+5 pinned both ways), thesis gate 0 FP, rtp2httpd 0,
self-scan clean. PLAN-f7a.md: 7A.3 DONE — F7A-core complete.

## 2026-07-24 — F7A.1: null-passthrough summaries (early slice, high effort)

The pointer twin of v0.4.7's zero-passthrough, pulled forward from
docs/PLAN-f7a.md because the machinery was still warm: summaries gain
nullFromParam ("the result is null only if argument #k is null"),
harvested by the same structural pass with POINTER discipline in
place of width discipline — every hop must be pointer-typed,
dynamic_cast blocks the claim (it can produce null FROM non-null),
integer hops block it too. Consumption is one stateless hook:
evaluateNullness's call case recurses into the argument, so
`p = keep(fopen(...))` inherits fopen's MaybeNull, `keep(&buf)` stays
NonNull, chains compose (two-hop pinned), and a plain-variable
argument stays Unknown exactly like a direct `p = q` copy — never a
manufactured MaybeNull. vstateOf recurses the same way, so summary
harvest composes across wrapper chains. Summary file format v5
(nullFromParam column; v1-v4 accepted, the >=-not-== parse trap
pinned one version forward this time).

Verification: 728/728 tests (+11: keep/two-hop/guard/written-param/
plain-var/alloc-through-wrapper/mixed-paths + v5 persistence), thesis
gate 0 FP, rtp2httpd 0, self-scan clean. Juliet CWE476 floor referees
in CI. PLAN-f7a.md updated: 7A.1 DONE.

## 2026-07-24 — v0.4.7: untrusted-length→bounds + zero-passthrough summaries (F7-small)

Two deferred engine slices, both recall moves with pinned precision.

**Untrusted-length → bounds sink** (docs/untrusted-length.md's design
placeholder, now landed). The interval dataflow's state gained an
untrusted-origin set — vars whose CURRENT value derives from a declared
untrusted-integer source (atoi/strtol family, scanf outputs,
--untrusted-int-sources). Plain reassignment recomputes membership from
the RHS (no stale taint), merge is set-union, and guards deliberately
do NOT clear it: the RANGE is the sole safety decider. The sized-copy
check (now including strncpy — it pads to exactly n bytes; its
constant arm is definite CWE-787) gained the possible arm: length
derives from an untrusted source AND its proven FINITE range exceeds
the destination capacity → CWE-120 warning. Unknown (top) lengths
never report — provenance alone cannot fire, which is what keeps
ordinary size parameters silent. 10 pinned tests both ways.

**Zero-passthrough summaries** (the zeroness-through-summaries
deferral). `int id(int x) { return x; }` left returnZeroness Unknown —
the documented v1 limit — so `r = id(d); 100 / r` lost d's zeroness.
Summaries now carry zeroFromParam: "the result is zero only if
argument #k is zero", harvested by a structural pass that runs only
when neither strong claim held (paths must be NeverZero or return an
UNWRITTEN param's entry value; an unwritten param's value is
path-independent, which is what makes the structural pass sound).
WIDTH DISCIPLINE throughout: a narrowing hop (int ← long long) can
fabricate zero from nonzero, so any step whose width exceeds its
target slot blocks the claim — on the harvest side AND on the
consumer unwrap (a false NonZero would wrongly SUPPRESS a real
hazard). Consumption reuses the copy machinery: unwrapZeroPassthrough
makes `r = id(d)` classify exactly like `r = d` (the copy-source
closure learns the same unwrap, or d's state is never computed);
zstateOf recurses through PT summaries for chains (two-hop pinned).
MaybeZero is never manufactured from Unknown. Summary file format v4
(zeroFromParam column; v1-v3 accepted on load — including the ==5 →
>=5 null-cond parse trap a compat pin now guards). 12 pinned tests.

Verification: 717/717 tests, thesis gate 0 FP / 9-of-9, rtp2httpd
re-scan 0, self-scan clean. Juliet floors + corpus pins referee in CI;
the CWE369 sampled hitrate and a possible floor raise land with the
lane's numbers.

## 2026-07-23 — Windows packaging: no more hard 7z requirement

The first external WINDOWS evaluation (native v0.4.5 build verified
end to end on a fresh machine, 682/682) left one MEDIUM:
`package_release.sh` hard-required `7z`, which fresh machines don't
have. The Windows arm now falls back to PowerShell `Compress-Archive`
(present on every Windows 10/11) when 7z isn't on PATH, and
windows.yml gained a second package rehearsal that PROVES the
fallback arm rather than trusting it: 7-Zip is masked out of PATH
(with a loud assert that the masking actually worked), packaging must
still produce the zip, and the zip must expand with codeskeptic.exe
inside. Also in this commit: the changelog's P1 entry is retitled to
v0.4.6 and reordered newest-first — the rebase over the sibling
Windows phases had left it labeled v0.4.5.

## 2026-07-23 — v0.4.6: the first external evaluation's P1

An evaluation run OUTSIDE this project's own loop — the maintainer's
macOS machine, a different AI toolchain, the docs/evaluate.md
protocol — confirmed the trust-chain surface end to end and caught
exactly the class of bug the protocol exists for: darwin binaries
baked the CI runner's versioned Xcode sysroot, so the no-compile-db
quickstart on a normal Mac silently analyzed NOTHING and printed
"Clean!" with exit 0. Fixed at both layers the report proposed:
runtime SDK resolution (SDKROOT verbatim -> cached xcrun probe ->
baked-if-exists; resolveMacSdkPath mirrors resolveResourceDir, with
the resolution order unit-tested) and a fail-loud exit policy
(all-TUs-broken -> exit 2 + ANALYSIS FAILED; partial breakage keeps
findings semantics — corpus flows depend on that; the Action already
escalates exit > 1 even in report-only). Fallout fixes the new policy
itself surfaced: broken-TU records deduplicated across
summary-inference re-parses, and a second positional path is now a
loud usage error instead of a silent no-op. macOS release smoke
gained the SDKROOT=/nonexistent -> exit-2 proof. 695 tests.

## 2026-07-23 — v0.4.5: the first native Windows binary

Packaging round (phase9-windows-package). `package_release.sh` gained
a Windows branch and runs under the runner's Git Bash: MINGW uname
normalization, `codeskeptic.exe`, `cygpath` for the clang resource
dir, zip via 7z, and no lib bundling at all — the official LLVM
windows-msvc dist is static-CRT, so the exe links only Windows system
DLLs (DEPENDENCIES.txt says exactly that). The release lane gained a
windows job (build → 682 tests → version/tag assert → package →
relocation smoke → draft upload) and publish now checksums all three
platforms' assets together. The relocation smoke is the Windows analog
of the Linux clean-container proof: C:\llvm — simultaneously the build
LLVM and the binary's baked resource-dir path — is renamed away and
the vcvars family stripped before the packaged exe must analyze
demo.c purely from its exe-relative bundled headers (the
GetModuleFileNameW branch added in Tier 1 doing its job) plus the
driver's own SDK discovery. The same package + smoke runs on every
push as a windows.yml rehearsal, mirroring how the Docker lane
exercises the Linux packaging path — packaging breaks at push time,
not tag time. The MSVC+LLVM bootstrap (cache, tarball, vcvars export,
DIA patch) was extracted to a local composite action shared by
windows.yml and release.yml so the two lanes cannot drift. README
flips the last "Planned" row: native Windows is now prebuilt-zip or
build-from-source, both CI-proven; version pins move to v0.4.5.

## 2026-07-22 — v0.4.4: the trust-chain round (critique-2)

Reproducibility gaps between LOOKING pinned and BEING pinned, all
verified against the repo before fixing: the Action's `version`
defaulted to `latest` (a pinned `uses:` ref still floated the
binary) — it now defaults to the action's own ref, with checksum
verification against the release's `sha256sums.txt` and a pinned
self-test lane asserting version identity after every release. The
clean-container smoke stopped installing the very libraries the
package claims to bundle (three releases of masking) and now proves
the self-contained claim via `ldd`: nothing missing, bundled deps
resolving from the package. README/Docker examples pin versions;
evaluate.md prerequisites rewritten for the binary/Docker era; FP and
evaluation issue templates added. Windows positioned honestly
(critique-3): a README WSL2/Docker section with the
compiler's-view caveat (`#ifdef _WIN32` branches are invisible under
WSL), a support table that separates "supported path" from "planned
native", and a windows-latest CI smoke that runs the Linux release
inside WSL against demo.c — the claim extends exactly as far as the
proof. No engine changes.

## 2026-07-22 — The real-world FP round: six root causes from the v0.4.2 scans

The post-release real-world scans (libgit2 v1.9.0 at 201 files,
rtp2httpd at current HEAD, via the new `realworld.yml` lane) reproduced
the stable core EXACTLY — the 23 triaged nulls, the 11 confirmed
OOM-path leaks, every deep-corpus pin — and surfaced 37 false
positives. Every one was adjudicated against upstream source, reduced
(where possible) to a local reproducer, and fixed at a ROOT — six of
them, across four engine rounds, each locked by both-direction pinned
tests (661 -> 683):

- **Correlation-miner entailment** (27 findings — every hashmap
  `__resize` expansion in libgit2, the khash `j`-flag shape): the
  disjunct-collapse miner tested compatibility and witness by EXACT
  fact key, blind to stamped equalities on other literals. Both tests
  now run through `factsContradict`'s stamp entailment; implication
  ACTIVATION got the same upgrade. Diagnosis burned three wrong
  hypotheses (widening memory, nested loops, condition misattribution)
  before segment-minimization pinned the disjunct-cap collapse.
- **Member fact keys** (the `if (c.has_x) produce; ... if (c.has_x)
  consume;` struct-field correlation had NO support at all — even
  `c.f = 1` directly above the guards false-positived). Dot-members of
  admitted local structs join the fact domain: keyed in conditions,
  stamped/erased flow-sensitively at field stores, erased wholesale at
  calls receiving `&c`, banned when `&c` escapes a call-argument
  position. Deliberate limit documented in PathFacts.h, mirroring the
  keyed-globals trade. Opt-in per analysis (`MemberFactScope`).
- **Implication payloads** (`condSt`): mined guards used to promise
  only NonNull; an out-param factory under a guard leaves the pointer
  UNKNOWN-not-proven-NonNull, which the cap-collapse decayed to an
  unrecoverable MaybeNull. Implications now carry the guarded state
  itself — "guarded absence of null-info" — and activation restores
  it. Default NonNull keeps every prior implication byte-identical.
- **Out-param success contracts** (the final msrc_res/fcc_res root):
  `rc = getaddrinfo(..., &res)` with rc == 0 GUARANTEES res non-null
  (POSIX). Contract-blind Unknown includes null, so the caller's OWN
  defensive `if (res && res->ai_next)` ambiguity check refined the
  short-circuit edge into a real-looking Null. The call now splits
  success{(rc EQ 0)=true, res NonNull} / failure{=false, res
  MaybeNull — the malloc bet}; an unchecked rc keeps the failure
  disjunct reportable. Curated: getaddrinfo, posix_memalign.
- **Miner slot discipline** (the chunked-decoder finding, diagnosed by
  state-dump instrumentation): the single implication slot went to a
  TAUTOLOGY — the pointer's own nullness key, first in FactKey order —
  shadowing the consumable length-contract candidate. Self-keys are
  skipped, and the witness runs in TWO passes: the original strict
  witness first (everything previously mined is mined identically — a
  one-pass loosening regressed the hashmap family and was caught by
  the local battery), then a complement-decider witness for the
  `if (!p && len > 0) return;` contract shape where no live path ever
  records the positive polarity.
- **scanf field-width blindness** (timezone.c ×3): `%2d` seeded the
  full int range, whose pseudo-finite endpoints doubled as overflow
  "witnesses". Conversions are now PAIRED with their arguments (`%*d`
  suppression included) and an explicit width bounds the seed
  (`%2d` -> [-9, 99], `%x`/`%o` by radix, `%n` non-negative).
  Widthless `%d` keeps the full-range untrusted model and still
  reports.
- **strlen-guard-blind bounds heuristic** (×6 — every one a correctly
  guarded copy): the CWE-120 message says "the source length is not
  checked"; the rule now actually looks. A `strlen(src)` of the same
  source expression in a dominating guard — the copy inside the
  guarded branch, or below a measure-and-exit if — suppresses;
  dst-only measurement, checks after the copy, measured-then-ignored
  and other-variable shapes all still fire.

End state, CI-verified on the frozen pinned versions: libgit2
61 -> **34** (exactly the stable documented core), rtp2httpd
12 -> **0**, all Juliet floors, corpus pins, the thesis gate and the
self-scan green throughout. 683 unit tests.

## 2026-07-20 — Config: untrusted length sources (`--untrusted-int-sources`)

Protocol/parser code reads a length or count field off the wire (a USB
descriptor, a packet header, a file-format field). Those reader function
names are project-specific, so they are configuration, not code. A listed
function's **return** is now treated as a full-range untrusted integer —
the exact discipline already applied to `atoi`/`strtol` — so a downstream
`n * k` that can escape its type is reported (CWE-190), while a guard
refines it and stays silent.

Designed to be reversible: the default is empty, so with no flag the engine
is byte-for-byte the previous behavior and every unit test and NIST Juliet
floor is unchanged. Re-hunt receipt: the full tinyusb device stack scanned
clean both without and with the flag on plausible sources — no new false
positives.

Honest limit (deferred, documented in `docs/untrusted-length.md`): the
source feeds the **int-overflow** rule today. Consuming an untrusted length
in the **bounds** rule — the `memcpy(fixed_buf, src, len)` catch, the real
protocol attack surface — is a separate increment, because it can shift
CWE-120/125 precision and must be validated against the Juliet floors in CI
before it lands.

### Added
- `--untrusted-int-sources <names>` flag and `untrusted_int_sources` config
  key; `setUntrustedIntSourceNames`/`untrustedIntSourceNames` registry.
- `UntrustedIntSourceTest.Configured_Reports`,
  `UntrustedIntSourceTest.NotConfigured_Clean` — the mechanism is on/off
  gated. 620 ctest total, shuffle-stable.
- `docs/untrusted-length.md` — design, reversibility receipt, deferred step.


## 2026-07-19 — Ablation: does CodeSkeptic cut tokens in an AI review loop?

Measured. CodeSkeptic's output is O(bugs), not O(lines): on a real-sized
file an agent processes far fewer tokens to locate the memory-safety bugs
(6–59x on 257–2417-line inputs), and gets a deterministic answer with a
trace instead of a probabilistic guess. Honest negative kept: on tiny files
(<~50 LOC) there is no saving — the findings payload costs as much as the
source.

### Added
- `scripts/token_ablation.py` — deterministic input-token footprint harness
  (baseline whole-file vs CodeSkeptic findings), with a controlled scaling
  series (bugs fixed, clean code grows).
- `scripts/token_ablation_live.py` — live harness (real model, real tokens +
  accuracy) to run with your own API key.
- `docs/token-ablation.md` + `docs/img/token-ablation.png` — the write-up,
  table, chart, and honest limits.


## 2026-07-19 — Guard: README comparison-table claims (Tier 1)

The README "How does it compare?" table asserts CodeSkeptic catches three
findings the everyday compiler warnings miss. Pin those cells so the claim
stays honest: if a change makes CodeSkeptic stop catching what docs/demo.c
or docs/custom.c show, CI turns red.

### Added
- `ReadmeCompareTest.DemoC_GetenvMalloc_NullDeref`,
  `ReadmeCompareTest.CustomC_HandWrittenNullReturner_NullDeref`,
  `ReadmeCompareTest.DemoC_AtoiOverflow` — the CodeSkeptic column of the
  comparison table, executable. 618 ctest total, shuffle-stable.

(Only our own cells are guarded — the external-tool cells are reproducible
by hand but not gated in CI, since a competitor's behavior across tool
versions is not ours to keep green.)


## 2026-07-19 — Regression pins: three open real-world bugs

Re-ran the current binary against the three real, still-open upstream
defects CodeSkeptic reported, and locked each in as a regression test so
recall on them is guaranteed by CI — a future change that stops catching
them fails the build.

### Added
- **`RealWorldReproTest.ShadPS4_4697_NullDescDeref_Reports`** —
  shadps4-emu/shadPS4#4697: `GetMaxPacketSize` dereferences a `desc`
  that stays null (passed by value). Definite null-deref (`error`).
- **`RealWorldReproTest.CarbonLang_7523_NullDeclContextDeref_Reports`** —
  carbon-language/carbon-lang#7523: `ExportClassToCpp` derefs the
  maybe-null `DeclContext` from `ExportNameScopeToCpp`. Interprocedural
  maybe-null (`warning`).
- **`MemoryLeakRuleExTest.TFLite_123387_Rfft2dWorkBufferLeak_Reports`** —
  tensorflow/tensorflow#123387: TFLite `rfft2d` leaks its FFT work buffer
  when a temporary-tensor lookup early-returns. Conditional leak
  (`warning`).

Test bodies are the real upstream functions reduced to minimal parseable
stubs (the sandbox cannot rebuild those projects' full compile databases).
615 ctest total, shuffle-stable.

## 2026-07-18 — Recall: null dereference through a libc call (#98)

The thesis-v3 miss `p07` — `strchr(getenv(x), ':')` — dereferences a
possibly-null pointer, but through a libc call rather than a `*p`/`p->f`
site, so the null-deref rule stayed silent. This closes that shape.

### Added
- **Passing a Null/MaybeNull pointer to a libc function that
  unconditionally dereferences that argument is a dereference by proxy.**
  A curated whitelist (`strlen`, `strcpy`, `strcat`, `strcmp`, `strchr`,
  `strstr`, `strdup`, `atoi`, `strtol`, `puts`, …) — functions whose
  contract makes the access certain, with NO length parameter that could
  be 0 to excuse it — is treated exactly like a direct deref: unguarded
  warns, a guard refines to NonNull and stays silent. Reuses the whole
  existing report path (severity ladder, report-flood dedup, traces).

### Receipts
- **thesis-v3 recall 9/16 → 10/16 = 0.625** (null-deref 2/3 → **3/3**;
  p07 now caught), **precision still 1.000** — the one unmatched finding
  remains the real `n06` scanf overflow, not an FP.
- **Juliet CWE476 unchanged: rprecision 1.000, fp=0** — the whitelist
  adds no false positives on the benchmark. 608→612 ctest with 4 new
  pins, shuffle-stable.

### Honest scope (known FNs)
- The dereferenced pointer must be a tracked VARIABLE. The inline form
  `strcpy(buf, getenv("X"))` — where the null source is the argument
  expression itself, not a variable — is not caught yet (follow-up:
  evaluate the argument's nullness, not just a variable's state).
- The n-bounded `mem*`/`strn*` forms are deliberately excluded: a 0
  length dereferences nothing, so they are not unconditional.
- A CUSTOM function that dereferences its parameter (VeraCrypt's
  `SetUserEnvPATH(getenv("PATH"))`) needs a per-callee "derefs-param"
  summary — a separate interprocedural follow-up.

## 2026-07-18 — Recall: scanf & getenv as untrusted sources (#97)

Data-driven increment from **thesis-v3** — a fresh 24-program blind AI
corpus (3 generator agents unaware of the rules, self-annotated ground
truth, 9 clean files). With the four prior recall rules active it
measured combined recall **6/16 = 0.375 at precision 1.000** (0 FP on 24
programs). Triaging the 10 misses showed 4 shared ONE root cause: the
value that flows into the bug comes from `scanf(&x)` or `getenv()`, both
unmodeled. This closes that cause with the same intrinsic-source recipe.

### Added
- **`scanf`/`fscanf`/`sscanf` output arguments are untrusted.** `&n` in a
  scanf call is filled from external text exactly as an `atoi` return is —
  now seeded with its type's full FINITE range (for int-overflow &
  bounds) and MaybeZero (for div-by-zero). `scanf("%d",&n); x/n` and
  `scanf("%d %d",&w,&h); w*h` now warn; a downstream guard refines and
  stays silent.
- **`getenv` / `fopen` family are null sources.** `getenv` returns NULL
  when the variable is unset; the fopen family on failure. An unchecked
  deref of the result warns (same #92 discipline as malloc); `if (p)`
  refines to NonNull.

### Receipts
- **thesis-v3 recall 6/16 → 9/16 = 0.562** (div-by-zero 2/4 → 4/4,
  int-overflow 1/2 → 2/2), **precision still 1.000** — 10 findings, all
  real (one, `n06` `r*8` from scanf, is a genuine overflow the generator
  did not annotate; not a false positive).
- All six Juliet floors unchanged and green: **CWE476 (getenv risk) and
  CWE369 (scanf-maybe-zero risk) both hold rprecision 1.000, fp=0.**
  602→608 ctest with 6 new pins, shuffle-stable. (Juliet filters the
  `fscanf` filename family, so the bare-`scanf` precision receipt is
  carried by thesis-v3's 9 clean files + the guard-refinement pins.)

### Honest negatives (known FNs, documented)
- **getenv through a libc call** (`strchr(getenv(x), ':')`, the corpus
  p07 sink) is still missed: the null-deref rule flags a DIRECT deref
  (`v[0]`, `*v`, `v->f`), not passing a maybe-null pointer to a libc
  function that dereferences it. Modeling which libc args are
  dereferenced is a separate follow-up. getenv on a direct deref is
  caught (verified).
- Remaining thesis-v3 misses are the genuinely harder classes:
  loop-write into a fixed buffer (p05), computed-index POSSIBLE OOB
  (n03/n06 — the bounds rule reports DEFINITE OOB only), cross-iteration
  / cross-function UAF (m04/m08), and leak on an error path (m07).

## 2026-07-18 — Recall: int-overflow from an untrusted source (#96)

Fourth application of the #92/#94/#95 recipe (from the thesis-v2 map,
where int-overflow recall was 0). CWE-190. Key on an INTRINSIC signal —
a text-parse call's result — never on caller data.

### Added
- **`int n = atoi(input); n * k` now proves overflow.** A parse-of-text
  source (`atoi`/`atol`/`atoll`/`strtol`/`strtoul`/`strtoll`/`strtoull`)
  puts no bound on its result beyond the return type, so the interval
  evaluator seeds it with that type's FULL FINITE range. A finite range
  multiplies into a provably-overflowing product (whereas the old top()
  collapsed every product back to top() and reported nothing). A
  downstream bound (`if (n < LIMIT)`) re-narrows the range on the guard's
  own edge, so validated input stays silent — precision holds by the
  same mechanism as #94's div-by-zero.
- **Constant-arithmetic guards now refine (Part 1).** An overflow guard
  written as `n < INT_MAX/2` (or `SIZE_MAX-1`, `1<<30`, a sizeof) folds
  through Clang's constant evaluator, so the guarded-safe branch narrows
  like a plain literal comparison. This closed a pre-existing false
  positive on such good sinks and is what keeps the new recall precise.

### Receipts
- **Juliet CWE190: 42 TP, 0 FP, precision 1.000** over the full
  3080-file corpus (400-file CI sample: rprecision 1.000, rhitrate
  0.010). NEW per-CWE floor added (0.95 / 0.005). All five prior floors
  unchanged and green — CWE369 (the other interval consumer) stays
  fp=0, confirming the atoi full-range does not leak into div-by-zero.
- 602/602 ctest incl. 4 new pins, shuffle-stable. Real-code boundary
  probe: guarded-atoi, `rand()%256 * k`, self-square, and 64-bit
  products all stay silent; only the unguarded `atoi()*2` fires.
- **Honest negatives (ablation).** (1) `rand()`/`random()` are excluded
  from the interval source set: their range is `[0, RAND_MAX]` and
  RAND_MAX is implementation-defined (as small as 32767), so a full-int
  over-approximation would false-positive on `rand()*k`. Zero measured
  recall cost — Juliet's rand family reaches the sink through the
  `RAND32()` bit-shuffle macro the interval evaluator cannot fold
  anyway. (2) Self-square `x*x` is skipped: its safe form is guarded by
  `abs(x) < sqrt(TYPE_MAX)`, which rests on `abs`/`sqrt` the integer
  refiner cannot fold — so a guarded-safe square is indistinguishable
  from an unguarded one, and reporting it would be an FP. Both are
  documented known FNs, not silent gaps.

## 2026-07-17 — Recall: unbounded string copy into a fixed buffer (#95)

Third application of the #92/#94 recipe (from the thesis-v2 map, where
bounds recall was 0). CWE-120.

### Added
- **`strcpy`/`strcat`/`stpcpy`/`gets` into a fixed-size array warns.**
  These functions carry NO length argument — the amount written is
  bounded only by the SOURCE, which the code does not check. The
  unboundedness is intrinsic to the FUNCTION (the #94 lesson: key on
  intrinsic signals, never caller-dependent ones), so keying on it
  stays precise. Restricted to genuinely fixed-size destinations (a
  local/global `char[N]` or a struct/union array member); heap
  pointers are excluded (the right-sized `malloc(strlen+1); strcpy`
  idiom must not FP). A string-literal source that provably fits is
  skipped.

### Receipts
- Thesis-v2 corpus miss recovered: `hash_djb2.c` `strcpy(n->key, key)`
  into `char key[32]` now flagged. Godot 175-TU C++: **0** (uses
  `String`, not fixed-buffer strcpy — no flood). tga clean; 598/598
  ctest incl. 4 new pins, 3-seed shuffle-stable. cJSON corpus measured
  in CI (a move, if any, is triaged TP-vs-FP before adjusting).
- Honest scope: v1 is the no-length-argument string family only. The
  memcpy-with-a-variable-length case (corpus `tokenize_fixed`) is a
  follow-up (Pattern B) — it needs the length's caller-dependency
  handled the way #94 handled the parameter divisor.

## 2026-07-17 — Recall: div-by-zero from untrusted input (#94)

Thesis test v2 (30-program blind AI corpus, 3 generator agents, broad
bug taxonomy) measured per-class recall on realistic first-draft code.
Result: unchecked-alloc null-deref (#92) is the ONLY class with real
recall (~45%); bounds, div-zero, int-overflow, leak, and UAF are all
~0. One root cause: the "prove-it-or-stay-silent" conservatism on
parameters / variables / loops.

### Added
- **A divisor parsed from an untrusted-input source is MaybeZero.**
  `atoi`/`atol`/`atoll`/`strtol`/`strtoul`/`strtoll`/`strtoull`/`rand`/
  `random` return a value that can intrinsically be zero (`atoi("0")`,
  `rand()`); assigned to a divisor and used without a guard → warning
  (CWE-369), while `if (n != 0)` / `if (n == 0) return` refines it to
  NonZero and stays clean. The div-by-zero twin of #92's known
  allocator — the zero-ness is intrinsic to the source.

### Ablation (rejected, documented)
- **A bare PARAMETER divisor was tried as MaybeZero and REJECTED.** It
  fails Juliet CWE369 precision (0.71 < 0.95 floor): the 26 FPs are all
  `goodG2BSink` — sink functions dividing by a parameter their caller
  already validated. Unlike malloc-null (intrinsic), a parameter's
  zero-ness is caller-dependent; an unguarded division by a parameter
  is a missing PRECONDITION (AssumptionRule's domain), not a
  div-by-zero bug. The intrinsic-source keying keeps precision.

### Receipts
- Juliet CWE369 rule-matched: **precision 1.000 (0 FP), recall
  0.053 → 0.228** (4.3×). Godot 175-TU C++: 0 div-by-zero FP. tga
  clean, dirty control warns; 594/594 ctest incl. 3 new pins.
- Honest scope: the corpus's own div-zero cases stay out of scope for
  principled reasons — `sum/n` on a double array is FLOATING division
  (inf/nan, not a crash — deliberately skipped); `num/gcd` divides by
  a LOCAL computed value (needs value tracking); `src_h/src_w` is the
  caller-dependent PARAMETER case above.

### Measurement (thesis v2, banked in ROADMAP 6.26)
- Per-class recall on 30 blind programs: null-deref ~45% (the #92
  win generalizes), **bounds/OOB 0, div-zero 0→(intrinsic slice now),
  int-overflow 0, memory-leak 0, UAF/double-free 0.** The map for the
  next recall increments (bounds unbounded-copy, malloc(a*b) overflow).

## 2026-07-17 — Recall: unchecked allocation, the #1 AI-code bug (#92)

The mission is an MCP server an AI calls in-the-loop to check its own
first-draft C/C++. A blind 12-program AI corpus (a generator agent
that did not know the analyzer's rules) put ~15 of its 23 real bugs in
ONE class: a `malloc`/`calloc`/`strdup`/`realloc` result dereferenced
with no null check (CWE-690/476) — and we caught none, because an
opaque call return is Unknown (silent by design, the anti-FP-flood
default that keeps mature codebases clean).

### Added
- **Known-allocator returns are MaybeNull, not Unknown.** A KNOWN
  allocator (`malloc`/`calloc`/`realloc`/`strdup`/`strndup`/
  `aligned_alloc`/`reallocarray` + the `--alloc-functions` wrappers) —
  never an arbitrary opaque return — now yields MaybeNull, handing the
  existing guard/refinement machinery its signal: an unguarded deref
  warns; `if (p)` / `if (!p) return` / `if (p==NULL)` / `p ? … : …` /
  `assert(p)` refines to NonNull and stays clean. Narrow by
  construction — the FP flood the NullDeref rule was built to avoid
  stays closed (arbitrary returns remain Unknown).

### Fixed
- **A bare `.c` file with no compile DB is now analyzed as C.** The
  fallback compilation database forced `-std=c++17` on every file;
  clang rejects that on a `.c` source, the TU failed to compile, and
  the broken-TU guard SILENTLY SKIPPED it — returning a false "clean".
  That is exactly the MCP-for-AI path (assistant hands the server a
  bare `.c` snippet). Fallback now picks the standard by extension
  (`.c` → gnu11, else c++17). Without this the new rule could never
  fire on the very inputs it exists for.

### Receipts
- Blind AI corpus (12 programs): null-deref findings **2 → 9**; the +7
  are all ground-truth-annotated unchecked allocations (base64 ×2,
  bst, csv_avg, json_tokens, lru_cache ×2) — real recall, not planted.
- FP discipline: Godot 175-TU core (C++): **0**; 6 guarded-allocation
  patterns: **0** null-deref; tga receipt clean, dirty control warns;
  592/592 ctest incl. 6 new UncheckedAllocTest pins. Juliet CWE476 +
  cJSON corpus measured authoritatively in CI (local suite download
  network-blocked this session).
- Methodology note: the corpus's first "0/23" score was a
  contamination artifact — the `.c` files were being force-compiled as
  C++ and skipped (the bug fixed above). Re-scored with a correct C
  compile DB, the honest before/after is 2 → 9.

### Juliet ground-truth correction (CI-driven)
- The rule flagged Juliet's CWE476 `null_check_after_deref` GOOD
  functions — which deref malloc with NO null check ("FIX: Don't check
  for NULL since we wouldn't reach this line if the pointer was NULL",
  which is false). Those good functions contain a real unchecked-alloc
  defect; the finding is a TRUE positive, so `juliet_eval` now EXCLUDES
  it (`isKnownLaxGood`, count printed for audit). This is a documented
  ground-truth fix, NOT a floor relaxation: the CWE476 precision floor
  stays 0.95 and fully sensitive to real regressions. Verified 32/32 of
  the new CWE476 null-deref "FPs" are exactly this class, 0 genuine FP;
  rule-matched precision holds at 1.000, recall rises to 0.347.

## 2026-07-17 — Leak rule: arena placement-new is not an owning allocation (#91b)

### Fixed
- **`new (arena) T` no longer reported as a leak.** The Carbon
  `call.cpp:108` FP surfaced by the 280-TU re-hunt:
  `new (ctx.ast_context()) CXXScalarValueInitExpr(...)` draws from an
  arena the ASTContext owns and frees en masse — the node is never
  individually `delete`d. Placement-new detection previously excluded
  only POINTER placement args (raw caller storage); a non-pointer,
  non-`std::nothrow` class/record placement arg now also designates
  managed storage. `std::nothrow` stays tracked (the one standard
  placement tag that still returns owned heap); `std::align_val_t`
  (enum) and scalar tags stay tracked too.

### Receipts
- Carbon 280-TU scan: **4 → 3** (call.cpp leak gone; nothing else
  moved). 2 new pins (arena by-reference + by-value clean);
  NothrowNew / PlacementNew / PlainNew pins unchanged; 586/586 ctest,
  shuffle-stable.


## 2026-07-17 — CHECK-macro transparency: Carbon's guard idiom opens (#91)

### Added
- **Identity-call transparency in the condition walk** (engine-wide):
  an exact-identity call — one parameter, VISIBLE body that is exactly
  `return <param>;` — is condition-transparent, the same class as
  `__builtin_expect` but proven by body instead of trusted by name.
  Carbon's `CARBON_CHECK` wraps every condition in such a wrapper
  (`CheckCondition(true && (cond))`, existing only to diagnose
  constant conditions); without the peel, neither the engine's
  assume-edges nor the guard-as-contract recognizer could read any
  CHECK. Transforming or declared-only wrappers stay opaque.
- **Guard recognizer: literal-true conjunct peel** (`true && x` → x)
  before the compound-condition bail; a VARIABLE conjunct still bails.
- **Transitive noreturn**: a call whose callee's visible body provably
  aborts is noreturn even without the attribute (depth-capped).
  Carbon's CheckFail carries `[[noreturn]]` only `#ifdef NDEBUG`, but
  its body is a single call to the noreturn CheckFailFormat.
  Deliberate limit: in Carbon's DEBUG parse the chain bottoms out in a
  declaration-only maybe-returning impl (non-fatal checks are a real
  debug build flag there) — the tool correctly infers nothing; scan
  with `-DNDEBUG` (shipped semantics) or `--fatal-asserts`.
- **Guard-violation dedup key includes the callee**: two same-line
  calls to different guarded callees are two violations, not one.

### Receipts (Carbon re-hunt, 280 TU — was 218 at #80)
- Ablation: old binary 7 findings → new binary same flags 7
  (transparency adds ZERO noise) → new binary -DNDEBUG **4**: the
  three `CARBON_CHECK(ptr)`-guarded FPs (import.cpp base_class,
  facet_type.cpp lhs_rewrite_value, lower/type.cpp previous_type) die
  exactly as predicted; nothing else moved.
- Survivors hand-classified: export.cpp:169 decl_context is
  TP-quality (callee has an explicit `return nullptr;` TODO path, the
  sibling variable is CHECK'd, this one is dereferenced unguarded);
  eval.cpp:2811 + import_ref.cpp:2548 are the KNOWN flag-encodes-
  nullness correlation gap (§6.22 family); call.cpp:108 is a NEW leak
  FP class — placement `new (arena)` treated as owning allocation
  (follow-up task).
- End-to-end probe through the real macro stack: caller passing
  `nullptr` into a CARBON_CHECK'd param → error, under -DNDEBUG.
- 8 new pins across recognizer + engine (identity peel; non-identity
  wrapper stays opaque; variable conjunct bails; transitive noreturn;
  returning body infers nothing; same-line dedup; engine clean/warn
  pair). 584/584 ctest, 5-seed shuffle-stable, tga/dirty unchanged.

## 2026-07-17 — Guard-as-contract v1: the callee's own entry guard, checked at the call site (#89)

### Added
- **`src/contracts/GuardContracts.{h,cpp}`** — recognize a function's
  LEADING entry guards and lift them into null-preconditions, no
  annotation required. Two shapes in v1: `if (<p is null>)
  <no-fallthrough branch>` (the ERR_FAIL expansion; a compound branch
  is decided by its last statement) and the glibc assert ternary
  (`cond ? void(0) : __assert_fail(...)`). Compound conditions
  (`!p && n > 0`) are structurally detected and skipped — lifting
  half of one would fabricate a requires the code does not enforce.
- **Severity by consequence class** (user decision): an assert-style
  guard vanishes in NDEBUG — a definite violating call crashes → new
  `ContractGuardCrash` ERROR. An if-return guard always runs — the
  callee refuses and the call silently does nothing → new
  `ContractGuardRejected` WARNING ("this call will always be
  refused"). EN/TR messages carry callee name + guard line.
- **Caller-side check in NullDerefRule**: memoized per-callee
  inference; DEFINITE violations only (literal null or flat-state
  Null) — zero possible-violation noise in v1; a param covered by a
  DECLARED contract defers to the author's clause (no double report);
  callers with no pointer locals still wake the pass.

### Scope (user decision)
- v1 is the compiler-silent slice only: null preconditions. Narrowing
  / int64→int32 mismatches are `-Wconversion` territory and excluded
  — no overlap with compiler warnings. Extensions (possible
  violations, relational guards, cross-TU) wait on verdict.

### Fixed (the cJSON lesson — caught by the corpus referee)
- **A SILENT early return is not a contract.** First CI run: cJSON
  corpus pin 53 → 88; all 35 extras were `if (item == NULL) return
  false;`-shaped "violations" — but those are null-TOLERANT APIs
  (`cJSON_IsInvalid(NULL)` → false is the documented answer;
  `cJSON_InitHooks(NULL)` MEANS "reset to defaults"), and their
  callers pass null on purpose. Refusal evidence now requires the
  guard to COMPLAIN before returning (an error-report call, then the
  return — exactly Godot's ERR_FAIL expansion) or to die
  (assert/abort/throw). Work-then-return (InitHooks) and bare returns
  (cJSON_Is*) infer nothing. 2 new soundness pins; corpus pin stays
  at 53 — the feature narrowed, the referee floor did not move.

### Receipts
- End-to-end: `crash_callee(nullptr)` → error naming the callee's own
  assert line; `reject_callee(nullptr)` → warning; declared-contract
  param single-reports; clean calls silent.
- 8 new pins incl. compound-guard-not-lifted and non-entry-guard-
  ignored soundness pins; 574/574 ctest, shuffle-stable;
  tga/picojpeg receipts unchanged.
- Godot 6-file noise check: **0 new findings** — mature in-tree
  callers don't violate their own guards; the feature targets
  AI-generated callers of guarded APIs and costs nothing in-tree.


## 2026-07-17 — Facts: an unsigned loop bound proves itself nonzero (#87)

### Added
- **`X < n` (both operands unsigned) proves `n != 0` on the true
  edge.** Nothing is unsigned-less-than zero, so if any value sits
  below n then n >= 1. Recorded as a TRUE-EDGE-ONLY fact (never
  flipped — the false edge `X >= n` carries no n==0 information), so
  it lives beside the flippable `conditionFact`, not inside it. On a
  loop body edge `for (i = 0; i < n; ++i)` this refutes any disjunct
  carrying the `n == 0` fact — the body is unreachable when n == 0.

### Fixed
- **The relational `requires p != null unless n == 0` escape no longer
  FPs through a loop.** The escape disjunct (n==0, p free) is dropped
  on the loop body edge, so a deref of p inside `for (i < n)` is clean.
- **The round-1 Godot `FileAccess::store_buffer` FP is dead, no
  contract needed** (`if (!p_src && p_length>0) return; for (i <
  p_length) use(p_src[i])`): the loop-bound fact completes the
  disjunction elimination `p_src || p_length==0` that the guard leaves,
  which the engine could not close before (var-vs-var loop bound).

### Receipts
- Godot core/io/file_access.cpp: **1 → 0**.
- Soundness pinned: the nonzero fact is per-disjunct on the iterated
  path — a genuinely-null p dereferenced AFTER the loop (n could be 0)
  still warns; a SIGNED loop bound infers nothing (X<n with n==0 holds
  for negative X). 4 new pins; tga/picojpeg unchanged; 566/566 ctest,
  shuffle-stable.


## 2026-07-17 — Contracts: `requires` proof burden survives partial guards

### Fixed
- **`requires p != null` now discharges its proof burden through a
  compound guard.** Discovered demonstrating the contract layer on
  Godot's `FileAccess::store_buffer` (`ERR_FAIL_COND_V(!p_src &&
  p_length > 0, ...)`): a seeded NonNull was fabricated back into a
  "may be null" by the short-circuit fall-through of `if (!p && cond)`,
  where `!p` held (p null) and `cond` did not. Clang routes p-is-null
  through to the dereference; the refinement OVERWROTE the seed with
  null instead of DROPPING the now-contradictory disjunct. A leaf-level
  domain-contradiction drop (the disjunct's established NonNull refutes
  the `!p`-true leaf → drop, exactly as a fact contradiction drops)
  closes it. This is the leaf-refute mechanism prototyped during #84
  and set aside for lack of a receipt — the contract demonstration is
  the receipt.

### Receipts
- `requires p != null` on `int f(T*p, unsigned n){ if(!p && n>0)
  return -1; return p->x; }`: 1 → 0. The no-contract control (p from
  an opaque source) still warns — the n==0 path is a genuine deref;
  the drop is scoped to an established/seeded NonNull.
- End-to-end on a store_buffer-shaped TU: the callee dereference
  clears AND a caller passing `nullptr` is flagged as a contract
  violation — the keystone relational-contract loop working on the
  shape drawn from real Godot code.
- 2 new pin tests; 562/562 ctest, shuffle-stable.

### Known gap (recorded)
- The RELATIONAL escape (`requires p != null unless n == 0`) still FPs
  when the guarded deref is inside `for (i < n)`: proving the loop body
  unreachable when n==0 needs the loop bound `i < n` connected to the
  `n == 0` fact (var-vs-var), which `conditionFact` does not key. This
  is the round-1 file_access "null + zero-length loop" class — the
  measured next lever.


## 2026-07-17 — #86: Godot hunt opens — static-local model + broken-TU guard

### Fixed
- **Static locals are once-per-program, not per-call.** Godot's GDCLASS
  double-checked lazy-init (`static T *inst = nullptr; static bool
  initialized = false; if (initialized) return *inst;`) produced a
  "definitely null" ERROR at every expansion site: the decl-inits were
  modeled as a per-call assignment plus a per-call fact stamp. Statics
  now decay to Unknown at their DeclStmt (NullDeref, DivByZero, fact
  stamps); mid-call assignments still track. Honest trade: a
  first-call-only null deref through a static goes silent — cross-call
  state is out of scope.
- **Broken-TU guard.** A TU whose parse ends in an uncompilable error
  is now SKIPPED with an honest per-file coverage note instead of
  analyzed through clang's error recovery — recovery eats initializers
  and declarations, and rules then report confidently about code that
  does not exist. `--analyze-broken-tus` restores the old behavior.

### Receipts
- Godot core/, 176 TUs: first scan (missing generated headers, broken
  ASTs) yielded 311 findings — 298 uninit-ptr ERRORS all artifacts.
  With the generated headers built and the two fixes: **0 broken TUs,
  18 findings** (15 null-deref + 3 div-by-zero warnings), a hand-
  triageable table over one of the most-used C++ codebases alive.
- Triage: 3 findings in gdextension.cpp share one shape — the author's
  own `p_object && ...` placeholder guard proves the parameter is
  considered nullable, then the non-static path dereferences it
  unguarded (the shadPS4 sibling-evidence class; upstream-report
  candidate). 9 in convex_hull.cpp (dense pointer-list geometry,
  next round's deep verify). 3 image.cpp div-by-zero via the callee
  may-return-zero summary. 1 file_access.cpp null+zero-length loop —
  a measured FP class (var-vs-var loop bound, `i < p_length` with the
  (p_length <= 0) fact in hand but no var-vs-var edge keying).
- 8 new tests (4 static-local pins, 4 BrokenTuTest); 560/560 ctest.


## 2026-07-17 — #85: toolchain moved to LLVM/Clang 20

### Changed
- **CI and recommended build now use LLVM 20** (ubuntu-24.04 packages;
  `-DCMAKE_PREFIX_PATH=/usr/lib/llvm-20`). Zero source changes — the
  LibTooling surface the analyzer uses is identical between 18 and 20,
  and LLVM 18 still builds (README documents both).
- Referee parity on 20: 552/552 ctest, 551 single-process, 12/12
  shuffle seeds, corpus pins intact; tga/picojpeg receipts unchanged.

### Receipts
- **Carbon parse ceiling: 218/286 → 280/286 TUs** (comparative
  `-fsyntax-only` sweep over the same include set). The entire
  63-TU "non-static data member cannot be constexpr" class — which
  locked us out of `toolchain/check/` and `lower/`, exactly where the
  real-world crash cluster lives (ROADMAP 6.16) — parses with the
  clang-20 frontend. The 6 remaining failures are infrastructure
  (Bazel-generated headers: runfiles/gmock/.inc/GPLATFORM), not
  language level.
- First analysis through the opened door: `toolchain/check/call.cpp`,
  previously rejected, now analyzes end-to-end (11 findings, all in
  dependency headers — `--report-paths` territory).

## 2026-07-16 — #84: implication witness — the #70 residual is dead

### Fixed
- **The verbatim `stbi__tga_load` false positive (stb_image.h:6004,
  our longest-lived real-world FP) is gone.** The #70 miner's
  non-vacuousness gate accepted only an EXPLICIT `key=wanted`
  recording as its witness; in the tga loader the guard's
  "wanted" side survived the mid-loop collapses only INSIDE
  already-mined implications (the prologue tests `indexed` early, so
  explicit recordings all carried `indexed == 0`), and the gate
  silently discarded a still-valid implication at 1585 of 1591
  collapses. An implication-carrying input now counts as a witness —
  it is proof a real partition mined the implication upstream.
- One-condition diff by ablation: two other principled candidates
  (refinement-keeps-implication; leaf-level domain-refuter disjunct
  drop) and two engine mechanisms built along the way (narrowing pass
  after the widened fixpoint; two-stage widening) were each measured
  to contribute NOTHING to the receipt and were dropped — mechanisms
  ship with receipts or not at all. The narrowing experiment's lesson
  is recorded in ROADMAP 6.19: temporal blends are self-consistent,
  so a descending pass cannot undo them.

### Receipts
- Verbatim stbi__tga_load standalone: 1 → 0. stb corpus per-TU:
  tu_image.c 1 → 0; tu_resize.c 2 → 2 (different, pre-#70 class —
  honest residual); all 8 #70 negative controls still warn.
- The full trimmed loader is pinned as a regression test that fails
  without the witness clause (verified against the pre-fix binary).
- 552/552 ctest, 551 single-process, 12/12 shuffle seeds.

## 2026-07-16 — #70: guard-implication mining (independent guards stop cross-multiplying)

### Added
- **Widening correlation miner**: the moment a disjunct collapse is
  about to erase a guard correlation, the miner records it as a
  per-variable implication — `flag != 0 ⟹ ptr NonNull` — on the
  collapsed value (`NullVal.fact`/`factVal`). N independently guarded
  pointers now cost N implications inside ONE disjunct instead of 2^N
  disjuncts, which `kMaxDisjuncts = 4` could never hold. Mining rule:
  a fact F and value v qualify when EVERY pre-collapse disjunct
  compatible with F=v (recorded F=v, or F unrecorded — such a
  disjunct's paths may carry either value, so it must qualify on both
  sides it joins) knows the pointer NonNull, directly or via the same
  implication. Consumption on assume-edges: a disjunct that records
  F=v sharpens the pointer to NonNull. Invalidation mirrors the fact
  lifecycle: assignment to the pointer or to the guard variable drops
  the implication.
- **Fact-aware same-facts meet** (`GuardedOps.meetVal`): two disjuncts
  with an identical fact map now combine UNDER that map — an
  implication whose condition the shared facts contradict holds
  vacuously and survives. The fact-blind merge had to drop it, and
  one such drop re-merged into every later join until no implication
  survived anywhere (13 seed drops → ~1300 downstream on stb_image's
  tga loader).
- Shared machinery: `GuardedOps` bundle + `widenGuardedOps` /
  `normalizeGuardedOps` / `mergeGuardedOps` / `applyStmtFactsOps` /
  `refineGuardedFactsOps` in engine/GuardedDisjuncts.h. The plain
  variants are untouched — MemoryLeak/DivByZero behavior unchanged.

### Receipts
- **Repro battery** (scratchpad fp70): the 4-independently-guarded-
  pointer scale shape **5 warnings → 0**; the single-guard TGA shape
  with RLE/read-next loop noise → 0; call-initialized and
  assignment-derived guard flags → 0. Negative controls all still
  warn: wrong guard, guard reassigned in loop, pointer nulled in
  loop, unguarded deref.
- **Recall win**: `if (fa) a = alloc(); if (fa) return a[0];` with NO
  failure check was silent before (false negative) — the sharper
  disjuncts now carry the MaybeNull to the deref and it warns.
- **Honest residual**: the full stbi__tga_load function STILL yields
  its 1 warning (stb corpus 1 → 1 vs main). The verbatim-extracted
  function reproduces it; the mechanism is NOT the guard cross-product
  (that is fixed — the reduced shapes are clean) but iterate-mixing in
  the engine's ACCUMULATIVE widening: widenMemory joins states from
  different fixpoint iterations, one of which lost the implication
  before it matured, and the poisoned copy re-enters every later
  collapse. Measured evidence: deleting the post-deref inverted-swap
  loop (or merely renaming its reused `i`/`j` counters) makes the
  warning vanish — the report is order/iterate-dependent, not
  value-domain-dependent. Next lever recorded in ROADMAP: a narrowing
  (descending) pass after the widened fixpoint, or provenance-carrying
  implications.
- 8 new GuardImplicationTest units; 551/551 ctest, 12/12 shuffle
  seeds; stb 5-TU corpus scan time 1.8 s → 1.3 s (no perf cost).

## 2026-07-16 — #69b: value-conditioned null-return summaries

### Added
- **Summaries can now say "returns null ONLY IF param #i is outside
  interval R"** (`nullCondParam`/`nullCondRange` on FunctionSummary).
  Harvested structurally from the two guard shapes that dominate real
  code: `switch(param)` where every case returns non-null and only the
  default returns null (case constants must be CONTIGUOUS — the safe
  zone must be one interval), and a single `if (param REL const)`
  comparison guarding the sole null return. Discipline: the function
  must have EXACTLY one structurally-null return, every other return
  provably non-null, and the parameter never mutated — anything else
  keeps the plain MaybeNull verdict (sound).
- **Sole-definition intervals** (`soleDefIntervals`): an integer local
  whose only write is its initializer (or exactly one plain `=` when
  declared uninitialized — the `uint8 tableIndex; tableIndex = ...;`
  C idiom) holds that value at every read, so callers can evaluate
  masked index expressions flow-insensitively:
  `int idx = ((x>>3)&2) + (x&1)` → [0,3].
- **Value-based narrowing-cast fit** in `evalInterval` (ctx-aware
  overload): a narrowing IntegralCast whose OPERAND interval already
  fits the destination type's range passes through (it cannot wrap);
  otherwise top() as before. Type-blind rejection was the last gap:
  `uint8 idx = smallExpr` erased a provably-in-range value.
- Summary disk format bumped to **v3** (5th column `paramIdx:lo:hi`,
  `~` = infinity, `-` = no condition). Version-strict field counts:
  a v1/v2 file with 5 fields is corrupt, not silently accepted.
  `mergeConservative` drops the condition when two TUs disagree.

### Receipts
- **picojpeg (real source, 2325 lines): 1 → 0 findings.** The one
  finding was our oldest known FP: `getHuffVal(pHuffVal, idx)` where
  every call site computes `idx` from masked bits (provably in the
  switch's safe zone) — now proven non-null via the condition.
  All negative controls still warn: unprovable args, out-of-range
  constants, non-contiguous cases, fallthrough defaults, mutated
  params, reassigned locals.
- **ImGui: 14 → 14, honestly no change.** The remaining GetFontBaked
  cluster's null root is the opaque `ImFontAtlasBakedAdd` (no body in
  the TU) — not a parameter-conditioned return; out of #69b's scope
  by design, stays on the board.
- 11 new ConditionedNullTest units (clean/dirty pairs per bail-out) +
  cross-TU condition travel + v3 file roundtrip; 543/543 ctest,
  12/12 shuffle seeds.

## 2026-07-16 — --report-paths: dependency-header noise filter

### Added
- **`--report-paths <paths>`** CLI flag / `report_paths` config key:
  only findings under the given path prefixes are reported (comma
  list, canonical-path prefix match). The Carbon scan lesson: 15 of 16
  findings were in LLVM dependency headers pulled into the TUs — noise
  for the project being scanned. Analysis itself is unaffected;
  filtering happens in the reporting pipeline next to
  suppression/baseline, with a count message when findings are
  dropped. Unset = report everything (unchanged default). Peer:
  clang-tidy's --header-filter.

## 2026-07-16 — Engine: assert's ternary no longer leaks the null disjunct (#79)

### Fixed
- **`assert(A && B)` between a null guard and a dereference no longer
  re-introduces a maybe-null disjunct.** glibc's C++ assert expands to
  `static_cast<bool>(expr) ? void(0) : __assert_fail(...)`; the
  EXPLICIT static_cast is invisible to IgnoreParenImpCasts, so every
  condition digest (edge refinement, the nullness walk, disjunct-fact
  keying) stopped at the cast and refined nothing — the maybe-null
  disjunct born on the `&&`'s short-circuit edge then sailed past the
  noreturn arm into the guarded code (found on ImGui: every IM_ASSERT).
  New shared `stripBoolPreservingCasts` applied at all three digest
  points, next to the __builtin_expect transparency.
- The strip is TYPE-based, not CastKind-based, deliberately: Clang
  marks the explicit node of `(char)x` CK_NoOp and hides the narrowing
  in a `part_of_explicit_cast` child, so a kind-based strip would
  "prove" x zero from `!(char)x` while x=256 takes the same branch
  (caught during development by a negative control, now a pinned test).
  Safe cases only: casts TO bool (truthiness preserved by
  construction) and pure same-type no-ops.

### Receipts
- ImGui whole-program: 18 → 14 null-deref warnings, zero new findings;
  all four killed are the IM_ASSERT-compound shape (SetCurrentFont,
  ListClipper_StepInternal, BringWindowToDisplayBehind,
  TableSetColumnWidth).
- 5 new unit tests (assert-ternary clean with/without outer guard,
  static_cast<bool> guard refines, assert-on-OTHER-variable keeps the
  unguarded report, narrowing-cast false-proof pinned).

## 2026-07-16 — Leak rule: modern-C++ ownership-escape FP fix (#75)

### Fixed
- **Owning-smart-pointer adoption** no longer reports a leak. A raw
  pointer adopted by constructing `std::unique_ptr` / `shared_ptr` /
  `auto_ptr` (built-in) — or a project wrapper registered via the new
  `--owning-pointers` allow-list (Jolt `Ref<T>`, `RefPtr<T>`,
  `scoped_refptr<T>`) — is modeled as an escape, whether returned or
  adopted into a local. Deliberately a name allow-list: non-adopting
  views and copying wrappers still leak.
- **Scope-guard / closure capture** no longer reports a leak. A tracked
  pointer captured by a lambda (`[&]{ Free(p); }`, `[p]{...}`) escapes —
  the closure body is opaque and may free/store/transfer it
  (JPH_SCOPE_EXIT, absl::Cleanup, Eigen `[ctx]{delete ctx;}`).

### Added
- **`--owning-pointers <names>`** CLI flag / `owning_pointers` config
  key: names treated as owning smart-pointer wrappers by the leak rule.
- 10 leak-rule unit tests: adoption cleared; genuine leak beside an
  adoption, an unconfigured wrapper, and a non-capturing lambda all
  still reported (the suppression is conservative and per-variable).

Cross-verified on TensorFlow Lite (unique_ptr returns) and JoltPhysics
(Ref<T> returns, scope-guard lambdas). Pure suppression, no CWE401
Juliet floor risk (Juliet is C).

## 2026-07-14 — IntervalEval + IntervalAnalysis: the numeric dataflow

### Added
- **`engine/IntervalEval`** — reusable interval evaluation over the
  AST: `evalInterval` (expression → interval; literals, tracked reads,
  unary +/-, binary + - *), `applyIntervalAssign` (assignment
  transfer), `refineIntervalOnEdge` (guard constrain via the shared
  ConditionWalk skeleton). Soundness carries from Interval: unknown
  forms and unmodeled assignments → top(); a NARROWING integral cast
  → top() (it can wrap, so its value set is not a subset — passing it
  through would be unsound).
- **`engine/IntervalAnalysis`** — the interval lattice run over a
  function's CFG via the shared DataflowEngine, recording the entry
  range-state at every statement so consumers can ask "what range does
  v hold at s?". Convergence via widening (a re-visited loop value not
  pinned to a constant collapses to top(); the post-loop guard edge
  then re-narrows the branch). Purely observational — it never
  reports; consumers own all reporting.
- 7 direct analysis tests (constant/arithmetic/branch-join/guard
  lower-bound/guard-range/unknown-top/loop-widening-terminates) +
  the IntervalEval logic exercised through them.

### Not wired into a rule yet — and why div-by-zero was NOT the consumer
- The first planned consumer was div-by-zero, but it produces **no
  measurable change**: ZeroState's generalized bound refinement (the
  tmux round) already covers the zero domain, and arithmetic drives
  ZeroState to Unknown (silent) rather than a false MaybeZero — so
  there is no false alarm for an interval to suppress. Adding a second
  per-function pass for zero net effect would be dead weight, so it
  was dropped. The interval's real payoff is RANGES: the integer-
  overflow rule (next) and the bounds rule (heap-overflow class) are
  the genuine consumers.

### Verification
- 426 → 433 tests both modes; corpus pins exact; analysis behavior
  byte-identical (no consumer yet).

## 2026-07-14 — Interval lattice v0: the numeric foundation opens

The engine's lattices were all SYMBOLIC (null? freed? zero?); none
numeric. Spatial safety (buffer/heap overflow) and integer overflow
are quantitative, so they were architecturally out of reach. This is
the foundation for reaching them (CAPABILITY_REPORT: value-range is
the keystone).

### Added
- **`engine/Interval`** — a sound over-approximating integer interval
  `[lo,hi]` with ±∞ endpoints and an empty (⊥) case. Soundness is
  absolute: an Interval contains EVERY real value; any operation that
  cannot preserve that cheaply returns top() (never a too-narrow
  interval — a false "safe" is worse than a miss). Lattice ops
  (join/meet/widen), saturating arithmetic (add/sub/mul/negate; any
  int64 overflow collapses to top(), so wraparound can never fool a
  bound), guard refinement (constrain lt/le/gt/ge/eq/ne), and the two
  consumer queries the next rounds need: `isKnownNonZero()`
  (div-by-zero) and `fitsSignedBits(n)` (integer overflow).
- 28 unit tests pinning the soundness invariant, incl. overflow
  collapse (INT64_MAX+1 → top, not a wrapped small number), the
  malloc(a*b) product query, and loop-widening termination.

### Not yet wired
- No rule consumes intervals yet — analysis behavior is byte-identical
  (Juliet floors + corpus pins unaffected by construction). The
  consumers land next: IntervalAnalysis, then sharpened div-by-zero,
  then the int-overflow and bounds rules.

### Verification
- 398 → 426 tests both modes (+28 interval units); corpus pins exact.

## 2026-07-13 — Two precision fixes surfaced by the tmux scan

Scanned tmux (mature, heavily-audited C) — clean of real bugs, but
it surfaced two clean, near-term false-positive classes, both fixed
test-first:

### Fixed
- **Static/thread-local pointers are no longer treated as
  uninitialized** (UninitPointerRule): C zero-initializes
  static-storage-duration objects, so `static char *buf;` starts as
  NULL (defined), not indeterminate — its null-ness is NullDeref's
  domain. The matcher now excludes static and thread storage
  duration; only automatic-storage locals without an initializer are
  tracked. (tmux `screen_print`/`buf` behind an `if (buf == NULL)`
  guard: 5 FPs → 0.)
- **DivByZero refinement generalized to any zero-excluding bound**
  (not just comparisons against 0): on a branch edge the holding
  constraint `var <op> c` proves `var != 0` whenever 0 does not
  satisfy it — so `if (n <= 1) return;` now leaves `n` NonZero on the
  fall-through. Subsumes the old zero-constant behavior; restricted
  to `c >= 0` so the signed 0-vs-c test matches the real (possibly
  unsigned) comparison. (tmux `layout_spread_cell`/`number`: 1 FP → 0.)

### Verification
- 398/398 tests both modes (+8: static-pointer no-warn ×2 +
  automatic-still-warns; divzero `<=1`/`<2`/`>=1` bounds, zero-const
  regression, unproven-path still-warns).
- Juliet floors byte-identical (CWE369 1.000/0.050 unchanged — the
  generalization is behavior-preserving); corpus pins exact.
- tmux re-scan: 72 → 66 findings (the 6 fixed FPs gone). Remaining:
  1 loop-bound-is-array-size FP (`nitems()`, value-range, engine-v2)
  and 5 error-recovery artifacts in compat/setenv.c (undeclared
  `environ` under fallback flags — scanned out of its build context;
  a scan-hygiene note, not an analyzer FP). No upstream report: no
  real bug.

## 2026-07-13 — Second upstream finding MERGED (shadPS4 #4703)

A second shadPS4 finding was fixed and merged upstream: issue #4696
(`sceSaveDataMount/Mount2` null-checked a pointer with `&&` where it
needed `||`, so the guard fell through and dereferenced the pointer
it had just checked for null) closed via PR #4703 — the canonical
looks-right-reads-wrong bug. Two of the three shadPS4 findings are now
merged (#4702 internal__Foprep, #4703 sceSaveDataMount); #4697
(usb_backend GetMaxPacketSize) still open. Proof points updated:
README real-world table (shadPS4 -> "2 merged (#4702, #4703)") + the
"Confirmed in the wild" callout now leads with the &&/|| bug;
RELEASE_NOTES.md and both v0.1.0 drafts likewise.

## 2026-07-13 — Kyty scan: clean of real bugs, one engine-v2 repro captured

Scanned Kyty (PS4/PS5 emulator, InoriRus) — 104 core files, clean
run (2 fatal errors were just missing generated/vendored headers,
isolated to 2 files; the project's `analyzer_noreturn` exit handlers
declared via `--fatal-asserts` collapsed the potential EXIT_IF
flood). No real bug: the 3 findings were all false positives (1 in
3rdparty stb, 2 twin FPs in Kyty's JSON parser). The two JSON FPs
trace to one clean, minimal limitation — **passthrough/identity
nullness** (`skip(p)` returns null iff `p` is null, but our
ReturnNullness lattice can't express it) — recorded in todo.md as an
engine-v2 summary-extension repro. No upstream report filed: no real
bug, and reporting an FP would burn credibility.

## 2026-07-13 — First upstream finding MERGED (shadPS4 #4702)

The `internal__Foprep` null-dereference we reported to shadPS4
(issue #4698) was fixed and merged upstream (PR #4702): the function
set `ENOMEM` on file-table exhaustion but fell through without a
`return`, dereferencing the null `FILE*` — exactly the shape the
dataflow trace described. The maintainers added the missing
`return nullptr;`. Recorded as a proof point:
- README real-world table: shadPS4 row now reads "3 reported
  upstream — 1 merged (#4702)", plus a "Confirmed in the wild"
  callout under the table.
- RELEASE_NOTES.md: a "Confirmed in the wild" section.
- Both v0.1.0 release-note drafts (contracts-headline / -preview)
  carry the same proof point.

## 2026-07-13 — Self-scan dogfood gate in CI

### Added
- **CI self-scan step**: the analyzer analyzes its own 30 source
  files on every PR, with `--policy no-absolute-paths` active (the
  founding policy applied to ourselves). Exit 0 required — any
  finding, including a hard-coded absolute path, fails CI. First
  run: clean (0 findings, 0 fatal errors). Known residue: 2 unique
  template functions in the guarded-disjunct machinery emit
  non-convergence warnings across instantiations — the same
  template-instantiation shape as llama's nlohmann residue (stderr
  only, FN direction, engine-v2 queue).

## 2026-07-13 — Pre-release sweep: --files papercut + todo truth pass

### Fixed
- **--files papercut**: a missing list file is now its own error
  ("--files list not found: <path>", exit 1) instead of silently
  leaving the set empty and surfacing as the generic usage message
  (the systemd 20-minute scan-diff hunt, immortalized).

### Changed
- todo.md truth pass before going public: shipped items checked off
  with what/when (README benchmark section, correlated-guards v2b,
  both report-flood dedup entries), the 2026-07-10 session plan
  archived, libgit2 triage numbers refreshed to the current 44, the
  rtp2httpd draft annotated with the Thursday filing plan.

### Verification
- 390/390 tests both modes; corpus pins exact; Juliet floors green.

## 2026-07-13 — Summary-diff gate flag + README truth fixes

### Added
- **`--gate error|warn`** (CONTRACTS.md §5, the last unimplemented
  spec row): `--gate warn` (or `summary_diff_gate = warn` in
  .codeskeptic.conf) keeps the full WEAKENED report but exits 0 — the
  adoption ramp for projects not ready to break CI on
  inferred-contract drift. Default stays `error` (exit 1). An
  unreadable summary file is exit 2 REGARDLESS of the gate: a gate
  that cannot read its input must never look green. Invalid gate
  values are rejected at argument parsing.

### Fixed
- README real-world table: the fprime row now shows the verified end
  state — 10 -> 0, clean with `--fatal-asserts SwAssert` (the
  delta-debugging round of 2026-07-12/13 eliminated the last two:
  unsigned zero-identities + the assert-handler declaration).

### Verification
- 390/390 tests in both modes (+1: gate-warn reports-but-exits-zero,
  unreadable-input stays exit 2 under warn).
- CLI smoke: default exit 1, `--gate warn` exit 0 with identical
  report text, `--gate bogus` rejected with a usage message.
- Juliet floors and corpus pins green (the gate lives in the
  summary-diff mode, before any analysis path).

## 2026-07-13 — Contracts Round E: policies + sidecars — v1 complete

### Added
- **Policy engine** (rule_id `policy`): `cs:policy` pattern
  prohibitions under the shared contract surface. v1 ships
  `no-absolute-paths` — a hard-coded absolute path in a string
  literal is an error. The founding Ruledsl release incident (a
  hard-coded rules path that crashed every machine but the dev box)
  is now a machine-checked rule. Activation: a `// cs:policy` comment
  scopes to its file; `policy = <name>` in .codeskeptic.conf or
  `--policy` activates project-wide. Unknown policy names are
  contract-syntax errors (a policy that silently fails to activate
  would be a false comfort); `cs:ai policy` activation downgrades
  violations to warnings. The path heuristic is conservative (>= 2
  segments, no whitespace, or a Windows drive root); macro-born
  literals (__FILE__) are skipped.
- **Sidecar contracts** (`src/core.c` -> `src/core.c.csk`): contracts
  for code you cannot annotate. Every entry is EXPLICITLY anchored
  (`vendor_find: requires id != 0`; optional `/arity` for overloads)
  — position-based mapping is forbidden by design. Sidecar clauses
  merge into the same enforcement pipeline (`allContractClausesForDecl`):
  requires seeding, call-site checks and guarded-ensures checks work
  identically; ContractRule reports sidecar findings AT the .csk
  file/line, and malformed sidecar lines are contract-syntax errors,
  never silently dropped. The cache is process-lifetime with a
  per-run clear (the MCP server must see an edited .csk).
- **README contracts section** + contract/policy rows in the rules
  table.

### Verification
- 389/389 tests in both modes (+13 Round E: path heuristic unit,
  file-comment activation, no-policy silence, non-path literals
  silent, unknown-name syntax error, profile-wide activation, cs:ai
  downgrade, sidecar text parse unit, sidecar requires at call site,
  sidecar ensures pointing at the .csk line, arity anchor, malformed
  lines reported, missing sidecar no-effect).
- Juliet floors and corpus pins green (byte-identical; policies and
  sidecars activate only where declared).
- Dogfood: the founding incident itself —
  `fopen("/home/tanzer/projects/ruledsl/rules.dsl", "r")` under
  `cs:policy no-absolute-paths` -> error at the literal; a sidecar
  `requires id != 0` on unannotatable third-party code fires at the
  caller's `vendor_find(0)`.

### Residuals (recorded in todo.md)
- Caller-side CONSUMPTION of declared ensures (treating a contracted
  callee's return as NonNull/MaybeNull per guard at call sites) is
  not implemented — ensures are verified against the callee only.
- Unenforced sidecar clauses on BODYLESS declarations are not
  reported as unverified (ContractRule only visits definitions); the
  enforced forms still work at call sites.
- Whole-program sidecar anchor coverage check (a typo'd anchor that
  matches nothing anywhere is currently silent).

## 2026-07-13 — Contracts Round D: guarded ensures + ownership effects

### Added
- **Guarded postconditions enforced**
  (`ensures return != null if <g>`): checked per disjunct at every
  return statement inside NullDeref. A path that REFUTES the guard is
  exempt (returning null there is exactly what the guard licenses); a
  path that PROVES the guard and returns definite null is an ERROR
  (warning for `cs:ai`); null under an undecided guard, or
  possibly-null, is a warning. The guard must be fact-keyable — the
  keyability decision lives in `analyzeNullEnsuresGuards`
  (ContractInfo), shared by NullDeref and ContractRule, so an
  unkeyable guard (address-taken parameter) falls back to the
  explicit `contract-unsupported` warning instead of opening a
  silent hole.
- **Ownership effects checked** (`owns(p)` / `borrows(p)` vs the
  inferred parameter effects): `owns` with a provably read-only body
  is a violation (ownership claimed, handoff leaks); `borrows` with a
  body that frees is a violation (caller's ownership broken — the
  double-free shape). Stores/Opaque stay explicitly unverified — no
  strong claim on ambiguity. Unknown parameter names in
  `owns/borrows` are `contract-syntax` errors. `returns owned` stays
  explicitly unverified (no return-ownership summary yet — residual).
  Caller-side leak suppression for `owns` needed no code: passing to
  a callee already conservatively escapes the pointer.
- **Violation traces on contract findings**: caller-side violations
  (Round C) and guarded-ensures violations now carry the existing
  "why null / why zero" dataflow traces (which assignment, which
  guard) — the LLM self-repair fuel of CONTRACTS.md §6.

### Verification
- 376/376 tests in both modes (+13 Round D: guard-true violation,
  guard-false licensed silence, undecided-guard warning, cs:ai
  downgrade, trace attachment, enforced-not-unverified, unkeyable
  guard stays reported, borrows-frees error, borrows-readonly
  silence, owns-readonly error, owns-frees silence, owns unknown
  param syntax error, call-site trace).
- Juliet floors and corpus pins green (cjson 50, tinyxml2 9 exact).
- Dogfood: the conditional promise (`ensures return != null if
  id != 0` + `if (id != 0) return NULL;`) is caught AT the violating
  return; `owns` on a read-only body and `borrows` on a freeing body
  both fire at the contract line.

## 2026-07-13 — Contracts Round C: requires — assume/guarantee

### Added
- **Shared requires recognizer** (`contracts/ContractInfo`):
  `contractsForDecl` (works on bodyless declarations too — that is
  how callers see out-of-TU callees) + `analyzeRequires` classifying
  the enforced forms: `requires p != null`, `requires n != 0`, and
  the relational `requires p != null || <n REL lit>`. One recognizer,
  consumed by both dataflow rules and ContractRule — "which clauses
  are enforced" cannot drift.
- **Callee-side seeding**: NullDeref seeds a declared non-null
  parameter NonNull at entry (the contract carries the proof burden);
  the relational form seeds a SPLIT initial state via fact keys —
  escape disjunct leaves p free, the other pins it NonNull, so
  `if (n > 0) *p;` is provably safe under
  `requires p != null || n <= 0`. DivByZero seeds declared non-zero
  parameters NonZero.
- **Caller-side checks at every visible call site**: a NULL-literal
  or definitely-null argument into `requires p != null` is an ERROR
  (warning for `cs:ai`); possibly-null is a warning; a guarded
  argument is silent. Same in the zero domain: literal `0` or a
  zero-state variable into `requires n != 0` (DivByZero tracks
  variables passed at contract positions even when they are never
  divisors, and a caller with no pointer variables of its own still
  gets the pass — `g() { f(NULL); }` is exactly the target shape).
  Relational escapes honor integer-literal condition arguments
  (`f(NULL, 0)` under `|| n <= 0` is satisfied); non-literal escapes
  stay conservative (silent).
- **ContractRule now delegates**: enforced requires clauses are no
  longer reported as unverified; a requires clause naming a
  parameter the function does not have is a `contract-syntax` error
  (it can never bind — that is a contract bug, not a later round).
- `compareFact` exported from PathFacts: the contract layer builds
  canonical fact keys without an Expr in hand (same unsigned
  zero-identities as conditions).

### Verification
- 363/363 tests in both modes (+15 Round C: seeding silences the
  callee deref, error/warning/cs:ai severity split at call sites,
  guarded-caller silence, relational escape satisfied/violated/
  callee-split, zero-domain literal + tracked-var + maybe + guarded,
  unknown-param contract-syntax, enforced-not-unverified).
- Juliet floors and corpus pins green (contracts add checks only
  where `cs:` comments exist; the referees confirm zero drift).
- Dogfood: `load_config(NULL)` under `requires path != null` → error
  at the call line; a maybe-null argument → warning; `average(100,
  count)` with a zero counter under `requires n != 0` → error; the
  contracted callee's own `*s` stays silent.

## 2026-07-13 — Contracts v1 Round B: the intent layer opens

### Added
- **CONTRACTS.md** — the contract-language design spec from the
  co-design session: a contract is a DECLARED function summary,
  checked by the same dataflow that infers summaries.
- **Contract parser** (`contracts/ContractParser`): `cs:` /
  `cs:ai` structured line comments, one expression grammar
  (`ensures return != null if n != 0`, `requires p != null || n == 0`),
  effect keywords (`owns/borrows/returns owned`), `cs:policy` names.
  Hand-written recursive descent; parse errors are NEVER silent.
- **ContractRule** (rule_id `contract`): Round B checks unconditional
  return postconditions (`ensures return != null` / `!= 0`) against
  the inferred return-nullness/zeroness summaries. Violation of a
  bare `cs:` contract is an ERROR (CI breaks — the friction is the
  product); a `cs:ai` proposal violating downgrades to warning.
  Unparseable lines are `contract-syntax` errors; parseable but
  not-yet/never-checkable clauses get explicit `contract-unsupported`
  warnings — a contract is never silently "accepted".
- `-fparse-all-comments` in both the product tool and the test
  harness (ordinary `//` comments otherwise never reach the AST).
- First dogfood: the founding-pain shape (`ensures return != null`
  + a later early `return NULL;`) is caught at the contract line.

### Verification
- 348/348 tests in both modes (+14: 5 parser units incl. the
  never-silent syntax pin, 9 rule pins incl. severity split,
  attachment, unverified-not-silent, param-vs-param unsupported,
  multi-clause independence).
- Juliet floors and corpus pins green with the new rule active
  (Juliet has no contracts; the rule adds zero noise by construction
  and the referees confirm it).

## 2026-07-12 — Unsigned zero-identities (the fprime PriorityMemQueue FP)

### Changed
- **normalizeCompare canonicalizes unsigned comparisons against
  zero**: for an unsigned variable `u <= 0` IS `u == 0` and `u > 0`
  IS `u != 0` — both now key as (u EQ 0). Un-canonicalized, the same
  knowledge lived under two keys, disjuncts split on a phantom
  dimension (an "u <= 0 but u != 0" disjunct is unsatisfiable yet
  stayed alive), real functions blew the disjunct cap, and the
  overflow widening erased exactly the correlated pointer fact the
  assert had established. `u < 0` (never true) and `u >= 0` (always
  true) carry no per-edge information and are no longer keyed.
- Root-caused by DELETION-based delta debugging on a faithful
  standalone copy of NASA fprime's PriorityMemQueue::configure: the
  warning needed BOTH the `required` assert (doubling disjuncts on a
  bool fact) AND the first `num > 0` block (splitting again) — five
  disjuncts at the join, cap 4, widen-to-one, correlation gone.
  (Construction-based repro attempts had missed it twice; the
  deletion direction found it in one round. Also: a stub overload
  mismatch in the copy produced an error-recovery AST whose phantom
  warning briefly pointed the wrong way — check compile errors in a
  repro before trusting it.)

### Results
- NASA fprime with `--fatal-asserts SwAssert`: CLEAN (0 findings) —
  the README table row (2) awaits correction to 0 with the flag
  documented.
- systemd 50 -> 51 nulls: one conservative loss (fstab-util.c
  flag-correlation) from unkeying always-false/always-true unsigned
  orderings — queued for a single-file bisect; direction is
  FP-conservative, not unsound.

### Verification
- 334/334 tests in both modes (+2: the fprime shape end-to-end, and
  the `u < 0` phantom-branch pin documenting the conservative
  severity).
- Juliet floors and corpus pins green on fresh replays.

## 2026-07-12 — MCP idiom parameters

### Changed
- The MCP `analyze` tool accepts `fatal_asserts`, `alloc_functions`
  and `free_functions` — the same project-idiom knowledge the CLI
  flags carry (assert handlers that never return; custom allocator
  wrappers), now available to agent loops. Config gains public
  addAllocFunctions/addFreeFunctions.
- Registrations are per-call: the long-lived server process does not
  leak one request's idioms into the next (pinned — the same file
  analyzed with and then without `fatal_asserts` flips back to
  reporting).

### Verification
- 332/332 tests in both modes (+3 MCP tests: schema advertises the
  params; fatal-assert path kill works through MCP and resets; custom
  allocator leak tracking works through MCP).

## 2026-07-12 — llama triage round: mutation visibility + template-parameter facts

### Changed
- **DivByZeroRule sees `++z` / `z--` / `z += n`**: increments,
  decrements and compound assignments now invalidate the zeroness
  fact (were completely invisible — a counter initialized to 0 stayed
  "definitely zero" forever). The llama.cpp ngram-cache
  `++n_done; ... x / n_done` was reported as a CERTAIN division by
  zero on a line that can never divide by zero.
- **Non-type template parameters are fact keys** (stableDeclRef):
  they are compile-time constants — unassignable, unaliasable — yet
  uninstantiated `if constexpr (FUSE == ...)` reads as a runtime
  branch, so "set under the flag, used under the flag" needs the
  same-condition correlation like any flow variant. The llama.cpp
  ggml rms_norm fused-op family (src1 set and used under the same
  FUSE check) reported a certain null dereference.

### Results
- llama.cpp 25 -> 23 findings and — more importantly — ERROR-level
  findings 2 -> 0: both "certain crash" claims were analyzer gaps,
  found and killed during hand-triage before any upstream report was
  drafted. The triage-before-reporting discipline paid for itself.

### Verification
- 329/329 tests in both modes (+5: incremented/compound counters
  clean, untouched zero still a definite error, template-param
  same-guard clean, different-guards still warns).
- Juliet floors and corpus pins green (fresh replays).

## 2026-07-12 — Comparator-ladder case exhaustion (libgit2 triage round)

### Changed
- **Pointer-pointer pairs now gate pointer facts too**
  (collectPtrFactDecls): a bare-pointer operand qualifies when its
  short-circuit partner is EITHER integer-keyable (the assert shape)
  OR another bare-pointer nullness operand. The comparator-ladder
  family falls out of the existing v2b machinery: after
  `if (!a && !b) ... if (!a && b) ... if (a && !b) ...` falls
  through, disjunction elimination over the split disjuncts proves
  both pointers non-null. Self-guards (`p && p->x`) stay ungated —
  the member side is not a bare pointer operand, so ordinary guards
  do not burn the disjunct cap.

### Results
- libgit2 nulls 29 -> 23 (checkout/status/merge cmp ladders died;
  index.c's pair survives — its correlation travels through a
  call-result int, documented). cJSON 52 -> 50, abseil 5 -> 4; both
  pins re-centered in this PR.
- libgit2 triage completed (29 nulls): 8 cmp-ladder (fixed here),
  2 member-field guard correlation (`hdr->chunks == 0` early-return
  proves a parse loop runs — member-expr fact keys are a v3 idea),
  19 callee-may-return-null sites for later per-site reading.
  0 new real bugs (the 11 verified OOM-path leaks stand).

### Verification
- 324/324 tests in both modes (+3: both ladder forms clean, and the
  over-blessing guard — a surviving null path through a fallen rung
  still warns).
- Juliet floors green at the RAISED v2b values (0.66/0.23/0.48);
  metrics unchanged.

## 2026-07-12 — Disjuncts v2b: cross-variable correlation (max-effort engine session)

### Changed
- **Fact lifecycle is now flow-sensitive**: the whole-function keying
  ban on assigned variables is gone. Assignments to locals ERASE the
  facts keyed on them at the assignment statement (applyStmtFacts, in
  all three GuardedState rules' transfer); address-taken decls and
  assigned globals stay permanently unkeyable (calls can change them
  invisibly — the documented trade-off class is unchanged).
- **Integer-constant stamping**: `have = 1` records (have EQ 1)=true
  in every disjunct (gated to condition-relevant locals,
  collectFactDecls; enum constants count). Paths that assigned
  different constants stay SEPARATE disjuncts at joins — the
  flag/status correlation family (rtp2httpd `if (have) use(x)`,
  fprime `if (st == OK) b->size`) and the Juliet flow-variant guards.
- **Entailment**: a stamped equality answers any later key on the same
  variable ((x EQ 6)=true refutes (x EQ 5)=true) — dead-branch
  sharpening for free (`x = 6; if (x == 5) *p;` is silent now).
- **Disjunction elimination with gated pointer facts**: systemd's own
  assert (`if (_unlikely_(!(expr))) log_assert_failed(...)`)
  materializes `s || l <= 0` as a VALUE — Clang joins the operand
  paths BEFORE the branch, so no per-leaf edge ever exists and only a
  fact difference survives the merge. Pointer-nullness facts
  ((s EQ 0), gated by collectPtrFactDecls to pointers sharing a
  short-circuit operator with a keyable partner) keep the split;
  refineDisjunctCondition then applies the surviving operand to the
  disjunct that refutes the other one (fact-based refuter for every
  rule + a nullness-domain refuter in NullDeref). Structural walk
  also records facts from BOTH sides of `a && b` true edges.
- **Convergence widening in the engine**: the guarded-disjunct domain
  is not monotone (facts are erased, disjuncts dropped) and real code
  OSCILLATES — rtp2httpd's parser functions cycled forever, an 8x
  iteration budget changed nothing. After latticeHeight+2 visits a
  block's entry is joined with the previous widened entry and
  collapsed to one disjunct: flip-flopping facts die in the
  intersection, var states only climb their finite lattice.
  Memoryless widening was measurably NOT enough (single-disjunct
  fact VALUES alternate across visits). Non-convergence warnings:
  rtp2httpd 6 -> 0, systemd 17 -> 0, and the systemd scan got faster
  (oscillating functions used to burn their whole iteration budget).
- **kMaxDisjuncts stays 4 — measured**: raising to 8 cost ~2.7x
  systemd scan time for 2 fewer findings. The remaining correlation
  misses cluster in many-condition functions; the future lever is
  fact-prioritized widening, not a bigger cap (noted in the header).

### Results (same 494-file systemd scan, apples to apples)
- systemd: 63 findings -> 53 (nulls 58 -> 50; both uninit findings
  died — a flag-correlated pair; leaks stay at the 3 deliberate
  residues). The assert pointer/length family went 18 -> 15 at cap 4
  (the canonical nulstr-util shape is pinned as a test and dies when
  disjunct pressure is low); the remaining 15 + 7 checked-cast macros
  + 28 hard singletons are the documented residue.
- rtp2httpd: 4 -> 3 (the verified TP stays; 1 correlation FP died;
  the 2 survivors correlate through STRING CONTENT — out of scope,
  documented).
- NASA fprime: 7 -> 2 (five status/pointer correlations died; note:
  an intermediate "7 -> 1" measurement was an artifact of scanning
  with the wrong build dir — 214 files failed to find headers and
  error-recovery ASTs produced a phantom finding; always check the
  fatal-error count of a scan before comparing it).
- cJSON: 54 -> 52 (two correlation FPs died; pin range holds).

### Verification
- 321/321 tests in both modes (+15: 12 DisjunctsV2bTest — three
  rules' flag correlation, enum status, assert family incl. the
  mutated-counter loop, stale-guard sharpening, compound-assign
  safety, global-flag limit, cap-overflow soundness — and 3
  systemd-assert value-materialized shapes incl. the
  unprotected-deref-still-warns pin).
- Local Juliet replay, three consecutive runs identical: CWE401
  precision 0.669 -> 0.692, CWE415 recall 0.225 -> 0.241, CWE416
  recall 0.476 -> 0.501, CWE476/CWE369 unchanged. Floors RAISED in
  the same PR: CWE401 0.62 -> 0.66, CWE415 0.21 -> 0.23, CWE416
  0.44 -> 0.48.

## 2026-07-12 — Pointer-relational validity (the FOREACH_ARRAY family)

### Changed
- **Pointer-pointer relational comparisons prove validity**: C11
  6.5.8p5 defines `p < q` only when both operands point into (one past
  the end of) the same object — which a null pointer never does. So
  EVALUATING the comparison now proves both operands non-null, on both
  edges; the result direction carries no nullness information.
  Orderings against the null constant are excluded (they carry no
  proof, and `if (p == 0) { if (p > (int*)0) *p; }` must keep its
  definite-null error).
- **walkCondition reports BOTH sides of a comparison**: the
  variable-on-left normalization used to drop the right side entirely
  (`i < end` never informed about `end`). All existing clients filter
  by literal on the other side, so the extra callback is free for them.
- **systemd null-derefs 302 → 58 (−81%)** on the same 494-file
  basic/core/shared scan. Full-family classification (programmatic,
  all 302): 235 were FOREACH_ARRAY/FOREACH_ELEMENT expansions — the
  macro's own defensive `i &&` check creates the may-be-null evidence,
  the ternary join keeps it, and the loop condition `end && i < end`
  used to refine only `end`. Zero survivors of the family after the
  fix; 9 misc singletons also cleared. Remaining 58: 18 assert
  pointer/length correlation + 7 checked-cast macros (both the
  disjuncts-v2b design inventory) + 33 hard singletons.
- **New FN discovered while building the repro (documented, not
  fixed)**: `q = (p && flag) ? p : NULL; q->value;` is not reported —
  the ternary result's nullness never reaches the assigned variable.
  The v2b design session inherits it (value-level join at
  ConditionalOperator).

### Verification
- 306/306 tests in both modes (+5 ForeachArrayFpTest: exact macro
  shape with statement expression, open-coded shape, both-operand
  proof, null-literal-ordering exclusion, post-loop deref still
  warns on the zero-iteration path).
- Local Juliet replay: all five CWE metrics IDENTICAL to pre-fix
  (CWE476 1.000/0.352 — the proof costs nothing on the benchmark).
  Corpus pins hold (cjson 54, tinyxml2 9).

### Debugging lesson
- Piping a referee run through `tail` in a background task truncates
  the log the notification later points at (two referees had to be
  re-derived from workdir artifacts). Capture full output to a file;
  filter at read time.

## 2026-07-12 — systemd macro idioms + rtp2httpd scan

### Changed
- **Composite-RHS escape**: a statement expression or compound literal
  assigned to ESCAPING storage walks its subtree for tracked pointers
  (`*ret = TAKE_PTR(cs);`, `*ret = IOVEC_MAKE(buf, n);`). Local-lhs
  stashes stay visible (the Juliet 66/67 pin).
- **Bare-address alias escape**: storing a pointer's OWN address
  (`_b = &(p);` — the free_and_replace macro) escapes conservatively
  even into a local; a MEMBER address into an ignored local still
  leaks (the fprime font pin holds — the two cases are distinguished).
- systemd leaks 9 → **3** (the remaining trio is the local
  compound-literal stash correlated with the aggregate's later use —
  aliasing v2 territory, documented). Referees: Juliet floors and
  corpus pins unchanged.
- **rtp2httpd scanned** (27k lines): **4 findings** — 1 hand-verified
  TP (configuration.c: `if (arg && ...)` admits arg may be NULL, the
  very next block dereferences `arg[0]` unconditionally) + 3 FPs, all
  the cross-variable correlation family. The disjuncts-v2b inventory
  now spans FOUR codebases (fprime, Juliet flow variants, libgit2,
  rtp2httpd).

### Verification
- 300/300 tests (+3 SystemdIdiomTest with the member-address
  distinction preserved).

## 2026-07-12 — --files UX hardening (the systemd lesson)

### Changed
- `--files` entries that do not exist as given are retried relative to
  `--build-path` (meson compile DBs carry build-dir-relative paths like
  `../src/foo.c` — a meson-driven list used to be skipped entirely).
- Zero analyzable files is now exit 2, not a "Clean!" exit 0 —
  analyzing nothing must not look like a clean pass.

### Verification
- 297/297 tests (+1 FilesUxTest zero-file pin); relative-path
  resolution verified end-to-end against systemd's meson build dir.

## 2026-07-12 — Disjuncts v2a: constant-returning call guards

### Changed
- **PathFacts keys one class of CALL conditions**: direct zero-argument
  calls whose entire visible body is `return <integer literal>;` key on
  the callee (a FunctionDecl is a ValueDecl — the key structure is
  unchanged). Such a helper CANNOT return anything else, so pairing the
  two guards is sound — no purity guessing involved. Anything weaker
  (rand(), extern declarations, bodies that read state) stays unkeyed;
  both flip sides pinned.
- Motivation: the Juliet flow variants (`static int staticReturnsTrue()
  { return 1; }`) that produced the ~24 realloc-family FPs measured in
  the previous round. Numbers in the verification note.

### Changed (the measurement chain — each fix's replay exposed the next)
- **Freed-through-alias suppression** (exit-time, per DISJUNCT): the
  Juliet malloc_realloc good shape frees the allocation under the
  alias's name; flattening first would dissolve the alias's Freed into
  None on guarded paths, so the check runs per disjunct. Frees still
  never propagate through the flow-insensitive groups (that would
  fabricate double-frees). Accepted FN pinned: alias variable reused
  for a second allocation.
- **Noreturn calls kill dataflow paths** (DataflowEngine,
  CFGBlock::hasNoReturnElement — the general form of --fatal-asserts):
  Clang wires `exit(-1)` blocks straight to the CFG exit, and their
  dead state DILUTED live-path facts there (Freed ⊔ None = None),
  blinding the alias check across the whole family. A process-killing
  path does not vote on end-of-function state.
- **Debugging lesson recorded**: ConsoleReporter writes findings to
  stderr — three "clean" replications during this hunt were grepping
  stdout. Empiricism still beat theory (the file-list bisect exposed
  the wrong assumption), but the stream mix-up cost an hour.

### Measured (local mirrored-suite replay, floors raised in this PR)
- CWE401 rprecision 0.559 (CI low) → **0.669**; floor 0.55 → **0.62**.
- CWE416 rhitrate 0.436 → **0.476** (call-guard pairing restored UAF
  TPs); floor 0.38 → **0.44**. CWE415 rhitrate 0.210 → 0.225; floor
  0.20 → 0.21. CWE476 overall precision 0.549 → 0.602 (leak-FP side).
- Corpus: cjson 55→54 (within pin tolerance), tinyxml2 9.

### Changed (round 3 — systemd first light)
- **Scanned systemd basic/core/shared** (494 files, ZERO parse errors
  through the macro-heaviest C in the wild): 414 raw findings.
  **`__attribute__((cleanup))` exemption** landed as v1: a variable the
  compiler auto-releases at scope exit cannot end-of-function leak
  (systemd `_cleanup_free_`, GLib `g_autofree`). Leaks 111 → **9**.
  The v2 design (modeling cleanup as scope-exit free to catch
  double-frees under the attribute) and the 302-null-deref triage are
  next rounds. Also recorded: the --files UX hardening lesson (meson's
  build-relative paths silently analyzed nothing with a "Clean!"
  exit 0).

### Verification
- 296/296 tests (+3 CallGuardTest, +4 alias/guard/noreturn pins, +2
  CleanupAttrTest with the plain-neighbor flip side). All five Juliet
  floors green at the RAISED values (verified locally before push).

## 2026-07-12 — Report-flood dedup: one warning per variable

### Changed
- **Warning-severity null-derefs report ONCE per (variable, function)**;
  every later dereference of the same variable becomes an "also
  dereferenced here" trace note on the first finding (notes capped at
  10). Definite (error) reports keep per-line granularity — they are
  rare and each site matters. The motivating floods: shadPS4
  internal__Foprep (one missing return = 25 identical warnings),
  fprime PriorityMemQueue (5x queueConfigs).
- Corpus pins re-measured in the same PR: cjson 123 → **55**,
  abseil 12 → **5** (same-variable floods collapsed); tinyxml2 9 and
  catch2 0 unchanged (distinct variables / nothing to report). Local
  Juliet replay: ALL FIVE floors green — case-level metrics are
  preserved by construction (each flooding variable still carries one
  report).

### Verification
- 287/287 tests (ctest + single-process; +3 ReportDedupTest: flood →
  one finding with notes, independent variables stay separate, errors
  keep per-line granularity).

## 2026-07-12 — Configurable allocators: the leak domain learns project wrappers

### Added
- **`--alloc-functions` / `--free-functions`** (CLI + conf keys):
  extend leak/double-free/UAF analysis to project heap wrappers
  (git__malloc, zmalloc, ...). Without them the whole domain is BLIND
  in wrapper-heavy codebases — libgit2 had produced literally zero
  leak findings. Tracked-variable collection now funnels through
  isAllocExpr (one place knowing built-ins, the registry, casts and
  the placement-new exemption; the old matcher list silently missed
  realloc). Registries share the fatal-calls lifecycle (cleared in
  ~StaticAnalyzer).

### Changed (escape refinements the libgit2 validation demanded)
- **Address-of-member escape**: `*out = &it->parent;`,
  `track(&boxed->glyph)`, `return &obj->member;` — handing out a
  member's address keeps the whole object reachable. Closes the todo
  item from the fprime font FP.
- **Alias escape propagation**: flow-insensitive alias groups over
  local pointer copies; an ESCAPE through any alias escapes the group
  (`dup = git__strdup(s); result = dup; return result;` — the libgit2
  realpath shape). Deliberately escape-only: frees stay per-variable
  (flow-insensitive groups would fabricate double-frees), and a
  non-escaping alias saves nothing (Juliet dataCopy pin re-stated).
- **Chained-assignment escape**: `*out = counts = git__calloc(...)`
  stores the allocation through the out-param (libgit2 checkout).
- libgit2 leak-domain result: 0 → 31 findings on first light, → **15**
  after the three refinements. Hand-verified sample: merge.c
  `similarity_ours` leaks when `similarity_theirs`'s allocation fails
  (GIT_ERROR_CHECK_ALLOC returns -1 without freeing the first buffer)
  — a REAL OOM-path leak class; the remaining findings match the same
  multi-allocation early-return shape (next-round triage / upstream
  report candidates).

### Changed (round 2 — the Juliet guard spoke, again)
- **CWE401 precision floor 0.60 → 0.55, with a main-vs-PR diff as
  evidence.** The guard flagged rprecision 0.559 (CI). Local replay
  against a mirrored Juliet suite: main 78TP/36FP (0.684) vs PR
  81TP/56FP (0.591 after the nothrow fix). Every one of the +24 FPs is
  a realloc-family file — the old matcher list NEVER tracked realloc,
  so those ~25 files were invisible; now visible, their good variants
  hit the documented correlated-guard limitation
  (staticReturnsTrue()/False() call conditions — PathFacts cannot key
  disjuncts on calls; the guarded-disjuncts-v2 item). 4 old FPs also
  vanished (escape refinements). Coverage widened, absolute TPs rose,
  the ratio dipped on the newly visible files: floor adjusted in the
  same PR, per policy.
- **Nothrow-new regression caught and pinned**: the placement-new
  exemption was excluding `new (std::nothrow) T` — a real heap
  allocation. Only POINTER-typed placement args mean caller storage.
  Worth 7 FPs of the CI drop (0.559 → 0.591).

### Verification
- 284/284 tests (ctest + single-process; +4 AllocFunctionsTest with
  the unregistered-wrapper-invisible pin, +3 AddrOfMemberTest with the
  local-alias flip side, +3 AliasEscapeTest with the Juliet dataCopy
  re-pin). Corpus pins unchanged (cjson 123, tinyxml2 9). Juliet
  floors referee in CI — the alias-escape direction only silences
  reports, never invents them.

## 2026-07-12 — libgit2 + llama.cpp FP hunt: two C-idiom families

### Changed
- **Assignment inside a condition refines its LHS** (ConditionWalk):
  `if ((p = alloc()) == NULL) return;`, `while ((e = next()) != NULL)`,
  `!(page = git__malloc(n))` — the guard tests the just-assigned value,
  but the variable extraction only saw bare DeclRefExprs, so the whole
  guard was invisible and every use after it warned. One look-through
  (isAssignmentOp, compound forms included) serves both the null and
  zero domains. This was libgit2's dominant FP family.
- **Value-selection rewind** (DataflowEngine): a ternary refines its
  ARMS (`z ? 100/z : 0` keeps z NonZero inside the true arm — pinned
  since the stress suite), but once the arms REJOIN its edge facts are
  tautological ("p is null or non-null") and must not downgrade the
  pre-ternary state to a reportable MaybeNull. The defensive macro
  shape `ne0 = p ? p->ne[0] : 0` (GGML_TENSOR_LOCALS) produced ~90% of
  llama.cpp's 511 findings. Detection: the join's two predecessors form
  one ConditionalOperator diamond and each arm's exit state equals the
  PURE refinement of the condition block's exit — then the join
  re-enters with the condition block's state; an arm with a real effect
  fails the equality and merges normally.
- **libgit2 scan** (168 files, pure C): 149 findings, ALL null-deref —
  and ZERO memory-leak, which is itself a finding about the analyzer:
  git__malloc/git__free are invisible to the fixed allocator list, so
  the leak rule tracked nothing. Configurable allocators
  (--alloc-functions/--free-functions) recorded in todo as the natural
  sibling of --fatal-asserts.
- **llama.cpp scan** (225 files): 511 findings before the fixes →
  **47 after** (ops.cpp's 407-finding cluster collapsed to 3; the
  remaining set is 37 null-deref / 9 memory-leak / 1 div-by-zero,
  next-round triage material). libgit2: 149 → **101**.

### Changed (round 2 — NASA fprime)
- **Scanned NASA F´ flight-software framework** (216 hand-written files
  after a full fprime-util build generated the FPP autocoder headers):
  **10 findings**, triaged to the last one. Fixed here: **placement new
  is not an allocation** (MemoryLeak isAllocExpr — the AtomicQueue
  slot-initialization loop `new (&m_slots[i]) Slot()` produced 2 FPs;
  plain new keeps full tracking, pinned). `--fatal-asserts SwAssert`
  killed the TlmChan FW_ASSERT-opacity warning — the feature's second
  real-world validation. Remaining 7: one family, cross-VARIABLE
  correlated guards (`FW_ASSERT(ptr != nullptr || count == 0)` then
  derefs inside `if (count > 0)`) — recorded in todo as the guarded
  disjuncts v2 design item.

### Verification
- 273/273 tests (ctest + single-process; +5 LibGit2FpTest including the
  null-branch flip side, +3 LlamaFpTest including the
  check-then-unguarded-use flip side that must KEEP warning, +2
  FprimeFpTest placement-new pins). The two BestCaseTest ternary-guard
  pins from the stress suite hold — the rewind preserves arm-internal
  refinement by construction.

## 2026-07-12 — shadPS4 round 2: --fatal-asserts (assert-opacity flood)

### Added
- **`--fatal-asserts <names>`** (CLI + `fatal_asserts` conf key): treat
  the listed functions as never returning even though their
  declarations lack `[[noreturn]]`. Engine-level kill: a dataflow path
  ends at a call to a registered name — the block's exit state is never
  recorded (phase 1) and nothing after the call is reported (phase 2),
  exactly as if the CFG had pruned it. Registry cleared in
  ~StaticAnalyzer (MCP-server safety, same lifecycle as the function
  filter).
- Why: projects with continue-able assert machinery (shadPS4's
  `assert_fail_impl` — "sometimes we want to try to continue") defeat
  the CFG's noreturn pruning; the failure path survives every
  `ASSERT(x)` and each later dereference warns. ~170 of shadPS4's
  findings were this one pattern. The default stays EMPTY — assuming
  termination the code does not promise is a per-project, deliberate
  decision (the Coverity kill-path model approach).
- shadPS4 measured effect: 209 findings (round 1 start) → 195 after the
  call-boundary fixes (all 6 error-level FPs gone; the 3 remaining
  errors are exactly the 3 real bugs) → **97** with
  `--fatal-asserts assert_fail_impl`. The ime_ui/ime_dialog_ui flood
  (72 findings) vanished entirely; both div-by-zero warnings
  (ASSERT_MSG-guarded folds) died with it. Largest remaining cluster is
  the 25 repeats of the real internal__Foprep bug — the report-flood
  dedup item in todo.md, not an FP.

### Verification
- 263/263 tests (ctest + single-process; +7 FatalCallsTest: kill on
  null/zero/leak paths, dead-code non-reporting, unregistered-name
  no-op pin, registry-cleanup pin). Corpus pins unchanged with the
  default-empty registry (cjson 123, tinyxml2 9 — measured locally).
  Juliet floors referee in CI (no fatal names registered there — zero
  expected drift).

## 2026-07-12 — shadPS4 FP hunt round 1: call-boundary soundness

### Changed
- **Scanned shadPS4** (PS4 emulator, 377 src/ files from a 2236-entry
  compile DB; C++20, zero crashes): 209 findings. Triage found 3 REAL
  bugs (savedata `&&`-guard derefs the pointer it just null-checked ×2;
  usb GetMaxPacketSize passes `desc = nullptr` BY VALUE then derefs it;
  libc internal__Foprep checks `file == nullptr`, sets ENOMEM and falls
  through to the deref) and two analyzer defects fixed here:
  1. **Non-const reference arguments invalidate facts**
     (engine/CallRefArgs.h, wired into ALL FOUR rules): `f(id, p)`
     where f takes `int*&` may rebind p — keeping "definitely null"
     across the call produced 6 error-level FPs (http.cpp
     ResolveEpollBinding). There is no AddrOf node to observe; only the
     parameter type reveals the out-param. NullDeref/DivByZero/
     UninitPtr drop the fact to Unknown/Init; MemoryLeak escapes.
     DivByZero also gained the missing `f(&z)` AddrOf invalidation.
  2. **Escape analysis sees through explicit casts and composite
     arguments** (MemoryLeak): `addTimer(33, cb, (void*)copy)`,
     `*out = reinterpret_cast<T*>(h)`, `io.UserData = bd` (reference
     base = storage owned elsewhere) and `push_back(Data{cast(m)})`
     (pointer riding inside an aggregate argument) all escape now.
     `free((void*)p)` is also finally visible as a free. Flip sides
     pinned: `f(*d)` reads the pointee (leak stays visible), cast
     local-to-local copies stay non-escaping, value/const-ref passes
     keep their facts.
- The ~170-finding assert-opacity flood (ASSERT whose failure handler
  deliberately returns) is documented as the round-2 design item in
  todo.md — not patched ad hoc here.

### Verification
- 256/256 tests (ctest + single-process; +17 ShadPS4FpTest across all
  four rule suites, each FP fix with its flip-side pin). Corpus pins
  hold exactly (cjson 123, tinyxml2 9). Juliet floors + deep-corpus
  pins (abseil 12, catch2 0) referee in CI.

## 2026-07-12 — Abseil FP hunt: three real-world false-positive families fixed

### Changed
- **Scanned abseil-cpp** (159 files, ~1m50s, zero crashes): 40 findings,
  all warnings, triaged by hand. Three FP families found and fixed:
  1. **`__builtin_expect` transparency** (ConditionWalk): ABSL_RAW_CHECK
     wraps a negated conjunction in `__builtin_expect`; the short-circuit
     value blocks inside the call refine "null" facts, and without
     looking through the builtin the if-edges could not correct them —
     the fact leaked into the continue path (8 findings from ONE check).
     Applies to every likely()/unlikely() macro in the wild. The flip
     side is pinned too: a non-terminating failure branch still warns.
  2. **Static/global storage exempt from end-of-function leak**
     (MemoryLeakRule): `static Mutex* mu = new Mutex;` is the deliberate
     leak-on-purpose singleton (destruction-order fiasco dodge) —
     program-long lifetime is not a function-local leak.
  3. **Member-assign and method-receiver escapes** (MemoryLeakRule):
     `slot_ = copy;` and `p->Track()` outlive/stash the pointer.
     Local-to-local copies deliberately stay non-escaping (Juliet's
     `dataCopy = data;` alias leaks must remain visible) and UAF through
     a receiver is unaffected (pre-call state check) — both pinned.
- Result: 40 → **12 findings** on abseil; the rest are invariant-checked
  ("a thread identity exists, see above") or genuinely worth a look.
- **abseil added to the corpus guard** (tag 20260526.0, pin 12) — deep
  mode only (`CORPUS_DEEP=1`, weekly cron; ~2.5 min stays out of PR
  runs for CI cost balance). run_corpus gained a compile-DB-driven `db`
  mode; cjson/tinyxml2 keep their original scan mode and pins.

### Changed (round 2 — the Juliet guard spoke)
- **JULIET_GUARD_FAIL CWE401** on the first CI run: recall 0.246→0.188
  (floor 0.22) while precision ROSE 0.623→0.672. The guard did exactly
  its job: the member-assign escape was too broad. Refined: a member of
  a LOCAL aggregate (`myStruct.ptr = data;`) is NOT an escape — the
  aggregate dies with the function, the leak is real (Juliet 66/67
  struct-passing families restored). `this`-members, `->` members,
  param-reachable aggregates, globals/statics still escape. abseil
  stays at 12 (the CrcCordState fix is a this-member).
- Known-FN note: the Juliet 44/45 "data passed via static global"
  families remain suppressed by design (storing into a global is not a
  function-local leak; tracking it needs whole-program global-flow —
  todo). If CWE401 recall still sits under the floor after the
  refinement, the floor gets adjusted with these numbers as rationale.
- **Round 3 — floor adjusted with rationale**: the second CI run
  measured rprecision 0.659 / rhitrate 0.201 — recall recovered
  (0.188→0.201) but stayed under the 0.22 floor, and the remaining gap
  is exactly the 44/45 static-global families above. Those old "hits"
  fired for the wrong reason (the leak completes in the sink function,
  not where we reported), so losing them is honesty, not regression.
  `juliet_expected.txt`: CWE401 `0.55 0.22` → `0.60 0.18` — precision
  floor RAISED to lock in the FP fixes, recall floor set to the
  measured truth. Per policy, floors change in the SAME PR as the rule
  change, rationale in the file and here.
- **Catch2 scanned too** (107 files, 42s): ZERO findings, zero crashes.
  Added to the deep corpus pinned at 0 (v3.15.2) — a clean modern-C++
  codebase is the FP-explosion tripwire.

### Verification
- 239/239 tests (ctest + single-process; +8 AbseilFpTest FP-killers and
  flip-side pins, +2 guard-taught refinement pins: local-struct-member
  leak stays visible, param-struct-member escapes). Corpus pins
  (cjson/tinyxml2 held on first CI run) and Juliet floors referee.

## 2026-07-10 — Summary-diff v1: contract change report (semantic regression gate)

### Added
- **`--summary-diff <old> <new>`**: instead of analyzing, reports how
  function CONTRACTS changed between two harvests. Classification is
  direction-aware: **WEAKENED** = loss/change of a strong claim (NeverNull /
  NeverZero dropped; a ReadsOnly/Frees param claim turned into something
  else) — CALLERS leaning on that claim must be re-reviewed, **exit 1 = CI
  gate**. STRENGTHENED is informational, CHANGED directionless,
  ADDED/REMOVED is key entry/exit (a signature change is REMOVED+ADDED —
  the key includes arity, deliberate). Weakened entries lead the report;
  SUMMARY_DIFF-prefixed lines are machine-greppable.
- `SummaryRegistry::parseSummaryFile`: parse a file without mixing it into
  the registry (loadGlobal was rebuilt on top of it — behavior identical).
- CLI smoke with a real scenario: after a `return &g` → `return 0`
  refactor, `WEAKENED find/1 returnNullness: NeverNull -> MaybeNull` +
  exit 1.
- Contract LANGUAGE design is deliberately out of scope for this round —
  a co-design session with the user (separate todo item). This tool
  produces input data for that session.

### Verification
- 228/228 tests (ctest + single-process; +7 SummaryDiffTest: weakening /
  param weakening / strengthening / directionless / added-removed+ordering /
  identical / E2E exit codes)

## 2026-07-10 — CFG cache: one build per function

### Added
- **engine/CfgCache**: memoized CFG store keyed by FunctionDecl* — every
  scan of the summary mini-flows + the 4 rules now share the same
  function's CFG (previously 6+ builds per function; a counter test pins
  the exact count: 2 functions = 2 misses, everything else hits). Build
  options (setAllAlwaysAdd) moved to a single place — consumers MUST see
  the same granularity (the two-phase reporting contract depends on it),
  they can no longer diverge.
- **Validity is doubly protected** (the CFG form of the never-serve-stale
  principle): explicit cleanup at TU end (same points as
  SummaryRegistry::clear: RuleEngine::runAll, TestHelper, whole-program
  harvest, ~StaticAnalyzer) + automatic flush on ASTContext change
  (backup safety — address reuse cannot turn into a false hit). A test
  also pins TU-end emptiness: this is a correctness condition, not
  hygiene.
- Measurement: ~10-15% end to end on a 600-function synthetic (parse
  included); the gain grows with large functions and the whole-program
  two-pass.

### Verification
- 221/221 tests (ctest + single-process; +2 CfgCacheTest) —
  behavior-preserving (the 219 existing tests are the referee);
  corpus/Juliet guards in CI

## 2026-07-10 — Editor integration guide (zero code)

### Added
- "Editor & code-scanning integration" section in the README: the VS Code
  SARIF Viewer flow (our traces are navigable step by step as related
  locations) and a GitHub code scanning upload-sarif YAML example (with a
  `|| true` note — we exit 1 on findings, code scanning does the gating).
  A screenshot could not be captured from this environment; the text
  guide covers the full flow.

## 2026-07-10 — HTML report (`--html`): first step of the UI phase

### Added
- **HtmlReporter**: a single, self-contained HTML file (no external
  resources — a test pins this with "contains no http://"; opens offline,
  as easy to share as an email/PR attachment). Summary cards double as
  filters (severity + rule, click to toggle); a text box filters by
  file/function/message; each finding's dataflow trace opens via
  `<details>`, and both the trace steps and the finding location are
  embedded WITH ±2 lines of SOURCE CONTEXT, target line highlighted
  (read at generation time — context isn't lost when the report is
  moved). Dark/light theme automatic via `prefers-color-scheme`.
- **Security invariant**: all user data is HTML-escaped — a `<script>` in
  source code cannot leak into the report (tested).
- `--html <file>` CLI flag + `html_output=` config key.
- If the source file is missing, context is skipped and the report is
  still produced (tested).

### Verification
- 219/219 tests (ctest + single-process; +5 HtmlReporterTest)
- CLI smoke: produced a demo report with 5 findings from 4 rule families
  (interprocedural zeroness and guard-null traces included)

## 2026-07-10 — Summary file staleness warning

### Added
- If a source NEWER than the summary file loaded via `--summary-in` is
  being analyzed, a single warning on stderr: "summaries may be stale;
  re-run --summary-out". Analysis does not stop, summaries are still
  used (a stale summary does not break correctness — at worst it carries
  missing/extra claims; but the user should know to refresh). The test
  stamps mtimes explicitly (no same-second flake) and pins both
  directions: stale → warning + findings still arrive; fresh → no
  warning.

### Verification
- 214/214 tests (ctest + single-process)

## 2026-07-10 — Trace v2: guard events in traces (onEdgeRefined)

### Added
- **Optional `onEdgeRefined` hook on DataflowEngine**: called only in the
  REPORTING pass, when edge refinement (assume edge) ACTUALLY changes the
  state — the same fixpoint rule as onStatement (in phase 1 a spurious
  guard event would be born from early state). Without the hook, behavior
  is bit-for-bit the old one (SFINAE).
- **Guard trace notes**: definite knowledge coming from a bare guard,
  with no assignment, previously had NO trace. The `if (p == 0) { *p }`
  finding now carries a note on the condition line: "'p' is null on this
  branch (per this condition)" (NullDeref, diffed with disjunct
  flattening); symmetric "zero on this branch" for `if (n == 0) 100 / n`
  (DivByZero). Two new i18n messages.
- The note points at the condition line (not the dereference/division
  line) — a test pins this with a line comparison.

### Verification
- 213/213 tests (ctest + single-process; +2 guard-trace tests; the
  existing 211 unchanged — hook-less analyses and existing traces are
  behavior-preserving)

## 2026-07-10 — Endpoints of the incremental flow: MCP `summaries` + diff loop docs

### Added
- **`summaries` argument on the MCP analyze tool**: a file written with
  --summary-out is handed to the MCP call; the agent loop analyzes a
  single file with whole-project knowledge (test: silent without
  summaries, null-deref visible with summaries — the file is the only
  thing carrying the knowledge).
- Since analyze_diff.sh already forwards extra arguments, `--summary-in`
  works from there today — documented in the script header and the
  README. The incremental story is complete: harvest (once) → diff loop /
  MCP call (on every edit, with whole-project knowledge).

### Changed
- README benchmark: the CWE369 row refreshed after PR #30
  (18→21 TP, hitrate 0.045→0.053, F1 0.086→0.100, precision 1.000
  unchanged) + a return-zeroness sentence in the numbers-journey
  paragraph.

### Verification
- 211/211 tests (ctest + single-process; +2: MCP summaries argument E2E,
  tools/list schema)

## 2026-07-10 — Return zeroness summary (DivByZero interprocedural)

### Added
- **ReturnZeroness summary field**: NeverZero/MaybeZero/Unknown for
  integer-returning functions — the mirror of null, the same mini
  value-flow is now domain-templated (`ReturnFlowAnalysis<ValueOf,
  Refine>`; vstateOf/zstateOf + applyNullCond/applyZeroCond). bool
  deliberately excluded (`return ok;` falses would produce MaybeZero
  everywhere).
- **walkZeroCondition** added to ConditionWalk (the symmetric of null);
  DivByZeroRule::applyCondition and the summary mini-flow share the same
  interpretation (behavior-preserving — DivByZero's edge tests
  unchanged).
- **DivByZero consumption via the assignment path**: `int d = badSource();`
  → d MaybeZero → unguarded division warns + "possibly-zero value" trace
  note; guards (`if (d != 0)`) silence it via the existing edge
  refinement. The Juliet CWE369 flow-variant source
  (`data = 0; ... return data;`) is now visible across functions/files
  (cross-TU tested).
- **Deliberate limit (pinned by test)**: a direct `x / f()` divisor is
  not reported — an unassigned call result cannot be guarded
  (`if (f() != 0) x / f()` is a fresh call), reporting it would spawn an
  FP family in real code.
- **Summary file format v2** (4th column zeroness); v1 files are
  recognized on load (zeroness Unknown), extra/missing fields rejected
  wholesale.
- FP-killer tests: if a 0 inside the source is later overwritten,
  NeverZero → silent (a flow-insensitive shortcut would warn incorrectly
  here).

### Verification
- 209/209 tests (ctest + single-process; +8: 7 zeroness behaviors +
  v1-file compatibility; persistence tests migrated to the v2 format)
- Corpus could not be run locally (proxy blocks the tarball) — the pin
  guard is the referee in CI; the CWE369 hitrate impact will be seen in
  the PR's Juliet run

## 2026-07-10 — Baseline v2: line-independent key

### Changed
- **The baseline key no longer contains the line number**: instead, the
  FNV-1a 64 hash of the finding line's trimmed TEXT content (not
  std::hash — the baseline goes into the repo and must match one
  produced on a different machine; FNV is stable across platforms). When
  code is added above and the finding shifts, the baseline stays valid
  (v1's known limitation solved); if the line ITSELF changes, the
  finding reappears — deliberate: a changed line should be re-reviewed.
  Thanks to trimming, an indentation-only change does not refresh it.
- **Multiset semantics**: findings with identical line+message are
  tracked by COUNT — baselining one of two separate `delete p;` lines
  does not hide the other (set semantics would swallow both; a source of
  silent FNs).
- **Backward compatibility**: the v2 file is written with a versioned
  header; old headerless v1 files are recognized on load and keep
  matching with the old line-numbered meaning. filter stayed const
  (counters are consumed on a local copy; repeated calls are
  independent).

### Verification
- 201/201 tests (ctest + single-process; +6: line shift, indentation,
  changed line reappears, identical-line counter, v1 compatibility,
  header)
- 2026-08-12: Qualified the current libgit2 head with 3/3 accepted repetitions at 168/168 translation units, 0 broken units, 0 incomplete functions, and 42 stable findings. The live-head manifest, full-dependency Clang 19 recipe, and three fresh raw receipts are retained and cross-checked automatically. This remains candidate evidence; the Phase 9 ledger is still 3 accepted fixes across 2 projects.
- 2026-08-12: Submitted rtp2httpd PR #709 and marked it ready for upstream review for the first newly triaged current-head candidate. The project builds, its executable smoke check passes, the focused independent path no longer reproduces, and duplicate search found no open match. Phase 9 acceptance remains unchanged pending upstream review.
- 2026-08-12: Submitted libgit2 PR #7345 and marked it ready for upstream review for the independently corroborated missing-mode path. The full project and test targets build, the local test partition passes, focused analysis is clean at 1/1, and no narrowed duplicate match was found. Phase 9 acceptance remains unchanged pending upstream review.
- 2026-08-12: Qualified the current lvgl head across three fresh repetitions: all accepted at 470/470 translation units, 0 broken, 0 incomplete, and 19 deterministic findings. Added a minimal frozen configuration profile required by the current build. This remains candidate evidence; the Phase 9 ledger is still 3 accepted fixes across 2 projects.
- CLI smoke: baseline written, 2 lines added at the top of the file,
  re-analysis "1 known finding(s) filtered by baseline → Clean"

## 2026-07-10 — Cross-TU v2: summaries to disk (incremental whole-program)

### Added
- **`--summary-out` / `--summary-in`**: harvested cross-TU function
  summaries are written to a versioned, line-based text file and loaded
  in later runs. The incremental whole-program story is complete:
  harvest the whole project once, then analyze the CHANGED file on its
  own but with whole-project knowledge (a "may return null" callee in
  another file is visible even in a single-file run — CLI smoke + E2E
  test prove it).
- **Harvest in the rules pass** (RuleEngine::enableGlobalHarvest): from
  the local table runAll already builds per TU, before cleanup — the
  second-parse cost of whole-program mode is not paid. That is why
  `--summary-out` also works without `--whole-program`.
- **Safety invariants**: a corrupt/missing file is rejected WHOLESALE
  (registry unchanged; analysis continues conservatively without
  summaries — warning on stderr); conflicting records fall to the weaker
  claim with the same conservative merge as harvest (N+M→U, R+F→O) — a
  wrong strong claim cannot enter via the file path. Deterministic
  output (sorted map) — the summary file is diffable, "did the summary
  change" is a file comparison.
- 4 new i18n messages (SummariesLoaded/Saved, SummaryLoad/SaveError).

### Verification
- 195/195 tests (ctest + single-process; +5: format round-trip, conflict
  merge, corrupt file rejection ×3 variants, missing file, E2E
  summary-out→summary-in cross-TU finding + summary-less control group)
- CLI smoke: harvesting callee.cpp produced `find/1 M O`; analyzing
  caller.cpp on its own with `--summary-in` showed the null-deref
  warning with a trace note

## 2026-07-10 — MCP v2: AST cache in the warm process

### Added
- **SourceManager warm AST cache** (`enableWarmCache`): in a long-lived
  process (MCP server) parsed TUs are kept for the process lifetime;
  later analyze calls on the same file don't pay the parse cost.
  Measurement (--serve, 5 calls): warm 0.51s vs cold 1.50s — repeat
  calls ~6x (on a small file; the gap widens with real header load).
- **Design invariant: a stale AST is never served.** Key is
  path+build-path; fingerprint is size+mtime. On mismatch the input is
  rebuilt. A test proves this end to end: when the file changes, the old
  use-after-free disappears, the new div-by-zero appears
  (WarmCache_InvalidatedOnChange).
- **Scope deliberately narrow**: only the MCP serve path enables it
  (`Config::setWarmCache`); off in CLI one-shot runs — keeping all ASTs
  alive while scanning a large directory is wrong memory-wise. Memory
  ceiling kMaxCachedAsts=16 (flush everything on overflow; not worth LRU
  complexity).
- Its relation to the filter-leak lesson was noted: here cross-call
  persistence IS the feature, correctness is protected by a
  content-derived key — global state isn't forbidden, keyless global
  state is.

### Verification
- 190/190 tests (ctest + single-process; +2: second-call hit counter and
  identical findings, fresh findings on a changed file)

## 2026-07-10 — Shared condition-walk skeleton (ConditionWalk)

### Changed
- **engine/ConditionWalk.h** (header-only): `walkCondition` — the shared
  backbone of branch-condition walking (`!` flips the edge, `&&` both
  sides on the true edge, `||` both sides on the false edge,
  variable-on-left normalization/mirroring for comparisons) +
  `walkNullCondition` — a ready-made summary of the pointer-null domain.
- **Four clients moved to the single skeleton** (behavior-preserving):
  NullDerefRule, MemoryLeakRule (null-edge only), the FunctionSummary
  mini-flow (null domain) and DivByZeroRule (zero domain, generic
  skeleton). The duplication the return-nullness round had grown to
  three copies dropped to zero; adding a new edge-knowledge domain is
  now two lambdas.

### Verification
- 188/188 tests (ctest + single-process) — pure refactoring; corpus and
  Juliet guards are the referee in CI

## 2026-07-10 — Return-nullness dataflow (the heart of summary v2)

### Added
- **`return p;` paths are now flow-sensitive** (`FunctionSummary`):
  pointer locals/parameters are tracked with a per-function mini
  null-flow — as a client of our own engine (runDataflow): two-phase
  reporting, assume-edge refinement and the lattice-height ceiling come
  for free. Every REACHABLE return contributes from the converged state
  (a return in dead code contributes nothing); the aggregation rule is
  the same as before (any null path → MaybeNull; all paths NonNull →
  NeverNull).
- **A flow-insensitive shortcut was deliberately rejected** (design
  record): the "was NULL ever assigned to the variable anywhere"
  approach produces a wrong MaybeNull for the common `p = NULL; p = &g;
  return p;` pattern and would burn precision 1.000. FP-killer
  regression test: InitNullThenSet.
- The early-return guard resolves correctly: `if (!p) return &fb; return p;`
  → both paths NonNull → **NeverNull** (thanks to assume-edge).
- The Juliet flow-variant source is now visible: `badSource(data){ data =
  NULL; return data; }` → MaybeNull → the caller's unguarded use warns
  (combined with cross-TU, the 61/63/64 families connect).
- The fast path is preserved: if no return returns a variable, no CFG is
  built (structural evaluation — the common case stays free).

### Deliberate limits
- Parameter passthrough (`int* id(int* p){ return p; }`) stays Unknown —
  a parameter-sensitive summary (nullness as a function of the argument)
  is a separate horizon; documented with a test.

### Verification
- 188/188 tests (8 new ReturnFlowTest: FP-killer, guarded fallthrough,
  definite-null, chain propagation, Juliet badSource pattern, cross-TU
  flow, param limit)
- Mini-suite clean end to end; the real corpus/Juliet impact will be
  read from CI (corpus numbers may deliberately change — the guard
  catches it, pins get updated with justification in the same PR)

## 2026-07-10 — Horizon 2 opening: cross-TU summaries (--whole-program)

### Added
- **Cross-TU store in SummaryRegistry**: qualified-name+arity key, ONLY
  externally-linked functions (static file-locals are not keyed — in
  Juliet they exist under the same name in every file and would produce
  wrong matches; soundness test `StaticCallee_NotShared`). On key
  collision (C++ overloads) fields merge conservatively:
  returnNullness→Unknown, param→Opaque — no wrong strong claim can be
  born.
- **`--whole-program` two-pass mode**: pass 1 harvests summaries from
  all TUs (`harvestGlobal`), pass 2 runs the rules — real summaries
  instead of Opaque on cross-file calls. The cost is a second parse;
  deliberate, opt-in via the flag. The summary computation itself also
  lands in the store (cross-TU nullness chains resolve).
- MCP hygiene: `~StaticAnalyzer` clears the store too (application of
  the filter-leak lesson — summaries don't leak across runs).
- The Juliet harness runs with `--whole-program`: flow variants
  (61/63/64...) split source/sink across a/b files — the recall impact
  will be measured from this PR's run.

### Verification
- 178/178 tests (5 new CrossTU tests: MaybeNull return, free-wrapper
  double-free, leak-behind-read-only-visible, static-not-shared,
  harvest-less control group)

## 2026-07-10 — Balanced metrics (F1) + Juliet score guard

### Added
- **Case-based F1** (`juliet_eval.py`): each file is a case — a matching
  finding in the bad function = case-TP, in good = case-FP, a silent bad
  file = FN. `rcaseprec/rf1` fields on the `JULIET_RESULT` line.
- **A second operating point**: the Error-only slice (`eprecision`) —
  the precision of definite claims is visible on its own.
- **ROC deliberately ABSENT** (justified in the README): the analyzer is
  evidence-based binary, not probabilistic; with no sweepable threshold
  an AUC from a two-point "curve" would be misleading. The honest
  counterpart: two operating points.
- **Juliet score guard**: `scripts/juliet_expected.txt` per-CWE
  rprecision/rhitrate floors; a violation is `JULIET_GUARD_FAIL` +
  exit 1 = CI red. The workflow trigger widened to `src/**`, `tests/**`
  and CMakeLists: the benchmark runs on EVERY PR touching analysis code
  (suite cached, ~3.5 min) — the "Juliet's CI weight" decision thus
  closed with full integration; docs-only PRs are exempt.

### Verification
- Mini-suite: F1/eprecision lines + guard OK path; the violation path
  (exit 1) verified pipe-free with a tight floor.

## 2026-07-10 — Path sensitivity for all rules: GuardedDisjuncts component

### Changed
- **The disjunct machinery was lifted into a shared template**
  (`engine/GuardedDisjuncts.h`, header-only): `Guarded<VarMap>` +
  `GuardedState<VarMap>` + `mergeGuarded` / `flattenGuarded` /
  `refineGuardedFacts` / `normalizeGuarded` — the value merger
  (mergeVal) is parametric. MemoryLeakRule moved from its local copy to
  the template (behavior identical, 168 tests unchanged).
- **UninitPointerRule + NullDerefRule port**: both rules use
  GuardedState; in NullDeref the pointer-nullness refinement
  (applyCondition) is additionally processed per disjunct — int facts
  and pointer guards work together in the same function. Target FP
  families: uninit-ptr 178 (char_07/08 pattern), null-deref 241
  (int_07/08/09 pattern) — real impact from this PR's Juliet run.

### Verification
- 173/173 tests (5 new: uninit/null correlated + anti-correlated +
  together-with-pointer-guard)
- Mini-suite: triple guard chain (`if(t) malloc; if(t) deref; if(t) free`)
  fp=0 across all rules, tp preserved

### Juliet impact (PR #18 run — measured)
- uninit-ptr FP 178→**80**; null-deref CWE416 noise FP 241→**129**;
  CWE476 overall precision 0.446→0.526. Mapped precisions stay 1.000.
- Coincidental "TPs" got cleaned up too (uninit 47→15, null-deref/416
  140→65): in the `if(staticTrue) data=NULL; if(staticTrue) *data` case
  "may be uninitialized" was the wrong justification, counted as TP only
  because it landed in the bad function — the actual defect is caught by
  null-deref (139 TP unchanged).
- The remaining FP families shrank to three principled limits: call
  guards (deliberately not keyed), distinct-global pairs (values outside
  the TU — cross-TU/Horizon 2), C++ tmpData local aliases (local alias
  tracking).
- A methodology note was added to the README: Juliet good functions are
  only free of the CWE under test — a memory-leak finding in a CWE416
  good counts as a "general FP" but may be a real leak; the robust
  metric is the mapped columns.

## 2026-07-10 — Targeted path sensitivity (guarded disjuncts)

### Diagnosis (from FP_SAMPLE data)
Nearly all Juliet FPs reduced to ONE pattern: the same invariant
condition tested twice (`if(globalFive==5) alloc; … if(globalFive==5)
free;` — the 05/07/09/10/11 control-flow families of the good variants).
When paths mixed at the join, a ghost "path that allocs but never frees"
was born. memory-leak's 92 FPs + its ~646 FPs in other CWE files,
uninit-ptr's 178, null-deref's 241 all point at the same root cause.

### Added
- **engine/PathFacts**: reduces conditions to a canonical key
  (`var REL literal`; NE/GT/GE normalized to EQ/LT/LE by inversion).
  Only integer variables never assigned/address-taken within the
  function and not volatile are keyed; function calls NEVER (rand()
  correlation would be wrong). `collectMutatedDecls` visitor.
- **MemoryLeakRule's State became a disjunct set**: at most 4
  (condition-facts, var-states) pairs; refineOnEdge drops a
  contradicting disjunct; on ceiling overflow, widening (facts
  intersection + var join) falls back to today's behavior. **The engine
  did not change** — the duck-typed State design carried the disjunctive
  lattice inside the analysis.
- Reporting is the same logic as today over the flattened view; the win
  is that dropped disjuncts never enter the join.

### Side benefits
- Correlated double-free/UAF is now CAUGHT (previously FN):
  `if(f) free(p); if(f) free(p);` only the Freed path enters the second
  body.
- If a never changes inside a `while(a)` body, the exit path means a==0 —
  the old exit-leak artifact disappeared (the NestedLoopConditionalFree
  test was updated to the semantics; a realistic mutated variant added).

### Deliberate limits (documented + tested)
- A call between the two guards may change the global → correlation can
  hide a real defect (FN direction; `CallBetweenCorrelatedGuards` test).
  No such risk with local/param conditions (a call cannot touch a local
  whose address never escapes).

### Verification
- 168/168 tests (10 new PathSensitivity + &arg escape test)
- Mini-suite end to end: goodB2G correlated guard fp=0, bad leak tp=1

### Juliet impact (PR #17 second run — measured)
| Rule | Before | After |
|------|--------|-------|
| memory-leak | 103 TP / 92 FP (p=0.528) | 103 TP / **61 FP** (p=0.628) |
| double-free | 47 TP | **79 TP** (+32; correlated double-free was FN) |
| use-after-free | 99 TP | **174 TP** (+75; hitrate 0.247→0.435) |

Path sensitivity went beyond cutting FPs and exposed hidden TPs —
defects invisible in the merged-path analysis became visible with
disjuncts. Extra fix: a `sink(&data)` argument now counts as an escape
(the Juliet 63x variant FP). Remaining FP families: uninit-ptr 178 +
null-deref 241 (the disjunct port — next round); part of the remaining
61 FPs in CWE401 are distinct-global pairs (globalTrue/globalFalse
values live outside the TU — an honest limit).

## 2026-07-10 — Juliet measurement accuracy + global filter leak fix

### Fixed (product bug — found by the tests)
- **Global function/line filter leak**: the `StaticAnalyzer` ctor set
  the global filter, nobody ever reset it. In a long-lived process (MCP
  server, single-process test run) a filtered analysis silently pruned
  SUBSEQUENT analyses. How it was found is instructive: when the test
  binary ran in a single process, InterproceduralTest's 11 tests
  expecting positive findings failed — because `ctest` runs each test in
  its own process, CI could never see this (the "conservatism" tests
  expecting 0 also passed spuriously since everything was filtered).
  Fix: `~StaticAnalyzer()` clears the filter (RAII); regression test
  `FilterStateResetAfterScopedAnalyze`; a **single-process test step**
  was added to CI so this bug class can never hide again.

### Changed
- **`double-free` now has its own rule_id** (previously under
  `memory-leak`; matching the `use-after-free` precedent). The CWE415
  mapping and the `--disable-rule`/baseline taxonomy can tell the
  finding type apart. README rule table updated.

### Added (measurement accuracy)
- **juliet_eval.py reports two views**: OVERALL (all findings in the
  file — the noise the user would see) + MAPPED (only the rule of the
  CWE under test — the rule's true quality). A per-rule tp/fp breakdown
  is printed; `rtp/rfp/rprecision/rhitrate` fields added to the
  `JULIET_RESULT` line (old fields preserved).
- **Strided sampling** in `run_juliet.sh`: `head -N` was picking the
  alphabetically first variant family (in CWE369 the entire first 400
  files came out `float_*` → 0 findings). LIMIT files are taken at equal
  intervals across the list — deterministic, all variant families
  represented.

### Verification
- 157/157 tests (ctest + single-process); on the synthetic mini-suite
  (CWE476/415/369) the mapped view and the new id give end-to-end
  precision 1.000.

### First REPRESENTATIVE numbers (this PR's CI run; strided sampling, 400/CWE)
| CWE | Mapped precision | Mapped hitrate | Overall precision |
|-----|-----------------:|----------------:|------------------:|
| CWE476 | **1.000** (139/0) | 0.347 | 0.446 |
| CWE415 | **1.000** (47/0) | 0.117 | 0.264 |
| CWE416 | **1.000** (99/0) | 0.247 | 0.273 |
| CWE369 | **1.000** (18/0) | 0.045 | 1.000 |
| CWE401 | 0.528 (103/92) | 0.250 | 0.528 |

The dramatic improvement over yesterday's table is the measurement
getting fixed: **four rules produce zero FPs** in their own CWE
(validation of the "unknown stays silent" design). The source of the
noise became clear: the memory-leak rule (its own 92 FPs + 646 FPs in
other CWE files) and uninit-ptr in CWE476 good functions (178 FPs) —
tomorrow's number-one improvement targets. A Benchmark section was added
to the README (with methodology + honest-reading notes). CWE369 is now
visible: 18 TP / 0 FP; the low hitrate is deliberate (float division is
defined in IEEE754 — not reported; rand()/socket sources are honestly
Unknown).

## 2026-07-09 — First real Juliet numbers (PR #14)

### Fixed (benchmark harness)
- **A false-green run was caught and closed**: in the first real run
  `run_juliet.sh` could not find its own directory because of a relative
  `BASH_SOURCE` after `cd`, and the `| tee` pipe masked the error code —
  0 CWEs were scanned but the job looked green. Fixes: `SCRIPT_DIR` is
  resolved BEFORE any `cd`; the suite root hardened with `find`
  fallbacks; the benchmark step runs with `shell: bash`
  (`-eo pipefail`).

### First real results (alphabetically first 400 files per CWE)
| CWE | TP | FP | Precision | File hit rate |
|-----|----|----|-----------|---------------|
| CWE476 NULL Pointer Deref | 216 | 262 | 0.452 | 0.375 |
| CWE401 Memory Leak | 64 | 58 | 0.525 | 0.155 |
| CWE415 Double Free | 55 | 145 | 0.275 | 0.138 |
| CWE416 Use After Free | 280 | 742 | 0.274 | 0.700 |
| CWE369 Divide by Zero | 0 | 0 | 0.000 | 0.000 |

### Analysis of the numbers (the plan for the next round)
1. **CWE369 = 0 findings is not a rule bug, it's sampling bias:** the
   file list is sorted alphabetically and `head -400` is taken; in
   CWE369 the `float_*` variants come first and the DivByZero rule
   DELIBERATELY skips float division (division by 0 is defined in
   IEEE754: inf/NaN — it's integer division that is UB). The entire
   first 400 files turned out to be float variants.
   → Fix: deterministic strided sampling instead of `head` — 400 files
   at equal intervals across the list, all variant families represented.
2. **The eval counts findings from all rules:** a `memory-leak` warning
   in a CWE416 file is booked as an FP against UAF precision. Two views
   are needed: overall precision (what the user sees) + the precision of
   the rule matching the CWE (the rule's true quality). → per-rule
   breakdown + a CWE→rule mapping in juliet_eval.py.
3. **The double-free finding ships with the `memory-leak` rule_id** (UAF
   has its own identity, double-free doesn't). For the CWE415 mapping
   and the user taxonomy it should get its own `double-free` id
   (pre-release — the baseline cost of an id change is near zero right
   now).
4. The CWE415/416 good-function FPs (their real size will show once
   item 2 is fixed) are rule-improvement candidates; the CWE401 file hit
   rate (0.155) is low — most Juliet leaks live in source/sink function
   pairs (interprocedural flow), the known v1 limit.

No numbers went into the README: this table does not go into the public
showcase before the sampling bias is fixed. Next round: harness fixes →
representative numbers → README benchmark section.

## 2026-07-09 — Juliet measurement infrastructure (Horizon 1 opening)

### Added
- **`Diagnostic.function`**: every finding now carries the qualified
  name of the function it sits in — the `function` field in JSON,
  `logicalLocations` in SARIF. (Juliet scoring relies on it; general
  value for agents too.)
- **`--files <list>`**: analyzes the sources in a list file containing
  one path per line — for benchmarks and bulk agent requests.
- **scripts/run_juliet.sh + juliet_eval.py**: downloads NIST Juliet
  C/C++ 1.3 (cached; skippable via `JULIET_DIR`), scans the 5 CWE
  directories matching our rules (476/401/415/416/369), filters out
  w32/pthread variants, produces a compile DB per CWE, scores findings
  with the Juliet naming convention: in a `bad` function → TP, in a
  `good` function → FP. Output: precision, file hit rate and
  grep-friendly `JULIET_RESULT` lines for trend tracking.
- **.github/workflows/juliet.yml**: weekly + manual trigger (with a
  file-limit input); the suite is cached; results in the job summary.

### Verification
- End to end with the synthetic mini-suite: TP=1 FP=0 in CWE476 and
  CWE415, precision 1.000. Real numbers will come from the first
  workflow run.
- 156/156 tests (the function field pinned in the main test path)

## 2026-07-09 — Interprocedural v2: alias tracking

### Added
- **Alias tracking in parameter effects** (`engine/FunctionSummary`):
  a two-pass design — (A) copy graph + taint seeds, (B) effects resolve
  to the parameter through clean aliases.
  - `void destroy(int* p) { int* cur = p; free(cur); }` is now **Frees** —
    cursor-style destructors (every C library's `*_Delete`) joined
    double-free/UAF detection through the wrapper. The real cJSON_Delete
    shape (the parameter is reassigned in a loop) is Frees with
    may-semantics.
  - **Taint rules** (a wrong Frees/ReadsOnly claim would spawn FPs): a
    local fed from a dirty source (`l = pick()`), address-taken (`&l`),
    static-local or reachable from more than one parameter is NOT a
    clean alias; a parameter reaching such a local falls to Stores.
    Taint propagates through the copy graph (a copy of dirty is dirty).
  - Read-only use through an alias also stays ReadsOnly (the leak stays
    visible); the alias being written to a global/returned is Stores
    (escape preserved).

### Verification
- 156/156 tests (8 new alias tests + the old conservatism test flipped
  to a Frees expectation: `AliasingCallee_NowFrees_DoubleFree`)

## 2026-07-09 — Phase 4 opening: interprocedural analysis v1 (function summaries)

### Added
- **SummaryRegistry** (`engine/FunctionSummary.h/.cpp`): per TU, BEFORE
  the rule runs, all functions with bodies are summarized; the table is
  cleared when the TU ends (so TU-local `FunctionDecl*` keys don't
  dangle).
  - **Return nullness:** NeverNull (all paths definitely non-null) /
    MaybeNull (some path may return a null literal) / Unknown. Via
    literal, `new`, `&x`, string and call chains; returning a variable
    is Unknown (v1 limit).
  - **Parameter effects:** Frees / ReadsOnly / Stores / Opaque.
    Deliberately blind to aliasing: assigning the parameter to anything
    is Stores (cJSON_Delete's `q=p; free(q)` pattern stays Escaped until
    v2).
  - **Fixed-point scan** (≤5 rounds, each from scratch): chains resolve
    (w2→w1→free), recursion cannot produce a strong claim (starts
    Unknown/Opaque).
- **NullDeref consumption:** `p = f()` — if the summary is MaybeNull, an
  unguarded dereference **warns** (guarded use is clean via
  assume-edge); a NeverNull chain is silent. New trace message:
  "possibly-null value here (callee may return null)".
- **MemLeak consumption:** call classification consults the summary —
  free-wrappers (including guarded `if(p) free(p)`) count as **Frees** →
  double-free and use-after-free through wrappers are now caught;
  read-only helpers are effect-free → the **leak behind them became
  visible**; storing/opaque calls are Escaped (no regressions).
- Safety hygiene: the `getIdentifier()` pattern instead of `getName()`
  (undefined behavior risk on operator overloads).

### Verification
- 148/148 tests (133 + 15 interprocedural: chains, recursion, mutual
  recursion, alias conservatism, external function regression)
- End-to-end demo: 3 new detection classes (wrapper-UAF with trace,
  possibly-null return with trace, leak behind a read-only helper) +
  defensive code fully clean

## 2026-07-09 — Phase 3 complete: MCP server mode

### Added
- **`--serve`** (`src/server/McpServer`): an MCP (Model Context
  Protocol) server — line-delimited JSON-RPC 2.0 over stdio. Agents like
  Claude Code start the process and call the `analyze` tool after every
  edit; findings come back as structured JSON with dataflow traces.
- Methods: `initialize`, `notifications/*` (no response), `ping`,
  `tools/list`, `tools/call` (`analyze`: `path` + optional
  `build_path`/`functions`/`lines` — incremental scoping is usable from
  MCP too).
- NO new dependency for JSON: the `llvm/json` library from the
  already-linked LLVMSupport was used.
- `handleMcpMessage()` decoupled from I/O — protocol behavior pinned
  with 10 unit tests (error codes -32700/-32601/-32602 included).
- Config: `--serve` flag; `addFunctions`/`addLines` public
  (programmatic scoping).

### Verification
- 133/133 tests (123 + 10 MCP)
- End-to-end real client flow: initialize → initialized notification →
  analyze call → structured response with count/findings/trace

## 2026-07-09 — Incremental v2: hunk → function mapping

### Added
- **`--lines <N-M,K>`**: only functions intersecting the given line
  ranges are analyzed. Ranges apply to the MAIN file under analysis
  (functions in headers are out of scope — diff hunks belong to the main
  file anyway). AND semantics when combined with `--function`.
- **analyze_diff.sh v2**: extracts changed line ranges from
  `git diff -U0` hunk headers (`+start,count`) and passes `--lines` per
  file. For deletion-only hunks (count 0) the insertion-point line is
  taken. Result: *the LLM changes a function → the script extracts the
  ranges from the diff → only the touched functions are re-analyzed* —
  a fully automatic incremental loop.
- Division-of-labor principle: git logic in the script, AST logic in the
  tool.

### Verification
- 123/123 tests (119 + 4 line filter: signature-line intersection, empty
  range, out-of-scope range)
- End to end: in a file with two buggy functions only one was touched →
  the script produced `--lines 8-8` → only the touched function's
  finding was reported

## 2026-07-09 — Phase 3 continued: incremental analysis primitive

### Added
- **`--function <names>`** (`core/FunctionFilter`): only functions whose
  name matches are analyzed — plain name (`parse`) or qualified name
  (`Parser::parse`), comma-separated list, repeatable flag, `function=`
  config key. Millisecond-scale targeted analysis for "re-check only the
  function you changed" in the agent/IDE loop. All four rules' callbacks
  honor the filter. 4 tests (global cleanup via an RAII guard).
- **`scripts/analyze_diff.sh <binary> <git-ref> [args...]`**: runs the
  C/C++ files changed since the given ref through the analyzer; exits 1
  if there are findings, stops with exit >1 on an analyzer error. A
  "check only the touched files" gate in CI. Verified end to end with a
  simulated git repo (diff with a finding → 1, clean diff → 0).

### Test results
- 119/119 tests passed (115 + 4 filter tests)

## 2026-07-09 — Phase 3 opening: dataflow traces

### Added
- **TraceNote** (`core/Diagnostic.h`): an event-chain step attached to a
  finding (file/line/column/message). Not part of ordering or equality.
- **Event recording in the rules** (before/after diff in the reporting
  pass):
  - MemLeak: "allocated here" / "freed here" (on UAF, double-free, leak
    reports)
  - NullDeref: "assigned null here"
  - DivByZero: "assigned zero here"
  - UninitPtr: "declared without an initializer here" (declaration
    point)
- Notes are attached at the END of the run (pending-report pattern) —
  since the reporting pass's block order is not source order, events may
  not be fully collected yet at report time. Sorted in source order,
  capped at 6.
- **Reporter support**: indented `-> file:line:col message` lines on the
  console; a `notes` array in JSON; `relatedLocations` in SARIF (GitHub
  code scanning shows them in the finding detail).
- i18n: 5 new trace messages (EN/TR).

### Why
The first stone of the Phase 3 vision: the trace is the answer to "why
does this finding exist?" for both humans and LLMs — the input to the
automatic fix loop.

### Test results
- 115/115 tests passed (110 + 5 trace tests)

## 2026-07-09 — Test hardening: best/worst-case matrix (+2 catches)

### Added
- **StressEdgeCaseTest.cpp** (17 tests, three sections):
  - *Best case* (FP boundary): the goto-fail cleanup idiom, ternary
    guard (division + null), break-edge guard, continue guard, comma
    operator sequencing
  - *Worst case* (FN + convergence boundary): 8 levels of nested if,
    30-variable product lattice (ceiling scaling test), 12-arm else-if
    chain, conditional free in nested loops, do-while first iteration,
    backward loop via goto, switch without default
  - *Documented limits*: unreachable code is not analyzed,
    self-assignment FN, compound-assignment FN, conditional double-free
    FN — if behavior changes the test breaks, kept in sync with the todo

### Two rule gaps the tests caught in the first round (fixed)
- **MemLeak malloc-failure FP**: a leak was reported on the
  `p = malloc(); if (p == 0) return -1;` path — there is no memory to
  leak on the null edge. `refineOnEdge` added to MemLeak: on edges where
  p is null (`!p`, `p == NULL/0/nullptr`, truthiness false, `&&`/`||`)
  Allocated → None. The FP on C's most common pattern closed.
- **DivByZero ternary FP**: the recursive DivFinder inside onStatement
  was discovering the division a second time, with the wrong state, in
  the join-block element containing it (a warning despite the
  `z ? 100/z : 0` guard). Moved to top-node classification per the
  engine contract.

### Test results
- 110/110 tests passed (93 + 17 stress/edge)

## 2026-07-09 — Engine fix: reporting after fixpoint

### Fixed (the corpus's first catch)
- **Reporting moved to the fixpoint**: `onStatement` is now called in a
  separate reporting pass after stabilization, NOT during worklist
  iteration. In the old behavior a report was produced on the first
  visit of a do-while/for body while the back-edge state did not exist
  yet, and the line dedup then blocked the later correct state's
  correction. That is why cJSON's `parse_array` linked-list-building
  pattern came out "definitely null" (Error) — the correct answer is
  MaybeNull (Warning). The regression test fails with the old engine and
  passes with the new one (falsification verified).
- **MemLeak transfer purified**: reassignment-leak and double-free
  reports moved from transfer into onStatement (engine contract:
  transfer is a pure state function, reporting happens only in the
  fixpoint pass).
- **Path canonicalization**: `tests/../cJSON.c` and `cJSON.c` are the
  same file — dedup and baseline keys are reliable via
  `weakly_canonical`.
- **Macro locations**: all rules use the expansion loc; the
  empty-file-name problem for findings inside macros fixed (seen in
  cJSON unity test macros).

### Test results
- 93/93 tests passed (92 + 1 engine regression test)

## 2026-07-09 — Real-world corpus in CI

### Added
- **scripts/run_corpus.sh**: downloads version-pinned cJSON v1.7.18 (C)
  and tinyxml2 10.0.0 (C++), produces `compile_commands.json` with
  CMake, runs codeskeptic. Success criterion: crash-free (exit 0/1);
  finding counts logged for information. The build directory is outside
  the source tree (so CMake feature-test sources are not scanned);
  `CMAKE_POLICY_VERSION_MINIMUM=3.5` (CMake 4 compatibility).
- **CI step "Real-world corpus"**: a regression run over two real
  projects on every PR.

### Note
- Since this session's network proxy limited GitHub tarball downloads to
  the repo scope, the script was verified locally with a simulated
  project; the PR CI verifies the real corpus run.

## 2026-07-09 — Fifth rule: NullDerefRule

### Added
- **NullDerefRule** (`src/rules/NullDerefRule.h/.cpp`): null pointer
  dereference detection with CFG dataflow. `NullState` lattice
  (Unknown / Null / NonNull / MaybeNull); `nullptr`, `NULL`, `0` literal
  flow; `&x`, `new`, string literal → NonNull; `&p` escape → Unknown
  (conservative). Branch-condition refinement: `p`, `!p`, `==`/`!=`
  nullptr (both directions), `&&` true / `||` false short-circuit.
  Definite null deref → Error, possible → Warning. Unknown values stay
  silent — a parameter dereference produces NO report (the old
  NullPointerRule's 68-FP trap).
- 16 tests: definite/possible deref, `->` and `[]`, guard patterns
  (truthiness, early return, definite error on the true branch of
  `== nullptr`, `&&` chain, null at while-loop exit), conservatism tests
  (parameter, opaque return, out-param escape).

### Verification
- 92/92 tests passed
- Realistic pattern file: for-loop guard, early return, `!= nullptr &&`
  chain, opaque `find()` → zero FPs; 2 deliberate bugs → 2 correct
  findings

## 2026-07-09 — Phase 2 continued: use-after-free + baseline

### Added
- **Use-after-free detection**: an `onStatement` hook on
  MemLeakAnalysis — dereferencing a pointer in Freed state (`*p`, `p->`,
  `p[i]`, top-node detection) produces an Error with the
  `use-after-free` rule_id. Reuses the existing Freed state; no extra
  dataflow run. 5 tests.
- **Baseline support** (`src/analyzer/Baseline.h/.cpp`):
  `--write-baseline <file>` records the current findings and exits clean
  (baseline production in CI); `--baseline <file>` filters known
  findings, only NEW findings are reported. Key:
  `rule|file|line|message` (line drift is a v1 limitation — documented).
  Config key: `baseline=`. 4 tests.

### Test results
- 75/75 tests passed (66 + 5 UAF + 4 baseline)
- End to end: UAF caught; write-baseline → exit 0; second run with the
  baseline is clean

## 2026-07-09 — Phase 2 start: SARIF + suppression

### Added
- **SarifReporter** (`src/reporter/SarifReporter.h/.cpp`): SARIF 2.1.0
  output — direct integration with GitHub code scanning. `--sarif <file>`
  CLI option and `sarif_output=` config key. Severity mapping:
  Error→error, Warning→warning, Info→note. Absolute paths as `file://`
  URIs. 5 tests; output validated with `json.load`.
- **SuppressionFilter** (`src/analyzer/SuppressionFilter.h/.cpp`):
  finding suppression via source comments.
  `// codeskeptic-disable-line [rule,list]` and
  `// codeskeptic-disable-next-line [...]`. A bare marker suppresses all
  rules, a rule list only the listed ones. The suppressed count is
  reported to stderr. File contents are read with caching. 9 tests.
- **MsgId::OutputFileOpenError / SuppressedCount** — a Turkish
  JsonReporter message that had escaped i18n was fixed as well.

### Test results
- 66/66 tests passed (52 + 5 SARIF + 9 suppression)
- End to end: a suppression comment drops the finding, SARIF is valid
  JSON

## 2026-07-08 (night) — Phase 1 leftovers: core consolidation

### Changed
- **DataflowEngine CFG granularity**: `BuildOptions::setAllAlwaysAdd()` —
  subexpressions are individual CFG elements in evaluation order too
  (same as CSA). Analyses now look only at each element's top node;
  nested searching inside a statement (findAll matcher) became entirely
  unnecessary.
- **UninitPointerRule_Ex fully rewritten**: instead of a separate CFG
  build + dataflow run per variable + 5-6 matchers per statement, all
  tracked pointers live in one product lattice (`map<VarDecl*, PtrState>`)
  in a single run. Classification is top-node `dyn_cast` — since the
  node itself says which variable it touches, there is no per-variable
  loop either (O(1) per element). Behavior preserved exactly (14/14
  tests).
- **Iteration ceiling tied to lattice height**: optional
  `latticeHeight()` hook (SFINAE); `maxIterations = numBlocks × (height+2)`.
  All three analyses report their height (variable count × chain
  length). The old default is kept for analyses that don't report one.

### Test results
- 52/52 tests passed; demo findings exactly identical (no behavior
  change)

## 2026-07-08 — Phase 0 (public prep) + assume edges

### Fixed
- **Linux header resolution bug**: the unconditional
  `-isystem /usr/include` was breaking GCC libstdc++'s `include_next`
  chain (`stdlib.h` not found, analysis silently continued with a
  partial AST). Now added only on macOS via `#ifdef __APPLE__`.
  Verification: the previously missed double-free in a demo file
  including `<cstdlib>` is now caught.
- **CMake portability**: the Homebrew `CMAKE_PREFIX_PATH` default only
  under `APPLE`. On Linux the system LLVM is found automatically.
- **Cross-TU duplicate findings**: `Diagnostic::operator==` +
  `operator<` deterministic over all fields; `StaticAnalyzer::run`
  deduplicates with `std::unique` after sorting.

### Added
- **Assume edges (branch-condition refinement)**: an optional
  `refineOnEdge(cond, isTrueBranch, State&, ASTContext&)` hook on
  `DataflowEngine` (SFINAE). On two-successor terminators (if/while/for)
  the predecessor state is refined per true/false edge and merged that
  way.
- **DivByZeroRule guard analysis**: `z != 0`, `z == 0`, `z`, `!z`,
  `z > 0` (+ mirrored forms `0 < z`), `>=`/`<=` false branches,
  `&&`/`||` short-circuit rules. The known guard FP solved;
  `if (z == 0) 1/z` is now caught as a definite error. 9 new tests.
- **DivByZero merge fix**: `Zero + Unknown = MaybeZero` (previously fell
  to Unknown and went silent). `int d = 0; if (z > 0) d = z; 100/d` now
  warns. Only `NonZero + Unknown` falls to ignorance.
- **i18n**: the `core/Messages` module (MsgId table EN/TR, `{0}`/`{1}`
  placeholders). Default English; `--lang tr` CLI option and `lang=`
  config key. All rule messages, reporters and CLI output migrated.
- **GitHub Actions CI**: Ubuntu 24.04 + LLVM 18, build + ctest +
  exit-code smoke test (`.github/workflows/ci.yml`).
- **README** (English, architecture + build + usage) and **LICENSE**
  (Apache-2.0).

### Test results
- 52/52 tests passed (41 existing + 1 dedup + 1 i18n + 9 assume-edge)
- Full verification on Linux (Ubuntu 24.04, LLVM 18.1.3)

## 2026-04-05 — DataflowEngine + DivByZeroRule

### Added
- **DataflowEngine** (`src/engine/DataflowEngine.h`): Template-based
  forward dataflow engine. `Analysis` provides State, initialState,
  merge, transfer, onStatement (optional via SFINAE) through duck
  typing. CFG build, worklist, predecessor merge, successor
  propagation — all shared code in one place.
- **DivByZeroRule** (`src/rules/DivByZeroRule.h`, `.cpp`): Two-phase
  division-by-zero detection. Phase 1: literal `100/0`
  (RecursiveASTVisitor, no CFG). Phase 2: variable divisor CFG dataflow
  (`ZeroState` lattice). Float division excluded (IEEE 754). 10 tests.

### Refactor
- **UninitPointerRule_Ex**: worklist loop removed, uses `runDataflow` +
  `UninitPtrAnalysis`.
- **DivByZeroRule**: worklist loop removed, uses `runDataflow` +
  `DivByZeroAnalysis`.
- **MemoryLeakRule_Ex**: worklist loop removed, uses `runDataflow` +
  `MemLeakAnalysis`. Exit block check via the engine result.

### Test results
- 41/41 tests passed — no behavior change

## 2026-04-05 — MemoryLeakRule_Ex (CFG-based leak + double-free)

### Changed
- **MemoryLeakRule deleted**, replaced by **MemoryLeakRule_Ex**. With
  forward dataflow over the CFG:
  - Memory leak detection (Allocated state in the exit block → Warning)
  - Reassignment leak detection (p=new; p=new → first allocation leaked
    → Warning)
  - Double-free detection (Free again in Freed state → Error)
  - Conservative escape analysis (return, function param → ownership
    transfer)
  - C compatibility: malloc/calloc/strdup/free support
- **classifyStmt fully rewritten**: a `dyn_cast` chain instead of
  matchers (DeclStmt, BinaryOperator, CXXDeleteExpr, CallExpr,
  ReturnStmt). Faster and more accurate.
- 13 tests: simple leak, correct usage, conditional leak, both branches
  delete, return escape, reassignment, malloc/free, function param
  escape, double-free, array new/delete, no allocation, multiple vars

### Test results
- 31/31 tests passed (14 UninitPointer_Ex + 13 MemoryLeak_Ex + 4
  Diagnostic)
- cJSON: 0 findings (no leaks), tinyxml2: 0 findings (all allocations
  managed)

## 2026-04-05 — MemoryLeakRule extension

### Added
- **Matcher 2 — assignment after declaration**: the `p = new int(42)`
  pattern. `BinaryOperator(=)` with pointer LHS, cxxNewExpr RHS.
- **Matcher 3 — return raw new**: the `return new int(100)` pattern.
  `ReturnStmt` with cxxNewExpr.
- **5 new tests**: AssignmentAfterDecl, ReturnRawNew,
  ReturnNullptr_Clean, MultiplePatterns, AssignMessageContainsVarName.

### Test results
- 26/26 tests passed (the existing 6 MemoryLeak tests unbroken)

## 2026-04-05 — string.h warning fix

### Fixed
- **SourceManager.cpp**: three system paths added via
  `ClangTool::appendArgumentsAdjuster()`:
  - `-isystem /usr/include` + `-isystem /usr/local/include` (Linux)
  - `-isysroot <SDK_PATH>` (macOS — found automatically via xcrun)
  - `-resource-dir <CLANG_DIR>` (intrinsic headers like stddef.h,
    stdarg.h)
- **src/CMakeLists.txt**: the paths are discovered at build time with
  `clang -print-resource-dir` and `xcrun --show-sdk-path` and passed
  through as `#define`s.

### Impact
- The `string.h` / `stdlib.h` warnings are completely gone
- cJSON now parses fully — the previous 47 findings (caused by
  incomplete parsing) → 1 real finding
- 21/21 tests still pass

## 2026-04-05 — NullPointerRule → UninitPointerRule

### Changed
- **NullPointerRule deleted**, replaced by **UninitPointerRule**
  (`src/rules/UninitPointerRule.h`, `.cpp`). Uninitialized pointer
  detection — `varDecl(pointerType, unless(hasInitializer),
  unless(parmVarDecl))`. A simple matcher, zero false positives.
- **NullPointerRuleTest deleted**, replaced by **UninitPointerRuleTest**
  (`tests/UninitPointerRuleTest.cpp`) — 11 tests: basic uninit,
  multiple, nullptr/address-of/new/function return clean, parameter
  ignored, mixed, var name in message, no pointer, location.
- **main.cpp**: `NullPointerRule` → `UninitPointerRule`
- **CMake files**: file names updated

### Why?
NullPointerRule caught every `*ptr` dereference (68 findings in cJSON,
mostly false positives). Instead of complex filters (address-of, null
guard), a fundamentally different approach: uninitialized pointer
detection. The matcher is precise, no filter needed.

### Test results
- 21/21 tests passed (11 UninitPointer + 6 MemoryLeak + 4 Diagnostic)
- cJSON: 47 uninit-ptr findings (all real), 0 memory-leak (C project)

## 2026-04-04 — GTest infrastructure

### Added
- **Test helper** (`tests/TestHelper.h`, `.cpp`): `runRule(rule, code)` —
  builds an AST from a string with `runToolOnCode` and runs the rule.
  The shared boilerplate of all tests.
- **DiagnosticTest** (`tests/DiagnosticTest.cpp`): 4 tests —
  severityToString, location format, severity ordering, file+line
  ordering.
- **NullPointerRuleTest** (`tests/NullPointerRuleTest.cpp`): 6 tests —
  basic deref, safe deref (false positive documentation), parameter
  deref, no pointer, multiple deref, location verification.
- **MemoryLeakRuleTest** (`tests/MemoryLeakRuleTest.cpp`): 6 tests —
  raw new int, array, no new, stack alloc, delete still warns, variable
  name in message.
- **CMake test support**: GTest v1.14.0 via FetchContent,
  `gtest_discover_tests`.

### Test results
- 16/16 tests passed (0.84 seconds)

## 2026-04-04 — MemoryLeakRule

### Added
- **MemoryLeakRule** (`src/rules/MemoryLeakRule.h`, `.cpp`): the second
  concrete rule. Searches for the `varDecl(pointerType, cxxNewExpr)`
  pattern with ASTMatchers. Adds the variable name to the message. Does
  not override `defaultSeverity()` — uses the base class's Warning
  default.
- **Test files**: `test_projects/samples/memory_leak.cpp`
- **cJSON test project**: `test_projects/cJSON/` — a real-world C
  project, tested with compile_commands.json.

### Test results
- memory_leak.cpp: 4/4 correct detections (raw new single, array,
  struct, even after delete)
- cJSON: 68 null-deref findings (the pipeline works), 0 memory-leak (C
  project, no new — expected)

## 2026-04-04 — NullPointerRule + main.cpp

### Added
- **NullPointerRule** (`src/rules/NullPointerRule.h`, `.cpp`): the first
  concrete rule. Searches for the `*ptr` dereference pattern with
  ASTMatchers, filters system headers. Callback in an anonymous
  namespace.
- **main.cpp** (`src/main.cpp`): entry point. Read Config → set up
  Analyzer → register rules → run → CI/CD exit code.
- **`codeskeptic` executable**: `add_executable` + `codeskeptic_core` link
  in CMake.

### Fixed
- **StaticAnalyzer constructor**: `sourcePath` may be a file or a
  directory. `is_directory` check added — `addSourceFile` for a file,
  `scanDirectory` for a directory.

## 2026-04-04 — Core architecture

### Added
- **Diagnostic** (`src/core/Diagnostic.h`): the finding data structure —
  severity, location, message. Header-only struct, ordering via
  `operator<`, `DiagnosticList` alias.
- **Rule** (`src/core/Rule.h`): abstract base class —
  `check(ASTContext&, DiagnosticList&)` pure virtual. `enabled_`
  private, `defaultSeverity()` virtual (default Warning).
- **SourceManager** (`src/source_manager/`): Clang LibTooling wrapper.
  Loads `compile_commands.json`, `FixedCompilationDatabase` as fallback.
  AST delivery via callback. The internal Clang chain
  (Factory→Action→Consumer) in an anonymous namespace.
- **RuleEngine** (`src/engine/`): rule manager. `addRule<T>()` variadic
  template, `runAll()` runs the active rules and returns a clean
  DiagnosticList, `enableRule()` toggles by id.
- **Reporter** (`src/reporter/`): abstract base + two concretes:
  ConsoleReporter (stderr), JsonReporter (to a file, safe via
  escapeJson).
- **Config** (`src/config/`): key=value file parser + CLI argument
  parser. Whitelist/blacklist rule management, severity filter, `--help`
  output.
- **StaticAnalyzer** (`src/analyzer/`): facade/orchestrator. Takes the
  Config, wires the components, `run()` flow: build ASTs → run rules →
  filter by severity → sort → report.
- **CMake build system**: LLVM/Clang find_package, `-fno-rtti`
  compatibility, `codeskeptic_core` static library.

### Fixed
- `SourceManager::processAll`: the callback is passed by copy instead of
  `std::move` (re-callability).
- `FixedCompilationDatabase`: working directory `"."` instead of
  `build_path_` (relative-path safety).
- CMake: `LANGUAGES CXX` → `LANGUAGES C CXX` (for LLVM's C check macro).
- Qualified the current Abseil head with 3/3 accepted repetitions: 159/159 translation units, 0 broken units, 0 incomplete functions, and 13 stable findings. The retained manifest and three fresh raw receipts bind the unchanged live head to the current LLVM19 analyzer. This adds candidate evidence only and leaves the accepted-upstream ledger at 3 fixes across 2 projects.
- Qualified the current systemd head with 3/3 accepted repetitions at 496/496 translation units, 0 broken units, 0 incomplete functions, and 0 stable findings. The exact LLVM19 Meson/Jinja/gperf recipe, manifest, and three fresh raw receipts are retained and cross-checked automatically; this adds candidate evidence only and leaves the accepted-upstream ledger unchanged.
- Qualified the current curl head with 3/3 accepted repetitions: 195/195 translation units, 0 broken units, 0 incomplete functions, and 62 stable findings. The live-head manifest and three fresh raw receipts are retained and cross-checked automatically. This adds candidate evidence only and leaves the accepted-upstream ledger unchanged.
- Qualified the current Redis head with 3/3 accepted repetitions: 122/122 translation units, 0 broken units, 0 incomplete functions, and 0 stable findings. The exact manifest and three fresh raw receipts bind the unchanged live head to the current LLVM19 analyzer. This adds candidate evidence only and leaves the accepted-upstream ledger unchanged.
- Qualified the current TensorFlow Lite head with 3/3 accepted repetitions: 240/240 translation units, 0 broken units, 0 incomplete functions, and 74 stable findings. Independent comparison found no exact location overlap, so the accepted upstream ledger remains 3 fixes across 2 projects. Independent review caught and corrected a transcribed revision and finding count; the three checksummed receipts plus exact input manifest are now retained and cross-checked automatically against the frozen record and canonical summaries.
- Recorded the independent evidence audit boundary: the prior eight current-head summaries are not Phase 9 completion evidence because their three raw receipts were not retained. They must be repeated under the new durable receipt gate; TensorFlow Lite is the first fully bound current-head record.
- Kept retained receipt bytes platform-invariant so Windows line-ending conversion cannot invalidate their recorded checksums.
