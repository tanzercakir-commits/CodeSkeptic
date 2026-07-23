# CodeSkeptic — Changelog

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
