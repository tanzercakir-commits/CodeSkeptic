# CodeSkeptic — TODO (aktif işler + açık kararlar)

> Bu belge canlı: sıradaki iş, öncelikler, kullanıcı kararları burada.
> Tamamlanan işler changelog'a taşınır ve buradan silinir. Sabit plan
> ve tüm yol haritası → `PLAN.md`.

## Şu anki durum

Aşağıdaki blok ÜRETİLİR — elle düzenleme. Tazele:
`scripts/check_docs_sync.sh --fix`. CI guard #6 phase* dallarında bunu
git gerçeğiyle karşılaştırır, bu yüzden bayatlayamaz.

<!-- cs:state-begin -->
```
base          = 7dfd375
in_flight     = phase-realworld-release-candidate-factory phase-upstream-validation
verified_main = 7dfd375
progress      = sha256:ad383b5215239a8324b155328f694bbba8b3f7e8a9dd90e5127b9238d7fec952
```
<!-- cs:state-end -->

Serbest not (insanda kalır): Faz 0, Faz 1, Faz 2 ve Faz 3 KAPANDI. v0.4.8 üç
platform paketi, Action, WSL2 ve Docker kapıları yeşil; public release ve GHCR
`v0.4.8` / `latest` kimlikleri doğru. Yanlış GHCR `v0.4.9` versiyonu tam digest ve
tek-tag kapısıyla kaldırıldı, post-delete current koruması geçti ve tek-
seferlik cleanup kodu silindi. Ürün kapsamı 14 bulgu ailesi için merkezi
registry, schema-v2 capability çıktısı ve docs-sync kapısıyla kilitlendi;
experimental bulgular ölçülür/raporlanır fakat verdict'i engellemez. Ölçüm
laboratuvarı exact base/head temiz-kusurlu-gerçek depo makbuzlarını, `csf1`
semantik bulgu kimliğini, Juliet üç-yollu kaçırma sınıflamasını ve PR kalite /
performance / coverage panosunu fail-closed CI sözleşmesine bağladı. Faz 3,
rtp2httpd'yi 38/38 TU'da 4 uygulanabilir / 0 bağlam FP'ye indirdi ve memory-leak
precision'ını 0.714→0.860'a yükseltti; `memory-leak` artık supported/blocking,
bağımsız örneklemi olmayan `resource-leak` experimental kaldı. Makbuzlar
changelog 2026-08-08 kayıtlarında.

## libarchive değerlendirmesi — KAPANDI (2026-08-01)

Üç precision notu, üçü de kapatıldı: BULGU 2 (sign-conversion non-size
sink kapısı) ve BULGU 1 (bounds struct-hack/FAM kuyruk muafiyeti) kod
olarak indi ve ikisi de **önceden yazılmış tahmine karşı** ölçüldü —
19→14 ve 14→13, ikisinde de delta'nın tamamı niyet edilen sınıf,
kolateral sıfır. BULGU 3 kod değil önkoşul; backlog #1'e işlendi.
Yan ürün: corpus pin'i 53→54 merkeze alındı (895c813'ten beri
sürükleniyordu, toleransın içinde sessizce).

## Next work

Phase 6 is merged through PR #133. Its exact squash commit is
`3aa85f9ed773c2473683e5a41593208e8945a0d9`; the squash tree
`12f62243ba39b3b7b49369f843f33af640619efb` matches the fully gated branch
head. The local and remote feature branches are deleted, and local/remote
`main` agree.

Phase 7 is active on `phase-memory-lifetime-v2` and is divided into five
independently measurable RED-to-GREEN slices:

1. **Exact local alias lifetime — boundary locked before implementation.**
   Replace the flow-insensitive alias-free suppression with a per-disjunct,
   exact local pointer-binding relation. A free through an unchanged exact
   alias must update the allocation owner so later dereference or release
   through any still-exact alias reports UAF or double-free. Direct
   reassignment invalidates only the overwritten binding; branch-conflicting,
   non-local, address-exposed, cast-changing, field, heap, and unknown aliases
   remain unproven and cannot create a finding. Reusing an alias for a second
   allocation must no longer hide a first-allocation leak. This development
   contract is stored here, separately from production code, and must not be
   changed during the slice. The exact file set is
   `src/rules/MemoryLeakRule_Ex.cpp`,
   `tests/MemoryLeakRuleExTest.cpp`, this TODO, and
   `docs/devlog/changelog.md`. `PLAN.md`, shared dataflow/guard engines,
   contract grammar, capability tiers, configuration, summary schemas, and
   accepted model channels remain unchanged.

   Contract-first shadow pre-screen: the critical binding, root-resolution,
   merge, release, dereference, and exit decisions all express native pointer
   identity/alias/heap lifetime semantics that the current verifier cannot
   prove. Dogfood is therefore not applicable: proposals 0, eligible 0,
   rejected 0, unsupported 6. No proof-bearing contract is invented; no
   `cs: ai` proposal can become accepted intent. The executable A7 RED fixtures
   and ordinary tests are the referee for this slice.

   **Completion evidence (appended after implementation; the locked contract
   above is unchanged).** Phase 7.1 is locally complete. A per-disjunct exact
   binding now carries releases, UAF, double-free, null-failure refinement,
   and exit-leak evidence through unchanged local pointer copies. Local
   pointer references are distinguished from value copies: a reference tracks
   its bound pointer variable across later allocation, while a copied pointer
   retains only the copied value. Reassignment, conflicting paths, address or
   writable-reference exposure, and cast-changing aliases remain conservative.
   The old alias-reuse accepted FN is now a positive leak fixture. Fifteen
   Phase 7.1 cases and the adjacent reference/Systemd controls pass; direct and
   CTest suites are 1077/1077.

   The first 400-file/CWE Juliet replay exposed a real reference-binding
   assumption bug: CWE401 moved to 92 TP / 17 FP, precision 0.844, below the
   unchanged 0.85 floor. The four added FPs were exactly local `T*&` variant-33
   good sinks. The corrected final replay is CWE401 92/13 (precision 0.876,
   hit rate 0.223), CWE415 119/0 (precision 1.000, hit rate 0.297), and CWE416
   212/0 (precision 1.000, hit rate 0.531). The other rule-matched receipts
   remain CWE476 140/0, CWE369 43/0, and CWE190 23/0. No floor changed. Frozen
   thesis is `clean_fp=0`, `bug_caught=9/15`, 11 findings; self-scan is clean
   and complete at 48/48 TUs; cJSON remains 54 and tinyxml2 9. The tested
   product SHA-256 is
   `2a0a43114832761ea60617bc553393f4b6b7b15fd64cd5bcbdc0e0659f9ad197`.

   Shadow completion report: the six critical binding, merge,
   root-resolution, release, dereference, and exit semantic units were
   considered; proposals 0, eligible 0, rejected 0, unsupported 6. No proposal
   exposed a problem because no native pointer/heap proposal was eligible.
   Independent RED tests, the Systemd full-suite regression, and Juliet exposed
   the implementation and reference-storage assumptions; all are closed.
   Candidate contracts requiring later human review: none. No `cs: ai`
   proposal became accepted intent, and native owned-memory parity remains
   deferred to executable A7 fixtures.
2. **`realloc` success/failure paths — boundary locked before
   implementation.** Preserve the original allocation on failure, transfer
   lifetime on success, and cover direct, temporary, overwrite,
   `reallocarray`, null-input, zero-size, guarded, and unknown outcomes without
   treating possible release as definite.

   The locked development contract is intentionally separate from production
   code. Reallocation authority is limited to direct global-C or `std`
   `realloc`/`reallocarray` calls whose local result and source have the same
   exact pointer type. A distinct temporary with a proven nonzero request
   keeps an exact pending relation: a proven null result preserves the old
   allocation, while a proven non-null result transfers the old lifetime and
   makes the result the owner. A direct overwrite with a proven nonzero
   request reports the possible failure-path leak when an old allocation is
   live. A null source behaves as allocation rather than replacement.
   `reallocarray` additionally requires both multiplicands to be proven
   nonzero; its overflow-failure path preserves the old allocation.

   Zero-size or otherwise unproven-size calls, indirect calls, methods, other
   namespaces, custom wrappers, type-changing results, address-exposed state,
   and conflicting paths cannot prove release, transfer, UAF, double-free, or
   an overwrite leak. Reassignment or exposure invalidates only the pending
   relation. An unresolved temporary result/source pair represents alternative
   outcomes and may emit at most one exit leak unless later evidence separates
   them. This slice does not invent implementation-defined zero-size behavior,
   allocator-family semantics, or native heap/alias proof authority.

   The exact file set is `src/rules/MemoryLeakRule_Ex.cpp`,
   `tests/MemoryLeakRuleExTest.cpp`, this TODO, and
   `docs/devlog/changelog.md`. Shared dataflow/guard engines, allocator
   registries, contract grammar, capability tiers, configuration, summary
   schemas, accepted model channels, and quality floors remain unchanged.

   Contract-first shadow pre-screen considered the seven critical call
   recognition, request classification, pending-relation, success transfer,
   failure preservation, overwrite, and exit-deduplication decisions. They all
   require native pointer/heap lifetime semantics unsupported by the current
   verifier, so dogfood is not applicable: proposals 0, eligible 0, rejected
   0, unsupported 7. Candidate contracts requiring human review: none. No
   proof-bearing contract is invented and no `cs: ai` proposal can become
   accepted intent. Executable A7 RED fixtures and ordinary tests are the
   referee; this pre-implementation contract record will not change during the
   slice.

   **Completion evidence (appended after implementation; the locked contract
   above is unchanged).** Phase 7.2 is locally complete. Exact direct global-C
   and `std` `realloc`/`reallocarray` calls now carry a per-disjunct pending
   source/result relation for proven nonzero requests. Null results preserve
   the source allocation, non-null results transfer its lifetime and invalidate
   the old owner, and proven-nonzero direct overwrite reports the possible
   failure-path leak. Null input remains allocation, `reallocarray` requires
   both operands to be nonzero, and zero/unknown sizes plus unsupported call,
   type, exposure, or conflict shapes remain conservative. Unresolved
   alternatives are deduplicated at exit.

   RED first recorded four implementation gaps after correcting one
   other-namespace test whose original leak expectation contradicted the
   existing generic escape semantics. The first full-suite replay exposed the
   Systemd copy-before-null regression; preserving pointer-value copy bindings
   closed it. Precision review then added an exact-result-alias guard RED and
   closed it by resolving the guard to the binding owner. Twenty Phase 7.2
   cases pass; the focused realloc/alias/Systemd replay is 24/24, and direct
   plus CTest suites are 1097/1097.

   Final 400-file/CWE Juliet rule-matched results are CWE476 140/0 (precision
   1.000, hit rate 0.347), CWE401 105/15 (precision 0.875, hit rate 0.253),
   CWE415 119/0 (precision 1.000, hit rate 0.297), CWE416 212/0 (precision
   1.000, hit rate 0.531), CWE369 43/0 (precision 1.000, hit rate 0.108), and
   CWE190 23/0 (precision 1.000, hit rate 0.057). Every existing floor passes
   and no floor changed. Frozen thesis is `clean_fp=0`, `bug_caught=9/15`, 11
   findings; self-scan is clean and complete at 48/48 TUs; cJSON remains 54
   findings (76 enumerated, 35 analyzed, 41 explicitly accepted broken
   fixtures) and tinyxml2 9 (3/3 analyzed). The tested Windows product SHA-256
   is `4ccb8e52a53e1af0905830c2889bb9ffc1467960c17a44cf4ac8e76c423c656d`.

   Shadow completion considered `reallocSite`, `reallocUpdates`,
   `collectReallocSites`, `invalidateReallocRelations`, `provesNonZero`,
   `provesNonZeroRequest`, and `applyNullCondition`: proposals 0, eligible 0,
   rejected 0, unsupported 7. Their composite authority depends on native
   pointer identity and heap lifetime semantics outside the current verifier,
   so no proposal was eligible and none exposed an implementation problem.
   Independent RED, full-suite, and precision-review tests exposed the
   implementation and assumption problems above; all are closed. Candidate
   contracts requiring later human review: none. No `cs: ai` proposal became
   accepted intent, and native owned-memory parity remains deferred to
   executable A7 fixtures.
3. **Custom allocator/deallocator pairs — boundary locked before
   implementation.** Add an opt-in exact-family channel without changing the
   meaning of the legacy independent `--alloc-functions` and
   `--free-functions` lists.

   The locked development contract is separate from production code. The CLI
   accepts `--allocator-pairs <allocator=deallocator,...>`, project config
   accepts `allocator_pairs = ...`, and MCP `analyze` accepts the same string
   as `allocator_pairs`. Each comma-separated entry has exactly one `=`, a
   nonempty allocator, and a nonempty deallocator. Malformed input rejects the
   complete value without partially registering it. Duplicate entries are
   idempotent; repeating an allocator with another deallocator adds another
   admitted release for that exact family.

   Pair authority requires a direct non-instance callee. A spelling containing
   `::` matches the exact qualified name; an unqualified spelling matches the
   direct callee identifier for compatibility with existing configuration.
   Paired names automatically enter allocator/deallocator recognition. An
   allocation produced directly by a paired allocator carries that exact
   family in each guarded disjunct. Only a directly called admitted
   deallocator on argument zero proves release, enables later UAF/double-free
   evidence, and closes the leak. Another paired or legacy deallocator,
   `delete`, or built-in `realloc` does not prove release for that family; a
   still-live allocation remains reportable as a leak.

   Conflicting family paths degrade to unknown family. A summary-owned return,
   summary-consumed parameter, unresolved or ambiguous indirect call, method
   receiver, non-variable argument, or unknown target cannot manufacture an
   exact family match. Passing an exact-family allocation through such a
   release-shaped call conservatively escapes it rather than asserting either
   release or a leak. A wrapper gains exact authority only when the wrapper
   names themselves are explicitly paired. Legacy independent name lists stay
   family-agnostic and retain their current behavior. Pair registration is
   scoped to one analyzer/MCP call and is cleared with the other idiom
   registries.

   The exact file set is `src/config/Config.h`, `src/config/Config.cpp`,
   `src/engine/AllocFunctions.h`, `src/engine/AllocFunctions.cpp`,
   `src/analyzer/StaticAnalyzer.cpp`, `src/server/McpServer.cpp`,
   `src/rules/MemoryLeakRule_Ex.cpp`, `tests/ConfigTest.cpp`,
   `tests/McpServerTest.cpp`, `tests/MemoryLeakRuleExTest.cpp`,
   `docs/usage.md`, `docs/integrations.md`, this TODO, and
   `docs/devlog/changelog.md`. Contract grammar, capability tiers, accepted
   model channels, summary schema, existing profiles, and quality floors remain
   unchanged.

   Contract-first shadow pre-screen considered `Config::addAllocatorPairs`,
   `setAllocatorPairs`, `pairedAllocatorFamily`,
   `isPairedDeallocatorCall`, `matchesAllocatorFamily`,
   `allocationFamilyOf`, and `releaseAuthority`. String/container parsing,
   Clang declaration identity, and native pointer/heap lifetime are outside the
   current verifier, so dogfood is not applicable: proposals 0, eligible 0,
   rejected 0, unsupported 7. Candidate contracts requiring human review:
   none. No proof-bearing contract is invented and no `cs: ai` proposal can
   become accepted intent. Executable A7 RED fixtures and ordinary tests are
   the referee; this pre-implementation contract record will not change during
   the slice.

   **Completed 2026-08-09.** Atomic CLI/config/MCP parsing, direct-callee
   qualified and unqualified matching, per-disjunct exact family state,
   matching-release authority, conservative uncertainty, and analyzer-scoped
   registry cleanup are implemented within the locked file set. The initial
   compile RED established the missing API; after registry plumbing, 6 of 14
   semantic cases remained RED. The first implementation closed all 14. A
   precision-review fixture then exposed that a paired allocation passed to
   built-in `realloc` emitted two leaks instead of one; preserving the direct
   source owner before binding invalidation closed that assumption gap. The
   final focused matrix is 20/20.

   Final local gates are direct suite 1117/1117, CTest 1117/1117,
   `CapabilitiesCliTest.py` schema 2 / rules 14 / supported 7 /
   out-of-scope 5, `ActionArgsTest.py` 5/5, docs sync, 8/8 profiles,
   README 315/315, and capability sync. Frozen thesis remains
   `clean_fp=0`, `bug_caught=9/15`, 11 findings; self-scan is clean and
   complete at 48/48 translation units. Corpus receipts are cJSON 54 findings
   (76 enumerated, 35 analyzed, 41 accepted broken fixtures) and tinyxml2 9
   findings (3/3). The full unchanged 400-file/CWE Juliet floors pass:
   CWE476 140/0, CWE401 105/15 (precision 0.875), CWE415 119/0, CWE416
   212/0, CWE369 43/0, and CWE190 23/0. The tested Windows product SHA-256 is
   `db1f7ba8eea153edaec1b9e4e77df191d77eb1f56a12e199b2494cd8de13fc68`.

   Contract-first shadow completion considered the same seven functions:
   proposals 0, eligible 0, rejected 0, unsupported 7. No proposal exposed a
   problem because none was eligible; independent RED and precision-review
   tests exposed the implementation and assumption problems above. Candidate
   contracts requiring later human review: none. No `cs: ai` proposal became
   accepted intent, and native owned-memory parity remains deferred to
   executable A7 fixtures.
4. **RAII and smart pointers — boundary locked before implementation.**
   Replace the current adoption-only escape with an exact, opt-in local-owner
   lifetime channel for supported standard smart pointers. The legacy
   configured-wrapper behavior remains conservative and is not promoted into
   native proof authority.

   The locked development contract is separate from production code. Exact
   owner state is limited to direct automatic local `std::unique_ptr`,
   `std::shared_ptr`, and `std::auto_ptr` objects whose declaration and raw
   allocation identity are visible in the same function and guarded
   disjunct. Direct construction or `reset(raw)` may adopt only an exact
   tracked local raw pointer with a compatible pointee type. `unique_ptr` and
   `auto_ptr` have one exact owner; `shared_ptr` may have an exact local owner
   set. Direct standard copy/move construction and assignment update that set:
   shared copies retain the source, while moves and `auto_ptr` transfer it.
   Replacing an owner releases its old object before acquiring the new one.

   A direct `unique_ptr`/`auto_ptr` `release()` removes that owner without
   freeing the allocation. If the result is captured in a compatible local raw
   pointer, it becomes an exact alias of the allocation; ignored release still
   leaves the allocation live and leak-reportable. Direct `reset()` and an
   automatic-object destructor remove one owner and prove a release only when
   that was the last exact owner. A raw alias used after that release may prove
   UAF, and another exact raw or owner release may prove double-free. A direct
   `get()` result captured in a compatible local raw pointer may become an
   exact non-owning alias. Normal scope exit and return cleanup are admitted;
   exceptional cleanup remains owned by Phase 7.5.

   Exact custom allocator families are not silently matched to an implicit
   smart-pointer deleter. Adoption of such a family, custom deleter arguments,
   incompatible pointee conversions, aliasing `shared_ptr` constructors,
   owner fields or heap objects, owner address exposure, references, lambdas,
   indirect or ambiguous calls, derived lookalikes, unsupported owner methods,
   conflicting owner paths, and unknown copy/move targets degrade to escape or
   unknown. They cannot fabricate release, UAF, double-free, or a blocking
   leak. Project owner wrappers still require `--owning-pointers` and retain
   the existing conservative adoption escape; unconfigured wrappers and
   non-owning views remain silent and leave genuine raw leaks visible.

   Implicit destructor CFGs are requested only by analyses that expose the new
   optional element hook. The normal cached CFG remains separately keyed and
   byte-for-byte available to every existing statement-only consumer. The
   exact file set is `src/engine/CfgCache.h`, `src/engine/CfgCache.cpp`,
   `src/engine/DataflowEngine.h`, `src/rules/MemoryLeakRule_Ex.cpp`,
   `tests/CfgCacheTest.cpp`, `tests/IntervalAnalysisTest.cpp`,
   `tests/MemoryLeakRuleExTest.cpp`, `docs/usage.md`, this TODO, and
   `docs/devlog/changelog.md`. Configuration, allocator-pair syntax, contract
   grammar, capability tiers, accepted model channels, summary schema,
   profiles, and quality floors remain unchanged.

   Contract-first shadow pre-screen considered `CfgCache::get`, `runDataflow`,
   `standardOwnerKind`, `ownerOperation`, `applyOwnerOperation`,
   `MemoryFlow::transferElement`, and `MemoryFlow::onCFGElement`. Template/CFG
   event dispatch, Clang declaration identity, native pointer aliasing, smart
   ownership, and heap lifetime are outside the current verifier, so dogfood
   is not applicable: proposals 0, eligible 0, rejected 0, unsupported 7.
   Candidate contracts requiring human review: none. No proof-bearing contract
   is invented and no `cs: ai` proposal can become accepted intent.
   Executable A7 RED fixtures and ordinary tests are the referee; this
   pre-implementation contract record will not change during the slice.

   **Completed 2026-08-10.** The shared CFG cache now keeps ordinary and
   implicit-destructor graphs under separate option keys, and the dataflow
   engine invokes optional transfer/reporting hooks for non-statement CFG
   elements without changing statement-only consumers. Memory lifetime state
   records exact local standard owners per guarded disjunct. Direct compatible
   adoption, `get`, `release`, `reset`, standard copy/move and replacement,
   last-owner destruction, raw-result aliases, UAF, and double-free evidence
   are implemented within the locked file set. Unsupported owner/deleter,
   custom-family, aliasing, exposure, reference, lambda, and ambiguous paths
   remain conservative.

   The initial compile RED proved that the option-keyed CFG API was absent.
   After engine plumbing, 10 of 17 initial lifetime cases remained semantic
   RED. The first lifetime implementation closed them. Precision fixtures then
   exposed three false authorities: owner address exposure, writable owner
   references, and a shared aliasing constructor; conservative owner escape
   closed all three. A later custom-deleter template fixture exposed one more
   false authority and was closed by requiring the admitted implicit/default
   deleter shape. The lambda-capture control was already conservative. The
   final Phase 7.4 plus legacy owner regression matrix is 41/41.

   Final local gates are direct suite 1148/1148, CTest 1148/1148,
   `CapabilitiesCliTest.py` schema 2 / rules 14 / supported 7 /
   out-of-scope 5, and `ActionArgsTest.py` 5/5. Frozen thesis remains
   `clean_fp=0`, `bug_caught=9/15`, 11 findings; self-scan is clean and
   complete at 48/48 translation units. Corpus receipts are cJSON 54 findings
   (76 enumerated, 35 analyzed, 41 accepted broken fixtures) and tinyxml2 9
   findings (3/3). The full unchanged 400-file/CWE Juliet floors pass:
   CWE476 140/0, CWE401 105/15 (precision 0.875), CWE415 119/0, CWE416
   212/0, CWE369 43/0, and CWE190 23/0. The tested Windows product SHA-256 is
   `19875c442be7e3f6bed6e50eba1f29374b685bc19275757a2c6370be7b9fd3d6`.

   Contract-first shadow completion considered the same seven functions:
   proposals 0, eligible 0, rejected 0, unsupported 7. No proposal was
   eligible, so none exposed an implementation or assumption problem;
   independent RED and precision-review tests exposed and closed the problems
   above. Candidate contracts requiring later human review: none. No `cs: ai`
   proposal became accepted intent, and native owned-memory parity remains
   deferred to executable A7 fixtures.
5. **Escape, ownership transfer, and exceptional exits — boundary locked
   before implementation.** Complete the Phase 7 production boundary without
   inventing native member/heap/whole-project pointer semantics ahead of the
   executable A7 reference fixtures.

   The locked development contract is separate from production code. The only
   new release authority in this slice is an explicit Clang exceptional CFG
   path that contains the same `CFGAutomaticObjDtor` already admitted for a
   direct automatic local standard owner in Phase 7.4. A throw from the
   owner's live lexical scope to a visible same-function handler, or to the
   function's exceptional exit when Clang emits that cleanup, removes the
   exact owner and proves release only for the last exact owner. A later raw
   alias use or exact release may therefore prove UAF or double-free. An owner
   declared outside the unwound scope remains live; `release()` before the
   throw leaves the allocation live; and exceptional paths without an emitted
   admitted destructor cannot manufacture cleanup.

   Exception-edge construction is opt-in per analysis and separately cached
   from both the ordinary statement-only CFG and the normal implicit-
   destructor CFG. Existing consumers retain their current graph and transfer
   behavior. Temporary destructors, constructor-failure cleanup, exception
   objects, catch-object ownership, rethrow identity, exception specifications,
   coroutine cleanup, and interprocedural exception propagation are not
   admitted in this slice.

   Existing summary ownership remains the transfer boundary. A direct or
   closed-target `Consumed` summary may retain its current exact release
   authority for a compatible legacy allocator family; `Transferred` and
   unknown ownership escape because the destination lifetime is outside the
   caller's view. `Owned` returns remain caller-owned and `Borrowed` returns do
   not hide a live allocation. Direct member/global stores keep their current
   conservative classification. No local record field, smart-owner field,
   heap owner, aliasing owner, persisted member identity, or cross-function
   pointee lifetime becomes exact without executable A7 fixtures. These
   controls pin the honest boundary; they do not claim native memory-
   verification parity.

   The exact file set is `src/engine/CfgCache.h`,
   `src/engine/CfgCache.cpp`, `src/engine/DataflowEngine.h`,
   `src/rules/MemoryLeakRule_Ex.cpp`, `tests/CfgCacheTest.cpp`,
   `tests/IntervalAnalysisTest.cpp`, `tests/MemoryLeakRuleExTest.cpp`,
   `tests/InterproceduralTest.cpp`, `docs/usage.md`, this TODO, and
   `docs/devlog/changelog.md`. Summary schema/persistence, contract grammar,
   capability tiers, configuration, accepted model channels, profiles, and
   quality floors remain unchanged.

   Contract-first shadow pre-screen considered `CfgCache::get`, `runDataflow`,
   the exceptional-CFG opt-in trait, `classifyStmtEffects`,
   `MemLeakAnalysis::transferElement`, `MemLeakAnalysis::onCFGElement`, and
   `analyzeFunction`. Template dispatch, Clang exceptional CFG identity,
   native pointer aliasing, ownership, and heap lifetime are outside the
   current verifier, so dogfood is not applicable: proposals 0, eligible 0,
   rejected 0, unsupported 7. Candidate contracts requiring human review:
   none. No proof-bearing contract is invented and no `cs: ai` proposal can
   become accepted intent. Clang-backed RED fixtures and ordinary tests are
   the referee; this pre-implementation contract record will not change during
   the slice.

   **Review-correction contract locked 2026-08-10.** The strict base/head
   semantic review exposed two new experimental assumption findings in
   `collectReallocSites` and `collectOwnerRawResultSites`: each internal
   `FunctionDecl*` parameter was dereferenced without a local null boundary.
   Before implementation, the correction is restricted to returning an empty
   site map for a null function and preserving all behavior for a non-null
   function. It grants no allocator, alias, ownership, cleanup, or proof
   authority. The exact correction file set is
   `src/rules/MemoryLeakRule_Ex.cpp`, this TODO, and
   `docs/devlog/changelog.md`, all already inside the locked Phase 7.5
   boundary. Contract-first shadow pre-screen considered the two helpers:
   proposals 0, eligible 0, rejected 0, unsupported 2 because native pointer
   nullability is outside the current verifier. Candidate contracts requiring
   human review: none. No `cs: ai` proposal can become accepted intent. The
   corrected strict diff review, full suite, and existing product floors are
   the referees; this correction contract will not change during
   implementation.

   **Review correction completed 2026-08-10.** Both helpers now return an
   empty site map for a null function. The corrected strict base/head semantic
   review covers all 12 changed C/C++ translation units and passes with
   `new_errors=0`, `new_warnings=0`, `weakened=0`; every analyzed function
   reaches a fixpoint. Direct and CTest suites remain 1164/1164. Self-scan is
   clean and complete at 48/48 TUs, frozen thesis remains `clean_fp=0` and
   `bug_caught=9/15` with 11 findings, corpus remains cJSON 54 (76 enumerated,
   35 analyzed, 41 accepted broken fixtures) and tinyxml2 9 (3/3), capability
   output remains schema 2 / rules 14 / supported 7 / out-of-scope 5, and
   ActionArgs remains 5/5. The final Windows product SHA-256 is
   `25e0a566990dedabf959a5c770079b362f5d462ae7af177cc81a8b2a9e9c120d`.
   The review also exposed Windows path-remap and coverage-path honesty gaps in
   the review harness; temporary referee-only corrections produced the receipt
   above, while the repository fix remains in the separately declared
   documentation/automation maintenance follow-up.

   **Completed 2026-08-10.** CFG cache entries now include both the implicit-
   destructor and EH-edge options, and analyses may explicitly opt into the EH
   graph without changing any default consumer. The compile RED established
   the missing four-argument cache API. After option plumbing, the initial 12
   semantic fixtures had 7 passes and 5 failures: exceptional unique/shared
   paths produced leaks instead of authoritative cleanup, manual delete plus
   throw failed to produce the proposed double-free, an outer shared owner was
   polluted by the missing inner cleanup, and the engine could not carry a
   destructor state to the handler exit.

   Direct CFG inspection corrected the assumption behind those expectations.
   Clang 20 emitted the automatic-destructor block, but that block had no
   predecessor and was disconnected from the throw-to-handler path. The
   locked contract admits cleanup only when Clang emits it on the exceptional
   path, so no release/UAF/double-free authority was added. Instead, an
   explicit `throw` now degrades only allocations with a live exact smart
   owner to escape/unknown. Ownerless allocations and allocations left live
   by `release()` remain leak-reportable. Unreachable throws retain normal
   destructor evidence, and conditional disconnected cleanup cannot
   manufacture an all-path UAF claim.

   Existing transfer semantics are pinned: a cross-TU `Consumed` summary
   still proves UAF for a compatible legacy allocation, `Transferred` cannot
   invent release, a direct local member store keeps a real leak visible, and
   a global member store escapes. The final Phase 7.5 matrix is 16/16. Direct
   and CTest suites pass 1164/1164; `CapabilitiesCliTest.py` remains schema 2 /
   rules 14 / supported 7 / out-of-scope 5, and `ActionArgsTest.py` is 5/5.
   Frozen thesis is `clean_fp=0`, `bug_caught=9/15`, 11 findings; self-scan is
   clean and complete at 48/48 TUs. Corpus remains cJSON 54 findings (76
   enumerated, 35 analyzed, 41 accepted broken fixtures) and tinyxml2 9 (3/3).
   The unchanged 400-file/CWE Juliet floors pass: CWE476 140/0, CWE401 105/15
   (precision 0.875), CWE415 119/0, CWE416 212/0, CWE369 43/0, and CWE190
   23/0. The tested Windows product SHA-256 is
   `25e0a566990dedabf959a5c770079b362f5d462ae7af177cc81a8b2a9e9c120d`.

   Contract-first shadow completion considered the original seven functions
   plus `collectReallocSites` and `collectOwnerRawResultSites`: proposals 0,
   eligible 0, rejected 0, unsupported 9. No proposal was eligible.
   Independent compile RED, semantic RED, CFG inspection, precision fixtures,
   and strict diff review exposed and closed the cache gap, the disconnected-
   cleanup assumption problem, and the two internal null-boundary assumptions.
   Candidate contracts requiring later human review: none. No `cs: ai`
   proposal became accepted intent. Member/heap/whole-project pointer identity
   and native memory-verification parity remain deferred to executable A7
   fixtures.

Phase 7 exits only when addressable UAF/double-free/leak recall rises,
`memory-leak` precision remains at least 0.85 (target 0.90), supported UAF and
double-free precision floors remain at least 0.95, clean corpora stay clean,
and every local/CI referee passes without weakening an existing floor.

## Documentation/progress automation maintenance — MERGED (2026-08-10)

Phase 7 is merged through protected-main PR #134 at
`47b03f4076f246c38a81fbc834693bed0f98ccc4`, tree
`d21f47b802f5a824626501d39425e98fb6509142`. The owner-requested maintenance
boundary is now locked before implementation.

The authority contract is deliberately mechanical. Only commits reachable
from `origin/main` may be appended to the generated progress ledger as
`MERGED`; a phase branch, local test run, changelog sentence, or AI statement
can never become completion authority. `sync` may append newly observed
protected-main commits to `docs/PROGRESS.md` and regenerate only TODO's marked
state block. `check` is read-only and must fail when the progress cursor is
missing, malformed, not an ancestor of main, behind main, or when TODO does
not match the derivable git/progress facts. Existing progress bytes are
append-only: history may not be rewritten to make a later result look older.
Git facts that cannot be resolved are errors under CI, never a silent green.
The changelog remains the rationale/evidence narrative; PROGRESS is the terse
verified transition ledger, and TODO remains the current compass.

The same boundary closes two measured Windows review-harness defects from the
Phase 7 referee. Compile-database root matching must accept both slash styles,
must not remap protected or build-output paths into the base worktree, and
must keep source paths on the base side. Repository-relative finding and
coverage paths must use Git's slash-separated form on every host. The strict
review must then report every changed C/C++ source as analyzed instead of the
contradictory "12 analyzed / 12 not analyzed" receipt observed before the
temporary referee correction.

The exact file set is `docs/PROGRESS.md`, this TODO,
`docs/devlog/changelog.md`, `CONTRIBUTING.md`,
`scripts/progress_status.py`, `scripts/check_docs_sync.sh`,
`scripts/review_report.py`, `tests/StatusAutomationTest.py`, and
`tests/CMakeLists.txt`. PLAN, product/runtime sources, contract grammar,
capabilities, profiles, workflows, release configuration, and quality floors
remain unchanged. Contract-first shadow dogfood is not applicable: this
maintenance slice creates or materially changes no C++ function. Functions
considered 0; proposals 0; eligible 0; rejected 0; unsupported 0. Candidate
contracts requiring later human review: none. No `cs: ai` proposal can become
accepted intent. The new automation tests, existing diff-review flow, full
suite, docs-sync, and a real branch/main replay are the referees; this contract
will not change during implementation.

Implementation stays inside the locked nine-file set. The status tool
bootstraps the append-only ledger at protected-main Phase 7, derives commit
and tree receipts from git, records live phase refs only as in-flight, and
atomically repairs the marked TODO view. Five focused tests prove initial
sync, stale-main detection, append-only advancement, missing-cursor/manual
rewrite rejection, non-ancestor rejection, TODO repair, and mixed Windows
path handling. The direct C++ suite passes 1164/1164 and CTest passes
1165/1165 including `StatusAutomationContract`; the existing end-to-end
review fixture passes. A real strict replay from `3aa85f9` analyzes all 12
changed C/C++ sources, reaches every fixpoint, and reports zero new errors,
warnings, or weakened contracts, without the former contradictory coverage
list. The read-only docs gate resolves `origin/main` at `47b03f4`, appends no
unmerged work, and passes capability, real-world ledger, and documentation
checks. These are branch verification facts only; this slice becomes
`MERGED` solely after protected main contains its squash commit and a later
`sync` appends that git fact to PROGRESS.

Protected main now contains the maintenance squash as PR #135 commit
`e146a434f17e61813cceb175ea8791c9065a1b38`, tree
`fc719f17f30e32bac49d80dac5f80b4002e9f32b`. The first Phase 8 branch sync
mechanically appended that transition to `docs/PROGRESS.md` and regenerated
the state block above; no manual completion statement supplied authority.

## Phase 8.1 — deterministic real-repository test factory — BOUNDARY LOCKED (2026-08-10)

Phase 8 starts with the nightly core factory: libgit2, rtp2httpd, Abseil, and
libarchive. Each project is defined once in a canonical machine-readable
manifest with its immutable 40-hex commit, repository URL, controlled
configure/build recipe, source selection, exact sorted translation-unit count
and SHA-256, expected analyzer coverage, expected finding/verdict tuple,
per-shard timeout, and three required independent repetitions. Mutable refs,
implicit current HEAD, partial translation-unit success, and an unclassified
verdict are invalid campaign inputs.

The runner has three separate authorities. `plan` validates the manifest and
emits a project-by-repetition matrix without executing projects. `run` checks
out one exact revision, produces a real compile database, derives and hashes
the exact translation-unit list, executes one analyzer process under its time
and memory boundary, and writes a receipt even when the verdict is
unavailable. `aggregate` verifies receipt and artifact checksums and accepts a
project only when all three independent receipts have identical semantic
coverage, finding fingerprints, and exit classification. Duration and host
metadata are evidence but are not part of semantic equality. Missing,
malformed, timed-out, stale, checksum-mismatched, broken, incomplete, skipped,
or solver-error evidence fails closed with exit 2.

Checkpoints are optimization evidence, never truth. A checkpoint may be
resumed only when its schema, manifest digest, project commit, analyzer digest,
recipe digest, translation-unit digest, and repetition identity all match the
requested shard; otherwise the project is rerun. Receipts carry SHA-256
sidecars, aggregation is order-independent, and one project failure cannot
erase the other project artifacts. GitHub Actions builds the analyzer once,
fans out the matrix into independent shards, always uploads each shard's
evidence, and gates the campaign in a separate aggregate job. The nightly
campaign has an honest aggregate window of at most 12 hours while each hosted
runner shard stays below the platform job limit. Later weekend and release-
candidate tiers will be separately bounded with measured pins and expectations
instead of being fabricated in this slice.

The ordinary PR contract remains fast and explicit: unit/full CTest, cJSON,
tinyxml2, self-scan, and the bounded Juliet PR sample each have a 30-minute job
ceiling. No floor, test, corpus expectation, or hook is weakened. RED-first
tests must reject mutable pins, duplicate identities, unsafe command shapes,
translation-unit drift, incomplete coverage, unavailable verdicts, stale
checkpoints, receipt tampering, missing repetitions, and nondeterministic
results, and must statically verify the workflow budget/sharding contract.

The exact Phase 8.1 file set is `.github/workflows/ci.yml`,
`.github/workflows/juliet.yml`, `.github/workflows/realworld.yml`,
`scripts/realworld_manifest.json`, `scripts/run_realworld_campaign.py`,
`scripts/check_realworld_ledger.py`, `scripts/realworld_expected.txt`,
`tests/RealworldCampaignTest.py`, `tests/RealworldLedgerTest.py`,
`tests/CMakeLists.txt`, `docs/benchmarks.md`, `docs/reproduce.md`, this TODO,
`docs/PROGRESS.md`, and `docs/devlog/changelog.md`. Product/runtime C++,
contract grammar, accepted contract intent, capability tiers, profiles,
summary schemas, release configuration, and all quality floors remain
unchanged. This development contract is stored separately from implementation
and will not change during the slice.

Contract-first shadow dogfood is not applicable because Phase 8.1 creates or
materially changes no C++ function. Functions considered 0; proposals 0;
eligible 0; rejected 0; unsupported 0. No proposal exposed an implementation
or assumption problem. Candidate contracts requiring later human review:
none. No `cs: ai` proposal can become accepted intent. Native pointer,
ownership, heap, alias, and lifetime parity remain deferred to executable A7
fixtures.

**Local and GitHub qualification complete; protected-main merge pending.** The Linux
referee accepted all twelve receipts from analyzer SHA-256
`e5f2031e0da767f636450e702b6487134256fd7da8bb03f3d5fd3eda888d562c`.
The three independent repetitions agree for libgit2 (167/167, 39 findings),
rtp2httpd (38/38, 24), Abseil (158/158, 12), and libarchive (132 requested,
255 whole-program executions, 38). All have zero broken TUs and zero
incomplete functions. The aggregate manifest SHA-256 is
`f8cae660758d1df9aeb0c931fa4a13028ffe8dd18d3645b12f220d601b765c36`.
GitHub workflow run
[`31370373875`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/31370373875)
independently accepted plan, one analyzer build, all 12 shards, and the
aggregate referee at commit `856cdc73a4ce245eb70cdf73da2c35fcd02545e7`.
Its campaign-wide analyzer SHA-256 is
`146e6761107acfaf7fd6a1057a420e7abadcdb2de77bc66b09d3e3af5933e4f3` and
its checksummed aggregate receipt SHA-256 is
`08f8fe075e2dba92c8706c9028026d46cbb6b5148913d113146c1b64ffd559f6`.
Phase 8.1 is delivered through protected-main PR #136 at squash commit
`3b1714e1e9e3997ab63507837c3a177c1bdefab1`, tree
`0293f291d2a4a7876eaa734e6b23dd0a82779377`. A second hosted replay on the
final documentation head, workflow run `31371349360`, accepted the same
project semantics with analyzer SHA-256
`e40d6c02b160c13a8bf9010b03dafe2d21fc1aed068c706770a79e95250cb72e`
and aggregate receipt SHA-256
`b576a9affbb2cc31d1fb0f7d94c1f1bcf4d25d678e7e166691d928a7cbe479b2`.

The hardened factory contract has 12/12 Python tests. It covers early
unavailable shard receipts, campaign-wide single-analyzer identity, semantic
fingerprint recomputation, malformed report roots, placeholder digests,
whole-program execution counts, checksum tampering, stale checkpoints,
missing repetitions, and nondeterminism. The scan job allows 355 minutes so
the runner's 330-minute project timeout retains 25 minutes to write and upload
fail-closed evidence below the hosted 360-minute ceiling. Final local product
gates are direct 1164/1164 and CTest 1166/1166, capability schema 2 / rules 14
/ supported 7 / out-of-scope 5, ActionArgs 5/5, docs/profile/README/capability
sync, frozen thesis `clean_fp=0` and `bug_caught=9/15` with 11 findings,
self-scan clean and complete at 48/48, cJSON 54 (76 attempted, 35 analyzed,
41 explicitly accepted broken fixtures), tinyxml2 9 (3/3), and the unchanged
400-file/CWE Juliet floors.

## Phase 8.2 — deterministic weekend real-repository capacity — BOUNDARY LOCKED (2026-08-10)

The weekend tier adds exactly four independently pinned projects to the
factory without changing the nightly tier: systemd v256.17 at
`009adf6c0e435376c80fbc11675d581e0a94d350`, curl 8.11.0 at
`b1ef0e1a01c0bb6ee5367bd9c186a603bde3615a`, Redis 7.4.2 at
`a0a6f23d997b024689ba157916837f493a593a34`, and LVGL 9.2.2 at
`7f07a129e8d77f4984fff8e623fd5be18ff42e74`. The weekend campaign has exactly
three repetitions and a 2,880-minute aggregate capacity; the validator must
reject a weekend boundary below 36 hours or above 48 hours. Each hosted shard
retains the existing 330-minute runner ceiling and 355-minute job ceiling.

The build surfaces were qualified against those exact commits before the
implementation boundary was opened. systemd uses Meson release setup with
tests, documentation, translations, boot/EFI, BPF, security integrations,
compression, crypto, and optional network dependencies disabled, followed by
the `systemd:executable` target; the admitted source roots are `src/basic`,
`src/core`, and `src/shared`. curl uses its CMake/Ninja HTTP-only static-lib
configuration with tests, the executable, TLS, PSL, SSH2, and zlib disabled,
and admits `lib`. Redis uses Bear around its native Make build with clang-20,
`MALLOC=libc`, `BUILD_TLS=no`, and `USE_SYSTEMD=no`, and admits `src`. LVGL uses
CMake/Ninja with `LV_CONF_SKIP=ON` and examples/demos disabled, and admits
`src`. All four surfaces admit only `.c` files and no fallback glob.

The locked sorted translation-unit identities are systemd 390 / SHA-256
`5a65361ff67a6bc1dca48d0da5aee60ead0f1a061084492684e2c1cb7313823c`,
curl 169 / `213f0c1cb75de379b16ade4d0ab7cc8e701ced13a51fc822060db1f95ec92a01`,
Redis 103 / `3b01da3958fa65529f859ca097ef6e471a8ec45f9976c31d833311559588aa1b`,
and LVGL 311 / `30a090f5cdffb81f3b2184b5cd537d4ac85fff23acf3cdccecdb9ec13af00e50`.
These counts describe the newly locked minimal build surfaces and must not be
substituted with historical README scan sizes from other revisions or build
configurations. Finding, coverage, exit, and fingerprint expectations remain
unclaimed until the current analyzer produces measured receipts; three-way
semantic equality is required before acceptance.

The command authority expands only through two strictly shaped adapters.
`meson` is admitted only as `setup {build} {source} ...` in configure rows and
`compile -C {build} ...` in build rows. `bear` is admitted only in a build row
whose fixed prefix is
`bear --output {build}/compile_commands.json -- make -C {source}`, followed
only by `-j{jobs}` and simple make variable assignments. Shell commands,
control tokens, response files, alternate makefiles, Meson introspection, and
other subcommands remain invalid. The existing token-array execution model is
unchanged; no shell authority is introduced.

GitHub Actions adds a `weekend` dispatch choice and one distinct weekly cron.
The scheduler maps only that exact weekly cron to `weekend`; the existing
daily cron remains `nightly`, and an unknown tier fails before matrix
execution. The scan image adds only the measured build dependencies needed by
the locked recipes. RED-first tests must pin the exact project membership,
weekend bounds, immutable revisions and TU identities, reject malformed Meson
and Bear shapes, and statically prove the dispatch/schedule/dependency and
hosted-time boundaries. Existing checksum, checkpoint, coverage,
determinism, and fail-closed evidence rules remain unchanged.

The exact Phase 8.2 file set is `.github/workflows/realworld.yml`,
`scripts/realworld_manifest.json`, `scripts/run_realworld_campaign.py`,
`tests/RealworldCampaignTest.py`, `docs/benchmarks.md`, `docs/reproduce.md`,
this TODO, `docs/PROGRESS.md`, and `docs/devlog/changelog.md`. No product C++,
contract grammar, accepted contract intent, capability tier, profile, summary
schema, release configuration, quality floor, nightly project, or ordinary PR
gate is admitted to change. This boundary is stored separately from
implementation and will not change during the slice.

Contract-first shadow dogfood is not applicable because Phase 8.2 creates or
materially changes no C++ function. Functions considered 0; proposals 0;
eligible 0; rejected 0; unsupported 0. No proposal has exposed an
implementation or assumption problem. Candidate contracts requiring later
human review: none. No `cs: ai` proposal can become accepted intent. Native
pointer, ownership, heap, alias, and lifetime parity remain deferred to
executable A7 fixtures.

**Pre-implementation boundary correction (2026-08-10).** The first official
runner probe reproduced the exact same sorted 103-file Redis list but exposed
that the preliminary PowerShell path/hash calculation, rather than the
factory's canonical `translation_unit_digest`, supplied the recorded digest.
The runner-derived SHA-256 is
`289cde3a18f71ccdcf3fd3b317a232e57514c14690b8d67f8551af261bcff844`;
it supersedes only the Redis SHA literal above. The implementation changes
were still uncommitted and acceptance was paused when this was found. curl,
LVGL, and systemd official probes independently reproduced their locked TU
counts and digests. The project pins, source lists, commands, file boundary,
and all other authority remain unchanged. This is an exposed measurement-tool
assumption problem, not accepted implementation drift.

**Local and hosted three-repeat qualification complete; protected-main merge
pending.** The runner now admits only the locked Meson
setup/compile and Bear/native-Make shapes, enforces the 36–48-hour weekend
window, and leaves the existing CMake/nightly behavior unchanged. The Actions
lane has separate daily-nightly and weekly-weekend selection, fails unknown
tiers before matrix execution, and installs the measured build dependencies.
The canonical manifest contains eight projects in two non-overlapping tiers.

RED first produced four expected failures: absent weekend membership, missing
weekend bounds, rejected Meson/Bear commands, and missing workflow selection
and dependencies. The 14/14 hardened factory tests now pass, as do manifest
ledger validation, Python bytecode compilation, workflow YAML parsing, and
whitespace checks. The complete local CTest suite is 1166/1166. A strict
target-token follow-up also rejects option-shaped Meson compile targets.

One current Linux analyzer SHA-256
`e5f2031e0da767f636450e702b6487134256fd7da8bb03f3d5fd3eda888d562c`
produced twelve independently built accepted shard receipts. All three
repetitions agree exactly for systemd (390 requested / 815 analyzed, 0
findings, exit 0), curl (169/169, 59, exit 1), Redis (103/206, 0, exit 0), and
LVGL (311/311, 16, exit 1). Every project has zero broken TUs and zero
incomplete functions. The aggregate manifest SHA-256 is
`88e7dbe8d46b88bd95e88b83106096953e90fed425b39a68d68225a78279a255`;
the checksummed aggregate receipt SHA-256 is
`9bbc429187d5059d0f292677420ff79c7d2755bc001deb5e80addb109f68e498`.

GitHub workflow run
[`31381555374`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/31381555374)
independently rebuilt analyzer SHA-256
`52f8520234e350ced20678a4f6356b0e96da3da6aa4d19be4e1f78046af54861`,
accepted all twelve weekend shards, and produced aggregate receipt SHA-256
`e781fbffa80f44b41a5bc97585c9385d950c5e6e8338d1bacf43c2a7fe111ec9`.
Every weekend project semantic SHA-256 exactly matches the local aggregate.
Nightly regression run
[`31382838369`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/31382838369)
used the same hosted analyzer, accepted all twelve original nightly shards,
preserved every project finding/fingerprint expectation, and produced
aggregate receipt SHA-256
`2954b90c3fba14d6d76bab985949428bc6cd091a466cf321970ddbf160a478ce`.
PR #137's Linux, Windows-native, quickstart, structure, base-head, and bounded
Juliet checks are green; there are no reviews or unresolved threads.

Shadow completion considered no C++ function because the final file set has
no C++: functions 0, proposals 0, eligible 0, rejected 0, unsupported 0. No
proposal exposed a problem because none was applicable; the independent
runner exposed the Redis pre-hash assumption problem and it was corrected
before implementation acceptance. Candidate contracts requiring later human
review: none. No `cs: ai` proposal became accepted intent, and native
owned-memory parity remains deferred to executable A7 fixtures.

## Phase 8.3 qualification-discovered GCC14 hardening — BOUNDARY LOCKED (2026-08-11)

The hosted TensorFlow Lite qualification run completed its 505-step build and
selected 269 production translation units, then the analyzer crashed while
summarizing `delegate_registry.cc`. Local reproduction on the exact pinned TU
and Clang 20 with GCC 14 libstdc++ returned exit 139. GDB proved unbounded
recursion below
`Expr::EvaluateAsInt` from `edgeInfeasibleByFlags`; the last evaluated
non-flag equality was in libstdc++ 14 `bits/unicode.h`. A five-line C++20
`<format>` fixture independently reproduces the same exit 139, so the product
defect is isolated from the release-candidate factory and TFLite itself.

This separate main-based branch may change only
`src/engine/ImmutableFlags.cpp`, the focused immutable-flag regression and
test-helper wiring, this TODO, mechanically synchronized `docs/PROGRESS.md`,
and `docs/devlog/changelog.md`. The implementation must first prove that the
new `<format>` regression is RED, then prevent integer evaluation unless the
opposite equality operand is a known immutable flag. Both operand orders and
both equality operators must retain their existing pruning semantics. GREEN
requires the focused regression, existing immutable-flag tests, the exact
GCC14 TFLite TU, the full CTest suite, document sync, and whitespace checks.
No release-candidate recipe, qualification expectation, rule finding policy,
contract grammar, accepted contract intent, capability tier, schema, or
release configuration may change in this branch. PR #138 remains
qualification-only.

**Local implementation and product gates complete.** The focused GCC14 test
first crashed the unmodified test process with exit 139. The implementation
now recognizes an immutable flag before evaluating the opposite operand and
the same test passes in 614 ms. A second executable regression pins `==` and
`!=` with the flag on either side. The related behavior set is 14/14 GREEN and
the full CTest suite is 1175/1175 GREEN; the direct single-process suite is
1166/1166 GREEN. Self-scan is clean and complete at 48/48 TUs with receipt
SHA-256
`53ddcd60f2fee8cbf6d7538c61bdbcec162ea2cba43562bee3911aefa941cc47`.
The frozen thesis gate remains `clean_fp=0`, `bug_caught=9/15`, and 11 total
findings. Real-corpus pins remain cJSON 54 findings (76 enumerated, 35
analyzed, 41 explicitly accepted broken fixtures) and tinyxml2 9 findings
(3/3 analyzed). Analyzer SHA-256
`2ad4991268a3a9921e9d8095b1f0cd1767893701427627425a624460da9bd0a2`
completed the exact GCC14 TFLite TU: 1/1 analyzed, zero broken TUs, zero
incomplete functions, and one supported blocking `memory-leak` finding
(`csf1-a845db511c25bcc3`) with normal exit 1. The complete JSON receipt SHA-256
is `fce1be0c540059ebd2f4b7c10a8abaf428677de48b308ac0cb7185717dfc1187`.

Contract-first shadow completion considered the one materially changed
production function, `edgeInfeasibleByFlags`: proposals 0, eligible 0,
rejected 0, unsupported 1. Its promise is conditional evaluation order over
Clang AST state, which the current contract grammar and referee cannot express
or verify. No proposal exposed another implementation or assumption problem;
the independent hosted run and executable GCC14 RED fixture exposed and now
close the defect. Candidate contracts requiring later human review: none. No
`cs: ai` proposal became accepted intent.

## Phase 8.3 — release-candidate real-repository capacity — QUALIFIED (2026-08-11)

The active branch is `phase-realworld-release-candidate-factory`. Its
observational boundary is locked in `docs/phase83-qualification-contract.md`:
the only candidates are llama.cpp, shadPS4, and the selected TensorFlow Lite
production library target at immutable commits. Qualification receipts cannot
become canonical expectations or accepted campaign intent. Production still
requires a later locked expectation boundary and three independent identical
semantic receipts.

llama.cpp remains pinned at
`4dee52f82dc455a035e900fed6a40cb45cd7a454`. Its low-parallelism Release
clang-20 CMake/Ninja `llama` target builds successfully. The admitted `src` and
`ggml/src` surface contains 200 compile-database translation units with digest
`e9ea7d634287ae942ce5c9b0b0cf5e1595114f60b13e8e7e431fff410ccf8783`.
Finding, coverage, exit, and fingerprint expectations remain unclaimed.

TensorFlow Lite remains pinned at
`a481b10260dfdf833a1b16007eead49c1d7febf3`, with its own source bound through
`TENSORFLOW_SOURCE_DIR`. The hosted build completed 505 Ninja steps. The broad
compile-database selector exposed 269 unique project paths but included ten
configured-only sources whose generated or Python binding headers do not exist
for the production library target; its 76 findings and incomplete exit are not
acceptance evidence. The exact `tensorflow-lite` Ninja target closure contains
241 unique translation units with digest
`2dd69e73c882f6a3ea17a63349500db7d350eb1d3aaa5a8a47f06a716f5fed5f`.
After protected-main PR #139, a full local observation of that target completed
with coverage fields 241 attempted, 245 analyzed, zero broken, and zero
incomplete functions; it reported 73 supported blocking findings with normal
exit 1. The ordered fingerprint digest is
`6cf30f16db0a5eb2537e6178a30087a0385b7dfdb1ff5f61d9bb2815a765a81a`;
the JSON report SHA-256 is
`717f15b1dab63648e5864c85db0994bdf1d1648a7bf6631cf11563babbf152fb`.
These values are observations only. The observer now derives the production
target closure from Ninja and intersects it with the admitted compile-database
surface before analysis; RED-first tests exclude configured-only and dependency
sources and reject paths outside the pinned source tree.

shadPS4 remains pinned at
`5a4373c80e32c7a9d5d6e5a0b7d31d371d194caa` with 53 recursive gitlinks. The
first hosted build using Clang 20 with GCC 14's default libstdc++ stopped at
2,088 of 2,452 steps on a compiler/library compatibility boundary. A narrow
libc++ 20 probe established only the required `std::jthread`/`std::stop_token`
surface (`_LIBCPP_VERSION=200100`); it did not prove the complete project
recipe. The full libc++ rerun reached step 2,181 but then proved that this
packaged library does not provide the `std::chrono::current_zone()` surface
used by the pinned source. The immutable upstream production workflow is the
stronger authority: it builds on Ubuntu 24.04 with Clang 19, the default
libstdc++, and mold. RED-first contract assertions now pin that exact compiler
and linker choice, preserve the upstream-enabled Discord/updater surface, and
enable Release IPO for shadPS4 while llama.cpp and TensorFlow Lite remain on
Clang 20. The first full production-shaped rerun configured successfully and
reached step 433 of 2,554, where CMake's C++23 dependency scan proved the
runner package set lacked `clang-scan-deps-19`; the checksummed unavailable
receipt records build exit 127. The workflow now installs the matching
`clang-tools-19` package rather than weakening IPO or the production surface.
That corrected hosted run completed all 2,554 build steps, then exposed a
qualification-parser defect: CMake's Clang dependency-scanner commands place
the admitted source path before `-c`, while the observer required it after
`-c`. The checksummed unavailable receipt therefore records an invalid target
closure even though the build succeeded. A RED-first regression now preserves
that real command form, and target selection matches tokens position-
independently against the already validated compile-database surface while
still rejecting ambiguous matches and empty closure intersections. The next
hosted run remains the authority for the translation-unit identity and analyzer
receipt.

No C++ production function changes in this qualification branch: functions 0,
proposals 0, eligible 0, rejected 0, unsupported 0. No `cs: ai` proposal became
accepted intent. The next gate is the corrected three-candidate hosted
observation; only complete candidate surfaces can proceed to locked
expectations and the required three repetitions.

**Qualification closeout (2026-08-11):** head `ecec77a8b02bb2ffdbf62d4deff936bbcaf65ff6`
passed run `31515185143` with one shared analyzer artifact
(`sha256:155f50b04c83ea7ebbcc2a5846482350468bdb3e62a9fe3b117a18ececc67e25`).
Pinned candidate receipts are complete with zero broken TUs and zero incomplete
functions: llama.cpp `4dee52f82dc4` requested/executed `200/200`, 40 findings;
TensorFlow Lite `a481b10260df` requested/executed `241/245`, 73 findings (the
documented admitted extra-execution case); ShadPS4 `5a4373c80e32` requested/executed
`382/382`, 66 findings. All three completed with the findings-only semantic exit
and immutable artifacts keyed to the same CodeSkeptic head.

## Phase 8.4 — release-candidate factory promotion — QUALIFIED (2026-08-12)

**Boundary:** promote only the three recipes qualified at CodeSkeptic head
`ecec77a8b02bb2ffdbf62d4deff936bbcaf65ff6`: llama.cpp `4dee52f82dc4`,
TensorFlow Lite `a481b10260df`, and ShadPS4 `5a4373c80e32`. The accepted
factory remains manifest-driven; candidate commands, source selection,
expected coverage, and semantic fingerprints must equal the immutable
qualification receipts rather than being rewritten during promotion.

**Factory gate:** add one manual 72-hour `release-candidate` tier with exactly
three repetitions per project. A single analyzer artifact serves every shard
in a run. Aggregation accepts a project only when all three checksummed
receipts have identical identity and semantic evidence, zero broken TUs, zero
incomplete functions, and the pinned findings-only verdict. ShadPS4 must also
verify its recursive 53-entry submodule identity and checksum before build.

**RED evidence:** at boundary head `0759dca`, planning the release-candidate
tier exits `2` because the campaign is absent. The implementation gate is a
`0` plan with exactly nine shards, the campaign and qualification contract
tests, full CTest, document automation, then a hosted aggregate receipt for
all nine shards.

**Local and hosted GREEN evidence:** the accepted manifest now has 11 projects and three
campaigns. `release-candidate` planning exits `0` with exactly nine shards
(three projects by three repetitions); campaign and qualification contract
tests pass; the LLVM 19 Release build completes `100/100`; and full CTest
passes `1177/1177`. Hosted run `31536531313` at
`21278b2e561c76aabc0fbca6c72c911eb341c62a` accepted all nine checksummed
receipts and the aggregate receipt. Every project has three identical semantic
receipts, all nine use one analyzer identity, and no receipt has a broken TU,
an incomplete function, or a failure entry.

**Hosted attempt 1 (run `31523815926`):** plan and the shared LLVM 19 analyzer
passed, but release-candidate shard images lacked the matching Clang resource
headers. The first llama.cpp receipts were unavailable (`200` attempted, `1`
analyzed, `199` broken), so the run was cancelled. The workflow now installs
`clang-19` on release-candidate shards while retaining `clang-20` for the
nightly and weekend tiers; no partial receipt is accepted as evidence.

**Hosted attempt 2 (run `31525147338`):** installing only `clang-19` supplied
the analyzer resources but removed the `clang-20` executable pinned by all
three qualified source-build recipes; TensorFlow Lite therefore failed during
configure. The run was cancelled. Release-candidate shards now install both
packages: `clang-20` preserves the immutable candidate build commands and
`clang-19` supplies the shared analyzer runtime resources. Existing tiers
continue to install only `clang-20`.

**Hosted attempts 3–8:** runs `31525916462`, `31528519780`, `31529684488`,
`31531567925`, `31532850193`, and `31534556897` successively exposed and
closed the qualified target-closure, binding, linker, Shad system-package,
package-array, and `clang-tools-19` environment gaps. Each unwinnable run was
cancelled; partial receipts remained unavailable. Focused campaign tests pass
`17/17`, qualification tests pass `7/7`, syntax and diff checks pass, and the
release-only package subset is pinned without changing nightly or weekend
shards.

**Hosted attempt 9 (run `31536531313`):** the plan, shared analyzer, all three
Llama receipts, all three TensorFlow Lite receipts, and Shad repeats 2 and 3
passed on the first attempt. Shad repeat 1 stopped before project work during
runner checkout; a failed-only rerun preserved the ten successful jobs, then
accepted Shad repeat 1 and the aggregate. Final evidence is Llama `200/200`
with 40 findings, Shad `382/382` with 66 findings, and TensorFlow Lite
`241` requested / `245` analyzed with 73 findings. All three repetitions per
project are semantically identical; broken and incomplete totals are zero.
The aggregate status is `accepted`, its checksum verifies, and all nine
receipts share analyzer SHA-256
`12e7409ef03aba54ac166898aaefb64f8ef7373adad89fe676162c4d95fc5f39`.

## Phase 9.0 — upstream validation boundary — BOUNDARY LOCKED (2026-08-12)

**Boundary:** apply PLAN section 6 Gates A, B, and C to current default-branch
heads. Completion requires at least ten accepted fixes across at least five
independent projects. An accepted fix must retain the observed affected head,
the four Gate A proofs, the Gate B channel/value decision, the Gate C report
or patch identity, the merged change identity, and proof that the merged
change remains in the current default-branch history.

**Classification gate:** rejected, duplicate, non-triggerable, stale, and
false-positive candidates remain durable learning records. They do not count
toward the acceptance target, cannot be silently removed, and cannot be
promoted by tool output alone. One candidate represents one defect and every
external action is preceded by a fresh current-head and duplicate check.

**Verified baseline:** three accepted fixes across two projects are currently
proven. shadPS4 PRs `#4702` and `#4703` are merged and their merge commits are
ancestors of current `main`; TensorFlow PR `#123994` is merged and its merge
commit is an ancestor of current `master`. The remaining measured gap is seven
accepted fixes and three independent projects.

**RED evidence:** the repository has no machine-readable Phase 9 candidate
ledger or validator, and the cumulative exit gate is objectively unmet at
`3/10` accepted fixes and `2/5` projects. The first GREEN slice must add a
schema-checked append-only ledger, import the three proven records, preserve
all non-accepted classifications, and fail closed when ancestry or required
Gate A/B/C evidence is missing. No candidate reporting begins until those
local ledger gates pass.

**Slice 9.1 local GREEN:** the schema-checked ledger imports the three proven
records and reports the measured incomplete state as `3/10` accepted fixes
across `2/5` projects. Its validator requires every accepted Gate A/B/C field,
merged-change identity, current default-branch ancestry evidence, unique IDs,
and the fixed cumulative target. Optional previous-ledger comparison permits
only an unchanged prefix plus appended records; mutation, deletion, and
reordering fail closed. A dedicated PR job compares proposed and target-tree
ledgers; the first addition permits a missing target ledger, while later
changes must retain the exact existing prefix. Gate C uses general report and
fix references rather than assuming one hosting platform, and recorded dates
have checked ISO forms. Ten focused tests, Python syntax, JSON parsing,
document automation, and diff checks pass. No new candidate was reported.

**Slice 9.2 candidate snapshot GREEN:** accepted Phase 8 receipts expose 260
findings across seven independent projects, so the candidate pool is larger
than the Phase 9 project target. The first current-head batch freezes three
low-drift heads verified on 2026-08-12: rtp2httpd (11 commits beyond its Phase
8 pin), llama.cpp (28), and libgit2 (538). A deterministic materializer copies
only those projects' qualified recipes, replaces only their immutable
revisions, rejects repository drift, unknown or duplicate projects, malformed
dates or commits, and produces a planner-accepted nine-shard campaign. Four
focused tests plus the ten ledger tests pass. This snapshot authorizes local
candidate discovery only; no finding becomes accepted or externally reported
without the Phase 9 Gates A, B, and C.

**Slice 9.2 current-head execution GREEN:** the first local rtp2httpd run
exposed two default-recipe defects in the shared runner: optional Ninja target
output had no default value, then an empty value still invoked target filtering
and removed every translation unit. The runner now initializes the optional
text and applies target filtering only when target evidence exists; focused
contracts pin both paths. With the Fedora LLVM 19 runtime and resource headers
isolated under `/tmp`, current rtp2httpd head
`e49df993ca2629bb116a29a87ce2afff24d97ef7` produced an accepted `38/38`
receipt, zero broken TUs, zero incomplete functions, and 24 findings. All
19 unique fingerprints exactly match the accepted Phase 8 pin: removed 0,
added 0. This is candidate-discovery evidence, not an accepted-fix count.

## Recovered product program — Phases 8–12

The owner-approved program recovered from the former external development
note is recorded here because `docs/PLAN.md` is intentionally fixed and the
repository forbids new `PLAN-*.md` files. This section is the durable queue;
each active slice still requires its own immutable boundary and RED-to-GREEN
evidence above before implementation.

- **Phase 8 — real-repository test factory.** PR work stays within 30 minutes:
  unit/full CTest, bounded Juliet, cJSON, tinyxml2, and self-scan. Nightly
  8–12-hour capacity covers libgit2, rtp2httpd, Abseil, and libarchive;
  weekend 36–48-hour capacity later covers systemd, curl, Redis, and measured
  larger projects; release-candidate 72-hour capacity later covers llama.cpp,
  shadPS4, and selected TensorFlow Lite surfaces. Every project requires an
  immutable commit, real compile database, exact requested-TU identity,
  timeout, resumable checkpoint, checksummed artifacts, and three independent
  identical semantic receipts. Broken/skipped TUs make the verdict explicitly
  unavailable; they never become a partial green.
- **Phase 9 — upstream validation.** Apply PLAN §6 Gates A, B, and C to current
- Güncel aday paketi kapsam yenilemesi doğrulandı: varsayılan tariflerde boş hedef bilgisi eski kapsam kapısını çalıştırmıyor.
- Güncel başlık kaydı kapsam grubuyla sınırlı; birim sayısı, incelenen sayısı ve bulgu özeti birlikte yenileniyor.
- İkinci proje güncel başlığı üç tekrarda da kabul edildi: 201/201, eksik 0, bulgu 41.
- [x] libgit2 current-head candidate qualification: three fresh repetitions accepted at 168/168 translation units, 0 broken, 0 incomplete, and 42 deterministic findings; the Phase 9 accepted-fix ledger remains 3 fixes across 2 projects.
- [ ] rtp2httpd allocation-result hardening submitted as PR #709 and marked ready for upstream review; build and executable smoke checks pass and the independently reproduced path is gone. Await upstream acceptance before changing the Phase 9 ledger.
- [ ] libgit2 missing-mode output guard submitted as PR #7345 and marked ready for upstream review; full build and local tests pass, focused analysis is clean at 1/1, and the independent path is gone. Await upstream acceptance before changing the Phase 9 ledger.
- Faz 9 kabul sayacı değişmedi; bu çalışma aday doğrulamasıdır, yukarı akış kabulü değildir.
  upstream HEADs. Target at least five independent projects and ten accepted
  fixes. Rejected, duplicate, non-triggerable, and false-positive candidates
  remain classified learning evidence rather than being hidden or promoted.
- **Phase 10 — robustness and performance.** Fuzz configuration,
  compile-database, JSON summary, and SARIF inputs; exercise ASAN/UBSAN and,
  if parallel execution exists, TSAN; stress broken ASTs, templates, macros,
  and CFGs; enforce per-TU timeout/memory budgets, cache correctness, and
  resumable checkpoints. Exit only after 72 hours without crash/hang and
  without an unexplained performance regression above 10%.
- **Phase 11 — distribution and governance.** Freeze stable JSON/SARIF with a
  migration policy; ship Baseline v2 with suppression reason and expiry;
  complete SECURITY, contribution/issue templates, public roadmap, dependency
  policy, SBOM, provenance/signing, troubleshooting, and offline operation
  documentation. Distribution artifacts must produce the same verdicts as
  source builds.
- **Phase 12 — beta and v1.0.** Run three external projects for 30 days in
  report-only mode, measure triage/suppression behavior, and permit optional
  blocking only after a clean week. Freeze breaking CLI/schema changes and
  publish the 1.0 checklist and support policy.

The cross-phase v1 gates remain cumulative: every analyzable requested TU is
processed or returns exit 2; 10/10 runs have deterministic fingerprints; no
default rule has precision below 0.85 and total default precision is at least
0.90; low-precision rules remain experimental; addressable default recall is
at least 0.70; the clean corpus has zero false positives; at least 200 findings
are triaged; at least five projects and ten upstream fixes are accepted; the
72-hour stability gate passes; distribution parity holds; and three external
pilots complete 30 days. No phase prose overrides measured evidence or the
protected-main PROGRESS authority.

## Açık kullanıcı kararları

Yok. Kullanıcı 2026-08-08'de ürün programı tamamlanana kadar dış etkili
işlemler için sürekli yürütme yetkisi verdi; tekrar onay beklenmeyecek. Güncel
CI makbuzları PR açıklamasında tutulur, bu TODO geçici run durumlarını
kopyalamaz. PR #119'un yönetici bypass'ı tamamlandı; TensorFlow PR #123994
merge edildi, issue #123387 kapandı ve PLAN §6 ledger'ı güncellendi.

## Backlog (öncelik sırası)

Phase 7 lifetime-v2 is delivered by PR #134 and the automation maintenance is
delivered by PR #135. Phase 8.1 is active on
`phase-realworld-test-factory` under the locked boundary above. Weekend and
release-candidate factory tiers follow only after the nightly core receipts
are repeatable.

## Not — dosya disiplini (2026-07-30 kararı)

Yeni PLAN-*.md AÇMA. Her iş: changelog'a giriş + bu TODO güncellenir +
PLAN sabit. Ölçüm makbuzları changelog'a yazılır (ayrı dated dosya değil).
Bu kural artık CI ile zorunlu: scripts/check_docs_sync.sh (build-and-test).
