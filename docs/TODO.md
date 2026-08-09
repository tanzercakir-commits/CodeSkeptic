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
base   = 3aa85f9
uçuşta = phase-memory-lifetime-v2
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
3. **Custom allocator/deallocator pairs — pending.** Move beyond independent
   name lists to exact configured families and validate mismatch, wrapper,
   indirect-summary, and conservative unknown-target behavior.
4. **RAII and smart pointers — pending.** Model exact adoption, release,
   reset, move, and destruction paths for supported standard owners while
   keeping project wrappers explicitly configured and non-owning views silent.
5. **Escape, ownership transfer, and exceptional exits — pending.** Complete
   exact local/member/summary transfers and admitted cleanup or exceptional
   exits, then pin real-repository and Juliet deltas.

Phase 7 exits only when addressable UAF/double-free/leak recall rises,
`memory-leak` precision remains at least 0.85 (target 0.90), supported UAF and
double-free precision floors remain at least 0.95, clean corpora stay clean,
and every local/CI referee passes without weakening an existing floor.

Documentation automation follow-up (owner request, 2026-08-09): after the
Phase 7.1 commit, declare a separate maintenance boundary for extending the
existing docs-sync path so verified stage transitions and progress receipts
update TODO/progress artifacts automatically. The automation must remain
fail-closed and must never infer completion before the relevant verifier
passes.

## Açık kullanıcı kararları

Yok. Kullanıcı 2026-08-08'de ürün programı tamamlanana kadar dış etkili
işlemler için sürekli yürütme yetkisi verdi; tekrar onay beklenmeyecek. Güncel
CI makbuzları PR açıklamasında tutulur, bu TODO geçici run durumlarını
kopyalamaz. PR #119'un yönetici bypass'ı tamamlandı; TensorFlow PR #123994
merge edildi, issue #123387 kapandı ve PLAN §6 ledger'ı güncellendi.

## Backlog (öncelik sırası)

The Phase 7 lifetime-v2 requirements are owned by the five active slices
above; there is no separate unowned lifetime item.

## Not — dosya disiplini (2026-07-30 kararı)

Yeni PLAN-*.md AÇMA. Her iş: changelog'a giriş + bu TODO güncellenir +
PLAN sabit. Ölçüm makbuzları changelog'a yazılır (ayrı dated dosya değil).
Bu kural artık CI ile zorunlu: scripts/check_docs_sync.sh (build-and-test).
