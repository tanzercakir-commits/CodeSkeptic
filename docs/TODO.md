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
2. **`realloc` success/failure paths — pending.** Preserve the original
   allocation on failure, transfer lifetime on success, and cover direct,
   temporary, overwrite, `reallocarray`, null-input, zero-size, guarded, and
   unknown outcomes without treating possible release as definite.
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
