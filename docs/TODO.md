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
base   = 8393a8b
uçuşta = phase-integer-allocation-v2
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

Phase 5 is merged through PR #132. Its exact squash commit is
`8393a8b0c07460c6636e4aa79528bdd7b55a5b22`; the squash tree
`bba0359b379cf264e52fca03a46eade2e542a760` matches the fully gated branch
head, the remote feature branch is deleted, and local/remote `main` agree.

Phase 6 is active on `phase-integer-allocation-v2` and is divided into
independently measurable RED-to-GREEN slices:

1. **64-bit `size_t` multiplication corner proof — locally complete.** Extend
   the allocation-size rule only when an untrusted unsigned operand, a finite
   constant factor, and the result type's width prove that the mathematical
   product can exceed the 64-bit maximum. A dominating division guard must
   silence the report; unknown factors, non-allocator arithmetic, ordinary
   inputs, and insufficient proof stay silent. The exact slice file set is
   `src/rules/AllocSizeOverflowRule.{h,cpp}`,
   `tests/AllocSizeOverflowRuleTest.cpp`, this TODO, and
   `docs/devlog/changelog.md`. `PLAN.md`, the interval engine, contract
   grammar, capability registry/tier, configuration, and accepted models
   remain unchanged. Gates: RED 2/12; focused 14/14; direct and CTest
   1026/1026; exact CLI 1 report / guarded twin 0; thesis `clean_fp=0` and
   `bug_caught=9/15`; clean 48/48-TU self-scan; cJSON 54 and tinyxml2 9.
   Shadow counts are proposals 0, eligible 0, rejected 0, unsupported 6;
   no `cs: ai` proposal became accepted intent.
2. **Checked arithmetic and signed/unsigned chains — locally complete.**
   Preserve the
   exact reachable upper corner through stable, local signed-to-unsigned cast
   and alias chains, including narrowing conversions. Recognize the
   Clang/GCC `__builtin_*mul*_overflow` family when its direct output variable
   reaches an allocator: a proven no-overflow branch is silent, while an
   ignored or overflow-path result reports only when the same finite-corner
   proof establishes wrap. Unknown factors, unstable/reassigned chains,
   non-allocator uses, and unproven relations stay silent. The exact slice
   file set is `src/rules/AllocSizeOverflowRule.{h,cpp}`,
   `tests/AllocSizeOverflowRuleTest.cpp`, this TODO, and
   `docs/devlog/changelog.md`. The shared interval engine,
   `SignConversionRule`, contract grammar, capability registry/tier,
   configuration, and accepted models remain unchanged. Gates: RED 5/25;
   focused 32/32; direct and CTest 1044/1044; exact CLI 1/0 for both the
   signed-cast and checked-builtin unsafe/safe pairs; thesis `clean_fp=0` and
   `bug_caught=9/15`; clean 48/48-TU self-scan; cJSON 54 and tinyxml2 9.
   Shadow counts are proposals 0, eligible 0, rejected 0, unsupported 50;
   no `cs: ai` proposal became accepted intent.
3. **Interprocedural allocator sinks and allocation-to-access evidence —
   locally complete.** Add a versioned allocator-size parameter relation to
   function summaries and propagate only exact, visible parameter-to-size flows through
   the existing SCC, indirect-target, persistence, and conservative-merge
   paths. The allocation rule may consume only a proven sink parameter;
   bodyless, conflicting, transformed, or unknown flows stay silent. Attach
   access trace evidence only when an exact local allocation result is later
   indexed or used by a bounded memory-access call with the same declared
   untrusted origin; absence of access evidence does not replace the existing
   wrap proof. Pin and replay the relevant LVGL example. The exact slice file
   set is `src/engine/FunctionSummary.{h,cpp}`,
   `src/engine/SummaryDiff.cpp`,
   `src/rules/AllocSizeOverflowRule.{h,cpp}`,
   `tests/AllocSizeOverflowRuleTest.cpp`, `tests/InterproceduralTest.cpp`,
   `tests/SummaryDiffTest.cpp`, `tests/CapabilitiesCliTest.py`, this TODO, and
   `docs/devlog/changelog.md`. `PLAN.md`, the shared interval engine,
   contract grammar, capability registry/tier, configuration, and accepted
   model channels remain unchanged. RED was recorded as 8 failures in the
   initial 11-case matrix; the expanded pointer-reassignment and uninvoked-
   lambda precision controls were each independently RED before their fixes.
   Gates: focused 51/51; direct and CTest 1063/1063; exact CLI wrapper 1 report
   / guarded twin 0; exact access fixture 1 report with one trace note; pinned
   LVGL v9.2.2 replay 1 report at `lv_binfont_loader.c:511:72`; capability CLI
   schema 2 / 14 rules / 7 supported with alloc-size-overflow still
   experimental and non-blocking; frozen thesis `clean_fp=0` and
   `bug_caught=9/15`; clean 48/48-TU self-scan; cJSON 54 and tinyxml2 9.
   Shadow counts are proposals 2, eligible 0, rejected 2, unsupported 40;
   Linux CI classified both proposals as `contract-unsupported`, so they were
   removed and no candidate remains for human review. Neither became accepted
   intent.

Phase 6 exits only when guarded cases are silent, unknown values remain
reportless, real-repository examples are pinned, and the full local/CI
referees pass without weakening existing floors.

## Açık kullanıcı kararları

Yok. Kullanıcı 2026-08-08'de ürün programı tamamlanana kadar dış etkili
işlemler için sürekli yürütme yetkisi verdi; tekrar onay beklenmeyecek. Güncel
CI makbuzları PR açıklamasında tutulur, bu TODO geçici run durumlarını
kopyalamaz. PR #119'un yönetici bypass'ı tamamlandı; TensorFlow PR #123994
merge edildi, issue #123387 kapandı ve PLAN §6 ledger'ı güncellendi.

## Backlog (öncelik sırası)

The former alloc-size v2 and sign-conversion v2 entries are now owned by the
active Phase 6 slices above; there is no separate unowned item.

## Not — dosya disiplini (2026-07-30 kararı)

Yeni PLAN-*.md AÇMA. Her iş: changelog'a giriş + bu TODO güncellenir +
PLAN sabit. Ölçüm makbuzları changelog'a yazılır (ayrı dated dosya değil).
Bu kural artık CI ile zorunlu: scripts/check_docs_sync.sh (build-and-test).
