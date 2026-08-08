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
base   = 6aad09c
uçuşta = phase-fd-resource-model
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

Phase 4 is merged through PR #131. Its exact squash commit is
`6aad09c8030ebdf14b4bef2eeb6596f25f650e17`; the squash tree matches the
fully gated Phase 4 head, and the local and remote `main` branches agree.

Phase 5 is active on `phase-fd-resource-model` and remains split into
measurable RED-to-GREEN slices:

1. **Direct POSIX descriptor lifecycle — locally complete.** A separate
   integer-resource rule covers global `open`/`openat`/`socket`/`dup`/
   `mkstemp`, `close`, the `-1` failure sentinel, branches, early returns,
   cleanup labels, local aliases, discarded results, and return/global
   ownership transfer. `shutdown` correctly does not close a descriptor.
   Namespace functions and methods with colliding names are excluded. The
   exact slice file set stayed
   `src/rules/FdResourceRule.{h,cpp}`, `src/main.cpp`,
   `src/server/McpServer.cpp`, `src/CMakeLists.txt`,
   `tests/FdResourceRuleTest.cpp`, `tests/CMakeLists.txt`, this TODO, and
   `docs/devlog/changelog.md`; `MemoryLeakRule_Ex` remained untouched.
   Gates: focused 21/21, direct and CTest 998/998, exact CLI smoke,
   thesis `clean_fp=0` / `bug_caught=9/15`, clean 48/48-TU self-scan,
   cJSON 54 and tinyxml2 9.
2. **Next:** inspect the existing summary/model axes, then declare the exact
   second-slice file set before adding wrapper propagation and explicit
   custom resource models. Reuse the strict model grammar; do not create a
   second grammar or implicit ownership authority.
3. Run the pinned libarchive validation, manually triage every new finding,
   and close Phase 5 only at measured precision of at least 0.90 with no
   regression in the existing local, thesis, self-scan, or corpus gates.

The first slice's contract-first shadow audit found no eligible function: its
40 new or materially changed source functions depend on enum lattice
relations, strings/containers, Clang AST/CFG identity, resource ownership, or
analyzer lifetime beyond the current contract referee. Counts are proposals
0, eligible 0, rejected 0, unsupported 40; no `cs: ai` proposal became
accepted intent. The independent RED suite found the planned feature gap and
the namespace/method precision assumption; both are closed.

## Açık kullanıcı kararları

Yok. Kullanıcı 2026-08-08'de ürün programı tamamlanana kadar dış etkili
işlemler için sürekli yürütme yetkisi verdi; tekrar onay beklenmeyecek. Güncel
CI makbuzları PR açıklamasında tutulur, bu TODO geçici run durumlarını
kopyalamaz. PR #119'un yönetici bypass'ı tamamlandı; TensorFlow PR #123994
merge edildi, issue #123387 kapandı ve PLAN §6 ledger'ı güncellendi.

## Backlog (öncelik sırası)

```
1. CWE-775 strict — Phase 5 aktif. Doğrudan POSIX integer-resource domain'i
   tamamlandı; wrapper/custom model ve libarchive triaj/precision kapısı açık.
   > BULGU 3 (libarchive, 2026-08-01): 43 ham fd açıcı ölçüldü
   > (open 28 · openat 8 · dup 4 · mkstemp 3). Pointer domain yalnızca
   > fopen/opendir/tmpfile toplam 3 kaynağı görüyordu; Phase 5 çıkış ölçümü
   > bu önkoşulu tam analiz ve manuel triajla kapatacak.
2. alloc-size v2: 64-bit size_t çarpım köşe-ispatı
3. sign-conversion v2: interprocedural sink (nlohmann'da harm başka fn'deydi)
```

## Not — dosya disiplini (2026-07-30 kararı)

Yeni PLAN-*.md AÇMA. Her iş: changelog'a giriş + bu TODO güncellenir +
PLAN sabit. Ölçüm makbuzları changelog'a yazılır (ayrı dated dosya değil).
Bu kural artık CI ile zorunlu: scripts/check_docs_sync.sh (build-and-test).
