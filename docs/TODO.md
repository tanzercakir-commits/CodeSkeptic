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

Phase 5 is locally complete on `phase-fd-resource-model` and remains split
into measurable RED-to-GREEN slices pending its PR gates and merge:

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
2. **Wrapper propagation and explicit models — locally complete.** The
   existing v10 return/parameter ownership axes are the only declaration
   channel. Visible integer wrapper chains now compose locally and across TUs
   through the existing SCC solver; bodyless acquire/consume/transfer APIs
   require an explicit reviewed v10 model. Conditional/conflicting effects
   degrade to `Unknown`, and `Unknown`/`Borrowed` never suppress a leak.
   The exact file set stayed `src/engine/FunctionSummary.cpp`,
   `src/rules/FdResourceRule.cpp`, `tests/FdResourceRuleTest.cpp`,
   `docs/engine.md`, `docs/usage.md`, this TODO, and
   `docs/devlog/changelog.md`; no header/API, configuration, grammar,
   ContractRule, or default model changed. Gates: RED 5/29, focused 33/33,
   summary/model/contract 129/129, direct and CTest 1010/1010, exact CLI
   smoke 2 report-only findings, thesis `clean_fp=0` / `bug_caught=9/15`,
   clean 48/48-TU self-scan, cJSON 54, and tinyxml2 9.
3. **Pinned libarchive validation and promotion — locally complete.** The
   exact 132-file library surface (123 compile-DB files plus nine controlled
   fallbacks, 255 analysis executions) is complete with zero broken TUs and
   zero incomplete functions. Manual triage classified all 12 initial
   descriptor reports as false and exposed non-local transfer plus negative
   snapshot gaps. RED was 3/39; GREEN is 42/42. The final clean run has zero
   descriptor findings, while three independent load-bearing close mutations
   produce exactly 3 TP / 0 FP: precision 1.000 and mutation recall 3/3.
   `resource-leak` is now supported, quality-gated, and blocking. Final local
   gates are focused 45/45, direct and CTest 1019/1019, thesis
   `clean_fp=0` / `bug_caught=9/15`, clean 48/48-TU self-scan, cJSON 54,
   and tinyxml2 9.

The first slice's contract-first shadow audit found no eligible function: its
40 new or materially changed source functions depend on enum lattice
relations, strings/containers, Clang AST/CFG identity, resource ownership, or
analyzer lifetime beyond the current contract referee. Counts are proposals
0, eligible 0, rejected 0, unsupported 40; no `cs: ai` proposal became
accepted intent. The independent RED suite found the planned feature gap and
the namespace/method precision assumption; both are closed.

The second slice's shadow audit likewise found no eligible function among 46
new or materially changed C++ functions. They depend on Clang type/AST/CFG
identity, enum/resource lattices, containers, summary-registry state,
filesystem streams, or analyzer lifetime beyond the current referee. Counts:
proposals 0, eligible 0, rejected 0, unsupported 46. The independent RED found
the planned wrapper/model gap; precision review removed an ordinary-integer
Borrowed overclaim. Candidate contracts: none. No `cs: ai` proposal became
accepted intent.

The third slice's shadow audit considered 15 new or materially changed
production functions. Every candidate depends on Clang AST/CFG identity,
container/lattice state, class members, or resource-ownership lifetime beyond
the current referee, so dogfood was not applicable. Counts: proposals 0,
eligible 0, rejected 0, unsupported 15. No proposal exposed a problem; the
independent libarchive scan exposed the non-local transfer and negative
snapshot assumptions, and both are closed. Candidate contracts: none. No
`cs: ai` proposal became accepted intent, and native memory semantics remain
deferred to executable A7 fixtures.

## Açık kullanıcı kararları

Yok. Kullanıcı 2026-08-08'de ürün programı tamamlanana kadar dış etkili
işlemler için sürekli yürütme yetkisi verdi; tekrar onay beklenmeyecek. Güncel
CI makbuzları PR açıklamasında tutulur, bu TODO geçici run durumlarını
kopyalamaz. PR #119'un yönetici bypass'ı tamamlandı; TensorFlow PR #123994
merge edildi, issue #123387 kapandı ve PLAN §6 ledger'ı güncellendi.

## Backlog (öncelik sırası)

```
1. alloc-size v2: 64-bit size_t multiplication corner proof
2. sign-conversion v2: interprocedural sink (the nlohmann harm was in a
   different function)
```

## Not — dosya disiplini (2026-07-30 kararı)

Yeni PLAN-*.md AÇMA. Her iş: changelog'a giriş + bu TODO güncellenir +
PLAN sabit. Ölçüm makbuzları changelog'a yazılır (ayrı dated dosya değil).
Bu kural artık CI ile zorunlu: scripts/check_docs_sync.sh (build-and-test).
