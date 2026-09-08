# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH07-S01-U001

### CS3-CH07-S01-U001 — Release adayını kullanıcı iş akışlarıyla kabul et

**Sonuç:** Kurulum, ilk tarama, CI, triage ve destek belgeleri aynı ürünü anlatır.

**Kabul:**

- Kabul matrisi her teslim sözü için exact source/artifact ve PASS kanıtı gösterir.
- Açık blocker, eksik platform veya karşılanmayan kalite hedefi gizlenmez.
- Main merge/release gerekiyorsa exact aday için ayrı kullanıcı yetkisi alınır.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** docs/release-checklist.md, docs/usage.md, docs/first-scan.md, README.md, RELEASE_NOTES.md
**Bağımlılıklar:** Yok

### CS3-CH07-S01-U002 — Yetkili teslimi ve son FIFO kapanışını doğrula

**Sonuç:** Tüm kabul edilmiş işler PROGRESS'te bulunur; TODO terminal boş duruma geçer.

**Kabul:**

- Yetkili yayın veya yalnız yerel teslim ayrımı açıkça kayıtlıdır; main izinsiz değiştirilmez.
- Görev/commit/bağımsız review kanıtları korunur; TODO'da sahte DONE/gizli yan kuyruk bulunmaz.
- Eksik required dış eylem varsa iş kapanmaz; tamamlandı denilerek kuyruk boşaltılmaz.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** docs/release-checklist.md, RELEASE_NOTES.md
**Bağımlılıklar:** CS3-CH07-S01-U001

## Sonraki chapter kuyruğu — henüz yürütülemez
