# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH05-S02-U002

### CS3-CH05-S02-U002 — Gerçek proje ve performans kabulünü ölç

**Sonuç:** Sabit girdilerde kullanılabilirlik, latency ve false positive yükü ölçülür.

**Kabul:**

- En az üç küçük/orta gerçek C/C++ proje veya önceden edinilmiş checksummed örnek kullanılır; kaynaklar izinsiz upload edilmez.
- Donanım, girdi, komut, sürüm ve süre/bellek ölçümleri kayıtlıdır.
- Ölçülmeyen performans/market başarısı iddia edilmez; blocker varsa aynı chapter kapanmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** scripts/measure_product.py, docs/quality_results.md, docs/benchmarks.md, tests/ProductMeasurementTest.py, scripts/test_measure_product.py
**Bağımlılıklar:** Yok

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
