# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH01-S07-U003

### CS3-CH01-S07-U003 — İlk hosted regresyon checkpoint'ini gerçek exact-head kanıtıyla kapat

**Sonuç:** Yeni kuyruk hattının eski ürün ve gerçek dünya kontrollerindeki durumu gerçek GitHub sonuçlarıyla doğrulanır; main entegrasyonu yapılmaz.

**Kabul:**

- Primary temiz feature commit'ini bağımsız yayın ön-kontrolünden sonra yalnız fast-forward push eder; ön-kontrol ürün PASS/POP değildir ve hosted kanıt gereğini kaldırmaz. Yeni PR, main yazma/merge, koruma değişimi, tag/release veya force-push yoktur.
- Aynı aday head için Linux build-and-test, Windows, Juliet ve base-head measurement gerçekten başarılıdır; yalnız Project FIFO veya başka SHA'nın yeşili yeterli değildir.
- Tek toplu T3 profili: mevcut nightly ve weekend manifestlerinin toplam sekiz projesi, proje başına üç tekrar, kesin base ve head analyzer ile tamamlanır. Mevcut proje timeout'ları ve en fazla altı paralel shard korunur; profil her atomik görevde tekrarlanmaz.
- Artifact eksikliği, erişilemeyen kayıt, başarısız proje, eşik ihlali veya açıklanmamış bulgu kaybı başarısızlıktır. Eski başarılı main koşusu, yerel PASS veya baseline düşürme yerine kullanılamaz.
- Maddi regresyon önce yeniden üretilir; aynı kabul için gerekli dar dosya eklemesi bağımsız kapsam geçişi ister. Yeni özellik ekleme, kuyruk atlama veya kabul zayıflatma yoktur.
- Bağımsız denetçi gerçek hosted sonuçları ve checksum'lı receipt'leri doğrulamadan POP olmaz; yerel tamamlanma, hosted yeterlilik ve main entegrasyonu ayrı raporlanır.

**Test bütçesi:** T3
**Kontroller:** hosted-regressions, hosted-realworld-base-head, checkpoint-receipt-validation, queue-check
**Kapsam:** ci/regression-checkpoint.json, docs/CI_GATES.md, tests/FdResourceRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S07-U002

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH02 — Güvenilir analiz girdisi ve kapsam
- CH03 — CWE bulgularını kullanılabilir ürüne dönüştürme
- CH04 — Sınırlı kaynakla dayanıklı çalışma
- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
