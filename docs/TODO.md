# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH01-S06-U002

### CS3-CH01-S06-U002 — Ortak integer literal ve guard çözümünde unsigned değeri koru

**Sonuç:** Paylaşılan interval literal/guard çözümünde unsigned sabitin gerçek değeri korunur; sahte negatif değerle erişilebilirlik veya kapasite kanıtı üretilmez.

**Kabul:**

- Unsigned 32-bit literal ve local initializer zincirinin negatif signed değere dönüştüğü hata önce değişikliksiz RED ile doğrulanır; doğrudan değer ve consumer branch guard ayrı sınanır.
- Signed/unsigned 32/64/128 literal ve cast sınırları gerçek AST türüyle değerlendirilir; int64 modeline sığmayan değer unknown kalır, düşük bitlere veya negatif değere sessiz daraltılmaz.
- INT64_MIN/MAX, karşılaştırma guard'ı, allocation boyutu ve kaynak/hedef bounds kontrollerinde mevcut pozitif ve güvenli negatifler korunur; bütün unsigned aritmetiğin çözüldüğü iddia edilmez.
- Ortak literal/guard üreticisi değişikliği tam Linux suite ve ilgili sayı/bounds corpus dilimi ile doğrulanır; gerçek CLI kapsamı ve bağımsız exact-head PASS gereklidir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/engine/IntervalEval.cpp, src/engine/IntervalEval.h, tests/IntervalAnalysisTest.cpp, tests/BoundsRuleTest.cpp, tests/IntOverflowRuleTest.cpp, tests/AllocSizeOverflowRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S02-U002

### CS3-CH01-S06-U003 — accept ailesinin wrapper sahipliğini ortak özette koru

**Sonuç:** accept/accept4 çağrısından dönen sahiplik ortak function summary üzerinden caller'a taşınır; wrapper arkasındaki sızıntı kaybolmaz.

**Kabul:**

- S04-U001 sırasında gerçek CLI ile görülen accept-returning wrapper eksikliği önce değişikliksiz RED ile doğrulanır; doğrudan native çağrı pozitif kontrolü aynı fixture'da bulunur.
- Gerçek C/C++ accept/accept4 imzaları, tek ve çok katlı return wrapper'ları ve caller close/leak ayrımı modellenir; dinlenen descriptor borrowed kalır, -1 yalnız başarısızlıktır.
- Yalnız isim eşleşen method/namespace/yanlış prototip ve owned olmayan constant-return fonksiyonlar otomatik owned sayılmaz; ortak producer tanımı ile FdResourceRule sözleşmesi ayrışmaz.
- Mevcut open/socket/dup, FILE/DIR, summary model/conflict ve cross-TU davranışları tam Linux suite ve ilgili ownership corpus/gerçek CLI diliminde korunur; çalışma dışı kod donor olarak kopyalanmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/engine/FunctionSummary*, src/rules/FdResourceRule*, tests/InterproceduralTest.cpp, tests/FdResourceRuleTest.cpp, tests/MemoryLeakRuleExTest.cpp
**Bağımlılıklar:** CS3-CH01-S04-U001

### CS3-CH01-S07-U001 — Mevcut CI kapılarını agent dalı push olayına bağla

**Sonuç:** Yeni görev dalları mevcut Linux, Windows ve ilgili Juliet kontrollerini tetikleyebilir; FIFO yeşili ürün yeterliliğiyle karıştırılmaz.

**Kabul:**

- agent/cs3-* push olayları Linux ve Windows işlerini; kaynak/test veya ci/regression-checkpoint.json değişikliği varsa Juliet'i seçer. Mevcut main, phase*, PR ve schedule davranışları korunur.
- build-and-test adı, self-scan, corpus, thesis ve Juliet adımları korunur; eski pin, tolerans, quality floor ve destek kararları değiştirilmez.
- Yeni agent olayları eski refs/status veya refs/ci-logs force-push adımlarını çalıştırmaz; normal job sonucu ve artifact kullanılır. Main ruleset değişimi, yeni PR veya merge yapılmaz.
- Dal/olay/yol matrisi ve seçilmemesi gereken negatifler yerel testle, workflow yapısı ayrı doğrulamayla sınanır; varsayılan dalda olmayan dispatch kaydına güvenilmez.
- Bu bir yerel tetikleme bağlantısı teslimidir; hosted PASS ve gerçek dünya yeterliliği sonraki exact-head checkpoint görevinin kabulüdür.

**Test bütçesi:** T0
**Kontroller:** workflow-policy-tests, workflow-validation, queue-check
**Kapsam:** .github/workflows/ci.yml, .github/workflows/windows.yml, .github/workflows/juliet.yml, tests/WorkflowPolicyTest.py, docs/CI_GATES.md
**Bağımlılıklar:** CS3-CH01-S06-U003

### CS3-CH01-S07-U002 — Exact base-head checkpoint ve kanıt doğrulayıcısını kur

**Sonuç:** Açıkça seçilen feature checkpoint'i sabit girdilerde kesin base/head analyzer sürümlerini karşılaştırır; eksik veya farklı kimlikte kanıt kabul edilmez.

**Kabul:**

- Checkpoint tam base SHA'yı belirtir; head olayın kesin SHA'sıdır. Kanıt workflow SHA, binary ve manifest digest, proje revision, run ID/attempt ve kapsamı taşır.
- Mevcut PR measurement ve manuel/zamanlanmış real-world yolları korunur. Yeni yol push ile açık checkpoint seçer; sıradan ledger push'ları ağır kampanyayı yeniden başlatmaz.
- Mevcut measurement ve real-world runner'ları ile aynı immutable manifest/proje girdileri iki analyzer için kullanılır; eski kalite koşulları ve pinler aynen uygulanır.
- Doğrulayıcı yanlış SHA/manifest, eksik proje/tekrar, skipped/cancelled/unavailable iş, coverage kaybı ve bozuk artifact/digest'i reddeder. Başarılı kontrol yanında bu negatifler ayrı test edilir.
- Süre/fingerprint raporu ile gerçekten engelleyen kalite koşulları ayrılır. Yerel fixture ve gerçek CLI dilimi çalışır; sentetik receipt veya hazırlanmış workflow hosted başarı sayılmaz.

**Test bütçesi:** T2
**Kontroller:** checkpoint-tests, workflow-validation, linux-suite, checkpoint-cli-smoke, queue-check
**Kapsam:** .github/workflows/measurement.yml, .github/workflows/realworld.yml, scripts/run_regression_checkpoint.py, scripts/verify_regression_checkpoint.py, tests/RegressionCheckpointTest.py, ci/regression-checkpoint.json, docs/CI_GATES.md
**Bağımlılıklar:** CS3-CH01-S07-U001

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
**Kapsam:** ci/regression-checkpoint.json, docs/CI_GATES.md
**Bağımlılıklar:** CS3-CH01-S07-U002

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH02 — Güvenilir analiz girdisi ve kapsam
- CH03 — CWE bulgularını kullanılabilir ürüne dönüştürme
- CH04 — Sınırlı kaynakla dayanıklı çalışma
- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
