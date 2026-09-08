# CodeSkeptic — CWE Ürün Planı

Sürüm: 61. Aynı Chapter → Section → Unit FIFO'sunda ürün tamamlama devamı; önceki kayıtlar korunur.

PLAN/TODO/PROGRESS aynı BOOK.json kaydından üretilir; elle değiştirilmez. Gelecek işler kontrollü olarak eklenebilir/güncellenebilir. Aktif işin kabulü ve tamamlanmış kayıtlar değiştirilmez.

## CH00 — Tek seferlik yeniden başlangıç ve FIFO

### CH00-S01 — Yürütme sözleşmesi

#### CS3-CH00-S01-U001 — Main tabanlı kitabı ve çalışan FIFO/POP sistemini kur

**Sonuç:** Eski dallar referans olarak saklanır; bağımsız doğrulama olmadan kuyruk ilerleyemez.

**Kabul:**

- Main ve src ağacı değişmez; eski yerel dal uçları geri yüklenebilir arşivde doğrulanır.
- PLAN tam chapter–section katalogdur; TODO yalnız aktif chapter'ın tam görevlerini gösterir.
- 30 veya daha fazla odaklı test FIFO, chapter geçişi, terminal durum, stale/missing kanıt, yanlış dal, scope ihlali, rollback ve gerçek süreç kesintisinden recovery'yi sınar.
- Gelecek iş ekleme/güncelleme mevcut front'u, eski görev sırasını ve tamamlanmış kayıtları bozmaz.
- Yerel kanıt kriptografik imza/remote destek diye sunulmaz; bağımsız exact-head PASS sonrası gerçek ilk POP yapılır.

**Test bütçesi:** T0
**Kontroller:** queue-tests, queue-check
**Kapsam:** AGENTS.md, INVARIANTS.md, MASTER_PROMPT.md, CONTRIBUTING.md, docs/BOOK.json, docs/PLAN.md, docs/TODO.md, docs/PROGRESS.md, docs/RESTART.md, docs/QUEUE_GUIDE.md, docs/CWE_SCOPE.md, scripts/project_queue.py, scripts/local_test.sh, scripts/check_docs_sync.sh, tests/test_project_queue.py, tests/CMakeLists.txt, .github/workflows/project-queue.yml, scripts/progress_status.py, tests/StatusAutomationTest.py
**Bağımlılıklar:** Yok

## CH01 — CWE çekirdeğini somut eksiklerle geliştirme

### CH01-S01 — Tamsayı ve ayırma boyutu

#### CS3-CH01-S01-U001 — 64-bit signed çıkarma taşmasını doğru hesapla

**Sonuç:** Çıkarma toplama gibi hesaplanmaz; kanıtlanabilir 64-bit overflow/underflow doğru raporlanır.

**Kabul:**

- Mevcut davranış önce değişikliksiz RED fixture ile doğrulanır; kaynak şüphesi tek başına hata/PASS sayılmaz.
- LLONG_MIN−1 ve LLONG_MAX−(−1) bulunur; LLONG_MAX−1 ve LLONG_MIN−(−1) temiz kalır.
- Unknown değerler, guard'lar ve 32-bit arithmetic davranışı korunur; ilgili IntOverflow regression ve gerçek CLI smoke geçer.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/IntOverflowRule.cpp, tests/IntOverflowRuleTest.cpp, scripts/local_test.sh
**Bağımlılıklar:** CS3-CH00-S01-U001

#### CS3-CH01-S01-U002 — 64-bit allocation-size toplamayı denetle

**Sonuç:** n+header gibi allocation boyutlarında unsigned sarma mevcut çarpım modeline eklenir.

**Kabul:**

- SIZE_MAX sınırı, exact fit, korumalı toplam ve taşan toplam karşılaştırılır.
- Mevcut 64-bit multiplication ve trusted/unknown kaynak sınırları bozulmaz.
- CWE-131/190 bulgusu gerçek ayırma boyutuna bağlıdır; bütün unsigned toplamalar uyarılmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/AllocSizeOverflowRule.cpp, tests/AllocSizeOverflowRuleTest.cpp
**Bağımlılıklar:** Yok

#### CS3-CH01-S01-U003 — Checked-add overflow sonucunun kullanımını izle

**Sonuç:** Checked-add çağrısının başarısızlık sonucu yok sayıldığında güvensiz boyut kullanımı yakalanır.

**Kabul:**

- Builtin add overflow kontrolsüz kullanım pozitif, doğrulanmış success branch negatiftir.
- Status/output reassignment ve escape önceki kanıtı geçersiz kılar.
- Checked-mul regresyonları ve ilgisiz arithmetic bulguları değişmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/AllocSizeOverflowRule.cpp, tests/AllocSizeOverflowRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S01-U002

### CH01-S02 — Bellek okuma ve yazma sınırları

#### CS3-CH01-S02-U001 — memcpy/memmove kaynak okuma kapasitesini denetle

**Sonuç:** Hedef yeterli olsa bile küçük kaynaktan taşan okuma CWE-125 olarak ayrılır.

**Kabul:**

- Büyük hedef/küçük kaynak, exact fit, zero length ve unknown source kapsanır.
- memset için kaynak okuması üretilmez; strncpy farklı semantiğiyle bu işin dışında kalır.
- Mevcut destination write sınırı ve güvenli corpus sonuçları korunur.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/BoundsRule.cpp, src/rules/BoundsRule.h, tests/BoundsRuleTest.cpp
**Bağımlılıklar:** Yok

#### CS3-CH01-S02-U002 — Sabit pointer-offset kalan kapasitesini izle

**Sonuç:** buf+k ve &buf[k] için bilinen kalan kapasite okuma/yazma denetimine girer.

**Kabul:**

- Son byte, taşma, negatif offset ve one-past ile zero length ayrı fixture'lardır.
- Bilinmeyen veya değiştirilmiş alias için kapasite uydurulmaz.
- Kaynak okuma ve hedef yazma bulguları doğru ayrılır; integer hesap taşması güvenli kalır.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/BoundsRule.cpp, src/rules/BoundsRule.h, src/engine/ExtentMap.cpp, src/engine/ExtentMap.h, tests/BoundsRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S02-U001

### CH01-S03 — Başlatılmamış scalar okumaları

#### CS3-CH01-S03-U001 — Yerel scalar uninitialized-read kuralını ekle

**Sonuç:** Yerel integer/bool değerinin atama öncesi gerçek okuması yeni experimental kimlikle raporlanır.

**Kabul:**

- int x; return x; ve arithmetic read pozitif; initializer, assignment-first, sizeof ve yalnız adres alma negatiftir.
- Static/thread-local sıfır başlangıcı yanlış bulgu üretmez.
- Pointer-only mevcut kuralın tüm CWE-457'yi kapsadığı iddia edilmez; kuralın kimliği ve registration'ı tutarlıdır.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/UninitScalarRule*, src/analyzer/StaticAnalyzer.cpp, src/main.cpp, src/server/McpServer.cpp, src/core/RuleCapabilities.def, src/core/Capabilities.cpp, src/CMakeLists.txt, tests/UninitScalarRuleTest.cpp, tests/CMakeLists.txt, docs/capabilities.md, README.md, scripts/check_capabilities_sync.py, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py
**Bağımlılıklar:** Yok

#### CS3-CH01-S03-U002 — Scalar initialization durumunu CFG birleşimlerinde koru

**Sonuç:** Branch/loop birleşimlerinde definitely-initialized ile possibly-uninitialized ayrılır.

**Kabul:**

- Her iki branch atama güvenlidir; yalnız bir branch atama gerçek okumada bulgu üretir.
- Loop zero-iteration, break/continue ve erken dönüş fixture'ları vardır.
- Kapsam yerel integer/bool'dur; struct/heap/exception tam desteği iddia edilmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/UninitScalarRule*, tests/UninitScalarRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S03-U001

### CH01-S04 — Kaynak sahipliği

#### CS3-CH01-S04-U001 — accept/accept4 descriptor sahipliğini modelle

**Sonuç:** Başarılı accept ailesi çağrısından dönen descriptor için close/transfer/leak takibi yapılır.

**Kabul:**

- Başarı sonrası kapatma, dönüşle ownership transferi ve leak ayrılır.
- −1 hata yolu kaynak yaratmaz; aynı isimli kullanıcı metodu yanlış eşleşmez.
- Mevcut open/socket/dup ve FILE/DIR modelleri korunur.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/FdResourceRule.cpp, src/rules/FdResourceRule.h, tests/FdResourceRuleTest.cpp
**Bağımlılıklar:** Yok

#### CS3-CH01-S04-U002 — pipe/pipe2 çift descriptor çıkışını modelle

**Sonuç:** Başarılı iki out-param descriptor bağımsız kaynak olarak izlenir.

**Kabul:**

- Başarıda iki kapatma, tek kapatma ve hiç kapatmama sonuçları ayrılır.
- Hatalı dönüş ve yeniden atanmış out-param sahte ownership yaratmaz.
- İki kaynak tek bulguda kaybolmaz; mevcut descriptor dönüş modeli bozulmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/FdResourceRule.cpp, src/rules/FdResourceRule.h, tests/FdResourceRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S04-U001

### CH01-S05 — Sayısal dönüşüm

#### CS3-CH01-S05-U001 — Uzunluk ve index sink'lerinde kanıtlı narrowing kaybını raporla

**Sonuç:** Implicit sayısal daraltmada hedef türe sığmayan kanıtlı aralık sink'e bağlanır.

**Kabul:**

- Exact fit, promotion, explicit intentional cast, enum/dependent ve unknown sınırları açıktır.
- Allocator dışındaki uzunluk/index sink'leri dar kapsamlı fixture'larla sınanır.
- Mevcut signed-overflow/narrowing ile çift rapor üretilmez; genel cast uyarıcısına dönüşmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/SignConversionRule.cpp, src/rules/SignConversionRule.h, tests/SignConversionRuleTest.cpp
**Bağımlılıklar:** Yok

### CH01-S06 — Beyan edilmiş boyut kaynağının genişlik sınırı

#### CS3-CH01-S06-U001 — uint64 out-param kaynak kökenini sayısal aralıktan ayır

**Sonuç:** Beyan edilmiş kaynağın doğrudan uint64 pointer/reference çıktısı, signed interval üst sınırı gösterilemiyor diye güvenilir kabul edilmez.

**Kabul:**

- U002 sırasında kaynak incelemesinde görülen doğrudan uint64 out-param eksikliği önce değişikliksiz RED ile doğrulanır; C &n ve C++ non-const reference ayrı sınanır.
- n+header ve n*constant için taşan pozitif ile gerçek SIZE_MAX korumalı negatif örnekler vardır; origin işareti ile top/finite aralık birbirine karıştırılmaz.
- 32-bit kaynak, signed kaynak, scanf, return-value/alias kökeni ve unknown mutation sınırları korunur; desteklenmeyen pointer-alias kaynağı çözüldü diye sunulmaz.
- Ortak transfer değişikliği tam Linux suite ve ilgili allocation/source corpus dilimi ile doğrulanır; eksik araç veya koşturulmayan kontrol PASS değildir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/engine/IntervalEval.cpp, src/engine/IntervalEval.h, tests/IntervalAnalysisTest.cpp, tests/AllocSizeOverflowRuleTest.cpp, tests/IntOverflowRuleTest.cpp, tests/SignConversionRuleTest.cpp, src/rules/AllocSizeOverflowRule.cpp
**Bağımlılıklar:** CS3-CH01-S01-U002

#### CS3-CH01-S06-U002 — Ortak integer literal ve guard çözümünde unsigned değeri koru

**Sonuç:** Paylaşılan interval literal/guard çözümünde unsigned sabitin gerçek değeri korunur; sahte negatif değerle erişilebilirlik veya kapasite kanıtı üretilmez.

**Kabul:**

- Unsigned 32-bit literal ve local initializer zincirinin negatif signed değere dönüştüğü hata önce değişikliksiz RED ile doğrulanır; doğrudan değer ve consumer branch guard ayrı sınanır.
- Signed/unsigned 32/64/128 literal ve cast sınırları gerçek AST türüyle değerlendirilir; int64 modeline sığmayan değer unknown kalır, düşük bitlere veya negatif değere sessiz daraltılmaz.
- INT64_MIN/MAX, karşılaştırma guard'ı, allocation boyutu ve kaynak/hedef bounds kontrollerinde mevcut pozitif ve güvenli negatifler korunur; bütün unsigned aritmetiğin çözüldüğü iddia edilmez.
- Ortak literal/guard üreticisi değişikliği tam Linux suite ve ilgili sayı/bounds corpus dilimi ile doğrulanır; gerçek CLI kapsamı ve bağımsız exact-head PASS gereklidir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/engine/IntervalEval.cpp, src/engine/IntervalEval.h, tests/IntervalAnalysisTest.cpp, tests/BoundsRuleTest.cpp, tests/IntOverflowRuleTest.cpp, tests/AllocSizeOverflowRuleTest.cpp, src/engine/ConditionWalk.h, src/rules/BoundsRule.cpp
**Bağımlılıklar:** CS3-CH01-S02-U002

#### CS3-CH01-S06-U003 — accept ailesinin wrapper sahipliğini ortak özette koru

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

### CH01-S07 — Hosted regresyon kapılarını yeni dal akışına bağla

#### CS3-CH01-S07-U001 — Mevcut CI kapılarını agent dalı push olayına bağla

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

#### CS3-CH01-S07-U002 — Exact base-head checkpoint ve kanıt doğrulayıcısını kur

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

#### CS3-CH01-S07-U003 — İlk hosted regresyon checkpoint'ini gerçek exact-head kanıtıyla kapat

**Sonuç:** Yeni kuyruk hattının eski ürün ve gerçek dünya kontrollerindeki durumu gerçek GitHub sonuçlarıyla doğrulanır; main entegrasyonu yapılmaz.

**Kabul:**

- Primary temiz feature commit'ini bağımsız yayın ön-kontrolünden sonra yalnız fast-forward push eder; ön-kontrol ürün PASS/POP değildir ve hosted kanıt gereğini kaldırmaz. Yeni PR, main yazma/merge, koruma değişimi, tag/release veya force-push yoktur.
- Aynı aday head için Linux build-and-test, Windows, Juliet ve base-head measurement gerçekten başarılıdır; yalnız Project FIFO veya başka SHA'nın yeşili yeterli değildir.
- Tek toplu T3 profili: mevcut nightly ve weekend manifestlerinin toplam sekiz projesi, proje başına üç tekrar, kesin base ve head analyzer ile tamamlanır. Mevcut proje timeout'ları ve en fazla altı paralel shard korunur; profil her atomik görevde tekrarlanmaz.
- Artifact eksikliği, erişilemeyen kayıt, başarısız proje, eşik ihlali veya açıklanmamış bulgu kaybı başarısızlıktır. Eski başarılı main koşusu, yerel PASS veya baseline düşürme yerine kullanılamaz.
- Maddi regresyon önce yeniden üretilir; aynı kabul için gerekli dar dosya eklemesi bağımsız kapsam geçişi ister. Yeni özellik ekleme, kuyruk atlama veya kabul zayıflatma yoktur.
- Bağımsız denetçi gerçek hosted sonuçları ve checksum'lı receipt'leri doğrulamadan POP olmaz; yerel tamamlanma, hosted yeterlilik ve main entegrasyonu ayrı raporlanır.
- Sahibin 2026-09-05 açık onayıyla, sabit base beklentileri değiştirilmeden yalnız head için kaynak ve regresyon kanıtına bağlı bağımsız incelenmiş kesin semantik fark kaydı kullanılabilir. Yanlış pozitif olduğu kanıtlanan eski bulgunun kaldırılması veya doğrulanmış yeni bulgunun eklenmesi proje/revision, eski beklenti ve tam fingerprint çoklu kümesiyle tek tek gerekçelendirilir; tolerans aralığı, genel bastırma ve açıklanmamış fark kabul edilmez. Base özgün manifestle, head ayrıca adlandırılmış ve hash'lenmiş kesin etkin beklentiyle doğrulanır; kaynaklar, tarifler, kapsam/kalite eşikleri, üç tekrar ve 48 shard şartı değişmez. Eski başarısız kayıtlar korunur; kabul ancak yeni exact-head başarılı hosted koşu ve bağımsız raw base/head fark denetimiyle sağlanır.

**Test bütçesi:** T3
**Kontroller:** hosted-regressions, hosted-realworld-base-head, checkpoint-receipt-validation, queue-check
**Kapsam:** ci/regression-checkpoint.json, docs/CI_GATES.md, tests/FdResourceRuleTest.cpp, src/rules/FdResourceRule.cpp, src/rules/UninitScalarRule.cpp, tests/UninitScalarRuleTest.cpp, scripts/run_regression_checkpoint.py, scripts/verify_regression_checkpoint.py, tests/RegressionCheckpointTest.py, ci/regression-adjudications.json
**Bağımlılıklar:** CS3-CH01-S07-U002

## CH02 — Güvenilir analiz girdisi ve kapsam

### CH02-S01 — Derleme gerçeği

#### CS3-CH02-S01-U001 — Compilation database keşfi ve doctor komutunu yeniden uygula

**Sonuç:** Kullanıcı doğru database'i veya düzeltilebilir açık hatayı görür.

**Kabul:**

- Eski 060bf4b yalnız fikir/dar kod kaynağıdır; dosyalar topluca kopyalanmaz.
- CMake/Ninja fixture, boş repo, iki database, bozuk JSON ve single-file kapsanır.
- Sessiz yanlış database/fallback yoktur; doctor ile gerçek analiz aynı seçim sonucunu kullanır.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/source_manager/CompilationDatabaseDiscovery*, src/source_manager/SourceManager*, src/config/Config*, src/analyzer/StaticAnalyzer*, src/core/Messages*, src/main.cpp, src/CMakeLists.txt, tests/CompilationDatabaseCliTest.py, tests/ConfigTest.cpp, tests/CMakeLists.txt, docs/first-scan.md, .github/workflows/windows.yml, tests/WorkflowPolicyTest.py, docs/windows-support.md
**Bağımlılıklar:** Yok

#### CS3-CH02-S01-U002 — Config ve target-scope güncellemelerini işlemsel yap

**Sonuç:** Geçersiz config/scope girdisi önceki geçerli durumu kısmen değiştirmez.

**Kabul:**

- Malformed, overflow, delimiter-only ve conflict girdilerinde state byte-equivalent kalır.
- Bozuk kapsam analizi genişletmez veya güvenilir temiz hüküm üretmez.
- CLI ve MCP girişleri aynı structured reason sözleşmesini uygular.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/config/Config*, src/source_manager/SourceManager*, src/core/Messages*, src/server/McpServer*, tests/ConfigTest.cpp, tests/SourceManagerTest.cpp, tests/McpServerTest.cpp, tests/CMakeLists.txt
**Bağımlılıklar:** Yok

#### CS3-CH02-S01-U003 — Çoklu producer kural seçimini diagnostic ID ile tutarlı uygula

**Sonuç:** Kural kapatma işlemi yalnız sınıf adını değil yayımlanan diagnostic ID sözleşmesini bütün ilgili producer'larda uygular.

**Kabul:**

- S04-U001 CLI keşfi önce RED ile yeniden doğrulanır: --disable-rule resource-leak sonrasında FILE/DIR aynı ID ile hâlâ raporlanıyor; yalnız native FD producer'ının kaldırılması yeterli değildir.
- Bilinen diagnostic ID kapatıldığında o ID'yi üreten bütün producer'ların bulguları tutarlı seçilir; farklı ID'lerin etkinliği, varsayılan kalite/tier ve kapsam sayaçları sessiz değişmez.
- CLI ve MCP'nin mevcut yapılandırma yüzeyleri aynı seçim sözleşmesini uygular; kapalı/açık/kapalı ardışık kullanımda istekler arasında durum sızmaz, var olmayan seçenek çalıştı sayılmaz.
- Native FD, FILE/DIR ve memory-leak pozitif/negatifleri gerçek CLI/MCP ve focused analyzer/config testleriyle sınanır; JSON/SARIF/verdict sayımları etkin bulgularla tutarlıdır.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/analyzer/StaticAnalyzer*, src/config/Config*, src/engine/RuleEngine*, src/core/Capabilities*, src/core/RuleCapabilities.def, src/server/McpServer*, src/main.cpp, tests/McpServerTest.cpp, tests/ConfigTest.cpp, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/AnalysisResultTest.cpp, tests/MemoryLeakRuleExTest.cpp, tests/FdResourceRuleTest.cpp, tests/VerdictIntegrityTest.cpp
**Bağımlılıklar:** CS3-CH01-S04-U001

### CH02-S02 — Kalıcı ve dış girdiler

#### CS3-CH02-S02-U001 — Fonksiyon özeti/model parser sınırlarını sağlamlaştır

**Sonuç:** Bozuk, sürümü uyumsuz veya aşırı büyük özet/model dosyası güvenli reddedilir.

**Kabul:**

- Arity/index, CRLF, embedded NUL, count/size ve version fixture'ları vardır.
- Hata kısmi model/state yayımlamaz; normal geçerli dosyalar korunur.
- Dar donor fikirleri yeni baseline üzerinde yeniden test edilir.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/engine/FunctionSummary*, src/contracts/*, tests/InterproceduralTest.cpp, tests/ContractRuleTest.cpp, tests/PolicyRuleTest.cpp, tests/ContractTest.cpp, tests/SummaryDiffTest.cpp
**Bağımlılıklar:** Yok

#### CS3-CH02-S02-U002 — MCP istek zarfını ve yaşam döngüsünü sınırla

**Sonuç:** Malformed JSON-RPC istekleri ve işlem hataları sunucuyu veya sonraki isteği bozmaz.

**Kabul:**

- Eksik/yanlış ID/version/method ve boyut sınırı deterministik hata üretir.
- Başarısız istek sonrası geçerli istek temiz state ile çalışır.
- CLI ile aynı analiz davranışı korunur; yeni ağ/cloud servisi eklenmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/server/McpServer*, src/config/Config*, tests/McpServerTest.cpp, src/source_manager/SourceManager.cpp, src/analyzer/StaticAnalyzer.cpp
**Bağımlılıklar:** Yok

### CH02-S03 — Eksik analizden sahte temiz sonuç üretmeme

#### CS3-CH02-S03-U001 — İstenen/analiz edilen/atlanan/başarısız dosyaları uzlaştır

**Sonuç:** Her istenen kaynak tek kimlikle sonuç sınıfına ve gerekçeye sahip olur.

**Kabul:**

- Tekrarlanan AST callback dosya sayısını artırmaz; eksik TU kaybolmaz.
- Kapsam eksikse sonuç güvenilir temiz olamaz; exit 0/1/2 sözleşmesi fixture'larla sınanır.
- JSON/SARIF ve CLI aynı kapsam özetini taşır.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/analyzer/StaticAnalyzer*, src/source_manager/SourceManager*, src/core/AnalysisResult.h, src/core/ExitPolicy.h, src/core/Messages*, src/reporter/*, tests/StaticAnalyzerTest.cpp, tests/SourceManagerTest.cpp, tests/ExitPolicyTest.cpp, tests/ReporterTest.cpp, src/source_manager/CompilationDatabaseDiscovery.cpp, tests/VerdictIntegrityTest.cpp, tests/AnalysisResultTest.cpp, tests/JsonReporterTest.cpp, tests/SarifReporterTest.cpp, tests/HtmlReporterTest.cpp, tests/CompilationDatabaseCliTest.py, docs/usage.md, tests/ConfigTest.cpp, tests/CapabilitiesCliTest.py, scripts/run_realworld_campaign.py, tests/RealworldCampaignTest.py, docs/reproduce.md, scripts/verify_regression_checkpoint.py, tests/RegressionCheckpointTest.py, src/server/McpServer.cpp, tests/McpServerTest.cpp, scripts/run_regression_checkpoint.py
**Bağımlılıklar:** Yok

#### CS3-CH02-S03-U002 — Frontend ve CFG düşmanca geçerli girdilerde sonlansın

**Sonuç:** Template/macro/CFG köşeleri crash/hang yerine sınırları belirli sonuç verir.

**Kabul:**

- Küçük, repository-contained template/macro/high-CFG fixture'ları kullanılır.
- Hata veya timeout eksik kapsama nedeni olarak korunur.
- Ortak motor değişirse tam Linux suite ve yalnız ilgili sanitizer/stress dilimi çalışır.
- Zaten gerekli Linux suite için ReviewDiffFlow önkoşulu da tamamlanır: 611edab hosted expected-1/got-2 hatası gerçek analyzer stderr ve base/head komut kimlikleriyle RED olarak doğrulanır. Yalnız review girdi hazırlama/remap ve fixture uyumluluğu düzeltilir; repo-root database, rename ve yeni dosya kapsamı sınanır. Gerçek build/generated-header koruması, exact-command reddi, new/fixed/weakened sayımları, shift/rename bağışıklığı, gate ladder, exclude ve malformed/missing-input negatifleri korunur; hiçbir kalite kapısı, pin veya suite kapsamı azaltılmaz. Frontend/CFG kabulleri aynen geçerlidir; ikisi de tamamlanmadan POP yoktur.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/StaticAnalyzer*, src/source_manager/SourceManager*, src/engine/*, tests/stress_corpus/*, tests/StressMatrixTest.py, scripts/run_stress_matrix.py, scripts/test_review_diff.sh, scripts/review_diff.sh, scripts/review_report.py, tests/CMakeLists.txt, tests/ReviewInputTest.py
**Bağımlılıklar:** Yok

### CH02-S04 — Hosted derleyici uyumluluğu

#### CS3-CH02-S04-U001 — Compilation discovery için native LLVM/MSVC uyumluluğunu doğrula

**Sonuç:** Mevcut Windows toolchain compilation discovery kodunu derler; komut kimliği doğrulaması ve ürün kapıları korunur.

**Kabul:**

- 611edab Windows hosted LLVM 20.1.8/MSVC OPT_ redefinition hatası kanıt olarak korunur, nedeni teşhis edilip yalnız gerekli uyumluluk düzeltmesi uygulanır.
- Geçerli compilation-command ve wrong-input/response-file negatifleri korunur; driver doğrulaması devre dışı bırakılamaz.
- Exact-head native Windows build, test, smoke, SDK ve relocation kapıları başarılı olmalıdır; atlanan adım başarı değildir. Main, mevcut toolchain pinleri ve kalite kapıları değişmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, compilation-database-cli, hosted-windows, queue-check
**Kapsam:** src/source_manager/CompilationDatabaseDiscovery.cpp, tests/CompilationDatabaseCliTest.py, src/CMakeLists.txt, tests/SourceManagerTest.cpp, scripts/review_report.py, tests/ReviewInputTest.py, src/windows_utf8.manifest, docs/windows-support.md, scripts/run_corpus.sh, scripts/corpus_compile_commands.cpp, tests/CMakeLists.txt, src/source_manager/SourceManager.cpp, docs/usage.md
**Bağımlılıklar:** CS3-CH02-S01-U001

## CH03 — CWE bulgularını kullanılabilir ürüne dönüştürme

### CH03-S01 — Rapor sözleşmesi

#### CS3-CH03-S01-U001 — Kural ve CWE eşlemesini tek sözleşmede yayınla

**Sonuç:** Bulguların stable rule ID, doğru CWE ve açıklama bağlantısı vardır.

**Kabul:**

- CWE-125 okuma ile CWE-787 yazma farklı açıklanır; her bounds bulgusu aynı CWE'ye yanlış eşlenmez.
- Existing supported/experimental durumu ölçümsüz yükseltilmez.
- JSON/SARIF metadata ve CLI capability listesi registry ile tutarlıdır.
- Aritmetik pozitif taşma ile negatif sınır taşması doğru mesajla ayrılır; 64-bit çıkarmada upward overflow underflow diye sunulmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/core/RuleCapabilities.def, src/core/Capabilities*, src/core/Diagnostic.h, src/core/AnalysisResult.h, src/reporter/*, src/rules/*, tests/SarifReporterTest.cpp, tests/CapabilitiesTest.cpp, docs/capabilities.md, src/core/Messages.*, tests/IntOverflowRuleTest.cpp, tests/JsonReporterTest.cpp, tests/CapabilitiesCliTest.py, README.md, scripts/check_capabilities_sync.py, tests/BoundsRuleTest.cpp, src/analyzer/StaticAnalyzer.cpp
**Bağımlılıklar:** Yok

#### CS3-CH03-S01-U002 — CLI/JSON/SARIF/HTML bulgu ve verdict tutarlılığını sabitle

**Sonuç:** Aynı analiz bütün çıktı yüzeylerinde aynı normalize bulguyu ve kapsamı verir.

**Kabul:**

- Rule/CWE, konum, trace, severity, tool/schema version ve verdict karşılaştırılır.
- Malformed option/config deterministik hatadır; makine çıktısına log karışmaz.
- Path component sınırları ve Windows path fixture'ları korunur.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/reporter/*, src/core/Capabilities*, src/core/Messages*, src/main.cpp, src/config/Config*, tests/*ReporterTest.cpp, tests/CapabilitiesTest.cpp, tests/ConfigTest.cpp, src/analyzer/StaticAnalyzer.cpp, tests/OutputParityCliTest.py, tests/CMakeLists.txt
**Bağımlılıklar:** Yok

### CH03-S02 — Günlük geliştirme kullanımı

#### CS3-CH03-S02-U001 — Baseline/suppression ile yalnız yeni bulguyu ayır

**Sonuç:** Yeni kod kontrolü legacy bulguları gizlice yeni veya yok sayılmış göstermeden çalışır.

**Kabul:**

- Stable fingerprint, moved lines, changed function ve malformed baseline/suppression kapsanır.
- Bastırma kaydı gerekçe/kapsam içerir; suppression analiz kapsamını değiştirmez.
- Eski bulgu yükü yeni yüksek güvenli bulguyu engellemez veya saklamaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/analyzer/Baseline*, src/analyzer/SuppressionFilter*, src/core/FindingFingerprint*, scripts/review_diff.sh, scripts/review_report.py, tests/BaselineTest.cpp, tests/SuppressionFilterTest.cpp, tests/test_review_diff.sh, src/core/AnalysisResult.h, src/analyzer/StaticAnalyzer.cpp, src/reporter/ReportContract.h, tests/HtmlReporterTest.cpp, scripts/test_review_diff.sh, src/core/Diagnostic.h, src/reporter/SarifReporter.cpp, tests/OutputParityCliTest.py
**Bağımlılıklar:** Yok

#### CS3-CH03-S02-U002 — Minimal ilk tarama ve CI kullanımını doğrula

**Sonuç:** Temiz bir örnek projede kurulmuş araçla ilk tarama ve rapor-only CI akışı tekrarlanır.

**Kabul:**

- En az bir küçük C ve bir C++ fixture yeni kullanıcı komutlarıyla çalışır.
- Eksik derleme girdisinde uygulanabilir düzeltme adımı vardır.
- Canlı GitHub yazma/bot devreye alma şart değildir; yerel örnek hazır olmadan destek iddiası yoktur.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** docs/first-scan.md, docs/usage.md, docs/integrations.md, README.md, tests/FirstScanTest.py, scripts/test_first_scan.sh
**Bağımlılıklar:** Yok

## CH04 — Sınırlı kaynakla dayanıklı çalışma

### CH04-S01 — İşlem izolasyonu

#### CS3-CH04-S01-U001 — Dosya başına taşınabilir worker protokolü kur

**Sonuç:** Bir dosyanın çökmesi diğer dosyaların sonuçlarını kaybettirmez.

**Kabul:**

- Aynı binary ile sürümlü child protocol ve deterministik TU sırası vardır.
- Crash/malformed child result ayrı failure olur; parent güvenilir temiz diyemez.
- Eski worker dalı topluca taşınmaz; sudo, broker, systemd/cgroup bağımlılığı yoktur.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, src/core/AnalysisResult.h, src/main.cpp, src/CMakeLists.txt, tests/WorkerProtocolTest.cpp, tests/AnalysisCoordinatorTest.cpp, tests/CMakeLists.txt, tests/HtmlReporterTest.cpp
**Bağımlılıklar:** Yok

#### CS3-CH04-S01-U002 — Timeout/bellek/iptal bütçesini uygula

**Sonuç:** Kaynak bütçesi aşan worker sonlandırılır; süreç ve descriptor sızıntısı bırakılmaz.

**Kabul:**

- Timeout, memory limit ve cancellation negatifleri gerçek subprocess ile sınanır.
- Partial failure sonuç ve kapsamda görünür; diğer sonuçlar deterministik toplanır.
- Host-wide/root authority yoktur; yalnız başlatılan çocuk süreçler yönetilir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, src/core/Resource*, src/config/Config*, src/main.cpp, src/CMakeLists.txt, tests/ResourceBudgetTest.cpp, tests/AnalysisCoordinatorTest.cpp, tests/CMakeLists.txt, docs/usage.md, src/server/McpServer.cpp
**Bağımlılıklar:** CS3-CH04-S01-U001

### CH04-S02 — Güvenli yeniden kullanım

#### CS3-CH04-S02-U001 — Cache kimliğini gerçek girdilere bağla

**Sonuç:** Cache yalnız aynı araç/ayar/girdi/header bağımlılıkları için kullanılabilir.

**Kabul:**

- Değişen header/compiler flag/profile/tool veya volatile input eski kaydı reddeder.
- Cache'siz ve cache'li normalize sonuç aynı olur.
- Eski a79c375 yardımcı fikir kaynağıdır; kanıt veya dosya paketi olarak taşınmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/analyzer/*, src/source_manager/*, src/config/Config*, tests/UnitEvidenceStoreTest.cpp, tests/AnalysisCoordinatorTest.cpp, src/CMakeLists.txt, tests/CMakeLists.txt, tests/SourceManagerTest.cpp, src/contracts/Sidecar.cpp, src/server/McpServer.cpp, docs/usage.md
**Bağımlılıklar:** Yok

#### CS3-CH04-S02-U002 — Cache yazımı ve saklama sınırını güvenli yap

**Sonuç:** Kısmi/bozuk/symlink kayıt kullanılmaz; disk kullanımı tanımlı tavanda kalır.

**Kabul:**

- Atomic temp-to-final, concurrent writers, truncated entry ve tamper fixture'ları vardır.
- Failed write önceki geçerli entry'yi bozmaz; retention sonucu analiz doğruluğu değişmez.
- Saklama tavanı aşılırsa açık durum verir; sınırsız cache oluşturulmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, tests/UnitEvidenceStoreTest.cpp, src/config/Config.cpp, src/config/Config.h, tests/ConfigTest.cpp, tests/AnalysisCoordinatorTest.cpp, docs/usage.md
**Bağımlılıklar:** CS3-CH04-S02-U001

#### CS3-CH04-S02-U003 — Checkpoint yalnız aynı geçerli analizi sürdürsün

**Sonuç:** Kesilen çalışma tam girdi kimliği doğrulandıktan sonra devam eder.

**Kabul:**

- Changed source/header/config/corrupt manifest resume'u reddeder.
- Resume ve fresh run sonuç/kapsam eşittir; eksik worker sonucu DONE sayılmaz.
- Disk ve süreç sınırları cache/worker sözleşmesini aşmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, src/config/Config*, src/main.cpp, tests/UnitEvidenceStoreTest.cpp, tests/AnalysisCoordinatorTest.cpp, tests/ConfigTest.cpp, docs/usage.md, tests/McpServerTest.cpp
**Bağımlılıklar:** CS3-CH04-S02-U002

### CH04-S03 — Yerel ve hosted platform tutarlılığı

#### CS3-CH04-S03-U001 — Windows fixture taşınabilirliğini gerçek hosted kapılarla doğrula

**Sonuç:** Windows testleri canonical path, size_t ve fiziksel kaynak byte sözleşmesini doğru sınar; mevcut ürün beklentileri ve hosted kapılar korunur.

**Kabul:**

- cab9493306752fa15e4fc74273678f674a5442d0 Windows run34045241136/job101519028589 içindeki dört gerçek RED saklanır: coordinator canonical yol, Bounds memcpy size_t, suppression CRLF ve baseline CRLF. Başarısız tarihsel sonuç yeniden PASS diye etiketlenmez.
- Dört test fixture'ının platform varsayımları düzeltilir; tüm bulgu sayıları, source/destination ayrımı, strong identity ve marker/target beklentileri korunur. Canonical beklenen yollar, hedefin gerçek __SIZE_TYPE__ prototipi ve byte-exact binary kaynak yazımı pozitif/negatif kontrollerle kanıtlanır; ürün kuralları veya assertion'lar gevşetilmez.
- Aynı aday exact head için native Windows build, CTest, tek-süreç suite, CLI smoke, SDK ve relocation dahil mevcut workflow gerçekten başarılıdır; atlanan adım başarı değildir. Linux suite ve ilgili sabit corpus tekrar geçer. Workflow, toolchain pinleri, kalite floor'ları, main ve tamamlanmış sözleşmeler değişmez.
- Bu dört fixture düzeltmesine ek olarak yalnız 94c83277b566813af3b6a3f5d916631900992492 Windows run34055351372 Build aşamasında kaydedilmiş MSVC C3861 _get_environ tanımsızlığı için ortam listeleme uyumluluğu düzeltilir; bu tarihsel RED ve testlerin o koşuda çalışmadığı kaydı korunur. src/source_manager/InputIdentity.cpp içindeki tam ortam kimliği, mevcut byte/entry sınırları ve fail-closed davranış korunur; ortam sessizce boş/filtrelenmiş sayılmaz. tests/SourceManagerTest.cpp içinde aynı ortamın sabit kimliği ve değişken ekleme/değiştirme/silmenin kimliği değiştirmesi ile geri yükleme gerçek platform API'si üzerinden sınanır. Bu dar derleme uyumluluğu dışında ürün davranışı, kurallar, worker/cache doğrulaması ve diğer platformların semantiği değiştirilmez; mevcut exact-head Windows ve Linux kapılarının tamamı yine gereklidir.
- Sahibin 2026-09-07 açık onayıyla, yukarıdaki ürün/kural değişikliği yasağına yalnız şu dar istisna eklenir: e4d52748937b39d5b72dd91d64a04d9a85c59fe8 self-scan kaydında teşhis edilen RAII yapıcı/yıkıcı sahipliği ve başarıya bağlı fdopendir tanıtıcı aktarımı analizde doğru modellenir. Gerçek sahiplik ve kapanış kanıtlanmadan her yapıcıya veya her fdopendir çağrısına koşulsuz tüketim/kaçış atanmaz; başarısız fdopendir çağrısında tanıtıcı çağıranın sorumluluğunda kalır. Aynı fonksiyondaki ilgisiz gerçek sızıntı, sahiplenmeyen yapıcı, eksik/koşullu kapanış ve başarısız aktarım negatifleri korunur; fonksiyon sonu resource-leak bastırmasıyla gerçek sızıntıyı gizlemek yasaktır. Mevcut cache/worker çalışma semantiği, ilgisiz kural davranışları, FIFO sırası, bitmiş kayıtlar, test bütçesi/kontrol adları, pinler, kalite eşikleri ve main değişmez. Eski başarısız kanıtlar korunur; dar RED/GREEN regresyonları, tam self-scan kapsamı, mevcut Linux/Windows hosted kapılarının yeni exact-head başarısı ve bağımsız inceleme yine zorunludur. Bu yalnız kabul istisnasıdır; gerekli uygulama dosyaları ayrıca bağımsız kapsam geçişiyle eklenir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, windows-hosted, queue-check
**Kapsam:** tests/AnalysisCoordinatorTest.cpp, tests/BoundsRuleTest.cpp, tests/SuppressionFilterTest.cpp, tests/BaselineTest.cpp, src/source_manager/InputIdentity.cpp, tests/SourceManagerTest.cpp, tests/UnitEvidenceStoreTest.cpp, tests/ConfigTest.cpp, src/rules/FdResourceRule.cpp, tests/FdResourceRuleTest.cpp, src/analyzer/RuntimeIdentity.cpp
**Bağımlılıklar:** CS3-CH04-S02-U003

## CH05 — Toplu doğrulama ve endüstriyel kabul

### CH05-S01 — Kapsam ve kalite kanıtı

#### CS3-CH05-S01-U001 — Kural bazlı pozitif/negatif doğrulama kataloğunu dondur

**Sonuç:** Ölçüm girdileri sonucu görmeden seçilir ve hangi CWE altkümesinin desteklendiği açıktır.

**Kabul:**

- Her desteklenecek kural için güvenli/buggy fixture kimliği ve beklenen bulgu kayıtlıdır.
- Yeni çekirdek testleri corpus dışında bırakılarak başarı şişirilmez; eski source/corpus floor'ları düşürülmez.
- Unknown/unsupported örnekler false negative veya clean ile karıştırılmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** tests/cwe_corpus/*, scripts/cwe_quality.py, docs/CWE_SCOPE.md, docs/quality_protocol.md
**Bağımlılıklar:** Yok

#### CS3-CH05-S01-U002 — Mevcut supported aileleri yeni motor üzerinde yeniden doğrula

**Sonuç:** Memory/lifetime/null/arithmetic/resource ailelerinin ölçümü mevcut executable'a bağlıdır.

**Kabul:**

- Tam Linux suite ve ilgili checksummed corpus çalışır; eski receipt'ler PASS yerine kullanılmaz.
- Mevcut Juliet ve corpus floor'larının hiçbiri düşürülmez; her yeni bulgu fixture ile açıklanır.
- Clean corpus'ta yeni yanlış pozitif veya sessiz bulgu kaybı çözülmeden iş kapanmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** tests/cwe_corpus/*, scripts/cwe_quality.py, docs/quality_results.md, src/rules/*, tests/*Rule*Test.cpp
**Bağımlılıklar:** CS3-CH05-S01-U001

#### CS3-CH05-S01-U003 — Yeni experimental CWE ailelerinin destek kararını kanıtla

**Sonuç:** Ölçülen altküme dışında destek veya blocking terfisi yapılmaz.

**Kabul:**

- Her yeni kuralın pozitif/negatif ve sınır fixture'ları ayrı raporlanır.
- Declared supported altkümesinde precision en az %90, addressable recall en az %70 ve deterministic safe fixture'larda sıfır FP gerekir; daha sıkı mevcut floor korunur.
- Başaramayan kural experimental/report-only kalır; teslim kapsamından çıkarma veya daha düşük hedef ayrıca kullanıcı kararı gerektirir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/core/RuleCapabilities.def, scripts/cwe_quality.py, tests/cwe_corpus/*, docs/CWE_SCOPE.md, docs/capabilities.md, docs/quality_results.md, README.md, scripts/check_capabilities_sync.py, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py
**Bağımlılıklar:** CS3-CH05-S01-U002

### CH05-S02 — Gerçek kullanım sınırları

#### CS3-CH05-S02-U001 — Sınırlı sanitizer/fuzz ve bozuk girdi kabulünü tamamla

**Sonuç:** Parser/worker/cache sınırları hedefli adversarial testlerden geçer.

**Kabul:**

- Yalnız ilgili sanitizer ve bounded fuzz seed'leri çalıştırılır; süreç/süre/bellek sınırı kayıtlıdır.
- Crash, hang, OOM, partial commit ve false-clean varsa PASS yoktur.
- Eksik araç veya koşmayan kontrol success sayılmaz; testler sırf yeşil için silinmez.
- Korunan c395903 Windows run34098971513 tek-süreç RED kaydındaki 300ms survivor timeout ayrıca teşhis edilir. Kaynak/bütçe fault-injection fixture zamanlaması düzeltilirse gerçek üretim timeout/bellek sınırları ve 150ms sleeping-child kill/reap regresyonu gevşetilmez; survivor bulguları, incomplete exit2 ve bütün mevcut assertions korunur. Eski başarısız koşu başarısız kalır; kontrollü RED/GREEN ve yeni exact-head Windows suite/tek-süreç/package hosted başarısı olmadan bu worker sınırı tamamlandı sayılmaz.
- Yalnız bu görevde gerekçeli test girdisi değişirse önce eski/yeni path-digest farkı bağımsız incelenir; regression_inventory ve catalog bağlantısı yeni ölçümden önce kontrollü successor freeze ile güncellenir. Hiçbir CWE fixture, beklenen bulgu, Juliet/corpus floor veya başarısız geçmiş sonuç değiştirilmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check, windows-hosted
**Kapsam:** tests/stress_corpus/*, fuzz/*, scripts/test_resilience.sh, docs/quality_results.md, tests/AnalysisCoordinatorTest.cpp, tests/ResourceBudgetTest.cpp, tests/cwe_corpus/catalog.json, tests/cwe_corpus/regression_inventory.json, CMakeLists.txt, src/analyzer/AnalysisCoordinator.cpp, src/analyzer/RuntimeIdentity.cpp, src/analyzer/RuntimeIdentity.h, tests/UnitEvidenceStoreTest.cpp
**Bağımlılıklar:** Yok

#### CS3-CH05-S02-U002 — Gerçek proje ve performans kabulünü ölç

**Sonuç:** Sabit girdilerde kullanılabilirlik, latency ve false positive yükü ölçülür.

**Kabul:**

- En az üç küçük/orta gerçek C/C++ proje veya önceden edinilmiş checksummed örnek kullanılır; kaynaklar izinsiz upload edilmez.
- Donanım, girdi, komut, sürüm ve süre/bellek ölçümleri kayıtlıdır.
- Ölçülmeyen performans/market başarısı iddia edilmez; blocker varsa aynı chapter kapanmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** scripts/measure_product.py, docs/quality_results.md, docs/benchmarks.md, tests/ProductMeasurementTest.py, scripts/test_measure_product.py
**Bağımlılıklar:** Yok

## CH06 — Paketleme ve dağıtım

### CH06-S01 — Çalıştırılabilir paket

#### CS3-CH06-S01-U001 — Linux kurulabilir artifact üret

**Sonuç:** Temiz ortamda açılıp çalışan sürümlü Linux paketi üretilir.

**Kabul:**

- CLI ve bütün temel çıktı biçimleri kaynak build ile aynı normalize sonucu verir.
- LLVM/runtime bağımlılıkları ve lisanslar eksiksizdir; geliştirme build'i release gibi adlandırılmaz.
- Paket first-scan smoke'tan geçer; normal kullanım sudo gerektirmez.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/package_release.sh, CMakeLists.txt, src/CMakeLists.txt, docs/release-checklist.md, tests/PackageTest.py, scripts/test_package.py, scripts/package_linux.py
**Bağımlılıklar:** Yok

#### CS3-CH06-S01-U002 — Container ve Action paketinde analiz paritesini doğrula

**Sonuç:** Container/Action aynı binary sözleşmesiyle güvenilir sonucu taşır.

**Kabul:**

- Kaynak kod/secret izinsiz dışarı gönderilmez; runtime varsayılan izinler minimaldir.
- Aynı fixture için CLI/container/Action exit ve SARIF sonuçları eşittir.
- Canlı destek iddiası yalnız gerçekten koşmuş platform/check kanıtına dayanır.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** Dockerfile, action.yml, scripts/action*, tests/ActionArgsTest.py, docs/integrations.md, .github/workflows/action-selftest.yml, .dockerignore
**Bağımlılıklar:** CS3-CH06-S01-U001

### CH06-S02 — Dağıtım güveni

#### CS3-CH06-S02-U001 — Sürüm, checksum, SBOM ve provenance üret

**Sonuç:** Artifact hangi kaynak ve bağımlılıklardan üretildiğini kanıtlarıyla taşır.

**Kabul:**

- Tek authored version source vardır; source SHA ve tool/schema version raporları tutarlıdır.
- Artifact checksum, bağımlılık/lisans listesi ve yeniden üretim komutu kayıtlıdır.
- İmza kimliği yoksa imzalı release iddiası yapılmaz; secret aranmaz veya uydurulmaz.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/package_release.sh, scripts/generate_sbom.py, docs/release-checklist.md, RELEASE_NOTES.md, .github/workflows/release.yml, scripts/test_generate_sbom.py
**Bağımlılıklar:** CS3-CH06-S01-U001

#### CS3-CH06-S02-U002 — Desteklenen platform sözünü gerçek paket testine bağla

**Sonuç:** Linux dışı platformların destek durumu fiilen çalışan artifact testine göre açıklanır.

**Kabul:**

- Windows/macOS dahil destek ilan edilen her platform exact artifact first-scan çalıştırır.
- Eksik runner/signer/authorization başarılı sayılmaz; açık blocker olarak kalır.
- Yerel branch senkronizasyonu main merge veya release yetkisi değildir.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** .github/workflows/windows.yml, .github/workflows/release.yml, docs/windows-support.md, README.md, docs/release-checklist.md, scripts/package_release.sh, scripts/platform_first_scan.py, scripts/test_platform_workflow.py, src/analyzer/StaticAnalyzer.cpp, src/analyzer/CheckpointTime.h, src/core/ResourceBudget.cpp, tests/CompilationDatabaseCliTest.py, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/quality_protocol.md, src/core/DarwinMemoryBudget.h, src/core/ResourceBudget.h, tests/ResourceBudgetTest.cpp, docs/usage.md
**Bağımlılıklar:** Yok

## CH07 — Teslim ve kapanış

### CH07-S01 — Release adayı

#### CS3-CH07-S01-U001 — Release adayını kullanıcı iş akışlarıyla kabul et

**Sonuç:** Kurulum, ilk tarama, CI, triage ve destek belgeleri aynı ürünü anlatır.

**Kabul:**

- Kabul matrisi her teslim sözü için exact source/artifact ve PASS kanıtı gösterir.
- Açık blocker, eksik platform veya karşılanmayan kalite hedefi gizlenmez.
- Main merge/release gerekiyorsa exact aday için ayrı kullanıcı yetkisi alınır.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** docs/release-checklist.md, docs/usage.md, docs/first-scan.md, README.md, RELEASE_NOTES.md
**Bağımlılıklar:** Yok

#### CS3-CH07-S01-U002 — Yetkili teslimi ve son FIFO kapanışını doğrula

**Sonuç:** Tüm kabul edilmiş işler PROGRESS'te bulunur; TODO terminal boş duruma geçer.

**Kabul:**

- Yetkili yayın veya yalnız yerel teslim ayrımı açıkça kayıtlıdır; main izinsiz değiştirilmez.
- Görev/commit/bağımsız review kanıtları korunur; TODO'da sahte DONE/gizli yan kuyruk bulunmaz.
- Eksik required dış eylem varsa iş kapanmaz; tamamlandı denilerek kuyruk boşaltılmaz.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** docs/release-checklist.md, RELEASE_NOTES.md
**Bağımlılıklar:** CS3-CH07-S01-U001

## CH08 — Ürün bitiş sözleşmesi ve sonuçtan önce dondurulan ölçüm

### CH08-S01 — Yeni planın tek gerçek kaynağı ve kabul kapıları

#### CS3-CH08-S01-U001 — Yeni ürün planını ve bitiş sözleşmesini FIFO'ya bağla

**Sonuç:** Yeni ürün planı ayrı dosyadadır; eski 46 kayıt değişmeden kalır ve ürün tamamlanmasının teknik/yayın koşulları açıkça tanımlanır.

**Kabul:**

- docs/PRODUCT_COMPLETION_PLAN.md yalnız CH08+ ürün hedeflerini anlatır; tek yürütülebilir kuyruk BOOK/PLAN/TODO/PROGRESS'tir. Görev ID/kapsam/kabul eşleşmesi otomatik test edilir; ikinci elle tutulan TODO oluşturulmaz.
- Önceki PLAN'ın 4fd4a21 exact içeriği tarihsel arşiv dosyasında korunur. Eski tamamlanmış kayıtlar ve kanıtlar byte/eşitlik denetiminden geçer; önceki yerel bitiş bir yayın başarısı olarak yeniden adlandırılmaz.
- Sahibin piyasa açısından değerli CWE ekleme isteğiyle hedef mevcut 12 + yeni 4 CWE ailesi olmak üzere 16 supported/blocking ailedir; eski 5 experimental terfi ve yeni format-string/CWE-134, command-injection/CWE-78, sql-injection/CWE-89, path-traversal/CWE-22 aileleri zorunludur. Bounds ayrıca CWE-121/122 proven write alt türlerini ekler; toplam 19 public diagnostic/26 CWE-ID yalnız sınırları kanıtlanmış destek iddiasıdır. Üç project diagnostic report-only kalır; sınırsız taint/race/IDE/cloud kapsam dışıdır.
- G1–G8 bitiş kapıları, sınırlı OS/SDK profilleri, yeni kalite eşikleri ve gerçek yayın zorunluluğu sonuçlardan önce kaydedilir. Main/tag/yayın/imza için plan onayı işlem yetkisi sayılmaz; eksik dış onay sonlandırmayı engeller.
- 2025 MITRE Top 25/Top 10 KEV ve resmi CWE-134 gerekçesi kaynaklı piyasa-priority matrisi docs/market-cwe-priorities.md'de yer alır; bu öncelik vekilidir, satış/sertifika veya bütün Top25 kapsamı iddiası değildir.
- Sekiz dosyalık aktivasyonun değiştirdiği tests/test_project_queue.py için exact eski/yeni kaynak farkına bağlı prospective inventory/catalog successor, eski snapshot/receipt silinmeden bağımsız doğrulanır. İlk normal görev bitiminde eski cwe_quality integrity de yeniden geçer; bu bir kalite eşiği/pin gevşetmesi değildir.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T0
**Kontroller:** plan-contract, queue-check
**Kapsam:** docs/PRODUCT_COMPLETION_PLAN.md, docs/product-quality-contract.md, docs/archive/CWE_RESTART_PLAN_2026-09-08.md, scripts/product_completion_plan.py, scripts/test_product_completion_plan.py, README.md, RELEASE_NOTES.md, docs/release-checklist.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/market-cwe-priorities.md, docs/CWE_SCOPE.md
**Bağımlılıklar:** CS3-CH07-S01-U002

#### CS3-CH08-S01-U002 — Katalog ve capability sözleşmesini eklemeli kanıt sürümlerine hazırla

**Sonuç:** Yeni aile/test/tier eklenebilir, ama eski korpus ve kalite kanıtı sessizce yeniden yazılamaz.

**Kabul:**

- Mevcut 15 capability, 12 CWE ailesi, 52 fixture ve kayıtlı input/label/threshold snapshot'ı sürümlü exact digest ile korunur. Eski receipts özgün sözleşmelerinde doğrulanabilir; yeni aileleri kapsıyor diye yeniden etiketlenmez.
- scripts/cwe_quality.py ve check_capabilities_sync içindeki sabit 15 ile test_catalog sabit sayıları yalnız reviewed katalog sürümündeki exact registry/input setine bağlanır. Gelişigüzel aile/fixture/tier ekleme veya eksiltme kabul edilmez; aynı-name fake/duplicate/missing/ghost kayıt negatifleri ret alır.
- Her ileriki scope içi test/registry/tier değişikliği source-derived bağımsız sınıflandırmalı prospective successor gerektirir; bütün eski daha sıkı profile floors ve eski fixture assertions korunur. Yeni büyük corpus, eski baseline/corpus beklentilerinin yerine geçmez.
- Bu görev yeni kuralı varmış gibi kaydetmez: installed capabilities sayısı gerçekten mevcut olandır, planned target ayrıdır. Eski v1 negatifleri, yeni sürüm migration RED/GREEN ve gerçek CLI capability parity geçer.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** scripts/cwe_quality.py, scripts/check_capabilities_sync.py, tests/cwe_corpus/test_catalog.py, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, tests/cwe_corpus/snapshots/terminal-4fd4a21-catalog.json, tests/cwe_corpus/snapshots/terminal-4fd4a21-inventory.json, tests/cwe_corpus/snapshots/terminal-4fd4a21-contract.json, docs/product-quality-contract.md, docs/CWE_SCOPE.md
**Bağımlılıklar:** CS3-CH08-S01-U001

#### CS3-CH08-S01-U003 — Gerçek proje girdilerini ve geniş kalite korpusunu önceden dondur

**Sonuç:** Bilinen kusurlar ile bağımsız değerlendirme girdileri ayrılır; payda ve eşikler sonuç görüldükten sonra değiştirilemez.

**Kabul:**

- cJSON 1.7.18, tinyxml2 10.0.0 ve GoogleTest 1.14.0 kaynakları/build seçenekleri/hedefleri/hashleri ayrı manifestlere bağlanır; library/test/example/generator yüzeyleri açıkça ayrılır.
- c4fa60864f2e5853581c2f8a0dd66a3fc967239b ölçümündeki 47 kanıtlı FP, 10 belirsiz ve 9 TP occurrence kimliği/multiplicity/kanıt kaynağı korunur; cJSON 54 occurrence/53 fingerprint ayrımı kaybolmaz.
- Hedef 16 CWE ailesinin her biri için >=30 bağımsız buggy + >=30 safe değerlendirme örneği dondurulur. Bounds içinde CWE-121 ve CWE-122 altprofilleri ayrı ayrı >=30 buggy + >=30 safe içerir; toplam en az 1020 benzersiz kaynak örneği vardır. Her aile/altprofil en az üç bağımsız köken taşır; yakın kopyalar bağımsız sayılmaz. Unknown/unsupported sınırlar, komut/hash/ground truth gerekçeleri sonuçlardan önce kaydedilir.
- Bilinen FP eğitim örnekleri değerlendirme paydasına gizlice eklenmez. Bağımsız hakem etiketleri ve örnek seçim kaydı vardır; üretici körlüğü veya pazar temsiliyeti kanıtsız iddia edilmez.
- Her ailede yeni profilde precision >=0.90, addressable recall >=0.70 ve deterministik safe FP=0 kapısı test edilir; daha sıkı mevcut profil eşikleri aynen korunur. En az üç tekrar ve sonuçlardan önce sabit sonlu performans bütçeleri manifestte yer alır.
- Dört yeni injection ailesinin native API/source/sink/sanitizer modelleri ve bounded TU-local flow yüzeyi dondurulur. Değerlendirme her yeni ailede kaynak-atıflı gerçek proje security-fix çiftleri ile ayrı safe kontroller içerir; SQL ilk profilinin SQLite API sözleşmesi açıkça sınırlıdır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** scripts/product_profiles.py, scripts/product_profiles.json, scripts/test_product_profiles.py, docs/product-quality-contract.md, scripts/product_quality.py, scripts/test_product_quality.py, tests/product_corpus/**, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, .github/workflows/product-identity.yml, scripts/product_identity.py, scripts/test_product_identity.py
**Bağımlılıklar:** CS3-CH08-S01-U002

#### CS3-CH08-S01-U004 — Temiz Release profilinde yeni exact-source RED başlangıcını ölç

**Sonuç:** Yeni işin başlangıç durumu tek gerçek kaynak ve build profiline bağlıdır; eski rakamlar güncelmiş gibi kullanılmaz.

**Kabul:**

- Temiz çalışma ağacından Release build alınır; source/tree/toolchain/flags/platform/binary/input hashes ile bütün özgün ham sonuçlar kaydedilir. Eski development cache yeni clean Release kanıtı sayılmaz.
- Bilinen FP/unknown/TP seti, yeni değerlendirme korpusu ve üç gerçek proje manifesti çalıştırılır; bugün başarısız olan ürün kapıları ayrı RED olarak görünür. Bu görev ölçüm altyapısını kabul eder, ürün kalitesine PASS vermez.
- Yeni ölçüm bu planın kapsamını veya dondurulmuş eşikleri değiştirmez; reproducer, atanmış ileriki görev ve çözülmemiş farklar açık kayda girer.
- Mevcut Linux suite, korumalı korpuslar ve başarısız çıktı/timeout kontrolleri başlangıç snapshot'ına bağlanır; payda azaltma, suppression/baseline ile sonuç temizleme yoktur.
- Henüz kurulmamış dört aile initial baseline'da PLANNED_NOT_IMPLEMENTED/RED'dir; sahte zero-finding PASS veya unknown CLI option ile gerçek analiz yapılmış gibi raporlanmaz. İlk yeni ürün ölçümüyle frozen profil değişmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** scripts/measure_product.py, scripts/test_measure_product.py, scripts/product_profiles.py, scripts/product_quality.py, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH08-S01-U003

## CH09 — Gerçek derleme girdileri ve tam analiz kapsamı

### CH09-S01 — İnferred benchmark ile gerçek build yüzeyini ayır

#### CS3-CH09-S01-U001 — cJSON gerçek build profilini ve 42 eski hatalı girdiyi uzlaştır

**Sonuç:** Seçilmiş gerçek upstream hedeflerinin tamamı doğru compilation commands ile analiz edilebilir.

**Kabul:**

- Eski 76-TU inferred profil değiştirilmeden ayrı tarihsel lane olarak kalır. 29 unity.h, 6 unity_fixture.h, 3 ProductionCode.h, 3 ProductionCode2.h ve bir AFL macro profil hatası kaynak yoluna kadar sınıflandırılır; bunlar 42 analyzer crash diye sunulmaz.
- Upstream'in gerçekten build ettiği hedefler ve gerekli include/define/generated inputs gerçek build üzerinden alınır. Generator örneklerini sahte komutla derlenebilir göstermek veya sırf 76/76 için hedef uydurmak yasaktır.
- Önceden seçilmiş gerçek hedeflerin %100 komut varyantı analiz edilir; failed/skipped/recovery TU ve incomplete function sıfırdır. Yanlış/missing input negatifleri exit2 kalır.
- İlave analyzer arızası açığa çıkarsa exact RED ve source-derived regresyonla giderilir; gerçek hedef kapsamını düşürerek bu görev kapatılamaz.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** scripts/product_profiles.py, scripts/product_profiles.json, scripts/test_product_profiles.py, docs/product-quality-contract.md, scripts/corpus_compile_commands.cpp, scripts/run_corpus.sh, scripts/measure_product.py, scripts/test_measure_product.py, src/source_manager/CompilationDatabaseDiscovery.cpp, src/source_manager/CompilationDatabaseDiscovery.h, tests/CompilationDatabaseCliTest.py, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH08-S01-U004

#### CS3-CH09-S01-U002 — GoogleTest ve tinyxml2 gerçek hedef profillerini tamamla

**Sonuç:** Library, test ve örnek hedeflerinin hangilerinin desteklendiği build kaynaklı ve ölçülmüş bir yüzeydir.

**Kabul:**

- GoogleTest'in önceki dört library entry TU ölçümü full upstream test kapsamı diye kullanılmaz; seçilmiş upstream library/test/example hedefleri ayrı manifestte gerçek build komutlarıyla bağlıdır.
- tinyxml2'nin üç-TU eski profili korunur; yeni seçilmiş hedefler gerçek build seçenekleri ve veri dosyalarıyla açıklanır.
- Her seçilmiş hedefte %100 command-variant coverage, sıfır failed/skipped/recovery TU ve sıfır incomplete function gerekir; yok sayılan veya seçilmemiş yüzeyler paydadan sonuç sonrası çıkarılamaz.
- Yanlış dosya/komut eşlemesi, eksik generated header ve geçersiz define negatifleri temiz rapora dönüşmez.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** scripts/product_profiles.py, scripts/product_profiles.json, scripts/test_product_profiles.py, docs/product-quality-contract.md, scripts/measure_product.py, scripts/test_measure_product.py, tests/CompilationDatabaseCliTest.py, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH09-S01-U001

#### CS3-CH09-S01-U003 — Kapsam kapısını CI'da fail-closed hale getir

**Sonuç:** Bir proje kısmen analiz edildiğinde ürün kabulü veya CI yeşil görünmez.

**Kabul:**

- Yeni gerçek build lane'i coverage.complete=true ve bütün requested/attempted/analyzed/variant sayımlarının eşitliğini zorunlu tutar; partial-accepted top-level complete bu lane'de PASS olamaz.
- Analyzer crash/timeout/boş veya stale çıktı, kayıp job/artifact, iç test SKIP'i ve wrapper exit0 negatifleri kapıyı gerçekten düşürür.
- Eski inferred cJSON ve tez korpuslarının mevcut pinleri/failure kayıtları korunur; yeni sıkı lane eski zayıf wrapper'ın yerine başarı kanıtı ödünç almaz.
- Bağımsız exact-head denetçi ham komut/rapor/exit ve başarısız kontrol örneklerini doğrular.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** scripts/product_profiles.py, scripts/test_product_profiles.py, scripts/measure_product.py, scripts/test_measure_product.py, .github/workflows/ci.yml, tests/WorkflowPolicyTest.py, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/CI_GATES.md, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH09-S01-U002

## CH10 — Kanıtlı yanlış alarmları semantik olarak gider

### CH10-S01 — Sahiplik ve predicate kanıtını kaybetme

#### CS3-CH10-S01-U001 — GoogleTest shared_ptr ve FILE-factory sahiplik yanlış alarmlarını gider

**Sonuç:** Kanıtlı local sahiplik ve caller tarafından kapatılan dönen kaynaklar doğru izlenir.

**Kabul:**

- İki gerçek GoogleTest FP, orijinal exact source ve küçültülmüş regresyonda RED olarak tekrar üretilir; yeni analyzer üzerinde gerçek source raporundan kalkar.
- shared_ptr adoption/retention, dönüşle ownership aktarımı ve caller close kanıtı gerçek kontrol/veri akışından gelir; ad bazlı blanket escape/consume yoktur.
- Kaybolan sahiplik, son owner'ın gitmesi, hatalı allocator/free, dönen ama sahiplenilmeyen kaynak ve gerçek aynı-fonksiyon sızıntıları raporlanmaya devam eder.
- Mevcut test gövdeleri/floors korunur; yalnız gerekli yeni test digestleri ayrı prospective incelemeyle güncellenir.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/MemoryLeakRule_Ex.cpp, src/engine/AllocFunctions.h, src/engine/AllocFunctions.cpp, src/engine/FunctionSummary.h, src/engine/FunctionSummary.cpp, tests/MemoryLeakRuleExTest.cpp, tests/InterproceduralTest.cpp, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH09-S01-U003

#### CS3-CH10-S01-U002 — Boolean alias ve nullable predicate implication yanlış alarmlarını gider

**Sonuç:** Değişmemiş predicate ile korunan pointer kullanımı kanıtlanır, invalidation kanıtı bozamaz.

**Kabul:**

- Bir GoogleTest ve beş cJSON kanıtlı FP için source-derived RED/GREEN ve safe/buggy eşleri vardır.
- const bool found = p != nullptr ve eşdeğer dondurulmuş predicate/alias ilişkileri dominance altında kullanılır; pointer/alias/predicate mutasyonu kanıtı iptal eder.
- Yanlış alias, farklı pointer, değişen bool, non-dominating guard ve gerçek null branch negatifleri korunur; kaynak/dizin adına suppression eklenmez.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/NullDerefRule.cpp, src/engine/FunctionSummary.h, src/engine/FunctionSummary.cpp, src/engine/PathFacts.h, src/engine/PathFacts.cpp, src/engine/ConditionWalk.h, tests/NullDerefRuleTest.cpp, tests/InterproceduralTest.cpp, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH10-S01-U001

### CH10-S02 — Assertion, ilişki ve tip kanıtı

#### CS3-CH10-S02-U001 — Unity assertion ve nonlocal-abort modelini dar kanıtla düzelt

**Sonuç:** 29 kanıtlı assertion/nonlocal-exit kaynaklı yanlış alarm giderilir.

**Kabul:**

- 29 frozen FP occurrence gerçek kaynakta ve dar regresyonda takip edilir; assertion terminating semantiği kaynak/model kanıtına dayanır.
- Geri dönebilen assert/log handler, yanlış macro, NDEBUG modu, setjmp/longjmp sınırları ve invalidated pointer için gerçek tehlikeler gizlenmez.
- Genel assert-name güveni, tüm Unity yollarını hariç tutma, baseline/suppression veya diagnostic tier düşürme PASS yöntemi olamaz.
- Mevcut gerçek TP seti, güvenli ve kötü karşı örnekler ve frozen değerlendirici değişmeden GREEN gerekir.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/NullDerefRule.cpp, src/engine/FunctionSummary.h, src/engine/FunctionSummary.cpp, src/engine/PathFacts.h, src/engine/PathFacts.cpp, src/engine/ConditionWalk.h, tests/NullDerefRuleTest.cpp, tests/InterproceduralTest.cpp, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, src/engine/AssertGuards.h, src/engine/AssertGuards.cpp, src/engine/FatalCalls.h, src/engine/FatalCalls.cpp, src/engine/DataflowEngine.h, tests/FatalCallsTest.cpp
**Bağımlılıklar:** CS3-CH10-S01-U002

#### CS3-CH10-S02-U002 — cJSON head/tail ilişki invariantını kanıtlı tut

**Sonuç:** Üç paired linked-list invariant FP'si yanlış branchleri bastırmadan giderilir.

**Kabul:**

- Üç FP için source-bound RED/GREEN; ilişki yalnız aynı kanıtlı durumdan ve uygun dominance'tan çıkarılır.
- Bozuk head/tail eşleşmesi, bağımsız mutation, alias invalidation, join/loop ve gerçek null erişimi için paired negative örnekler geçer.
- Closing-brace suppression, list/field ismi özel-casing veya tüm pointer'ları güvenli varsayma yoktur.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/NullDerefRule.cpp, src/engine/FunctionSummary.h, src/engine/FunctionSummary.cpp, src/engine/PathFacts.h, src/engine/PathFacts.cpp, src/engine/ConditionWalk.h, tests/NullDerefRuleTest.cpp, tests/InterproceduralTest.cpp, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, src/engine/GuardedDisjuncts.h, src/engine/DataflowEngine.h, tests/DisjunctsV2bTest.cpp
**Bağımlılıklar:** CS3-CH10-S02-U001

#### CS3-CH10-S02-U003 — Caller-established nonnull helper kanıtını doğru aktar

**Sonuç:** İki cJSON helper/parser FP'si doğru call-context ile ayrılır.

**Kabul:**

- İki source-derived FP RED/GREEN; yalnız kanıtlı caller koşulu ilgili formal/actual binding'e aktarılır.
- İkinci güvenli olmayan caller, recursive/unknown body, mutation, wrong argument index ve nullable return negatifleri korunur; bir caller'ın koşulu bütün caller'lara taşınmaz.
- Interprocedural caching ve summary yeniden kullanımı farklı bağlamlar arasında sahte nonnull üretmez.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/NullDerefRule.cpp, src/engine/FunctionSummary.h, src/engine/FunctionSummary.cpp, src/engine/PathFacts.h, src/engine/PathFacts.cpp, src/engine/ConditionWalk.h, tests/NullDerefRuleTest.cpp, tests/InterproceduralTest.cpp, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH10-S02-U002

#### CS3-CH10-S02-U004 — tinyxml2 literal XML ve node-type çıkarım sınırlarını düzelt

**Sonuç:** Beş kanıtlı literal XML/node-type yanlış alarmı kaynak kanıtıyla giderilir.

**Kabul:**

- Beş frozen FP için exact RED, küçültülmüş safe/buggy eşler ve gerçek kaynakta GREEN gerekir.
- Bilinen literal içeriğin type/provenance ilişkisi yalnız doğrulanabilir kapsamda kullanılır; arbitrary runtime XML, parse failure, nullable cast ve I/O başarı varsayımı kapsam dışına sessizce geçirilmez.
- Genel ToElement/ToText vb. cast'leri koşulsuz nonnull saymak veya kütüphane/dosya adına bastırmak yasaktır; yanlış tip/bozuk XML/eksik dosya karşı örnekleri raporlanır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/NullDerefRule.cpp, src/engine/FunctionSummary.h, src/engine/FunctionSummary.cpp, src/engine/PathFacts.h, src/engine/PathFacts.cpp, src/engine/ConditionWalk.h, tests/NullDerefRuleTest.cpp, tests/InterproceduralTest.cpp, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, src/engine/AllocFunctions.h, src/engine/AllocFunctions.cpp, tests/ContractTest.cpp, CONTRACTS.md
**Bağımlılıklar:** CS3-CH10-S02-U003

### CH10-S03 — Belirsizlikleri kaynak kanıtına bağla

#### CS3-CH10-S03-U001 — On eski belirsiz occurrence'ı bağımsız ground truth ile çöz

**Sonuç:** Eski on belirsiz bulgunun her biri doğru diagnostic davranışına bağlı kapatılmış bir inceleme kaydıdır.

**Kabul:**

- Altı cJSON ve dört tinyxml2 belirsiz occurrence için kaynak/çağrı/veri/IO önkoşulları ve karşı örnekler incelenir; gerekirse kontrollü repro ile TP veya FP kararı bağımsız olarak kanıtlanır.
- FP ise dar analyzer düzeltmesi ve negatif eşleri gerekir; TP ise gerçek bug davranışı korunur. Unknown'ı safe/TP diye yalnız yeniden etiketlemek veya bool/IO başarı varsayımı eklemek yasaktır.
- Gerçekten çözülemeyen zorunlu-scope belirsizlik FRONT'u bloke eder; bu görevin PASS koşulu 'belirsizlik raporu yazıldı' değildir.
- Önceki 47 FP düzeltmesi ve 9 kanıtlı TP occurrence/multiplicity korunur; yeni bulgular da adjudication dışında bırakılmaz.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/NullDerefRule.cpp, src/engine/FunctionSummary.h, src/engine/FunctionSummary.cpp, src/engine/PathFacts.h, src/engine/PathFacts.cpp, src/engine/ConditionWalk.h, tests/NullDerefRuleTest.cpp, tests/InterproceduralTest.cpp, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, src/rules/MemoryLeakRule_Ex.cpp, src/engine/AllocFunctions.h, src/engine/AllocFunctions.cpp, tests/MemoryLeakRuleExTest.cpp, src/engine/AssertGuards.h, src/engine/AssertGuards.cpp, tests/ContractTest.cpp, docs/product-quality-adjudication.md
**Bağımlılıklar:** CS3-CH10-S02-U004

## CH11 — On altı CWE ailesi ve altı yeni CWE için kanıtlı ürün kalitesi

### CH11-S01 — Mevcut supported ailelerin genişletilmiş kalite kapısı

#### CS3-CH11-S01-U001 — memory-leak geniş korpus kalite kapısını kapat

**Sonuç:** memory-leak dondurulmuş değerlendirmede yeni ürün eşiğini ve eski korumaları birlikte sağlar.

**Kabul:**

- Mevcut CWE-401/772/775 public eşlemesi korunur: malloc/new, pointer-owned FILE/DIR, alias, escape ve eşleşmiş sahiplik; gerçek sızıntılar korunur.
- En az 30 bağımsız buggy + 30 safe frozen örnekte precision >=0.90, addressable recall >=0.70 ve deterministik safe FP=0; daha sıkı eski profil kapıları ayrıca geçer.
- Eşik başarısızsa exact RED, sınırlı semantik düzeltme, paired safe/dangerous regresyon ve GREEN gerekir. Holdout/etiket/pin/payda/runner sonucu gizlemek için değiştirilmez.
- Focused rule testleri, bütün Linux suite ve ilgili korpus üç tekrar exact source/binary/input kimlikleriyle geçer; unsupported sınırlar görünür kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/MemoryLeakRule_Ex.cpp, src/rules/MemoryLeakRule_Ex.h, tests/MemoryLeakRuleExTest.cpp, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH10-S03-U001

#### CS3-CH11-S01-U002 — double-free geniş korpus kalite kapısını kapat

**Sonuç:** double-free dondurulmuş değerlendirmede yeni ürün eşiğini ve eski korumaları birlikte sağlar.

**Kabul:**

- Mevcut CWE-415/675 public eşlemesi korunur: aynı allocation/resource identity, alias, path ayrımı ve belirsiz ownership; farklı allocationlar çifte release sayılmaz.
- En az 30 bağımsız buggy + 30 safe frozen örnekte precision >=0.90, addressable recall >=0.70 ve deterministik safe FP=0; daha sıkı eski profil kapıları ayrıca geçer.
- Eşik başarısızsa exact RED, sınırlı semantik düzeltme, paired safe/dangerous regresyon ve GREEN gerekir. Holdout/etiket/pin/payda/runner sonucu gizlemek için değiştirilmez.
- Focused rule testleri, bütün Linux suite ve ilgili korpus üç tekrar exact source/binary/input kimlikleriyle geçer; unsupported sınırlar görünür kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/MemoryLeakRule_Ex.cpp, src/rules/MemoryLeakRule_Ex.h, tests/MemoryLeakRuleExTest.cpp, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S01-U001

#### CS3-CH11-S01-U003 — use-after-free geniş korpus kalite kapısını kapat

**Sonuç:** use-after-free dondurulmuş değerlendirmede yeni ürün eşiğini ve eski korumaları birlikte sağlar.

**Kabul:**

- Mevcut CWE-416/672 public eşlemesi korunur: yaşam süresi, alias, yeniden atama/allocation ve release sonrası gerçek use; yeni güvenli nesne alarm üretmez.
- En az 30 bağımsız buggy + 30 safe frozen örnekte precision >=0.90, addressable recall >=0.70 ve deterministik safe FP=0; daha sıkı eski profil kapıları ayrıca geçer.
- Eşik başarısızsa exact RED, sınırlı semantik düzeltme, paired safe/dangerous regresyon ve GREEN gerekir. Holdout/etiket/pin/payda/runner sonucu gizlemek için değiştirilmez.
- Focused rule testleri, bütün Linux suite ve ilgili korpus üç tekrar exact source/binary/input kimlikleriyle geçer; unsupported sınırlar görünür kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/MemoryLeakRule_Ex.cpp, src/rules/MemoryLeakRule_Ex.h, tests/MemoryLeakRuleExTest.cpp, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S01-U002

#### CS3-CH11-S01-U004 — resource-leak geniş korpus kalite kapısını kapat

**Sonuç:** resource-leak dondurulmuş değerlendirmede yeni ürün eşiğini ve eski korumaları birlikte sağlar.

**Kabul:**

- resource-leak'ın mevcut public CWE eşlemesi korunur; fd/DIR, RAII ve başarıya bağlı ownership transfer test edilir. Pointer-owned FILE/DIR yolu memory-leak ile tutarlı kalır; başarısız aktarım ve eksik destructor-close gerçek leak olarak korunur.
- En az 30 bağımsız buggy + 30 safe frozen örnekte precision >=0.90, addressable recall >=0.70 ve deterministik safe FP=0; daha sıkı eski profil kapıları ayrıca geçer.
- Eşik başarısızsa exact RED, sınırlı semantik düzeltme, paired safe/dangerous regresyon ve GREEN gerekir. Holdout/etiket/pin/payda/runner sonucu gizlemek için değiştirilmez.
- Focused rule testleri, bütün Linux suite ve ilgili korpus üç tekrar exact source/binary/input kimlikleriyle geçer; unsupported sınırlar görünür kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/FdResourceRule.cpp, src/rules/FdResourceRule.h, tests/FdResourceRuleTest.cpp, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S01-U003

#### CS3-CH11-S01-U005 — div-by-zero geniş korpus kalite kapısını kapat

**Sonuç:** div-by-zero dondurulmuş değerlendirmede yeni ürün eşiğini ve eski korumaları birlikte sağlar.

**Kabul:**

- CWE-369: integer/floating profile ayrımı, path guard, alias ve type sınırları; nonzero kanıtı ve gerçek sıfır birlikte test edilir.
- En az 30 bağımsız buggy + 30 safe frozen örnekte precision >=0.90, addressable recall >=0.70 ve deterministik safe FP=0; daha sıkı eski profil kapıları ayrıca geçer.
- Eşik başarısızsa exact RED, sınırlı semantik düzeltme, paired safe/dangerous regresyon ve GREEN gerekir. Holdout/etiket/pin/payda/runner sonucu gizlemek için değiştirilmez.
- Focused rule testleri, bütün Linux suite ve ilgili korpus üç tekrar exact source/binary/input kimlikleriyle geçer; unsupported sınırlar görünür kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/DivByZeroRule.cpp, src/rules/DivByZeroRule.h, tests/DivByZeroRuleTest.cpp, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S01-U004

#### CS3-CH11-S01-U006 — null-deref geniş korpus kalite kapısını kapat

**Sonuç:** null-deref dondurulmuş değerlendirmede yeni ürün eşiğini ve eski korumaları birlikte sağlar.

**Kabul:**

- CWE-476: nullable flow, alias, guard, helper ve call-site kanıtı; kanıtsız nonnull varsayımı yoktur.
- En az 30 bağımsız buggy + 30 safe frozen örnekte precision >=0.90, addressable recall >=0.70 ve deterministik safe FP=0; daha sıkı eski profil kapıları ayrıca geçer.
- Eşik başarısızsa exact RED, sınırlı semantik düzeltme, paired safe/dangerous regresyon ve GREEN gerekir. Holdout/etiket/pin/payda/runner sonucu gizlemek için değiştirilmez.
- Focused rule testleri, bütün Linux suite ve ilgili korpus üç tekrar exact source/binary/input kimlikleriyle geçer; unsupported sınırlar görünür kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/NullDerefRule.cpp, src/rules/NullDerefRule.h, tests/NullDerefRuleTest.cpp, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S01-U005

#### CS3-CH11-S01-U007 — int-overflow geniş korpus kalite kapısını kapat

**Sonuç:** int-overflow dondurulmuş değerlendirmede yeni ürün eşiğini ve eski korumaları birlikte sağlar.

**Kabul:**

- Mevcut CWE-190/191/681 public eşlemesi korunur: signedness, promotion, type width, overflow/underflow/conversion ve guard sınırları; host genişliği target genişliğinin yerine geçmez.
- En az 30 bağımsız buggy + 30 safe frozen örnekte precision >=0.90, addressable recall >=0.70 ve deterministik safe FP=0; daha sıkı eski profil kapıları ayrıca geçer.
- Eşik başarısızsa exact RED, sınırlı semantik düzeltme, paired safe/dangerous regresyon ve GREEN gerekir. Holdout/etiket/pin/payda/runner sonucu gizlemek için değiştirilmez.
- Focused rule testleri, bütün Linux suite ve ilgili korpus üç tekrar exact source/binary/input kimlikleriyle geçer; unsupported sınırlar görünür kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/IntOverflowRule.cpp, src/rules/IntOverflowRule.h, tests/IntOverflowRuleTest.cpp, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S01-U006

### CH11-S02 — Experimental CWE ailelerini kanıtlı supported düzeye terfi ettir

#### CS3-CH11-S02-U001 — uninit-ptr için production terfisini kanıtla

**Sonuç:** uninit-ptr experimental'dan supported/blocking'e yalnız kanıtlı yeni sözleşmeyle geçer.

**Kabul:**

- Mevcut CWE-824 public eşlemesi korunur: pointer initialization, path birleşimi, alias ve güvenli varsayılan initialization.
- Önce dondurulmuş >=30 buggy + >=30 safe örnekte precision >=0.90, addressable recall >=0.70, safe FP=0 ve eski daha sıkı kontroller sağlanır; exact RED/GREEN ve dangerous negatives zorunludur.
- Bağımsız semantik inceleme sonrası capability/tier, help/JSON/SARIF/policy davranışı ve belgeler tutarlı terfi edilir. Meşru ileriye dönük tier beklentisi değişikliği tarihsel kanıtı yeniden yazmaz.
- Report-only ve explicit policy opt-in uyumluluğu test edilir; yeni supported blocker'ın gerçek CLI exit davranışı doğrulanır. Sadece etiketi değiştirerek veya eski testleri gevşeterek PASS yoktur.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/UninitPointerRule_Ex.cpp, src/rules/UninitPointerRule_Ex.h, tests/UninitPointerRuleExTest.cpp, src/core/RuleCapabilities.def, docs/capabilities.md, README.md, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S01-U007

#### CS3-CH11-S02-U002 — uninit-scalar için production terfisini kanıtla

**Sonuç:** uninit-scalar experimental'dan supported/blocking'e yalnız kanıtlı yeni sözleşmeyle geçer.

**Kabul:**

- CWE-457: scalar read-before-write, path merge, out-param ve language initialization kuralları.
- Önce dondurulmuş >=30 buggy + >=30 safe örnekte precision >=0.90, addressable recall >=0.70, safe FP=0 ve eski daha sıkı kontroller sağlanır; exact RED/GREEN ve dangerous negatives zorunludur.
- Bağımsız semantik inceleme sonrası capability/tier, help/JSON/SARIF/policy davranışı ve belgeler tutarlı terfi edilir. Meşru ileriye dönük tier beklentisi değişikliği tarihsel kanıtı yeniden yazmaz.
- Report-only ve explicit policy opt-in uyumluluğu test edilir; yeni supported blocker'ın gerçek CLI exit davranışı doğrulanır. Sadece etiketi değiştirerek veya eski testleri gevşeterek PASS yoktur.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/UninitScalarRule.cpp, src/rules/UninitScalarRule.h, tests/UninitScalarRuleTest.cpp, src/core/RuleCapabilities.def, docs/capabilities.md, README.md, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S02-U001

#### CS3-CH11-S02-U003 — bounds için production terfisini kanıtla

**Sonuç:** bounds experimental'dan supported/blocking'e yalnız kanıtlı yeni sözleşmeyle geçer.

**Kabul:**

- Mevcut CWE-120/125/787/823 public eşlemesi korunur: read/write, array/heap extent, signed index, one-past address/dereference ve güvenli sentinel ayrımı. Daha sonraki ayrı görevler yalnız proven write/storage kanıtıyla CWE-121/122 ekler.
- Önce dondurulmuş >=30 buggy + >=30 safe örnekte precision >=0.90, addressable recall >=0.70, safe FP=0 ve eski daha sıkı kontroller sağlanır; exact RED/GREEN ve dangerous negatives zorunludur.
- Bağımsız semantik inceleme sonrası capability/tier, help/JSON/SARIF/policy davranışı ve belgeler tutarlı terfi edilir. Meşru ileriye dönük tier beklentisi değişikliği tarihsel kanıtı yeniden yazmaz.
- Report-only ve explicit policy opt-in uyumluluğu test edilir; yeni supported blocker'ın gerçek CLI exit davranışı doğrulanır. Sadece etiketi değiştirerek veya eski testleri gevşeterek PASS yoktur.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/BoundsRule.cpp, src/rules/BoundsRule.h, tests/BoundsRuleTest.cpp, src/core/RuleCapabilities.def, docs/capabilities.md, README.md, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S02-U002

#### CS3-CH11-S02-U004 — sign-conversion için production terfisini kanıtla

**Sonuç:** sign-conversion experimental'dan supported/blocking'e yalnız kanıtlı yeni sözleşmeyle geçer.

**Kabul:**

- Mevcut CWE-195/681 public eşlemesi korunur: hedef type genişliği, negatif kaynak, range guard ve value-preserving dönüşüm.
- Önce dondurulmuş >=30 buggy + >=30 safe örnekte precision >=0.90, addressable recall >=0.70, safe FP=0 ve eski daha sıkı kontroller sağlanır; exact RED/GREEN ve dangerous negatives zorunludur.
- Bağımsız semantik inceleme sonrası capability/tier, help/JSON/SARIF/policy davranışı ve belgeler tutarlı terfi edilir. Meşru ileriye dönük tier beklentisi değişikliği tarihsel kanıtı yeniden yazmaz.
- Report-only ve explicit policy opt-in uyumluluğu test edilir; yeni supported blocker'ın gerçek CLI exit davranışı doğrulanır. Sadece etiketi değiştirerek veya eski testleri gevşeterek PASS yoktur.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/SignConversionRule.cpp, src/rules/SignConversionRule.h, tests/SignConversionRuleTest.cpp, src/core/RuleCapabilities.def, docs/capabilities.md, README.md, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S02-U003

#### CS3-CH11-S02-U005 — alloc-size-overflow için production terfisini kanıtla

**Sonuç:** alloc-size-overflow experimental'dan supported/blocking'e yalnız kanıtlı yeni sözleşmeyle geçer.

**Kabul:**

- Mevcut CWE-131 public eşlemesi korunur: çarpım/toplam boyut taşması, calloc/sized allocation, doğru target width ve güvenli checked arithmetic; otomatik CWE-190 yeniden eşlemesi yapılmaz.
- Önce dondurulmuş >=30 buggy + >=30 safe örnekte precision >=0.90, addressable recall >=0.70, safe FP=0 ve eski daha sıkı kontroller sağlanır; exact RED/GREEN ve dangerous negatives zorunludur.
- Bağımsız semantik inceleme sonrası capability/tier, help/JSON/SARIF/policy davranışı ve belgeler tutarlı terfi edilir. Meşru ileriye dönük tier beklentisi değişikliği tarihsel kanıtı yeniden yazmaz.
- Report-only ve explicit policy opt-in uyumluluğu test edilir; yeni supported blocker'ın gerçek CLI exit davranışı doğrulanır. Sadece etiketi değiştirerek veya eski testleri gevşeterek PASS yoktur.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/AllocSizeOverflowRule.cpp, src/rules/AllocSizeOverflowRule.h, tests/AllocSizeOverflowRuleTest.cpp, src/core/RuleCapabilities.def, docs/capabilities.md, README.md, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/product_corpus/regressions/**, tests/CMakeLists.txt, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S02-U004

### CH11-S03 — Yeni sınırlı string-origin ve source-to-sink altyapısı

#### CS3-CH11-S03-U001 — Intraprocedural string-origin akışını ve API modellerini ekle

**Sonuç:** Yeni injection kuralları regex veya yalnız fonksiyon adına değil kanıtlanmış untrusted içerik akışına dayanabilir.

**Kabul:**

- Clang CFG üzerinden locals/assignment kill, join, alias, modeled copy/concatenation ve output-buffer mutation için yeni sonlu StringFlow domain'i uygulanır. Integer-origin/nullness mevcut alanları string taint kanıtı diye kullanılmaz.
- argv, getenv, stdin/file/network read gibi önceden adlandırılmış kaynaklar ve declaration/signature doğrulanmış native API'ler modellenir. Kullanıcı aynı isimli fake fonksiyon, unknown mutation, unsound generic sanitizer ve branch/loop kontrolleri yanlış güven üretmez.
- Bu aşama yalnız intraprocedural'dır; heap graph/arbitrary containers/fields, indirect/virtual calls ve whole-program/persisted string taint supported değildir. Sonlu convergence/budget aşımı görünür unsupported/incomplete sonucu verir, sahte trace üretmez.
- Source/propagation/sink location trace ve category-specific validation trust sözleşmesi JSON/SARIF/worker parity için tanımlanır; henüz yeni CWE kuralı installed/supported diye ilan edilmez. Focused negatifler, Linux suite ve eski bütün floors geçer.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/engine/StringFlow.h, src/engine/StringFlow.cpp, src/engine/DataflowEngine.h, src/engine/CfgCache.h, src/core/Diagnostic.h, src/CMakeLists.txt, tests/CMakeLists.txt, tests/StringFlowTest.cpp, docs/string-flow-contract.md, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S02-U005

#### CS3-CH11-S03-U002 — Bounded TU-local helper string özetlerini ekle

**Sonuç:** Seçilmiş doğrudan helper çağrıları için parametre/return/sink akışı sonlu ve provenance-aware'dir.

**Kabul:**

- Aynı TU içindeki doğrudan çağrılar için parameter/return/output-buffer/sink relations, önceden dondurulmuş call-depth/state/iteration bütçeleriyle taşınır; recursive/mutually-recursive/indirect/virtual/dış-TU sınırlar açıkça unsupported'dır.
- Summary bir callee'nin gerçek declaration/body/model kimliğine bağlıdır; call-site alias, branch ve sanitization context kaybolmaz. Eksik/unknown summary safe sayılmaz; cached ownership summary string taint olarak yorumlanmaz.
- Konumlu trace çağıran ve helper kaynak satırlarını ayırır. Aynı isimli farklı overload/declaration, changed body, caller mutation, trusted argument ve gerçek dangerous helper paired negatifleri geçer.
- Mevcut incremental/worker cache formatı bu ilk üründe persisted string summary iddiası kazanmaz. Tüm eski kural davranışları ve resource budget/failure kontrolleri korunur.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/engine/StringFlow.h, src/engine/StringFlow.cpp, src/engine/StringFlowSummary.h, src/engine/StringFlowSummary.cpp, src/engine/FunctionSummary.h, src/engine/FunctionSummary.cpp, src/CMakeLists.txt, tests/CMakeLists.txt, tests/StringFlowTest.cpp, tests/StringFlowSummaryTest.cpp, docs/string-flow-contract.md, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S03-U001

### CH11-S04 — Piyasa öncelikli dört yeni aile: önce experimental sonra kanıtlı terfi

#### CS3-CH11-S04-U001 — format-string / CWE-134 deneysel kuralını ekle

**Sonuç:** Externally-controlled format string bounded supported-input yüzeyinde gerçek source-to-sink kanıtıyla experimental/report-only üretilir.

**Kabul:**

- Declaration-validated printf/fprintf/snprintf ailesinde sadece format argümanına ulaşan proven untrusted içerik alarmdır; nonliteral tek başına yeterli değildir. Sabit format + %s input, trusted format, yanlış parametre indeksi ve fake API güvenli negatiflerdir.
- Yeni rule başlangıçta experimental/report-only ve quality-gated=false/blocks-verdict=false'dur. Gerçek capability/CLI/worker/report parity, exact CWE mapping, source/flow/sink trace ve pratik düzeltme açıklaması vardır; henüz production başarı iddiası yoktur.
- Önce yokluğu/dar bug için RED, sonra odaklı dangerous/safe/unknown/unsupported GREEN; yeni frozen >=30 buggy + >=30 safe profilin dürüst ölçümü kaydedilir. Bilinen eğitim örneğiyle bağımsız değerlendirme karıştırılmaz.
- Aile eklenince registry/catalog/inventory yalnız source-derived prospective successor olarak güncellenir; eski 12 aile/floors ve üç report-only project rule korunur. Linux suite ve aynı-build worker/output parity gerçekten geçer.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/FormatStringRule.h, src/rules/FormatStringRule.cpp, tests/FormatStringRuleTest.cpp, src/engine/StringFlow.h, src/engine/StringFlow.cpp, src/engine/StringFlowSummary.h, src/engine/StringFlowSummary.cpp, src/analyzer/BuiltinRules.h, src/core/RuleCapabilities.def, src/core/Capabilities.cpp, src/core/Diagnostic.h, src/CMakeLists.txt, tests/CMakeLists.txt, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/OutputParityCliTest.py, scripts/check_capabilities_sync.py, docs/capabilities.md, docs/CWE_SCOPE.md, docs/market-cwe-priorities.md, README.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, tests/product_corpus/regressions/**
**Bağımlılıklar:** CS3-CH11-S03-U002

#### CS3-CH11-S04-U002 — format-string / CWE-134 üretim kalite kapısını kapat

**Sonuç:** format-string ayrı bağımsız ölçümden sonra supported/blocking düzeye terfi eder.

**Kabul:**

- Önceki experimental SHA başlangıç adayıdır; eşikler geçmezse bu görevde dar düzeltme yapılarak yeni exact SHA üretilir ve eski RED korunur. Terfi öncesindeki güncel hâlâ-experimental adayda frozen >=30 buggy + >=30 safe, >=3 bağımsız kökenli profil üzerinde precision >=0.90, addressable recall >=0.70 ve safe FP=0 sağlanır; native API/flow/guard/unknown sınırları ayrıca ölçülür.
- Başarısızlıkta dar semantik RED/GREEN düzeltme ve safe/dangerous counterexample gerekir; payda/etiket/eşik/model trust veya baseline ile temizleme yoktur. Actual source-to-sink trace bağımsız denetlenir.
- Bağımsız ölçüm PASS'inden sonra yalnız prospective capability/tier/policy sözleşmesi supported/blocking'e terfi edilir; son değişmiş exact-head için yeniden bağımsız PASS gerekir. İlk deneysel sürümün kanıtı yeniden adlandırılmaz.
- Gerçek CLI findings/clean/incomplete/report-only ve policy exit davranışları, all-rule etkileşimi, worker/JSON/SARIF parity ve eski bütün quality floors geçer. Production eşiği sağlanamazsa görev/FIFO açık kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/FormatStringRule.h, src/rules/FormatStringRule.cpp, tests/FormatStringRuleTest.cpp, src/engine/StringFlow.h, src/engine/StringFlow.cpp, src/engine/StringFlowSummary.h, src/engine/StringFlowSummary.cpp, src/analyzer/BuiltinRules.h, src/core/RuleCapabilities.def, src/core/Capabilities.cpp, src/core/Diagnostic.h, src/CMakeLists.txt, tests/CMakeLists.txt, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/OutputParityCliTest.py, scripts/check_capabilities_sync.py, docs/capabilities.md, docs/CWE_SCOPE.md, docs/market-cwe-priorities.md, README.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, tests/product_corpus/regressions/**
**Bağımlılıklar:** CS3-CH11-S04-U001

#### CS3-CH11-S04-U003 — command-injection / CWE-78 deneysel kuralını ekle

**Sonuç:** OS command injection bounded supported-input yüzeyinde gerçek source-to-sink kanıtıyla experimental/report-only üretilir.

**Kabul:**

- Proven untrusted içerik system/popen ve açık desteklenen native shell-command API argümanına ulaşmalıdır. Sabit executable + ayrı argv otomatik shell injection değildir; genel quoting bütün platformlarda sanitizer sayılmaz. User-chosen executable ayrı tehdittir; bu bounded shell-string profilinin dışındaysa açıkça belirtilir.
- Yeni rule başlangıçta experimental/report-only ve quality-gated=false/blocks-verdict=false'dur. Gerçek capability/CLI/worker/report parity, exact CWE mapping, source/flow/sink trace ve pratik düzeltme açıklaması vardır; henüz production başarı iddiası yoktur.
- Önce yokluğu/dar bug için RED, sonra odaklı dangerous/safe/unknown/unsupported GREEN; yeni frozen >=30 buggy + >=30 safe profilin dürüst ölçümü kaydedilir. Bilinen eğitim örneğiyle bağımsız değerlendirme karıştırılmaz.
- Aile eklenince registry/catalog/inventory yalnız source-derived prospective successor olarak güncellenir; eski 12 aile/floors ve üç report-only project rule korunur. Linux suite ve aynı-build worker/output parity gerçekten geçer.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/CommandInjectionRule.h, src/rules/CommandInjectionRule.cpp, tests/CommandInjectionRuleTest.cpp, src/engine/StringFlow.h, src/engine/StringFlow.cpp, src/engine/StringFlowSummary.h, src/engine/StringFlowSummary.cpp, src/analyzer/BuiltinRules.h, src/core/RuleCapabilities.def, src/core/Capabilities.cpp, src/core/Diagnostic.h, src/CMakeLists.txt, tests/CMakeLists.txt, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/OutputParityCliTest.py, scripts/check_capabilities_sync.py, docs/capabilities.md, docs/CWE_SCOPE.md, docs/market-cwe-priorities.md, README.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, tests/product_corpus/regressions/**
**Bağımlılıklar:** CS3-CH11-S04-U002

#### CS3-CH11-S04-U004 — command-injection / CWE-78 üretim kalite kapısını kapat

**Sonuç:** command-injection ayrı bağımsız ölçümden sonra supported/blocking düzeye terfi eder.

**Kabul:**

- Önceki experimental SHA başlangıç adayıdır; eşikler geçmezse bu görevde dar düzeltme yapılarak yeni exact SHA üretilir ve eski RED korunur. Terfi öncesindeki güncel hâlâ-experimental adayda frozen >=30 buggy + >=30 safe, >=3 bağımsız kökenli profil üzerinde precision >=0.90, addressable recall >=0.70 ve safe FP=0 sağlanır; native API/flow/guard/unknown sınırları ayrıca ölçülür.
- Başarısızlıkta dar semantik RED/GREEN düzeltme ve safe/dangerous counterexample gerekir; payda/etiket/eşik/model trust veya baseline ile temizleme yoktur. Actual source-to-sink trace bağımsız denetlenir.
- Bağımsız ölçüm PASS'inden sonra yalnız prospective capability/tier/policy sözleşmesi supported/blocking'e terfi edilir; son değişmiş exact-head için yeniden bağımsız PASS gerekir. İlk deneysel sürümün kanıtı yeniden adlandırılmaz.
- Gerçek CLI findings/clean/incomplete/report-only ve policy exit davranışları, all-rule etkileşimi, worker/JSON/SARIF parity ve eski bütün quality floors geçer. Production eşiği sağlanamazsa görev/FIFO açık kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/CommandInjectionRule.h, src/rules/CommandInjectionRule.cpp, tests/CommandInjectionRuleTest.cpp, src/engine/StringFlow.h, src/engine/StringFlow.cpp, src/engine/StringFlowSummary.h, src/engine/StringFlowSummary.cpp, src/analyzer/BuiltinRules.h, src/core/RuleCapabilities.def, src/core/Capabilities.cpp, src/core/Diagnostic.h, src/CMakeLists.txt, tests/CMakeLists.txt, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/OutputParityCliTest.py, scripts/check_capabilities_sync.py, docs/capabilities.md, docs/CWE_SCOPE.md, docs/market-cwe-priorities.md, README.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, tests/product_corpus/regressions/**
**Bağımlılıklar:** CS3-CH11-S04-U003

#### CS3-CH11-S04-U005 — sql-injection / CWE-89 deneysel kuralını ekle

**Sonuç:** SQL injection bounded supported-input yüzeyinde gerçek source-to-sink kanıtıyla experimental/report-only üretilir.

**Kabul:**

- İlk native API profili SQLite SQL-text argümanlarıdır: sqlite3_exec ve sqlite3_prepare_v2/v3 için constructed SQL içindeki untrusted içeriği izle. Constant query + bind parametre güvenlidir; önceden concat edilmiş query prepare çağrısıyla temiz sayılmaz. Diğer DB/ORM kütüphaneleri supported diye ilan edilmez.
- Yeni rule başlangıçta experimental/report-only ve quality-gated=false/blocks-verdict=false'dur. Gerçek capability/CLI/worker/report parity, exact CWE mapping, source/flow/sink trace ve pratik düzeltme açıklaması vardır; henüz production başarı iddiası yoktur.
- Önce yokluğu/dar bug için RED, sonra odaklı dangerous/safe/unknown/unsupported GREEN; yeni frozen >=30 buggy + >=30 safe profilin dürüst ölçümü kaydedilir. Bilinen eğitim örneğiyle bağımsız değerlendirme karıştırılmaz.
- Aile eklenince registry/catalog/inventory yalnız source-derived prospective successor olarak güncellenir; eski 12 aile/floors ve üç report-only project rule korunur. Linux suite ve aynı-build worker/output parity gerçekten geçer.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/SqlInjectionRule.h, src/rules/SqlInjectionRule.cpp, tests/SqlInjectionRuleTest.cpp, src/engine/StringFlow.h, src/engine/StringFlow.cpp, src/engine/StringFlowSummary.h, src/engine/StringFlowSummary.cpp, src/analyzer/BuiltinRules.h, src/core/RuleCapabilities.def, src/core/Capabilities.cpp, src/core/Diagnostic.h, src/CMakeLists.txt, tests/CMakeLists.txt, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/OutputParityCliTest.py, scripts/check_capabilities_sync.py, docs/capabilities.md, docs/CWE_SCOPE.md, docs/market-cwe-priorities.md, README.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, tests/product_corpus/regressions/**
**Bağımlılıklar:** CS3-CH11-S04-U004

#### CS3-CH11-S04-U006 — sql-injection / CWE-89 üretim kalite kapısını kapat

**Sonuç:** sql-injection ayrı bağımsız ölçümden sonra supported/blocking düzeye terfi eder.

**Kabul:**

- Önceki experimental SHA başlangıç adayıdır; eşikler geçmezse bu görevde dar düzeltme yapılarak yeni exact SHA üretilir ve eski RED korunur. Terfi öncesindeki güncel hâlâ-experimental adayda frozen >=30 buggy + >=30 safe, >=3 bağımsız kökenli profil üzerinde precision >=0.90, addressable recall >=0.70 ve safe FP=0 sağlanır; native API/flow/guard/unknown sınırları ayrıca ölçülür.
- Başarısızlıkta dar semantik RED/GREEN düzeltme ve safe/dangerous counterexample gerekir; payda/etiket/eşik/model trust veya baseline ile temizleme yoktur. Actual source-to-sink trace bağımsız denetlenir.
- Bağımsız ölçüm PASS'inden sonra yalnız prospective capability/tier/policy sözleşmesi supported/blocking'e terfi edilir; son değişmiş exact-head için yeniden bağımsız PASS gerekir. İlk deneysel sürümün kanıtı yeniden adlandırılmaz.
- Gerçek CLI findings/clean/incomplete/report-only ve policy exit davranışları, all-rule etkileşimi, worker/JSON/SARIF parity ve eski bütün quality floors geçer. Production eşiği sağlanamazsa görev/FIFO açık kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/SqlInjectionRule.h, src/rules/SqlInjectionRule.cpp, tests/SqlInjectionRuleTest.cpp, src/engine/StringFlow.h, src/engine/StringFlow.cpp, src/engine/StringFlowSummary.h, src/engine/StringFlowSummary.cpp, src/analyzer/BuiltinRules.h, src/core/RuleCapabilities.def, src/core/Capabilities.cpp, src/core/Diagnostic.h, src/CMakeLists.txt, tests/CMakeLists.txt, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/OutputParityCliTest.py, scripts/check_capabilities_sync.py, docs/capabilities.md, docs/CWE_SCOPE.md, docs/market-cwe-priorities.md, README.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, tests/product_corpus/regressions/**
**Bağımlılıklar:** CS3-CH11-S04-U005

#### CS3-CH11-S04-U007 — path-traversal / CWE-22 deneysel kuralını ekle

**Sonuç:** Restricted-root path traversal bounded supported-input yüzeyinde gerçek source-to-sink kanıtıyla experimental/report-only üretilir.

**Kabul:**

- Yalnız açık restricted-root/trust-boundary sözleşmesi altında untrusted path construction→filesystem sink akışı raporlanır. Her open(user_filename) traversal değildir; canonicalize tek başına containment kanıtı değildir. Absolute path, parent segment, prefix collision, separator/platform farkları ve doğru component containment paired testlerle ayrılır; symlink/TOCTOU güvenliği kanıtsız iddia edilmez.
- Yeni rule başlangıçta experimental/report-only ve quality-gated=false/blocks-verdict=false'dur. Gerçek capability/CLI/worker/report parity, exact CWE mapping, source/flow/sink trace ve pratik düzeltme açıklaması vardır; henüz production başarı iddiası yoktur.
- Önce yokluğu/dar bug için RED, sonra odaklı dangerous/safe/unknown/unsupported GREEN; yeni frozen >=30 buggy + >=30 safe profilin dürüst ölçümü kaydedilir. Bilinen eğitim örneğiyle bağımsız değerlendirme karıştırılmaz.
- Aile eklenince registry/catalog/inventory yalnız source-derived prospective successor olarak güncellenir; eski 12 aile/floors ve üç report-only project rule korunur. Linux suite ve aynı-build worker/output parity gerçekten geçer.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/PathTraversalRule.h, src/rules/PathTraversalRule.cpp, tests/PathTraversalRuleTest.cpp, src/engine/StringFlow.h, src/engine/StringFlow.cpp, src/engine/StringFlowSummary.h, src/engine/StringFlowSummary.cpp, src/analyzer/BuiltinRules.h, src/core/RuleCapabilities.def, src/core/Capabilities.cpp, src/core/Diagnostic.h, src/CMakeLists.txt, tests/CMakeLists.txt, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/OutputParityCliTest.py, scripts/check_capabilities_sync.py, docs/capabilities.md, docs/CWE_SCOPE.md, docs/market-cwe-priorities.md, README.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, tests/product_corpus/regressions/**
**Bağımlılıklar:** CS3-CH11-S04-U006

#### CS3-CH11-S04-U008 — path-traversal / CWE-22 üretim kalite kapısını kapat

**Sonuç:** path-traversal ayrı bağımsız ölçümden sonra supported/blocking düzeye terfi eder.

**Kabul:**

- Önceki experimental SHA başlangıç adayıdır; eşikler geçmezse bu görevde dar düzeltme yapılarak yeni exact SHA üretilir ve eski RED korunur. Terfi öncesindeki güncel hâlâ-experimental adayda frozen >=30 buggy + >=30 safe, >=3 bağımsız kökenli profil üzerinde precision >=0.90, addressable recall >=0.70 ve safe FP=0 sağlanır; native API/flow/guard/unknown sınırları ayrıca ölçülür.
- Başarısızlıkta dar semantik RED/GREEN düzeltme ve safe/dangerous counterexample gerekir; payda/etiket/eşik/model trust veya baseline ile temizleme yoktur. Actual source-to-sink trace bağımsız denetlenir.
- Bağımsız ölçüm PASS'inden sonra yalnız prospective capability/tier/policy sözleşmesi supported/blocking'e terfi edilir; son değişmiş exact-head için yeniden bağımsız PASS gerekir. İlk deneysel sürümün kanıtı yeniden adlandırılmaz.
- Gerçek CLI findings/clean/incomplete/report-only ve policy exit davranışları, all-rule etkileşimi, worker/JSON/SARIF parity ve eski bütün quality floors geçer. Production eşiği sağlanamazsa görev/FIFO açık kalır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/PathTraversalRule.h, src/rules/PathTraversalRule.cpp, tests/PathTraversalRuleTest.cpp, src/engine/StringFlow.h, src/engine/StringFlow.cpp, src/engine/StringFlowSummary.h, src/engine/StringFlowSummary.cpp, src/analyzer/BuiltinRules.h, src/core/RuleCapabilities.def, src/core/Capabilities.cpp, src/core/Diagnostic.h, src/CMakeLists.txt, tests/CMakeLists.txt, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/OutputParityCliTest.py, scripts/check_capabilities_sync.py, docs/capabilities.md, docs/CWE_SCOPE.md, docs/market-cwe-priorities.md, README.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md, tests/product_corpus/regressions/**
**Bağımlılıklar:** CS3-CH11-S04-U007

### CH11-S05 — Mevcut bounds ailesinde kanıtlı stack ve heap overflow kapsamı

#### CS3-CH11-S05-U001 — Bounds içinde CWE-121 stack overflow alt türünü kanıtla

**Sonuç:** Kanıtlanmış stack destination üzerindeki gerçek sınır dışı yazma, doğru CWE alt türüyle raporlanır.

**Kabul:**

- CWE-121 yalnız proven out-of-bounds write ve proven stack storage provenance birlikteyse atanır. Read, unchecked-copy riski, legal one-past address, unknown storage veya yalnız pointer değişkeninin local olması bu alt türe yeterli değildir.
- Stack/global/static/heap, pointer alias/reassignment, array/member destination, copy offset ve allocation extent source-derived RED/GREEN ile ayrılır; eksik provenance en yakın kanıtlı eski finding türünü veya açık unknown'u korur, yeni CWE uydurmaz.
- Frozen ayrı CWE-121 >=30 buggy + >=30 safe altprofilinde precision >=0.90, addressable recall >=0.70, safe FP=0 ve >=3 köken gerekir. Parent bounds profili ve eski bütün floors geçer; parent/child CWE aynı hata için ayrı TP sayısını şişirmez.
- Public registry/explanations ve finding mapping prospective ve source-kanıtlıdır. Yeni FindingKind gerekiyorsa WorkerProtocol üst sınırı, malformed/unknown kind negatifleri ve JSON/SARIF/CLI parity birlikte güncellenir; isolated worker reddi gizlenmez.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/BoundsRule.cpp, src/rules/BoundsRule.h, src/engine/ExtentMap.h, src/core/Diagnostic.h, src/core/Capabilities.cpp, src/core/RuleCapabilities.def, src/analyzer/WorkerProtocol.cpp, tests/BoundsRuleTest.cpp, tests/WorkerProtocolTest.cpp, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/OutputParityCliTest.py, scripts/check_capabilities_sync.py, docs/capabilities.md, docs/CWE_SCOPE.md, docs/market-cwe-priorities.md, README.md, tests/product_corpus/regressions/**, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH11-S04-U008

#### CS3-CH11-S05-U002 — Bounds içinde CWE-122 heap overflow alt türünü kanıtla

**Sonuç:** Kanıtlanmış heap destination üzerindeki gerçek sınır dışı yazma, doğru CWE alt türüyle raporlanır.

**Kabul:**

- CWE-122 yalnız proven out-of-bounds write ve proven heap storage provenance birlikteyse atanır. Read, unchecked-copy riski, legal one-past address, unknown storage veya yalnız pointer değişkeninin local olması bu alt türe yeterli değildir.
- Stack/global/static/heap, pointer alias/reassignment, array/member destination, copy offset ve allocation extent source-derived RED/GREEN ile ayrılır; eksik provenance en yakın kanıtlı eski finding türünü veya açık unknown'u korur, yeni CWE uydurmaz.
- Frozen ayrı CWE-122 >=30 buggy + >=30 safe altprofilinde precision >=0.90, addressable recall >=0.70, safe FP=0 ve >=3 köken gerekir. Parent bounds profili ve eski bütün floors geçer; parent/child CWE aynı hata için ayrı TP sayısını şişirmez.
- Public registry/explanations ve finding mapping prospective ve source-kanıtlıdır. Yeni FindingKind gerekiyorsa WorkerProtocol üst sınırı, malformed/unknown kind negatifleri ve JSON/SARIF/CLI parity birlikte güncellenir; isolated worker reddi gizlenmez.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/rules/BoundsRule.cpp, src/rules/BoundsRule.h, src/engine/ExtentMap.h, src/core/Diagnostic.h, src/core/Capabilities.cpp, src/core/RuleCapabilities.def, src/analyzer/WorkerProtocol.cpp, tests/BoundsRuleTest.cpp, tests/WorkerProtocolTest.cpp, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/OutputParityCliTest.py, scripts/check_capabilities_sync.py, docs/capabilities.md, docs/CWE_SCOPE.md, docs/market-cwe-priorities.md, README.md, tests/product_corpus/regressions/**, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH11-S05-U001

### CH11-S06 — Bütün ürün modunda ortak kalite

#### CS3-CH11-S06-U001 — Tüm CWE'ler birlikteyken kaliteyi ve proje sonuçlarını doğrula

**Sonuç:** On altı supported CWE ailesi, kanıtlı CWE-121/122 altprofilleri ve üç bilinçli report-only project diagnostic birlikte gerçek ürün modunda geçer.

**Kabul:**

- Tek tek rule skorları yeterli değildir: tüm kurallar açıkken bütün frozen korpus, üç authentic build profili, known-FP regresyonları ve scope-boundary negatifleri yeniden çalışır.
- 47 eski kanıtlı FP=0; 10 eski belirsiz bağımsız çözümlenmiş ve sınıflarına göre düzeltilmiş/korunmuş; 9 eski TP kayıpsızdır. Yeni authentic hedeflerdeki bulgular da occurrence düzeyinde hakemlenir; ürün kapsamındaki açıklanmamış unknown yoktur.
- Her CWE ailesi yeni 0.90/0.70 ve safe0 kapısını, mevcut daha sıkı profiller özgün kapılarını geçer; %100 seçilmiş command-variant coverage ve sıfır failure/recovery/incomplete koşulu birlikte sağlanır.
- assumption/contract/policy üçlüsünün CWE olmadığı, trust sınırları ve report-only default bilerek test edilir. Platformlar veya rule etkileşimleri arasında açıklanmamış fark, toplu suppression ya da baseline temizliği yoktur.
- Yeni dört aile ve CWE-121/122 altprofilleri dondurulmuş 1020+ benzersiz source setinde ortak ölçülür; native API/trace/metadata tarafında exact 19 public diagnostic/26 CWE-ID hedefi gerçekleşir. Top25/KEV öncelik haritası yalnız gerçekten qualified altkapsamı işaretler; pazar geneli precision veya tam Top25 kapsamı iddiası yoktur.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** scripts/product_quality.py, scripts/test_product_quality.py, scripts/measure_product.py, scripts/test_measure_product.py, tests/product_corpus/regressions/**, docs/product-quality-results.md, docs/capabilities.md, docs/CI_GATES.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S05-U002

## CH12 — Üç yerel platformda eşdeğer davranış ve dayanıklılık

### CH12-S01 — Native kabul, negatifler ve sonlu kaynak sınırları

#### CS3-CH12-S01-U001 — Windows destek yüzeyindeki anlamlı test boşluklarını kapat

**Sonuç:** Windows desteği wrapper yeşili değil gerçek native davranış ve negatif kanıtıdır.

**Kabul:**

- Linux unreadable-directory/POSIX-only örnekleri Windows'ta çalışmış gibi sayılmaz; desteklenen Windows input/ACL/worker yollarında aynı ürün sözüne karşılık gelen gerçek olumlu ve olumsuz testler vardır.
- Worker iptali, timeout/crash sonrası child process temizliği, cache/checkpoint bozulması, Unicode/uzun yol ve compilation-command ayrımı native Windows Release profilinde doğrulanır.
- Gerçekten uygulanamaz OS-only durumlar önceden açık N/A'dır; supported davranışın yerine SKIP konamaz. İç test/assertion sayımı ham kanıta bağlıdır; incomplete analiz exit2 kalır.
- Mevcut RAII/fdopendir dangerous negatives, Linux korumaları ve tüm Windows hosted kapıları korunur; necessary fixes exact RED/GREEN ile sınırlıdır.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/platform_first_scan.py, scripts/test_platform_workflow.py, .github/workflows/ci.yml, tests/WorkflowPolicyTest.py, tests/CompilationDatabaseCliTest.py, tests/WorkerProtocolTest.cpp, tests/SourceManagerTest.cpp, tests/CfgCacheTest.cpp, tests/RegressionCheckpointTest.py, src/source_manager/SourceManager.cpp, src/source_manager/SourceManager.h, src/core/ResourceBudget.cpp, src/core/ResourceBudget.h, src/core/DarwinMemoryBudget.h, docs/platform-support.md, docs/product-quality-results.md, .github/workflows/windows.yml, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH11-S06-U001

#### CS3-CH12-S01-U002 — macOS destek sınırları ve kernel-ceiling kanıtını tamamla

**Sonuç:** macOS'un uygulanabilir input ve kernel kaynak sözleşmesi gerçek native testlerle doğrulanır.

**Kabul:**

- OS'nin oluşturmayı EILSEQ ile reddettiği raw-byte path yaratılmış gibi sayılmaz. Geçerli native path/UTF-8 normalization, bozuk input ve public error davranışı test edilir; prerequisite/N/A sözleşmesi dürüst kalır.
- Sonlu süreç/bellek/mapping sınırı gerçek kernel readback ve zorlanmış limit negatifiyle doğrulanır; address-space/data limiti RSS limiti diye adlandırılmaz.
- Worker cancellation/child cleanup, bozuk cache/checkpoint, fatal signal/timeout ve partial-result fail-closed native arm64 Release profilinde geçer; aynı frozen semantic corpus target-width farklarıyla açıklanır.
- Native hosted çalıştırma, iç assertion sayımı ve SDK/toolchain manifesti gerekir; Linux emülasyonu veya wrapper exit0 native PASS değildir.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/platform_first_scan.py, scripts/test_platform_workflow.py, .github/workflows/ci.yml, tests/WorkflowPolicyTest.py, tests/CompilationDatabaseCliTest.py, tests/WorkerProtocolTest.cpp, tests/SourceManagerTest.cpp, tests/CfgCacheTest.cpp, tests/RegressionCheckpointTest.py, src/source_manager/SourceManager.cpp, src/source_manager/SourceManager.h, src/core/ResourceBudget.cpp, src/core/ResourceBudget.h, src/core/DarwinMemoryBudget.h, docs/platform-support.md, docs/product-quality-results.md, .github/workflows/windows.yml, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH12-S01-U001

#### CS3-CH12-S01-U003 — Linux Windows macOS dayanıklılık matrisini exact source ile kapat

**Sonuç:** Desteklenen üç profilde gerekli testler gerçekten çalışır ve kaynak kullanımı sınırlandırılmıştır.

**Kabul:**

- Aynı temiz source commit için Linux x86_64, Windows x64 ve macOS arm64 full native CI, platform ilk-scan ve product profile kapıları çalışır; build/test/source/runtime/artifact hashleri eşleşir.
- İç SKIP/xfail/eksik artifact, stale output, crash, timeout ve başarısız alt süreç wrapper PASS'ine dönüşmez. Önceden onaylı gerçek OS-N/A ayrı raporlanır, yürütülmüş PASS sayılmaz.
- İlgili sanitizer slice ve sonlu malformed input/cache/checkpoint/worker stress kampanyası Linux'ta; native equivalent negatifler diğer profillerde geçer. Süre/bellek/process bütçeleri ölçüm öncesi dondurulur.
- Koşu sonunda yetim süreç ve kirli kullanıcı state yoktur; failure injection exit2 ve açık incomplete raporu üretir. Eski başarısız kayıtlar korunur.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** .github/workflows/ci.yml, scripts/test_platform_workflow.py, scripts/platform_first_scan.py, scripts/product_quality.py, scripts/test_product_quality.py, scripts/native_qualification.py, scripts/test_native_qualification.py, tests/WorkflowPolicyTest.py, docs/platform-support.md, docs/CI_GATES.md, docs/product-quality-results.md, .github/workflows/windows.yml, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH12-S01-U002

## CH13 — Aynı kaynaklı Release, güven zinciri ve gerçek kullanıcı akışları

### CH13-S01 — Yayın öncesi teknik hazırlık

#### CS3-CH13-S01-U001 — Release orkestrasyonunu yetki ve exact-source kapılarıyla düzelt

**Sonuç:** Tag oluşturulmadan önce eski otomatik yayın ve ref-writer yolları kaldırılır; candidate ve public işlemleri ayrılır.

**Kabul:**

- Mevcut release.yml içindeki force-push refs/ci-logs/status yazıcıları ve tag tetiklenince otomatik public publish kaldırılır. Read-only candidate build/test jobs ile yazma yetkili açık onaylı release jobs ayrılır; negatif workflow-policy testleri zorunludur.
- Eski tek CH06 candidate branch'e bağlı koşul yeni FRONT/candidate kullanımını güvenli kapsar; her zorunlu Linux/Windows/macOS kalite/platform job'u exact source SHA'ya bağlanır. Missing/skipped/stale checks yayın izni vermez.
- Main'e yazma/merge, force-push, mevcut tag overwrite veya yayımlı asset clobber yolu yoktur. Loglar artifacts'te tutulur; candidate çalıştırmak draft/public release oluşturmaz.
- Version source/tag/dirty tree kontrolü Linux Windows macOS için ortak fail-closed sözleşmedir. Workflow testleri sahte onay, yanlış SHA/tag, eksik job ve asset değişikliğini RED/GREEN ile kapsar.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** .github/workflows/release.yml, tests/ReleaseWorkflowTest.py, tests/WorkflowPolicyTest.py, scripts/test_platform_workflow.py, scripts/release_gate.py, scripts/test_release_gate.py, docs/release-checklist.md, docs/CI_GATES.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH12-S01-U003

#### CS3-CH13-S01-U002 — Üç platformu tek temiz Release kaynağından paketle

**Sonuç:** Dağıtılabilir paketler ortak source/version sözleşmesini ve kendi native dependency profilini taşır.

**Kabul:**

- Üç archive temiz Release build ile aynı SOURCE commit'ten üretilir; her birinin toolchain/flags/SDK, source/tree/binary/archive hashleri ve version bilgisi manifestte vardır. Dev-cache binary yeni tag/version diye damgalanmaz.
- Runtime shared/static dependency ve target header/SDK ayrımı her platformda belgelenir; no-LLVM/no-buildtree bağımsız çalışma iddiası ancak ilgili temiz-host testinin gerçekten gösterdiği sınırda yapılır.
- Paket relocation, path-with-spaces, missing runtime/header, wrong architecture/version/source ve bozuk archive negatifleri temiz sonuç vermez. Linux Ubuntu 22.04 ek destek iddiası korunacaksa ayrıca gerçekten test edilir; varsayılan ürün profili Ubuntu 24.04'tür.
- Paket hazırlığı public dağıtım veya publisher-signed olduğu iddiası üretmez; sonraki imzalama değişiklikleri yeni archive hashleriyle yeniden qualified edilir.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/package_linux.py, scripts/package_release.sh, scripts/test_package.py, scripts/platform_first_scan.py, scripts/test_platform_workflow.py, CMakeLists.txt, src/CMakeLists.txt, .github/workflows/release.yml, docs/release-checklist.md, docs/windows-support.md, docs/platform-support.md, README.md
**Bağımlılıklar:** CS3-CH13-S01-U001

#### CS3-CH13-S01-U003 — Üç platform için SBOM provenance lisans ve imza doğrulama hazırlığını tamamla

**Sonuç:** Her ürün paketinin içeriği, build kökeni ve yayıncı güveni doğrulanabilir bir sözleşmeye bağlanır.

**Kabul:**

- Linux ile sınırlı mevcut inventory Windows/macOS ve paketlenmiş static/shared runtime bileşenlerini kapsar; gerçekten bilinmeyen target-host SDK sürümü uydurulmaz. Lisans/notice dağıtım yükümlülükleri inventory ile eşleşir.
- Source/tag/toolchain/build recipe/input/output hashes manifest ve doğrulayıcıya bağlıdır; provenance self-assertion ile bağımsız/signed attestation farkı açıktır. Kanıtsız reproducible-build veya SLSA seviye iddiası yoktur.
- Planlanan yayın güven kapısı Linux signed checksum manifest + doğrulanabilir publisher identity, Windows Authenticode ve macOS Developer ID + notarization'dır. Uygun owner identity/credential yalnız güvenli signing ortamında kullanılır; sohbete secret istenmez.
- Bu görev validator/negatifler/dry-run hazırlığını kapatır, gerçek production-signing başarısı sayılmaz. Unsigned, yanlış publisher, altered asset/SBOM/provenance, invalid chain/expiry/notary negatifleri kapıyı düşürür; gerçek kimlik yokluğu CH14'ü bloke eder.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/generate_sbom.py, scripts/test_generate_sbom.py, scripts/release_gate.py, scripts/test_release_gate.py, scripts/signing_qualification.py, scripts/test_signing_qualification.py, .github/workflows/release.yml, docs/release-checklist.md, docs/provenance.md, THIRD_PARTY_NOTICES.md, LICENSE, README.md
**Bağımlılıklar:** CS3-CH13-S01-U002

#### CS3-CH13-S01-U004 — Kurulmuş artifact üzerinden CLI container ve hosted Action akışlarını doğrula

**Sonuç:** Yeni kullanıcı repo build ağacına dayanmadan beyan edilen uçtan uca akışları tamamlar.

**Kabul:**

- Aynı candidate source/artifact setinden temiz Linux Windows macOS kurulum, doctor, C/C++ compilation database first scan, JSON/SARIF, report-only ve policy/delta exit davranışları native çalışır.
- Container Linux-view olarak açıkça sınırlandırılır; Windows-native gibi sunulmaz. Gerçek hosted GitHub Action fresh consumer fixture üzerinde artifact digest/source ile çalışır; yerel action unit testi hosted kanıtın yerine geçmez.
- Yanlış source/artifact, missing SDK/header, private/invalid build path, findings/clean/incomplete/timeout ve bozuk config negatifleri test edilir. Helper gizli download, sistem volume/config değişimi veya buildtree fallback yapmaz.
- Dondurulmuş proje/resource profillerinde >=3 tekrar wall time, peak memory/process ve cold/warm cache ölçümleri bütçeleri geçer; doğruluk feda edilmez. README/quickstart yalnız bu akışlarla kanıtlanan komutları ve sınırları söyler.
- Korumalı inventory/catalog değişikliği yalnız bu task'ın gerçek kaynak/test/tier farkına bağlı, bağımsız sınıflandırmalı prospective successor'dır; eski snapshot/receipt/fixture anlamı ve daha sıkı floors korunur. Yeni frozen değerlendirme seti bu izinle düzenlenmez.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/platform_first_scan.py, scripts/test_platform_workflow.py, scripts/action_qualification.py, scripts/action_container.py, scripts/action_container_test.py, scripts/user_journey.py, scripts/test_user_journey.py, tests/FirstScanTest.py, tests/ActionArgsTest.py, action.yml, Dockerfile, .github/workflows/action-selftest.yml, README.md, docs/release-checklist.md, docs/windows-support.md, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH13-S01-U003

## CH14 — Gerçek yayın onayı, güvenilir dağıtım ve ürün kapanışı

### CH14-S01 — Kaynak adayı ve dış yetki kapısı

#### CS3-CH14-S01-U001 — Nihai exact-source RC'nin bütün teknik kapılarını yeniden kapat

**Sonuç:** Tek release candidate üzerinde bütün teknik kanıtlar günceldir; tarihsel farklı binary PASS'leri birleştirilmez.

**Kabul:**

- Temiz ortak SOURCE commit için G1–G4, G7 ve G5'in tag öncesi candidate build/source/version ön kontrolleri fresh başarılıdır; mevcut bütün daha sıkı korumalar geçer. G5'in gerçek tag bağı ve G6'nın gerçek production imza/notary kanıtı bu aşamada BEKLİYOR'dur, PASS sayılmaz.
- Global product profile içinde açıklanmamış bulgu, required-input unknown, gerçek FP/TP kaybı, iç test SKIP/missing job veya stale output yoktur; named residual unsupported sınırlar sözleşme dışıdır.
- Read-only independent_verifier exact SOURCE, pre-sign teknik sonuçlar, failure controls ve candidate manifest'i inceler. G6 için yalnız CH13'teki hazırlık/validator testleri incelenir; bunlar actual signing başarısı değildir. Receipt-only ledger commit'leriyle product source arasındaki fark ayrıca doğrulanır; ürün/source/workflow değişikliği yeni pre-sign qualification gerektirir.
- RC sonuçları ile yayına hazır imzasız taslak kanıt paketi hazırlanır; henüz yayımlandı veya ürün tamamlandı denmez.
- Release kaynak sınırı bu görevde dondurulur: sonraki ürün, build, workflow veya pakete giren belge değişikliği aday kimliğini geçersiz kılar. Yalnız paketlenmeyen receipt/ledger dosyaları mevcut SOURCE'a referansla ilerleyebilir; allowlist ve diff doğrulanır.
- Bu task'a ait repo commit SHA'sı ile frozen product SOURCE ayrı kimliklerdir; exact-head bağımsız inceleme her ikisini ve aradaki yalnız izinli kanıt/ledger farkını denetler. Pakete giren dosya değişmişse eski binary PASS'i kullanılamaz.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/release_gate.py, scripts/test_release_gate.py, docs/release-checklist.md, docs/product-quality-results.md, docs/release-candidate.json
**Bağımlılıklar:** CS3-CH13-S01-U004

#### CS3-CH14-S01-U002 — Tam kaynak adayı için owner tag ve signing yetkisini al

**Sonuç:** Dış işlem yetkileri kesin source/version/target ve sınırlarıyla kayıtlıdır.

**Kabul:**

- Sahip exact SOURCE SHA, yeni tag/version, signing identity/procedure ve private draft asset hedeflerini açıkça onaylar; planı kabul etmiş olması tag/secret/public işlem yetkisi değildir.
- Bu planın yayın yolu onaylı feature SOURCE commit'idir; main merge/rebase/integration görevi içermez ve main değişmez. Sahip daha sonra integration isterse bu ayrı yetki ve yeniden plan/source/qualification değerlendirmesi gerektirir; mevcut plan veya tag onayı otomatik main yetkisi değildir.
- Gerekli runner/hesap/signing kimliği yoksa FRONT açık/bloke kalır; unsigned/local-delivery fallback ile DONE yoktur. Secret sohbete veya repository'ye yazılmaz.
- Bu bir kanıt/yetki görevidir: sonraki işlemleri yapmış gibi göstermez. Approval kimliği, kapsamı ve tarihçesi manifestte doğrulanır; exact-source mismatch/withdrawn approval negatifleri ret alır.
- Bu task'a ait repo commit SHA'sı ile frozen product SOURCE ayrı kimliklerdir; exact-head bağımsız inceleme her ikisini ve aradaki yalnız izinli kanıt/ledger farkını denetler. Pakete giren dosya değişmişse eski binary PASS'i kullanılamaz.

**Test bütçesi:** T0
**Kontroller:** plan-contract, queue-check
**Kapsam:** docs/release-authorization.json, docs/release-checklist.md, scripts/release_gate.py, scripts/test_release_gate.py
**Bağımlılıklar:** CS3-CH14-S01-U001

### CH14-S02 — İmzalı yayın ve dışarıdan doğrulama

#### CS3-CH14-S02-U001 — Onaylı tag'den gerçek imzalı Release paketlerini üret ve qualify et

**Sonuç:** Actual tag-version temiz build, gerçek publisher imzası ve native kurulum kanıtı aynı artifact setine bağlıdır.

**Kabul:**

- Yalnız onaylı yeni tag exact SOURCE'ta oluşturulur; mevcut tag/asset veya main overwrite yoktur. Üç platform gerçek tag version'ından temiz Release build, signing/notary ve SBOM/provenance/checksum üretir; önceki dev paketleri yeniden etiketlenmez.
- Linux doğrulanabilir signed manifest, Windows Authenticode chain/publisher ve macOS Developer ID/notary/stapling uygun native validator ile doğrulanır; signing veya notarization başarısızsa task kapanmaz.
- İmzalama sonrası nihai archive/binary hashleriyle tüm artifact user journeys, platform first scans ve G1–G7 release-qualification gate yeniden sağlanır; SOURCE/recipe/workflow farkı yeni aday/onay gerektirir.
- Gerekirse yalnız onaylı private draft hedefinde tutulur; public görünürlük açılmaz. Independent exact-head + exact-artifact manifest PASS ve ham negatif kanıtları zorunludur.
- Bu task'a ait repo commit SHA'sı ile frozen product SOURCE ayrı kimliklerdir; exact-head bağımsız inceleme her ikisini ve aradaki yalnız izinli kanıt/ledger farkını denetler. Pakete giren dosya değişmişse eski binary PASS'i kullanılamaz.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** docs/release-checklist.md, docs/release-candidate.json, docs/release-authorization.json, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH14-S01-U002

#### CS3-CH14-S02-U002 — Kesin imzalı artifact manifest'i için yayın onayı al ve gerçekten yayımla

**Sonuç:** Sahibin onayladığı aynı immutable ürün seti gerçek public dağıtımdadır.

**Kabul:**

- Sahip exact SOURCE/tag/version, imzalı archive hashleri, release metni ve görünürlük hedefini açıkça onaylar; önceki tag/private-draft onayı public yayın izni sayılmaz.
- Yalnız o approved artifact set public yapılır; imzalar, checksums, SBOM/provenance ve kullanıcı bağımlılıkları erişilebilirdir. Missing/changed asset veya withdrawn approval hard stop'tur; yeniden build edip aynı onayı kullanmak yoktur.
- Release rollback/deprecation prosedürü açıktır; yayımlı asset overwrite/force-push veya main yazımı yapılmaz. İşlemi yalnız primary, kullanıcı yetkisi sınırında yürütür.
- Gerçek yayın ID/URL/timestamp/source/tag/assets receipt'i kaydedilir; dry-run veya draft bu görevin kabulü değildir.
- Bu task'a ait repo commit SHA'sı ile frozen product SOURCE ayrı kimliklerdir; exact-head bağımsız inceleme her ikisini ve aradaki yalnız izinli kanıt/ledger farkını denetler. Pakete giren dosya değişmişse eski binary PASS'i kullanılamaz.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** docs/release-authorization.json, docs/release-checklist.md
**Bağımlılıklar:** CS3-CH14-S02-U001

#### CS3-CH14-S02-U003 — Public indirmeden ürünü doğrula ve FIFO'yu gerçekten kapat

**Sonuç:** Ürün hem teknik olarak qualified hem gerçek tüketici yolunda dağıtılmıştır; bütün yeni görevler kanıtlı kapanır.

**Kabul:**

- Public URL'den yeni temiz tüketici ortamlarına indirilen üç artifact'in publisher imzası/notary/hash/SBOM/provenance/source/tag bağı doğrulanır; local staging dosyası tüketici download kanıtı değildir.
- Fresh Linux Windows macOS user journeys ve gerçek hosted consumer Action/container akışı yayımlanmış source/artifact/digest ile çalışır. Hiçbir final required gate local-only fallback, SKIP, stale CI veya eski binary sonucuyla kapanmaz.
- Son bağımsız exact-head/exact-published-artifact denetimi G1–G8'i, bütün 51 yeni sözleşme/receipt'i, korunan eski 46 kayıt ve main unchanged koşulunu inceler. Açık material finding varsa son POP yoktur.
- Kanıtlar kalıcı yerel paket + erişilebilir yayın/checksum referanslarında korunur. Son POP ve ledger commit sonrası queue check/history transition ve ayrı terminal read-only audit gerçekten geçer; ancak bundan sonra bu sınırlı sürüm hedefi için ürün tamamlandı denir.
- Bu task'a ait repo commit SHA'sı ile frozen product SOURCE ayrı kimliklerdir; exact-head bağımsız inceleme her ikisini ve aradaki yalnız izinli kanıt/ledger farkını denetler. Pakete giren dosya değişmişse eski binary PASS'i kullanılamaz.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** docs/release-checklist.md, docs/product-quality-results.md
**Bağımlılıklar:** CS3-CH14-S02-U002
