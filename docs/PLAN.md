# CodeSkeptic — CWE Ürün Planı

Sürüm: 4. Eski planın devamı değil; main tabanlı yeni program.

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
**Kapsam:** src/engine/IntervalEval.cpp, src/engine/IntervalEval.h, tests/IntervalAnalysisTest.cpp, tests/AllocSizeOverflowRuleTest.cpp, tests/IntOverflowRuleTest.cpp, tests/SignConversionRuleTest.cpp
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
**Kapsam:** src/engine/IntervalEval.cpp, src/engine/IntervalEval.h, tests/IntervalAnalysisTest.cpp, tests/BoundsRuleTest.cpp, tests/IntOverflowRuleTest.cpp, tests/AllocSizeOverflowRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S02-U002

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
**Kapsam:** src/source_manager/CompilationDatabaseDiscovery*, src/source_manager/SourceManager*, src/config/Config*, src/analyzer/StaticAnalyzer*, src/core/Messages*, src/main.cpp, src/CMakeLists.txt, tests/CompilationDatabaseCliTest.py, tests/ConfigTest.cpp, tests/CMakeLists.txt, docs/first-scan.md
**Bağımlılıklar:** Yok

#### CS3-CH02-S01-U002 — Config ve target-scope güncellemelerini işlemsel yap

**Sonuç:** Geçersiz config/scope girdisi önceki geçerli durumu kısmen değiştirmez.

**Kabul:**

- Malformed, overflow, delimiter-only ve conflict girdilerinde state byte-equivalent kalır.
- Bozuk kapsam analizi genişletmez veya güvenilir temiz hüküm üretmez.
- CLI ve MCP girişleri aynı structured reason sözleşmesini uygular.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/config/Config*, src/source_manager/SourceManager*, src/core/Messages*, src/server/McpServer*, tests/ConfigTest.cpp, tests/SourceManagerTest.cpp, tests/McpServerTest.cpp
**Bağımlılıklar:** Yok

### CH02-S02 — Kalıcı ve dış girdiler

#### CS3-CH02-S02-U001 — Fonksiyon özeti/model parser sınırlarını sağlamlaştır

**Sonuç:** Bozuk, sürümü uyumsuz veya aşırı büyük özet/model dosyası güvenli reddedilir.

**Kabul:**

- Arity/index, CRLF, embedded NUL, count/size ve version fixture'ları vardır.
- Hata kısmi model/state yayımlamaz; normal geçerli dosyalar korunur.
- Dar donor fikirleri yeni baseline üzerinde yeniden test edilir.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/engine/FunctionSummary*, src/contracts/*, tests/InterproceduralTest.cpp, tests/ContractRuleTest.cpp, tests/PolicyRuleTest.cpp
**Bağımlılıklar:** Yok

#### CS3-CH02-S02-U002 — MCP istek zarfını ve yaşam döngüsünü sınırla

**Sonuç:** Malformed JSON-RPC istekleri ve işlem hataları sunucuyu veya sonraki isteği bozmaz.

**Kabul:**

- Eksik/yanlış ID/version/method ve boyut sınırı deterministik hata üretir.
- Başarısız istek sonrası geçerli istek temiz state ile çalışır.
- CLI ile aynı analiz davranışı korunur; yeni ağ/cloud servisi eklenmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/server/McpServer*, src/config/Config*, tests/McpServerTest.cpp
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
**Kapsam:** src/analyzer/StaticAnalyzer*, src/source_manager/SourceManager*, src/core/AnalysisResult.h, src/core/ExitPolicy.h, src/core/Messages*, src/reporter/*, tests/StaticAnalyzerTest.cpp, tests/SourceManagerTest.cpp, tests/ExitPolicyTest.cpp, tests/ReporterTest.cpp
**Bağımlılıklar:** Yok

#### CS3-CH02-S03-U002 — Frontend ve CFG düşmanca geçerli girdilerde sonlansın

**Sonuç:** Template/macro/CFG köşeleri crash/hang yerine sınırları belirli sonuç verir.

**Kabul:**

- Küçük, repository-contained template/macro/high-CFG fixture'ları kullanılır.
- Hata veya timeout eksik kapsama nedeni olarak korunur.
- Ortak motor değişirse tam Linux suite ve yalnız ilgili sanitizer/stress dilimi çalışır.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/StaticAnalyzer*, src/source_manager/SourceManager*, src/engine/*, tests/stress_corpus/*, tests/StressMatrixTest.py, scripts/run_stress_matrix.py
**Bağımlılıklar:** Yok

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
**Kapsam:** src/core/RuleCapabilities.def, src/core/Capabilities*, src/core/Diagnostic.h, src/core/AnalysisResult.h, src/reporter/*, src/rules/*, tests/SarifReporterTest.cpp, tests/CapabilitiesTest.cpp, docs/capabilities.md, src/core/Messages.*, tests/IntOverflowRuleTest.cpp, tests/JsonReporterTest.cpp, tests/CapabilitiesCliTest.py, README.md, scripts/check_capabilities_sync.py
**Bağımlılıklar:** Yok

#### CS3-CH03-S01-U002 — CLI/JSON/SARIF/HTML bulgu ve verdict tutarlılığını sabitle

**Sonuç:** Aynı analiz bütün çıktı yüzeylerinde aynı normalize bulguyu ve kapsamı verir.

**Kabul:**

- Rule/CWE, konum, trace, severity, tool/schema version ve verdict karşılaştırılır.
- Malformed option/config deterministik hatadır; makine çıktısına log karışmaz.
- Path component sınırları ve Windows path fixture'ları korunur.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/reporter/*, src/core/Capabilities*, src/core/Messages*, src/main.cpp, src/config/Config*, tests/*ReporterTest.cpp, tests/CapabilitiesTest.cpp, tests/ConfigTest.cpp
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
**Kapsam:** src/analyzer/Baseline*, src/analyzer/SuppressionFilter*, src/core/FindingFingerprint*, scripts/review_diff.sh, scripts/review_report.py, tests/BaselineTest.cpp, tests/SuppressionFilterTest.cpp, tests/test_review_diff.sh
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
**Kapsam:** src/analyzer/*, src/core/AnalysisResult.h, src/main.cpp, src/CMakeLists.txt, tests/WorkerProtocolTest.cpp, tests/AnalysisCoordinatorTest.cpp, tests/CMakeLists.txt
**Bağımlılıklar:** Yok

#### CS3-CH04-S01-U002 — Timeout/bellek/iptal bütçesini uygula

**Sonuç:** Kaynak bütçesi aşan worker sonlandırılır; süreç ve descriptor sızıntısı bırakılmaz.

**Kabul:**

- Timeout, memory limit ve cancellation negatifleri gerçek subprocess ile sınanır.
- Partial failure sonuç ve kapsamda görünür; diğer sonuçlar deterministik toplanır.
- Host-wide/root authority yoktur; yalnız başlatılan çocuk süreçler yönetilir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, src/core/Resource*, src/config/Config*, src/main.cpp, src/CMakeLists.txt, tests/ResourceBudgetTest.cpp, tests/AnalysisCoordinatorTest.cpp
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
**Kapsam:** src/analyzer/*, src/source_manager/*, src/config/Config*, tests/UnitEvidenceStoreTest.cpp, tests/AnalysisCoordinatorTest.cpp
**Bağımlılıklar:** Yok

#### CS3-CH04-S02-U002 — Cache yazımı ve saklama sınırını güvenli yap

**Sonuç:** Kısmi/bozuk/symlink kayıt kullanılmaz; disk kullanımı tanımlı tavanda kalır.

**Kabul:**

- Atomic temp-to-final, concurrent writers, truncated entry ve tamper fixture'ları vardır.
- Failed write önceki geçerli entry'yi bozmaz; retention sonucu analiz doğruluğu değişmez.
- Saklama tavanı aşılırsa açık durum verir; sınırsız cache oluşturulmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, tests/UnitEvidenceStoreTest.cpp
**Bağımlılıklar:** CS3-CH04-S02-U001

#### CS3-CH04-S02-U003 — Checkpoint yalnız aynı geçerli analizi sürdürsün

**Sonuç:** Kesilen çalışma tam girdi kimliği doğrulandıktan sonra devam eder.

**Kabul:**

- Changed source/header/config/corrupt manifest resume'u reddeder.
- Resume ve fresh run sonuç/kapsam eşittir; eksik worker sonucu DONE sayılmaz.
- Disk ve süreç sınırları cache/worker sözleşmesini aşmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, src/config/Config*, src/main.cpp, tests/UnitEvidenceStoreTest.cpp, tests/AnalysisCoordinatorTest.cpp
**Bağımlılıklar:** CS3-CH04-S02-U002

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

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** tests/stress_corpus/*, fuzz/*, scripts/test_resilience.sh, docs/quality_results.md
**Bağımlılıklar:** Yok

#### CS3-CH05-S02-U002 — Gerçek proje ve performans kabulünü ölç

**Sonuç:** Sabit girdilerde kullanılabilirlik, latency ve false positive yükü ölçülür.

**Kabul:**

- En az üç küçük/orta gerçek C/C++ proje veya önceden edinilmiş checksummed örnek kullanılır; kaynaklar izinsiz upload edilmez.
- Donanım, girdi, komut, sürüm ve süre/bellek ölçümleri kayıtlıdır.
- Ölçülmeyen performans/market başarısı iddia edilmez; blocker varsa aynı chapter kapanmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** scripts/measure_product.py, docs/quality_results.md, docs/benchmarks.md
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
**Kapsam:** scripts/package_release.sh, CMakeLists.txt, src/CMakeLists.txt, docs/release-checklist.md, tests/PackageTest.py
**Bağımlılıklar:** Yok

#### CS3-CH06-S01-U002 — Container ve Action paketinde analiz paritesini doğrula

**Sonuç:** Container/Action aynı binary sözleşmesiyle güvenilir sonucu taşır.

**Kabul:**

- Kaynak kod/secret izinsiz dışarı gönderilmez; runtime varsayılan izinler minimaldir.
- Aynı fixture için CLI/container/Action exit ve SARIF sonuçları eşittir.
- Canlı destek iddiası yalnız gerçekten koşmuş platform/check kanıtına dayanır.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** Dockerfile, action.yml, scripts/action*, tests/ActionArgsTest.py, docs/integrations.md, .github/workflows/action-selftest.yml
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
**Kapsam:** scripts/package_release.sh, scripts/generate_sbom.py, docs/release-checklist.md, RELEASE_NOTES.md, .github/workflows/release.yml
**Bağımlılıklar:** CS3-CH06-S01-U001

#### CS3-CH06-S02-U002 — Desteklenen platform sözünü gerçek paket testine bağla

**Sonuç:** Linux dışı platformların destek durumu fiilen çalışan artifact testine göre açıklanır.

**Kabul:**

- Windows/macOS dahil destek ilan edilen her platform exact artifact first-scan çalıştırır.
- Eksik runner/signer/authorization başarılı sayılmaz; açık blocker olarak kalır.
- Yerel branch senkronizasyonu main merge veya release yetkisi değildir.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** .github/workflows/windows.yml, .github/workflows/release.yml, docs/windows-support.md, README.md, docs/release-checklist.md
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
