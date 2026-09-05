# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH02-S01-U001

### CS3-CH02-S01-U001 — Compilation database keşfi ve doctor komutunu yeniden uygula

**Sonuç:** Kullanıcı doğru database'i veya düzeltilebilir açık hatayı görür.

**Kabul:**

- Eski 060bf4b yalnız fikir/dar kod kaynağıdır; dosyalar topluca kopyalanmaz.
- CMake/Ninja fixture, boş repo, iki database, bozuk JSON ve single-file kapsanır.
- Sessiz yanlış database/fallback yoktur; doctor ile gerçek analiz aynı seçim sonucunu kullanır.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/source_manager/CompilationDatabaseDiscovery*, src/source_manager/SourceManager*, src/config/Config*, src/analyzer/StaticAnalyzer*, src/core/Messages*, src/main.cpp, src/CMakeLists.txt, tests/CompilationDatabaseCliTest.py, tests/ConfigTest.cpp, tests/CMakeLists.txt, docs/first-scan.md
**Bağımlılıklar:** Yok

### CS3-CH02-S01-U002 — Config ve target-scope güncellemelerini işlemsel yap

**Sonuç:** Geçersiz config/scope girdisi önceki geçerli durumu kısmen değiştirmez.

**Kabul:**

- Malformed, overflow, delimiter-only ve conflict girdilerinde state byte-equivalent kalır.
- Bozuk kapsam analizi genişletmez veya güvenilir temiz hüküm üretmez.
- CLI ve MCP girişleri aynı structured reason sözleşmesini uygular.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/config/Config*, src/source_manager/SourceManager*, src/core/Messages*, src/server/McpServer*, tests/ConfigTest.cpp, tests/SourceManagerTest.cpp, tests/McpServerTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH02-S01-U003 — Çoklu producer kural seçimini diagnostic ID ile tutarlı uygula

**Sonuç:** Kural kapatma işlemi yalnız sınıf adını değil yayımlanan diagnostic ID sözleşmesini bütün ilgili producer'larda uygular.

**Kabul:**

- S04-U001 CLI keşfi önce RED ile yeniden doğrulanır: --disable-rule resource-leak sonrasında FILE/DIR aynı ID ile hâlâ raporlanıyor; yalnız native FD producer'ının kaldırılması yeterli değildir.
- Bilinen diagnostic ID kapatıldığında o ID'yi üreten bütün producer'ların bulguları tutarlı seçilir; farklı ID'lerin etkinliği, varsayılan kalite/tier ve kapsam sayaçları sessiz değişmez.
- CLI ve MCP'nin mevcut yapılandırma yüzeyleri aynı seçim sözleşmesini uygular; kapalı/açık/kapalı ardışık kullanımda istekler arasında durum sızmaz, var olmayan seçenek çalıştı sayılmaz.
- Native FD, FILE/DIR ve memory-leak pozitif/negatifleri gerçek CLI/MCP ve focused analyzer/config testleriyle sınanır; JSON/SARIF/verdict sayımları etkin bulgularla tutarlıdır.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/analyzer/StaticAnalyzer*, src/config/Config*, src/engine/RuleEngine*, src/core/Capabilities*, src/core/RuleCapabilities.def, src/server/McpServer*, src/main.cpp, tests/McpServerTest.cpp, tests/ConfigTest.cpp, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py, tests/AnalysisResultTest.cpp, tests/MemoryLeakRuleExTest.cpp, tests/FdResourceRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S04-U001

### CS3-CH02-S02-U001 — Fonksiyon özeti/model parser sınırlarını sağlamlaştır

**Sonuç:** Bozuk, sürümü uyumsuz veya aşırı büyük özet/model dosyası güvenli reddedilir.

**Kabul:**

- Arity/index, CRLF, embedded NUL, count/size ve version fixture'ları vardır.
- Hata kısmi model/state yayımlamaz; normal geçerli dosyalar korunur.
- Dar donor fikirleri yeni baseline üzerinde yeniden test edilir.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/engine/FunctionSummary*, src/contracts/*, tests/InterproceduralTest.cpp, tests/ContractRuleTest.cpp, tests/PolicyRuleTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH02-S02-U002 — MCP istek zarfını ve yaşam döngüsünü sınırla

**Sonuç:** Malformed JSON-RPC istekleri ve işlem hataları sunucuyu veya sonraki isteği bozmaz.

**Kabul:**

- Eksik/yanlış ID/version/method ve boyut sınırı deterministik hata üretir.
- Başarısız istek sonrası geçerli istek temiz state ile çalışır.
- CLI ile aynı analiz davranışı korunur; yeni ağ/cloud servisi eklenmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/server/McpServer*, src/config/Config*, tests/McpServerTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH02-S03-U001 — İstenen/analiz edilen/atlanan/başarısız dosyaları uzlaştır

**Sonuç:** Her istenen kaynak tek kimlikle sonuç sınıfına ve gerekçeye sahip olur.

**Kabul:**

- Tekrarlanan AST callback dosya sayısını artırmaz; eksik TU kaybolmaz.
- Kapsam eksikse sonuç güvenilir temiz olamaz; exit 0/1/2 sözleşmesi fixture'larla sınanır.
- JSON/SARIF ve CLI aynı kapsam özetini taşır.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/analyzer/StaticAnalyzer*, src/source_manager/SourceManager*, src/core/AnalysisResult.h, src/core/ExitPolicy.h, src/core/Messages*, src/reporter/*, tests/StaticAnalyzerTest.cpp, tests/SourceManagerTest.cpp, tests/ExitPolicyTest.cpp, tests/ReporterTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH02-S03-U002 — Frontend ve CFG düşmanca geçerli girdilerde sonlansın

**Sonuç:** Template/macro/CFG köşeleri crash/hang yerine sınırları belirli sonuç verir.

**Kabul:**

- Küçük, repository-contained template/macro/high-CFG fixture'ları kullanılır.
- Hata veya timeout eksik kapsama nedeni olarak korunur.
- Ortak motor değişirse tam Linux suite ve yalnız ilgili sanitizer/stress dilimi çalışır.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/StaticAnalyzer*, src/source_manager/SourceManager*, src/engine/*, tests/stress_corpus/*, tests/StressMatrixTest.py, scripts/run_stress_matrix.py
**Bağımlılıklar:** Yok

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH03 — CWE bulgularını kullanılabilir ürüne dönüştürme
- CH04 — Sınırlı kaynakla dayanıklı çalışma
- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
