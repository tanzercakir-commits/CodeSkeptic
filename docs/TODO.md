# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH04-S02-U001

### CS3-CH04-S02-U001 — Cache kimliğini gerçek girdilere bağla

**Sonuç:** Cache yalnız aynı araç/ayar/girdi/header bağımlılıkları için kullanılabilir.

**Kabul:**

- Değişen header/compiler flag/profile/tool veya volatile input eski kaydı reddeder.
- Cache'siz ve cache'li normalize sonuç aynı olur.
- Eski a79c375 yardımcı fikir kaynağıdır; kanıt veya dosya paketi olarak taşınmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/analyzer/*, src/source_manager/*, src/config/Config*, tests/UnitEvidenceStoreTest.cpp, tests/AnalysisCoordinatorTest.cpp, src/CMakeLists.txt, tests/CMakeLists.txt, tests/SourceManagerTest.cpp, src/contracts/Sidecar.cpp, src/server/McpServer.cpp, docs/usage.md
**Bağımlılıklar:** Yok

### CS3-CH04-S02-U002 — Cache yazımı ve saklama sınırını güvenli yap

**Sonuç:** Kısmi/bozuk/symlink kayıt kullanılmaz; disk kullanımı tanımlı tavanda kalır.

**Kabul:**

- Atomic temp-to-final, concurrent writers, truncated entry ve tamper fixture'ları vardır.
- Failed write önceki geçerli entry'yi bozmaz; retention sonucu analiz doğruluğu değişmez.
- Saklama tavanı aşılırsa açık durum verir; sınırsız cache oluşturulmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, tests/UnitEvidenceStoreTest.cpp
**Bağımlılıklar:** CS3-CH04-S02-U001

### CS3-CH04-S02-U003 — Checkpoint yalnız aynı geçerli analizi sürdürsün

**Sonuç:** Kesilen çalışma tam girdi kimliği doğrulandıktan sonra devam eder.

**Kabul:**

- Changed source/header/config/corrupt manifest resume'u reddeder.
- Resume ve fresh run sonuç/kapsam eşittir; eksik worker sonucu DONE sayılmaz.
- Disk ve süreç sınırları cache/worker sözleşmesini aşmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, src/config/Config*, src/main.cpp, tests/UnitEvidenceStoreTest.cpp, tests/AnalysisCoordinatorTest.cpp
**Bağımlılıklar:** CS3-CH04-S02-U002

### CS3-CH04-S03-U001 — Windows fixture taşınabilirliğini gerçek hosted kapılarla doğrula

**Sonuç:** Windows testleri canonical path, size_t ve fiziksel kaynak byte sözleşmesini doğru sınar; mevcut ürün beklentileri ve hosted kapılar korunur.

**Kabul:**

- cab9493306752fa15e4fc74273678f674a5442d0 Windows run34045241136/job101519028589 içindeki dört gerçek RED saklanır: coordinator canonical yol, Bounds memcpy size_t, suppression CRLF ve baseline CRLF. Başarısız tarihsel sonuç yeniden PASS diye etiketlenmez.
- Yalnız dört test fixture'ının platform varsayımları düzeltilir; tüm bulgu sayıları, source/destination ayrımı, strong identity ve marker/target beklentileri korunur. Canonical beklenen yollar, hedefin gerçek __SIZE_TYPE__ prototipi ve byte-exact binary kaynak yazımı pozitif/negatif kontrollerle kanıtlanır; ürün kuralları veya assertion'lar gevşetilmez.
- Aynı aday exact head için native Windows build, CTest, tek-süreç suite, CLI smoke, SDK ve relocation dahil mevcut workflow gerçekten başarılıdır; atlanan adım başarı değildir. Linux suite ve ilgili sabit corpus tekrar geçer. Workflow, toolchain pinleri, kalite floor'ları, main ve tamamlanmış sözleşmeler değişmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, windows-hosted, queue-check
**Kapsam:** tests/AnalysisCoordinatorTest.cpp, tests/BoundsRuleTest.cpp, tests/SuppressionFilterTest.cpp, tests/BaselineTest.cpp
**Bağımlılıklar:** CS3-CH04-S02-U003

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
