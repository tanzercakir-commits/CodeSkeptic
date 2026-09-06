# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH04-S03-U001

### CS3-CH04-S03-U001 — Windows fixture taşınabilirliğini gerçek hosted kapılarla doğrula

**Sonuç:** Windows testleri canonical path, size_t ve fiziksel kaynak byte sözleşmesini doğru sınar; mevcut ürün beklentileri ve hosted kapılar korunur.

**Kabul:**

- cab9493306752fa15e4fc74273678f674a5442d0 Windows run34045241136/job101519028589 içindeki dört gerçek RED saklanır: coordinator canonical yol, Bounds memcpy size_t, suppression CRLF ve baseline CRLF. Başarısız tarihsel sonuç yeniden PASS diye etiketlenmez.
- Dört test fixture'ının platform varsayımları düzeltilir; tüm bulgu sayıları, source/destination ayrımı, strong identity ve marker/target beklentileri korunur. Canonical beklenen yollar, hedefin gerçek __SIZE_TYPE__ prototipi ve byte-exact binary kaynak yazımı pozitif/negatif kontrollerle kanıtlanır; ürün kuralları veya assertion'lar gevşetilmez.
- Aynı aday exact head için native Windows build, CTest, tek-süreç suite, CLI smoke, SDK ve relocation dahil mevcut workflow gerçekten başarılıdır; atlanan adım başarı değildir. Linux suite ve ilgili sabit corpus tekrar geçer. Workflow, toolchain pinleri, kalite floor'ları, main ve tamamlanmış sözleşmeler değişmez.
- Bu dört fixture düzeltmesine ek olarak yalnız 94c83277b566813af3b6a3f5d916631900992492 Windows run34055351372 Build aşamasında kaydedilmiş MSVC C3861 _get_environ tanımsızlığı için ortam listeleme uyumluluğu düzeltilir; bu tarihsel RED ve testlerin o koşuda çalışmadığı kaydı korunur. src/source_manager/InputIdentity.cpp içindeki tam ortam kimliği, mevcut byte/entry sınırları ve fail-closed davranış korunur; ortam sessizce boş/filtrelenmiş sayılmaz. tests/SourceManagerTest.cpp içinde aynı ortamın sabit kimliği ve değişken ekleme/değiştirme/silmenin kimliği değiştirmesi ile geri yükleme gerçek platform API'si üzerinden sınanır. Bu dar derleme uyumluluğu dışında ürün davranışı, kurallar, worker/cache doğrulaması ve diğer platformların semantiği değiştirilmez; mevcut exact-head Windows ve Linux kapılarının tamamı yine gereklidir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, windows-hosted, queue-check
**Kapsam:** tests/AnalysisCoordinatorTest.cpp, tests/BoundsRuleTest.cpp, tests/SuppressionFilterTest.cpp, tests/BaselineTest.cpp, src/source_manager/InputIdentity.cpp, tests/SourceManagerTest.cpp
**Bağımlılıklar:** CS3-CH04-S02-U003

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
