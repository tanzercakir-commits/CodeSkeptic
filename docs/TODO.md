# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH01-S01-U001

### CS3-CH01-S01-U001 — 64-bit signed çıkarma taşmasını doğru hesapla

**Sonuç:** Çıkarma toplama gibi hesaplanmaz; kanıtlanabilir 64-bit overflow/underflow doğru raporlanır.

**Kabul:**

- Mevcut davranış önce değişikliksiz RED fixture ile doğrulanır; kaynak şüphesi tek başına hata/PASS sayılmaz.
- LLONG_MIN−1 ve LLONG_MAX−(−1) bulunur; LLONG_MAX−1 ve LLONG_MIN−(−1) temiz kalır.
- Unknown değerler, guard'lar ve 32-bit arithmetic davranışı korunur; ilgili IntOverflow regression ve gerçek CLI smoke geçer.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/IntOverflowRule.cpp, tests/IntOverflowRuleTest.cpp, scripts/local_test.sh
**Bağımlılıklar:** CS3-CH00-S01-U001

### CS3-CH01-S01-U002 — 64-bit allocation-size toplamayı denetle

**Sonuç:** n+header gibi allocation boyutlarında unsigned sarma mevcut çarpım modeline eklenir.

**Kabul:**

- SIZE_MAX sınırı, exact fit, korumalı toplam ve taşan toplam karşılaştırılır.
- Mevcut 64-bit multiplication ve trusted/unknown kaynak sınırları bozulmaz.
- CWE-131/190 bulgusu gerçek ayırma boyutuna bağlıdır; bütün unsigned toplamalar uyarılmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/AllocSizeOverflowRule.cpp, tests/AllocSizeOverflowRuleTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH01-S01-U003 — Checked-add overflow sonucunun kullanımını izle

**Sonuç:** Checked-add çağrısının başarısızlık sonucu yok sayıldığında güvensiz boyut kullanımı yakalanır.

**Kabul:**

- Builtin add overflow kontrolsüz kullanım pozitif, doğrulanmış success branch negatiftir.
- Status/output reassignment ve escape önceki kanıtı geçersiz kılar.
- Checked-mul regresyonları ve ilgisiz arithmetic bulguları değişmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/AllocSizeOverflowRule.cpp, tests/AllocSizeOverflowRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S01-U002

### CS3-CH01-S02-U001 — memcpy/memmove kaynak okuma kapasitesini denetle

**Sonuç:** Hedef yeterli olsa bile küçük kaynaktan taşan okuma CWE-125 olarak ayrılır.

**Kabul:**

- Büyük hedef/küçük kaynak, exact fit, zero length ve unknown source kapsanır.
- memset için kaynak okuması üretilmez; strncpy farklı semantiğiyle bu işin dışında kalır.
- Mevcut destination write sınırı ve güvenli corpus sonuçları korunur.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/BoundsRule.cpp, src/rules/BoundsRule.h, tests/BoundsRuleTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH01-S02-U002 — Sabit pointer-offset kalan kapasitesini izle

**Sonuç:** buf+k ve &buf[k] için bilinen kalan kapasite okuma/yazma denetimine girer.

**Kabul:**

- Son byte, taşma, negatif offset ve one-past ile zero length ayrı fixture'lardır.
- Bilinmeyen veya değiştirilmiş alias için kapasite uydurulmaz.
- Kaynak okuma ve hedef yazma bulguları doğru ayrılır; integer hesap taşması güvenli kalır.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/BoundsRule.cpp, src/rules/BoundsRule.h, src/engine/ExtentMap.cpp, src/engine/ExtentMap.h, tests/BoundsRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S02-U001

### CS3-CH01-S03-U001 — Yerel scalar uninitialized-read kuralını ekle

**Sonuç:** Yerel integer/bool değerinin atama öncesi gerçek okuması yeni experimental kimlikle raporlanır.

**Kabul:**

- int x; return x; ve arithmetic read pozitif; initializer, assignment-first, sizeof ve yalnız adres alma negatiftir.
- Static/thread-local sıfır başlangıcı yanlış bulgu üretmez.
- Pointer-only mevcut kuralın tüm CWE-457'yi kapsadığı iddia edilmez; kuralın kimliği ve registration'ı tutarlıdır.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/UninitScalarRule*, src/analyzer/StaticAnalyzer.cpp, src/main.cpp, src/server/McpServer.cpp, src/core/RuleCapabilities.def, src/core/Capabilities.cpp, src/CMakeLists.txt, tests/UninitScalarRuleTest.cpp, tests/CMakeLists.txt, docs/capabilities.md, README.md, scripts/check_capabilities_sync.py, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py
**Bağımlılıklar:** Yok

### CS3-CH01-S03-U002 — Scalar initialization durumunu CFG birleşimlerinde koru

**Sonuç:** Branch/loop birleşimlerinde definitely-initialized ile possibly-uninitialized ayrılır.

**Kabul:**

- Her iki branch atama güvenlidir; yalnız bir branch atama gerçek okumada bulgu üretir.
- Loop zero-iteration, break/continue ve erken dönüş fixture'ları vardır.
- Kapsam yerel integer/bool'dur; struct/heap/exception tam desteği iddia edilmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/UninitScalarRule*, tests/UninitScalarRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S03-U001

### CS3-CH01-S04-U001 — accept/accept4 descriptor sahipliğini modelle

**Sonuç:** Başarılı accept ailesi çağrısından dönen descriptor için close/transfer/leak takibi yapılır.

**Kabul:**

- Başarı sonrası kapatma, dönüşle ownership transferi ve leak ayrılır.
- −1 hata yolu kaynak yaratmaz; aynı isimli kullanıcı metodu yanlış eşleşmez.
- Mevcut open/socket/dup ve FILE/DIR modelleri korunur.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/FdResourceRule.cpp, src/rules/FdResourceRule.h, tests/FdResourceRuleTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH01-S04-U002 — pipe/pipe2 çift descriptor çıkışını modelle

**Sonuç:** Başarılı iki out-param descriptor bağımsız kaynak olarak izlenir.

**Kabul:**

- Başarıda iki kapatma, tek kapatma ve hiç kapatmama sonuçları ayrılır.
- Hatalı dönüş ve yeniden atanmış out-param sahte ownership yaratmaz.
- İki kaynak tek bulguda kaybolmaz; mevcut descriptor dönüş modeli bozulmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/FdResourceRule.cpp, src/rules/FdResourceRule.h, tests/FdResourceRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S04-U001

### CS3-CH01-S05-U001 — Uzunluk ve index sink'lerinde kanıtlı narrowing kaybını raporla

**Sonuç:** Implicit sayısal daraltmada hedef türe sığmayan kanıtlı aralık sink'e bağlanır.

**Kabul:**

- Exact fit, promotion, explicit intentional cast, enum/dependent ve unknown sınırları açıktır.
- Allocator dışındaki uzunluk/index sink'leri dar kapsamlı fixture'larla sınanır.
- Mevcut signed-overflow/narrowing ile çift rapor üretilmez; genel cast uyarıcısına dönüşmez.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/rules/SignConversionRule.cpp, src/rules/SignConversionRule.h, tests/SignConversionRuleTest.cpp
**Bağımlılıklar:** Yok

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH02 — Güvenilir analiz girdisi ve kapsam
- CH03 — CWE bulgularını kullanılabilir ürüne dönüştürme
- CH04 — Sınırlı kaynakla dayanıklı çalışma
- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
