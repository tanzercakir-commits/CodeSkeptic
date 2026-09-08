# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH08-S01-U001

### CS3-CH08-S01-U001 — Yeni ürün planını ve bitiş sözleşmesini FIFO'ya bağla

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

### CS3-CH08-S01-U002 — Katalog ve capability sözleşmesini eklemeli kanıt sürümlerine hazırla

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

### CS3-CH08-S01-U003 — Gerçek proje girdilerini ve geniş kalite korpusunu önceden dondur

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
**Kapsam:** scripts/product_profiles.py, scripts/product_profiles.json, scripts/test_product_profiles.py, docs/product-quality-contract.md, scripts/product_quality.py, scripts/test_product_quality.py, tests/product_corpus/**, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
**Bağımlılıklar:** CS3-CH08-S01-U002

### CS3-CH08-S01-U004 — Temiz Release profilinde yeni exact-source RED başlangıcını ölç

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

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH09 — Gerçek derleme girdileri ve tam analiz kapsamı
- CH10 — Kanıtlı yanlış alarmları semantik olarak gider
- CH11 — On altı CWE ailesi ve altı yeni CWE için kanıtlı ürün kalitesi
- CH12 — Üç yerel platformda eşdeğer davranış ve dayanıklılık
- CH13 — Aynı kaynaklı Release, güven zinciri ve gerçek kullanıcı akışları
- CH14 — Gerçek yayın onayı, güvenilir dağıtım ve ürün kapanışı
