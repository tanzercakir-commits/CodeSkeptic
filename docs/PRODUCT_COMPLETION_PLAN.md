# CodeSkeptic — Ürün Tamamlama Planı

Durum: sahibin 2026-09-08 onayladığı CH08–CH14 planı, aynı aktif FIFO'da.
Başlangıç terminali `4fd4a21f9b5dc381ea1ec3014daa3082a9d14e24`; bağımsız incelenmiş
aktivasyon `3ae794e3f552aa5040b5c12f53082ad14977e3cc`. Aktivasyon ürün POP'u değildir.
Önceki 46 kayıt korunur; 51 yeni görevle toplam katalog 97'dir.
Anlık FRONT ve tamamlanmalar yalnız [TODO](TODO.md) / [PROGRESS](PROGRESS.md)'ten okunur;
bu belgede ikinci bir tamamlanma listesi tutulmaz. Bu dosya ürünün tamamlandığı anlamına gelmez.

## “Tamam” ne demek?

Bu sınırlı sürüm için “ürün tamamlandı” ancak mevcut 12 ve yeni 4 CWE tanı ailesi ile CWE-121/122 altprofilleri belirtilen kaliteyi sağladığında,
Linux x86_64 / Windows x64 / macOS arm64 destek profillerinde aynı temiz ürün kaynağından paketlenip
güvenilir yayıncı kimliğiyle imzalandığında, sahibin açık onayıyla gerçekten yayımlandığında ve
public indirmeden gerçek kullanıcı akışları doğrulandığında söylenir. Son görevde bağımsız PASS ve
gerçek FIFO kapanış denetimi zorunludur. Yerel paket, draft release, eski CI veya yalnız ölçüm yapmış
olmak bu yeni bitişin yerine geçmez.

Başlangıçta 15 public diagnostic vardır: **12 CWE-bearing aile** ve CWE olmayan
`assumption`, `contract`, `policy`. Sahibin son piyasa önceliği isteğiyle hedef
**19 public diagnostic = 16 CWE ailesi + 3 project diagnostic** olur.
Dört yeni aile `format-string` (CWE-134), `command-injection` (CWE-78),
`sql-injection` (CWE-89) ve `path-traversal` (CWE-22)'dir.
`bounds` ailesi kanıtlı stack/heap taşmaları için CWE-121/122 alt türlerini de kazanır.
Mevcut 20 benzersiz CWE eşlemesi korunur; altı yeni ID ile hedef 26'dır. Bu bir
tam-CWE veya her örneği tespit etme iddiası değil, kesin API/semantik sınırları olan coverage sözleşmesidir.

Beş mevcut experimental CWE ailesinin terfisi ve dört yeni ailenin **ayrı experimental
uygulama → bağımsız ölçüm → supported/blocking terfi görevleri** zorunludur.
Üç project diagnostic bilinçli report-only davranışını korur.
Destek yalnız açıkça belgelenmiş input/semantik sınırlar içindir.
“Tüm CWE'ler”, bütün C/C++ programları, sıfır gelecekteki hata, IDE/cloud ürünü,
sınırsız whole-program taint/race motoru ve sınırsız OS/SDK desteği vaat edilmez.
Yeni sınırlı string-origin/source-to-sink analizi ise artık açık uygulama kapsamıdır;
eski `injection-taint: out-of-scope` beyanı yalnız bu kanıtlanmış altkapsam için güncellenir.
Yeni keşifler scope içindeyse ilgili görevde çözülür; kapsam dışı keşifler kontrollü
plan önerisidir, sessiz ek iş değildir.

## Piyasa açısından anlamlı CWE öncelikleri

2026-09-08'de resmi Top25 ana sayfasında güncel liste **2025** sürümüdür.
Aşağıdaki seçim, gerçek risk öncelikleri ile C/C++ analiz edilebilirliğinin birleşimidir;
ticari talep, satış başarısı, sertifikasyon veya bütün Top25 desteği kanıtı değildir.
Kaynaklar: [MITRE Top25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html),
[MITRE KEV Top10](https://cwe.mitre.org/top25/archive/2025/2025_kev_list.html),
[resmi CWE-134](https://cwe.mitre.org/data/definitions/134.html).

| Ek / yatırım | Resmi öncelik ve ürün karşılığı |
|---|---|
| CWE-78 — OS command injection | Top25 #9, KEV #1. Network appliance/native helper için shell-string source-to-sink kanıtı. |
| CWE-22 — Path traversal | Top25 #6, KEV #6. Açık restricted-root sözleşmeli dosya/çıkarma iş akışları; sıradan user filename alarm değildir. |
| CWE-89 — SQL injection | Top25 #2. İlk somut C/C++ API profili SQLite SQL-text/bound-parameter ayrımıdır; bütün DB/ORM'ler vaat edilmez. |
| CWE-121 / CWE-122 — Stack/heap taşması | Top25 #14/#16; heap KEV #9. Bounds'taki gerçek overflow-write + destination provenance kanıtı; etikete göre sayım şişirme yoktur. |
| CWE-134 — Uncontrolled format string | 2025 Top25/KEV Top10'da olduğu iddia edilmez. Resmi tanımı C/C++ format-argument source-to-sink analizi için somut, ölçülebilir bir ek yüzeydir. |
| Mevcut memory safety yatırımı | CWE-787/416/125 zaten Top25 #5/#7/#8'dir. Var olan motorun doğruluğu yeni aile sayısı uğruna ikinci plana atılmaz. |

[Resmi CWE-78](https://cwe.mitre.org/data/definitions/78.html),
[CWE-22](https://cwe.mitre.org/data/definitions/22.html) ve
[CWE-89](https://cwe.mitre.org/data/definitions/89.html) semantik sınırları kaynak/sink/sanitizer
sözleşmelerini yönlendirir. Her yeni sonuçta kaynak→yayılma→sink izi, doğru CWE ve pratik düzeltme
açıklaması gerekir. Sahte “nonliteral == vulnerable” yaklaşımı kabul edilmez.
CWE-121/122 için [stack](https://cwe.mitre.org/data/definitions/121.html) /
[heap](https://cwe.mitre.org/data/definitions/122.html) ayrımı destination nesnesinin gerçek
saklama kökenine bağlıdır, pointer değişkeninin local olmasına değil.

XSS/CSRF/authentication/authorization gibi web/framework bağlamı gerektiren Top25 maddeleri
yalnız listede üstte diye bu sürüme eklenmez. Bunlar ancak ayrı framework/trust-boundary sözleşmesi
ve test verisiyle gelecekteki kontrollü plan konusu olur. Bu sürümün veri-akışı sınırı:
intraprocedural locals + modellenmiş copy/concat ve sonlu TU-local doğrudan helper özetleri;
indirect/virtual/dış-TU/persisted string taint, keyfi container/heap graph ve symlink/TOCTOU garantisi yoktur.
Call-depth/state/iteration tavanları ölçümden önce dondurulur. Bilinmeyen akış “safe” yapılmaz.

## Kanıtlı başlangıç ve giderilecek açıklar

Bunlar eski ölçümün bulgularıdır; yeni HEAD/binary ölçümü değildir. Kaynak:
[tarihsel release-checklist](release-checklist.md#candidate-limits-and-publication-boundary),
[capabilities](capabilities.md).

- `c4fa60864f2e5853581c2f8a0dd66a3fc967239b` ölçümünde üç projede toplam **47 kanıtlı FP,
  10 belirsiz, 9 TP occurrence** vardır. Bunlar sonuç gizleyerek değil kaynak temelli düzeltme/hakemlikle kapatılır.
- Eski cJSON inferred lane'i 34/76 analyzed TU ve 42 hatalı input içerir; bu sayılar 42 analyzer crash değildir.
  Gerçek upstream build hedefleri ayrı authentic lane'de %100 seçilmiş komut varyantı ile ölçülür.
  GoogleTest'in eski dört library TU sonucu tam upstream test kapsamı diye adlandırılmaz.
- Eski ölçülmüş Linux ve native Windows/macOS paketleri farklı source/build kimliklerine aittir;
  tek Release source/artifact seti olarak yeniden qualification gerekir.
- Native testlerde OS prerequisite/SKIP farkları ve unsigned/not-notarized dağıtım sınırları vardır.
- Eski release workflow'unda tag otomatik-yayın ve force-push ref-writer yolları vardır;
  herhangi bir yeni tag'den **önce** güvenli candidate/yayın ayrımı yapılmalıdır.
- Mevcut eşikler tarihsel profillere aittir (örneğin memory-leak legacy precision floor 0.85);
  aşağıdaki 0.90/0.70 kapısı mevcut başarı gibi değil **yeni ve daha sıkı hedef** olarak kaydedilir.

## Sonucun önceden tanımlı sekiz kapısı

| Kapı | Zorunlu kabul |
|---|---|
| G1 — Girdi ve kapsam | cJSON 1.7.18, tinyxml2 10.0.0, GoogleTest 1.14.0 için önceden dondurulmuş gerçek upstream hedeflerinde %100 compilation-command varyantı; failed/skipped/recovery TU ve incomplete function sıfır. Sahte komut veya sonuç sonrası payda küçültme yok. |
| G2 — Bilinen ürün gürültüsü | 47 eski kanıtlı FP sıfır, 10 belirsiz source-ground-truth ile çözümlenmiş ve gereği uygulanmış, 9 eski TP kayıpsız. Yeni seçilmiş authentic yüzeyin bulguları da hakemli; ürün kapsamındaki açıklanmamış unknown kapatmayı engeller. |
| G3 — On altı CWE ailesi | Her aile için en az 30 bağımsız buggy + 30 safe frozen örnek; bounds içindeki CWE-121/122 için ayrı 30+30 altprofiller. Toplam en az 1020 benzersiz kaynak, her aile/altprofilde >=3 köken; precision >=0.90, addressable recall >=0.70, safe FP=0. Eski daha sıkı floors ve all-rule modu ayrıca geçer; eski beş ve yeni dört experimental terfi zorunludur. |
| G4 — Native dayanıklılık | Linux x86_64, Windows x64, macOS arm64 native full test/negatif/worker/cache/checkpoint kanıtı; Linux ilgili sanitizer slice. Gerçek OS-N/A ölçüm öncesi ayrı tanımlanır ve PASS sayılmaz; desteklenen davranışın karşılığı gerçekten çalışır. |
| G5 — Tek kaynaklı Release | Temiz aynı SOURCE commit ve doğru tag/version'dan üç Release artifact; source/tree/toolchain/SDK/flags/binary/archive hashleri, kurulum/relocation/runtime bağımlılık testleri. Eski dev binary yeniden damgalanmaz. |
| G6 — Dağıtım güveni | Üç platform SBOM/provenance/lisans kapsamı; Linux doğrulanabilir publisher-signed manifest, Windows Authenticode, macOS Developer ID + notarization. İmza ve değişmiş artifact negatifleri gerçekten ret. Kanıtsız SLSA/reproducible iddiası yok. |
| G7 — Kullanıcı ve bütçe | Aynı candidate/published artifact üzerinden native install/doctor/first scan/JSON/SARIF/report-only/policy-delta, container ve gerçek hosted consumer Action. Önceden sabit sonlu kaynak/süre profillerinde en az üç tekrar; buildtree fallback/gizli download yok. |
| G8 — Gerçek dağıtım ve kapanış | Exact source/tag/signing için owner yetkisi ve ayrıca kesin signed manifest için public yayın onayı; gerçek public release, public download doğrulaması ve bütün 51 görevin exact-head bağımsız PASS + POP/ledger + terminal audit kapanışı. Eksik yetki/credential yerel fallback ile DONE olamaz. |

Precision, addressable recall, safe/buggy/unknown/unsupported ve occurrence/fingerprint paydaları
CH08'de sonuçlardan önce tanımlanır. Bilinen FP düzeltme örnekleri yeni bağımsız değerlendirme
paydasına karıştırılmaz; örnek kökenleri/ground-truth gerekçeleri saklanır. Korpus makul çeşitlilik
ölçümüdür, pazar geneli temsil iddiası değildir. Etiket hatası bulunursa eski başarısız sonuç korunur;
bağımsız gerekçe + kontrollü ileriye dönük yeni profil ve yeniden baseline gerekir; sessiz fixture değişimi yoktur.

Başlangıç platform sözleşmesi mevcut ölçülebilen Ubuntu 24.04 x86_64, Windows Server 2025 x64
MSVC/Windows SDK ve macOS 14 arm64 Darwin 23/CLT profilleridir. Gerçek runner image,
compiler, SDK ve dependency sürümleri CH08'de manifestte dondurulacak; başka OS desteği ilan
edilirse ayrı gerçek qualification gerekecektir. macOS'un raw-byte adı oluşturmayı reddetmesi
başarılı test olarak sunulmaz. Kernel address-space/data ceiling, RSS ceiling diye adlandırılmaz.
Sayısal süre/bellek/process/cold-warm bütçeleri ilk yeni ölçümden **önce** kaynak profiline bağlanır;
sonuç görüldükten sonra gevşetilemez.

## FIFO, belgeler ve uygulama düzeni

Yeni insan-okur planı bu dosyadır: `docs/PRODUCT_COMPLETION_PLAN.md`.
Eski PLAN'ın exact terminal içeriği `docs/archive/CWE_RESTART_PLAN_2026-09-08.md` altında korunur.
`docs/BOOK.json` tek yürütülebilir sözleşme; `docs/PLAN.md` tam üretilen katalog,
`docs/TODO.md` tek aktif FIFO, `docs/PROGRESS.md` tarihsel tamamlanma kaydı olmaya devam eder.
İkinci elle tutulan TODO yoktur. Yeni plan/BOOK ID ve kabul eşleşmesi otomatik denetlenir.

Her görev yalnız FRONT iken kendi `agent/<task-id>-<slug>` dalında uygulanır.
Önce contract/queue check, varsa RED, dar uygulama, bütçesine uygun GREEN, exact-head read-only
bağımsız PASS, sonra üç ledger dosyasının POP commit'i ve transition check; ancak ardından sonraki dal.
Görev değişince eski PASS kullanılamaz. Helpers yalnız primary'nin bounded read-only soruları
veya izinli ayrı workspace göreviyle çalışır; doğrulayıcı yazmaz/yayımlamaz.
Ana dal, arşivler, eski 46 sözleşme ve receipt'ler korunur.

T0 = docs/Python/queue; T1 = focused component + gerçek CLI smoke;
T2 = Linux suite + ilgili corpus; T3 = belirtilen gerçek release/native/hosted profili.
Görev JSON'undaki test adı tek başına PASS değildir: acceptance içindeki bütün kanıtlar check receipt'ine bağlanır.
Scope listeleri başlangıç izinleridir; mevcut dosyalarla birlikte bilerek yeni dosya hedefleri de içerir.
Eksik gerekli exact path olağan independently-reviewed extend-scope ile eklenebilir; outcome/eşik/FIFO değişmez.
Korunan yönetişim dosyaları normal ürün görevi scope'u ile değiştirilemez.

Bugünkü corpus validator bütün test ağacını hash'ler ve 15 capability/12 CWE ailesine bağlıdır.
Bu nedenle ilk normal CH08 görevi aktivasyonun test dosyası değişikliğini bağımsız sınıflandırmalı
prospective inventory successor ile uzlaştırır; ardından CH08-S01-U002 ayrı eklemeli katalog/evidence
sürüm görevini tamamlar. Eski 52 fixture ve bütün eski floors/receipts korunur. Yeni/eksik/farklı
registry/test/metadata sırf sayı kontrolü kaldırılarak kabul edilmez. Sonraki task'a özgü değişiklikler
yalnız bu sürümlü, kaynak-farkı kanıtlı successor'larla ilerler; frozen değerlendirme seti bundan
ayrıdır ve aynı izinle düzenlenemez.

## Kaynak dondurma ve dış bağımlılıklar

CH14 RC aşamasında ürün SOURCE ayrı sabitlenir. Sonraki evidence/ledger HEAD'leri SOURCE ile
karıştırılmaz. Yalnız paketlenmeyen açık allowlist receipt/ledger değişiklikleri ilerleyebilir;
ürün/build/workflow/pakete giren doküman değişikliği yeni SOURCE, fresh pre-sign teknik qualification ve yeni onay demektir.
Tag imzalama sonrası archive hashleri değişeceğinden final signed set ayrıca yeniden qualified edilir.

Kapıların FIFO sırası açıkça ayrıdır: CH14-S01-U001 **pre-sign RC** yalnız G1–G4, G7 ve
G5'in candidate build/source/version ön kontrollerini kapatır. G5'in gerçek tag bağı ve
G6'nın actual publisher imzası/notary kanıtı o noktada **BEKLİYOR**'dur; validator dry-run
bu kapılara PASS vermez. CH14-S01-U002 exact-source/tag/signing yetkisini alır.
CH14-S02-U001 gerçek tag build + imza/notary sonrasında **tam G1–G7**'yi kapatır.
CH14-S02-U002 kesin signed manifest için public onay/yayını yapar; CH14-S02-U003
public tüketici doğrulaması ve terminal denetimle **G8 dahil bütün kapıları** kapatır.
Bu ayrım final G5/G6 şartını düşürmez; signing yetkisi gelmeden gerçek signing isteme
döngüsünü önler.

Owner signing kimlikleri/hesapları, native runners veya yayın yetkisi yoksa ilgili FRONT bloke kalır.
Plan bunları elimizde varsaymaz, secret istemez veya maliyetli hesap açmaz.
Teknik görevler sonuçsuz kalırsa eşikleri/scope'u düşürmek yerine açık failure kanıtı ve kontrollü
gelecek plan kararı gerekir. “Bütün görevler yeşil olsun” amacı kalite tabanını düşürme yetkisi değildir.


## Onaylı bölüm / section / atomik görev sözleşmeleri

Aşağıdaki bloklar aktivasyondaki BOOK'tan birebir üretilmiştir; yalnız CH08+ içerir.
`python3 -B scripts/product_completion_plan.py check` ID, outcome, acceptance, scope,
checks, bütçe ve sıralamayı otomatik denetler; eski 46 sözleşme/receipt, PROGRESS
bölümleri ve kanıt dosyası hashlerini de doğrular. `render` yalnız stdout üretir;
hiçbir dosyayı veya kuyruğu güncellemez. Bu kontrol ürünün çalıştırıldığı anlamına gelmez.

Gösterilen scope ilk onaylı kapsamdır. Sonradan gerekli exact file eklenirse ayrı
bağımsız scope-review kararı BOOK'ta korunur; denetçi bu karar zincirini kontrol ederek
ilk kapsam + yalnız onaylı eklerin güncel BOOK ile eşitliğini sınar. Gövde/kabul/eşik
ve FIFO değiştirilemez. Bu belgeye elle yeni TODO veya tamamlanma işareti eklenmez.

<!-- BEGIN APPROVED PRODUCT CONTRACTS -->

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
**Kapsam:** scripts/product_profiles.py, scripts/product_profiles.json, scripts/test_product_profiles.py, docs/product-quality-contract.md, scripts/product_quality.py, scripts/test_product_quality.py, tests/product_corpus/**, docs/product-quality-results.md, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json
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

<!-- END APPROVED PRODUCT CONTRACTS -->
