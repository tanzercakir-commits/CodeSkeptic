# CH08+ ürün kalite ve gerçek bitiş sözleşmesi

Onay tarihi: 2026-09-08. Bu görev hedefleri sonuçlardan önce kaydeder; yeni ürün ölçümleri
henüz yapılmadı, metrikler `null`, G1–G8 ürün PASS durumu **BEKLİYOR**'dur.
Aktivasyon/plan integrity PASS'i analyzer veya release qualification değildir.
[BOOK](BOOK.json) tek yürütülebilir sözleşme, [ürün planı](PRODUCT_COMPLETION_PLAN.md)
onaylı CH08+ insan-okur görünümüdür; eski [kalite protokolü](quality_protocol.md)
ve bütün daha sıkı korumalı profil tabanları yürürlükte kalır.

## Başlangıç ve hedef ayrımı

Aktivasyon kaynak snapshot'ı: 15 public diagnostic, 12 CWE ailesi / 20 unique CWE-ID;
yedi supported CWE ailesi, beş experimental CWE ailesi ve üç report-only project
diagnostic. Hedef: 19 public diagnostic, 16 supported/blocking CWE ailesi / 26 bounded
CWE-ID. Yeni format-string/134, command-injection/78, sql-injection/89, path-traversal/22
önce experimental uygulanır; her biri ayrı exact-source kanıt ve bağımsız terfi
incelemesi olmadan blocking yapılamaz. Mevcut beş experimental terfi de zorunludur.
Bounds'a CWE-121/122 yalnız kanıtlı write overflow ve destination storage provenance ile eklenir.
Üç project diagnostic assumption/contract/policy bilinçli report-only kalır.
[Sınırlar ve resmi öncelikler](market-cwe-priorities.md) bütün-CWE/pazar kabul garantisi değildir.

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


## Paydalar ve ölçüm disiplini

Her aile ve altprofil için TP, FP ve FN occurrence çokluğu ayrı saklanır.
Precision = TP/(TP+FP); addressable recall = TP/(TP+FN). Sıfır payda `null`dır,
geçmiş ölçüm veya sıfır sonuçtan 100% üretilmez. Safe örnekte ilgili aile bulgusu FP'dir;
buggy örnekte eksik beklenen bulgu FN, fazla bulgu FP'dir. Duplicate occurrence ve aynı
fingerprint birleşimi kayıpsız korunur. Aileler arası mikro-ortalama bir aile başarısızlığını gizlemez.

1020 alt sınırı = bounds dışındaki 15 aile × 60 + iki bounds altprofili × 60.
CWE-121 ve CWE-122 altprofilleri birbirinden ayrık kaynak örnekleridir; bunların 120 örneği
bounds ailesinin 30 buggy + 30 safe alt sınırını da sağlar, ek kopyalarla sayım şişirilmez.
Her aile/altprofil >=3 bağımsız kaynak kökeni taşır. Yakın varyantlar bağımsız örnek değildir.
Kaynak-atıflı gerçek security-fix çiftleri yeni dört ailede ayrıca zorunludur; düzeltme
öncesi ve sonrası ilişkinin ground truth gerekçesi tutulur. Ayrı safe kontroller gereklidir.

`unknown` ve `unsupported` seçimden önce gerekçelendirilir; sonuç sonrası kaçış etiketi,
TN veya safe değildir. Kapsam içi çözülmemiş proje unknown'u G2'yi bloke eder. Unknown
akış safe sayılmaz; seçimden önceki addressable buggy örnek yeni miss görüldü diye dışlanmaz.
Crash/timeout/OOM/bozuk veya eksik report/TU failure kalite sayacı değil kapsam/altyapı RED'idir.
Bilinen 47 FP eğitim örneği frozen bağımsız değerlendirme paydasından ayrıdır; eski 10 unknown
kaynak hakemliğiyle çözülür ve dokuz TP korunur. Eski başarısızlar tarihsel RED kalır.

U003 manifesti input/hash/label/API source-sink-sanitizer sınırlarını, üç tekrar ve sayısal
sonlu süre/bellek/process/call-depth/state/iteration bütçelerini ilk yeni ölçümden önce dondurur.
Bu ilk belge sayı uydurmaz ve ölçülmemiş donanım performansı vaat etmez. U004 ancak o freeze
sonrası yeni temiz Release baseline ölçer. Yeni aile yoksa PLANNED_NOT_IMPLEMENTED/RED;
bilinmeyen CLI seçeneğiyle çalıştırılan komut gerçek aile analizi diye raporlanmaz.

### Native API taslağı — henüz dondurulmuş veya kurulmuş model değil

[`native-api-models.json`](../tests/product_corpus/native-api-models.json), manifestin
exact byte hash'iyle bağlı bir seçim taslağıdır: sekiz kaynak rolü ve dört yeni ailede
14 çağrı/argüman rolü. `api-check` yalnız bu taslağın şema, rol ve sınır tutarlılığını
sınar; gerçek header/ABI doğrulaması, Clang veri akışı veya korpus kabulü yapmaz.
Native header closure/hashleri, copy/concat ve C++ overload seçimi, gerçek örnekler ve
bağımsız etiket incelemesi tamamlanmadan U003 için freeze/PASS yoktur.

Argüman indeksleri sıfır tabanlıdır: `printf` format=0, `fprintf`/`sprintf` format=1,
`snprintf` format=2; formatla veri argümanı ayrıdır. Bu roller
[glibc çağrı sözleşmelerine](https://sourceware.org/glibc/manual/2.42/html_node/Formatted-Output-Functions.html)
dayanır; aynı isimli kullanıcı fonksiyonu veya yalnız system-header işareti gerçek
API kimliğini kanıtlamaz. Kimlik, native platform/header/complete signature ve varsa
gerçek callee body ilişkisine bağlanmalıdır; `argv` ise ayrı entry-point modelidir.

SQLite'ta `exec`/`prepare_v2`/`prepare_v3` SQL metni argümanı=1, bind değeri argümanı=2,
SQL parametre numarası ise bir tabanlıdır. [Prepare](https://www.sqlite.org/c3ref/prepare.html)
önceden kurulmuş SQL metnini temizlemez; [bind](https://www.sqlite.org/c3ref/bind_blob.html)
değeri sorgu metninden ayrı taşır ve kaynak string'i diğer kullanımlar için temizlemez.
Bu dar SQL ayrımı lifetime/return-code/all-rule güvenliği veya başka DB desteği değildir.

Shell modeli [POSIX `system`](https://sourceware.org/glibc/manual/2.42/html_node/Running-a-Command.html)
ile [Windows command processor](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=msvc-170)
bağlamlarını ayırır; genel quoting sanitizer değildir. Path modeli önceden kaydedilmiş
restricted-root sözleşmesi ister: sıradan dosya adı, string prefix veya
[canonicalization](https://eel.is/c++draft/fs.op.canonical) tek başına containment değildir.
Platform/path-component kontrolü, başarılı dal ve değişmemiş değer korunur;
symlink/TOCTOU garantisi üretilmez.

Unknown mutation eski doğrulamayı geçersiz kılar. Kısmi okuma/yazma, byte/item sayısı,
sonlandırma, yardımcı fonksiyon ve bütçe sınırları ayrı kalır; metadata negatiflerinin
geçmesi bu davranışların analyzer'da uygulanmış olduğunu kanıtlamaz.

Tam kalite hem isolated aile/subprofile hem all-rule ürün modunda sağlanmalıdır;
eski 52 fixture/124 korumalı input ve ayrı Juliet/thesis/real-world/sanitizer kapıları
bu büyük korpusla değiştirilmez. Katalog sürüm geçişi U002'dir, bu ilk görev değildir.

## Aktivasyon test kaynağı için ileriye dönük tek satırlık successor

Eski snapshot terminal Git nesnesinde ve tüm eski receipt'lerde korunur.
Exact `4fd4a21f9b5dc381ea1ec3014daa3082a9d14e24` →
`3ae794e3f552aa5040b5c12f53082ad14977e3cc` farkı yalnız kuyruk test dosyasına
319 satır ekledi. Bağımsız read-only `/root/market_cwe_architecture`, freeze öncesi
64 eski testin 188 assertion'ı dahil byte/AST eşitliğini, 80 eski function/method'un ve
imports/setup/module AST'nin değişmediğini doğruladı. Yalnız 20 yeni governance negatif/
geçiş testi ve üç fixture helper eklendi. Ürün detector/fixture/label/tier değişmedi.

| Bağlı girdi | Eski SHA-256 | Yeni SHA-256 |
|---|---|---|
| tests/test_project_queue.py | 11c9e2ef8c32d7eb13afb84f02ad206038e68d50f5106560e2e81b5ff7465dc5 | c64cbb55bb2750c5e8be896861418f313d38809fd4be34e69e72f9d5867c1ec6 |
| regression_inventory.json | 8eb0230c7c3135816d9aecf37e8d4351be5e943a151443b26e0309d16a69ac9c | f018bfc0844bec6d12af82f7691fedd1857557852a16a4b970c2dc6e5c1a9e28 |
| catalog.json | ceaf1a23727e5379f55c7fa8baec97e30d29d9897c59f24d543617ba4cfb3681 | ed163a76437f70d4179b05973c3d2566cc8d1f13cbdf01c5eaedf576f53451c8 |

Eski gerçek integrity sonucu `protected input changed: tests/test_project_queue.py`
ile exit 2'dir; sonradan PASS diye yeniden adlandırılmaz. Yeni freeze yalnız bu inventory
satırını ve catalog.inventory_sha256 linkini değiştirir: diğer 123 hash, 52 fixture source,
label, rationale, expected multiplicity, flags, selection base, registry ve bütün floors aynıdır.
Hiçbir expected analyzer çıktısı ölçümden türetilmedi. Bağımsız in-memory successor integrity
kontrolü 124 input / 12 aile / 52 case ve quality_measured=false döndürdü. Uygulanmış durumun
check'i ve exact-head görev review'u ayrıca gerekir; bu kaynak sınıflandırması ürün PASS'i değildir.

## U002 — Eklemeli katalog ve kanıt sürümleri

Native capabilities API `schema_version=2`, report ve measurement v1 semantiği değişmez.
Sürümlenen şey analyzer API değil, `catalog.json` / `regression_inventory.json` girdi
sözleşmesidir. Gerçek seçili schema ve `evidence_version.id` katalogda okunur. Bir v2
adayının hazırlanması, source review veya metadata integrity, ürün terfisi/yayın değildir.
Bu görevde registry gerçekten 15 public diagnostic / 12 CWE ailesi olarak kalır.

`snapshots/terminal-4fd4a21-{catalog,inventory,contract}.json` tam üç izinli metadata
dosyasıdır. İlk ikisi terminal Git nesnelerinin byte-eşit kopyasıdır; üçüncüsü 15
capability'nin tüm bool bayrakları, tier/CWE/açıklamaları, 52/124/96 eski sayımları ve
beş sabit kalite/pin girdisinin SHA-256'sını taşır. Üç dosyanın digest'i validator'da
sabitlenmiştir. U001'in ayrı ed163a7/f018bfc successor kimlikleri de burada korunur;
U001 bytes'ı yanlışlıkla terminal diye etiketlenmez. Başka snapshot dosyası, symlink,
değişmiş metadata veya omitted corpus dosyası kabul edilmez.

`historical-identity` yalnız bu dondurulmuş metadata kimliğini doğrular ve
`current_inputs_verified=false`, `quality_measured=false` döndürür. Eski ölçüm/receipt
yalnız özgün source/binary/catalog/tier bağlamında geçerlidir; yeni HEAD'e bağlanamaz.
Normal `check` v1 dahil her zaman gerçek mevcut dosya/hash/closure denetiminden geçer.
Eski catalog'u yeni input ağacına vermek digest kontrolünü atlatmaz. Tarihsel replay için
özgün Git checkout ve kendi hash'li araç/kanıtları korunur; identity-only modu tarama değildir.

V2'nin content-addressed ID'si bütün catalog gövdesini, tam registry descriptor'larını,
registry digest'ini, exact input path/fixture ID listelerini, önceki catalog/inventory/
version kimliklerini ve source-review metadata'sını bağlar. Yalnız ID'nin kendisi ve
review içindeki aynı payload digest alanı döngüyü önlemek için hash dışında kalır.
Review; exact source-base/head, ayrı implementer/verifier, gerekçe, PASS ve boş bulgu
listesi taşır. Alan tipi, digest veya kaynak kimliği değişirse eski version ID geçmez.
Bu ortak kullanıcı hesabında prosedürel bağımsızlık ve Git geçmişi denetimidir;
imza, kötü niyetli root'a dayanıklılık veya doğrulanmış uzak üretici attestation'ı değildir.
Self-authored/rehashed review metadata bağımsız incelemenin yerine geçemez.

İlk sequence yalnız U001'in tam ed163a7/f018bfc çiftini parent kabul eder; sonraki
sequence önceki content-addressed version ve catalog/inventory digest'lerini belirtir.
Her ileri successor kendi kaynak farkı ve gerçek bağımsız sınıflandırmasıyla hazırlanır;
önceki kaynak/catalog/receipt Git ve kalıcı kanıtta korunur. Validator hash/shape kontrolü
tek başına önceki Git kaydının veya review üreticisinin güvenilirliğini kanıtlamaz;
actual ancestry/source değişikliği ayrıca exact-head bağımsız görev audit'inin kapısıdır.

V2 envanteri eski 124 girdi kimliğini korur; cwe_quality.py,
check_capabilities_sync.py ve test_catalog.py de doğrudan hash'lenir (ilk v2: 127 girdi).
Tam test-tree closure korunur; ileride tests/product_corpus eklemek de yeni exact
inventory/version ister. Eski dosya çıkarılamaz. Beş immutable base dosyası
corpus_expected.txt, juliet_expected.txt, measurement_baseline.json,
realworld_expected.txt ve realworld_manifest.json'dur; bunları birlikte rehash etmek
eski pin veya floor azaltmayı meşrulaştıramaz. Diğer korumalı runner/workflow/test
değişiklikleri yine task scope, source-derived bağımsız sınıflandırma, eski daha sıkı
floor/başarısız kanıt koruması ve fresh qualification gerektirir.

Eski 52 case'in tam kaydı ve sırası prefix olarak kalır: kaynak hash'i, role, expected
multiplicity, flags, origin, rationale ve untrusted sources değişmez. Yeni case yalnız
sonuna eklenir; her current CWE ailesinde buggy/safe çifti gerekir. Planlanmış dört yeni
adı kaydetmek kurulu hale getirmez: version descriptor seti gerçek kaynak registry'siyle
birebir aynı olmalıdır. İzinli büyüme o dört ID ve bounds için 121/122 ile sınırlıdır;
supported eski aile demote edilemez, üç project diagnostic değişmeden report-only kalır.
Native discovery bütün bool bayrakları dahil tam descriptor'a göre karşılaştırılır;
aynı sayıda fake/duplicate/missing/ghost kayıt veya 1/true, float/int benzerliği ret alır.

Ölçüm hâlâ tam seçili tier'ı çalıştırır; unknown/unsupported score dışıdır, aynı
fingerprint'li farklı occurrence çokluğu korunur ve eski sıfır-FP/FN regression kapısı
değişmez. Yeni 0.90/0.70 ürün profili bunun yerine geçmez. Testlerdeki sentetik 16'ncı
capability/terfi yalnız metadata transition positive kontrolüdür; detector uygulaması,
ground truth veya ürün ölçümü değildir. Native testlerdeki mevcut 15/7 beklentilerini
gelecekte değiştirmek ilgili gerçek kural/terfi görevlerinin ayrı source review işidir.

## U003 seçim muhasebesi — henüz dondurulmamış hazırlık

[Yeni sonuç kaydı](product-quality-results.md) gerçek hazırlık ile eksik değerlendirmeyi
ayırır. Şu an yalnız üç upstream kaynak envanteri ve eski occurrence kayıtları doğrulandı;
`scripts/product_profiles.json` DRAFT_NOT_FROZEN'dır. İlk yeni analyzer sonucu yoktur.

Yakın kopya kuralının muhafazakâr uygulaması: semantik cluster global tek kota kredisi
alır; bad/fixed çift üyeleri farklı hash/role diye iki bağımsız örnek sayılmaz.
Zorunlu gerçek çiftler ayrıca supplemental değerlendirmede saklanır, bütün gözlemleri
ve başarısızlıkları görünür kalır ve bağımsız kota-cohort sonucunu düzeltemez. Bu bir
yeni görev kabulü değil, mevcut bağımsızlık şartını sayım şişirmeden uygulama tercihidir.
Kaynak kökeni ve cluster/etiket gerekçesi bağımsız kaynak incelemesi ister; üç keyfi
origin etiketi veya üç farklı repo adresi otomatik üç bağımsız köken değildir.

Ön sayısal bütçeler sonuç kaydında ve LIMITS sözleşmesinde görünürdür; bu görevdeki
gerçek freeze ve bağımsız kabulden sonra sonuçlara bakılarak değiştirilemez.
Ortam kimlikleri ölçüm öncesi gerçekten yakalanıp karşılaştırılmalıdır; eski rolling
hosted image gözlemi replay edilebilir sabit image diye sunulamaz. Eksik kaynak/etiket,
güvenlik-fix incelemesi veya ortam kanıtı task/FIFO kapanışında atlanamaz.
