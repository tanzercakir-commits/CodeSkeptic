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
