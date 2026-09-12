# CH08+ ürün ölçümleri — henüz freeze veya ürün PASS'i yok

U003 çalışması devam ediyor. Yeni analyzer baseline'ı çalıştırılmadı; G1–G8
ürün sonuçları **BEKLİYOR**. [BOOK](BOOK.json) tek görev durumu kaynağıdır;
bu belge ikinci TODO veya tamamlanma kaydı değildir.

## Şu an gerçekten doğrulanan hazırlık

- cJSON 1.7.18: 216; tinyxml2 10.0.0: 273; GoogleTest 1.14.0: 245 dosya.
  Toplam 734 kaynak dosyasının exact SHA-256/size ve tam dosya kümesi yerelde
  tekrar doğrulandı. Bu, CMake configure/build, command coverage veya analiz değildir.
- Eski `c4fa60864f2e5853581c2f8a0dd66a3fc967239b` ölçümünün ham raporları,
  kaynak hakemliği ve başvurulan gerçek kaynak byte'ları yeni tarihsel indeksle
  karşılaştırıldı: 47 FP, 10 unknown, 9 TP. cJSON'daki 54 occurrence / 53
  fingerprint korunur; diğer projeler tinyxml2 9/9, GoogleTest 3/3'tür.
- Tarihsel indeks yeni değerlendirme örneği değildir. On unknown'un yeniden
  hakemliği ve 47 FP'nin giderilmesi ileriki görevlerdir; burada sonuçları değişmedi.
- Yeni arithmetic/manifest unit testleri sentetik harness testidir. Bunların
  başarısı gerçek analyzer precision/recall, üç köken veya örnek kotası kanıtlamaz.

`scripts/product_profiles.json` açıkça **DRAFT_NOT_FROZEN** durumundadır.
`readiness` eksik veride exit 2 döndürür; `sources-check` ve
`historical-check` yalnız adlarındaki dar sınırı doğrular. Korumalı CWE inventory
şu anda eklenen tarihsel indeks yüzünden expected RED'dir; eski inventory veya
catalog sessizce yenilenmedi. Stable kaynak ve tam seçimden sonra ayrı bağımsız
source-derived successor sınıflandırması gereklidir.

## Kısmi bağımsız kaynak seçimi — tam değerlendirme henüz dondurulmadı

Bağımsız karar ile seçilmiş kaynak: **1 / en az 1020** — tek GCC memory-leak buggy
örneği, tek köken ve tek global cluster. Bu, frozen değerlendirme paydası değildir.
[Bağlı seçim kaydı](../tests/product_corpus/selection.json) ve aşağıdaki yeni
source-admission bölümü geçerli kısmi durumu taşır. Kaynak seçimi,
bağımsız etiket/semantik cluster incelemesi ve dört yeni ailede zorunlu gerçek
security-fix çiftlerinin incelenmesi bitmedi. Bu eksiklik fixture çoğaltma,
köken yeniden adlandırma veya unknown'u safe sayma yoluyla giderilemez.

Aşağıdaki eski head/kanıt kayıtlarının **0/1020** sayıları o kayıtların tarihsel
durumudur; held incelemeler veya native v1 gözlemleri geriye dönük değiştirilmez.

Kaynak havuzu ayrı, kabul edilmiş değerlendirme ayrı tutulur. Mevcut tam NIST
Juliet 1.3 arşivi tek türetim kökenidir; template/type/flow-number varyantları
bağımsız örnek sayılmaz. CodeQL'nin bazı testleri de Juliet türevidir; farklı
repo adı ikinci köken yapmaz. LLVM/CodeQL warning beklentileri ayrıca kaynak
hakemliği olmadan ground truth değildir. [NIST arşiv kimliği ve lisans sınırı](https://samate.nist.gov/SARD/test-suites/112),
[CodeQL köken uyarısı](https://github.com/github/codeql/tree/main/cpp/ql/test/query-tests/Security/CWE).

Seçimde tek semantik cluster'a global olarak en fazla bir kota kredisi verilir.
Dar bad/fixed çiftleri aynı cluster/kökeni paylaşır; zorunlu çiftler en güvenli
muhasebeyle ayrı supplemental değerlendirmede tutulacaktır. Supplemental
sonuç/başarısızlıkları görünür kalır, kota açığını veya kota-cohort metriklerini
kapatamaz. Benzerlik taraması sadece adayları işaretleyebilir; hash veya bir
cluster ID, bağımsızlık ve etiket doğruluğunun kendi başına kanıtı değildir.

İncelenen iki LLVM adayının kaynak/uyarlama/lisans hashleri ve dar etiket gerekçeleri
[`selection-record.json`](../tests/product_corpus/candidates/selection-record.json)
içindedir. Ayrı read-only kaynak incelemesi receiver-after-delete adayının mevcut
`MethodCallReceiver_AfterFree_StillUAF` eğitim örneğinin semantik tekrarı olduğunu
saptadı: bağımsız kotadan dışlandı. Derived-return/matching-delete adayı daha
sonraki standalone kaynak hakemliğinde memory-leak ailesi için safe, ancak
eğitim yakın varyantı nedeniyle supplemental/nonquota bulundu. İkisi de analiz edilmedi ve **0/1020**
sayısı değişmedi. GCC 16.1.1 ile C++17 syntax-only kontrolü ürün ölçümü değildir.

Tarihsel indeksin manifestteki exact yol/hash bağı artık manifest okuyan profile CLI
komutlarında gerçek byte'lara karşı sınanır. Eksik/değişmiş/symlink indeks ve
geçersiz manifest bağı reddedilir; aynı JSON'a eklenen boş satır da hash farkıdır.
Bu ret testleri ve kaynak hazırlık testleri başarılı olsa da U003 bitmiş değildir.

Native API taslağı da manifestte exact hash'e bağlandı: sekiz source rolü ve dört
yeni ailede 14 sink/argüman rolü. Yeni `api-check`, şema ve bu rollerin tutarlılığını
denetler; `installed=false`, `native_headers_verified=false`, `product_qualified=false`
çıktıları bilinçlidir. Fake API, yanlış argüman/signature/platform, genel sanitizer,
unknown'u safe sayma, değişmiş bütçe ve root/containment karışıklıklarının metadata
negatifleri eklendi. Bu testler analyzer davranışı değildir. Copy/concat/C++ overload
seçimi, gerçek header/ABI kanıtları ve bağımsız örnekler hâlâ tamamlanmalıdır.

Zorunlu dört yeni ailenin gerçek security-fix çiftlerini araştıran dış araç
güvenlik engeli döndürdü; aynı istek başka araç veya ajan üzerinden tekrarlanmadı.
Kaynak erişimi ve bağımsız inceleme tamamlanmadan bu zorunlu kabul karşılanamaz.
Bu engel, başka bir FRONT'a geçme veya kabulü azaltma yetkisi değildir.

## Gerçek upstream yüzeyinin taslağı

Yeni taslak native static/default-all CMake grafiğini seçer: cJSON'da utils ve
native testler; TinyXML2'de library/xmltest; GoogleTest'te gtest/gmock testleri,
helper/exception/RTTI/shared-link varyantları ve on native sample hedefi.
cJSON `ENABLE_FUZZING=OFF` olsa da testler açıkken oluşan `fuzz_main` ayrı seçili
native-driver grubudur. AFL ve root grafiği dışındaki ancillary generator/example
yüzeyleri ayrıca açıklanır. Gerçek configure henüz yapılmadığı için herhangi bir
TU/command sayısı veya tam coverage iddiası yoktur.

Orijinal CMake compilation-command kayıtları ve target/configuration kimlikleri
korunacaktır; aynı source'un farklı komutları birleştirilmez. Eski inferred
76-source cJSON profili, yeni authentic profil diye yeniden adlandırılmaz.

## Ortam ve süre sınırları

Taslakta üç tekrar; case başına 30 saniye, tam upstream project profili başına
1200 saniye ve tüm campaign için 43200 saniye sonlu üst sınır seçildi.
Bu seçim tam test/sample grafiği için ilk yeni sonuçtan önce yapıldı;
ölçülmüş performans veya piyasa latency vaadi değildir. Linux harness: 2 CPU,
6144 MiB RAM, toplam RAM+swap 12288 MiB, 256 PID ve 1024 MiB tmpfs.
Worker: 120000 ms / 2048 MiB; native bellek semantiği platforma göre ayrıdır.
String-flow taslağı: doğrudan call-depth 4, function başına 256 state ve 65536
transfer adımı. Bütçe aşımı incomplete/unsupported; safe veya temiz sonuç değildir.

Tarihsel hosted image sürümleri tekrar seçilebilir immutable VM pinleri değildir.
Gerçek compiler/SDK/package kimliği ve resource sınırlarının realization/readback
kanıtı ölçümden önce ayrıca gerekir. Eksik SDK hash'i tahmin edilmez; rolling
runner label veya eski successful job yeni ortamın kanıtı sayılmaz. Hiçbir eski
measurement, yayın veya imza bu taslakta güncelmiş gibi gösterilmez.

### Native kimlik toplayıcısının yerel hazırlığı

U003 kapsamına üç kesin yol, bağımsız scope incelemesi ve yalnız BOOK/PLAN/TODO
değiştiren `8f0f243` geçişiyle eklendi. Geçişin kendisi ve dokuz scope negatif/geçiş
testi bağımsız doğrulandı; PROGRESS, 48 bitmiş kayıt, FIFO ve main korunur.

Yeni collector sabit header dependency probe'ları ve kurulu araç metadata'sını
okur; kurulum, analyzer build/run, ürün ölçümü veya kabul edilmiş korpus eklemez.
İlk arayüz yokluğu RED'i ardından yerel testler geçmiştir. Geliştirme sırasında
Mac SDK sürüm sorgusunu başka komutla etiketleme, sürüm yerine yol, yanlış SDKSettings
yolu, boş Windows OS kaydı ve tutarsız UCRT ortamı için beş RED kontrolü ayrıca
üretildi; düzeltme sonrasında reddedilirler. Windows/macOS şema testleri sentetiktir,
o sistemlerin SDK/ABI davranışının gerçekten çalıştığı iddiası değildir.

`14e1bac` bağımsız reader incelemesinde dört tutarsız kayıt kabul edildi: ilgisiz
Linux package-query komutu, seçili toolset dışı MSVC, C/C++ arasında aynı header için
çelişkili hash ve seçili Xcode'a rağmen atlanmış version sorgusu. Bu head'in incelemesi
başarısızdır; 114 geçen test bunu PASS'e çevirmedi. Dört odaklı RED ve ek alias/prefix/
CLT kontrolleri ardından reader bağları düzeltildi; yeni exact-head inceleme gerekir.
Kanıt runner'ındaki ayrı `ready_to_freeze`/`task_ready` marker hatasının başarısız
attempt'i de korunur; bu yardımcı hata analyzer veya ürün regression'u değildir.
`85a4d7a` incelemesi ayrıca bir resolved hedefin başka kayıtta alias olabildiğini
buldu. İki karşılaşma sırası ve eşit/farklı içerik için dört RED korunur; tek ortak
logical/resolved kimlik tablosu ve gerçekçi safe-alias kontrolleriyle düzeltildi.
Bu ikinci başarısız inceleme de sonradan PASS diye etiketlenmez.

`ef2dd8c` alias düzeltmesi bağımsız kısmi incelemede bulgusuzdur; bu U003 PASS'i
değildir. Ayrı portability incelemesi Git-clean CRLF checkout'un aynı HEAD altında
farklı helper byte hashleri üretebildiğini belirledi. Dört kaynak dosyası için bu
durum ayrı, gerçek geçici Git depolarında RED olarak üretildi; collector artık
çalışma dosyasını doğrudan HEAD blob hash'iyle de karşılaştırır. Workflow checkout
öncesinde CRLF dönüşümünü kapatır. İlk test düzeneğinin temiz-index koşulunu
sağlayamayan denemeleri bu RED kanıtı değildir. Native Windows çalışması ayrıca gerekir.
Her lane test ve capture için aynı açık Python yolunu kullanır; Windows yolu
vcvars PATH değişiminden önce seçilir. Python 3.10 altı ortam baştan reddedilir.

`8890413` bağımsız kısmi incelemesinden sonra yalnız U003 feature dalı normal push
ile gönderildi; main değişmedi. İlk gerçek metadata çalışması
[`34286039331`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34286039331)
başarısızdır: Ubuntu gözlemi başarılı, macOS ve Windows aynı pozitif CLI testinin
kanonik olmayan geçici dosya yolunda durmuştur. Bu iki lane native capture'a
ulaşmamıştır. Ham run/job/log ve Ubuntu ZIP/JSON kanıtları exact head/run-attempt'e
bağlı saklandı; özet SHA-256
`c6b70e7cfda7363329da4b16a3d0d058676cd69159e50fd2c9087e3ba9d13e7a`.
İlk ham-log retention denemesinde gh terminal-escape koruması durdurdu; bu ayrı
yardımcı hata da korunur, CI başarısızlığının nedeni olarak gösterilmez.

Geçici dizin alias'ı ile yerelde aynı pozitif-test RED'i üretildi. CLI testleri
artık gerçek kanonik geçici yolu kullanır; reader'ın alias/overwrite ret koşulları
gevşetilmedi. Yanlış qualification negatifi ayrıca ret nedenini doğrular; yanlış
bir yol nedeniyle erken reddi ürün-güvence kanıtı saymaz. Bu düzeltmenin sonraki
hosted denemesi aşağıdadır; eski başarısız run daha sonra PASS diye etiketlenmez.

Workflow sadece kurulu Clang'ı gözler; LLVM-20/nihai API modeline seçildiği veya
native qualification geçtiği varsayılmaz. SQLite dependency'si, tam compiler
runtime closure'ı, gerçek korpus ve dondurulmuş ortam karşılaştırması bu hazırlıkla
tamamlanmış sayılmaz. Otomatik genel CI sonuçları bu dar metadata gözleminden ayrıdır.

`533cc11` test düzeltmesinin bağımsız kısmi incelemesi ardından ikinci gerçek
[`34286875317`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34286875317)
metadata çalışması yapıldı. Sonuç yine **FAIL**: Ubuntu ve macOS gözlemleri başarılı,
Windows 34 testten sonra gerçek capture sırasında `unsupported dependency escape`
ile durdu. Windows artefact'i yoktur; o hatanın tam dependency stdout'u tutulmadığı
için hangi bayt dizisinin tetiklediği gözlendi diye iddia edilmez. Saklanan ikinci
paketin özet SHA-256'sı
`5a1f00d21ec5bd68a47383f2f8b64921c948eb6ab8e2115646977604d7908e28`;
run/attempt/source ve iki artefact bağı bağımsız denetlendi.

Ubuntu'da GCC/G++ 13.3 yanında probe Clang 18.1.3 ve libstdc++14 header'ları seçmiştir
(64 C, 272 C++). macOS arm64 14.8.9 gözlemi seçili Xcode 15.4 / Apple Clang 15.0.0 /
SDK 14.5 ile 146 C ve 890 C++ header kaydı içerir. Ayrı kurulu CLT 16.2 seçili
developer directory değildir. Mac hashleri `/usr/bin/clang` giriş noktalarını ve
seçili header/SDKSettings dosyalarını kapsar; gerçek Xcode compiler/runtime closure'ı
veya bütün SDK/ABI yeterliliği diye sunulmaz. Hiçbiri LLVM-20 ürün profili değildir.

Bağımsız kaynak incelemesi [LLVM 20.1.8 dependency writer](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/Frontend/DependencyFile.cpp#L292-L378)
içinde normal Windows backslash ayraçlarının literal yazıldığını doğruladı. Reader
bu geçerli biçimi reddediyordu. Literal drive/UNC, backslash-run/space/#/dollar ve
LF/CRLF regresyonlarıyla düzeltilir; belirsiz trailing-backslash/tab adları bu dar
regular-header altkümesine alınmaz. Harf büyüklüğü değişen aynı Windows yolu için
ayrı duplicate RED'i de kapatıldı. Bu kaynak-format kanıtı kaybolan stdout'un
yerine geçirilmez; yeni gerçek Windows gözlemi gereklidir.

### Üç platformda başarılı gözlem, henüz ürün yeterliliği değil

`b5579bc` parser düzeltmesi bağımsız kısmi incelemeden geçti: 129 test, ek 60
writer-tabanlı dönüş kontrolü ve önceki Ubuntu/macOS metadata uyumluluğu doğrulandı.
Üçüncü gerçek çalışma
[`34288222384`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34288222384)
aynı exact kaynakta Ubuntu, macOS ve Windows lane'lerinde **SUCCESS** döndü. Üç
JSON/ZIP, run/job/log ve kaynak/attempt bağları saklandı; özet SHA-256
`1e7c1e7ca8b504a963f731e11fc39997d383ffdec177051e3543ef1085765fc1`.
Bağımsız kanıt incelemesi üç ZIP/API/upload bağını, 22 saklanan dosya hash'ini,
exact kaynak kimliğini ve her lane'de geçen 39 testi doğruladı. Windows gözlemi
VS 18.9.12112.369, MSVC 19.51.36256, Clang 20.1.8 ve SDK/UCRT 10.0.26100.0;
188 C ve 427 C++ header kaydı içerir. MSVC toolset directory sürümü 14.51.36231,
compiler sürümüyle aynı alan değildir. Driver hashleri c1/c1xx/c2/link/runtime DLL
kapanımını kapsamaz; Linux shared-library bağımlılıkları da bu gözlemin dışındadır.

Üçüncü Ubuntu image'ı `20260907.300.1`, OS kaydı 24.04.5 LTS olmuştur; önceki
image/OS/os-release hash'iyle aynı değildir. Compiler/package/probe/header
kayıtları aynı kalmıştır. macOS native kayıtları aynı kalmıştır. Rolling image
etiketleri için immutable replay veya bütün ortamın değişmediği iddiası yoktur.
Bu yalnız kurulu araç ve seçili header kimliklerinin toplanabildiğini gösterir.
`native_qualified`, `product_qualified` ve `immutable_image` hâlâ false'tur.
Önceki iki başarısız gözlem aynı sonuçla korunur; yeni başarı onların yerine geçmez.

Ayrı genel Linux CI'ın `533cc11` çalışması
[`34286875301`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34286875301)
1583 testten birinde başarısızdır:
`AnalysisCacheTest.CheckpointSnapshotBindsPendingHeaderAndSidecarWithoutPublishingFindings`.
Salt-okunur teşhis ilk Snapshot reusable kanıtında `runtime_before:deadline`
gösterir: 5,000,212 µs wall, 911,500 µs current-thread CPU; sekiz tamamlanan modül ve
207,822,040 byte okunmuş/hashlenmiştir. Header/sidecar replay ve mutasyon kontrollerine
ulaşılmamıştır. `module_read` sürenin dolduğunun fark edildiği aşamadır; wall/CPU
farkının I/O veya scheduling'den kaynaklandığı kanıtlanmadı. Beş saniyelik bütçe ve
reusable admission koşulları değiştirilmedi; bu keşif U003 içine cache düzeltmesi
olarak alınmaz. Ham genel-CI paket özeti SHA-256
`af2c996b00deb1580a9dd82eb1903710fe15ba32d7bf02b845aa52693df90d7b`.
Önceki genel CI run'larının iptal sonuçları da PASS değildir. Workflow aynı ref için
otomatik iptal yapılandırır; run metadata'sı tek başına iptal nedenini kanıtlamaz.
`b5579bc` genel CI sonuçları metadata run'ından ayrı değerlendirilir.

U003 hâlâ FRONT'tur. Üç gözlem 0/1020 bağımsız korpus açığını, dört yeni ailenin
eksik gerçek security-fix çiftlerini, dondurulmamış native/API profilini veya
korumalı inventory RED'ini kapatmaz. Plan, FIFO ve kalite eşikleri değişmedi;
canonical completion receipt ya da POP oluşturulmadı.

### Yerel kaynak hakemliği — bağımsız kotaya girmeyen güvenli örnek

`llvm-derived-return-matching-delete.cpp` için bağımsız kaynak incelemesi,
açık standalone C++17 / ordinary global new-delete varsayımları altında
memory-leak hedef etiketini **SAFE** olarak doğruladı. Gerçek GCC ve Clang
syntax kontrolleri standart include araması kapalıyken geçti; bunlar native
ürün profili veya analyzer ölçümü değildir. İncelenmemiş upstream simulator
harness'ine eşdeğerlik iddiası yoktur.

Aynı inceleme bağımsız kota için **SUPPLEMENTAL_NONQUOTA** kararı verdi:
mevcut `SummaryOwnedReturnHasNoInventedFamily` eğitimi zaten allocation wrapper,
caller cast ve matching release birleşimini içerir. Farklı allocator ve sonraki
kullanım nedeniyle karşılaştırma yalnız memory-leak ailesi içindir; bütün kurallar
açısından güvenli olduğu söylenmez. Typed Base/Derived eklemesi bağımsız kota için
yeterli ayrım değildir. Karar, exact kaynak/inceleme/ham syntax hash'leriyle
`candidates/selection-record.json` içinde tutulur. Önceki held öneri korunur;
receiver-after-delete eğitim kopyası da dışarıda kalır. Kota hâlâ **0/1020**'dir.

### Değer döndürürken kaybolan sahiplik — etiketi doğrulandı, seçim bekliyor

Yeni [`llvm-value-return-selection.json`](../tests/product_corpus/candidates/llvm-value-return-selection.json)
kaydı, LLVM'nin aynı kökenindeki ayrı `NewDeleteLeaks.cpp` bölümünü kaynak ve
bağımsız inceleme hashlerine bağlar. `new Wrapping()` sonrasında pointer taşımayan
alt nesnenin değer kopyası döner; helper'ın tahsisi serbest bırakılmaz veya
devredilmez. Bağımsız hakem başarıyla tahsis edilen yol için **BUGGY/CWE-401**
etiketini doğruladı. Caller ikinci bir sızıntı veya ayrı safe kota örneği değildir.

Seçim **HELD_NONQUOTA** kaldı: denetçi `SourceManagerTest.cpp` içindeki
`WarmBackendPreservesOriginalAssertPreprocessingSemantics` kaynak parçasında
aynı fonksiyonda allocation → value return → owner loss yapısını buldu.
Bu test null-dereference/cache davranışını çalıştırır; memory-leak qualification
kanıtı değildir. Scalar yerine aggregate kopyasının bağımsız cluster oluşturduğu
henüz kanıtlanmadı. Kaynaktan türetilen olası rapor yeri helper kapanışıdır
(satır 18), fakat bu gözlenmiş analyzer sonucu değildir; exact komut/rapor bağı
ve native profil hâlâ bekler. Üç LLVM adayı da bağımsız kota dışındadır.

Ayrı GCC 15.2.0 kaynak havuzundan sekiz bellek yönetimi test dosyası ve `COPYING3`,
`5115c7e447fc07457443df874bf57840e8316d5f` revision'ına ve gerçek Git blob/SHA-256
kimliklerine bağlı olarak repo dışında saklandı. Paket özet SHA-256'sı
`a790d69453c182f4607e16b75d5737a054772548bf9e9cbdc5d3907ad71f89f5`'tir.
Bu havuz kabul edilmiş korpus değildir. İki kaynak dosyası aynı HAProxy 2.7.1
örneğinden türetildiğini belirtir; dosya/repo sayısı bağımsız köken sayısına
çevrilmez. Upstream warning/no-warning direktifleri etiket kanıtı sayılmaz.
Bu olağan bellek testleri, engellenen dört yeni ailelik security-fix araştırmasının
tekrarı değildir; o zorunlu kabulün eksikliğini de kapatmaz. Kota **0/1020**,
U003 ve kalan bütün ürün kapıları beklemededir; hiçbir POP hazırlanmadı.

### GCC kaynak kümesi — bağımsızlık açısından olumlu, tam kabul bekliyor

[`gcc-mixed-storage-selection.json`](../tests/product_corpus/candidates/gcc-mixed-storage-selection.json)
ilk **DISTINCT_PROSPECTIVE_CLUSTER** kararını kaydeder. Aynı pointer'ın bir dalda
yeni heap tahsisine, diğerinde otomatik diziye bağlanıp görünür ve tüketmeyen
helper sonrasında heap sahipliğini kaybetmesi, incelenen mevcut eğitim
yapılarından ayrışmıştır. `n=11` ve başarılı tahsis yolunun **BUGGY/CWE-401**
etiketi bağımsız doğrulandı. Bu kaynak, parent/sibling/helper ve dil/derleyici
varyantlarıyla birlikte yalnız tek global cluster olabilir.

Tam kabul **HELD** kalır: kaynağa özgü lisans/dağıtım/atıf sınırı, nihai
kaynak–komut–ortam–occurrence bağı ve seçili native platform kanıtları eksiktir.
GCC kaynak kodu repoya eklenmedi; yalnız dış kanıtın kimliği ve inceleme kararı
kaydedildi. Bu, gelecekteki yayın için uygulanmış bir internal-only politika
veya lisans sonucu değildir. Genel GCC/libstdc++ belgelerinden bu dosyaya özel
izin varsayılmadı; tag kimlik bağı da doğrulanmış imza diye sunulmaz.

Yerel GCC 16.1.1 ve Clang 22.1.8 ile sekiz syntax/ABI/dependency kontrolü geçti;
16/19 girdi hash'i ve `int/size_t/pointer=4/8/8` boyutları yeniden denetlendi.
Bunlar runtime closure, Windows/macOS yeterliliği veya analyzer sonucu değildir.
Prospektif rapor yeri `test_2` kapanışıdır (satır 28). Bağımsız seçim çalışması
ilerlemiş olsa da kabul edilmiş kota hâlâ **0/1020** ve U003 tamamlanmamıştır.

### Dış kaynak girdilerinin yerel byte bağı

[`gcc-mixed-storage-binding.json`](../tests/product_corpus/candidates/gcc-mixed-storage-binding.json)
636 byte'lık adayı, upstream kaynağını, parent dosyasını ve iki korunmuş notice
dosyasını ayrı roller/yollar/boyutlar/SHA-256 kimlikleriyle bağlar: beş dosya,
toplam 43.256 byte. Önceki bağımsız karar kaydı da exact digest ile bağlanır;
aday ve upstream source digest'leri o kayıtla karşılaştırılır. Notice dosyalarının
korunması kaynağa özgü lisans hakkının çözüldüğü anlamına gelmez.

`product_profiles.py external-source-check`, açıkça verilen `--binding` ve
`--external-root` ile bu küçük snapshot'ı okur; download, compiler/analyzer
çalıştırma veya kaynak metnini stdout/stderr'e yazma yapmaz. Repo dışında,
canonical absolute bir kök ister; eksik/fazla/değişmiş dosyaları, traversal,
symlink/hardlink, dosya/dizin çakışması, geçersiz JSON ve sonlu boyut ihlallerini
reddeder. Descriptor ve final kimlik kontrolleri olağan okuma yarışlarını yakalar;
kötücül root'a karşı atomik filesystem snapshot veya izolasyon iddiası yoktur.
Başka makinede aynı exact beş dosya aynı göreli yollara hazırlanmalıdır; otomatik
edinim veya yayın politikası bu kontrolün parçası değildir. Yerel hazırlık ve
RED/GREEN kanıtları repo dışındaki U003 `external-binding-v1` dizinindedir.

Başarı yalnız `source_bytes_verified=true` üretir. `native_commands_bound`,
`license_qualified`, `task_ready` ve `product_qualified` false kalır; kabul edilmiş
kota **0/1020**'dir. Bu kaydın kendi hashleri bağımsız hakemliğin yerine geçmez:
güven çapası exact Git manifesti ve onu inceleyen hakemdir. Kaynak/manifest birlikte
değişirse başka bir kimlik oluşur, geçmiş karar yeni kaynağa taşınmış olmaz.
Nihai native komut/header/ABI/ortam ve occurrence yeterliliği hâlâ dondurulmamıştır.
Önceki başarısızlıklar, FRONT, ledger ve tamamlanma kapıları değişmez.

### Aynı GCC adayı için gerçek Linux kaynak/komut önkontrolü

[`gcc-mixed-storage-linux.json`](../tests/product_corpus/candidates/gcc-mixed-storage-linux.json)
aynı 636 byte'lık dış kaynağı yeni, gerçek bir Ubuntu 24.04.4 kullanıcı-alanı
kontrolüne bağlar. Önceden mevcut CodeSkeptic image'ı `25640c190484…` pull/kurulum
yapılmadan, ağsız ve salt-okunur root/input ile kullanıldı. Varsayılan installer
CMD çalıştırılmadı; yalnız açık Python observer başlatıldı. Fedora host çekirdeği
`6.19.10-300.fc44.x86_64` ayrıca kaydedildi: bu, hosted Ubuntu veya tam native
platform yeterliliği değildir.

GCC 13.3 ve Clang 20.1.2, C17 adayını ve ayrı `malloc`/veri-genişliği probe'unu
derledi. `CHAR_BIT=8`, `int/size_t/pointer=4/8/8` ve uyumlu `void *(*)(size_t)`
bildirimi doğrulandı; yanlış int genişliği ve yanlış malloc dönüş tipi iki
derleyicide de static assertion ile ret aldı. On altı komutun 12'si beklenen
exit 0, dördü beklenen exit 1'dir. Aday girdi listeleri 16/19, ABI probe listeleri
19/21 kayıt içerir. Cgroup readback 2 CPU kota, 6 GiB RAM, 6 GiB ek swap ve 256
PID sınırını doğruladı; bunlar ayrılmış kaynak veya performans kararlılığı değildir.
Bağımsız kaynak/kanıt incelemesinde paket içi maddi tutarsızlık bulunmadı.

Seçilen tek kaynak/tek komut [compilation database](../tests/product_corpus/candidates/gcc-mixed-storage-linux/compile_commands.json)
ayrıca gerçek Clang ile çalıştırıldı. C17/target/resource-dir bilgisi database'e
bağlıdır; olmayan CLI passthrough seçeneği uydurulmadı. Aynı resource-dir hem
prospektif child environment'ta hem database'de seçildi. Mevcut frontend'in
eklediği resource-dir ve `-fparse-all-comments` argümanlarıyla yapılan ayrı native
syntax kontrolü de geçti; 19 girdilik liste aynı kaldı. Bu ikinci paket yedi
başarılı compiler komutudur, CodeSkeptic invocation gözlemi değildir.

Henüz çalıştırılmayan iki analyzer argv'si önceden kaydedildi: memory-leak-only
ve varsayım raporlaması dâhil bütün mevcut kurallar. Diğer kuralların temiz
olacağı varsayılmadı; dört yeni aile ayrı PLANNED_NOT_IMPLEMENTED/RED kalır.
`test_2:28:1`, tek CWE-401 occurrence için kaynak-tabanlı beklentidir; gözlenmiş
diagnostic veya fingerprint değildir. Gerçek Release executable kimliği ve
analyzer sonuçları U004'e aittir; bu kayıt ölçümü öne çekmez.

Kaynağa özgü lisans, runtime/calling-ABI/noninterposition, bütün compiler bağımlılıkları,
Windows/macOS per-case kanıtı ve tam profil/korpus freeze hâlâ açık kapılardır.
Image içi header/driver byte kayıtları observer metadata'sıdır; bağımsız denetçi
bunları image içinde yeniden açmış gibi sunulmaz. Önceki Fedora ve hosted include
gözlemleriyle bu yeni Linux per-case kanıtı birbirinin yerine geçirilmez.
Kabul edilmiş kota **0/1020**; U003 için completion receipt veya POP yoktur.

### Windows/macOS per-case kanıtı için açık hazırlama yolu

`stage-gcc-inputs` yalnız açık çağrıda, sabit GCC `5115c7e…` revizyonundaki dört
ordinary kaynak/notice dosyasını indirir. Redirect kabul etmez; sonlu boyut ve
exact hash doğrulamasından sonra yeni bir dış dizine yazar. Mevcut dizin veya
checkout hedefi reddedilir; başarısız kısmi çıktı otomatik silinmez. İncelenmiş
satır-seçim uyarlaması aynı 636 byte'lık adayı üretir. Gerçek staging beş dosyanın
43.256 byte'lık closure'ını doğruladı; kaynak kodu Git'e eklenmedi.

Yeni opt-in `capture-case` / `check-case`, eski include-only v1 belgesinden ayrı
şema kullanır. Exact-clean HEAD/helper/binding/adjudication kimliklerine aday
C17 komutunu, ABI probe'unu, iki kontrollü yanlış ABI ret denemesini ve gerçek
dependency hashlerini bağlar. Compiler tanıları source/SDK metni içerebildiğinden
yalnız byte sayısı/hashleri ve sabit negatif marker kaydedilir. Child environment
allowlist'tir; credential ve ambient compiler/include override'ları taşınmaz.

macOS case lane'i açık standalone CLT compiler/SDK ve arm64 macOS 14 hedefi seçer;
eski Xcode gözlemi yeniden etiketlenmez. Windows gözlenen vcvars64 toolset/SDK
köklerinden ayrı bir case-only VC/UCRT/Windows SDK INCLUDE profili seçer; özgün
tam vcvars ortamı yeniden etiketlenmez. x64 MSVC target ve gerçek header alt
ağaçları bu yeni child ortamına bağlanır. Yapısal safe/ret
testleri gerçek native çalışmanın yerine geçmez; gerçek hosted denemeler aşağıda
ayrıca kaydedilir.
Bu hazırlık kaynak lisansını, runtime ABI'yi veya nihai LLVM-20 frontend modelini
tamamlamaz; `native_qualified/license_qualified/task_ready/product_qualified=false`,
kota **0/1020**, FRONT U003 ve bütün gerçek tamamlanma kapıları değişmeden kalır.

`fdaba601` bağımsız incelemesi başarısızdır: özgün Windows INCLUDE'daki ek
Auxiliary VS/NETFXSDK yolları yeni seçime uymuyordu; beklenen assertion yanında
ilgisiz hata kabul ediliyordu; iç include probe'larının stderr'i case çıktısında
kalabiliyordu. Üç odaklı testte beş RED assertion korunmuştur. Yeni case kaydı
tek beklenen assertion hatası ve sıfır ek hata/warning ister; iç header tanılarını
reddeder. Eski v1 reader geçmiş belgeleri aynı anlamla okumayı sürdürür. Seçilen
Windows INCLUDE eski gözlemin 188 C/427 C++ dependency'sini kapsar, ancak bu
geçmiş karşılaştırma yeni native çalışmanın kanıtı değildir.

İlk gerçek per-case hosted çalışması
[`34324181485`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34324181485),
bağımsız kısmi hazırlık PASS alan `4cc3fe7` kaynağında Ubuntu ve macOS lane'lerini
geçirdi; Windows lane'i başarısızdır. Windows native capture'a ulaşmadan testteki
LF-only stderr beklentisi, Python'ın normal CRLF çıktısını reddetti. İleti içeriği
ve gizlilik kontrolü korunarak yalnız testin CRLF taşıma farkı normalleştirildi;
Git source/helper byte kontrolü değiştirilmedi. Bu başarısız hosted denemesi,
ham üç job logu ve dört oluşmuş metadata artifact'iyle dış kanıtta korunur.
Windows için yeni native çalıştırma hâlâ gereklidir; eski başarısızlık PASS değildir.

`3ea26de2` tekrar incelemesi, ilk dependency TU yolunda ham string karşılaştırmasının
eşdeğer Windows slash/case yazımlarını reddettiğini buldu. İki probe ve iki yazım
için dört RED korunur; diğer header kayıtları gibi platform path eşdeğerliğiyle
karşılaştırılırken ham argv/dependency yazımı saklanır. Gerçekten farklı TU'lar
üç platformdaki altı negatifte reddedilmeye devam eder. Bu düzeltme de yeni
exact-head incelemesi ve gerçek Windows çalıştırması gerektirir.

İkinci hosted deneme
[`34325058939`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34325058939)
`5ab1d2c` kaynağında yine Ubuntu/macOS case'lerini geçti. Windows'ta 54 test ile
eski native kimlik capture'ı (188 C/427 C++ header) geçti; sabit kaynak staging'i
sonra reddedildi. Bu run başarısız kalır; generic hata kök nedeni kanıtlamaz.
Kaynak/SDK metni veya exception içeriği yazdırmadan aşama, script kontrol satırı
ve varsa uyuşmayan stat alanının sabit adı eklendi. Ret koşulları gevşetilmedi;
Windows'taki gerçek reddin kaynağı yeni kanıtla ayrıca belirlenmelidir.
Her native lane başarılı staging sonrasında ayrıca gerçek tempfile kullanan
dış-girdi ve staging güvenlik testlerini çalıştırır; eski 54 identity testi
descriptor/pathname karşılaştırmalarını kapsıyor gibi sunulmaz.

Üçüncü hosted deneme
[`34326603690`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34326603690)
`ae6ac13b` kaynağında Windows staging reddini `descriptor-open:ctime_ns` olarak
yerelleştirdi; diğer altı alan eşleşti. Ubuntu/macOS case'leri geçti, run yine
başarısızdır. CPython 3.12.10'un [pathname sorgusu](https://github.com/python/cpython/blob/v3.12.10/Modules/posixmodule.c#L2139)
`ctime` alanını creation time ile doldururken [descriptor sorgusu](https://github.com/python/cpython/blob/v3.12.10/Python/fileutils.c#L1233)
ChangeTime dönüşümünü korur. Bu API anlam farkı, dosya değişikliği kanıtı değildir.
Yeni dar karşılaştırma yalnız Windows cross-query çiftinde iki gerçek integer
`birthtime_ns` varsa creation/creation kullanır. Eksik/asimetrik alan ret alır;
iki tarafta da yoksa eski raw timestamp karşılaştırması sürer. Ham lstat/lstat
ve ek fstat/fstat kontrolleri `ctime_ns` değişimini korur; dosya kimliği, byte/hash,
link ve alias kontrolleri kaldırılmadı. Windows biçimli pozitif RED ve timestamp,
diğer kimlik alanları, POSIX/eksik-alan negatifleri ayrı kayıtta tutulur. Bu
düzeltmenin gerçek Windows sonucu yeni exact-head run ile kanıtlanmalıdır.

`01e483a` incelemesi ilk CPython kanıt paketini reddetti: tarayıcının görüntü
satırları ham kaynak satırları sanıldığı için ilgisiz alıntılar seçilmişti.
Bu paket geçersiz olarak korunur. Ayrı v2 paket gerçek fonksiyon adlarını
bulup ham dosya digest'iyle doğru alıntıları bağlar; kaynak bağlantıları buna
göre düzeltildi. Bu kaynak sürümü runner Python sürümünün bağımsız attestation'ı
değildir. Kod ve testler aynı kalır; yeni exact-head incelemesi zorunludur.

`61688d6` incelemesinde test-evidence açığı ayrıca doğrulandı: bir değişiklik
denemesi, işlem başarıyla tamamlanmadan `changed` sayılıyordu. Enjekte edilen
PermissionError altında sıfır tamamlanmış replacement ile test geçiyordu.
Artık attempted/completed/OS-denied ayrı tutulur; OS reddinde özgün byte ve
kimliğin korunduğu sınanır, bu sonuç mutation guard kanıtı sayılmaz. Gerçek
replacement ayrıca lstat ile open arasında uygulanır ve inode reddi doğrulanır;
böylece Windows'un açık dosya değiştirme yasağına bağlı olmayan gerçek negatif
vardır. Okuma sonrası diğer mutation bayrağı da ancak başarılı işlemden sonra
işaretlenir. Yeni odaklı RED/GREEN kaydı önceki yanıltıcı PASS'i değiştirmez.

Dördüncü run
[`34328127135`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34328127135)
`abfde218` kaynağında Windows staging'ini beş dosya/43.256 byte ile ve ardından
26 dış-girdi testini geçti. Böylece önceki timestamp engeli gerçek Windows'ta
aşıldı; native case capture daha sonra generic ret verdi. Ubuntu/macOS geçti,
run başarısız kaldı. Yeni hata iletisi yalnız sabit script adları ve kontrol
satırlarını verir; native tanı, exception metni veya kaynak/SDK byte'ı içermez.
Bu tanılama eklemesi hiçbir kabul koşulunu değiştirmez; sonraki gerçek run
reddin yerini kanıtlamadan kök neden veya native Windows PASS iddiası yoktur.

Beşinci run
[`34328908820`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34328908820)
`cde0b84d` üzerinde aynı staging/26-test başarısından sonra native metadata'nın
PowerShell işletim sistemi sorgusunda kaldı. Kaynak konumları capture →
native_metadata → subprocess çizgisini ve yaklaşık 30 saniyelik süreyi gösterir;
henüz aday compiler komutuna ulaşılmadı. Normal ortamda aynı sorgu geçmiştir.

Case allowlist'i Windows profil/önbellek yollarını düşürüyordu. Microsoft'un
[ortam belgesi](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
ve [PowerShell konum testleri](https://github.com/PowerShell/PowerShell/blob/master/test/powershell/Host/Base-Directory.Tests.ps1)
bu native yolların kullanımını açıklar. Yeni dar değişiklik yalnız Windows için
gözlenen `USERPROFILE`, `APPDATA`, `LOCALAPPDATA` absolute yollarını korur;
relative/parent-traversal/boş değerler reddedilir. Linux/macOS ortamı, secret ve
compiler-override retleri ile 30 saniyelik sınır aynı kalır. Bu üç-yol değişikliğinin
gerçek timeout'u gidermesi henüz kanıtlanmamıştır; odaklı RED/GREEN native sonuç
yerine geçmez. Önceki run'lar ve U003'ün bütün açık kapıları korunur.

### Aynı kaynak için başarılı üç-platform C17/static-ABI önkontrolü

[`34329928158`](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34329928158)
tam `24ebf9de6864d4cc99b6176fbf0659fdb205caaf` kaynağında üç işi de geçti.
Bu, yukarıdaki üç Windows profil yolunu koruyan değişiklikten sonraki yeni
gözlemdir; tek tek hangi yolun gerekli olduğunu izole eden deney değildir.
Eski beş başarısız run başarısız kalır. Aynı 636 byte'lık adayın SHA-256'sı
üçünde de `5c5563b8ed6e5715cb1913e223276146bc4c8799c11ee4dace55cf6e8a5e4b0a`.

Her lane'de aday ve ABI probe'u exit 0; yanlış int genişliği ve yanlış malloc
dönüş tipi ayrı beklenen assertion ile exit 1 verdi. İki pozitif TU için ayrıca
dependency komutları exit 0 verdi. Byte genişliği 8, int/size_t/pointer boyutları
4/8/8 ve C17 `void *(*)(size_t)` bildirimi bu sınırda kontrol edilmiştir.

| Hosted lane | Gözlenen case compiler | TU dâhil aday / ABI girdileri |
| --- | --- | --- |
| windows-2025, AMD64 | Clang 20.1.8 | 22 / 22 |
| macos-14, arm64 | Apple Clang 16.0.0 | 73 / 79 |
| ubuntu-24.04, x86_64 | Ubuntu Clang 18.1.3 | 19 / 21 |

Windows case'i VC toolset 14.51.36231 ve Windows SDK/UCRT 10.0.26100.0
seçimine bağlıdır. Mac case'i standalone CLT/SDK 15.2 kullanır; ayrı eski v1
record'undaki Xcode 15.4/SDK 14.5 bunun yerine geçirilmez. Native case komutları
Clang ile çalıştı; MSVC `/Bv` gözlemi MSVC ile aday derlemesi sayılmaz.

`native-gcc-cross-v1/hosted-34329928158` dış kanıt paketinde ham run/jobs/logs,
altı artifact ZIP'i ve altı JSON dâhil 31 dosya saklandı. Paket özetinin SHA-256'sı
`d13177c8fb5091eabc5697b73ece8e80020b29b997d468c95aeaaf1be98b7335`.
Bağımsız salt-okunur denetim exact source/helper/binding/adjudication bağlarını,
bütün dosya/ZIP digest'lerini ve altı reader kontrolünü doğruladı; bu dar
hosted önkontrol için maddi bulgu yoktur. Saklanan SDK/compiler byte kimlikleri
observer metadata'sıdır: denetçi native makinedeki byte'ları yeniden açmadı.

Bu ek belge yeni bir hosted source sonucu üretmez; test edilmiş SHA yukarıdaki
`24ebf9d` olarak kalır. Farklı Clang sürümleri nihai LLVM-20 frontend eşdeğerliği,
runtime/calling-ABI, analyzer kalitesi veya lisans yeterliliği değildir. Kaynak ve
SDK gövdeleri artifact'e eklenmedi; negatif tanılar yalnız boyut/hash taşır.
`native_qualified/license_qualified/task_ready/product_qualified=false`, kota
**0/1020**, aynı FRONT U003 ve bütün gerçek freeze/tamamlanma kapıları korunur.
Bağımsız U003 completion receipt veya POP yoktur.
## U003 — İlk kaynak-sayım kararı için bağlı GCC adayı

Bu ek, eski held kararını veya native sonuçları yeniden etiketlemez. Aynı 636-byte
GCC uyarlaması için [kaynak seçim adayı](../tests/product_corpus/candidates/gcc-mixed-storage-source-candidate.json)
source/hash, bağımsız label/tek cluster kaydı, Linux C17 CDB/analiz tarifi, prospective
occurrence ve bütün sabit limitleri bir araya getirir. `source-candidate-check`
beş tracked linki, önceki üç source-review kanıtını ve beş Linux native/recipe kanıtını
gerçek byte/hash üzerinden okur; ayrıca beş kaynak dosyası ve üç lisans referansını
bağlar. Bu komut analyzer çalıştırmaz ve kendi başına kota kabul etmez.

[Lisans dayanağı kaydı](../tests/product_corpus/candidates/gcc-mixed-storage-license-basis.json)
ayrı `license-basis-check` ile sınanır. Sabit GCC revizyonunun
[root README](https://raw.githubusercontent.com/gcc-mirror/gcc/5115c7e447fc07457443df874bf57840e8316d5f/README)
COPYING dosyalarına yönlendirir;
[resmî GCC açıklaması](https://gcc.gnu.org/pipermail/gcc/2021-June/236201.html)
proje lisansını GPL version 3 or later olarak belirtir. Bunlar proje düzeyinde
dayanaktır: seçili testcase'in ayrı banner'ı yoktur; test dizini README'sinin
kopyalama izni yalnız README'ye uygulanır. Kayda source-specific legal clearance,
tam authorship, Runtime Library Exception veya redistribution onayı eklenmez.
GPL/source içerikleri repository'ye alınmadı. Gelecekte kaynak iletimi için gerekli
upstream notices, değişiklik/tarih bildirimi ve kesin dağıtım yüzeyi ayrıca ele alınır.

Saklanan yeni referanslar `CS3-CH08-S01-U003/gcc-license-basis-v1` dizinindedir;
retention summary SHA-256 `a52c025b1beea1855d85a08e49d6acdefd1c427f77473c3a9a51340aea9f1049`.
Root README 1026 byte, COPYING3 35147 byte, resmî açıklama HTML'i 4703 byte;
COPYING3 eski beş dosyalı source snapshot'taki notice ile byte eşittir.

U003'ün source-count kararı ile U004'ün clean Release ölçümü ve sonraki native
runtime/artifact kapıları ayrıdır. Bir kaynak, açıkça seçilmiş Linux tarifinde
önceden etiketlenebilir; bu tam cohort freeze, Windows/macOS nihai analiz tarifi,
all-rule ground truth, ürün başarısı veya dağıtım izni anlamına gelmez. Bir sonraki
bağımsız exact-source karar açıkça source-count admission vermeden eski sıfır kota
değişmez. Tüm 1020/üç-köken eşikleri, daha sıkı floors ve FIFO aynen korunur.

### Ayrı kaynak kabulü ve v2 kısmi sayaç bağı

Read-only `/root/native_case_verifier`, exact `d817a8d5fbf17a2dbc3e68b5df9c3438c56d3696`
üzerinde altı dosyalık implementasyon için material findings olmadan PASS ve ayrı
**ADMIT_ONE_SOURCE** kararı verdi. Gerçek uyarlama, komşu ownership yapıları,
14 bağlı kanıt, iki Linux ham paketinin 33+15 dosyası ve eski üç native reader
incelendi; 182 odaklı test/iki CLI/queue/guard PASS. Yeniden native execution veya
container-içi compiler/header byte reopening yapılmadı. Kaynak-karar JSON SHA-256:
`b6bc33764e669176bd1a5e8a28f351e8aa656553d4f8e26d2af22e7a73fec91e`.

Yeni profiles **v2**, [seçim indeksini](../tests/product_corpus/selection.json) exact
yol/hash ile bağlar. `selection-check` önce gerçek review/candidate byte'larını,
kararın gerçek ancestor Git commit'indeki candidate/beş link byte'larını ve mevcut
source/license/recipe kanıtını doğrular; ancak bütün kayıtlar geçince mevcut global
hash/cluster kotasını hesaplar. Yeni integration HEAD'in eski reviewed HEAD'den
farklı olması tek başına ret değildir; reviewed source ve bağlı dosyalar değişmişse
ret gerekir. Held karar, eksik/değişmiş karar, yanlış commit, tekrar kaynak/cluster
ve sonradan bozulan bir entry kısmi count döndüremez. Git repo yönlendiren kalıtılmış
`GIT_*` değerleri kullanılmaz; lazy object download, replacement ve prompt kapalıdır.

Sayaç bir memory-leak buggy kaynak, sıfır safe ve tek GCC kökeni gösterir; **1019
kaynak eksiği** ve bütün bucket/family/köken eksikleri görünürdür. `readiness` hâlâ
exit 2, `task_ready/product_qualified/evaluation_frozen=false` verir. Salt v1 draft
okuyucusu, eski held source-binding/candidate okuyucuları ve native v1 zero/false
gözlemleri değişmez. V2 bir alan sayısına güvenmez; gerçek seçimi tekrar okumadan
ve declared count ile karşılaştırmadan readiness üretemez. Bu ortak hesapta saklanan
bağımsız ajan kararı prosedürel denetimdir; imza veya sahte producer'a karşı attestation
değildir. Lisans ve dağıtım false kalır; U003 için POP ya da completion receipt yoktur.

### 4ff3150 sonrası native gözlem — Windows tekrar başarısız

V2 integration `4ff315057d5145e10318be3dd13da211b78a686b`, bağımsız
`/root/external_binding_verifier` tarafından material finding olmadan PASS aldı;
193 odaklı test ve gerçek source-selection/diğer read-only CLI kanıtları geçti.
Bu yalnız bir kaynak sayımının ve v2 bağlantısının kabulüdür. Normal feature push'un
başlattığı [34335727168 koşusu](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34335727168)
**failure**: Ubuntu ve macOS gözlemleri başarılı, Windows gözlemi başarısızdır.

Windows'ta 57 kimlik testi ve 26 external-input testi geçti; özgün v1 collector
188/427 header kaydı üretti ve beş GCC girdisi/43256 byte staging doğrulandı.
Ardından case collector yaklaşık 30 saniye sonra
`identity:857,755,471,285,115,111` failure zinciriyle durdu. Exact kaynakta bu zincir
`capture_case → capture → native_metadata → powershell.exe Get-CimInstance
Win32_OperatingSystem → subprocess.run` yoludur; GCC candidate syntax aşamasına
ulaşılmadı. Hata zinciri OSError/TimeoutExpired alt türünü dışa aktarmadığından
kesin exception türü yalnız süreye bakılarak ileri sürülmez.

Yeni run/jobs/logs, iki başarılı lane'in dört JSON/ZIP gözlemi ve katalog dış
`native-gcc-cross-v1/hosted-34335727168` paketindedir; summary SHA-256
`2d7631f6f9111fc5ba4b6b007d046b5a27bf4631aa2ec4dcbd1a0fdf119b4645`.
Başarısız Windows step'i nedeniyle o lane'in JSON artifact'i yüklenmedi; v1'in
başarılı dönüşü ve output hash'i ham logda vardır, tam belge varmış gibi davranılmaz.

Eski başarılı `34329928158` başarı olarak, yeni koşu failure olarak korunur.
Üç Windows profile/cache değişkeninin önceki başarılı denemesi sorgunun güvenilir
çözümü olduğunu kanıtlamaz: aynı sorgu yeri yeniden başarısızdır. Sonraki teşhis,
native host'ta açık ve sonlu startup/module/CIM kontrolleriyle full ve seçilmiş
ortamı karşılaştırmalıdır; kör env genişletme, timeout gevşetme veya sırf yeniden
çalıştırıp yeşili kabul etme yoktur. Bu OS metadata başarısızlığı, bağımsız Linux
tarifine bağlı tek kaynak kararını değiştirmez; Windows/final native freeze ve
U003 zaten açık kalır. Yeni doküman HEAD'i bu koşunun tested HEAD'i değildir.

### Tekrarın ardından bounded Windows tanısı — henüz neden kanıtı değil

`34329928158` başarılı koşusu ile `34335727168` başarısız koşusunun collector ve
workflow byte'ları aynıdır; ikisi de `20260824.214.3` runner image etiketini bildirir.
Bu aynı host/cache/provider durumunu kanıtlamaz. Başarılı case ortamında da
`PSModulePath` bulunmadığı için bu değişkenin yokluğu tek başına zorunlu hata nedeni
olarak sunulmaz.

Ek `diagnose-windows`, gerçek case denemesinden **sonra** çalışır. Özgün case hata
zincirinden yalnız `TIMEOUT`, `OS_ERROR` veya `INVALID` kategorisi loglanır; native
diagnostic veya exception metni basılmaz. Case başarısızsa sonraki tanı ne döndürürse
döndürsün workflow o başarısız exit'i korur. Windows tanısının kendi başarılı çıkışı
yalnız altı gözlem kaydının üretildiği anlamına gelir; içindeki probe başarısızlıkları
saklanır ve native/product/task qualification daima false'tur.

Üç sabit PowerShell probe'u startup, `CimCmdlets` ve `Microsoft.PowerShell.Utility`
import'u, ardından özgün OS sorgusunu gözler. Her probe ayrı süreçte, önce mevcut
dar ortam sonra yalnız yerel Windows sistem `Modules` dizini `PSModulePath` olarak
eklenmiş ortamda çalışır: toplam altı süreç, her biri 30 saniye timeout, retry yok.
Özgün ambient module path, credential veya bütün legacy ortamı aktarılmaz. Bu
**system-module-path-only** karşılaştırmasıdır, full-environment eşdeğerliği değildir.
Asıl v1 OS komutu/şeması, case ortam allowlist'i, compiler/SDK seçimi ve timeout'u
değişmez. Tanı, asıl OS sorgusunu yeniden başarılı ilan etmez.

Tanı JSON'u source/collector/workflow ve gerçek shell hash'i, runner/run kimliği,
sabit marker'lar, exit kategorisi ve süre taşır; raw stdout/stderr, genel ortam dökümü,
kaynak/SDK içerikleri veya exception metinleri taşımaz. Beklenmeyen çıktı yalnız
boolean ile belirtilir. Exported system executable/module path'leri kimlik alanıdır;
credential veya module-path environment dökümü değildir. Output ancak repo dışındaki
yeni dosyaya yazılır. Upload adımları artık failure sonrasında da mevcut v1/case/tanı
dosyalarını saklamayı dener; eksik artifact hata olarak kalır.

[PowerShell'in resmi ortam belgesi](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-5.1)
modül araması ve modül analiz cache'inin startup/import ile ilişkisini açıklar.
Bu nedenle tanı ilk case öncesinde yapılmaz; cache silme, WMI restart, modül
kurma veya full environment ekleme yoktur. Probe sırası/cache etkisi yine vardır:
iki ortamın geçmesi nedenin çözüldüğünü kanıtlamaz; yalnız sistem-module-path
varyantının geçmesi de tek başına nedenselliği ispatlamaz. Subprocess timeout ve
post-capture çıktı boyutu kontrolü hard RSS/descendant-process/output-production
sınırı değildir; ürün worker bütçesi burada sınanmıyor.

Eksik tanı API'leri için korunmuş iki RED testten sonra yerel testler fixed cause,
timeout/OS-error/nonzero/bozuk veya aşırı çıktı, secret/ambient-module dışlama,
network/relative module-root reddi, marker/schema tahrifi, asıl case exit'ini koruma,
repo-içi/mevcut output reddi ve read-only CLI sınırlarını kapsar. Gerçek Windows
kanıtı ve bağımsız exact-head inceleme olmadan bu ekleme bir çözüm veya U003 PASS'i
sayılmaz. Önceki başarısız ve başarılı hosted kayıtlar aynen korunur.

### 772d332 gerçek Windows tanısı — TIMEOUT doğrulandı, çözüm doğrulanmadı

Bağımsız read-only inceleme `772d332172c2576f93da4b87b0a628f0891d324e` tanı
implementasyonuna material finding olmadan PASS verdi. Exact-head 205 ürün testi,
13 kaynak/CLI/queue/guard kontrolü ve önceki üç native JSON'un yapısal replay'i
geçti. Bu sayılar runtime ürün qualification veya U003 tamamlanması değildir.

Normal feature push'un başlattığı yeni
[34338848236 koşusu](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34338848236)
**failure** olarak tamamlandı: Linux/macOS başarılı, Windows başarısız. Windows'ta
69 kimlik testi, özgün v1 identity capture, beş hash-sabitli kaynak girdisinin
staging'i ve 26 external-input testi geçti. İlk case capture yine OS sorgusunda
durdu; bu kez `CASE_FAILURE_KIND TIMEOUT` gerçek exception türünü doğruluyor.
Sonraki tanı, başarısız case'in yerine kullanılmadı; workflow özgün başarısızlığı
korudu ve eksik case artifact'ini de hata olarak bildirdi.

Tanının aynı shell hash'ine bağlı altı probe'u aşağıdaki gibi sonuçlandı:

| Ayrı süreç probe'u | Mevcut dar ortam | Yalnız sistem module path ekli |
| --- | --- | --- |
| Startup | OK, 172 ms | OK, 188 ms |
| CimCmdlets + Utility import | OK, 24562 ms | OK, 22438 ms |
| OS sorgusu, otomatik modül yüklemeli | OK, 23375 ms | OK, 22625 ms |

Altı kayıtta da beklenmeyen output false ve beklenen son marker mevcuttur.
Tanı öncesindeki özgün timeout başarısız olarak kalır. Bu gözlem hızlı boş
PowerShell startup'ını yavaş modül/sorgu yolundan ayırır; iki import'un hangisinin
geciktiğini veya ilk 30 saniyelik timeout'un tam nedenini henüz ayırmaz. İki ortam
da geçtiği ve probe sırası/cache/provider durumu kontrol edilmediği için
`PSModulePath` eklemesi bir düzeltme veya nedensellik kanıtı değildir. Sonraki dar
teşhis, bu iki modülün yükleme aşamalarını ayrı zamanlamalıdır; kör timeout/ortam
genişletme, cache temizliği, servis restart veya sırf yeşil tekrar kabulü yoktur.

Yeni `windows-query-diagnostic-v1/hosted-34338848236` paketi run/jobs/logs ve
altı ZIP/JSON artifact'i saklar: iki başarılı lane'in v1/case kayıtları, Windows
v1 kaydı ve Windows tanısı. Tanı JSON SHA-256
`24586b0e85401ca191866c2522bea86a3dae96b50f62da26518ffd002b3efdf5`;
paket summary SHA-256
`2f1d1ece8d7b527c2d3f0107e66f8ee1b6c2fb4cf86919fe890eaae10c8558a9`.
Kaynak/SDK dosyaları upload edilmedi. Native input byte'ları primary Linux host'ta
yeniden açılmış sayılmaz. Kaynak kabulü hâlâ **1/1020**, tüm native/task/product
qualification ve full freeze false; U003 için POP yoktur. Bu raporun belge HEAD'i
koşunun tested HEAD'i değildir.

### Aşama zamanlı tanı v2 — aynı 30 saniye, ayrı import/query ölçümü

`diagnose-windows-stages` önceki v1 tanısını yeniden etiketlemez. Ayrı
`codeskeptic-windows-query-diagnostic/v2` şemasını ve `check-windows-stages`
okuyucusunu kullanır; eski v1 CLI/validator ve altı-probe kayıtları korunur.
Workflow mevcut tanı çağrısını bu yeni komutla değiştirir, artifact'in genel adı
aynı kalır. V2 yalnız asıl case denemesinden sonra, değiştirilmemiş dar case
ortamında tek PowerShell süreci çalıştırır; module-path karşılaştırması eklemez.

Tek .NET Stopwatch ve flush edilen sabit marker'lar sırasıyla script başlangıcını,
CimCmdlets import bitişini, Utility import bitişini, yalnız CIM sorgusunun bitişini
ve selection/JSON dönüşümünün bitişini zamanlar. OS nesnesi/JSON değeri dışarı
aktarılmaz. Asıl v1 `WINDOWS_OS_QUERY` ve identity kabulü değişmez; pipeline'ı
bölmek yalnız tanı içindir. Bütün script tek 30 saniyelik subprocess timeout'a
tabidir; aşama başında süre sıfırlama, yeniden deneme veya case öncesi prewarming
yoktur. Testler gerçek PowerShell başlatmaz; native probe testleri mock kullanır.

V2 yalnız sıralı, tekrarsız, tamamlanmış marker prefix'ini saklar. Sayaçlar sonlu,
monotonik tamsayıdır; parent süresine yalnız 1 ms yuvarlama payı tanınır. Bozuk tam
satır ve sonrasındaki marker'lar kabul edilmez; yarım son satır ayrıca flag taşır.
Timeout'ta tamamlanma zamanı uydurulmaz. Bütün marker'lar görülse bile süreç
timeout/nonzero ile biterse süreç başarılı sayılmaz. Raw stdout/stderr, exception
ve ortam sırları kayda girmez. Eski hard-resource-containment sınırlaması ve
qualification=false anlamı aynen geçerlidir.

Ölçülen farklar aynı post-attempt süreçteki sıralı import/query/serialization
maliyetidir; cold host, yalnız modül CPU zamanı veya ilk timeout'un kök nedeni
değildir. Code/CLI negatifleri başarılı olsa da gerçek Windows gözlemi olmadan
bu v2 tanısı sonuç üretmiş, hata çözülmüş veya U003 tamamlanmış sayılmaz.

### 146bd12 gerçek v2 gözlemi — yavaş aşama CimCmdlets import'u

`146bd125084a84070a86a7400020f37873e67cba` bağımsız exact-head incelemeden geçti;
214 yerel ürün testi ve 13 kaynak/CLI/queue kontrolü başarılıdır. Normal feature
push ile başlayan [34340950607 koşusu](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34340950607)
**failure**: Linux/macOS başarılı, Windows başarısız. Windows'ta 78 kimlik testi,
v1 capture, beş sabit kaynak girdisinin staging'i ve 26 external-input testi geçti;
asıl case yine OS sorgusunda `CASE_FAILURE_KIND TIMEOUT` ile durdu. Case derlemesine
ulaşılmadı; sonradan tanı dosyası üretilmesi bu başarısızlığı değiştirmedi.

V2 tanısı aynı dar ortamda tek süreçte 25453 ms sonunda exit 0 döndü. Beş marker
sıralı/tam, bütün bozuk/yarım/aşırı çıktı ve stderr flag'leri false'tur:

| Tamamlanan aşama | Clock başlangıcından ms | Önceki marker'dan ms |
| --- | --- | --- |
| STARTED | 1 | — |
| CIM_LOADED | 25187 | 25186 |
| UTILITY_LOADED | 25192 | 5 |
| CIM_QUERY_DONE | 25238 | 46 |
| QUERY_DONE | 25263 | 25 |

Bu post-attempt süreçteki büyük gecikme CimCmdlets import aşamasındadır; sonraki
Utility import'u, gerçek CIM sorgusu ve JSON dönüşümü çok daha kısadır. Import
aşaması bağımlılık/initialization ve eşzamanlı runtime işlerini de içerebilir;
bu exclusive CPU süresi veya özgün timeout'un kök nedeni değildir. Module-path
veya execution policy değiştirilmedi, cache/servis müdahalesi yapılmadı.

Yeni runner image `20260907.229.1` bildirir; önceki `34338848236` tanısı
`20260824.214.3` kullanmıştı. Bu nedenle koşular aynı image/host/cache üzerindeymiş
gibi karşılaştırılmaz; yeni gözlemdeki süre ayrımı kendi tek sürecine aittir.
Sonraki teşhis CimCmdlets yükleme yolunu ve etkili runtime/policy gözlemlerini
daraltmalıdır; henüz policy gevşetme veya timeout artırma gerekçesi oluşmamıştır.

`windows-stage-diagnostic-v2/hosted-34340950607` paketi run/jobs/logs ve altı
ZIP/JSON artifact'ini korur. Windows case artifact'i eksik ve upload hatalıdır;
Windows v1 ve v2 tanı dosyaları saklanmıştır. V2 JSON SHA-256
`9e1f644b98bbb1495c1e0ad81ee7951e962c73b78704f532700fa80b76c6b821`;
paket summary SHA-256
`c5ab20a724db7f4852c6cc1bde741bab925b41ee522b2f030d7c02ecc474033b`.
Kaynak/SDK içerikleri upload edilmedi; primary host native byte'ları yeniden
açmış sayılmaz. Kaynak sayacı 1/1020, freeze/native/task/product qualification
false ve U003 açık kalır. Bu raporun belge HEAD'i tested `146bd12` değildir.

### Windows post-attempt politika gözlemi — eklemeli v3 sözleşmesi

`diagnose-windows-context` önce değişmemiş v2 staged collector'ını bir kez,
ardından aynı dar ortam ve aynı hash-bound Windows PowerShell executable'ı ile
ayrı bir policy-only süreci bir kez çalıştırır. `check-windows-context` yalnız
`codeskeptic-windows-query-diagnostic/v3` okur: `policy` dışındaki alanlar,
schema v2'ye projekte edilerek eski v2 validator'ından geçer. Ek/bilinmeyen
alanlar düşürülmez, reddedilir. V1/v2 collector, script ve reader anlamı değişmez.

Policy alanı Python parent'ında `PSExecutionPolicyPreference` için yalnız
`absent/recognized/unrecognized` ve bilinen policy enum'u veya null kaydeder;
case-insensitive ad/value sınıflandırması yapılır, boş veya bilinmeyen değer
aynen dışarı verilmez. Aynı sınıflandırma dar case ortamında `absent` olmalıdır.
ENV_KEYS/CASE_ENV_KEYS genişlemez; bu değişken child'a aktarılmaz veya değiştirilmez.
[Microsoft'un Windows PowerShell 5.1 sözleşmesi](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1)
process politikasını bu değişkene bağlar, Group Policy'nin önceliğini açıklar.
Bu kaynak davranış hipotezidir; mevcut parent değeri veya gecikme nedeni değildir.

Ayrı child sırasıyla STARTED, gerçek engine'in bounded dotted numeric sürümü,
`Get-ExecutionPolicy` effective sonucu ve MachinePolicy/UserPolicy/Process/
CurrentUser/LocalMachine scope enum'larını, ardından POLICY_DONE marker'ını verir.
Komut module-qualified `Microsoft.PowerShell.Security\\Get-ExecutionPolicy`'dir;
PowerShell 7 parent'ının engine/policy sonucu Windows PowerShell child'a atfedilmez.
Engine sürümü gözlenir, sırf executable konumundan 5.1 olduğu varsayılmaz.
Sıralı tamamlanmış prefix saklanır; bilinmeyen/tekrarlı/bozuk/yarım çıktı flag
olur, arbitrary stdout/stderr veya environment içeriği artifact'e girmez.

Üstteki `timeout_seconds=30` her child'a ait ayrı subprocess sınırıdır; v3 toplamı
30 saniye değildir. Eski stage clock'ları ve elapsed değeri değişmez; policy'nin
kendi elapsed/outcome/exit/flag kaydı vardır. Policy elapsed, Security modülünün
yüklenmesini de içerir; saf policy-resolution süresi veya CimCmdlets kök nedeni
değildir. Process exit ve eksik çıktı başarısızlıkları eski kayıtlar gibi korunur.
Kaynak/shell byte kimliği iki süreçten sonra yeniden denetlenir. Asıl case exit'i
workflow'da tanıdan önce saklanır; policy sonucu case TIMEOUT'unu değiştiremez.

Set-ExecutionPolicy, execution-policy argümanı, signature/cache/service müdahalesi,
ortam genişletme veya yeniden case denemesi yoktur. Tanı her iki aşamadan sonra
çalıştığı için önceki staged module ölçümünü prewarm etmez; testler native çağrıları
mock eder. Mevcut capture-output sınırları hard RSS/descendant/output-production
garantisine dönüşmez. Bu prospective gözlem henüz yeni hosted sonuç değildir;
native/task/product qualification false, U003 açık ve kaynak sayacı 1/1020'dir.

### Windows v3 gerçek gözlemi — politika hipotezi desteklenmedi, uzun import sürdü

Bağımsız exact-head PASS alan `3fcf06a35c1b2ac8cca6c48168cbc96675090007`
üzerine yalnız cache durumuna ilişkin kanıtsız “cold” sözcüğü düzeltildi.
Yeni temiz `7cfec2d51385377ce5d50d3392246d9b49a974e7` tekrar bağımsız PASS ve
224 test/13 kontrol ile doğrulandı. Normal feature push'un gerçek
[34343205581 koşusu](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34343205581)
üç platformda **success** oldu. Windows'ta 88 identity ve 26 external-input testi,
beş sabit girdinin staging'i, v1 capture, dört case syntax/ABI probe'u ve v3
tanısı tamamlandı. Önceki başarısız koşular başarısız olarak korunur; yeni başarı
onların yeniden etiketlenmesi değildir.

V3 tanısında stage süreci exit 0/22546 ms, ayrı policy süreci exit 0/235 ms
döndü. Her iki kayıt tam ve sıralı, bütün malformed/trailing/stderr/output-limit
flag'leri false'tur. Stage clock değerleri ve kendi sürecindeki farklar:

| Tamamlanan aşama | Clock başlangıcından ms | Önceki marker'dan ms |
| --- | --- | --- |
| STARTED | 1 | — |
| CIM_LOADED | 22275 | 22274 |
| UTILITY_LOADED | 22279 | 4 |
| CIM_QUERY_DONE | 22321 | 42 |
| QUERY_DONE | 22343 | 22 |

`PSExecutionPolicyPreference`, Python parent'ında da dar case ortamında da
`absent/null` çıktı. Gerçek Windows PowerShell child engine'i
`5.1.26100.33296`, effective policy `Unrestricted` olarak gözlendi. MachinePolicy,
UserPolicy, Process ve CurrentUser `Undefined`; LocalMachine `Unrestricted` idi.
Bunlar runner'dan okunmuş değerlerdir: collector/workflow hiçbir policy ayarı
yapmadı. Effective sonucu parent değişkeninden veya parent PowerShell 7'den
türetilmedi.

Bu koşu, filtrelemenin mevcut bir process-policy değişkenini sildiği hipotezini
desteklemez: gözlem sırasında parent'ta silinecek değişken yoktu. Önceki koşularda
bu değer ölçülmediği için onlar hakkında geriye dönük politika sonucu kurulmaz.
235 ms, Security modülünü yükleme ve policy sorgularını kapsayan ayrı sürecin
süresidir; signature verification veya CimCmdlets yükleme maliyetini ölçmez.

Asıl case/OS query kodu, dar ortam ve 30 saniyelik sınır değişmeden Windows bu
kez tamamlandı; buna rağmen post-attempt CimCmdlets import'u 22,274 saniye sürdü.
Başarılı tek koşu kalıcı timeout düzeltmesi veya determinizm kanıtı değildir.
Image `20260824.214.3` idi; hemen önceki `34340950607` koşusu
`20260907.229.1` bildirmişti. Aynı host/cache/image üzerinde kontrollü A/B sonucu
veya kök neden iddiası yoktur; policy gevşetme/timeout artırma gerekçesi üretilmedi.

`windows-policy-diagnostic-v3/hosted-34343205581` paketi gerçek run/jobs/logs,
yedi provider-digest-bound ZIP ve içlerindeki tek JSON dosyalarını saklar.
Hepsi aynı tested kaynak head/tree ve committed collector/workflow/profile/API
hashlerine bağlandı; üç native case ayrıca dört case-helper hashini taşır.
Windows v3 JSON SHA-256
`691ac2d932f9aa93028c712990ae9df856f09e4ddd7914ac9dbbabccf07ad1b1`;
Windows native case JSON SHA-256
`9df30f27f9c26d39d8f80a056d1ce67ff21a80b0d3e2315a4783b9eeb9b12e42`;
paket summary SHA-256
`ac5110f79f0c59b63ce9bf0268e107e692a5bf41c2b987939b590602eba3fbd8`.
Primary host native SDK/source byte'larını yeniden açmış sayılmaz. Bu metadata
ve syntax gözlemleri frozen korpus, native/product/task qualification veya POP
değildir; kaynak sayacı 1/1020 ve U003 açık kalır. Bu raporun belge HEAD'i tested
`7cfec2d` değildir.

### GCC tek girdisi — kaynak temelli all-rule etiket önerisi

`gcc-mixed-storage-ground-truth.json`, aynı 28 satırlık C17 girdisinin
`5c5563b8ed6e5715cb1913e223276146bc4c8799c11ee4dace55cf6e8a5e4b0a`
byte kimliğine eklemeli bağlanır. Eski candidate/selection/admission/recipe
hashleri değişmez. Kaynakta `n > 10` ve başarılı ordinary native malloc yolunda
tek memory-leak/CWE-401 beklentisi `test_2:28:1`, multiplicity 1 olarak korunur.
Görünür helper parametreleri okumadan sıfır döndürür; heap pointer'ını tüketmez,
saklamaz veya dışarı taşımaz. Allocation failure ile automatic-array yolları
ayrı kota kaynağı değildir.

Diğer 15 aile için kaynakta neden ek ihlal beklenmediği satır referanslarıyla
ayrı kaydedildi. Pointer her iki branch'te atanır; array elemanları okunmaz ve
malloc failure sonucu null pointer dereference edilmez. Ayırma dalında int32
`n` aralığı 11..2147483647'dir; `sizeof(int) * n` size_t64 üzerinde en çok
8589934588 byte olur ve sarmaz. Etiketin veri modeli bağlı Linux native tarifinin
char/int/size_t/pointer boyutlarıyla çapraz kontrol edilir; farklı width/profile'a
sessizce taşınmaz. Sadece çağrı bulunmayan dört yeni aileyi bu kaynaktan safe
etiketlemek, o aileler için bağımsız safe quota veya kurulmuş detector kanıtı değildir.

Assumption, contract ve policy, CWE precision/recall satırlarına sokulmaz.
Referans kodda assumption için dereference edilen pointer parametresi; contract
için seçilmiş deklarasyon/sidecar; policy için deklarasyon/profile tetikleyicisi
yoktur. Bu üç report-only diagnostic için de prospective boş beklenti gerekçesi
saklanır; gelecekteki ham çıktılar atılmaz. Kaynak etiketlemesi analyzer'ın
fiilen ne raporlayacağını veya ürün kalitesini önceden gözlemiş değildir.

Referans contract/registry/CWE eşleme ve üç project-rule kodu exact
`ff7ae4ca69be751e9d0301cf87c08b9cf577cb07` Git nesnelerine bağlandı. Bu kaynak
etiketleme işi detector kodunu, current/planned ayrımını veya native collector'ı
değiştirmez. `ground-truth-candidate-check` yalnız öneri byte/şema bağını denetler;
gerçek ayrı source-review receipt'i ve indeks olmadan `ground-truth-check`
başarılı reviewed sonuç üretemez. Etiket ve entegrasyon için bağımsız exact-head
inceleme ayrıca gerekir. Korpus sayacı 1/1020, ek kota 0, bütün freeze/native/
analyzer/license/distribution/product/task qualification bayrakları false kalır.

### GCC all-rule source-review bağlantısı — kısmi, frozen değil

Önerinin `f2b833ad3ab1541d8972b42a2be0778e2b09425d` exact-head durumunda
ayrı kaynak hakemi gerçek kaynak, 16 aile ve üç project-diagnostic gerekçesini
inceleyerek `ACCEPT_SOURCE_LABELS` verdi. Primary'den farklı hakemin receipt'i
checkout dışında saklanır; `ground_truth.json` hem değişmemiş öneriyi hem de
`c192bb63d2097f79a375028ec81717e7e2bb3d33203876b139359f9607572837`
SHA-256 receipt'ini bağlar. Etiket önerisi receipt için yeniden yazılmaz.
Kod/doğrulama önerisi aynı head'de ayrı bağımsız PASS aldı; indeks entegrasyonu
bu iki incelemeden ayrı exact-head kontrol gerektirir.

İndeks kontrolü gerçek dış receipt, incelenmiş Git nesneleri, kaynak/native-width
bağı ve eski kabul/seçim zincirini birlikte yeniden açar. Eksik veya değişmiş
bir bağlantı reviewed sonucu vermez. Kabul yalnız bir kaynağın etiketlerinindir:
memory-leak beklentisi bir occurrence olarak korunur, diğer ailelerin etiketleri
yeni kota oluşturmaz. Sayım 1/1020, ek örnek 0, state
`PARTIAL_REVIEWED_SOURCE_LABELS_NOT_FROZEN` kalır; bütün qualification bayrakları
false ve genel readiness hâlâ başarısızdır.

Native kimlik workflow'una on yeni all-rule doğrulama/bozulma testi eklendi;
mevcut 26 external-input/staging testiyle birlikte her lane 36 odaklı test seçer.
Bu testler sentetik geçici fixture kullanır; dış kaynakları yeni örnek olarak
kaydetmez, analyzer çalıştırmaz ve bu ekleme kendi başına yeni hosted başarı
kanıtı değildir. Önceki native koşuların tarihî sonuçları değişmez.

### All-rule native test seçimi — ilk Windows RED ve fixture düzeltmesi

Entegrasyon `6b4478df32ee3c86367393f36bd094d82de95871` ayrı exact-head
bağımsız PASS aldı; 234 yerel test ve 15 kontrol beklenen exit sonuçlarını verdi.
Ancak [native koşu 34346981841](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34346981841)
attempt 1 genel **failure** kaldı: Ubuntu/macOS geçti, Windows 88 identity testini
ve gerçek kaynak staging'ini geçtikten sonra 36 external-input/staging/all-rule
testinden `test_reviewed_reader_binds_procedural_review_without_extra_quota`
hata verdi. Windows case/ABI ve post-attempt diagnostic adımları çalışmadı;
eksik artifact'ler başarı sayılmaz. Beş mevcut JSON artifact'i, run/job metadata,
loglar ve ZIP/JSON SHA-256'ları checkout dışındaki
`gcc-all-rule-ground-truth-v1/hosted-34346981841` paketinde korundu; summary
SHA-256 `1eac27a2d5f76683750d06c46033b4d8f8ed63cdcf27097b838f3fa59a0dc638`.

Yeni sentetik fixture, gerçek Linux manifestinden üç projenin mutlak snapshot
yollarını kopyalıyordu. Windows `Path.is_absolute()` bu drive içermeyen POSIX
yolları reddeder; production `source_metadata` kontrolü bu nedenle doğru biçimde
fail-closed kaldı. Fixture artık yalnız geçici test manifestindeki snapshot
yollarını kendi host'una göre kurar. Gerçek profil, source reader, etiket,
receipt/admission/selection ve path güvenlik koşulları değiştirilmez.

Fixture regresyonunun RED exit 1 ve GREEN exit 0 kanıtları aynı dış pakette
`windows-fixture-red.json` / `windows-fixture-green.json` olarak saklandı.
Yeni test ayrıca her host'ta `PureWindowsPath` ile POSIX-rooted yol reddini ve
drive içeren sentetik yol kabulünü kontrol eder. Native lane seçiminde artık
37 test (26 önceki + 11 all-rule) bulunur. Yerel GREEN Windows native GREEN
yerine geçmez; ilk hosted failure değişmeden korunur ve yeni exact-head inceleme
ile yeni hosted sonuç ayrıca gerekir. Korpus 1/1020 ve bütün qualification
bayrakları false kalır.

### All-rule fixture native GREEN; Windows kimlik sorgusu ayrı RED

Fixture/report commit'i `dd7f0ab3b63528f2b8632565cb8722df81d7cbe6` bağımsız
exact-head PASS aldı; 235 yerel test, 37 seçili test, üç workflow testi ve 15
kayıtlı kontrol doğrulandı. [Yeni native koşu 34348054597](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34348054597)
attempt 1'de üç platformun her birinde 88 identity ve 37 external-input/staging/
all-rule testi geçti. Böylece önceki Windows fixture hatası için gerçek native
GREEN vardır; bu sonuç tüm Windows job'unun başarısı değildir.

Ubuntu/macOS job'ları ve case/ABI gözlemleri başarılıdır. Windows case capture
daha sonra değişmemiş `windows_sdk_identity` PowerShell OS sorgusunda 30 saniye
timeout verdi (`CASE_FAILURE_KIND TIMEOUT`; exact producer kodundaki
`identity:286` → `identity:112`). Windows case artifact'i oluşmadı ve bütün koşu
**failure** kaldı. Önceki koşu `34346981841` de failure olarak korunur.

Altı mevcut metadata JSON'u, loglar, run/job/artifact kayıtları ve ZIP/JSON
SHA-256'ları checkout dışındaki `gcc-all-rule-ground-truth-v1/hosted-34348054597`
paketinde saklandı; summary SHA-256
`1053f6a1fdb32b52cbcd30c05c1c570e3a99398cb0ec52dffbdf1f5f10db2b73`.
Case denemesinden sonraki staged sorgu 22562 ms'de tamamlandı, `CIM_LOADED`
22303 ms'de gözlendi. Ayrı policy gözlemi effective `Unrestricted`, MachinePolicy/
UserPolicy/Process/CurrentUser `Undefined`, LocalMachine `Unrestricted` bildirdi;
inherited/case execution-policy preference yoktu. Bunlar timeout sonrasındaki
diagnostic gözlemleridir: ilk sorgunun kök nedenini, kalıcı çözümü veya native
qualification'ı kanıtlamaz; ilk başarısız sonucu değiştirmez.

Yeni timeout için collector, süre sınırı, ortam veya workflow değiştirilmedi;
aynı head körlemesine yeniden çalıştırılmadı. Bağımsız kabul edilmiş kaynak
etiketleri 16 aile + üç project-diagnostic olarak bağlıdır, ancak tek kaynak
1/1020 ve ek kota 0 kalır. Windows native kapısı, eksik diğer değerlendirme
kaynakları ve platform analiz tarifleri açık; evaluation freeze, task/product
qualification ve U003 POP hâlâ yoktur.

### GCC Windows/macOS prospective analiz tarifleri

`gcc-mixed-storage-windows.json` ve `gcc-mixed-storage-macos.json`, her biri ayrı
tek-source/tek-command `compile_commands.json` ile mevcut GCC girdisine eklenir.
Eski Linux tarifi, source candidate, admission, selection, all-rule önerisi ve
bağımsız source-review receipt'i yeniden yazılmaz. İki platform hâlâ tek kaynak
ve tek global cluster'dır; ek kota 0, kaynak sayacı 1/1020 kalır.

Tarifler son başarılı üç-platform preflight koşusu `34343205581` / producer
`7cfec2d51385377ce5d50d3392246d9b49a974e7` üzerinde hashli tarihsel referanstır.
Windows Clang 20.1.8, `x86_64-pc-windows-msvc`, MSVC 14.51.36231 ve SDK/UCRT
10.0.26100.0; macOS Apple Clang 16.0.0, CLT 16.2, SDK 15.2 ve explicit
`arm64-apple-macos14.0` seçimi korunur. Windows candidate closure 22 input
(kaynak + 21 header), macOS 73 input (kaynak + 72 header) içerir. Native JSON'un
tam header kayıtları hash üzerinden bağlıdır; bu sayılar ek değerlendirme örneği
değildir. Windows `cl.exe /Bv` kaydı candidate'ın MSVC ile derlendiğini göstermez.
Sonraki `34346981841` ve `34348054597` Windows başarısızlıkları geçerli kalır.

Seçilen CDB argv, gözlenmiş C17 candidate `-fsyntax-only` komutunu ve native
kaynak yolunu korur. Analyzer komutları kendi ayrı binary/profile/output yollarını,
14 diğer aileyi kapatan memory-only listesi ile `--assumptions` içeren all-current
seçimini önceden kaydeder. `--lang en` diagnostic dilidir; C17 seçimi CDB'dedir.
Yeni binary hash'i pending U004'tür, hiçbir analyzer çıktısı üretilmemiştir.

Salt-okunur kontrol gerçek source/etiket zincirini, iki CDB'yi, tarihsel run/head/
tree/helper/workflow bağlarını ve on bir CLI/frontend/registry/worker referansını
yeniden denetler. Native absolute path'ler yalnız ait oldukları platformun
leksik kurallarıyla işlenir; Linux host'ta SDK/compiler yolları açılmış gibi
yapılmaz. Kaynak dışı veya kaçan yol map edilemez ve sonra sessizce atılamaz.

Yeni on odaklı test sentetik Windows/macOS metadata fixture'larıyla pozitif
şekilleri, komut/SDK/resource/closure/ABI/label/quota forgeries'ini, bağlı dış dosya
bozulmasını, producer tree ve exact workflow Git blob'unu denetler. Compiler veya
network çağrısı yapılmadığı ayrıca kontrol edilir. Native workflow test seçimi
37'den 47'ye çıkar; bu değişiklik tek başına yeni hosted PASS değildir.

Tariflerin ilk `7568f69` checkpoint'indeki durum
`PREDECLARED_NATIVE_RECIPE_NOT_QUALIFIED`'dır. Explicit küçültülmüş
analyzer environment'in native eşdeğerliği, SourceManager tarafından eklenen
header seçenekleriyle closure eşitliği, embedded frontend uyumu, güncel native
byte reopening ve ek platform source-label incelemesi pending'dir. Mevcut Linux
etiket kabulü bu kapıları kapatmaz. Tüm qualification bayrakları false kalır;
genel readiness başarısız, U003 ve tam ürün hedefi açık durumdadır.

### GCC platform kaynak etiketleri — ek koşullu kabul

`7568f69427dd6d78704c7c40d5e11297dee489c9` üzerinde bağımsız kaynak hakemi
iki exact tarif için `ACCEPT_CONDITIONAL_PLATFORM_SOURCE_LABELS` verdi.
Özgün dış receipt SHA-256:
`c782ce6c939a868af2295545a32db151fa3c404fa61be16a35d131071fd31a5d`.
Yeni `platform_source_labels.json` index'i bu kaydı, iki özgün tarif hash'ini ve
eski all-rule etiket hash'ini bağlar; eski tarif/CDB/kaynak/admission/selection
byte'ları değiştirilmez. Koşullu kaynak kararı uygulama PASS'i değildir.
Kesintiye uğrayan kod incelemesi ayrıca aynı temiz `7568f69` üzerinde yenilendi
ve yalnız prospective-tarif checkpoint'i için bağımsız PASS alındı; bu bölümün
ek entegrasyonu kendi yeni exact-head incelemesini gerektirir.

`platform-source-labels-check` eski native/source kanıt zincirini de doğrular.
Hash eksikliği, stale review, aynı implementer/verifier, boş koşul, değişmiş
tarif/CDB/etiket veya dosya kimliği başarısız olur. Source-review bayrağı true
olsa da `conditional_only=true`, `conditions_satisfied=false` ve diğer dokuz
qualification bayrağı false kalır; sekiz hakem koşulu çıktıda aynen korunur.

Önemli sınır: tutulan native ABI helper `INT_MAX` veya `SIZE_MAX` değerini ve
padding yokluğunu assert etmez. `INT_MAX<=2147483647` ve
`SIZE_MAX>=8589934588`, pozitif n'nin kayıpsız dönüşümüyle birlikte aritmetik
gerekçe için yeterli koşuldur; bu değerler yeni ölçüm yapılmış gibi sunulmaz.
Native malloc/header annotation davranışı, adjusted closure ve frontend/runtime
eşdeğerliği açık kalır. Dört planlı aile kurulu sayılmaz; eksik leak bir miss,
beklenmeyen diagnostic adjudication gerektiren gözlemdir, bastırma gerekçesi değil.

Altı yeni odaklı metadata/IO/Git/CLI testi `NativeRecipeTests` seçimine eklenir;
native workflow aynı selector ile bunları da seçer. Yerel testler ve kaynak
incelemesi yeni hosted başarı anlamına gelmez. Korpus 1/1020, ek kota 0;
evaluation freeze, U004 çalışması, U003 POP ve ürün yeterliliği hâlâ yoktur.

### Koşullu etiket entegrasyonu — yeni üç-platform hosted GREEN

Entegrasyon commit'i `6dabb74334d45de48ae0c31cff62bbf1bdaf9d5c`, 251 yerel
test ve 17 kayıtlı kontrolün ardından bağımsız exact-head checkpoint PASS aldı.
`gcc-platform-recipes-v1/checkpoint-review-6dabb74.json` receipt SHA-256:
`49716d43073206af4962eb13eaf7caab6c34bca12461bfa38422ad93d66be983`.
Bu karar yalnız entegrasyonu kapsar; U003 tamamlanması değildir.

[Yeni koşu 34686787454](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34686787454),
aynı exact head'in feature push'ından attempt 1 olarak çalıştı ve başarılı oldu.
Linux, Windows ve macOS job'larının her birinde gerçek loglara göre 88 identity
ve 53 seçili external-input/staging/ground-truth/recipe testi geçti. Üç native
case'te candidate/ABI syntax kontrolleri başarılı, yanlış genişlik ve yanlış
imza negatif kontrolleri beklenen şekilde başarısızdır. Bunlar native derleyici
ön kontrolleridir; CodeSkeptic analyzer veya embedded frontend çalışması değildir.

Yedi metadata JSON'u, ZIP'leri, üç job log'u ve run/job/artifact API kayıtları
checkout dışındaki U003 `gcc-platform-recipes-v1/hosted-34686787454` paketinde
saklandı. Summary SHA-256:
`c283663207e92d874789b195f19ce0f55a938597fd9afe68212e0ef47ae5029e`.
Bağımsız ham kanıt denetimi bütün dosya hashlerini, ZIP/API/upload-log
eşleşmelerini, JSON byte eşitliğini ve exact producer Git bağlarını doğruladı.
Yalnız bu hosted kanıt için PASS receipt'i
`gcc-platform-recipes-v1/hosted-review-34686787454.json`; SHA-256:
`1d7e282b46760e27998461d2187ef466cbe3dfa1efe7718f67b9662a5755b72f`.
Kaynak dosyası, SDK header'ı veya compiler binary'si artifact olarak yüklenmedi.

Windows case sonrası ayrı staged sorgu bu kez 17594 ms'de tamamlandı;
`CIM_LOADED` 17357 ms'de gözlendi. Collector, 30 saniyelik sorgu sınırı ve
workflow bu checkpoint'te değiştirilmedi. Bu yeni başarı, önceki timeout'un
kök nedenini veya kalıcı düzeltmesini kanıtlamaz: `34346981841` ve `34348054597`
koşuları failure olarak korunur. Özgün prospective tariflerin eski native
referansları yeni koşuya sessizce yeniden pinlenmedi.

Sekiz kaynak-hakemi koşulu hâlâ koşulludur; `conditions_satisfied=false` ve
dokuz qualification bayrağı false kalır. Güncel native byte reopening,
adjusted header closure ve embedded frontend eşdeğerliği doğrulanmış değildir.
Korpus 1/1020, ek kota 0; readiness exit 2, evaluation freeze yok, U003/ürün
hedefi açık ve `main` değişmemiştir. Bu kayıt bir POP değildir.

### İkinci kaynak adayı — heap parent serbest, child sahipliği kayıp

Mevcut GCC 15.2.0 havuzundaki `leak-4.c:5–23`, native `stdlib.h`, tek pointer
alanlı yapı ve `test_1` korunarak 15 satırlık ayrı kaynak önerisine bağlandı.
Kaynak SHA-256 `7e0b0494e9572d46eecce6049b968917044a677608f1f934f6c9ad6bbe85651c`;
[kaynak/hakem kaydı](../tests/product_corpus/candidates/gcc-parent-child-selection.json)
özgün revision/blob/hash, çıkarım ve dış kanıtları taşır. Kaynak byte'ları repo'ya
eklenmedi. GCC/Clang ile toplam 14 yerel version/dependency/syntax/ABI/negatif
kontrol beklenen sonuçları verdi; aday çalıştırılmadı ve analyzer kullanılmadı.

Bağımsız kaynak hakemi iki tahsis de başarılıyken yalnız child için bir CWE-401
sızıntısını kabul etti. Parent doğru serbest bırakılır; başarısız tahsis ek leak
yaratmaz. İncelenen stack-aggregate eğitim örneği ayrı local owner taşır ve farklı
yapıdadır. Bununla birlikte LLVM `testMallocIntoMalloc` aynı core cluster'dır;
ikinci kaynak/köken sayılmaz ve bu benzerlik genetik türetim kanıtı değildir.

İlk hakem kararı addressability için HOLD'dur ve özgün byte'ları korunur.
Mevcut motor direct `a->ptr = malloc(...)` için field-owner kaydı tutmaz;
closing-brace emitter'ın bu child'ı raporladığı ileri sürülmez. Ayrı, hashli
ölçüm-öncesi öneri ve bağımsız ek inceleme bu sınırlı örneğin hedef değerlendirme
seçimini kabul etti: istenen occurrence `test_1:15:1`, memory-leak/CWE-401,
multiplicity 1. Bu mevcut çıktı değil, önceden tanımlanan hedef convention'dır.
Sonradan normal raporda eksik child FN olarak kalacak; sonuç görüldükten sonra
unsupported etiketi veya konum değişikliği yapılmayacak. U003'te detector
değişikliği, genel field/heap-graph destek iddiası veya eşik gevşetmesi yoktur.

İlk review, ek karar, öneri ve 14 kontrolün özgün kanıtları checkout dışındaki
U003 `gcc-parent-child-source-review-v1` paketinde korunur. Generic kaynak
bağlama/admission entegrasyonu, nihai analiz tarifleri, matching/bütçe bağları,
platform ve all-rule etiketleri ile köken/hak sınırları hâlâ eksiktir. Bu aday
**FULL_ADMISSION_HELD**, ek kota 0'dır; kabul edilmiş seçim hâlâ **1/1020**.
Yeni kayıt eski GCC kaynağının lisans/admission veya native CI kararını devralmaz.

### İkinci aday — retained kaynak bayt bağlama protokolü

`gcc-parent-child-binding.json`, eski `external-inputs/v1` biçimini değiştirmeyen
ayrı `codeskeptic-product-retained-github-inputs/v1` protokolünü kullanır. Bu dar
biçim bir candidate, bir origin, bir retained GitHub metadata belgesi, bir
extraction açıklaması, bir semantic-comparison ve en az bir notice ister.
Genetic history açıkça `UNKNOWN_NOT_ASSERTED` kalır; karşılaştırma `lineage`
yerine geçirilemez. Eski GCC lisans okuyucusu yalnız eski protokol sonucunu kabul
eder; mevcut GCC pinleri, kabul kaydı ve seçim manifesti değişmez.

Okuyucu gerçek dosyaların hash/boyutlarını ve son dosya kimliklerini kontrol
eder. Retained metadata'nın sabit repository/revision/path, Git blob, içerik
ve boyut alanları gerçek origin baytlarıyla eşleşir; extraction kaynak hashleri,
artan/ayrık/geçerli satır aralıkları ve açıklaması mevcut adjudication'a bağlıdır.
LLVM karşılaştırmasının hash'i aynı eski kaynak kararına bağlanır. Yerel portable
dosya yolu sınırları genişlemez; upstream `c++` yolu yalnız metadata/URL'de işlenir.
Bu tutarlılık denetimi upstream kimlik doğrulaması, otomatik extraction eşdeğerlik
ispatı, semantik bağımsızlık, lisans izni veya source ADMIT değildir.

U003 `gcc-parent-child-binding-v1/inputs` dış paketinin yedi dosyası / 93.831
baytı doğrulandı; kaynak `7e0b0494…51c` aynı kalır. Değiştirilmiş gerçek kaynak
kopyası exit2 ile reddedildi. Yeni protokolün başlangıç RED'i, legacy-dispatch
negatifi ve ilk uygulamadaki upstream `c++` yolu ayrım hatası ayrı başarısız
kanıtlardır; sonraki GREEN bunları yeniden etiketlemez. 148 profile ve 88 identity
testi yerelde geçti; source CLI ve mutation kontrolleri dış kanıt paketinde tutulur.

Bu checkpoint yalnız kaynak bayt bağlamasını ekler. Generic candidate/admission
dispatch, nihai native tarifler, matching/bütçeler, all-rule/platform kararları
ve hak sınırları tamamlanmadı. Analyzer çalıştırılmadı; ikinci aday hâlâ
**FULL_ADMISSION_HELD**, ek kota 0 ve toplam kabul edilmiş seçim **1/1020**.
Yeni kodun hosted sonucu ayrıca doğrulanmalıdır; eski CI bu checkpoint'e taşınmaz.

### Retained binding hosted kontrolü — Windows timeout, koşu başarısız

`36c4f578ecf5e5e3fc6cd96071b7bd517013cf14` için
[34689801293 koşusu](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34689801293)
attempt 1 **failure** kaldı. Linux/macOS job'ları başarılıdır. Windows'ta 88
identity ve 75 seçili profile testi geçti; sonraki native `capture-case`,
`WINDOWS_OS_QUERY` PowerShell sorgusunun 30 saniyelik sınırında timeout oldu.
Windows native-case artifact'i oluşmadı. Başarılı iki case eski mixed-storage
kaynağına aittir; yeni parent/child kaynağını native-qualified yapmaz.

Sonraki ayrı diagnostic 23016 ms sürdü; CIM modülü 22763 ms'de yüklendi ve
kayıtlı query aralığı 41 ms idi. Effective execution policy Unrestricted,
iki preference da absent'tı. Önceki başarılı koşudaki CIM load 17357 ms idi.
Bu sonradan alınan gözlemler başarısız sorgunun iç zamanlamasını veya kalıcı
kök nedenini kanıtlamaz. Budget/policy değiştirilmedi ve kör tekrar yapılmadı.

31 hashli dosya ve altı API artifact ZIP digest'i U003
`gcc-parent-child-binding-v1/hosted-34689801293` paketinde korunur; summary
SHA-256 `e72241904a692c1badc9503d2c303eb326aa3ab99a095202134d845aba4858e0`.
Bağımsız ham kanıt kararı `VERIFIED_FAILED_RUN_NOT_QUALIFICATION`:
`gcc-parent-child-binding-v1/hosted-review-34689801293.json`, SHA-256
`57e301257b5310d3865485592fbb9e95042a5f6b18dd86aa37cd94c230d3ffe6`.
Başarısız koşu ve eksik Windows kapısı başarılı diye yeniden etiketlenmez.

### İkinci aday — yeni Linux compiler ön kontrolü ve genel okuyucu

Aynı 193 baytlık parent/child kaynağı için yerelde mevcut image, ağ ve pull
kapalı, read-only girdiler ve sonlu container/compiler sınırlarıyla kullanıldı.
Seçili C17 CDB ve SourceManager custom-adjuster sırasını simüle eden komut ayrı
çalıştı. 20 komuttan 14'ü exit 0; iki komut biçiminin üçer yanlış width/malloc/
free kontrolü amaçlanan assertion ile exit 1 verdi. Candidate/ABI bağımlılıkları
önce/sonra ve iki biçim arasında aynı: candidate 19 input/18 header, ABI 26
input/24 header. Ne aday program ne CodeSkeptic analyzer çalıştırıldı.

U003 `native-gcc-parent-child-linux-v1/summary.json` SHA-256
`6f07afd4c3b51662521bf37f75307abc1083452f94f9e552f2f6bb2d5b63ca1d`;
ham observation summary SHA-256
`3e5a205f2e2f6aa675b7523e6b68486c072282bb4fbd7fa70c9c6c28ecd2678b`.
Bağımsız preflight kararı aynı dizindeki `independent-review.json`, SHA-256
`c313acd3c60c52aba5bf9f18e4b1e871478e455a93dfd820f68a4f8fb8b874fa`;
yalnız kayıtlı compiler ön kontrolüne `PASS_WITH_STATED_BOUNDARIES` verir.
Calling ABI, allocator noninterposition, image signature, runtime closure,
embedded frontend, üç-platform ürün ve kaynak kabulü bu PASS kapsamında değildir.

Yeni [aday kaydı](../tests/product_corpus/candidates/gcc-parent-child-source-candidate.json)
kendi kaynak/hak sınırı, Linux tarifi, desired occurrence ve değişmemiş LIMITS
bağlarını taşır. Genel okuyucu gerçek paket üzerinde sıfır kota ile geçer.
Eski GCC lisans/admission/native kararı yeni adaya devredilmez. Generic projection
başlangıç RED'i ve ilk underscore ayrım hatası korunur. Git okumasının timeout
istisnasının dışarı sızdığı ayrıca RED ile gösterildi; sabit, redacted rejection
düzeltmesinden sonra aynı kontrol GREEN oldu.

12 yeni sentetik test, geçici gerçek dosyalar ve Git nesneleriyle bu protokolü
sınar; yerel dış kanıt paketine bağımlı değildir. Sonradan kaynak değişiminin
gözden kaçması ve ortamın tanımsız alan/yeterlilik türünü kabul etmesi ayrı RED
olarak kaydedildi. Kaynağın son sınırda yeniden okunması, tüm kaynak/stream
kimliklerinin korunması ve exact environment alanları bu açıkları kapattı.
160 profile, 88 identity ve 24 product-quality testi geçti. Yeni 12 test mevcut
native workflow seçimine de eklendi; yerel GREEN hosted başarı iddiası değildir.
Workflow selector'ını eski tam metne bağlayan test ilk değişiklikte RED oldu;
aynı eski seçimleri ve yeni test sınıfını iki lane'de zorunlu tutan assertion
güncellendi. Native collector, PowerShell query ve sonlu bütçeler değişmedi.

Ek legacy korpus integrity kontrolü `missing/extra/unordered protected inputs`
ile başarısızdır. Bu fark yeni okuyucudan önce de vardı: `36c4f57` üzerinde 127
kayıtlı girdiye karşı 151 gerçek protected input; yeni dört aday metadata/CDB
dosyasıyla gereksinim 155 oldu. Eski 127 input hash'i değişmemiştir. Bu RED'i
kapatmak için kaynak farkına bağlı bağımsız sınıflandırılmış prospective
inventory/catalog successor gerekir; kontrol veya collector gevşetilmez.

Bu kayıt kaynak ADMIT değildir: ikinci aday için ayrı exact-source kabul ve
selection entegrasyonu henüz yok; seçim **1/1020** kalır. Tam all-rule/platform
ve hak yeterliliği, cohort freeze, U003 POP ve U004 ölçümü açık kapılardır.

### İkinci kaynak kararı ve selection okuma penceresi

Bağımsız kaynak hakemi exact `810cae2bc134e618482d7ec2aca9ba2a183c54cd`
üzerinde yalnız bir-source partial admission verdi. Karar U003
`retained-candidate-reader-v1/source-admission-810cae2.json`, SHA-256
`f81b53999165ed6c4b7d1d98751c096f57b796e72a1560e4964ef84e80ce2d64`.
GCC köken sayısı artmaz; LLVM benzeri ve dil/platform varyantları ek kaynak
sayılmaz. Yedi qualification alanı false ve bütün açık kapılar korunur.
Bu karar henüz selection'a uygulanmadı; sayı **1/1020** kalır.

Ayrı implementation denetimi aynı head'e PASS vermedi: ikinci sentetik aday
okunurken ilk adayın gerçek kaynak baytları değiştirildiğinde toplam hâlâ 2
dönebiliyordu. `selection-transitive-window-red.json` bu bulguyu yeniden üretir.
Legacy ve retained kaynak/rights/stream/dizin kimliklerini bütün selection
boyunca taşıyan private kontrol eklendi. İlk adayın source, rights, raw stream
ve dizin değişimi negatifleri ile legacy guard regresyonu sonrasında 161
profile testi ve iki gerçek candidate/selection CLI kontrolü geçti. Eski
başarısız denetim korunur; düzeltme yeni exact-head bağımsız inceleme ister.

28 dosyalık eklemeli inventory farkı ayrıca bağımsız sınıflandırıldı:
`retained-candidate-reader-v1/input-classification-810cae2.json`, SHA-256
`e07e208199dcee3b60884f453ec5a0c29348a9a5f5bd6158b1182bf4e4dedc46`.
127 eski input, 52 fixture, 15 capability, floor ve snapshot byte'ları değişmez.
Bu yalnız `ELIGIBLE_ADDITIVE_CLOSURE_ONLY` kararıdır; pending successor henüz
uygulanmadı ve son payload/head incelemesinin yerine geçmez.

### İkinci kaynak — partial selection'a bağlandı

Aggregate kimlik düzeltmesi `247b61558676d9d7dce01c438b998bc152ef3af0`
üzerinde yeni bağımsız checkpoint PASS aldı. Receipt:
`retained-candidate-reader-v1/checkpoint-review-247b615.json`, SHA-256
`7fa85bde580aa0fac0b8fc5dfd0feb987d91598d0c01f44c68b94d6b7a8b0371`.
Denetçi özgün RED'e ek olarak aynı baytların geri konması, silme, boş stream'in
büyümesi, yeni dizin, inode değiştirme ve tekrar gözlem negatiflerini de sınadı.
Bu PASS kaynak sayım kararının entegrasyonundaki kod kapısını kapatır; inventory
ve U003 kapılarının PASS'i değildir.

Ardından değişmemiş exact `source-admission-810cae2` kararı selection'a eklendi.
Yeni selection SHA-256:
`773825b8678f225a9d2e8db4879909ef1d2b82ef677ca858fdb5f0088caeceeb`.
Eski GCC admission girişi, candidate/recipe/etiket pinleri ve köken kaydı aynıdır.
Gerçek selection CLI iki source/review zincirini doğruladı: **2/1020**, memory-leak
buggy 2, safe 0, GCC kökeni yalnız 1. Kaynak ve semantic cluster başına tek kredi
kuralı korunur; desired `test_1:15:1` henüz bir analyzer sonucu değildir.

Entegrasyonun ilk 161-test koşusu bir fixture uyumsuzluğu nedeniyle RED oldu:
tek kaynağı mock eden all-rule fixture, canlı manifestten yeni sayı 2'yi
devralıyordu. Bu bir ürün ground-truth hatası değil; fixture kendi tek-source
sayımını açıkça tanımlamalıdır. Readiness beklenen exit 2'dir. Entegrasyonun exact-head
incelemesi ve 155-input prospective successor hâlâ gereklidir. All-rule/platform,
hak ve tam cohort freeze tamamlanmadı; U003 POP veya U004 ölçümü yapılmadı.

Fixture sayımı kendi tek girişine bağlandıktan sonra 161 test yeniden geçti.
Gerçek all-rule ve platform-label okuyucuları da eski kaynak kararlarını
koruyarak geçti; iki-source toplamı ikinci kaynağa all-rule/platform kabulü
vermez. Önceki başarısız test capture'ı RED olarak saklanır.

### İkinci kaynak entegrasyonu ve korunan girdi kapanışı

Selection entegrasyonu ve tek-source fixture düzeltmesi exact
`847c38568a1f957f5dde4c5a7283fb3b5bf12c6e` üzerinde bağımsız PASS aldı:
`retained-candidate-reader-v1/selection-integration-review-847c385.json`,
SHA-256 `fb41a04fd5603e864fbdc65b19ee3b0da836edd9fd9c84033ae5323d43e0e9ad`.
Bu karar yalnız dört dosyalık entegrasyona aittir; katalog kararının yerine geçmez.

Ardından aynı exact source head ve `5db8970b199801bb7029007eb40a99cb309414a7`
predecessor kaynağı için 28 ek girdi bağımsız olarak yeniden sınıflandırıldı.
Onaylanan prospective katalog/inventory baytları aynen uygulandı: korunan girdi
sayısı **127 → 155**. Eski 127 satır ve hash, 52 fixture sözleşmesi/kaynakları,
15 capability, kalite floor'ları ve tarihsel snapshot'lar değişmedi. Eklemeler
kaynak/evidence/recipe/model/index kapanışıdır; admission veya native yeterlilik
değildir. Önceki eksik-input RED'i korunur.

Prospective karar `retained-candidate-reader-v1/inventory-proposal-review-847c385.json`,
SHA-256 `8bef8b9186ee0e1a949dc25d2d43a462ded6d0497f05950944a82f8bee05af60`;
bu kararın tarihsel `applied: false` alanı sonradan değiştirilmez. Uygulanan
inventory SHA-256 `9198353752f102a98711a53946743507153df5a421f88cae3324256f98bd5ed4`,
katalog SHA-256 `79df3c5bcc81bc5cffb4624eec374970396b40bf6f16babb41dae8cbe5440cc7`,
successor payload ID `72f7c04ed924c32577a0288e4091d7576d57f35f7598ff2cf848f3eac5cb734e`.
Gerçek integrity kontrolü, 65 katalog testi ve eski/yeni input değiştirme,
silme/çoğaltma, predecessor/source/reviewer/PENDING bağları dahil 12 in-memory
geçiş negatifi geçti. Negatiflerin bir kısmı ek exact-transition assertion'larıdır;
bunlar production validator'ın tek başına sağladığı garanti diye sunulmaz.
Uygulanmış commit hâlâ yeni bağımsız exact-head denetim ister. Seçim **2/1020**,
readiness exit 2, eski hosted Windows başarısızlığı ve tüm U003 açık kapıları aynıdır.

### İkinci kaynak — bağımsız all-rule kaynak etiketleri

Exact `de17573eebcd2cf6ac9333c37d9957a0042a2bf8` üzerinde yeni parent/child
kaydı kaynak bazlı bağımsız `ACCEPT_SOURCE_LABELS` aldı. Kayıt SHA-256
`b7b470b5b3ccbc7abb09de53ad04e9e4b083a4de72fc6c1504526a7a2294daca`;
karar U003 `retained-source-labels-v1/retained-label-source-review-de17573.json`,
SHA-256 `20b2b74f522308aa8c1fafc8837c2bca9d019ae13817b67f66fd5deda3c8991a`.
Hakem gerçek 193 bayt/15 satırı, beş aday bağlantısını, sekiz referansı ve
koşullu native kanıtı okudu; compiler veya analyzer çalıştırmadı.

Başarılı iki allocation durumunda yalnız child sızıntısı beklenir; parent
doğru serbest bırakılır ve allocation failure dalları yeni child yükümlülüğü
yaratmaz. Diğer 15 aile ve üç proje tanısı ayrı kaynak gerekçeleri taşır.
Bu safe etiketler ek bağımsız safe örnek veya köken sayılmaz. Desired
`test_1:15:1` hâlâ unimplemented/unobserved hedeftir; sonuç sonrası unsupported
etiketine dönüştürülemez. Kaynak hakkı, runtime allocator, embedded analyzer,
Windows/macOS uygulanabilirliği ve native/product kapıları tamamlanmadı.

Explicit retained etiket okuyucusu ve ayrı index eski label/platform hashlerini
korur. Sekiz yeni sentetik test gerçek geçici dosya/Git nesneleriyle eksik veya
stale review, çapraz kaynak, yanlış konum/tür/kota ve source/rights/stream
okuma pencerelerini sınar. İlk API/CLI eksikliği RED'i ve ilk uygulamanın
145 KB'lık mevcut manifesti etiketlere özgü 64 KiB sınırında reddettiği RED
saklanır. Manifest için mevcut 16 MiB girdi sınırı kullanıldıktan sonra sekiz
test ve tam **169 profile testi** geçti; küçük etiket/review sınırı gevşetilmedi.
Gerçek yeni index bir retained kaynak etiketi, eski okuyucular eski kaynak
etiketleri için geçer. Seçim **2/1020**, ek kota sıfır ve readiness exit 2 kalır.
Uygulama/index yeni exact-head bağımsız inceleme, iki yeni protected input da
prospective inventory successor ister; bunlar henüz bu kaynak kararının PASS'i değildir.

### Önceki okuyucu checkpoint'inin yeni hosted gözlemi

Exact `05a5c1de2f9045814b7daa424afb4cdc67527391` için
[34693664339 koşusu](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34693664339)
attempt 1 üç platformda başarılıdır. Her lane'de 88 identity ve 87 seçili profile
testi geçti; 12 retained-candidate testi sentetiktir. Üç native-case artifact'i
eski 636 baytlık mixed-storage kaynağına aittir, parent/child'a değil.
Yedi API ZIP digest'i ve 34 dosya hash'i ayrı bağımsız ham-kanıt incelemesi aldı:
`retained-candidate-reader-v1/hosted-review-34693664339.json`, SHA-256
`bc4fc44ab2d56e52b258a1cfec903408b7e89b334973958070ad92698a37a7ca`.
Korunan summary SHA-256
`ed7922ee671813b7478af5cfb6f55d702c35eb84bd88b84d2223bbdc91ec9595`.

Collector/query bütçesi değişmedi. Başarılı Windows case sonrası diagnostic
22828 ms; CIM_LOADED 22549 ms ve kaydedilen query aralığı 44 ms idi. Bu gözlem
eski timeout'un kök nedeni veya kalıcı onarım ispatı değildir; `34689801293`
başarısız kalır. Yeni all-rule okuyucusu bu eski exact-head koşusunda yoktur;
ona veya ikinci kaynağa hosted/native/product PASS devredilmez.

### Retained etiketler — tarihsel referans entegrasyon düzeltmesi

`d5dfe86a483091a45512682693b0d8720a3b259c` sonrasında gerçek etiket/index
okuyucusu exit 2 verdi; bağımsız implementation denetimi de aynı bulguyu
bildirdi. Sebep, historical `05a5c1d` referans hashlerinin bugünkü checkout
dokümanlarıyla yanlış karşılaştırılmasıydı. Yeni contract dokümantasyonu bu
yanlış eşitliği bozdu; sentetik fixture o zamana kadar iki sürümü aynı tutuyordu.
`exact-d5dfe86-label-index-green.json` adı başarı kanıtı değildir: içindeki
gerçek exit 2 ve bu başarısız checkpoint korunur.

Yeni regresyon, kaynak kararı sonrasında ayrı dokümantasyon commit'i oluşturur.
Mevcut ancestor Git-blob doğrulaması kullanıldığında eski kaynak kararı geçer;
yeni doküman hash'ini eski head'e bağlamak ve yeni öneriyi eski review'la kabul
etmek reddedilir. Kaynak/rights/stream girdileri hâlâ gerçek dosyalardan okunur
ve ortak kimlik kontrolünde kalır; historical referanslar yeniden yazılmaz.
Dar RED/GREEN, tam **170 profile testi** ve gerçek retained index yeniden geçti.
Bu düzeltme yeni exact-head bağımsız inceleme ister; U003 açık kapıları aynıdır.

### Retained etiket checkpoint'i ve iki girdilik successor

Düzeltilmiş `8c28e275d662d222fc30e655c6aae80b73ca521f` bağımsız implementation
PASS aldı. Aynı kararın ayrı prospective sınıflandırması yalnız yeni etiket
sidecar'ı ve ayrı review-link index'ini onayladı. Karar:
`retained-source-labels-v1/label-review-8c28e27.json`, SHA-256
`f651c3b5121db20784d6fbeb8ca6a1998c4159432f5dfd91ae59226931fc9aaf`.
Onaylanan sequence 3 baytları uygulandı: **155 → 157** korunan girdi; eski
155 satır/hash, 52 fixture, 15 capability ve bütün floor/snapshot'lar değişmez.
Inventory SHA-256 `40dfedb3ebe09f3b7575fe8e8e3b5063719fab184467504283c4ba98237713c9`,
katalog SHA-256 `31384b65ee813ca82d6825fd222b4f8986afe1b56218d55150c5c6b943801dc2`.
Gerçek integrity, 65 katalog testi ve 12 in-memory exact-transition negatifi
geçti; ek transition assertion'ları production validator garantisi diye sunulmaz.
Uygulanmış commit yeni bağımsız exact-head denetim ister. Seçim **2/1020**,
readiness exit 2, ek kota sıfır ve yedi qualification alanı false kalır.

### Ayrı genel Linux CI — runtime kimlik süresi nedeniyle RED

`05a5c1d` için genel [CI 34693664328](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34693664328)
başarısızdır: 1583 testten biri, checkpoint snapshot testinin ilk reusable-response
assertion'ında düştü. `runtime_before` gözlemi sabit 5 saniyelik wall sınırını
`module_read` ön kontrolünde gördü; iki modül ve 185023160 byte okunup hashlenmişti.
Fresh snapshot coverage tamam olsa da runtime digest/witness verilmediği için
reuse fail-closed kaldı. Resume/header/sidecar kontrollerine ulaşılamadı; sonraki
single-process/smoke/dogfood/real-world/thesis adımları skipped kaldı.

5.000717 s wall ve 0.801927 s thread CPU, I/O veya scheduling gecikmesiyle
uyumludur fakat host contention/kök neden kanıtı değildir. İlgili runtime/test/
workflow kaynakları `36c4f57` ile byte eşittir. Salt-okunur bağımsız teşhis
`retained-candidate-reader-v1/general-ci-diagnosis-05a5c1d.md` altında korunur.
Başarılı kimlik workflow'u ayrı kalır; bütün CI veya ürün yeterliliği iddia edilmez.
U004 bu çözülmemiş RED'i kaydeder, CH12-S01-U003 ilgili dayanıklılık kapısını
ele alır. Burada cache kodu, süre bütçesi veya warmup değiştirilmedi/çalıştırılmadı;
FIFO atlanmadı ve kör tekrar yapılmadı.

### Retained etiket testleri — Windows host yolu regresyonu

Exact `6c61f92250e3916b1760a21831d33fa19050daa1` için
[identity 34695543309](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34695543309)
attempt 1 başarısızdır. Linux/macOS işleri geçti; Windows'ta 88 identity testi,
gerçek identity capture ve pinned source staging başarılı olduktan sonra
96 seçili profile testinde dört failure ve iki error oluştu. Yeni retained
etiket fixture'ı canlı manifestin üç Linux `local_snapshot` yolunu kopyalıyordu;
Windows'ta bunlar host-absolute değildir. `source_metadata` doğru biçimde
reddetti. Bu koşu önceki CIM timeout'u değildir: native-case ve post-case
diagnostic adımlarına ulaşılamadı; eksik artifact'ler PASS sayılamaz.

Ham API/job/log/ZIP ve beş metadata observation, U003 kanıt kökündeki
`retained-label-host-path-v1/hosted-34695543309` altında korunur. Summary SHA-256
`576e00c136cddca1402e1bd09cdb7676e0f1bcede32227f2af41e63a2e0a4dd7`.
Salt-okunur bağımsız teşhis, aynı manifestin POSIX yol semantiğinde geçip
Windows semantiğinde reddedildiğini, yalnız üç snapshot yolunu Windows'a
uygunlaştırınca metadata kontrolünün geçtiğini doğruladı.

Düzeltme yalnız sentetik test fixture'ına host-local boş snapshot dizinleri
verir; gerçek kaynak snapshot'ı veya proje yeterliliği üretmez. Production
okuyucu, mutlak yol şartı, workflow, collector, süre bütçesi, korunan korpus
ve katalog/inventory baytları değişmez. Dar regresyon önce gerçek yol farkıyla
RED verdi, sonra GREEN; ayrıca her proje için yabancı-host yolu yeniden
reddedilir. Tam 171 profile, 88 identity, workflow'un 97 seçili profile testi,
gerçek retained index ve integrity kontrolü yerelde geçti. Bunlar yeni bir
Windows hosted başarı iddiası değildir; değişen head bağımsız inceleme ve
yeni gerçek CI sonucu ister. U003 seçimi 2/1020 ve readiness exit 2 kalır.

İlk taslak regresyonun list/dict hatası, yanlış `validate` CLI çağrısı ve
commit öncesi dirty-tree guard reddi ayrı başarısız denemeler olarak saklanır;
hedef RED veya ürün regresyonu kanıtı yerine kullanılmaz. Dosya adında
`green` bulunması gerçek exit değerini değiştirmez.

### Gerçek LLVM kaynak çifti — paketli hazırlık, henüz kabul değil

`tests/product_corpus/cohorts/llvm-caller-slot-v1.json`, pinned LLVM `malloc.c`
1930–1933 satırlarındaki caller-slot overwrite adayını ve 1935–1937 komşu
kontrolünü tek content-addressed hazırlık dosyasında tutar. Native `stdlib.h`
öneki dışında özgün ifadeler/yorumlar/boşluklar değişmez. Tam TU SHA-256'ları
`a118c66873a197c3b55534f86500828492724ebd2e347df4414e2a71d322617a`
ve `a99952fd6198cb713db7d260925467f68181fcba3f9d6acc571eb2c87386381a`.

Bağımsız ön inceleme, overwrite mekanizmasını hazırlığa uygun buldu; komşu
kontrol ayrı safe kota değildir. Diğer logical-result-after-free adayı mevcut
frozen scalar-after-release örneğine yakın bulundu ve kota dışında tutuldu.
Gerçek API response/base64/file/blob/span eşleşmesi ve ön karar U003
`retained-label-host-path-v1` kanıtlarında korunur; önceki dosyanın yalnız dizin
adı veya başka LLVM dosyasının receipt'i köken kanıtı yapılmadı. Kaynak/API
eşleşmesi signed-tag, kaynak-bağımsız lineage veya hak/yayın izni ispatı değildir.

Yeni explicit `source-cohort-check --cohort ...` okuyucusu 64 kayıtlık paket,
ayrı canonical kayıt/source hashleri, shared-origin API/raw satır eşleşmesi,
same-cluster kontrol bağı ve bütün okuma boyunca son kimlik denetimi kullanır.
20 yeni sentetik test; bozuk/çapraz API, hash/range/rewrite, duplicate/orphan,
erken qualification, 64 MiB bağlı girdi bütçesi, geç kaynak/API/paket değişimi
ve private payload sızıntısını sınar. İzole eski kod + yeni test RED'i saklandı;
uygulama sonrası 191 profile ve 88 identity testi, 117 testlik aynı workflow
seçimi ve gerçek çiftin CLI kontrolü yerelde geçti. 1020 sentetik kaydın 16
pakete sığması yalnız temsil testi, gerçek korpus veya bağımsızlık kanıtı değildir.

Gerçek kaynak çiftinin native compiler/ABI preflight'i, all-rule etiketleri,
rights/admission ve katalog farkının bağımsız prospective successor'ı bu
hazırlıktan ayrı kapılardır. Mevcut seçim 2/1020 kalır; yeni candidate/control
henüz eklenmez, admitted_sources ve ek kota sıfır, yedi qualification false.
Korumalı eski 157 girdi ve daha sıkı kalite eşikleri değiştirilmez.

### Yeni genel CI koşusunda aynı deadline RED'i

Exact `ef039c68cd2d059d4afa2e42b83e725597c6f813` için genel
[CI 34696545887](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34696545887)
yine 1/1583 testte başarısızdır. Aynı checkpoint testinin ilk reusable-response
assertion'ı, `runtime_before` beş saniyelik deadline'ı nedeniyle düşer: bu kez
8 modül, 208542936 byte read/hash, 5015822 us wall ve 412150 us thread CPU.
İlgili runtime/coordinator/test/workflow baytları `05a5c1d` ile aynıdır;
sonraki ürün kapıları skipped kalır. Bağımsız salt-okunur teşhis aynı mekanizmayı
doğruladı, kalıcı kök neden veya U003'ten kaynaklandığı iddia edilmedi.
U004 RED kaydı ve CH12 dayanıklılık sahipliği değişmez. Başarılı ayrı identity
koşusu bu genel CI'ı onarmaz; cache kodu/bütçesi, warmup veya kör rerun yoktur.

### LLVM paket checkpoint'i — bağımsız hazırlık ve compiler preflight

Exact `5fc09da642bd45f4555cfd343cfcd983a5089b4e` üzerindeki yedi dosyalık
hazırlık uygulaması bağımsız PASS aldı. Karar, U003 kalıcı kanıt kökündeki
`source-cohort-v1/checkpoint-review-5fc09da.json`, SHA-256
`537e32ea9a9803ceae31c82216a2dc079e363d391c245f59d68c14fff1c9d379`.
Bu, kaynak kabulü veya U003 receipt'i değil; yalnız okuyucu/hazırlık sınırıdır.

Aynı temiz head'de iki gerçek TU, Ubuntu Clang 20.1.2 ve native `stdlib.h`
ile offline/read-only container içinde ayrı ayrı kontrol edildi. Seçili CDB
ve simüle frontend-adjusted komut biçimlerinde toplam 26 adımın 20'si exit 0;
yanlış pointer genişliği, malloc dönüş tipi ve caller-slot parametre tipinin
altı negatif derlemesi amaçlanan static assertion'da exit 1 verdi. İki kaynak
ve birleşik probe için dependency listeleri önce/sonra ve komut biçimleri
arasında eşleşti; 27 dosyalık birleşim ve 53 stream/CDB dosyası yeniden hashlendi.
Bu gerçek fonksiyon/analyzer yürütümü veya calling-ABI/allocator davranış
kanıtı değildir. Kaynaklar, compiler ve probe boyut/tip ön koşullarıyla sınırlıdır.

İlk geçici deney değiştirilmeden saklandı. Aynı producer/source baytları kalıcı
dizine alındıktan sonraki yeni capture kalıcı yolları bağlar; observation baytları
aynıdır. Bu, başarısız ölçümü temizleyen rerun veya performans warmup değildir.
Kalıcı `source-cohort-v1/native/summary.json` SHA-256
`a5bb4cf7e5e4aeb9ebcfbd698e98ed7e09f4ab4db8b777f469fdd94114288869`,
`native/observation/summary.json` SHA-256
`5443995ea09a455e2d481581062379be69a4ff9791e9aa41c52243941e6d5bd3`.
Ayrı bağımsız raw-packet denetimi `source-cohort-v1/native-review-5fc09da.json`,
SHA-256 `ba3f01d88086ffb94032d413a1feba3284caba2b100d620b6b59a3a99bd735ef`;
yalnız `PASS_BOUNDED_COMPILER_ONLY_PREFLIGHT` verir.

Ayrı prospective sınıflandırmanın onayladığı sequence 4 baytları uygulandı:
yalnız yeni LLVM paketi ile **157 → 158** korunan girdi. Önceki 157 satır/hash,
52 fixture, 15 capability, tarihsel snapshot/receipt ve bütün floors korunur.
Inventory SHA-256 `4ac2a1c318b1c44e8168d7aa7b44aec96baaa36926e1ac0044d59c0adec873d2`,
katalog SHA-256 `56a99a03102a1988f8e1dfb896184b3a52a95cbd186c721346390ff208ca055f`.
Uygulanmış checkpoint ayrıca yeni exact-head inceleme gerektirir.

Yeni paketin source/cluster admission, bağımsız all-rule etiketleri ve hak/yayın
clearance'ı hâlâ açık kapılardır. Caller-slot overwrite aday, komşusu aynı
mekanizmalı nonquota kontrol olarak kalır; beklenen satır 5/sütun 3 henüz
gözlenmiş rapor değildir. Sonraki normal eksik rapor FN kalır. Seçim **2/1020**,
ek kota sıfır, yedi qualification false ve readiness exit 2 değişmez.
Yeni head için hosted başarı veya tüm genel CI yeşil iddiası yoktur.

### LLVM source-entry ve gerçek compiler packet okuyucusu

Yeni `cohort-native-check` yolu iki LLVM kaydını ayrı 3681 baytlık
`tests/product_corpus/cohort_evidence/llvm-caller-slot-v1.json` sidecar'ıyla
kaydedilmiş gerçek compiler packet'ine bağlar. Source shard, iki TU, eski GCC
seçim/etiket/platform kayıtları ve 158 korunan input baytı değiştirilmedi.
Sidecar SHA-256 `0e8aebb79d802c9353f329ba8b5971744aa486fe8e546b8549481069c7d68275`.

Gerçek çiftin CLI okuyucusu 26 komut/53 stream-CDB dosyasını, altı amaçlanan
static-assert reddini, tam raw dependency birleşimini, image/producer/source
bağlarını ve geçmiş `5fc09da` Git nesnelerini doğruladı. Yeni bir compiler veya
analyzer çalıştırılmadı. Producer helper'ının bugünkü sürümü değişebilir; eski
hash ve boyut gerçek ancestor blob'una bağlı kalır. Bütün canlı dış dosyalar,
boş container/observation stderr'leri ve üç native dizin ortak son kimlik
kontrolündedir. Hakem yalnız bu compiler ön kontrolünün bağını onaylamıştı;
bu okuyucu yeni all-rule veya source-admission kararı üretmez.

20 yeni bağımsız kurulmuş sentetik packet testi, eski temiz `67e131f` kodunda
RED verdi; CLI'nin bilinmeyen komut reddi ve eksik API/private-guard hataları
korundu. Geliştirilen kodda 211 profile, 88 identity ve 24 quality testi;
workflow'un 137 seçili profile testi ve gerçek packet CLI kontrolü geçti.
Tutarlı yeniden hashlenmiş eksik stdlib/peer dependency, her yerde aynı sahte
historical helper boyutu ve iki formda aynı değiştirilmiş source identity de
ret alır. Native fixture'lar gerçek upstream/derleme/kota kanıtı sayılmaz.
Windows link oluşturma yetkisi yoksa test bir gözlenen canonical-path alias
reddini ayrıca zorlar; fiziksel NTFS symlink kapsamı varmış gibi sunulmaz.

Yeni sidecar için integrity'nin eksik protected-input RED'i beklenendir;
ayrı bağımsız source-derived prospective successor ve exact-head uygulama
denetimi tamamlanmadan katalog güncellenmiş veya U003 bitmiş sayılmaz.
Seçim hâlâ 2/1020, kontrol nonquota, ek kota sıfır ve qualification false.
All-rule etiketleri, source/cluster/origin kabulü, haklar ve tam quota kapıları
ayrı açık işlerdir; yeni native okuyucu bunların yerine geçmez.

### 67e131f gerçek hosted identity başarısı ve ayrı genel CI RED'i

[Identity 34699316728](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34699316728)
attempt 1 üç platformda başarılıdır. Her lane'de 88 identity ve 117 seçili
profile testi geçti; bu koşu yeni cohort-native okuyucusundan ÖNCEDİR.
Eski 636 baytlık mixed-storage native case, yeni LLVM/parent-child yeterliliği
değildir. Yedi API/ZIP/member/source bağı ve 34 kayıtlı dosya hash'i bağımsız
denetlendi. Windows post-case diagnostic 23297 ms, CIM_LOADED 22946 ms,
query aralığı 44 ms ve ayrı policy probe 531 ms idi; kalıcı CIM onarımı iddiası yoktur.
Ham kanıt U003 `cohort-native-bridge-v1/hosted-34699316728` altında,
summary SHA-256 `4073daf7b6d26d567a5efc9bd9ef652392d18f5bc4bc21bda4d5f1e5f1e30d83`.

Ayrı [genel CI 34699316742](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34699316742)
yine aynı ilk reusable-response assertion'ında 1/1583 RED verdi.
`runtime_before:deadline`, module_read, 8 modül, 234233048 byte read/hash,
5014776 us wall ve 1014945 us thread CPU kaydedildi. Runtime digest/input
witness boş kalıp reuse doğru reddedildi; sonraki ürün kapıları skipped.
İlgili runtime/coordinator/worker/test/workflow baytları EF ve 05a5 ile aynı;
bu, bütün olası nedenlerden bağımsızlık veya kesin I/O/host-contention teşhisi
değildir. Cache fix, warmup, süre artırma veya kör rerun yapılmadı; U004 RED
kaydı ve ilgili CH12 dayanıklılık sahipliği korunur.

Her iki gerçek bağımsız karar `cohort-native-bridge-v1/hosted-review-67e131f.json`,
SHA-256 `e3cbf66d09b444cca0a0fc6fa7b9f8fdfdeb2bbbe16ea82198eae0bc5841e14f`.
Ham GH capture wrapper'ları o sırada düzenlenen primary checkout'u bildirir;
hosted head ve kaynak bağları ayrıca temiz exact `67e131f` klonuyla doğrulandı.
Identity başarısı genel CI veya U003/ürün başarı iddiasına dönüştürülmez.
