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

### Compiler packet okuyucusu — bağımsız inceleme düzeltmeleri

Bağımsız denetçi `ea5c1ac27e131926a565a43ba5b6417042b4bf90` için PASS
vermedi: mapped kaynakların her kayıtlı formda aynı yabancı absolute yola
çözülmesi ve compiler kimliğinin producer'ın 512 MiB sınırını aşması kabul
ediliyordu. Ayrıca açık Linux/x86-64 profiliyle çelişen image Os/Architecture
metadata'sı reddedilmiyordu. Gerçek retained packet bu çelişkileri taşımıyordu.

Üç odaklı regresyon, dış hashleri ve tekrarlanan iç iddiaları birlikte
yenileyerek eski kodda 18 ayrı beklenen-ret başarısızlığını üretti; yalnız
hash uyuşmazlığına dayalı test değildir. RED capture SHA-256
`b25fdcc0b569b7885d5198e1b8255bbeb65eacd06db879d4ac30a3320c26143b`.
Dar düzeltme sonrasında aynı testler GREEN verdi; capture SHA-256
`5a1376e8c16e275d6de97b436f1b768bfd4d0669c588cce29e93382f36577961`.
Meşru compiler/OS symlink'leri ve 512 MiB metadata sınırının kendisi kabul
edilir; sınırın bir bayt üstü ve 4 GiB hem compiler hem header kaydında ret alır.
Sabit mount'ların tüm sekiz kaynak/probe/helper logical kimliği ayrıca sınanır.

214 profile, 88 identity ve 24 quality testi ile gerçek 26-komut/53-stream
packet CLI okuması geçti. Yeni compiler/analyzer çalıştırılmadı; eski native
baytlar, source shard, seçim 2/1020, sıfır ek kota ve qualification false
korundu. Bu düzeltme için yeni exact-head bağımsız inceleme gerekir; eski
inceleme PASS'e çevrilmez ve pending inventory önerisi uygulanmış sayılmaz.

### İncelenmiş compiler-evidence envanter ardılı

Temiz `244a994411e5174b553e10304f5bdc4f559af9e0` üzerinde bağımsız
`/root/retained_binding_exact_verifier` okuyucu checkpoint'ine ve ayrı
prospective input sınıflandırmasına PASS verdi; önceki `ea5c1ac` bulguları
tarihsel başarısız inceleme olarak korunur. Gerçek karar
`cohort-native-bridge-v1/checkpoint-review-244a994.json`, SHA-256
`f4de8f6ef838900caf177fe543a1f527c0eeef08d02b0eb2379ab98dede28851`.
214 profile, 88 identity ve 24 quality testi bağımsız çalıştırıldı. Temiz
head'de workflow'un 140 seçili profile testi ve gerçek native okuyucu da geçti.

Yalnız önceden incelenen `cohort_evidence/llvm-caller-slot-v1.json` eklenerek
korumalı input sayısı 158'den 159'a, evidence sequence 4'ten 5'e çıkarıldı.
Önceki 158 girdi, 52 fixture sözleşmesi, 15 capability, selection, snapshots,
eşikler ve bütün BOOK/PLAN/TODO/PROGRESS baytları değişmez. Source base
`67e131fa3fa358f50bc8433ec8378aaa6d0b1db5`, source head `244a994` kalır.
Onaylı tam katalog SHA-256
`10d6031382098dc12649af86ef968c35a2da24931534341b998d65960104cfb5`,
inventory `5bbffcaa2510892e2989606ff0708ce0307bbc7b2abc6e28d5694d0c61c59c9c`,
payload `06b371221edd01a87b22acba2960fd399bede89c6e7573b25256011872312698`.
Gerçek integrity kontrolü ve ayrı exact-old/new harness'in 12 in-memory
negatifi geçti; bu harness'in ek iddiaları production validator'a mal edilmez.

Kanıt düzeltmesi: `cohort-native-fixed-exact-successor-required-red.json`
yanlış `integrity` altkomutunun argparse reddidir, eksik-input kanıtı değildir.
Silinmedi veya yeniden etiketlenmedi. Doğru `cwe_quality.py check` denemesi
`cohort-native-fixed-exact-missing-input-red.json`, SHA-256
`13390eac9a8c8447c470fa652a63a712ab13cbf3e002722b1a4aaf8320ae3d90`,
temiz aynı head'de gerçek protected-input RED'ini gösterir; uygulama sonrası
aynı kontrol GREEN oldu. Bağımsız denetçi bu ayrımı da doğruladı.

Bu uygulama için yeni temiz exact-head bağımsız denetim gerekir; prospective
PASS uygulama PASS'i olarak taşınmaz. U003 POP yoktur. Seçim 2/1020, LLVM
aday/kontrol non-admitted, ek kota sıfır ve qualification false kalır.
Sıradaki ayrı etiket hazırlığında `--assumptions` açıkken iki kaynağın birer
`assumption` Info hedefi temsil edilmelidir; eski yalnız no-trigger kabul eden
retained etiket şeması bu girdilere zorlanmaz. Henüz all-rule etiket PASS'i yoktur.

Önceki exact `67e131f` [Windows 34699316708](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34699316708)
koşusunun tamamlanmış başarı durumu API'den ayrıca okundu. Bu durum kontrolü
yeni reader'ın hosted başarısı veya ham Windows suite denetimi değildir;
önceden kaydedilen genel CI deadline RED'i değişmez.

### Caller-slot çiftinin bağımsız all-rule etiket önerisi

Yeni `tests/product_corpus/cohort_labels/llvm-caller-slot-v1.json`, aynı iki
kaynağı değiştirmeden 32 aile ve altı proje-diagnostiği satırına bağlar.
Öneri SHA-256 `a9b8d266b43881aa950cb0fa19ba5d59900e3403966352b87cc198ed817d6ef0`.
Özgün memory-leak hedefi `testMallocWithParam:5:3`, CWE-401, multiplicity 1
korunur. Assumptions-enabled profil iki ayrı Info hedefi önerir: candidate
`3:32`, control `3:34`, her biri multiplicity 1 ve boş CWE listesi. Bunlar
statik kaynak çıkarımlarıdır, gözlenmiş analyzer çıktısı veya CWE metric'i değil.

İlk semantik ön inceleme bütün satırları, gerçek kaynak/API extraction'ı,
22 definition referansını ve native CDB bağını inceledi. İki ifade düzeltildi:
control'da bulunmayan zero assignment gerekçeden çıkarıldı; default assert
recovery açık olarak kaydedilip yasak broken-TU recovery/partial coverage
kabulünden ayrıldı. Bu ön inceleme ACCEPT_SOURCE_LABELS veya implementation
PASS vermedi; temiz exact-head incelemeleri ayrı gerekir.

Bağımsız kurulan 23 yeni sentetik etiket testi gerçek eski `37e99c7` kodunda
RED verdi: 21 eksik API hatası ve üç CLI alt-test başarısızlığı. Son test dosyası
baseline ile byte eşittir. Capture SHA-256
`d3a195a810c2459c86ef5a12f7a3cae9c542de12f667b3f8e5b4e8bce79ec077`;
aynı testlerin geliştirme ağacındaki GREEN capture'ı
`2b520b2f8c16829951ddb671015ddf27f1355264414b9fcbcecd97a945e7c2a1`.
Sentetik review kayıtları gerçek semantik onay değildir. Unknown/unsupported
null hedefleri scored-safe boş listeden; proje multiplicity sayımı CWE
sayımından ayrı sınanır. Windows'ta fiziksel link oluşturulamazsa gözlenen
canonical-path alias reddi zorlanır; sessiz skip veya NTFS kapsamı iddiası yoktur.

237 profile, 88 identity ve 24 quality testi; workflow'un 163 seçili profile
testi ve gerçek öneri CLI okuması geçti. CLI yalnız 1 önerilen CWE occurrence,
2 proje occurrence ve doğrulanmış kaynak bağları döndürdü; henüz semantik
review false, review_head null, admission/ek kota sıfır ve qualification false.
Gerçek native çift, eski labels/selection ve quota 2/1020 değiştirilmedi.
Yeni label input'u için protected inventory RED'i beklenendir; yalnız yeni
bağımsız prospective successor sonrası integrity GREEN elde edilebilir.

Komut tek-TU/üç tekrar için UNEXECUTED şablondur. Eski gerçek iki-entry native
CDB hash'i ile gelecekteki tek-entry ürün CDB kimliği ayrıdır. Binary, path,
environment, compiler/resource/header ve embedded-frontend bağları bekler.
Otomatik config ve bütün source/header lexical alias .csk girdilerinin yokluğu
bir gelecek çalıştırma şartıdır; şimdi doğrulanmış yokluk gibi sunulmaz.
Dört planlı aile hâlâ PLANNED_NOT_IMPLEMENTED, control aynı cluster'da nonquota.
All-rule kabulü, source/origin bağımsızlığı, haklar ve U003 bitişi ayrı kapılardır.

### İncelenmiş all-rule etiket checkpoint'i ve korumalı girdi ardılı

Temiz `0595f96581b7cb76698da6756a77e3746987dc39` üzerinde iki ayrı karar
alındı. `/root/parent_child_native_verifier`, bütün 32 aile ve altı proje
satırını gerçek kaynak/API extraction'ı, 22 Git referansı ve native CDB bağıyla
inceleyip koşullu `ACCEPT_SOURCE_LABELS` verdi. Gerçek dış receipt
`cohort-ground-truth-v1/source-label-review-0595f96.json`, SHA-256
`1090769d2f19f23c14aa02dfce49d8b1c9fedaa00ca91cd436ec58f02e73e297`.
Bağımsız `/root/retained_binding_exact_verifier`, okuyucu uygulamasına ve ayrı
prospective girdi sınıflandırmasına PASS verdi; gerçek kayıt
`cohort-ground-truth-v1/checkpoint-review-0595f96.json`, SHA-256
`34c5ea76d112d20cab63437c02fa84524254db7c8e1d6f07d002cabd19f1c569`.
237 profile, 88 identity ve 24 quality testi bağımsız çalıştırıldı; ek
değişim/boş-stream/dizin negatifleri de ret verdi. Bu iki karar birbirinin
yerine geçmez ve gerçekleşmemiş analyzer çalıştırması iddia etmez.

Gerçek receipt ile CLI artık `source_labels_independently_reviewed=true` ve
`review_head=0595f96…` döndürür. Capture SHA-256
`afe2b7f5303eb67b2940871a3de179e3e2643fe3bc846d04cfcaeaa02c122bfc`.
Bir önerilen CWE occurrence ve iki önerilen proje occurrence hâlâ gözlenmemiş
hedeflerdir. Admission ve ek kota sıfır; yedi qualification bayrağı false.
Control aynı cluster'da nonquota; koşullu safe etiketler caller'ın gelecekte
free yapacağını veya planlı ailelerin ürün başarısını kanıtlamaz.

Yalnız önceden incelenen `cohort_labels/llvm-caller-slot-v1.json` eklenerek
korumalı input sayısı 159'dan 160'a, sequence 5'ten 6'ya çıkarıldı. Source base
`37e99c7f660f5cebc8f3b8a78a884cd01810a0ed`, source head `0595f96` kalır.
Önceki 159 girdi, 52 fixture sözleşmesi, 15 capability, selection, snapshots,
eşikler ve bütün BOOK/PLAN/TODO/PROGRESS baytları korunur. Tam katalog SHA-256
`94bfef3b3eb52a02a28f921a20b674d69a4486e9b3c41fac305cdf86d69553dd`,
inventory `2813fb229394b535b475660b9a9d8e71c9d6c71988e93acc20334d8f0f4c0f0d`,
payload `9fc9f5e8ca79970ecd275854227b3040588a4426cee0e3e14c2ef2ee57342f6a`.
Gerçek `cwe_quality.py check` GREEN; ayrı exact-old/new harness'in 12
in-memory negatifi geçti. Harness'e özgü ek iddialar production validator'a
mal edilmez. Uygulanan temiz head için yeni bağımsız denetim gerekir.

Kanıt düzeltmesi: `cohort-label-applied-catalog-tests-green.json` adındaki
ilk capture yanlış test yolu nedeniyle sıfır test, exit 5 kaydetmiştir;
başarı kanıtı değildir ve silinmez. Doğru hedef
`tests/cwe_corpus/test_catalog.py` ayrıca çalıştırıldı: 65 test geçti, capture
SHA-256 `d0e0eceaa72f235cb4b77d96d82636ddbbb8852404c45817c41001cdee3d40fd`.
Commit öncesi guard denemesi de beklenen clean-tree şartında exit 2
`dirty implementation` verdi; dosya adındaki GREEN sözcüğü başarı değildir.
Gerçek guard sonucu yalnız temiz commit üzerinde yeniden alınacaktır.

### Önceki 37e99c7 hosted sonuçları: başarısızlıklar korunur

[Identity 34702319454](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34702319454)
attempt 1 tamamlandı ve **başarısız**. Gerçek 31 dosya, altı API ZIP/member
bağı, source/helper/parser kimliği bağımsız denetlendi. Ham paket özeti
SHA-256 `b2c923169f7dca7409c6a8b1dcdb8f11793cf63bdafaf13d61f721ec559ce504`;
`cohort-ground-truth-v1/hosted-review-37e99c7.json` kararı
`308cbe5ebcb59af20d672771afd04ee951dfe37ae1ff226bf3ecf4c6f3ccdde8`.
Linux/macOS işleri başarılı, Windows işi başarısızdır. Üçünde de 88 identity
ve 140 seçili profile testi geçti; Windows profile testleri 251.217 saniye.
Windows native-case artifact'ı yoktur. İki başarılı native-case artifact'ı
eski GCC mixed-storage girdisidir, yeni LLVM çiftinin native-product kanıtı değil.

Windows hata zinciri `capture_case → capture → native_metadata → WINDOWS_OS_QUERY`:
30 saniyelik PowerShell TIMEOUT, ilk case metadata aşamasında, kaynak
materialization/compiler probe başlamadan oluştu. İlgili helper baytları
`244a994` ve `67e131f` ile aynıdır. Özgün sorgunun iç zaman dökümü yoktur;
startup, module load, CIM, serialization veya host contention kök nedeni
kanıtlanmış sayılmaz. Sonraki ayrı teşhis 22531 ms, CIM_LOADED 22290 ms,
Utility import 4 ms ve gerçek CIM query aralığı 41 ms kaydetti. 45 ms ifadesi
Utility import'u da içerir. Sonraki başarı önceki TIMEOUT'u düzeltmez veya
onun iç nedenini kanıtlamaz; retry/warmup/timeout artırımı uygulanmadı.

Aynı SHA'nın son API durumları: Project FIFO `34702319362`, Juliet
`34702319397` ve Windows `34702319404` başarılı; genel CI `34702319380`
başarısız. Bunlar status yenilemesidir, genel CI kök neden denetimi değildir.
Capture SHA-256 `1af56d4c875f0a0777ddb123688ba80496bb3569a26f028e92032dc9aa2c47b1`.
Bu sonuçlar yeni checkpoint'in hosted başarısına taşınmaz. U003 POP yok;
selection 2/1020, LLVM non-admitted, haklar ve ürün/native qualification bekler.

### Pinned LLVM yol/notice gözlemi ve bağımsızlık HOLD'u

Temiz `9900bbffecaa2d8cba110b1dacb7bed3d3efb811` üzerinde aynı LLVM revision
`87f0227cb60147a26a1eeb4fb06e3b505e9c7261` için root → clang → test → Analysis
Git ağacı zinciri ve özgün `malloc.c` blob'u yeniden bağlandı. Dört complete
nonrecursive ağaçtaki 38/21/80/816 entry'nin Git tree OID'leri hesaplandı.
Yedi actual API yanıtı ve source-parent LICENSE/COPYING/NOTICE ad eşleşmeleri
iki notice verdi: root `LICENSE.TXT` (15141 byte, SHA-256
`8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee`) ve
`clang/LICENSE.TXT` (15140 byte,
`ebcd9bbf783a73d05c53ba4d586b8d5813dcdf3bbec50265860ccc885e606f47`).
Legacy copyright aralıkları ve son boş satır farklıdır; tek belgeymiş gibi
birleştirilmez. Byte/Git-nesnesi doğrulaması kaynak özelinde hukuki uygulanabilirlik,
tam attribution veya dağıtım onayı değildir. Commit API'de unsigned görünür;
commit→root tree bağı API gözlemidir, imza/kimliği doğrulanmış lineage değildir.

`/root/parent_child_native_verifier` 18 ham dosya, yedi empty stderr, iki
notice ve source/API bağını bağımsız doğruladı. Paket
`cohort-provenance-v1/llvm-pinned-path-notices/summary.json`, SHA-256
`73b172264c23085dbac67b281b617e209597461482ee69c6466479bfae2a698c`;
gerçek `notice-observation-review-9900bbf.json`
`76bd24ab24d1c679adb2d1b9aaf5e20d8e345d14e78094d520a974de4fd7e203`.
Yalnız gözlem PASS'i; lisans/redistribution/admission/ek kota false/sıfır.

Ayrı comparison packet 14 karşılaştırma, 25 repository referansı ve 25
repository/external span'i; gerçek iki GCC source byte'ını ve üç tam saklanan
arama çıktısını bağladı. Paket SHA-256
`ceefb642839e36850f87c8cd2699fca0b094b33c5c74ce7e41a0477b2a05cfcb`.
Sınırlı spelling araması global özgünlük veya bütün eşdeğerlerin yokluğu kanıtı
değildir. Yeni maddi yakınlıklar: `InterproceduralTest.cpp` 1884–1936 aynı
caller slot'una static pointer yazıp alias ile siler; `FdResourceRuleTest.cpp`
306–347 acquired FD/DIR handle slot'larını alias/helper üzerinden siler;
`MemoryLeakRuleExTest.cpp` 1662–1677 storage reassignment ile eski allocation
sorumluluğunu ayırır. Ayrı API/family veya doğrudan malloc RHS farkı bu
bileşimin eğitimden bağımsızlığını tek başına kanıtlamaz.

Gerçek `/root/retained_binding_exact_verifier` kararı
`cohort-provenance-v1/source-cluster-review-9900bbf.json`, SHA-256
`d8e96ea89143c044689337b0e13e5c9f8cf56e71a045bbf875d7512f885d12d5`:
candidate **HELD_NONQUOTA**, control **SUPPLEMENTAL_NONQUOTA**. Önceki
`ACCEPT_SOURCE_LABELS` ve preparation-only kararları değiştirilmez; etiket
kabulü cluster yeniliği değildir. Selection 2/1020 ve source/label/native
baytları korunur. Bu aday için admission entegrasyonuna geçilmez; yeni somut
bağımsızlık kanıtı olmadan aynı öneri başka isimle tekrar sayılmaz.

### 9900bbf Windows identity iptali ve dar Git-okuma düzeltmesi

[Identity 34704593020](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34704593020)
attempt 1 **cancelled** kaldı. Linux/macOS 88 identity +163 profile testini
tamamladı; profile süreleri 48.284/167.866 saniye. Windows 88 identity testi
geçti, ancak profile suite tamamlanmadı. Üç identity ve eski 636-byte GCC
mixed-storage kaynağına ait iki native-case artifact'ı vardır; Windows
native-case ve post-case diagnostic yoktur. LLVM native ürün kanıtı değildir.

Exact Windows check annotation, 10m0s job sınırının aşıldığını açıkça bildirir;
capture SHA-256 `77d7f900129c60af89030f1446bef3b0535c85ac8876326eac12c3f2b4387414`.
Kesilme, yeni source-target negatifinde `verify_cohort_ground_truth` → native
reader → `verify_reviewed_files` → `git cat-file -e` sırasında KeyboardInterrupt
olarak görünür. Bu stack o tek Git çağrısının tüm süreyi tükettiğini veya bütün
profile süresinin dökümünü kanıtlamaz. Önceki 37e99c7 PowerShell query TIMEOUT'u
ile aynı olay diye adlandırılmaz. Workflow timeout 10 dakika ve cancel-in-progress
false kalır; iptal olmuş işlem yeniden başlatılmadı.

Ham paket özeti SHA-256
`a1db519e5e4639168e03fd10ed013cb835fde5834bb692d804d9049ff88537cf`.
`/root/parent_child_native_verifier` temiz detached 9900 audit clone'unda 29
dosya, 11 empty stderr, beş ZIP/member, source/helper/parser ve annotation bağını
doğruladı. Gerçek `cohort-provenance-v1/hosted-review-9900bbf.json`
SHA-256 `302d5afcf73b42f4ddc9529d59c0e666eb4d6f300047cea9463d97ca48f318a4`.
Windows suite/native kapısı başarısız kalır; hiçbir eski failure temizlenmez.

Tekrarlanabilir yerel process-count RED'i, gerçek 22 Git referansının eski
okuyucuda 68 süreç açtığını gösterdi; capture SHA-256
`d135baeef0ac3a5799a33a7325a8cc5b300f95da816a7b2daee7953a9dcde3a6`.
Önbelleksiz sınırlı ls-tree/cat-file batch düzeltmesi aynı gerçek hashleri dört
süreçle doğruladı; ilk GREEN
`db77b7ce0dfc61c79e81542627c4601739f61e77a3fb131716b52a452902fbdb`.
Mevcut 237 profile testi geçti. Bu yapısal süreç azalması observed Windows
deadline düzeldi iddiası değildir; yeni exact-head bağımsız kod denetimi ve
fresh hosted sonuç gerekir. Saklanan native packet/producer baytları, eski review head'leri,
dosya/aggregate kabul sınırları, all-rule/kota semantiği ve sabit süreler korunur.

Bağımsız test üreticisinin yalnız test dosyası değişen isolated 9900 checkout'unda
22 yeni test eski production'a karşı 53 beklenen failure, sıfır error/skip verdi;
primary tekrarının capture SHA-256'sı
`ed20b200925bedbe31c5a8d66f2b0ec41f58aab5f1dfeea7c13aee7ec91e67f9`.
Yeni production'da aynı 22 test GREEN; capture
`30c57dc7061f1fea7de88468f909b0b09a73d86e8b73056766abefe0278fbdba`.
Gerçek Git fixture'ları historical ancestor/dirty checkout ayrımını, executable,
symlink/gitlink modlarını, aynı OID'nin ayrı yollarını, Unicode UTF-16 argv
sınırını, tam 16 MiB ve daha büyük toplamların bölünmesini sınar. Kırk tree/batch
protocol bozumu, sonraki chunk hatası ve tekrar okumada cache olmaması ret
sınırlarını kontrol eder; synthetic test nesneleri gerçek source/native kanıtı
diye sunulmaz. Fiziksel 8 KiB checkout yolu değil, tek-yol soft sınırı için
yalnız serialization ölçümü yapay büyütülür.

Tam profile suite 259 test (23.455 saniye), capture SHA-256
`3a1d3c7b37775f07d3db0761ad666015c45a5a36af2b3472d6aec55367fb7286`;
workflow'un korunan seçimine eklenen yeni sınıfla 185 test (22.549 saniye),
`294ca10a3050060c98ff3d3a976d429480f1a0ad98ecce253fe5dd758588a295`.
Ayrıca 88 identity, 24 quality ve 65 catalog testi geçti. İki workflow satırının
selector assertion'ı ayrı RED/GREEN ile bağlandı; eski seçili testler çıkarılmadı.
Gerçek reviewed-label, legacy-label ve native-packet CLI okumaları ile inventory
kontrolü GREEN; readiness beklenen exit 2 ve selection 2/1020 olarak kaldı.
Bunlar commit öncesi yerel sonuçlardır; temiz exact-head guard/bağımsız denetim
ve yeni hosted Windows başarısının yerine geçmez. Yeni quota veya U003 POP yoktur.

### f2f2dad bağımsız ret ve POSIX byte-yol regresyonu

Temiz `f2f2dadfe176fa81f9684f6b3aebd402613ac322` bağımsız denetimi
`BLOCKED_FINDINGS` verdi; bu head push edilmedi. Gerçek karar
`cohort-provenance-v1/checkpoint-review-f2f2dad-blocked.json`, SHA-256
`f3195e7375cbcd18ddd0b4ce0b82ed26bae72bd2383d813ffec3849409a0f56d`.
259/88/24 test ve temiz guard geçse de, geçerli canonical POSIX checkout kökündeki
undecodable filename byte'ı için yeni UTF-16 hesabı `UnicodeEncodeError` üretti.
Hakem aynı historical Git blob'unu eski 9900 okuyucunun kabul ettiğini gösterdi.
Primary eski-kod GREEN ve f2f2dad RED tekrarlarını ayrı kaydetti; yeni dar
regresyon testi de düzeltmeden önce RED, capture SHA-256
`a4f68f1f7bc0ca3f47b67e53c729ebe8cf3f9730f4877062d2587d2a1b505547`.

Sayımda `surrogatepass` kullanımı bu kabul daralmasını giderir; Git'e verilen yol,
Windows UTF-16 unit/quoting hesabı ve tüm diğer sınırlar korunur. Gerçek
byte-yol probe GREEN; 23 focused test GREEN, SHA-256
`f9324ef2ed7d9559588028fc04f444db82fc61ab6eca554fed27d65fca79dc00`.
Tam Linux profile suite 260 test ve 88 identity testi geçti; full-profile capture
`7e193bc036471fe01b30287d3f7a7386ad9e4a2ae98ff41129dfa9a61638a041`.
Yeni filesystem regresyonunun POSIX koşulu Windows'ta açık skip gerekçesidir;
önceki 22 ortak test atlanmaz. Bu sonuçlar yeni exact-head bağımsız PASS değildir;
ilk ret kaydı ve eski hosted failures korunur.

### 9900bbf genel CI başarısızlığı ayrı kalır

[Genel CI 34704593063](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34704593063)
1583 CTest kaydından birinde başarısız, exit 8: `AnalysisCacheTest.`
`CheckpointSnapshotBindsPendingHeaderAndSidecarWithoutPublishingFindings`.
`reusableWorkerResponse` ilk assertion'ı false döner; sonraki resume/header/sidecar
assertion'larına ulaşılmaz. Exact log, runtime-before proof'un `module_read`
aşamasında beş saniyelik deadline'ı aştığını bildirir: wall 5005114 µs,
thread CPU 764590 µs, iki modülde 174537400 byte read/hash. Runtime digest ve
input witness boş; fresh analyzed coverage kaybolmaz, fakat reuse kanıtı verilmez.
Bu I/O, scheduler veya contention alt nedenini ya da hangi modülü kanıtlamaz.

`/root/parent_child_native_verifier` ham capture ve 3207 log satırını,
9900 exact source bağını bağımsız denetledi. Karar
`cohort-provenance-v1/prior-ci-review-9900bbf.json`, SHA-256
`7e919adedb6887985bed41c3afad3971592b078561c35a4a450be2a1972fe40a`.
Collector head f2f2dad ile gerçek hosted head 9900 ayrıdır. Failing runtime/test
ve genel CI dosyaları U003 kapsamı dışındadır ve 37e99c7'den beri değişmemiştir;
bu kayıt onları burada değiştirme izni değildir. U004 RED baseline ve sonraki
CH12 dayanıklılık sorumluluğu korunur. Git batching bu ayrı hatanın düzeltmesi
olarak sunulmaz; sonraki single-process/smoke/dogfood/corpus/thesis kapıları
çalışmamıştır ve all-CI PASS yoktur.

### a4cac55 gerçek hosted sonucu ve eksik fixture hata ayrıntısı

Bağımsız `PASS_IMPLEMENTATION_ONLY` alınan
`a4cac55f1996f50ef1fa253c7ac1f7ec385352e8` feature'a fast-forward gönderildi;
main ve ledger değişmedi. Gerçek review SHA-256
`2a963bb6dfce895700f355f77a1729ea06417920463e6f655bd5c27613ab3fd4`.
[Identity 34707372235](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34707372235)
attempt 1 **failure** ile tamamlandı; bu yerel review hosted/native PASS değildir.
Linux başarılı, macOS ve Windows işleri başarısız. Terminal packet özeti
`cohort-provenance-v1/hosted-34707372235/summary.json`, SHA-256
`4cf0aaad72e401f7198429423f3c91110652e9baf792de45440b216ddb899ee1`;
üç identity, yalnız Linux native-case ve bir Windows diagnostic artifact'ı vardır.
Linux native-case eski 636-byte GCC mixed-storage girdisidir; LLVM kanıtı değildir.

macOS 88 identity testini geçtikten sonra 186 profile testinde bir error verdi
(48.432 saniye). POSIX byte-root regresyonunun `os.fsencode` assertion'ı geçti;
fixture Git clone exit 128 verdi. Canonical destination çözümü ve production
`verify_reviewed_files` çağrısı henüz gerçekleşmedi. Captured stderr exception
metninde görünmediğinden filesystem, Git, normalization, config veya izin nedenleri
ayırt edilemez; APFS veya doğal macOS UTF-8 yasağı diye ilan edilmez. Diğer 185
test error/failure/skip bildirmedi. Native-case'e ulaşılmadı; artifact'ın yokluğu
compiler hatası kanıtı değildir. Bağımsız dar teşhis
`reviewed-fixture-diagnostics-v1/macos-fixture-review-a4cac55.json`, SHA-256
`17ce829f64d18e84fa7284fc409c70eb270e2c5a182a4ebd5a544c67cb28fcad`,
`CONFIRMED_FIXTURE_FAILURE_CAUSE_UNRESOLVED` kararıdır. O ilk snapshot'taki
Windows-running durumu sonraki terminal sonuca geriye dönük çevrilmez.

Windows bu kez 186 profile testini 319.623 saniyede tamamladı: 185 PASS, yalnız
POSIX filesystem regresyonu skipped=1. Bu tek actual completion, bütün gelecekteki
job deadline'larının çözüldüğünü veya kontrollü Windows performans farkını kanıtlamaz.
Ardından native-case, ilk kimlik toplamadaki `WINDOWS_OS_QUERY` sırasında 30 saniye
TIMEOUT verdi; native-case artifact'ı yoktur. Sonraki ayrı staged diagnostic OK:
elapsed 17547 ms, CIM_LOADED 17276 ms, Utility import aralığı 3 ms, CIM query
aralığı 36 ms ve serialization/son marker aralığı 18 ms. Bu sonraki ölçümler ilk
timeout'un iç dökümü değildir; sonraki başarı önceki başarısızlığı düzeltmez.
Policy gözleminde preference absent, effective/LocalMachine Unrestricted, diğer
scope'lar Undefined; bu tek başına performans kök nedeni veya policy değişikliği
gereği değildir. Query, timeout, environment ve workflow değiştirilmedi.

Eksik macOS hata kanıtı için yalnız test-owned fixture hata biçimlendirmesi eklendi:
asıl `CalledProcessError` cause ve byte alanları korunur; phase/exit/tam byte sayıları,
ilk 256 byte'ın escaped temsili ve truncation bayrakları görünür olur. Komut bir kez
çalışır; hata yine hatadır. Yeni dört test eski exact-a4 fixture'da altı beklenen
failure, sıfır error/skip verdi; primary RED capture SHA-256
`27fed4a681775c5a23a111f324b326dbd19a0914e004773b083ec1d98330dbd2`.
Gerçek yerel clone hatası ve açıkça synthetic 0/255/256/257/16384-byte transport
sınırları kullanıldı; test-owned destination korunur, stdout/OS_ERROR/TIMEOUT
davranışı değişmez. Yeni GREEN capture
`09613b4466e1b48bcd50ffae3b3b391b3bf6ff9d13e33249ef94157904992168`.
Tam 264 profile, 88 identity ve 24 quality testi GREEN; full-profile capture
`b214bcd9a214f30a36c212c5865612575539092b6948e67c8f6c14058b69d073`.
Bu diagnostic-only değişiklik macOS clone nedenini veya Windows timeout'unu
henüz çözmez. Yeni exact-head bağımsız denetim ve gerçek hosted hata ayrıntısı
gerekir. Production, selection 2/1020, LLVM HOLD, native/source/label/inventory
ve ledger baytları korunur; yeni kota veya U003 POP yoktur.

### 0b2f05e diagnostic checkpoint: gerçek clone hata baytları

Diagnostic-only `0b2f05e7bb041fdce9574ecc908e26b5d44e1828`, bağımsız
`PASS_IMPLEMENTATION_ONLY` sonrası feature'a fast-forward gönderildi; review
SHA-256 `9f5a0cee433bf07d4e58e7917837d646a26b0baf47e991adabe17daa3242da55`.
[Identity 34708661693](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34708661693)
attempt 1 failure: Linux success, macOS ve Windows failure. Terminal packet
`reviewed-fixture-diagnostics-v1/hosted-34708661693/summary.json`, SHA-256
`0d48e409d100570ee44926e2579b7011b37ab4c4135e15e1276610046ebfcbbf`.
Üç identity, yalnız Linux GCC native-case ve Windows diagnostic artifact'ı vardır;
metadata doğrulaması native tool/header byte'larının bağımsız yeniden açılması
veya LLVM/ürün yeterliliği değildir.

macOS 88 identity testi geçti; 190 profile testinde tek error, 54.647 saniye.
Yeni clone diagnostic stdout=0, stderr=161 byte ve truncated=false bildirir.
Git istenen byte-adlı worktree dizinini oluşturamadığını, `Illegal byte sequence`
hatasını bildirir. Decoded tam stderr SHA-256
`10f58d333ba0e5780e093881056de8568b1e0831d54b1355804293ac76d141d4`.
Hata hâlâ canonical root/production reader öncesindedir. Bu Git metni tek başına
doğrudan syscall errno gözlemi veya APFS teşhisi değildir.

Windows 190 profile testini 273.996 saniyede tamamladı, yalnız eski POSIX testi
skipped=1; ardından native-case TIMEOUT ve artifact yokluğu devam etti. Sonraki
ayrı staged query OK, elapsed 28219 ms; CIM_LOADED 27961, UTILITY_LOADED 27965,
CIM_QUERY_DONE 28006, QUERY_DONE 28029 ms. Bu sonraki başarılı query ilk timeout'un
iç dökümü veya düzeltmesi değildir; süre/policy/environment değiştirilmedi.

Dar test-feasibility önerisi bağımsız
`APPROVE_BOUNDED_PROPOSAL_WITH_REQUIRED_GATES` aldı; karar
`reviewed-fixture-feasibility-v1/proposal-review-0b2f05e.json`, SHA-256
`c0c9ec8ab0cbeee009e47374884ec8b3743fa096beaea7f1600bde6388d12709`.
Bu implementation PASS değildir. Normal clone/reader pozitif kontrolü, yalnız
Darwin mkdir EILSEQ sınırı, diğer bütün hataların korunması ve ortak serializer
regresyonu gerekir. Gerçek hosted mkdir errno/skip sayısı henüz gözlenmemiştir;
önceki başarısız kampanyalar başarılı diye yeniden etiketlenmez.

Terminal 0b packet'ini `/root/parent_child_native_verifier` bağımsız doğruladı:
`reviewed-fixture-diagnostics-v1/hosted-review-0b2f05e.json`, SHA-256
`4ec986b6888a2556003bcb72236d135ff8be9f53081c1528210f14cdffb97570`,
`OBSERVATIONS_VERIFIED_RUN_FAILED`. 28 kayıt hash'i, beş ZIP/JSON bağı, exact
head/source/helper/workflow ve gerçek loglar tutarlı. Collection wrapper ayrı
primary çalışma alanındaki extraction diff'ini kaydeder; temiz hosted checkout
ve gerçek executed head onunla karıştırılmaz. Windows'un kendi TIMEOUT stack'i
özgün `Win32_OperatingSystem` sorgusundaki 30 saniye sınırına bağlanır; case
materialization/compiler probe'ları öncesidir. İç kök neden hâlâ kanıtlanmaz.

Uygulama öncesi yalnız eski clone/read gövdesi helper'a çıkarıldı; eski 27 test
GREEN kaldı. Test-only izole baseline'a eklenen dokuz regresyon 15 beklenen
failure, sıfır error/skip üretti; RED capture SHA-256
`ff884eb2953c9fc15f6f4a3876961b50b5a9472a289342ace4f60b709a419468`.
ASCII probe'larda gerçek Git/historical byte'lar, yalnız hedeflenen noktada
sentetik mkdir/listing/reader hataları kullanıldı. Ortak serializer testinin
in-memory strict-encoding mutasyonu ayrıca tek `UnicodeEncodeError` RED verdi,
SHA-256 `37574fa78152be3a65847302f30841d2a45294aa6ca5177321dded8830b5d2a0`;
bu üretim dosyası veya gerçek subprocess argv değişikliği değildir.

Dar helper düzenlemesiyle 36 focused test sıfır skip/error/failure geçti,
GREEN SHA-256 `5ca465266cbfc57306ec2e5cb27518586c44d8e22885b98aac3adde58723a914`.
Tam 273 profile, 88 identity ve 24 quality testi GREEN; full-profile capture
SHA-256 `8ff89531dd06f30b73e95280bf5f7b3c6188663898a48a8e5f08ce128100080d`.
Linux'ta gerçek undecodable byte checkout okundu; portable sentetik skip akışı
gerçek macOS filesystem başarısı sayılmadı. Üretim okuyucusu, workflow/deadline,
source/native/label/inventory ve ledger değişmedi; selection 2/1020 ve LLVM HOLD
korunur. Bu kayıt tek başına yeni exact-head bağımsız PASS veya hosted onayı
değildir; U003 hazır değildir ve POP yapılmaz.

Ayrı [a4 genel CI 34707372190](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34707372190)
da kendi loguyla bağımsız failure: 1583 CTest kaydından 1582 PASS, bir failure,
exit 8. Aynı checkpoint snapshot testinin ilk reuse assertion'ında runtime-before
proof, `module_read` noktasında beş saniye deadline verdi: wall 5020909 µs,
thread CPU 738527 µs, iki modülde 170080952 byte read/hash. Hangi modül veya
I/O/scheduler/contention kök nedeni çıkarılamaz. Sonraki test/smoke/corpus kapıları
çalışmadı. Önceki 9900 failure'dan çıkarım yapılmadı; bu runtime/test/CI dosyaları
0b test-feasibility kapsamına taşınmadı ve eski RED yerinde kalır.
Retained karar SHA-256 `0beb790df2a161f4deceab6d026d7465fe4a7df554a469e2d1674d74eb197db3`;
bu yeniden kaydedilmiş JSON'da `lines` alanı `decoded_stdout_lines` olarak
adlandırılmıştır. Hakem yukarıdaki 0b hosted review'da bütün esas iddiaları
doğruladı; kayıt byte/alan bazında özgün receipt kopyası diye sunulmaz.

### Adlandırılmış skip gözlemi; aynı kabul sınırı

Temiz `2e810b3cd84beee7f3df854df4cbbe40caa4da5a` bağımsız
`PASS_IMPLEMENTATION_ONLY` aldı; review SHA-256
`270d12c873b756e316e09b7c88af12806881f73622d989bcb236c735325b3a09`.
Hakem 36/273/88/24 test, 199-test workflow seçimi, gerçek CLI ve queue guard'ı
doğruladı. Fakat sessiz macOS `skipped=1` toplamı bu fiziksel testi tanımlamaz:
seçili NativeRecipeTests ve ExternalInputTests içinde de koşullu skip vardır.
Toplamdan gerçek mkdir EILSEQ veya belirli skip kimliği çıkarılmayacak.

Gönderim öncesi bu kanıt boşluğu için yalnız mevcut Darwin mkdir EILSEQ dalına
sabit `REVIEWED_BYTE_ROOT_SKIP` ve aynı gerekçeyi stderr'e yazma eklendi; koşul,
SkipTest, positive control ve diğer hata davranışları değişmedi. Path veya Git
stderr'i bu işarete eklenmez. İzole exact-2e test-only baseline 36 testte tek
beklenen failure, sıfır error/skip verdi; capture SHA-256
`5d38c352a426efc2a4aac4bbd35f8d071a3bd969ea8f74626c4a740a766d668b`.
Sentetik sys görünümünün ayrı StringIO'su yalnız bu dalda exact marker üretimini,
diğer bütün akışlarda boş kalmasını doğrular. 36 focused GREEN capture
`c43cf386a4a4722b1d560819f5476c5cbef156cfa73b7dc50087664b02b1f25a`.
Bu sonraki satırlar 2e incelemesinin PASS kapsamına girmez; yeni temiz exact-head
denetimi ve gerçek hosted gözlem gerekir. Native/ürün/U003 yeterliliği değişmez.

### CIndex bildirim yakalaması — yerel uygulama adayı

`44788dc` identity run `34710516744` üç platformda başarılı tamamlandı; yedi
artifact/log paketinin bağımsız review SHA-256'sı
`95bdba51a2bc1a6ecac09e466f215ca8aeb12f654688647d8e692ef17e7be61f`.
Dört workflow'un daha sonraki completed/success API snapshot'ı ayrıca denetlendi;
bu, bütün workflow loglarının bağımsız semantik doğrulaması değildir. Önceki
başarısız koşular başarısız kalır; GCC case LLVM kabulü veya U003 bitişi olmaz.

Yerel Fedora/Clang22.1.8 syntax/AST deneyi, görünmeyen popen/openat ve hatalı
openat→open recovery nedeniyle RED kaldı. Ayrı CIndex provasının dört sabit
çıktısı bağımsız olarak byte-byte tekrarlandı; gerçek header/definition ayrımı
ve recursive türler gözlendi. Review SHA-256
`93c0ff0756e040c728dd884e2edd7c28c3d176e81cbf0cf233cec0ccc2b92238`,
`OBSERVATIONS_VERIFIED_NOT_QUALIFIED`. Canonical function type'ın kaybettiği
parameter-level restrict, ayrıca gerçek parameter-declaration yakalamasını
gerektirdi. Bu deney üç hosted platform veya üretim adapter PASS'i değildir.

Eklemeli üretim adayı bu ayrımı mevcut dört Python uygulama/test dosyasında
uygular; eski şemalar/collector'lar/workflow/model/ledger/corpus pinleri değişmez.
Yeni semantic negatifler ilk adayda iki gerçek failure verdi: declared parameter
uyuşmazlığı ve nested unsupported tür issue-free kalabiliyordu. RED capture SHA
`1e0debb984840262b8db523e31c3099febca207b5f8b4145e95b1daec98f21eb`.
Düzeltme sonrası bu 14 test geçti; capture SHA
`fa7c93fcab9259df4a1e01b0953153766afc0888f13463fb9c1f8955db08a9fa`.
Backend failure retention, çapraz fiziksel identity uyuşmazlığı, pure reader ve
selector kontrolleri de eklendi. Temiz exact-head gerçek capture ve bağımsız
uygulama denetimi bu aday kaydının ardından yapılmalıdır; bu paragraf onları
önceden olmuş saymaz. Selection 2/1020 ve LLVM HOLD korunur; POP yapılmaz.

Temiz `de2a68094b5a0fb8c7dc7b58f65071b1b30945d1` üzerinde gerçek capture
exit 2 ile syntax RED packet'ini yazdı; SHA-256
`0ab49b3e450be4f60a03c7265ae312414ce702438bb7c2209ade5e4218545fb9`.
Altı CIndex error, popen/openat eksikleri ve 14 isteğin unqualified durumu korunur.
Bağımsız denetçi 407 testi ve üç gerçek sınırlı native kontrolü yeniden çalıştırdı;
çıktılar byte-byte eşleşti. Buna rağmen uygulama review'u **BLOCKED** verdi:
geçerli ama yanlış yapıda worker JSON'u önceki syntax RED packet'ini kaybettiriyordu.
Bu bulgu eski PASS diye yeniden etiketlenmez.

R1 için exact de2a680 producer byte'ları belleğe yüklenerek current regresyonlar
ayrıca çalıştırıldı; üst/alt JSON yapıları RED'i yeniden üretti, geçerli-shape
kontrolü geçti. Capture SHA-256
`04dc41244796a8d4c14346e920a815f093071f8539142421f9c29de7d1a526c7`.
Dar düzeltme çocuk-result doğrulamasını bağımsız envelope/identity denetimlerinden
ayırır; INVALID_RESULT stdout/stderr byte/hash kaydı, önceki syntax sonucu ve
sonraki fatal kaynak/header kontrolleri birlikte test edilir. Dört focused GREEN
capture SHA-256 `fa334d081284b7619b07a0619f08bbf30c5d38a32dbb972badc4c5d6e636bfd7`.
Önceki test taslaklarının fixture-path/sanitized-message hataları ayrıca korunur;
bunlar ek ürün hatası sayılmaz. Yeni temiz exact-head review henüz bu paragrafın
iddiası değildir; hosted declaration ve U003 kapıları açık kalır.
Üç sentetik Linux capture/writer regresyonu yalnız POSIX filesystem üzerinde
çalışır; Windows'ta açık gerekçeli skip'tir. Ayrı saf worker/result-shape testi
platformdan bağımsız kalır; bu ayrım gerçek Windows native capture kanıtı sayılmaz.

`588a4b4c8c460a48bbd8d4005e20d0af56cb3649` review'u R1'i çözülmüş buldu;
425 testi bağımsız çalıştırdı, fakat R2 nedeniyle **BLOCKED** kaldı. Worker'ın
library_version alanındaki JSON-escaped lone surrogate UTF-8 yazımını bozuyor,
syntax RED yerine sıfır-byte output bırakıyordu. Gerçek capture/writer yolundaki
iki surrogate negatifi ve saf worker negatifi bunu yeniden üretti; RED capture
SHA-256 `1bc638d61595747989b5a1a4058981f51c34abfd6e8aba1c07d912fef9ca056b`.
Dar düzeltme sürüm için UTF-8 byte sınırı ve bütün çocuk sonucu için serialization
preflight ekler. Geçerli non-ASCII sürüm kontrolü geçerken lone surrogate ve byte
sınırını aşan sürüm reddedilir; altı focused testin GREEN capture SHA-256'sı
`099e1ce78acbc0c5b2044ae18c0d7aef38ec7e5cc1110ccbe3e7ca022e17054e`.
Yeni Unicode writer testiyle sentetik POSIX orchestration testleri dört oldu;
Windows native capture yapılmış sayılmaz. R2 sonrası temiz exact-head review
ayrıca gereklidir; önceki iki BLOCKED kaydı değişmez, U003/POP hâlâ açık kalır.

### Açık POSIX görünürlük profili — ayrı üretim adayı

`1168a717d5116b1fcab3ef732ccf67e8237c82b1` önceki R1/R2 düzeltmeleri için gerçek
PASS_IMPLEMENTATION_ONLY aldı; 426 yerel testin bağımsız inceleme receipt SHA'sı
`487894db181f4b10327fa052785845500b25ef38fa145465cbf5943161ace9b2`.
Bu, yeni POSIX profilinin önceden verilmiş onayı değildir. Aynı head'in FIFO/CI/
Windows workflow'ları completed/success, identity run34715529749 completed/failure
oldu. Ham identity paketinin bağımsız review SHA'sı
`1fa98657fe4c9080b4747716db8bf0970e519a1f8affcf5988fcbf98ea434152`.
Windows'un özgün OS metadata sorgusu30s timeout verdi; native-case artifact eksik.
Sonraki başarılı staged diagnostic eski failure'ı düzeltmez veya iç kök nedenini
kanıtlamaz. Bu workflow yeni declaration/CIndex komutunu çalıştırmıyordu.

Ayrı önceden dondurulmuş Linux deneyinde özgün C17, açık POSIX2008 prefix'i ve
yanlış getenv imzası karşılaştırıldı. İlk yardımcı incelemesinin stream/hash ve
cross-case header tutarlılığı bulguları uygulamadan önce ayrı sürümde düzeltildi;
eski taslak/inceleme korunur. Reviewed PLAN SHA
`94fba29fea5c89a14ead5a952336cf4aa537ba4144f914fa3350c2db180b3c6b`, gerçek observation
SHA `16fdf5c9197130be512d0e47ed5e35ab3add27a1b527205e190f1be1b25d115f`.
Özgün C17 syntax RED ve popen/openat eksiklerini korudu; POSIX varyantı14 isteği
issue-free OBSERVED_UNADJUDICATED gözledi; yanlış imza bir driver/CIndex error ve
getenv SIGNATURE_MISMATCH/SYNTAX_FAILED verdi. Bağımsız post-observation review
SHA `d9177beb560d1cc397302b74d56537560cb43a679e29d99762beea3cf958cb82`, verdict
OBSERVATIONS_VERIFIED_NOT_QUALIFIED. Denetçi native deneyi yeniden çalıştırmadı;
ham komut/stream, güncel byte kimlikleri, gerçek header konumları ve saf sonuç
kontrollerini inceledi. Bu packet üretim v1/v2 veya Darwin/Windows kanıtı değildir.

Yeni eklemeli aday açık `c17-posix2008/v1` seçimini, ayrı v2 descriptor/source/
child bağlarını, bounded tam başarılı makro çıktısını ve başarısızlık retention'ını
uygular. Eski default v1 kaynak byte'ları üç platform için bağımsız exact1168
hash'leriyle korunur. Yeni kabul testleri eski implementation'da beklenen şekilde
başarısızdı: capture SHA
`cf44f95da08e65f6aafa58490b1560442e6be0d92248736dbef69c6841eda274`.
Bu yeni profilin henüz bulunmamasıdır, eski v1 davranışını sonradan bug saymak değildir.

Uygulama adayında birleşik backend/önişleme failure'ı ortak issue listesini tekrar
ekleyebiliyordu. Dar regresyon bunu RED gösterdi (capture SHA
`765cc58e9d5a172e4b2a088533635e4e6284ab4085da4a8a6a497bc3439da208`); her istek için
ayrı sonuç listesi düzeltmesi GREEN verdi (SHA
`bc0e58db913b4be9a7f8cf5dfe46cb52ec1152fcdeb1555d4014fa4d55c82bbf`).
Temiz exact-head native CLI yakalaması ve bağımsız uygulama review'u ayrıca
gereklidir; bu aday paragrafı onları olmuş saymaz. U003, selection2/1020, LLVM HOLD,
model/rights/admission ve Windows failure kapıları değişmez; POP yapılmaz.

Temiz `001e786661b88e7284df2bb0cce9ec5def3941a6` üzerinde gerçek v1 capture exit2
ile eski14 INCOMPLETE/popen-openat RED'ini korudu; ayrı v2 capture exit0 ile14
issue-free OBSERVED_UNADJUDICATED kaydetti. Paket SHA'ları sırasıyla
`53a0fea7221dcfaca894a106225477078aa7b613a5bce32c1a673b581b0f372e` ve
`b380863620ea6e8097f0f19f1962b8d7027c37e213b1f84e0faceab7be0557f1`.
Bağımsız denetçi444 testi yeniden çalıştırdı,300 güncel fiziksel kimliği kontrol
etti ve bu gerçek paketleri doğruladı; fakat uygulama **BLOCKED_IMPLEMENTATION**
aldı. Review SHA `4803c0cac7f9e06c8503e7b882977d33e2bb8a112e14ad493c4de8c02626fd53`.

F1: Python splitlines, fiziksel directive sonu olmayan FF/VT/NEL/LS/PS ayraçlarını
yeni makro satırı sanabiliyordu. Denetçi gerçek v2 paketin beş mutasyonunun full
validator'da yanlış visibility_pass aldığını ayrıca üretti. Özgün capture'lar
geçerli gözlemler olarak kalır; bu hata başka girdiler için uygulama onayını engeller.
Primary'nin saf RED capture SHA'sı
`7731e4a1704d897e33236648e6694a3e2a66f476a4c0c7f934164c72ca4a563c`; depo içi full-packet
regresyon RED SHA'sı
`360e6c91dfc9415e8e31d4a0b84ec76498c27401e7ca1a3b03383175b61fcc6c`.
Dar düzeltme yalnız fiziksel LF üzerinden ayırır; LF/CRLF pozitifleri korunur,
tek CR dahil fiziksel olmayan ayraçlar yeni directive üretmez. Tutarlı yeniden
hesaplanmış eksik projection INCOMPLETE kalır; uydurulmuş olumlu projection ret alır.
F1 sonrası temiz exact-head inceleme ayrıca gereklidir; eski BLOCKED kaydı ve
native/task/productfalse sınırları değişmez.

`23e73e6f1577be5fdba7822495da859a5dcb640c` incelemesi F1'i çözülmüş buldu ve445
testi bağımsız çalıştırdı; fakat F2 nedeniyle BLOCKED_IMPLEMENTATION kaldı.
Receipt SHA `1a462b4af48aa672165a37fecc7577507fcee99c15d14c1b4d0863dfefbf80a6`.
isspace/strip'in Unicode kapsamı NBSP ayırıcıyı veya NEL/LS replacement suffix'ini
silerek yine sahte olumlu visibility üretebiliyordu; denetçi gerçek yeni v2 pakette
üç ayrı mutasyonu yeniden gösterdi. Yeni projection/full-packet regresyonları
RED verdi: capture SHA
`12259f74b096ff35b1dfe2aff662a61d7cf58dd9423e5a454d00954534e3996c`.
Dar düzeltme SP/HT ve fiziksel LF/CRLF gramerini açıklar; ASCII dışı replacement
karakterleri normalize edilmez, sahte Unicode boş satırlar atılmaz. Gerçek eski
packet'ler ve iki BLOCKED inceleme korunur; F2 sonrası yeni exact-head PASS henüz
bu paragrafın iddiası değildir. Ürün/U003 yeterliliği değişmez.

### f3ec95f hosted Windows fixture RED ve dar yol-eşleme düzeltmesi

Exact `f3ec95fc9474aaaa410365f81c2b7a77f611cb69` bağımsız uygulama incelemesi447
test ve ek172 bozuk makro metni denemesiyle PASS_IMPLEMENTATION_ONLY aldı;
F1/F2 kapandı. Receipt SHA
`51ade62008e05f3ae1f4c0e34257ccaee3669a79b27ee428f52ad8205fe1c5e8`.
Bu hosted/native yeterlilik değildir. Normal feature fast-forward sonrasında
[identity run34719586304](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34719586304)
başarısız oldu: Linux/macOS job API durumları success; Windows job103622853708
132 identity testinde üç error ve altı skip kaydetti. Üç hata, aynı yeni child
fixture'ının None/missing/prefix alt durumlarında Windows Path'in ters bölü
çıktısını POSIX string anahtarlı sözlükte aramasıyla oluşan KeyError'dır.
Başarısız adım log capture SHA
`f447e753ef185f99ca917aa2a6ecdcc086684e347d1e6d0ef4a0ec09b7334537`.
Windows native capture'a ulaşılmadı; üç Windows artifact'ı yok. Bu hata eski
30s OS sorgusu timeout'undan ayrıdır; ikisi de kendi başarısızlığı olarak korunur.

Yeni saf regresyon, gerçek fixture testinin bütün alt durumlarını PurePosixPath
ve PureWindowsPath ile tekrarlar; yalnız sentetik input/library yolları farklı
flavor kullanır, gerçek depo okumaları native kalır. Özgün kod üzerinde aynı üç
Windows KeyError ile RED verdi; capture SHA
`d5ec8c1a4f74ac82fee07166b24b5be62fe556b195aa88a80eb6d3fa63e75d2c`.
Dar düzeltme fixture sözlüğünü Path anahtarlarıyla kurup Path ile okur. Pozitif
argv/14-request kontrolleri, beş negatif ve backend.assert_not_called korunur;
test skip edilmez ve üretim kodu değişmez. Focused GREEN capture SHA
`4b56b2feb906c1e1d4fb95d6b63a032617b005eb004bf3b63499ca6c79479789`.
Bu saf iki-flavor deneyi gerçek Windows CI değildir. Yeni exact-head bağımsız
inceleme ve gerçek hosted sonuç ayrıca gerekir; eski PASS yeni head'e taşınmaz.
Selection2/1020, native/model/rights kapıları, main ve U003 FRONT değişmez; POP yok.

### f057694 gerçek Windows fixture sonucu ve ayrı bildirim job adayı

Exact f057694 identity run34720540354 yine failure, fakat önceki fixture hatası
gerçek Windows'ta tekrar etmedi:133 identity testi9.318s içinde OK (altı eski skip),
identity artifact'ı oluştu. Seçilmiş199 profile testi395.291s içinde OK (bir skip).
Ardından capture-case'in özgün30s Windows OS metadata sorgusu TIMEOUT oldu;
native-case artifact'ı yoktur. Sonraki diagnostic30,078ms içinde yalnız STARTED
işaretini gözleyip TIMEOUT verdi; ayrı policy sorgusu1078ms içinde Unrestricted
kaydetti. Bunlar başarısız sorgunun kök nedenini veya onarımını kanıtlamaz.

Bağımsız exact-source hosted review HOSTED_OBSERVATIONS_VERIFIED_NOT_QUALIFIED;
receipt SHA `51653aff93842c07f00a18671dbedcd52757219324fcfff382735f84ff5f3102`.
Altı ZIP/artifact/payload,31 manifest girdisi ve gerçek üç platform logu denetlendi;
summary SHA `ed5beef806f49bda28312157aaf2a883a1695ae089ef8788999d1f4339d0f879`.
Linux/macOS yalnız özgün GCC case'in candidate/ABI exit0 ve bad-width/signature
exit1 gözlemlerini içerir; CIndex veya tam native yeterlilik değildir. Eski f3
identity ve genel CI başarısızlıkları bu sonuçla temizlenmez.

Yeni aday özgün workflow/job byte'larını koruyup ayrı üç-platform declarations
işi ekler. Yeni contract testleri eski workflow'da missing-job RED verdi: SHA
`eddd75ec83bdb786ebe43b6f396b015cb312a20e95b920d4f7969e18a3e1124e`.
İş eklenince bu dört test GREEN: SHA
`d4ac58fcbb09e60900a9460ac7d5bea6aa7b5a027eb605ef01d0d8c8670e6d42`.
Eski global upload/interpreter sayımları ek job nedeniyle iki RED verdi; özgün
job'un exact prefix hash'i ayrıca sabitlenirken global sayılar gerçek yeni4/4
oldu. Hiçbir eski case adımı, timeout veya failure kontrolü azaltılmadı.

Yeni iş kurulum/fallback olmadan açık installed CIndex adaylarını seçer;
Linux/macOS v2 POSIX ve Windows default v1 yakalaması ile yalnız metadata upload
eder. Bu paragraf yeni job'un koştuğunu, library adaylarının bulunduğunu veya
platformların geçtiğini iddia etmez. Yerel statik test/CLI, temiz exact-head
bağımsız inceleme ve gerçek yeni hosted packet ayrıca gerekir. SQLite seçilmez,
selection2/1020, native0/50+3, haklar/model/FIFO kapıları aynı kalır; U003 POP yok.

Exact `98e932fc9ee2ad6eb99fae4b8690f83632a0ad2c` bağımsız incelemesi452 testi
yeniden çalıştırdı, fakat yeni Darwin SDK selector'ında F1 nedeniyle
BLOCKED_IMPLEMENTATION verdi. Receipt SHA
`74f79bda17467c3559dcbe1195a889fc2bc4a8314c5185fdba497ea44ea7927a`.
`export SDKROOT="$(xcrun ...)"`, makul SDK stdout'u ile exit7 dönen seçicinin
hatasını export exit0 altında maskeliyordu. Gerçek yeni job fragment'ini yalnız
Bash built-in stub ile çalıştıran regresyon RED verdi; capture SHA
`f255839d1fc6ec586fe45055ee445610df13319b75f1ca01618dc142fcbc0ead`.

İlk patch yanlışlıkla eski job'daki aynı ifadeye eşleşti; sabit prefix denetimi
beş testi durdurdu. Başarısız capture, adına rağmen GREEN değildir ve korunur:
`4133ed5f649573b6902980a6648415c5623fa0f14ac3fb1c79af6cea9d0721dc`.
Bu yerel değişiklik geri alındı; yalnız yeni declarations job'unda önce assignment,
sonra export uygulanınca beş focused test GREEN verdi. Capture SHA
`bb1ad68ba678d2e1b145403d2499e79964f49e4d7ecb70a3311dd7a61efdb000`.
Pozitif exit0 SDK'yı geçirir; negatif exit7 continuation/capture'a ulaşmaz. Eski
job byte'ları ve bütün önceki failure kayıtları korunur. Gerçek xcrun/SDK çalışması,
yeni exact-head PASS veya hosted başarı bu dar yerel deneyin iddiası değildir.

### 8953056 gerçek hosted CIndex gözlemleri ve Windows pre-envelope failure

Exact `89530563ec912385b38bd4c06bea60cc38c84146`, bağımsız453 test ile
PASS_IMPLEMENTATION_ONLY aldı; receipt SHA
`65cd252d348697e83a3d9bea043beed983c4719e58d424b64eb4925455205f19`.
Normal feature fast-forward sonrasında identity run34722436917 attempt1 failure
oldu: altı işten beşi success, yalnız Declare Windows failure. Aynı head'in
FIFO34722436904, CI34722436910 ve Windows34722436938 run'ları terminal/success.
Eski başarısız run'lar bu yeni sonuçlarla yeniden etiketlenmez.

Yeni altı-job/dokuz-mevcut-artifact paketi gerçek logları, ZIP'leri, JSON'ları ve
ilk/son API kimliklerini tutar; summary SHA
`476f6593aeb0a4767af86f9ad0443c675c87ace10f7b9fb95c8dc71faa3cb293`.
Retainer'ın tanımsız job sonucu ve bool/float kimlik açıkları önce bağımsız
BLOCKED aldı,15 RED alt durumuyla yeniden üretildi ve dar guard düzeltmesiyle
14 test/20 ek bağımsız kontrol sonrası PASS_HELPER_ONLY aldı. Bu helper onayı,
indirilen gerçek paketlerin bağımsız denetimi veya native yeterlilik değildir.

Primary'nin saf/source-bound okuyucuları gerçek Linux ve Darwin v2 paketlerinde
syntax_pass/visibility_pass=true,14'er issue-free OBSERVED_UNADJUDICATED kaydetti.
Paket SHA'ları sırasıyla
`db310c6a273bec6356a96df7e347ca6e59ee93525e95b8b6d6e0932bfc015a59` ve
`0a33ab29d7983f31af533fccab959fc9770ce76d07740878b4d0c785cf72a426`.
Linux Ubuntu Clang18.1.3 ve67 declaration closure girdisi; Darwin standalone
CLT Apple Clang16.0.0 ve108 closure girdisi gözlendi (üretilen kaynak dahil).
İkisinde CIndex diagnostic
listesi boş; bu tam ABI/runtime closure, sanitizer veya model davranış onayı
değildir. Hosted native dosyalar bağımsız olarak yeniden açılmadı.

Declare Windows138 identity testi (yedi skip) ve dört declaration reader testi
geçti; ardından ilk native identity yakalamasındaki özgün powershell.exe OS
sorgusu OSError veya TimeoutExpired ortak handler'ına ulaştı. Log SHA
`61cc64704a34c914eb91eaf4c2bdc9ce01db62e4c6c5555753c7c56a7fb605f8`.
Bu kayıt hangi sınıf olduğunu ayırmaz; aradaki40.6s özgün sorgunun ölçülmüş süresi
değildir. DLL pathname seçimi tamamlandı, fakat collector library hash/load,
compiler/header/syntax/CIndex adımlarına ulaşmadı; declaration JSON/artifact yok.
Bu, geçerli retained syntax RED değil, pre-envelope capture failure'dır.

Ayrı Observe Windows job'u identity/case/diagnostic artifact'larını başarıyla
üretti. Sonraki staged query17375ms OK ve policy188ms OK gözlendi; bu başka job'un
sonucu Declare failure'ını onarmaz veya onun iç nedenini kanıtlamaz. Yeni dar
regresyon, declaration exception yolunun TIMEOUT/OS_ERROR/INVALID sınıflarını
sabit ve özel metin içermeyen marker ile ayırmasını ister; mevcut kodda üç RED
alt durum verdi: SHA
`9e87958972ed0ad0bdcb00a2310656749f796eb969c3d4ff76b17c8b5da9b622`.
Sorgu/timeout/policy değişikliği, retry veya önceki failure'ın temizlenmesi bu
gözlem ihtiyacının kapsamı değildir. Gerçek paketlerin bağımsız audit'i ve yeni
uygulama incelemesi ayrıca gerekir; selection2/1020, native0/50+3 ve U003 açık.

Gerçek paketin bağımsız denetimi tamamlandı:
HOSTED_OBSERVATIONS_VERIFIED_NOT_QUALIFIED receipt SHA
`be8b847c51c0556e99c5f2d533ceb4c73480c4d6a4ffe44869e7fbe9ef6579da`.
52 manifest girdisi+summary, dokuz ZIP/payload ve altı gerçek job logu incelendi;
iki yeni v2 paketindeki10 ek saf negatif, syntax/makro/hedef/imza eksiklerini
INCOMPLETE tuttu ve sahte qualification'ı reddetti. Windows yokluğu ve bütün
native/task/productfalse sınırları korundu; hosted header/library yeniden açılmadı.

Dar uygulama yalnız declaration exception yoluna mevcut sabit classifier'ın
marker'ını ekler. Timeout/OSError/generic validation regresyonları ve mevcut
gerçek writer-orchestration success/retained-RED stderr kontrolleri GREEN verdi:
`4ad8aeb8e0950c705562a2a5370adca14d264f83d07667abf50e156ac03fc8a2`.
Özgün OS query argv/30s bütçesi, ortam, tek invocation, syntax/JSON şekilleri ve
eski case marker'ı değişmedi. Yeni exact-head uygulama PASS'i ve marker'ın taze
hosted gözlemi ayrıca gereklidir; bu eski8953056 failure sınıfını tamamlamaz.

### bcec66f checkpoint'i ve eklemeli declaration review okuyucusu

Önceki marker değişikliği exact bcec66f üzerinde bağımsız454 test/queue/guard/CLI
PASS aldı ve yalnız feature ref'e normal fast-forward gönderildi. Receipt SHA
`134d088969d7393475da444410f5c7999aba7a4ac5e76447418a2220831a17e0`.
Gerçek yeni identity34724198593/attempt1, Declare Windows103635345122 logunda
`DECLARATION_FAILURE_KIND TIMEOUT` kaydetti; ilk OS metadata sorgusu declaration
JSON oluşmadan durdu. Bu yeni denemeyi sınıflandırır, iç nedenini veya eski895
denemesinin sınıfını kanıtlamaz. Taze API'de identity failure ve FIFO success;
CI/Windows o gözlemde in_progress. Tam yeni artifact audit'i yapılmış değildir.

Kalıcı checkpoint:
`/home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH08-S01-U003/native-declaration-failure-kind-bcec66f-v1`
Manifest SHA `8d9279e840089339be8734b6409fe14796f8361aaa163da952f875446715004b`.
Bağımsız kopya audit'i23 manifest girdisi+manifest olmak üzere24 dosyanın gerçek
bytes/hash eşitliğini, eksik/ek/symlink bulunmadığını doğruladı. Önceki sealed
895 paketi değişmedi; main hâlâ7dfd37596414c9512316093ff4fb6b039673f55f.

U003'ün bir sonraki dar uygulaması tek API/platform declaration candidate'ini
özgün packet/model/producer kaynaklarına ve isteğe bağlı bağımsız incelemeye
bağlar. Yeni okuyucu/CLI bulunmadığı için test-first RED alındı:
`c8f01a9b335ab29498ea1f816db20f565d90eefd9f963ef06a633254444b6693`.
İlk genişletilmiş focused GREEN32 test:
`cce84068fc3bf2e2e660a1238c7d1367381e301ecb710ef8f673418ea794de58`.

Sentetik karşı örnekler syntax/backend/visibility/definition/imza/reference
eksiklerini kabulden ayırır. İki ayrı target eski saf okuyucuda tek tek temiz
olsa bile canonical kimlikleri çelişiyorsa review reddedilir; aynı target'ın
tekrarı korunur. Stale/aynı-agent/findings içeren review, projection/model/packet
drift, yinelenen JSON key, fazla alan, sahte qualification, aşırı boyut ve geç
input değişikliği ret alır. Gerçek geçici Git producer/candidate commit'leri ve
olumlu CLI fixture'ı iki ayrı kaynak bağını doğrular; native araç çalıştırmaz.

Bu test fixture'ları gerçek API incelemesi değildir. Henüz yeni gerçek candidate
ve kabul receipt'i yoktur; declaration reviewed sayısı bu uygulamayla kendiliğinden
artmaz. Windows/SQLite ve model-semantic/corpus/security-pair/freeze yükümlülükleri
açıktır. T1 bütün test kümesi464 test/30.519s ile yerelde PASS verdi (skip yok):
`164000f528ba94e626a4642772f96dc4c666815bf1c3882ecfed33534b997945`.
Yeni exact-head bağımsız uygulama denetimi ayrıca gerekir; task_ready,
native/model/product qualification ve POP iddiası yoktur.

### Gerçek895 Linux/Darwin declaration candidate kayıtları

Önceden bağımsız denetlenmiş iki gerçek hosted v2 packet'ten28 eklemeli candidate
hazırlandı: her platformda14 non-SQLite library API. Kayıtlar
`tests/product_corpus/declaration_candidates/` altındadır; yeni declaration
yakalama veya sentetik header değildir. Her candidate özgün895 producer head'i,
değişmemiş model digest'ini, paket kimliğini, tüm raw target'ları ve yeniden
hesaplanan projection'ı bağlar. Canonical kimlik/imza/header/visibility ve
definition/redirection değerlendirmeleri yalnız bildirilen kanıtla sınırlıdır.

Hazırlama yakalama SHA:
`6bc802ba1e49cc7338044a8e949a9c6af2d5e60e0f6c8905ab991340779dfd29`.
32 odaklı metadata/review/negatif test GREEN:
`14dc1f77c91b2854626735f78a73675a08ddab89dd8b9ef3830e41153a0d5c1d`.
Gerçek Linux getenv candidate CLI kontrolü exit0 verdi:
`ddb0b49a2cb5280c1257a1627658ce30bdcf57677415eac0daf34242f0a91113`.

Bu hazırlama independent review değildir.28 kaydın ilk source-bound toplu
kontrolünde hepsi declaration incelemesine uygun, fakat reviewed count0;
qualified count0/50+3'tür. Ayrı exact-record/source-head bağımsız kararlar dış
receipt olarak saklanmalı ve okuyucuda gerçek dosyalarıyla doğrulanmalıdır.
Model semantics/transfer/SQLite/Windows/entry ve bütüncül corpus/security-fix/
safe-control freeze yükümlülükleri açıktır. Scope, eski model/packet anlamları,
kalite eşikleri, completed kayıtlar ve FIFO değişmedi; U003 henüz tamamlanmadı.

### Parameter-view ayrımı: eklemeli v2 assessment successor

Exact `b73b52f03eecc54827c733f7c972d7722e8a21e4` üzerinde Darwin denetçisi,
altı stdio API'sinin assessment metninde canonical-cursor parametrelerinin
`Declared parameter types` diye sunulmasını HOLD bulgusu yaptı. Referenced
header parametrelerindeki `restrict` ve gerçek konumlar bu özette ayrılmıyordu;
ham packet/projection sağlamdı. Linux denetçisi aynı ayrımı açıkça not ederek
kendi14 declaration kaydını dar kapsamda kabul etti. Bu iki tarihsel karar
birbirinin yerine kullanılmadı ve ürün/native kabulüne yükseltilmedi.

İncelenmiş28 v1 dosyası değiştirilmedi.28 eklemeli v2 successor yalnız id,
boundary ve signature assessment metnini yeniler; canonical-cursor ve
referenced-header ad/type/qualifier/konum görünümlerini ayrı açıklar. Her
platformda altı stdio API'sinde bu görünümler farklıdır. Tam recursive type
ağaçları aynı özgün projection'da kalır; eski model/packet/projection digest'leri,
diğer assessment alanları ve false qualification bayrakları aynıdır.56 dosya
56 farklı API çifti değildir; aktif v2 seçiminde28 aynı pair vardır.

Korunmuş v1 metinleri üzerindeki ayrım regresyonu RED yakalama SHA:
`610a3bc64b12fa31972d416096bbca25594b14d17f2f4f18bd5113ceeb270241`.
V2 ayrım ve v1 byte-preservation GREEN:
`a50525c0ecd13e235571eb0c3256760aa3fa694128d4292b6dd9277e9940de5a`.
28 gerçek v2 source-bound candidate kontrolü GREEN:
`ebc6f9d9db01b1b0de91ddc385af98a023b0f07ed162831c727db90c3f37d9ec`.
Yeni kayıtlar için yeniden bağımsız exact-head inceleme gerekir; eski v1
receipt'leri yeni kayıtların kabulü sayılamaz. Qualified50+3 payı ve quota
katkısı sıfırdır; U003/global freeze, model semantics ve corpus kabulü açıktır.

### Declaration worker için sınırlı failure provenance

V2 declaration kayıtları exact `d005d4cce36dcad00ff2331d7c911714ab44b44e`
üzerinde iki platform için ayrı bağımsız inceleme ve58 dosyalık integration
PASS aldı; yalnız feature dalı fast-forward gönderildi.28 gerçek API/platform
pair'in declaration review'u vardır, ancak native/model qualification hâlâ0'dır.
101 dosyalık kalıcı kanıt paketi `native-api-declaration-assessments-d005d4c-v1`
manifest SHA `13050d000899076e3597d40718cf61b7ba897761e2e3b14b987bceb23d7b9c5b`
ve ayrı bağımsız byte-for-byte copy audit'i ile korunur. Main değişmedi.

Bu pakette saklanan gerçek3cd producer Windows declaration denemesi
run34725540585/attempt1, job103638902285, artifact10307742295'tir. Packet SHA
`68df8fc7e8b57a328c640e7186612753b498d46ebe264cb36877e0ae423e47ba`:
backend PROCESS_FAILED/exit2, stdout0, stderr144 byte ve13 BACKEND_FAILED kayıt.
Raw syntax exit0 ve dependency exit0, native backend başarısı değildir; syntax
stderr'i de boş değildir. Saklanan stderr hash'i mesajın içeriğini, kök nedeni
veya library yüklemeye ulaşıldığını göstermez. Eski başarısızlık başarısız kalır.

Yeni dar değişiklik yalnız sonraki PROCESS_FAILED gözlemlerinde ayrı, sınırlı
stderr JSON tanısı üretir. İki tam allowlisted child satırı, exit2 ve boş stdout
eşleşirse CHILD_REPORTED category/check satırları; aksi hâlde UNRECOGNIZED
yazılır. Bu kimlik doğrulaması veya native aşama kanıtı değildir. Parent failure,
ham stream boyut/hash değerleri, packet schema, komut/ortam/tek deneme/30s bütçesi
değişmez. Child-reported TIMEOUT parent PROCESS_FAILED olarak kalır; log yazma
hatası asıl RED'i değiştirmez. Özel exception metni/argv/path/environment basılmaz.

Test-first genişletilmiş RED yakalama SHA:
`a8df6d8fff7831118d43fc87a60dd24b9b1524db2445c7adc5e2c7a32f21333b`.
10 odaklı testin son GREEN'i:
`30e130a4f79f3f7fe9a3d2bde70a99c94162131fb117de9bac31ab69694e41c3`.
Kategori/LF/CRLF/sınırlar, özel veya bozuk girdiler, farklı exit/stdout,
success/diğer failure sınıfları, log-write failure, korunmuş syntax RED ve fatal
parent identity drift denetlendi. Gerçek writer orchestration testleri sentetik
Linux native I/O kullanır; iki POSIX fixture Windows'ta açıkça skip edilir.

Gerçek sabit Python child CLI smoke SHA
`c8ad6ffa27ac46b88eeff66f6693dbdf87aa3845172ac73105c9edce8e2c6691`:
özel sentinel sızmadan INVALID/CHILD_REPORTED verdi. Geçersiz config native
komutlardan önce reddedildi; bu Windows/native yeniden üretimi değildir.
Eski gerçek Windows packet'inin saf CLI kontrolü aynı13 BACKEND_FAILED sonucunu
korudu; exit0 metadata geçerliliğidir, native PASS değildir:
`e66ace5ee0ab75c21bde26b2f9d258029b99ff82725e95b68ab3c0e19b7abb3a`.

T1 identity/profiles/quality460 test30.702s GREEN:
`cbc87e2d1653835eb42b80ea1839f1386f427d7954deeb65b5f8182baa1aea83`.
Ayrı completion-plan14 test0.285s GREEN (toplam474, yerelde skip yok):
`aa9e3ea5d91c8a69c1acbb3565eafe395b3f37a0fc5fbeef09129b2499054aab`.
Yeni exact-head bağımsız implementation incelemesi ve taze hosted gözlem ayrıca
gerekir. Windows kök nedeni/fix'i, U003/global freeze ve bütün ürün kabulü açık;
bu tanı checkpoint'i için POP veya task_ready iddiası yoktur.

### Exact-5a Windows kanıtı ve sınırlı TU seçimi

Gerçek5a0273c producer Windows denemesi run34729029339/attempt1,
job103648291085, artifact10309131832 üzerinde terminal failure'dır.
54930-byte ZIP SHA
`8b7d17c0499c8e68152d7e389c4c3ad2259ed2ce4935ea063472df4a05cc3a57`;
323735-byte packet SHA
`ff7aaed16b983564aff478fb38f0adf824968d3030ce823aa6d195fa152eee86`.
Gerçek20 dosya, metadata/ZIP/CRC/packet ve tam günlük bağımsız incelendi.
37 dosyalık `native-declaration-worker-packet-5a0273c-v1` kalıcı paketi ve
ayrı byte-for-byte kopya denetimi korundu; manifest SHA
`47b37f68f77fee5752f09d84af69e7788c7fa06b917d09c9813b62aab5f085c5`.

Actual PROCESS_FAILED/exit2, stdout0, stderr185-byte/hash kaydıyla eşleşen
tek tanı CHILD_REPORTED/INVALID'dir. Kaynağa bağlı
2093→1964→1514→1435→1427→58 zinciri doğrudan TU çocuklarını toplarken
16.384 cursor guard'ının reddini gösterir; parent timeout değildir.
Günlükteki ayrı-11 mock-test marker'ı gerçek native crash sayılmaz. Toplam/unique
native cursor sayısı, kökenleri ve guard aşımının alt nedeni gözlenmedi.
13 istek BACKEND_FAILED/INCOMPLETE kalır; raw syntax/dependency exit0 backend
başarısı değildir. Önceki Windows denemeleri geriye dönük sınıflandırılmadı.

Fake-CDLL regresyonu mevcut5a collector'da gerçek ctypes callback yoluyla
aynı child-bound reddini yeniden üretti; native DLL/SDK çalıştırılmadı.
Test-first RED capture SHA
`84d36216fbfedb412ff67a3f5027f2061bb92d3779e7313365e8f26da05aef28`.
Dar değişiklik bütün doğrudan TU ziyaretlerini sonlu65.536 sınırına sayar,
yalnız gerekli exact kind/ad eşleşmelerini saklar ve son düğüme kadar sürer.
Bu yeni private kaynak politikasıdır; eski16.384 all-child sınırına eşdeğerlik,
native başarı veya dondurulmuş değerlendirme bütçesi değişikliği değildir.
16.384 stored/recursive sınırları,30s timeout, validator ve bütün model/kalite
kapıları korunur. Fail-closed callback/interruption ve kaynak cleanup eklenir.

14 odaklı adapter testi GREEN capture SHA
`78f0e0d18fed5f75ce17512316945e53019134bbab4606d01986da37d78b252f`.
17.000 ilgisiz prefix/suffix sonrası tam gözlem eşitliği, geç duplicate
typedef/variable/main, exact kind/ad ve eksik probe,65.536/65.537 ziyaret,
16.384/16.385 stored/recursive sınırları, nested/tekrarlı/çelişen referanslar,
UTF-8/string/getter hatası, traversal interruption, Break sonrası durma ve
CXString/TU/index cleanup sınandı. children/observe taklit edilmedi; sahte
CDLL gerçek adapter callback'ini çağırır. Bu offline test native callback
ömür güvenliği, süre/RSS veya Windows tamamlanması kanıtı değildir.

Yeni exact-head bağımsız implementation incelemesi ve gerçek native hosted
qualification ayrıca gerekir. U003 FRONT kalır; model/native/product kabulü,
global evaluation freeze veya POP yoktur. Eski kaynak/packet/receipt anlamları,
corpus/model byte'ları, FIFO ve main korunur.

T1 identity/profiles/quality/completion-plan toplam488 test32.600s GREEN,
yerelde skip yok; capture SHA
`a2dab2b475c15f30aeee547e4354b4fcace6745ecfeaa75c297136b41538c609`.
Gerçek5a Windows packet'inin saf `check-declarations` CLI'si exit0 verdi,
13 BACKEND_FAILED sonucunu korudu; metadata geçerliliği native PASS değildir:
`59cc4d08729c04b150a3922dc8dd120ac28d70cc1376a9f40e8026630c7e5de9`.

### Exact-250 Windows RED ve parent sonuç-ret tanısı

250c01f producer'ın run34731828949/attempt1 sonucu terminal failure'dır;
altı job terminaldir. Windows declaration job103655905367,
artifact10309831434 gerçek ZIP/packet ve tam log baytlarıyla yeniden bağlandı.
54.935-byte ZIP SHA
`a49c0c96cf653525fbc952feee3bab4eadd5be873e5980d9f9534ed1422efc64`;
323.738-byte packet SHA
`43f5a5ec638e47503d2f02e7f1d366120d0a34767c6fd424cbb5aec91241487c`.
33 dosyalık `native-declaration-worker-packet-250c01f-v1` paketinin manifest SHA'sı
`878e46d6bcd0c225f6ada6820ae94bf3d2fa2000dfe9960fbe3aa8f1eae1c8b8`.
Gerçek20 acquisition dosyası ve kalıcı kopyası ayrı bağımsız denetimden geçti;
bu yalnız kanıt/kopya bütünlüğü PASS'idir, native veya power-loss garantisi değildir.

Backend `INVALID_RESULT/exit0`, stdout230.099 byte ve boş stderr kaydeder.
Özgün çocuk stdout'u tutulmadığı için hash'i tam ret aşamasını veya nedenini
göstermez. Exact250 kaynağında ret decode/parse/validate/canonical UTF-8
serialization-boyut sınırındadır; `TIMEOUT` veya `PROCESS_FAILED` değildir.
Günlükteki tek eski child marker ayrı mock testinden gelir. Raw syntax/dependency
exit0, syntax stderr11.119 byte ve188 header kaydı backend kabulü değildir.
13 istek hâlâ BACKEND_FAILED/INCOMPLETE; cindex null, yeterlilik alanları false.
Eski5a child-bound RED'i değişmez. D24 önceki log/catalog gözlemiydi; actual
packet veya terminal run kanıtı içermediği anlamı geriye dönük değiştirilmedi.

Aynı run'ın Linux Observe job'u GCC staging download-1 sırasında reddetti;
native-case packet üretmedi. Korunmuş log ve exact kaynak opener.open sınırını
gösterir, HTTP/transport nedenini göstermez. Buradaki Windows parent tanısı
Linux indirme hatasını düzeltmez veya yeniden sınıflandırmaz.

Prospective değişiklik yalnız sonraki INVALID_RESULT retlerini parent'ın
beş sabit aşamasıyla ayırır. Child metni echo edilmez; kaynak ipuçları sekiz
context/64 toplam frame/24 allowlisted token, satır1024 ASCII byte ile sınırlıdır.
Tanı çıkarma/serialization/yazma asıl failure hesaplandıktan sonra ayrıdır;
başarısız tanı orijinal kind/exit/stream hash'lerini değiştirmez. Packet şeması,
validator kabulü, timeout, tek deneme, corpus/model ve kalite kapıları korunur.

İlk test-first beş-aşama RED capture SHA
`52f2de6802d19f769e2786f1425cc08328de2246ac606afc98b3dd7ea1aae494`.
Genişletilen testlerde bir fixture çağrı hatası düzeltildi; son13 yeni regresyon
exact250 kaynak blob'u altında tekrar RED verdi (native reproducer değildir):
`33aee398f4c7ef371122f721f449f908123bccca6a196bb4092bf012d9b30680`.
69 declaration/child-parent diagnostic/v1-v2 writer testi GREEN:
`d20e869b754e69d0827f7a44fbf055c14c0c6690175427cb8f6b0f7bba9a0d54`.
Selective diagnostic serialization ve write hataları, özel/bozuk girdiler,
context-cycle/izinli-olmayan uzun traceback, exact byte sınırı, korunmuş syntax
RED ve fatal source/header drift sınandı. Linux writer fixture'ları Windows'ta
açık skip'tir; platform-bağımsız parent testleri native kanıt yerine geçmez.

Gerçek sabit Python child CLI'si yanlış config'i native yüklemeden önce reddetti;
eski CHILD_REPORTED davranışı korundu, capture SHA
`6bcf48ded28d05a544bf01804409e681844a25e08837e9ff5ba9c4ac9b0cf2ad`.
Actual250 packet saf CLI'si aynı13 BACKEND_FAILED sonucuyla exit0 verdi:
`700c058b790149dbf6b89f6078609c9669dee2ea1bfe2849d8a288463303e82f`.
Bu metadata okuma PASS'idir; Windows tamiri/native kabulü değildir. Yeni temiz
exact-head implementation için bağımsız inceleme ve taze hosted gözlem ayrıca
gerekir; U003/global freeze/model/product kabulü açıktır, POP yoktur.

T1 identity/profiles/quality/completion-plan toplam501 test32.736s GREEN,
yerelde skip yok; capture SHA
`ce478f7057ea5ddea385082e57023d6e92ad1cadb1659ab4d595498d4592743f`.

### Exact-be05adf Windows include-closure RED ve sınırlı fark tanısı

be05adf215ba6910e5cbbd2a8c02a472d0160a0c producer'ın gerçek
run34734183301/attempt1 Windows declaration job103662472503 sonucu failure'dır;
altı job terminaldir. Artifact10310169756 ZIP54.934 byte SHA
`9c7dd8b213bdd4cc35bec2fccb94d0c69496977796c7ba4bccf2a4c6849cf192`,
packet323.738 byte SHA
`7116da55a43c33b8ab1a556d1abee1706d7f8045e813671b1011eb26664c34f1`.
Gerçek acquisition ve kalıcı kopyanın ayrı bağımsız incelemeleri korunmuştur:
`native-declaration-worker-packet-be05adf-v1` manifest SHA
`364865a76c5153ba28ef79c0dc334e5f57b9ba115f685392de97eb6c9ac3f315`.

Gerçek packet failure'ıyla birebir eşleşen tek parent marker VALIDATE ve
exact-be kaynak ipuçları2047→2135→1792→58 gösterir. Kaynaktan çıkarım, include
guard'ının false olduğudur; hangi conjunct veya header farkı olduğu değildir.
Mock test marker'ları gerçek capture marker'ından ayrılmıştır. Backend hâlâ
INVALID_RESULT/exit0, stdout230.099 byte, stderr0; özgün stdout tutulmamıştır.
Raw syntax/dependency exit0 ve188 header kaydı native kabulü değildir;
cindex null,13 istek BACKEND_FAILED/INCOMPLETE ve yeterlilik alanları false.
Bu bulgu önceki250 RED'inin bilinmeyen ret aşamasını geriye dönük belirlemez.

Prospective tanı yalnız özgün include guard reddine bağlı private annotation
üzerinden, aynı hata nesnesi/type/args ve predicate sırasını koruyarak eklenir.
Sıralı header-array SHA256'sı, eksik header indeksleri ve beklenmeyen normalize
path hash'leriyle sınırlı ilişkilendirme yapılır; ham yollar basılmaz. Tam fark
sayıları ile kesilmiş32 indeks/8 hash listeleri ayrıdır. Windows PurePath lower
ile Unicode casefold farkı, POSIX case duyarlılığı, drive-relative/device-prefix
ve `..` sınırları test edilir. Bu offline gözlemler native filesystem eşdeğerliği
veya Windows düzeltmesi kanıtı değildir; kabul koşulları değiştirilmemiştir.

İlk test-first guard RED capture SHA
`12f8fb5678bf3c2670aceba5f018174b767e12fc2fa63b9892944198a26bc252`.
12 yeni testin exact eski be05adf producer blob'u altında düzeltilmiş tam RED'i:
`cf46bffcfcdd3d7dd336f5fe23eda16f65f99c00c62f14a3b7b95436ff528b94`.
Genişletilen header fixture'ında alias kaynaklı bir test hatası düzeltildi;
ilk başarısız81-test capture da saklandı. Düzeltilmiş81 odaklı test1.175s GREEN:
`0c7be4631630dbd251816b57f6f19222c0d041d74cd34cfb41fe6b28f10bea54`.
Annotation/extraction/serialization/log yazma hataları, byte ve rapor sınırları,
ilk/sonraki guard ve predicate hatası ayrımı, değişmiş referanslar ve gerçek
writer orkestrasyonunda syntax RED/packet koruması sınandı. Native araçlar bu
synthetic testlerde çalıştırılmadı. Linux writer testi Windows'ta açık skip'tir.
Yeni temiz exact-head bağımsız inceleme ve fresh hosted gözlem ayrıca gerekir;
U003 FRONT, global freeze/model/native/product kabulü açık ve main değişmemiştir.
POP veya sonraki task'a geçiş yoktur.

Son direct-call hardening, yanlış exception nesnesini getattr'dan önce ve header
key'lerini set karşılaştırmasından önce primitive type ile reddeder. Son12-test
eski-source RED capture SHA
`21d3a3067c2836f92eaeb85d7ae2b84bd7af6f270dcc9f01fabfb172bef082e6`;
son81 odaklı test1.164s GREEN capture SHA
`5bfb8d08107434a283e8b0d739dd9dcfd1021115541cb9434f0171e328e28b55`.
Bu iki hardening öncesindeki513-test T1 koşusu32.617s GREEN idi:
`f329b6188af3ad228934371ca76633cf9085f49b47655be12fcbc8640672b718`.
Son temiz commit'in T1 tekrarı bağımsız exact-head incelemenin parçasıdır.
Gerçek sabit Python child CLI native yüklemeden önce yanlış config'i reddetti:
`0670d10e51bd654117812aed0cc8fe9131b9e09a5c2658ec30becc2daac67d48`.
Actual-be packet digest/producer Git blob bağlı CLI aynı13 BACKEND_FAILED
sonucunu korudu, capture SHA
`a918e908d28300bad65429b785d622da3e0ae0ec1ad533aef74e397261e941b9`.

## U003 eklemeli snprintf sabit-%s referans etkisi

2a01ff0 continuation'da gerçek Windows declaration ve Observe jobs, farklı
runner'larda mevcut OS metadata query timeout'u ile terminal failure oldu;
inclusion diagnostic'e erişildiği kanıtlanmadı. Aynı head'in normal CI ve Windows
build/test workflow'ları terminal success olarak gözlendi; identity failure
bunlarla PASS'e çevrilmez. Manuel workflow/job rerun onayı yok ve rerun yapılmadı.
Bu açık hosted sonuçlardan bağımsız mevcut U003 format-output transfer
yükümlülüğünün bir somut primitive'i uygulanıyor; FRONT değişmedi.

Eklemeli `api_effects/c-snprintf-linux-glibc239-v1.json`, özgün c.snprintf Linux
v2 declaration candidate/review/projection/model bağlarını değiştirmeden kullanır.
İlgili hosted packet'ta libc6/libc6-dev2.39-0ubuntu8.8 gözlenmişti. GNU glibc2.39
kılavuzunun yalnız iki izinli sayfası tek edinimde saklandı; gerçek kaynak ve
kopya ayrı bağımsız PASS aldı. Kalıcı arşiv:
`/home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH08-S01-U003/native-api-snprintf-manual-glibc239-v1`.
14 dosya50,888byte; manifest SHA
`92a45c1716163e7c685c4876aab8c6515458fbf717f4cf2782a807733c90ad56`.
İki HTML hash'i sırasıyla
`32f864f7f1b01a5cae74a2ada88af4fc516a2654c3540124563a5ee16fcc5f00` ve
`0cd33ffff54bf3964563e22e4ac53021e606f65bca5572f2e39a0e03bf640296`;
actual-source review SHA
`1746af065c2f66e63268bb24a1eb900205e8834b53ba70576e73fa631d11bd75`.
Kaynak belge sürüm bildirimi gözlendi; patched runtime eşdeğerliği/native
yeterlilik iddiası yok. Eski model2.42 reference pin'i yeniden yazılmadı.

19 yeni test exact2a01ff0 source altında62 beklenen missing-feature/subtest
error ile RED: capture SHA
`4bb90f13d985a437d8b553d55ea021aa1a371425fdf7e3464382c8678d6bca3d`.
12 ilk operation testi, full/truncated/zero/one/empty/offset/alias/overlap,
return belirsizliği/çelişkisi, source generation, validation invalidation ve
uint64 capacity'ye orantılı olmayan region storage'ı sınar. Altı reader testi
yanlış gerçek-bağ hash'leri, metadata sürümü, promotion/expected-output
forgery, CLI selector'ları ve late transitive input mutation negatiflerini
ekler. Bir mevcut declaration-reader testi enclosing guard paylaşımını sınar.
Reader testleri synthetic/stubbed kaynaklarla çalışır; gerçek kaynak bağı
ayrı CLI smoke'tur ve ikisi birbirinin yerine sayılmaz.

İlk reader koşusunda Path value eşitliği yerine Python nesne kimliği assertion'ı
hatalıydı. Bu fixture düzeltildi; başarısız capture saklandı, ürün RED'i diye
sunulmadı. Düzeltilmiş29 odaklı test GREEN capture SHA
`dafcdd088e5569e6d9918685ecb300219a39d792bb86d1a6c6eec4daccb02f74`.
532-test T1 paketi33.588s GREEN capture SHA
`6f671ceddaba3d3c1ae0eda1cfe403dcb6a8e2d54da8b18cd470ccbbff17094a`.
Gerçek hash/ancestor Git/declaration review/manual bağlı CLI altı referans
örneğinin tamamını doğruladı: dört MODELED_REFERENCE_EFFECT, iki açık
INCOMPLETE_NOT_SAFE. Capture SHA
`39824006697fea041b727f434b327e756449897d80c97e71110e2d6b0eb986a1`.
INCOMPLETE negatifler safe/native/ürün PASS değildir; bütün qualification
alanları false, quota katkısı sıfırdır. Yeni temiz exact-head bağımsız inceleme
ayrı gereklidir; tüm U003 acceptance veya global freeze tamamlanmış değildir.

Bağımsız exact9688a38 incelemesi532 test/CLI/queue ve2,500 byte-level pozitif
karşılaştırma geçmesine rağmen BLOCKED_IMPLEMENTATION verdi: pozitif capacity,
SAME_OBJECT ve negative/unknown return yolu overlap denetiminden önce dönüp
unrelated validation'ları koruyordu. INCOMPLETE demek bu bellek garantisini
kanıtlamaz. İlk bulgu ve önceki GREEN sonuçları değişmeden saklandı; ilk commit
PASS veya upstream yayını sayılmadı. Bulgu envelope SHA
`9bcca83655319d8c94d831419a5d61b26b5efea77a89a800db742636095aa115`.

Yeni test eski9688a38 implementasyonunda iki subcase ile RED:
`4df17fe29bf86e68d9c6925c7510e1c5c5b6de6ce730b52b6c9fd28d0a530806`.
Dar düzeltme aynı-object error-effect yolunu açık destek dışı bırakıp
outside-state uncertainty ile bütün validation'ları düşürür; sıfır capacity
no-write/unchanged-state yolu korunur.30 odaklı test GREEN capture SHA
`2f2771a4136533491b2d3c82d9e7ab4b06d7a0d1f0df9a876e4befec6d3b4ab6`.
533-test T1 paketi32.918s GREEN capture SHA
`a17ca6a332dafb137d94dbd27ef28e51a64af139f547c48bbdceb41aff3130da`.
Değişen head için yeni bağımsız inceleme gerekir; eski ret kararı geriye dönük
PASS'e çevrilmez. Yerel referans operator native/corpus/global-freeze kabulü
vermez ve U003 FRONT kalır.

## U003 Windows açılan-header gözlemi — eklemeli v3

Exact de6f9d1 Windows declaration packet'i yeniden indirildi ve bağımsız
denetlendi:188 hashli bağımlılığa karşı186 CIndex inclusion gözlendi;13 ve146
indeksleri eksik, unexpected sıfırdı. Tam worker stdout daha önce atılmıştı;
eşleme retained diagnostic'e bağlıdır. Eski run34739033719 terminal failure,
13 BACKEND_FAILED/INCOMPLETE ve qualified coverage0 olarak kalır. Dependency
ve özgün syntax komutları exit0'dı; summary syntax false backend RED'i içerir.
Normal Windows build'in ayrı success'i bu declaration sonucunu değiştirmez.
Genel CI'nın checkpoint runtime-before deadline failure'ı da ayrı açık kalır;
ne timeout floor'u ne başka task'ın runtime/test kodu bu değişiklikle düzenlenir.

Gerçek LLVM20 resource header byte hash'leri upstream20.1.8 kaynaklarıyla
eşleşti. `__has_include_next` lookup'ının `-M` bağımlılığına katılıp CIndex
entered-file listesinde yer almaması, sabit kendi Linux/LLVM22 dört-durum
deneyinde tekrarlandı. Bu mekanizma exact Windows kayıp içeriğinin yeniden
oynatılması veya MSVC/UCRT kaynaklarının yeniden okunması değildir. İlk packet,
kaynak, deney ve bağımsız inceleme53 dosya/1,352,556byte kalıcı arşivdedir:
`native-declaration-header-lookup-diagnosis-de6f9d1-v1`, manifest SHA
`f86278f9535ea2cd3b883fc15a4d8eeacafa75597797bd04ade53094756dd6a1`.

Yeni açık Windows modu full dependency dizisini aynen koruyup ayrı path-only
`-w -H -fsyntax-only` gözlemi toplar; özgün syntax/CIndex argv'si değişmez.
Saf okuyucu raw trace'ten projection'ı yeniden üretir ve main input dahil
CIndex entered set ile tam eşitlik ister. Gramer, LF/CRLF, path/depth/event/byte
sınırları, argv/source/environment/model/producer bağları fail-closed'dur.
Non-entered bağımlılık otomatik lookup-only muafiyeti değildir. Trace failure'da
özel error metni atılır, stream kimlikleri korunur ve worker açıkça başlatılmaz.
Eski v1/v2 closure/diagnostic anlamları, kaynak snapshot'ları ve 50+3 coverage
yükümlülüğü değişmez. Yeni guard eski inclusion annotation'ını yeniden kullanmaz.

Paket modu öncesi8-test RED capture SHA
`d97b513e080bf75e6ac375873df61d194867af217eb30a96556f85b4f05d3fc3`;
Windows workflow seçimi öncesi RED SHA
`8c0332b106ac937a574d292cbb73b1e4da108b302818e62cd0f6803b74505fdc`.
İlk GREEN denemelerindeki iki fixture hatası (`os` import adı ve Windows
platform etiketinin yazımı) ayrı başarısız capture'larda korundu; ürün RED'i
sayılmadı.120 declaration/legacy/writer/adapter kontrolü GREEN SHA
`c2fa8e9c699ecaa93f278a2a60cecd51c0cbcdb1a1781a27fa31501cc27fc16f`;
16 source-bound reader/candidate kontrolü GREEN SHA
`572e5a08f489bf52d90349fc48ac8b4b94f65bba663e72861229207c4383df1d`.
554-test T1 paketi34.137s GREEN SHA
`01b2579c12eeeb0a4474663fb7464266da7f5a7aea2435510befff1dd107b23c`.
Gerçek Git/declaration/manual bağlı snprintf effect CLI korunuyor: SHA
`5dbc5ef31a581b9e2b5169f2015bc479c1d4310bea19702ecb6684b1d94831f7`.

Üretim trace capture ve pure trace reader, yedi sabit kendi-kaynak Linux/LLVM22
kontrolünde ayrıca çalıştı: dört include/lookup durumu, özgün warning,
gerçek error ve pragma-once tekrarları. Başarılı entered set CIndex'le tam
eşleşti; warning özgün kanallarda kaldı, error raw trace'e dönüştürülmedi.
Capture SHA `141eb8cf2d496084734b79e933230ccf65864b0fb53a29a8610ff4223ed46c0a`.
Bu test Windows v3 packet yakalaması değildir. Sentetik Windows writer/reader
testleri de native execution veya producer Git blob doğrulaması yerine geçmez.

İlk saf-helper incelemesi yalnız advisory idi; paket entegrasyonu için yeni
temiz exact-head bağımsız inceleme ve taze gerçek Windows gözlemi ayrıca gerekir.
Henüz yeni hosted packet/candidate/review veya Windows/native/model/global-freeze
PASS yoktur. U003 FRONT, >=1020 bağımsız örnek ve bütün API/flow yükümlülükleri
açıktır; hiçbir POP, main değişikliği veya manuel workflow rerun yapılmadı.
