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

## Bağımsız değerlendirme henüz yok

Kabul edilmiş yeni bağımsız kota örneği: **0 / en az 1020**. Kaynak seçimi,
bağımsız etiket/semantik cluster incelemesi ve dört yeni ailede zorunlu gerçek
security-fix çiftlerinin incelenmesi bitmedi. Bu eksiklik fixture çoğaltma,
köken yeniden adlandırma veya unknown'u safe sayma yoluyla giderilemez.

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
