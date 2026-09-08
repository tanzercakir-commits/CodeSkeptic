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
saptadı: bağımsız kotadan dışlandı. Derived-return/matching-delete adayı yalnız
memory-leak ailesi için safe etiket önerisidir; tam bağımlılık ve bağımsızlık
incelemesi bitmediğinden kabul edilmedi. İkisi de analiz edilmedi ve **0/1020**
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
