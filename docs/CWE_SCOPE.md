# Ürün sınırı ve ölçülü kalite hedefi

Hedef mevcut C/C++ analiz çekirdeğine gerçekten eksik, pratikte kullanılabilir
davranışlar eklemek; her CWE'nin her varyantını çözdüğünü iddia etmek değildir.
Kapsam araştırması main kodu üzerinden yapıldı; kaynakta görülen boşluklar
çalıştırılmış regresyonla doğrulanmadan kanıtlanmış hata sayılmaz.

| Öncelik | Yeni davranış | Bölüm |
|---|---|---|
| Sayısal boyut güvenliği | Signed64 çıkarma, unsigned64 allocation toplamı, checked-add, kanıtlı narrowing | CH01 S01/S05 |
| Buffer okuma güvenliği | memcpy/memmove kaynak kapasitesi, sabit pointer offset sonrası kalan alan | CH01 S02 |
| Başlatılmamış değer | Scalar integer/bool okuma, ardından CFG birleşmeleri | CH01 S03 |
| Kaynak ömrü | accept/accept4 ve pipe/pipe2 FD sahipliği | CH01 S04 |
| Kullanılabilirlik | Doctor, dürüst TU coverage, sağlam parser, tutarlı raporlar | CH02/CH03 |
| Güvenilir işletim | Worker sınırları, iptal/bellek, cache/checkpoint | CH04 |
| Teslim kalitesi | Sabit test katalogları, ölçüm, artifact/container/platform | CH05–CH07 |

CWE bağlamı: [CWE-125](https://cwe.mitre.org/data/definitions/125.html),
[CWE-131](https://cwe.mitre.org/data/definitions/131.html),
[CWE-457](https://cwe.mitre.org/data/definitions/457.html),
[CWE-787](https://cwe.mitre.org/data/definitions/787.html).
Bu eşleme sertifikasyon veya evrensel tespit garantisi değildir.

## Test ekonomisi

Her çekirdek işi: önce küçük RED, ardından pozitif + yakın güvenli negatif,
ilgili component ve gerçek CLI smoke. Derin worker/parser değişikliği: tam Linux
suite ve yalnız ilgili sanitizer/corpus kesiti. Paketleme: adı verilmiş kullanıcı
akışları ve hedef platformlar. T0 değişikliğine bütün C++/sanitizer evreni koşulmaz.

CH05 katalogları değerlendirmeden önce sabitlenir; başarısız örnekler sonradan
çıkarılmaz. Yeni supported promotion için plandaki en az %90 precision ve
%70 addressable recall hedefi ölçülür; mevcut daha sıkı tabanlar korunur.
Güvenli deterministik negatiflerde false positive kabul edilmez. Örnek sayıları,
kapsam dışı nedenleri ve tüm başarısızlar raporlanır; küçük fixture başarısı gerçek
piyasa genellemesi gibi sunulmaz. Ölçüt sağlanmazsa özellik experimental kalır.

Global interprocedural pointer çözümü, tüm C++ standardı, yeni diller, SaaS/GUI,
sertifikasyon ve ölçülmemiş performans vaatleri bu programın dışında. Yeni
gereksinimler gerekçeli plan amendment ile eklenir, sessiz kapsam büyümesi olmaz.

## CH05 — sabit katalog ve destek kararı

`tests/cwe_corpus/catalog.json` bütün 12 CWE ailesi için kaynak üzerinden seçilmiş
52 örneği sabitler: 24 hatalı, 22 ilgili kural açısından güvenli, 3 unknown ve
3 unsupported. Rationale, kaynak regresyonu, compiler/source ayarı, dosya SHA-256
ve beklenen kural/fonksiyon çokluğu her örnekte açıkça kayıtlıdır. Katalog
tek başına kalite ölçümü veya terfi kararı değildir; 7 supported / 8 experimental
public capability düzeni değişmez. Assumption/contract/policy CWE ailesi değildir,
ancak mevcut kaynak ve dış kontrol görevlerinden çıkarılmaz.

Yeni çekirdeğin signed64 çıkarma, uint64 allocation toplamı, checked-add
status/output kimliği, implicit narrowing, copy source/offset, scalar CFG,
accept/pipe ve dar RAII/fdopendir davranışları katalogda temsil edilir. Tüm
96 eski test dosyası ve 28 registry/build/runner/pin/workflow girdisi ayrıca
hash ile bağlanmıştır. Küçük örnekler zor alias/mutation/worker/cache testlerinin
yerine geçmez. Dosya sayısı çalıştırılmış test veya bağımsız ölçüm sayısı değildir.

`docs/quality_protocol.md` iki farklı “sessiz” sonucu ayırır: kanıtlı safe negatif
ve model/kaynak sınırı nedeniyle unknown/unsupported. İkinciler clean/TN veya
addressable FN diye sayılmaz; bilinen kapsam dışı kusur da güvenli ilan edilmez.
Katalog kontrolü `python3 -B scripts/cwe_quality.py check` ile yapılır.

U002/U003 gerçek ölçümleri [quality_results.md](quality_results.md) içinde ayrı
revision, executable hash ve paydalarıyla kayıtlıdır. U003'te beş experimental
CWE ailesinin 27 örneği çalıştı: 12 buggy, 10 safe, 2 unknown, 3 unsupported.
Her ailenin adreslenebilir küçük örneklerinde precision/recall 1.000 ve safe FP
sıfırdır; bu bağımsız piyasa doğruluğu ölçümü değildir. Unknown/unsupported
sessiz çıktılar güvenli örnek sayılmamıştır. Pointer kuralının sınır kanıtı ayrıca
tam kaynak testlerinde raporlanır; katalogdaki iki örneğin paydasına eklenmez.

Karar: beş aile de ürünün parçası ve varsayılan report-only olarak kalır.
Bağımsız aile precision örneklemi eksik olduğu için supported/blocking terfisi
yoktur; hiçbir özellik teslim kapsamından çıkarılmamış, %90/%70 hedefi veya
mevcut daha sıkı floor/pin düşürülmemiştir. Gelecekte terfi değerlendirilirse
örneklem sonucu görülmeden sabitlenmeli, bağımsız sınıflandırılmalı ve bütün
ilgili kalite kapıları yeniden sağlanmalıdır. Bu karar mevcut Windows hatasını,
sanitizer/performance/paketleme ve teslim görevlerini tamamlanmış saymaz.
