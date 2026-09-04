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
