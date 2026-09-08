# Piyasa öncelikleri — sınırlı C/C++ CWE ürünü

Bu kayıt CH08+ için onaylı öncelik gerekçesidir; bugün kurulu capability listesi değildir.
Mevcut davranış [capabilities](capabilities.md), hedef [ürün planı](PRODUCT_COMPLETION_PLAN.md)
ve [kalite sözleşmesi](product-quality-contract.md) ile ayrıdır.

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
