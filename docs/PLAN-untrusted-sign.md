# PLAN — İşaretli→işaretsiz güvenilmez uzunluk kuralı (3a) + out-param kaynakları (3b)

> 2026-07-29. nlohmann kampanyasının mirası. Bu belge bir sonraki
> oturumun kendi kendine yeten başlangıç brifingidir — taze bağlam +
> max effort işi (PLAN-f7a.md disiplini aynen).

## Kanıtlanmış false negative (motivasyon)

nlohmann/json #3491 (UBSAN null-deref) + #3492 (ASAN heap-buffer-
overflow), fix `93c9e0c7`. Düzeltme-öncesi ağaç (`6a739205`),
`binary_reader.hpp get_ubjson_size_value`:

```cpp
std::int8_t number{};
if (JSON_HEDLEY_UNLIKELY(!get_number(input_format, number)))  // out-param doldurur
    return false;
result = static_cast<std::size_t>(number);   // number NEGATİF olabilir → devasa size_t
```

CodeSkeptic üç yoldan tarandı (iki TU + `--function`), üçünde de
**Clean** — false negative. Neden, tahmin değil, kaynak okumasıyla
kanıtlı: `IntOverflowRule.cpp` bu deseni İKİ kapıyla BİLEREK dışlıyor:

1. `ce->isPartOfExplicitCast()` → açık cast "beyan edilmiş niyet"
   sayılıp geçiliyor (satır ~126),
2. hedef işaretsizse → sarma UB değil diye sessiz (satır ~130).

Yani bu bir ayar meselesi değil, **kapsam boşluğu**: ayrı kural ister.
İkinci kanıt: 4-şekilli izole sonda (`/tmp/probe2` — out-param,
dönüş-değeri, en bariz `int→size_t`, `malloc`'a giden hali) —
`--untrusted-int-sources` AÇIKKEN bile hepsi temiz, çünkü bayrak
bugün yalnız DÖNÜŞ değerlerini güvenilmez sayıyor; nlohmann'ın
`get_number(fmt, number)`'ı REFERANS out-param dolduruyor.

## 3a — Kural: "sign-conversion of untrusted length" (CWE-195 komşuluğu)

Rapor koşulu (ÜÇÜ birden, precision-first):

1. Değer İŞARETLİ bir tamsayı ve kaynağı GÜVENİLMEZ (mevcut model:
   atoi/strtol ailesi, scanf çıktıları, `--untrusted-int-sources`);
   sağlanmamış provenans ASLA varsayılmaz (untrusted-length.md
   doktrini aynen),
2. işaretsiz bir tamsayıya dönüştürülüyor (implicit VEYA explicit —
   DİKKAT: bu kuralda `isPartOfExplicitCast` MUAFİYET DEĞİL; nlohmann
   hatası cast'i bizzat yazarak yapıldı. IntOverflowRule'un muafiyeti
   oradaki anlamıyla doğru ve DEĞİŞMEZ; yeni kural kendi sorusunu
   sorar),
3. yolda negatifliği dışlayan guard YOK. Interval makinesi zaten var:
   `if (x >= 0)` / `if (x < 0) return` daraltır → sessiz;
   **yalnız üst sınır kontrolü (`if (x > 100) return`) SUSTURMAZ** —
   negatif aralık hâlâ içeride (nlohmann'ın gerçek hatası tam buydu).

v1 kapsam kararı: dönüşümün KENDİSİ raporlanır (sink-agnostik) —
negatifin devasa işaretsize sarılması, lavabodan bağımsız olarak
kusurdur ve nlohmann'da sink başka fonksiyondaydı (interprocedural
akış v1'i beklemesin). Severity: warning.

## 3b — Out-param güvenilmez kaynak modeli

`--untrusted-int-sources`'a eklenen fonksiyonlar dönüş değerine ek
olarak şunları da kirletsin: non-const referans tamsayı paramlar ve
tamsayıya-pointer paramlar (çağrı sonrası tam-aralık güvenilmez).
scanf çıktı-doldurma mekanizması zaten mevcut — aynı tesisatı genelle.

## Kabul testleri (asgari)

- 4 sonda şekli (A out-param / B dönüş / C bariz int→size_t /
  D malloc'a giden) → hepsi RAPOR (bugün: hepsi sessiz, KIRMIZI
  başlanacak),
- `x >= 0` guard'ı → sessiz; yalnız-üst-sınır guard → RAPOR,
- işaretsiz kaynak → sessiz; bayraklar kapalı → bayt-bayt eski
  davranış (Juliet tabanları ve tüm süit değişmez),
- kupa testi (konvansiyon: `TFLite_123387_...` gibi):
  `Nlohmann_3491_UbjsonSizeValue_Reports` — düzeltme-öncesi şeklin
  minimal kopyası rapor vermeli.

## Yürütme notları

- Dal: `phase-untrusted-sign` ← main (`a6454b4` sonrası güncel uç).
- Önce testler KIRMIZI, sonra kural — AR.3 fix turlarında işleyen
  disiplinin aynısı.
- Ölçüm hedefleri: nlohmann pre-fix ağacı (retro-tespit artık YEŞİL
  olmalı), tinyusb (mevcut temizlik bozulmamalı — untrusted-length.md
  makbuzu), Juliet CWE-195/196 dosyaları varsa keşif amaçlı koşulur
  (taban eklenmez, önce gözlenir).
- Oturum pratiği: sandbox'ın GitHub token'ı oturumla ölür — yeni
  oturumda push için token yeniden verilmeli.
