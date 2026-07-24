# Assert-Refinement Precision Turu — Fizibilite ve İş Planı

> 2026-07-25, tarama survey'inin (docs/scan-survey-2026-07-25.md)
> devamı. ÖLÇÜMLE düzeltilmiş plan: ilk hipotez "motor assert'i
> daraltmıyor" idi; yerel deney bunu ÇÜRÜTTÜ ve gerçek boşluğu buldu.

## Belirleyici deney (2026-07-25, yerel)

```c
int* p = malloc(4);
assert(p != NULL);      /* CANLI glibc assert */
return *p;              /* SONUÇ: uyarı YOK — motor zaten daraltıyor */
```

Canlı (derlenmiş) bir assert bugün DOĞRU çalışıyor: `__assert_fail`
noreturn → false-kenar ölür (DataflowEngine noreturn desteği) +
true-kenar refineOnEdge ile NonNull. Kontrol fonksiyonu (assert'siz
malloc deref) uyarıyor. Yani daraltma makinesinde İŞ YOK.

## Gerçek boşluk: DERLEMEDEN ÇIKARILAN assert'ler

Beş tanığın assert'leri default derlemede `((void)0)`a genişliyor —
invariant AST'de HİÇ YOK; motor görmediğini daraltamaz:

| Tanık | Makro | Etkinleştiren define |
|---|---|---|
| zstd | assert (debug.h sarmalı) | -DDEBUGLEVEL=1 |
| lua | lua_assert | -DLUAI_ASSERT |
| curl | DEBUGASSERT | -DDEBUGBUILD |
| sqlite | assert | -DSQLITE_DEBUG |
| raylib | standart assert | AÇIK SORU: canlıysa neden 177? → AR.2
|        |                  | yeniden-taraması cevaplar (muhtemelen
|        |                  | vendored kod + farklı aileler) |

## Dilimler (ölçüm-öncelikli sıra)

### AR.1 — Canlı-assert davranışını pinle (TRİVİAL, ~%0.5) — ✔ TAMAM (2026-07-25)
Yukarıdaki deneyi çift yönlü kalıcı teste çevir (canlı assert →
sessiz; assert'siz kontrol → uyarı). Bugünkü doğru davranış
regresyona kapansın.

### AR.2 — "Assertion-enabled scan" doktrini — ✘ ÖLÇÜLDÜ, ÇÜRÜDÜ (2026-07-25)

**Sonuç: define-tabanlı yaklaşım KİRLİ ANAHTAR, temiz düzeltme DEĞİL.**
curl off-vs-on kanıt sondası (e9b5c3f):
- assertions_off: 82 null-deref (baseline)
- assertions_on (-DENABLE_DEBUG=ON → DEBUGBUILD → DEBUGASSERT canlı): 110
- Site diff: ~181 konum assert AÇILINCA SUSTU (mekanizma ÇALIŞIYOR,
  assert-ailesi gerçek) AMA DEBUGBUILD alakasız debug kodunu da açtı
  (multi.c debug-only bloğu) → susandan çok gürültü ekledi, net ARTTI.

Ders: assert-daraltma DOĞRU çalışıyor (AR.1 + bu 181 konum), ama
"kullanıcı debug define'ıyla derlesin" teslim mekanizması yanlış —
semantiği değiştirir, gürültü katar. Kalan 4 tanık için tekrar
ölçmeye GEREK YOK; define-yolu elendi.

**Sonuç AR.3'ü ZORUNLU kılar** (aşağıda) — tercih değil, tek temiz yol.

### AR.2-eski — [define doktrini, çürütüldü — yukarı bakın]
Profil katmanı işi, motor işi DEĞİL: tarama compile db'si assertion
define'larıyla üretilir (tablodaki -D'ler; realworld lane'de configure
bayrağı). Doktrin gerekçesi: assert, geliştiricinin KENDİ yazdığı
sözleşmedir — analiz onları açık görmelidir. Beş tanık yeniden
taranır; FP çöküşü ÖLÇÜLÜR (beklenti: lua 36→~0, sqlite/curl büyük
düşüş). Yan etki dürüstlüğü: debug define'ları başka kod da açar
(sqlite'ta çok); sayılar bunu da gösterecek — susturulmaz, raporlanır.

### AR.3 — Kaybolan-assert kurtarma (MOTOR dilimi) — ✔ UYGULANDI (2026-07-25)

Clang `PPCallbacks::MacroExpands` ile, koşulunu ATAN assert-benzeri
makroların çağrıları yakalanır; argüman token'ları dar bir null-sabiti
grameriyle çözülür; genişleme konumuna "sanal guard" düşer;
`DataflowEngine` sonraki deyimden ÖNCE `applyAssertGuard`'ı çağırır
(NullDerefRule NonNull'a daraltır). `--fatal-asserts`ten FARKLI iş: o,
görünür ÇAĞRIları noreturn sayar; bu, GÖRÜNMEYEN makroları kurtarır.

Dört kapı (hepsi geçilmeden kayıt yok):
1. **Gövde koşulu atıyor mu** — makro gövdesi argümanı KULLANIYORSA
   koşul zaten AST'de; kurtarma yok (AR.1'in pinlediği canlı yol
   dokunulmadan çalışır, çift-işleme yapısal olarak imkânsız).
   **Ayrıca TAM BİR parametre**, variadic değil: çok argümanlı bir
   assert argümanları arasında BAĞINTI kurar, tek başına 0. argüman
   başka bir iddiadır — `ASSERT_EQ(p, NULL)` örneğinde tam TERSİ.
2. **Adı assert-benzeri mi** — "assert" alt-dizisi (harf duyarsız)
   veya `--assert-macros` ile açıkça bildirilmiş. **OLUMSUZ iddia
   duyuran ad yazımla veto edilir** (`null`, `false`, `zero`, `not`,
   `fail`): cmocka `assert_null`, Unity `TEST_ASSERT_NULL` pointer'ın
   null OLDUĞUNU söyler; tersten inanmak kanıtlanmış olguyu ters
   çevirir. Açık bildirim vetoyu ezer (anlamı orada kullanıcı verir).
3. **Token şekli dar mı** — `x`, `x != NULL`, `NULL != x`, `A && B`
   (üstünde `||` YOKSA konjonktler ayrı ayrı düşürülebilir; `||`
   varsa TÜM kayıt reddedilir). NULL yazımları: `NULL`, `nullptr`,
   `0`, `(void*)0`, `((void*)0)` — hepsi dilin kurallarınca null
   pointer sabiti, ek varsayım eklemez.
4. **Konum kanıtlanabilir mi** — guard, genişlemeden SONRAKİ ilk
   deyime bağlanır; parantezsiz `if`/`while` gövdesi, `switch`
   düşmesi, `goto`/etiket, gölgelenmiş/çift isim → reddedilir.
   **Hedef DÖNGÜ olamaz**: guard, deyim her transfer edildiğinde
   yeniden ateşlenir; döngüden ÖNCEKİ assert ise bir kez çalışıp
   sadece GİRİŞİ domine eder — döngüye bağlamak, gövdede yeniden
   atanan pointer'ı her turun başında temize çıkarırdı.

**Dürüst kayıt:** bu bir SAĞLAMLIK düzeltmesi DEĞİL. NDEBUG'lu build
o kontrolü gerçekten çalıştırmaz. Bu, "yazarın assert'i, olduğunu
söylediği invaryanttır" kararının bilinçli, ilan edilmiş kabulüdür —
`--no-assert-recovery` ile kapatılır (o zaman rapor, sevk edilen
build'in gördüğü koda birebir uyar).

v1 kapsam dışı: tamsayı `!= 0` assert'leri, alan/dizi özneleri, başka
bir makro genişlemesi içine gömülü assert'ler, MCP sıcak-AST yolu.

Batarya: `tests/AssertRecoveryTest.cpp`, 38 test (kontrol / susan
şekiller / dört kapının reddettikleri / canlı-yol regresyonu / config
/ mekanizma sayacı). Toplam süit 734 → 772, sıfır regresyon.

**Düşman gözüyle inceleme (adversarial review) — 3 SESSİZ HATA.**
İlk 33 testlik batarya YEŞİLKEN, kodu "ne yaptığına" değil "neye
İNANDIĞINA" bakarak okuyan bir gözden geçirme üç yanlış-negatif buldu;
üçü de bulguyu sessizce emekliye ayırıyordu:

| # | Hata | Kapı | Kapanış |
|---|---|---|---|
| 1 | Döngüden önceki assert döngüye bağlanıp her turda yeniden ateşleniyordu → gövdede `malloc`'a yeniden atanan pointer'ın deref'i susuyordu | 4 | while/do/for/range-for hedefleri reddedilir |
| 2 | Çok parametreli makroda yalnız 0. argüman ayrıştırılıyordu → `ASSERT_EQ(p, NULL)` "p non-null" diye kaydediliyordu | 1 | tam 1 parametre, variadic değil |
| 3 | "assert" alt-dizisi iddianın YÖNÜNÜ hiç sormuyordu → `assert_null(p)` **kesin-null** bir bulguyu susturuyordu | 2 | olumsuz-ad vetosu |

Ders: yeşil süit, kapsanmamış bir varsayımı kanıtlamaz. Üçü de
`tests/AssertRecoveryTest.cpp` C2 bölümünde pinli ve her biri
düzeltme-öncesi ikilide DÜŞTÜĞÜ doğrulanarak yazıldı.

## Sıra ve karar kapısı

```
AR.1 (pin) → AR.2 (doktrin + ÖLÇÜM) → [sayılara bak] → AR.3 mü, 7A.2 mi?
```

KARAR VERİLDİ (ölçümle): AR.2 define-yolu net gürültü ARTIRDI (curl
82→110), yani elendi. AR.3 (PPCallbacks kurtarma) tek temiz yol ve
ZORUNLU. Sıra: AR.3 (max, taze kota) → sonra 7A.2. curl'ün gerçek
assert-ailesi (~181 konum) AR.3 landing'inde ölçülür.

## Bütçe ve Go

- AR.1+AR.2: ~%3 — taze kota şartı YOK, düşük efor yeter (profil+CI).
- AR.3: taze kota + max; PLAN-f7a.md'deki disiplin kuralları aynen.
