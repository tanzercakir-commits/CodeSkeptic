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

### AR.1 — Canlı-assert davranışını pinle (TRİVİAL, ~%0.5)
Yukarıdaki deneyi çift yönlü kalıcı teste çevir (canlı assert →
sessiz; assert'siz kontrol → uyarı). Bugünkü doğru davranış
regresyona kapansın.

### AR.2 — "Assertion-enabled scan" doktrini + 5 tanığın yeniden ölçümü (~%2-3, çoğu CI)
Profil katmanı işi, motor işi DEĞİL: tarama compile db'si assertion
define'larıyla üretilir (tablodaki -D'ler; realworld lane'de configure
bayrağı). Doktrin gerekçesi: assert, geliştiricinin KENDİ yazdığı
sözleşmedir — analiz onları açık görmelidir. Beş tanık yeniden
taranır; FP çöküşü ÖLÇÜLÜR (beklenti: lua 36→~0, sqlite/curl büyük
düşüş). Yan etki dürüstlüğü: debug define'ları başka kod da açar
(sqlite'ta çok); sayılar bunu da gösterecek — susturulmaz, raporlanır.

### AR.3 — Kaybolan-assert kurtarma (MOTOR dilimi, ORTA, ~%5-8, max)
AR.2 sayıları "define'la açmak yetmiyor/istenmiyor" derse: Clang
PPCallbacks ile, kayıtlı assert-benzeri makroların (assert,
lua_assert, DEBUGASSERT, ... — config listesi) BOŞ genişleyen
çağrılarını yakala; argüman token'larını dar v1 şekillerinde çöz
(`x`, `x != NULL`, `x && y`); genişleme konumuna bir "sanal guard"
kaydı düş; akış transferi o konumda refineOnEdge eşdeğerini uygular.
- Repo'da PP altyapısı HENÜZ YOK (grep doğrulandı) → yeni alt sistem.
- Risk ORTA: token-düzeyi çözümleme + konum eşleme incelikleri;
  v1 şekil listesi bilinçli dar, her genişletme pinli.
- Not: --fatal-asserts'ten FARKLI iş (o, görünür ÇAĞRIları noreturn
  sayar; bu, GÖRÜNMEYEN makroları kurtarır). İkisi tamamlayıcı.

## Sıra ve karar kapısı

```
AR.1 (pin) → AR.2 (doktrin + ÖLÇÜM) → [sayılara bak] → AR.3 mü, 7A.2 mi?
```

AR.2'nin çöküş sayıları karar verdirir: define-yolu FP'lerin %80+'ını
düşürüyorsa AR.3 ertelenebilir (7A.2 UAF dilimi öne geçer); düşüş
sınırlıysa AR.3 motor dilimi önceliklidir. Tahminle değil ölçümle.

## Bütçe ve Go

- AR.1+AR.2: ~%3 — taze kota şartı YOK, düşük efor yeter (profil+CI).
- AR.3: taze kota + max; PLAN-f7a.md'deki disiplin kuralları aynen.
