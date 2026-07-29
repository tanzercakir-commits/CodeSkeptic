# PLAN — FINDING 2: olumsuz-ad vetosunun açığa düşmesi (2b)

> 2026-07-30. AR.3 incelemesinin geri kalan bulgusu. Sonraki oturumun
> kendi kendine yeten brifingi — taze bağlam, precision/recall tasarım
> kararı (kod değil, önce KARAR).

## Açık — kesin yeri

`src/engine/AssertGuards.cpp:574` — `isAssertLikeName()` içinde:

```cpp
for (const char* negative : {"null", "false", "zero", "not", "fail"})
    if (lower.find(negative) != std::string::npos) return false;
return true;
```

Adında "assert" geçen bir makro, bu 5 alt-dizinin HİÇBİRİNİ içermiyorsa
**pozitif non-null iddiası** sayılır ve kurtarılır (gate 2 geçer).

## Neden "fails open" — ciddiyet

Bu bir kaçırma (recall) değil, **olguyu ters çevirme** riski. Adı
olumsuz iddia duyuran ama denylist'te olmayan bir makro:

- `assert_nil(p)` — "nil" listede YOK ("null" var ama "nil" ayrı kelime)
- `assert_empty(p)`, `assert_none(p)`, `assert_absent(p)`,
  `assert_missing(p)`, `assert_no(...)`, `assert_bad(...)`,
  `assert_invalid(...)`

`p`'nin NULL OLDUĞUNU söyleyen bir assert, "p non-null" diye kaydedilir
→ kesin-null bir deref bulgusu **sessizce susturulur.** Gate 2'nin var
oluş sebebi tam olarak buydu (cmocka `assert_null` vakası); denylist o
vakayı kapatıyor ama komşularını açık bırakıyor.

## Tasarım gerilimi — bu yüzden taze oturum

Kritik kısıt: **kaybolan assert'te koşul AST'de YOK.** Elimizde yalnız
(a) makro ADI ve (b) argüman token'ları var. `assert_null(p)`'nin
argümanı `p` — bu, pozitif gramerle (`x`) BİREBİR aynı. Yani argüman
şekli iki yönü ayırt edemez; **ad tek sinyal.** Denylist doğası gereği
eksiktir: bir sonraki bilinmeyen olumsuz kelimede yine açığa düşer.

Bu yüzden bu "5 kelimeyi 12 kelime yap" işi değil — bir DOKTRIN kararı:

## Seçenekler (karar sonraki oturuma ait)

1. **Denylist'i gerçek-dünya olumsuz-assert sözlüğüne genişlet**
   (nil, empty, none, absent, missing, no, bad, invalid, err) + kalan
   fails-open'ı DÜRÜSTÇE belgele. Ucuz, düşük risk, yaygın vakaları
   kapatır. Ama ilkesel olarak hâlâ eksik.
2. **Yön çıkarımını tamamen bırak, muhafazakâr varsayıl** — bilinmeyen
   assert-alt-dizili makroyu kurtarma, YALNIZ `--assert-macros` ile açık
   bildirilmişse kurtar. Bu, AR.3'ün değerinin ÇOĞUNU öldürür (çünkü
   yaygın `assert`/`DEBUGASSERT`/`lua_assert` ekosistem aileleri açık
   bildirim olmadan çalışıyordu). recall'a ağır bedel — muhtemelen HAYIR.
3. **Melez (ÖNERİLEN):** (a) denylist'i olumsuz-assert sözlüğüyle
   genişlet, (b) projeye özel olumsuz adlar için bir bayrak ekle
   (`--negative-assert-macros`, `--assert-macros`'un tersi), (c) kalan
   fails-open'ı usage.md'de açıkça yaz. Yaygın gerçek çerçeveleri
   kapatır, kaçış kapağı verir, dürüstlüğü korur. En düşük risk / en
   yüksek kapsam.

## Kabul testleri (KIRMIZI-önce, AssertRecoveryTest.cpp)

- `assert_nil(p)`, `assert_empty(p)`, `assert_none(p)` → non-null guard
  ÜRETMEMELİ (pre-fix binary'de kesin-null bulgu susuyor mu, RED
  doğrula) — kupa: bu makronun altındaki deref UYARMALI;
- `--negative-assert-macros CHECK_NIL` → CHECK_NIL(p) vetolanır;
- regresyon: `assert(p)`, `DEBUGASSERT(p)`, `lua_assert(p)` hâlâ
  kurtarılır (pozitif yol bozulmamalı);
- `assert_non_null(p)` / `ASSERT_NOT_NULL(p)` hâlâ vetolu kalır (mevcut
  davranış — "not" ile yakalanıyor, guessing-right onlara değmez).

## Ölçüm

- Gerçek hedef aranmalı: adında olumsuz-assert kelimesi (nil/empty/…)
  geçen makro kullanan bir C/C++ projesi. AR.3 tanıklarında (curl,
  sqlite, lua, zstd) bu şekil YOKTU — desen taraması gerekebilir.
- Juliet tabanları etkilenmez (assert-recovery varsayılan açık ama bu
  kural yalnız kurtarma yönünü daraltır; precision-safe).

## Yürütme

- Dal: `phase-negname` ← main güncel uç.
- Bağlam kalabalıksa ÖNCE bu kararı ver (1/2/3), sonra kod.
- Push öncesi YERELDE: full suite + thesis + corpus (bu turda CI'ın
  yakaladığı thesis-precision dersini tekrarlama).
- Token bu sandbox'la ölür; yeni oturumda yeniden ver.
