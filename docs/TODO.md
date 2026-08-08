# CodeSkeptic — TODO (aktif işler + açık kararlar)

> Bu belge canlı: sıradaki iş, öncelikler, kullanıcı kararları burada.
> Tamamlanan işler changelog'a taşınır ve buradan silinir. Sabit plan
> ve tüm yol haritası → `PLAN.md`.

## Şu anki durum

Aşağıdaki blok ÜRETİLİR — elle düzenleme. Tazele:
`scripts/check_docs_sync.sh --fix`. CI guard #6 phase* dallarında bunu
git gerçeğiyle karşılaştırır, bu yüzden bayatlayamaz.

<!-- cs:state-begin -->
```
base   = 38e29e2
uçuşta = phase-truth-sync-v048 phase-v048-release-smoke-fix phase-verdict-integrity-validation
```
<!-- cs:state-end -->

Serbest not (insanda kalır): Faz 0 verdict-integrity ve truth-sync dilimleri
PR #119 (`dd08970`) ve PR #120 (`38e29e2`) ile `main`e alındı. İlk v0.4.8
tag koşusu ürün/paket kontrollerini geçti; macOS negative-smoke adımı doğru
`VERDICT UNAVAILABLE` çıktısında eski metni aradığı için release-contract
hotfix'i hazırlanıyor.

## libarchive değerlendirmesi — KAPANDI (2026-08-01)

Üç precision notu, üçü de kapatıldı: BULGU 2 (sign-conversion non-size
sink kapısı) ve BULGU 1 (bounds struct-hack/FAM kuyruk muafiyeti) kod
olarak indi ve ikisi de **önceden yazılmış tahmine karşı** ölçüldü —
19→14 ve 14→13, ikisinde de delta'nın tamamı niyet edilen sınıf,
kolateral sıfır. BULGU 3 kod değil önkoşul; backlog #1'e işlendi.
Yan ürün: corpus pin'i 53→54 merkeze alındı (895c813'ten beri
sürükleniyordu, toleransın içinde sessizce).

## Sıradaki iş

Bağlayıcı ürün programı sırası: v0.4.8 release-smoke sözleşme düzeltmesini
CI kanıtıyla birleştir, etiketi doğrulanmış `main`e taşı ve üç platformlu
yayını tamamla. Ardından Faz 0'ı kapatıp Faz 1 capability tier sözleşmesine
geç.

## Açık kullanıcı kararları

Yok. Kullanıcı 2026-08-08'de ürün programı tamamlanana kadar dış etkili
işlemler için sürekli yürütme yetkisi verdi; tekrar onay beklenmeyecek. Güncel
CI makbuzları PR açıklamasında tutulur, bu TODO geçici run durumlarını
kopyalamaz. PR #119'un yönetici bypass'ı tamamlandı; TensorFlow PR #123994
merge edildi, issue #123387 kapandı ve PLAN §6 ledger'ı güncellendi.

## Backlog (öncelik sırası)

```
1. CWE-775 strict (int fd: open/socket) — integer-kaynak modeli
   > BULGU 3 (libarchive, 2026-08-01): artık tahmin değil ÖNKOŞUL.
   > Dosya açan bir kütüphanede resource-leak 0 verdi; sebebi ölçüldü —
   > 43 ham fd açıcı (open 28 · openat 8 · dup 4 · mkstemp 3) karşısında
   > pointer tabanlı domain'in gördüğü fopen/opendir/tmpfile toplam 3.
   > CWE-404'ün idiyomatik POSIX C'de karşılık bulması buna bağlı; o
   > zamana dek "resource leak" kapsamı FILE*/DIR* ile sınırlı
   > anlatılmalı. Makbuz: changelog 2026-08-01 (BULGU 1 kaydı).
2. alloc-size v2: 64-bit size_t çarpım köşe-ispatı
3. FINDING 3 kalıntısı: alan-özneli assert'ler   (DEBUGASSERT(data->conn) sınıfı)
5. sign-conversion v2: interprocedural sink (nlohmann'da harm başka fn'deydi)
```

## Not — dosya disiplini (2026-07-30 kararı)

Yeni PLAN-*.md AÇMA. Her iş: changelog'a giriş + bu TODO güncellenir +
PLAN sabit. Ölçüm makbuzları changelog'a yazılır (ayrı dated dosya değil).
Bu kural artık CI ile zorunlu: scripts/check_docs_sync.sh (build-and-test).
