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
base   = a4fc98f
uçuşta = phase-v048-ghcr-legacy-cleanup
```
<!-- cs:state-end -->

Serbest not (insanda kalır): Faz 0 analyzer/release zinciri v0.4.8 olarak
`530e8f2` commitinden yayımlandı; üç platform, Action ve WSL2 kapıları yeşil.
Exact release SHA/tag binding PR #123, eski etiketlere güvenilir tarif desteği
PR #124 ile indi. Korumalı republish `0.4.8` kimliğini doğrulayıp `v0.4.8` ve
`latest` etiketlerini aynı doğru digest'e yayımladı. Yanlış GHCR `v0.4.9`
versiyonu şimdi tek-tag + tam-digest kapılı geçici cleanup ile kaldırılacak;
makbuzdan sonra cleanup adımı da silinecek.

## libarchive değerlendirmesi — KAPANDI (2026-08-01)

Üç precision notu, üçü de kapatıldı: BULGU 2 (sign-conversion non-size
sink kapısı) ve BULGU 1 (bounds struct-hack/FAM kuyruk muafiyeti) kod
olarak indi ve ikisi de **önceden yazılmış tahmine karşı** ölçüldü —
19→14 ve 14→13, ikisinde de delta'nın tamamı niyet edilen sınıf,
kolateral sıfır. BULGU 3 kod değil önkoşul; backlog #1'e işlendi.
Yan ürün: corpus pin'i 53→54 merkeze alındı (895c813'ten beri
sürükleniyordu, toleransın içinde sessizce).

## Sıradaki iş

Bağlayıcı ürün programı sırası: Docker release kimliğini exact tag'e bağla,
CI ile birleştir, v0.4.8 image'ını yeniden yayınla ve yanlış v0.4.9 paket
versiyonunu kaldır. Nihai makbuzla Faz 0'ı kapatıp Faz 1 capability tier
sözleşmesine geç.

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
