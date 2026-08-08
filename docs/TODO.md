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
base   = be577ab
uçuşta = phase-precision-debt
```
<!-- cs:state-end -->

Serbest not (insanda kalır): Faz 0, Faz 1, Faz 2 ve Faz 3 KAPANDI. v0.4.8 üç
platform paketi, Action, WSL2 ve Docker kapıları yeşil; public release ve GHCR
`v0.4.8` / `latest` kimlikleri doğru. Yanlış GHCR `v0.4.9` versiyonu tam digest ve
tek-tag kapısıyla kaldırıldı, post-delete current koruması geçti ve tek-
seferlik cleanup kodu silindi. Ürün kapsamı 14 bulgu ailesi için merkezi
registry, schema-v2 capability çıktısı ve docs-sync kapısıyla kilitlendi;
experimental bulgular ölçülür/raporlanır fakat verdict'i engellemez. Ölçüm
laboratuvarı exact base/head temiz-kusurlu-gerçek depo makbuzlarını, `csf1`
semantik bulgu kimliğini, Juliet üç-yollu kaçırma sınıflamasını ve PR kalite /
performance / coverage panosunu fail-closed CI sözleşmesine bağladı. Faz 3,
rtp2httpd'yi 38/38 TU'da 4 uygulanabilir / 0 bağlam FP'ye indirdi ve memory-leak
precision'ını 0.714→0.860'a yükseltti; `memory-leak` artık supported/blocking,
bağımsız örneklemi olmayan `resource-leak` experimental kaldı. Makbuzlar
changelog 2026-08-08 kayıtlarında.

## libarchive değerlendirmesi — KAPANDI (2026-08-01)

Üç precision notu, üçü de kapatıldı: BULGU 2 (sign-conversion non-size
sink kapısı) ve BULGU 1 (bounds struct-hack/FAM kuyruk muafiyeti) kod
olarak indi ve ikisi de **önceden yazılmış tahmine karşı** ölçüldü —
19→14 ve 14→13, ikisinde de delta'nın tamamı niyet edilen sınıf,
kolateral sıfır. BULGU 3 kod değil önkoşul; backlog #1'e işlendi.
Yan ürün: corpus pin'i 53→54 merkeze alındı (895c813'ten beri
sürükleniyordu, toleransın içinde sessizce).

## Sıradaki iş

Bağlayıcı ürün programı sırası: Faz 4 interprocedural motor v2. Return-alias
ilişkileri, parametre precondition/postcondition özetleri, yan etkiler ve
ownership transferi, call-graph SCC sabit noktası, alan duyarlılığı, kontrollü
function-pointer çözümü ve kütüphane model dosyaları küçük dilimler halinde
eklenecek. Her ilişki önce RED testle kanıtlanacak; gerçek korpusta kontrolsüz
bulgu artışı olmayacak.

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
3. sign-conversion v2: interprocedural sink (nlohmann'da harm başka fn'deydi)
```

## Not — dosya disiplini (2026-07-30 kararı)

Yeni PLAN-*.md AÇMA. Her iş: changelog'a giriş + bu TODO güncellenir +
PLAN sabit. Ölçüm makbuzları changelog'a yazılır (ayrı dated dosya değil).
Bu kural artık CI ile zorunlu: scripts/check_docs_sync.sh (build-and-test).
