# CodeSkeptic — TODO (aktif işler + açık kararlar)

> Bu belge canlı: sıradaki iş, öncelikler, kullanıcı kararları burada.
> Tamamlanan işler changelog'a taşınır ve buradan silinir. Sabit plan
> ve tüm yol haritası → `PLAN.md`.

## Şu anki durum

```
main = 3ae3ecb  (FINDING 2 dahil; kilitli)
Uçuşta: phase-triage-close + phase-binfont-hunt (doc-only, CI'da)
        → bu doc-konsolidasyon dalı ikisinin superset'i olacak
```

## Sıradaki iş (kod)

**Üç hedef CWE TAMAMLANDI** (131 alloc-size · 191 underflow · 404
resource-leak — changelog 2026-07-30). Sıradaki: aşağıdaki backlog'dan
kullanıcı seçer. En doğal aday sign-conversion/alloc-size v2
(interprocedural sink + 64-bit köşe ispatı) veya FINDING 3 kalıntısı.

## Açık kullanıcı kararları

1. **LVGL binfont açıklaması** — kural landing + duplikat/CVE taraması
   SONRASI karar; kanal SECURITY.md (halka açık tracker değil). Şimdi
   HİÇBİR ŞEY bildirilmez.
2. **zlib "core clean" trophy** — kullanıcı GEREK YOK dedi (kapalı).
3. **TF PR #123994** — hâlâ açık; takipte, aksiyon yok.

## Backlog (öncelik sırası)

```
1. CWE-775 strict (int fd: open/socket) — integer-kaynak modeli
2. alloc-size v2: 64-bit size_t çarpım köşe-ispatı
3. FINDING 3 kalıntısı: alan-özneli assert'ler   (DEBUGASSERT(data->conn) sınıfı)
5. sign-conversion v2: interprocedural sink (nlohmann'da harm başka fn'deydi)
6. tinyusb untrusted-length makbuzu → changelog'a resmi kayıt (ölçüldü, temiz)
```

## Not — dosya disiplini (2026-07-30 kararı)

Yeni PLAN-*.md AÇMA. Her iş: changelog'a giriş + bu TODO güncellenir +
PLAN sabit. Ölçüm makbuzları changelog'a yazılır (ayrı dated dosya değil).
Bu kural artık CI ile zorunlu: scripts/check_docs_sync.sh (build-and-test).
