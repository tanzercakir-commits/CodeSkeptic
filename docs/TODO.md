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

**CWE-775/404 fd/kaynak sızıntısı** — MemoryLeakRule genellemesi
(open/fopen/socket → close/fclose eşleşmesi). (CWE-131 ve CWE-191
TAMAMLANDI — changelog 2026-07-30.)

## Açık kullanıcı kararları

1. **LVGL binfont açıklaması** — kural landing + duplikat/CVE taraması
   SONRASI karar; kanal SECURITY.md (halka açık tracker değil). Şimdi
   HİÇBİR ŞEY bildirilmez.
2. **zlib "core clean" trophy** — kullanıcı GEREK YOK dedi (kapalı).
3. **TF PR #123994** — hâlâ açık; takipte, aksiyon yok.

## Backlog (öncelik sırası)

```
1. CWE-775/404 fd/kaynak sızıntısı genellemesi   ← sıradaki (3. CWE)
2. FINDING 3 kalıntısı: alan-özneli assert'ler   (DEBUGASSERT(data->conn) sınıfı)
5. sign-conversion v2: interprocedural sink (nlohmann'da harm başka fn'deydi)
6. tinyusb untrusted-length makbuzu → changelog'a resmi kayıt (ölçüldü, temiz)
```

## Not — dosya disiplini (2026-07-30 kararı)

Yeni PLAN-*.md AÇMA. Her iş: changelog'a giriş + bu TODO güncellenir +
PLAN sabit. Ölçüm makbuzları changelog'a yazılır (ayrı dated dosya değil).
