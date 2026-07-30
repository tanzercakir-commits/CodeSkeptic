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

**alloc-size-overflow kuralı (CWE-131)** — spec `PLAN.md §4`.
Güvenilmez operand + allocator sink + kanıtlı unsigned wrap. Varsayılan
kapalı. RED-önce + yerel kapılar (suite/thesis/corpus) şart.

## Açık kullanıcı kararları

1. **LVGL binfont açıklaması** — kural landing + duplikat/CVE taraması
   SONRASI karar; kanal SECURITY.md (halka açık tracker değil). Şimdi
   HİÇBİR ŞEY bildirilmez.
2. **zlib "core clean" trophy** — kullanıcı GEREK YOK dedi (kapalı).
3. **TF PR #123994** — hâlâ açık; takipte, aksiyon yok.

## Backlog (öncelik sırası)

```
1. alloc-size-overflow kuralı (CWE-131)         ← sıradaki
2. FINDING 3 kalıntısı: alan-özneli assert'ler   (DEBUGASSERT(data->conn) sınıfı)
3. CWE-191 integer underflow ('-' operatörü)
4. CWE-775/404 fd/kaynak sızıntısı genellemesi
5. sign-conversion v2: interprocedural sink (nlohmann'da harm başka fn'deydi)
6. tinyusb untrusted-length makbuzu → changelog'a resmi kayıt (ölçüldü, temiz)
```

## Not — dosya disiplini (2026-07-30 kararı)

Yeni PLAN-*.md AÇMA. Her iş: changelog'a giriş + bu TODO güncellenir +
PLAN sabit. Ölçüm makbuzları changelog'a yazılır (ayrı dated dosya değil).
