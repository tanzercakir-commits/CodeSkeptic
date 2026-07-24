# Faz 7A — Flow-Through-Calls Fizibilitesi ve İş Planı

> Hazırlayan: 2026-07-24 gecesi, v0.4.7 sonrası (fizibilite turu —
> motor koduna dokunulmadı). Uygulama: taze haftalık kota + max efor
> ister; bu doküman o oturumun sıfır-bağlam giriş kapısıdır.
> Okuyacak oturuma not: önce "Mevcut envanter"i, sonra dilimleri oku;
> ölçüm protokolü ve disiplin kuralları en altta.

## Hedef (tek cümle)

Değer ve durum bilgisinin ÇAĞRI SINIRLARINI geçerken kaybolduğu
belgeli sınıfları kapatmak — bilinen en büyük kaçırılan-hata (false
negative) kütlesi; "insanlara kullanma sebebi" turu.

## Mevcut envanter (ne VAR — yeniden inşa etme!)

| Domain | Dönüş özeti (return summary) | Param tohumlama (seeding) | Geçiş (passthrough) |
|---|---|---|---|
| Null | ✔ Never/MaybeNull + değer-koşullu (#69b nullCond) | ✘ YOK | ✘ YOK |
| Zeroness | ✔ Never/MaybeZero | ✔ (C3 kuralı: internal-linkage + adresi-alınmamış) | ✔ zeroFromParam (v0.4.7) |
| Interval | ✘ YOK | ✔ ParamIntervals (C3) | — |
| Memory | ✔ ParamEffect (Frees/Stores/ReadsOnly) — SADECE leak kuralı tüketiyor | — | — |

Ortak altyapı: SummaryRegistry (TU-içi sweep + cross-TU global store +
v4 disk formatı), ReturnFlowAnalysis şablonu (null+zero mini-flow),
unwrittenParams/resolveZeroReturn (PT hasadı), unwrapZeroPassthrough
(tüketici), buildParamZeroness (tek-hop tohum), ParamIntervals.
C3 sağlamlık kuralı her yerde: yalnız internal-linkage +
adresi-alınmamış çağrılılar; fonksiyon işaretçisi KAPSAM DIŞI (bilinçli).

## Dilimler (değer/risk sırasıyla)

### 7A.1 — Null passthrough (işaretçi kimlik sarmalayıcıları) — ✔ TAMAM (2026-07-24, erken dilim)
`void* keep(void* p) { return p; }` → dönüş nullness'ı argümanınki.
- Mekanizma: zeroFromParam'ın birebir simetriği (nullFromParam);
  hasat resolveZeroReturn'ün null ikizi (genişlik disiplini POINTER'da
  gerekmez — cast'ler null'ı korur; ama integer↔pointer cast BLOKE).
  Tüketici: NullDerefRule'un atama yolu + kopya kapanışı (DivByZero'daki
  unwrap deseninin aynısı).
- Ölçüm: Juliet CWE476 hitrate 0.347 / rhitrate 0.347 taban 0.30;
  libgit2 34 pini (sarmalayıcı-yoğun kod — hem fırsat hem FP riski).
- Risk: DÜŞÜK (kanıtlanmış desenin kopyası). Tahmin: ~%2-3 kota.

### 7A.2 — UAF/double-free için ParamEffect tüketimi
Özet zaten `Frees` biliyor ama SADECE leak kuralı okuyor. `helper(p)`
p'yi serbest bırakıyorsa, çağıran taraftaki sonraki kullanım UAF,
ikinci free double-free — bugün görünmez.
- Mekanizma: NullDeref/UAF durum makinesinde çağrı transferi:
  arg → callee paramEffect(i)==Frees → o disjunct'ta Freed durumu.
  Leak kuralındaki mevcut tüketim deseni şablon.
- Ölçüm: CWE415 rhitrate 0.242 (taban 0.21), CWE416 0.496 (taban
  0.44) — Juliet'in çağrılar-arası free varyantları buradadır.
- Risk: ORTA-YÜKSEK. Tarihsel ders: alias/serbest-bırakma FP aileleri
  (v0.4 escape refinements, freed-through-alias). Her adım çift yönlü
  pinli; libgit2 (custom free: git__free zaten --free-functions'ta)
  ve rtp2httpd pinleri hakem. Tahmin: ~%4-6.

### 7A.3 — Çok-hop param tohumlama (fixpoint)
buildParamZeroness tek hop: A→B tohumlanıyor, B→C'ye taşınmıyor
(CWE369 54-dosyalık dilimin belgeli kalıntısı; fn-pointer hariç).
- Mekanizma: tohum haritasını sabit noktaya kadar yinele (callee'nin
  tohumlanmış paramı, kendi çağrılarına arg olarak akar). ParamIntervals
  için de aynı yineleme (bounds/overflow kazanımı bedava gelir).
- Ölçüm: CWE369 rhitrate 0.108 (taban 0.095) + CWE190 0.052 (taban
  0.040).
- Risk: DÜŞÜK-ORTA (sonlanma: hop sayısı sınırı, örn. 4; MaybeZero
  asla Unknown'dan üretilmez ilkesi aynen). Tahmin: ~%2-3.

### 7A.4 — Dönüş-aralığı özetleri (return intervals)
`int cap(void){ return x & 15; }` → çağıranda [0,15] görünmeli; bugün
top. Bounds + overflow recall'u.
- Mekanizma: SummaryRegistry'ye returnInterval alanı (v5 format);
  hasat: return ifadelerinin evalInterval'ı üzerinden join (mini-flow
  durumuyla); tüketici: evalInterval'ın call dalı.
- Risk: ORTA (widening/yakınsama etkileşimi; Interval'in soundness
  şartı — SADECE kanıtlanabilir sonlu aralık yaz, şüphede top).
  Tahmin: ~%3-5.

### 7A.5 — Alloc-sarmalayıcı çıkarımı (STRETCH — tartışmalı)
Kayıtsız `my_malloc()` sarmalayıcısı bugün BİLİNÇLİ görünmez
(AllocFunctionsTest pini + --alloc-functions config sözleşmesi).
Özetten "taze sahiplik döndürür" bayrağı çıkarmak pini ve config
felsefesini değiştirir → önce KARAR: bu pin bir sınır mı, sözleşme mi?
- Risk: YÜKSEK (FP ailesi + mevcut kullanıcı sözleşmesini bozma).
  Bu turda YAPMA; ayrı tartışma dokümanı aç. Tahmin: —.

## Önerilen paketler

```
7A-core   = 7A.1 + 7A.3          (~%4-6)  düşük risk, iki domain kazanımı
7A-full   = core + 7A.2          (~%8-12) CWE415/416 büyük dilim dahil
7A-stretch= full + 7A.4          (~%11-17) yalnız full sorunsuz biterse
```

Sıra ZORUNLU: 7A.1 → 7A.3 → (tam batarya + realworld) → 7A.2 →
(tam batarya + realworld) → karar → 7A.4. Her dilim kendi commit'i;
her dilim sonrası TAM yerel batarya; 7A.2'den önce ve sonra realworld
lane koşusu ŞART (libgit2 sarmalayıcı-yoğun — FP ailesi ilk orada
görünür).

## Ölçüm protokolü

1. Yerel: 717 test + tez kapısı + self-scan + rtp2httpd (/tmp/rtp
   yoksa realworld lane) her dilim sonrası.
2. Juliet: CI lane JULIET_RESULT satırları; kazanım ölçülürse taban
   AYNI PR'da yükselir (ratchet politikası), ölçülmezse dürüstçe
   "değişmedi" yazılır (v0.4.7 CWE369 örneği emsal).
3. Realworld: libgit2 34 / rtp2httpd 0 pinleri; sapma = adjudikasyon
   (yeni bulgu gerçek mi FP mi — tek tek, kaynak koda karşı).
4. Kapanış: changelog + (sayılar anlamlıysa) v0.4.8.

## Disiplin hatırlatmaları (pahalı derslerden)

- Kanıtsız değişiklik yok: hipotez → yerel repro → fix → çift yönlü pin.
- Bir dilimde 2 başarısız hipotez üst üste → dilimi bırak, sıradakine
  geç, devlog'a not düş (FP turunun 3-hipotez dersi).
- grep -c && zinciri yasak; commit'ten önce checkout deneyi yasak;
  backtick'li commit mesajı -F ile.
- Fonksiyon işaretçisi tartışmaya AÇILMAZ (C3 sağlamlık kuralı).
- MaybeX asla Unknown'dan üretilmez; suppress yalnız kanıtla.

## Go/No-Go

- GO şartı: taze kota ≥ %80 + max efor + bu doküman okunmuş.
- Oturum içi NO-GO: 7A.2 realworld'de adjudike edilemeyen FP ailesi
  çıkarırsa → 7A.2 revert, core ile kapanış (core tek başına da
  yayınlanabilir değer).
