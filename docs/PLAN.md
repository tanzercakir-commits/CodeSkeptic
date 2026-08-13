# CodeSkeptic — PLAN (sabit referans, tüm plan)

> Bu belge **sabit kalır**: projenin hedef mimarisi, CWE kapsamı, yol
> haritası ve çalışma protokolü tek yerde. Aktif işler `TODO.md`'de,
> ne yapıldığı `devlog/changelog.md`'de. Ölçüm makbuzları (dated
> `scan-*.md`, `*-campaign.md`) yaz-bir-kez kanıt dosyalarıdır; yeni
> ölçümler changelog'a yazılır, yeni PLAN-*.md AÇILMAZ.

---

## 1. Ne + felsefe

CodeSkeptic: Clang LibTooling tabanlı C/C++ statik analizci.
**Precision-first / "kanıtı göster"** — bir bulgu ancak kanıtlanabildiği
zaman raporlanır; kaçırmak (recall), yanlış alarmdan (precision) iyidir.
Aynı ilke iş akışına da uygulanır (bkz. §5).

Ürün kapsamının bağlayıcı tier sözleşmesi `docs/capabilities.md` ve
`src/core/RuleCapabilities.def` içindedir: `supported` varsayılan açık,
kalite kapılı ve blocking; `experimental` ölçülen/report-only;
`out-of-scope` v1'de bilinçli olarak yapılmaz. CWE sayısı başarı metriği
değildir.

## 2. Mimari

```
Clang LibTooling (AST + Preprocessor)
   └── CFG worklist dataflow (DataflowEngine)
         ├── Interval domain (IntervalAnalysis/Eval) — aralık + untrusted-origin
         ├── PathFacts / guard refinement (refineOnEdge / applyAssertGuard)
         ├── AssertGuards — NDEBUG ile silinen assert'leri PPCallbacks ile kurtarır
         └── AllocFunctions / untrusted-source registry (config'ten beslenir)
   └── Kurallar (her biri kendi sink kararını verir; motor rapor etmez)
   └── Reporter (Console / JSON / SARIF / HTML)
```

Çıktı: bulgular **STDERR**'e; `CodeSkeptic: N finding(s)` / `Clean!`.
Exit 1 = supported/blocking bulgu, 0 = blocking bulgu yok (experimental
bulgular report-only kalabilir), 2 = güvenilir verdict üretilemedi.

## 3. CWE kapsam haritası

**Bulgu üreten aileler (15 CWE eşleşmesi) — support tier'ları için
`docs/capabilities.md`:**

| CWE | Zafiyet | Kural | Juliet floor? |
|---|---|---|:--:|
| 476 | NULL pointer dereference | NullDerefRule | ✓ |
| 690 | kontrolsüz dönüş → null deref | NullDerefRule | ✓ |
| 125 | sınır-dışı okuma | BoundsRule | |
| 787 | sınır-dışı yazma | BoundsRule | |
| 120 | klasik buffer overflow | BoundsRule | |
| 401 | bellek sızıntısı | MemoryLeakRule | ✓ |
| 404 | kaynak sızıntısı (FILE*/DIR*) | MemoryLeakRule (resource-leak) | |
| 415 | double-free | MemoryLeakRule | ✓ |
| 416 | use-after-free | MemoryLeakRule | ✓ |
| 457/824 | başlatılmamış pointer | UninitPointerRule | |
| 190 | integer overflow | IntOverflowRule | ✓ |
| 195 | signed→unsigned dönüşüm | SignConversionRule | |
| 131 | hatalı buffer-boyutu hesabı | AllocSizeOverflowRule | |
| 191 | integer underflow (signed `-`) | IntOverflowRule | |
| 369 | sıfıra bölme | DivByZeroRule | ✓ |

Meta kurallar (CWE-bağımsız): AssumptionRule · ContractRule · PolicyRule.
**Juliet floor** = CI'da recall/precision tabanı zorunlu (7 CWE).

**Planlı / aday:**

| CWE | Zafiyet | Durum |
|---|---|---|
| 775 | file descriptor sızıntısı (int fd: open/socket) | ertelendi — integer-kaynak modeli ister (CWE-404 FILE*/DIR* aktif) |
| 131-64bit | 64-bit size_t çarpım sarması | ertelendi — operand-köşe ispatı (alloc-size v1 sub-64) |

**Bilinçli kapsam-DIŞI:** enjeksiyon/taint ailesi (CWE-89 SQLi, 79 XSS,
78 cmd-inj, 22 path-traversal, 352 CSRF), race detection, otomatik fix,
IDE ürünü ve bulut dashboard. Kaynak→sink taint ile concurrency farklı
motor ister; precision-first v1 hedefi değildir.

## 4. Kural spec'i — alloc-size-overflow (CWE-131, UYGULANDI 2026-07-30)

**Kaynak:** LVGL binfont avı (2026-07-30). Güvenilmez uzunluk
`lv_malloc(sizeof(T) * (n + 1))` boyutunu sarabilir → küçük tampon →
döngüde OOB yazma. Mevcut kuralların hepsi tasarımca kaçırıyor
(IntOverflow signed-only; sign-conversion cast + allocator-hariç; bounds
sabit-extent). nlohmann dersinin bir üst katı.

**Rapor koşulu (hepsi, precision-first):**
1. İşlenenlerden biri bildirilmiş güvenilmez kaynak (dönüş + out-param);
2. sonuç (dolaylı) bir allocator'ın boyut argümanı
   (`isAllocatorCallee` — SignConversionRule'dan paylaşılan header'a taşı);
3. kanıtlı sarma: sonucun ispatlanan aralığı işaretsiz tip sınırını aşıyor
   (sonlu-tanık disiplini, unsigned modülü).

**Precision çıpaları:** guard (`if (n < LIMIT)`) susturur · güvenilmez
değilse sessiz · allocator sink'i BURADA hedeftir (sign-conversion'da
hariçti — ikisi uzayı temiz böler). v1 kapsam dürüstlüğü: yazma-döngüsü
bağı kanıtlanmaz, boyut hesabı sink-farkındalıklı raporlanır.

**Kabul testleri (RED-önce):** `malloc(sizeof(T)*(n+1))` güvenilmez n →
RAPOR · guard'lı → sessiz · signed operand → IntOverflow'un işi · non-
untrusted → sessiz · LVGL loca_count replikası → RAPOR.

**Yürütme:** dal `phase-alloc-size-overflow` ← main · varsayılan KAPALI
(provenans bayrağı gerekir) · push öncesi yerel kapılar (§5).

## 5. Çalışma protokolü

**Bağlayıcı kurallar:**
- `main`'e ASLA doğrudan iş yapılmaz. Her şey `phase-*` dalında.
- `main` GitHub ruleset ile korunuyor: DOĞRUDAN push reddedilir
  (deneyip gördük). Dalın zorunlu kapıları yeşil olmadan merge edilmez;
  ruleset kalite kapısıdır ve gevşetilmez.
- **Sürekli yürütme yetkisi (2026-08-08; kapsamı 2026-08-13'te
  düzeltildi):** kullanıcı, CodeSkeptic çalışma deposundaki push,
  draft/ready PR, ara merge ve release/tag işlemleri için yeniden onay
  bekleme şartını kaldırdı. Her işlemden önce hedef ref/SHA, CI ve kapsam
  yine doğrulanır; bu yetki kalite kapılarını atlama veya `main`e doğrudan
  çalışma izni değildir ve hiçbir upstream işlemi kapsamaz.
- **Upstream ve son teslim onayı (2026-08-13):** upstream issue, PR, yorum,
  fork veya maintainer teması öncesinde aday kullanıcıya sunulur ve hedefe
  özel açık onay beklenir. Varsayılan sunum issue-first'tür; doğrudan PR ayrı
  onay gerektirir. Ürün programı tamamen bittiğinde son `main` merge'i
  öncesinde kullanıcı bilgilendirilir ve açık devam onayı beklenir.
- Yanıtlar **Türkçe**, teknik jargon parantez içinde, plan/şema/tree ile.
- Her zaman dürüst; max efor gerekiyorsa önceden söyle; model düştüğünü
  içeriden teyit EDEMEM — kullanıcının ekranı asıl sinyaldir.

**Döngü (her kod işi):**
```
1. RED-önce test (hatayı gösteren, düşen test) — binary ile de kanıtla
2. Uygula → yeşil
3. Push ÖNCESİ yerel kapılar: full suite + thesis (clean_fp=0) + corpus
4. phase-* dala push → CI 6 hat (build-and-test·juliet·docker·windows·docs×2)
5. Zorunlu kapılar yeşil → exact head/tree doğrula → ara merge'i sürekli yetkiyle tamamla → temizle
   (ürün programının son `main` merge'inde kullanıcı onayını bekle)
6. Her adımı changelog'a yaz; TODO'yu güncelle; PLAN sabit kalır
```

**CI çıktı-okuma tuzağı:** bulgular STDERR'de; `CodeSkeptic: N finding(s)`
satırından say; `[CodeSkeptic]` banner'ları SAYMA.

## 6. Upstream rapor kriterleri (her aday bundan geçer)

Precision-first raporlamaya iki kat: bir kötü rapor, on raporlanmamış
gerçek bug'dan pahalı.

**Gate A — kusur kesinliği (4/4 ZORUNLU):**
1. Mekanizma KAYNAK okuyarak kanıtlı (araç çıktısı yetmez);
2. tetiklenme yolu gerçek (test-only/ölü/config-ardı değil);
3. duplikat YOK (issue + commit + CVE taraması);
4. güncel HEAD hâlâ etkilenmiş (sürüm silinmiş/düzeltilmiş olabilir).

**Gate B — rapor değeri:** kod bakımlı mı (contrib/examples/vendored =
DÜŞÜK) · şiddet tek başına taşır mı · doğru kanal (güvenlik → SECURITY.md,
halka açık tracker değil).

**Gate C — sunum:** repro önce (file:line + minimal akış + "static
dataflow ile bulundu") · 1 issue = 1 kusur · mütevazı fix önerisi.

Varsayılan ilk dış sunum issue'dur; doğrudan upstream PR ancak ayrı kullanıcı
onayıyla açılır. Maintainer'ın kusuru kabul veya teyit ettiği issue vitrin
adayıdır. Phase 9 kabul-fix ledger'ı ise aşağıdaki mevcut ölçütü korur ve
yalnızca upstream'e merge edilmiş düzeltmeleri sayar. Gate A/B/C'yi geçen bir
aday dahi kullanıcıdan hedefe özel upstream onayı alınmadan dışarı gönderilmez.

**Ledger:**
| Aday | Gate A | Sonuç |
|---|---|---|
| TFLite rfft2d/irfft2d leak (#123387/#123994) | 4/4 | DÜZELTİLDİ — PR #123994 merge (`68a7e5821cbb2beb76eeebbbbdffda85a418b254`), issue kapandı (2026-08-07) |
| zlib untgz strcpy/strdup (1.3.1) | 4'te düştü (HEAD'de kod silinmiş) | rapor yok |
| LVGL binfont alloc-size | A: ✓ (mekanizma+HEAD+dup-yok) · B: ✗ | HOLD — LVGL'de threat-model/SECURITY.md yok, font'lar güvenilir sayılıyor; özel kanal yok. Rapor edilmedi (kural için kanıt olarak kalır). |

## 7. Yol haritası — tamamlanan (özet; detay changelog'da)

- Motor: CFG dataflow, interval domain, C3 interproc seed, noreturn/fatal
- AR.1/AR.2/AR.3: canlı-assert pin → define-doktrini çürütüldü →
  kaybolan-assert kurtarma (gate-4 per-variable + compound-body dahil)
- FINDING 2: olumsuz-ad vetosu → nullness sözlüğü + `--negative-assert-macros`
- SignConversionRule (CWE-195) + out-param güvenilmez kaynak modeli
- Park triyajı kapandı: zlib core-clean, LVGL sınıflandırıldı
- Platform: Linux/macOS/Windows CI lane'leri, portable release
- Kalıcı devlog: `devlog/ROADMAP-full.md` (tam günlük) + `changelog.md`

Aktif iş ve açık kararlar → **TODO.md**.
