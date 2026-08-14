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
- **Upstream ve son teslim onayı (2026-08-13):** ürün programı sürerken her
  aday; tetikleme yolu, CWE, güncel HEAD, duplikat taraması, önem ve taslak
  issue metniyle içeride dosyalanır. Tek tek kullanıcıya sorulmaz ve hiçbir
  upstream issue, PR, yorum, fork veya maintainer teması yapılmaz. Program
  tamamen bittiğinde aday dosyalarının tamamı tek paket halinde kullanıcıya
  sunulur; yalnızca kullanıcının seçtiği hedefler için açık onaydan sonra
  issue-first akışı başlar, doğrudan PR ayrıca onay gerektirir. Son `main`
  merge'i öncesinde de kullanıcı bilgilendirilir ve açık devam onayı beklenir.
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
6. Her adımı changelog'a yaz; TODO/PROGRESS'i jeneratörle doğrula; PLAN sabit kalır
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
yalnızca upstream'e merge edilmiş düzeltmeleri sayar. Gate A/B/C'yi geçen
adaylar program boyunca içeride biriktirilir; kullanıcı tek tek kesilmez.
Program sonundaki toplu incelemede hedefe özel onay alınmayan hiçbir aday
dışarı gönderilmez.

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

Aktif iş → **TODO.md** (aşağıdaki sabit katalogdan otomatik üretilir).

## 8. Sabit v1.0 görev kataloğu

Bu katalog, protected `main` üzerinde henüz kapanmamış Phase 8.3/8.4/9
göç işleri ile Phase 10–12 ürün programının tek görev kaynağıdır. Kimlikler,
sıra, bağımlılıklar, sınırlar ve kabul kapıları sabittir. `TODO.md`, bu
katalogdan protected-main üzerinde henüz kapanmamış görevleri üretir;
`PROGRESS.md` ise legacy prefix sonrasında yalnız protected-main commit
mesajının gerçek final trailer bloğundaki tam biçimli
`Closes-CodeSkeptic-Task: CS-Pxx-yy` kayıtlarını tamamlanma otoritesi sayarak
append-only makbuz üretir. Phase dalları görevi kapatamaz. Yeni çalışma yalnız
`phase-*` dalında yürütülür; doğrudan `main` üzerinde durum üretimi veya
geliştirme reddedilir. Son görevi kapatan protected-main commit'inden sonra,
trailer içermeyen son bir `phase-*` reconciliation dalı TODO'yu boş ve ledger'ı
güncel üretir. V2 ledger sıradan reconciliation commit'lerini kaydetmediği için
bu protokol sonludur.

<!-- cs:work-items-begin -->
```json
{
  "schema": 1,
  "program": "CodeSkeptic measurable v1.0 completion",
  "items": [
    {
      "id": "CS-P08-03",
      "phase": 8,
      "title": "Release-candidate qualification promotion",
      "boundary": "Promote the retained Phase 8.3 qualification only when protected main contains the immutable three-project qualification contract and its complete hosted evidence.",
      "gates": [
        "llama.cpp, TensorFlow Lite, and shadPS4 identities, admitted translation units, toolchains, verdicts, and checksummed receipts match the retained qualification contract.",
        "Every requested surface is complete with zero broken translation units and zero incomplete functions; unavailable attempts remain explicitly unavailable.",
        "The qualifying implementation, focused contracts, full regression, and hosted aggregate are reachable from protected main."
      ],
      "depends_on": []
    },
    {
      "id": "CS-P08-04",
      "phase": 8,
      "title": "Release-candidate factory promotion",
      "boundary": "Promote the retained Phase 8.4 factory only when protected main contains the nine-shard three-project campaign and its accepted aggregate receipt.",
      "gates": [
        "The release-candidate tier plans exactly three repetitions for each of the three qualified projects from one analyzer artifact.",
        "All nine checksummed receipts reproduce the qualified identities and semantics with zero broken units or incomplete functions.",
        "The accepted aggregate identity, checksum, tests, and workflow implementation are reachable from protected main."
      ],
      "depends_on": ["CS-P08-03"]
    },
    {
      "id": "CS-P09-01",
      "phase": 9,
      "title": "Accepted-fix and project target",
      "boundary": "Preserve the incomplete Phase 9 ledger and close it only after at least ten fixes across five independent projects are accepted under the frozen Gate A/B/C contract; no active external target research or upstream action occurs during the product program.",
      "gates": [
        "The append-only validator proves at least ten accepted fixes across at least five independent projects, including merged-change ancestry and every required Gate A/B/C field.",
        "Rejected, duplicate, stale, non-triggerable, and false-positive records remain durable and never count toward completion.",
        "Any remaining candidate review or upstream action occurs only in the owner-controlled end-of-program review with target-specific authorization."
      ],
      "depends_on": ["CS-P08-04"]
    },
    {
      "id": "CS-P10-01",
      "phase": 10,
      "title": "Targeted-scope input validation",
      "boundary": "Function and line scopes fail closed across CLI, project config, and MCP; invalid values never widen analysis and every rejected update preserves prior state atomically.",
      "gates": [
        "Empty and delimiter-only function values are rejected on CLI, config, and MCP surfaces.",
        "Invalid line ranges preserve all previously accepted line state byte-for-byte.",
        "Focused Config/MCP tests, direct single-process suite, full CTest, and negative CLI replay pass."
      ],
      "depends_on": []
    },
    {
      "id": "CS-P10-02",
      "phase": 10,
      "title": "Structured input fuzzing",
      "boundary": "Build deterministic fuzz targets for project configuration, compile-database, strict text summary/model, and MCP JSON-RPC input parsers without expanding analyzer semantics.",
      "gates": [
        "Each named input surface has a bounded reproducible fuzz target and retained seed corpus.",
        "Malformed input fails closed with no crash, hang, partial state commit, or silent scope expansion.",
        "CI smoke fuzzing and a documented extended local campaign pass with checksummed receipts."
      ],
      "depends_on": ["CS-P10-01"]
    },
    {
      "id": "CS-P10-03",
      "phase": 10,
      "title": "Sanitizer runtime matrix",
      "boundary": "Exercise the production analyzer and fuzz targets under ASAN and UBSAN, and under TSAN only when parallel execution exists.",
      "gates": [
        "ASAN and UBSAN build, focused parser corpus, complete unit suite, and representative analyzer runs are clean.",
        "TSAN is either clean on a proven parallel surface or recorded as not applicable with executable evidence that execution is serial.",
        "Sanitizer options, toolchain identity, commands, exits, and logs are retained."
      ],
      "depends_on": ["CS-P10-02"]
    },
    {
      "id": "CS-P10-04",
      "phase": 10,
      "title": "Frontend and CFG stress matrix",
      "boundary": "Stress broken AST recovery, templates, macros, pathological CFGs, and incomplete translation units while preserving explicit verdict availability.",
      "gates": [
        "Broken or skipped requested translation units make the verdict unavailable and return exit 2.",
        "Template, macro, malformed-source, and high-complexity CFG fixtures terminate deterministically without crash or fabricated clean verdict.",
        "Stress corpus identities and expected outcomes are machine-checked in CI."
      ],
      "depends_on": ["CS-P10-03"]
    },
    {
      "id": "CS-P10-05",
      "phase": 10,
      "title": "Per-TU resource budgets",
      "boundary": "Enforce explicit per-translation-unit timeout and memory budgets with deterministic cancellation and honest partial-run reporting.",
      "gates": [
        "Timeout and memory exhaustion are independently triggerable, bounded, and return exit 2 without a clean verdict.",
        "Budget failures identify the exact translation unit and preserve completed-unit receipts without promoting a project verdict.",
        "Default and configurable budgets have regression tests on CLI, config, and MCP entry paths."
      ],
      "depends_on": ["CS-P10-04"]
    },
    {
      "id": "CS-P10-06",
      "phase": 10,
      "title": "Cache correctness and resumable checkpoints",
      "boundary": "Prove cache identity, invalidation, corruption handling, and resumable campaign checkpoints against exact analyzer inputs and outputs.",
      "gates": [
        "Source, compile-command, configuration, rule-set, and analyzer-version changes invalidate every affected cache entry.",
        "Corrupt or incompatible cache/checkpoint data fails closed and cannot manufacture a verdict.",
        "Interrupted campaigns resume without duplicate or omitted requested translation units and reproduce cold-run fingerprints."
      ],
      "depends_on": ["CS-P10-05"]
    },
    {
      "id": "CS-P10-07",
      "phase": 10,
      "title": "Determinism and performance budgets",
      "boundary": "Freeze representative performance baselines and semantic fingerprints for unit, real-repository, and release-candidate workloads.",
      "gates": [
        "Ten of ten identical runs produce identical semantic fingerprints for every gated workload.",
        "No unexplained wall-time, CPU, or peak-memory regression exceeds 10 percent against the pinned baseline.",
        "Every measurement records toolchain, hardware class, inputs, repetitions, statistics, and raw checksummed receipts."
      ],
      "depends_on": ["CS-P10-06"]
    },
    {
      "id": "CS-P10-08",
      "phase": 10,
      "title": "Cumulative quality-floor audit",
      "boundary": "Re-prove v1 default-rule quality and requested-TU truthfulness before the long stability campaign.",
      "gates": [
        "Every analyzable requested translation unit is processed; otherwise the run returns exit 2 and no project verdict.",
        "No default rule precision is below 0.85, total default precision is at least 0.90, and lower-precision rules remain experimental.",
        "Addressable default recall is at least 0.70 and the clean corpus has zero false positives."
      ],
      "depends_on": ["CS-P10-07"]
    },
    {
      "id": "CS-P10-09",
      "phase": 10,
      "title": "Seventy-two-hour stability gate",
      "boundary": "Run the qualified release-candidate matrix continuously for 72 hours using resource budgets, checkpoints, deterministic fingerprints, and sanitizer-supported diagnostics.",
      "gates": [
        "The full 72-hour window completes without analyzer crash or hang.",
        "No unexplained performance regression above 10 percent or semantic fingerprint drift occurs.",
        "All requested-unit coverage, restart, resource, and checksummed campaign receipts validate."
      ],
      "depends_on": ["CS-P10-08"]
    },
    {
      "id": "CS-P11-01",
      "phase": 11,
      "title": "Stable JSON and SARIF contracts",
      "boundary": "Freeze versioned JSON and SARIF output contracts with explicit compatibility, deprecation, and migration policy.",
      "gates": [
        "Canonical schemas, golden outputs, deterministic ordering, and consumer validation pass across supported platforms.",
        "Every allowed additive change and every forbidden breaking change is executable in compatibility tests.",
        "Migration and deprecation windows are documented and schema versions are emitted by the product."
      ],
      "depends_on": ["CS-P10-09"]
    },
    {
      "id": "CS-P11-02",
      "phase": 11,
      "title": "Baseline v2 lifecycle",
      "boundary": "Ship Baseline v2 entries with stable identity, suppression reason, owner-neutral expiry, migration, and deterministic multiset consumption.",
      "gates": [
        "Reason and expiry are schema-validated and expired suppressions fail visibly without hiding findings.",
        "Baseline v1 migration is deterministic, lossless for supported entries, and rejects malformed or ambiguous data.",
        "Line movement, duplicates, path normalization, and package/source parity tests pass."
      ],
      "depends_on": ["CS-P11-01"]
    },
    {
      "id": "CS-P11-03",
      "phase": 11,
      "title": "Governance and maintenance policy",
      "boundary": "Complete security policy, contribution and issue templates, public roadmap, dependency policy, troubleshooting, and supported-use documentation.",
      "gates": [
        "All governance artifacts are present, internally linked, version-consistent, and checked by docs CI.",
        "Supported, experimental, and out-of-scope capabilities match the executable registry.",
        "Disclosure, dependency update, deprecation, and troubleshooting procedures name owners by role and measurable response windows."
      ],
      "depends_on": ["CS-P11-02"]
    },
    {
      "id": "CS-P11-04",
      "phase": 11,
      "title": "SBOM provenance and signing",
      "boundary": "Produce verifiable software bills of materials, build provenance, checksums, and signatures for every distribution channel.",
      "gates": [
        "SBOMs cover direct and packaged runtime dependencies and validate against the release artifact.",
        "Provenance binds source revision, workflow identity, toolchain, inputs, and artifact digest.",
        "Signature verification, tamper rejection, key-rotation procedure, and offline verification are tested."
      ],
      "depends_on": ["CS-P11-03"]
    },
    {
      "id": "CS-P11-05",
      "phase": 11,
      "title": "Offline installation and operation",
      "boundary": "Make documented source and packaged installation, analysis, schema validation, baseline use, and signature verification work without network access.",
      "gates": [
        "A clean offline environment installs each supported artifact using only retained inputs.",
        "Representative CLI and report-only workflows complete without network fallback or undeclared downloads.",
        "Missing offline prerequisites fail with actionable diagnostics and no partial success claim."
      ],
      "depends_on": ["CS-P11-04"]
    },
    {
      "id": "CS-P11-06",
      "phase": 11,
      "title": "Distribution verdict parity",
      "boundary": "Prove source builds and every supported package produce identical verdicts for identical inputs and configuration.",
      "gates": [
        "Source, archive, container, action, and supported platform packages emit identical semantic fingerprints.",
        "Version, rule registry, JSON/SARIF schema, Baseline v2, exit code, and requested-TU behavior are identical.",
        "Parity is reproduced from clean environments with checksummed artifacts and no undeclared network dependency."
      ],
      "depends_on": ["CS-P11-05"]
    },
    {
      "id": "CS-P12-01",
      "phase": 12,
      "title": "Report-only pilot protocol",
      "boundary": "Freeze a privacy-conscious, reproducible 30-day report-only protocol for three independent external projects before any pilot begins.",
      "gates": [
        "Project selection, immutable inputs, cadence, requested-TU coverage, triage, suppression, incident, and withdrawal procedures are fixed.",
        "Blocking is technically disabled throughout the initial report-only period.",
        "Pilot receipts contain only approved product measurements and no external write or maintainer contact occurs without owner authorization."
      ],
      "depends_on": ["CS-P11-06"]
    },
    {
      "id": "CS-P12-02",
      "phase": 12,
      "title": "First thirty-day pilot",
      "boundary": "Operate the first independent project for 30 consecutive days under the frozen report-only protocol.",
      "gates": [
        "Thirty daily windows have valid coverage, fingerprint, crash/hang, performance, triage, and suppression receipts.",
        "Unavailable or missed windows are reported and replayed under the protocol rather than silently counted green.",
        "The project-level pilot report is complete and independently auditable."
      ],
      "depends_on": ["CS-P12-01"]
    },
    {
      "id": "CS-P12-03",
      "phase": 12,
      "title": "Second thirty-day pilot",
      "boundary": "Operate a second independent project for 30 consecutive days under the same report-only protocol.",
      "gates": [
        "Thirty daily windows have valid coverage, fingerprint, crash/hang, performance, triage, and suppression receipts.",
        "Unavailable or missed windows are reported and replayed under the protocol rather than silently counted green.",
        "The project-level pilot report is complete and independently auditable."
      ],
      "depends_on": ["CS-P12-01"]
    },
    {
      "id": "CS-P12-04",
      "phase": 12,
      "title": "Third thirty-day pilot",
      "boundary": "Operate a third independent project for 30 consecutive days under the same report-only protocol.",
      "gates": [
        "Thirty daily windows have valid coverage, fingerprint, crash/hang, performance, triage, and suppression receipts.",
        "Unavailable or missed windows are reported and replayed under the protocol rather than silently counted green.",
        "The project-level pilot report is complete and independently auditable."
      ],
      "depends_on": ["CS-P12-01"]
    },
    {
      "id": "CS-P12-05",
      "phase": 12,
      "title": "Pilot triage and suppression audit",
      "boundary": "Aggregate all three pilots without hiding rejected findings, unavailable runs, suppression costs, or project-specific limitations.",
      "gates": [
        "At least 200 findings are human-triaged with reproducible classification and suppression outcomes.",
        "Precision, recall proxies, time-to-triage, suppression expiry, unavailable-run, and performance measures are reported per project and in aggregate.",
        "All three pilots satisfy the 30-day report-only requirement and retain a complete audit trail."
      ],
      "depends_on": ["CS-P12-02", "CS-P12-03", "CS-P12-04"]
    },
    {
      "id": "CS-P12-06",
      "phase": 12,
      "title": "Optional blocking after a clean week",
      "boundary": "Permit opt-in blocking for a pilot only after seven consecutive clean, fully available report-only days under frozen rules.",
      "gates": [
        "The clean-week counter resets on blocking false positive, unavailable run, semantic drift, crash, hang, or unexplained budget regression.",
        "Blocking remains opt-in, project-scoped, reversible, and defaults to report-only.",
        "Positive and reset paths are end-to-end tested before any pilot enables blocking."
      ],
      "depends_on": ["CS-P12-05"]
    },
    {
      "id": "CS-P12-07",
      "phase": 12,
      "title": "CLI and schema freeze",
      "boundary": "Freeze v1 CLI, exit codes, configuration, MCP surface, JSON/SARIF, Baseline v2, and compatibility policy against breaking changes.",
      "gates": [
        "Golden discovery, help, schema, configuration, MCP, and exit-code contracts pass on every supported platform.",
        "Breaking-change fixtures fail CI and additive changes require explicit version-policy evidence.",
        "Package and source artifacts expose the identical frozen contract."
      ],
      "depends_on": ["CS-P12-06"]
    },
    {
      "id": "CS-P12-08",
      "phase": 12,
      "title": "v1.0 checklist support policy and final audit",
      "boundary": "Close v1.0 only after a requirement-by-requirement audit proves every cumulative product, quality, distribution, pilot, governance, and support gate.",
      "gates": [
        "The v1 checklist maps every Phase 10–12 item to authoritative commands, artifacts, measurements, and independent review evidence.",
        "Cumulative gates prove deterministic 10-of-10 fingerprints, quality floors, zero clean-corpus false positives, 200 triaged findings, five projects and ten accepted fixes, 72-hour stability, distribution parity, and three 30-day pilots.",
        "Support versions, platforms, response windows, deprecation policy, known limitations, rollback, and release procedure are published with no blocking audit finding."
      ],
      "depends_on": ["CS-P09-01", "CS-P12-07"]
    }
  ]
}
```
<!-- cs:work-items-end -->
