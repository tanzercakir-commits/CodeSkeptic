# ZeroDefect — Yapılacaklar ve Notlar

## Sıradaki Görevler (yol haritası: analiz-2026-07.md)

### Faz 1 kalanları
- [ ] Fonksiyon başına CFG önbelleği — kurallar arası paylaşım (şu an her
      kural kendi CFG'sini kuruyor; fonksiyon başına 3 build). Kurallara
      ortak bir analiz bağlamı geçirmek gerekir — mimari karar.
- [ ] converged=false durumunu görünür yap (Info diagnostic veya stderr) —
      yükseklik-tabanlı tavanla artık pratikte imkânsız ama sessiz kalmasın
- [ ] MemoryLeakRule transfer'ını da tepe-düğüm Effect desenine taşı
      (değişken başına classify döngüsü kalksın — UninitPtr'daki gibi)

### Faz 2 kalanları
- [ ] NIST Juliet ile precision/recall ölçümü (indirme ~120MB — CI'da veya
      yerelde koşacak ayrı harness; korpus scripti şablon olarak kullanılabilir)
- [ ] Korpus bulgu sayılarını sabitle (beklenen sayı dosyası + tolerans) —
      önce birkaç CI koşusuyla sayıların kararlılığını gözle
- [ ] Baseline v2: satır-bağımsız anahtar (mesaj + bağlam hash'i)

### Kural iyileştirme notları
- NullDeref: çoklu bildirim (`int *a = nullptr, *b = nullptr;`) yalnızca
  ilk pointer'ı işler — kalanlar Unknown başlar (bilinen FN, nadir).
  Effect'i çoklu sonuç dönecek şekilde genişletilebilir.
- NullDeref + DivByZero applyCondition yapısal olarak benzer — ortak
  "koşul yürüyüşü" yardımcıya çıkarılabilir (iki domain, tek iskelet).

### Faz 3 (AI döngüsü)
- [x] Artımlı analiz primitifi: --function filtresi + analyze_diff.sh
- [x] Artımlı v2: --lines aralıkları + hunk ayrıştırma (tam otomatik
      "yalnızca dokunulan fonksiyonları analiz et" döngüsü)
- [x] Bulgulara dataflow izi (TraceNote; konsol/JSON/SARIF relatedLocations)
- [x] MCP server modu (--serve; initialize / tools/list / tools/call analyze)
- [ ] İz v2: guard/refine olayları da eklensin (kenar olayları onStatement'ta
      görünmüyor — motor desteği gerekir)
- [ ] MCP v2: sıcak süreçte AST/derleme önbelleği (şu an her çağrı yeniden
      parse ediyor — kalıcı sürecin asıl hız kazancı burada)

### Faz 4 (araştırma ufku — sıradaki büyük hedef)
- [ ] İnterprosedürel analiz v1: fonksiyon özetleri — dönüş nullability'si,
      parametre sahipliği (free eder mi / saklar mı / sadece okur mu).
      Çağrı grafiği üzerinde aşağıdan yukarı geçiş; MemLeak'in Escaped
      muhafazakârlığını ve NullDeref'in opak-dönüş sessizliğini gerçek
      bilgiye çevirir.
- [ ] Özet önbelleği (TU başına; artımlı modda yalnızca değişen
      fonksiyonların özetleri tazelenir)

## Tamamlanan Görevler

- [x] Core mimari (Diagnostic, Rule, SourceManager, RuleEngine, Reporter, Config, StaticAnalyzer)
- [x] UninitPointerRule_Ex (CFG dataflow, 14 test)
- [x] MemoryLeakRule_Ex (CFG dataflow, leak + double-free + escape, 13 test)
- [x] DivByZeroRule (literal + CFG dataflow, 10 test)
- [x] DataflowEngine template (ortak worklist altyapısı, SFINAE onStatement)
- [x] string.h uyarısı çözümü (resource-dir + isysroot + isystem)
- [x] GTest altyapısı (41/41 test)
- [x] Durum tespiti + yol haritası dokümanı (analiz-2026-07.md)
- [x] Linux header çözümleme düzeltmesi (isystem yalnızca macOS)
- [x] CMake taşınabilirlik (Homebrew prefix yalnızca APPLE)
- [x] Çapraz-TU bulgu tekilleştirme (operator== + std::unique)
- [x] i18n: EN varsayılan + --lang tr (core/Messages)
- [x] Assume edges: DataflowEngine refineOnEdge + DivByZero guard analizi (9 test)
- [x] DivByZero merge düzeltmesi (Zero + Unknown = MaybeZero)
- [x] GitHub Actions CI (Ubuntu 24.04 + LLVM 18)
- [x] README (EN) + LICENSE (Apache-2.0)
- [x] GTest 52/52
- [x] CFG granülerliği: setAllAlwaysAdd (alt ifadeler eleman — CSA paritesi)
- [x] UninitPointerRule çarpım lattice + tepe-düğüm dyn_cast (tek koşu)
- [x] İterasyon tavanı lattice yüksekliğine bağlandı (latticeHeight hook)
- [x] SARIF 2.1.0 reporter (--sarif, sarif_output=)
- [x] Suppression yorumları (disable-line / disable-next-line, kural listesi)
- [x] Use-after-free tespiti (MemLeak Freed state + dereference)
- [x] Baseline desteği (--write-baseline / --baseline)
- [x] NullDerefRule (NullState lattice + assume edges, 16 test)
- [x] GTest 92/92
- [x] Gerçek dünya korpusu CI'da (cJSON + tinyxml2, scripts/run_corpus.sh)
- [x] Motor: fixpoint sonrası raporlama geçişi (erken-state severity hatası)
- [x] Path kanonikleştirme + makro expansion loc (korpus bulguları)
- [x] Best/worst-case stress süiti (17 test; belgelenmiş FN'ler dahil)
- [x] MemLeak null-farkındalıklı refineOnEdge (malloc-başarısızlık FP'si)
- [x] DivByZero onStatement tepe-düğüm sınıflandırması (ternary FP'si)
- [x] GTest 110/110

## Teknik Notlar (Aklında Tut)

### Severity enum sırası bağımlılığı
`StaticAnalyzer::run()` içindeki severity filtresi (`d.severity < config_.minSeverity()`) enum'un sırasına bağlı: `Info=0, Warning=1, Error=2`. Araya yeni seviye eklenirse hem `core/Diagnostic.h`'deki enum hem de bu karşılaştırma güncelleneli.

### processAll callback — move güvenliği
`SourceManager::processAll` callback'i kopya alıyor (move değil). Birden fazla kez çağrılabilir.

### FixedCompilationDatabase working directory
Fallback durumunda `"."` olarak ayarlandı (`build_path_` değil).

### JSON string escaping
`JsonReporter` elle JSON yazıyor. `escapeJson` helper'ı `"`, `\`, `\n`, `\r`, `\t` handle ediyor. İleride nlohmann/json'a geçilebilir.

### LLVM RTTI uyumu
LLVM `-fno-rtti` ile derlenir. CMake'de `LLVM_ENABLE_RTTI` kontrolü var.

### CMake C dili gereksinimi
`project()` satırında `LANGUAGES C CXX` olmalı — LLVM'in `check_include_file` macro'su C gerektiriyor.

### StaticAnalyzer sourcePath — dosya vs dizin
`is_directory` ile kontrol ediliyor: dizinse `scanDirectory`, dosyaysa `addSourceFile`.

### DataflowEngine — Analysis duck typing
Analysis sınıfı `State`, `initialState()`, `merge()`, `transfer()` sağlamalı. `onStatement()`, `refineOnEdge()` ve `latticeHeight()` opsiyonel (SFINAE ile `if constexpr`). `DataflowResult` `exitBlockID` içerir — exit block check için CFG rebuild gereksiz.

### Motor sözleşmesi — transfer saf, raporlama fixpoint'te
`transfer()` SAF olmalı (yalnızca state döndürür, yan etki üretmez) — worklist fazında defalarca çağrılır. Raporlama `onStatement()` içinde yapılır; motor onu yalnızca fixpoint SONRASI raporlama geçişinde çağırır. Erken state ile rapor üretmek yanlış severity verir (cJSON parse_array vakası, 2026-07-09).

### CFG granülerliği — setAllAlwaysAdd
Motor CFG'yi `setAllAlwaysAdd` ile kurar: alt ifadeler değerlendirme sırasında ayrı elemanlardır (DumpCFG'deki gibi). Analizler her elemanın YALNIZCA tepe düğümüne bakmalı; findAll/descendant araması hem gereksiz hem mükerrer tetikler (aynı ifade hem kendi elemanı hem üst statement elemanı içinde görünür — rapor dedup'ları bu yüzden var).

### Assume edges — kenar konvansiyonu
İki ardıllı terminator'da (if/while/for) `succ[0]` = true dalı, `succ[1]` = false dalı (Clang CFG konvansiyonu). `refineOnEdge` yalnızca `succ_size() == 2` ve `trueSucc != falseSucc` iken çağrılır; switch gibi çok ardıllı terminatorlarda çağrılmaz. Iyileştirme predecessor'ın exit state kopyası üzerinde, merge'den önce yapılır.

### UninitPointerRule_Ex — bilinen sınırlamalar

**ÇÖZÜLDÜ (2026-07): CFG cache / classify maliyeti.** Artık fonksiyon başına tek CFG + tek dataflow koşusu (çarpım lattice); classify tepe-düğüm `dyn_cast`, eleman başına O(1). `setAllAlwaysAdd` ile alt ifadeler kendi elemanları olduğundan nested arama gerekmez.

**Compound expression false negative:** `*p = (p = &x, 42)` — comma operator'da eval sırası sorunlu. Nadir.

### MemoryLeakRule_Ex — bilinen sınırlamalar

**Koşullu double-free kaçırılıyor:** `if(c) delete p; delete p;` — merge `Freed + Allocated = Allocated`, ikinci delete yakalanmaz. Path-sensitive analiz gerekir. (Test olarak sabitlendi: `DocumentedLimitTest.ConditionalDoubleFree_KnownFN`)

**Null-farkındalık VAR (2026-07):** `p = malloc(); if (!p) return;` yolu artık leak DEĞİL — refineOnEdge null kenarında Allocated → None yapar.

**realloc ikili doğası eksik:** `q = realloc(p, n)` durumunda eski p invalid — yakalayamıyoruz.

**Conservative escape:** `foo(p)` → Escaped. Ownership almıyorsa false negative. Annotation sistemi gerekir.

### DivByZeroRule — bilinen sınırlamalar

**Guard analizi VAR (2026-07):** `if (z != 0) { x = 1/z; }` artık temiz; `if (z == 0) 1/z` kesin hata. Desteklenen kalıplar: `z`, `!z`, `==`/`!=` (sıfır ve sıfır-olmayan sabit), `>`/`<`/`>=`/`<=` sıfır sabitiyle (ayna halleri dahil), `&&` true dalı, `||` false dalı. Desteklenmeyen: değişken-değişken karşılaştırma (`z != y`), aritmetik içeren koşullar.

**Expression-level constant folding yok:** `a / (b - b)` yakalayamaz. Sadece IntegerLiteral ve basit variable tracking.

**Float division hariç:** IEEE 754'te `1.0/0.0 = inf`, UB değil. Bilinçli karar.

**Compound assignment izlenmiyor:** `z -= z` gibi ifadeler AssignsUnknown bile üretmez (BO_Assign değil) — state eski değerde kalır. Nadir ama yanlış yönde: ileride `CompoundAssignOperator` desteği eklenebilir.

### string.h / header çözümleme — çözüm
`ClangTool::appendArgumentsAdjuster()` ile `-resource-dir` (tüm platformlar), `-isysroot` + `-isystem /usr/include` (yalnızca macOS — `#ifdef __APPLE__`). Linux'ta `/usr/include`'u öne eklemek GCC libstdc++ `include_next` zincirini kırar (stdlib.h bulunamaz), resource-dir orada yeterli. macOS SDK path `xcrun --show-sdk-path` ile, Clang resource dir `clang -print-resource-dir` ile CMake'te bulunuyor.
