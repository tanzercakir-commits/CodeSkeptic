# ZeroDefect — Yapılacaklar ve Notlar

## Sıradaki Görevler (yol haritası: analiz-2026-07.md)

### Faz 1 kalanları
- [ ] UninitPointerRule'u çarpım lattice + dyn_cast desenine taşı
      (MemLeak deseniyle birleştir — değişken başına CFG koşusu kalksın)
- [ ] Fonksiyon başına CFG önbelleği (tüm kurallar paylaşsın)
- [ ] İterasyon tavanını lattice yüksekliğine bağla; sabitlenmeyen
      fonksiyonu raporla (şu an converged=false sessizce kullanılıyor)

### Faz 2
- [ ] SARIF reporter
- [ ] `// zerodefect-disable-line <rule>` bastırma + baseline dosyası
- [ ] NIST Juliet ile precision/recall ölçümü; cJSON/tinyxml2 CI koşusu
- [ ] Yeni kural: use-after-free (Freed state + dereference kontrolü)
- [ ] Yeni kural: null-deref (assume edges üzerine)

### Faz 3 (AI döngüsü)
- [ ] Artımlı mod (yalnızca değişen fonksiyonlar)
- [ ] Bulgulara dataflow izi (LLM'in tüketeceği açıklama formatı)
- [ ] MCP server / JSON-RPC modu

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
Analysis sınıfı `State`, `initialState()`, `merge()`, `transfer()` sağlamalı. `onStatement()` ve `refineOnEdge()` opsiyonel (SFINAE ile `if constexpr`). `DataflowResult` `exitBlockID` içerir — exit block check için CFG rebuild gereksiz.

### Assume edges — kenar konvansiyonu
İki ardıllı terminator'da (if/while/for) `succ[0]` = true dalı, `succ[1]` = false dalı (Clang CFG konvansiyonu). `refineOnEdge` yalnızca `succ_size() == 2` ve `trueSucc != falseSucc` iken çağrılır; switch gibi çok ardıllı terminatorlarda çağrılmaz. Iyileştirme predecessor'ın exit state kopyası üzerinde, merge'den önce yapılır.

### UninitPointerRule_Ex — bilinen sınırlamalar

**CFG cache yok:** Aynı fonksiyonda N uninit pointer → N kez CFG build. İleride cache eklenebilir.

**classifyStmt maliyeti:** Her CFGElement için 5-6 matcher. Büyük fonksiyonlarda yavaşlayabilir, ileride `dyn_cast` zincirine geçilebilir.

**Compound expression false negative:** `*p = (p = &x, 42)` — comma operator'da eval sırası sorunlu. Nadir.

### MemoryLeakRule_Ex — bilinen sınırlamalar

**Koşullu double-free kaçırılıyor:** `if(c) delete p; delete p;` — merge `Freed + Allocated = Allocated`, ikinci delete yakalanmaz. Path-sensitive analiz gerekir.

**realloc ikili doğası eksik:** `q = realloc(p, n)` durumunda eski p invalid — yakalayamıyoruz.

**Conservative escape:** `foo(p)` → Escaped. Ownership almıyorsa false negative. Annotation sistemi gerekir.

### DivByZeroRule — bilinen sınırlamalar

**Guard analizi VAR (2026-07):** `if (z != 0) { x = 1/z; }` artık temiz; `if (z == 0) 1/z` kesin hata. Desteklenen kalıplar: `z`, `!z`, `==`/`!=` (sıfır ve sıfır-olmayan sabit), `>`/`<`/`>=`/`<=` sıfır sabitiyle (ayna halleri dahil), `&&` true dalı, `||` false dalı. Desteklenmeyen: değişken-değişken karşılaştırma (`z != y`), aritmetik içeren koşullar.

**Expression-level constant folding yok:** `a / (b - b)` yakalayamaz. Sadece IntegerLiteral ve basit variable tracking.

**Float division hariç:** IEEE 754'te `1.0/0.0 = inf`, UB değil. Bilinçli karar.

**Compound assignment izlenmiyor:** `z -= z` gibi ifadeler AssignsUnknown bile üretmez (BO_Assign değil) — state eski değerde kalır. Nadir ama yanlış yönde: ileride `CompoundAssignOperator` desteği eklenebilir.

### string.h / header çözümleme — çözüm
`ClangTool::appendArgumentsAdjuster()` ile `-resource-dir` (tüm platformlar), `-isysroot` + `-isystem /usr/include` (yalnızca macOS — `#ifdef __APPLE__`). Linux'ta `/usr/include`'u öne eklemek GCC libstdc++ `include_next` zincirini kırar (stdlib.h bulunamaz), resource-dir orada yeterli. macOS SDK path `xcrun --show-sdk-path` ile, Clang resource dir `clang -print-resource-dir` ile CMake'te bulunuyor.
