# ZeroDefect — Yapılacaklar ve Notlar

## Tamamlanan Görevler

- [x] Core mimari (Diagnostic, Rule, SourceManager, RuleEngine, Reporter, Config, StaticAnalyzer)
- [x] UninitPointerRule_Ex (CFG dataflow, 14 test)
- [x] MemoryLeakRule_Ex (CFG dataflow, leak + double-free + escape, 13 test)
- [x] DivByZeroRule (literal + CFG dataflow, 10 test)
- [x] DataflowEngine template (ortak worklist altyapısı, SFINAE onStatement)
- [x] string.h uyarısı çözümü (resource-dir + isysroot + isystem)
- [x] GTest altyapısı (41/41 test)

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
Analysis sınıfı `State`, `initialState()`, `merge()`, `transfer()` sağlamalı. `onStatement()` opsiyonel (SFINAE ile `if constexpr`). `DataflowResult` `exitBlockID` içerir — exit block check için CFG rebuild gereksiz.

### UninitPointerRule_Ex — bilinen sınırlamalar

**CFG cache yok:** Aynı fonksiyonda N uninit pointer → N kez CFG build. İleride cache eklenebilir.

**classifyStmt maliyeti:** Her CFGElement için 5-6 matcher. Büyük fonksiyonlarda yavaşlayabilir, ileride `dyn_cast` zincirine geçilebilir.

**Compound expression false negative:** `*p = (p = &x, 42)` — comma operator'da eval sırası sorunlu. Nadir.

### MemoryLeakRule_Ex — bilinen sınırlamalar

**Koşullu double-free kaçırılıyor:** `if(c) delete p; delete p;` — merge `Freed + Allocated = Allocated`, ikinci delete yakalanmaz. Path-sensitive analiz gerekir.

**realloc ikili doğası eksik:** `q = realloc(p, n)` durumunda eski p invalid — yakalayamıyoruz.

**Conservative escape:** `foo(p)` → Escaped. Ownership almıyorsa false negative. Annotation sistemi gerekir.

### DivByZeroRule — bilinen sınırlamalar

**Guard analizi yok:** `if (z != 0) { x = 1/z; }` — MaybeZero olarak raporlar (false positive). İleride CFG terminator condition analizi eklenebilir.

**Expression-level constant folding yok:** `a / (b - b)` yakalayamaz. Sadece IntegerLiteral ve basit variable tracking.

**Float division hariç:** IEEE 754'te `1.0/0.0 = inf`, UB değil. Bilinçli karar.

### string.h uyarısı — çözüm
`ClangTool::appendArgumentsAdjuster()` ile `-isystem`, `-resource-dir`, `-isysroot`. macOS SDK path `xcrun --show-sdk-path` ile, Clang resource dir `clang -print-resource-dir` ile CMake'te bulunuyor.
