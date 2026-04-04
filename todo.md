# ZeroDefect — Yapılacaklar ve Notlar

## Bekleyen Görevler

- [x] ~~NullPointerRule~~ → UninitPointerRule ile değiştirildi
- [x] MemoryLeakRule
- [x] main.cpp giriş noktası
- [x] Test altyapısı ve testler (GTest) — 21/21 geçiyor
- [ ] string.h bulunamıyor uyarısı (fallback modunda stdlib path eksik)

## Teknik Notlar (Aklında Tut)

### Severity enum sırası bağımlılığı
`StaticAnalyzer::run()` içindeki severity filtresi (`d.severity < config_.minSeverity()`) enum'un sırasına bağlı: `Info=0, Warning=1, Error=2`. Araya yeni seviye (Hint, Fatal vb.) eklenirse hem `core/Diagnostic.h`'deki enum hem de bu karşılaştırma güncelleneli.

### processAll callback — move güvenliği
`SourceManager::processAll` callback'i kopya alıyor (move değil). Bu sayede `processAll` birden fazla kez çağrılabilir. Bu bilinçli düzeltmeydi.

### FixedCompilationDatabase working directory
Fallback durumunda working directory `"."` olarak ayarlandı (`build_path_` değil). Göreceli path sorunlarını önlemek için.

### JSON string escaping
`JsonReporter` elle JSON yazıyor (harici kütüphane yok). `escapeJson` helper'ı `"`, `\`, `\n`, `\r`, `\t` handle ediyor. İleride nlohmann/json'a geçilebilir.

### LLVM RTTI uyumu
LLVM genelde `-fno-rtti` ile derlenir. CMake'de `LLVM_ENABLE_RTTI` kontrolü var, uyumsuzluk olursa linker hata verir.

### CMake C dili gereksinimi
LLVM'in `check_include_file` macro'su C dili gerektiriyor. `project()` satırında `LANGUAGES C CXX` olmalı — sadece CXX ile configure hata verir.

### StaticAnalyzer sourcePath — dosya vs dizin
`sourcePath` dosya veya dizin olabilir. Constructor'da `std::filesystem::is_directory` ile kontrol ediliyor: dizinse `scanDirectory`, dosyaysa `addSourceFile` çağrılıyor. Bu düzeltme ilk testte keşfedildi.

### MemoryLeakRule — cJSON'da sessiz
cJSON saf C projesi, `new` yok. MemoryLeakRule sadece C++ `new` ifadesini arar (`cxxNewExpr`). C projelerinde doğal olarak sessiz kalır.

### NullPointerRule → UninitPointerRule geçişi
NullPointerRule her `*ptr` dereference'ı yakalıyordu — 68 bulgu, çoğu false positive. Karmaşık filtreler (address-of, null guard, dataflow) yerine tamamen farklı bir yaklaşım seçildi: başlatılmamış pointer tespiti. Basit matcher, sıfır false positive. cJSON'da 47 gerçek bulgu.
