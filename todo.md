# ZeroDefect — Yapılacaklar ve Notlar

## Bekleyen Görevler

- [x] ~~NullPointerRule~~ → UninitPointerRule ile değiştirildi
- [x] MemoryLeakRule
- [x] main.cpp giriş noktası
- [x] Test altyapısı ve testler (GTest) — 21/21 geçiyor
- [x] string.h bulunamıyor uyarısı — çözüldü (resource-dir + isysroot + isystem)

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

### UninitPointerRule_Ex — bilinen sınırlamalar ve ileride yapılacaklar

**CFG cache yok:** Aynı fonksiyonda N uninit pointer varsa, N kez `CFG::buildCFG` çağrılıyor. Büyük fonksiyonlarda gereksiz iş. İleride `FunctionDecl*` → `CFG*` cache'i eklenebilir.

**classifyStmt maliyeti:** Her CFGElement için 5-6 matcher çalıştırılıyor. Küçük fonksiyonlarda sorun değil, 500+ satırlık fonksiyonlarda hissedilir. İleride manuel `dyn_cast` zincirine geçilebilir.

**Compound expression false negative:** `*p = (p = &x, 42)` gibi comma operator pattern'inde `classifyStmt` bunu `Assigns` olarak sınıflandırır çünkü assign matcher önce çalışıyor. Ama `*p` dereference'ı `p = &x` atamasından önce evaluate ediliyor. Pratikte nadir ama bilinmeli.

**id() çakışması:** Eski UninitPointerRule ve yeni UninitPointerRule_Ex ikisi de `"uninit-ptr"` dönüyor. Bilinçli — main.cpp'de sadece biri kayıtlı. Paralel tutulacaksa yeni rule'a `"uninit-ptr-ex"` verilebilir.

### MemoryLeakRule_Ex — bilinen sınırlamalar

**Koşullu double-free kaçırılıyor:** `if(c) delete p; delete p;` durumunda merge `Freed + Allocated = Allocated` döner, sonra ikinci delete Allocated→Freed olur — double-free yakalanmaz. Path-sensitive analiz olmadan çözülemez, bilinen trade-off.

**realloc ikili doğası eksik:** `isAllocExpr` realloc tanıyor ama `classifyStmt`'te `realloc(p, n)` eski p'yi free olarak işlemiyor. `p = realloc(p, n)` sadece Allocates dönüyor (reassignment leak tetiklenmez çünkü state zaten Allocated). Ama `q = realloc(p, n)` durumunda eski p invalid — yakalayamıyoruz.

**Conservative escape:** `foo(p)` çağrısı Escaped olarak işaretleniyor. Eğer foo ownership almıyorsa (sadece okuyorsa) bu false negative. Annotation sistemi (`[[takes_ownership]]`) olmadan çözülemez.

### string.h uyarısı — kök neden ve çözüm
Clang LibTooling kendi compiler instance'ını çalıştırıyor ama sistemdeki stdlib header arama yollarını otomatik bilmiyor. `compile_commands.json`'da explicit `-I` yoksa `string.h` vb. bulunamıyor. Çözüm: `ClangTool::appendArgumentsAdjuster()` ile `-isystem /usr/include` ekleme. `-I` değil `-isystem` kullanılmalı — sistem header uyarılarını bastırır. `BEGIN` pozisyonuna ekle ki kullanıcı flag'leri override edebilsin. macOS'ta path farklı (`/Library/Developer/CommandLineTools/SDKs/...`), platforma göre ayarlanmalı. İkinci adım olarak CMake'ten `clang -print-resource-dir` ile `stddef.h`/`stdarg.h` için resource dir eklenebilir.
