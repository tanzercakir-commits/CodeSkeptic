# ZeroDefect — Değişiklik Günlüğü

## 2026-04-05 — DataflowEngine + DivByZeroRule

### Eklenen
- **DataflowEngine** (`src/engine/DataflowEngine.h`): Template-based forward dataflow engine. `Analysis` duck typing ile State, initialState, merge, transfer, onStatement (SFINAE ile opsiyonel) sağlar. CFG build, worklist, predecessor merge, successor propagation — tüm ortak kod tek yerde.
- **DivByZeroRule** (`src/rules/DivByZeroRule.h`, `.cpp`): İki aşamalı sıfıra bölme tespiti. Phase 1: literal `100/0` (RecursiveASTVisitor, CFG'siz). Phase 2: variable divisor CFG dataflow (`ZeroState` lattice). Float division hariç (IEEE 754). 10 test.

### Refactor
- **UninitPointerRule_Ex**: worklist döngüsü kaldırıldı, `runDataflow` + `UninitPtrAnalysis` kullanılıyor.
- **DivByZeroRule**: worklist döngüsü kaldırıldı, `runDataflow` + `DivByZeroAnalysis` kullanılıyor.
- **MemoryLeakRule_Ex**: worklist döngüsü kaldırıldı, `runDataflow` + `MemLeakAnalysis` kullanılıyor. Exit block check engine sonucu üzerinden.

### Test sonuçları
- 41/41 test geçti — davranış değişikliği yok

## 2026-04-05 — DivByZeroRule (eski — merged above)

### Eklenen
- **DivByZeroRule** (`src/rules/DivByZeroRule.h`, `.cpp`): İki aşamalı analiz:
  - Phase 1: Literal sıfıra bölme (CFG'siz, `RecursiveASTVisitor` ile `100/0` pattern)
  - Phase 2: Variable divisor CFG dataflow — `ZeroState` lattice (Unknown/Zero/NonZero/MaybeZero)
- `classifyStmt`: `dyn_cast` ile DeclStmt/BinaryOperator, `evaluateAsZero` ile IntegerLiteral analizi
- `DivFinder` (RecursiveASTVisitor): her Stmt subtree'de `/` ve `%` operatörlerini bulur
- Float division bilinçli olarak dışarıda (IEEE 754: `1.0/0.0 = inf`, UB değil)
- Severity: Error (kesin sıfır), Warning (MaybeZero), rapor yok (Unknown — conservative)
- 10 test: literal div/mod, var zero/nonzero, parameter unknown, conditional maybe, reassign, float, no division

### Test sonuçları
- 41/41 test geçti (14 UninitPtr + 13 MemLeak + 4 Diagnostic + 10 DivByZero)
- cJSON: 0 bulgu, tinyxml2: 0 bulgu (3 kural aktif)

## 2026-04-05 — MemoryLeakRule_Ex (CFG-based leak + double-free)

### Değiştirildi
- **MemoryLeakRule silindi**, yerine **MemoryLeakRule_Ex** eklendi. CFG üzerinde forward dataflow ile:
  - Memory leak tespiti (exit block'ta Allocated state → Warning)
  - Reassignment leak tespiti (p=new; p=new → ilk allocation leaked → Warning)
  - Double-free tespiti (Freed state'te tekrar Free → Error)
  - Conservative escape analizi (return, function param → ownership transfer)
  - C uyumu: malloc/calloc/strdup/free desteği
- **classifyStmt** tamamen yeniden yazıldı: matcher yerine `dyn_cast` zinciri (DeclStmt, BinaryOperator, CXXDeleteExpr, CallExpr, ReturnStmt). Daha hızlı ve doğru.
- 13 test: simple leak, correct usage, conditional leak, both branches delete, return escape, reassignment, malloc/free, function param escape, double-free, array new/delete, no allocation, multiple vars

### Test sonuçları
- 31/31 test geçti (14 UninitPointer_Ex + 13 MemoryLeak_Ex + 4 Diagnostic)
- cJSON: 0 bulgu (leak yok), tinyxml2: 0 bulgu (tüm allocation'lar yönetiliyor)

## 2026-04-05 — MemoryLeakRule genişletme

### Eklenen
- **Matcher 2 — sonradan atama**: `p = new int(42)` pattern'i. `BinaryOperator(=)` ile LHS pointer, RHS cxxNewExpr.
- **Matcher 3 — return raw new**: `return new int(100)` pattern'i. `ReturnStmt` ile cxxNewExpr.
- **5 yeni test**: AssignmentAfterDecl, ReturnRawNew, ReturnNullptr_Clean, MultiplePatterns, AssignMessageContainsVarName.

### Test sonuçları
- 26/26 test geçti (mevcut 6 MemoryLeak testi bozulmadı)

## 2026-04-05 — string.h uyarısı çözümü

### Düzeltilen
- **SourceManager.cpp**: `ClangTool::appendArgumentsAdjuster()` ile üç sistem path eklendi:
  - `-isystem /usr/include` + `-isystem /usr/local/include` (Linux)
  - `-isysroot <SDK_PATH>` (macOS — xcrun ile otomatik bulunur)
  - `-resource-dir <CLANG_DIR>` (stddef.h, stdarg.h gibi intrinsic header'lar)
- **src/CMakeLists.txt**: `clang -print-resource-dir` ve `xcrun --show-sdk-path` ile derleme zamanında path'ler bulunup `#define` olarak aktarılıyor.

### Etki
- `string.h` / `stdlib.h` uyarıları tamamen gitti
- cJSON artık tam parse ediliyor — önceki 47 bulgu (eksik parse kaynaklı) → 1 gerçek bulgu
- 21/21 test hala geçiyor

## 2026-04-05 — NullPointerRule → UninitPointerRule

### Değiştirildi
- **NullPointerRule silindi**, yerine **UninitPointerRule** (`src/rules/UninitPointerRule.h`, `.cpp`) eklendi. Başlatılmamış pointer tespiti — `varDecl(pointerType, unless(hasInitializer), unless(parmVarDecl))`. Basit matcher, sıfır false positive.
- **NullPointerRuleTest silindi**, yerine **UninitPointerRuleTest** (`tests/UninitPointerRuleTest.cpp`) — 11 test: basic uninit, multiple, nullptr/address-of/new/function return clean, parameter ignored, mixed, var name in message, no pointer, location.
- **main.cpp**: `NullPointerRule` → `UninitPointerRule`
- **CMake dosyaları**: dosya adları güncellendi

### Neden?
NullPointerRule her `*ptr` dereference'ı yakalıyordu (cJSON'da 68 bulgu, çoğu false positive). Karmaşık filtreler (address-of, null guard) yerine temelden farklı bir yaklaşım: başlatılmamış pointer tespiti. Matcher kesin, filtre gereksiz.

### Test sonuçları
- 21/21 test geçti (11 UninitPointer + 6 MemoryLeak + 4 Diagnostic)
- cJSON: 47 uninit-ptr bulgusu (hepsi gerçek), 0 memory-leak (C projesi)

## 2026-04-04 — GTest Altyapısı

### Eklenen
- **Test helper** (`tests/TestHelper.h`, `.cpp`): `runRule(rule, code)` — `runToolOnCode` ile string'den AST üretip kuralı çalıştırır. Tüm testlerin ortak boilerplate'i.
- **DiagnosticTest** (`tests/DiagnosticTest.cpp`): 4 test — severityToString, location formatı, severity sıralaması, dosya+satır sıralaması.
- **NullPointerRuleTest** (`tests/NullPointerRuleTest.cpp`): 6 test — basic deref, safe deref (false positive belgeleme), parameter deref, no pointer, multiple deref, location doğrulama.
- **MemoryLeakRuleTest** (`tests/MemoryLeakRuleTest.cpp`): 6 test — raw new int, array, no new, stack alloc, delete still warns, mesajda değişken adı.
- **CMake test desteği**: FetchContent ile GTest v1.14.0, `gtest_discover_tests`.

### Test sonuçları
- 16/16 test geçti (0.84 saniye)

## 2026-04-04 — MemoryLeakRule

### Eklenen
- **MemoryLeakRule** (`src/rules/MemoryLeakRule.h`, `.cpp`): İkinci concrete rule. ASTMatcher ile `varDecl(pointerType, cxxNewExpr)` pattern'i arar. Değişken adını mesaja ekler. `defaultSeverity()` override etmez — base class'ın Warning varsayılanını kullanır.
- **Test dosyaları**: `test_projects/samples/memory_leak.cpp`
- **cJSON test projesi**: `test_projects/cJSON/` — gerçek dünya C projesi, compile_commands.json ile test.

### Test sonuçları
- memory_leak.cpp: 4/4 doğru tespit (raw new single, array, struct, delete sonrası bile)
- cJSON: 68 null-deref bulgusu (pipeline çalışıyor), 0 memory-leak (C projesi, new yok — beklenen)

## 2026-04-04 — NullPointerRule + main.cpp

### Eklenen
- **NullPointerRule** (`src/rules/NullPointerRule.h`, `.cpp`): İlk concrete rule. ASTMatcher ile `*ptr` dereference pattern'i arar, sistem header'larını filtreler. Callback anonymous namespace'de.
- **main.cpp** (`src/main.cpp`): Giriş noktası. Config oku → Analyzer kur → kuralları kaydet → çalıştır → CI/CD exit code.
- **`zerodefect` executable**: CMake'de `add_executable` + `zerodefect_core` link.

### Düzeltilen
- **StaticAnalyzer constructor**: `sourcePath` dosya veya dizin olabilir. `is_directory` kontrolü eklendi — dosyaysa `addSourceFile`, dizinse `scanDirectory`.

## 2026-04-04 — Temel Mimari

### Eklenen
- **Diagnostic** (`src/core/Diagnostic.h`): Bulgu veri yapısı — severity, location, message. Header-only struct, `operator<` ile sıralama, `DiagnosticList` alias.
- **Rule** (`src/core/Rule.h`): Abstract base class — `check(ASTContext&, DiagnosticList&)` pure virtual. `enabled_` private, `defaultSeverity()` virtual (varsayılan Warning).
- **SourceManager** (`src/source_manager/`): Clang LibTooling sarmalayıcı. `compile_commands.json` yükler, fallback olarak `FixedCompilationDatabase`. Callback ile AST teslimi. İç Clang zinciri (Factory→Action→Consumer) anonymous namespace'de.
- **RuleEngine** (`src/engine/`): Kural yöneticisi. `addRule<T>()` variadic template, `runAll()` aktif kuralları çalıştırıp temiz DiagnosticList döner, `enableRule()` id ile aç/kapa.
- **Reporter** (`src/reporter/`): Abstract base + iki concrete: ConsoleReporter (stderr), JsonReporter (dosyaya, escapeJson ile güvenli).
- **Config** (`src/config/`): key=value dosya parser + CLI argüman parser. Whitelist/blacklist kural yönetimi, severity filtresi, `--help` çıktısı.
- **StaticAnalyzer** (`src/analyzer/`): Facade/orkestratör. Config alır, bileşenleri kurar, `run()` ile akış: AST üret → kuralları çalıştır → severity filtrele → sırala → raporla.
- **CMake build sistemi**: LLVM/Clang find_package, `-fno-rtti` uyumu, `zerodefect_core` static library.

### Düzeltilen
- `SourceManager::processAll`: callback `std::move` yerine kopya ile geçiriliyor (tekrar çağrılabilirlik).
- `FixedCompilationDatabase`: working directory `build_path_` yerine `"."` (göreceli path güvenliği).
- CMake: `LANGUAGES CXX` → `LANGUAGES C CXX` (LLVM'in C check macro'su için).
