# ZeroDefect — Değişiklik Günlüğü

## 2026-07-09 — Beşinci kural: NullDerefRule

### Eklenen
- **NullDerefRule** (`src/rules/NullDerefRule.h/.cpp`): CFG dataflow ile
  null pointer dereference tespiti. `NullState` lattice (Unknown / Null /
  NonNull / MaybeNull); `nullptr`, `NULL`, `0` literal akışı; `&x`, `new`,
  string literal → NonNull; `&p` escape → Unknown (muhafazakâr).
  Dal koşulu iyileştirmesi: `p`, `!p`, `==`/`!=` nullptr (her iki yön),
  `&&` true / `||` false kısa devre. Kesin null deref → Error, olası →
  Warning. Bilinmeyen değerler sessiz — parametre dereference'i rapor
  ÜRETMEZ (eski NullPointerRule'un 68-FP tuzağı).
- 16 test: kesin/olası deref, `->` ve `[]`, guard desenleri (truthiness,
  erken dönüş, `== nullptr` doğru dalında kesin hata, `&&` zinciri,
  while-loop çıkışında null), muhafazakârlık testleri (parametre, opak
  dönüş, out-param escape).

### Doğrulama
- 92/92 test geçti
- Gerçekçi desen dosyası: for-döngüsü guard'ı, erken dönüş, `!= nullptr
  &&` zinciri, opak `find()` → sıfır FP; kasıtlı 2 hata → 2 doğru bulgu

## 2026-07-09 — Faz 2 devam: use-after-free + baseline

### Eklenen
- **Use-after-free tespiti**: MemLeakAnalysis'e `onStatement` hook'u —
  Freed durumdaki pointer'ın dereference'i (`*p`, `p->`, `p[i]`, tepe-düğüm
  tespiti) `use-after-free` rule_id'siyle Error üretir. Var olan Freed
  state'i yeniden kullanır; ek dataflow koşusu yok. 5 test.
- **Baseline desteği** (`src/analyzer/Baseline.h/.cpp`):
  `--write-baseline <dosya>` mevcut bulguları kaydeder ve temiz çıkar
  (CI'da baseline üretimi); `--baseline <dosya>` bilinen bulguları
  filtreler, yalnızca YENİ bulgular raporlanır. Anahtar:
  `rule|file|line|message` (satır kayması v1 sınırlaması — dokümante).
  Config anahtarı: `baseline=`. 4 test.

### Test sonuçları
- 75/75 test geçti (66 + 5 UAF + 4 baseline)
- Uçtan uca: UAF yakalanıyor; write-baseline → exit 0; baseline ile
  ikinci koşu temiz

## 2026-07-09 — Faz 2 başlangıcı: SARIF + suppression

### Eklenen
- **SarifReporter** (`src/reporter/SarifReporter.h/.cpp`): SARIF 2.1.0
  çıktı — GitHub code scanning ile doğrudan entegrasyon. `--sarif <dosya>`
  CLI seçeneği ve `sarif_output=` config anahtarı. Severity eşlemesi:
  Error→error, Warning→warning, Info→note. Mutlak path'ler `file://` URI.
  5 test; çıktı `json.load` ile doğrulandı.
- **SuppressionFilter** (`src/analyzer/SuppressionFilter.h/.cpp`): kaynak
  yorumlarıyla bulgu bastırma. `// zerodefect-disable-line [kural,listesi]`
  ve `// zerodefect-disable-next-line [...]`. Çıplak marker tüm kuralları,
  kural listesi yalnızca sayılanları bastırır. Bastırılan sayı stderr'e
  raporlanır. Dosya içeriği önbellekli okunur. 9 test.
- **MsgId::OutputFileOpenError / SuppressedCount** — i18n'den kaçmış
  JsonReporter Türkçe mesajı da düzeltildi.

### Test sonuçları
- 66/66 test geçti (52 + 5 SARIF + 9 suppression)
- Uçtan uca: suppression yorumu bulguyu düşürüyor, SARIF geçerli JSON

## 2026-07-08 (gece) — Faz 1 kalanları: çekirdek birleştirme

### Değiştirildi
- **DataflowEngine CFG granülerliği**: `BuildOptions::setAllAlwaysAdd()` —
  alt ifadeler de değerlendirme sırasında birer CFG elemanı (CSA ile aynı).
  Analizler artık her elemanın yalnızca tepe düğümüne bakıyor; statement
  içinde nested arama (findAll matcher) tamamen gereksizleşti.
- **UninitPointerRule_Ex tamamen yeniden yazıldı**: değişken başına ayrı
  CFG build + dataflow koşusu + statement başına 5-6 matcher yerine, tüm
  izlenen pointerlar tek çarpım lattice'inde (`map<VarDecl*, PtrState>`)
  tek koşuda. Sınıflandırma tepe-düğüm `dyn_cast` — düğüm hangi değişkene
  dokunduğunu kendisi söylediği için değişken başına döngü de yok (O(1)
  eleman başına). Davranış birebir korundu (14/14 test).
- **İterasyon tavanı lattice yüksekliğine bağlandı**: opsiyonel
  `latticeHeight()` hook'u (SFINAE); `maxIterations = numBlocks × (height+2)`.
  Üç analiz de yüksekliğini bildiriyor (değişken sayısı × zincir uzunluğu).
  Bildirmeyen analizler için eski varsayılan korunuyor.

### Test sonuçları
- 52/52 test geçti; demo bulguları birebir aynı (davranış değişikliği yok)

## 2026-07-08 — Faz 0 (public hazırlık) + assume edges

### Düzeltilen
- **Linux header çözümleme hatası**: koşulsuz `-isystem /usr/include` GCC
  libstdc++'ın `include_next` zincirini kırıyordu (`stdlib.h` bulunamıyor,
  analiz kısmi AST ile sessizce devam ediyordu). Artık `#ifdef __APPLE__`
  ile yalnızca macOS'ta ekleniyor. Doğrulama: `<cstdlib>` içeren demo
  dosyasında daha önce kaçan double-free artık yakalanıyor.
- **CMake taşınabilirliği**: Homebrew `CMAKE_PREFIX_PATH` varsayılanı
  yalnızca `APPLE` altında. Linux'ta sistem LLVM'i otomatik bulunuyor.
- **Çapraz-TU mükerrer bulgu**: `Diagnostic::operator==` + `operator<`
  tüm alanlarla deterministik; `StaticAnalyzer::run` sıralama sonrası
  `std::unique` ile tekilleştiriyor.

### Eklenen
- **Assume edges (dal koşulu iyileştirmesi)**: `DataflowEngine`'e opsiyonel
  `refineOnEdge(cond, isTrueBranch, State&, ASTContext&)` hook'u (SFINAE).
  İki ardıllı terminator'larda (if/while/for) predecessor state'i true/false
  kenarına göre iyileştirilip öyle merge ediliyor.
- **DivByZeroRule guard analizi**: `z != 0`, `z == 0`, `z`, `!z`, `z > 0`
  (+ ayna halleri `0 < z`), `>=`/`<=` false dalları, `&&`/`||` kısa devre
  kuralları. Bilinen guard FP'si çözüldü; `if (z == 0) 1/z` artık kesin
  hata olarak yakalanıyor. 9 yeni test.
- **DivByZero merge düzeltmesi**: `Zero + Unknown = MaybeZero` (eskiden
  Unknown'a düşüp susuyordu). `int d = 0; if (z > 0) d = z; 100/d`
  artık uyarı veriyor. Yalnızca `NonZero + Unknown` bilgisizliğe düşer.
- **i18n**: `core/Messages` modülü (MsgId tablosu EN/TR, `{0}`/`{1}`
  yer tutucu). Varsayılan İngilizce; `--lang tr` CLI seçeneği ve `lang=`
  config anahtarı. Tüm kural mesajları, reporter ve CLI çıktıları taşındı.
- **GitHub Actions CI**: Ubuntu 24.04 + LLVM 18, build + ctest + exit-code
  smoke testi (`.github/workflows/ci.yml`).
- **README** (İngilizce, mimari + build + kullanım) ve **LICENSE**
  (Apache-2.0).

### Test sonuçları
- 52/52 test geçti (41 mevcut + 1 dedup + 1 i18n + 9 assume-edge)
- Linux (Ubuntu 24.04, LLVM 18.1.3) üzerinde tam doğrulama

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
