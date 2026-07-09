# ZeroDefect — Değişiklik Günlüğü

## 2026-07-09 — Faz 4 açılışı: interprosedürel analiz v1 (fonksiyon özetleri)

### Eklenen
- **SummaryRegistry** (`engine/FunctionSummary.h/.cpp`): TU başına, kural
  koşularından ÖNCE tüm gövdeli fonksiyonlar özetlenir; TU bitince tablo
  temizlenir (TU-yerel `FunctionDecl*` anahtarları sarkmasın).
  - **Dönüş nullness'i:** NeverNull (tüm yollar kesin non-null) /
    MaybeNull (bir yol null literal dönebilir) / Unknown. Literal, `new`,
    `&x`, string ve çağrı zinciriyle; değişken dönüşü Unknown (v1 sınırı).
  - **Parametre etkileri:** Frees / ReadsOnly / Stores / Opaque.
    Alias'a bilinçli kör: parametrenin herhangi bir şeye atanması Stores
    (cJSON_Delete'in `q=p; free(q)` kalıbı v2'ye kadar Escaped kalır).
  - **Sabit-nokta taraması** (≤5 tur, her tur sıfırdan): zincirler çözülür
    (w2→w1→free), rekursiyon güçlü iddia üretemez (Unknown/Opaque başlar).
- **NullDeref tüketimi:** `p = f()` — özet MaybeNull ise korumasız
  dereference **uyarı** (guard'lı kullanım assume-edge ile temiz);
  NeverNull zinciri sessiz. Yeni iz mesajı: "possibly-null value here
  (callee may return null)".
- **MemLeak tüketimi:** çağrı sınıflandırması özete bakar —
  free-wrapper'lar (guard'lı `if(p) free(p)` dahil) **Frees** sayılır →
  wrapper üzerinden double-free ve use-after-free artık yakalanıyor;
  salt-okur yardımcılar etkisiz → arkalarındaki **leak görünür oldu**;
  saklayan/opak çağrılar Escaped (regresyon yok).
- Güvenlik hijyeni: `getName()` yerine `getIdentifier()` deseni
  (operator overload'larında tanımsız davranış riski).

### Doğrulama
- 148/148 test (133 + 15 interprosedürel: zincirler, rekursiyon,
  karşılıklı rekursiyon, alias muhafazakârlığı, dış fonksiyon regresyonu)
- Uçtan uca demo: 3 yeni tespit sınıfı (wrapper-UAF izli, olası-null
  dönüş izli, salt-okur arkası leak) + savunmacı kod tamamen temiz

## 2026-07-09 — Faz 3 tamam: MCP server modu

### Eklenen
- **`--serve`** (`src/server/McpServer`): MCP (Model Context Protocol)
  sunucusu — stdio üzerinden satır-ayrımlı JSON-RPC 2.0. Claude Code
  gibi ajanlar süreci başlatıp her düzenleme sonrası `analyze` aracını
  çağırır; bulgular dataflow izleriyle yapısal JSON döner.
- Metodlar: `initialize`, `notifications/*` (yanıtsız), `ping`,
  `tools/list`, `tools/call` (`analyze`: `path` + opsiyonel
  `build_path`/`functions`/`lines` — artımlı kapsam MCP'den de
  kullanılabilir).
- JSON için yeni bağımlılık YOK: zaten link edilen LLVMSupport'un
  `llvm/json` kütüphanesi kullanıldı.
- `handleMcpMessage()` I/O'dan ayrık — 10 birim testle protokol
  davranışı sabitlendi (hata kodları -32700/-32601/-32602 dahil).
- Config: `--serve` bayrağı; `addFunctions`/`addLines` public
  (programatik kapsam).

### Doğrulama
- 133/133 test (123 + 10 MCP)
- Uçtan uca gerçek istemci akışı: initialize → initialized bildirimi →
  analyze çağrısı → count/findings/trace'li yapısal yanıt

## 2026-07-09 — Artımlı v2: hunk → fonksiyon eşlemesi

### Eklenen
- **`--lines <N-M,K>`**: yalnızca verilen satır aralıklarıyla kesişen
  fonksiyonlar analiz edilir. Aralıklar analiz edilen ANA dosyaya
  uygulanır (header'daki fonksiyonlar kapsam dışı — diff hunk'ları zaten
  ana dosyaya aittir). `--function` ile birlikte AND semantiği.
- **analyze_diff.sh v2**: `git diff -U0` hunk başlıklarından
  (`+başlangıç,adet`) değişen satır aralıklarını çıkarıp dosya başına
  `--lines` geçirir. Salt-silme hunk'larında (adet 0) ekleme noktası
  satırı alınır. Sonuç: *LLM fonksiyonu değiştirir → script diff'ten
  aralıkları çıkarır → yalnızca dokunulan fonksiyonlar yeniden analiz
  edilir* — tam otomatik artımlı döngü.
- İş bölümü ilkesi: git mantığı script'te, AST mantığı araçta.

### Doğrulama
- 123/123 test (119 + 4 satır filtresi: imza satırı kesişmesi, boş
  aralık, kapsam dışı aralık)
- Uçtan uca: iki hatalı fonksiyonlu dosyada yalnızca birine dokunuldu →
  script `--lines 8-8` üretti → yalnızca dokunulan fonksiyonun bulgusu
  raporlandı

## 2026-07-09 — Faz 3 devam: artımlı analiz primitifi

### Eklenen
- **`--function <adlar>`** (`core/FunctionFilter`): yalnızca adı eşleşen
  fonksiyonlar analiz edilir — düz ad (`parse`) veya nitelikli ad
  (`Parser::parse`), virgüllü liste, tekrarlanabilir bayrak, `function=`
  config anahtarı. Ajan/IDE döngüsünde "yalnızca değiştirdiğin fonksiyonu
  yeniden kontrol et" için milisaniyelik hedefli analiz. Dört kuralın
  callback'i de filtreye uyar. 4 test (RAII guard ile global temizliği).
- **`scripts/analyze_diff.sh <binary> <git-ref> [args...]`**: verilen
  ref'ten bu yana değişen C/C++ dosyalarını analizciden geçirir; bulgu
  varsa exit 1, analizci hatasında exit >1 ile durur. CI'da "yalnızca
  dokunulan dosyaları denetle" kapısı. Simüle git deposuyla uçtan uca
  doğrulandı (bulgulu diff → 1, temiz diff → 0).

### Test sonuçları
- 119/119 test geçti (115 + 4 filtre testi)

## 2026-07-09 — Faz 3 açılışı: dataflow izleri

### Eklenen
- **TraceNote** (`core/Diagnostic.h`): bulguya iliştirilen olay zinciri
  adımı (file/line/column/message). Sıralama ve eşitlikte yer almaz.
- **Kurallarda olay kaydı** (raporlama geçişinde before/after diff'i):
  - MemLeak: "allocated here" / "freed here" (UAF, double-free, leak
    raporlarına)
  - NullDeref: "assigned null here"
  - DivByZero: "assigned zero here"
  - UninitPtr: "declared without an initializer here" (bildirim noktası)
- Notlar koşu SONUNDA iliştirilir (bekleyen-rapor deseni) — raporlama
  geçişinin blok sırası kaynak sırası olmadığından rapor anında olaylar
  henüz tam toplanmamış olabilir. Kaynak sırasına göre sıralanır, 6 ile
  sınırlanır.
- **Reporter desteği**: konsolda girintili `-> file:line:col mesaj`
  satırları; JSON'da `notes` dizisi; SARIF'te `relatedLocations`
  (GitHub code scanning bulgu detayında gösterir).
- i18n: 5 yeni iz mesajı (EN/TR).

### Neden
Faz 3 vizyonunun ilk taşı: iz, hem insana hem LLM'e "bu bulgu neden
var?" sorusunun cevabıdır — otomatik düzeltme döngüsünün girdisi.

### Test sonuçları
- 115/115 test geçti (110 + 5 iz testi)

## 2026-07-09 — Test donanımlandırma: best/worst-case matrisi (+2 av)

### Eklenen
- **StressEdgeCaseTest.cpp** (17 test, üç bölüm):
  - *Best case* (FP sınırı): goto-fail cleanup idiom'u, ternary guard
    (bölme + null), break-kenarı guard'ı, continue guard'ı, comma
    operatörü sıralaması
  - *Worst case* (FN + yakınsama sınırı): 8 seviye iç içe if, 30
    değişkenli çarpım lattice (tavan ölçekleme testi), 12 kollu else-if
    zinciri, iç içe döngüde koşullu free, do-while ilk iterasyon,
    goto ile geri döngü, default'suz switch
  - *Belgelenmiş sınırlar*: erişimsiz kod analiz edilmez, self-assignment
    FN'i, compound-assignment FN'i, koşullu double-free FN'i — davranış
    değişirse test kırılır, todo ile senkron

### Testlerin ilk turda yakaladığı iki kural açığı (düzeltildi)
- **MemLeak malloc-başarısızlık FP'si**: `p = malloc(); if (p == 0)
  return -1;` yolunda leak raporlanıyordu — null kenarında ortada
  sızacak bellek yok. MemLeak'e `refineOnEdge` eklendi: p'nin null
  olduğu kenarlarda (`!p`, `p == NULL/0/nullptr`, truthiness false,
  `&&`/`||`) Allocated → None. C'nin en yaygın kalıbındaki FP kapandı.
- **DivByZero ternary FP'si**: onStatement içindeki recursive DivFinder,
  bölmeyi kapsayan join-blok elemanında yanlış state ile ikinci kez
  keşfediyordu (`z ? 100/z : 0` guard'ına rağmen uyarı). Motor
  sözleşmesine uygun tepe-düğüm sınıflandırmasına geçildi.

### Test sonuçları
- 110/110 test geçti (93 + 17 stress/edge)

## 2026-07-09 — Motor düzeltmesi: fixpoint sonrası raporlama

### Düzeltilen (korpusun ilk avı)
- **Raporlama fixpoint'e taşındı**: `onStatement` artık worklist iterasyonu
  sırasında DEĞİL, sabitleme sonrası ayrı bir raporlama geçişinde çağrılıyor.
  Eski davranışta do-while/for gövdesinin ilk ziyaretinde back-edge state'i
  henüz yokken rapor üretiliyor, satır dedup'ı da sonraki doğru state'in
  düzeltmesini engelliyordu. cJSON'da `parse_array`'in linked-list kurma
  kalıbı bu yüzden "kesinlikle null" (Error) çıkıyordu — doğrusu MaybeNull
  (Warning). Regresyon testi eski motorla kırılıyor, yenisiyle geçiyor
  (falsifikasyon doğrulandı).
- **MemLeak transfer'ı saflaştırıldı**: reassignment-leak ve double-free
  raporları transfer'dan onStatement'a taşındı (motor sözleşmesi: transfer
  saf state fonksiyonu, raporlama yalnızca fixpoint geçişinde).
- **Path kanonikleştirme**: `tests/../cJSON.c` ile `cJSON.c` aynı dosya —
  `weakly_canonical` ile tekilleştirme ve baseline anahtarları güvenilir.
- **Makro konumları**: tüm kurallar expansion loc kullanıyor; makro içi
  bulgularda dosya adının boş kalması sorunu giderildi (cJSON unity
  test makrolarında görüldü).

### Test sonuçları
- 93/93 test geçti (92 + 1 motor regresyon testi)

## 2026-07-09 — Gerçek dünya korpusu CI'da

### Eklenen
- **scripts/run_corpus.sh**: sabit sürümlü cJSON v1.7.18 (C) ve tinyxml2
  10.0.0 (C++) projelerini indirir, CMake ile `compile_commands.json`
  üretir, zerodefect'i koşar. Başarı kriteri: crash-free (exit 0/1);
  bulgu sayıları bilgi amaçlı loglanır. Build dizini kaynak ağacının
  dışında (CMake feature-test kaynakları taranmasın);
  `CMAKE_POLICY_VERSION_MINIMUM=3.5` (CMake 4 uyumu).
- **CI adımı "Real-world corpus"**: her PR'da iki gerçek proje üzerinde
  regresyon koşusu.

### Not
- Bu oturumun ağ proxy'si GitHub tarball indirmesini repo kapsamıyla
  sınırladığından script yerelde simüle projeyle doğrulandı; gerçek
  korpus koşusunu PR CI'ı doğrular.

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
