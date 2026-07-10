# ZeroDefect — Yapılacaklar ve Notlar

## 📅 Yarının planı (2026-07-10 oturumu için hazırlandı)

Sıralama önerisi — her madde bağımsız bir PR turu:

1. **Juliet rakam analizi + zayıf-CWE kural iyileştirmesi.** PR #16'nın
   temsili rakamlarıyla başla (README'ye işlendi/işlenecek). Eşlemeli
   precision hangi kuralda düşükse oraya odaklan:
   - CWE415/416 good-fonksiyon FP'leri: Juliet good varyantlarının tipik
     kalıpları (goodB2G/goodG2B çağrı zincirleri) hangi FP'yi üretiyor?
     `findings_*.json`'daki `function` alanından iki-üç örnek dosya seç,
     kalıbı çıkar, kurala test-önce düzeltme uygula.
   - CWE369: adımlı örneklemeden sonra int varyantları görünür olacak;
     rand()/fgets kaynaklı akışlarda muhafazakâr sessizlik doğru
     (Unknown), `data=0` yerel akışları yakalanmalı.
2. **Korpus bulgu sayısı sabitleme** (küçük tur): beklenen bulgu sayısı
   dosyası + tolerans; korpus CI adımı sapmada kırmızı. Semantik
   regresyonların erken yakalayıcısı.
3. **MemLeak transfer'ını tepe-düğüm Effect desenine taşı** (orta tur):
   UninitPtr'daki desen; değişken-başına classify döngüsü kalkar,
   MemLeak Juliet koşusu da hızlanır.
4. Vakit kalırsa: ortak koşul-yürüyüşü yardımcısı (NullDeref + DivByZero
   applyCondition tekilleştirmesi) — davranış değişikliği yok, testler
   sabit kalmalı.

Açık kullanıcı kararları (yol haritası artifact'ındaki 4 madde):
public v0.1 zamanlaması (önerim: Juliet rakamları README'de olduktan
sonra), kontrat dili sözdizimi (Ufuk 3 öncesi birlikte tasarım),
Juliet'in CI ağırlığı, proje adı kontrolü.

## Sıradaki Görevler (yol haritası: analiz-2026-07.md)

### Faz 1 kalanları
- [ ] Fonksiyon başına CFG önbelleği — kurallar arası paylaşım (şu an her
      kural kendi CFG'sini kuruyor; fonksiyon başına 3 build). Kurallara
      ortak bir analiz bağlamı geçirmek gerekir — mimari karar.
- [x] converged=false artık stderr'de görünür (AnalysisNotConverged,
      4 kuralda; i18n'li)
- [x] MemoryLeakRule tepe-düğüm Effect desenine taşındı
      (classifyStmtEffects: ifade bir kez sınıflandırılır)

### Faz 2 kalanları
- [x] NIST Juliet ölçüm altyapısı (haftalık workflow + juliet_eval;
      gerçek rakamlar ilk koşudan sonra README'ye)
- [x] Juliet ilk gerçek koşu tamam (PR #14) — rakamlar ve analiz
      changelog'da (2026-07-09 girişi)
- [x] **Juliet ölçüm doğruluğu turu**: adımlı örnekleme + eşlemeli
      precision (`rprecision`) + double-free rule_id — 2026-07-10
      changelog girişine bakınız. Bonus: tek-süreç koşuda global filtre
      sızıntısı bulundu ve düzeltildi (~StaticAnalyzer RAII; CI'ya
      tek-süreç test adımı eklendi).
- [ ] Temsili rakamlar (bu PR'ın Juliet CI koşusundan) README'ye
      benchmark bölümü olarak işlensin
- [ ] CWE415/416 good-fonksiyon FP'lerini incele (eşlemeli precision
      sonrası gerçek boyut belli olur); CWE401 dosya isabeti için
      interprosedürel kaynak/lavabo akışı (bilinen v1 sınırı)
- [x] Korpus bulgu sayılarını sabitle (corpus_expected.txt: cjson 111,
      tinyxml2 9; %10+2 tolerans; sapma = kırmızı = semantik regresyon)
- [x] Baseline v2: satır-bağımsız anahtar (satır içeriği FNV-1a hash'i;
      multiset sayacı — özdeş bulgular tek tek; v1 dosyaları geriye uyumlu)

### Kural iyileştirme notları
- ~~NullDeref çoklu bildirim FN'i~~ — deneyle geçersiz çıktı: ince
  taneli CFG çoklu bildirimi değişken başına böler, ikinci pointer da
  izleniyor (regresyon testleriyle sabitlendi, 2026-07-10).
- ~~Ortak koşul-yürüyüşü~~ — yapıldı (engine/ConditionWalk.h):
  walkCondition (genel iskelet: !, &&/||, değişken-solda normalizasyon) +
  walkNullCondition (pointer-null domain'i). Dört istemci: NullDeref,
  MemLeak, FunctionSummary (null), DivByZero (sıfır, genel iskelet).

### Faz 3 (AI döngüsü)
- [x] Artımlı analiz primitifi: --function filtresi + analyze_diff.sh
- [x] Artımlı v2: --lines aralıkları + hunk ayrıştırma (tam otomatik
      "yalnızca dokunulan fonksiyonları analiz et" döngüsü)
- [x] Bulgulara dataflow izi (TraceNote; konsol/JSON/SARIF relatedLocations)
- [x] MCP server modu (--serve; initialize / tools/list / tools/call analyze)
- [ ] İz v2: guard/refine olayları da eklensin (kenar olayları onStatement'ta
      görünmüyor — motor desteği gerekir)
- [x] MCP v2: sıcak süreçte AST/derleme önbelleği (yol+build-path anahtarı,
      boyut+mtime parmak izi — bayat AST asla servis edilmez; yalnız MCP
      yolunda açık, CLI kapalı; tekrar çağrıda ~6x hız)

### Arayüz (UI) — son etap, pratiklik + görsellik
- [ ] **HTML rapor**: `--html rapor.html` — tek, kendine yeten dosya
      (bağımlılıksız, offline açılır). Bulgular kural/severity/dosya
      filtresiyle; her bulgunun dataflow izi tıklanınca kaynak bağlamıyla
      açılır; özet kartları (kural başına sayı, severity dağılımı).
      En pratik ilk adım: kurulum yok, paylaşımı e-posta/PR eki kadar
      kolay.
- [ ] **Editör entegrasyonu belgesi**: SARIF çıktımız VS Code "SARIF
      Viewer" ve GitHub code scanning ile bugün çalışıyor — README'ye
      ekran görüntülü kısa rehber (sıfır kod, hazır kazanım).
- [ ] **Trend paneli**: haftalık JULIET_RESULT/CORPUS_RESULT satırlarını
      işleyen statik sayfa (GitHub Pages) — F1/precision zaman serisi.
      Skor bekçisinin görsel yüzü.
- [ ] (Değerlendirme) VS Code eklentisi: MCP/--serve üzerinden canlı
      analiz + satır içi squiggle. En yüksek etki, en yüksek maliyet —
      HTML rapor + SARIF deneyiminden gelen geri bildirimle karar.

### Faz 4 (araştırma ufku)
- [x] İnterprosedürel v1: fonksiyon özetleri (dönüş nullness + parametre
      etkileri; sabit-nokta taraması, rekursiyon-güvenli)
- [x] İnterprosedürel v2: alias izleme (kopya grafı + taint yayılımı;
      imleç-desenli yıkıcılar Frees; kirli/çok-kaynaklı/adresli yereller
      muhafazakâr)
- [x] Dönüş-nullness dataflow'u: `return p;` yolları mini null-akışıyla
      (runDataflow istemcisi) akış-duyarlı çözülür; param passthrough
      Unknown kalır (parametre-duyarlı özet ayrı ufuk)
- [x] Cross-TU özetler v1 (--whole-program iki geçişli mod; ad+arite
      anahtarı, yalnız harici bağlantı, çakışmada muhafazakâr birleşim)
- [x] Cross-TU v2: özetleri diske yaz/yükle (--summary-out/--summary-in;
      sürümlü satır formatı, bozuk dosya bütünüyle red, çakışmada
      muhafazakâr birleşim; hasat rules geçişinde — ikinci parse yok)
- [ ] Cross-TU v3 fikirleri: analyze_diff.sh'a --summary-in entegrasyonu;
      MCP analyze aracına summaries argümanı; özet dosyası tazelik
      kontrolü (kaynak mtime > özet mtime uyarısı)
- [ ] Dönüş-akışının Juliet 61-ailesi doğrulaması: haftalık derin koşu
      (cron limit=1600) trendde göstermeli; ilk cron sonucunu kontrol et
- [ ] Int dönüş sıfır-olabilirliği özeti (DivByZero tüketsin)
- [ ] Özet önbelleği (artımlı modda yalnızca değişen fonksiyon tazelenir;
      "özet değişti → çağıranlar etkilendi" = semantik regresyon sinyali)

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
