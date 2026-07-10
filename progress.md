# ZeroDefect — İlerleme Durumu

## Tamamlanan Bileşenler

| Bileşen | Dosyalar | Durum |
|---------|----------|-------|
| Diagnostic | `src/core/Diagnostic.h` | Tamamlandı (operator== + tam sıralama) |
| Rule | `src/core/Rule.h` | Tamamlandı |
| Messages (i18n) | `src/core/Messages.h`, `.cpp` | Tamamlandı (EN varsayılan, `--lang tr`) |
| SourceManager | `src/source_manager/SourceManager.h`, `.cpp` | Tamamlandı (Linux header fix + sıcak AST önbelleği, MCP yolu) |
| RuleEngine | `src/engine/RuleEngine.h`, `.cpp` | Tamamlandı |
| DataflowEngine | `src/engine/DataflowEngine.h` | Tamamlandı (template + assume edges + latticeHeight + ince taneli CFG + iki fazlı raporlama) |
| PathFacts | `src/engine/PathFacts.h`, `.cpp` | Tamamlandı (koşul→kanonik anahtar; mutasyon görücüsü) |
| GuardedDisjuncts | `src/engine/GuardedDisjuncts.h` | Tamamlandı (guard'lı disjunkt şablonu — 3 kural kullanıyor) |
| FunctionSummary | `src/engine/FunctionSummary.h`, `.cpp` | Tamamlandı (TU-yerel + cross-TU depo; --whole-program; diske yaz/yükle) |
| Reporter (abstract) | `src/reporter/Reporter.h` | Tamamlandı |
| ConsoleReporter | `src/reporter/ConsoleReporter.h`, `.cpp` | Tamamlandı |
| JsonReporter | `src/reporter/JsonReporter.h`, `.cpp` | Tamamlandı |
| SarifReporter | `src/reporter/SarifReporter.h`, `.cpp` | Tamamlandı (SARIF 2.1.0) |
| HtmlReporter | `src/reporter/HtmlReporter.h`, `.cpp` | Tamamlandı (tek dosya; filtreler + kaynak bağlamlı izler) |
| SuppressionFilter | `src/analyzer/SuppressionFilter.h`, `.cpp` | Tamamlandı (disable-line / next-line) |
| Baseline | `src/analyzer/Baseline.h`, `.cpp` | Tamamlandı (v2: satır-bağımsız içerik-hash anahtarı; v1 uyumlu) |
| Config | `src/config/Config.h`, `.cpp` | Tamamlandı (`--lang` dahil) |
| StaticAnalyzer | `src/analyzer/StaticAnalyzer.h`, `.cpp` | Tamamlandı (çapraz-TU dedup) |
| UninitPointerRule_Ex | `src/rules/UninitPointerRule_Ex.h`, `.cpp` | Tamamlandı (çarpım lattice + guard'lı disjunktlar) |
| MemoryLeakRule_Ex | `src/rules/MemoryLeakRule_Ex.h`, `.cpp` | Tamamlandı (leak + double-free + UAF; disjunktlar + Effect deseni + özet tüketimi) |
| DivByZeroRule | `src/rules/DivByZeroRule.h`, `.cpp` | Tamamlandı (literal + CFG + guard analizi) |
| NullDerefRule | `src/rules/NullDerefRule.h`, `.cpp` | Tamamlandı (NullState + assume edges + disjunktlar + dönüş-nullness özeti) |
| main.cpp | `src/main.cpp` | Tamamlandı (4 kural kayıtlı, 5 rule_id) |
| CMake build sistemi | `CMakeLists.txt`, `src/CMakeLists.txt` | Tamamlandı (Linux + macOS) |
| GTest altyapısı | `tests/` | Tamamlandı (219/219; ctest + tek-süreç) |
| CI | `.github/workflows/ci.yml` | Tamamlandı (build + test + smoke + korpus) |
| Korpus scripti | `scripts/run_corpus.sh` | Tamamlandı (cJSON v1.7.18 + tinyxml2 10.0.0) |
| Juliet benchmark | `scripts/run_juliet.sh`, `juliet_eval.py`, `juliet.yml` | Tam entegrasyon: F1 + skor bekçisi; her kod PR'ında koşar (draft hariç); rakamlar README'de |
| README / LICENSE | `README.md`, `LICENSE` | Tamamlandı (EN, Apache-2.0) |
| Durum tespiti / yol haritası | `analiz-2026-07.md` | Tamamlandı |

## Bekleyen Sorunlar

Yok. (Bilinen analiz sınırlamaları için `todo.md`'ye bakınız.)

## Dizin Yapısı

```
ZeroDefect/
├── CMakeLists.txt
├── README.md
├── LICENSE
├── architecture.txt
├── analiz-2026-07.md
├── progress.md
├── todo.md
├── changelog.md
├── .github/workflows/ci.yml
├── src/
│   ├── CMakeLists.txt
│   ├── main.cpp
│   ├── analyzer/
│   │   ├── StaticAnalyzer.h
│   │   └── StaticAnalyzer.cpp
│   ├── config/
│   │   ├── Config.h
│   │   └── Config.cpp
│   ├── core/
│   │   ├── Diagnostic.h          (header-only)
│   │   ├── Messages.h/.cpp       (i18n: EN/TR mesaj tablosu)
│   │   └── Rule.h                (header-only)
│   ├── engine/
│   │   ├── DataflowEngine.h      (template, header-only)
│   │   ├── RuleEngine.h
│   │   └── RuleEngine.cpp
│   ├── reporter/
│   │   ├── Reporter.h            (abstract)
│   │   ├── ConsoleReporter.h/.cpp
│   │   └── JsonReporter.h/.cpp
│   ├── rules/
│   │   ├── UninitPointerRule_Ex.h/.cpp  (CFG dataflow)
│   │   ├── MemoryLeakRule_Ex.h/.cpp     (CFG dataflow)
│   │   └── DivByZeroRule.h/.cpp         (literal + CFG dataflow)
│   └── source_manager/
│       ├── SourceManager.h
│       └── SourceManager.cpp
├── tests/
│   ├── CMakeLists.txt
│   ├── TestHelper.h/.cpp
│   ├── DiagnosticTest.cpp          (6 test: 4 + dedup + i18n)
│   ├── UninitPointerRuleExTest.cpp (14 test)
│   ├── MemoryLeakRuleExTest.cpp    (13 test)
│   └── DivByZeroRuleTest.cpp       (19 test: 10 + 9 guard)
├── test_projects/
│   ├── cJSON/                      (C test projesi)
│   └── tinyxml2/                   (C++ test projesi)
```
