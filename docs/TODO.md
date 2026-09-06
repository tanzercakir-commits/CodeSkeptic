# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH02-S04-U001

### CS3-CH02-S04-U001 — Compilation discovery için native LLVM/MSVC uyumluluğunu doğrula

**Sonuç:** Mevcut Windows toolchain compilation discovery kodunu derler; komut kimliği doğrulaması ve ürün kapıları korunur.

**Kabul:**

- 611edab Windows hosted LLVM 20.1.8/MSVC OPT_ redefinition hatası kanıt olarak korunur, nedeni teşhis edilip yalnız gerekli uyumluluk düzeltmesi uygulanır.
- Geçerli compilation-command ve wrong-input/response-file negatifleri korunur; driver doğrulaması devre dışı bırakılamaz.
- Exact-head native Windows build, test, smoke, SDK ve relocation kapıları başarılı olmalıdır; atlanan adım başarı değildir. Main, mevcut toolchain pinleri ve kalite kapıları değişmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, compilation-database-cli, hosted-windows, queue-check
**Kapsam:** src/source_manager/CompilationDatabaseDiscovery.cpp, tests/CompilationDatabaseCliTest.py, src/CMakeLists.txt, tests/SourceManagerTest.cpp, scripts/review_report.py, tests/ReviewInputTest.py, src/windows_utf8.manifest, docs/windows-support.md, scripts/run_corpus.sh, scripts/corpus_compile_commands.cpp, tests/CMakeLists.txt, src/source_manager/SourceManager.cpp, docs/usage.md
**Bağımlılıklar:** CS3-CH02-S01-U001

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH03 — CWE bulgularını kullanılabilir ürüne dönüştürme
- CH04 — Sınırlı kaynakla dayanıklı çalışma
- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
