# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH02-S03-U002

### CS3-CH02-S03-U002 — Frontend ve CFG düşmanca geçerli girdilerde sonlansın

**Sonuç:** Template/macro/CFG köşeleri crash/hang yerine sınırları belirli sonuç verir.

**Kabul:**

- Küçük, repository-contained template/macro/high-CFG fixture'ları kullanılır.
- Hata veya timeout eksik kapsama nedeni olarak korunur.
- Ortak motor değişirse tam Linux suite ve yalnız ilgili sanitizer/stress dilimi çalışır.
- Zaten gerekli Linux suite için ReviewDiffFlow önkoşulu da tamamlanır: 611edab hosted expected-1/got-2 hatası gerçek analyzer stderr ve base/head komut kimlikleriyle RED olarak doğrulanır. Yalnız review girdi hazırlama/remap ve fixture uyumluluğu düzeltilir; repo-root database, rename ve yeni dosya kapsamı sınanır. Gerçek build/generated-header koruması, exact-command reddi, new/fixed/weakened sayımları, shift/rename bağışıklığı, gate ladder, exclude ve malformed/missing-input negatifleri korunur; hiçbir kalite kapısı, pin veya suite kapsamı azaltılmaz. Frontend/CFG kabulleri aynen geçerlidir; ikisi de tamamlanmadan POP yoktur.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/StaticAnalyzer*, src/source_manager/SourceManager*, src/engine/*, tests/stress_corpus/*, tests/StressMatrixTest.py, scripts/run_stress_matrix.py, scripts/test_review_diff.sh, scripts/review_diff.sh, scripts/review_report.py, tests/CMakeLists.txt, tests/ReviewInputTest.py
**Bağımlılıklar:** Yok

### CS3-CH02-S04-U001 — Compilation discovery için native LLVM/MSVC uyumluluğunu doğrula

**Sonuç:** Mevcut Windows toolchain compilation discovery kodunu derler; komut kimliği doğrulaması ve ürün kapıları korunur.

**Kabul:**

- 611edab Windows hosted LLVM 20.1.8/MSVC OPT_ redefinition hatası kanıt olarak korunur, nedeni teşhis edilip yalnız gerekli uyumluluk düzeltmesi uygulanır.
- Geçerli compilation-command ve wrong-input/response-file negatifleri korunur; driver doğrulaması devre dışı bırakılamaz.
- Exact-head native Windows build, test, smoke, SDK ve relocation kapıları başarılı olmalıdır; atlanan adım başarı değildir. Main, mevcut toolchain pinleri ve kalite kapıları değişmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, compilation-database-cli, hosted-windows, queue-check
**Kapsam:** src/source_manager/CompilationDatabaseDiscovery.cpp, tests/CompilationDatabaseCliTest.py
**Bağımlılıklar:** CS3-CH02-S01-U001

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH03 — CWE bulgularını kullanılabilir ürüne dönüştürme
- CH04 — Sınırlı kaynakla dayanıklı çalışma
- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
