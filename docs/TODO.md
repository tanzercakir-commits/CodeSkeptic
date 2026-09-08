# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH06-S02-U002

### CS3-CH06-S02-U002 — Desteklenen platform sözünü gerçek paket testine bağla

**Sonuç:** Linux dışı platformların destek durumu fiilen çalışan artifact testine göre açıklanır.

**Kabul:**

- Windows/macOS dahil destek ilan edilen her platform exact artifact first-scan çalıştırır.
- Eksik runner/signer/authorization başarılı sayılmaz; açık blocker olarak kalır.
- Yerel branch senkronizasyonu main merge veya release yetkisi değildir.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** .github/workflows/windows.yml, .github/workflows/release.yml, docs/windows-support.md, README.md, docs/release-checklist.md, scripts/package_release.sh, scripts/platform_first_scan.py, scripts/test_platform_workflow.py, src/analyzer/StaticAnalyzer.cpp, src/analyzer/CheckpointTime.h, src/core/ResourceBudget.cpp, tests/CompilationDatabaseCliTest.py, tests/cwe_corpus/regression_inventory.json, tests/cwe_corpus/catalog.json, docs/quality_protocol.md, src/core/DarwinMemoryBudget.h, src/core/ResourceBudget.h, tests/ResourceBudgetTest.cpp, docs/usage.md
**Bağımlılıklar:** Yok

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH07 — Teslim ve kapanış
