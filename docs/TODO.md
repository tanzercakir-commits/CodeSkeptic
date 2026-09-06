# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH03-S02-U001

### CS3-CH03-S02-U001 — Baseline/suppression ile yalnız yeni bulguyu ayır

**Sonuç:** Yeni kod kontrolü legacy bulguları gizlice yeni veya yok sayılmış göstermeden çalışır.

**Kabul:**

- Stable fingerprint, moved lines, changed function ve malformed baseline/suppression kapsanır.
- Bastırma kaydı gerekçe/kapsam içerir; suppression analiz kapsamını değiştirmez.
- Eski bulgu yükü yeni yüksek güvenli bulguyu engellemez veya saklamaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/analyzer/Baseline*, src/analyzer/SuppressionFilter*, src/core/FindingFingerprint*, scripts/review_diff.sh, scripts/review_report.py, tests/BaselineTest.cpp, tests/SuppressionFilterTest.cpp, tests/test_review_diff.sh, src/core/AnalysisResult.h, src/analyzer/StaticAnalyzer.cpp, src/reporter/ReportContract.h, tests/HtmlReporterTest.cpp, scripts/test_review_diff.sh, src/core/Diagnostic.h, src/reporter/SarifReporter.cpp, tests/OutputParityCliTest.py
**Bağımlılıklar:** Yok

### CS3-CH03-S02-U002 — Minimal ilk tarama ve CI kullanımını doğrula

**Sonuç:** Temiz bir örnek projede kurulmuş araçla ilk tarama ve rapor-only CI akışı tekrarlanır.

**Kabul:**

- En az bir küçük C ve bir C++ fixture yeni kullanıcı komutlarıyla çalışır.
- Eksik derleme girdisinde uygulanabilir düzeltme adımı vardır.
- Canlı GitHub yazma/bot devreye alma şart değildir; yerel örnek hazır olmadan destek iddiası yoktur.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** docs/first-scan.md, docs/usage.md, docs/integrations.md, README.md, tests/FirstScanTest.py, scripts/test_first_scan.sh
**Bağımlılıklar:** Yok

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH04 — Sınırlı kaynakla dayanıklı çalışma
- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
