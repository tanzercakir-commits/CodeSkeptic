# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH03-S01-U001

### CS3-CH03-S01-U001 — Kural ve CWE eşlemesini tek sözleşmede yayınla

**Sonuç:** Bulguların stable rule ID, doğru CWE ve açıklama bağlantısı vardır.

**Kabul:**

- CWE-125 okuma ile CWE-787 yazma farklı açıklanır; her bounds bulgusu aynı CWE'ye yanlış eşlenmez.
- Existing supported/experimental durumu ölçümsüz yükseltilmez.
- JSON/SARIF metadata ve CLI capability listesi registry ile tutarlıdır.
- Aritmetik pozitif taşma ile negatif sınır taşması doğru mesajla ayrılır; 64-bit çıkarmada upward overflow underflow diye sunulmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/core/RuleCapabilities.def, src/core/Capabilities*, src/core/Diagnostic.h, src/core/AnalysisResult.h, src/reporter/*, src/rules/*, tests/SarifReporterTest.cpp, tests/CapabilitiesTest.cpp, docs/capabilities.md, src/core/Messages.*, tests/IntOverflowRuleTest.cpp, tests/JsonReporterTest.cpp, tests/CapabilitiesCliTest.py, README.md, scripts/check_capabilities_sync.py, tests/BoundsRuleTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH03-S01-U002 — CLI/JSON/SARIF/HTML bulgu ve verdict tutarlılığını sabitle

**Sonuç:** Aynı analiz bütün çıktı yüzeylerinde aynı normalize bulguyu ve kapsamı verir.

**Kabul:**

- Rule/CWE, konum, trace, severity, tool/schema version ve verdict karşılaştırılır.
- Malformed option/config deterministik hatadır; makine çıktısına log karışmaz.
- Path component sınırları ve Windows path fixture'ları korunur.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/reporter/*, src/core/Capabilities*, src/core/Messages*, src/main.cpp, src/config/Config*, tests/*ReporterTest.cpp, tests/CapabilitiesTest.cpp, tests/ConfigTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH03-S02-U001 — Baseline/suppression ile yalnız yeni bulguyu ayır

**Sonuç:** Yeni kod kontrolü legacy bulguları gizlice yeni veya yok sayılmış göstermeden çalışır.

**Kabul:**

- Stable fingerprint, moved lines, changed function ve malformed baseline/suppression kapsanır.
- Bastırma kaydı gerekçe/kapsam içerir; suppression analiz kapsamını değiştirmez.
- Eski bulgu yükü yeni yüksek güvenli bulguyu engellemez veya saklamaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/analyzer/Baseline*, src/analyzer/SuppressionFilter*, src/core/FindingFingerprint*, scripts/review_diff.sh, scripts/review_report.py, tests/BaselineTest.cpp, tests/SuppressionFilterTest.cpp, tests/test_review_diff.sh
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
