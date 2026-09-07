# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH05-S01-U002

### CS3-CH05-S01-U002 — Mevcut supported aileleri yeni motor üzerinde yeniden doğrula

**Sonuç:** Memory/lifetime/null/arithmetic/resource ailelerinin ölçümü mevcut executable'a bağlıdır.

**Kabul:**

- Tam Linux suite ve ilgili checksummed corpus çalışır; eski receipt'ler PASS yerine kullanılmaz.
- Mevcut Juliet ve corpus floor'larının hiçbiri düşürülmez; her yeni bulgu fixture ile açıklanır.
- Clean corpus'ta yeni yanlış pozitif veya sessiz bulgu kaybı çözülmeden iş kapanmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** tests/cwe_corpus/*, scripts/cwe_quality.py, docs/quality_results.md, src/rules/*, tests/*Rule*Test.cpp
**Bağımlılıklar:** CS3-CH05-S01-U001

### CS3-CH05-S01-U003 — Yeni experimental CWE ailelerinin destek kararını kanıtla

**Sonuç:** Ölçülen altküme dışında destek veya blocking terfisi yapılmaz.

**Kabul:**

- Her yeni kuralın pozitif/negatif ve sınır fixture'ları ayrı raporlanır.
- Declared supported altkümesinde precision en az %90, addressable recall en az %70 ve deterministic safe fixture'larda sıfır FP gerekir; daha sıkı mevcut floor korunur.
- Başaramayan kural experimental/report-only kalır; teslim kapsamından çıkarma veya daha düşük hedef ayrıca kullanıcı kararı gerektirir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/core/RuleCapabilities.def, scripts/cwe_quality.py, tests/cwe_corpus/*, docs/CWE_SCOPE.md, docs/capabilities.md, docs/quality_results.md, README.md, scripts/check_capabilities_sync.py, tests/CapabilitiesTest.cpp, tests/CapabilitiesCliTest.py
**Bağımlılıklar:** CS3-CH05-S01-U002

### CS3-CH05-S02-U001 — Sınırlı sanitizer/fuzz ve bozuk girdi kabulünü tamamla

**Sonuç:** Parser/worker/cache sınırları hedefli adversarial testlerden geçer.

**Kabul:**

- Yalnız ilgili sanitizer ve bounded fuzz seed'leri çalıştırılır; süreç/süre/bellek sınırı kayıtlıdır.
- Crash, hang, OOM, partial commit ve false-clean varsa PASS yoktur.
- Eksik araç veya koşmayan kontrol success sayılmaz; testler sırf yeşil için silinmez.
- Korunan c395903 Windows run34098971513 tek-süreç RED kaydındaki 300ms survivor timeout ayrıca teşhis edilir. Kaynak/bütçe fault-injection fixture zamanlaması düzeltilirse gerçek üretim timeout/bellek sınırları ve 150ms sleeping-child kill/reap regresyonu gevşetilmez; survivor bulguları, incomplete exit2 ve bütün mevcut assertions korunur. Eski başarısız koşu başarısız kalır; kontrollü RED/GREEN ve yeni exact-head Windows suite/tek-süreç/package hosted başarısı olmadan bu worker sınırı tamamlandı sayılmaz.
- Yalnız bu görevde gerekçeli test girdisi değişirse önce eski/yeni path-digest farkı bağımsız incelenir; regression_inventory ve catalog bağlantısı yeni ölçümden önce kontrollü successor freeze ile güncellenir. Hiçbir CWE fixture, beklenen bulgu, Juliet/corpus floor veya başarısız geçmiş sonuç değiştirilmez.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check, windows-hosted
**Kapsam:** tests/stress_corpus/*, fuzz/*, scripts/test_resilience.sh, docs/quality_results.md, tests/AnalysisCoordinatorTest.cpp, tests/ResourceBudgetTest.cpp, tests/cwe_corpus/catalog.json, tests/cwe_corpus/regression_inventory.json
**Bağımlılıklar:** Yok

### CS3-CH05-S02-U002 — Gerçek proje ve performans kabulünü ölç

**Sonuç:** Sabit girdilerde kullanılabilirlik, latency ve false positive yükü ölçülür.

**Kabul:**

- En az üç küçük/orta gerçek C/C++ proje veya önceden edinilmiş checksummed örnek kullanılır; kaynaklar izinsiz upload edilmez.
- Donanım, girdi, komut, sürüm ve süre/bellek ölçümleri kayıtlıdır.
- Ölçülmeyen performans/market başarısı iddia edilmez; blocker varsa aynı chapter kapanmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** scripts/measure_product.py, docs/quality_results.md, docs/benchmarks.md
**Bağımlılıklar:** Yok

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
