# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH05-S01-U001

### CS3-CH05-S01-U001 — Kural bazlı pozitif/negatif doğrulama kataloğunu dondur

**Sonuç:** Ölçüm girdileri sonucu görmeden seçilir ve hangi CWE altkümesinin desteklendiği açıktır.

**Kabul:**

- Her desteklenecek kural için güvenli/buggy fixture kimliği ve beklenen bulgu kayıtlıdır.
- Yeni çekirdek testleri corpus dışında bırakılarak başarı şişirilmez; eski source/corpus floor'ları düşürülmez.
- Unknown/unsupported örnekler false negative veya clean ile karıştırılmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** tests/cwe_corpus/*, scripts/cwe_quality.py, docs/CWE_SCOPE.md, docs/quality_protocol.md
**Bağımlılıklar:** Yok

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

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** tests/stress_corpus/*, fuzz/*, scripts/test_resilience.sh, docs/quality_results.md
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
