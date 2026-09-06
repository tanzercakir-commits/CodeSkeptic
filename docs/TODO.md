# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH04-S01-U001

### CS3-CH04-S01-U001 — Dosya başına taşınabilir worker protokolü kur

**Sonuç:** Bir dosyanın çökmesi diğer dosyaların sonuçlarını kaybettirmez.

**Kabul:**

- Aynı binary ile sürümlü child protocol ve deterministik TU sırası vardır.
- Crash/malformed child result ayrı failure olur; parent güvenilir temiz diyemez.
- Eski worker dalı topluca taşınmaz; sudo, broker, systemd/cgroup bağımlılığı yoktur.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, src/core/AnalysisResult.h, src/main.cpp, src/CMakeLists.txt, tests/WorkerProtocolTest.cpp, tests/AnalysisCoordinatorTest.cpp, tests/CMakeLists.txt, tests/HtmlReporterTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH04-S01-U002 — Timeout/bellek/iptal bütçesini uygula

**Sonuç:** Kaynak bütçesi aşan worker sonlandırılır; süreç ve descriptor sızıntısı bırakılmaz.

**Kabul:**

- Timeout, memory limit ve cancellation negatifleri gerçek subprocess ile sınanır.
- Partial failure sonuç ve kapsamda görünür; diğer sonuçlar deterministik toplanır.
- Host-wide/root authority yoktur; yalnız başlatılan çocuk süreçler yönetilir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, src/core/Resource*, src/config/Config*, src/main.cpp, src/CMakeLists.txt, tests/ResourceBudgetTest.cpp, tests/AnalysisCoordinatorTest.cpp
**Bağımlılıklar:** CS3-CH04-S01-U001

### CS3-CH04-S02-U001 — Cache kimliğini gerçek girdilere bağla

**Sonuç:** Cache yalnız aynı araç/ayar/girdi/header bağımlılıkları için kullanılabilir.

**Kabul:**

- Değişen header/compiler flag/profile/tool veya volatile input eski kaydı reddeder.
- Cache'siz ve cache'li normalize sonuç aynı olur.
- Eski a79c375 yardımcı fikir kaynağıdır; kanıt veya dosya paketi olarak taşınmaz.

**Test bütçesi:** T1
**Kontroller:** focused-tests, cli-smoke, queue-check
**Kapsam:** src/analyzer/*, src/source_manager/*, src/config/Config*, tests/UnitEvidenceStoreTest.cpp, tests/AnalysisCoordinatorTest.cpp
**Bağımlılıklar:** Yok

### CS3-CH04-S02-U002 — Cache yazımı ve saklama sınırını güvenli yap

**Sonuç:** Kısmi/bozuk/symlink kayıt kullanılmaz; disk kullanımı tanımlı tavanda kalır.

**Kabul:**

- Atomic temp-to-final, concurrent writers, truncated entry ve tamper fixture'ları vardır.
- Failed write önceki geçerli entry'yi bozmaz; retention sonucu analiz doğruluğu değişmez.
- Saklama tavanı aşılırsa açık durum verir; sınırsız cache oluşturulmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, tests/UnitEvidenceStoreTest.cpp
**Bağımlılıklar:** CS3-CH04-S02-U001

### CS3-CH04-S02-U003 — Checkpoint yalnız aynı geçerli analizi sürdürsün

**Sonuç:** Kesilen çalışma tam girdi kimliği doğrulandıktan sonra devam eder.

**Kabul:**

- Changed source/header/config/corrupt manifest resume'u reddeder.
- Resume ve fresh run sonuç/kapsam eşittir; eksik worker sonucu DONE sayılmaz.
- Disk ve süreç sınırları cache/worker sözleşmesini aşmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/analyzer/*, src/config/Config*, src/main.cpp, tests/UnitEvidenceStoreTest.cpp, tests/AnalysisCoordinatorTest.cpp
**Bağımlılıklar:** CS3-CH04-S02-U002

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
