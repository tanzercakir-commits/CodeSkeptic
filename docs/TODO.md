# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH00-S01-U001

### CS3-CH00-S01-U001 — Main tabanlı kitabı ve çalışan FIFO/POP sistemini kur

**Sonuç:** Eski dallar referans olarak saklanır; bağımsız doğrulama olmadan kuyruk ilerleyemez.

**Kabul:**

- Main ve src ağacı değişmez; eski yerel dal uçları geri yüklenebilir arşivde doğrulanır.
- PLAN tam chapter–section katalogdur; TODO yalnız aktif chapter'ın tam görevlerini gösterir.
- 30 veya daha fazla odaklı test FIFO, chapter geçişi, terminal durum, stale/missing kanıt, yanlış dal, scope ihlali, rollback ve gerçek süreç kesintisinden recovery'yi sınar.
- Gelecek iş ekleme/güncelleme mevcut front'u, eski görev sırasını ve tamamlanmış kayıtları bozmaz.
- Yerel kanıt kriptografik imza/remote destek diye sunulmaz; bağımsız exact-head PASS sonrası gerçek ilk POP yapılır.

**Test bütçesi:** T0
**Kontroller:** queue-tests, queue-check
**Kapsam:** AGENTS.md, INVARIANTS.md, MASTER_PROMPT.md, CONTRIBUTING.md, docs/BOOK.json, docs/PLAN.md, docs/TODO.md, docs/PROGRESS.md, docs/RESTART.md, docs/QUEUE_GUIDE.md, docs/CWE_SCOPE.md, scripts/project_queue.py, scripts/local_test.sh, scripts/check_docs_sync.sh, tests/test_project_queue.py, tests/CMakeLists.txt, .github/workflows/project-queue.yml, scripts/progress_status.py, tests/StatusAutomationTest.py
**Bağımlılıklar:** Yok

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH01 — CWE çekirdeğini somut eksiklerle geliştirme
- CH02 — Güvenilir analiz girdisi ve kapsam
- CH03 — CWE bulgularını kullanılabilir ürüne dönüştürme
- CH04 — Sınırlı kaynakla dayanıklı çalışma
- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
