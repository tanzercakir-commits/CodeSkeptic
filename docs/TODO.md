# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH06-S01-U001

### CS3-CH06-S01-U001 — Linux kurulabilir artifact üret

**Sonuç:** Temiz ortamda açılıp çalışan sürümlü Linux paketi üretilir.

**Kabul:**

- CLI ve bütün temel çıktı biçimleri kaynak build ile aynı normalize sonucu verir.
- LLVM/runtime bağımlılıkları ve lisanslar eksiksizdir; geliştirme build'i release gibi adlandırılmaz.
- Paket first-scan smoke'tan geçer; normal kullanım sudo gerektirmez.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/package_release.sh, CMakeLists.txt, src/CMakeLists.txt, docs/release-checklist.md, tests/PackageTest.py, scripts/test_package.py
**Bağımlılıklar:** Yok

### CS3-CH06-S01-U002 — Container ve Action paketinde analiz paritesini doğrula

**Sonuç:** Container/Action aynı binary sözleşmesiyle güvenilir sonucu taşır.

**Kabul:**

- Kaynak kod/secret izinsiz dışarı gönderilmez; runtime varsayılan izinler minimaldir.
- Aynı fixture için CLI/container/Action exit ve SARIF sonuçları eşittir.
- Canlı destek iddiası yalnız gerçekten koşmuş platform/check kanıtına dayanır.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** Dockerfile, action.yml, scripts/action*, tests/ActionArgsTest.py, docs/integrations.md, .github/workflows/action-selftest.yml
**Bağımlılıklar:** CS3-CH06-S01-U001

### CS3-CH06-S02-U001 — Sürüm, checksum, SBOM ve provenance üret

**Sonuç:** Artifact hangi kaynak ve bağımlılıklardan üretildiğini kanıtlarıyla taşır.

**Kabul:**

- Tek authored version source vardır; source SHA ve tool/schema version raporları tutarlıdır.
- Artifact checksum, bağımlılık/lisans listesi ve yeniden üretim komutu kayıtlıdır.
- İmza kimliği yoksa imzalı release iddiası yapılmaz; secret aranmaz veya uydurulmaz.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/package_release.sh, scripts/generate_sbom.py, docs/release-checklist.md, RELEASE_NOTES.md, .github/workflows/release.yml
**Bağımlılıklar:** CS3-CH06-S01-U001

### CS3-CH06-S02-U002 — Desteklenen platform sözünü gerçek paket testine bağla

**Sonuç:** Linux dışı platformların destek durumu fiilen çalışan artifact testine göre açıklanır.

**Kabul:**

- Windows/macOS dahil destek ilan edilen her platform exact artifact first-scan çalıştırır.
- Eksik runner/signer/authorization başarılı sayılmaz; açık blocker olarak kalır.
- Yerel branch senkronizasyonu main merge veya release yetkisi değildir.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** .github/workflows/windows.yml, .github/workflows/release.yml, docs/windows-support.md, README.md, docs/release-checklist.md
**Bağımlılıklar:** Yok

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH07 — Teslim ve kapanış
