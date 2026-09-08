# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH06-S02-U001

### CS3-CH06-S02-U001 — Sürüm, checksum, SBOM ve provenance üret

**Sonuç:** Artifact hangi kaynak ve bağımlılıklardan üretildiğini kanıtlarıyla taşır.

**Kabul:**

- Tek authored version source vardır; source SHA ve tool/schema version raporları tutarlıdır.
- Artifact checksum, bağımlılık/lisans listesi ve yeniden üretim komutu kayıtlıdır.
- İmza kimliği yoksa imzalı release iddiası yapılmaz; secret aranmaz veya uydurulmaz.

**Test bütçesi:** T3
**Kontroller:** release-qualification, queue-check
**Kapsam:** scripts/package_release.sh, scripts/generate_sbom.py, docs/release-checklist.md, RELEASE_NOTES.md, .github/workflows/release.yml, scripts/test_generate_sbom.py
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
