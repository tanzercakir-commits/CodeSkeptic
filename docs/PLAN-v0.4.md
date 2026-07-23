# CodeSkeptic — Dış Eleştiri Yanıt Planı (v0.4 Turu)

> **DURUM (2026-07-22 gece):** Faz 0 ✔ · Faz 1 ✔ (v0.4.0 yayında) ·
> Faz 3 Claude-tarafı ✔ (3a raporlar kullanıcıda) · Faz 4a ✔ ·
> Faz 2 ✔✔ (2c int-overflow, 2b kopya-taint + interproc zeroness,
> 2a bayrak-constprop + çağrı-bayrağı/kopya kapanışı, 2d thesis gate
> CI'da —
> ölçümler benchmarks.md'de; 2d thesis-gate ile derin dilimler
> [sabit-dönüş bayrakları, zeroness-özet birleşmesi] sonraki tura
> devredildi ve guard dosyalarında belgeli). v0.4.1 bu turun kapanış
> sürümüdür.
>
> **Faz 5 (plan-dışı, 2026-07-22): gerçek-dünya FP turu ✔ — v0.4.3.**
> realworld.yml taramaları 37 FP çıkardı; ALTI kök neden kapatıldı
> (madenci entailment'ı, üye fact anahtarları, ima payload'ları,
> getaddrinfo kontratları, madenci slot disiplini, scanf genişlik +
> bounds strlen tanıklığı). CI-doğrulamalı sonuç: libgit2 61→34
> (kararlı çekirdek birebir), rtp2httpd 12→0. 683 test; ayrıntı
> devlog/changelog.md 2026-07-22. v0.4.3 bu turun kapanış sürümüdür.

Tarih: 2026-07-22 · Girdi: dış AI değerlendirmesi (`CodeSkeptic_plan.txt`) · Repo durumu: `main @ 4c62bde`, 158 commit, v0.3.0

Bu plan, dış değerlendirmedeki her maddeyi repo'daki gerçek durumla doğrulayıp, geçerli bulunanları faz faz işe çeviriyor. Her fazda her zamanki disiplin geçerli: iş → test → koruma (guard) → bitti kriteri (Definition of Done, DoD).

---

## A. Eleştirinin dürüst değerlendirmesi

Önce hüküm: eleştiri gerçekten isabetli. Benim doğrulamamda da ~%90–95'i repo gerçekleriyle birebir örtüşüyor. Madde madde:

| # | Eleştiri | Repo'daki gerçek | Hükmüm | Faz |
|---|----------|------------------|--------|-----|
| 1 | Kapsam dar, recall düşük; mevcut araçların yerine değil yanına | Juliet'te div-by-zero recall 0.095, int-overflow 0.010 (örneklemli), memory-leak precision 0.716 — README'nin kendi tablosu. "Yanına koyun" konumlandırması metinde ima ediliyor ama açık bir "neyi yakalamaz / neyin yerine geçmez" bölümü YOK | **Doğru** | Faz 0 (konumlandırma) + Faz 2 (recall/gürültü) |
| 2 | Kurulum sürtünmesi yüksek: kaynaktan derleme, LLVM dev kütüphaneleri, tek binary yok | Doğrulandı: v0.2.0 ve v0.3.0 release'lerinde **binary asset yok** (yalnız source tarball). Dockerfile yok, paketlenmiş GitHub Action yok, Homebrew formülü yok | **Doğru — en yüksek kaldıraçlı madde** | Faz 1 |
| 3 | Windows "plan only" | Doğru: `docs/windows-support.md` gereksinimleri kayıt altına almış, kod yazılmamış. Eleştirinin kendisi de "Windows-only geliştirici beklesin" diyor — yani tam port bu haftanın işi değil; ama içinde 30 dakikalık gerçek bir düzeltme saklı (SARIF sürücü-harfi hatası, aşağıda) | **Doğru; sıralaması tartışılır** | Faz 4 (kademeli) |
| 4 | Dış doğrulama sınırlı: 1 star, 0 fork; ölçümler self-reported | Doğru ve doğal (repo günler önce public oldu). Asıl aksiyon alınabilir kısım: libgit2 (11 OOM-path leak), rtp2httpd ve Redis upstream rapor taslakları HAZIR ama henüz DOSYALANMAMIŞ (ROADMAP §5). Ölçümler ise zaten tek komutla tekrarlanabilir (`run_juliet.sh`, `run_corpus.sh`) — bunu kimse bilmiyor çünkü belgelenmemiş | **Doğru; kısmen sunum sorunu** | Faz 3 |
| 5 | README fazla uzun; ilk 5 dakika soruları gömülü | Doğrulandı: README 742 satır. Kurulum (Building) 312. satırda başlıyor; token-ekonomisi bölümü 67. satırda, yani Rules tablosundan bile ÖNCE. Eleştirinin önerdiği lede ("Real C/C++ bugs, deterministic dataflow traces, low-noise PR gating") repo'nun gerçek kanıtlarıyla birebir örtüşüyor | **Doğru** | Faz 0 |
| 6 | Token tasarrufu iddiası ikinci katmana inmeli | Katılıyorum — silinmesin, taşınsın. MCP/ajan entegrasyonu projenin uzun vadeli tezi; ama ilk ekranın işi güven vermek, tez anlatmak değil | **Doğru** | Faz 0 |

### Katılmadığım / nüans eklediğim ~%5

1. **Juliet int-overflow 0.010 "düşük recall" olarak okunuyor** — ama bu belgelenmiş, bilinçli bir FN (false negative): rand-source ailesi sink'e interval evaluator'ın katlayamadığı bir bit-shuffle makrosuyla ulaşıyor; precision 1.000 korunarak sessiz kalınmış. Projenin asıl görev ekseni (AI first-draft kodu) için ölçü Juliet değil, kör AI corpus'u: orada recall 0.625 @ precision 1.000. Yani buradaki iş "Juliet skorunu kurtarmak" değil, **iki ekseni (Juliet=olgun kod, thesis corpus=first-draft) okuyucuya görünür kılmak** + adreslenebilir FN'leri kapatmak. Faz 2'de bu ayrım korunuyor.
2. **Star/fork sayısı doğrudan aksiyon alınamaz** — üretilebilir olan kanıt ve sürtünmesizlik. Faz 1+3 bunu üretir; duyuru (Show HN / r/cpp) senin kararın (Bölüm F).
3. **"Bir saatlik deneme" akışı** (eleştirideki 9 adım) aslında ürünün hedef onboarding'i olmalı — bunu eleştiri olarak değil, Faz 0'ın kabul testi olarak kullanacağız: README'nin ilk ekranı o deneyi kopyala-yapıştır yapılabilir hale getirmeli.

---

## B. Bu turun hedefi (DoD)

Tur sonunda dışarıdan bakan aynı değerlendirici şu satırları yazamıyor olmalı:

- "Tek binary indirip beş dakikada deneyeyim diyen kullanıcı: onboarding henüz yeterli değil" → **kurulumdan ilk SARIF raporuna < 5 dakika**. Bu haftanın garantili yolu Docker (konteyner, header-taşıma sorunu yok); yerel binary, resource-dir taşınabilirliği çözüldüğü an eklenir (Faz 1a'da dürüst kapsamı var).
- "Cevaplar büyük bir teknik savunmanın içine gömülü" → README ≤ 300 satır (hedef ~250), ilk ekranda 5 sorunun 5'i.
- "Benchmark sonuçları proje sahibinin ölçümleri" → `docs/reproduce.md`: her tablo için tek komut; + dosyalanmış 2–3 yeni upstream rapor; + `docs/evaluate.md`: eleştirmenin 9 adımlık deneme akışının ürün belgesi hali ("kendi kodunda 1 saatte değerlendir").
- Puan hedefi (aynı rubrikle öz-değerlendirme): Kurulum 4→8, Platform 4→5 (Windows dürüstçe ertelenmiş ama SARIF hatası ölü), Dış doğrulama 3→5; kapsam 5→6 ise **Faz 2 gerçekleşirse** — kesme çizgisi altında kalırsa bu hedef bir sonraki tura devreder (Bölüm D).

---

## C. Faz ağacı (genel bakış)

```
FAZ 0  Karşılama katmanı (README mimarisi + konumlandırma)     [düşük efor / en hızlı algı kazancı]
 ├─ 0a README'yi ~250 satıra indir: quickstart ilk ekrana
 ├─ 0b "What it won't catch" + "Use alongside" dürüstlük blokları
 ├─ 0c Derin içerik docs/'a: benchmarks.md, comparison.md, token-ablation zaten var
 ├─ 0d Kök temizliği: ROADMAP/changelog devlog'unu docs/devlog/'a taşı (kota bombası, bkz. Bölüm E)
 └─ 0e Ufak tefek: çift lisans satırı, rozet düzeni
FAZ 1  Sürtünmesiz kurulum (packaging)                          [orta efor / eleştirinin ana maddesi]
 ├─ 1a release.yml: tag → Linux x86_64 + macOS arm64 binary asset
 ├─ 1b Dockerfile + ghcr.io imajı (tek komut deneme)
 ├─ 1c action.yml: uses: tanzercakir-commits/CodeSkeptic@v0 (SARIF upload dahil)
 └─ 1d (ops.) Homebrew tap
FAZ 2  Kural kalitesi (motor işi)                               [yüksek efor / kota yeterse]
 ├─ 2a memory-leak precision 0.716 → FP taksonomisi + hedefli düzeltme
 ├─ 2b div-by-zero: FN sınıflandırması (adreslenebilir/float/opak) → adreslenebilirleri kapat
 ├─ 2c int-overflow: sınıflandır → A) makro-katlama  B) narrow-by-design belgele (karar noktası)
 └─ 2d Thesis recall gate'ini CI'a bağla (mission ekseninin kalıcı guard'ı)
FAZ 3  Ekosistem kanıtı (çoğu senin insan-işin, kota harcamaz)  [düşük Claude eforu]
 ├─ 3a Hazır taslakları dosyala: libgit2 (11 leak), rtp2httpd, Redis
 ├─ 3b docs/reproduce.md: "sayılarımızı kendin üret" — tablo başına tek komut
 ├─ 3c profiles/ dizini: systemd/libgit2/llama idiom profilleri (.conf)
 └─ 3d CONTRIBUTING.md + issue şablonları + 3-5 good-first-issue tohumu
FAZ 4  Windows (kademeli — bu hafta yalnız ucuz kısmı)
 ├─ 4a ŞİMDİ: SarifReporter.cpp:39 mutlak-yol düzeltmesi (C:\ ve \\ UNC) + test
 └─ 4b SONRA (ayrı tur): vcpkg LLVM build lane → CI build-only → SDK keşfi → binary
FAZ 5  (yedek) Performans görünürlüğü: corpus koşularına süre ölçümü + yumuşak eşik
```

Sıralama gerekçesi: Faz 0+1 eleştirinin 4/10 verdiği iki alanı vurur — düşük risk, motor koduna dokunmaz, algıyı en hızlı değiştirir. Faz 2 en pahalı iş; kota durumuna göre ölçeklenir. Faz 3'ün yarısı Claude kotası hiç harcamaz (rapor dosyalamak senin işin) ve Faz 1'e paralel yürür.

---

## FAZ 0 — Karşılama katmanı

**Amaç:** İlk 5 dakikada 5 sorunun cevabı ilk ekranda: nasıl kurarım / nasıl çalıştırırım / ne verir / neyi yakalamaz / neden mevcut araçlarıma eklemeliyim.

**İşler:**

1. README yeni iskeleti (~250 satır hedef):
   - Başlık + tek cümle lede: *"Real C/C++ bugs, deterministic dataflow traces, low-noise PR gating"* ekseni (eleştirinin önerisi; repo kanıtlarıyla örtüşüyor).
   - **Quickstart** (Faz 1 bitince binary/Docker komutu; o güne dek apt+cmake'in 4 satırlık en kısa hali) + `docs/demo.c` üzerinde beklenen çıktı bloğu.
   - Kanıt vitrini: gerçek dünya tablosu (systemd 414→53, shadPS4 2 merge, …) + 2 upstream PR linki — bunlar en güçlü güven sinyali, yukarı taşınıyor.
   - **What it won't catch** (dürüstlük bloğu): recall sınırları, Juliet vs first-draft ekseni, "bulgu yoksa kod güvenli demek değildir".
   - **Use it alongside, not instead**: compiler warnings / sanitizers / clang analyzer / `-fanalyzer` / CodeQL / fuzzing tamamlayıcılık tablosu — eleştirinin 1. maddesinin doğrudan cevabı.
   - Rules tablosunun kısa hali + Juliet/AI-corpus özet skorları (3–4 satır) → detay `docs/benchmarks.md`'ye.
   - Token-ekonomisi: 1 kısa paragraf + `docs/token-ablation.md` linki (**ikinci katmana iner**, silinmez).
   - Kullanım/incremental/MCP/kontrat bölümlerinin özetleri + `docs/` linkleri.
2. Taşınan içerik: `docs/benchmarks.md` (Juliet metodolojisi + tablo + okuma notları), `docs/comparison.md` (araç karşılaştırma + MSVC/cppcheck dipnotu), `docs/integrations.md` (VS Code, code scanning YAML, MCP ayrıntısı).
   - Yeni: `docs/evaluate.md` — eleştirmenin 9 adımlık deneme akışı ürün belgesine dönüşür: kendi projenden 10–30 TU (translation unit) seç, gerçek `compile_commands.json` kullan, memory-leak'i ayrı değerlendir (en gürültülü kuralımız — kendi uyarımız), HTML/SARIF üret, trace'leri elle doğrula, clang analyzer / `-fanalyzer` ile karşılaştır, **ilk hafta CI'ı bloklatma (report-only)**, 10 bulgudan 7–8'i anlamlıysa `review_diff.sh` veya MCP'yi bağla. Eleştiriyi onboarding'e çevirmenin en doğrudan yolu.
3. Kök temizliği: `ROADMAP.md` (1 494 satır) ve `changelog.md` (2 928 satır) → `docs/devlog/`'a; kökte 60–80 satırlık küratörlü `ROADMAP.md` kalır (mevcut §1–§5 özetinden). Git geçmişi korunur (`git mv`).
4. Ufak tefek: README sonundaki çift "Apache License 2.0" satırı; platform rozetinden `docs/windows-support.md`'ye link.

**Testler:** README quickstart bloğundaki komutları ayıklayıp temiz Ubuntu konteynerde aynen çalıştıran CI adımı (doc-test) — kopyala-yapıştır kurulum her PR'da kanıtlanır. Taşınan dosyalar için link bütünlüğü kontrolü (kırık göreli link = fail; basit `lychee` ya da grep tabanlı script).

**Guard'lar:** `scripts/check_readme.sh` — satır bütçesi (≤300 uyarı eşiği) + zorunlu bölüm başlıkları (Quickstart, What it won't catch, Use alongside) mevcut mu; CI'da koşar. Bu, README'nin yeniden şişmesine karşı kalıcı fren (eleştiri bir daha yazılamasın diye).

**DoD:** 5 soru ilk ekranda; README ≤ 300 satır; doc-test ve link kontrolü yeşil; `docs/evaluate.md` yayında; hiçbir içerik silinmedi, yalnız katmanlandı.

**Efor:** 1 oturum. Motor koduna dokunulmaz — risk ~0.

---

## FAZ 1 — Sürtünmesiz kurulum (packaging)

**Amaç:** "Tek binary indirip beş dakikada deneyeyim" kullanıcısı beş dakikada ilk raporu görsün.

**İşler:**

1. **1a `release.yml`:** tag push → build → binary asset. Dürüst kapsam: bunun bilinen-zor kısmı derleme değil, **taşınabilirlik** — iki somut engel ve çözümü:
   - *LLVM link modu:* dağıtım paketine göre statik `.a` ya da `libLLVM.so` gelebilir; release lane'i statik LLVM'i zorlar (ya da `libLLVM.so`'yu tarball'a koyar) + `-static-libstdc++ -static-libgcc`; `ldd` çıktısı release notuna eklenir.
   - *Resource-dir taşınması:* build sırasında mutlak `CLANG_RESOURCE_DIR` gömülüyor — kullanıcının makinesinde o yol yok. Çözüm: tarball yapısı `bin/codeskeptic` + `lib/clang/<ver>/include`, çalışma anında binary'e GÖRELİ keşif (+ ortam değişkeni/bayrakla override). Clang tabanlı araçların klasik zorlu noktası; bu yüzden **binary bu haftanın "hedefi", Docker (1b) "garantisi"** — binary gecikirse hafta başarısı etkilenmez.
   - Runner: `ubuntu-22.04` + apt.llvm.org LLVM 20 (22.04 arşivinde llvm-20-dev yok; eski glibc = geniş uyumluluk) — ya da pragmatik geri çekilme: 24.04'te derle, "glibc ≥ 2.39 gerekir" diye açıkça yaz. macOS arm64: `macos-14` + brew llvm.
   - Asset adlandırma: `codeskeptic-v0.4.0-linux-x86_64.tar.gz` (+ `sha256sums.txt`).
2. **1b Dockerfile + ghcr.io:** multi-stage build; final imajda binary + LLVM runtime + temel sistem başlıkları. Kullanım: `docker run --rm -v $PWD:/work ghcr.io/tanzercakir-commits/codeskeptic /work/src --sarif /work/out.sarif`. `latest` + sürüm tag'i; imaj boyutu release notunda. Caveat belgelenir: konteyner kendi sistem başlıklarını kullanır; gerçek projede `compile_commands.json` mount etmek doğru yol.
3. **1c `action.yml`** (composite action): release binary'sini (o güne dek: Docker imajını) çeker, analiz eder, istenirse `github/codeql-action/upload-sarif` ile Security sekmesine yükler. Kritik tasarım: `gate` girdisi **varsayılan `report-only`** — eleştirmenin deneme akışındaki 8. adım ("ilk aşamada CI'ı bloklatmaz, yalnız rapor toplardım") ürünün varsayılanı olur; bloklamak bilinçli tercihle açılır (`gate: error`), analizördeki `--gate warn` felsefesinin aynısı. README'deki 30 satırlık elle-yazılmış YAML'ın CodeSkeptic tarafı 6 satıra iner (projenin kendi `compile_commands.json` üretimi doğal olarak kullanıcıda kalır). Marketplace listelemesi opsiyonel tek tık (Bölüm F).
4. **1d (ops.) Homebrew tap:** `homebrew-codeskeptic` reposu + formula (source build, brew llvm bağımlılığı). Konfor kazancı güzel ama binary+Docker'dan sonra marjinal — hafta sıkışırsa atlanır.

**Testler:** Release workflow'u içinde kurulum entegrasyon testi: üretilen asset'i TEMİZ bir konteynere indir → `docs/demo.c`'yi analiz et → 3 bilinen bulgu + exit code 1 bekle. Docker imajı için aynı smoke. Action için self-test job: action bu repoda kendi üzerinde koşar.

**Guard'lar:** Release, smoke yeşil olmadan YAYINLANMAZ (workflow sırası: build → smoke → upload; draft release ancak smoke sonrası publish). `--version` çıktısı tag ile eşleşmeli (mevcut `--version` bayrağı var; CMake `project(VERSION)`'dan beslendiği workflow'da assert edilir) — sürüm kayması ölür.

**DoD:** Temiz makinede `curl → tar → ./codeskeptic demo.c` VE `docker run` yolu < 5 dk; action.yml ile 6 satırda PR gate; README quickstart bu komutlara güncellenir (Faz 0'ın bloğu).

**Efor:** 2–3 oturum (release workflow'ları CI üzerinde birkaç deneme-yanılma turu ister; bu normaldir).

---

## FAZ 2 — Kural kalitesi (motor işi)

**Amaç:** Eleştirinin veri destekli üç sayısını hedefli iyileştirmek — precision felsefesini bozmadan.

**İşler:**

1. **2a memory-leak (precision 0.716, "the one noisy rule"):**
   - Juliet case-FP'lerini + corpus kalıntılarını (systemd 53, llama 25) dök → FP taksonomisi (aile aile sınıflandırma; bu, targeted path-sensitivity turunda 235-bulguluk tek-kök-neden yakalayan mevcut yöntemin aynısı).
   - En büyük 2–3 aileye hedefli motor düzeltmesi; her düzeltme = pinned test + `juliet_expected.txt`/`corpus_expected.txt` floor'ları AYNI PR'da güncellenir (mevcut süreç korunur).
   - Hedef bandı: rule precision 0.716 → ≥0.80 (recall floor'u düşürmeden). Ölçmeden söz vermiyoruz; taksonomi çıkınca hedef netleşir.
2. **2b div-by-zero (Juliet recall 0.095):**
   - Önce `juliet_eval.py`'a FN sınıflandırıcısı: her kaçan vakayı {float-division (bilinçli sessiz), opak kaynak (rand/socket — dürüst analizör sıfır diyemez), ADRESLENEBİLİR (struct alanı akışı, çağrı zinciri, 61-ailesi sparse flow)} olarak etiketle.
   - Adreslenebilir dilimi kapat (muhtemel araçlar: alan-duyarlılığı (field sensitivity) genişletmesi, summary'lere sıfırlık (zeroness) taşınımının eksik kalıpları).
   - Raporlama dürüstlüğü: README/benchmarks'ta ham recall'un yanına "adreslenebilir-recall" satırı — hem sayı iyileşir hem metodoloji şeffaflaşır.
3. **2c int-overflow (0.010):** aynı sınıflandırma; sonra karar noktası (Bölüm F): (A) bit-shuffle makro ailesini interval evaluator'da katla (maliyetli, FP riski) vs (B) narrow-by-design ilan et, `docs/benchmarks.md`'de belirgin belgele ve AI-corpus ekseniyle ölç. Ön eğilimim B + A'nın ucuz alt kümesi; veri karar verdirir.
4. **2d Thesis recall gate CI'a:** kör AI corpus'u (24 program) şu an elle koşuluyor; `scripts/run_thesis.sh` + pinned beklentiler (`thesis_expected.txt`) olarak haftalık CI'a eklenir. Böylece görev ekseninin (first-draft recall) kalıcı guard'ı olur — Juliet floors'un misyon-tarafı ikizi.

**Testler:** Her motor değişikliği pinned birim testi + Juliet PR-guard (CWE başına 400 dosya) + corpus pins. FN sınıflandırıcısının kendisi için de birim test (etiketleme yanlışsa metrik yalan söyler).

**Guard'lar:** Mevcut üçlü hakem zaten dünya standardında: Juliet floors + corpus pins (10%+2 tolerans) + self-scan dogfood. Bu faz onlara `thesis_expected.txt`'yi ekler. Floor güncellemesi yalnız aynı PR'da, gerekçesi commit mesajında — mevcut kural aynen.

**DoD:** Leak FP taksonomisi belgelendi + ≥1 aile kapandı; div FN sınıflandırması yayında + adreslenebilir dilimde ölçülür iyileşme; int-ovf kararı verildi ve belgelendi; thesis gate CI'da.

**Efor:** 3–5 oturum (en pahalı faz; 2a/2b bağımsız oturumlara bölünür, kota biterse tur devrine kalan tek faz budur).

---

## FAZ 3 — Ekosistem kanıtı

**Amaç:** "Self-reported" algısını kırmak: bağımsız doğrulanabilirlik + upstream kanıt.

**İşler:**

1. **3a (SENİN işin, kota harcamaz):** hazır taslak raporları dosyala — libgit2 (11 OOM-path leak, tek issue sınıfı), rtp2httpd (NULL-contract), Redis. Sonuçları README trophy tablosuna işle. shadPS4'teki 2 merge'ün yanına her yeni kabul, eleştirinin 3. maddesini doğrudan eritir.
2. **3b `docs/reproduce.md`:** tablo başına tek komut — Juliet (`run_juliet.sh`), corpus (`run_corpus.sh`), token ablation (`token_ablation.py`), araç karşılaştırması (demo.c + hangi bayraklarla). Altyapı ZATEN var; eksik olan tek sayfa belge.
3. **3c `profiles/` dizini:** kampanyada üretilen idiom konfigürasyonları (`systemd.conf`, `libgit2.conf`, `llama.conf`, `fprime.conf`) — ROADMAP §4.C'deki "idioms are configuration" içgörüsünün paketlenmesi. Düşük efor, yüksek güvenilirlik sinyali.
4. **3d Katkı kapısı:** `CONTRIBUTING.md` (build + test + üç-hakem süreci anlatımı), issue/PR şablonları, 3–5 `good first issue` tohumu (örn. FN sınıflandırıcı etiket ekleme, profil ekleme — gerçekçi ilk katkılar).

**Testler/Guard'lar:** `reproduce.md` komutları da doc-test kapsamına girer (en azından smoke seviyesinde). Profiller için gerçekçi doğrulama: anahtarları `Config`'in tanıdığı sözlüğe karşı doğrulayan küçük bir format kontrolü CI'a girer (`profiles/` altındaki her `.conf` parse edilebilir + bilinmeyen anahtar yok); corpus'ta koşarak doğrulama YAPILMAZ — CI corpus'u cJSON+tinyxml2, profillerin projeleri (systemd, libgit2, …) orada yok ve o build'leri CI'a eklemek bu haftanın işi değil.

**DoD:** ≥2 yeni upstream rapor dosyalanmış; reproduce.md yayında; profiles/ + CONTRIBUTING yayında.

**Efor:** 1 oturum Claude işi + senin rapor dosyalama zamanın. Faz 1 CI koşularını beklerken araya mükemmel sığar.

---

## FAZ 4 — Windows (kademeli)

**Amaç:** Bu hafta yalnız ucuz-ve-gerçek kısmı; tam port ayrı tur (eleştiri de "beklesin" diyor — erteleme dürüst, gizli değil).

**İşler:**

1. **4a ŞİMDİ:** `SarifReporter.cpp:39` mutlak yol sınıflandırması yalnız `path[0]=='/'` — sürücü harfi (`C:\`) ve UNC (`\\`) eklenir + birim test. Windows'ta üretilmemiş olsa bile Windows yollu compile_commands ile beslenen SARIF tüketicileri için bugünkü gerçek hata; `docs/windows-support.md` §4'ün kapanışı.
2. **4b SONRA (ayrı tur, Bölüm F kararı):** windows-support.md'deki sıra: vcpkg/choco LLVM lane → `if(MSVC)` bayrak koruması (`/GR-`, `/bigobj`) → CI build-only job → SDK header keşfi (`vswhere`/`INCLUDE`) → binary. Her adım kendi guard'ıyla (build-only yeşil kalmadan sonraki adım açılmaz — ratchet).

**DoD (bu hafta):** 4a merge'lendi; README platform satırı windows-support.md'ye link veriyor.

**Efor:** 4a: 0.5 oturum (Faz 1 oturumlarından birine binebilir).

---

## FAZ 5 — (Yedek) Performans görünürlüğü

Corpus koşularına duvar-saati ölçümü (`CORPUS_TIME` satırı) + yumuşak eşik (2× yavaşlama = sarı uyarı, kırmızı değil). "Milisaniyede re-check" iddiasının sayısal sigortası. Hafta sıkışırsa sonraki tura devreder — eleştiride karşılığı yok, bizim iç kalite maddemiz.

---

## D. Haftalık program (bugün: Çarşamba 22 Tem)

```
Çar 22  ► Bu plan + onayın. Akşam: FAZ 0 oturumu (README mimarisi)          [Sonnet katmanı]
Per 23  ► FAZ 1a+1b (release.yml + Docker) — CI deneme turları              [Sonnet katmanı]
        ► CI beklerken paralel: SEN 3a raporlarını dosyalarsın (kota: 0)
Cum 24  ► FAZ 1c (action) + 4a (SARIF fix) + FAZ 3b/3c/3d                   [Sonnet katmanı]
        ► Hedef: v0.4.0 tag + release — Docker yolu kesin, binary asset
          resource-dir işi yetişirse (yetişmezse Cmt sabahı tampon; 1a
          "hedef", 1b "garanti")
Cmt 25  ► FAZ 2a (leak FP taksonomisi → düzeltme PR'ları)                   [taksonomi: Sonnet,
                                                                             motor fix: üst katman]
Paz 26  ► FAZ 2b (div FN sınıflandırıcı + adreslenebilir dilim) + 2d        [motor: üst katman]
        ► Hafta kapanışı: 2c kararı + duyuru kararı (Bölüm F)
```

Kota erken biterse kesme çizgisi net: **Faz 0+1+3+4a bitmişse tur başarılıdır** — eleştirinin 4/10'luk iki alanı ve dış-doğrulama maddesi kapanmış olur; Faz 2 bir sonraki kota haftasının ilk işi olarak devreder (planın bu dosyası repo'ya commit'lenir, kaldığı yer bellidir).

---

## E. Model ve kota stratejisi

Dürüst ön not: kota sayaçlarını ben göremiyorum ve model adları/sürümleri değişebiliyor — o yüzden katman mantığıyla anlatıyorum; oturum açarken listende hangi adlar varsa bu katmanlara eşlersin.

**Katman eşlemesi:**

| Katman | Ne zaman | Bu plandaki işler |
|--------|----------|-------------------|
| Üst katman (Fable/Opus sınıfı, gerekirse max effort) | Tasarım kararları, motor (engine) değişiklikleri, lattice/transfer function işi, çetin FP/FN hükümleri | Faz 2a'nın motor düzeltmeleri, 2b'nin summary/interval genişletmeleri, 2c kararı; plan revizyonları |
| Orta katman (Sonnet sınıfı) — **haftanın iş atı** | İskeleti belli, geri bildirimi CI'dan gelen her iş | Faz 0 (README/docs taşıma), Faz 1'in tamamı (YAML/Docker/action), Faz 3, 4a, testlerin çoğu |
| Alt katman (Haiku sınıfı) | Gerçekten mekanik yığın işler | Link düzeltme, dosya taşıma doğrulaması, şablon doldurma — pratikte Sonnet oturumunun içinde halletmek çoğu kez daha az tur = daha az token |

**Kota taktikleri (etkisi model seçiminden büyük):**

1. **Oturum başına tek faz, oturuma dar giriş:** her oturumu "repo'daki `docs/PLAN-v0.4.md` Faz N'i uygula" diye aç. Plan repo'da olduğu için modele geçmişi yeniden anlattırmazsın.
2. **Bağlam bombalarını okutma:** `ROADMAP.md` 1 494 satır, `changelog.md` 2 928 satır — bir coding-agent oturumuna yanlışlıkla girerlerse tek başına ciddi token yakar. Faz 0d'nin `docs/devlog/`'a taşıma işi aynı zamanda bir **kota optimizasyonu**: kökte kalan kısa ROADMAP her oturumun sabit maliyetini düşürür.
3. **CI'ı bilek gücü yerine kullan:** release workflow denemelerinde logu komple yapıştırma; yalnız failing adımın son ~50 satırı. Testler lokalde koşup yalnız kırmızıları göster.
4. **Uzun otonom turlar yerine kısa hedefli turlar:** "şu üç dosyayı oluştur, CI'a it, sonucu bekle" netliğindeki istekler, "packaging'i hallet" serbestliğinden hem ucuz hem isabetli.
5. **Fazlar arası model düşür:** Faz 1 YAML'ı için üst katmana gerek yok; üst katmanı Cmt/Paz motor günlerine sakla. Hafta sonu kota daralmışsa Faz 2a'nın taksonomi (ucuz, okuma-ağırlıklı) kısmını yap, motor değişikliğini yeni kota haftasına bırak.

---

## F. Karar noktaları (senin onayın)

1. **Duyuru:** v0.4.0 (binary'li sürüm) çıktıktan sonra Show HN / r/cpp / lobste.rs paylaşımı yapılsın mı, yoksa 2–3 upstream kabul daha mı beklensin? (Önerim: Faz 0+1 bitmeden ASLA; bittiğinde erken paylaşım lehine — ilk izlenim artık hazır.)
2. **2c int-overflow:** sınıflandırma verisi geldiğinde A (makro katlama) / B (narrow-by-design belgeleme) kararı.
3. **Windows 4b:** gelecek tura mı, yoksa bu hafta beklenmedik boşluk kalırsa build-only lane denemesi mi? (Önerim: gelecek tur — bu haftanın kotası packaging+motora gitsin.)
4. **1d Homebrew:** hafta sıkışırsa atlanacak ilk madde — itirazın var mı?

---

## G. Kapsama matrisi (eleştiri → plan)

| Eleştiri cümlesi/maddesi | Plandaki karşılığı |
|--------------------------|--------------------|
| "Mevcut araçların yerine değil yanına" + şunları değiştirmezdim listesi | Faz 0b "Use it alongside" tablosu + "What it won't catch" bloğu |
| Recall düşük (div 0.095, int-ovf 0.010), leak gürültülü | Faz 2a/2b/2c + 2d thesis gate; nüans Bölüm A-1 |
| "Bulgu yokluğu ≠ güvenli" | Faz 0b dürüstlük bloğunda açık cümle |
| Kaynaktan derleme zorunlu, LLVM dev gerek | Faz 1a binary, 1b Docker, 1c action, 1d brew |
| "Tek binary indirip 5 dakikada deneyeyim → onboarding yetersiz" | Faz 1 DoD: <5 dk (Docker garantili, binary hedef); Faz 0 quickstart |
| Windows "plan only" | Faz 4a şimdi (SARIF fix), 4b ayrı tur (karar noktası 3) |
| 1 star / 0 fork / bağımsız kanıt yok | Faz 3a upstream raporlar, 3d katkı kapısı, karar noktası 1 (duyuru) |
| "Benchmark'lar proje sahibinin ölçümü; kendim üretmeden kabul etmem" | Faz 3b reproduce.md (tek komut/tablo) + docs/evaluate.md ("kendi kodunda precision'ı ölç" çağrısının belgesi) |
| README uzun; 5 soru gömülü | Faz 0a yeni iskelet + check_readme guard'ı |
| Token iddiası ilk çekim maddesi olmamalı | Faz 0a: 1 paragraf + docs linki (ikinci katman) |
| "Nasıl denerdim" 9 adımlık akış (10–30 TU, memory-leak ayrı, report-only CI, 7–8/10 → diff/MCP) | `docs/evaluate.md` (Faz 0) adım adım aynı akış; 8. adım ayrıca 1c action'ın varsayılanı (`gate: report-only`) |
| "Tek güvenlik kapısı olarak kullanma: 3/10" | Faz 0b "Use it alongside, not instead" + "bulgu yokluğu ≠ güvenli" cümlesi — bu puanı yükseltmeye çalışmıyoruz, README bunu kendisi söylüyor (dürüstlük eleştirmenin de olumlu bulduğu çizgi) |
| Puan tablosu: kurulum 4/10, platform 4/10, ekosistem 3/10, kapsam 5/10 | Bölüm B hedefleri: 4→8, 4→5, 3→5; kapsam 5→6 Faz 2 koşullu |

Kapsanmayan tek şey star/fork sayısının kendisi — o bizim çıktı değil, sonuç. Plan kanıt ve sürtünmesizlik üretir; sayılar arkasından gelir.
