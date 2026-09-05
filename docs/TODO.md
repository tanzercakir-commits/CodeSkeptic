# CodeSkeptic — FIFO TODO

Tek yürütülebilir iş aşağıdaki FRONT'tur. İç kuyruk chapter chapter açılır; POP ancak exact-head bağımsız PASS sonrası yapılır. BOOK.json ile byte eşitliği guardrail tarafından doğrulanır.

## FRONT — CS3-CH01-S06-U002

### CS3-CH01-S06-U002 — Ortak integer literal ve guard çözümünde unsigned değeri koru

**Sonuç:** Paylaşılan interval literal/guard çözümünde unsigned sabitin gerçek değeri korunur; sahte negatif değerle erişilebilirlik veya kapasite kanıtı üretilmez.

**Kabul:**

- Unsigned 32-bit literal ve local initializer zincirinin negatif signed değere dönüştüğü hata önce değişikliksiz RED ile doğrulanır; doğrudan değer ve consumer branch guard ayrı sınanır.
- Signed/unsigned 32/64/128 literal ve cast sınırları gerçek AST türüyle değerlendirilir; int64 modeline sığmayan değer unknown kalır, düşük bitlere veya negatif değere sessiz daraltılmaz.
- INT64_MIN/MAX, karşılaştırma guard'ı, allocation boyutu ve kaynak/hedef bounds kontrollerinde mevcut pozitif ve güvenli negatifler korunur; bütün unsigned aritmetiğin çözüldüğü iddia edilmez.
- Ortak literal/guard üreticisi değişikliği tam Linux suite ve ilgili sayı/bounds corpus dilimi ile doğrulanır; gerçek CLI kapsamı ve bağımsız exact-head PASS gereklidir.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/engine/IntervalEval.cpp, src/engine/IntervalEval.h, tests/IntervalAnalysisTest.cpp, tests/BoundsRuleTest.cpp, tests/IntOverflowRuleTest.cpp, tests/AllocSizeOverflowRuleTest.cpp
**Bağımlılıklar:** CS3-CH01-S02-U002

### CS3-CH01-S06-U003 — accept ailesinin wrapper sahipliğini ortak özette koru

**Sonuç:** accept/accept4 çağrısından dönen sahiplik ortak function summary üzerinden caller'a taşınır; wrapper arkasındaki sızıntı kaybolmaz.

**Kabul:**

- S04-U001 sırasında gerçek CLI ile görülen accept-returning wrapper eksikliği önce değişikliksiz RED ile doğrulanır; doğrudan native çağrı pozitif kontrolü aynı fixture'da bulunur.
- Gerçek C/C++ accept/accept4 imzaları, tek ve çok katlı return wrapper'ları ve caller close/leak ayrımı modellenir; dinlenen descriptor borrowed kalır, -1 yalnız başarısızlıktır.
- Yalnız isim eşleşen method/namespace/yanlış prototip ve owned olmayan constant-return fonksiyonlar otomatik owned sayılmaz; ortak producer tanımı ile FdResourceRule sözleşmesi ayrışmaz.
- Mevcut open/socket/dup, FILE/DIR, summary model/conflict ve cross-TU davranışları tam Linux suite ve ilgili ownership corpus/gerçek CLI diliminde korunur; çalışma dışı kod donor olarak kopyalanmaz.

**Test bütçesi:** T2
**Kontroller:** linux-suite, relevant-corpus, queue-check
**Kapsam:** src/engine/FunctionSummary*, src/rules/FdResourceRule*, tests/InterproceduralTest.cpp, tests/FdResourceRuleTest.cpp, tests/MemoryLeakRuleExTest.cpp
**Bağımlılıklar:** CS3-CH01-S04-U001

## Sonraki chapter kuyruğu — henüz yürütülemez

- CH02 — Güvenilir analiz girdisi ve kapsam
- CH03 — CWE bulgularını kullanılabilir ürüne dönüştürme
- CH04 — Sınırlı kaynakla dayanıklı çalışma
- CH05 — Toplu doğrulama ve endüstriyel kabul
- CH06 — Paketleme ve dağıtım
- CH07 — Teslim ve kapanış
