# FIFO kullanım kılavuzu

## Bakılacak dosyalar

- PLAN.md: tüm Chapter → Section → Unit kitabı ve kabul/test sınırları.
- TODO.md: yalnız aktif chapter'ın tam görevleri; FRONT tek yürütülebilir iş.
- PROGRESS.md: en yeni tamamlanma üstte; commit ve bağımsız kanıt özeti.
- BOOK.json: aynı kitabın ve kayıtların makinece işlenen tek işlem durumu.
  Üç Markdown dosyası buradan üretilir ve byte-byte karşılaştırılır.

PLAN'ın tamamı kilitli değildir. JSON elle güncellenerek kuyruğa iş sokulmaz;
amend komutu geleceğe yönelik değişikliği gerekçesiyle kaydeder. Eski task ID'leri
silinmez/sıralanmaz, sıradan amend front ve bitmiş işleri değiştiremez. Aktif chapter'a ek iş
ancak mevcut bekleyen işlerin arkasından girebilir. Gelecek chapter'lar henüz
açılmadığından section sonlarına yeni atomik işler eklenebilir.

## Başlatma ve tamamlama

Her iş öncesi `python3 -B scripts/project_queue.py check` ve `status` çalıştır.
Front sözleşmesine göre ayrı dalda uygula; gerekli dar testleri çalıştır. Temiz
implementation commit'ini bağımsız read-only denetçiye ver. Onun PASS kaydını
kanonik JSON olarak repo dışında sakla. Ardından yalnız primary:

```bash
python3 -B scripts/project_queue.py finalize --review /absolute/review.json
git add -- docs/BOOK.json docs/TODO.md docs/PROGRESS.md
git commit -m 'chore(queue): finalize <TASK-ID>'
python3 -B scripts/project_queue.py guard --base HEAD^
```

finalize kendi commit atmaz: tek POP'u hazırlar, üç dosya birlikte commit edilir.
Guard geçmeden DONE duyurulmaz ve sonraki task'a geçilmez. Review SHA tam olarak
ledger commit'inin parent'ı olmalıdır. Sıradaki iş için o ledger commit'inden yeni
task dalı açılır. Bootstrap'ta bağımsız PASS implementation'ı doğrular; ilk gerçek
POP ve guard bunun hemen ardından çalıştırılır, önce yapılmış gibi raporlanmaz.
Son task bitince TODO yalnız terminal açıklaması taşır, işler PROGRESS'tedir.
Terminal kuyruk sıradan amend ile yeniden açılamaz. Aşağıdaki sahibin onayladığı
tek tarihsel devam geçişi aynı sistemi yeni bölümlere bağlar; ikinci TODO yoktur.

İlk main-child bootstrap adayı henüz finalize edilmediyse inceleme bulgularının
düzeltilmesi için `bootstrap` görünümleri yeniden üretebilir; front kabulü aynı
kalır, primary yalnız kendi yayımlanmamış aday commit'ini amend eder. Bu yeni SHA
yeniden bağımsız inceleme ister. İlk POP'tan sonra bu yol kesinlikle kapanır.

Guard/finalize yalnız son commit farkını değil, önceki POP'tan bu yana bütün
implementation commit'lerini kontrol eder. Kapsam dışı değişiklik sonradan geri
alınmış olsa bile gizlenemez. Plan amendment bu geçmişi yeni taban yapıp aklayamaz.

## Bağımsız receipt

Schema: `codeskeptic-review/v1`. Exact alanlar: schema, task_id, head, branch,
contract_sha256, implementer, verifier, verdict, findings, checks. Contract digest
task JSON'unun sorted-key, compact UTF-8, ensure_ascii=false biçimi + tek LF için
SHA-256'dır. Receipt de aynı canonical biçimde saklanır. Verdict PASS ve findings
boş; implementer/verifier farklı run kimlikleri olmalıdır. Her check'te name,
command, result=PASS, sha256 ve absolute evidence dosya yolu bulunur. Görevdeki
bütün check isimleri bulunmalıdır. Evidence mevcut, regular, symlink olmayan,
en fazla 10 MiB ve digest'i doğru dosyadır. Receipt en fazla 64 KiB'dır.
Denetçi gerçek dosyaları, komut çıktısını, RED/GREEN ve risk sınırlarını inceler.
Bu ortak kullanıcı hesabında prosedürel bağımsızlıktır, imza/uzak attestation değil.

### Onaylı tarihsel Abseil kabul checkpoint'i

Sahip, gerçek Abseil taramasında saptanan eski one-past yanlış alarmı için
2026-09-05 tarihinde açık kabul politikası onayı verdi. Yalnız doğrudan parent
`695839b6f99d8c47113482d163eb5d6aca697617`, exact U003 dalı, eski/yeni BOOK
digest'leri ve dokuz kesin dosyaya bağlı tarihsel geçiş kullanılabilir:
BOOK/PLAN/TODO, AGENTS, INVARIANTS, QUEUE_GUIDE, project_queue.py,
test_project_queue.py ve CI_GATES. PROGRESS byte-byte aynı kalır; hiçbir POP,
ürün kodu, scope, check, bütçe, outcome veya başka görev değişmez.

`checkpoint_policy_book` yalnız sabit eski kitaptan önceden belirlenmiş yeni
kitabı hesaplayan saf fonksiyondur; genel bir FRONT düzenleme komutu değildir.
Görünümler mevcut `publish` işlem/journal mekanizmasıyla birlikte hazırlanır.
Primary exact aday commit'ini bağımsız denetletir ve parent guard'ını çalıştırır.
Guard ve geçmiş denetimi aynı dar geçişi doğrular; önceki kapsamı geri yükleyip
önceki POP'a kadar denetime devam eder. Bu noktada geçmiş denetimi kesilmez.
Eski ve bitmiş sözleşmeler yeniden yazılmaz, ordinary amend/scope kilitleri açılmaz.

Bu geçiş yalnız U003'e kesin, bağımsız incelenmiş head semantik farkı kabulünü
ekler. Base manifest/pinleri korunur; head etkin beklentisi ayrı ad/digest taşır.
Kaynak ve regresyon kanıtı, fingerprint çoklu-küme farkı, tam kapsam, üç tekrar,
yeni başarılı exact-head hosted sonuç ve bağımsız ham kanıt denetimi şarttır.
Başarısız eski receipt'ler başarısız kalır. Uygulama dosyaları için daha sonra
normal bağımsız scope-extension gerekir; bu checkpoint ürün PASS'i değildir.

### Onaylı RAII/fdopendir kabul istisnası

Sahip2026-09-07 tarihinde, teşhis edilmiş RAII/fdopendir yanlış alarmlarının
analizde düzeltilmesini açıkça onayladı. Yalnız doğrudan parent
`e4d52748937b39d5b72dd91d64a04d9a85c59fe8` ve
`agent/cs3-ch04-s03-u001-windows-portability` dalındaki tek geçiş kullanılabilir.
Sekiz dosya: BOOK/PLAN/TODO, AGENTS, INVARIANTS, QUEUE_GUIDE, project_queue.py,
test_project_queue.py. Eski/yeni BOOK digest'leri ve saf
`ownership_checkpoint_book` çıktısı exact guard ile doğrulanır. Mevcut işlem
yazıcısı görünümleri birlikte hazırlar; bağımsız exact-head inceleme ve guard
olmadan ürün uygulamasına geçilmez. Önceki Abseil geçişi aynen korunur.

Yalnız FRONT kabulüne dondurulmuş dar istisna ve karar eklenir. PROGRESS byte
eşit kalır; scope, outcome, bütçe/kontrol adları, bağımlılıklar ve sıra değişmez.
Yapıcı/yıkıcı sahipliği kanıtlanmalı, fdopendir başarısızlığında çağıranın
sorumluluğu korunmalıdır. Aynı fonksiyondaki gerçek sızıntıyı gizleyen satır
bastırması veya koşulsuz tüketim/kaçış kabul edilmez. Başarısız eski kanıtlar
başarısız kalır; Linux/Windows kapıları ve kalite eşikleri değişmez.

Bu kayıt tamamlanma değildir. Uygulama dosyaları sonra bağımsız scope-extension
ile eklenir, dar RED/GREEN ve yeni exact-head gerçek kapılar tekrar doğrulanır.
Geçmiş denetimi checkpoint'te durmaz: eski kapsamla önceki POP'a kadar sürer.
Ordinary amend ve extend-scope herhangi bir FRONT kabulünü yeniden yazamaz;
bu tek istisna daha sonra yönetişim değişikliği yapma yetkisi vermez.

### Onaylı ikinci perde — aynı FIFO'da ürün tamamlama devamı

Sahip2026-09-08 tarihinde bağımsız incelenmiş 51 görevlik CH08-CH14 planını
değiştirmeden sonuna kadar uygulamayı açıkça onayladı. Eski 46 tamamlanmış
görev korunur; hedef toplam 97 görevdir. Yalnız doğrudan parent
`4fd4a21f9b5dc381ea1ec3014daa3082a9d14e24` ve
`agent/cs3-ch08-s01-u001-product-completion-contract` dalında bir kez:
BOOK/PLAN/TODO, AGENTS, INVARIANTS, QUEUE_GUIDE, project_queue.py ve
test_project_queue.py değişebilir. Ürün dosyası veya POP bu geçişe karışamaz;
PROGRESS byte-byte aynı kalır. İlk yeni FRONT `CS3-CH08-S01-U001` olur.

`product_restart_book` yalnız sabit eski BOOK ile dondurulmuş tam chapter
önerisinden sabit yeni BOOK'u hesaplar. Eski bölümler, bitmiş sözleşmeler,
receipt'ler ve karar geçmişi değişmez; tek yeni karar ve 51 görev eklenir.
Eski/yeni BOOK ve proposal SHA-256 sabitleri bu exact yetkiyi sınırlar.
Olağan amend/extend-scope terminal açma veya kabul zayıflatma izni kazanmaz.
Saf dönüşüm yazma yapmaz; primary mevcut journal/lock/publish mekanizmasıyla
sekiz dosyalık aday hazırlayıp tek commit olarak bağımsız exact-head denetletir.
Guard başarıyla uygulanmış geçişi doğrulamadan ilk normal görev başlamaz.

Doğrudan geçiş guard'ı exact dalı denetler. Daha sonraki implementation replay,
Git commit'inin dal adı saklamadığı gerçeğine uygun olarak immutable parent,
dosya kümesi ve BOOK/proposal kimlikleriyle bu sınırı tanır. Sınırda körlemesine
durmaz: eski terminal commit'inin tek parent'ını, tam üç POP dosyasını ve
gerçek review-head/branch ile `complete` eşitliğini denetler; ardından eski son
görevin implementation geçmişini önceki POP'a kadar doğrular. Terminal
pending listesine index atılmaz. Yanlış parent/digest, değiştirilmiş eski kayıt,
eksik/ek dosya, gizli eski uygulama, sahte veya merge POP ve sonradan yeni
yönetişim değişikliği ret alır. Yeni task'ın olağan dal/scope/receipt kontrolleri
aynen geçerlidir.

Öneri PASS'i gelecekteki kodun PASS'i değildir. Aktivasyon da yeni ürün görevinin
tamamlanması değildir. İlk normal görev ayrı ürün planı/kalite sözleşmesini
yayımlar ve aktivasyonun test farkı için onaylı prospective inventory successor'ı
bağımsız doğrular; burada eski korpus pinleri veya kalite eşikleri değiştirilmez.
Tag, publisher signing ve gerçek public yayın için planda ayrılan exact-target
onayları ayrıca alınır. Main'e merge/yazma veya force-push izni yoktur.

## Değişiklik ve hata kurtarma

Yeni fikirleri hemen uygulama. Gelecek chapter/section/task listesini repo dışında
bir proposal JSON'a hazırla; önce bağımsız incelet, sonra temiz dalda
`amend --proposal /absolute/chapters.json --reason 'neden'` kullan. Yalnız managed
dosyaları commit et, `guard --base HEAD^` çalıştır. Bu kontrol edilen plan bakımıdır;
TODO dışı ürün işi değildir. Front'u zayıflatmak veya engeli atlamak için kullanılamaz.
Front'un kabulü gerçekten olanaksızsa kullanıcıya somut engeli bildir; sahte POP yok.

### Aynı iş için eksik dosya kapsamı

Kullanıcının2026-09-05 kalıcı izni: aynı kabulü gerçekleştirmek için gerekli dar
dosya eklemelerinde tekrar insan onayı istenmez. Önce bağımsız salt-okunur denetçi
gerekliliği, exact temiz HEAD'i, mevcut sözleşmeyi ve ek dosyaları doğrular.
Sonra `extend-scope --review /absolute/scope-review.json` yalnız FRONT scope'una
1–8 açık dosya yolu ekler. Glob/dizin, zaten kapsamda olan yol, .git/.agents/.codex
ve yönetişim çekirdeği eklenemez. Yeni ürün özelliği bu işlemle içeri sokulmaz.

Receipt schema `codeskeptic-scope-review/v1`; exact alanlar: schema, task_id,
head, branch, contract_sha256, additions, reason, implementer, verifier, verdict,
findings. Kanonik JSON+LF; distinct implementer/verifier, PASS ve boş findings.
Bu ürün tamamlanma PASS'i değildir. Denetçi dosyayı repo dışında primary'ye verir.
Primary komutu çalıştırır; yalnız BOOK/PLAN/TODO dosyalarını birlikte commit eder
ve `guard --base HEAD^` çalıştırır. PROGRESS byte-byte aynı kalır; hiçbir POP yok.
Uygulanan geçiş bağımsız denetlenmeden ek dosyada ürün değişikliği başlamaz.

Outcome, Acceptance, budget/checks, bağımlılıklar, diğer bütün task'lar ve FIFO
sırası aynen korunur. Yeni contract digest eski ürün receipt'ini geçersiz kılar.
Guard önceki commit'leri eski kapsamla yeniden doğrular: kapsam dışı bir dosyayı
önceden değiştirip sonra izin eklemek mümkün değildir. Scope ledger'ına ürün kodu
karıştırılamaz. Yeni review mevcut ekleme HEAD'ine bağlı olduğu için replay olmaz.

Bu komutu kuran bir defalık politika checkpoint'i sahibin açık iznine bağlıdır:
parent `0e589b5e9e7084a4f2a88e8ff9b1633d0e2d5ee1`, mevcut S06-U001 dalı, yalnız
AGENTS/INVARIANTS/QUEUE_GUIDE/project_queue.py/test_project_queue.py. Kitap ve ürün
değişmez; bağımsız exact-head denetim ve T0 kanıt gerekir. Sabit historical edge
başka commit'te yönetişim düzenleme yetkisi vermez; root'a karşı kriptografik
koruma iddiası da değildir.

Yazma hatasında araç eski dört dosyayı geri yükler. Ani kapanmada `.git` içindeki
recovery journal kalabilir: `check` fail eder. Aynı HEAD'de `recover` çalıştır;
arada ilgisiz bir kullanıcı düzenlemesi varsa araç üstüne yazmayı reddeder.
Journal yokken hazırlanmış fakat commit edilmemiş geçerli bir POP varsa yalnız
o ledger diff'ini inceleyip tamamla; finalize'ı ikinci kez çağırma. Herhangi bir
şüphede ilerlemeyi durdur, çalışmayı kaybetmeden exact parent ile karşılaştır.

Yerel komutlar network/GitHub çağırmaz. Push isteğe bağlıdır; hiçbir yerel kayıt
hosted CI, korunmuş main veya yayın tamamlandı anlamına gelmez. CI workflow dosyası
yalnız ilgili dal GitHub'a gönderilince çalışabilir; şu an yerelde kullanılabilir.
