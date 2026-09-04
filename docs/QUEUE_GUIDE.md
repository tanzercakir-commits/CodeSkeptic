# FIFO kullanım kılavuzu

## Bakılacak dosyalar

- PLAN.md: tüm Chapter → Section → Unit kitabı ve kabul/test sınırları.
- TODO.md: yalnız aktif chapter'ın tam görevleri; FRONT tek yürütülebilir iş.
- PROGRESS.md: en yeni tamamlanma üstte; commit ve bağımsız kanıt özeti.
- BOOK.json: aynı kitabın ve kayıtların makinece işlenen tek işlem durumu.
  Üç Markdown dosyası buradan üretilir ve byte-byte karşılaştırılır.

PLAN'ın tamamı kilitli değildir. JSON elle güncellenerek kuyruğa iş sokulmaz;
amend komutu geleceğe yönelik değişikliği gerekçesiyle kaydeder. Eski task ID'leri
silinmez/sıralanmaz, front ve bitmiş işler değiştirilmez. Aktif chapter'a ek iş
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

## Değişiklik ve hata kurtarma

Yeni fikirleri hemen uygulama. Gelecek chapter/section/task listesini repo dışında
bir proposal JSON'a hazırla; önce bağımsız incelet, sonra temiz dalda
`amend --proposal /absolute/chapters.json --reason 'neden'` kullan. Yalnız managed
dosyaları commit et, `guard --base HEAD^` çalıştır. Bu kontrol edilen plan bakımıdır;
TODO dışı ürün işi değildir. Front'u zayıflatmak veya engeli atlamak için kullanılamaz.
Front'un kabulü gerçekten olanaksızsa kullanıcıya somut engeli bildir; sahte POP yok.

Yazma hatasında araç eski dört dosyayı geri yükler. Ani kapanmada `.git` içindeki
recovery journal kalabilir: `check` fail eder. Aynı HEAD'de `recover` çalıştır;
arada ilgisiz bir kullanıcı düzenlemesi varsa araç üstüne yazmayı reddeder.
Journal yokken hazırlanmış fakat commit edilmemiş geçerli bir POP varsa yalnız
o ledger diff'ini inceleyip tamamla; finalize'ı ikinci kez çağırma. Herhangi bir
şüphede ilerlemeyi durdur, çalışmayı kaybetmeden exact parent ile karşılaştır.

Yerel komutlar network/GitHub çağırmaz. Push isteğe bağlıdır; hiçbir yerel kayıt
hosted CI, korunmuş main veya yayın tamamlandı anlamına gelmez. CI workflow dosyası
yalnız ilgili dal GitHub'a gönderilince çalışabilir; şu an yerelde kullanılabilir.
