# Main tabanlı yeniden başlangıç — 2026-09-05

Kullanıcı eski main-sonrası yerel dalları aktif çalışmadan çıkarmayı, faydalı
kodları ipucu olarak saklamayı, ürün ağırlıklı esnek kitap/FIFO ile yeniden
başlamayı onayladı. Bu kayıt eski sürümün devam/ratification iddiası değildir.

- Korunan main: `7dfd37596414c9512316093ff4fb6b039673f55f`.
- Eski aktif governance ucu: `44a3ce5ae1bb17f728ed66874cba34f04adf3ddb`.
- Eski aktif src ağacı main ile aynıydı; yeni ürün özelliği taşımıyordu.
- 15 eski yerel head, aynı SHA ile `refs/archive/pre-cwe-restart-20260905/`
  altına alındı. GitHub dalları ve main değiştirilmedi/silinmedi.
- Tam, doğrulanmış bundle ve dal listesi:
  `/home/tanzer/.local/state/codeskeptic/pre-cwe-restart-20260905/`.
  Bundle: `codeskeptic-pre-cwe-restart-20260905.bundle`.
  Manifest: `codeskeptic-pre-cwe-restart-20260905-heads.txt`.

Geri dönüş mümkündür: bundle ayrı dizine clone edilebilir veya manifestteki exact
SHA'dan yeni bir inceleme dalı oluşturulabilir. Arşiv refleksle temizlenmez.
Eski build/corpus cache varlığı o kodun güncel PASS'ı değildir.

## Kirli donor ipuçları

`060bf4b012dac7802da23c17654dd3815dfdb83b`: compile-command doctor adayı;
17 dosya, +1855/-53; eski kuyruğa final olmamıştı. CH02'de davranışı yeniden
incelenecek, dosyalar topluca taşınmayacak.

`a79c37581cec8f78ebf7dd4a5f49eec3ac413ee6`: eski kümülatif kaynak adayı;
main'e göre 32 kaynak dosyası, +5631/-297. Parser/coverage/worker/cache ipuçları
var. Eski kanıtlar yeni SHA veya yeni kabul için kullanılamaz.

Eski 7 tamamlanmış governance kaydı yeni ürün ilerlemesi sayılmadı. Yeni epoch
CS3 ayrı ID'lerle sıfırdan başlar. İlk tek seferlik CH00 sadece küçük FIFO/plan
kurulumudur; hemen ardından CH01 gerçek CWE çekirdeğini geliştirir.

## Referanslardan bilinçli ayrımlar

Kullanıcının UNIVERSAL_PROJECT_GOVERNANCE_GUIDE.md belgesi ve
[ReprForge](https://github.com/tanzercakir-commits/ReprForge) AGENTS/queue kodu
incelendi. FIFO ve bağımsız kanıt ilkeleri alındı; bütün planı dondurma,
ürün öncesi zorunlu main merge/remote commissioning ve denetçiye PR yazma
yetkisi alınmadı. Bunlar kullanıcının son açık talimatlarıyla çelişiyordu.
