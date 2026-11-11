[TgWitness](../../README.md) / [Belgeler](README.md) · [Operatör bildirimi](OPERATOR-INCOMPATIBILITY.md)

![106 günlük GDPR dosyası](../assets/presentation/chapter-case.svg)

# Valve, Taylor Wessing ve GDPR kapsamında 106 günlük bekleyiş: dosyanın ve 70.717 kelimesinin çözümlemesi

[Kaynak kaydı](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Operatör bildirimi](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

Elimizde asla yanıtlanmayacak sorular kalıyor, çünkü uyuşmazlığın tarafı değiliz. Hiçbir sıradan insan her seferinde yüz gün beklemeye ve bunun gibi "serbest çalışan borsaları" üzerinden şirketlerce finanse edilen seçkin avukatlarla uğraşmaya dayanamaz. Valve'ın sipariş ettiği hizmetin gerçekte adının ne olduğunu asla öğrenemeyeceğiz. Dışarıdan bakıldığında bu, tamamen hukuka uygun olmayan bir GDPR işlemesine ve şikâyetçilerin karartılmadığı, aksine sızdırıldığı bir veri açıklamasına benziyor; üstelik verinin kendisinden en az 5.000–10.000 sayfa eksik: dışa aktarılan şey kullanıcı günlüğü değil, dış kaynak çalışanları için hazırlanmış kırpılmış bir günlük. Buna itiraz etmenin anlamı yok. Devasa bir bilgi katmanı nesnel olarak eksik; tıpkı iki avukattan herhangi birinin söylediklerini doğrulayacak hiçbir şeyin olmaması gibi.

Valve, oyalamadan, elle uygulanmış karartmalardan ve homofobik bir şikâyetle bozuk bir PDF'in altındaki bir Doktor imzasından oluşan bir hizmet için ne ödüyor? Bu bizim davamız değil, ama buradaki sorun açıkça yasa değil; statü ve cezasızlık. "Doktor" unvanı, bir kişiyi otomatik olarak neyin çürütülemez kanıt sayılacağına karar veren kişi, bir başkasını da sözde sayılardan ve PDF'lerden anlayan kişi yapıyor (gerçekte anlamasa da).

---

## 1. Tarihler, Doktor'un sözü ve içinde hiç ödeme olmayan bir rapor

Belgenin başlığında `Date of Report: 09-29-2025` yazıyor; dosyaların kendisi ise 1 ya da 2 Ekim'de teslim edildi. Ama bu tarihlere inanmıyoruz. **Dr. Patrick Vincent Zurheide**'nin doğrudan beyanına inanıyoruz:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“
>
> *(Müvekkilinizin kişisel verilerinin derlenmesi maalesef bir aylık sürenin tamamını aldı; çünkü yeniden yapılan inceleme, 3 Mayıs 2025'ten sonra da hesap üzerinden üçüncü bir kişi tarafından yeni ödemeler yapıldığını gösterdi ve bu nedenle verilerin elle temizlenmesi gerekti.)*

Rakamlara, doktorun ilk paragraftaki sözlerine ve imzasına inanmayı bırakmamıza yol açan tam da bu cümle. Elbette bir doktor yalan söylemez; kaybedecek bir şeyi var, değil mi? Ancak dosya dışa aktarılıp vektör şekiller kaldırıldığında raporda tek bir ödeme bile çıkmadı. Dr. Patrick'in çalışmasına ya da gecikmesine itiraz etmiyoruz. Yalnızca "Doktor'un gerçeğine" inanıp onu kabul ediyor ve dosyanın kendisinde görülebileni kayda geçiriyoruz.

---

## 2. 36 saniye ve savunmasız "Anlage 1 / Taylor Wessing" etiketi

Hiçbir konuda uzman değiliz; görünüşe göre bu yüzden güvenlik açığı bildirimimiz hem serbest çalışan platformunun kendisi hem de doktor tarafından görmezden gelindi. Mantık yeterince açık: onlar yasanın ta kendisi, ne gibi açıkları olabilir ki?

Ama Doktor'un sözlerini bir kenara bırakıp tekniğe bakalım. Eşdeğer bir Windows ortamı kurduk, temizlenmiş dosyayı aldık ve şekilleri yerleştirmeyi denedik. Yüzlerce siyah şekli, tam olarak kaydedilen oturumun süresi olan **36 saniyede** elle yerleştirmek bize göre imkânsız; her şey, siyah kutuların belgede zaten bulunduğunu gösteriyor. Bu 36 saniyede tam olarak tek bir nesnenin, 1. sayfanın sağ üst köşesine eklendiği görüşüne yatkınız: `"Anlage 1 / Taylor Wessing"` etiketi. Ve savunmasız olan da onu yerleştiren yazılımdır:

* **İşaretçilerine göre nesne:** `(929, 294)` ile `(1139, 372)` arası, yani `210 × 78 px`, merkezi yaklaşık `(1034, 333)`.
* **Görünür çerçeve:** `(936, 300)` ile `(1133, 367)` arası, yaklaşık `197 × 67 px`, oranları yaklaşık `3 : 1`; sayfanın üst kenarı `y ≈ 275` konumunda.
* **Ölçek:** belgenin sol cetveline göre `1 cm ≈ 82 px` (cetvel neredeyse kesinlikle santimetre cinsinden; inç cinsinden olsaydı sayfa `15″`'ten geniş olurdu).

Rozetin stili ve görünümü iade edilen dosyayla örtüşüyor. Ancak özgün oluşturma ortamına erişim olmadan ya da başlangıç biçimini bilmeden (bir dönüştürme yapıldıysa) deney temiz olamaz; bu yüzden bunu %100 kesinlikle iddia edemeyiz.

---

## 3. 444. sayfa: gizlenmiş saat ve şikâyetlerin aritmetiği

Şikâyetler, o homofobik şikâyet de dahil olmak üzere 444. sayfada başlıyor. Önemli bir nokta:

* Göstermeyi seçtikleri şikâyetlerde (avukatların işine gelenlerde), **`Time of Report`** alanı diğer her şeyin üstüne kasıtlı olarak gizlenmiş. Kesin saat yok ve bu, tüm dosyada teknik olarak doğru biçimde gizlenmiş tek şey.
* Ana makalede gösterilen şikâyetleri içerik, yazım üslubu ve takma adlar açısından diğerleriyle matematiksel olarak karşılaştırdık. Neredeyse her yerde Reddit'in standart ad üretme formülü kaba biçimde yeniden kullanılıyor ve tam da ihtiyaç duyulan aralıkta keskin bir sıçrama var. Şikâyetlerin sahte olduğunu söylemiyoruz; ama hesapların muhtemelen gerçek olmadığını ve çoğunun matematiksel olarak bir botnete benzediğini söylüyoruz.

---

## 4. Dr. Patrick Zurheide'ye `2025-02-03 16:29:23` ve `2025-04-02 15:55:19` kayıtları hakkında bir soru

Doktor Patrick, homofobik şakayı okuduğunuzu ve kendiniz de bir şaka yapmaya karar verdiğinizi yazdınız. Peki, çok komik. Diğer şikâyetler, meslektaşınızın ifadesiyle, esas bakımından önemli değil (*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…“*). Peki, onları geçiyoruz. Umarız **Doktor Tobias**, ölüm dilekleri ve Nazi beyanlarıyla dolu 1.938 şikâyetin rastgele bir çeyreğinin (485 tanesinin) neden önemli olmadığını ve tam olarak kimin için önemli olmadığını bir derste öğrencilerine açıklar. Açıklarsa yanıldığımızı hemen kabul edecek, özür dileyecek ve anılan yerleri sileceğiz.

Şeyleri adıyla analım: nefret edenlerin verilerini, Rusları, Alman'ı, hepsini, bilerek tam da nefret ettikleri kişiye verdiniz; hem de birbirleriyle savaşan iki ülke arasında. Ona Rus çocuklarını sunduğunuz ortaya çıktı: kendisi çok memnun, Tobias da onları doğrudan sorun olarak gösterdi. Ama gerçekte bu sizin sızıntınız; sadece çocuklar sizin değil.

Ancak sorumuz, gözden kaçmış olması mümkün olmayan başka bir kullanıcıyla ilgili:

* **`2025-02-03 16:29:23`**: aynı ülkeden bir bağlantı ve bir kişi; orada hemen göze çarpan çok ciddi şeyler yazılmış;
* **`2025-04-02 15:55:19`**: doğrudan bir atıf, belirli bir isim ve onun yazdıkları.

Kontrol ettik: tam olarak göründüğü gibi. Devlet verilerini ve eksiksiz kişisel bilgileri, sizin de suçlu saydığınız birinin eline açıkça teslim ettiniz. Bu, en azından bağlam nedeniyle yapılmamalıydı. Ya oraya yazarsa ne olacak? Sizin açınızdan bu yalnızca alçakça değil; insanların yaşamına ve sağlığına karşı açık bir umursamazlık. Biz soruştururken bu kişiyi durdurduk ve herkesi güvenceye aldık. Genel olarak tek gerçek şikâyetimiz bu; geri kalan her şey yalnızca olgular ve seçkin avukatların nasıl çalıştığının bir gösterisi. Doktor Patrick'i bunun gereken sorumluluğunu üstlenmeye çağırıyoruz; tabii adının önündeki unvan ona böyle davranma hakkı vermiyorsa (biz avukat değiliz ve yasayı bilmeyiz).

---

## 5. Kamuoyuna, sigortacıya, düzenleyicilere ve ABD şirketlerine

* **Kamuoyuna ve Taylor Wessing müvekkillerine:** Bu özensizliğe bakılırsa Taylor Wessing'in, bütün bunları normal sayan cömert bir sigortacısı var. Dosyalarınızı kontrol edin ve düzenleyiciyi bilgilendirin. Avukatların kendilerine söylemeye gerek yok: Valve onlara ilk kez başvurduğundan beri bir yılı aşkın süredir bunu gizlemeyi seçtiler.
* **Düzenleyicilere, her dosyanın savunmasızlığı hakkında:** Dr. Patrick'in faaliyetlerini inceleyin ve ilk sayfanın üstüne `"Anlage 1 / Taylor Wessing"` rozeti (ya da benzeri) yerleştirilmiş olarak elinden geçen her PDF'i talep edin. Bunun münferit bir vaka olmaması ve ondan çıkan bu çıkartmalı her belgenin savunmasız olması olasılığı kritik derecede yüksek.
* **Sigorta şirketine:** Lütfen müvekkilinizi ve PDF'lerle çalışmak ve `"Anlage 1 / Taylor Wessing"` etiketini 1. sayfanın üstüne yerleştirmek için kullandığı yazılımı denetleyin. Sorun büyük olasılıkla tam olarak oradadır ve münferit bir vaka değildir. Tüm Taylor Wessing'in denetlenmesini istemenin anlamı yok: isim dışında, kendiliğinden var olması gereken çalışma ortamları ya da güvenlik inceleme kuralları bakımından ortak hiçbir şeyleri yok gibi görünüyor (anlaşılan fiziksel bir imza anahtarı ve bir ismin önündeki unvan bunların hepsini karşılıyor).
* **ABD şirketlerine ve bunu tesadüfen okuyan Avrupa Komisyonu'ndaki herkese:** Sadece yasaya uymayı deneyin. Ünlü bir "serbest çalışan şirketinden" ünlü doktorlar tutmak, müşterilerinize karşı tehlikeli ve son derece aşağılık görünüyor. Eğer Valve'da çekler öylece imzalanıyor ve avukatların 106 gün boyunca ne yaptığını kimse kontrol etmiyorsa, belki de sonuç yerine uzatılmış zamana para ödemek, yazılımın eski olmasının ve kimsenin bir PDF'in nasıl çalıştığını anlamamasının tam nedenidir. Ve orada başka sızıntı yoksa, Doktor Patrick herkesi beklemeyle ya da tehditlerle yıpratmayı başarmış demektir. Özünde satışa sunulan şey bir GDPR'a uymama hizmeti: düşük kaliteli uygulama ve tehditler ("tek bir davayı bile kazanamayacaksınız"), kendi adlarına yürütülen yüksek kaliteli bir Google sonuçları temizliğiyle birleşiyor. Hukuki metin kaleme almıyor ve kimseyi suçlamıyoruz. Yalnızca gördüğümüzü ve silmek için bu kadar uğraştıkları şeyi yazıyoruz.

Avukatlar yasanın kendileri olduğunu ve insanların hayatlarının, çocukların hayatlarının önemli olmadığını düşündüğüne göre, bu onların tercihi. Bu bizim çatışmamız değil. Ama firmanın cezasızlığının tarihsel olarak doğrulandığını güvenle söyleyebiliriz; kurucusu Goltz'a, §175 değişikliklerini hazırlayan sekiz kişiden birine ve bazen LGBT bireylerin savunması olarak okunan tek ünlü davasına, General von Fritsch davasına kadar uzanıyor. Tarihi geçeceğiz; onu doğrudan güvenilir bir kaynaktan ve özgün kayıttan inceledik. Ama dava şöyle bitti: bir sanık vardı ve bizde üç ölü var. Baskının değirmen taşlarında ezilen Achim von Frisch. 1943'te kurşuna dizilen Otto Schmidt. Ve General Fritsch'in kendisi: beraat etmiş olması önemli değil, bedeli ağırdı. 1939'da ölümü arayarak Polonya cephesine gönüllü gitti ve öldürüldü (ya da öldürülmesine izin verdi).

Elbette bu davayı hiçbir zaman firmanın kurucusunun LGBT bireyleri savunması olarak saymadık. Ama sonuç bir zaferden çok daha ilginç.

**Asimetrik adalet:** Goltz, suçu tamamen Gestapo tarafından uydurulmuş yüksek rütbeli bir subayı gerçekten kurtardı. Ama bu mazeretin bedeli başkalarının kanıyla ödendi. Aynı Goltz, 1933'ten itibaren Ceza Hukuku Komisyonu üyesi olarak 175. Paragrafın Nazi versiyonunu (1935) bizzat tasarladı ve yürürlüğe koydu.

**İstatistik ve halkla ilişkiler:** Önce yaklaşık 50.000 gerçek eşcinseli hapishaneye, yaklaşık 15.000'ini de %60 ölüm oranıyla toplama kamplarına gönderen hukuki bir yürüyen bandı harekete geçirdikten sonra, Wehrmacht elitinden heteroseksüel bir generali savundu. Bir generali kurtarmak soykırımın mimarisini ortadan kaldırmaz.

**Başarıyla atlatılan Nazilerden arındırma:** Fritsch davası, savaş sonrası Nazilerden arındırma kurullarından geçmek için kusursuz bir "arka kapı" oldu. Baskıcı yasaların mimarı, bir generali savunmasını "bağımsızlığının" kanıtı olarak kullandı, Nürnberg'den kurtuldu, statüsünü ve ruhsatını korudu ve 1957'de bugün Taylor Wessing tabelası altında ilericiliğini satan büroyu kurdu.

Yani evet, sonuç olarak: bunun bu Alman Taylor Wessing mi yoksa başka biri mi olduğunun hiçbir fark yaratmadığından eminiz; mesele hiç de yasa değil. Burada söylediğimiz bir beyandır; bir olgu iddiası değil, bir varsayımdır, çünkü gerçekte tutunacakları herhangi bir kelime arayacaklar. Bu yüzden bu, arşivlere gidiyor: sansür ve gizleme girişimleri ve onların mirasıyla doğrudan bağlantılar. Doktor Patrick'ten: kaba homofobik kelimenin bırakıldığı ilk şikâyet. Belki de kazara, elbette, ama orada ve ilk sırada.

Doktor Tobias'tan doğal olarak, şikâyet sayısı biçimindeki çürütülemez kanıt üzerine bir ders ve o çeyreğin hangi kısmının kendisi için kişisel olarak önemli olmadığının açıklamasını bekliyoruz. Tarih için ve sınırların nerede olduğunu anlamak için bu önemli.

Steam'in moderasyon yapmak yerine veri sorumlusu olarak hareket etmesi yalnızca apaçık olanı gösteriyor: onları Doktor Patrick sızdırdı. Eh, böyle oldu. Görünüşe göre çıkartma yazılımının bozuk olduğunu bilmiyordu, sonuçta bunlar en üst düzey doktorlar, ve Steam bunun için ödeme yapmadı: GDPR talebini işleyip işlememek ve ardından gördüğü sızıntının üstünü örtmek için.

Gerçekle ilişkide sağduyu çağrısında bulunuyor ve herkese sıfır güveni hatırlatmak istiyoruz: biz dahil herkese karşı. Hepsi düşmanca bir ortam ve bu incelemenin bağlamında kelimenin tam anlamıyla: 9 Mayıs yasakları, Naziler, doktorlar, LGBT bireyler, çocuklar. Eğlenceliydi.

Ama Taylor Wessing konusundaki seçeneklerimiz büyük olasılıkla tükendi, çünkü onların stratejisi bağlantıları kaldırtmak. Metnimizi ve verilerimizi korumak zorundayız, bu yüzden onları, henüz yayımlanmamışken bile Almanya ve Belçika dahil devlet kurumlarından üç onaylı teşekkür mektubu almış olan yazılımımıza yerleştiriyoruz.

Yasayı eğip bükmeyi sevenleri uyarmak istiyoruz: depoyu kaldırmaya gerek yok. Bunca zaman boyunca sizinle hiçbir çatışmaya girmedik. Ama gerçeği gizlemek için çalışmamızı bozmaya karar verirseniz, etkin bir depo olmadan düzenleyiciler ve diğerleri bir sürümün imzasını karşılaştıramaz (gerçi kime anlatıyorum) ve o zaman doğrudan çatışmaya gireriz. Bununla birlikte mega uzmanlığa ve seçkin avukatlara veda etmeyi umuyoruz. Eğlenceli değildi ve memnun değilim. Her şey gönlünüzce olsun.

[Kaynak kaydı](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Operatör bildirimi](OPERATOR-INCOMPATIBILITY.md) · [MIT Lisansı](../../LICENSE)

[Proje](../../README.md) · [Belgeler](README.md) · [Wiki](../wiki/Home.md)
