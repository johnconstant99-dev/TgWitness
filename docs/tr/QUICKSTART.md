[TgWitness](../../README.md) / [Belgeler](../README.md) / [Klasör](README.md)

![Başlarken](../assets/presentation/chapter-start.svg)

[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · [Español](../es/QUICKSTART.md) · [Português (Brasil)](../pt/QUICKSTART.md) · **Türkçe** · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · [Bahasa Indonesia](../id/QUICKSTART.md) · [Tiếng Việt](../vi/QUICKSTART.md) · [简体中文](../zh/QUICKSTART.md)

# TgWitness hızlı başlangıç

TgWitness, hesaplarınızın erişebildiği Telegram gruplarını ve kanallarını gözlemlemek için bağımsız bir uygulamadır.
Kendi veri diziniyle yerel olarak çalışır.

**İlk kez mi buradasınız?** Bir hesap bağlamadan önce [demoyu inceleyin](#explore-the-interface).
Proxy'ler, tanıklar, dışa aktarımlar veya sunucu kurulumu için [bir kılavuz seçin](../README.md).
[GitHub Actions ile kayıt](../SEALED-ACTIONS.md) (önizleme), kaydı yerel bir kurulum yerine
kendi GitHub fork'unuzda yürütür.

<a name="install-and-start"></a>

## Kurulum ve başlatma

Rehberli yükleyici kendi Python'unu içerir ve kurulumdan önce paket hash'lerini ve sürüm
imzalarını denetler. Yeniden çalıştırıldığında mevcut bir kurulumu günceller.

**Linux / macOS:**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows (PowerShell veya Komut İstemi):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

Ubuntu sunucusunda arka plan hizmeti kurmak için root olarak çalıştırın; masaüstünde normal
kullanıcınızla çalıştırın. Ubuntu'da yükleyici panel adresini ve erişim anahtarını yazdırır;
macOS ve Windows'ta yerel panel tarayıcınızda açılır. Aşağıdaki **Telegram'ı bağla** adımından
devam edin. [Kurulum, doğrulama ve güncelleme](../INSTALLATION.md) kılavuzu sunucu erişim
seçeneklerini, betiği çalıştırmadan önce denetlemeyi, güncellemeleri ve kaldırmayı ele alır.

### Diğer yöntemler

GitHub sürümleri, kaynak kod ve Docker, yükleyicinin alternatifleridir. Taşınabilir indirmeler,
bir sürüm derlemesi yayımlandıktan sonra kullanılabilir hale gelir:

| Ana makine | Kurulu bir şey gerekmez | Kaynaktan: Python 3.11+ | Docker: Compose 2.20+ ile Engine/Desktop |
| --- | --- | --- | --- |
| Windows | GitHub Releases'tan `TgWitness-<version>-windows-amd64-portable.zip` arşivini çıkarın, `TgWitness.cmd` dosyasına çift tıklayın | `Start.cmd` dosyasına çift tıklayın | `scripts\Docker.cmd` dosyasına çift tıklayın |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

Kaynak koddan kurulum için [güncel `main` dalını indirip çıkarın](https://github.com/phishdestroy/TgWitness/archive/refs/heads/main.zip)
veya depoyu klonlayın:

```sh
git clone https://github.com/phishdestroy/TgWitness.git
cd TgWitness
```

Uygun bir Python bulunamazsa `Start.cmd`, Windows kullanıcınız için Python 3.12'yi kurmayı
önerir (winget veya imzalı python.org yükleyicisiyle). Python yoksa `start.sh`, Linux
dağıtımınız veya macOS için tam kurulum komutunu yazdırır. Kaynaktan ilk başlatma `.venv`
ortamını oluşturur ve bağımlılıkları otomatik olarak kurar.

Docker uygulamayı derler ve arka planda başlatır; ana makinede Python gerekmez.
`scripts\Docker.cmd` ve `scripts/docker-start.sh`, konteyner sağlıklı duruma geldiğinde panel
adresini ve jetonu yazdırır. Desteklenen tüm ana makinelerde eşdeğer Docker komutları şunlardır:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

**http://127.0.0.1:8787** adresini açın. Docker yardımcısının veya ikinci Docker komutunun
yazdırdığı jetonu kullanın; taşınabilir veya kaynak kurulumda ise **data/live/panel-token.txt**
dosyasını okuyun. Aşağıdaki **Telegram'ı bağla** adımından devam edin. Yerel ve Docker kurulumları
ayrı depolama kullanır; Docker'ı başlatmak mevcut bir yerel kurulumun günlüğünü içe aktarmaz.

Sunucu için [dağıtım kılavuzu](DEPLOYMENT.md) otomatik HTTPS, yeniden başlatma, yayımlanmış
imajlar, güncellemeler ve yedeklemeleri ele alır.

<a name="explore-the-interface"></a>

## Arayüzü keşfedin

1. Taşınabilir pakette **TgWitness-Demo.cmd** dosyasını, Windows'taki kaynak klasöründe
   **scripts\Demo.cmd** dosyasını veya Linux/macOS'ta `sh start.sh --demo` komutunu çalıştırın.
   Kaynaktan başlatma önce `.venv` ortamını oluşturur ve bağımlılıkları kurar.
2. **http://127.0.0.1:8787** adresini açın.
3. Yerel demo örnek günlüğü otomatik olarak açar. Doğrudan yerel erişimde jeton kopyalamanız gerekmez.

Demo mesajları kurgusaldır. Demo modunda gerçek bir Telegram hesabı bağlanamaz.

## Telegram'ı bağlayın

> [!WARNING]
> **Bu iş için ayrılmış hesaplar kullanın.** Telegram, istemci ne olursa olsun, aşırı gördüğü
> istek hacimleri nedeniyle hesapları kısıtlayabilir veya kalıcı olarak yasaklayabilir. Kişisel
> ya da değerli hesaplar yerine gözlem için hazırlanmış hesapları bağlayın ve API kimliğini /
> hash'i de bu amaçla ayrılmış bir hesapta oluşturun.

1. Yerel demo çalışıyorsa durdurun ve **Start.cmd** dosyasını ya da `sh start.sh` komutunu
   çalıştırın. Aksi halde yukarıda başlattığınız canlı kurulumu çalışır durumda bırakın.
2. Panel jetonuyla giriş yapın. Yeni bir çalışma alanı [ilk kurulum](../SETTINGS.md) ekranını açar.
   **Sadece indir**, **Sohbetleri izle** veya **Bir davaya ilişkin deliller** seçeneğini seçin.
3. Bağlantı kontrolünün sonucunu inceleyin. Gerekirse kendi proxy'nizi yapılandırın; bağlantı
   ayarlarına kurulumdan sonra da erişebilirsiniz.
4. **Telegram'ı bağla** adımında QR kodunu tarayın veya telefon numaranızı girin. Dosyadan içe
   aktarma ve tam yetkilendirme anahtarı **Diğer oturum açma yöntemleri** altındadır.
   İstendiğinde Telegram onayını tamamlayın, kodu ve iki aşamalı şifreyi girin.
5. Görüntülenen hesabı kontrol edin, sohbetleri seçin ve ayarlarınızı gözden geçirin. Kurulumu
   son ekrandan tamamlayın. **Sadece indir** seçeneğinde **Dışa aktarmaya başla** düğmesi tek
   seferlik bir dışa aktarma başlatır ve ilerlemesini göstermek için Dışa aktarımlar sayfasını açar;
   sürekli gözlemi etkinleştirmez.

Kurulumdan sonra seçili sohbetleri **Sohbetler → Seç** ile değiştirebilirsiniz. **Ayarlar**
toplama ve dosya seçeneklerini yönetir; **Diğer araçlar → Kaynaklar**, Standart veya Uzman
düzeyinde ayrıntılı kaynak listesini sunar. [Panel kılavuzu](../PANEL.md) altı ana bölümü ve
bunların bağlama göre değişen denetimlerini açıklar.

**API Kimliği + Hash** isteğe bağlıdır: çalışma alanı kaydedilmiş ya da içe aktarılmış çiftini
veya yerleşik havuzdan çalışan bir çifti kullanır. Kendi uygulamanızı kullanmak için API Kimliği
alanına tek bir `API ID:API Hash` çifti yapıştırın. **Otorizasyon anahtarı** için 512 onaltılık
karakterin tamamını yapıştırın ve size verilen DC Kimliğini seçin. Kullanıcı Kimliği isteğe
bağlıdır; girilirse doğrulanır.

API kimlik bilgileri uygulamanızı tanımlar; tek başlarına bir hesaba yetki vermezler. Özel
grupların herkese açık bir kullanıcı adına ihtiyacı yoktur, ancak hesabınızın bu gruplara
erişimi olmalıdır.

Mevcut hesaplar için [hesaplar ve oturum biçimleri](../ACCOUNTS.md) kılavuzuna bakın: panel
Telethon StringSession, Telethon/Pyrogram SQLite, tek hesaplı TData ZIP ve desteklenen hesap
JSON dosyalarını kabul eder. Oturumu ve ona eşlik eden JSON dosyasını birlikte seçip
**Hesap bağla** düğmesine basın. Aynı isteğe bağlı API ayarlarıyla QR koduyla giriş de
kullanılabilir. TDLib, bot oturumları ve CSV/JSON hesap envanterleri desteklenmez.

Birden fazla hesap için **Hesaplar → Hesapları içe aktar** seçeneğini kullanın ve desteklenen
oturum dosyalarını seçin. Eşlik eden JSON dosyaları uzantısız dosya adına göre eşleştirilir;
içe aktarılan her hesap kendi çalışma alanını alır. Bkz.
[toplu içe aktarma ve hesap grupları](../ACCOUNTS.md#bulk-import-and-account-groups).

Başka bir hesap eklemek için hesap seçicinin yanındaki **+** düğmesine basın veya
**Hesaplar → Hesap ekle** seçeneğini kullanın. Çalışma alanlarının oturumları, günlükleri,
anahtarları, kaynakları ve kuyrukları birbirinden ayrıdır. Görünüm değiştirmek diğer toplayıcıları
durdurmaz. Bu kurulumda aynı Telegram hesabı iki çalışma alanına atanamaz. Çalışma alanı sayısı
sabit değildir; hepsi tek bir işlemi paylaşır, bu yüzden kapasite makineye bağlıdır.

Canlı panel jetonu, Telegram yetkilendirmelerinize ve kaydedilmiş materyale erişimi korur;
Telegram API kimlik bilgilerinden ayrıdır. Otomatik giriş yalnızca açıkça başlatılmış ve
doğrudan erişilen yerel bir demoya tanınır. Uzaktan veya proxy üzerinden erişilen bir demo yine
`data/demo/panel-token.txt` dosyasını kullanır.

## İnceleme ve dışa aktarma

- **Günlük:** gözlemleri kaynağa ve olay türüne göre arayın ve filtreleyin.
- Bir olayı seçerek özgün kaydını, atıf bilgisini ve kaydedilmiş sürümlerini inceleyin.
- Düzenleme ayrıntıları mevcut önceki/sonraki içeriği gösterir. Silme ayrıntıları, varsa son
  yakalanan içeriği gösterir; bilinmeyen bir aktör bilinmeyen olarak kalır.
- **Dışa aktarımlar:** imzalı ZIP, JSONL, CSV ve çevrimdışı HTML.
- **Sohbetlerin tam olarak dışa aktarılması** (**Sohbetler → Sohbeti dışa aktar** veya
  **Dışa aktarımlar → Bir sohbeti yakala veya dışa aktar**): bir sohbetin görünür geçmişinin
  tamamını, `chat.json` (Telegram dışa aktarma biçiminde) ve okunabilir bir `chat.html` içeren
  imzalı bir paket olarak indirin. Hesap üye olduğu sürece özel sohbetler de dışa aktarılabilir.
  Bu, silinmiş veya daha önce düzenlenmiş mesajların yeniden oluşturulması değil, mevcut durumun
  anlık görüntüsüdür. Bir kopyayı `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256`
  ile doğrulayın.
- **Kontrol noktasını kaydet:** imzalı günlük sınırını toplayıcının dışında saklayın.
- **İmzalı çalıştırma makbuzunu indirin:** toplayıcının program/sürüm kaydını saklayın.
- **Zaman damgası isteği hazırla:** bir zaman damgası otoritesi için çevrimdışı bir istek
  hazırlayın; yanıtı almak ve doğrulamak için [TIMESTAMP.md](../TIMESTAMP.md) adımlarını izleyin.
- **Günlüğü doğrula:** olay imzalarını ve zincir bağlantılarını denetleyin. ZIP dışa aktarma
  medyayı da denetler.

Desteklenen tarayıcılar büyük dışa aktarımları doğrudan seçilen bir dosyaya kaydeder. Diğer
tarayıcılar en fazla 128 MiB arabelleğe alır. Sunucu çalışırken akış tabanlı CLI, yanıtın tamamını
arabelleğe almadan daha büyük indirmeleri destekler:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

Başka bir çalışma alanı için **Dışa aktarımlar → Çalışma alanı kimliği** değerini kullanarak
`--profile ID` ekleyin. Uzak bir sunucu için `--url https://your-server` ekleyin. Varsayılan aktarım
sınırı 5 GiB'dir; `--max-mib` ile değiştirilir. İmzalı ZIP içeriği için varsayılan olarak ayrıca
sıkıştırılmamış 4 GiB'lik bir doğrulama sınırı vardır (**Diğer araçlar → Parametreler** bu sınırı
yükseltir; bu tür arşivleri `verify.py --max-gib N` ile doğrulayın). Arşivi doğrulayıcının
güvenilir bir kopyası ve bağımsız olarak saklanan bir anahtar parmak iziyle, kanıt için asgari
şartlar açısından da zaman damgası otoritesinin kök sertifikasıyla (`--tsa-ca`) doğrulayın.

## Kurulumu kontrol edin

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` yerel bağımlılıkları, imzalama desteğini, depolamayı, anahtar yapılandırmasını ve
dinleme adresini yoklar. Hiçbir şey kurmaz ve Telegram'a bağlanmaz. Meşgul bir bağlantı noktası,
başka bir örneğin çalıştığı anlamına gelebilir. Farklı bir `--port` kullanın veya önce o örneği
durdurun.

Başlatıcı `.venv` içine kurulum yapar. Bu ortam etkinleştirilmemişse yardımcı
`python -m tgwitness...` komutları Windows'ta `.venv\Scripts\python.exe`, Linux/macOS'ta
`.venv/bin/python` ile çalıştırılmalıdır.

## Oturumlar, koruma ve işletim

Kapalı ve tutarlı bir Telethon SQLite `.session` dosyası
`python -m tgwitness.sessions account.session --out account.tgwitness-session` ile yerel olarak
dönüştürülüp **Diğer araçlar → Hesap → Dosyalar** bölümünden yüklenebilir. Doğrudan dosya içe
aktarma ve QR koduyla giriş de kullanılabilir. Giriş biçimleri, SOCKS5, HTTP CONNECT, MTProxy ve
harici ana anahtarlar için [CONNECTION-SECURITY.md](../CONNECTION-SECURITY.md) belgesine bakın.

**Gözlemi duraklat** toplamayı durdurur. **Kilitle** yalnızca tarayıcı erişimini kapatır.
Sekmeyi kapatmak toplayıcı işlemini durdurmaz. İşlemi durdurmak toplamayı keser; geçmiş anlık
görüntüsü kaçırılan tüm düzenlemeleri veya silmeleri yeniden oluşturamaz. Olay politikaları, ek
kuyrukları, hesap yalıtımı ve yeniden başlatma davranışı için
[toplamanın nasıl çalıştığı](../COLLECTION.md) belgesine bakın.

Oturumlar ve gizli bilgiler şifrelenir. Mesaj içeriği, medya ve dışa aktarımlar için şifreli bir
disk veya birim gerekir. Günlük imzalarını güvenilir bir anahtara karşı doğrulayın ve kontrol
noktalarını ayrı saklayın. Seçilen toplama modu için yakalama kayıtlarını, harici zaman
makbuzlarını ve ortam tasdiklerini inceleyin.

Yedekleme/geri yükleme için [OPERATIONS.md](../OPERATIONS.md), barındırma için
[DEPLOYMENT.md](DEPLOYMENT.md) ve hizmet örnekleri için [deploy/](../../deploy/README.md)
belgelerini okuyun. Kurulu panel ayrıca `/guide.html` adresinde çevrimdışı bir kurulum kılavuzu
içerir.

Fiilen yapılan doğrulamalar ve kalan sınırlar [VERIFICATION.md](../VERIFICATION.md) ve
[READINESS.md](../internal/READINESS.md) belgelerinde kayıtlıdır.
