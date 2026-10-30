[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · [Español](../es/QUICKSTART.md) · [Português (Brasil)](../pt/QUICKSTART.md) · **Türkçe** · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · [Bahasa Indonesia](../id/QUICKSTART.md) · [Tiếng Việt](../vi/QUICKSTART.md) · [简体中文](../zh/QUICKSTART.md)

# TgWitness hızlı başlangıç

TgWitness, hesaplarınızın erişebildiği Telegram gruplarını ve kanallarını gözlemlemek için kullanılan bağımsız bir uygulamadır. Kendi veri diziniyle yerel olarak çalışır.

**İlk kez mi ziyaret ediyorsunuz?** Hesabınızı bağlamadan önce [demoyu inceleyin](#arayüzü-keşfedin). Proxy'ler, tanıklar, veri aktarımları veya sunucu kurulumu için [bir kılavuz seçin](../README.md).

## Yükle ve başlat

Bir yöntem seçin. Sürüm derlemesi yayınlandıktan sonra taşınabilir indirme dosyaları kullanıma sunulur:

| Barındırma | Yüklü bir şey yok | Kaynak: Python 3.11+ | Docker: Engine/Desktop ile Compose 2.20+ |
| --- | --- | --- | --- |
| Windows | GitHub Sürümleri'nden `TgWitness-<version>-windows-amd64-portable.zip` dosyasını çıkarın, `TgWitness.cmd` dosyasına çift tıklayın | `Start.cmd` öğesine çift tıklayın | `scripts\Docker.cmd` öğesine çift tıklayın |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

Kaynak kod yöntemleri için, GitHub Releases'tan kaynak ZIP dosyasını indirip açın veya depoyu klonlayın. `Start.cmd`, uygun bir Python bulunamadığında (winget veya imzalı python.org yükleyicisi) Windows kullanıcınız için Python 3.12'yi yüklemeyi önerir. `start.sh`, Python eksikse Linux dağıtımınız veya macOS için tam yükleme komutunu görüntüler. Kaynak kodun ilk çalıştırılması, `.venv` dosyasını oluşturur ve bağımlılıkları otomatik olarak yükler.

Docker, uygulamayı derler ve arka planda çalıştırır; ana bilgisayarda Python bulunması gerekmez. `scripts\Docker.cmd` ve `scripts/docker-start.sh`, konteyner düzgün çalıştığında panel adresini ve jetonu görüntüler. Desteklenen tüm ana bilgisayarlarda kullanılabilecek eşdeğer Docker komutları şunlardır:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

**http://127.0.0.1:8787** dosyasını açın. Docker yardımcı programı veya ikinci Docker komutu tarafından yazdırılan jetonu kullanın ya da taşınabilir veya kaynak kurulum için **data/live/panel-token.txt dosyasını** okuyun. Aşağıdaki **"Telegram'a Bağlan"** bölümünden devam edin. Yerel ve Docker kurulumları ayrı depolama alanları kullanır; Docker'ı başlatmak mevcut bir yerel günlüğü içe aktarmaz.

Sunucu için [dağıtım](DEPLOYMENT.md), otomatik HTTPS, yeniden başlatma, yayınlanan görseller, güncellemeler ve yedeklemeleri kapsar.

## Arayüzü keşfedin

1. Taşınabilir paketteki **TgWitness-Demo.cmd** **dosyasını**, Windows kaynak klasöründeki **scripts\Demo.cmd** dosyasını veya Linux/macOS'ta `sh start.sh --demo` dosyasını çalıştırın. Kaynak dosyasını çalıştırdığınızda önce `.venv` dosyası oluşturulur ve bağımlılıklar yüklenir.
2. **http://127.0.0.1:8787** dosyasını açın.
3. Yerel demo, örnek günlüğü otomatik olarak açar. Doğrudan yerel erişim için token kopyalamaya gerek yoktur.

Demo mesajları kurgusaldır. Demo modunda gerçek bir Telegram hesabına bağlanılamaz.

## Telegram'a bağlanın

> [!WARNING]
> **Kaybetmeyi göze alamayacağınız hiçbir şeyi kullanmayın.** Kişisel veya değerli hesaplarınızı bağlamamanızı ve değer verdiğiniz bir hesap üzerinde API kimliği / hash oluşturmamanızı şiddetle tavsiye ederiz. Telegram, istemciden bağımsız olarak hesapları öngörülemez bir şekilde ve genellikle kalıcı olarak yasaklar. Sorunsuz bir test çalışması TgWitness'e değil Telegram'a bağlıdır ve ileride herhangi bir garanti vermez.

1. Yerel demo çalışıyorsa, onu durdurun ve **Start.cmd** dosyasını veya `sh start.sh` komutunu çalıştırın. Aksi takdirde, yukarıda başlatılan canlı kurulumu çalışır durumda bırakın.
2. Paneli açmak için kurulum yönteminize uygun panel jetonunu kullanın.
3. Proxy'ye ihtiyacınız varsa, bunu **Hesap → Ayarlar → Bağlantı ayarları → Bağlantı yolunu değiştir** seçeneği altında kaydedin.
4. **Hesap** bölümünde telefon numaranızı girin ve **Devam'a** basın, **QR kodu → QR kodunu göster'i** seçin veya dosyaları seçip **Hesabı bağla'ya** basın. **API Kimliği + Hash** isteğe bağlıdır: çalışma alanı, kaydedilmiş veya içe aktarılmış çifti ya da yerleşik havuzdan çalışan bir çifti kullanır. Kendi uygulamanızı kullanmak için, API Kimliği alanına bir `API ID:API Hash` çifti yapıştırın. Tam bir yetkilendirme anahtarı için **Yetkilendirme anahtarı'nı** seçin, 512 onaltılık karakterin tamamını yapıştırın ve sağlanan DC Kimliği'ni seçin. Kullanıcı Kimliği isteğe bağlıdır ve girildiğinde işaretlenir.
5. Seçtiğiniz oturum açma yöntemini tamamlayın: telefon/kod/2FA, QR kodu için oturum açılmış bir Telegram uygulamasından onay veya desteklenen bir yetkili oturum içe aktarımı.
6. Görüntülenen hesap kimliğini kontrol edin. Açık **Kaynaklar**: sohbetleriniz otomatik olarak yüklenir; gruplarınızı ekleyin.
7. "**Hangi değişikliklerin korunacağını seçin**" bölümünde, olay kategorilerini veya "**Mesajlar, düzenlemeler ve silme işlemleri"** ön ayarını seçin, ardından izleme ayarlarını kaydedin.
8. Ek ayarlarını ayrı ayrı seçin, ardından **Gözlem başlat düğmesine** basın.

API kimlik bilgileri uygulamanızı tanımlar; tek başlarına bir hesaba yetki vermezler. Özel gruplar için herkese açık kullanıcı adı gerekmez, ancak hesabınızın erişim izni olmalıdır.

Mevcut hesaplar için [hesaplara ve oturum formatlarına](../ACCOUNTS.md) bakın: panel, Telethon StringSession, Telethon/Pyrogram SQLite, tek hesaplı TData ZIP ve desteklenen hesap JSON formatlarını kabul eder. Bir oturumu ve ona ait JSON dosyasını birlikte seçin, ardından "**Hesabı bağla"** düğmesine basın. Aynı isteğe bağlı API ayarlarıyla QR koduyla giriş de yapılabilir. TDLib, botlar ve toplu hesap listeleri desteklenmemektedir.

Başka bir hesap eklemek için hesap seçicinin yanındaki **+ işaretine** basın veya **Hesap → Ayarlar → Bağlantı ayarları → Çalışma alanları'nı** açın ya da **Hesaplar'ı** kullanın. Çalışma alanlarının ayrı oturumları, günlükleri, anahtarları, kaynakları ve kuyrukları vardır. Görünümler arasında geçiş yapıldığında diğer toplayıcılar çalışmaya devam eder. Bu kurulumda aynı Telegram hesabı iki çalışma alanına atanamaz. Çalışma alanlarının sayısı sabit değildir; hepsi tek bir işlemi paylaşır, bu nedenle kapasite makineye bağlıdır.

Canlı panel jetonu, Telegram yetkilendirmelerinize ve kaydedilmiş materyallerinize erişimi korur; bu jeton, Telegram API kimlik bilgilerinden ayrıdır. Yalnızca açıkça başlatılmış ve doğrudan erişilen yerel bir demo otomatik olarak giriş yapabilir. Uzak/proxy üzerinden erişilen bir demo ise hâlâ `data/demo/panel-token.txt` kullanır.

## İnceleme ve dışa aktarma

- **Günlük:** Gözlemleri kaynağa ve olay türüne göre arayın ve filtreleyin.
- Bir olayı seçerek orijinal kaydını, kaynağını ve kaydedilmiş sürümlerini inceleyin.
- Düzenleme ayrıntıları, mevcut önceki/sonraki içeriği gösterir. Silme ayrıntıları, varsa en son yakalanan içeriği gösterir; kimliği bilinmeyen bir aktör ise bilinmez olarak kalır.
- **Dışa aktarma formatları:** imzalı ZIP, JSONL, CSV ve çevrimdışı HTML.
- **Sohbetin tam olarak dışa aktarılması** (Kaynaklar → Sohbetin tam olarak dışa aktarılması): Bir sohbetin görünür geçmişinin tamamını, `chat.json` (Telegram dışa aktarma stili) ve okunabilir bir `chat.html` içeren imzalı bir paket olarak indirin. Özel sohbetler, hesap üye olduğunda çalışır. Bu, silinmiş veya daha önce düzenlenmiş mesajların yeniden oluşturulmuş hali değil, o anki bir anlık görüntüdür. Bir kopyayı `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256` ile doğrulayın.
- **Kontrol noktası kaydetme:** imzalanmış günlük sınırını toplayıcının dışında tutun.
- **İmzalı çalıştırma makbuzunu indirin:** toplayıcının program/sürüm kaydını saklayın.
- **Zaman damgası isteği hazırlama:** bir zaman damgası yetkilisi için çevrimdışı bir istek hazırlayın; yanıtı almak ve doğrulamak için [TIMESTAMP.md dosyasını](../TIMESTAMP.md) izleyin.
- **Günlüğü doğrulayın:** olay imzalarını ve zincir bağlantılarını kontrol edin. ZIP dışa aktarma işlemi, medya dosyalarını da kontrol eder.

Desteklenen tarayıcılar, büyük boyutlu dışa aktarımları doğrudan seçilen bir dosyaya kaydeder. Diğer tarayıcılar ise en fazla 128 MiB'lik bir tampon alanı kullanır. Sunucu çalışırken, akış CLI'si tüm yanıtı tampona almadan daha büyük boyutlu indirmeleri destekler:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

Başka bir çalışma alanı için, **İhracat → Çalışma Alanı Kimliği'ni** kullanarak `--profile ID` ekleyin. Uzak bir sunucu için `--url https://your-server` ekleyin. Varsayılan aktarım sınırı 5 GiB'dir; `--max-mib` ile bu sınır değiştirilebilir. İmzalı ZIP içeriği, varsayılan olarak ayrı bir 4 GiB sıkıştırılmamış doğrulama sınırına sahiptir (**Parameters** bu sınırı artırır; bu tür arşivleri `verify.py --max-gib N` ile doğrulayın). Doğrulayıcının güvenilir bir kopyasını ve bağımsız olarak saklanan anahtar parmak izi/kontrol noktasını kullanarak arşivi doğrulayın.

## Kurulumu kontrol edin

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check`, yerel bağımlılıkları, imza desteğini, depolama alanını, anahtar yapılandırmasını ve dinleme adresini kontrol eder. Herhangi bir şey yüklemez veya Telegram'a bağlanmaz. Bağlantı noktası meşgulse, başka bir örnek çalışıyor olabilir. Farklı bir `--port` kullanın veya önce onu durdurun.

Başlatıcı, `.venv` konumuna kurulur. Yardımcı `python -m tgwitness...` komutları, ilgili ortam halihazırda etkinleştirilmemişse, Windows'ta `.venv\Scripts\python.exe` veya Linux/macOS'ta `.venv/bin/python` komutunu kullanmalıdır.

## Oturumlar, koruma ve işletim

Kapalı, tutarlı bir Telethon SQLite `.session` dosyası, `python -m tgwitness.sessions account.session --out account.tgwitness-session` ile yerel olarak dönüştürülebilir ve ardından Account'a yüklenebilir. Doğrudan dosya içe aktarma ve QR koduyla giriş seçenekleri de mevcuttur. Giriş formatları, SOCKS5, HTTP CONNECT, MTProxy ve harici anahtarlar hakkında bilgi için [CONNECTION-SECURITY.md dosyasına](../CONNECTION-SECURITY.md) bakın.

**Gözlemi duraklatmak**, veri toplama işlemini durdurur. **Kilitleme** yalnızca tarayıcı erişimini kapatır. Sekmeyi kapatmak, toplayıcı sürecinin çalışmaya devam etmesine neden olur. Süreci durdurmak, veri toplama işlemini kesintiye uğratır; geçmiş anlık görüntüsü, kaçırılan tüm düzenlemeleri veya silme işlemlerini yeniden oluşturamaz. Olay politikaları, ek kuyrukları, hesap izolasyonu ve yeniden başlatma davranışı için [veri toplama işleminin nasıl çalıştığını](../COLLECTION.md) inceleyin.

Oturumlar ve gizli bilgiler şifrelenmiştir. Mesaj içeriği, medya dosyaları ve dışa aktarımlar için şifrelenmiş bir disk veya birim gereklidir. İmzalar, güvenilir bir anahtara göre bütünlüğü sağlar; Telegram'ın kaynağını doğrulamaz veya toplayıcıyı ve anahtarını kontrol eden bir operatör tarafından sahte içerik oluşturulmasını engellemez.

Yedekleme/geri yükleme için [OPERATIONS.md dosyasını](../OPERATIONS.md), barındırma için [DEPLOYMENT.md dosyasını](DEPLOYMENT.md) ve hizmet örnekleri için [deploy/ dizinini](../../deploy/README.md) inceleyin. Yüklenen panelde ayrıca `/guide.html` adresinde bir çevrimdışı kurulum kılavuzu da bulunmaktadır.

Gerçek doğrulama ve mevcut sınırlamalar, [VERIFICATION.md](../VERIFICATION.md) ve [READINESS.md](../internal/READINESS.md) dosyalarında kaydedilmiştir.
