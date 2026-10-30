[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · [Español](../es/DEPLOYMENT.md) · [Português (Brasil)](../pt/DEPLOYMENT.md) · **Türkçe** · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · [Bahasa Indonesia](../id/DEPLOYMENT.md) · [Tiếng Việt](../vi/DEPLOYMENT.md) · [简体中文](../zh/DEPLOYMENT.md)

# Dağıtım ve işletim

## Bir kurulum seçeneği belirleyin

Taşınabilir paket için, GitHub Sürümleri'nden `TgWitness-<version>-windows-amd64-portable.zip` dosyasını çıkarın. Diğer yöntemler için, kaynak ZIP dosyasını indirip açın veya depoyu klonlayın, ardından proje dizininden aşağıdakileri çalıştırın:

| Kurulum | Başlangıç | Arka planda çalışır mı? |
| --- | --- | --- |
| Windows taşınabilir paketi | `TgWitness.cmd` | Hayır; pencereyi açık tutun. |
| Windows için yerel sürüm | `Start.cmd` | Hayır; arka planda çalıştırmak için isteğe bağlı oturum açma görevini kullanın. |
| Linux/macOS için yerel sürüm | `sh start.sh` | Hayır; arka planda çalıştırmak için systemd/launchd kullanın. |
| Desteklenen herhangi bir ana bilgisayarda Docker | `docker compose up -d --build --wait` | Evet, Docker arka plan programı çalışırken. |
| Windows'ta Docker yardımcısı | `scripts\Docker.cmd` | Evet; yardımcı program, web sunucusunun durumunu bekler. |
| Linux/macOS üzerinde Docker yardımcısı | `sh scripts/docker-start.sh` | Evet; yardımcı program, web sunucusunun durumunu bekler. |

Yerel başlatma işlemi, özel bir `.venv` oluşturur ve sabitlenmiş bağımlılıkları yükler. Docker, ana bilgisayar Python'una ihtiyaç duymadan bunları görüntü içinde derler. İlk kurulum için İnternet erişimi gereklidir. Python 3.11+ bulunmadığında, `Start.cmd`, mevcut Windows kullanıcısı için Python 3.12'yi yüklemeden önce sorar (winget; aksi takdirde, Python Software Foundation imzasını kontrol ettikten sonra python.org yükleyicisi kullanılır); hiçbir zaman yönetici ayrıcalıkları talep etmez. Docker ve işletim sistemi hizmetleri ön koşul olarak kalır.

Yerel ve taşınabilir kurulumlar, kendi klasörleri içinde `data/live` kullanır. Docker ise `/data` konumunda `tgwitness-data` adlı birim kullanır. Veri dizinini kasıtlı olarak tamamen taşıyana kadar bunlar ayrı kurulumlardır. Yeni bir Docker konteynerinin yerel hesapları otomatik olarak algılamasını beklemeyin.

## Kurulum gereksinimleri

Yerel kurulum için Python 3.11 veya üstü sürümü (`venv` ve `ensurepip` ile birlikte), ilk bağımlılık kurulumunda internet erişimi ve `.venv` için yazma izni olan bir proje dizini gereklidir. Pakete dahil olan panel için Node.js veya ön uç derlemesi gerekmez. Başlatıcıyı normal işletim sistemi hesabınızdan çalıştırın; TgWitness için yönetici/root ayrıcalıkları gerekmez.

- **Windows:** `Start.cmd` önce `py -3`'yi, ardından `python`'yi, sonra da varsayılan kullanıcı başına ve Program Files kurulum klasörlerini kontrol eder ve 3.11 veya daha yeni bir sürümü gerektirir. Hiçbiri işe yaramazsa, yukarıda açıklanan otomatik kullanıcı başına kurulum seçeneğini sunar. `py -3 start.py` de çalışır. Taşınabilir paket için Python'a hiç gerek yoktur.
- **Linux:** `start.sh`, `python3.13`, `python3.12`, `python3.11`, `python3` ve `python` komutlarını dener ve uygun bir seçenek bulunmadığında apt, dnf, pacman, zypper, apk veya Homebrew için kurulum komutunu görüntüler. Debian/Ubuntu kurulumlarında, seçilen yorumlayıcıyla eşleşen `python3-venv` paketinin yüklenmesi gerekebilir. Dağıtımın eski varsayılan Python sürümü, Python 3.11+ ile değiştirilmeli veya bu sürümle desteklenmelidir.
- **macOS:** Güncel bir Python 3.11+ dağıtımını yükleyin; işletim sistemi tarafından sağlanan yorumlayıcının gereksinimleri karşıladığını varsaymayın. Proje dizininden `python3 start.py` dosyasını kullanın.
- **Docker:** Compose v2.20 veya daha yeni bir sürümle birlikte Docker Engine/Desktop kullanın. Docker Desktop, Windows üzerinde Linux konteynerleri kullanmalıdır. Konteyner kendi Python bağımlılıklarını yükler; ana bilgisayarda ayrı bir Python kurulumu gerekmez.

Veri dizini için kalıcı yerel depolama alanı kullanın. Mesajlar, medya, WAL büyümesi, dışa aktarmalar ve yedeklemelerden yola çıkarak kapasite planlaması yapın; her iş yükü için kanıta dayalı, evrensel bir minimum disk/RAM spesifikasyonu bulunmamaktadır. Uyumlu bağımlılık tekerlekleri (dependency wheels) bulunmayan CPU mimarileri ve Python sürümleri, ek derleme araçları ve kendi yeterlilik testlerini gerektirebilir. "Taşınabilir" ifadesi, evrensel işletim sistemi veya donanım desteği iddiası değildir.

Windows 11/Python 3.12 yerel olarak doğrulanmıştır. Linux/macOS/konteyner tanımları ve CI sağlanmıştır ancak bu geliştirme sunucusunda çalıştırılmamıştır. Kesin kapsam için [VERIFICATION.md](../VERIFICATION.md) dosyasına bakınız.

## Yerel bilgisayar

Windows'ta `Start.cmd`, Linux/macOS'ta ise `sh start.sh` komutunu kullanın. `scripts\Setup.cmd` veya `sh start.sh --setup-only` komutları ortamı hazırlar. Başlatıcı, ilk kullanımda bağımlılıkları yükler; sonraki başlatmalarda mevcut ortam kullanılır. Kurulum ve Telegram verilerinin toplanması için internet erişimi gereklidir, ancak mevcut kayıtların görüntülenmesi ve dışa aktarımların oluşturulması çevrimdışı olarak yapılabilir.

Kurulumdan sonra `python start.py --check` komutunu çalıştırarak, bir toplayıcı başlatmadan yerel bağımlılıkları, Ed25519'u, depolama alanını, anahtar yapılandırmasını ve dinleme adresini kontrol edin. Yapılandırılmış çıktı için `--json` komutunu kullanın. İstenen `--data-dir`, `--host` ve `--port` parametrelerini aktarın. Bu kontrol, paketleri yüklemez, bir günlük oluşturmaz veya Telegram'a bağlanmaz; bir bütünlük veya kapsama yeterliliği değerlendirmesi değildir. Başlangıç işlemi, mevcut günlükleri ayrı olarak doğrular. `python start.py --help` da kurulumdan kaçınır.

Seçenekler:

start.py dosyasını kullandıktan sonra, Windows'ta `.venv\Scripts\python.exe`, Linux/macOS'ta `.venv/bin/python` komutlarıyla yardımcı komutları çalıştırın veya önce o ortamı etkinleştirin. Aşağıdaki `python -m ...` örnekleri, ortamın etkin olduğunu varsaymaktadır.

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

Ortam değişkenleri: TGWITNESS_DATA, TGWITNESS_HOST, TGWITNESS_PORT, TGWITNESS_TOKEN. TGWITNESS_VAULT_KEY_FILE, yeni bir kurulum için harici anahtar modunu seçer; aşağıya bakınız. TGWITNESS_TOKEN, belirtilirse en az 24 karakter içermelidir; kriptografik olarak rastgele bir değer kullanın. Bu değer belirtilmezse, uygulama panel-token.txt dosyasında 256 bitlik rastgele bir token oluşturur. Ortam değişkeni bu dosyayı yeniden yazmaz. Kimlik bilgilerini yenilemek için sistemi yeniden başlatın.

Bir veri dizinine tam olarak tek bir işlem sahip olabilir. Platformlar arası bir işletim sistemi dosya kilidi, kazara eşzamanlı yazma işlemlerini önler. Tek bir Uvicorn işçisi kullanın. Panel, profiller/<id>/ altındaki ek çalışma alanı dizinleriyle birlikte istediği sayıda çalışma alanını yönetebilir. Ayrı hizmet örnekleri için ayrı dizinler ve bağlantı noktaları kullanın. SQLite WAL dosyaları, ağ dosya sisteminde değil, yerel kalıcı depolama alanında bulunmalıdır. Replikalar arasında tek bir birimi paylaşmayın.

## Windows taşınabilir paketi

Her GitHub Sürümü, `TgWitness-<version>-windows-amd64-portable.zip` ve `.sha256` öğelerini içerir. Bu sürüm, python.org'dan alınan resmi gömülebilir Python 3.12 çalışma zamanını (`tools/build_portable.py` öğesinde sabitlenmiş sağlama toplamı), TgWitness ve sabitlenmiş bağımlılıklarını ve üç başlatıcıyı içerir:

| Dosya | Amaç |
| --- | --- |
| `TgWitness.cmd` | Paneli başlatın; ek seçenekler aktarılır, örneğin `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | `data\demo` adresindeki sentetik demoyu başlatın |
| `TgWitness-Check.cmd` | Başlatmadan hazırlık kontrolünü çalıştırın |

Arşivin tamamını `Documents\TgWitness` gibi yazılabilir bir klasöre çıkarın; ZIP dosyasının içinden veya Program Files klasöründen çalıştırmayın. Çalışma ortamı izole bir modül yolu kullanır, bu nedenle diğer Python kurulumları ve `PYTHONPATH` onu etkilemez. Veriler, paketin `data` klasöründe kalır. Güncellemek için TgWitness'i durdurun, yeni sürümü yeni bir klasöre çıkarın ve `data` klasörünü buraya kopyalayın.

Python 3.12 kullanarak 64 bit Windows üzerinde kendiniz derleyin:

~~~sh
python tools/build_portable.py
~~~

Oluşturucu, çalışma zamanı sağlama toplamını doğrular, kısıtlı bağımlılıkları pakete yükler, gömülü yorumlayıcıyla hazırlık kontrolünü çalıştırır ve ZIP dosyasını ve sağlama toplamını `dist/` dosyasına yazar.

## Konteyner

```sh
docker compose up -d --build --wait
```

Bu, /data için adlandırılmış bir kalıcı birim oluşturur. Web bağlantı noktası 127.0.0.1:8787 adresine eşlenir. İşlem, yetkileri kaldırılmış UID 10001 olarak, salt okunur bir kök dosya sistemi ve yazılabilir /data ile /tmp dizinleriyle çalışır. `--wait`, geri dönüş yapmadan önce web sunucusunun durumunu kontrol eder; Telegram yetkilendirme veya mesaj teslimi işlemi gerçekleştirmez. Sağlanan yardımcı programlar, derlemeden sonra 180 saniyelik bir hazırlık zaman aşımı kullanır. İlk bağımlılık indirmeleri bu süreden daha uzun sürebilir.

Her iki temel Compose dosyası da proje adı `tgwitness` kullanır; bu nedenle, yeni bir sürümü başka bir dizine çıkardığınızda sistem otomatik olarak yeni bir veri birimi seçmez. O proje için yalnızca bir dağıtımı aktif tutun. Bağımsız kurulumlar için benzersiz bir `docker compose -p NAME ...` ve farklı bir ana bilgisayar bağlantı noktası kullanın ve güncellemelerde her ikisini de koruyun. Farklı bir proje adı kullanan eski bir dağıtım için, `-p` ile orijinal adını kullanmaya devam edin; `docker compose ls` mevcut projeleri listeler.

`deploy/env.example`'yi `.env`'ye kopyalayın ve `TGWITNESS_PORT`'yi farklı bir loopback bağlantı noktası kullanacak şekilde değiştirin. Örneğin, `TGWITNESS_PORT=8788` paneli `http://127.0.0.1:8788` adresinde gösterir; konteyner ise hala 8787 numaralı bağlantı noktasını dinler. `.env`, Git tarafından göz ardı edilir.

İlk jetonu alın:

~~~sh
docker compose exec tgwitness cat /data/panel-token.txt
~~~

Yararlı komutlar:

```sh
docker compose ps
docker compose logs --tail 100 -f
docker compose stop
docker compose up -d --wait
```

`restart: unless-stopped`, bir çökme veya Docker arka plan hizmetinin yeniden başlatılmasından sonra toplayıcıyı yeniden başlatır. Linux sunucusunda, dağıtımınızın hizmet yöneticisini (genellikle `sudo systemctl enable --now docker`) kullanarak önyükleme sırasında Docker'ı etkinleştirin. Windows/macOS'ta, Docker Desktop'ın oturum açıldığında başlatma ayarını etkinleştirin. Masaüstünden çıkış, uyku modu veya durdurulmuş bir Docker arka plan hizmeti, veri toplama işlemini kesintiye uğratabilir. Açıkça durdurulmuş bir konteyner, siz onu yeniden başlatana kadar durdurulmuş halde kalır.

Örnek yapılandırmada /tmp biriminin üst sınırı 512 MiB olarak belirlenmiştir. Dışa aktarma yapısı, bunun yerine her çalışma alanının `temporary-exports/` öğesini kalıcı /data dizininde kullanır. Eşzamanlı dışa aktarmalar, günlük/WAL büyümesi, medya ve yedeklemeler için burada yer ayırın. Başlatıcı ve Docker, qualified runtime bağımlılık sürümlerini sabitlemek için deploy/constraints.txt dosyasını kullanır. Bu, hash kilitli bir tedarik zinciri değildir: Python temel görüntüsü ve paket yapı öğeleri hâlâ bağımsız sürüm onayına tabidir.

Günlüğü ve anahtarları silmek niyetinde değilseniz, docker compose down -v komutunu kullanmayın. Konteyner durum raporu, web sunucusunun erişilebilirliğini gösterir; Telegram verilerinin başarılı bir şekilde yakalandığını göstermez. Panelin toplayıcı durumunu, kalp atışını, hatalarını ve kapsama olaylarını inceleyin.

### Bağımsız tanık profili

İsteğe bağlı `witness` hizmeti, kendi konteynerinde [bağımsız tanık](../WITNESS.md) çalıştırır; bu hizmetin `witness-data` biriminde kendi anahtarı ve günlüğü bulunur ve toplayıcı için yalnızca salt okunur bir tanık jetonu vardır. Jetonu panelin **Witness** sayfasında oluşturun, bir bot jetonu ve kanal ile birlikte `.env` adresine ekleyin, ardından profili başlatın:

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

Hizmet, Compose ağı içindeki toplayıcıya `http://tgwitness:8787` adresinden ulaşır (`TGWITNESS_WITNESS_COLLECTOR` bu adresi geçersiz kılar; örneğin, başka bir çalışma alanı için `/profiles/<workspace ID>`). Başka biri tarafından işletilen ayrı bir sunucudaki tanık için, orada `deploy/compose/compose.witness.yaml` dosyasını kullanın ve `TGWITNESS_WITNESS_COLLECTOR` dosyasını toplayıcının HTTPS adresine ayarlayın; bu dosya yalnızca tanığı içerir.

## Yayınlanmış bir görüntüyü yükleyin

Bu, başarılı bir [sürüm iş akışı](#otomatik-github-sürümleri) ve halka açık GHCR paketi yapılandırmasının ardından kullanıma sunulur. Deponun sahibi/adı bu kaynak ağacına sabit olarak kodlanmamıştır. İlgili sürümün iş akışı özetinde gösterilen görüntüyü kullanın.

`deploy/env.example` öğesini `.env` öğesine kopyalayın. `TGWITNESS_IMAGE` öğesini, **küçük harfli** depo yolunu kullanarak yayınlanan sürüme ayarlayın, örneğin:

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.7.0
TGWITNESS_PORT=8787
```

`compose.yaml` yerine bu dosyayı tek başına çalıştırın:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

Ana bilgisayarda kaynak derleme, Python veya derleyici gerekmez. Sürüm iş akışı, Docker Desktop'ın Linux VM'si dahil olmak üzere Linux AMD64 ve ARM64 kapsayıcılarını hedefler. İş akışı özetinden bir sürüm etiketi veya `ghcr.io/owner/repository@sha256:...` kullanın. `latest` etiketinin taşınması veya gözetimsiz uygulama yükseltmesi yapılandırılmamıştır. Görüntü ve kaynak varyantları, proje adları eşleştiğinde aynı veri hacmini kullanır.

## Sunucuda otomatik HTTPS

Docker yüklü bir sunucu, sizin kontrolünüz altındaki bir alan adı ve kalıcı yerel depolama alanı kullanın. Alan adının A/AAAA kayıtlarını sunucuya yönlendirin; yalnızca IPv6 erişimi varsa AAAA kaydını yayınlayın. Sertifika düzenlenmesi için gelen TCP 80 ve 443 bağlantılarına ve giden DNS/HTTPS bağlantılarına izin verin. Bu bağlantı noktaları başka hizmetler tarafından kullanılmamalıdır.

`deploy/env.example`'yi `.env`'ye kopyalayın ve şema veya yol olmadan bir ana bilgisayar adı belirleyin:

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

HTTPS overlay ile kaynak derlemesini başlatın:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

Yayınlanmış bir resim için, bunun yerine ilk dosya olarak `deploy/compose/compose.image.yaml`'yi kullanın. `-f` argümanlarının her ikisini de daha sonraki durum, günlük, güncelleme ve durdurma komutları için saklayın.

Caddy, sertifikayı alır ve yeniler, HTTP'yi HTTPS'ye yönlendirir ve istekleri özel Compose ağındaki toplayıcıya iletir. Sertifika durumu kendi kalıcı biriminde bulunur. Toplayıcının doğrudan ana bilgisayar bağlantı noktası yalnızca döngü içi (loopback) olarak kalır. Sağlanan Caddy yapılandırması, erişim günlüğü kaydını etkinleştirmez.

`https://watch.your-domain.org` dosyasını açın ve panel jetonunu girin. Hazırlık durumu, sertifika verilmesini veya harici erişilebilirliği teyit etmez. HTTPS hazır değilse, DNS'yi, güvenlik duvarı kurallarını ve aşağıdakileri kontrol edin:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

Sağlanan Caddy görüntüsü, `2-alpine` etiketinin hemen ardından gelir. Pull işlemi bu görüntüyü yeniler; sabit altyapı sürümlerine ihtiyacınız varsa, dağıtımınıza test edilmiş bir özeti sabitleyin.

## Güncellemeler ve yedeklemeler

Güncellemeler sırasında Compose proje adını ve veri hacmini koruyun. Öncelikle toplayıcıyı durdurun ve tam bir yedekleme yapın. Varsayılan kaynak tabanlı dağıtım için:

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

Her seferinde, depo dışında yeni bir yedekleme hedefi kullanın ve bunu hesap erişim materyali olarak koruyun. Örnek yol sadece açıklayıcı niteliktedir; kendi özel yedekleme konumunuzu kullanın. Gizli dosyalar, tüm çalışma alanları, anahtarlar, günlükler ve medya dahil olmak üzere tüm dizini kopyalayın. Yapılandırılmışsa, harici kasa anahtarını ayrı olarak yedekleyin. Kanıt ZIP dosyası, geri yüklenebilir bir uygulama yedeği değildir. HTTPS için, sertifika/hesap durumunu korumak istiyorsanız Caddy birimlerini de saklayın.

Kaynak dağıtımı için yeni sürüm dosyalarını edinin ve şu komutu çalıştırın:

```sh
docker compose up -d --build --wait
```

Görüntü dağıtımı için `TGWITNESS_IMAGE`'yi istediğiniz sürüme değiştirin, ardından şunu çalıştırın:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

Yukarıdaki durdurma/kopyalama komutları için de kurulumunuzun Compose dosyalarını kullanın. `.env` öğesini, özel yapılandırmayı ve aynı proje adını koruyun. `down`, adlandırılmış birimleri korur; **`down -v`** ise **bunları siler**. `.venv` öğesini işletim sistemleri veya Python sürümleri arasında kopyalamayın. Yerel güncellemeler için TgWitness'i durdurun, tüm veri dizinini yedekleyin, kaynak dosyaları değiştirin ve başlatmadan önce `python start.py --setup-only` komutunu çalıştırın.

Güncellemeden sonra panel erişimini, hesap kimliğini, gözlem durumunu ve kapsama alanını kontrol edin. Yeniden başlatma, kaçırılan Telegram güncellemelerini geri yüklemez. Gelecekteki bir sürümde depolama formatlarında değişiklik olması durumunda, geri alma işlemi için güncelleme öncesi yedeğin kullanılması gerekebilir.

## Otomatik GitHub sürümleri

Bu proje, Actions özelliği etkinleştirilmiş bir GitHub deposuna gönderildikten sonra [sürüm yayınlama iş akışı](../../.github/workflows/release.yml) kullanıma hazır hale gelir. Bu iş akışı, ön sürüm dahil olmak üzere bir GitHub Sürümü yayınlandığında çalışır. Taslaklar ve etiket gönderimleri tek başına paketlerin yayınlanmasına yol açmaz.

1. Paket sürümünü ve değişiklik günlüğünü belirleyin, ardından `v` etiketiyle ve tam `pyproject.toml` sürümüyle (örneğin `v0.7.0`) bir sürüm yayınlayın.
2. İş akışı, etiketi doğrular ve paylaşılan Windows/Linux/macOS Python, genel/hesap içe aktarma/QR tarayıcı, kaynak paket ve Docker kontrollerini çalıştırır. Ayrıca, Python 3.12 kullanılarak üç işletim sisteminin tümünde yeni yerel kurulum da gerçekleştirilir.
3. Bu kontroller başarıyla tamamlandıktan sonra, QEMU altında bir ARM64 görüntüsünü hızlı test eder, AMD64/ARM64 görüntülerini `ghcr.io/<lowercase-owner>/<lowercase-repository>:<version>` adresine yayınlar ve kaynak ZIP dosyasını, sağlama toplamını ve Python wheel dosyasını sürüme ekler. Ayrı bir Windows işi, taşınabilir ZIP dosyasını ve sağlama toplamını derler ve ekler.
4. İlk yayınlamadan sonra, GHCR paket ayarlarını açın ve anonim görüntü çekimleri planlanıyorsa görünürlüğü "**Herkese Açık**" olarak ayarlayın. Yalnızca herkese açık bir kaynak deposu, paketin herkese açık bir konteyner paketi olacağını garanti etmez. Kuruluş politikaları, paket yayınlamasına izin vermelidir. İş akışı `GITHUB_TOKEN` kullanır; depoda kayıt defteri şifresi veya VPS kimlik bilgileri bulunmamalıdır.

Bu yerel hazırlık ile uzaktan iş akışının başarısı henüz kanıtlanmamıştır. ARM64 emülasyonu, yerel donanım veya canlı Telegram yeterliliği değil, bir ön test niteliğindedir. Bu, sürüm paketlemeyi otomatikleştirir; ancak bir sunucuyu başlatmak için hâlâ Compose komutu ve bunun etki alanı/ana bilgisayar ön koşulları gereklidir. Bir sürüm yayınlandığında, mevcut sunucular otomatik olarak güncellenmez veya yeniden başlatılmaz.

## Uzak sunucu

Hizmeti loopback'e bağlı tutun ve bir SSH tüneli kullanın ya da HTTPS'yi bir ters proxy'de sonlandırın. Temel Compose dosyası yalnızca yerel kullanım içindir; isteğe bağlı `deploy/compose/compose.https.yaml` katmanı, yapılandırılmış bir etki alanı için Caddy sağlar. Bearer token'ını URL'lerden ve proxy günlüklerinden uzak tutun. Bir ters proxy, istek boyutunu ve bağlantı hızlarını sınırlamalıdır. Düz HTTP'yi İnternet'e maruz bırakmayın.

[deploy/](../../deploy/README.md) dizininde systemd, bir Windows oturum açma görevi, bir macOS kullanıcı ajanı ve Caddy için örnekler sunulmaktadır. Kurulumdan önce bunların yollarını gözden geçirin ve uyarlayın. Bunlar, yerel olarak yürütülen platform yapılandırmaları değil, şablonlar olarak sağlanmıştır. Normal başlatıcı tarafından hiçbir arka plan hizmeti veya görevi kaydedilmez.

Windows'ta, penceresiz `pythonw.exe` başlatma işlemi, başlangıç/sunucu tanılama bilgilerini veri dizini altındaki `logs/server.log` konumuna kaydeder (dosya başına 5 MiB, iki adet dönüşümlü yedek). Konsol başlatmaları, konsol günlüğünü korur. Her iki modda da HTTP erişim günlüğü devre dışıdır. Günlükleri veri diziniyle koruyun ve paylaşmadan önce gözden geçirin.

## Yeniden başlatma ve boşluklar

En son istenen gözlem durumu kalıcı olarak saklanır. Gözlem etkin durumdaysa, başlangıç sırasında seçilen kaynaklara yeniden bağlanılmaya ve izlemeye devam edilmeye çalışılır. Manuel duraklatma işlemi bu niyeti siler. Başarısız bir yeniden başlatma kayda alınır ve panelde gösterilir.

StringSession, yetkilendirmeyi korur ancak Telethon'un kalıcı güncelleme/varlık durumunu korumaz. Diyaloglar başlangıçta yeniden yüklenir. Telegram/Telethon, çalışırken bazı aktarım kesintilerini telafi edebilir, ancak TgWitness, işlem yeniden başlatmaları arasında kalıcı tekrar oynatma özelliğini garanti etmez. Her başlatma işleminde, bir önceki günlük başlığı ve çevrimdışı sınır kaydedilir. İzleyici, her 10 saniyede bir bağlantı durumunu kontrol eder ve her dakikada bir kalp atışı ekler (**Parametreler → Canlılık kaydı her**). Kısa süreli kesintiler gözden kaçabilir; bağlantılı bir aktarım, güncellemelerin tam olarak iletilmesini garanti etmez. Anlık görüntüler, açıkça güncel geçmiş gözlemleridir ve asla boşlukları doldurmaz.

Medya kuyruğu, her çalışma alanının SQLite veritabanında saklanır. Bir mesaj ve ilgili iş, atomik olarak kaydedilir. Yürütülmesi kesintiye uğrayan işler, başlangıçta yeniden deneme amacıyla kurtarılır. Her indirme işlemi için 120 saniyelik bir temel zaman aşımı süresi ile dosya boyutuna göre 256 KiB/s hızda hesaplanan süre ve ek türü başına 1–2.000 MiB'lik bir sınır vardır; zaman aşımı, hız ve yeniden deneme ayarları **Parametreler** bölümünde bulunur. Toplayıcı, boyutu bilinmeyen dosyaları atlar. Duraklatma işlemi, kuyrukta bekleyen işleri korur. Yeniden deneme, orijinal gözlemlenen dosya tanımlayıcısını kullanır; daha sonra düzenlenmiş bir mesajın en son sürümünü asla kullanmaz. Geçici arızalar için sınırlı sayıda yeniden deneme vardır; FloodWait duraklamaları yeniden başlatma sonrasında da korunur. Medya kurtarma, Telegram güncelleme kurtarmasından ayrıdır ve kaybolan dosyaları yeniden oluşturamaz.

## Yedekleme, geri yükleme ve kapasite

Vault.key, signing.enc, credentials.enc, SQLite veritabanı/WAL dosyaları, medya, token, kontrol noktaları ve tüm profiller/alt dizinler dahil olmak üzere **tüm veri dizin**ini kopyalamadan önce işlemi durdurun. Hedef hizmet durdurulmuşken kopyanın tamamını geri yükleyin. Eksik vault anahtarları veya imza anahtarı uyuşmazlığı, başlatma işleminin başarısız olmasına neden olur; erişimi zorlamak için anahtarları yeniden oluşturmayın.

Gizli yedeklemeleri şifreli tutun ve erişim kontrolü uygulayın. Kanıt ZIP dosyaları, uygulama yedeklemeleri veya Telegram oturum yedeklemeleri değil, taşınabilir inceleme öğeleridir. Otomatik saklama süresi dolduktan sonra silme işlemi yoktur. Tüm mesajlar, ham meta veriler, medya dosyaları, geçici dışa aktarımlar ve yedeklemeler için disk alanı ayırın.

Günlüğün tamamını yüklemek yerine, başlangıç doğrulaması ve akış kayıtlarının dışa aktarılması. Dışa aktarma işlemi, okunan anlık görüntüyü sabitlerken yeni WAL yazma işlemleri devam edebilir; uzun süren dışa aktarma işlemleri WAL sayfalarını tutabilir, bu nedenle disk kapasitesi hâlâ önemlidir. ZIP dosyaları, bağımsız doğrulayıcının varsayılan ayarına uymak için sıkıştırılmamış halde 4 GiB ile sınırlandırılmıştır; **Parametreler → En Büyük İmzalı ZIP seçeneği** bu sınırı artırır ve bu tür arşivler `verify.py --max-gib N` ile doğrulanır. Diğer formatlarda olay sayısı sınırı yoktur. Desteklenen tarayıcılar, yanıt parçalarını kullanıcının seçtiği bir dosyaya akış olarak gönderir. Diğer tarayıcılar en fazla 128 MiB'yi arabelleğe alır ve daha büyük aktarımları kimliği doğrulanmış CLI'ye yönlendirir:

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

Başka bir çalışma alanı için **İhracat → Çalışma Alanı Kimliği**'nden `--profile ID`'yi, uzak bir sunucu için `--format zip|jsonl|csv|html`, `--url https://your-server`'yi veya 5 GiB aktarım sınırını değiştirmek için `--max-mib`'yi kullanın. Düz HTTP yalnızca döngü geri dönüşü için izin verilir. Jetonlar başlıklarda iletilir, yönlendirmeler reddedilir, mevcut dosyalar üzerine yazılmaz ve tamamlanmamış indirmeler tamamlanmış dosyalar olarak yayınlanmaz. TGWITNESS_TOKEN, oluşturulan jetonu geçersiz kılarsa, bu etkin değeri içeren ayrı olarak korunan bir dosya kullanın: panel-token.txt dosyası, geçersiz kılma işlemiyle yeniden yazılmaz. Komutun SHA-256 değeri yalnızca bir aktarım sağlama toplamıdır; imzalı ZIP dosyasını bağımsız olarak doğrulayın.

Sunucu dışa aktarım dosyaları, her çalışma alanının özel `temporary-exports/` dizininde kalır. Başarılı yanıtlar, dosyalarını temizler. Kesintiye uğrayan dışa aktarımlar, özel örnek kilidi tutulmuş haldeyken bir sonraki çalışma alanı başlatıldığında kaldırılır. Bu dizin, depolama tehdidi/kapasite modelinin bir parçasıdır; şifrelenmiş bir veri birimi kullanın. Üretim ölçeğindeki multi-gigabyte aktarımlar için hedef sisteminizde yine de uygunluk testi gereklidir.

Panel, kuyrukta bekleyen/başarısız olan medya öğelerini, en eski bekleyen medya öğelerini, boş disk alanını, Telegram istek duraklamalarını ve erişimi onaylanmamış kaynakları gösterir. Bu tanılama bilgileri, eksiksiz bir uçtan uca teslimat izleme aracı değildir. Çalışma alanları aynı süreci paylaşır; sorunlu bir hesap, diğerlerini yine de etkileyebilir. Ayrı işçi süreçleri, saklama/dönüşüm, kalıcı güncelleme kurtarma, uzaktan kontrol noktası sabitleme, roller ve tam dağıtım yeterliliği konuları hâlâ ele alınmalıdır.

## Bağlantı ve koruma seçenekleri

Bağlantı yolları çalışma alanı başına belirlenir ve yetkilendirme işleminden önce yapılandırılmalıdır. SOCKS5/HTTP CONNECT, sabitlenmiş python-socks bağımlılığını kullanır. MTProxy, Telethon'un deneysel rastgele ara aktarımını kullanır; sahte TLS ee gizli anahtarları desteklenmez. Otomatik doğrudan yedekleme yapılandırılmamıştır. Bu, sistem genelinde geçerli bir ağ yolu değildir.

Yeni kurulumlarda, TGWITNESS_VAULT_KEY_FILE, ayrı olarak korunan rastgele bir ana anahtar dosyasına işaret eder. Bu dosyayı bir konteyner içinde /data dizininin dışında salt okunur olarak bağlayın. Her çalışma alanı ve ana anahtar için public vault.external.json salt meta verilerini ayrı ayrı saklayın. Mevcut yerel kasalar için planlı bir geçiş gereklidir; bu değişkenin ayarlanması, kasaları otomatik olarak dönüştürmez. Mesaj/medya depolama ve dışa aktarımlar uygulama düzeyinde şifrelenmez. Gerektiğinde şifreli birimler ve yeterli miktarda özel geçici depolama alanı kullanın.

Ayrıntılı prosedürler: [bağlantı/güvenlik](../CONNECTION-SECURITY.md) ve [çalışma modları](../OPERATIONS.md).
