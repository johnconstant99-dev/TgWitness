[TgWitness](../../README.md) / [Belgeler](../README.md) / [Klasör](README.md)

![Dağıtım ve kurtarma](../assets/presentation/chapter-operate.svg)

[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · [Español](../es/DEPLOYMENT.md) · [Português (Brasil)](../pt/DEPLOYMENT.md) · **Türkçe** · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · [Bahasa Indonesia](../id/DEPLOYMENT.md) · [Tiếng Việt](../vi/DEPLOYMENT.md) · [简体中文](../zh/DEPLOYMENT.md)

# Dağıtım ve işletim

## Kurulum türünü seçin

Taşınabilir paket için GitHub Releases'tan `TgWitness-<version>-windows-amd64-portable.zip`
arşivini çıkarın. Diğer yöntemler için kaynak ZIP dosyasını indirip çıkarın veya depoyu
klonlayın, ardından proje dizininde aşağıdakini çalıştırın:

| Kurulum | Başlatma | Arka planda çalışır mı? |
| --- | --- | --- |
| Windows taşınabilir paketi | `TgWitness.cmd` | Hayır; pencereyi açık tutun. |
| Yerel Windows kurulumu | `Start.cmd` | Hayır; arka planda çalıştırmak için isteğe bağlı oturum açma görevini kullanın. |
| Yerel Linux/macOS kurulumu | `sh start.sh` | Hayır; arka planda çalıştırmak için systemd/launchd kullanın. |
| Desteklenen herhangi bir ana makinede Docker | `docker compose up -d --build --wait` | Evet, Docker daemon'ı çalıştığı sürece. |
| Windows'ta Docker yardımcısı | `scripts\Docker.cmd` | Evet; yardımcı, web sunucusunun sağlıklı duruma gelmesini bekler. |
| Linux/macOS'ta Docker yardımcısı | `sh scripts/docker-start.sh` | Evet; yardımcı, web sunucusunun sağlıklı duruma gelmesini bekler. |

Üçüncü bir tarafın denetleyebilmesi gereken bir bulut sunucusu için — sağlayıcının API'si
üzerinden, SSH olmadan oluşturulan ve yalnızca bir Cloudflare Tunnel üzerinden erişilen —
[yüksek güvenceli dağıtım](../HIGH-ASSURANCE.md) belgesine bakın.

Yerel başlatma özel bir `.venv` oluşturur ve sürümü sabitlenmiş bağımlılıkları kurar. Docker
bunları imajın içinde derler; ana makinede Python gerekmez. İlk kurulum İnternet erişimi
gerektirir. Python 3.11+ bulunamazsa `Start.cmd`, geçerli Windows kullanıcısı için Python 3.12'yi
kurmadan önce onay ister (winget ile, o olmazsa Python Software Foundation imzasını
doğruladıktan sonra python.org yükleyicisiyle); hiçbir zaman yönetici ayrıcalığı istemez. Docker
ve işletim sistemi hizmetleri yine ön koşuldur.

Yerel ve taşınabilir kurulumlar kendi klasörlerindeki `data/live` dizinini kullanır. Docker,
`/data` konumundaki `tgwitness-data` adlı birimi kullanır. Veri dizininin tamamını bilinçli olarak
taşıyana kadar bunlar ayrı kurulumlardır. Yeni bir Docker konteynerinin yerel kurulumdaki
hesapları kendiliğinden bulmasını beklemeyin.

## Kurulum gereksinimleri

Yerel kurulum için `venv` ve `ensurepip` içeren Python 3.11 veya üstü, ilk bağımlılık kurulumu
için İnternet erişimi ve `.venv` için yazılabilir bir proje dizini gerekir. Pakete dahil panel için
Node.js veya ön yüz derlemesi gerekmez. Başlatıcıyı normal işletim sistemi hesabınızla
çalıştırın; TgWitness yönetici/root ayrıcalığı gerektirmez.

- **Windows:** `Start.cmd` sırasıyla `py -3`, `python` ve ardından kullanıcıya özel ve
  Program Files altındaki varsayılan kurulum klasörlerini dener; 3.11 veya üstü sürüm gerektirir.
  Hiçbiri işe yaramazsa yukarıda açıklanan otomatik, kullanıcıya özel kurulumu önerir.
  `py -3 start.py` de çalışır. Taşınabilir paket Python'a hiç ihtiyaç duymaz.
- **Linux:** `start.sh` sırasıyla `python3.13`, `python3.12`, `python3.11`, `python3` ve
  `python` komutlarını dener; hiçbiri uygun değilse apt, dnf, pacman, zypper, apk veya Homebrew
  için kurulum komutunu yazdırır. Debian/Ubuntu kurulumlarında seçilen yorumlayıcıyla eşleşen
  `python3-venv` paketi gerekebilir. Dağıtımın varsayılan Python'u eskiyse Python 3.11+ ile
  değiştirilmeli veya yanına Python 3.11+ kurulmalıdır.
- **macOS:** güncel bir Python 3.11+ dağıtımı kurun; işletim sistemiyle gelen yorumlayıcının
  gereksinimi karşıladığını varsaymayın. Proje dizininde `python3 start.py` komutunu kullanın.
- **Docker:** Compose v2.20 veya üstüyle Docker Engine/Desktop kullanın. Docker Desktop,
  Windows'ta Linux konteynerlerini kullanmalıdır. Konteyner kendi Python bağımlılıklarını kurar;
  ana makinede ayrıca Python kurulumu gerekmez.

## Yerel bilgisayar

Windows'ta `Start.cmd`, Linux/macOS'ta `sh start.sh` kullanın. `scripts\Setup.cmd` veya
`sh start.sh --setup-only` ortamı hazırlar. Başlatıcı bağımlılıkları ilk kullanımda kurar;
sonraki başlatmalar aynı ortamı yeniden kullanır. Kurulum ve Telegram'dan toplama için İnternet
erişimi gerekir; mevcut kayıtlara göz atmak ve dışa aktarım oluşturmak ise çevrimdışı çalışır.

Kurulumdan sonra, toplayıcıyı başlatmadan yerel bağımlılıkları, Ed25519'u, depolamayı, anahtar
yapılandırmasını ve dinleme adresini incelemek için `python start.py --check` komutunu
çalıştırın. Yapılandırılmış çıktı için `--json` kullanın. Kullanmayı planladığınız `--data-dir`,
`--host` ve `--port` değerlerini verin. Kontrol paket kurmaz, günlük oluşturmaz ve Telegram'a
bağlanmaz; bir bütünlük veya kapsam yeterlilik testi değildir. Mevcut günlükler başlatma sırasında
ayrıca doğrulanır. `python start.py --help` da kurulum yapmaz.

start.py'yi kullandıktan sonra yardımcı komutları Windows'ta `.venv\Scripts\python.exe`,
Linux/macOS'ta `.venv/bin/python` ile çalıştırın ya da önce bu ortamı etkinleştirin. Aşağıdaki
`python -m ...` örnekleri ortamın etkin olduğunu varsayar.

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

Ortam değişkenleri: TGWITNESS_DATA, TGWITNESS_HOST, TGWITNESS_PORT, TGWITNESS_TOKEN.
TGWITNESS_VAULT_KEY_FILE yeni bir kurulum için harici anahtar modunu seçer; bkz. [Harici ana anahtar](../SECURITY-MODEL.md#external-master-key).
TGWITNESS_TOKEN verilirse en az 24 karakter içermelidir; kriptografik olarak rastgele bir değer
kullanın. Verilmezse uygulama panel-token.txt dosyasında 256 bitlik rastgele bir jeton üretir.
Ortam değişkeniyle yapılan geçersiz kılma bu dosyayı yeniden yazmaz. Kimlik bilgilerini yenilemek
için yeniden başlatın.

Bir veri dizinine yalnızca tek bir işlem sahip olabilir. Platformlar arası bir işletim sistemi
dosya kilidi, birden fazla yazıcının yanlışlıkla aynı anda çalışmasını önler. Tek bir Uvicorn
worker kullanın. Panel istenen sayıda çalışma alanını yönetebilir; ek çalışma alanı dizinleri
profiles/<id>/ altında bulunur. Ayrı hizmet örnekleri için ayrı dizinler ve bağlantı noktaları
kullanın. SQLite WAL dosyaları ağ dosya sisteminde değil, yerel kalıcı depolamada bulunmalıdır.
Bir birimi replikalar arasında paylaşmayın.

## Windows taşınabilir paketi

Her GitHub Release, `TgWitness-<version>-windows-amd64-portable.zip` arşivini ve onun `.sha256`
dosyasını içerir. Arşivde python.org'un resmi gömülebilir Python 3.12 çalışma zamanı (sağlama
toplamı `tools/build_portable.py` içinde sabitlenmiştir), TgWitness ve sürümü sabitlenmiş
bağımlılıkları ile üç başlatıcı bulunur:

| Dosya | Amaç |
| --- | --- |
| `TgWitness.cmd` | Paneli başlatır; ek seçenekler aynen iletilir, örneğin `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | `data\demo` içinde sentetik demoyu başlatır |
| `TgWitness-Check.cmd` | Uygulamayı başlatmadan hazırlık kontrolünü çalıştırır |

Sürümü sabitlenmiş Rusça morfoloji sözlüğü ve PDF renk profilleri çevrimdışı kullanım için pakete
dahildir. Paketleme, bağımlılıkların `data` dizinlerinde yalnızca bu dosyaların bilinen yollarına
izin verir; bu dizinlerde beklenmeyen bir dosya bulunursa derleme başarısız olur.

Arşivin tamamını `Documents\TgWitness` gibi yazılabilir bir klasöre çıkarın; ZIP'in içinden veya
Program Files'tan çalıştırmayın. Çalışma zamanı yalıtılmış bir modül yolu kullanır; bu nedenle
diğer Python kurulumları ve `PYTHONPATH` onu etkilemez. Veriler paketin `data` klasöründe kalır.
Güncellemek için TgWitness'i durdurun, yeni sürümü yeni bir klasöre çıkarın ve `data` klasörünü
oraya kopyalayın.

Paketi 64 bit Windows'ta Python 3.12 ile kendiniz derleyebilirsiniz:

~~~sh
python tools/build_portable.py
~~~

## Konteyner

```sh
docker compose up -d --build --wait
```

Bu komut /data için adlandırılmış kalıcı bir birim oluşturur. Web bağlantı noktası
127.0.0.1:8787 adresine eşlenir. İşlem UID 10001 olarak, yetenekleri (capabilities) kısıtlanmış
şekilde, salt okunur bir kök dosya sistemi ve yazılabilir /data ile /tmp dizinleriyle çalışır.
`--wait`, komut dönmeden önce web sunucusunun sağlığını denetler; Telegram yetkilendirmesi ve
teslimat durumu panelde görünür. Sağlanan yardımcılar derlemeden sonra 180 saniyelik bir hazır olma
zaman aşımı kullanır. İlk bağımlılık indirmeleri bundan uzun sürebilir.

Her iki temel Compose dosyası da `tgwitness` proje adını kullanır; bu sayede yeni bir sürümü başka
bir dizine çıkarmak sessizce yeni bir veri biriminin seçilmesine yol açmaz. Bu proje için yalnızca
bir dağıtımı etkin tutun. Bağımsız kurulumlar için benzersiz bir `docker compose -p NAME ...` ve
farklı bir ana makine bağlantı noktası kullanın ve güncellemelerde ikisini de koruyun. Farklı
proje adı kullanan eski bir dağıtımda `-p` ile özgün adı kullanmaya devam edin;
`docker compose ls` mevcut projeleri listeler.

Farklı bir loopback bağlantı noktası kullanmak için `deploy/env.example` dosyasını `.env` olarak
kopyalayın ve `TGWITNESS_PORT` değerini değiştirin. Örneğin `TGWITNESS_PORT=8788` paneli
`http://127.0.0.1:8788` adresinde sunar; konteyner yine 8787'de dinler. `.env` Git tarafından yok
sayılır.

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

`restart: unless-stopped`, bir çökmeden veya Docker daemon'ının yeniden başlatılmasından sonra
toplayıcıyı yeniden başlatır. Linux sunucuda Docker'ın açılışta başlamasını dağıtımınızın hizmet
yöneticisiyle etkinleştirin; bu genellikle `sudo systemctl enable --now docker` komutudur.
Windows/macOS'ta Docker Desktop'ın oturum açıldığında başlama ayarını etkinleştirin. Masaüstü
oturumunun kapatılması, uyku modu veya durmuş bir Docker daemon'ı toplamayı kesintiye
uğratabilir. Açıkça durdurulan bir konteyner, siz yeniden başlatana kadar durmuş kalır.

Örnek yapılandırmada /tmp birimi 512 MiB ile sınırlıdır. Dışa aktarımlar bunun yerine kalıcı
/data üzerindeki her çalışma alanının `temporary-exports/` dizininde oluşturulur. Eşzamanlı dışa
aktarımlar, günlük/WAL büyümesi, medya ve yedeklemeler için orada yer ayırın. Başlatıcı,
yeterliliği doğrulanmış çalışma zamanı bağımlılık sürümlerini sabitlemek için
deploy/constraints.txt dosyasını kullanır. Docker ve yüksek güvenceli sunucular
deploy/requirements.lock ve deploy/build.lock dosyalarından pip --require-hashes ile kurulum yapar:
her paket dosyası commit'te kayıtlı bir SHA-256 değeriyle eşleşmelidir, bu nedenle PyPI'da veya
bir yansıda değiştirilmiş bir dosya reddedilir. Python temel imajı ve işletim sistemi paketleri ise
hâlâ sürüm için bağımsız yeterlilik doğrulaması gerektirir.

Günlüğü ve anahtarları yok etmek istemiyorsanız docker compose down -v kullanmayın. Konteyner
sağlık durumu Telegram'dan başarılı yakalamayı değil, web sunucusunun erişilebilirliğini bildirir.
Paneldeki toplayıcı durumunu, kalp atışını, hataları ve kapsam olaylarını inceleyin.

### Bağımsız tanık profili

İsteğe bağlı `witness` hizmeti, [bağımsız tanığı](../WITNESS.md) kendi konteynerinde çalıştırır:
anahtarı ve günlüğü `witness-data` biriminde ayrı tutulur ve toplayıcı için elinde yalnızca salt
okunur bir tanık jetonu bulunur. Jetonu panelde **Diğer araçlar → Ekstralar → Bağımsız tanık**
altında oluşturun, bir bot jetonu ve kanalla birlikte `.env` dosyasına ekleyin, ardından profili
başlatın:

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

Hizmet, Compose ağı içinde toplayıcıya `http://tgwitness:8787` adresinden ulaşır
(`TGWITNESS_WITNESS_COLLECTOR` bunu geçersiz kılar; örneğin başka bir çalışma alanı için
`/profiles/<workspace ID>`). Başka birinin işlettiği ayrı bir sunucudaki tanık için orada
`deploy/compose/compose.witness.yaml` dosyasını, `TGWITNESS_WITNESS_COLLECTOR` değerini
toplayıcının HTTPS adresine ayarlayarak kullanın; bu dosya yalnızca tanığı içerir.

## Yayımlanmış bir imajı kurun

`deploy/env.example` dosyasını `.env` olarak kopyalayın. `TGWITNESS_IMAGE` değerini, depo yolunu
**küçük harflerle** yazarak yayımlanmış sürüme ayarlayın, örneğin:

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.9.2
TGWITNESS_PORT=8787
```

Bu dosyayı `compose.yaml` yerine tek başına kullanın:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

Ana makinede kaynak derlemesi, Python veya derleyici gerekmez. Sürüm iş akışı, Docker Desktop'ın
Linux sanal makinesi dahil Linux AMD64 ve ARM64 konteynerlerini hedefler. İş akışı özetindeki bir
sürüm etiketini veya `ghcr.io/owner/repository@sha256:...` değerini kullanın. Değişken bir `latest`
etiketi ya da gözetimsiz uygulama yükseltmesi yapılandırılmamıştır. İmaj ve kaynak varyantları,
proje adları aynı olduğunda aynı veri birimini kullanır.

<a name="automatic-https-on-a-server"></a>

## Sunucuda otomatik HTTPS

Docker kurulu bir sunucu, denetiminizdeki bir alan adı ve kalıcı yerel depolama kullanın. Alan
adının A/AAAA kayıtlarını sunucuya yönlendirin; AAAA kaydını yalnızca sunucuya IPv6 ile
ulaşılabiliyorsa yayımlayın. Sertifika verilmesi için gelen TCP 80 ve 443 ile giden DNS/HTTPS
trafiğine izin verin. Bu bağlantı noktaları başka hizmetler tarafından kullanılıyor olmamalıdır.

`deploy/env.example` dosyasını `.env` olarak kopyalayın ve şema veya yol içermeyen bir ana makine
adı ayarlayın:

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

Kaynak derlemesini HTTPS katmanıyla başlatın:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

Yayımlanmış bir imaj için ilk dosya olarak bunun yerine `deploy/compose/compose.image.yaml`
kullanın. Sonraki durum, log, güncelleme ve durdurma komutlarında her iki `-f` bağımsız değişkenini
de koruyun.

Caddy sertifikayı alır ve yeniler, HTTP'yi HTTPS'ye yönlendirir ve istekleri özel Compose ağındaki
toplayıcıya iletir. Sertifika durumu kendi kalıcı biriminde tutulur. Toplayıcının ana makinedeki
doğrudan bağlantı noktası yalnızca loopback'e açık kalır. Sağlanan Caddy yapılandırması erişim
loglamasını etkinleştirmez.

`https://watch.your-domain.org` adresini açın ve panel jetonunu girin. Compose'un hazır olma
denetimi konteynerleri kapsar; sertifika verilmesi ve dışarıdan erişilebilirlik DNS'e ve
güvenlik duvarına bağlıdır. HTTPS hazır değilse DNS'i, güvenlik duvarı kurallarını ve şu komutun
çıktısını inceleyin:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

Sağlanan Caddy imajı `2-alpine` etiketini izler. Pull işlemi bu imajı yeniler; sabit altyapı
sürümlerine ihtiyacınız varsa dağıtımınızda test edilmiş bir digest değerini sabitleyin.

## Güncellemeler ve yedeklemeler

Güncellemeler boyunca Compose proje adını ve veri birimini koruyun. Önce toplayıcıyı durdurun ve
eksiksiz bir yedek alın. Varsayılan, kaynaktan derlenen dağıtım için:

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

Her seferinde depo dışında yeni bir yedekleme hedefi kullanın ve onu hesaplara erişim sağlayan
materyal olarak koruyun. Örnek yol yalnızca açıklama amaçlıdır; kendi özel yedekleme konumunuzu
kullanın. Gizli dosyalar, tüm çalışma alanları, anahtarlar, günlükler ve medya dahil dizinin
tamamını kopyalayın. Yapılandırılmışsa harici kasa ana anahtarını ayrıca yedekleyin. Bir kanıt
ZIP'i geri yüklenebilir bir uygulama yedeği değildir. HTTPS kullanıyorsanız ve Caddy'nin
sertifika/hesap durumunu korumanız gerekiyorsa Caddy birimlerini de saklayın.

Kaynaktan dağıtımda yeni sürüm dosyalarını edinin ve şunu çalıştırın:

```sh
docker compose up -d --build --wait
```

İmaj dağıtımında `TGWITNESS_IMAGE` değerini istenen sürüme değiştirin, ardından şunu çalıştırın:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

Yukarıdaki durdurma/kopyalama komutlarında da kurulumunuzun Compose dosyasını (dosyalarını)
kullanın. `.env` dosyasını, özel yapılandırmayı ve aynı proje adını koruyun. `down` adlandırılmış
birimleri korur; **`down -v` bunları siler**. `.venv` dizinini işletim sistemleri veya Python
sürümleri arasında kopyalamayın. Yerel kurulumu güncellemek için TgWitness'i durdurun, veri
dizininin tamamını yedekleyin, kaynak dosyaları değiştirin ve başlatmadan önce
`python start.py --setup-only` komutunu çalıştırın.

Güncellemeden sonra panel erişimini, hesap kimliğini, gözlem durumunu ve kapsamı kontrol edin.
Yeniden başlatmanın ardından TgWitness kaydedilmiş Telegram güncelleme konumundan devam eder ve
güncelleme sırasında kaçırılan güncellemeleri ister. Gelecekteki bir sürüm depolama biçimlerini
değiştirirse geri dönüş için güncelleme öncesi yedek gerekebilir.

## Uzak sunucu

Hizmeti loopback'e bağlı tutup bir SSH tüneli kullanın veya HTTPS'yi bir ters proxy'de
sonlandırın. Temel Compose dosyası yalnızca yerel erişim içindir; isteğe bağlı
`deploy/compose/compose.https.yaml` katmanı, yapılandırılmış bir alan adı için Caddy sağlar.
Bearer jetonunu URL'lerin ve proxy loglarının dışında tutun. Ters proxy, istek boyutunu ve bağlantı
hızlarını sınırlamalıdır. Şifresiz HTTP'yi İnternet'e açmayın.

systemd, Windows oturum açma görevi, macOS kullanıcı aracısı (user agent) ve Caddy için örnekler
[deploy/](../../deploy/README.md) dizinindedir. Kurmadan önce içlerindeki yolları gözden geçirip
uyarlayın. Bunlar sağlanan şablonlardır; yerelde çalıştırılmış platform yeterlilik testleri
değildir. Normal başlatıcı hiçbir arka plan hizmeti veya görevi kaydetmez.

Windows'ta penceresiz `pythonw.exe` başlatması, başlatma/sunucu tanılama bilgilerini veri dizini
altındaki `logs/server.log` dosyasına yazar (dosya başına 5 MiB, döndürülen iki yedek). Konsoldan
yapılan başlatmalarda loglar konsola yazılmaya devam eder. HTTP erişim loglaması her iki modda da
kapalıdır. Logları veri diziniyle birlikte koruyun ve paylaşmadan önce gözden geçirin.

## Yeniden başlatma ve boşluklar

Son istenen gözlem durumu kalıcı olarak saklanır. Gözlem etkinse başlatma sırasında yeniden
bağlanılmaya ve seçili kaynaklara devam edilmeye çalışılır. Elle duraklatma bu niyeti temizler.
Başarısız bir yeniden başlatma kaydedilir ve panelde gösterilir.

TgWitness, Telegram'ın hesap ve her kanal için güncelleme konumunu (pts, qts, seq ve date)
çalışma alanının kasasında saklar ve bir sonraki başlatmada geri yükler. İstemci ardından işlem
dururken kaçırılan güncellemeleri ister; periyodik yeniden kontrol ise kaçırılan mesajları kurtarır
ve kaydedilmiş olup Telegram'ın artık döndürmediği mesajları kayda geçirir. Diyaloglar başlatmada
yeniden yüklenir. Her başlatma; önceki günlük başını (head), çevrimdışı dönemin sınırını ve devam
edilen güncelleme konumunu kaydeder. İzleyici bağlantıyı 10 saniyede bir denetler ve dakikada bir
kalp atışı ekler (**Diğer araçlar → Parametreler → Canlılık kaydı her**). Bağlantı kopmaları ve
sessiz dönemler, nedenleriyle birlikte kapsam boşlukları olarak kaydedilir. Geçmiş anlık
görüntüleri, canlı kayıtların yanında ayrı "güncel geçmiş" gözlemleri olarak saklanır.

Medya kuyruğu her çalışma alanının SQLite veritabanında saklanır. Mesaj ve ona ait iş atomik
olarak kaydedilir (commit). Yarıda kesilen çalışan işler başlatmada yeniden denenmek üzere
kurtarılır. Her indirmenin 120 saniyelik temel zaman aşımı ile buna eklenen ve boyutuna göre
256 KiB/s hızla hesaplanan bir süresi vardır; ek türü başına sınır 1–2.000 MiB'dir. Zaman aşımı,
hız ve yeniden deneme ayarları **Diğer araçlar → Parametreler** altındadır. Toplayıcı boyutu
bilinmeyen dosyaları atlar. Duraklatma kuyruktaki işleri korur. Yeniden deneme, sonradan
düzenlenmiş bir mesajın en son sürümünü asla kullanmaz; ilk gözlemlenen dosya tanımlayıcısını
kullanır. Geçici hatalar için yeniden deneme sayısı sınırlıdır; medya FloodWait duraklamaları
yeniden başlatmadan sonra da sürer. Medya kurtarma Telegram güncelleme kurtarmasından ayrıdır ve
kaybolmuş dosyaları yeniden oluşturamaz.

## Yedekleme, geri yükleme ve kapasite

vault.key, signing.enc, credentials.enc, SQLite veritabanı/WAL dosyaları, medya, jeton, kontrol
noktaları ve tüm profiles/ alt dizinleri dahil **veri dizininin tamamını** kopyalamadan önce işlemi
durdurun. Kopyanın tamamını hedef hizmet dururken geri yükleyin. Eksik kasa anahtarları veya
imzalama anahtarı uyuşmazlığı başlatmanın başarısız olmasına neden olur; erişimi zorlamak için
anahtarları yeniden üretmeyin.

Gizli bilgi içeren yedekleri şifreli ve erişim denetimli tutun. Kanıt ZIP'leri taşınabilir inceleme
çıktılarıdır; uygulama yedeği veya Telegram oturumu yedeği değildir. Saklama süresine bağlı
otomatik silme yoktur. Tüm mesajlar, ham meta veriler, medya, geçici dışa aktarımlar ve yedekler
için disk alanı planlayın.

Başlatma doğrulaması ve dışa aktarma, günlüğün tamamını yüklemek yerine kayıtları akış halinde
işler. Bir dışa aktarma bir okuma anlık görüntüsünü sabitlerken yeni WAL yazmaları sürebilir; uzun
süren dışa aktarımlar WAL sayfalarını tutabilir, bu yüzden disk kapasitesi yine önemlidir. ZIP'ler,
bağımsız doğrulayıcının varsayılanıyla uyumlu olarak sıkıştırılmamış 4 GiB ile sınırlıdır;
**Diğer araçlar → Parametreler → En büyük imzalı ZIP dosyası** bu sınırı yükseltir ve bu tür
arşivler `verify.py --max-gib N` ile doğrulanır. Diğer biçimlerde olay sayısı sınırı yoktur.
Desteklenen tarayıcılar yanıt parçalarını kullanıcının seçtiği bir dosyaya akış halinde yazar.
Diğer tarayıcılar en fazla 128 MiB arabelleğe alır ve daha büyük aktarımları kimliği doğrulanmış
CLI'ye yönlendirir:

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

Başka bir çalışma alanı için **Dışa aktarımlar → Çalışma alanı kimliği** değeriyle `--profile ID`,
`--format zip|jsonl|csv|html`, uzak sunucu için `--url https://your-server` ya da 5 GiB aktarım
sınırını değiştirmek için `--max-mib` kullanın. Şifresiz HTTP'ye yalnızca loopback için izin
verilir. Jetonlar başlıklarda taşınır, yönlendirmeler reddedilir, mevcut dosyaların üzerine
yazılmaz ve tamamlanmamış indirmeler bitmiş dosya olarak yayımlanmaz. TGWITNESS_TOKEN oluşturulan
jetonu geçersiz kılıyorsa, bu etkin değeri içeren ve ayrıca korunan bir dosya kullanın:
geçersiz kılma panel-token.txt dosyasını yeniden yazmaz. Komutun gösterdiği SHA-256 yalnızca bir
aktarım sağlama toplamıdır; imzalı ZIP'i bağımsız olarak doğrulayın.

Panel kuyruktaki/başarısız medyayı, bekleyen en eski medyayı, boş disk alanını, Telegram istek
duraklamalarını ve erişimi doğrulanmamış kaynakları gösterir. Bu tanılamalar uçtan uca eksiksiz bir
teslimat izleyicisi değildir. Çalışma alanları tek bir işlemi paylaşır; yoğun trafik üreten bir
hesap diğerlerini yine de etkileyebilir. Ayrı worker işlemleri, saklama/döndürme, kalıcı güncelleme
kurtarma ve tam dağıtım yeterlilik doğrulaması hâlâ yapılacak işler arasındadır. Kapsamı
sınırlandırılmış panel erişimi [erişim ve izinler](../ACCESS.md) belgesinde, bağımsız kontrol
noktaları ise [tanık kılavuzunda](../WITNESS.md) anlatılır.

Ayrıntılı prosedürler: [bağlantı/güvenlik](../CONNECTION-SECURITY.md) ve
[çalışma modları](../OPERATIONS.md).
