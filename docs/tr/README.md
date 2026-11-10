<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Diğer diller</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — İzi sürün. Delilleri koruyun. Hash ile birbirine bağlanmış imzalı bir günlük, ayrı saklanan bir kontrol noktası ve doğrulanabilir bir delil arşivi.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=tr"><b>Demoyu keşfedin&nbsp;↗</b></a><br><sub>Kurgusal kayıtlarla gerçek arayüz</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>İndirin ve başlatın&nbsp;↓</b></a><br><sub>Linux, macOS ve Windows için tek komut</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>El kitabını okuyun&nbsp;↗</b></a><br><sub>Adım adım araştırma kılavuzları</sub></td>
</tr>
</table>

<p align="center"><strong>Telegram araştırmaları için kendi sunucunuzda barındırdığınız çalışma alanı.</strong><br>Sohbetleri kaydedin, düzenlemeleri ve silmeleri saklayın, kimin kiminle bağlantılı olduğunu görün<br>ve herkesin kontrol edebileceği imzalı dışa aktarımlar teslim edin.</p>

<p align="center"><strong>SIFIR GÜVEN.</strong> TgWitness taraf tutmaz: aynı kontroller operatöre, PhishDestroy'a ve diğer herkese uygulanır.<br>Yalnızca üçüncü bir tarafın veya matematiğin doğruladığı şey geçerlidir. <a href="../LIMITS-AND-OBJECTIONS.md">Sınırlar ve itirazlar</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · ön sürüm"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Test edilen ortamlar</a> · 25 arayüz dili · 26 kılavuz dili</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=tr">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="TgWitness demosu iş başında: yakalanan mesajlar, kaydedilen sürümler ve silindikten sonra korunan içerik. Kurgusal gösterim kayıtları.">
</picture>
</a>

<p align="center"><sub>Gerçek arayüzü kurgusal kayıtlarla keşfedin. Denemek için çalışma alanına tıklayın.</sub></p>

## TgWitness ne yapar

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Her düzenleme ve silme saklanır</a></b><br><sub>Bir mesajın her sürümü kaydedilir ve metni silme bildiriminden sonra da kalır.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Herkesin kontrol edebileceği kanıt</a></b><br><sub>İmzalı, hash zinciriyle bağlı kayıtlar. Alıcı arşivi tek komutla çevrimdışı doğrular.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Gösterilebilir köken</a></b><br><sub>Mesajlar hesabın kimliği doğrulanmış MTProto oturumu üzerinden alınır ve gelir gelmez imzalanır; GitHub Actions ve Intel TDX tasdik ekler.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Büyük ölçekte ölçüldü</a></b><br><sub>3.598.381 kayıt içeren 48 doğrulanmış arşiv; sekiz hesap 768.007 geçmiş kaydını 687,5 kayıt/sn hızla edindi.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Araştırmalar için tasarlandı</a></b><br><sub>Metin, QR kodları ve OCR üzerinde izleme listeleri, cüzdan kontrolleri, profil kartları, Vaka Panosu ve bir mahkeme paketi.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Kontrol sizde</a></b><br><sub>Kendi sunucunuzda, telemetri olmadan. Oturumlar şifreli bir kasada saklanır; panel localhost'u dinler.</sub></td>
</tr>
</table>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Kurulum

Python dahil. Güncellemek için de aynı komutları kullanın.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell veya CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Ubuntu sunucu: root olarak çalıştırın. Masaüstü: normal kullanıcınızla çalıştırın. `-ExecutionPolicy Bypass` yalnızca bu PowerShell işlemi için geçerlidir.</sub>

İmzalı derlemeler herkese açık [Installer iş akışından](../../.github/workflows/installer.yml) gelir; yükleyici kurulumdan önce her paketin SHA-256 değerini ve RSA imzasını kontrol eder.

[Önce betiği doğrulayın](../INSTALLATION.md#verify-before-running) · [İlk kurulum](../SETTINGS.md) · [Sürümler](https://github.com/phishdestroy/TgWitness/releases) · [Docker](DEPLOYMENT.md)

<details>
<summary><strong>Yükleyici ve verileriniz nasıl korunur</strong></summary>

`get.destroy.tools` projenin indirme sitesidir. Herkese açık
[Installer iş akışı](../../.github/workflows/installer.yml) bu siteyi `main` dalının tam o revizyonu için
[`deploy/installer/`](../../deploy/installer/README.md) içeriğinden oluşturur,
Linux ve Windows kurulum testleri geçtikten sonra yayımlar ve yükleyici
betiklerini ve uygulama paketlerini
[`release-signing.pub`](../../deploy/installer/release-signing.pub) içindeki sürüm anahtarıyla imzalar. Yükleyici kurulumdan önce
paketin ve bağımlılık kilit dosyasının SHA-256 değerini ve RSA imzasını kontrol eder.
Önce betiğin kendisini kontrol etmek için betiği imzasıyla birlikte indirin ve
[önce doğrulama komutlarını](../INSTALLATION.md#verify-before-running) çalıştırın. Başarısız bir derleme
önceki indirmeyi korur; yüklü paneller yükleyiciyi yeniden çalıştırdığınızda güncellenir.
GitHub [Sürümleri](https://github.com/phishdestroy/TgWitness/releases), kaynak kod ve
[Docker](DEPLOYMENT.md) diğer kurulum yollarıdır.

**Oturumlarınız ve verileriniz.** TgWitness kendi bilgisayarınızda veya sunucunuzda çalışır ve panel
varsayılan olarak localhost'u dinler. Telegram oturumları, proxy kimlik bilgileri ve erişim belirteci
hash'leri her çalışma alanının şifreli kasasında, isteğe bağlı bir
[harici ana anahtarla](../SECURITY-MODEL.md#external-master-key) saklanır. Uygulamada
telemetri yoktur. Telegram'a ve ayarlarının kullandığı hizmetlere bağlanır:
herkese açık MTProxy listeleri, proxy'leriniz, S3 depolama, bir tanık botu, zaman damgası
otoriteleri, yapay zekâ sağlayıcıları ve webhook'lar. [Sistem haritası](../SYSTEM-MAP.md),
uygulama sürecinin kurduğu bağlantıları listeler.
[Ayrı bir Telegram hesabıyla](https://phishdestroy.github.io/TgWitness/tr/docs/dedicated-account/) gözlem yapın.

Sürüm rozeti bu kaynak ağacını tanımlar. Kurulabilir derlemeler
[Sürümler](https://github.com/phishdestroy/TgWitness/releases) altında listelenir;
`main` dalına birleştirilen bir özellik bu indirmelere bir sonraki sürümle ulaşır.

[Kurulum ve panel erişimi](../INSTALLATION.md) ·
[İmzalar ve SHA-256](https://get.destroy.tools/#verification) ·
[Güncelleme](../INSTALLATION.md#update-an-existing-installation) ·
[Mevcut yetenekler ve yeterlilik doğrulaması](../STATUS.md) ·
[Bir toplama yöntemi seçin](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Başkasının kontrol edebileceği bir kayıt

Hesap açmadan ve kurulum yapmadan kontrol edin. Yayımlanan örnek kendi doğrulayıcısını içerir:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # doğrulayıcı arşivin içinde gelir
python verify.py tgwitness-demo.zip          # Python 3.11+, yalnızca `cryptography` gerekir
```

İmzalı kayıtları, en yeni kaydın hash değerini ve imzalayanın parmak izini yazdırır ve `0` koduyla çıkar.
Örnek kurgusaldır; aynı doğrulayıcı her gerçek dışa aktarımda çalışır.

Bir dışa aktarım mesajları, dosyaları ve doğrulayıcıyı içerir. Anahtar parmak izinizi alıcıya
başka bir kanaldan gönderin; alıcı kontrolü kendisi yapabilir:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Doğrulayıcı imzaları, günlük zincirini, dosya listesini ve ekleri kontrol eder.
Delil düzeyi için anahtar parmak izinize ve son kaydı kapsayan bir üçüncü taraf zaman damgasına ihtiyaç duyar;
örneğin otoritenin kök sertifikasına göre kontrol edilmiş bir RFC 3161 zaman damgası.

**Mesajlar nereden gelir.** TgWitness mesajları, resmî uygulamalar gibi hesabın şifreli
MTProto oturumu üzerinden Telegram'dan alır ve her birini geldiği anda
günlüğe imzalayarak yazar. [GitHub Actions yakalaması](../SEALED-ACTIONS.md) ve
[Phala Intel TDX](../HIGH-ASSURANCE.md) mesajları alan toplayıcıyı ayrıca tasdik eder.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Yeni mesajlar, kaydedilen düzenlemeler ve silme gözlemleri birbirine bağlı, imzalı bir günlük oluşturur. Bağımsız olarak güvenilen bir anahtarla doğrulayın.">
</picture>

[Arşiv doğrulama](../wiki/Exports-and-Verification.md) · [Delil biçimi](../EVIDENCE.md) · [Bağımsız tanık](../WITNESS.md) · [Harici zaman damgaları](../TIMESTAMP.md) · [Kontroller ve test edilen ölçek](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Bir konuşmadan bir davaya

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Üç animasyonlu iş akışı: bir sohbeti HTML ve JSON olarak dışa aktarma, kaydedilmiş sohbetlerde paylaşılan bir bağlantıyı bulma ve bir silme bildiriminden sonra yakalanan sürümleri koruma.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Sohbet dışa aktarımı&nbsp;↗</b></a><br><sub>Tek sohbet, imzalı HTML ve JSON olarak</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Araştırma&nbsp;↗</b></a><br><sub>Kaydedilmiş sohbetlerde bir ipucunu takip edin</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Kaydedilen sürümler&nbsp;↗</b></a><br><sub>Düzenlemeler ve silme bildirimleri saklanır</sub></td>
</tr>
</table>

İki kullanım yolu var: [hesabınızı bir kez dışa aktarın](../ACCOUNT-EXPORT.md) ya da
[bir araştırmayı takip edin](../INVESTIGATION.md) ve değişiklikleri kaydetmeye devam edin.
Birkaç sohbet, bir Telegram klasörü veya hesabın tamamını seçin. Her hesabın kendi
çalışma alanı, oturumu ve imza anahtarı olur.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Daha fazlasını keşfedin

<details>
<summary><strong>Ölçülen dışa aktarımlar · 6 Kasım 2026</strong> · 56.329 mesaj, iki arşiv de doğrulandı</summary>

**İki yeni çalıştırmada 56.329 mesaj dışa aktarıldı.** İmzalı iki arşiv de sabitlenmiş toplayıcı anahtarlarıyla doğrulamayı geçti.

[![Ölçülen toplama ve tam dışa aktarma hızı](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/tr/docs/validation/)

| Çalıştırma | Mesaj | Toplama süresi | Toplama hızı | Tam dışa aktarma | Uçtan uca hız |
| --- | ---: | ---: | ---: | ---: | ---: |
| Sunucu A | 27.030 | 189,043 sn | **142,983 mesaj/sn** | 211,647 sn | 127,713 mesaj/sn |
| Sunucu B | 29.299 | 182,513 sn | **160,531 mesaj/sn** | 206,650 sn | 141,781 mesaj/sn |

WARP üzerinden metin ve meta veriler, sunucu başına iki hesap, ek dosya veya yeniden kullanılan kayıt yok.
[`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e) revizyonunda ölçüldü.
Yayımlanan her çalıştırma kaynak revizyonunu, iş yükünü, süreleri ve doğrulama sonucunu listeler:
[iş yükü, süreler ve doğrulama](../EXPORT-BENCHMARK-2026-11-06.md). `main` dalındaki değişiklikler
herkese açık [CI iş akışlarından](../../.github/workflows/README.md) geçer; buna Linux ve Windows
yükleyici testleri ile bağımsız doğrulayıcı derlemesi de dahildir.

[**Demoyu keşfedin →**](https://phishdestroy.github.io/TgWitness/demo/?lang=tr) ·
[**Ölçümler, tarihler ve yöntem →**](https://phishdestroy.github.io/TgWitness/tr/docs/validation/) ·
[Kurgusal bir örnek dışa aktarımı indirin](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[İmzalı İngilizce denetim raporu](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Basit başlayın. Tüm rotaları görün.</strong> · ilk başlatma ve sistem haritası</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="İlk başlatma Sadece indir, Sohbetleri izle veya Bir davaya ilişkin deliller seçeneklerini sunar ve yalnızca ilgili bölümleri gösterir. Sistem haritası paneli, toplayıcıyı, Telegram'ı, günlüğü, tanığı ve dış hizmetleri ağ gözlemleriyle birlikte birbirine bağlar. Kurgusal değerler.">
</picture>

İlk başlatmada tek bir soru sorulur: **Sadece indir**, **Sohbetleri izle** veya
**Bir davaya ilişkin deliller**. Yanıt, amacı ve arayüz düzeyini belirler; böylece
panel yalnızca o görevin gerektirdiği bölümleri gösterir. Bağlantı, Telegram'da oturum açma ve
sohbet seçimi beş aşamada gelir. Bağlantı kontrolü kendiliğinden çalışır;
rota seçenekleri yalnızca kontrol başarısız olursa açılır. Uzman araçları tek bir anahtarla açılır.

**Sistem haritası**, kurulumun Telegram'a ve dış hizmetlere nasıl ulaştığını gösterir:
panel erişimi, her hesabın rotası ve Telegram hedefi, günlük ve
tanık yolu ile en son ağ gözlemleri. Eksik bir gözlem
eksik olarak etiketlenir.

[İlk kurulum](../SETTINGS.md) · [Sistem haritası](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Araştırmanın geri kalanı için tasarlandı</strong> · profil kartları, izleme listeleri, cüzdanlar, çevrimiçi takip, mahkeme belgeleri</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Adları ve kullanıcı adlarını Telegram ID'sine göre takip edin. Desteklenen bot etkileşimlerini imzalı makbuzlarla kaydedin. Arşivlenmiş mesajlarda arama yapın ve salt okunur MCP istemcilerini bağlayın. SSH'si maskelenmiş bir toplayıcıyı, incelenmek üzere sağlayıcı kayıtlarıyla birlikte dağıtın. Bir konuşmayı günlük referanslarıyla adım adım belgeleyin. Mahkeme şablonları içeren bir BagIt dava paketi teslim edin. Örnek iş akışları.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Kişiler ve profil dosyaları&nbsp;↗</b></a><br><sub>Telegram ID'sine göre takip edilen adlar ve kullanıcı adları</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Bot araştırması&nbsp;↗</b></a><br><sub>İmzalı makbuzlarla bot etkileşimleri</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/tr/docs/archive/"><b>Arşiv araması, yapay zekâ ve MCP&nbsp;↗</b></a><br><sub>Arşivde arayın, salt okunur istemcileri bağlayın</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Mühürlü bulut dağıtımı&nbsp;↗</b></a><br><sub>Intel TDX içinde bir toplayıcı</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Üç animasyonlu adım: sonraki anlık görüntüsü bir ad değişikliğini kaydeden bir profil kartı, amaçları günlük kayıtlarıyla kapanan bir konuşma planı ve sağlama toplamı geçerli bir cüzdana çözülüp izleme listesinde eşleşme tetikleyen bir ödeme QR kodu. Kurgusal değerler.">
</picture>

**Konuşmayı belgeleyin.** **Belgeler** çekmecesinde bir sohbet için tutanak başlatın;
her adım kendiliğinden yazılır: panel eylemleri, öncesindeki bekleme süresiyle yanıtlar,
düzenlemeler, silme bildirimleri, notlar ve yapay zekâ taslakları. Her adım kendi günlük
kaydına ve SHA-256 değerine atıf yapar. Belge kesinleştirildiğinde imzalanır ve beyan hash'i
günlüğe yazılır.

| | |
| --- | --- |
| [Profil kartları](../INVESTIGATION-MODE.md#subject-cards) | Telegram'ın BOT, VERIFIED, SCAM ve FAKE etiketleriyle bir botun, kişinin, kanalın veya grubun profil anlık görüntüleri; sonraki bir anlık görüntü nelerin değiştiğini listeler |
| [Konuşma planları](../INVESTIGATION-MODE.md#conversation-plans) | Ödeme yolu, altyapı veya kişilere yönelik amaçlar, hazırlanmış mesajlar, yanıt süreleri, saate göre etkinlik ve karşı tarafın yazım üslubu |
| [Çeviri](../INVESTIGATION-MODE.md#machine-translation) | Dilleri, modeli ve günlük kaydıyla birlikte orijinalin altında gösterilir |
| [İzleme listeleri](../INVESTIGATION-MODE.md#watchlists) | Kelimeler, kalıplar, cüzdanlar, @kullanıcı adları, ID'ler, alan adları, telefonlar ve bağlantılar; metinde, düzenlemelerde, gizli bağlantı hedeflerinde, bot düğmelerinde, QR kodlarında ve OCR'da eşleştirilir |
| [Çevrimiçi takip](../INVESTIGATION-MODE.md#online-watch) | 1–60 dakikada bir kontrol, istek başına en fazla 100 hesap, saate ve haftanın gününe göre örüntü |
| [Kodlar ve cüzdanlar](../INVESTIGATION-MODE.md#codes-in-images) | Ödeme QR kodları; EIP-55'e göre kontrol edilen EVM adresleri, ham biçimde TON, XRP Ledger sağlama toplamları, zincir, tutar ve token içeren ödeme bağlantıları |
| [İstemci izleri](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-can-and-cannot-show) | Yuvarlak videolarda ve sesli mesajlarda kodlayıcı izleri; yükleme zamanının gönderme zamanıyla karşılaştırılması önceden kaydedilmiş “canlı” kanıtları ortaya çıkarır |
| [Gizli kimlik ve yetki](../INVESTIGATION-MODE.md#cover-and-authority) | Kurgusal kimlikler, yetkilendirmeler ve yetkili sohbetlerin veya dönemin dışındaki mesajları işaretleyen bir gizli faaliyet kaydı |
| [Hesap denetimi](../INVESTIGATION-MODE.md#account-control) | Önce/sonra kayıtlarıyla profil ve gizlilik düzenleme, ifşa kontrolü ve her işlemden hemen sonra çevrimdışına geçme |
| [Mahkeme belgeleri](../INVESTIGATION-MODE.md#documents-for-court) | Rule 902(13)/(14) sertifikasyon şablonu, delil dizini, talep eki ve ekran kayıtları için WebVTT/SRT altyazıları içeren BagIt dava paketi |

18+, şiddet veya kişisel veri olarak işaretlenen içerik, AES-256-GCM ile mühürlenmiş olarak
mahkeme kopyasında kalır; anahtarlar ayrı iletilir.

[Dışa aktarma ayarları](../EXPORT_HASHES.md) normal API ve Takeout ile edinimi,
eklerden önce mesaj geçmişini, dosya indirmelerini veya sunucu hash'lerini ve uyumlu
Telegram Desktop JSON/HTML görünümlerini kapsar. [Dağıtık sohbet dışa aktarımı](../DISTRIBUTED-EXPORT.md#history-acquisition)
herkese açık geçmiş için isteğe bağlı bir Takeout yolu, her 100 mesajda bir imzalı kontrol noktaları
ve aynı hesapla bir aralık içinde kurtarma sunar; bunun
[performans tasarımı](../FAST-ACQUISITION.md) test edilen edinim davranışını
ve planlanan canlı ölçümleri listeler.

</details>

<details>
<summary><strong>Diğer her şey</strong> · geçmiş, hesaplar, proxy'ler, yapay zekâ, entegrasyonlar</summary>

| | |
| --- | --- |
| [Eski mesajları yükleyin](../HISTORY.md) | Seçili sohbetlerin geçmişini çekin; istediğiniz zaman duraklatıp sürdürün |
| [Birkaç hesap](../ACCOUNTS.md#multiple-accounts) | Her biri kendi Telegram oturumuna, günlüğüne ve imza anahtarına sahip ayrı çalışma alanları |
| [Toplu içe aktarma](../ACCOUNTS.md#bulk-import-and-account-groups) | Bir yığın oturum dosyasını bırakın, hesapları ortak ayarlara sahip gruplara ayırın |
| [MTProxy havuzu](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, ülkeler, filtreler, kendi listeleriniz |
| [Mevcut oturumlar](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key veya bir `key:DC` satırı; içe aktarılan bir donörden isteğe bağlı bağımsız QR yetkilendirmesi |
| [Hesap güvenliği](../ACCOUNTS.md#create-an-independent-authorization) | Yeni oturum uyarıları, diğer oturumları sonlandırma, iki adımlı doğrulama parolası da belirleyen tek oturum modu ve canlı güncellemeler bu oturuma ulaşmayı bıraktığında bunu fark eden bir [tanık yoklaması](../ACCOUNTS.md#witness-probe) |
| [Devam ettirilebilir sohbet dışa aktarımı](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Durdurulan bir dışa aktarım imzalı kısmi bir kopya tutar: sürdürün, baştan başlayın veya kaydedileni indirin |
| [Proxy'ler](../CONNECTION-SECURITY.md#ip-modes) | Çalışma alanı başına SOCKS5, HTTP CONNECT veya MTProxy. **IP Gizleme** asla doğrudan bağlantıya geri dönmez |
| [Arama ve yapay zekâ](../ANALYSIS.md) | Yerel arama, kontrol edebileceğiniz kaynaklarla isteğe bağlı yapay zekâ |
| [Tam metin arama](../SEARCH.md) | Kelime biçimleri, tam ifadeler, alan adları, @kullanıcı adları ve boşluksuz Çince; en iyi eşleşmeler önce (**önizleme sürümü**) |
| [MCP](../MCP.md) | MCP istemcileri için seçtiğiniz sohbetlerle sınırlı salt okunur erişim |
| [Komut satırı](../CLI.md) | Betikler ve ajanlar için `--json` ile `search`, `context`, `messages`, `stats` ve JSON Lines `export`; yerel olarak veya kapsamı sınırlı bir belirteçle (**önizleme sürümü**) |
| [OCR ve transkripsiyon](../MEDIA-ANALYSIS.md) | Yerel olarak çalışır, orijinallere dokunulmaz |
| [Bağımsız yakalama](../OPTIONAL-CAPTURE.md) | **Diğer araçlar → Ekstralar** altında isteğe bağlı tarayıcı/AyuGram kaydedicileri (önizleme, varsayılan olarak kapalı) |
| [Trusted Live](../TRUSTED-LIVE.md) | Resmî Desktop/Web oturumu, korumalı video ve Telegram'ın kendi dışa aktarımıyla süreklilik analizi (önizleme; canlı yeterlilik doğrulaması bekleniyor) |
| [Mühürlü resmî Web](../OFFICIAL-WITNESS.md) | GitHub Actions üzerinde yeni başlatılmış resmî tarayıcı, kısıtlı kontroller, imzalı video ve bağımsız olarak beklenen kaynak/ayarlar |
| [Webhook'lar](../WEBHOOKS.md) | Yeniden denemeli imzalı giden olaylar, n8n örneği dahil |
| [Paylaşılan erişim](../ACCESS.md) | Birine yalnızca seçili sohbetleri verin; süre sonu ve IP sınırlarıyla |
| [Eksik mesaj numaraları](../EVIDENCE.md#missing-message-numbers-gap_summary) | Telegram'ın atadığı ancak hiç gözlemlenmemiş numaralar; kanal başına ve tüm hesap için, kapsamda, raporlarda ve MCP'de (**önizleme sürümü**) |
| [Sohbet durumu anlık görüntüleri](../COLLECTION.md) | Başlık, açıklama, sabitlenmiş mesajlar, yöneticiler ve hediyelerin, değişenleri gösteren periyodik imzalı anlık görüntüleri (**önizleme sürümü**) |
| [Sistem haritası](../SYSTEM-MAP.md) | Panel erişimi, hesap rotaları, Telegram hedefleri ve dış hizmetlerin canlı haritası; en fazla 2.000 ağ gözleminden en son 200'üyle |

</details>

<details>
<summary><strong>Kaydı neyin desteklediğini seçin</strong> · yerel, denetlenmiş bulut, GitHub Actions veya Intel TDX</summary>

Yerel olarak çalıştırın, denetlenmiş bir bulut dağıtımı ekleyin veya **Intel TDX'li bir Phala Cloud
gizli VM'si** içinde toplayın. Her seçenek imzalı günlüğü korur; ek
kontroller, toplamanın yapıldığı ortamı ele alır.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Üç dağıtım seçeneği: yerel günlük doğrulaması; sağlayıcı ve erişim kayıtlarına sahip denetlenmiş bir VM; doğrulanmış quote, ölçülmüş işletim sistemi ve uygulama ile bağlı bir toplayıcı anahtarı içeren Phala Intel TDX.">
</picture>

TDX doğrulayıcısı quote'u Intel'in sabitlenmiş köküne ve iptal verilerine göre kontrol eder,
onu imzalı bir toplayıcı beyanına ve yeni bir sınamaya bağlar ve ölçülen
işletim sistemi ile uygulamayı bağımsız olarak beklenen girdilerle karşılaştırır. Rapor
her sonucu ayrı ayrı listeler; böylece ölçülen ortam, toplayıcı kimliği, yakalama
kayıtları ve kapsam birlikte incelenebilir.

**GitHub köken bilgisiyle yakalama** (önizleme). Bir sohbeti sabitlenmiş bir TgWitness sürümü ve yeni bir Telegram oturumuyla
GitHub tarafından barındırılan bir runner üzerinde toplayın, ardından şifreli
arşivi GitHub tasdikiyle birlikte indirin. Doğrulayıcı onaylı iş akışını ve
toplayıcı sürümünü, arşiv özetini, günlüğü ve ekleri kontrol eder. Paneldeki
**Dışa aktarımlar** bölümünde de bulunur.
[Yakalama sayfasını açın](https://phishdestroy.github.io/TgWitness/tr/docs/capture/) · [Talimatlar](../SEALED-ACTIONS.md)

Canlı gözlem, geçmiş veya tek seferlik bir dışa aktarım için bir
[toplama yöntemi](../COLLECTION-MODES.md) seçin. Özel bulut sohbetleri, bağlı hesap
bunlara erişebiliyorsa kullanılabilir. Yayımlanan uygulama ayrıca
[Gizli Sohbet entegrasyonunu](../PSEUDO-SECRET.md) içerir: isteğe bağlı protokol bağımlılığını kurun
ve orada oluşturulan veya kabul edilen sohbetleri kaydetmek için hesap bazında etkinleştirin.
Kullanılabilir edinim yolları için [toplama kapsamına](../COLLECTION.md) bakın.

[Phala / Intel TDX ve denetlenmiş dağıtımlar](../HIGH-ASSURANCE.md) ·
[Canlı Phala yeterlilik doğrulaması](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Güven sınırları](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Yakalamayı ve saklanan kaydı kontrol edin</strong> · alıcının neyi doğruladığı ve Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Konuşmayı yakalayın. Kaydı doğrulayın. Mesajları, düzenlemeleri ve dosyaları kaydedin, imzaları ve kontrol noktalarını kontrol edin ve yakalama sürecini inceleyin.">
</picture>

TgWitness, bağlı Telegram hesabına iletilen içeriği sohbet, mesaj ve gönderen
tanımlayıcıları, yakalanan sürümler ve toplama meta verileriyle birlikte kaydeder.
Arşiv bu kayıtları, korunan ekleri ve doğrulama verilerini inceleme için
bir araya getirir.

| Kontrol | Alıcının doğruladığı |
| --- | --- |
| İmzalı günlük ve manifest | Kayıt imzaları, hash zinciri ve teslim edilen dosyalar, beklenen imza anahtarına göre. |
| Ayrı saklanan kontrol noktası | Günlük, önceden kaydedilmiş bir uzunluğa ve en yeni kaydın hash değerine göre. |
| Bağımsız tanık | Günlük, ayrı bir tanığın sakladığı kontrol noktalarına göre. |
| GitHub Actions yakalaması | Arşiv; tasdikine, onaylı barındırılan iş akışına ve toplayıcı sürümüne göre. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
bir Telegram konuşmasını kasıtlı olarak değiştirilmiş Desktop dışa aktarma dosyalarının yanında gösterir.
Sürümleri karşılaştırın, değişiklikleri inceleyin ve imzalı bir TgWitness arşivi için
toplama ve doğrulama adımlarını izleyin.

[Doğrulama adımları](../wiki/Exports-and-Verification.md) ·
[GitHub yakalaması](../SEALED-ACTIONS.md) ·
[Teknik güven modeli](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Araştırmayı sürdürün</strong> · bildirimler, depolama ve kurtarma</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Animasyonlu iş akışları: Apprise yapılandırılmış uyarıları gönderir; site dışı kopyalar S3 uyumlu depolamaya yüklenmeden önce şifrelenir.">
</picture>

[Bildirimler](../OPERATIONS.md#notifications) · [Şifreli site dışı kopya](../wiki/Off-site-Copy.md) · [Yedekleme ve kurtarma](../wiki/Backup-and-Recovery.md) · [Sorun giderme](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/tr/docs/start/"><b>Kurulum kılavuzu&nbsp;↗</b></a><br><sub>Kurulumdan ilk sohbete</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/tr/docs/dedicated-account/"><b>Hesabınızı hazırlayın&nbsp;↗</b></a><br><sub>Ayrı bir Telegram hesabı</sub></td>
<td width="33%" align="center"><a href="DEPLOYMENT.md"><b>Docker ve sunucular&nbsp;↗</b></a><br><sub>HTTPS, yeniden başlatmalar ve güncellemeler</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Depoyu keşfedin</strong> · kod, belgeler ve araçlar nerede</summary>

| Dizin | Buradan başlayın |
| --- | --- |
| [docs/](../README.md) | Kurulum, araştırma iş akışları ve teknik başvuru |
| [tgwitness/](../../tgwitness/README.md) | Ana uygulama, toplayıcı, günlük ve web paneli |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Bağımsız kaydediciler ve doğrulama kodları |
| [addons/](../../addons/README.md) | İsteğe bağlı yakalamanın kurulumu, yapılandırması ve testleri |
| [deploy/](../../deploy/README.md) | Yükleyiciler, konteynerler ve arka plan hizmetleri |
| [examples/](../../examples/README.md) | Hesap dışa aktarma ve mühürlü yakalama yapılandırmaları |
| [integrations/](../../integrations/README.md) | İmzalı webhook'lar ve bir n8n alıcısı |
| [.agents/](../../.agents/README.md) | Arşivi CLI üzerinden okumak için görev talimatları |
| [scripts/](../../scripts/README.md) | Başlatıcılar ve CI yardımcı araçları |
| [tools/](../../tools/README.md) | Derlemeler, kontroller ve paketleme |
| [website/](../../website/README.md) | Herkese açık site, çevrilmiş kılavuzlar ve etkileşimli demo |
| [.github/](../../.github/AUTOMATION.md) | İş akışları, katkı yönergeleri ve destek |

[Eksiksiz proje kılavuzu](../PROJECT-GUIDE.md) ·
[Katkıda bulunma](../../.github/CONTRIBUTING.md) · [Yardım alın](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Etik Bildirim ve Tarihsel Süreklilik</strong></summary>

Yazarların tutumu ve operatör bildirimi, bu dilde:

[Lisans ve Mimari Uyumsuzluk Bildirimi](TAYLOR-WESSING-EXCLUSION.md) · [Operatör bildirimi](OPERATOR-INCOMPATIBILITY.md) · [MIT Lisansı](../../LICENSE) · [Orijinal NOTICE](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Proje tanıtımını kendi dilinizde okuyun</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · **Türkçe** · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Teknik belgeler</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Araştırma el kitabı</b></a> ·
  <a href="https://github.com/phishdestroy"><b>PhishDestroy tarafından geliştirildi</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Katkıda bulunun</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Yardım alın</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Güvenlik açığı bildirin</b></a>
</p>

[Makine tarafından okunabilir proje dizini](../../llms.txt) · [Eksiksiz metin el kitabı](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Ajanlar için depo kuralları](../../AGENTS.md)
