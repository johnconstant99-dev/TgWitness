<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Boshqa tillar</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Izdan boring. Dalillarni saqlang. Xesh orqali bog‘langan imzolangan jurnal, alohida saqlanadigan tekshiruv punkti va tekshirib bo‘ladigan dalillar arxivi.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=uz"><b>Demoni ko‘ring&nbsp;↗</b></a><br><sub>To‘qima yozuvlar bilan haqiqiy interfeys</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Yuklab oling va ishga tushiring&nbsp;↓</b></a><br><sub>Linux, macOS va Windows uchun bitta buyruq</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Qo‘llanmani o‘qing&nbsp;↗</b></a><br><sub>Tergov bo‘yicha bosqichma-bosqich qo‘llanmalar</sub></td>
</tr>
</table>

<p align="center"><strong>Telegram tergovlari uchun o‘z serveringizda ishlaydigan ish maydoni.</strong><br>Chatlarni saqlang, tahrir va o‘chirilgan xabarlarni yo‘qotmang, kim kim bilan bog‘liqligini ko‘ring<br>va har kim tekshira oladigan imzolangan eksportlarni topshiring.</p>

<p align="center"><strong>NOL ISHONCH.</strong> TgWitness hech kimning tarafini olmaydi: operator, PhishDestroy va boshqa har kim bir xil tekshiruvlardan o‘tadi.<br>Faqat uchinchi tomon yoki matematika tasdiqlagan narsa hisobga olinadi. <a href="../LIMITS-AND-OBJECTIONS.md">Cheklovlar va e’tirozlar</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · dastlabki reliz"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Sinovdan o‘tgan muhitlar</a> · 25 ta interfeys tili · 26 ta qo‘llanma tili</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=uz">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="TgWitness demosi harakatda: yozib olingan xabarlar, saqlangan versiyalar va o‘chirilgandan keyin saqlab qolingan kontent. To‘qima namoyish yozuvlari.">
</picture>
</a>

<p align="center"><sub>Haqiqiy interfeysni to‘qima yozuvlar bilan ko‘ring. Sinab ko‘rish uchun ish maydonini bosing.</sub></p>

## TgWitness nima qiladi

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Har bir tahrir va o‘chirish saqlanadi</a></b><br><sub>Xabarning har bir versiyasi saqlanadi, o‘chirish bildirishnomasidan keyin ham uning matni qoladi.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Har kim tekshira oladigan isbot</a></b><br><sub>Imzolangan, xesh zanjiri bilan bog‘langan yozuvlar. Qabul qiluvchi arxivni bitta buyruq bilan oflayn tekshiradi.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Ko‘rsatib berish mumkin bo‘lgan manba</a></b><br><sub>Xabarlar hisobning autentifikatsiyadan o‘tgan MTProto sessiyasi orqali olinadi va kelishi bilan imzolanadi; GitHub Actions va Intel TDX attestatsiya qo‘shadi.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Katta hajmda o‘lchangan</a></b><br><sub>3 598 381 ta yozuvdan iborat 48 ta tekshirilgan arxiv; sakkizta hisob 768 007 ta tarix yozuvini soniyasiga 687,5 yozuv tezlikda oldi.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Tergov uchun yaratilgan</a></b><br><sub>Matn, QR kodlar va OCR bo‘yicha kuzatuv ro‘yxatlari, hamyon tekshiruvlari, subyekt kartochkalari, Holat doskasi va sud paketi.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Boshqaruv sizda</a></b><br><sub>O‘z serveringizda, telemetriyasiz. Sessiyalar shifrlangan omborda saqlanadi; panel localhost’da tinglaydi.</sub></td>
</tr>
</table>

<p align="center"><sub>Taxminan olti oy davomida ishlab chiqilib sinovdan o'tkazildi: avvalo yig'uvchi, imzolangan jurnal va tekshiruvchi, keyin esa panel va qo'shimcha modullar. Ushbu ombor 2026-yil 29-oktabrda nashr etish uchun yaratilgan, shuning uchun uning yoshi loyihaning yoshi emas.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## O‘rnatish

Python birga keladi. Yangilash uchun ham shu buyruqlardan foydalaning.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell yoki CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Ubuntu server: root sifatida ishga tushiring. Desktop: oddiy foydalanuvchingiz nomidan ishga tushiring. `-ExecutionPolicy Bypass` faqat shu bitta PowerShell jarayoniga taalluqli.</sub>

Imzolangan buildlar ochiq [Installer ish jarayonidan](../../.github/workflows/installer.yml) olinadi, o‘rnatuvchi esa har bir paketni o‘rnatishdan oldin uning SHA-256 qiymati va RSA imzosini tekshiradi.

[Avval skriptni tekshiring](../INSTALLATION.md#verify-before-running) · [Birinchi sozlash](../SETTINGS.md) · [Relizlar](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>O‘rnatuvchi va ma’lumotlaringiz qanday himoyalangan</strong></summary>

`get.destroy.tools` — loyihaning yuklab olish sayti. Ochiq
[Installer ish jarayoni](../../.github/workflows/installer.yml) uni
[`deploy/installer/`](../../deploy/installer/README.md) asosida `main`ning aynan shu reviziyasi uchun yig‘adi,
Linux va Windows’dagi o‘rnatish sinovlari muvaffaqiyatli o‘tgach nashr qiladi hamda
o‘rnatuvchi skriptlari va ilova paketlarini
[`release-signing.pub`](../../deploy/installer/release-signing.pub) faylidagi reliz kaliti bilan imzolaydi. O‘rnatuvchi o‘rnatishdan oldin
paket va bog‘liqliklar qulf faylining SHA-256 qiymati hamda RSA imzosini tekshiradi.
Skriptning o‘zini oldindan tekshirish uchun uni imzosi bilan birga yuklab oling va
[oldindan tekshirish buyruqlarini](../INSTALLATION.md#verify-before-running) bajaring. Build muvaffaqiyatsiz bo‘lsa,
avvalgi yuklab olish fayli saqlanib qoladi; o‘rnatilgan panellar o‘rnatuvchini qayta ishga tushirganingizda yangilanadi.
GitHub [relizlari](https://github.com/phishdestroy/TgWitness/releases), manba kodi va
[Docker](../DEPLOYMENT.md) — o‘rnatishning boshqa usullari.

**Sessiyalaringiz va ma’lumotlaringiz.** TgWitness kompyuteringiz yoki serveringizda ishlaydi, panel esa
standart holatda localhost’da tinglaydi. Telegram sessiyalari, proksi kirish ma’lumotlari va kirish tokenlarining
xeshlari har bir ish maydonining shifrlangan omborida saqlanadi, ixtiyoriy ravishda
[tashqi master kalit](../SECURITY-MODEL.md#external-master-key) bilan. Ilovada
telemetriya yo‘q. U Telegram’ga va sozlamalarida ko‘rsatilgan xizmatlarga ulanadi:
ochiq MTProxy ro‘yxatlari, proksilaringiz, S3 xotirasi, guvoh bot, vaqt tamg‘asi
markazlari, sun’iy intellekt provayderlari va webhooklar. [Tizim xaritasi](../SYSTEM-MAP.md)
ilova jarayoni o‘rnatadigan ulanishlarni ko‘rsatadi.
Kuzatishni [alohida Telegram hisobi](https://phishdestroy.github.io/TgWitness/uz/docs/dedicated-account/) bilan olib boring.

Versiya nishoni shu manba daraxtini tavsiflaydi. O‘rnatiladigan buildlar
[Relizlar](https://github.com/phishdestroy/TgWitness/releases) bo‘limida keltirilgan;
`main`ga birlashtirilgan funksiya bu yuklab olishlarga keyingi reliz bilan yetib boradi.

[O‘rnatish va panelga kirish](../INSTALLATION.md) ·
[Imzolar va SHA-256](https://get.destroy.tools/#verification) ·
[Yangilash](../INSTALLATION.md#update-an-existing-installation) ·
[Joriy imkoniyatlar va kvalifikatsiya](../STATUS.md) ·
[Yig‘ish usulini tanlang](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Boshqalar tekshira oladigan yozuv

Hisob ochmasdan va hech narsa o‘rnatmasdan tekshiring. E’lon qilingan namuna o‘z tekshiruvchisi bilan keladi:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # tekshiruvchi arxiv ichida keladi
python verify.py tgwitness-demo.zip          # Python 3.11+, faqat `cryptography` kerak
```

U imzolangan yozuvlarni, eng yangi yozuv xeshini va imzolovchining barmoq izini chiqaradi hamda `0` kodi bilan yakunlanadi.
Namuna to‘qima; xuddi shu tekshiruvchi har qanday haqiqiy eksportda ishlaydi.

Eksportda xabarlar, fayllar va tekshiruvchi bo‘ladi. Kalitingizning barmoq izini qabul qiluvchiga
boshqa kanal orqali yuboring, shunda u o‘zi tekshira oladi:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Tekshiruvchi imzolarni, jurnal zanjirini, fayllar ro‘yxatini va biriktirmalarni tekshiradi.
Dalil darajasi uchun unga kalitingiz barmoq izi va oxirgi yozuvni qamrab oluvchi uchinchi tomon vaqt tamg‘asi kerak,
masalan, markazning ildiz sertifikati bo‘yicha tekshirilgan RFC 3161 vaqt tamg‘asi.

**Xabarlar qayerdan keladi.** TgWitness ularni Telegram’dan, rasmiy ilovalar kabi,
hisobning shifrlangan MTProto sessiyasi orqali oladi va har birini kelishi bilan
jurnalga imzolab yozadi. [GitHub Actions orqali yozib olish](../SEALED-ACTIONS.md) va
[Phala Intel TDX](../HIGH-ASSURANCE.md) ularni qabul qilgan yig‘uvchini ham attestatsiya qiladi.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Yangi xabarlar, saqlangan tahrirlar va o‘chirish kuzatuvlari bog‘langan, imzolangan jurnalni hosil qiladi. Uni mustaqil ravishda ishonchli deb topilgan kalit bilan tekshiring.">
</picture>

[Arxivni tekshirish](../wiki/Exports-and-Verification.md) · [Dalillar formati](../EVIDENCE.md) · [Mustaqil guvoh](../WITNESS.md) · [Tashqi vaqt tamg‘alari](../TIMESTAMP.md) · [Tekshiruvlar va sinalgan hajm](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Suhbatdan ishgacha

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Uchta animatsion ish jarayoni: chatni HTML va JSON’ga eksport qilish, yozib olingan chatlar bo‘ylab ulashilgan havolani topish va o‘chirish bildirishnomasidan keyin yozib olingan versiyalarni saqlab qolish.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Chat eksporti&nbsp;↗</b></a><br><sub>Bitta chat — imzolangan HTML va JSON</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Tergov&nbsp;↗</b></a><br><sub>Yozib olingan chatlar bo‘ylab izdan boring</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Saqlangan versiyalar&nbsp;↗</b></a><br><sub>Tahrirlar va o‘chirish bildirishnomalari saqlanadi</sub></td>
</tr>
</table>

Ikki xil foydalanish usuli bor: [hisobingizni bir marta eksport qilish](../ACCOUNT-EXPORT.md) yoki
[tergovni kuzatib borish](../INVESTIGATION.md) va o‘zgarishlarni doimiy saqlab borish.
Bir nechta chat, Telegram papkasi yoki butun hisobni tanlang. Har bir hisobga o‘zining
ish maydoni, sessiyasi va imzolash kaliti beriladi.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Ko‘proq bilib oling

<details>
<summary><strong>O‘lchangan eksportlar · 2026-yil 6-noyabr</strong> · 56 329 ta xabar, ikkala arxiv ham tekshirilgan</summary>

**Ikki yangi ishga tushirishda 56 329 ta xabar eksport qilindi.** Ikkala imzolangan arxiv ham qat’iy belgilangan yig‘uvchi kalitlari bilan tekshiruvdan o‘tdi.

[![O‘lchangan yig‘ish va to‘liq eksport tezligi](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/uz/docs/validation/)

| Ishga tushirish | Xabarlar | Yig‘ish vaqti | Yig‘ish tezligi | To‘liq eksport | Boshidan oxirigacha tezlik |
| --- | ---: | ---: | ---: | ---: | ---: |
| Server A | 27 030 | 189,043 s | **142,983 xabar/s** | 211,647 s | 127,713 xabar/s |
| Server B | 29 299 | 182,513 s | **160,531 xabar/s** | 206,650 s | 141,781 xabar/s |

Matn va metama’lumotlar WARP orqali, har bir serverda ikkita hisob, biriktirmalarsiz va qayta ishlatilgan yozuvlarsiz.
[`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e) reviziyasida o‘lchangan.
E’lon qilingan har bir ishga tushirish manba reviziyasi, ish yuklamasi, vaqtlar va tekshiruv natijasini ko‘rsatadi:
[ish yuklamasi, vaqtlar va tekshiruv](../EXPORT-BENCHMARK-2026-11-06.md). `main`dagi o‘zgarishlar
ochiq [CI ish jarayonlaridan](../../.github/workflows/README.md) o‘tadi; ular qatorida Linux va Windows
o‘rnatuvchi sinovlari hamda mustaqil tekshiruvchi buildi ham bor.

[**Demoni ko‘ring →**](https://phishdestroy.github.io/TgWitness/demo/?lang=uz) ·
[**O‘lchovlar, sanalar va usul →**](https://phishdestroy.github.io/TgWitness/uz/docs/validation/) ·
[To‘qima namunaviy eksportni yuklab oling](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Imzolangan inglizcha audit](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Oddiy boshlang. Barcha yo‘nalishlarni ko‘ring.</strong> · birinchi ishga tushirish va tizim xaritasi</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="Birinchi ishga tushirishda Shunchaki yuklab olish, Chatlarni kuzatish yoki Ish uchun dalillar tanlovi taklif etiladi va faqat mos bo‘limlar ko‘rsatiladi. Tizim xaritasi panel, yig‘uvchi, Telegram, jurnal, guvoh va tashqi xizmatlarni tarmoq kuzatuvlari bilan bog‘laydi. To‘qima qiymatlar.">
</picture>

Birinchi ishga tushirishda bitta savol beriladi: **Shunchaki yuklab olish**, **Chatlarni kuzatish** yoki
**Ish uchun dalillar**. Javob maqsad va interfeys darajasini belgilaydi, shuning uchun
panel faqat shu vazifaga kerakli bo‘limlarni ko‘rsatadi. Ulanish, Telegram’ga kirish va
chatlarni tanlash beshta bosqichda davom etadi. Ulanish tekshiruvi o‘zi ishga tushadi,
yo‘nalish variantlari esa faqat u muvaffaqiyatsiz bo‘lganda ochiladi. Ekspert vositalari bitta tugma bilan yoqiladi.

**Tizim xaritasi** o‘rnatilgan tizim Telegram’ga va tashqi xizmatlarga qanday yetib borishini ko‘rsatadi:
panelga kirish, har bir hisobning yo‘nalishi va Telegram manzili, jurnal va
guvoh yo‘li hamda eng so‘nggi tarmoq kuzatuvlari. Mavjud bo‘lmagan kuzatuv
mavjud emas deb belgilanadi.

[Birinchi sozlash](../SETTINGS.md) · [Tizim xaritasi](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Tergovning qolgan qismi uchun yaratilgan</strong> · subyekt kartochkalari, kuzatuv ro‘yxatlari, hamyonlar, onlayn holatni kuzatish, sud hujjatlari</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Ismlar va foydalanuvchi nomlarini Telegram ID bo‘yicha kuzating. Qo‘llab-quvvatlanadigan bot muloqotlarini imzolangan kvitansiyalar bilan qayd eting. Arxivlangan xabarlarni qidiring va faqat o‘qish uchun MCP mijozlarini ulang. SSH yashirilgan va provayder yozuvlari ko‘rib chiqish uchun saqlangan yig‘uvchini joylashtiring. Suhbatni jurnalga havolalar bilan bosqichma-bosqich hujjatlashtiring. Sud shablonlari bilan BagIt ish paketini topshiring. Namuna ish jarayonlari.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Odamlar va dosyelar&nbsp;↗</b></a><br><sub>Telegram ID bo‘yicha kuzatiladigan ismlar va foydalanuvchi nomlari</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Botlar bo‘yicha tergov&nbsp;↗</b></a><br><sub>Imzolangan kvitansiyalar bilan bot muloqotlari</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/uz/docs/archive/"><b>Arxiv qidiruvi, sun’iy intellekt va MCP&nbsp;↗</b></a><br><sub>Arxivda qidiring, faqat o‘qish uchun mijozlarni ulang</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Muhrlangan bulutli joylashtirish&nbsp;↗</b></a><br><sub>Intel TDX ichidagi yig‘uvchi</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Uchta animatsion bosqich: keyingi snapshoti nom o‘zgarishini qayd etgan subyekt kartochkasi, maqsadlari jurnal yozuvlari bilan yopiladigan suhbat rejasi va nazorat summasi to‘g‘ri bo‘lgan hamyonga dekodlanib, kuzatuv ro‘yxatida moslik qo‘zg‘atadigan to‘lov QR kodi. To‘qima qiymatlar.">
</picture>

**Suhbatni hujjatlashtiring.** **Dokumentatsiya** panelida chat uchun bayonnoma boshlang,
shunda har bir qadam o‘zi yoziladi: panel amallari, javoblar va ulardan oldingi
kutish vaqti, tahrirlar, o‘chirish bildirishnomalari, eslatmalar va sun’iy intellekt qoralamalari. Har bir qadam o‘zining jurnal
yozuvi va SHA-256 qiymatiga havola beradi. Hujjat qat’iylashtirilganda u imzolanadi va bayonot xeshi
jurnalga yoziladi.

| | |
| --- | --- |
| [Subyekt kartochkalari](../INVESTIGATION-MODE.md#subject-cards) | Bot, shaxs, kanal yoki guruh profilining Telegram’ning BOT, VERIFIED, SCAM va FAKE belgilari bilan snapshotlari; keyingi snapshot nima o‘zgarganini ko‘rsatadi |
| [Suhbat rejalari](../INVESTIGATION-MODE.md#conversation-plans) | To‘lov yo‘li, infratuzilma yoki odamlarga oid maqsadlar, tayyorlangan xabarlar, javob vaqtlari, soatlar bo‘yicha faollik va qarshi tomonning yozish uslubi |
| [Tarjima](../INVESTIGATION-MODE.md#machine-translation) | Asl matn ostida tillar, model va jurnal yozuvi bilan ko‘rsatiladi |
| [Kuzatuv ro‘yxatlari](../INVESTIGATION-MODE.md#watchlists) | So‘zlar, andozalar, hamyonlar, @foydalanuvchi nomlari, ID’lar, domenlar, telefonlar va havolalar; matn, tahrirlar, yashirin havola manzillari, bot tugmalari, QR kodlar va OCR’da topiladi |
| [Onlayn holatni kuzatish](../INVESTIGATION-MODE.md#online-watch) | Har 1–60 daqiqada tekshirish, bir so‘rovda 100 tagacha hisob, soat va hafta kuni bo‘yicha naqsh |
| [Kodlar va hamyonlar](../INVESTIGATION-MODE.md#codes-in-images) | To‘lov QR kodlari; EIP-55 bo‘yicha tekshirilgan EVM manzillari, xom shakldagi TON, XRP Ledger nazorat summalari, tarmoq, miqdor va token ko‘rsatilgan to‘lov havolalari |
| [Mijoz izlari](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-can-and-cannot-show) | Dumaloq videolar va ovozli xabarlardagi enkoder izlari; yuklash vaqtini yuborish vaqti bilan solishtirish oldindan yozib olingan «jonli» isbotni fosh qiladi |
| [Maxfiy qiyofa va vakolat](../INVESTIGATION-MODE.md#cover-and-authority) | O‘ylab topilgan shaxslar, ruxsatnomalar va ruxsat etilgan chatlar yoki davrdan tashqaridagi xabarlarni belgilaydigan yashirin faoliyat qaydnomasi |
| [Hisobni boshqarish](../INVESTIGATION-MODE.md#account-control) | Profil va maxfiylikni oldin/keyin yozuvlari bilan tahrirlash, oshkorlik tekshiruvi va har bir amaldan so‘ng darhol oflayn rejimga o‘tish |
| [Sud uchun hujjatlar](../INVESTIGATION-MODE.md#documents-for-court) | Rule 902(13)/(14) sertifikatlash shabloni, ashyoviy dalillar ko‘rsatkichi, so‘rovga ilova va ekran yozuvlari uchun WebVTT/SRT subtitrlari bilan BagIt ish paketi |

18+, zo‘ravonlik yoki shaxsiy ma’lumot deb belgilangan kontent sud nusxasida qoladi va
AES-256-GCM bilan muhrlanadi; kalitlar alohida yuboriladi.

[Eksport sozlamalari](../EXPORT_HASHES.md) oddiy API va Takeout orqali olishni,
xabarlar tarixini biriktirmalardan oldin olishni, fayllarni yuklab olish yoki server xeshlarini hamda mos
Telegram Desktop JSON/HTML ko‘rinishlarini qamrab oladi. [Taqsimlangan chat eksporti](../DISTRIBUTED-EXPORT.md#history-acquisition)
ochiq tarix uchun ixtiyoriy Takeout yo‘lini, har 100 xabarda imzolangan tekshiruv punktlarini
va o‘sha hisob bilan oraliq ichida tiklashni taklif qiladi; uning
[unumdorlik dizayni](../FAST-ACQUISITION.md) sinovdan o‘tgan olish xatti-harakatini
va rejalashtirilgan jonli o‘lchovlarni bayon qiladi.

</details>

<details>
<summary><strong>Qolgan hammasi</strong> · tarix, hisoblar, proksilar, sun’iy intellekt, integratsiyalar</summary>

| | |
| --- | --- |
| [Eski xabarlarni yuklash](../HISTORY.md) | Tanlangan chatlarning o‘tmish tarixini yuklab oling, istalgan vaqtda pauza qiling va davom ettiring |
| [Bir nechta hisoblar](../ACCOUNTS.md#multiple-accounts) | Har birida o‘z Telegram sessiyasi, jurnali va imzolash kaliti bo‘lgan alohida ish maydonlari |
| [Ommaviy import](../ACCOUNTS.md#bulk-import-and-account-groups) | Bir to‘da sessiya fayllarini tashlang, hisoblarni umumiy sozlamali guruhlarga ajrating |
| [MTProxy to‘plami](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, mamlakatlar, filtrlar, o‘z ro‘yxatlaringiz |
| [Mavjud sessiyalar](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key yoki `key:DC` qatori; import qilingan donordan ixtiyoriy mustaqil QR avtorizatsiyasi |
| [Hisob xavfsizligi](../ACCOUNTS.md#create-an-independent-authorization) | Yangi sessiyalar haqida ogohlantirishlar, boshqa sessiyalarni tugatish, ikki bosqichli parolni ham o‘rnatadigan yagona sessiya rejimi va jonli yangilanishlar bu sessiyaga kelmay qolganini sezadigan [guvoh tekshiruvi](../ACCOUNTS.md#witness-probe) |
| [Davom ettiriladigan chat eksporti](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | To‘xtatilgan eksport imzolangan qisman nusxani saqlaydi: uni davom ettiring, qaytadan boshlang yoki saqlanganini yuklab oling |
| [Proksilar](../CONNECTION-SECURITY.md#ip-modes) | Har bir ish maydoni uchun SOCKS5, HTTP CONNECT yoki MTProxy. **IPni yashirish** hech qachon to‘g‘ridan-to‘g‘ri ulanishga qaytmaydi |
| [Qidiruv va sun’iy intellekt](../ANALYSIS.md) | Mahalliy qidiruv, manbalarini tekshirsa bo‘ladigan ixtiyoriy sun’iy intellekt |
| [To‘liq matnli qidiruv](../SEARCH.md) | So‘z shakllari, aniq iboralar, domenlar, @foydalanuvchi nomlari va bo‘sh joysiz xitoycha matn, eng yaxshi mosliklar birinchi (**sinov versiyasi**) |
| [MCP](../MCP.md) | MCP mijozlari uchun faqat o‘qish huquqi, siz tanlagan chatlar bilan cheklangan |
| [Buyruq qatori](../CLI.md) | Skriptlar va agentlar uchun `--json` bilan `search`, `context`, `messages`, `stats` va JSON Lines `export`, mahalliy ravishda yoki doirasi cheklangan token bilan (**sinov versiyasi**) |
| [OCR va transkripsiya](../MEDIA-ANALYSIS.md) | Mahalliy ishlaydi, asl fayllarga tegilmaydi |
| [Mustaqil yozib olish](../OPTIONAL-CAPTURE.md) | **Qo‘shimcha vositalar → Qo‘shimchalar** ostidagi ixtiyoriy brauzer/AyuGram yozuvchilari (oldindan ko‘rish, standart holatda o‘chiq) |
| [Trusted Live](../TRUSTED-LIVE.md) | Rasmiy Desktop/Web sessiyasi, himoyalangan video va Telegram’ning o‘z eksporti bilan uzluksizlik tahlili (oldindan ko‘rish; jonli kvalifikatsiya kutilmoqda) |
| [Muhrlangan rasmiy Web](../OFFICIAL-WITNESS.md) | GitHub Actions’da yangi ishga tushirilgan rasmiy brauzer, cheklangan boshqaruv, imzolangan video va mustaqil ravishda kutilgan manba/sozlamalar |
| [Webhooklar](../WEBHOOKS.md) | Qayta urinishli imzolangan chiquvchi hodisalar, n8n misoli bilan |
| [Umumiy kirish](../ACCESS.md) | Kimgadir faqat tanlangan chatlarni muddat va IP cheklovlari bilan bering |
| [Yetishmayotgan xabar raqamlari](../EVIDENCE.md#missing-message-numbers-gap_summary) | Telegram bergan, ammo hech qachon kuzatilmagan raqamlar, har bir kanal va butun hisob bo‘yicha, qamrovda, hisobotlarda va MCP’da (**sinov versiyasi**) |
| [Chat holati snapshotlari](../COLLECTION.md) | Sarlavha, tavsif, qadalgan xabarlar, administratorlar va sovg‘alarning nima o‘zgarganini ko‘rsatuvchi davriy imzolangan snapshotlari (**sinov versiyasi**) |
| [Tizim xaritasi](../SYSTEM-MAP.md) | Panelga kirish, hisob yo‘nalishlari, Telegram manzillari va tashqi xizmatlarning jonli xaritasi, 2 000 tagacha tarmoq kuzatuvidan eng so‘nggi 200 tasi bilan |

</details>

<details>
<summary><strong>Yozuvga nima tayanch bo‘lishini tanlang</strong> · mahalliy, audit qilingan bulut, GitHub Actions yoki Intel TDX</summary>

Mahalliy ishga tushiring, audit qilingan bulutli joylashtirishni qo‘shing yoki **Intel TDX’li Phala Cloud
maxfiy virtual mashinasi** ichida yig‘ing. Har bir variant imzolangan jurnalni saqlaydi; qo‘shimcha
tekshiruvlar u yig‘ilgan muhitga taalluqli.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Uchta joylashtirish varianti: mahalliy jurnal tekshiruvi; provayder va kirish yozuvlari bo‘lgan audit qilingan VM; tekshirilgan quote, o‘lchangan operatsion tizim va ilova hamda bog‘langan yig‘uvchi kaliti bilan Phala Intel TDX.">
</picture>

TDX tekshiruvchisi quote’ni Intel’ning qat’iy belgilangan ildizi va bekor qilish ma’lumotlari bo‘yicha tekshiradi,
uni imzolangan yig‘uvchi bayonoti va yangi chaqiriq bilan bog‘laydi hamda o‘lchangan
operatsion tizim va ilovani mustaqil ravishda kutilgan kirish ma’lumotlari bilan solishtiradi. Hisobot
har bir natijani alohida ko‘rsatadi, shuning uchun o‘lchangan muhit, yig‘uvchi identifikatori, yozib olish
yozuvlari va qamrovni birgalikda ko‘rib chiqish mumkin.

**GitHub kelib chiqishi bilan yozib olish** (oldindan ko‘rish). Chatni qat’iy belgilangan TgWitness versiyasi va yangi Telegram sessiyasi bilan
GitHub’da joylashgan runner’da yig‘ing, so‘ng shifrlangan
arxivni uning GitHub attestatsiyasi bilan yuklab oling. Tekshiruvchi tasdiqlangan ish jarayoni va
yig‘uvchi versiyasini, arxiv xeshini, jurnal va biriktirmalarni tekshiradi. Paneldagi
**Eksportlar** bo‘limida ham mavjud.
[Yozib olish sahifasini oching](https://phishdestroy.github.io/TgWitness/uz/docs/capture/) · [Ko‘rsatmalar](../SEALED-ACTIONS.md)

Jonli kuzatuv, tarix yoki bir martalik eksport uchun
[yig‘ish usulini](../COLLECTION-MODES.md) tanlang. Xususiy bulutli chatlar ulangan hisob
ularga kira olsa, mavjud bo‘ladi. E’lon qilingan ilovada
[Maxfiy chat integratsiyasi](../PSEUDO-SECRET.md) ham bor: ixtiyoriy protokol bog‘liqligini o‘rnating
va u yerda yaratilgan yoki qabul qilingan chatlarni yozib olish uchun uni har bir hisobda yoqing.
Mavjud olish yo‘llari uchun [yig‘ish doirasi](../COLLECTION.md) sahifasiga qarang.

[Phala / Intel TDX va audit qilingan joylashtirishlar](../HIGH-ASSURANCE.md) ·
[Phala’da jonli kvalifikatsiya](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Ishonch chegaralari](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Yozib olishni va saqlangan yozuvni tekshiring</strong> · qabul qiluvchi nimani tekshiradi va Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Suhbatni yozib oling. Yozuvni tekshiring. Xabarlar, tahrirlar va fayllarni saqlang, imzolar va tekshiruv punktlarini tekshiring hamda yozib olish jarayonini ko‘rib chiqing.">
</picture>

TgWitness ulangan Telegram hisobiga yetkazilgan kontentni chat, xabar va jo‘natuvchi
identifikatorlari, yozib olingan versiyalar va yig‘ish metama’lumotlari bilan birga qayd etadi.
Arxiv bu yozuvlarni, saqlab qolingan biriktirmalarni va tekshirish ma’lumotlarini
ko‘rib chiqish uchun bir joyga jamlaydi.

| Tekshiruv | Qabul qiluvchi nimani tekshiradi |
| --- | --- |
| Imzolangan jurnal va manifest | Yozuv imzolari, xesh zanjiri va yetkazilgan fayllar — kutilgan imzolash kalitiga nisbatan. |
| Alohida saqlanadigan tekshiruv punkti | Jurnal — oldin qayd etilgan uzunlik va eng yangi yozuv xeshiga nisbatan. |
| Mustaqil guvoh | Jurnal — alohida guvoh saqlagan tekshiruv punktlariga nisbatan. |
| GitHub Actions orqali yozib olish | Arxiv — uning attestatsiyasi, GitHub’da bajariladigan tasdiqlangan ish jarayoni va yig‘uvchi versiyasiga nisbatan. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
Telegram suhbatini ataylab o‘zgartirilgan Desktop eksport fayllari yonida ko‘rsatadi.
Versiyalarni solishtiring, o‘zgarishlarni ko‘rib chiqing va imzolangan TgWitness arxivi uchun
yig‘ish hamda tekshirish bosqichlarini kuzating.

[Tekshirish bosqichlari](../wiki/Exports-and-Verification.md) ·
[GitHub orqali yozib olish](../SEALED-ACTIONS.md) ·
[Texnik ishonch modeli](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Tergovni to‘xtatmang</strong> · bildirishnomalar, saqlash va tiklash</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Animatsion ish jarayonlari: Apprise sozlangan ogohlantirishlarni yuboradi; tashqi nusxalar S3 bilan mos xotiraga yuklashdan oldin shifrlanadi.">
</picture>

[Bildirishnomalar](../OPERATIONS.md#notifications) · [Shifrlangan tashqi nusxa](../wiki/Off-site-Copy.md) · [Zaxira nusxa va tiklash](../wiki/Backup-and-Recovery.md) · [Muammolarni bartaraf etish](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/uz/docs/start/"><b>Sozlash qo‘llanmasi&nbsp;↗</b></a><br><sub>O‘rnatishdan birinchi chatgacha</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/uz/docs/dedicated-account/"><b>Hisobingizni tayyorlang&nbsp;↗</b></a><br><sub>Alohida Telegram hisobi</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker va serverlar&nbsp;↗</b></a><br><sub>HTTPS, qayta ishga tushirish va yangilanishlar</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Repozitoriyni ko‘rib chiqing</strong> · kod, hujjatlar va vositalar qayerda</summary>

| Katalog | Shu yerdan boshlang |
| --- | --- |
| [docs/](../README.md) | Sozlash, tergov ish jarayonlari va texnik ma’lumotnoma |
| [tgwitness/](../../tgwitness/README.md) | Asosiy ilova, yig‘uvchi, jurnal va veb-panel |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Mustaqil yozuvchilar va ularning tekshirish kodi |
| [addons/](../../addons/README.md) | Ixtiyoriy yozib olishni o‘rnatish, sozlash va sinovlar |
| [deploy/](../../deploy/README.md) | O‘rnatuvchilar, konteynerlar va fon xizmatlari |
| [examples/](../../examples/README.md) | Hisob eksporti va muhrlangan yozib olish konfiguratsiyalari |
| [integrations/](../../integrations/README.md) | Imzolangan webhooklar va n8n qabul qiluvchisi |
| [.agents/](../../.agents/README.md) | Arxivni CLI orqali o‘qish bo‘yicha vazifa ko‘rsatmalari |
| [scripts/](../../scripts/README.md) | Ishga tushirgichlar va CI yordamchi vositalari |
| [tools/](../../tools/README.md) | Buildlar, tekshiruvlar va paketlash |
| [website/](../../website/README.md) | Ochiq sayt, tarjima qilingan qo‘llanmalar va interaktiv demo |
| [.github/](../../.github/AUTOMATION.md) | Ish jarayonlari, hissa qo‘shish qoidalari va yordam |

[Loyihaning to‘liq qo‘llanmasi](../PROJECT-GUIDE.md) ·
[Hissa qo‘shish](../../.github/CONTRIBUTING.md) · [Yordam olish](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Axloqiy bildirishnoma va tarixiy davomiylik</strong></summary>

Mualliflarning pozitsiyasi va operator haqidagi bildirishnoma, shu tilda:

[Litsenziya va arxitektura nomuvofiqligi to'g'risidagi bildirishnoma](TAYLOR-WESSING-EXCLUSION.md) · [Operator haqida bildirishnoma](OPERATOR-INCOMPATIBILITY.md) · [MIT litsenziyasi](../../LICENSE) · [Asl NOTICE](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Loyiha sharhini o‘z tilingizda o‘qing</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · **O‘zbekcha** · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Texnik hujjatlar</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Tergov qo‘llanmasi</b></a> ·
  <a href="https://github.com/phishdestroy"><b>PhishDestroy tomonidan yaratilgan</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Hissa qo‘shing</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Yordam olish</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Zaiflik haqida xabar bering</b></a>
</p>

[Mashina o‘qiy oladigan loyiha indeksi](../../llms.txt) · [To‘liq matnli qo‘llanma](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Agentlar uchun repozitoriy qoidalari](../../AGENTS.md)
