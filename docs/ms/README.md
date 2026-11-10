<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Bahasa lain</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Jejaki petunjuk. Pelihara bukti. Jurnal bertandatangan yang dirangkai dengan hash, titik pemeriksaan yang disimpan berasingan dan arkib bukti yang boleh disahkan.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=ms"><b>Terokai demo&nbsp;↗</b></a><br><sub>Antara muka sebenar dengan rekod rekaan</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Muat turun dan mulakan&nbsp;↓</b></a><br><sub>Satu arahan untuk Linux, macOS dan Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Baca buku panduan&nbsp;↗</b></a><br><sub>Panduan siasatan langkah demi langkah</sub></td>
</tr>
</table>

<p align="center"><strong>Ruang kerja hos sendiri untuk siasatan Telegram.</strong><br>Simpan sembang, kekalkan suntingan dan pemadaman, lihat siapa berkait dengan siapa<br>dan serahkan eksport bertandatangan yang boleh disemak oleh sesiapa sahaja.</p>

<p align="center"><strong>ZERO TRUST.</strong> TgWitness tidak memihak: semakan yang sama terpakai kepada operator, PhishDestroy dan sesiapa sahaja.<br>Hanya perkara yang disahkan oleh pihak ketiga atau matematik diambil kira. <a href="../LIMITS-AND-OBJECTIONS.md">Had dan bantahan</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · pra-keluaran"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Persekitaran yang diuji</a> · 25 bahasa antara muka · 26 bahasa panduan</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=ms">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="Demo TgWitness sedang berjalan: mesej yang ditangkap, versi yang disimpan dan kandungan yang kekal selepas pemadaman. Rekod demonstrasi rekaan.">
</picture>
</a>

<p align="center"><sub>Terokai antara muka sebenar dengan rekod rekaan. Klik ruang kerja untuk mencubanya.</sub></p>

## Apa yang dilakukan oleh TgWitness

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Setiap suntingan dan pemadaman disimpan</a></b><br><sub>Setiap versi mesej disimpan, dan teksnya kekal selepas notis pemadaman.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Bukti yang boleh disemak oleh sesiapa</a></b><br><sub>Rekod bertandatangan yang dirantai dengan hash. Penerima mengesahkan arkib secara luar talian dengan satu arahan.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Asal usul yang boleh ditunjukkan</a></b><br><sub>Diterima melalui sesi MTProto akaun yang berautentikasi dan ditandatangani sebaik tiba; GitHub Actions dan Intel TDX menambah atestasi.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Diukur pada skala besar</a></b><br><sub>48 arkib yang disahkan dengan 3,598,381 rekod; lapan akaun memperoleh 768,007 rekod sejarah pada kadar 687.5 rekod/saat.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Dibina untuk siasatan</a></b><br><sub>Senarai pantau merangkumi teks, kod QR dan OCR, semakan dompet, kad subjek, Papan Kes dan pakej mahkamah.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Di bawah kawalan anda</a></b><br><sub>Dihos sendiri tanpa telemetri. Sesi disimpan dalam peti besi yang disulitkan; panel mendengar pada localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Dibangunkan dan diuji selama kira-kira enam bulan: pengumpul, jurnal yang ditandatangani dan pengesah terlebih dahulu, kemudian panel dan modul tambahan. Repositori ini dicipta pada 29 Oktober 2026 untuk penerbitan, jadi umurnya bukan umur projek.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Pasang

Python disertakan. Gunakan arahan yang sama untuk mengemas kini.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell atau CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Pelayan Ubuntu: jalankan sebagai root. Desktop: jalankan sebagai pengguna biasa anda. `-ExecutionPolicy Bypass` hanya terpakai pada proses PowerShell yang satu ini.</sub>

Binaan bertandatangan datang daripada [aliran kerja Installer](../../.github/workflows/installer.yml) awam, dan pemasang menyemak SHA-256 serta tandatangan RSA setiap pakej sebelum memasang.

[Sahkan skrip dahulu](../INSTALLATION.md#verify-before-running) · [Persediaan pertama](../SETTINGS.md) · [Keluaran](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>Cara pemasang dan data anda dilindungi</strong></summary>

`get.destroy.tools` ialah tapak muat turun projek.
[Aliran kerja Installer](../../.github/workflows/installer.yml) awam membinanya daripada
[`deploy/installer/`](../../deploy/installer/README.md) untuk revisi `main` yang tepat,
menerbitkannya selepas ujian pemasangan Linux dan Windows lulus, dan menandatangani
skrip pemasang serta pakej aplikasi dengan kunci keluaran dalam
[`release-signing.pub`](../../deploy/installer/release-signing.pub). Pemasang menyemak
SHA-256 dan tandatangan RSA pakej serta fail lock kebergantungan sebelum memasang.
Untuk menyemak skrip itu sendiri dahulu, muat turun skrip bersama tandatangannya dan jalankan
[arahan sahkan-dahulu](../INSTALLATION.md#verify-before-running). Jika binaan gagal,
muat turun sebelumnya dikekalkan; panel yang telah dipasang dikemas kini apabila anda menjalankan semula pemasang.
[Keluaran](https://github.com/phishdestroy/TgWitness/releases) GitHub, kod sumber dan
[Docker](../DEPLOYMENT.md) ialah cara lain untuk memasang.

**Sesi dan data anda.** TgWitness berjalan pada komputer atau pelayan anda, dan secara lalai panel
mendengar pada localhost. Sesi Telegram, maklumat log masuk proksi dan hash token akses
disimpan dalam peti besi yang disulitkan bagi setiap ruang kerja, dengan
[kunci induk luaran](../SECURITY-MODEL.md#external-master-key) sebagai pilihan. Aplikasi ini
tidak mempunyai telemetri. Ia bersambung ke Telegram dan ke perkhidmatan yang digunakan oleh tetapannya:
senarai MTProxy awam, proksi anda, storan S3, bot saksi, pihak berkuasa
cap masa, penyedia AI dan webhook. [Peta sistem](../SYSTEM-MAP.md) menyenaraikan
sambungan yang dibuat oleh proses aplikasi.
Buat pemerhatian dengan [akaun Telegram khusus](https://phishdestroy.github.io/TgWitness/ms/docs/dedicated-account/).

Lencana versi menerangkan pepohon sumber ini. Binaan yang boleh dipasang disenaraikan di bawah
[Keluaran](https://github.com/phishdestroy/TgWitness/releases); ciri yang digabungkan ke dalam
`main` sampai ke muat turun tersebut dalam keluaran seterusnya.

[Persediaan & akses panel](../INSTALLATION.md) ·
[Tandatangan & SHA-256](https://get.destroy.tools/#verification) ·
[Kemas kini](../INSTALLATION.md#update-an-existing-installation) ·
[Keupayaan semasa dan ujian kelayakan](../STATUS.md) ·
[Pilih kaedah pengumpulan](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Rekod yang boleh disemak oleh orang lain

Semak tanpa akaun atau pemasangan. Sampel yang diterbitkan membawa pengesahnya sendiri:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # pengesah disertakan di dalam arkib
python verify.py tgwitness-demo.zip          # Python 3.11+, hanya perlukan `cryptography`
```

Ia memaparkan rekod bertandatangan, hash rekod terbaru dan cap jari penandatangan, kemudian keluar dengan kod `0`.
Sampel ini rekaan; pengesah yang sama berjalan pada mana-mana eksport sebenar.

Eksport mengandungi mesej, fail dan pengesah. Hantar cap jari kunci anda kepada penerima
melalui saluran lain, dan mereka boleh menyemaknya sendiri:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Pengesah menyemak tandatangan, rantaian jurnal, senarai fail dan lampiran.
Untuk tahap bukti, ia memerlukan cap jari kunci anda dan cap masa pihak ketiga yang meliputi rekod
terakhir, seperti cap masa RFC 3161 yang disemak terhadap sijil akar pihak berkuasa itu.

**Dari mana mesej datang.** TgWitness menerimanya daripada Telegram melalui sesi MTProto
akaun yang disulitkan, sama seperti aplikasi rasmi, dan menandatangani setiap mesej ke dalam
jurnal sebaik ia tiba. [Tangkapan GitHub Actions](../SEALED-ACTIONS.md) dan
[Phala Intel TDX](../HIGH-ASSURANCE.md) turut memberikan atestasi bagi pengumpul yang menerimanya.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Mesej baharu, suntingan yang disimpan dan pemerhatian pemadaman membentuk jurnal bertandatangan yang saling dirangkai. Sahkan jurnal itu terhadap kunci yang dipercayai secara bebas.">
</picture>

[Pengesahan arkib](../wiki/Exports-and-Verification.md) · [Format bukti](../EVIDENCE.md) · [Saksi bebas](../WITNESS.md) · [Cap masa luaran](../TIMESTAMP.md) · [Semakan dan skala yang diuji](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Daripada perbualan kepada kes

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Tiga aliran kerja beranimasi: mengeksport sembang ke HTML dan JSON, mencari pautan yang dikongsi merentas sembang yang dirakam, dan mengekalkan versi yang ditangkap selepas notis pemadaman.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Eksport sembang&nbsp;↗</b></a><br><sub>Satu sembang kepada HTML dan JSON bertandatangan</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Siasatan&nbsp;↗</b></a><br><sub>Ikut petunjuk merentas sembang yang dirakam</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Versi yang disimpan&nbsp;↗</b></a><br><sub>Suntingan dan notis pemadaman, dikekalkan</sub></td>
</tr>
</table>

Dua cara menggunakannya: [eksport akaun anda](../ACCOUNT-EXPORT.md) sekali, atau
[ikuti siasatan](../INVESTIGATION.md) dan terus simpan perubahan.
Pilih beberapa sembang, folder Telegram atau keseluruhan akaun. Setiap akaun mendapat
ruang kerja, sesi dan kunci tandatangan tersendiri.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Terokai lagi

<details>
<summary><strong>Eksport yang diukur · 6 November 2026</strong> · 56,329 mesej, kedua-dua arkib disahkan</summary>

**56,329 mesej dieksport dalam dua larian baharu.** Kedua-dua arkib bertandatangan lulus pengesahan dengan kunci pengumpul yang disematkan.

[![Kelajuan pengumpulan dan eksport lengkap yang diukur](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/ms/docs/validation/)

| Larian | Mesej | Masa pengumpulan | Kelajuan pengumpulan | Eksport lengkap | Kelajuan hujung ke hujung |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pelayan A | 27,030 | 189.043 s | **142.983 mesej/s** | 211.647 s | 127.713 mesej/s |
| Pelayan B | 29,299 | 182.513 s | **160.531 mesej/s** | 206.650 s | 141.781 mesej/s |

Teks dan metadata melalui WARP, dua akaun setiap pelayan, tanpa lampiran atau rekod yang digunakan semula.
Diukur pada revisi [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Setiap larian yang diterbitkan menyenaraikan revisi sumber, beban kerja, masa dan keputusan pengesahannya:
[beban kerja, masa dan pengesahan](../EXPORT-BENCHMARK-2026-11-06.md). Perubahan pada `main`
menjalankan [aliran kerja CI](../../.github/workflows/README.md) awam, termasuk ujian pemasang Linux dan Windows
serta binaan pengesah kendiri.

[**Terokai demo →**](https://phishdestroy.github.io/TgWitness/demo/?lang=ms) ·
[**Ukuran, tarikh dan kaedah →**](https://phishdestroy.github.io/TgWitness/ms/docs/validation/) ·
[Muat turun contoh eksport rekaan](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Audit bahasa Inggeris bertandatangan](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Mula dengan mudah. Lihat setiap laluan.</strong> · permulaan pertama dan peta sistem</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="Permulaan pertama menawarkan “Muat turun sahaja”, “Pantau sembang” atau “Bukti untuk satu kes” dan hanya memaparkan bahagian yang sepadan. Peta sistem menghubungkan panel, pengumpul, Telegram, jurnal, saksi dan perkhidmatan luar, berserta pemerhatian rangkaian. Nilai rekaan.">
</picture>

Permulaan pertama hanya bertanya satu soalan: **Muat turun sahaja**, **Pantau sembang** atau
**Bukti untuk satu kes**. Jawapannya menetapkan matlamat dan tahap antara muka, jadi
panel hanya memaparkan bahagian yang diperlukan oleh tugas itu. Sambungan, log masuk Telegram dan
pemilihan sembang menyusul dalam lima peringkat. Semakan sambungan berjalan sendiri, dan
pilihan laluan hanya dibuka apabila semakan itu gagal. Alat pakar hanya sejauh satu suis.

**Peta sistem** menunjukkan cara pemasangan mencapai Telegram dan perkhidmatan
luar: akses panel, laluan dan sasaran Telegram setiap akaun, laluan jurnal dan
saksi, serta pemerhatian rangkaian terkini. Pemerhatian yang tiada
dilabel sebagai tiada.

[Persediaan pertama](../SETTINGS.md) · [Peta sistem](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Dibina untuk baki siasatan</strong> · kad subjek, senarai pantau, dompet, pemantauan dalam talian, dokumen mahkamah</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Jejaki nama dan nama pengguna mengikut ID Telegram. Rakam interaksi bot yang disokong dengan resit bertandatangan. Cari mesej yang diarkibkan dan sambungkan klien MCP baca sahaja. Atur gerak pengumpul dengan SSH disamarkan dan rekod penyedia untuk semakan. Dokumentasikan perbualan langkah demi langkah dengan rujukan jurnal. Serahkan pakej kes BagIt dengan templat mahkamah. Aliran kerja ilustrasi.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Orang dan dosier&nbsp;↗</b></a><br><sub>Nama dan nama pengguna dijejaki mengikut ID Telegram</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Siasatan bot&nbsp;↗</b></a><br><sub>Interaksi bot dengan resit bertandatangan</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ms/docs/archive/"><b>Carian arkib, AI dan MCP&nbsp;↗</b></a><br><sub>Cari dalam arkib, sambungkan klien baca sahaja</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Atur gerak awan termeterai&nbsp;↗</b></a><br><sub>Pengumpul di dalam Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Tiga langkah beranimasi: kad subjek yang syot kilat kemudiannya merekodkan pertukaran nama, pelan perbualan yang matlamatnya ditutup dengan rekod jurnal, dan kod QR pembayaran yang dinyahkod kepada dompet dengan checksum yang sah lalu mencetuskan padanan senarai pantau. Nilai rekaan.">
</picture>

**Dokumentasikan perbualan.** Mulakan rekod untuk sesuatu sembang dalam panel sisi **Dokumentasi**
dan setiap langkah ditulis dengan sendirinya: tindakan panel, balasan berserta selang masa sebelumnya,
suntingan, notis pemadaman, nota dan draf AI. Setiap langkah merujuk rekod
jurnal dan SHA-256nya. Memuktamadkan dokumen akan menandatanganinya dan menulis hash kenyataan ke dalam
jurnal.

| | |
| --- | --- |
| [Kad subjek](../INVESTIGATION-MODE.md#subject-cards) | Syot kilat profil bot, orang, saluran atau kumpulan dengan label BOT, VERIFIED, SCAM dan FAKE daripada Telegram; syot kilat kemudian menyenaraikan perkara yang berubah |
| [Pelan perbualan](../INVESTIGATION-MODE.md#conversation-plans) | Matlamat bagi laluan pembayaran, infrastruktur atau orang, mesej yang disediakan, masa balasan, aktiviti mengikut jam dan gaya penulisan pihak lawan |
| [Terjemahan](../INVESTIGATION-MODE.md#machine-translation) | Dipaparkan di bawah teks asal berserta bahasa, model dan rekod jurnal |
| [Senarai pantau](../INVESTIGATION-MODE.md#watchlists) | Perkataan, corak, dompet, @nama pengguna, ID, domain, nombor telefon dan pautan, dipadankan dalam teks, suntingan, sasaran pautan tersembunyi, butang bot, kod QR dan OCR |
| [Pemantauan dalam talian](../INVESTIGATION-MODE.md#online-watch) | Semakan setiap 1–60 minit, sehingga 100 akaun bagi setiap permintaan, dengan corak mengikut jam dan hari dalam minggu |
| [Kod dan dompet](../INVESTIGATION-MODE.md#codes-in-images) | Kod QR pembayaran; alamat EVM yang disemak terhadap EIP-55, TON dalam bentuk mentah, checksum XRP Ledger, pautan pembayaran dengan rantaian, jumlah dan token |
| [Kesan klien](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-can-and-cannot-show) | Kesan pengekod dalam video bulat dan mesej suara; perbandingan masa muat naik dengan masa hantar mendedahkan bukti “langsung” yang sebenarnya dirakam lebih awal |
| [Penyamaran dan kuasa](../INVESTIGATION-MODE.md#cover-and-authority) | Persona, kebenaran dan rekod aktiviti penyamaran yang menandakan mesej di luar sembang atau tempoh yang dibenarkan |
| [Kawalan akaun](../INVESTIGATION-MODE.md#account-control) | Penyuntingan profil dan privasi dengan rekod sebelum/selepas, semakan pendedahan dan status luar talian sejurus selepas setiap tindakan |
| [Dokumen untuk mahkamah](../INVESTIGATION-MODE.md#documents-for-court) | Pakej kes BagIt dengan templat pensijilan Rule 902(13)/(14), indeks ekshibit, lampiran permintaan dan sari kata WebVTT/SRT untuk rakaman skrin |

Kandungan yang ditandakan 18+, keganasan atau data peribadi kekal dalam salinan mahkamah, dimeterai dengan
AES-256-GCM; kuncinya dihantar secara berasingan.

[Tetapan eksport](../EXPORT_HASHES.md) meliputi pemerolehan melalui API biasa dan Takeout,
sejarah mesej sebelum lampiran, muat turun fail atau hash pelayan, serta paparan
JSON/HTML yang serasi dengan Telegram Desktop. [Eksport sembang teragih](../DISTRIBUTED-EXPORT.md#history-acquisition)
menawarkan laluan Takeout pilihan untuk sejarah awam, titik pemeriksaan bertandatangan setiap 100 mesej,
serta pemulihan dalam sesuatu julat menggunakan akaun yang sama;
[reka bentuk prestasinya](../FAST-ACQUISITION.md) menyenaraikan tingkah laku pemerolehan yang telah diuji
dan ukuran langsung yang dirancang.

</details>

<details>
<summary><strong>Selebihnya</strong> · sejarah, akaun, proksi, AI, integrasi</summary>

| | |
| --- | --- |
| [Muatkan mesej lama](../HISTORY.md) | Tarik sejarah lepas bagi sembang terpilih, jeda dan sambung pada bila-bila masa |
| [Beberapa akaun](../ACCOUNTS.md#multiple-accounts) | Ruang kerja berasingan, masing-masing dengan sesi Telegram, jurnal dan kunci tandatangan sendiri |
| [Import pukal](../ACCOUNTS.md#bulk-import-and-account-groups) | Masukkan banyak fail sesi sekali gus, susun akaun ke dalam kumpulan dengan tetapan dikongsi |
| [Himpunan MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, negara, penapis, senarai anda sendiri |
| [Sesi sedia ada](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key atau baris `key:DC`; kebenaran QR bebas sebagai pilihan daripada penderma yang diimport |
| [Keselamatan akaun](../ACCOUNTS.md#create-an-independent-authorization) | Amaran sesi baharu, menamatkan sesi lain, mod sesi tunggal yang turut menetapkan kata laluan dua langkah, dan [probe saksi](../ACCOUNTS.md#witness-probe) yang mengesan apabila kemas kini langsung berhenti sampai ke sesi ini |
| [Eksport sembang boleh disambung](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Eksport yang terhenti menyimpan salinan separa bertandatangan: sambung semula, mula semula atau muat turun apa yang telah disimpan |
| [Proksi](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT atau MTProxy bagi setiap ruang kerja. **Sembunyikan IP** tidak sekali-kali beralih kepada sambungan terus |
| [Carian dan AI](../ANALYSIS.md) | Carian setempat, AI pilihan dengan sumber yang boleh anda semak |
| [Carian teks penuh](../SEARCH.md) | Bentuk kata, frasa tepat, domain, @nama pengguna dan bahasa Cina tanpa jarak, padanan terbaik dahulu (**Pratonton**) |
| [MCP](../MCP.md) | Akses baca sahaja untuk klien MCP, terhad kepada sembang yang anda pilih |
| [Baris arahan](../CLI.md) | `search`, `context`, `messages`, `stats` dan `export` JSON Lines dengan `--json` untuk skrip dan ejen, secara setempat atau dengan token berskop (**Pratonton**) |
| [OCR dan transkripsi](../MEDIA-ANALYSIS.md) | Berjalan secara setempat, fail asal tidak disentuh |
| [Tangkapan bebas](../OPTIONAL-CAPTURE.md) | Perakam pelayar/AyuGram pilihan di bawah **Alat lain → Tambahan** (pratonton, dimatikan secara lalai) |
| [Trusted Live](../TRUSTED-LIVE.md) | Sesi Desktop/Web rasmi, video berkawal dan analisis kesinambungan dengan eksport asli (pratonton; ujian kelayakan langsung belum selesai) |
| [Web rasmi termeterai](../OFFICIAL-WITNESS.md) | Pelayar rasmi baharu pada GitHub Actions, kawalan terhad, video bertandatangan dan sumber/tetapan yang dijangka secara bebas |
| [Webhook](../WEBHOOKS.md) | Peristiwa keluar bertandatangan dengan cubaan semula, termasuk contoh n8n |
| [Akses dikongsi](../ACCESS.md) | Beri seseorang akses kepada sembang terpilih sahaja, dengan tarikh luput dan had IP |
| [Nombor mesej yang hilang](../EVIDENCE.md#missing-message-numbers-gap_summary) | Nombor yang diberikan Telegram tetapi tidak pernah diperhatikan, bagi setiap saluran dan seluruh akaun, dalam liputan, laporan dan MCP (**Pratonton**) |
| [Syot kilat keadaan sembang](../COLLECTION.md) | Syot kilat bertandatangan berkala bagi tajuk, penerangan, pin, pentadbir dan hadiah, berserta perkara yang berubah (**Pratonton**) |
| [Peta sistem](../SYSTEM-MAP.md) | Peta langsung akses panel, laluan akaun, sasaran Telegram dan perkhidmatan luar, dengan 200 terkini daripada sehingga 2,000 pemerhatian rangkaian |

</details>

<details>
<summary><strong>Pilih asas yang menyokong rekod</strong> · setempat, awan yang diaudit, GitHub Actions atau Intel TDX</summary>

Jalankan secara setempat, tambah atur gerak awan yang diaudit, atau kumpul di dalam **VM sulit Phala Cloud
dengan Intel TDX**. Setiap pilihan mengekalkan jurnal bertandatangan; semakan
tambahan memberi tumpuan kepada persekitaran tempat jurnal itu dikumpul.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Tiga pilihan atur gerak: pengesahan jurnal setempat; VM yang diaudit dengan rekod penyedia dan akses; Phala Intel TDX dengan quote yang disahkan, OS dan aplikasi yang diukur, serta kunci pengumpul yang terikat.">
</picture>

Pengesah TDX menyemak quote terhadap akar dan data pembatalan Intel yang disematkan,
mengikatnya kepada kenyataan pengumpul yang ditandatangani dan cabaran baharu, kemudian membandingkan
OS dan aplikasi yang diukur dengan input yang dijangka secara bebas. Laporan menyenaraikan
setiap keputusan secara berasingan, supaya persekitaran yang diukur, identiti pengumpul, rekod
tangkapan dan liputan boleh disemak bersama.

**Tangkapan dengan provenans GitHub** (pratonton). Kumpul sembang pada runner yang dihoskan GitHub
dengan TgWitness yang disematkan dan sesi Telegram baharu, kemudian muat turun arkib
yang disulitkan berserta atestasi GitHubnya. Pengesah menyemak aliran kerja yang diluluskan dan
versi pengumpul, digest arkib, jurnal dan lampiran. Turut tersedia
di bawah **Eksport** dalam panel.
[Buka halaman tangkapan](https://phishdestroy.github.io/TgWitness/ms/docs/capture/) · [Arahan](../SEALED-ACTIONS.md)

Untuk pemerhatian langsung, sejarah atau eksport sekali sahaja, pilih
[kaedah pengumpulan](../COLLECTION-MODES.md). Sembang awan peribadi tersedia
apabila akaun yang disambungkan boleh mengaksesnya. Aplikasi yang diterbitkan juga menyertakan
[integrasi Sembang Rahsia](../PSEUDO-SECRET.md): pasang kebergantungan protokol pilihan
dan dayakannya bagi setiap akaun untuk merakam sembang yang dicipta atau diterima di sana.
Lihat [skop pengumpulan](../COLLECTION.md) untuk laluan pemerolehan yang tersedia.

[Phala / Intel TDX dan atur gerak yang diaudit](../HIGH-ASSURANCE.md) ·
[Ujian kelayakan langsung Phala](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Sempadan kepercayaan](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Semak tangkapan dan rekod yang disimpan</strong> · apa yang disahkan oleh penerima dan Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Tangkap perbualan. Sahkan rekod. Simpan mesej, suntingan dan fail, semak tandatangan dan titik pemeriksaan, dan kaji proses tangkapan.">
</picture>

TgWitness merakam kandungan yang dihantar ke akaun Telegram yang disambungkan, berserta
pengecam sembang, mesej dan pengirim, versi yang ditangkap dan metadata pengumpulan.
Arkib menghimpunkan rekod tersebut, lampiran yang dipelihara dan data pengesahan
untuk disemak.

| Semakan | Apa yang disahkan oleh penerima |
| --- | --- |
| Jurnal dan manifes bertandatangan | Tandatangan rekod, rantaian hash dan fail yang diserahkan terhadap kunci tandatangan yang dijangka. |
| Titik pemeriksaan yang disimpan berasingan | Jurnal terhadap panjang dan hash rekod terbaru yang direkodkan sebelum ini. |
| Saksi bebas | Jurnal terhadap titik pemeriksaan yang disimpan oleh saksi yang berasingan. |
| Tangkapan GitHub Actions | Arkib terhadap atestasinya, aliran kerja dihoskan yang diluluskan dan versi pengumpul. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
memaparkan perbualan Telegram bersebelahan fail eksport Desktop yang sengaja diubah.
Bandingkan versi, periksa perubahan, dan ikuti langkah pengumpulan dan
pengesahan untuk arkib TgWitness bertandatangan.

[Langkah pengesahan](../wiki/Exports-and-Verification.md) ·
[Tangkapan GitHub](../SEALED-ACTIONS.md) ·
[Model kepercayaan teknikal](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Pastikan siasatan terus berjalan</strong> · pemberitahuan, storan dan pemulihan</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Aliran kerja beranimasi: Apprise menghantar amaran yang dikonfigurasi; salinan luar tapak disulitkan sebelum dimuat naik ke storan yang serasi dengan S3.">
</picture>

[Pemberitahuan](../OPERATIONS.md#notifications) · [Salinan luar tapak yang disulitkan](../wiki/Off-site-Copy.md) · [Sandaran dan pemulihan](../wiki/Backup-and-Recovery.md) · [Penyelesaian masalah](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ms/docs/start/"><b>Panduan persediaan&nbsp;↗</b></a><br><sub>Daripada pemasangan hingga sembang pertama</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ms/docs/dedicated-account/"><b>Sediakan akaun anda&nbsp;↗</b></a><br><sub>Akaun Telegram khusus</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker dan pelayan&nbsp;↗</b></a><br><sub>HTTPS, mula semula dan kemas kini</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Terokai repositori</strong> · lokasi kod, dokumen dan alat</summary>

| Direktori | Mula di sini |
| --- | --- |
| [docs/](../README.md) | Persediaan, aliran kerja siasatan dan rujukan teknikal |
| [tgwitness/](../../tgwitness/README.md) | Aplikasi utama, pengumpul, jurnal dan panel web |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Perakam bebas dan kod pengesahannya |
| [addons/](../../addons/README.md) | Pemasangan, konfigurasi dan ujian tangkapan pilihan |
| [deploy/](../../deploy/README.md) | Pemasang, bekas dan perkhidmatan latar belakang |
| [examples/](../../examples/README.md) | Konfigurasi eksport akaun dan tangkapan termeterai |
| [integrations/](../../integrations/README.md) | Webhook bertandatangan dan penerima n8n |
| [.agents/](../../.agents/README.md) | Arahan tugas untuk membaca arkib melalui CLI |
| [scripts/](../../scripts/README.md) | Pelancar dan utiliti CI |
| [tools/](../../tools/README.md) | Binaan, semakan dan pembungkusan |
| [website/](../../website/README.md) | Tapak awam, panduan terjemahan dan demo interaktif |
| [.github/](../../.github/AUTOMATION.md) | Aliran kerja, garis panduan sumbangan dan sokongan |

[Panduan projek lengkap](../PROJECT-GUIDE.md) ·
[Menyumbang](../../.github/CONTRIBUTING.md) · [Dapatkan bantuan](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Notis Etika &amp; Kesinambungan Sejarah</strong></summary>

Pendirian pengarang dan notis operator, dalam bahasa ini:

[Notis operator](OPERATOR-INCOMPATIBILITY.md) · [Lesen MIT](../../LICENSE) · [NOTICE asal](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Baca gambaran keseluruhan projek dalam bahasa anda</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · **Bahasa Melayu** · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Dokumentasi teknikal</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Buku panduan siasatan</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Dibina oleh PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Menyumbang</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Dapatkan bantuan</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Laporkan kelemahan</b></a>
</p>

[Indeks projek boleh dibaca mesin](../../llms.txt) · [Buku panduan teks lengkap](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Peraturan repositori untuk ejen](../../AGENTS.md)
