<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Bahasa lain</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Telusuri jejaknya. Amankan buktinya. Jurnal bertanda tangan yang terhubung dengan hash, titik pemeriksaan yang disimpan terpisah, dan arsip bukti yang dapat diverifikasi.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=id"><b>Jelajahi demo&nbsp;↗</b></a><br><sub>Antarmuka asli dengan catatan fiktif</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Unduh dan mulai&nbsp;↓</b></a><br><sub>Satu perintah untuk Linux, macOS, dan Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Baca buku panduan&nbsp;↗</b></a><br><sub>Panduan investigasi langkah demi langkah</sub></td>
</tr>
</table>

<p align="center"><strong>Ruang kerja self-hosted untuk investigasi Telegram.</strong><br>Simpan chat, pertahankan suntingan dan penghapusan, lihat siapa terhubung dengan siapa,<br>dan serahkan ekspor bertanda tangan yang dapat diperiksa siapa pun.</p>

<p align="center"><strong>ZERO TRUST.</strong> TgWitness tidak memihak: pemeriksaan yang sama berlaku bagi operator, PhishDestroy, dan siapa pun.<br>Yang dihitung hanyalah apa yang dikonfirmasi pihak ketiga atau matematika. <a href="../QUESTIONS-AND-CHECKS.md">Pertanyaan dan pemeriksaan</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.3 · pra-rilis"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Lingkungan yang diuji</a> · 25 bahasa antarmuka · 26 bahasa panduan</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=id">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="Demo TgWitness saat berjalan: pesan yang direkam, versi yang tersimpan, dan konten yang tetap ada setelah dihapus. Catatan demonstrasi fiktif.">
</picture>
</a>

<p align="center"><sub>Jelajahi antarmuka sebenarnya dengan catatan fiktif. Klik ruang kerja untuk mencobanya.</sub></p>

## Apa yang dilakukan TgWitness

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Setiap suntingan dan penghapusan tersimpan</a></b><br><sub>Setiap versi pesan disimpan, dan teksnya tetap ada setelah pemberitahuan penghapusan.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Bukti yang dapat diperiksa siapa pun</a></b><br><sub>Catatan bertanda tangan yang dirantai dengan hash. Penerima memverifikasi arsip secara offline dengan satu perintah.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Asal-usul yang dapat ditunjukkan</a></b><br><sub>Diterima melalui sesi MTProto akun yang terautentikasi dan ditandatangani saat tiba; GitHub Actions dan Intel TDX menambahkan atestasi.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Terukur dalam skala besar</a></b><br><sub>48 arsip terverifikasi dengan 3.598.381 catatan; delapan akun mengambil 768.007 catatan riwayat dengan kecepatan 687,5 catatan/detik.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Dibuat untuk investigasi</a></b><br><sub>Daftar pantauan untuk teks, kode QR, dan OCR, pemeriksaan dompet, kartu subjek, Papan Kasus, dan paket untuk pengadilan.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Di bawah kendali Anda</a></b><br><sub>Self-hosted tanpa telemetri. Sesi tersimpan di brankas terenkripsi; panel mendengarkan di localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Dikembangkan dan diuji selama sekitar enam bulan: pertama-tama pengumpul, jurnal yang telah ditandatangani, dan verifikator, kemudian panel serta modul tambahan. Repositori ini dibuat pada 29 Oktober 2026 untuk dipublikasikan, sehingga usianya tidak sama dengan usia proyek.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Instalasi

Python sudah disertakan. Gunakan perintah yang sama untuk memperbarui.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell atau CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Server Ubuntu: jalankan sebagai root. Desktop: jalankan sebagai pengguna biasa Anda. `-ExecutionPolicy Bypass` hanya berlaku untuk satu proses PowerShell ini.</sub>

Build bertanda tangan berasal dari [alur kerja Installer](../../.github/workflows/installer.yml) publik, dan penginstal memeriksa SHA-256 serta tanda tangan RSA setiap paket sebelum menginstal.

[Verifikasi skrip terlebih dahulu](../INSTALLATION.md#verify-before-running) · [Penyiapan pertama](../SETTINGS.md) · [Rilis](https://github.com/phishdestroy/TgWitness/releases) · [Docker](DEPLOYMENT.md)

<details>
<summary><strong>Bagaimana penginstal dan data Anda dilindungi</strong></summary>

`get.destroy.tools` adalah situs unduhan proyek.
[Alur kerja Installer](../../.github/workflows/installer.yml) publik membangunnya dari
[`deploy/installer/`](../../deploy/installer/README.md) untuk revisi `main` yang persis,
menerbitkannya setelah uji instalasi Linux dan Windows lulus, lalu menandatangani
skrip penginstal dan paket aplikasi dengan kunci rilis di
[`release-signing.pub`](../../deploy/installer/release-signing.pub). Penginstal memeriksa
SHA-256 dan tanda tangan RSA paket serta berkas lock dependensi sebelum menginstal.
Untuk memeriksa skripnya sendiri terlebih dahulu, unduh skrip beserta tanda tangannya lalu jalankan
[perintah verifikasi-terlebih-dahulu](../INSTALLATION.md#verify-before-running). Jika build gagal,
unduhan sebelumnya tetap tersedia; panel yang sudah terinstal diperbarui saat Anda menjalankan ulang penginstal.
[Rilis](https://github.com/phishdestroy/TgWitness/releases) GitHub, kode sumber, dan
[Docker](DEPLOYMENT.md) adalah cara lain untuk menginstal.

**Sesi dan data Anda.** TgWitness berjalan di komputer atau server Anda, dan secara default panel
mendengarkan di localhost. Sesi Telegram, kredensial proxy, dan hash token akses
disimpan di brankas terenkripsi milik setiap ruang kerja, dengan
[kunci master eksternal](../SECURITY-MODEL.md#external-master-key) opsional. Aplikasi ini
tidak memiliki telemetri. Aplikasi terhubung ke Telegram dan ke layanan yang digunakan oleh pengaturannya:
daftar MTProxy publik, proxy Anda, penyimpanan S3, bot saksi, otoritas
cap waktu, penyedia AI, dan webhook. [Peta sistem](../SYSTEM-MAP.md) mencantumkan
koneksi yang dibuat oleh proses aplikasi.
Lakukan observasi dengan [akun Telegram khusus](https://phishdestroy.github.io/TgWitness/id/docs/dedicated-account/).

Lencana versi menggambarkan pohon sumber ini. Build yang dapat diinstal tercantum di
[Rilis](https://github.com/phishdestroy/TgWitness/releases); fitur yang digabungkan ke
`main` akan masuk ke unduhan tersebut pada rilis berikutnya.

[Penyiapan & akses panel](../INSTALLATION.md) ·
[Tanda tangan & SHA-256](https://get.destroy.tools/#verification) ·
[Pembaruan](../INSTALLATION.md#update-an-existing-installation) ·
[Kemampuan saat ini dan kualifikasi](../STATUS.md) ·
[Pilih metode pengumpulan](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Catatan yang dapat diperiksa orang lain

Periksa tanpa akun maupun instalasi. Sampel yang dipublikasikan membawa verifikatornya sendiri:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # verifikator disertakan di dalam arsip
python verify.py tgwitness-demo.zip          # Python 3.11+, hanya butuh `cryptography`
```

Perintah ini menampilkan catatan bertanda tangan, hash catatan terbaru, dan sidik jari penanda tangan, lalu keluar dengan kode `0`.
Sampel ini fiktif; verifikator yang sama berjalan pada ekspor nyata apa pun.

Ekspor berisi pesan, berkas, dan verifikator. Kirimkan sidik jari kunci Anda kepada penerima
melalui saluran lain, dan mereka dapat memeriksanya sendiri:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Verifikator memeriksa tanda tangan, rantai jurnal, daftar berkas, dan lampiran.
Untuk tingkat bukti, verifikator memerlukan sidik jari kunci Anda dan cap waktu pihak ketiga yang mencakup catatan
terakhir, misalnya cap waktu RFC 3161 yang diperiksa terhadap sertifikat root otoritasnya.

**Asal pesan.** TgWitness menerimanya dari Telegram melalui sesi MTProto terenkripsi
milik akun, seperti aplikasi resmi, dan menandatangani setiap pesan ke dalam
jurnal saat tiba. [Pengambilan melalui GitHub Actions](../SEALED-ACTIONS.md) dan
[Phala Intel TDX](../HIGH-ASSURANCE.md) juga memberikan atestasi atas pengumpul yang menerimanya.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Pesan baru, suntingan yang tersimpan, dan pengamatan penghapusan membentuk jurnal bertanda tangan yang saling terhubung. Verifikasi jurnal itu terhadap kunci yang dipercaya secara independen.">
</picture>

[Verifikasi arsip](../wiki/Exports-and-Verification.md) · [Format bukti](../EVIDENCE.md) · [Saksi independen](../WITNESS.md) · [Cap waktu eksternal](../TIMESTAMP.md) · [Pemeriksaan dan skala yang diuji](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Dari percakapan menjadi perkara

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Tiga alur kerja animasi: mengekspor chat ke HTML dan JSON, menemukan tautan yang dibagikan di seluruh chat yang direkam, dan mempertahankan versi yang direkam setelah pemberitahuan penghapusan.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Ekspor chat&nbsp;↗</b></a><br><sub>Satu chat menjadi HTML dan JSON bertanda tangan</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Investigasi&nbsp;↗</b></a><br><sub>Ikuti petunjuk di seluruh chat yang direkam</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Versi tersimpan&nbsp;↗</b></a><br><sub>Suntingan dan pemberitahuan penghapusan tetap tersimpan</sub></td>
</tr>
</table>

Dua cara menggunakannya: [ekspor akun Anda](../ACCOUNT-EXPORT.md) sekali, atau
[ikuti investigasi](../INVESTIGATION.md) dan terus simpan perubahannya.
Pilih beberapa chat, folder Telegram, atau seluruh akun. Setiap akun mendapat
ruang kerja, sesi, dan kunci penandatanganan sendiri.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Jelajahi lebih lanjut

<details>
<summary><strong>Ekspor terukur · 6 November 2026</strong> · 56.329 pesan, kedua arsip terverifikasi</summary>

**56.329 pesan diekspor dalam dua putaran baru.** Kedua arsip bertanda tangan lolos verifikasi dengan kunci pengumpul yang di-pin.

[![Kecepatan pengumpulan dan ekspor lengkap yang terukur](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/id/docs/validation/)

| Putaran | Pesan | Waktu pengumpulan | Kecepatan pengumpulan | Ekspor lengkap | Kecepatan ujung ke ujung |
| --- | ---: | ---: | ---: | ---: | ---: |
| Server A | 27,030 | 189.043 s | **142.983 pesan/s** | 211.647 s | 127.713 pesan/s |
| Server B | 29,299 | 182.513 s | **160.531 pesan/s** | 206.650 s | 141.781 pesan/s |

Teks dan metadata melalui WARP, dua akun per server, tanpa lampiran atau catatan yang digunakan ulang.
Diukur pada revisi [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Setiap putaran yang dipublikasikan mencantumkan revisi sumber, beban kerja, waktu, dan hasil verifikasinya:
[beban kerja, waktu, dan verifikasi](../EXPORT-BENCHMARK-2026-11-06.md). Perubahan pada `main`
menjalankan [alur kerja CI](../../.github/workflows/README.md) publik, termasuk uji penginstal Linux dan Windows
serta build verifikator mandiri.

[**Jelajahi demo →**](https://phishdestroy.github.io/TgWitness/demo/?lang=id) ·
[**Pengukuran, tanggal, dan metode →**](https://phishdestroy.github.io/TgWitness/id/docs/validation/) ·
[Unduh contoh ekspor fiktif](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Audit berbahasa Inggris bertanda tangan](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Mulai dengan sederhana. Lihat setiap rute.</strong> · peluncuran pertama dan peta sistem</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="Peluncuran pertama menawarkan “Unduh saja”, “Pantau chat”, atau “Bukti dalam suatu perkara” dan hanya menampilkan bagian yang sesuai. Peta sistem menghubungkan panel, pengumpul, Telegram, jurnal, saksi, dan layanan luar, lengkap dengan pengamatan jaringan. Nilai fiktif.">
</picture>

Peluncuran pertama hanya mengajukan satu pertanyaan: **Unduh saja**, **Pantau chat**, atau
**Bukti dalam suatu perkara**. Jawabannya menentukan tujuan dan tingkat antarmuka, sehingga
panel hanya menampilkan bagian yang dibutuhkan tugas itu. Koneksi, masuk ke Telegram, dan
pemilihan chat menyusul dalam lima tahap. Pemeriksaan koneksi berjalan sendiri, dan
opsi rute hanya terbuka jika pemeriksaan itu gagal. Alat ahli hanya berjarak satu sakelar.

**Peta sistem** menunjukkan bagaimana instalasi menjangkau Telegram dan layanan
luar: akses panel, rute dan tujuan Telegram tiap akun, jalur jurnal dan
saksi, serta pengamatan jaringan terbaru. Pengamatan yang tidak ada
diberi label tidak ada.

[Penyiapan pertama](../SETTINGS.md) · [Peta sistem](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Dibuat untuk sisa investigasi</strong> · kartu subjek, daftar pantauan, dompet, pemantauan online, dokumen pengadilan</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Lacak nama dan username berdasarkan ID Telegram. Rekam interaksi bot yang didukung dengan tanda terima bertanda tangan. Cari pesan yang diarsipkan dan hubungkan klien MCP baca-saja. Terapkan pengumpul dengan SSH tersamarkan dan catatan penyedia untuk ditinjau. Dokumentasikan percakapan langkah demi langkah dengan referensi jurnal. Serahkan paket perkara BagIt dengan templat pengadilan. Alur kerja ilustratif.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Orang dan dosir&nbsp;↗</b></a><br><sub>Nama dan username dilacak berdasarkan ID Telegram</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Investigasi bot&nbsp;↗</b></a><br><sub>Interaksi bot dengan tanda terima bertanda tangan</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/id/docs/archive/"><b>Pencarian arsip, AI, dan MCP&nbsp;↗</b></a><br><sub>Cari di arsip, hubungkan klien baca-saja</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Penerapan cloud tersegel&nbsp;↗</b></a><br><sub>Pengumpul di dalam Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Tiga langkah animasi: kartu subjek yang snapshot berikutnya mencatat perubahan nama, rencana percakapan yang tujuannya ditutup dengan catatan jurnal, dan kode QR pembayaran yang didekode menjadi dompet dengan checksum valid sehingga memicu kecocokan daftar pantauan. Nilai fiktif.">
</picture>

**Dokumentasikan percakapan.** Mulai catatan untuk sebuah chat di panel samping **Dokumentasi**
dan setiap langkah tercatat dengan sendirinya: tindakan panel, balasan beserta jeda sebelum
balasan itu, suntingan, pemberitahuan penghapusan, anotasi, dan draf AI. Setiap langkah merujuk catatan
jurnal dan SHA-256-nya. Memfinalisasi dokumen akan menandatanganinya dan menulis hash pernyataan ke
jurnal.

| | |
| --- | --- |
| [Kartu subjek](../INVESTIGATION-MODE.md#subject-cards) | Snapshot profil bot, orang, kanal, atau grup dengan label BOT, VERIFIED, SCAM, dan FAKE dari Telegram; snapshot berikutnya mencantumkan apa yang berubah |
| [Rencana percakapan](../INVESTIGATION-MODE.md#conversation-plans) | Tujuan terkait jalur pembayaran, infrastruktur, atau orang, pesan yang telah disiapkan, waktu balasan, aktivitas per jam, dan gaya menulis pihak lawan |
| [Terjemahan](../INVESTIGATION-MODE.md#machine-translation) | Ditampilkan di bawah teks asli beserta bahasa, model, dan catatan jurnal |
| [Daftar pantauan](../INVESTIGATION-MODE.md#watchlists) | Kata, pola, dompet, @username, ID, domain, nomor telepon, dan tautan, dicocokkan dalam teks, suntingan, tujuan tautan tersembunyi, tombol bot, kode QR, dan OCR |
| [Pemantauan online](../INVESTIGATION-MODE.md#online-watch) | Pemeriksaan setiap 1–60 menit, hingga 100 akun per permintaan, dengan pola per jam dan hari dalam seminggu |
| [Kode dan dompet](../INVESTIGATION-MODE.md#codes-in-images) | Kode QR pembayaran; alamat EVM yang diperiksa terhadap EIP-55, TON dalam bentuk raw, checksum XRP Ledger, tautan pembayaran dengan chain, jumlah, dan token |
| [Jejak klien](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-show) | Jejak encoder pada video bulat dan pesan suara; membandingkan waktu unggah dengan waktu kirim mengungkap bukti “langsung” yang sebenarnya direkam sebelumnya |
| [Penyamaran dan kewenangan](../INVESTIGATION-MODE.md#cover-and-authority) | Persona, otorisasi, dan catatan aktivitas penyamaran yang menandai pesan di luar chat atau periode yang diotorisasi |
| [Kontrol akun](../INVESTIGATION-MODE.md#account-control) | Penyuntingan profil dan privasi dengan catatan sebelum/sesudah, pemeriksaan keterpaparan, dan status offline segera setelah setiap tindakan |
| [Dokumen untuk pengadilan](../INVESTIGATION-MODE.md#documents-for-court) | Paket perkara BagIt dengan templat sertifikasi Rule 902(13)/(14), indeks barang bukti, lampiran permintaan, dan teks WebVTT/SRT untuk rekaman layar |

Konten yang ditandai 18+, kekerasan, atau data pribadi tetap ada di salinan pengadilan, disegel dengan
AES-256-GCM; kuncinya dikirim terpisah.

[Pengaturan ekspor](../EXPORT_HASHES.md) mencakup pengambilan melalui API biasa dan Takeout,
riwayat pesan sebelum lampiran, unduhan berkas atau hash server, serta tampilan
JSON/HTML yang kompatibel dengan Telegram Desktop. [Ekspor chat terdistribusi](../DISTRIBUTED-EXPORT.md#history-acquisition)
menawarkan jalur Takeout opsional untuk riwayat publik, titik pemeriksaan bertanda tangan setiap 100 pesan,
serta pemulihan dalam suatu rentang menggunakan akun yang sama;
[desain kinerjanya](../FAST-ACQUISITION.md) mencantumkan perilaku pengambilan yang telah diuji
dan pengukuran langsung yang direncanakan.

</details>

<details>
<summary><strong>Semua yang lain</strong> · riwayat, akun, proxy, AI, integrasi</summary>

| | |
| --- | --- |
| [Muat pesan lama](../HISTORY.md) | Tarik riwayat lampau dari chat terpilih, jeda dan lanjutkan kapan saja |
| [Beberapa akun](../ACCOUNTS.md#multiple-accounts) | Ruang kerja terpisah, masing-masing dengan sesi Telegram, jurnal, dan kunci penandatanganan sendiri |
| [Impor massal](../ACCOUNTS.md#bulk-import-and-account-groups) | Masukkan banyak berkas sesi sekaligus, kelompokkan akun dengan pengaturan bersama |
| [Pool MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, negara, filter, daftar Anda sendiri |
| [Sesi yang ada](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key, atau baris `key:DC`; otorisasi QR independen opsional dari donor yang diimpor |
| [Keamanan akun](../ACCOUNTS.md#create-an-independent-authorization) | Peringatan sesi baru, mengakhiri sesi lain, mode sesi tunggal yang juga memasang kata sandi dua langkah, dan [probe saksi](../ACCOUNTS.md#witness-probe) yang mendeteksi saat pembaruan langsung berhenti sampai ke sesi ini |
| [Ekspor chat yang dapat dilanjutkan](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Ekspor yang berhenti menyimpan salinan parsial bertanda tangan: lanjutkan, mulai ulang, atau unduh yang sudah tersimpan |
| [Proxy](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT, atau MTProxy per ruang kerja. **Sembunyikan IP** tidak pernah beralih ke koneksi langsung |
| [Pencarian dan AI](../ANALYSIS.md) | Pencarian lokal, AI opsional dengan sumber yang dapat Anda periksa |
| [Pencarian teks lengkap](../SEARCH.md) | Bentuk kata, frasa persis, domain, @username, dan bahasa Tionghoa tanpa spasi, hasil paling cocok lebih dulu (**Pratinjau**) |
| [MCP](../MCP.md) | Akses baca-saja untuk klien MCP, terbatas pada chat yang Anda pilih |
| [Baris perintah](../CLI.md) | `search`, `context`, `messages`, `stats`, dan `export` JSON Lines dengan `--json` untuk skrip dan agen, secara lokal atau dengan token berlingkup terbatas (**Pratinjau**) |
| [OCR dan transkripsi](../MEDIA-ANALYSIS.md) | Berjalan secara lokal, berkas asli tidak diubah |
| [Pengambilan independen](../OPTIONAL-CAPTURE.md) | Perekam browser/AyuGram opsional di **Alat lainnya → Tambahan** (pratinjau, nonaktif secara default) |
| [Trusted Live](../TRUSTED-LIVE.md) | Sesi Desktop/Web resmi, video terlindungi, dan analisis kesinambungan dengan ekspor bawaan (pratinjau; kualifikasi langsung masih tertunda) |
| [Web resmi tersegel](../OFFICIAL-WITNESS.md) | Browser resmi baru di GitHub Actions, kontrol terbatas, video bertanda tangan, serta sumber/pengaturan yang diharapkan secara independen |
| [Webhook](../WEBHOOKS.md) | Event keluar bertanda tangan dengan percobaan ulang, termasuk contoh n8n |
| [Akses bersama](../ACCESS.md) | Berikan seseorang akses hanya ke chat terpilih, dengan masa berlaku dan batasan IP |
| [Nomor pesan yang hilang](../EVIDENCE.md#missing-message-numbers-gap_summary) | Nomor yang diberikan Telegram tetapi tidak pernah teramati, per kanal dan untuk seluruh akun, di cakupan, laporan, dan MCP (**Pratinjau**) |
| [Snapshot status chat](../COLLECTION.md) | Snapshot bertanda tangan berkala atas judul, deskripsi, pin, administrator, dan hadiah, beserta apa yang berubah (**Pratinjau**) |
| [Peta sistem](../SYSTEM-MAP.md) | Peta langsung akses panel, rute akun, tujuan Telegram, dan layanan luar, dengan 200 terbaru dari maksimal 2.000 pengamatan jaringan |

</details>

<details>
<summary><strong>Pilih apa yang menopang catatan</strong> · lokal, cloud teraudit, GitHub Actions, atau Intel TDX</summary>

Jalankan secara lokal, tambahkan penerapan cloud teraudit, atau kumpulkan di dalam **VM konfidensial
Phala Cloud dengan Intel TDX**. Setiap opsi mempertahankan jurnal bertanda tangan; pemeriksaan
tambahan menyasar lingkungan tempat jurnal itu dikumpulkan.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Tiga pilihan penerapan: verifikasi jurnal lokal; VM teraudit dengan catatan penyedia dan akses; Phala Intel TDX dengan quote terverifikasi, OS dan aplikasi terukur, serta kunci pengumpul yang terikat.">
</picture>

Verifikator TDX memeriksa quote terhadap root dan data pencabutan Intel yang di-pin,
mengikatnya ke pernyataan pengumpul yang ditandatangani dan tantangan baru, lalu membandingkan
OS dan aplikasi yang terukur dengan input yang diharapkan secara independen. Laporan mencantumkan
setiap hasil secara terpisah, sehingga lingkungan terukur, identitas pengumpul, catatan
pengambilan, dan cakupan dapat ditinjau bersama.

**Pengambilan dengan provenans GitHub** (pratinjau). Kumpulkan chat di runner yang di-host GitHub
dengan TgWitness yang di-pin dan sesi Telegram baru, lalu unduh arsip terenkripsi
beserta atestasi GitHub-nya. Verifikator memeriksa alur kerja yang disetujui dan
versi pengumpul, digest arsip, jurnal, dan lampiran. Juga tersedia
di bawah **Ekspor** pada panel.
[Buka halaman pengambilan](https://phishdestroy.github.io/TgWitness/id/docs/capture/) · [Petunjuk](../SEALED-ACTIONS.md)

Untuk observasi langsung, riwayat, atau ekspor sekali jalan, pilih
[metode pengumpulan](../COLLECTION-MODES.md). Chat cloud pribadi tersedia
jika akun yang terhubung dapat mengaksesnya. Aplikasi yang dipublikasikan juga menyertakan
[integrasi Chat Rahasia](../PSEUDO-SECRET.md): pasang dependensi protokol opsional
dan aktifkan per akun untuk merekam chat yang dibuat atau diterima di sana.
Lihat [cakupan pengumpulan](../COLLECTION.md) untuk jalur pengambilan yang tersedia.

[Phala / Intel TDX dan penerapan teraudit](../HIGH-ASSURANCE.md) ·
[Kualifikasi langsung Phala](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Batas kepercayaan](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Periksa pengambilan dan catatan yang tersimpan</strong> · apa yang diverifikasi penerima dan Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Rekam percakapannya. Verifikasi catatannya. Simpan pesan, suntingan, dan berkas, periksa tanda tangan dan titik pemeriksaan, serta tinjau proses pengambilan.">
</picture>

TgWitness merekam konten yang dikirim ke akun Telegram yang terhubung, beserta
pengenal chat, pesan, dan pengirim, versi yang direkam, serta metadata pengumpulan.
Arsip menyatukan catatan tersebut, lampiran yang disimpan, dan data verifikasi
untuk ditinjau.

| Pemeriksaan | Yang diverifikasi penerima |
| --- | --- |
| Jurnal dan manifes bertanda tangan | Tanda tangan catatan, rantai hash, dan berkas yang diserahkan terhadap kunci penandatanganan yang diharapkan. |
| Titik pemeriksaan yang disimpan terpisah | Jurnal terhadap panjang dan hash catatan terbaru yang dicatat sebelumnya. |
| Saksi independen | Jurnal terhadap titik pemeriksaan yang disimpan oleh saksi terpisah. |
| Pengambilan melalui GitHub Actions | Arsip terhadap atestasinya, alur kerja ter-host yang disetujui, dan versi pengumpul. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
menampilkan percakapan Telegram berdampingan dengan berkas ekspor Desktop yang sengaja diubah.
Bandingkan versinya, periksa perubahannya, dan ikuti langkah pengumpulan dan
verifikasi untuk arsip TgWitness bertanda tangan.

[Langkah verifikasi](../wiki/Exports-and-Verification.md) ·
[Pengambilan GitHub](../SEALED-ACTIONS.md) ·
[Model kepercayaan teknis](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Jaga investigasi tetap berjalan</strong> · notifikasi, penyimpanan, dan pemulihan</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Alur kerja animasi: Apprise mengirim peringatan yang dikonfigurasi; salinan off-site dienkripsi sebelum diunggah ke penyimpanan yang kompatibel dengan S3.">
</picture>

[Notifikasi](../OPERATIONS.md#notifications) · [Salinan off-site terenkripsi](../wiki/Off-site-Copy.md) · [Cadangan dan pemulihan](../wiki/Backup-and-Recovery.md) · [Pemecahan masalah](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/id/docs/start/"><b>Panduan penyiapan&nbsp;↗</b></a><br><sub>Dari instalasi hingga chat pertama</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/id/docs/dedicated-account/"><b>Siapkan akun Anda&nbsp;↗</b></a><br><sub>Akun Telegram khusus</sub></td>
<td width="33%" align="center"><a href="DEPLOYMENT.md"><b>Docker dan server&nbsp;↗</b></a><br><sub>HTTPS, restart, dan pembaruan</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Jelajahi repositori</strong> · letak kode, dokumen, dan alat</summary>

| Direktori | Mulai di sini |
| --- | --- |
| [docs/](../README.md) | Penyiapan, alur kerja investigasi, dan referensi teknis |
| [tgwitness/](../../tgwitness/README.md) | Aplikasi utama, pengumpul, jurnal, dan panel web |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Perekam independen dan kode verifikasinya |
| [addons/](../../addons/README.md) | Instalasi, konfigurasi, dan pengujian pengambilan opsional |
| [deploy/](../../deploy/README.md) | Penginstal, kontainer, dan layanan latar belakang |
| [examples/](../../examples/README.md) | Konfigurasi ekspor akun dan pengambilan tersegel |
| [integrations/](../../integrations/README.md) | Webhook bertanda tangan dan penerima n8n |
| [.agents/](../../.agents/README.md) | Instruksi tugas untuk membaca arsip melalui CLI |
| [scripts/](../../scripts/README.md) | Peluncur dan utilitas CI |
| [tools/](../../tools/README.md) | Build, pemeriksaan, dan pengemasan |
| [website/](../../website/README.md) | Situs publik, panduan terjemahan, dan demo interaktif |
| [.github/](../../.github/AUTOMATION.md) | Alur kerja, pedoman kontribusi, dan dukungan |

[Panduan proyek lengkap](../PROJECT-GUIDE.md) ·
[Berkontribusi](../../.github/CONTRIBUTING.md) · [Dapatkan bantuan](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Pemberitahuan Etis &amp; Kesinambungan Historis</strong></summary>

Posisi para penulis dan pemberitahuan untuk operator, dalam bahasa ini:

[Pemberitahuan operator](OPERATOR-INCOMPATIBILITY.md) · [Lisensi MIT](../../LICENSE) · [NOTICE asli](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Baca ikhtisar proyek dalam bahasa Anda</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · **Bahasa Indonesia** · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Dokumentasi teknis</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Buku panduan investigasi</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Dibuat oleh PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Berkontribusi</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Dapatkan bantuan</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Laporkan kerentanan</b></a>
</p>

[Indeks proyek yang dapat dibaca mesin](../../llms.txt) · [Buku panduan teks lengkap](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Aturan repositori untuk agen](../../AGENTS.md)
