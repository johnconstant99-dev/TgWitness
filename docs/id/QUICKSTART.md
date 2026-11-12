[TgWitness](../../README.md) / [Dokumentasi](../README.md) / [Folder](README.md)

![Memulai](../assets/presentation/chapter-start.svg)

[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · [Español](../es/QUICKSTART.md) · [Português (Brasil)](../pt/QUICKSTART.md) · [Türkçe](../tr/QUICKSTART.md) · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · **Bahasa Indonesia** · [Tiếng Việt](../vi/QUICKSTART.md) · [简体中文](../zh/QUICKSTART.md)

# Mulai cepat dengan TgWitness

TgWitness adalah aplikasi mandiri untuk memantau grup dan saluran Telegram yang dapat diakses
oleh akun Anda. Aplikasi ini berjalan secara lokal dengan direktori datanya sendiri.

**Baru pertama kali?** [Jelajahi demo](#explore-the-interface) sebelum menghubungkan akun.
[Pilih panduan](../README.md) untuk proxy, saksi, ekspor, atau penyiapan server.
[Perekaman dengan GitHub Actions](../SEALED-ACTIONS.md) (pratinjau) menjalankan perekaman di fork
GitHub Anda sendiri, bukan di instalasi lokal.

<a name="install-and-start"></a>

## Instal dan jalankan

Penginstal terpandu menyertakan Python-nya sendiri serta memeriksa hash paket dan tanda tangan
rilis sebelum menginstal. Menjalankannya lagi akan memperbarui instalasi yang sudah ada.

**Linux / macOS:**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows (PowerShell atau Command Prompt):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

Di server Ubuntu, jalankan sebagai root untuk memasang layanan latar belakang; di desktop, jalankan
sebagai pengguna biasa. Di Ubuntu, penginstal menampilkan alamat panel dan kunci akses; di macOS dan
Windows, panel lokal terbuka di browser Anda. Lanjutkan ke **Hubungkan Telegram** di bawah.
[Instal, verifikasi, dan perbarui](../INSTALLATION.md) menjelaskan pilihan akses server, pemeriksaan
skrip sebelum dijalankan, pembaruan, dan penghapusan.

### Metode lain

Rilis GitHub, kode sumber, dan Docker adalah alternatif selain penginstal. Unduhan portabel
tersedia setelah build rilis diterbitkan:

| Host | Tanpa instalasi apa pun | Dari sumber: Python 3.11+ | Docker: Engine/Desktop dengan Compose 2.20+ |
| --- | --- | --- | --- |
| Windows | Ekstrak `TgWitness-<version>-windows-amd64-portable.zip` dari GitHub Releases, klik dua kali `TgWitness.cmd` | Klik dua kali `Start.cmd` | Klik dua kali `scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

Untuk metode dari sumber, [unduh dan ekstrak `main` terkini](https://github.com/phishdestroy/TgWitness/archive/refs/heads/main.zip)
atau kloning repositori:

```sh
git clone https://github.com/phishdestroy/TgWitness.git
cd TgWitness
```

`Start.cmd` menawarkan untuk menginstal Python 3.12 bagi pengguna Windows Anda jika tidak ditemukan
Python yang sesuai (melalui winget atau penginstal python.org yang bertanda tangan). `start.sh` menampilkan
perintah instalasi yang tepat untuk distribusi Linux Anda atau macOS jika Python tidak ada.
Peluncuran pertama dari sumber membuat `.venv` dan menginstal dependensi secara otomatis.

Docker membangun aplikasi dan menjalankannya di latar belakang; Python di host tidak diperlukan.
`scripts\Docker.cmd` dan `scripts/docker-start.sh` menampilkan alamat panel dan token setelah
kontainer berstatus sehat. Perintah Docker yang setara di setiap host yang didukung adalah:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

Buka **http://127.0.0.1:8787**. Gunakan token yang ditampilkan oleh helper Docker atau perintah Docker
kedua, atau baca **data/live/panel-token.txt** untuk instalasi portabel atau dari sumber. Lanjutkan ke
**Hubungkan Telegram** di bawah. Instalasi native dan Docker menggunakan penyimpanan terpisah;
menjalankan Docker tidak mengimpor jurnal native yang sudah ada.

Untuk server, panduan [penerapan](DEPLOYMENT.md) mencakup HTTPS otomatis, mulai ulang,
image yang diterbitkan, pembaruan, dan pencadangan.

<a name="explore-the-interface"></a>

## Jelajahi antarmuka

1. Jalankan **TgWitness-Demo.cmd** di paket portabel, **scripts\Demo.cmd** di folder sumber Windows,
   atau `sh start.sh --demo` di Linux/macOS. Peluncuran dari sumber terlebih dahulu membuat `.venv`
   dan menginstal dependensi.
2. Buka **http://127.0.0.1:8787**.
3. Demo lokal membuka jurnal contoh secara otomatis. Untuk akses lokal langsung, token tidak perlu disalin.

Pesan demo bersifat fiktif. Mode demo tidak dapat menghubungkan akun Telegram sungguhan.

## Hubungkan Telegram

> [!WARNING]
> **Gunakan akun khusus.** Apa pun kliennya, Telegram dapat membatasi atau memblokir akun secara
> permanen karena volume permintaan yang dianggapnya berlebihan. Hubungkan akun yang disiapkan untuk
> pemantauan, bukan akun pribadi atau berharga, dan buat API ID / hash di akun khusus.

1. Jika demo native sedang berjalan, hentikan lalu jalankan **Start.cmd** atau `sh start.sh`.
   Jika tidak, biarkan instalasi live yang dijalankan di atas tetap berjalan.
2. Masuk menggunakan token panel. Ruang kerja baru membuka [penyiapan awal](../SETTINGS.md).
   Pilih **Unduh saja**, **Pantau chat**, atau **Bukti dalam suatu perkara**.
3. Tinjau hasil pemeriksaan koneksi. Atur proxy Anda sendiri jika perlu; pengaturan koneksi
   tetap tersedia setelah penyiapan.
4. Pada **Connect Telegram**, pilih nomor telepon, kode QR, berkas akun (TData, `.session`,
   StringSession, JSON akun), atau kunci otorisasi lengkap. Lengkapi konfirmasi Telegram, kode,
   dan kata sandi dua langkah saat diminta.
5. Periksa akun yang ditampilkan, pilih obrolan, dan tinjau pengaturan Anda. Selesaikan dari layar
   terakhir. Untuk **Unduh saja**, **Mulai ekspor** memulai ekspor satu kali dan membuka bagian Ekspor
   untuk menampilkan progresnya; ini tidak mengaktifkan pemantauan berkelanjutan.

Setelah penyiapan, **Obrolan → Pilih** mengubah obrolan yang dipilih. **Pengaturan** mengatur
pengumpulan dan berkas; **Alat lainnya → Sumber** menyediakan daftar sumber terperinci
pada tingkat Standar atau Ahli. [Panduan panel](../PANEL.md) menjelaskan enam bagian utama
dan kontrol kontekstualnya.

**ID API + Hash** bersifat opsional: ruang kerja memakai pasangan yang tersimpan atau diimpor,
atau pasangan yang berfungsi dari kumpulan bawaan. Untuk memakai aplikasi Anda sendiri, tempelkan satu
pasangan `API ID:API Hash` ke kolom ID API. Untuk **Kunci otentikasi**, tempelkan seluruh 512 karakter
heksadesimal dan pilih ID DC yang diberikan. ID Pengguna bersifat opsional dan diperiksa jika diisi.

Kredensial API mengidentifikasi aplikasi Anda; kredensial itu sendiri tidak mengotorisasi akun.
Grup privat tidak memerlukan nama pengguna publik, tetapi akun Anda harus memiliki akses.

Untuk akun yang sudah ada, lihat [akun dan format sesi](../ACCOUNTS.md): panel menerima Telethon
StringSession, Telethon/Pyrogram SQLite, TData ZIP satu akun, dan JSON akun yang didukung. Pilih
sesi beserta JSON pendampingnya sekaligus, lalu tekan **Hubungkan akun**. Login QR juga tersedia
dengan pengaturan API opsional yang sama. TDLib, sesi bot, dan daftar akun CSV/JSON tidak didukung.

Untuk beberapa akun, gunakan **Akun → Impor akun** dan pilih berkas sesi yang didukung.
Berkas JSON pendamping dipasangkan berdasarkan nama dasar berkas; setiap akun yang diimpor
mendapat ruang kerjanya sendiri. Lihat [impor massal dan grup akun](../ACCOUNTS.md#bulk-import-and-account-groups).

Untuk menambahkan akun lain, tekan **+** di samping pemilih akun atau gunakan
**Akun → Tambahkan akun**. Setiap ruang kerja memiliki sesi, jurnal, kunci, sumber, dan antrean
sendiri. Berpindah tampilan tidak menghentikan pengumpul lainnya.
Akun Telegram yang sama tidak dapat ditetapkan ke dua ruang kerja dalam instalasi ini.
Jumlah ruang kerja tidak dibatasi secara tetap; semuanya berbagi satu proses, sehingga kapasitasnya
bergantung pada mesin.

Token panel live melindungi akses ke otorisasi Telegram dan materi tersimpan Anda; token ini
terpisah dari kredensial API Telegram. Hanya demo lokal yang dijalankan secara eksplisit dan diakses
langsung yang mendapat akses masuk otomatis. Demo jarak jauh atau melalui proxy tetap menggunakan
`data/demo/panel-token.txt`.

## Tinjau dan ekspor

- **Jurnal:** cari dan saring pengamatan berdasarkan sumber dan jenis peristiwa.
- Pilih peristiwa untuk memeriksa catatan aslinya, atribusi, dan versi yang tersimpan.
- Detail pengeditan menampilkan konten sebelum/sesudah yang tersedia. Detail penghapusan menampilkan
  konten terakhir yang terekam, jika ada; pelaku yang tidak diketahui tetap tidak diketahui.
- **Ekspor:** ZIP bertanda tangan, JSONL, CSV, dan HTML offline.
- **Ekspor obrolan lengkap** (**Obrolan → Ekspor obrolan**, atau **Ekspor → Rekam atau ekspor satu chat**):
  unduh seluruh riwayat yang terlihat dari satu obrolan sebagai bundel bertanda tangan dengan
  `chat.json` (bergaya ekspor Telegram) dan `chat.html` yang mudah dibaca. Obrolan privat juga bisa,
  asalkan akun tersebut menjadi anggotanya. Ini adalah snapshot kondisi saat ini, bukan rekonstruksi
  pesan yang telah dihapus atau diedit sebelumnya. Verifikasi salinan dengan
  `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256`.
- **Simpan titik pemeriksaan:** simpan batas jurnal bertanda tangan di luar pengumpul.
- **Unduh tanda terima eksekusi yang ditandatangani:** simpan catatan program/versi pengumpul.
- **Siapkan permintaan cap waktu:** siapkan permintaan offline untuk otoritas cap waktu;
  ikuti [TIMESTAMP.md](../TIMESTAMP.md) untuk memperoleh dan memverifikasi respons.
- **Verifikasi jurnal:** periksa tanda tangan peristiwa dan tautan rantai. Ekspor ZIP juga memeriksa media.

Browser yang didukung menyimpan ekspor besar langsung ke berkas yang dipilih. Browser lain
menampung paling banyak 128 MiB di buffer. Selama server berjalan, CLI streaming mendukung
unduhan yang lebih besar tanpa menampung seluruh respons di buffer:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

Untuk ruang kerja lain, tambahkan `--profile ID` yang diambil dari **Ekspor → ID Ruang Kerja**.
Untuk server jarak jauh, tambahkan `--url https://your-server`. Batas transfer bawaan adalah
5 GiB; `--max-mib` mengubahnya. Konten ZIP bertanda tangan secara bawaan memiliki batas verifikasi
terpisah sebesar 4 GiB tanpa kompresi (**Alat lainnya → Parameter** menaikkannya; verifikasi arsip
seperti itu dengan `verify.py --max-gib N`). Verifikasi arsip menggunakan salinan verifier tepercaya,
sidik jari kunci yang disimpan secara independen, dan—sebagai syarat minimum untuk bukti—sertifikat
root otoritas cap waktu (`--tsa-ca`).

## Periksa instalasi

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` memeriksa dependensi lokal, dukungan penandatanganan, penyimpanan, konfigurasi kunci, dan
alamat yang didengarkan. Perintah ini tidak menginstal apa pun dan tidak terhubung ke Telegram. Port
yang sibuk bisa berarti ada instance lain yang sedang berjalan. Gunakan `--port` lain atau hentikan
instance tersebut terlebih dahulu.

Peluncur menginstal ke `.venv`. Perintah tambahan `python -m tgwitness...` harus dijalankan dengan
`.venv\Scripts\python.exe` di Windows atau `.venv/bin/python` di Linux/macOS,
kecuali lingkungan tersebut sudah diaktifkan.

## Sesi, perlindungan, dan pengoperasian

Berkas Telethon SQLite `.session` yang sudah ditutup dan konsisten dapat dikonversi secara lokal dengan
`python -m tgwitness.sessions account.session --out account.tgwitness-session`, lalu
dimuat di **Alat lainnya → Akun → Berkas**. Impor berkas langsung dan login QR juga tersedia. Lihat
[CONNECTION-SECURITY.md](../CONNECTION-SECURITY.md) untuk format login, SOCKS5,
HTTP CONNECT, MTProxy, dan kunci master eksternal.

**Jeda pengamatan** menghentikan pengumpulan. **Kunci** hanya menutup akses browser.
Menutup tab tidak menghentikan proses pengumpul. Menghentikan proses akan menyela pengumpulan;
snapshot riwayat tidak dapat merekonstruksi semua pengeditan atau penghapusan yang terlewat.
Lihat [cara kerja pengumpulan](../COLLECTION.md) untuk kebijakan peristiwa, antrean lampiran,
isolasi akun, dan perilaku saat mulai ulang.

Sesi dan rahasia dienkripsi. Konten pesan, media, dan ekspor memerlukan disk atau volume
terenkripsi. Verifikasi tanda tangan jurnal terhadap kunci tepercaya dan simpan titik pemeriksaan secara terpisah.
Tinjau catatan perekaman, tanda terima waktu eksternal, dan atestasi lingkungan untuk
mode pengumpulan yang dipilih.

Baca [OPERATIONS.md](../OPERATIONS.md) untuk pencadangan/pemulihan, [DEPLOYMENT.md](DEPLOYMENT.md)
untuk hosting, dan [deploy/](../../deploy/README.md) untuk contoh layanan. Panel yang
terinstal juga menyertakan panduan penyiapan offline di `/guide.html`.

Verifikasi yang benar-benar dilakukan dan batasan yang tersisa dicatat dalam
[VERIFICATION.md](../VERIFICATION.md) dan [READINESS.md](../internal/READINESS.md).
