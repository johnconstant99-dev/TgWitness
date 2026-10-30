[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · [Español](../es/QUICKSTART.md) · [Português (Brasil)](../pt/QUICKSTART.md) · [Türkçe](../tr/QUICKSTART.md) · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · **Bahasa Indonesia** · [Tiếng Việt](../vi/QUICKSTART.md) · [简体中文](../zh/QUICKSTART.md)

# Panduan Memulai TgWitness

TgWitness adalah aplikasi mandiri untuk memantau grup dan saluran Telegram yang dapat diakses oleh akun Anda. Aplikasi ini berjalan secara lokal dengan direktori data tersendiri.

**Pertama kali berkunjung?** [Jelajahi demo](#jelajahi-antarmuka) sebelum menghubungkan akun. [Pilih panduan](../README.md) untuk proxy, saksi, ekspor, atau pengaturan server.

## Instal dan jalankan

Pilih salah satu metode. Unduhan portabel akan tersedia setelah rilis build diterbitkan:

| Host | Belum ada yang terinstal | Dari sumber: Python 3.11+ | Docker: Engine/Desktop dengan Compose 2.20+ |
| --- | --- | --- | --- |
| Windows | Ekstrak `TgWitness-<version>-windows-amd64-portable.zip` dari GitHub Releases, klik dua kali `TgWitness.cmd` | Klik dua kali `Start.cmd` | Klik dua kali `scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

Untuk kode sumbernya, unduh dan ekstrak berkas ZIP sumber dari GitHub Releases atau kloning repositori tersebut. `Start.cmd` menawarkan untuk menginstal Python 3.12 bagi pengguna Windows jika tidak ditemukan Python yang sesuai (winget, atau penginstal python.org yang telah ditandatangani). `start.sh` menampilkan perintah instalasi yang tepat untuk distribusi Linux atau macOS Anda jika Python tidak terpasang. Saat pertama kali dijalankan, kode sumber akan membuat berkas `.venv` dan menginstal dependensi secara otomatis.

Docker membangun aplikasi dan menjalankannya di latar belakang; Python di host tidak diperlukan. `scripts\Docker.cmd` dan `scripts/docker-start.sh` menampilkan alamat panel dan token saat kontainer dalam kondisi baik. Perintah Docker yang setara di setiap host yang didukung adalah:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

Buka **http://127.0.0.1:8787**. Gunakan token yang dihasilkan oleh Docker helper atau perintah Docker kedua, atau baca **berkas** **data/live/panel-token.txt** untuk instalasi portabel atau dari sumber kode. Lanjutkan ke bagian **"Hubungkan Telegram"** di bawah ini. Instalasi native dan Docker menggunakan penyimpanan terpisah; menjalankan Docker tidak akan mengimpor jurnal native yang sudah ada.

Untuk server, [penerapan](DEPLOYMENT.md) mencakup HTTPS otomatis, restart, gambar yang dipublikasikan, pembaruan, dan pencadangan.

## Jelajahi antarmuka

1. Jalankan **TgWitness-Demo.cmd** dalam paket portabel, **scripts\Demo.cmd** di folder sumber Windows, atau `sh start.sh --demo` di Linux/macOS. Peluncuran dari sumber akan terlebih dahulu membuat `.venv` dan menginstal dependensi.
2. Buka **http://127.0.0.1:8787**.
3. Demo lokal akan membuka jurnal contoh secara otomatis. Tidak diperlukan salinan token untuk akses lokal langsung.

Pesan demo bersifat fiktif. Mode demo tidak dapat terhubung ke akun Telegram yang sebenarnya.

## Hubungkan Telegram

> [!WARNING]
> **Jangan gunakan apa pun yang tidak dapat Anda tanggung kehilangannya.** Kami sangat menyarankan agar Anda tidak menghubungkan akun pribadi atau akun berharga, serta tidak membuat ID API / hash pada akun yang Anda hargai. Telegram memblokir akun secara tidak terduga dan seringkali secara permanen, terlepas dari klien yang digunakan. Kelancaran uji coba bergantung pada Telegram, bukan pada TgWitness, dan tidak menjamin apa pun untuk masa mendatang.

1. Jika demo bawaan sedang berjalan, hentikan dan jalankan **Start.cmd** atau `sh start.sh`. Jika tidak, biarkan instalasi langsung yang telah dijalankan di atas tetap berjalan.
2. Gunakan token panel sesuai metode instalasi Anda untuk membuka panel.
3. Jika Anda memerlukan proxy, simpan di bawah **Akun → Pengaturan → Pengaturan koneksi → Ubah rute koneksi**.
4. Di bagian **Akun**, masukkan nomor telepon Anda dan tekan **Lanjutkan**, pilih **kode QR → Tampilkan kode QR**, atau pilih file dan tekan **Hubungkan akun**. **API ID + Hash** bersifat opsional: ruang kerja akan menggunakan pasangan yang tersimpan atau diimpor, atau pasangan yang berfungsi dari kumpulan bawaan. Untuk menggunakan aplikasi Anda sendiri, tempelkan satu pasangan `API ID:API Hash` ke kolom ID API. Untuk kunci otorisasi lengkap, pilih **Kunci otorisasi**, tempelkan seluruh 512 karakter heksadesimal, dan pilih ID DC yang disediakan. ID Pengguna bersifat opsional dan akan dicentang jika dimasukkan.
5. Lengkapi metode masuk yang Anda pilih: nomor telepon/kode/2FA, konfirmasi dari aplikasi Telegram yang sudah masuk untuk QR, atau impor sesi otorisasi yang didukung.
6. Periksa ID akun yang ditampilkan. **Sumber** Terbuka: obrolan Anda dimuat secara otomatis; tambahkan grup Anda.
7. Di bawah **"Pilih perubahan yang akan dipertahankan**", pilih kategori peristiwa atau preset "**Pesan, pengeditan**, **& penghapusan**", lalu simpan pengaturan pemantauan.
8. Pilih pengaturan lampiran secara terpisah, lalu tekan **Mulai pemantauan**.

Kredensial API mengidentifikasi aplikasi Anda; kredensial tersebut tidak secara otomatis memberikan otorisasi atas akun. Grup pribadi tidak memerlukan nama pengguna publik, tetapi akun Anda harus memiliki akses.

Untuk akun yang sudah ada, lihat [format akun dan sesi](../ACCOUNTS.md): panel ini mendukung Telethon StringSession, Telethon/Pyrogram SQLite, TData ZIP untuk satu akun, dan JSON akun yang didukung. Pilih sesi beserta file JSON-nya secara bersamaan, lalu tekan **"Hubungkan Akun**". Masuk melalui QR juga tersedia dengan pengaturan API opsional yang sama. TDLib, bot, dan daftar akun massal tidak didukung.

Untuk menambahkan akun lain, tekan **tombol** **+** di sebelah pemilih akun atau buka **Akun → Pengaturan → Pengaturan koneksi → Ruang kerja**, atau gunakan **menu Akun**. Setiap ruang kerja memiliki sesi, jurnal, kunci, sumber, dan antrian yang terpisah. Mengganti tampilan tidak akan menghentikan pengumpul data lainnya. Akun Telegram yang sama tidak dapat ditugaskan ke dua ruang kerja dalam instalasi ini. Tidak ada batasan jumlah ruang kerja; semuanya berbagi satu proses, sehingga kapasitasnya bergantung pada mesin.

Token panel langsung melindungi akses ke otorisasi Telegram dan materi yang disimpan; token ini terpisah dari kredensial API Telegram. Hanya demo lokal yang dijalankan secara eksplisit dan diakses langsung yang mendapatkan akses otomatis. Demo jarak jauh/proksi tetap menggunakan `data/demo/panel-token.txt`.

## Tinjauan dan ekspor

- **Jurnal:** cari dan saring pengamatan berdasarkan sumber dan jenis peristiwa.
- Pilih sebuah peristiwa untuk memeriksa catatan aslinya, atribusi, dan versi yang disimpan.
- Rincian pengeditan menampilkan konten sebelum dan sesudah yang tersedia. Rincian penghapusan menampilkan konten terakhir yang terekam, jika ada; pelaku yang tidak dikenal tetap tidak diketahui.
- **Format ekspor:** ZIP yang ditandatangani, JSONL, CSV, dan HTML offline.
- **Ekspor obrolan lengkap** (Sumber → Ekspor obrolan lengkap): unduh seluruh riwayat obrolan yang terlihat sebagai bundel yang ditandatangani dengan `chat.json` (gaya ekspor Telegram) dan `chat.html` yang dapat dibaca. Obrolan pribadi berfungsi jika akun tersebut merupakan anggota. Ini adalah cuplikan terkini, bukan rekonstruksi dari pesan yang telah dihapus atau diedit sebelumnya. Verifikasi salinannya dengan `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256`.
- **Simpan titik pemeriksaan:** simpan batas jurnal yang telah ditandatangani di luar pengumpul.
- **Unduh tanda terima eksekusi yang ditandatangani:** simpan catatan program/versi pengumpul.
- **Siapkan permintaan cap waktu:** siapkan permintaan offline ke otoritas cap waktu; ikuti petunjuk di berkas [TIMESTAMP.md](../TIMESTAMP.md) untuk memperoleh dan memverifikasi respons.
- **Verifikasi jurnal:** periksa tanda tangan peristiwa dan tautan rantai. Ekspor ZIP juga memeriksa media.

Browser yang didukung dapat menyimpan ekspor berukuran besar langsung ke file yang dipilih. Browser lain hanya dapat menyimpan dalam buffer maksimal 128 MiB. Selama server berjalan, CLI streaming mendukung unduhan berukuran lebih besar tanpa perlu menyimpan seluruh respons dalam buffer:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

Untuk ruang kerja lain, tambahkan `--profile ID` menggunakan **Ekspor → ID Ruang Kerja**. Untuk server jarak jauh, tambahkan `--url https://your-server`. Batas transfer default adalah 5 GiB; `--max-mib` mengubahnya. Konten ZIP yang ditandatangani memiliki batas verifikasi terkompresi terpisah sebesar 4 GiB secara default (**Parameters** dapat menaikkannya; verifikasi arsip semacam itu dengan `verify.py --max-gib N`). Verifikasi arsip tersebut menggunakan salinan verifier yang tepercaya dan sidik jari kunci/titik pemeriksaan yang disimpan secara independen.

## Periksa proses instalasi

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` memeriksa dependensi lokal, dukungan penandatanganan, penyimpanan, konfigurasi kunci, dan alamat pendengar. Alat ini tidak menginstal apa pun atau terhubung ke Telegram. Port yang sibuk mungkin menandakan bahwa ada instance lain yang sedang berjalan. Gunakan `--port` yang berbeda atau hentikan instance tersebut terlebih dahulu.

Launcher diinstal ke `.venv`. Perintah tambahan `python -m tgwitness...` harus menggunakan `.venv\Scripts\python.exe` di Windows atau `.venv/bin/python` di Linux/macOS, kecuali jika lingkungan tersebut sudah diaktifkan.

## Sesi, perlindungan, dan pengoperasian

Sebuah basis data Telethon SQLite yang tertutup dan konsisten `.session` dapat dikonversi secara lokal menggunakan `python -m tgwitness.sessions account.session --out account.tgwitness-session`, kemudian dimuat ke dalam Account. Impor file langsung dan login melalui QR juga tersedia. Lihat [CONNECTION-SECURITY.md](../CONNECTION-SECURITY.md) untuk format login, SOCKS5, HTTP CONNECT, MTProxy, dan kunci utama eksternal.

**Menjeda pemantauan** akan menghentikan pengumpulan data. **Mengunci** hanya akan menutup akses browser. Menutup tab akan membiarkan proses pengumpul tetap berjalan. Menghentikan proses akan menghentikan pengumpulan data; cuplikan riwayat tidak dapat merekonstruksi semua pengeditan atau penghapusan yang terlewatkan. Lihat [cara kerja pengumpulan data](../COLLECTION.md) untuk kebijakan peristiwa, antrian lampiran, isolasi akun, dan perilaku saat dimulai ulang.

Sesi dan rahasia dienkripsi. Isi pesan, media, dan ekspor memerlukan disk atau volume yang dienkripsi. Tanda tangan memastikan integritas relatif terhadap kunci tepercaya; tanda tangan tersebut tidak memastikan asal Telegram atau mencegah pemalsuan oleh operator yang mengendalikan pengumpul dan kuncinya.

Baca [berkas OPERATIONS.md](../OPERATIONS.md) untuk pencadangan/pemulihan, [DEPLOYMENT.md](DEPLOYMENT.md) untuk hosting, dan [direktori deploy/](../../deploy/README.md) untuk contoh layanan. Panel yang telah diinstal juga menyertakan panduan pengaturan offline di `/guide.html`.

Verifikasi aktual dan batasan yang masih ada dicatat dalam [berkas VERIFICATION.md](../VERIFICATION.md) dan [READINESS.md](../internal/READINESS.md).
