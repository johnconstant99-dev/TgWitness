[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · [Español](../es/DEPLOYMENT.md) · [Português (Brasil)](../pt/DEPLOYMENT.md) · [Türkçe](../tr/DEPLOYMENT.md) · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · **Bahasa Indonesia** · [Tiếng Việt](../vi/DEPLOYMENT.md) · [简体中文](../zh/DEPLOYMENT.md)

# Penerapan dan pengoperasian

## Pilih metode instalasi

Untuk paket portabel, ekstrak `TgWitness-<version>-windows-amd64-portable.zip` dari GitHub Releases. Untuk metode lainnya, unduh dan ekstrak berkas ZIP sumber atau kloning repositori, lalu jalankan perintah berikut dari direktori proyek:

| Instalasi | Mulai | Berjalan di latar belakang? |
| --- | --- | --- |
| Paket portabel untuk Windows | `TgWitness.cmd` | Tidak; biarkan jendela tetap terbuka. |
| Versi asli Windows | `Start.cmd` | Tidak; gunakan tugas login opsional untuk penggunaan di latar belakang. |
| Versi asli untuk Linux/macOS | `sh start.sh` | Tidak; gunakan systemd/launchd untuk penggunaan di latar belakang. |
| Docker di host apa pun yang didukung | `docker compose up -d --build --wait` | Ya, selama daemon Docker sedang berjalan. |
| Alat bantu Docker di Windows | `scripts\Docker.cmd` | Ya; program bantu tersebut menunggu status kesehatan server web. |
| Alat bantu Docker di Linux/macOS | `sh scripts/docker-start.sh` | Ya; program bantu tersebut menunggu status kesehatan server web. |

Proses startup asli membuat `.venv` pribadi dan menginstal dependensi yang disematkan. Docker membangunnya di dalam gambar, tanpa memerlukan Python host. Pengaturan pertama kali memerlukan akses internet. Jika Python 3.11+ tidak ditemukan, `Start.cmd` akan meminta konfirmasi sebelum menginstal Python 3.12 untuk pengguna Windows saat ini (menggunakan winget, atau penginstal python.org setelah memverifikasi tanda tangan Python Software Foundation); proses ini tidak pernah meminta hak akses administrator. Docker dan layanan sistem operasi tetap menjadi prasyarat.

Instalasi native dan portabel menggunakan `data/live` di dalam foldernya. Docker menggunakan volume bernama `tgwitness-data` di `/data`. Ini adalah instalasi terpisah hingga Anda secara sengaja memigrasikan direktori data secara keseluruhan. Jangan berharap kontainer Docker baru akan mendeteksi akun native secara otomatis.

## Persyaratan instalasi

Instalasi native memerlukan Python 3.11 atau versi yang lebih baru dengan `venv` dan `ensurepip`, akses internet untuk instalasi dependensi pertama, serta direktori proyek yang dapat ditulis untuk `.venv`. Panel yang disertakan tidak memerlukan Node.js atau build frontend. Jalankan peluncur dari akun OS biasa Anda; TgWitness tidak memerlukan hak akses administrator/root.

- **Windows:** `Start.cmd` memeriksa `py -3`, lalu `python`, kemudian folder instalasi default per-pengguna dan Program Files, serta memerlukan versi 3.11 atau yang lebih baru. Jika tidak ada yang berhasil, aplikasi ini menawarkan instalasi otomatis per-pengguna seperti yang dijelaskan di atas. `py -3 start.py` juga berfungsi. Paket portabel sama sekali tidak memerlukan Python.
- **Linux:** `start.sh` mencoba `python3.13`, `python3.12`, `python3.11`, `python3`, dan `python`, serta menampilkan perintah instalasi untuk apt, dnf, pacman, zypper, apk, atau Homebrew jika tidak ada yang memenuhi syarat. Instalasi Debian/Ubuntu mungkin memerlukan paket `python3-venv` yang sesuai dengan interpreter yang dipilih. Python default versi lama pada suatu distribusi harus diganti atau dilengkapi dengan Python 3.11+.
- **macOS:** instal distribusi Python 3.11+ terbaru; jangan berasumsi bahwa interpreter yang disediakan sistem operasi sudah memenuhi persyaratan. Gunakan `python3 start.py` dari direktori proyek.
- **Docker:** gunakan Docker Engine/Desktop dengan Compose v2.20 atau yang lebih baru. Docker Desktop harus menggunakan kontainer Linux di Windows. Kontainer tersebut menginstal dependensi Python-nya sendiri; host tidak memerlukan instalasi Python terpisah.

Gunakan penyimpanan lokal yang persisten untuk direktori data. Rencanakan kapasitas berdasarkan pesan, media, pertumbuhan WAL, ekspor, dan cadangan; tidak ada spesifikasi minimum disk/RAM universal yang didasarkan pada bukti untuk setiap beban kerja. Arsitektur CPU dan versi Python yang tidak memiliki roda dependensi yang kompatibel mungkin memerlukan alat pembangunan tambahan dan kualifikasi tersendiri. "Portable" bukanlah klaim dukungan universal terhadap sistem operasi atau perangkat keras.

Windows 11/Python 3.12 telah diverifikasi secara lokal. Definisi untuk Linux/macOS/kontainer serta CI telah disediakan, namun belum dijalankan di host pengembangan ini. Lihat [berkas VERIFICATION.md](../VERIFICATION.md) untuk cakupan yang tepat.

## Komputer lokal

Gunakan `Start.cmd` di Windows atau `sh start.sh` di Linux/macOS. `scripts\Setup.cmd` atau `sh start.sh --setup-only` mempersiapkan lingkungan. Peluncur akan menginstal dependensi saat pertama kali digunakan; peluncuran berikutnya akan menggunakan kembali lingkungan tersebut. Akses internet diperlukan untuk pengaturan dan pengumpulan data Telegram, tetapi penelusuran catatan yang ada serta pembuatan ekspor dapat dilakukan secara offline.

Jalankan `python start.py --check` setelah penyiapan untuk memeriksa dependensi lokal, Ed25519, penyimpanan, konfigurasi kunci, dan alamat pendengar tanpa memulai pengumpul. Gunakan `--json` untuk keluaran terstruktur. Masukkan `--data-dir`, `--host`, dan `--port` yang dimaksud. Pemeriksaan ini tidak menginstal paket, membuat jurnal, atau menghubungkan Telegram; ini bukan kualifikasi integritas atau cakupan. Proses startup memverifikasi jurnal yang sudah ada secara terpisah. `python start.py --help` juga menghindari proses instalasi.

Opsi:

Setelah menjalankan start.py, jalankan perintah tambahan dengan `.venv\Scripts\python.exe` di Windows atau `.venv/bin/python` di Linux/macOS, atau aktifkan lingkungan tersebut terlebih dahulu. Contoh-contoh `python -m ...` di bawah ini mengasumsikan bahwa lingkungan tersebut sudah aktif.

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

Variabel lingkungan: TGWITNESS_DATA, TGWITNESS_HOST, TGWITNESS_PORT, TGWITNESS_TOKEN. TGWITNESS_VAULT_KEY_FILE memilih mode kunci eksternal untuk instalasi baru; lihat di bawah. TGWITNESS_TOKEN, jika disediakan, harus berisi setidaknya 24 karakter; gunakan nilai acak kriptografis. Tanpa itu, aplikasi akan menghasilkan token acak 256-bit di panel-token.txt. Penggantian variabel lingkungan tidak akan menimpa berkas tersebut. Mulai ulang untuk merotasi kredensial.

Hanya satu proses yang boleh memiliki direktori data. Kunci file lintas platform OS mencegah terjadinya penulisan bersamaan yang tidak disengaja. Gunakan satu pekerja Uvicorn. Panel ini dapat mengelola sejumlah ruang kerja, dengan direktori ruang kerja tambahan di bawah `profiles/<id>/`. Untuk instance layanan terpisah, gunakan direktori dan port yang berbeda. Berkas WAL SQLite harus disimpan di penyimpanan lokal yang persisten, bukan di sistem berkas jaringan. Jangan berbagi satu volume antar replika.

## Paket portabel untuk Windows

Setiap Rilis GitHub berisi `TgWitness-<version>-windows-amd64-portable.zip` dan `.sha256`. Rilis tersebut berisi runtime Python 3.12 resmi yang dapat disematkan dari python.org (checksum terpasang di `tools/build_portable.py`), TgWitness beserta dependensinya yang terpasang, serta tiga peluncur:

| Berkas | Tujuan |
| --- | --- |
| `TgWitness.cmd` | Jalankan panel; opsi tambahan diteruskan, misalnya `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | Jalankan demo sintetis di `data\demo` |
| `TgWitness-Check.cmd` | Jalankan pemeriksaan kesiapan tanpa memulai |

Ekstrak seluruh arsip ke folder yang dapat ditulis seperti `Documents\TgWitness`; jangan menjalankannya dari dalam ZIP atau dari Program Files. Runtime menggunakan jalur modul yang terisolasi, sehingga instalasi Python lain dan `PYTHONPATH` tidak memengaruhinya. Data tetap berada di folder `data` dalam paket tersebut. Untuk memperbarui, hentikan TgWitness, ekstrak versi baru ke folder baru, lalu salin folder `data` ke sana.

Buat sendiri di Windows 64-bit dengan Python 3.12:

~~~sh
python tools/build_portable.py
~~~

Pembangun memverifikasi checksum runtime, menginstal dependensi yang dibatasi ke dalam paket, menjalankan pemeriksaan kesiapan dengan interpreter tertanam, dan menulis berkas ZIP serta checksum ke `dist/`.

## Kontainer

```sh
docker compose up -d --build --wait
```

Ini akan membuat volume persisten bernama untuk /data. Port web dipetakan ke 127.0.0.1:8787. Proses ini berjalan sebagai UID 10001 dengan kemampuan yang dibatasi, sistem berkas root yang hanya dapat dibaca, serta /data dan /tmp yang dapat ditulis. `--wait` memeriksa kesehatan server web sebelum mengembalikan hasil; proses ini tidak melakukan otorisasi atau pengiriman Telegram. Pembantu yang disediakan menggunakan batas waktu kesiapan 180 detik setelah proses pembangunan. Pengunduhan dependensi awal mungkin memakan waktu lebih lama dari itu.

Kedua berkas Compose dasar menggunakan nama proyek `tgwitness`, sehingga mengekstrak rilis baru ke direktori lain tidak secara otomatis memilih volume data baru. Jaga agar hanya ada satu penerapan yang aktif untuk proyek tersebut. Untuk instalasi independen, gunakan `docker compose -p NAME ...` yang unik dan port host yang berbeda, serta pertahankan keduanya saat pembaruan. Untuk penerapan lama yang menggunakan nama proyek berbeda, lanjutkan menggunakan nama aslinya dengan `-p`; `docker compose ls` mencantumkan proyek-proyek yang ada.

Salin `deploy/env.example` ke `.env` dan ubah `TGWITNESS_PORT` agar menggunakan port loopback yang berbeda. Misalnya, `TGWITNESS_PORT=8788` menampilkan panel di `http://127.0.0.1:8788`; kontainer tetap mendengarkan di port 8787. `.env` diabaikan oleh Git.

Ambil token awal:

~~~sh
docker compose exec tgwitness cat /data/panel-token.txt
~~~

Perintah yang berguna:

```sh
docker compose ps
docker compose logs --tail 100 -f
docker compose stop
docker compose up -d --wait
```

`restart: unless-stopped` memulai ulang pengumpul data setelah terjadi crash atau daemon Docker dimulai ulang. Pada server Linux, aktifkan Docker saat boot menggunakan pengelola layanan distribusi Anda, umumnya `sudo systemctl enable --now docker`. Pada Windows/macOS, aktifkan pengaturan "start-at-sign-in" di Docker Desktop. Keluar dari Desktop, mode tidur, atau daemon Docker yang dihentikan dapat mengganggu proses pengumpulan data. Kontainer yang dihentikan secara eksplisit akan tetap dalam keadaan berhenti hingga Anda memulainya kembali.

Volume /tmp dibatasi hingga 512 MiB dalam konfigurasi contoh. Proses ekspor menggunakan elemen `temporary-exports/` dari setiap ruang kerja ke direktori /data yang persisten. Sediakan ruang di sana untuk ekspor simultan, pertumbuhan jurnal/WAL, media, dan cadangan. Peluncur dan Docker menggunakan deploy/constraints.txt untuk mengunci versi dependensi runtime yang memenuhi syarat. Ini bukanlah rantai pasokan yang terkunci dengan hash: gambar dasar Python dan artefak paket masih memerlukan kualifikasi rilis independen.

Jangan gunakan perintah `docker compose down -v` kecuali Anda bermaksud menghapus jurnal dan kunci. Laporan kesehatan kontainer menunjukkan ketersediaan server web, bukan keberhasilan penangkapan pesan Telegram. Periksa status pengumpul, detak jantung, kesalahan, dan peristiwa cakupan pada panel.

### Profil saksi independen

Layanan opsional `witness` menjalankan [saksi independen](../WITNESS.md) dalam kontainernya sendiri, dengan kunci dan jurnal tersendiri di volume `witness-data` serta hanya token saksi yang hanya dapat dibaca untuk pengumpul. Buat token tersebut di halaman **Saksi** pada panel, tambahkan bersama token bot dan saluran ke `.env`, lalu mulai profil:

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

Layanan ini terhubung ke kolektor di dalam jaringan Compose di `http://tgwitness:8787` (`TGWITNESS_WITNESS_COLLECTOR` menggantikannya, misalnya `/profiles/<workspace ID>` untuk ruang kerja lain). Untuk saksi di server terpisah yang dijalankan oleh pihak lain, gunakan `deploy/compose/compose.witness.yaml` di sana dengan `TGWITNESS_WITNESS_COLLECTOR` disetel ke alamat HTTPS kolektor; berkas tersebut hanya berisi saksi.

## Instal gambar yang telah dipublikasikan

Ini akan tersedia setelah [alur kerja rilis](#rilis-github-otomatis) berhasil dan konfigurasi paket GHCR publik selesai. Nama pemilik repositori tidak terkodekan secara permanen dalam pohon sumber ini. Gunakan gambar yang ditampilkan dalam ringkasan alur kerja rilis tersebut.

Salin `deploy/env.example` ke `.env`. Atur `TGWITNESS_IMAGE` ke versi yang telah dipublikasikan, dengan menggunakan jalur repositori **dalam** **huruf** **kecil**, misalnya:

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.7.1
TGWITNESS_PORT=8787
```

Jalankan berkas ini secara terpisah, bukan `compose.yaml`:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

Tidak diperlukan build sumber, Python, atau kompiler di host. Alur kerja rilis ini ditujukan untuk kontainer Linux AMD64 dan ARM64, termasuk VM Linux di Docker Desktop. Gunakan tag versi atau `ghcr.io/owner/repository@sha256:...` dari ringkasan alur kerja. Tidak ada konfigurasi pemindahan tag `latest` atau pembaruan aplikasi tanpa pengawasan. Gambar dan varian sumber menggunakan volume data yang sama jika nama proyeknya sama.

## HTTPS otomatis di server

Gunakan server dengan Docker, domain yang Anda kendalikan, dan penyimpanan lokal yang persisten. Arahkan catatan A/AAAA domain ke server; publikasikan AAAA hanya jika IPv6 dapat menjangkaunya. Izinkan lalu lintas masuk TCP 80 dan 443 serta lalu lintas keluar DNS/HTTPS untuk penerbitan sertifikat. Layanan lain tidak boleh sudah menggunakan port-port ini.

Salin `deploy/env.example` ke `.env` dan tentukan nama host, tanpa skema atau jalur:

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

Mulai proses kompilasi kode sumber dengan overlay HTTPS:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

Untuk gambar yang telah dipublikasikan, gunakan `deploy/compose/compose.image.yaml` sebagai file pertama. Pertahankan kedua argumen `-f` untuk perintah status, log, pembaruan, dan penghentian di kemudian hari.

Caddy memperoleh dan memperbarui sertifikat, mengalihkan HTTP ke HTTPS, serta meneruskan permintaan ke pengumpul di jaringan Compose pribadi. Status sertifikat memiliki volume persisten tersendiri. Port host langsung pengumpul tetap hanya untuk loopback. Konfigurasi Caddy yang disediakan tidak mengaktifkan pencatatan akses.

Buka `https://watch.your-domain.org` dan masukkan token panel. Kesiapan Compose tidak menjamin penerbitan sertifikat atau aksesibilitas eksternal. Jika HTTPS belum siap, periksa DNS, aturan firewall, dan:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

Gambar Caddy yang disediakan mengikuti tag `2-alpine`-nya. Melakukan pull akan memperbarui gambar tersebut; sematkan digest yang telah diuji dalam penyebaran Anda jika Anda memerlukan versi infrastruktur yang tetap.

## Pembaruan dan cadangan

Pertahankan nama proyek Compose dan volume data selama pembaruan. Pertama, hentikan pengumpul data dan buat cadangan lengkap. Untuk penerapan berbasis sumber default:

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

Gunakan tujuan cadangan baru setiap kali, di luar repositori, dan lindungi sebagai materi yang memerlukan akses akun. Jalur contoh hanya sebagai ilustrasi; gunakan lokasi cadangan pribadi Anda. Salin seluruh direktori, termasuk file tersembunyi, semua ruang kerja, kunci, jurnal, dan media. Cadangkan kunci utama vault eksternal secara terpisah jika telah dikonfigurasi. File ZIP bukti bukanlah cadangan aplikasi yang dapat dipulihkan. Untuk HTTPS, simpan juga volume Caddy jika Anda perlu mempertahankan status sertifikat/akunnya.

Untuk penerapan dari sumber, unduh berkas rilis terbaru dan jalankan:

```sh
docker compose up -d --build --wait
```

Untuk penerapan berbasis gambar, ubah `TGWITNESS_IMAGE` menjadi versi yang diinginkan, lalu jalankan:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

Gunakan berkas Compose pada instalasi Anda untuk perintah stop/copy di atas juga. Pertahankan `.env`, konfigurasi khusus, dan nama proyek yang sama. `down` mempertahankan volume bernama; **`down -v` menghapusnya**. Jangan menyalin `.venv` antar sistem operasi atau versi Python. Untuk pembaruan asli, hentikan TgWitness, buat cadangan direktori datanya secara lengkap, ganti berkas sumber, dan jalankan `python start.py --setup-only` sebelum meluncurkan.

Periksa akses panel, identitas akun, status pemantauan, dan cakupan setelah pembaruan. Memulai ulang tidak akan memulihkan pembaruan Telegram yang terlewat. Pengembalian ke versi sebelumnya mungkin memerlukan cadangan sebelum pembaruan jika versi mendatang mengubah format penyimpanan.

## Rilis GitHub otomatis

[alur kerja rilis](../../.github/workflows/release.yml) ini siap digunakan setelah proyek ini di-push ke repositori GitHub dengan Actions yang diaktifkan. Proses ini berjalan saat GitHub Release **diterbitkan**, termasuk prerelease. Draft dan push tag saja tidak akan menerbitkan paket.

1. Tentukan versi paket dan catatan perubahan, lalu terbitkan rilis yang diberi tag dengan `v` ditambah versi `pyproject.toml` yang tepat, seperti `v0.7.1`.
2. Alur kerja ini memvalidasi tag dan menjalankan pemeriksaan Python yang dapat digunakan di Windows/Linux/macOS, browser umum/impor akun/QR, paket sumber, serta Docker. Instalasi asli yang baru juga dilakukan pada ketiga sistem operasi tersebut menggunakan Python 3.12.
3. Setelah pemeriksaan tersebut lulus, sistem ini melakukan uji coba awal (smoke test) terhadap gambar ARM64 di bawah QEMU, mempublikasikan gambar AMD64/ARM64 ke `ghcr.io/<lowercase-owner>/<lowercase-repository>:<version>`, serta melampirkan berkas ZIP sumber, checksum, dan Python wheel ke dalam rilis. Sebuah tugas terpisah di Windows membangun dan melampirkan berkas ZIP portabel beserta checksum-nya.
4. Setelah publikasi pertama, buka pengaturan paket GHCR dan atur visibilitas menjadi **Publik** jika Anda bermaksud melakukan pengunduhan gambar secara anonim. Repositori sumber yang publik saja tidak menjamin paket kontainer yang publik. Kebijakan organisasi harus mengizinkan publikasi paket. Alur kerja ini menggunakan `GITHUB_TOKEN`; kata sandi registri atau kredensial VPS tidak boleh disertakan dalam repositori.

Keberhasilan alur kerja jarak jauh belum dapat dipastikan melalui persiapan lokal ini. Emulasi ARM64 hanyalah uji coba awal, bukan pengujian pada perangkat keras asli atau pengujian Telegram secara langsung. Fitur ini mengotomatiskan proses pengemasan rilis; namun, untuk memulai server, Anda tetap memerlukan perintah Compose beserta prasyarat domain/host-nya. Server yang sudah ada tidak akan diperbarui atau di-restart secara otomatis saat rilis baru diterbitkan.

## Server jarak jauh

Pastikan layanan terikat ke loopback dan gunakan terowongan SSH, atau akhiri koneksi HTTPS di proxy terbalik. Berkas Compose dasar hanya berlaku secara lokal; overlay opsional `deploy/compose/compose.https.yaml` menyediakan Caddy untuk domain yang telah dikonfigurasi. Jaga agar token bearer tidak muncul di URL maupun log proxy. Proxy terbalik harus membatasi ukuran permintaan dan laju koneksi. Jangan mengekspos HTTP biasa ke Internet.

Contoh untuk systemd, tugas masuk Windows, agen pengguna macOS, dan Caddy disediakan di [folder deploy/.](../../deploy/README.md) Periksa dan sesuaikan jalurnya sebelum instalasi. Contoh-contoh ini hanyalah templat, bukan konfigurasi platform yang dijalankan secara lokal. Tidak ada layanan latar belakang atau tugas yang didaftarkan oleh peluncur standar.

Di Windows, peluncuran tanpa jendela `pythonw.exe` menyimpan diagnostik startup/server di `logs/server.log` di bawah direktori data (5 MiB per file, dua cadangan yang dirotasi). Peluncuran melalui konsol tetap menyimpan log konsol. Pencatatan akses HTTP dinonaktifkan di kedua mode. Lindungi log dengan direktori data dan tinjau terlebih dahulu sebelum membagikannya.

## Mulai ulang dan celah

Status pemantauan terakhir yang diminta disimpan. Jika pemantauan sedang aktif, saat startup sistem akan mencoba terhubung kembali dan melanjutkan sumber-sumber yang dipilih. Penundaan manual akan menghapus niat tersebut. Kegagalan restart akan dicatat dan ditampilkan di panel.

StringSession mempertahankan otorisasi tetapi tidak mempertahankan pembaruan/status entitas Telethon yang tahan lama. Dialog dimuat ulang saat dimulai. Telegram/Telethon dapat memulihkan beberapa gangguan transmisi saat berjalan, tetapi TgWitness tidak menjamin pemutaran ulang yang tahan lama saat proses dimulai ulang. Setiap kali dimulai, sistem mencatat kepala jurnal sebelumnya dan batas offline. Monitor memeriksa konektivitas setiap 10 detik dan menambahkan sinyal detak jantung setiap menit (**Parameter → Catat aktivitas setiap**). Gangguan singkat mungkin terlewatkan; koneksi transportasi yang aktif tidak menjamin pengiriman pembaruan yang lengkap. Snapshot merupakan pengamatan riwayat terkini yang eksplisit, bukan perbaikan celah.

Antrian media disimpan dalam basis data SQLite masing-masing ruang kerja. Sebuah pesan dan tugasnya dikomit secara atomik. Tugas yang sedang berjalan dan terputus akan dipulihkan untuk dicoba kembali saat dimulai. Setiap unduhan memiliki batas waktu dasar 120 detik ditambah waktu sesuai ukuran file pada kecepatan 256 KiB/s, serta batas 1–2.000 MiB per jenis lampiran; batas waktu, kecepatan, dan upaya ulang diatur di **bagian** **Parameter**. Pengumpul akan melewati file yang ukurannya tidak diketahui. Menjeda akan mempertahankan pekerjaan yang ada dalam antrian. Upaya ulang menggunakan deskriptor file asli yang teramati, bukan versi terbaru dari pesan yang telah diedit setelahnya. Kegagalan sementara memiliki batasan upaya ulang; jeda FloodWait media tetap berlaku setelah restart. Pemulihan media terpisah dari pemulihan pembaruan Telegram dan tidak dapat membuat ulang file yang hilang.

## Pencadangan, pemulihan, dan kapasitas

Hentikan proses sebelum menyalin **seluruh direktori data**, termasuk vault.key, signing.enc, credentials.enc, file basis data SQLite/WAL, media, token, titik pemeriksaan, dan semua profil/subdirektori. Pulihkan salinan lengkap tersebut saat layanan tujuan dalam keadaan berhenti. Kunci vault yang hilang atau ketidaksesuaian kunci penandatanganan akan menyebabkan kegagalan saat memulai; jangan membuat ulang kunci untuk memaksa akses.

Simpan cadangan rahasia dalam bentuk terenkripsi dan dengan kontrol akses. Berkas ZIP bukti merupakan artefak tinjauan yang portabel, bukan cadangan aplikasi atau cadangan sesi Telegram. Tidak ada penghapusan otomatis berdasarkan masa retensi. Rencanakan ruang penyimpanan untuk semua pesan, metadata mentah, media, ekspor sementara, dan cadangan.

Verifikasi saat startup dan ekspor catatan aliran alih-alih memuat seluruh jurnal. Ekspor mengunci snapshot yang telah dibaca sementara penulisan WAL baru dapat berlanjut; ekspor yang berlangsung lama dapat menyimpan halaman WAL, sehingga kapasitas disk tetap menjadi pertimbangan. Ukuran ZIP dibatasi hingga 4 GiB (tidak terkompresi) agar sesuai dengan pengaturan default verifikator independen; **Parameter → ZIP bertanda terbesar** menaikkan batas tersebut, dan arsip semacam itu diverifikasi dengan `verify.py --max-gib N`. Format lain tidak memiliki batas jumlah peristiwa. Browser yang didukung mengalirkan potongan respons ke file yang dipilih pengguna. Browser lain menyimpan dalam buffer maksimal 128 MiB dan mengarahkan transfer yang lebih besar ke CLI yang terotentikasi:

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

Gunakan `--profile ID` dari **Ekspor → ID Ruang Kerja** untuk ruang kerja lain, `--format zip|jsonl|csv|html`, `--url https://your-server` untuk server jarak jauh, atau `--max-mib` untuk mengubah batas transfer 5 GiB. HTTP biasa hanya diizinkan untuk loopback. Token dikirim melalui header, pengalihan ditolak, file yang sudah ada tidak ditimpa, dan unduhan yang belum selesai tidak dipublikasikan sebagai file yang sudah selesai. Jika TGWITNESS_TOKEN menggantikan token yang dihasilkan, gunakan berkas yang dilindungi secara terpisah yang berisi nilai aktif tersebut: panel-token.txt tidak akan ditimpa oleh penggantian tersebut. SHA-256 perintah ini hanyalah checksum transfer; verifikasi ZIP yang ditandatangani secara terpisah.

Berkas ekspor server tetap tersimpan di dalam direktori pribadi `temporary-exports/` masing-masing ruang kerja. Respons yang berhasil akan menghapus berkas-berkasnya. Ekspor yang terputus akan dihapus pada saat ruang kerja dimulai kembali dengan kunci instance eksklusifnya masih aktif. Direktori ini merupakan bagian dari model ancaman/kapasitas penyimpanan; gunakan volume data terenkripsi. Transfer multi-gigabyte skala produksi masih memerlukan pengujian pada sistem target Anda.

Panel ini menampilkan media yang sedang dalam antrian/gagal, media tertunda tertua, ruang disk kosong, jeda permintaan Telegram, dan sumber yang aksesnya belum dikonfirmasi. Diagnostik ini bukanlah pemantau pengiriman end-to-end yang lengkap. Ruang kerja berbagi proses; akun yang aktif berlebihan tetap dapat memengaruhi yang lain. Proses pekerja terpisah, retensi/rotasi, pemulihan pembaruan yang tahan lama, penambatan titik pemeriksaan jarak jauh, peran, dan kualifikasi penerapan penuh masih berlaku.

## Opsi koneksi dan perlindungan

Rute koneksi berlaku per ruang kerja dan harus dikonfigurasi sebelum otorisasi. SOCKS5/HTTP CONNECT menggunakan dependensi python-socks yang disematkan. MTProxy menggunakan transportasi perantara acak eksperimental dari Telethon; rahasia TLS palsu tidak didukung. Tidak ada pengalihan langsung otomatis yang dikonfigurasi. Ini bukan rute jaringan yang berlaku secara sistem.

Untuk instalasi baru, TGWITNESS_VAULT_KEY_FILE mengarah ke berkas kunci utama acak yang dilindungi secara terpisah. Pasang berkas tersebut dalam mode baca-saja di luar direktori /data di dalam kontainer. Simpan metadata garam publik vault.external.json secara terpisah untuk setiap ruang kerja dan kunci utama. Vault lokal yang sudah ada memerlukan migrasi terencana; pengaturan variabel ini tidak akan mengonversinya secara otomatis. Penyimpanan pesan/media serta ekspor tidak dienkripsi oleh aplikasi. Gunakan volume terenkripsi dan penyimpanan sementara pribadi yang memadai jika diperlukan.

Prosedur terperinci: [koneksi/keamanan](../CONNECTION-SECURITY.md) dan [mode operasi](../OPERATIONS.md).
