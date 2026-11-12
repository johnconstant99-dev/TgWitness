[TgWitness](../../README.md) / [Dokumentasi](../README.md) / [Folder](README.md)

![Penerapan & pemulihan](../assets/presentation/chapter-operate.svg)

[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · [Español](../es/DEPLOYMENT.md) · [Português (Brasil)](../pt/DEPLOYMENT.md) · [Türkçe](../tr/DEPLOYMENT.md) · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · **Bahasa Indonesia** · [Tiếng Việt](../vi/DEPLOYMENT.md) · [简体中文](../zh/DEPLOYMENT.md)

# Penerapan dan pengoperasian

## Pilih instalasi

Untuk paket portabel, ekstrak `TgWitness-<version>-windows-amd64-portable.zip` dari
GitHub Releases. Untuk metode lain, unduh dan ekstrak ZIP sumber atau kloning repositori,
lalu jalankan perintah berikut dari direktori proyek:

| Instalasi | Menjalankan | Berjalan di latar belakang? |
| --- | --- | --- |
| Paket portabel Windows | `TgWitness.cmd` | Tidak; biarkan jendela tetap terbuka. |
| Windows native | `Start.cmd` | Tidak; gunakan tugas logon opsional untuk berjalan di latar belakang. |
| Linux/macOS native | `sh start.sh` | Tidak; gunakan systemd/launchd untuk berjalan di latar belakang. |
| Docker di host apa pun yang didukung | `docker compose up -d --build --wait` | Ya, selama daemon Docker berjalan. |
| Helper Docker di Windows | `scripts\Docker.cmd` | Ya; helper menunggu server web berstatus sehat. |
| Helper Docker di Linux/macOS | `sh scripts/docker-start.sh` | Ya; helper menunggu server web berstatus sehat. |

Untuk server cloud yang harus dapat diperiksa oleh pihak ketiga—dibuat melalui API penyedia,
tanpa SSH, dan hanya dapat dijangkau melalui Cloudflare Tunnel—lihat
[penerapan dengan jaminan tinggi](../HIGH-ASSURANCE.md).

Startup native membuat `.venv` privat dan menginstal dependensi dengan versi terpatok.
Docker membangunnya di dalam image tanpa memerlukan Python di host. Penyiapan pertama memerlukan
akses Internet. Jika Python 3.11+ tidak ditemukan, `Start.cmd` meminta persetujuan sebelum menginstal
Python 3.12 untuk pengguna Windows saat ini (melalui winget, atau jika tidak tersedia, penginstal
python.org setelah tanda tangan Python Software Foundation-nya diperiksa); skrip ini tidak pernah
meminta hak administrator. Docker dan layanan OS tetap menjadi prasyarat.

Instalasi native dan portabel menggunakan `data/live` di dalam foldernya. Docker menggunakan volume
bernama `tgwitness-data` di `/data`. Keduanya tetap merupakan instalasi terpisah sampai Anda dengan
sengaja memigrasikan seluruh direktori data. Jangan berharap kontainer Docker baru akan menemukan
akun native secara otomatis.

## Persyaratan instalasi

Instalasi native memerlukan Python 3.11 atau yang lebih baru dengan `venv` dan `ensurepip`, akses
Internet untuk instalasi dependensi pertama, dan direktori proyek yang dapat ditulisi untuk
`.venv`. Panel bawaan tidak memerlukan Node.js atau build frontend. Jalankan peluncur dari akun OS
biasa Anda; TgWitness tidak memerlukan hak administrator/root.

- **Windows:** `Start.cmd` memeriksa `py -3`, lalu `python`, lalu folder instalasi bawaan per pengguna
  dan Program Files, dan mensyaratkan versi 3.11 atau yang lebih baru. Jika tidak ada yang berfungsi,
  skrip ini menawarkan instalasi otomatis per pengguna yang dijelaskan di atas. `py -3 start.py` juga
  dapat digunakan. Paket portabel sama sekali tidak memerlukan Python.
- **Linux:** `start.sh` mencoba `python3.13`, `python3.12`, `python3.11`, `python3`, dan
  `python`, lalu menampilkan perintah instalasi untuk apt, dnf, pacman, zypper, apk, atau Homebrew
  jika tidak ada yang memenuhi syarat. Instalasi Debian/Ubuntu mungkin memerlukan paket
  `python3-venv` yang sesuai dengan interpreter yang dipilih. Python bawaan distribusi yang lebih lama
  harus diganti atau dilengkapi dengan Python 3.11+.
- **macOS:** instal distribusi Python 3.11+ terkini; jangan berasumsi interpreter bawaan OS
  memenuhi persyaratan. Gunakan `python3 start.py` dari direktori proyek.
- **Docker:** gunakan Docker Engine/Desktop dengan Compose v2.20 atau yang lebih baru. Di Windows,
  Docker Desktop harus menggunakan kontainer Linux. Kontainer menginstal dependensi Python-nya
  sendiri; host tidak memerlukan instalasi Python terpisah.

## Komputer lokal

Gunakan `Start.cmd` di Windows atau `sh start.sh` di Linux/macOS. `scripts\Setup.cmd` atau
`sh start.sh --setup-only` menyiapkan lingkungan. Peluncur menginstal dependensi pada penggunaan
pertama; peluncuran berikutnya menggunakan kembali lingkungan tersebut. Akses Internet diperlukan untuk
penyiapan dan pengumpulan dari Telegram, tetapi menelusuri catatan yang ada dan membuat ekspor dapat
dilakukan secara offline.

Jalankan `python start.py --check` setelah penyiapan untuk memeriksa dependensi lokal, Ed25519,
penyimpanan, konfigurasi kunci, dan alamat yang didengarkan tanpa memulai pengumpul.
Gunakan `--json` untuk keluaran terstruktur. Berikan `--data-dir`, `--host`, dan `--port` yang akan
dipakai. Pemeriksaan ini tidak menginstal paket, tidak membuat jurnal, dan tidak menghubungkan Telegram;
ini bukan kualifikasi integritas atau cakupan. Saat startup, jurnal yang ada diverifikasi secara
terpisah. `python start.py --help` juga tidak memicu instalasi.

Setelah menggunakan start.py, jalankan perintah tambahan dengan `.venv\Scripts\python.exe` di
Windows atau `.venv/bin/python` di Linux/macOS, atau aktifkan lingkungan tersebut terlebih dahulu.
Contoh `python -m ...` di bawah mengasumsikan lingkungan sudah aktif.

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

Variabel lingkungan: TGWITNESS_DATA, TGWITNESS_HOST, TGWITNESS_PORT, TGWITNESS_TOKEN.
TGWITNESS_VAULT_KEY_FILE memilih mode kunci eksternal untuk instalasi baru; lihat [Kunci master eksternal](../SECURITY-MODEL.md#external-master-key).
Jika diberikan, TGWITNESS_TOKEN harus berisi minimal 24 karakter; gunakan nilai acak kriptografis.
Tanpanya, aplikasi membuat token acak 256-bit di panel-token.txt.
Nilai dari variabel lingkungan tidak menulis ulang berkas tersebut. Mulai ulang untuk merotasi kredensial.

Tepat satu proses yang boleh memiliki satu direktori data. Kunci berkas OS lintas platform mencegah
penulis bersamaan yang tidak disengaja. Gunakan satu worker Uvicorn. Panel dapat mengelola ruang kerja
dalam jumlah berapa pun, dengan direktori ruang kerja tambahan di bawah profiles/<id>/.
Untuk instance layanan terpisah, gunakan direktori dan port yang berbeda. Berkas WAL SQLite harus
berada di penyimpanan lokal yang persisten, bukan di sistem berkas jaringan. Jangan berbagi satu
volume antar-replika.

## Paket portabel Windows

Setiap GitHub Release menyertakan `TgWitness-<version>-windows-amd64-portable.zip` dan
`.sha256`-nya. Paket ini berisi runtime Python 3.12 embeddable resmi dari python.org
(checksum-nya dipatok di `tools/build_portable.py`), TgWitness beserta dependensinya yang versinya
dipatok, dan tiga peluncur:

| Berkas | Fungsi |
| --- | --- |
| `TgWitness.cmd` | Menjalankan panel; opsi tambahan diteruskan, misalnya `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | Menjalankan demo sintetis di `data\demo` |
| `TgWitness-Check.cmd` | Menjalankan pemeriksaan kesiapan tanpa memulai aplikasi |

Kamus morfologi bahasa Rusia dan profil warna PDF yang versinya dipatok disertakan untuk penggunaan
offline. Proses pengemasan hanya mengizinkan jalur berkas yang sudah dikenal di dalam direktori `data`
milik dependensi; berkas tak terduga di direktori tersebut membuat build gagal.

Ekstrak seluruh arsip ke folder yang dapat ditulisi, misalnya `Documents\TgWitness`; jangan
menjalankannya dari dalam ZIP atau dari Program Files. Runtime menggunakan jalur modul yang terisolasi,
sehingga instalasi Python lain dan `PYTHONPATH` tidak memengaruhinya. Data tetap berada di folder
`data` milik paket. Untuk memperbarui, hentikan TgWitness, ekstrak versi baru ke folder baru,
lalu salin folder `data` ke sana.

Untuk membangunnya sendiri di Windows 64-bit dengan Python 3.12:

~~~sh
python tools/build_portable.py
~~~

## Kontainer

```sh
docker compose up -d --build --wait
```

Perintah ini membuat volume persisten bernama untuk /data.
Port web dipetakan ke 127.0.0.1:8787. Proses berjalan sebagai UID 10001 dengan capabilities yang
dilepas, sistem berkas root hanya-baca, serta /data dan /tmp yang dapat ditulisi.
`--wait` memeriksa kesehatan server web sebelum selesai; status otorisasi dan pengiriman Telegram
terlihat di panel. Helper yang disertakan menggunakan batas waktu kesiapan 180 detik setelah build.
Unduhan dependensi awal bisa memakan waktu lebih lama dari itu.

Kedua berkas Compose dasar menggunakan nama proyek `tgwitness`, sehingga mengekstrak rilis baru ke
direktori lain tidak diam-diam memilih volume data baru. Pertahankan hanya satu penerapan aktif untuk
proyek tersebut. Untuk instalasi yang independen, gunakan `docker compose -p NAME ...` yang unik dan
port host yang berbeda, dan pertahankan keduanya saat pembaruan. Untuk penerapan lama yang memakai
nama proyek berbeda, tetap gunakan nama aslinya dengan `-p`; `docker compose ls` menampilkan daftar
proyek yang ada.

Salin `deploy/env.example` ke `.env` dan ubah `TGWITNESS_PORT` untuk memakai port loopback lain.
Misalnya, `TGWITNESS_PORT=8788` membuka panel di `http://127.0.0.1:8788`; kontainer tetap
mendengarkan di 8787. `.env` diabaikan oleh Git.

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

`restart: unless-stopped` menjalankan ulang pengumpul setelah crash atau setelah daemon Docker dimulai
ulang. Di server Linux, aktifkan Docker saat boot dengan pengelola layanan distribusi Anda, biasanya
`sudo systemctl enable --now docker`. Di Windows/macOS, aktifkan pengaturan Docker Desktop untuk
berjalan otomatis saat masuk. Keluar dari sesi desktop, mode tidur, atau daemon Docker yang berhenti
dapat menyela pengumpulan. Kontainer yang dihentikan secara eksplisit tetap berhenti sampai Anda
menjalankannya lagi.

Volume /tmp dibatasi 512 MiB dalam konfigurasi contoh. Pembuatan ekspor sebagai gantinya menggunakan
`temporary-exports/` milik setiap ruang kerja di /data yang persisten. Sisihkan ruang di sana untuk
ekspor yang berjalan bersamaan, pertumbuhan jurnal/WAL, media, dan cadangan.
Peluncur menggunakan deploy/constraints.txt untuk mematok versi dependensi runtime yang telah dikualifikasi.
Docker dan server jaminan tinggi menginstal dari deploy/requirements.lock dan deploy/build.lock
dengan pip --require-hashes: setiap berkas paket harus cocok dengan SHA-256 yang tercatat dalam commit,
sehingga berkas yang diganti di PyPI atau mirror akan ditolak. Image dasar Python dan paket sistem
operasi tetap memerlukan kualifikasi rilis secara independen.

Jangan gunakan docker compose down -v kecuali Anda memang ingin memusnahkan jurnal dan kunci.
Kesehatan kontainer menunjukkan ketersediaan server web, bukan keberhasilan perekaman Telegram.
Periksa status pengumpul, heartbeat, galat, dan peristiwa cakupan di panel.

### Profil saksi independen

Layanan opsional `witness` menjalankan [saksi independen](../WITNESS.md) di kontainernya sendiri,
dengan kunci dan jurnal sendiri di volume `witness-data` serta hanya token saksi baca-saja untuk
mengakses pengumpul. Buat token di panel melalui **Alat lainnya → Tambahan → Saksi independen**,
tambahkan ke `.env` bersama token bot dan saluran, lalu jalankan profilnya:

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

Layanan ini menjangkau pengumpul di dalam jaringan Compose melalui `http://tgwitness:8787`
(`TGWITNESS_WITNESS_COLLECTOR` menggantinya, misalnya `/profiles/<workspace ID>` untuk
ruang kerja lain). Untuk saksi di server terpisah yang dijalankan oleh pihak lain, gunakan
`deploy/compose/compose.witness.yaml` di sana dengan `TGWITNESS_WITNESS_COLLECTOR` diatur ke alamat
HTTPS pengumpul; berkas tersebut hanya berisi saksi.

## Instal image yang diterbitkan

Salin `deploy/env.example` ke `.env`. Atur `TGWITNESS_IMAGE` ke versi yang diterbitkan, menggunakan
jalur repositori dalam **huruf kecil**, misalnya:

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.9.3
TGWITNESS_PORT=8787
```

Jalankan berkas ini secara tersendiri, bukan `compose.yaml`:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

Host tidak memerlukan build dari sumber, Python, atau kompiler. Alur kerja rilis menargetkan kontainer
Linux AMD64 dan ARM64, termasuk VM Linux milik Docker Desktop.
Gunakan tag versi atau `ghcr.io/owner/repository@sha256:...` dari ringkasan alur kerja.
Tidak ada tag `latest` yang bergerak maupun peningkatan aplikasi tanpa pengawasan yang dikonfigurasi.
Varian image dan sumber menggunakan volume data yang sama jika nama proyeknya sama.

<a name="automatic-https-on-a-server"></a>

## HTTPS otomatis di server

Gunakan server dengan Docker, domain yang Anda kendalikan, dan penyimpanan lokal yang persisten.
Arahkan catatan A/AAAA domain ke server; terbitkan AAAA hanya jika server dapat dijangkau melalui
IPv6. Izinkan TCP 80 dan 443 masuk serta DNS/HTTPS keluar untuk penerbitan sertifikat.
Port ini tidak boleh sudah dipakai layanan lain.

Salin `deploy/env.example` ke `.env` dan atur nama host, tanpa skema atau jalur:

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

Jalankan build dari sumber dengan overlay HTTPS:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

Untuk image yang diterbitkan, gunakan `deploy/compose/compose.image.yaml` sebagai berkas pertama.
Pertahankan kedua argumen `-f` untuk perintah status, log, pembaruan, dan penghentian berikutnya.

Caddy memperoleh dan memperbarui sertifikat, mengalihkan HTTP ke HTTPS, dan meneruskan permintaan
ke pengumpul di jaringan Compose privat. Status sertifikat memiliki volume persistennya sendiri.
Port host langsung milik pengumpul tetap hanya untuk loopback.
Konfigurasi Caddy yang disertakan tidak mengaktifkan log akses.

Buka `https://watch.your-domain.org` dan masukkan token panel. Kesiapan Compose hanya mencakup
kontainer; penerbitan sertifikat dan keterjangkauan dari luar bergantung pada DNS dan firewall.
Jika HTTPS belum siap, periksa DNS, aturan firewall, dan:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

Image Caddy yang disertakan mengikuti tag `2-alpine`-nya. Pull akan memperbarui image tersebut;
patok digest yang telah diuji dalam penerapan Anda jika Anda memerlukan versi infrastruktur yang tetap.

## Pembaruan dan cadangan

Pertahankan nama proyek Compose dan volume data di setiap pembaruan. Pertama, hentikan pengumpul
dan buat cadangan lengkap. Untuk penerapan bawaan berbasis sumber:

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

Gunakan tujuan cadangan baru setiap kali, di luar repositori, dan lindungi sebagai materi yang memberi
akses ke akun. Jalur contoh hanya ilustrasi; gunakan lokasi cadangan privat Anda. Salin seluruh
direktori, termasuk berkas tersembunyi, semua ruang kerja, kunci, jurnal, dan media.
Cadangkan kunci master brankas eksternal secara terpisah jika dikonfigurasi.
ZIP bukti bukanlah cadangan aplikasi yang dapat dipulihkan. Untuk HTTPS, simpan juga volume Caddy
jika Anda perlu mempertahankan status sertifikat/akunnya.

Untuk penerapan dari sumber, ambil berkas rilis baru dan jalankan:

```sh
docker compose up -d --build --wait
```

Untuk penerapan berbasis image, ubah `TGWITNESS_IMAGE` ke versi yang diinginkan, lalu jalankan:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

Gunakan juga berkas Compose instalasi Anda untuk perintah stop/copy di atas.
Pertahankan `.env`, konfigurasi khusus, dan nama proyek yang sama. `down` mempertahankan volume
bernama; **`down -v` menghapusnya**. Jangan menyalin `.venv` antar sistem operasi atau versi Python.
Untuk pembaruan native, hentikan TgWitness, cadangkan seluruh direktori datanya, ganti berkas sumber,
dan jalankan `python start.py --setup-only` sebelum meluncurkan.

Setelah pembaruan, periksa akses panel, identitas akun, status pemantauan, dan cakupan. Setelah dimulai
ulang, TgWitness melanjutkan dari posisi update Telegram yang tersimpan dan meminta update yang
terlewat selama pembaruan. Rollback mungkin memerlukan cadangan sebelum pembaruan jika versi mendatang
mengubah format penyimpanan.

## Server jarak jauh

Biarkan layanan terikat ke loopback dan gunakan tunnel SSH, atau terminasikan HTTPS di reverse proxy.
Berkas Compose dasar hanya untuk akses lokal; overlay opsional `deploy/compose/compose.https.yaml`
menyediakan Caddy untuk domain yang dikonfigurasi. Jangan biarkan token bearer muncul di URL dan log
proxy. Reverse proxy perlu membatasi ukuran permintaan dan laju koneksi. Jangan mengekspos HTTP biasa
ke Internet.

Contoh untuk systemd, tugas logon Windows, agen pengguna macOS, dan Caddy tersedia di
[deploy/](../../deploy/README.md). Tinjau dan sesuaikan jalurnya sebelum instalasi.
Contoh-contoh ini adalah templat yang disediakan, bukan kualifikasi platform yang telah dijalankan
secara lokal. Peluncur biasa tidak mendaftarkan layanan atau tugas latar belakang apa pun.

Di Windows, peluncuran tanpa jendela melalui `pythonw.exe` menyimpan diagnostik startup/server di
`logs/server.log` di bawah direktori data (5 MiB per berkas, dua cadangan rotasi).
Peluncuran dari konsol tetap mencatat log ke konsol. Log akses HTTP dinonaktifkan di kedua mode.
Lindungi log bersama direktori data dan tinjau sebelum membagikannya.

## Mulai ulang dan celah

Status pemantauan terakhir yang diminta disimpan. Jika pemantauan sedang aktif, saat startup aplikasi
mencoba terhubung kembali dan melanjutkan sumber yang dipilih. Jeda manual menghapus niat tersebut.
Mulai ulang yang gagal dicatat dan ditampilkan di panel.

TgWitness menyimpan posisi update Telegram untuk akun dan setiap saluran (pts, qts, seq, dan date)
di brankas ruang kerja dan memulihkannya pada startup berikutnya. Klien kemudian meminta update yang
terlewat selama proses berhenti, dan pemeriksaan ulang berkala memulihkan pesan yang terlewat serta
mencatat pesan tersimpan yang tidak lagi dikembalikan Telegram. Dialog dimuat ulang saat startup.
Setiap startup mencatat kepala jurnal sebelumnya, batas offline, dan posisi update tempat pemantauan
dilanjutkan. Monitor memeriksa konektivitas setiap 10 detik dan menambahkan heartbeat setiap menit
(**Alat lainnya → Parameter → Catatan keaktifan setiap**).
Pemutusan koneksi dan periode senyap dicatat sebagai celah cakupan beserta alasannya.
Snapshot riwayat disimpan sebagai pengamatan riwayat terkini yang terpisah, di samping catatan live.

Antrean media disimpan di basis data SQLite setiap ruang kerja. Pesan dan tugasnya di-commit secara
atomik. Tugas yang terputus saat berjalan dipulihkan untuk dicoba ulang saat startup. Setiap unduhan
memiliki batas waktu dasar 120 detik ditambah waktu sesuai ukurannya pada 256 KiB/s, serta batas
1–2000 MiB per jenis lampiran; batas waktu, kecepatan, dan percobaan ulang ada di
**Alat lainnya → Parameter**. Pengumpul melewati berkas yang ukurannya tidak diketahui. Jeda
mempertahankan pekerjaan dalam antrean. Percobaan ulang menggunakan deskriptor berkas asli yang
teramati, tidak pernah versi terbaru dari pesan yang kemudian diedit. Kegagalan sementara memiliki
percobaan ulang yang terbatas; jeda FloodWait media tetap berlaku setelah mulai ulang.
Pemulihan media terpisah dari pemulihan update Telegram dan tidak dapat membuat ulang berkas yang
sudah hilang.

## Pencadangan, pemulihan, dan kapasitas

Hentikan proses sebelum menyalin **seluruh direktori data**, termasuk vault.key, signing.enc,
credentials.enc, berkas basis data/WAL SQLite, media, token, titik pemeriksaan, dan semua subdirektori
profiles/. Pulihkan salinan lengkap saat layanan tujuan dalam keadaan berhenti. Kunci brankas yang
hilang atau kunci penandatanganan yang tidak cocok membuat startup gagal; jangan membuat ulang kunci
untuk memaksakan akses.

Simpan cadangan yang berisi rahasia dalam keadaan terenkripsi dan dengan kontrol akses. ZIP bukti
adalah artefak peninjauan yang portabel, bukan cadangan aplikasi atau cadangan sesi Telegram.
Tidak ada penghapusan otomatis berdasarkan masa retensi. Rencanakan ruang disk untuk semua pesan,
metadata mentah, media, ekspor sementara, dan cadangan.

Verifikasi saat startup dan ekspor membaca catatan secara streaming, bukan memuat seluruh jurnal.
Ekspor mematok snapshot baca sementara penulisan WAL baru dapat berlanjut; ekspor yang berjalan lama
dapat menahan halaman WAL, sehingga kapasitas disk tetap penting. ZIP dibatasi 4 GiB tanpa kompresi
agar sesuai dengan batas bawaan verifier independen; **Alat lainnya → Parameter → File ZIP bertanda terbesar**
menaikkan batas tersebut, dan arsip seperti itu diverifikasi dengan `verify.py --max-gib N`. Format lain
tidak memiliki batas jumlah peristiwa. Browser yang didukung mengalirkan potongan respons ke berkas
yang dipilih pengguna. Browser lain menampung paling banyak 128 MiB di buffer dan mengarahkan transfer
yang lebih besar ke CLI yang terautentikasi:

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

Gunakan `--profile ID` dari **Ekspor → ID Ruang Kerja** untuk ruang kerja lain,
`--format zip|jsonl|csv|html`, `--url https://your-server` untuk server jarak jauh, atau
`--max-mib` untuk mengubah batas transfer 5 GiB. HTTP biasa hanya diizinkan untuk loopback.
Token dikirim di header, pengalihan ditolak, berkas yang sudah ada tidak ditimpa, dan unduhan yang
belum lengkap tidak diterbitkan sebagai berkas jadi.
Jika TGWITNESS_TOKEN menggantikan token yang dibuat otomatis, gunakan berkas terlindungi terpisah yang
berisi nilai aktif tersebut: panel-token.txt tidak ditulis ulang oleh penggantian itu.
SHA-256 dari perintah ini hanya checksum transfer; verifikasi ZIP bertanda tangan secara independen.

Panel menampilkan media yang mengantre/gagal, media tertunda tertua, ruang disk kosong, jeda
permintaan Telegram, dan sumber yang aksesnya belum terkonfirmasi. Diagnostik ini bukan pemantau
pengiriman end-to-end yang lengkap. Ruang kerja berbagi satu proses; akun yang sangat sibuk tetap
dapat memengaruhi yang lain. Proses worker terpisah, retensi/rotasi, pemulihan update yang persisten,
dan kualifikasi penerapan menyeluruh masih belum selesai. Akses panel dengan cakupan terbatas
didokumentasikan di [akses dan izin](../ACCESS.md); titik pemeriksaan independen dibahas dalam
[panduan saksi](../WITNESS.md).

Prosedur terperinci: [koneksi/keamanan](../CONNECTION-SECURITY.md) dan
[mode pengoperasian](../OPERATIONS.md).
