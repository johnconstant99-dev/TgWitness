[TgWitness](../../README.md) / [Dokumentasi](README.md) · [Pemberitahuan operator](OPERATOR-INCOMPATIBILITY.md)

![Berkas GDPR 106 hari](../assets/presentation/chapter-gdpr-file.svg)

# Valve, Taylor Wessing, dan 106 hari menunggu berdasarkan GDPR: uraian berkas dan 70.717 katanya

[Catatan sumber](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Pemberitahuan operator](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

Kami ditinggalkan dengan pertanyaan yang tidak akan pernah terjawab, karena kami bukan pihak dalam sengketa ini. Tidak ada orang biasa yang sanggup bertahan menunggu seratus hari setiap kali dan berhadapan dengan pengacara elite yang dibiayai korporasi melalui "bursa pekerja lepas" seperti ini. Kami tidak akan pernah tahu apa sebenarnya nama layanan yang dipesan Valve. Dari luar, ini tampak seperti pemrosesan GDPR yang tidak sepenuhnya sah, dan pengungkapan data yang para pelapornya tidak dihitamkan melainkan dibocorkan, sementara setidaknya 5.000–10.000 halaman data itu sendiri hilang: yang diekspor bukan log pengguna, melainkan log yang dipangkas dan dibuat untuk pihak alih daya. Tidak ada gunanya menggugatnya. Lapisan informasi yang sangat besar secara objektif tidak ada, sama halnya tidak ada apa pun yang mengonfirmasi apa yang dikatakan salah satu dari kedua pengacara itu.

Berapa yang dibayar Valve untuk layanan yang terdiri dari mengulur waktu, penghitaman yang diterapkan dengan tangan, dan tanda tangan seorang Doktor di bawah laporan homofobik dan PDF yang rusak? Ini bukan perkara kami, tetapi masalahnya di sini jelas bukan hukum; melainkan status dan impunitas. Gelar "Doktor" secara otomatis menjadikan satu orang sebagai pihak yang memutuskan apa yang dianggap bukti tak terbantahkan, dan orang lain sebagai pihak yang konon memahami angka dan PDF (padahal kenyataannya tidak).

---

## 1. Tanggal, kata-kata sang Doktor, dan laporan tanpa satu pun pembayaran

Kepala dokumen bertuliskan `Date of Report: 09-29-2025`, dan berkasnya sendiri diserahkan pada 1 atau 2 Oktober. Tetapi kami tidak memercayai tanggal-tanggal ini. Kami memercayai pernyataan langsung **Dr. Patrick Vincent Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“
>
> *(Penyusunan data pribadi klien Anda sayangnya memakan seluruh jangka waktu satu bulan, karena pemeriksaan ulang menunjukkan bahwa setelah 3 Mei 2025 pun ada pembayaran baru oleh pihak ketiga melalui akun tersebut, sehingga data harus dibersihkan secara manual.)*

Justru kalimat inilah yang membuat kami berhenti memercayai angka-angka, kata-kata sang doktor di paragraf pertama, dan tanda tangannya. Tentu saja seorang doktor tidak akan berbohong; ia punya sesuatu yang dipertaruhkan, bukan? Hanya saja, setelah berkas diekspor dan bentuk-bentuk vektor dihapus, tidak satu pun pembayaran muncul dalam laporan. Kami tidak mempersoalkan pekerjaan Dr. Patrick atau keterlambatannya. Kami hanya memercayai dan menerima "kebenaran sang Doktor", dan mencatat apa yang terlihat dalam berkas itu sendiri.

---

## 2. 36 detik dan label rentan "Anlage 1 / Taylor Wessing"

Kami bukan ahli dalam apa pun, dan rupanya itulah sebabnya pemberitahuan kerentanan kami diabaikan, baik oleh platform pekerja lepas itu sendiri maupun oleh sang doktor. Logikanya cukup jelas: merekalah hukumnya, kerentanan apa yang mungkin mereka miliki?

Tetapi kesampingkan kata-kata sang Doktor dan lihat teknologinya. Kami menyiapkan lingkungan Windows yang setara, mengambil berkas yang telah dibersihkan, dan mencoba menempatkan bentuk-bentuknya. Menempatkan ratusan bentuk hitam dengan tangan dalam **36 detik**, persis selama sesi yang tercatat berlangsung, menurut kami mustahil; dari semua tanda, kotak-kotak hitam itu sudah ada di dokumen. Kami cenderung berpendapat bahwa dalam 36 detik itu tepat satu objek ditambahkan, di kanan atas halaman 1: label `"Anlage 1 / Taylor Wessing"`. Dan perangkat lunak yang menempatkannya itulah yang rentan:

* **Objek, menurut penandanya:** dari `(929, 294)` hingga `(1139, 372)`, yaitu `210 × 78 px`, berpusat kira-kira di `(1034, 333)`.
* **Bingkai yang terlihat:** dari `(936, 300)` hingga `(1133, 367)`, sekitar `197 × 67 px`, dengan proporsi kira-kira `3 : 1`; tepi atas lembar berada di `y ≈ 275`.
* **Skala:** diukur terhadap penggaris kiri dokumen, `1 cm ≈ 82 px` (penggaris hampir pasti dalam sentimeter; dalam inci, lembar itu akan lebih lebar dari `15″`).

Gaya dan tampilan lencana itu cocok dengan berkas yang dikembalikan. Tetapi tanpa akses ke lingkungan pembuatan asli, atau tanpa mengetahui format awal (jika ada konversi), eksperimen ini tidak bisa bersih, sehingga kami tidak dapat menyatakannya dengan kepastian 100%.

---

## 3. Halaman 444: waktu yang disembunyikan dan aritmetika laporan

Laporan-laporan dimulai di halaman 444, termasuk laporan homofobik itu. Satu hal penting:

* Pada laporan yang mereka pilih untuk ditampilkan (yang menguntungkan para pengacara), kolom **`Time of Report`** sengaja disembunyikan di atas segala hal lainnya. Tidak ada waktu yang pasti, dan inilah satu-satunya hal di seluruh berkas yang disembunyikan dengan cara yang benar secara teknis.
* Dalam artikel utama, kami membandingkan secara matematis laporan yang ditampilkan dengan sisanya, berdasarkan isi, gaya penulisan, dan nama panggilan. Hampir di mana-mana rumus standar pembuatan nama Reddit dipakai ulang secara kasar, dan ada lonjakan tajam tepat di rentang yang dibutuhkan. Kami tidak mengatakan laporan-laporan itu dipalsukan, tetapi kami mengatakan bahwa akun-akun itu kemungkinan tidak nyata, dan sebagian besar secara matematis mirip botnet.

---

## 4. Pertanyaan untuk Dr. Patrick Zurheide tentang entri `2025-02-03 16:29:23` dan `2025-04-02 15:55:19`

Doktor Patrick, Anda menulis bahwa Anda membaca lelucon homofobik itu dan memutuskan untuk membuat lelucon sendiri. Baiklah, lucu sekali. Laporan-laporan lain, seperti kata rekan Anda, tidak penting secara substansi (*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…“*). Baiklah, kami lewati. Kami berharap **Doktor Tobias** akan menjelaskan kepada mahasiswanya dalam sebuah kuliah mengapa seperempat acak dari 1.938 laporan (485 di antaranya), yang penuh harapan kematian dan pernyataan Nazi, tidak penting, dan bagi siapa tepatnya tidak penting. Jika ia melakukannya, kami akan segera mengakui kesalahan, meminta maaf, dan menghapus penyebutannya.

Mari kita sebut segala sesuatu dengan namanya: Anda dengan sadar menyerahkan data para pembenci, yang Rusia, yang Jerman, semuanya, kepada orang yang justru mereka benci, dan ini terjadi di antara dua negara yang sedang berperang. Ternyata Anda menyodorkan anak-anak Rusia kepadanya: ia senang sekali, dan Tobias secara langsung menunjuk mereka sebagai masalahnya. Tetapi kenyataannya ini adalah kebocoran Anda; hanya saja anak-anak itu bukan anak Anda.

Namun, pertanyaan kami menyangkut pengguna lain, yang tidak mungkin terlewat:

* **`2025-02-03 16:29:23`**: sebuah tautan dan seseorang dari negara yang sama, dengan hal-hal sangat serius tertulis di sana yang langsung menonjol;
* **`2025-04-02 15:55:19`**: rujukan langsung, nama tertentu, dan apa yang ia tulis.

Kami memeriksanya: memang persis seperti yang terlihat. Anda secara terbuka menempatkan data negara dan rincian pribadi lengkap di tangan seseorang yang Anda sendiri anggap sebagai penjahat. Ini tidak seharusnya dilakukan, setidaknya karena konteksnya. Apa yang terjadi jika ia menulis di sana? Di pihak Anda, ini bukan sekadar rendah; ini pengabaian terang-terangan terhadap nyawa dan kesehatan orang. Selama penyelidikan, kami menghentikan orang ini dan mengamankan semua orang. Secara keseluruhan, inilah satu-satunya keluhan nyata kami; selebihnya hanyalah fakta dan peragaan tentang bagaimana pengacara elite bekerja. Kami meminta Doktor Patrick memikul tanggung jawab yang semestinya atas hal ini, kecuali, tentu saja, gelar di depan namanya memberinya hak untuk bertindak seperti ini (kami bukan pengacara dan tidak mengerti hukum).

---

## 5. Kepada publik, perusahaan asuransi, regulator, dan perusahaan AS

* **Kepada publik dan klien Taylor Wessing:** Melihat kecerobohannya, Taylor Wessing memiliki perusahaan asuransi yang murah hati yang menganggap semua ini normal. Periksa berkas Anda dan beri tahu regulator. Tidak perlu memberi tahu para pengacara itu sendiri: mereka memilih menyembunyikan ini selama lebih dari setahun, sejak Valve pertama kali datang kepada mereka.
* **Kepada regulator, tentang kerentanan setiap berkas:** Tinjau kegiatan Dr. Patrick dan minta setiap PDF yang melewatinya dengan lencana `"Anlage 1 / Taylor Wessing"` (atau yang serupa) di bagian atas halaman pertama. Kemungkinan bahwa ini bukan kasus tunggal, dan bahwa setiap dokumen darinya yang memuat stiker ini rentan, sangat tinggi.
* **Kepada perusahaan asuransi:** Mohon audit klien Anda dan perangkat lunak yang ia gunakan untuk mengolah PDF dan menempatkan label `"Anlage 1 / Taylor Wessing"` di bagian atas halaman 1. Kemungkinan besar di sanalah tepatnya masalahnya, dan ini bukan kasus tunggal. Tidak ada gunanya menyerukan audit atas seluruh Taylor Wessing: selain nama, mereka tampaknya tidak berbagi apa pun dalam hal lingkungan kerja atau aturan tinjauan keamanan, yang seharusnya ada dengan sendirinya (rupanya kunci tanda tangan fisik dan gelar di depan nama sudah menutupi semua itu).
* **Kepada perusahaan AS, dan siapa pun di Komisi Eropa yang kebetulan membaca ini:** Cobalah sekadar menaati hukum. Mempekerjakan doktor ternama dari "perusahaan pekerja lepas" ternama tampak berbahaya dan sungguh keji terhadap pelanggan Anda. Jika di Valve cek begitu saja ditandatangani dan tidak ada yang memeriksa apa yang dikerjakan para pengacara selama 106 hari, mungkin membayar waktu yang diulur alih-alih hasil itulah alasan perangkat lunaknya usang dan tidak ada yang memahami cara kerja PDF. Dan jika tidak ada kebocoran lain di sana, berarti Doktor Patrick hanya berhasil membuat semua orang lelah dengan penantian atau ancaman. Pada dasarnya, yang dijual adalah layanan ketidakpatuhan GDPR: pelaksanaan berkualitas buruk dan ancaman ("Anda tidak akan memenangkan satu perkara pun"), dipadukan dengan pembersihan hasil Google berkualitas tinggi yang dilakukan atas nama mereka sendiri. Kami tidak menyusun teks hukum dan tidak menuduh siapa pun. Kami hanya menuliskan apa yang kami lihat, dan apa yang mereka berusaha keras hapus.

---

## 6. Yang dibeli Valve bukan pemrosesan GDPR

Kami bukan pihak dalam sengketa ini dan kami tidak membela akun maupun pemblokirannya. Tinggal satu pertanyaan. Valve menyewa pengacara papan atas: dua doktor ternama dari "perusahaan pekerja lepas" ternama, **Dr. Tobias Schelinski** (`Doc. No. 42282474`, 15 Agustus 2025) dan **Dr. Patrick Vincent Zurheide** (`Doc. No. 42603633`, 1 Oktober 2025). Untuk apa Valve membayar? Bukan untuk pemrosesan GDPR: permintaannya tidak dipenuhi saat itu dan tidak dipenuhi sampai sekarang.

### Yang diserahkan sebagai gantinya, dengan kata-kata mereka sendiri

* **Tenggat "kalaupun ada":** *„wenn überhaupt“* — Doktor Tobias.
* **Minta datamu, kehilangan akunmu:** pemutusan *„mit sofortiger Wirkung“*, sebagai jawaban atas permintaan akses data — Doktor Tobias.
* **Bukti dengan jumlah:** *„Unabhängig von den Einzelheiten der Beschwerden…“* Isi tidak penting, semuanya dihitung — Doktor Tobias.
* **Diagnosis bagi pemohon:** *„…Ihr Mandant bzw. dessen Komplizen…“* — Doktor Patrick.
* **Vonis atas nama setiap pengadilan:** *„Aus unserer Erfahrung wird jedes Gericht…“* — Doktor Patrick. Belum ada pengadilan yang memutus; kami kira justru untuk itulah pengadilan ada.
* **Empat pasal Kitab Undang-Undang Hukum Pidana:** `§§ 263, 263a, 202a, 303a StGB`, karena meminta data milik sendiri.
* **Sebagai ganti data:** lima halaman Kebijakan Privasi publik Steam, salinan Dashboard yang sudah bisa dilihat pengguna, dan balasan Dukungan Steam yang diterjemahkan. Dua doktor hukum menyerahkan apa yang sudah ditulis seorang agen dukungan.
* **Surat utang tertulis:** *„Gerne beauskunften wir die restlichen … Daten, sobald …“* Sisanya, suatu hari nanti.
* **Pihak ketiga dilindungi dengan membocorkannya:** data pemblokiran ditahan "untuk melindungi pihak ketiga", data pihak ketiga dikirim dalam PDF yang kotak hitamnya bisa dilepas.
* **Dua versi fakta:** satu doktor menanggali pengguna sejak Mei 2025, yang lain sejak 2019. Keduanya menandatangani. Seorang doktor tidak akan menandatangani hal yang tidak benar, jadi kami menerima keduanya.
* **Ejaan premium:** *„Die Antwortet lautet ja“*, dua kali, dan e-mail milik sang partner sendiri salah eja di tanda tangannya sendiri.

### Bukan kekeliruan

> [!IMPORTANT]
> Kekeliruan biasanya disembunyikan. Di sini tidak ada yang mencoba sama sekali. **Yang dijual adalah ketidakpatuhan GDPR, dan dijual secara terbuka.** Itu bukan kekeliruan; itu arogansi.

### Untuk diri sendiri, untuk pengguna, dan untuk semua orang lain

* **Untuk diri sendiri:** penghapusan dari hasil pencarian berdasarkan `Art. 17`. Doktor Patrick mengajukan lebih dulu; kami menerbitkan Bagian 3 di Medium; tepat setelahnya, hasil tentang Doktor Tobias juga dihapus.
* **Untuk subjek data:** tujuh belas bulan dan terus bertambah.
* **Tanpa pengacara:** Dukungan Steam menutup permintaan pemegang akun lain dalam **3 hari**, dengan tautan ke Account Data: *"there's no further information Steam Support can offer, this request will be closed"* (tiket `HT-2YBP-F7JP-D4VB`; tangkapan layar pemohon, [Bagian 18 dosir Steam](https://phishdestroy.io/steam_dossier/#gdpr-live-case)).
* **Dengan pengacara:** tiket tertutup yang sama dalam **106 hari**, di atas kop surat. Siapa yang mengizinkan Valve sama sekali tidak memproses permintaan GDPR? Doktor Tobias?

### Gelar

Kami menyebut mereka "Doktor" di sepanjang tulisan, dan kami mengatakannya dengan hormat: gelar adalah fakta sejarah. Gelar Doktor Tobias bertumpu pada [studi tahun 2005 tentang cara otoritas Jerman mengawasi layanan daring asing](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm); gelar Doktor Patrick pada [studi tahun 2020 tentang kontrak pengembangan perangkat lunak dalam Scrum](https://books.google.pl/books/about/Herausforderungen_bei_einer_Softwareentw.html?id=uh4PzgEACAAJ&redir_esc=y). Masing-masing adalah satu penelitian sempit, tentang satu topik sempit, yang dikerjakan sekali. Itu bukan keahlian dalam perlindungan data, dalam berkas PDF, atau dalam apa yang akan diputuskan setiap pengadilan. Di bawah gelar-gelar itu, dalam berkas ini: tidak ada pengawasan, dan sebuah PDF yang dibuat dengan `Aspose.PDF for .NET 20.8` dari tahun 2020.

Kami belum membaca kedua disertasi itu, baik milik Doktor Tobias maupun Doktor Patrick. Kami membaca deskripsi penerbit untuk disertasi Doktor Tobias. Pada 2005 tentu saja belum ada GDPR. Tetapi kedengarannya solusinya sudah ada sejak itu.

<details>
<summary><b>Deskripsi penerbit untuk disertasi Doktor Tobias (asli berbahasa Jerman dan terjemahan)</b></summary>

> „Darüber hinaus geht der Autor auf Probleme ein, die sich aus der Durchführung der behördlichen Aufsicht über die Online-Dienste ergeben. Hier sind insbesondere die Ausführungen über die örtliche Zuständigkeit von Behörden hervorzuheben. Dem Autor gelingt es insoweit, anhand einzelner Gesetze Lösungsmöglichkeiten aufzuzeigen wie der Gegensatz einer beschränkten örtlichen Zuständigkeit im Verhältnis zu der weltweiten Präsenz von Online-Diensten zu lösen ist.“
>
> *(Selain itu, penulis membahas masalah yang timbul dari pelaksanaan pengawasan oleh otoritas terhadap layanan daring. Yang patut disorot khususnya adalah uraiannya tentang kewenangan wilayah otoritas. Berdasarkan undang-undang tertentu, penulis berhasil menunjukkan kemungkinan solusi atas pertentangan antara kewenangan wilayah yang terbatas dan kehadiran layanan daring di seluruh dunia.)*

Sumber: [Verlag Dr. Kovač](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm).

</details>

Menilik berkas ini, sang penulis memang menemukan solusi, juga untuk GDPR: satu pengacara memutuskan siapa yang berhak atas datanya sendiri dan siapa yang tidak. Undang-undang mana yang harus dipakai untuk mempersempit sebuah regulasi Eropa demi kepentingan satu perusahaan Amerika, kami tidak tahu. Salah satu solusi yang mungkin adalah memproses permintaan GDPR itu secara sah. Tetapi penulisnya sudah doktor.

### Tiga cara menangani permintaan akses dengan salah

Sejauh kami, yang bukan pengacara, bisa membaca Regulasi itu, ada tiga, dan ketiganya diambil:

* **Tidak menyerahkan data:** melanggar hukum.
* **Menyerahkannya tidak lengkap:** melanggar hukum.
* **"Membersihkan secara manual" dan membocorkan data pihak ketiga:** dua kali melanggar hukum (`Art. 5(1)(f)`, `Art. 32`).

> [!TIP]
> **Cara keempat:** cukup penuhi permintaannya. Itulah satu-satunya cara yang tidak diambil dua doktor hukum. Itu bukan sial; itu pilihan.

### Siapa yang bertanggung jawab?

Sejauh yang kami lihat, tidak ada: baik secara finansial maupun pribadi. Anda tidak bisa memberi mereka ulasan. Anda tidak bisa menulis opini. Perusahaannya "terdesentralisasi", jadi tidak ada perusahaan lain untuk dituju. Dan begitu Anda menyebut nama orang-orang yang menandatangani surat atas nama perusahaan, para perwakilan perusahaan tiba-tiba menjadi individu pribadi, dengan hak untuk dilupakan yang ditulis untuk individu pribadi, diterapkan seketika. Padahal semua yang dihapus menyangkut pekerjaan profesional mereka. Apakah laporan tentang pelanggaran, atau tentang kompetensi profesional, benar-benar termasuk hak untuk dilupakan? Bagaimana orang seharusnya membedakan pengacara yang baik dari yang buruk: dari profil di situs web Taylor Wessing sendiri? Dan bisakah itu dipercaya, ketika firma itu menyunting sejarahnya sendiri di Wikipedia?

Kami sungguh tidak mengerti mengapa fakta sejarah sebuah gelar doktor dalam topik sempit memberi seseorang hak untuk mematikan hak-hak GDPR. Mungkin kami salah memahaminya. Mungkin Doktor Tobias mengajarkan sesuatu yang kurang tepat kepada mahasiswanya. Atau mungkin itu benar, dan Jerman diam-diam telah menyerah pada GDPR. Atau itu Doktor Tobias yang memutuskan?

Dan mengapa, hanya untuk menerbitkan audit kami, opini kami, dan pengalaman kami (tentang kompetensi, dan tentang risiko kebocoran pada perangkat lunak rentan milik Doktor Patrick), kami harus menanamkan teksnya ke dalam perangkat lunak kami sendiri agar teks itu bertahan? Justru karena itulah semua ini tampak bagi kami sebagai korporatokrasi. Dan jika orang yang bertanya tidak mendapat apa-apa, untuk apa ada GDPR? Pendapatan bagi pengacara yang tidak bisa memakai PDF?

### Kesimpulan kami

Kami bukan pihak dalam sengketa ini, dan terus terang kami sudah lelah dengannya. Selama ini kami sudah melihat semuanya: riwayat Wikipedia yang dihapus dua kali, anak-anak dalam laporan, permintaan GDPR yang tidak pernah diproses, hak untuk dilupakan yang dipakai untuk diri sendiri, pendiri yang ikut menulis versi Nazi §175, dan struktur "terdesentralisasi" di mana tanggung jawab bukan milik siapa pun. Dari pengalaman kecil kami, kesimpulannya menyedihkan: gelar hanyalah gelar. Tanggung jawab di pihak pengacara: nol. Yang tersisa adalah arogansi, dan GDPR yang tidak dipatuhi. Kami hanya bertanya apa yang dibeli Valve, karena jelas itu bukan pemrosesan GDPR.

---

Karena para pengacara menganggap merekalah hukum, dan bahwa nyawa manusia, nyawa anak-anak, tidak penting, itu pilihan mereka. Ini bukan konflik kami. Tetapi kami dapat mengatakan dengan yakin bahwa impunitas firma ini terkonfirmasi secara historis, sejak pendirinya Goltz, salah satu dari delapan orang yang menyusun amandemen §175, dan sejak satu-satunya perkaranya yang terkenal, yang kadang dibaca sebagai pembelaan terhadap orang LGBT: perkara Jenderal von Fritsch.

<details>
<summary><b>Sejarah: Goltz, §175, dan perkara Fritsch</b></summary>

Kami lewati sejarahnya; kami mempelajarinya langsung dari sumber tepercaya dan catatan aslinya. Tetapi beginilah perkara itu berakhir: ada satu terdakwa, dan kita punya tiga orang tewas. Achim von Frisch, digilas roda penindasan. Otto Schmidt, ditembak mati pada 1943. Dan Jenderal Fritsch sendiri: tidak penting bahwa ia dibebaskan, harganya mahal. Pada 1939, mencari kematian, ia menjadi sukarelawan untuk front di Polandia dan tewas (atau membiarkan dirinya terbunuh).

Tentu saja, kami tidak pernah menganggap perkara ini sebagai pembelaan pendiri firma terhadap orang LGBT. Tetapi hasil akhirnya jauh lebih menarik daripada sebuah kemenangan.

**Keadilan asimetris:** Goltz memang menyelamatkan seorang perwira tinggi, yang kesalahannya sepenuhnya direkayasa oleh Gestapo. Tetapi alibi ini dibayar dengan darah orang lain. Goltz yang sama, sebagai anggota Komisi Hukum Pidana sejak 1933, secara pribadi merancang dan memberlakukan versi Nazi dari Paragraf 175 (1935).

**Statistik versus PR:** Ia membela seorang jenderal heteroseksual dari kalangan elite Wehrmacht setelah lebih dulu menggerakkan ban berjalan hukum yang mengirim sekitar 50.000 homoseksual sungguhan ke penjara dan sekitar 15.000 ke kamp konsentrasi, dengan tingkat kematian 60%. Menyelamatkan satu jenderal tidak menghapus arsitektur genosida.

**Denazifikasi, berhasil dihindari:** Perkara Fritsch menjadi "pintu belakang" sempurna melewati panel denazifikasi pascaperang. Arsitek undang-undang represif itu memakai pembelaannya atas satu jenderal sebagai bukti "independensinya", lolos dari Nuremberg, mempertahankan status dan izinnya, dan pada 1957 mendirikan kantor yang kini memperdagangkan progresivitasnya di bawah papan nama Taylor Wessing.

</details>

Jadi ya, secara keseluruhan: kami yakin tidak ada bedanya apakah ini Taylor Wessing Jerman ini atau yang lain; ini sama sekali bukan soal hukum. Apa yang kami katakan di sini adalah sebuah pernyataan, bukan penegasan fakta melainkan asumsi, karena kenyataannya mereka akan mencari kata apa pun untuk dijadikan pegangan. Itulah sebabnya ini masuk ke arsip: upaya sensor dan penyembunyian, serta kaitan langsung dengan warisan mereka. Dari Doktor Patrick: laporan paling pertama, dengan kata homofobik kasar yang dibiarkan. Mungkin tidak sengaja, tentu saja, tetapi kata itu ada di sana, dan itu yang pertama.

Dari Doktor Tobias kami tentu mengharapkan kuliah tentang bukti tak terbantahkan dalam bentuk jumlah laporan, dan penjelasan bagian mana dari seperempat itu yang tidak penting baginya secara pribadi. Bagi sejarah, dan untuk memahami di mana batasnya, ini penting.

Bahwa Steam bertindak sebagai pengendali data alih-alih melakukan moderasi hanya menunjukkan hal yang jelas: Doktor Patrick yang membocorkannya. Ya, begitulah jadinya. Rupanya ia tidak tahu bahwa perangkat lunak untuk stiker itu rusak, mengingat mereka doktor papan atas, dan Steam tidak membayar untuk itu: apakah memproses permintaan GDPR atau tidak, lalu menutupi kebocoran yang telah ia lihat.

Kami menyerukan kewarasan dalam memperlakukan kebenaran, dan ingin mengingatkan semua orang tentang zero trust: terhadap semua orang, termasuk kami. Semuanya adalah lingkungan yang bermusuhan, dan dalam konteks ulasan ini secara harfiah: larangan pada 9 Mei, Nazi, doktor, orang LGBT, anak-anak. Seru sekali.

Tetapi pilihan kami terkait Taylor Wessing kemungkinan besar sudah habis, karena strategi mereka adalah membuat tautan dihapus. Kami terpaksa melestarikan teks dan data kami, sehingga kami menanamkannya ke dalam perangkat lunak kami, yang sudah memiliki tiga surat terima kasih terkonfirmasi dari lembaga pemerintah, termasuk di Jerman dan Belgia, padahal belum dirilis.

Kami ingin memperingatkan mereka yang gemar membengkokkan hukum: tidak perlu menurunkan repositori. Selama ini kami tidak pernah berkonflik dengan Anda. Tetapi jika Anda memutuskan merusak pekerjaan kami demi menyembunyikan kebenaran, maka tanpa repositori yang aktif, regulator dan pihak lain tidak akan bisa membandingkan tanda tangan sebuah versi (walau kepada siapa saya menceritakan ini), dan saat itulah kami akan masuk ke konflik langsung. Dengan ini kami berharap dapat berpamitan dengan keahlian mega dan para pengacara elite. Ini tidak menyenangkan, dan saya tidak senang. Semoga sukses.

> [!CAUTION]
> **Menurunkan repositori ini tidak akan menghapus apa pun.** Penyidik dan peneliti menggunakan TgWitness, dan salinan mereka diverifikasi terhadap repositori ini. Kami punya cadangan. Tetapi penurunan akan mengubah kami dari auditor satu kasus menjadi pihak dalam konflik. Cukup sudah menghapus kebenaran.

[Catatan sumber](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Pemberitahuan operator](OPERATOR-INCOMPATIBILITY.md) · [Lisensi MIT](../../LICENSE)

[Proyek](../../README.md) · [Dokumentasi](README.md) · [Wiki](../wiki/Home.md)
