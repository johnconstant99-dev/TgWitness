[TgWitness](../../README.md) / [Dokumentasi](README.md) · [Notis pengendali](OPERATOR-INCOMPATIBILITY.md)

![Fail GDPR 106 hari](../assets/presentation/chapter-gdpr-file.svg)

# Valve, Taylor Wessing dan 106 hari menunggu di bawah GDPR: huraian fail dan 70,717 patah perkataannya

[Rekod sumber](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Notis pengendali](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

Kami ditinggalkan dengan soalan yang tidak akan pernah terjawab, kerana kami bukan pihak dalam pertikaian ini. Tiada orang biasa yang mampu bertahan menunggu seratus hari setiap kali dan berdepan dengan peguam elit yang dibiayai syarikat besar melalui "bursa pekerja bebas" seperti ini. Kami tidak akan pernah tahu apakah sebenarnya nama perkhidmatan yang ditempah oleh Valve. Dari luar, ia kelihatan seperti pemprosesan GDPR yang tidak sepenuhnya sah, dan pendedahan data yang pelapornya tidak dihitamkan tetapi dibocorkan, sedangkan sekurang-kurangnya 5,000–10,000 halaman data itu sendiri hilang: yang dieksport bukan log pengguna, tetapi log yang dipangkas dan dibuat untuk pihak penyumberan luar. Tiada gunanya mempertikaikannya. Satu lapisan maklumat yang sangat besar secara objektif tiada, sama seperti tiada apa-apa yang mengesahkan kata-kata mana-mana daripada dua peguam itu.

Berapakah yang dibayar Valve untuk perkhidmatan yang terdiri daripada melengah-lengahkan, penghitaman yang dibuat dengan tangan, dan tandatangan seorang Doktor di bawah laporan homofobik dan PDF yang rosak? Ini bukan kes kami, tetapi masalahnya di sini jelas bukan undang-undang; ia adalah status dan kebal hukuman. Gelaran "Doktor" secara automatik menjadikan seseorang sebagai pihak yang memutuskan apa yang dikira sebagai bukti yang tidak dapat disangkal, dan seorang lagi sebagai pihak yang kononnya memahami angka dan PDF (walaupun hakikatnya tidak).

---

## 1. Tarikh, kata-kata Doktor dan laporan tanpa sebarang bayaran

Kepala dokumen tertulis `Date of Report: 09-29-2025`, dan fail itu sendiri diserahkan pada 1 atau 2 Oktober. Tetapi kami tidak mempercayai tarikh-tarikh ini. Kami mempercayai kenyataan langsung **Dr. Patrick Vincent Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“
>
> *(Penyusunan data peribadi anak guam anda malangnya mengambil keseluruhan tempoh sebulan, kerana semakan semula menunjukkan bahawa selepas 3 Mei 2025 juga terdapat bayaran baharu oleh pihak ketiga melalui akaun tersebut, dan oleh itu data perlu dibersihkan secara manual.)*

Ayat inilah yang membuatkan kami berhenti mempercayai angka-angka, kata-kata doktor dalam perenggan pertama dan tandatangannya. Sudah tentu seorang doktor tidak akan berbohong; dia ada sesuatu yang dipertaruhkan, bukan? Cuma, setelah fail dieksport dan bentuk vektor dibuang, tiada satu pun bayaran muncul dalam laporan. Kami tidak mempertikaikan kerja Dr. Patrick atau kelewatannya. Kami hanya mempercayai dan menerima "kebenaran Doktor", dan merekodkan apa yang dapat dilihat dalam fail itu sendiri.

---

## 2. 36 saat dan label terdedah "Anlage 1 / Taylor Wessing"

Kami bukan pakar dalam apa-apa, dan nampaknya sebab itulah notis kerentanan kami diabaikan oleh platform pekerja bebas itu sendiri dan juga oleh doktor. Logiknya cukup jelas: merekalah undang-undang, apakah kerentanan yang mungkin mereka ada?

Tetapi ketepikan kata-kata Doktor dan lihat teknologinya. Kami menyediakan persekitaran Windows yang sepadan, mengambil fail yang telah dibersihkan dan cuba meletakkan bentuk-bentuknya. Meletakkan ratusan bentuk hitam dengan tangan dalam **36 saat**, tepat selama sesi yang direkodkan berlangsung, pada pandangan kami adalah mustahil; dari segala tanda, kotak hitam itu sudah pun ada pada dokumen. Kami cenderung berpendapat bahawa dalam 36 saat itu tepat satu objek ditambah, di bahagian kanan atas halaman 1: label `"Anlage 1 / Taylor Wessing"`. Dan perisian yang meletakkannya itulah yang terdedah:

* **Objek, mengikut penandanya:** dari `(929, 294)` hingga `(1139, 372)`, iaitu `210 × 78 px`, berpusat kira-kira pada `(1034, 333)`.
* **Bingkai yang kelihatan:** dari `(936, 300)` hingga `(1133, 367)`, kira-kira `197 × 67 px`, nisbah kira-kira `3 : 1`; tepi atas helaian berada pada `y ≈ 275`.
* **Skala:** diukur berbanding pembaris kiri dokumen, `1 cm ≈ 82 px` (pembaris hampir pasti dalam sentimeter; dalam inci, helaian itu akan lebih lebar daripada `15″`).

Gaya dan rupa lencana itu sepadan dengan fail yang dikembalikan. Tetapi tanpa akses kepada persekitaran pengarangan asal, atau pengetahuan tentang format awal (jika ada penukaran), eksperimen ini tidak boleh bersih, jadi kami tidak dapat mendakwanya dengan kepastian 100%.

---

## 3. Halaman 444: masa yang disembunyikan dan aritmetik laporan

Laporan bermula di halaman 444, termasuk laporan homofobik itu. Satu perkara penting:

* Pada laporan yang mereka pilih untuk ditunjukkan (yang memudahkan para peguam), medan **`Time of Report`** sengaja disembunyikan di atas segala yang lain. Tiada masa yang tepat, dan inilah satu-satunya perkara dalam keseluruhan fail yang disembunyikan dengan cara yang betul dari segi teknikal.
* Dalam artikel utama, kami membandingkan laporan yang ditunjukkan dengan selebihnya secara matematik, mengikut kandungan, gaya penulisan dan nama samaran. Hampir di mana-mana, formula standard penjanaan nama Reddit digunakan semula secara kasar, dan terdapat lonjakan mendadak tepat dalam julat yang diperlukan. Kami tidak mengatakan laporan itu dipalsukan, tetapi kami mengatakan bahawa akaun-akaun itu mungkin tidak sebenar, dan kebanyakannya secara matematik menyerupai botnet.

---

## 4. Soalan kepada Dr. Patrick Zurheide tentang entri `2025-02-03 16:29:23` dan `2025-04-02 15:55:19`

Doktor Patrick, anda menulis bahawa anda membaca jenaka homofobik itu dan memutuskan untuk membuat jenaka sendiri. Baiklah, sangat lucu. Laporan-laporan lain, seperti kata rakan sekerja anda, tidak penting dari segi substansi (*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…“*). Baiklah, kami langkau. Kami berharap **Doktor Tobias** akan menerangkan kepada pelajarnya dalam satu kuliah mengapa satu perempat rawak daripada 1,938 laporan (485 daripadanya), yang penuh dengan hasrat kematian dan kenyataan Nazi, tidak penting, dan kepada siapa tepatnya ia tidak penting. Jika dia berbuat demikian, kami akan segera mengaku silap, memohon maaf dan memadamkan sebutan itu.

Mari kita namakan perkara dengan nama sebenar: anda dengan sedar menyerahkan data para pembenci, yang Rusia, yang Jerman, semuanya, kepada orang yang mereka benci itu sendiri, dan ini antara dua negara yang sedang berperang. Ternyata anda menyuapkan kanak-kanak Rusia kepadanya: dia gembira, dan Tobias menunjuk mereka secara langsung sebagai masalahnya. Tetapi hakikatnya ini kebocoran anda; cuma kanak-kanak itu bukan anak anda.

Namun, soalan kami berkaitan pengguna lain, yang tidak mungkin terlepas pandang:

* **`2025-02-03 16:29:23`**: satu pautan dan seseorang dari negara yang sama, dengan perkara yang sangat serius ditulis di sana yang terus menonjol;
* **`2025-04-02 15:55:19`**: rujukan langsung, nama tertentu dan apa yang ditulisnya.

Kami telah menyemak: ia betul-betul seperti yang kelihatan. Anda secara terbuka meletakkan data negara dan butiran peribadi lengkap di tangan seseorang yang anda sendiri anggap penjenayah. Ini tidak sepatutnya dilakukan, sekurang-kurangnya kerana konteksnya. Apa yang berlaku jika dia menulis di sana? Di pihak anda, ini bukan sekadar hina; ia pengabaian terang-terangan terhadap nyawa dan kesihatan manusia. Semasa kami menyiasat, kami menghentikan orang ini dan memastikan semua orang selamat. Secara keseluruhannya, inilah satu-satunya aduan sebenar kami; selebihnya hanyalah fakta dan demonstrasi bagaimana peguam elit bekerja. Kami menyeru Doktor Patrick untuk memikul tanggungjawab yang sewajarnya atas perkara ini, melainkan, sudah tentu, gelaran di hadapan namanya memberinya hak untuk bertindak begini (kami bukan peguam dan tidak mengetahui undang-undang).

---

## 5. Kepada orang awam, penanggung insurans, pengawal selia dan syarikat AS

* **Kepada orang awam dan pelanggan Taylor Wessing:** Melihat kecuaian ini, Taylor Wessing mempunyai penanggung insurans yang pemurah yang menganggap semua ini biasa. Semak fail anda dan maklumkan kepada pengawal selia. Tidak perlu memberitahu peguam itu sendiri: mereka memilih untuk menyembunyikannya selama lebih setahun, sejak Valve mula-mula datang kepada mereka.
* **Kepada pengawal selia, tentang kerentanan setiap fail:** Semak aktiviti Dr. Patrick dan minta setiap PDF yang melaluinya dengan lencana `"Anlage 1 / Taylor Wessing"` (atau yang serupa) diletakkan di bahagian atas halaman pertama. Kebarangkalian bahawa ini bukan kes terpencil, dan bahawa setiap dokumen daripadanya yang membawa pelekat ini terdedah, adalah sangat tinggi.
* **Kepada syarikat insurans:** Sila audit pelanggan anda dan perisian yang digunakannya untuk mengendalikan PDF dan meletakkan label `"Anlage 1 / Taylor Wessing"` di bahagian atas halaman 1. Kemungkinan besar di situlah masalahnya, dan ia bukan kes terpencil. Tiada gunanya menyeru audit ke atas seluruh Taylor Wessing: selain nama, mereka nampaknya tidak berkongsi apa-apa dari segi persekitaran kerja atau peraturan semakan keselamatan, yang sepatutnya wujud dengan sendirinya (nampaknya kunci tandatangan fizikal dan gelaran di hadapan nama sudah meliputi semua itu).
* **Kepada syarikat AS, dan sesiapa di Suruhanjaya Eropah yang kebetulan membaca ini:** Cubalah sekadar mematuhi undang-undang. Mengupah doktor terkenal daripada "syarikat pekerja bebas" yang terkenal kelihatan berbahaya dan amat keji terhadap pelanggan anda. Jika di Valve cek hanya ditandatangani dan tiada siapa menyemak apa yang dilakukan oleh peguam selama 106 hari, mungkin membayar untuk masa yang dipanjangkan dan bukannya hasil itulah sebabnya perisian ketinggalan zaman dan tiada siapa memahami cara PDF berfungsi. Dan jika tiada kebocoran lain di sana, maka Doktor Patrick hanya berjaya meletihkan semua orang dengan penantian atau ugutan. Pada dasarnya, yang dijual ialah perkhidmatan ketidakpatuhan GDPR: pelaksanaan berkualiti rendah dan ugutan ("anda tidak akan menang satu kes pun"), digabungkan dengan pembersihan hasil carian Google berkualiti tinggi yang dijalankan atas nama mereka sendiri. Kami tidak merangka teks undang-undang dan kami tidak menuduh sesiapa. Kami hanya menulis apa yang kami lihat, dan apa yang mereka bersungguh-sungguh cuba padamkan.

---

## 6. Yang dibeli Valve bukan pemprosesan GDPR

Kami bukan pihak dalam pertikaian ini dan kami tidak membela akaun mahupun sekatannya. Tinggal satu soalan. Valve mengupah peguam terkemuka: dua doktor terkenal daripada "syarikat pekerja bebas" yang terkenal, **Dr. Tobias Schelinski** (`Doc. No. 42282474`, 15 Ogos 2025) dan **Dr. Patrick Vincent Zurheide** (`Doc. No. 42603633`, 1 Oktober 2025). Untuk apa Valve membayar? Bukan untuk pemprosesan GDPR: permintaan itu tidak dipenuhi ketika itu dan tidak dipenuhi sekarang.

### Apa yang diserahkan sebagai ganti, dengan kata-kata mereka sendiri

* **Tarikh akhir "itu pun kalau ada":** *„wenn überhaupt“* — Doktor Tobias.
* **Minta data anda, hilang akaun anda:** penamatan *„mit sofortiger Wirkung“*, sebagai jawapan kepada permintaan akses data — Doktor Tobias.
* **Bukti melalui jumlah:** *„Unabhängig von den Einzelheiten der Beschwerden…“* Kandungan tidak penting, semuanya dikira — Doktor Tobias.
* **Diagnosis terhadap pemohon:** *„…Ihr Mandant bzw. dessen Komplizen…“* — Doktor Patrick.
* **Keputusan bagi pihak setiap mahkamah:** *„Aus unserer Erfahrung wird jedes Gericht…“* — Doktor Patrick. Tiada mahkamah yang memutuskan; kami sangka untuk itulah mahkamah wujud.
* **Empat seksyen Kanun Keseksaan:** `§§ 263, 263a, 202a, 303a StGB`, kerana meminta data sendiri.
* **Sebagai ganti data:** lima halaman Dasar Privasi awam Steam, salinan Dashboard yang memang sudah dilihat pengguna, dan jawapan Sokongan Steam yang diterjemahkan. Dua doktor undang-undang menyerahkan apa yang telah ditulis oleh seorang ejen sokongan.
* **Surat hutang bertulis:** *„Gerne beauskunften wir die restlichen … Daten, sobald …“* Bakinya, suatu hari nanti.
* **Pihak ketiga dilindungi dengan membocorkan mereka:** data sekatan ditahan "untuk melindungi pihak ketiga", data pihak ketiga dihantar dalam PDF yang kotak hitamnya boleh ditanggalkan.
* **Dua versi fakta:** seorang doktor menarikhkan pengguna dari Mei 2025, seorang lagi dari 2019. Kedua-duanya menandatangani. Seorang doktor tidak akan menandatangani perkara yang tidak benar, jadi kami terima kedua-duanya.
* **Ejaan premium:** *„Die Antwortet lautet ja“*, dua kali, dan e-mel rakan kongsi itu sendiri salah eja dalam tandatangannya sendiri.

### Bukan kesilapan

> [!IMPORTANT]
> Kesilapan biasanya disembunyikan. Di sini tiada siapa pun yang cuba. **Yang dijual ialah ketidakpatuhan GDPR, dan ia dijual secara terbuka.** Itu bukan kesilapan; itu keangkuhan.

### Untuk diri sendiri, untuk pengguna, dan untuk orang lain

* **Untuk diri sendiri:** penyahsenaraian di bawah `Art. 17`. Doktor Patrick memfailkan dahulu; kami menerbitkan Bahagian 3 di Medium; sejurus selepas itu, hasil carian tentang Doktor Tobias juga dinyahsenaraikan.
* **Untuk subjek data:** tujuh belas bulan dan masih berjalan.
* **Tanpa peguam:** Sokongan Steam menutup permintaan pemegang akaun lain dalam **3 hari**, dengan pautan ke Account Data: *"there's no further information Steam Support can offer, this request will be closed"* (tiket `HT-2YBP-F7JP-D4VB`; tangkapan skrin pemohon, [Seksyen 18 dosier Steam](https://phishdestroy.io/steam_dossier/#gdpr-live-case)).
* **Dengan peguam:** tiket tertutup yang sama dalam **106 hari**, di atas kepala surat. Siapa yang membenarkan Valve langsung tidak memproses permintaan GDPR? Doktor Tobias?

### Gelaran

Kami memanggil mereka "Doktor" sepanjang tulisan ini, dan kami maksudkannya dengan hormat: gelaran ialah fakta sejarah. Gelaran Doktor Tobias bersandar pada [kajian tahun 2005 tentang cara pihak berkuasa Jerman menyelia perkhidmatan dalam talian asing](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm); gelaran Doktor Patrick pada [kajian tahun 2020 tentang kontrak pembangunan perisian dalam Scrum](https://books.google.pl/books/about/Herausforderungen_bei_einer_Softwareentw.html?id=uh4PzgEACAAJ&redir_esc=y). Setiap satu ialah penyelidikan sempit, tentang satu topik sempit, yang dibuat sekali. Itu bukan kepakaran dalam perlindungan data, dalam fail PDF, atau dalam apa yang akan diputuskan oleh setiap mahkamah. Di bawah gelaran itu, dalam fail ini: tiada penyeliaan, dan sebuah PDF yang dibuat dengan `Aspose.PDF for .NET 20.8` dari tahun 2020.

Kami belum membaca kedua-dua tesis itu, sama ada milik Doktor Tobias atau Doktor Patrick. Kami membaca huraian penerbit bagi tesis Doktor Tobias. Pada 2005 sudah tentu belum ada GDPR. Tetapi bunyinya seolah-olah penyelesaiannya sudah ada ketika itu.

<details>
<summary><b>Huraian penerbit bagi tesis Doktor Tobias (asal bahasa Jerman dan terjemahan)</b></summary>

> „Darüber hinaus geht der Autor auf Probleme ein, die sich aus der Durchführung der behördlichen Aufsicht über die Online-Dienste ergeben. Hier sind insbesondere die Ausführungen über die örtliche Zuständigkeit von Behörden hervorzuheben. Dem Autor gelingt es insoweit, anhand einzelner Gesetze Lösungsmöglichkeiten aufzuzeigen wie der Gegensatz einer beschränkten örtlichen Zuständigkeit im Verhältnis zu der weltweiten Präsenz von Online-Diensten zu lösen ist.“
>
> *(Selain itu, penulis membincangkan masalah yang timbul daripada pelaksanaan penyeliaan pihak berkuasa ke atas perkhidmatan dalam talian. Yang wajar ditonjolkan khususnya ialah huraiannya tentang bidang kuasa tempatan pihak berkuasa. Berdasarkan undang-undang tertentu, penulis berjaya menunjukkan penyelesaian yang mungkin bagi percanggahan antara bidang kuasa tempatan yang terhad dan kehadiran perkhidmatan dalam talian di seluruh dunia.)*

Sumber: [Verlag Dr. Kovač](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm).

</details>

Berdasarkan fail ini, penulis memang menemui penyelesaian, untuk GDPR juga: seorang peguam memutuskan siapa yang berhak ke atas datanya sendiri dan siapa yang tidak. Undang-undang mana yang perlu digunakan untuk menyempitkan peraturan Eropah demi kepentingan satu syarikat Amerika, kami tidak tahu. Satu penyelesaian yang mungkin ialah memproses permintaan GDPR itu secara sah. Tetapi penulis itu sudah pun doktor.

### Tiga cara mengendalikan permintaan akses dengan salah

Setakat yang kami, bukan peguam, dapat membaca Peraturan itu, ada tiga, dan ketiga-tiganya diambil:

* **Tidak menyerahkan data:** menyalahi undang-undang.
* **Menyerahkannya tidak lengkap:** menyalahi undang-undang.
* **"Membersihkan secara manual" dan membocorkan data pihak ketiga:** dua kali menyalahi undang-undang (`Art. 5(1)(f)`, `Art. 32`).

> [!TIP]
> **Cara keempat:** penuhi sahaja permintaan itu. Itulah satu-satunya cara yang tidak diambil oleh dua doktor undang-undang. Itu bukan nasib malang; itu pilihan.

### Siapa yang bertanggungjawab?

Setakat yang kami lihat, tiada sesiapa: sama ada dari segi kewangan atau peribadi. Anda tidak boleh meninggalkan ulasan untuk mereka. Anda tidak boleh menulis pendapat. Syarikat itu "terdesentralisasi", jadi tiada syarikat lain untuk dihubungi. Dan sebaik sahaja anda menamakan orang yang menandatangani surat bagi pihak syarikat, wakil syarikat itu tiba-tiba menjadi individu persendirian, dengan hak untuk dilupakan yang ditulis untuk individu persendirian, digunakan serta-merta. Namun semua yang dinyahsenaraikan berkaitan kerja profesional mereka. Adakah laporan tentang pelanggaran, atau tentang kecekapan profesional, benar-benar termasuk dalam hak untuk dilupakan? Bagaimana orang ramai sepatutnya membezakan peguam yang baik daripada yang buruk: daripada profil di laman web Taylor Wessing sendiri? Dan bolehkah itu dipercayai, apabila firma itu menyunting sejarahnya sendiri di Wikipedia?

Kami benar-benar tidak faham mengapa fakta sejarah sebuah ijazah kedoktoran dalam topik sempit memberi seseorang hak untuk mematikan hak GDPR. Mungkin kami salah faham. Mungkin Doktor Tobias mengajar pelajarnya sesuatu yang kurang tepat. Atau mungkin itu betul, dan Jerman diam-diam telah meninggalkan GDPR. Atau adakah itu untuk Doktor Tobias putuskan?

Dan mengapa, semata-mata untuk menerbitkan audit kami, pendapat kami dan pengalaman kami (tentang kecekapan, dan tentang risiko kebocoran dalam perisian Doktor Patrick yang terdedah), kami terpaksa membenamkan teks itu ke dalam perisian kami sendiri supaya ia kekal? Kerana itulah semua ini kelihatan kepada kami seperti korporatokrasi. Dan jika orang yang bertanya tidak mendapat apa-apa, untuk apa GDPR? Pendapatan bagi peguam yang tidak tahu menggunakan PDF?

### Kesimpulan kami

Kami bukan pihak dalam pertikaian ini, dan terus terang kami sudah penat dengannya. Dalam tempoh ini kami telah melihat segalanya: sejarah Wikipedia yang dipadam dua kali, kanak-kanak dalam laporan, permintaan GDPR yang tidak pernah diproses, hak untuk dilupakan yang digunakan untuk diri sendiri, pengasas yang membantu menulis versi Nazi §175, dan struktur "terdesentralisasi" di mana tanggungjawab bukan milik sesiapa. Daripada pengalaman kecil kami, kesimpulannya menyedihkan: gelaran tetap gelaran. Tanggungjawab di pihak peguam: sifar. Yang tinggal ialah keangkuhan, dan GDPR yang tidak dipatuhi. Kami cuma bertanya apa yang dibeli Valve, kerana jelas sekali ia bukan pemprosesan GDPR.

---

Oleh kerana para peguam menganggap merekalah undang-undang, dan nyawa manusia, nyawa kanak-kanak, tidak penting, itu pilihan mereka. Ini bukan konflik kami. Tetapi kami boleh mengatakan dengan yakin bahawa kekebalan firma ini disahkan dari segi sejarah, sejak pengasasnya Goltz, salah seorang daripada lapan yang merangka pindaan §175, dan sejak satu-satunya kesnya yang terkenal, yang kadangkala dibaca sebagai pembelaan terhadap golongan LGBT: kes Jeneral von Fritsch.

<details>
<summary><b>Sejarah: Goltz, §175 dan kes Fritsch</b></summary>

Kami langkau sejarahnya; kami mengkajinya terus daripada sumber yang boleh dipercayai dan rekod asal. Tetapi beginilah kes itu berakhir: ada seorang tertuduh, dan kita ada tiga yang mati. Achim von Frisch, dihancurkan oleh batu kisar penindasan. Otto Schmidt, ditembak mati pada 1943. Dan Jeneral Fritsch sendiri: tidak penting bahawa dia dibebaskan, harganya tinggi. Pada 1939, mencari maut, dia menawarkan diri secara sukarela ke barisan hadapan di Poland dan terbunuh (atau membiarkan dirinya dibunuh).

Sudah tentu, kami tidak pernah mengira kes ini sebagai pembelaan pengasas firma terhadap golongan LGBT. Tetapi kesudahannya jauh lebih menarik daripada sebuah kemenangan.

**Keadilan asimetri:** Goltz memang menyelamatkan seorang pegawai berpangkat tinggi, yang kesalahannya direka sepenuhnya oleh Gestapo. Tetapi alibi ini dibayar dengan darah orang lain. Goltz yang sama, sebagai ahli Suruhanjaya Undang-undang Jenayah sejak 1933, secara peribadi mereka bentuk dan memperkenalkan versi Nazi Perenggan 175 (1935).

**Statistik berbanding PR:** Dia membela seorang jeneral heteroseksual daripada golongan elit Wehrmacht selepas terlebih dahulu menggerakkan tali sawat undang-undang yang menghantar kira-kira 50,000 homoseksual sebenar ke penjara dan kira-kira 15,000 ke kem tahanan, dengan kadar kematian 60%. Menyelamatkan seorang jeneral tidak membatalkan seni bina pembunuhan beramai-ramai.

**Denazifikasi, berjaya dielakkan:** Kes Fritsch menjadi "pintu belakang" yang sempurna melalui panel denazifikasi selepas perang. Arkitek undang-undang yang menindas itu menggunakan pembelaannya terhadap seorang jeneral sebagai bukti "kebebasannya", terlepas daripada Nuremberg, mengekalkan status dan lesennya, dan pada 1957 mengasaskan firma yang hari ini memperdagangkan sifat progresifnya di bawah papan tanda Taylor Wessing.

</details>

Jadi ya, secara keseluruhan: kami pasti tiada bezanya sama ada Taylor Wessing Jerman ini atau yang lain; ini langsung bukan soal undang-undang. Apa yang kami katakan di sini ialah satu kenyataan, bukan penegasan fakta tetapi andaian, kerana hakikatnya mereka akan mencari apa-apa perkataan untuk dijadikan pegangan. Sebab itulah ini dihantar ke arkib: percubaan menapis dan menyembunyikan, serta kaitan langsung dengan warisan mereka. Daripada Doktor Patrick: laporan yang paling pertama, dengan perkataan homofobik kasar yang dibiarkan. Mungkin secara tidak sengaja, sudah tentu, tetapi ia ada di sana, dan ia yang pertama.

Daripada Doktor Tobias, kami tentunya mengharapkan kuliah tentang bukti yang tidak dapat disangkal dalam bentuk kiraan laporan, dan penjelasan bahagian mana daripada satu perempat itu yang tidak penting baginya secara peribadi. Untuk sejarah, dan untuk memahami di mana batasnya, ini penting.

Hakikat bahawa Steam bertindak sebagai pengawal data dan bukannya menyederhana hanya menunjukkan perkara yang jelas: Doktor Patrick yang membocorkannya. Ya, begitulah jadinya. Nampaknya dia tidak tahu bahawa perisian untuk pelekat itu rosak, memandangkan mereka doktor terulung, dan Steam tidak membayar untuknya: sama ada untuk memproses permintaan GDPR atau tidak, dan kemudian menutup kebocoran yang telah dilihatnya.

Kami menyeru kewarasan dalam berurusan dengan kebenaran, dan ingin mengingatkan semua orang tentang zero trust: terhadap semua orang, termasuk kami. Semuanya persekitaran yang bermusuhan, dan dalam konteks ulasan ini secara literal: sekatan pada 9 Mei, Nazi, doktor, golongan LGBT, kanak-kanak. Seronok.

Tetapi pilihan kami berkenaan Taylor Wessing kemungkinan besar sudah habis, kerana strategi mereka ialah membuang pautan. Kami terpaksa memelihara teks dan data kami, jadi kami menyepadukannya ke dalam perisian kami, yang sudah mempunyai tiga surat penghargaan yang disahkan daripada badan kerajaan, termasuk di Jerman dan Belgium, walaupun ia belum pun dikeluarkan.

Kami ingin memberi amaran kepada mereka yang suka membengkokkan undang-undang: tidak perlu menurunkan repositori. Sepanjang masa ini kami tidak pernah berkonflik dengan anda. Tetapi jika anda memutuskan untuk merosakkan kerja kami bagi menyembunyikan kebenaran, maka tanpa repositori yang aktif, pengawal selia dan pihak lain tidak akan dapat membandingkan tandatangan sesuatu versi (walaupun kepada siapa saya memberitahu ini), dan ketika itulah kami akan memasuki konflik langsung. Dengan itu, kami berharap dapat mengucapkan selamat tinggal kepada kepakaran mega dan peguam elit. Ia tidak seronok, dan saya tidak gembira. Semoga berjaya.

> [!CAUTION]
> **Menurunkan repositori ini tidak akan memadam apa-apa.** Penyiasat dan penyelidik menggunakan TgWitness, dan salinan mereka disahkan berbanding repositori ini. Kami ada sandaran. Tetapi penurunan akan mengubah kami daripada juruaudit satu kes menjadi pihak dalam konflik. Cukuplah memadam kebenaran.

[Rekod sumber](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Notis pengendali](OPERATOR-INCOMPATIBILITY.md) · [Lesen MIT](../../LICENSE)

[Projek](../../README.md) · [Dokumentasi](README.md) · [Wiki](../wiki/Home.md)
