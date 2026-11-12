[TgWitness](../../README.md) / [Tài liệu](README.md) · [Thông báo dành cho người vận hành](OPERATOR-INCOMPATIBILITY.md)

![Hồ sơ GDPR 106 ngày](../assets/presentation/chapter-gdpr-file.svg)

# Valve, Taylor Wessing và 106 ngày chờ đợi theo GDPR: phân tích hồ sơ và 70.717 từ của nó

[Bản ghi nguồn](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Thông báo dành cho người vận hành](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

Chúng tôi còn lại những câu hỏi sẽ không bao giờ được trả lời, vì chúng tôi không phải là một bên trong tranh chấp. Không người bình thường nào có thể chịu đựng việc mỗi lần chờ một trăm ngày và đối đầu với những luật sư tinh hoa được các tập đoàn tài trợ thông qua những "sàn freelance" như thế này. Chúng tôi sẽ không bao giờ biết dịch vụ mà Valve đặt hàng thực ra tên là gì. Nhìn từ bên ngoài, nó giống như một hoạt động xử lý theo GDPR không hoàn toàn hợp pháp, và một lần cung cấp dữ liệu mà trong đó những người báo cáo không bị bôi đen mà bị làm lộ, trong khi ít nhất 5.000–10.000 trang của chính dữ liệu bị thiếu: thứ được xuất ra không phải nhật ký người dùng, mà là một nhật ký bị cắt gọt làm cho bên thuê ngoài. Tranh cãi điều đó là vô ích. Một lớp thông tin khổng lồ khách quan là không có, cũng như không có gì xác nhận lời của bất kỳ ai trong hai luật sư.

Valve trả bao nhiêu cho một dịch vụ gồm trì hoãn, bôi đen thủ công và chữ ký của một Tiến sĩ dưới một báo cáo kỳ thị đồng tính và một tệp PDF hỏng? Đây không phải vụ việc của chúng tôi, nhưng vấn đề ở đây rõ ràng không phải là luật; đó là địa vị và sự miễn trừ trách nhiệm. Danh xưng "Tiến sĩ" tự động biến một người thành người quyết định điều gì được coi là bằng chứng không thể bác bỏ, và một người khác thành người được cho là hiểu về con số và PDF (dù trên thực tế thì không).

---

## 1. Các ngày tháng, lời của Tiến sĩ và một báo cáo không có khoản thanh toán nào

Phần đầu tài liệu ghi `Date of Report: 09-29-2025`, còn bản thân các tệp được bàn giao vào ngày 1 hoặc 2 tháng 10. Nhưng chúng tôi không tin những ngày này. Chúng tôi tin vào tuyên bố trực tiếp của **Dr. Patrick Vincent Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“
>
> *(Việc tổng hợp dữ liệu cá nhân của thân chủ quý vị rất tiếc đã chiếm trọn thời hạn một tháng, vì một lần kiểm tra lại cho thấy rằng cả sau ngày 3 tháng 5 năm 2025 vẫn có các khoản thanh toán mới do một bên thứ ba thực hiện qua tài khoản, vì vậy dữ liệu phải được làm sạch thủ công.)*

Chính câu này khiến chúng tôi thôi tin vào các con số, vào lời của tiến sĩ trong đoạn đầu và vào chữ ký của ông. Tất nhiên, một tiến sĩ sẽ không nói dối; ông ấy có thứ để mất, phải không? Chỉ là, khi tệp được xuất ra và các hình vector bị gỡ bỏ, không một khoản thanh toán nào xuất hiện trong báo cáo. Chúng tôi không tranh cãi công việc của Dr. Patrick hay sự chậm trễ của ông. Chúng tôi chỉ đơn giản tin và chấp nhận "sự thật của Tiến sĩ", và ghi lại những gì có thể thấy trong chính tệp.

---

## 2. 36 giây và nhãn dễ bị tổn thương "Anlage 1 / Taylor Wessing"

Chúng tôi không phải chuyên gia về bất cứ điều gì, có lẽ vì vậy mà thông báo lỗ hổng của chúng tôi bị cả nền tảng freelance lẫn vị tiến sĩ phớt lờ. Logic khá rõ ràng: họ chính là luật, họ có thể có lỗ hổng gì chứ?

Nhưng hãy gác lại lời của Tiến sĩ và nhìn vào kỹ thuật. Chúng tôi dựng một môi trường Windows tương đương, lấy tệp đã làm sạch và thử đặt các hình. Đặt thủ công hàng trăm hình đen trong **36 giây**, đúng bằng thời lượng của phiên đã ghi, theo chúng tôi là không thể; xét mọi dấu hiệu, các ô đen đã có sẵn trên tài liệu. Chúng tôi nghiêng về quan điểm rằng trong 36 giây đó đúng một đối tượng đã được thêm vào, ở góc trên bên phải trang 1: nhãn `"Anlage 1 / Taylor Wessing"`. Và chính phần mềm đã đặt nó mới là thứ có lỗ hổng:

* **Đối tượng, theo các điểm đánh dấu:** từ `(929, 294)` đến `(1139, 372)`, tức là `210 × 78 px`, tâm vào khoảng `(1034, 333)`.
* **Khung nhìn thấy:** từ `(936, 300)` đến `(1133, 367)`, khoảng `197 × 67 px`, tỷ lệ khoảng `3 : 1`; mép trên của trang ở `y ≈ 275`.
* **Tỷ lệ:** đo theo thước bên trái của tài liệu, `1 cm ≈ 82 px` (thước gần như chắc chắn tính bằng centimet; nếu tính bằng inch thì trang sẽ rộng hơn `15″`).

Kiểu dáng và hình thức của huy hiệu khớp với tệp được trả lại. Nhưng nếu không có quyền truy cập vào môi trường soạn thảo gốc, hoặc không biết định dạng ban đầu (nếu đã có chuyển đổi), thí nghiệm không thể sạch, nên chúng tôi không thể khẳng định điều này với độ chắc chắn 100%.

---

## 3. Trang 444: thời gian bị ẩn và phép tính số học của các báo cáo

Các báo cáo bắt đầu từ trang 444, bao gồm cả báo cáo kỳ thị đồng tính đó. Một điểm quan trọng:

* Trên những báo cáo mà họ chọn hiển thị (những báo cáo có lợi cho luật sư), trường **`Time of Report`** đã bị cố ý ẩn thêm, chồng lên mọi thứ khác. Không có thời gian chính xác, và đây là thứ duy nhất trong toàn bộ tệp được ẩn theo cách đúng về mặt kỹ thuật.
* Trong bài viết chính, chúng tôi đã so sánh về mặt toán học các báo cáo được hiển thị với phần còn lại, theo nội dung, văn phong và biệt danh. Gần như ở khắp nơi, công thức tạo tên tiêu chuẩn của Reddit bị tái sử dụng một cách thô thiển, và có một đỉnh tăng vọt đúng trong khoảng cần thiết. Chúng tôi không nói rằng các báo cáo bị làm giả, nhưng chúng tôi nói rằng các tài khoản có lẽ không có thật, và phần lớn trong số đó về mặt toán học giống một botnet.

---

## 4. Một câu hỏi dành cho Dr. Patrick Zurheide về các mục `2025-02-03 16:29:23` và `2025-04-02 15:55:19`

Tiến sĩ Patrick, ông đã viết rằng ông đọc câu đùa kỳ thị đồng tính và quyết định tự mình đùa lại. Được thôi, rất buồn cười. Những báo cáo khác, như đồng nghiệp của ông nói, không quan trọng về thực chất (*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…“*). Được thôi, chúng tôi bỏ qua chúng. Chúng tôi hy vọng **Tiến sĩ Tobias** sẽ giải thích cho sinh viên của mình trong một bài giảng vì sao một phần tư ngẫu nhiên của 1.938 báo cáo (485 báo cáo), đầy những lời mong người khác chết và những phát ngôn Quốc xã, lại không quan trọng, và chính xác là không quan trọng với ai. Nếu ông làm vậy, chúng tôi sẽ lập tức thừa nhận mình sai, xin lỗi và xóa các đề cập.

Hãy gọi đúng tên sự việc: các ông đã cố ý trao dữ liệu của những kẻ thù ghét, những người Nga, người Đức, tất cả bọn họ, cho chính người mà họ thù ghét, và điều này xảy ra giữa hai quốc gia đang có chiến tranh với nhau. Hóa ra các ông đã dâng cho hắn những đứa trẻ Nga: hắn rất thích thú, còn Tobias thì chỉ thẳng vào chúng như là vấn đề. Nhưng thực ra đây là vụ rò rỉ của các ông; chỉ là những đứa trẻ không phải con của các ông.

Tuy nhiên, câu hỏi của chúng tôi liên quan đến một người dùng khác, người không thể nào bị bỏ sót:

* **`2025-02-03 16:29:23`**: một đường liên kết và một người từ cùng một quốc gia, với những điều rất nghiêm trọng được viết ở đó, nổi bật ngay lập tức;
* **`2025-04-02 15:55:19`**: một tham chiếu trực tiếp, một cái tên cụ thể và những gì người đó viết.

Chúng tôi đã kiểm tra: đó đúng là những gì nó trông như vậy. Các ông đã công khai đặt dữ liệu nhà nước và thông tin cá nhân đầy đủ vào tay một người mà chính các ông coi là tội phạm. Lẽ ra không được làm điều này, dù chỉ vì bối cảnh. Chuyện gì xảy ra nếu hắn viết vào đó? Về phía các ông, đây không chỉ là thấp hèn; đó là sự coi thường trắng trợn tính mạng và sức khỏe của con người. Trong khi điều tra, chúng tôi đã ngăn chặn người này và đảm bảo an toàn cho mọi người. Nhìn chung, đây là lời phàn nàn thực sự duy nhất của chúng tôi; mọi thứ khác chỉ đơn giản là sự thật và một minh chứng về cách các luật sư tinh hoa làm việc. Chúng tôi kêu gọi Tiến sĩ Patrick chịu trách nhiệm thích đáng về việc này, trừ khi, tất nhiên, danh xưng trước tên ông cho phép ông hành động như vậy (chúng tôi không phải luật sư và không biết luật).

---

## 5. Gửi công chúng, công ty bảo hiểm, cơ quan quản lý và các công ty Hoa Kỳ

* **Gửi công chúng và khách hàng của Taylor Wessing:** Xét theo sự cẩu thả, Taylor Wessing có một công ty bảo hiểm hào phóng coi tất cả những điều này là bình thường. Hãy kiểm tra các tệp của bạn và thông báo cho cơ quan quản lý. Không cần nói với chính các luật sư: họ đã chọn che giấu điều này hơn một năm, kể từ khi Valve lần đầu tìm đến họ.
* **Gửi các cơ quan quản lý, về lỗ hổng của mọi tệp:** Hãy xem xét hoạt động của Dr. Patrick và yêu cầu mọi tệp PDF đi qua tay ông có huy hiệu `"Anlage 1 / Taylor Wessing"` (hoặc tương tự) đặt ở đầu trang đầu tiên. Xác suất đây không phải là trường hợp cá biệt, và mọi tài liệu của ông mang nhãn dán này đều có lỗ hổng, là cực kỳ cao.
* **Gửi công ty bảo hiểm:** Vui lòng kiểm toán khách hàng của quý vị và phần mềm mà ông ấy dùng để xử lý PDF và đặt nhãn `"Anlage 1 / Taylor Wessing"` ở đầu trang 1. Rất có thể vấn đề nằm chính ở đó, và đây không phải trường hợp cá biệt. Kêu gọi kiểm toán toàn bộ Taylor Wessing là vô ích: ngoài cái tên, họ dường như không có điểm chung nào về môi trường làm việc hay quy tắc rà soát bảo mật, những thứ lẽ ra phải tự nhiên tồn tại (có vẻ một chiếc khóa ký vật lý và danh xưng trước tên đã bao trùm tất cả).
* **Gửi các công ty Hoa Kỳ, và bất kỳ ai ở Ủy ban châu Âu tình cờ đọc được điều này:** Hãy thử đơn giản là tuân thủ pháp luật. Thuê những tiến sĩ danh tiếng từ một "công ty freelance" danh tiếng trông vừa nguy hiểm vừa hết sức hèn hạ đối với khách hàng của các bạn. Nếu ở Valve séc chỉ đơn giản được ký và không ai kiểm tra các luật sư đã làm gì trong 106 ngày, thì có lẽ việc trả tiền cho thời gian bị kéo dài thay vì cho kết quả chính là lý do phần mềm lỗi thời và không ai hiểu PDF hoạt động thế nào. Và nếu ở đó không có vụ rò rỉ nào khác, thì Tiến sĩ Patrick chỉ đơn giản là đã làm mọi người kiệt sức bằng sự chờ đợi hoặc đe dọa. Về bản chất, thứ được bán là một dịch vụ không tuân thủ GDPR: thực hiện kém chất lượng và đe dọa ("các anh sẽ không thắng nổi một vụ nào"), kết hợp với việc dọn dẹp kết quả Google chất lượng cao được thực hiện dưới chính tên của họ. Chúng tôi không soạn thảo văn bản pháp lý và không buộc tội ai. Chúng tôi chỉ viết những gì chúng tôi đã thấy, và những gì họ đang cố gắng hết sức để xóa.

---

## 6. Thứ Valve mua không phải là việc xử lý theo GDPR

Chúng tôi không phải một bên của tranh chấp và chúng tôi không bênh vực tài khoản hay lệnh cấm. Chỉ còn một câu hỏi. Valve đã thuê những luật sư hàng đầu: hai tiến sĩ danh tiếng từ một "công ty freelance" danh tiếng, **Dr. Tobias Schelinski** (`Doc. No. 42282474`, ngày 15 tháng 8 năm 2025) và **Dr. Patrick Vincent Zurheide** (`Doc. No. 42603633`, ngày 1 tháng 10 năm 2025). Valve đã trả tiền cho cái gì? Không phải cho việc xử lý theo GDPR: yêu cầu đã không được đáp ứng khi đó và đến nay vẫn không được đáp ứng.

### Thứ được giao thay vào đó, bằng chính lời của họ

* **Một thời hạn "nếu có":** *„wenn überhaupt“* — Tiến sĩ Tobias.
* **Đòi dữ liệu của mình, mất tài khoản của mình:** chấm dứt *„mit sofortiger Wirkung“*, để đáp lại một yêu cầu truy cập dữ liệu — Tiến sĩ Tobias.
* **Chứng minh bằng số lượng:** *„Unabhängig von den Einzelheiten der Beschwerden…“* Nội dung không quan trọng, cứ đếm hết — Tiến sĩ Tobias.
* **Một chẩn đoán dành cho người yêu cầu:** *„…Ihr Mandant bzw. dessen Komplizen…“* — Tiến sĩ Patrick.
* **Một phán quyết thay cho mọi tòa án:** *„Aus unserer Erfahrung wird jedes Gericht…“* — Tiến sĩ Patrick. Chưa tòa án nào phán quyết; chúng tôi tưởng tòa án sinh ra là để làm việc đó.
* **Bốn điều của Bộ luật Hình sự:** `§§ 263, 263a, 202a, 303a StGB`, vì đã đòi dữ liệu của chính mình.
* **Thay cho dữ liệu:** năm trang Chính sách quyền riêng tư công khai của Steam, một bản sao Dashboard mà người dùng vốn đã thấy, và một câu trả lời đã dịch của Bộ phận hỗ trợ Steam. Hai tiến sĩ luật đã giao lại thứ mà một nhân viên hỗ trợ đã viết từ trước.
* **Một giấy nợ viết tay:** *„Gerne beauskunften wir die restlichen … Daten, sobald …“* Phần còn lại, một ngày nào đó.
* **Bảo vệ bên thứ ba bằng cách làm lộ họ:** dữ liệu về lệnh cấm bị giữ lại "để bảo vệ bên thứ ba", còn dữ liệu của bên thứ ba thì được gửi đi trong một tệp PDF mà các ô đen gỡ ra được.
* **Hai phiên bản sự thật:** một tiến sĩ tính người dùng từ tháng 5 năm 2025, người kia từ năm 2019. Cả hai đều ký. Một tiến sĩ sẽ không ký điều sai sự thật, nên chúng tôi chấp nhận cả hai.
* **Chính tả cao cấp:** *„Die Antwortet lautet ja“*, hai lần, và chính địa chỉ e-mail của vị luật sư thành viên bị viết sai trong chữ ký của chính ông.

### Không phải sai sót

> [!IMPORTANT]
> Sai sót thường được giấu đi. Ở đây không ai thèm thử. **Thứ đang được bán là sự không tuân thủ GDPR, và nó được bán công khai.** Đó không phải sai sót; đó là sự kiêu ngạo.

### Cho chính họ, cho người dùng, và cho tất cả những người khác

* **Cho chính họ:** gỡ khỏi kết quả tìm kiếm theo `Art. 17`. Tiến sĩ Patrick nộp trước; chúng tôi đăng Phần 3 trên Medium; ngay sau đó, các kết quả về Tiến sĩ Tobias cũng bị gỡ.
* **Cho chủ thể dữ liệu:** mười bảy tháng và vẫn đang đếm.
* **Không có luật sư:** Bộ phận hỗ trợ Steam đã đóng yêu cầu của một chủ tài khoản khác trong **3 ngày**, kèm đường dẫn tới Account Data: *"there's no further information Steam Support can offer, this request will be closed"* (phiếu `HT-2YBP-F7JP-D4VB`; ảnh chụp màn hình của người yêu cầu, [Mục 18 của hồ sơ Steam](https://phishdestroy.io/steam_dossier/#gdpr-live-case)).
* **Có luật sư:** cùng một phiếu đã đóng đó, trong **106 ngày**, trên giấy tiêu đề. Ai đã cho phép Valve hoàn toàn không xử lý các yêu cầu GDPR? Tiến sĩ Tobias chăng?

### Học vị

Chúng tôi gọi họ là "Tiến sĩ" từ đầu đến cuối, và chúng tôi nói điều đó với sự tôn trọng: học vị là một sự thật lịch sử. Học vị của Tiến sĩ Tobias dựa trên [một nghiên cứu năm 2005 về cách các cơ quan Đức giám sát dịch vụ trực tuyến nước ngoài](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm); của Tiến sĩ Patrick dựa trên [một nghiên cứu năm 2020 về hợp đồng phát triển phần mềm theo Scrum](https://books.google.pl/books/about/Herausforderungen_bei_einer_Softwareentw.html?id=uh4PzgEACAAJ&redir_esc=y). Mỗi cái là một nghiên cứu hẹp, về một chủ đề hẹp, làm một lần. Đó không phải là chuyên môn về bảo vệ dữ liệu, về tệp PDF, hay về điều mà mọi tòa án sẽ quyết định. Dưới những học vị ấy, trong hồ sơ này: không có giám sát nào, và một tệp PDF được tạo bằng `Aspose.PDF for .NET 20.8` từ năm 2020.

Chúng tôi chưa đọc luận án nào trong hai luận án, của Tiến sĩ Tobias hay của Tiến sĩ Patrick. Chúng tôi đã đọc phần giới thiệu của nhà xuất bản về luận án của Tiến sĩ Tobias. Năm 2005 dĩ nhiên chưa có GDPR. Nhưng nghe như thể giải pháp đã có từ hồi đó.

<details>
<summary><b>Phần giới thiệu của nhà xuất bản về luận án của Tiến sĩ Tobias (bản gốc tiếng Đức và bản dịch)</b></summary>

> „Darüber hinaus geht der Autor auf Probleme ein, die sich aus der Durchführung der behördlichen Aufsicht über die Online-Dienste ergeben. Hier sind insbesondere die Ausführungen über die örtliche Zuständigkeit von Behörden hervorzuheben. Dem Autor gelingt es insoweit, anhand einzelner Gesetze Lösungsmöglichkeiten aufzuzeigen wie der Gegensatz einer beschränkten örtlichen Zuständigkeit im Verhältnis zu der weltweiten Präsenz von Online-Diensten zu lösen ist.“
>
> *(Ngoài ra, tác giả bàn đến những vấn đề phát sinh từ việc thực hiện giám sát của cơ quan nhà nước đối với các dịch vụ trực tuyến. Đặc biệt đáng chú ý là những phân tích về thẩm quyền theo lãnh thổ của các cơ quan. Dựa trên từng đạo luật cụ thể, tác giả đã chỉ ra được các giải pháp khả dĩ cho mâu thuẫn giữa thẩm quyền theo lãnh thổ có giới hạn và sự hiện diện toàn cầu của các dịch vụ trực tuyến.)*

Nguồn: [Verlag Dr. Kovač](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm).

</details>

Xét theo hồ sơ này, tác giả quả thực đã tìm ra một giải pháp, cho cả GDPR: một luật sư quyết định ai có quyền với dữ liệu của chính mình và ai thì không. Cần dùng những đạo luật nào để thu hẹp một quy định của châu Âu vì lợi ích của một công ty Mỹ duy nhất, chúng tôi không biết. Một giải pháp khả dĩ lẽ ra là xử lý yêu cầu GDPR một cách hợp pháp. Nhưng tác giả thì đã là tiến sĩ rồi.

### Ba cách làm sai một yêu cầu truy cập

Trong chừng mực chúng tôi, những người không phải luật sư, đọc được Quy định, có ba cách, và cả ba đều đã được dùng:

* **Không giao dữ liệu:** trái luật.
* **Giao không đầy đủ:** trái luật.
* **"Làm sạch thủ công" và làm lộ dữ liệu của bên thứ ba:** trái luật hai lần (`Art. 5(1)(f)`, `Art. 32`).

> [!TIP]
> **Cách thứ tư:** đơn giản là đáp ứng yêu cầu. Đó là cách duy nhất mà hai tiến sĩ luật đã không chọn. Đó không phải xui xẻo; đó là một lựa chọn.

### Ai chịu trách nhiệm?

Theo những gì chúng tôi thấy, không ai cả: cả về tài chính lẫn cá nhân. Bạn không thể để lại đánh giá cho họ. Bạn không thể viết một ý kiến. Công ty thì "phi tập trung", nên không có công ty nào khác để gửi đến. Và ngay khi bạn nêu tên những người đã ký thư thay mặt công ty, các đại diện của công ty bỗng trở thành cá nhân, với quyền được lãng quên vốn viết cho cá nhân, được áp dụng tức thì. Thế nhưng mọi thứ bị gỡ đều liên quan đến công việc chuyên môn của họ. Một bản tường thuật về vi phạm, hay về năng lực chuyên môn, có thật sự thuộc phạm vi quyền được lãng quên? Người ta phải phân biệt luật sư giỏi với luật sư kém bằng cách nào: bằng hồ sơ trên chính trang web của Taylor Wessing? Và có thể tin vào đó không, khi hãng tự sửa lịch sử của mình trên Wikipedia?

Chúng tôi đơn giản là không hiểu vì sao sự thật lịch sử về một học vị tiến sĩ trong một chủ đề hẹp lại cho ai đó quyền tắt các quyền theo GDPR. Có lẽ chúng tôi hiểu sai. Có lẽ Tiến sĩ Tobias dạy sinh viên của mình điều gì đó không hẳn đúng. Hoặc có lẽ điều đó đúng, và nước Đức đã lặng lẽ từ bỏ GDPR. Hay việc đó là do Tiến sĩ Tobias quyết định?

Và tại sao, chỉ để công bố bản kiểm toán, ý kiến và kinh nghiệm của chúng tôi (về năng lực, và về rủi ro rò rỉ trong phần mềm có lỗ hổng của Tiến sĩ Patrick), chúng tôi lại phải nhúng văn bản vào chính phần mềm của mình để nó tồn tại? Chính vì thế mà tất cả những điều này trông với chúng tôi như một chế độ tập đoàn trị. Và nếu người hỏi chẳng nhận được gì, thì GDPR để làm gì? Để làm doanh thu cho những luật sư không biết dùng PDF?

### Kết luận của chúng tôi

Chúng tôi không phải một bên của tranh chấp này, và thật lòng mà nói chúng tôi đã mệt mỏi vì nó. Trong thời gian đó chúng tôi đã xem xét mọi thứ: lịch sử Wikipedia bị xóa hai lần, những đứa trẻ trong các báo cáo, một yêu cầu GDPR chưa bao giờ được xử lý, quyền được lãng quên được dùng cho chính mình, một nhà sáng lập đã góp tay viết phiên bản Quốc xã của §175, và một cấu trúc "phi tập trung" nơi trách nhiệm không thuộc về ai. Từ kinh nghiệm nhỏ của chúng tôi, kết luận thật đáng buồn: học vị vẫn chỉ là học vị. Trách nhiệm từ phía luật sư: bằng không. Những gì còn lại là sự kiêu ngạo, và một GDPR không được tuân thủ. Chúng tôi chỉ hỏi Valve đã mua gì, vì rõ ràng đó không phải là việc xử lý theo GDPR.

---

Vì các luật sư nghĩ rằng họ là luật, và tính mạng con người, tính mạng trẻ em, không quan trọng, đó là lựa chọn của họ. Đây không phải xung đột của chúng tôi. Nhưng chúng tôi có thể tự tin nói rằng sự miễn trừ trách nhiệm của hãng được xác nhận về mặt lịch sử, từ người sáng lập Goltz, một trong tám người soạn thảo các sửa đổi của §175, và từ vụ án nổi tiếng duy nhất của ông, đôi khi được hiểu là sự bảo vệ người LGBT: vụ án Tướng von Fritsch.

<details>
<summary><b>Lịch sử: Goltz, §175 và vụ Fritsch</b></summary>

Chúng tôi sẽ bỏ qua phần lịch sử; chúng tôi đã nghiên cứu trực tiếp từ một nguồn đáng tin cậy và hồ sơ gốc. Nhưng vụ án đã kết thúc như thế này: có một bị cáo, và chúng ta có ba người chết. Achim von Frisch, bị nghiền nát dưới cối xay đàn áp. Otto Schmidt, bị xử bắn năm 1943. Và chính Tướng Fritsch: việc ông được tha bổng không quan trọng, cái giá rất đắt. Năm 1939, tìm đến cái chết, ông tình nguyện ra mặt trận ở Ba Lan và tử trận (hoặc để mình bị giết).

Tất nhiên, chúng tôi chưa bao giờ coi vụ án này là sự bảo vệ người LGBT của người sáng lập hãng. Nhưng kết cục thú vị hơn nhiều so với một chiến thắng.

**Công lý bất đối xứng:** Goltz quả thực đã cứu một sĩ quan cấp cao, người có tội danh hoàn toàn do Gestapo bịa đặt. Nhưng chứng cứ ngoại phạm này được trả bằng máu của người khác. Cũng chính Goltz, với tư cách thành viên Ủy ban Luật Hình sự từ năm 1933, đã đích thân thiết kế và ban hành phiên bản Quốc xã của Điều 175 (1935).

**Thống kê đối đầu với quan hệ công chúng:** Ông bảo vệ một vị tướng dị tính thuộc giới tinh hoa Wehrmacht sau khi trước đó đã khởi động một dây chuyền pháp lý đưa khoảng 50.000 người đồng tính thực sự vào tù và khoảng 15.000 người vào trại tập trung, với tỷ lệ tử vong 60%. Cứu một vị tướng không xóa bỏ được kiến trúc của tội diệt chủng.

**Phi Quốc xã hóa, được lách qua thành công:** Vụ Fritsch trở thành "cửa hậu" hoàn hảo để đi qua các hội đồng phi Quốc xã hóa thời hậu chiến. Kiến trúc sư của các đạo luật đàn áp đã dùng việc bảo vệ một vị tướng làm bằng chứng cho "sự độc lập" của mình, thoát khỏi Nuremberg, giữ được địa vị và giấy phép hành nghề, và năm 1957 thành lập văn phòng mà ngày nay đang kinh doanh sự cấp tiến của mình dưới tấm biển Taylor Wessing.

</details>

Vậy đúng thế, tóm lại: chúng tôi chắc chắn rằng không có gì khác biệt dù đó là Taylor Wessing Đức này hay bất kỳ hãng nào khác; chuyện này hoàn toàn không phải về pháp luật. Những gì chúng tôi nói ở đây là một phát biểu, không phải khẳng định về sự thật mà là một giả định, vì trên thực tế họ sẽ tìm bất kỳ từ nào để bám vào. Đó là lý do điều này được đưa vào kho lưu trữ: những nỗ lực kiểm duyệt và che giấu, và các mối liên hệ trực tiếp với di sản của họ. Từ Tiến sĩ Patrick: báo cáo đầu tiên nhất, với từ ngữ kỳ thị đồng tính thô tục bị để nguyên. Có lẽ do vô tình, tất nhiên, nhưng nó ở đó, và nó là cái đầu tiên.

Từ Tiến sĩ Tobias, đương nhiên chúng tôi chờ đợi một bài giảng về bằng chứng không thể bác bỏ dưới dạng số lượng báo cáo, và một lời giải thích phần nào trong một phần tư đó không quan trọng với cá nhân ông. Đối với lịch sử, và để hiểu giới hạn nằm ở đâu, điều này quan trọng.

Việc Steam đóng vai trò là bên kiểm soát dữ liệu thay vì kiểm duyệt nội dung chỉ đơn giản chỉ ra điều hiển nhiên: Tiến sĩ Patrick đã làm rò rỉ chúng. Thôi thì, mọi chuyện đã diễn ra như vậy. Có vẻ ông không biết phần mềm dán nhãn bị lỗi, dù sao đây cũng là những tiến sĩ hàng đầu, và Steam không trả tiền cho việc đó: có xử lý yêu cầu GDPR hay không, rồi sau đó che đậy vụ rò rỉ mà ông đã thấy.

Chúng tôi kêu gọi sự tỉnh táo khi đối xử với sự thật, và muốn nhắc mọi người về zero trust: đối với tất cả mọi người, kể cả chúng tôi. Tất cả đều là một môi trường thù địch, và trong bối cảnh bài phân tích này thì theo nghĩa đen: lệnh cấm ngày 9 tháng 5, Quốc xã, tiến sĩ, người LGBT, trẻ em. Thật vui.

Nhưng các lựa chọn của chúng tôi đối với Taylor Wessing rất có thể đã cạn, vì chiến lược của họ là khiến các đường liên kết bị gỡ bỏ. Chúng tôi buộc phải bảo tồn văn bản và dữ liệu của mình, nên chúng tôi tích hợp chúng vào phần mềm của mình, vốn đã có ba thư cảm ơn được xác nhận từ các cơ quan nhà nước, trong đó có ở Đức và Bỉ, và thậm chí còn chưa được phát hành.

Chúng tôi muốn cảnh báo những ai thích bẻ cong pháp luật: không cần phải đánh sập kho mã. Suốt thời gian qua chúng tôi chưa hề xung đột với các bạn. Nhưng nếu các bạn quyết định phá hỏng công việc của chúng tôi để che giấu sự thật, thì khi không có kho mã đang hoạt động, các cơ quan quản lý và những người khác sẽ không thể đối chiếu chữ ký của một phiên bản (dù tôi đang kể cho ai nghe chứ), và khi đó chúng tôi sẽ bước vào xung đột trực tiếp. Với điều đó, chúng tôi hy vọng được chia tay với siêu chuyên môn và các luật sư tinh hoa. Chẳng vui chút nào, và tôi không vui. Chúc mọi điều tốt đẹp.

> [!CAUTION]
> **Gỡ kho lưu trữ này xuống sẽ không xóa được gì.** Các nhà điều tra và nhà nghiên cứu dùng TgWitness, và bản sao của họ được đối chiếu với chính kho lưu trữ này. Chúng tôi có bản sao lưu. Nhưng một lần gỡ xuống sẽ biến chúng tôi từ người kiểm toán một vụ việc thành một bên của cuộc xung đột. Đừng xóa sự thật nữa.

[Bản ghi nguồn](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Thông báo dành cho người vận hành](OPERATOR-INCOMPATIBILITY.md) · [Giấy phép MIT](../../LICENSE)

[Dự án](../../README.md) · [Tài liệu](README.md) · [Wiki](../wiki/Home.md)
