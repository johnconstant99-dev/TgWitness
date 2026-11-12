<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Ngôn ngữ khác</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Lần theo dấu vết. Bảo toàn bằng chứng. Sổ nhật ký có chữ ký liên kết bằng mã băm, điểm kiểm tra được lưu giữ riêng và tệp lưu trữ bằng chứng có thể xác minh.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=vi"><b>Xem bản demo&nbsp;↗</b></a><br><sub>Giao diện thật với bản ghi hư cấu</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Tải xuống và bắt đầu&nbsp;↓</b></a><br><sub>Một lệnh cho Linux, macOS và Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Đọc sổ tay&nbsp;↗</b></a><br><sub>Hướng dẫn điều tra từng bước</sub></td>
</tr>
</table>

<p align="center"><strong>Không gian làm việc tự lưu trữ cho các cuộc điều tra trên Telegram.</strong><br>Lưu cuộc trò chuyện, giữ lại các lần sửa và xóa, xem ai liên hệ với ai<br>và bàn giao bản xuất có chữ ký mà ai cũng kiểm tra được.</p>

<p align="center"><strong>ZERO TRUST.</strong> TgWitness không đứng về phía nào: các bước kiểm tra như nhau áp dụng cho nhà vận hành, cho PhishDestroy và cho bất kỳ ai khác.<br>Chỉ những gì bên thứ ba hoặc toán học xác nhận mới được tính. <a href="../QUESTIONS-AND-CHECKS.md">Câu hỏi và kiểm tra</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.3 · bản tiền phát hành"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Môi trường đã kiểm thử</a> · 25 ngôn ngữ giao diện · 26 ngôn ngữ hướng dẫn</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=vi">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="Bản demo TgWitness đang hoạt động: tin nhắn đã ghi lại, các phiên bản đã lưu và nội dung được giữ lại sau khi bị xóa. Bản ghi minh họa hư cấu.">
</picture>
</a>

<p align="center"><sub>Khám phá giao diện thật với bản ghi hư cấu. Nhấp vào không gian làm việc để dùng thử.</sub></p>

## TgWitness làm được gì

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Giữ lại mọi lần sửa và xóa</a></b><br><sub>Mọi phiên bản của tin nhắn đều được lưu, và văn bản vẫn còn sau thông báo xóa.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Bằng chứng ai cũng kiểm tra được</a></b><br><sub>Bản ghi có chữ ký, liên kết theo chuỗi băm. Người nhận xác minh tệp lưu trữ ngoại tuyến bằng một lệnh.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Nguồn gốc chứng minh được</a></b><br><sub>Nhận qua phiên MTProto đã xác thực của tài khoản và ký ngay khi đến; GitHub Actions và Intel TDX bổ sung chứng thực.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Đo lường ở quy mô lớn</a></b><br><sub>48 tệp lưu trữ đã xác minh với 3,598,381 bản ghi; tám tài khoản thu được 768,007 bản ghi lịch sử với tốc độ 687.5 bản ghi/s.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Xây dựng cho điều tra</a></b><br><sub>Danh sách theo dõi trên văn bản, mã QR và OCR, kiểm tra ví, thẻ đối tượng, Bảng vụ án và gói hồ sơ cho tòa án.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Do bạn tự vận hành</a></b><br><sub>Tự lưu trữ, không có telemetry. Phiên được giữ trong kho dữ liệu được mã hóa; bảng điều khiển lắng nghe trên localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Đã được phát triển và thử nghiệm trong khoảng sáu tháng: trước tiên là bộ thu thập, sổ nhật ký đã được ký và bộ xác minh, sau đó là bảng điều khiển và các mô-đun bổ sung. Kho lưu trữ này được tạo vào ngày 29 tháng 10 năm 2026 để xuất bản, do đó tuổi của nó không phải là tuổi của dự án.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Cài đặt

Đã kèm sẵn Python. Dùng chính các lệnh này để cập nhật.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell hoặc CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Máy chủ Ubuntu: chạy với quyền root. Máy tính để bàn: chạy bằng tài khoản người dùng thông thường. `-ExecutionPolicy Bypass` chỉ áp dụng cho tiến trình PowerShell này.</sub>

Các bản dựng có chữ ký đến từ [quy trình Installer](../../.github/workflows/installer.yml) công khai, và trình cài đặt kiểm tra SHA-256 cùng chữ ký RSA của từng gói trước khi cài đặt.

[Xác minh script trước](../INSTALLATION.md#verify-before-running) · [Thiết lập ban đầu](../SETTINGS.md) · [Bản phát hành](https://github.com/phishdestroy/TgWitness/releases) · [Docker](DEPLOYMENT.md)

<details>
<summary><strong>Cách bảo vệ trình cài đặt và dữ liệu của bạn</strong></summary>

`get.destroy.tools` là trang tải xuống của dự án. [Quy trình Installer](../../.github/workflows/installer.yml)
công khai dựng trang này từ
[`deploy/installer/`](../../deploy/installer/README.md) cho đúng bản sửa đổi `main`,
xuất bản sau khi các bài kiểm thử cài đặt trên Linux và Windows đạt, rồi ký các
script cài đặt và gói ứng dụng bằng khóa phát hành trong
[`release-signing.pub`](../../deploy/installer/release-signing.pub). Trình cài đặt kiểm tra
SHA-256 và chữ ký RSA của gói và tệp khóa phụ thuộc trước khi cài đặt.
Để kiểm tra chính script trước, hãy tải nó xuống cùng chữ ký và chạy
[các lệnh xác minh trước](../INSTALLATION.md#verify-before-running). Khi bản dựng thất bại,
bản tải xuống trước đó được giữ nguyên; các bảng điều khiển đã cài sẽ cập nhật khi bạn chạy lại trình cài đặt.
Các [bản phát hành](https://github.com/phishdestroy/TgWitness/releases) trên GitHub, mã nguồn và
[Docker](DEPLOYMENT.md) là những cách cài đặt khác.

**Phiên và dữ liệu của bạn.** TgWitness chạy trên máy tính hoặc máy chủ của bạn, và bảng điều khiển
mặc định lắng nghe trên localhost. Phiên Telegram, thông tin đăng nhập proxy và mã băm
token truy cập được lưu trong kho dữ liệu được mã hóa của từng không gian làm việc, có thể dùng thêm
[khóa chính bên ngoài](../SECURITY-MODEL.md#external-master-key) tùy chọn. Ứng dụng
không có telemetry. Ứng dụng kết nối tới Telegram và các dịch vụ được dùng trong phần cài đặt:
danh sách MTProxy công khai, proxy của bạn, bộ lưu trữ S3, bot nhân chứng, tổ chức cấp dấu
thời gian, nhà cung cấp AI và webhook. [Sơ đồ hệ thống](../SYSTEM-MAP.md) liệt kê
các kết nối mà tiến trình ứng dụng tạo ra.
Hãy quan sát bằng một [tài khoản Telegram chuyên dụng](https://phishdestroy.github.io/TgWitness/vi/docs/dedicated-account/).

Huy hiệu phiên bản mô tả cây mã nguồn này. Các bản dựng cài đặt được liệt kê trong mục
[Bản phát hành](https://github.com/phishdestroy/TgWitness/releases); một tính năng được hợp nhất vào
`main` sẽ có trong các bản tải xuống đó từ lần phát hành kế tiếp.

[Thiết lập và truy cập bảng điều khiển](../INSTALLATION.md) ·
[Chữ ký và SHA-256](https://get.destroy.tools/#verification) ·
[Cập nhật](../INSTALLATION.md#update-an-existing-installation) ·
[Năng lực hiện tại và tình trạng thẩm định](../STATUS.md) ·
[Chọn phương pháp thu thập](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Bản ghi mà người khác có thể kiểm tra

Kiểm tra mà không cần tài khoản hay cài đặt. Bản mẫu được công bố có kèm trình xác minh riêng:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # trình xác minh nằm sẵn trong tệp lưu trữ
python verify.py tgwitness-demo.zip          # Python 3.11+, chỉ cần `cryptography`
```

Lệnh in ra các bản ghi có chữ ký, mã băm của bản ghi mới nhất, dấu vân tay của người ký và thoát với mã `0`.
Bản mẫu là hư cấu; cùng trình xác minh đó chạy được với mọi bản xuất thật.

Một bản xuất chứa tin nhắn, tệp và trình xác minh. Gửi dấu vân tay khóa của bạn cho người nhận
qua một kênh khác, và họ có thể tự kiểm tra:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Trình xác minh kiểm tra chữ ký, chuỗi sổ nhật ký, danh sách tệp và tệp đính kèm.
Để dùng làm bằng chứng, nó cần dấu vân tay khóa của bạn và một dấu thời gian của bên thứ ba bao phủ
bản ghi cuối cùng, chẳng hạn dấu thời gian RFC 3161 được đối chiếu với chứng chỉ gốc của tổ chức cấp.

**Tin nhắn đến từ đâu.** TgWitness nhận tin nhắn từ Telegram qua phiên MTProto
được mã hóa của tài khoản, giống như các ứng dụng chính thức, và ký từng tin vào
sổ nhật ký ngay khi tin đến. [Ghi lại trên GitHub Actions](../SEALED-ACTIONS.md) và
[Phala Intel TDX](../HIGH-ASSURANCE.md) còn chứng thực trình thu thập đã nhận các tin nhắn đó.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Tin nhắn mới, các lần sửa đã lưu và các quan sát về việc xóa tạo thành một sổ nhật ký có chữ ký, liên kết với nhau. Hãy xác minh bằng một khóa được tin cậy một cách độc lập.">
</picture>

[Xác minh tệp lưu trữ](../wiki/Exports-and-Verification.md) · [Định dạng bằng chứng](../EVIDENCE.md) · [Nhân chứng độc lập](../WITNESS.md) · [Dấu thời gian bên ngoài](../TIMESTAMP.md) · [Các bước kiểm tra và quy mô đã kiểm thử](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Từ một cuộc trò chuyện đến một vụ án

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Ba quy trình động: xuất một cuộc trò chuyện sang HTML và JSON, tìm một liên kết được chia sẻ trong các cuộc trò chuyện đã ghi, và giữ lại các phiên bản đã ghi sau thông báo xóa.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Bản xuất cuộc trò chuyện&nbsp;↗</b></a><br><sub>Một cuộc trò chuyện thành HTML và JSON có chữ ký</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Điều tra&nbsp;↗</b></a><br><sub>Lần theo manh mối qua các cuộc trò chuyện đã ghi</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Phiên bản đã lưu&nbsp;↗</b></a><br><sub>Các lần sửa và thông báo xóa đều được giữ lại</sub></td>
</tr>
</table>

Có hai cách dùng: [xuất tài khoản của bạn](../ACCOUNT-EXPORT.md) một lần, hoặc
[theo đuổi một cuộc điều tra](../INVESTIGATION.md) và liên tục lưu các thay đổi.
Chọn vài cuộc trò chuyện, một thư mục Telegram hoặc toàn bộ tài khoản. Mỗi tài khoản có
không gian làm việc, phiên và khóa ký riêng.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Tìm hiểu thêm

<details>
<summary><strong>Kết quả đo xuất dữ liệu · 6 tháng 11 năm 2026</strong> · 56,329 tin nhắn, cả hai tệp lưu trữ đều đã xác minh</summary>

**56,329 tin nhắn được xuất trong hai lần chạy mới.** Cả hai tệp lưu trữ có chữ ký đều vượt qua bước xác minh với khóa trình thu thập đã ghim.

[![Tốc độ thu thập và tốc độ xuất trọn vẹn đo được](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/vi/docs/validation/)

| Lần chạy | Tin nhắn | Thời gian thu thập | Tốc độ thu thập | Xuất trọn vẹn | Tốc độ đầu cuối |
| --- | ---: | ---: | ---: | ---: | ---: |
| Máy chủ A | 27,030 | 189.043 s | **142.983 tin nhắn/s** | 211.647 s | 127.713 tin nhắn/s |
| Máy chủ B | 29,299 | 182.513 s | **160.531 tin nhắn/s** | 206.650 s | 141.781 tin nhắn/s |

Văn bản và siêu dữ liệu qua WARP, hai tài khoản mỗi máy chủ, không có tệp đính kèm hay bản ghi dùng lại.
Đo trên bản sửa đổi [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Mỗi lần chạy được công bố đều nêu bản sửa đổi mã nguồn, khối lượng công việc, thời gian và kết quả xác minh:
[khối lượng công việc, thời gian và xác minh](../EXPORT-BENCHMARK-2026-11-06.md). Mọi thay đổi trên `main`
đều chạy qua các [quy trình CI](../../.github/workflows/README.md) công khai, bao gồm kiểm thử trình cài đặt trên Linux và Windows
và bản dựng trình xác minh độc lập.

[**Xem bản demo →**](https://phishdestroy.github.io/TgWitness/demo/?lang=vi) ·
[**Số liệu đo, ngày và phương pháp →**](https://phishdestroy.github.io/TgWitness/vi/docs/validation/) ·
[Tải xuống bản xuất mẫu hư cấu](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Báo cáo kiểm toán tiếng Anh có chữ ký](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Bắt đầu đơn giản. Thấy mọi tuyến kết nối.</strong> · lần khởi động đầu tiên và sơ đồ hệ thống</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="Lần khởi động đầu tiên cho chọn Chỉ tải xuống, Theo dõi cuộc trò chuyện hoặc Bằng chứng cho một vụ án và chỉ hiển thị các mục tương ứng. Sơ đồ hệ thống liên kết bảng điều khiển, trình thu thập, Telegram, sổ nhật ký, nhân chứng và các dịch vụ bên ngoài, kèm các quan sát mạng. Giá trị hư cấu.">
</picture>

Lần khởi động đầu tiên chỉ hỏi một câu: **Chỉ tải xuống**, **Theo dõi cuộc trò chuyện** hay
**Bằng chứng cho một vụ án**. Câu trả lời xác định mục tiêu và cấp độ giao diện, nên
bảng điều khiển chỉ hiện các mục mà nhiệm vụ đó cần. Tiếp theo là kết nối, đăng nhập Telegram và
chọn cuộc trò chuyện qua năm giai đoạn. Bước kiểm tra kết nối tự chạy, và
các tùy chọn tuyến kết nối chỉ mở ra khi bước này thất bại. Công cụ chuyên gia luôn sẵn sau một công tắc.

**Sơ đồ hệ thống** cho thấy bản cài đặt kết nối tới Telegram và các dịch vụ bên ngoài
như thế nào: quyền truy cập bảng điều khiển, tuyến kết nối và đích Telegram của từng tài khoản, đường đi của sổ nhật ký và
nhân chứng, cùng các quan sát mạng mới nhất. Quan sát nào bị thiếu sẽ được
đánh dấu là thiếu.

[Thiết lập ban đầu](../SETTINGS.md) · [Sơ đồ hệ thống](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Phục vụ phần còn lại của cuộc điều tra</strong> · thẻ đối tượng, danh sách theo dõi, ví, theo dõi trạng thái trực tuyến, tài liệu cho tòa án</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Theo dõi tên và tên người dùng theo Telegram ID. Ghi lại các tương tác được hỗ trợ với bot kèm biên nhận có chữ ký. Tìm kiếm tin nhắn đã lưu trữ và kết nối các máy khách MCP chỉ đọc. Triển khai trình thu thập với SSH được che và bản ghi của nhà cung cấp để xem xét. Ghi lại từng bước một cuộc trò chuyện kèm tham chiếu sổ nhật ký. Bàn giao gói vụ án BagIt kèm mẫu văn bản cho tòa án. Quy trình minh họa.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Con người và hồ sơ&nbsp;↗</b></a><br><sub>Tên và tên người dùng được theo dõi theo Telegram ID</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Điều tra bot&nbsp;↗</b></a><br><sub>Tương tác với bot kèm biên nhận có chữ ký</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/vi/docs/archive/"><b>Tìm kiếm tệp lưu trữ, AI và MCP&nbsp;↗</b></a><br><sub>Tìm trong tệp lưu trữ, kết nối máy khách chỉ đọc</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Triển khai đám mây niêm phong&nbsp;↗</b></a><br><sub>Trình thu thập bên trong Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Ba bước động: thẻ đối tượng có ảnh chụp nhanh sau đó ghi nhận việc đổi tên, kế hoạch hội thoại có các mục tiêu được hoàn tất bằng bản ghi sổ nhật ký, và mã QR thanh toán được giải mã thành địa chỉ ví có checksum hợp lệ, kích hoạt một kết quả khớp danh sách theo dõi. Giá trị hư cấu.">
</picture>

**Ghi lại cuộc trò chuyện.** Bắt đầu ghi cho một cuộc trò chuyện trong ngăn **Tài liệu hướng dẫn**
và mọi bước sẽ tự được ghi lại: thao tác trên bảng điều khiển, câu trả lời kèm độ trễ trước
đó, các lần sửa, thông báo xóa, ghi chú và bản nháp AI. Mỗi bước dẫn chiếu bản ghi sổ nhật ký
và SHA-256 của bản ghi đó. Khi chốt tài liệu, tài liệu được ký và mã băm của bản tường trình được ghi vào
sổ nhật ký.

| | |
| --- | --- |
| [Thẻ đối tượng](../INVESTIGATION-MODE.md#subject-cards) | Ảnh chụp nhanh hồ sơ của bot, người, kênh hoặc nhóm với nhãn BOT, VERIFIED, SCAM và FAKE của Telegram; ảnh chụp sau liệt kê những gì đã thay đổi |
| [Kế hoạch hội thoại](../INVESTIGATION-MODE.md#conversation-plans) | Mục tiêu về đường đi của tiền thanh toán, hạ tầng hoặc con người, tin nhắn soạn sẵn, thời gian trả lời, mức hoạt động theo giờ và văn phong của phía bên kia |
| [Bản dịch](../INVESTIGATION-MODE.md#machine-translation) | Hiển thị bên dưới bản gốc, kèm ngôn ngữ, mô hình và bản ghi sổ nhật ký |
| [Danh sách theo dõi](../INVESTIGATION-MODE.md#watchlists) | Từ khóa, mẫu, ví, @tên người dùng, ID, tên miền, số điện thoại và liên kết, được đối chiếu trong văn bản, các lần sửa, đích liên kết ẩn, nút bot, mã QR và OCR |
| [Theo dõi trạng thái trực tuyến](../INVESTIGATION-MODE.md#online-watch) | Kiểm tra mỗi 1–60 phút, tối đa 100 tài khoản mỗi yêu cầu, kèm quy luật theo giờ và ngày trong tuần |
| [Mã và ví](../INVESTIGATION-MODE.md#codes-in-images) | Mã QR thanh toán; địa chỉ EVM được kiểm tra theo EIP-55, TON ở dạng thô, checksum XRP Ledger, liên kết thanh toán kèm chuỗi, số tiền và token |
| [Dấu vết ứng dụng khách](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-show) | Dấu vết bộ mã hóa trong video tròn và tin nhắn thoại; so sánh thời gian tải lên với thời gian gửi sẽ lật tẩy bằng chứng “trực tiếp” được quay sẵn |
| [Danh tính ngụy trang và thẩm quyền](../INVESTIGATION-MODE.md#cover-and-authority) | Nhân dạng giả, giấy ủy quyền và bản ghi hoạt động bí mật, gắn cờ các tin nhắn nằm ngoài các cuộc trò chuyện hoặc khoảng thời gian được phép |
| [Kiểm soát tài khoản](../INVESTIGATION-MODE.md#account-control) | Chỉnh sửa hồ sơ và quyền riêng tư kèm bản ghi trước/sau, kiểm tra mức độ lộ diện và chuyển ngoại tuyến ngay sau mỗi thao tác |
| [Tài liệu cho tòa án](../INVESTIGATION-MODE.md#documents-for-court) | Gói vụ án BagIt kèm mẫu chứng nhận Rule 902(13)/(14), danh mục vật chứng, phụ lục yêu cầu và phụ đề WebVTT/SRT cho video quay màn hình |

Nội dung được đánh dấu 18+, bạo lực hoặc dữ liệu cá nhân vẫn nằm trong bản dành cho tòa án, được niêm phong bằng
AES-256-GCM; khóa được chuyển riêng.

[Cài đặt xuất](../EXPORT_HASHES.md) bao gồm thu thập qua API thông thường và Takeout,
lấy lịch sử tin nhắn trước tệp đính kèm, tải tệp xuống hoặc dùng mã băm của máy chủ, và các chế độ xem
JSON/HTML tương thích với Telegram Desktop. [Xuất cuộc trò chuyện phân tán](../DISTRIBUTED-EXPORT.md#history-acquisition)
cung cấp lộ trình Takeout phải chủ động bật cho lịch sử công khai, điểm kiểm tra có chữ ký sau mỗi 100 tin nhắn,
và khôi phục trong một khoảng bằng cùng tài khoản; tài liệu
[thiết kế hiệu năng](../FAST-ACQUISITION.md) của tính năng này liệt kê hành vi thu thập đã kiểm thử
và các phép đo thực tế đã lên kế hoạch.

</details>

<details>
<summary><strong>Mọi thứ khác</strong> · lịch sử, tài khoản, proxy, AI, tích hợp</summary>

| | |
| --- | --- |
| [Tải tin nhắn cũ hơn](../HISTORY.md) | Kéo lịch sử trước đây của các cuộc trò chuyện đã chọn, tạm dừng và tiếp tục bất cứ lúc nào |
| [Nhiều tài khoản](../ACCOUNTS.md#multiple-accounts) | Các không gian làm việc riêng biệt, mỗi nơi có phiên Telegram, sổ nhật ký và khóa ký riêng |
| [Nhập hàng loạt](../ACCOUNTS.md#bulk-import-and-account-groups) | Thả vào cả loạt tệp phiên, sắp xếp tài khoản thành nhóm có chung cài đặt |
| [Kho MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, quốc gia, bộ lọc, danh sách của riêng bạn |
| [Phiên có sẵn](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key hoặc một dòng `key:DC`; tùy chọn ủy quyền QR độc lập từ tài khoản nguồn đã nhập |
| [Bảo mật tài khoản](../ACCOUNTS.md#create-an-independent-authorization) | Cảnh báo phiên mới, kết thúc các phiên khác, chế độ phiên duy nhất đồng thời đặt mật khẩu xác minh hai bước, và [đầu dò nhân chứng](../ACCOUNTS.md#witness-probe) nhận ra khi cập nhật trực tiếp không còn đến được phiên này |
| [Xuất cuộc trò chuyện có thể tiếp tục](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Bản xuất bị dừng giữa chừng vẫn giữ một bản sao một phần có chữ ký: tiếp tục, làm lại từ đầu hoặc tải xuống phần đã lưu |
| [Proxy](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT hoặc MTProxy cho từng không gian làm việc. **Ẩn IP** không bao giờ quay về kết nối trực tiếp |
| [Tìm kiếm và AI](../ANALYSIS.md) | Tìm kiếm cục bộ, AI tùy chọn với nguồn bạn có thể kiểm tra |
| [Tìm kiếm toàn văn](../SEARCH.md) | Các dạng từ, cụm từ chính xác, tên miền, @tên người dùng và tiếng Trung không có dấu cách, kết quả khớp nhất lên đầu (**bản xem trước**) |
| [MCP](../MCP.md) | Quyền truy cập chỉ đọc cho máy khách MCP, giới hạn ở các cuộc trò chuyện bạn chọn |
| [Dòng lệnh](../CLI.md) | `search`, `context`, `messages`, `stats` và `export` dạng JSON Lines với `--json` cho script và agent, chạy cục bộ hoặc với token có phạm vi giới hạn (**bản xem trước**) |
| [OCR và chuyển giọng nói thành văn bản](../MEDIA-ANALYSIS.md) | Chạy cục bộ, bản gốc giữ nguyên |
| [Ghi lại độc lập](../OPTIONAL-CAPTURE.md) | Trình ghi trình duyệt/AyuGram tùy chọn trong **Các công cụ khác → Tiện ích bổ sung** (xem trước, tắt theo mặc định) |
| [Trusted Live](../TRUSTED-LIVE.md) | Phiên Desktop/Web chính thức, video được bảo vệ và phân tích tính liên tục của bản xuất gốc (xem trước; đang chờ thẩm định thực tế) |
| [Web chính thức niêm phong](../OFFICIAL-WITNESS.md) | Trình duyệt chính thức mới khởi chạy trên GitHub Actions, điều khiển bị hạn chế, video có chữ ký, nguồn/cài đặt có giá trị kỳ vọng được xác định độc lập |
| [Webhooks](../WEBHOOKS.md) | Sự kiện gửi đi có chữ ký kèm cơ chế thử lại, có sẵn ví dụ n8n |
| [Chia sẻ quyền truy cập](../ACCESS.md) | Chỉ cấp cho người khác các cuộc trò chuyện đã chọn, kèm thời hạn và giới hạn IP |
| [Số tin nhắn bị thiếu](../EVIDENCE.md#missing-message-numbers-gap_summary) | Những số Telegram đã cấp nhưng chưa từng được quan sát, theo từng kênh và cho toàn bộ tài khoản, trong mức độ bao phủ, báo cáo và MCP (**bản xem trước**) |
| [Ảnh chụp trạng thái cuộc trò chuyện](../COLLECTION.md) | Ảnh chụp có chữ ký định kỳ về tiêu đề, mô tả, tin ghim, quản trị viên và quà tặng, kèm những gì đã thay đổi (**bản xem trước**) |
| [Sơ đồ hệ thống](../SYSTEM-MAP.md) | Bản đồ trực tiếp về truy cập bảng điều khiển, tuyến kết nối của tài khoản, đích Telegram và dịch vụ bên ngoài, với 200 quan sát mạng mới nhất trong tối đa 2,000 quan sát |

</details>

<details>
<summary><strong>Chọn nền tảng bảo chứng cho bản ghi</strong> · cục bộ, đám mây đã kiểm toán, GitHub Actions hoặc Intel TDX</summary>

Chạy cục bộ, thêm một bản triển khai đám mây đã kiểm toán, hoặc thu thập bên trong **máy ảo bảo mật Phala Cloud
với Intel TDX**. Phương án nào cũng giữ sổ nhật ký có chữ ký; các bước kiểm tra bổ sung
nhắm vào môi trường nơi dữ liệu được thu thập.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Ba lựa chọn triển khai: xác minh sổ nhật ký cục bộ; máy ảo đã kiểm toán kèm bản ghi của nhà cung cấp và bản ghi truy cập; Phala Intel TDX với quote đã xác minh, hệ điều hành và ứng dụng đã đo, cùng khóa trình thu thập được ràng buộc.">
</picture>

Trình xác minh TDX kiểm tra quote dựa trên gốc tin cậy đã ghim và dữ liệu thu hồi của Intel,
ràng buộc quote với một bản tường trình có chữ ký của trình thu thập và một challenge mới, rồi so sánh
hệ điều hành và ứng dụng đã đo với các đầu vào kỳ vọng được xác định độc lập. Báo cáo liệt kê
từng kết quả riêng, nhờ đó có thể xem xét cùng lúc môi trường đã đo, danh tính trình thu thập,
bản ghi quá trình ghi lại và mức độ bao phủ.

**Ghi lại có nguồn gốc xác thực từ GitHub** (xem trước). Thu thập một cuộc trò chuyện trên runner do GitHub lưu trữ
với TgWitness được ghim phiên bản và một phiên Telegram mới, sau đó tải xuống tệp lưu trữ
đã mã hóa kèm chứng thực GitHub. Trình xác minh kiểm tra quy trình và phiên bản
trình thu thập đã được phê duyệt, digest của tệp lưu trữ, sổ nhật ký và tệp đính kèm. Tính năng này cũng có
trong mục **Xuất dữ liệu** trên bảng điều khiển.
[Mở trang ghi lại](https://phishdestroy.github.io/TgWitness/vi/docs/capture/) · [Hướng dẫn](../SEALED-ACTIONS.md)

Với quan sát trực tiếp, lịch sử hay một lần xuất duy nhất, hãy chọn một
[phương pháp thu thập](../COLLECTION-MODES.md). Có thể thu thập các cuộc trò chuyện đám mây riêng tư
khi tài khoản được kết nối có quyền truy cập. Ứng dụng đã phát hành còn có
[tích hợp Secret Chat](../PSEUDO-SECRET.md): cài phần phụ thuộc giao thức tùy chọn
và bật cho từng tài khoản để ghi lại các cuộc trò chuyện được tạo hoặc chấp nhận trong tài khoản đó.
Xem [phạm vi thu thập](../COLLECTION.md) để biết các cách thu thập hiện có.

[Phala / Intel TDX và các bản triển khai đã kiểm toán](../HIGH-ASSURANCE.md) ·
[Thẩm định thực tế trên Phala](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Ranh giới tin cậy](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Kiểm tra quá trình ghi lại và bản ghi đã lưu</strong> · những gì người nhận xác minh và Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Ghi lại cuộc trò chuyện. Xác minh bản ghi. Lưu tin nhắn, các lần sửa và tệp, kiểm tra chữ ký và điểm kiểm tra, rồi xem xét quá trình ghi lại.">
</picture>

TgWitness ghi lại nội dung được gửi đến tài khoản Telegram đã kết nối, kèm
mã định danh cuộc trò chuyện, tin nhắn và người gửi, các phiên bản đã ghi lại và siêu dữ liệu thu thập.
Tệp lưu trữ tập hợp các bản ghi đó, tệp đính kèm được bảo toàn và dữ liệu xác minh
để phục vụ việc xem xét.

| Bước kiểm tra | Những gì người nhận xác minh |
| --- | --- |
| Sổ nhật ký có chữ ký và manifest | Chữ ký bản ghi, chuỗi băm và các tệp được giao, đối chiếu với khóa ký dự kiến. |
| Điểm kiểm tra được lưu giữ riêng | Sổ nhật ký, đối chiếu với độ dài và mã băm của bản ghi mới nhất đã ghi nhận trước đó. |
| Nhân chứng độc lập | Sổ nhật ký, đối chiếu với các điểm kiểm tra do một nhân chứng riêng lưu giữ. |
| Ghi lại trên GitHub Actions | Tệp lưu trữ, đối chiếu với chứng thực, quy trình được lưu trữ đã phê duyệt và phiên bản trình thu thập. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
đặt một cuộc trò chuyện Telegram cạnh các tệp xuất Desktop đã bị cố ý chỉnh sửa.
Hãy so sánh các phiên bản, xem xét các thay đổi, rồi làm theo các bước thu thập và
xác minh cho một tệp lưu trữ TgWitness có chữ ký.

[Các bước xác minh](../wiki/Exports-and-Verification.md) ·
[Ghi lại trên GitHub](../SEALED-ACTIONS.md) ·
[Mô hình tin cậy kỹ thuật](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Giữ cho cuộc điều tra luôn vận hành</strong> · thông báo, lưu trữ và khôi phục</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Các quy trình động: Apprise gửi các cảnh báo đã cấu hình; bản sao ngoài site được mã hóa trước khi tải lên bộ lưu trữ tương thích S3.">
</picture>

[Thông báo](../OPERATIONS.md#notifications) · [Bản sao ngoài site được mã hóa](../wiki/Off-site-Copy.md) · [Sao lưu và khôi phục](../wiki/Backup-and-Recovery.md) · [Khắc phục sự cố](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/vi/docs/start/"><b>Hướng dẫn thiết lập&nbsp;↗</b></a><br><sub>Từ cài đặt đến cuộc trò chuyện đầu tiên</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/vi/docs/dedicated-account/"><b>Chuẩn bị tài khoản&nbsp;↗</b></a><br><sub>Một tài khoản Telegram chuyên dụng</sub></td>
<td width="33%" align="center"><a href="DEPLOYMENT.md"><b>Docker và máy chủ&nbsp;↗</b></a><br><sub>HTTPS, khởi động lại và cập nhật</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Khám phá kho mã</strong> · nơi chứa mã nguồn, tài liệu và công cụ</summary>

| Thư mục | Bắt đầu từ đây |
| --- | --- |
| [docs/](../README.md) | Thiết lập, quy trình điều tra và tài liệu tham khảo kỹ thuật |
| [tgwitness/](../../tgwitness/README.md) | Ứng dụng chính, trình thu thập, sổ nhật ký và bảng điều khiển web |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Các trình ghi độc lập và mã xác minh của chúng |
| [addons/](../../addons/README.md) | Cài đặt, cấu hình và kiểm thử tính năng ghi lại tùy chọn |
| [deploy/](../../deploy/README.md) | Trình cài đặt, container và dịch vụ chạy nền |
| [examples/](../../examples/README.md) | Cấu hình xuất tài khoản và ghi lại niêm phong |
| [integrations/](../../integrations/README.md) | Webhook có chữ ký và bộ nhận n8n |
| [.agents/](../../.agents/README.md) | Hướng dẫn tác vụ để đọc tệp lưu trữ qua CLI |
| [scripts/](../../scripts/README.md) | Trình khởi chạy và tiện ích CI |
| [tools/](../../tools/README.md) | Bản dựng, kiểm tra và đóng gói |
| [website/](../../website/README.md) | Trang web công khai, hướng dẫn đã dịch và bản demo tương tác |
| [.github/](../../.github/AUTOMATION.md) | Quy trình, hướng dẫn đóng góp và hỗ trợ |

[Hướng dẫn đầy đủ về dự án](../PROJECT-GUIDE.md) ·
[Đóng góp](../../.github/CONTRIBUTING.md) · [Nhận trợ giúp](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Thông báo về đạo đức &amp; tính liên tục lịch sử</strong></summary>

Quan điểm của các tác giả và thông báo cho nhà vận hành, bằng tiếng Việt:

[Thông báo cho nhà vận hành](OPERATOR-INCOMPATIBILITY.md) · [Giấy phép MIT](../../LICENSE) · [NOTICE gốc](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Đọc tổng quan dự án bằng ngôn ngữ của bạn</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · **Tiếng Việt** · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Tài liệu kỹ thuật</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Sổ tay điều tra</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Do PhishDestroy phát triển</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Đóng góp</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Nhận trợ giúp</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Báo cáo lỗ hổng</b></a>
</p>

[Chỉ mục dự án dạng máy đọc được](../../llms.txt) · [Sổ tay dạng văn bản đầy đủ](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Quy tắc kho mã dành cho agent](../../AGENTS.md)
