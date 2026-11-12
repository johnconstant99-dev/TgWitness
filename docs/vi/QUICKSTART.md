[TgWitness](../../README.md) / [Tài liệu hướng dẫn](../README.md) / [Thư mục](README.md)

![Bắt đầu](../assets/presentation/chapter-start.svg)

[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · [Español](../es/QUICKSTART.md) · [Português (Brasil)](../pt/QUICKSTART.md) · [Türkçe](../tr/QUICKSTART.md) · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · [Bahasa Indonesia](../id/QUICKSTART.md) · **Tiếng Việt** · [简体中文](../zh/QUICKSTART.md)

# Bắt đầu nhanh với TgWitness

TgWitness là một ứng dụng độc lập để quan sát các nhóm và kênh Telegram mà tài khoản của bạn có quyền truy cập. Ứng dụng chạy cục bộ với thư mục dữ liệu riêng.

**Lần đầu sử dụng?** Hãy [khám phá bản demo](#explore-the-interface) trước khi kết nối tài khoản. [Chọn hướng dẫn](../README.md) về proxy, nhân chứng, xuất dữ liệu hoặc thiết lập máy chủ. [Thu thập bằng GitHub Actions](../SEALED-ACTIONS.md) (xem trước) chạy quá trình thu thập trong bản fork GitHub của riêng bạn thay vì trên một bản cài đặt cục bộ.

<a name="install-and-start"></a>

## Cài đặt và khởi động

Trình cài đặt có hướng dẫn đi kèm Python riêng và kiểm tra mã băm của các gói cũng như chữ ký của bản phát hành trước khi cài đặt. Chạy lại trình cài đặt sẽ cập nhật bản cài đặt hiện có.

**Linux / macOS:**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows (PowerShell hoặc Command Prompt):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

Trên máy chủ Ubuntu, hãy chạy với quyền root để cài đặt dịch vụ chạy nền; trên máy tính để bàn, hãy chạy bằng tài khoản người dùng thông thường. Trên Ubuntu, trình cài đặt in ra địa chỉ bảng điều khiển và khóa truy cập; trên macOS và Windows, bảng điều khiển cục bộ sẽ mở trong trình duyệt. Tiếp tục ở bước **Kết nối Telegram** bên dưới. [Cài đặt, xác minh và cập nhật](../INSTALLATION.md) trình bày các lựa chọn truy cập máy chủ, cách kiểm tra tập lệnh trước khi chạy, cách cập nhật và gỡ cài đặt.

### Các cách cài đặt khác

Ngoài trình cài đặt, bạn có thể dùng bản phát hành trên GitHub, mã nguồn hoặc Docker. Các bản tải xuống portable sẽ có sau khi một bản build phát hành được công bố:

| Hệ điều hành | Không cần cài sẵn gì | Từ mã nguồn: Python 3.11+ | Docker: Engine/Desktop với Compose 2.20+ |
| --- | --- | --- | --- |
| Windows | Giải nén `TgWitness-<version>-windows-amd64-portable.zip` tải từ GitHub Releases, nhấp đúp vào `TgWitness.cmd` | Nhấp đúp vào `Start.cmd` | Nhấp đúp vào `scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

Với các cách chạy từ mã nguồn, hãy [tải xuống và giải nén nhánh `main` hiện tại](https://github.com/phishdestroy/TgWitness/archive/refs/heads/main.zip) hoặc clone kho mã nguồn:

```sh
git clone https://github.com/phishdestroy/TgWitness.git
cd TgWitness
```

Nếu không tìm thấy Python phù hợp, `Start.cmd` sẽ đề nghị cài Python 3.12 cho tài khoản người dùng Windows của bạn (qua winget hoặc trình cài đặt có chữ ký từ python.org). Nếu thiếu Python, `start.sh` in ra chính xác lệnh cài đặt cho bản phân phối Linux hoặc macOS của bạn. Lần khởi chạy từ mã nguồn đầu tiên sẽ tự động tạo `.venv` và cài đặt các thành phần phụ thuộc.

Docker sẽ build ứng dụng và khởi chạy nó ở chế độ nền; máy host không cần Python. `scripts\Docker.cmd` và `scripts/docker-start.sh` in ra địa chỉ bảng điều khiển và mã thông báo khi container hoạt động bình thường. Các lệnh Docker tương đương trên mọi máy host được hỗ trợ là:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

Mở **http://127.0.0.1:8787**. Dùng mã thông báo do tập lệnh hỗ trợ Docker hoặc lệnh Docker thứ hai in ra; với bản portable hoặc bản cài từ mã nguồn, hãy đọc **data/live/panel-token.txt**. Tiếp tục ở bước **Kết nối Telegram** bên dưới. Bản cài đặt trực tiếp (native) và bản cài đặt Docker dùng bộ nhớ lưu trữ riêng; khởi động Docker không nhập sổ nhật ký hiện có của bản cài đặt trực tiếp.

Đối với máy chủ, tài liệu [triển khai](DEPLOYMENT.md) trình bày HTTPS tự động, khởi động lại, các image đã phát hành, cập nhật và sao lưu.

<a name="explore-the-interface"></a>

## Khám phá giao diện

1. Chạy **TgWitness-Demo.cmd** trong gói portable, **scripts\Demo.cmd** trong thư mục mã nguồn trên Windows, hoặc `sh start.sh --demo` trên Linux/macOS. Khi khởi chạy từ mã nguồn, trước tiên `.venv` sẽ được tạo và các thành phần phụ thuộc được cài đặt.
2. Mở **http://127.0.0.1:8787**.
3. Bản demo cục bộ tự động mở sổ nhật ký mẫu. Khi truy cập trực tiếp tại máy, không cần sao chép mã thông báo.

Tin nhắn trong bản demo là hư cấu. Chế độ demo không thể kết nối tài khoản Telegram thật.

## Kết nối Telegram

> [!WARNING]
> **Hãy dùng tài khoản chuyên dụng.** Telegram có thể hạn chế hoặc cấm vĩnh viễn tài khoản nếu cho rằng khối lượng yêu cầu là quá mức, bất kể dùng ứng dụng khách nào. Hãy kết nối các tài khoản được chuẩn bị riêng cho việc quan sát thay vì tài khoản cá nhân hoặc tài khoản có giá trị, và tạo ID API / băm API trên một tài khoản chuyên dụng.

1. Nếu bản demo chạy trực tiếp (native) đang chạy, hãy dừng nó rồi chạy **Start.cmd** hoặc `sh start.sh`. Nếu không, hãy để bản cài đặt thực đã khởi động ở trên tiếp tục chạy.
2. Dùng mã thông báo bảng điều khiển để đăng nhập. Một không gian làm việc mới sẽ mở phần [thiết lập ban đầu](../SETTINGS.md). Chọn **Chỉ tải xuống**, **Theo dõi cuộc trò chuyện** hoặc **Bằng chứng cho một vụ án**.
3. Xem lại kết quả kiểm tra kết nối. Nếu cần, hãy cấu hình proxy của riêng bạn; cài đặt kết nối vẫn khả dụng sau khi hoàn tất thiết lập.
4. Tại **Connect Telegram**, hãy chọn số điện thoại, mã QR, tệp tài khoản (TData, `.session`,
   StringSession, tệp JSON tài khoản) hoặc khóa ủy quyền hoàn chỉnh. Hoàn tất xác nhận
   Telegram, nhập mã và mật khẩu xác thực hai bước khi được yêu cầu.
5. Kiểm tra tài khoản được hiển thị, chọn các cuộc trò chuyện và xem lại cài đặt. Hoàn tất ở màn hình cuối cùng. Với **Chỉ tải xuống**, **Bắt đầu xuất** sẽ chạy một lần xuất duy nhất và mở mục Xuất dữ liệu để hiển thị tiến độ; thao tác này không bật quan sát liên tục.

Sau khi thiết lập, **Cuộc trò chuyện → Chọn** dùng để thay đổi các cuộc trò chuyện đã chọn. **Cài đặt** điều khiển việc thu thập và tệp; **Các công cụ khác → Nguồn** cung cấp danh sách nguồn chi tiết ở cấp Tiêu chuẩn hoặc Chuyên gia. [Hướng dẫn bảng điều khiển](../PANEL.md) mô tả sáu mục chính và các điều khiển theo ngữ cảnh của chúng.

**ID API + Băm** là tùy chọn: không gian làm việc sẽ dùng cặp đã lưu hoặc đã nhập, hoặc một cặp còn hoạt động từ kho tích hợp sẵn. Để dùng ứng dụng của riêng bạn, hãy dán một cặp `API ID:API Hash` vào trường ID API. Với **Khóa xác thực**, hãy dán đủ 512 ký tự thập lục phân và chọn DC ID được cung cấp kèm theo. ID người dùng là tùy chọn và sẽ được kiểm tra nếu bạn nhập.

Thông tin xác thực API dùng để định danh ứng dụng của bạn; bản thân chúng không ủy quyền cho tài khoản. Nhóm riêng tư không cần tên người dùng công khai, nhưng tài khoản của bạn phải có quyền truy cập.

Với tài khoản có sẵn, xem [định dạng tài khoản và phiên](../ACCOUNTS.md): bảng điều khiển chấp nhận Telethon StringSession, Telethon/Pyrogram SQLite, tệp ZIP TData của một tài khoản và JSON tài khoản được hỗ trợ. Chọn cùng lúc tệp phiên và tệp JSON đi kèm, rồi nhấn **Kết nối tài khoản**. Đăng nhập bằng mã QR cũng khả dụng với cùng các cài đặt API tùy chọn. TDLib, phiên bot và danh sách tài khoản dạng CSV/JSON không được hỗ trợ.

Với nhiều tài khoản, dùng **Tài khoản → Nhập các tài khoản** và chọn các tệp phiên được hỗ trợ của chúng. Các tệp JSON đi kèm được ghép cặp theo tên tệp (basename); mỗi tài khoản được nhập sẽ có không gian làm việc riêng. Xem [nhập hàng loạt và nhóm tài khoản](../ACCOUNTS.md#bulk-import-and-account-groups).

Để thêm tài khoản khác, nhấn **+** bên cạnh bộ chọn tài khoản hoặc dùng **Tài khoản → Thêm tài khoản**. Các không gian làm việc có phiên, sổ nhật ký, khóa, nguồn và hàng đợi riêng. Chuyển chế độ xem không làm dừng các trình thu thập khác. Trong bản cài đặt này, một tài khoản Telegram không thể được gán cho hai không gian làm việc. Số lượng không gian làm việc không cố định; chúng dùng chung một tiến trình, nên khả năng đáp ứng phụ thuộc vào máy.

Mã thông báo bảng điều khiển của bản cài đặt thực bảo vệ quyền truy cập vào các ủy quyền Telegram và dữ liệu đã lưu của bạn; nó tách biệt với thông tin xác thực API Telegram. Chỉ bản demo cục bộ được khởi động có chủ đích và truy cập trực tiếp mới được vào tự động. Bản demo truy cập từ xa hoặc qua proxy vẫn dùng `data/demo/panel-token.txt`.

## Xem lại và xuất dữ liệu

- **Sổ nhật ký:** tìm kiếm và lọc các quan sát theo nguồn và loại sự kiện.
- Chọn một sự kiện để xem bản ghi gốc, thông tin quy kết (attribution) và các phiên bản đã lưu của nó.
- Chi tiết chỉnh sửa hiển thị nội dung trước/sau hiện có. Chi tiết xóa hiển thị nội dung được thu thập lần cuối, nếu có; người thực hiện không xác định thì vẫn là không xác định.
- **Xuất dữ liệu:** ZIP có chữ ký, JSONL, CSV và HTML ngoại tuyến.
- **Xuất toàn bộ nội dung trò chuyện** (**Cuộc trò chuyện → Xuất nội dung trò chuyện**, hoặc **Xuất dữ liệu → Thu thập hoặc xuất một cuộc trò chuyện**): tải xuống toàn bộ lịch sử hiển thị của một cuộc trò chuyện dưới dạng gói có chữ ký, gồm `chat.json` (theo kiểu bản xuất của Telegram) và tệp `chat.html` dễ đọc. Cuộc trò chuyện riêng tư cũng xuất được khi tài khoản là thành viên. Đây là ảnh chụp nhanh trạng thái hiện tại, không phải bản tái dựng các tin nhắn đã bị xóa hoặc đã bị chỉnh sửa trước đó. Xác minh bản sao bằng `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256`.
- **Lưu điểm kiểm tra:** lưu giữ ranh giới đã ký của sổ nhật ký ở bên ngoài trình thu thập.
- **Tải xuống biên nhận thực thi đã được ký điện tử:** lưu giữ bản ghi chương trình/phiên bản của trình thu thập.
- **Chuẩn bị yêu cầu đóng dấu thời gian:** chuẩn bị một yêu cầu ngoại tuyến gửi tới cơ quan cấp dấu thời gian; làm theo [TIMESTAMP.md](../TIMESTAMP.md) để nhận và xác minh phản hồi.
- **Xác minh sổ nhật ký:** kiểm tra chữ ký sự kiện và các liên kết chuỗi. Với bản xuất ZIP, việc kiểm tra còn bao gồm cả tệp phương tiện.

Các trình duyệt được hỗ trợ lưu bản xuất lớn thẳng vào tệp do bạn chọn. Các trình duyệt khác chỉ đệm tối đa 128 MiB. Khi máy chủ đang chạy, CLI truyền theo luồng (streaming) hỗ trợ tải xuống dung lượng lớn hơn mà không cần đệm toàn bộ phản hồi:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

Với không gian làm việc khác, thêm `--profile ID`, lấy ID tại **Xuất dữ liệu → ID không gian làm việc**. Với máy chủ từ xa, thêm `--url https://your-server`. Giới hạn truyền mặc định là 5 GiB; `--max-mib` dùng để thay đổi giới hạn này. Theo mặc định, nội dung ZIP có chữ ký còn có một giới hạn xác minh riêng là 4 GiB khi chưa nén (**Các công cụ khác → Các tham số** cho phép nâng giới hạn này; hãy xác minh các tệp lưu trữ như vậy bằng `verify.py --max-gib N`). Xác minh tệp lưu trữ bằng một bản sao đáng tin cậy của trình xác minh, một dấu vân tay khóa được lưu giữ độc lập và, để đạt mức tối thiểu cho bằng chứng, chứng chỉ gốc của cơ quan cấp dấu thời gian (`--tsa-ca`).

## Kiểm tra bản cài đặt

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` kiểm tra các thành phần phụ thuộc cục bộ, khả năng ký, bộ nhớ lưu trữ, cấu hình khóa và địa chỉ lắng nghe. Lệnh này không cài đặt gì và không kết nối Telegram. Nếu cổng đang bận, có thể một phiên chạy khác đang hoạt động. Hãy dùng `--port` khác hoặc dừng phiên chạy đó trước.

Trình khởi chạy cài đặt vào `.venv`. Các lệnh phụ trợ `python -m tgwitness...` phải dùng `.venv\Scripts\python.exe` trên Windows hoặc `.venv/bin/python` trên Linux/macOS, trừ khi môi trường đó đã được kích hoạt.

## Phiên, bảo vệ và vận hành

Một tệp Telethon SQLite `.session` đã đóng và nhất quán có thể được chuyển đổi cục bộ bằng `python -m tgwitness.sessions account.session --out account.tgwitness-session`, sau đó tải lên tại **Các công cụ khác → Tài khoản → Tệp tin**. Nhập tệp trực tiếp và đăng nhập bằng mã QR cũng khả dụng. Xem [CONNECTION-SECURITY.md](../CONNECTION-SECURITY.md) để biết về định dạng đăng nhập, SOCKS5, HTTP CONNECT, MTProxy và khóa chính bên ngoài.

**Tạm dừng quan sát** sẽ dừng việc thu thập. **Khóa** chỉ đóng quyền truy cập qua trình duyệt. Đóng tab không làm dừng tiến trình thu thập. Dừng tiến trình sẽ làm gián đoạn việc thu thập; ảnh chụp nhanh lịch sử không thể tái dựng mọi chỉnh sửa hoặc thao tác xóa đã bị bỏ lỡ. Xem [cách hoạt động của việc thu thập](../COLLECTION.md) để biết về chính sách sự kiện, hàng đợi tệp đính kèm, cách ly tài khoản và hành vi khi khởi động lại.

Phiên và các thông tin bí mật được mã hóa. Nội dung tin nhắn, tệp phương tiện và bản xuất cần được lưu trên ổ đĩa hoặc volume được mã hóa. Hãy xác minh chữ ký sổ nhật ký bằng một khóa đáng tin cậy và lưu giữ điểm kiểm tra ở nơi riêng. Xem xét bản ghi thu thập, biên nhận thời gian bên ngoài và chứng thực môi trường tương ứng với chế độ thu thập đã chọn.

Đọc [OPERATIONS.md](../OPERATIONS.md) về sao lưu/khôi phục, [DEPLOYMENT.md](DEPLOYMENT.md) về triển khai trên máy chủ, và [deploy/](../../deploy/README.md) để xem ví dụ về dịch vụ. Bảng điều khiển đã cài đặt cũng có hướng dẫn thiết lập ngoại tuyến tại `/guide.html`.

Các bước xác minh đã thực hiện trên thực tế và những giới hạn còn lại được ghi trong [VERIFICATION.md](../VERIFICATION.md) và [READINESS.md](../internal/READINESS.md).
