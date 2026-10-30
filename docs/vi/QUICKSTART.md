[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · [Español](../es/QUICKSTART.md) · [Português (Brasil)](../pt/QUICKSTART.md) · [Türkçe](../tr/QUICKSTART.md) · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · [Bahasa Indonesia](../id/QUICKSTART.md) · **Tiếng Việt** · [简体中文](../zh/QUICKSTART.md)

# Hướng dẫn bắt đầu nhanh với TgWitness

TgWitness là một ứng dụng độc lập dùng để theo dõi các nhóm và kênh Telegram mà tài khoản của quý vị có thể truy cập. Ứng dụng này chạy cục bộ với thư mục dữ liệu riêng.

**Đây là lần đầu tiên quý vị ghé thăm?** [Hãy khám phá bản demo](#khám-phá-giao-diện) trước khi kết nối tài khoản. [Vui lòng chọn hướng dẫn phù hợp](../README.md) về proxy, chứng nhân, xuất dữ liệu hoặc thiết lập máy chủ.

## Cài đặt và khởi động

Vui lòng chọn một phương thức. Các bản tải xuống di động sẽ có sẵn sau khi bản phát hành chính thức được công bố:

| Máy chủ | Chưa cài đặt bất kỳ phần mềm nào | Từ nguồn: Python 3.11 trở lên | Docker: Engine/Desktop với Compose 2.20 trở lên |
| --- | --- | --- | --- |
| Windows | Trích xuất `TgWitness-<version>-windows-amd64-portable.zip` từ GitHub Releases, nhấp đúp vào `TgWitness.cmd` | Nhấp đúp vào `Start.cmd` | Nhấp đúp vào `scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

Đối với các phương pháp nguồn, quý vị vui lòng tải xuống và giải nén tệp ZIP nguồn từ GitHub Releases hoặc sao chép kho lưu trữ. `Start.cmd` sẽ đề xuất cài đặt Python 3.12 cho người dùng Windows nếu không tìm thấy phiên bản Python phù hợp (winget hoặc trình cài đặt có chữ ký từ python.org). `start.sh` sẽ hiển thị lệnh cài đặt chính xác dành cho bản phân phối Linux hoặc macOS của quý vị nếu thiếu Python. Lần khởi chạy mã nguồn đầu tiên sẽ tạo tệp `.venv` và tự động cài đặt các phụ thuộc.

Docker sẽ biên dịch ứng dụng và khởi chạy nó ở chế độ nền; không cần cài đặt Python trên máy chủ. `scripts\Docker.cmd` và `scripts/docker-start.sh` sẽ hiển thị địa chỉ bảng điều khiển và mã thông báo khi container đang hoạt động bình thường. Các lệnh Docker tương ứng trên mọi máy chủ được hỗ trợ là:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

Mở tệp **http://127.0.0.1:8787**. Sử dụng mã thông báo được tạo bởi công cụ hỗ trợ Docker hoặc lệnh Docker thứ hai, hoặc tham khảo **tệp** **data/live/panel-token.txt** trong trường hợp cài đặt di động hoặc từ mã nguồn. Tiếp tục tại **phần** **“Kết nối Telegram”** bên dưới. Các bản cài đặt gốc và Docker sử dụng bộ nhớ lưu trữ riêng biệt; việc khởi động Docker sẽ không nhập nhật ký gốc hiện có.

Đối với máy chủ, [quá trình triển khai](DEPLOYMENT.md) bao gồm kích hoạt HTTPS tự động, khởi động lại, hình ảnh được công bố, cập nhật và sao lưu.

## Khám phá giao diện

1. Vui lòng chạy **tệp TgWitness-Demo.cmd** trong gói di động, tệp **scripts\Demo.cmd** trong thư mục nguồn trên Windows, hoặc `sh start.sh --demo` trên Linux/macOS. Khi khởi chạy từ nguồn, hệ thống sẽ tạo tệp `.venv` và cài đặt các phụ thuộc.
2. Mở **http://127.0.0.1:8787**.
3. Bản demo cục bộ sẽ tự động mở nhật ký mẫu. Quý vị không cần sao chép mã thông báo để truy cập trực tiếp tại máy cục bộ.

Các tin nhắn trong bản demo là hư cấu. Chế độ demo không thể kết nối với tài khoản Telegram thực.

## Kết nối với Telegram

> [!WARNING]
> **Xin đừng sử dụng bất kỳ thứ gì mà quý vị không thể chấp nhận mất mát.** Chúng tôi khuyến cáo mạnh mẽ quý vị không nên kết nối các tài khoản cá nhân hoặc có giá trị, cũng như không nên tạo ID API / mã băm trên tài khoản mà quý vị coi trọng. Telegram có thể khóa tài khoản một cách bất ngờ và thường là vĩnh viễn, bất kể ứng dụng khách nào được sử dụng. Việc chạy thử nghiệm suôn sẻ phụ thuộc vào Telegram, không phải vào TgWitness, và không đảm bảo bất kỳ điều gì cho các giai đoạn sau này.

1. Nếu bản demo gốc đang chạy, xin vui lòng dừng nó lại và chạy **tệp** **Start.cmd** hoặc `sh start.sh`. Trong trường hợp khác, xin vui lòng tiếp tục duy trì bản cài đặt trực tiếp đã khởi chạy ở trên.
2. Vui lòng sử dụng mã thông báo (token) của bảng điều khiển tương ứng với phương thức cài đặt của quý vị để mở bảng điều khiển.
3. Nếu quý vị cần sử dụng máy chủ trung gian (proxy), vui lòng lưu cài đặt tại **mục** **Tài khoản → Cài đặt → Cài đặt kết nối → Thay đổi đường dẫn kết nối**.
4. Trong **phần** **Tài khoản**, vui lòng nhập số điện thoại của quý vị và nhấn **Tiếp tục**, chọn **Mã QR → Hiển thị mã QR**, hoặc chọn tệp và nhấn **Kết nối tài khoản**. **API ID + Hash** là tùy chọn: không gian làm việc sẽ sử dụng cặp thông tin đã lưu hoặc nhập vào, hoặc một cặp thông tin hoạt động từ kho dự trữ tích hợp sẵn. Để sử dụng ứng dụng của riêng quý vị, hãy dán một cặp `API ID:API Hash` vào trường API ID. Để có khóa ủy quyền đầy đủ, hãy chọn **Khóa ủy quyền**, dán toàn bộ 512 ký tự thập lục phân và chọn DC ID được cung cấp. ID người dùng là tùy chọn và sẽ được xác nhận nếu được nhập.
5. Vui lòng hoàn tất phương thức đăng nhập mà quý vị đã chọn: số điện thoại/mã xác thực/xác thực hai yếu tố (2FA), xác nhận từ ứng dụng Telegram đã đăng nhập đối với mã QR, hoặc nhập phiên đăng nhập được ủy quyền từ các nền tảng được hỗ trợ.
6. Vui lòng kiểm tra ID tài khoản được hiển thị. **Nguồn** mở: các cuộc trò chuyện của quý vị sẽ được tải tự động; hãy thêm các nhóm của quý vị.
7. Trong phần **“Chọn những thay đổi cần lưu giữ**”, hãy chọn các danh mục sự kiện hoặc cài đặt sẵn **“Tin** **nhắn, chỉnh sửa và xóa”**, sau đó lưu cài đặt giám sát.
8. Vui lòng chọn các thiết lập tệp đính kèm riêng biệt, sau đó nhấn **Bắt đầu quan sát**.

Thông tin đăng nhập API dùng để xác định ứng dụng của quý vị; bản thân chúng không có chức năng cấp quyền truy cập cho tài khoản. Các nhóm riêng tư không yêu cầu tên người dùng công khai, nhưng tài khoản của quý vị phải có quyền truy cập.

Đối với các tài khoản hiện có, vui lòng tham khảo [các định dạng tài khoản và phiên làm việc](../ACCOUNTS.md): bảng điều khiển hỗ trợ Telethon StringSession, Telethon/Pyrogram SQLite, tệp ZIP TData cho một tài khoản duy nhất và định dạng JSON tài khoản được hỗ trợ. Vui lòng chọn một phiên làm việc cùng với tệp JSON tương ứng, sau đó nhấn **“Kết nối tài khoản**”. Tính năng đăng nhập qua mã QR cũng có sẵn với các cài đặt API tùy chọn tương tự. TDLib, các bot và danh sách tài khoản số lượng lớn không được hỗ trợ.

Để thêm một tài khoản khác, quý vị hãy nhấn vào **biểu** **tượng** **+** bên cạnh trình chọn tài khoản hoặc mở **Tài khoản → Cài đặt → Cài đặt kết nối → Không gian làm việc**, hoặc sử dụng **mục Tài khoản**. Các không gian làm việc có các phiên làm việc, nhật ký, khóa, nguồn và hàng đợi riêng biệt. Việc chuyển đổi chế độ xem sẽ không làm gián đoạn hoạt động của các trình thu thập dữ liệu khác. Trong bản cài đặt này, cùng một tài khoản Telegram không thể được gán cho hai không gian làm việc. Không có số lượng không gian làm việc cố định; các không gian này chia sẻ chung một tiến trình, do đó dung lượng phụ thuộc vào máy tính.

Mã thông báo bảng điều khiển trực tiếp bảo vệ quyền truy cập vào các thông tin ủy quyền Telegram và tài liệu đã lưu của quý vị; mã này tách biệt với thông tin đăng nhập API Telegram. Chỉ bản demo cục bộ được khởi chạy rõ ràng và truy cập trực tiếp mới được cấp quyền truy cập tự động. Bản demo từ xa hoặc qua proxy vẫn sử dụng thẻ `data/demo/panel-token.txt`.

## Xem lại và xuất dữ liệu

- **Tạp chí:** tìm kiếm và lọc các quan sát theo nguồn và loại sự kiện.
- Vui lòng chọn một sự kiện để xem bản ghi gốc, nguồn trích dẫn và các phiên bản đã lưu của sự kiện đó.
- Chi tiết chỉnh sửa hiển thị nội dung trước và sau khi chỉnh sửa (nếu có). Chi tiết xóa hiển thị nội dung được ghi lại lần cuối (nếu có); đối tượng không xác định vẫn được giữ nguyên trạng thái không xác định.
- **Các định dạng xuất:** tệp ZIP có chữ ký, JSONL, CSV và HTML ngoại tuyến.
- **Xuất toàn bộ lịch sử trò chuyện** (Nguồn → Xuất toàn bộ lịch sử trò chuyện): tải xuống toàn bộ lịch sử hiển thị của một cuộc trò chuyện dưới dạng gói dữ liệu đã được ký số kèm theo `chat.json` (theo phong cách xuất dữ liệu của Telegram) và một tệp `chat.html` có thể đọc được. Tính năng này hoạt động với các cuộc trò chuyện riêng tư khi tài khoản là thành viên của nhóm. Đây là bản chụp nhanh tại thời điểm hiện tại, không phải là bản tái tạo các tin nhắn đã bị xóa hoặc đã được chỉnh sửa trước đó. Vui lòng xác minh bản sao bằng `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256`.
- **Lưu điểm kiểm tra:** duy trì ranh giới của nhật ký đã được ký bên ngoài bộ thu thập dữ liệu.
- **Tải xuống biên nhận chạy đã được ký:** lưu giữ bản ghi chương trình/phiên bản của bộ thu thập dữ liệu.
- **Chuẩn bị yêu cầu dấu thời gian:** chuẩn bị một yêu cầu ngoại tuyến gửi đến cơ quan cấp dấu thời gian; làm theo hướng dẫn trong [tệp TIMESTAMP.md](../TIMESTAMP.md) để nhận và xác minh phản hồi.
- **Xác minh nhật ký:** kiểm tra chữ ký sự kiện và các liên kết chuỗi. Tệp ZIP xuất ra cũng kiểm tra các tệp phương tiện.

Các trình duyệt được hỗ trợ có thể lưu trực tiếp các tệp xuất có dung lượng lớn vào tệp đã chọn. Các trình duyệt khác chỉ có thể lưu tạm tối đa 128 MiB. Trong khi máy chủ đang hoạt động, CLI truyền trực tuyến hỗ trợ tải xuống các tệp có dung lượng lớn hơn mà không cần lưu tạm toàn bộ phản hồi:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

Đối với không gian làm việc khác, hãy thêm `--profile ID` bằng cách sử dụng **Xuất → ID không gian làm việc**. Đối với máy chủ từ xa, hãy thêm `--url https://your-server`. Giới hạn truyền tải mặc định là 5 GiB; `--max-mib` cho phép thay đổi giới hạn này. Nội dung ZIP đã ký có giới hạn xác minh khi giải nén riêng biệt là 4 GiB theo mặc định (**tùy chọn Parameters** cho phép tăng giới hạn này; hãy xác minh các tệp lưu trữ như vậy bằng `verify.py --max-gib N`). Vui lòng xác minh tệp lưu trữ bằng cách sử dụng bản sao đáng tin cậy của công cụ xác minh cùng với dấu vân tay khóa hoặc điểm kiểm tra được lưu giữ độc lập.

## Kiểm tra quá trình cài đặt

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` kiểm tra các phụ thuộc cục bộ, hỗ trợ ký số, bộ nhớ lưu trữ, cấu hình khóa và địa chỉ lắng nghe. Công cụ này không cài đặt bất kỳ thành phần nào cũng như không kết nối với Telegram. Nếu cổng đang bận, điều đó có thể có nghĩa là một phiên bản khác đang chạy. Vui lòng sử dụng một `--port` khác hoặc dừng phiên bản đó trước.

Trình khởi chạy sẽ được cài đặt vào `.venv`. Các lệnh phụ trợ `python -m tgwitness...` phải sử dụng `.venv\Scripts\python.exe` trên Windows hoặc `.venv/bin/python` trên Linux/macOS, trừ khi môi trường đó đã được kích hoạt sẵn.

## Các phiên làm việc, bảo mật và vận hành

Một cơ sở dữ liệu Telethon SQLite khép kín và nhất quán `.session` có thể được chuyển đổi cục bộ bằng `python -m tgwitness.sessions account.session --out account.tgwitness-session`, sau đó được tải vào Tài khoản. Tính năng nhập tệp trực tiếp và đăng nhập qua mã QR cũng được hỗ trợ. Vui lòng tham khảo [tệp CONNECTION-SECURITY.md](../CONNECTION-SECURITY.md) để biết các định dạng đăng nhập, SOCKS5, HTTP CONNECT, MTProxy và các khóa chính bên ngoài.

**Tạm dừng quan sát** sẽ ngừng quá trình thu thập dữ liệu. **Chế độ Khóa** chỉ chặn quyền truy cập qua trình duyệt. Việc đóng một tab sẽ không làm dừng quá trình thu thập; quá trình này vẫn tiếp tục chạy. Việc dừng quá trình mới thực sự ngắt quá trình thu thập; bản chụp lịch sử không thể khôi phục lại toàn bộ các chỉnh sửa hoặc xóa bỏ đã bị bỏ lỡ. Vui lòng tham khảo [cách thức hoạt động của quá trình thu thập](../COLLECTION.md) đối với các chính sách sự kiện, hàng đợi tệp đính kèm, cách ly tài khoản và hành vi khởi động lại.

Các phiên làm việc và thông tin bí mật đều được mã hóa. Nội dung tin nhắn, tệp đa phương tiện và các tệp xuất ra yêu cầu phải được lưu trữ trên đĩa hoặc phân vùng được mã hóa. Chữ ký số xác nhận tính toàn vẹn dựa trên một khóa tin cậy; chúng không xác nhận nguồn gốc từ Telegram cũng như không ngăn chặn việc làm giả bởi người vận hành kiểm soát bộ thu thập dữ liệu và khóa của nó.

Vui lòng tham khảo [tệp OPERATIONS.md](../OPERATIONS.md) để biết thông tin về sao lưu/khôi phục, [tệp DEPLOYMENT.md](DEPLOYMENT.md) để biết về việc lưu trữ, và [thư mục deploy/](../../deploy/README.md) để xem các ví dụ về dịch vụ. Bảng điều khiển đã cài đặt cũng bao gồm hướng dẫn thiết lập ngoại tuyến tại `/guide.html`.

Các kết quả xác minh thực tế và những hạn chế còn tồn tại được ghi chép trong [các tệp VERIFICATION.md](../VERIFICATION.md) và [READINESS.md](../internal/READINESS.md).
