[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · [Español](../es/DEPLOYMENT.md) · [Português (Brasil)](../pt/DEPLOYMENT.md) · [Türkçe](../tr/DEPLOYMENT.md) · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · [Bahasa Indonesia](../id/DEPLOYMENT.md) · **Tiếng Việt** · [简体中文](../zh/DEPLOYMENT.md)

# Triển khai và vận hành

## Chọn phương thức cài đặt

Đối với gói phần mềm di động, vui lòng giải nén tệp `TgWitness-<version>-windows-amd64-portable.zip` từ GitHub Releases. Đối với các phương pháp khác, quý vị hãy tải xuống và giải nén tệp ZIP chứa mã nguồn hoặc sao chép kho lưu trữ, sau đó thực thi lệnh sau từ thư mục dự án:

| Cài đặt | Bắt đầu | Chạy ngầm? |
| --- | --- | --- |
| Gói phần mềm di động dành cho Windows | `TgWitness.cmd` | Không; xin vui lòng giữ cửa sổ này mở. |
| Phiên bản gốc dành cho Windows | `Start.cmd` | Không; vui lòng sử dụng tác vụ đăng nhập tùy chọn để chạy nền. |
| Phiên bản gốc dành cho Linux/macOS | `sh start.sh` | Không; hãy sử dụng systemd/launchd để chạy nền. |
| Docker trên bất kỳ máy chủ nào được hỗ trợ | `docker compose up -d --build --wait` | Đúng vậy, miễn là daemon Docker vẫn đang chạy. |
| Công cụ hỗ trợ Docker trên Windows | `scripts\Docker.cmd` | Đúng vậy; trình hỗ trợ sẽ theo dõi tình trạng hoạt động của máy chủ web. |
| Công cụ hỗ trợ Docker trên Linux/macOS | `sh scripts/docker-start.sh` | Đúng vậy; trình hỗ trợ sẽ theo dõi tình trạng hoạt động của máy chủ web. |

Quá trình khởi động gốc sẽ tạo ra một tệp `.venv` riêng tư và cài đặt các phụ thuộc được ghim sẵn. Docker sẽ xây dựng chúng bên trong hình ảnh, mà không cần đến Python trên máy chủ. Quá trình thiết lập lần đầu tiên cần có kết nối Internet. Khi không tìm thấy Python 3.11 trở lên, `Start.cmd` sẽ yêu cầu xác nhận trước khi cài đặt Python 3.12 cho người dùng Windows hiện tại (sử dụng winget, hoặc trình cài đặt từ python.org sau khi xác minh chữ ký của Python Software Foundation); hệ thống tuyệt đối không yêu cầu quyền quản trị viên. Docker và các dịch vụ hệ điều hành vẫn là các điều kiện tiên quyết.

Các bản cài đặt gốc và di động sử dụng `data/live` bên trong thư mục của chúng. Docker sử dụng khối lượng có tên `tgwitness-data` tại `/data`. Đây là các bản cài đặt riêng biệt cho đến khi quý vị chủ động di chuyển toàn bộ thư mục dữ liệu. Xin lưu ý rằng một container Docker mới sẽ không tự động phát hiện các tài khoản gốc.

## Yêu cầu cài đặt

Việc cài đặt bản gốc yêu cầu Python 3.11 trở lên cùng với `venv` và `ensurepip`, kết nối Internet để cài đặt các phụ thuộc ban đầu, cũng như một thư mục dự án có quyền ghi để chứa `.venv`. Giao diện đi kèm không yêu cầu Node.js hay quá trình xây dựng frontend. Vui lòng chạy trình khởi chạy từ tài khoản hệ điều hành thông thường của quý vị; TgWitness không yêu cầu quyền quản trị viên/root.

- **Trên Windows:** `Start.cmd` sẽ kiểm tra `py -3`, sau đó là `python`, tiếp theo là các thư mục cài đặt mặc định theo người dùng và thư mục Program Files, đồng thời yêu cầu phiên bản 3.11 trở lên. Nếu không có phương án nào hoạt động, hệ thống sẽ đề xuất phương án cài đặt tự động theo người dùng như đã mô tả ở trên. `py -3 start.py` cũng hoạt động bình thường. Gói phần mềm di động hoàn toàn không cần Python.
- **Trên Linux:** `start.sh` sẽ thử các tùy chọn `python3.13`, `python3.12`, `python3.11`, `python3` và `python`, đồng thời hiển thị lệnh cài đặt tương ứng cho apt, dnf, pacman, zypper, apk hoặc Homebrew nếu không có tùy chọn nào phù hợp. Các hệ thống Debian/Ubuntu có thể cần cài đặt gói `python3-venv` tương ứng với trình thông dịch đã chọn. Phiên bản Python mặc định cũ hơn của hệ điều hành phải được thay thế hoặc bổ sung bằng Python 3.11 trở lên.
- **macOS:** Vui lòng cài đặt phiên bản Python 3.11 trở lên mới nhất; không nên cho rằng trình thông dịch do hệ điều hành cung cấp đã đáp ứng yêu cầu. Sử dụng tệp `python3 start.py` từ thư mục dự án.
- **Docker:** sử dụng Docker Engine/Desktop cùng với Compose phiên bản 2.20 trở lên. Trên hệ điều hành Windows, Docker Desktop bắt buộc phải sử dụng các container Linux. Container sẽ tự cài đặt các phụ thuộc Python của riêng mình; do đó, máy chủ không cần cài đặt Python riêng biệt.

Vui lòng sử dụng bộ nhớ cục bộ lâu dài cho thư mục dữ liệu. Hãy lập kế hoạch dung lượng dựa trên số lượng tin nhắn, tệp đa phương tiện, sự gia tăng WAL, các bản xuất và bản sao lưu; không có thông số kỹ thuật tối thiểu chung nào về đĩa/RAM dựa trên bằng chứng cho mọi khối lượng công việc. Các kiến trúc CPU và phiên bản Python không có các gói phụ thuộc tương thích có thể yêu cầu các công cụ xây dựng bổ sung và quá trình kiểm định riêng. Thuật ngữ “di động” không phải là tuyên bố về khả năng hỗ trợ phổ quát trên mọi hệ điều hành hay phần cứng.

Hệ điều hành Windows 11 và Python 3.12 đã được kiểm chứng trên môi trường cục bộ. Các định nghĩa dành cho Linux, macOS và container cùng với quy trình CI đã được cung cấp nhưng chưa được thực thi trên máy chủ phát triển này. Vui lòng tham khảo [tệp VERIFICATION.md](../VERIFICATION.md) để biết phạm vi cụ thể.

## Máy tính cục bộ

Vui lòng sử dụng `Start.cmd` trên Windows hoặc `sh start.sh` trên Linux/macOS. `scripts\Setup.cmd` hoặc `sh start.sh --setup-only` sẽ chuẩn bị môi trường. Trình khởi chạy sẽ cài đặt các phụ thuộc khi sử dụng lần đầu; các lần khởi chạy sau đó sẽ tái sử dụng môi trường này. Cần có kết nối Internet để thiết lập và thu thập dữ liệu từ Telegram, tuy nhiên, việc duyệt qua các bản ghi hiện có và tạo tệp xuất vẫn có thể thực hiện được khi không có kết nối mạng.

Vui lòng chạy lệnh `python start.py --check` sau khi thiết lập để kiểm tra các phụ thuộc cục bộ, Ed25519, bộ nhớ lưu trữ, cấu hình khóa và địa chỉ lắng nghe mà không cần khởi động bộ thu thập dữ liệu. Sử dụng lệnh `--json` để nhận kết quả đầu ra có cấu trúc. Vui lòng truyền các tham số dự kiến `--data-dir`, `--host` và `--port`. Quá trình kiểm tra này không cài đặt gói phần mềm, không tạo nhật ký cũng như không kết nối với Telegram; đây không phải là quy trình đánh giá tính toàn vẹn hay phạm vi phủ sóng. Quá trình khởi động sẽ xác minh riêng các nhật ký hiện có. Lệnh `python start.py --help` cũng tránh việc cài đặt.

Các tùy chọn:

Sau khi sử dụng start.py, quý vị hãy chạy các lệnh phụ trợ bằng `.venv\Scripts\python.exe` trên Windows hoặc `.venv/bin/python` trên Linux/macOS, hoặc kích hoạt môi trường đó trước. Các ví dụ `python -m ...` dưới đây giả định rằng môi trường đã được kích hoạt.

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

Các biến môi trường: TGWITNESS_DATA, TGWITNESS_HOST, TGWITNESS_PORT, TGWITNESS_TOKEN. Biến TGWITNESS_VAULT_KEY_FILE được sử dụng để chọn chế độ khóa bên ngoài cho lần cài đặt mới; xin tham khảo phần dưới đây. TGWITNESS_TOKEN, nếu được cung cấp, phải chứa ít nhất 24 ký tự; vui lòng sử dụng một giá trị ngẫu nhiên được tạo bằng thuật toán mã hóa. Nếu không có thông số này, ứng dụng sẽ tự động tạo một mã thông báo ngẫu nhiên 256-bit trong tệp panel-token.txt. Việc ghi đè biến môi trường sẽ không ghi đè lên tệp đó. Vui lòng khởi động lại hệ thống để thay đổi thông tin xác thực.

Chỉ có đúng một tiến trình được phép sở hữu một thư mục dữ liệu. Cơ chế khóa tệp trên nhiều nền tảng hệ điều hành sẽ ngăn chặn việc ghi dữ liệu đồng thời vô tình xảy ra. Vui lòng sử dụng một công cụ Uvicorn. Bảng điều khiển có thể quản lý bất kỳ số lượng không gian làm việc nào, với các thư mục không gian làm việc bổ sung nằm trong thư mục profiles/<id>/. Đối với các phiên bản dịch vụ riêng biệt, vui lòng sử dụng các thư mục và cổng kết nối riêng biệt. Các tệp WAL của SQLite phải được lưu trữ trên bộ nhớ lưu trữ cục bộ lâu dài, không phải trên hệ thống tệp mạng. Không chia sẻ một khối lưu trữ giữa các bản sao.

## Gói phần mềm di động dành cho Windows

Mỗi bản phát hành trên GitHub đều chứa `TgWitness-<version>-windows-amd64-portable.zip` và `.sha256` tương ứng. Bản phát hành này bao gồm môi trường chạy Python 3.12 chính thức có thể nhúng từ python.org (tổng kiểm tra được cố định trong `tools/build_portable.py`), TgWitness cùng các phụ thuộc được cố định của nó, và ba trình khởi chạy:

| Tệp | Mục đích |
| --- | --- |
| `TgWitness.cmd` | Khởi động bảng điều khiển; các tùy chọn bổ sung sẽ được truyền qua, ví dụ: `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | Khởi chạy bản demo mô phỏng tại `data\demo` |
| `TgWitness-Check.cmd` | Chạy kiểm tra sẵn sàng mà không cần khởi động |

Giải nén toàn bộ tệp lưu trữ vào một thư mục có quyền ghi như `Documents\TgWitness`; không chạy chương trình từ bên trong tệp ZIP hoặc từ thư mục Program Files. Môi trường chạy sử dụng đường dẫn mô-đun cách ly, do đó các bản cài đặt Python khác và `PYTHONPATH` sẽ không ảnh hưởng đến nó. Dữ liệu được lưu trữ trong thư mục `data` của gói phần mềm. Để cập nhật, quý vị hãy dừng TgWitness, giải nén phiên bản mới vào một thư mục mới và sao chép thư mục `data` sang đó.

Tự xây dựng trên hệ điều hành Windows 64-bit với Python 3.12:

~~~sh
python tools/build_portable.py
~~~

Trình xây dựng sẽ xác minh tổng kiểm tra thời gian chạy, cài đặt các phụ thuộc được giới hạn vào gói phần mềm, thực hiện kiểm tra sẵn sàng bằng trình thông dịch nhúng và ghi tệp ZIP cùng tổng kiểm tra vào `dist/`.

## Container

```sh
docker compose up -d --build --wait
```

Quá trình này sẽ tạo ra một khối lượng lưu trữ cố định có tên cho thư mục /data. Cổng web được ánh xạ đến địa chỉ 127.0.0.1:8787. Quá trình này chạy với UID 10001 cùng các quyền hạn bị giới hạn, hệ thống tệp gốc chỉ đọc, và các thư mục /data và /tmp có thể ghi. `--wait` sẽ kiểm tra tình trạng hoạt động của máy chủ web trước khi trả về kết quả; nó không thiết lập xác thực Telegram hay quá trình gửi tin nhắn. Các hàm trợ giúp được cung cấp sẽ áp dụng thời gian chờ sẵn sàng là 180 giây sau khi hoàn tất quá trình xây dựng. Quá trình tải xuống các phụ thuộc ban đầu có thể mất nhiều thời gian hơn mức đó.

Cả hai tệp Compose cơ sở đều sử dụng tên dự án `tgwitness`; do đó, việc giải nén bản phát hành mới vào một thư mục khác sẽ không tự động chọn một khối dữ liệu mới. Vui lòng chỉ duy trì một bản triển khai đang hoạt động cho dự án đó. Đối với các cài đặt độc lập, hãy sử dụng một `docker compose -p NAME ...` duy nhất và cổng máy chủ khác, đồng thời giữ nguyên cả hai khi cập nhật. Đối với bản triển khai cũ hơn sử dụng tên dự án khác, hãy tiếp tục sử dụng tên ban đầu của nó với `-p`; `docker compose ls` liệt kê các dự án hiện có.

Vui lòng sao chép `deploy/env.example` vào `.env` và thay đổi `TGWITNESS_PORT` để sử dụng cổng loopback khác. Ví dụ: `TGWITNESS_PORT=8788` sẽ hiển thị bảng điều khiển tại `http://127.0.0.1:8788`; container vẫn lắng nghe trên cổng 8787. `.env` bị Git bỏ qua.

Lấy mã thông báo ban đầu:

~~~sh
docker compose exec tgwitness cat /data/panel-token.txt
~~~

Các lệnh hữu ích:

```sh
docker compose ps
docker compose logs --tail 100 -f
docker compose stop
docker compose up -d --wait
```

`restart: unless-stopped` sẽ khởi động lại trình thu thập dữ liệu sau khi xảy ra sự cố hoặc khi daemon Docker được khởi động lại. Trên máy chủ Linux, hãy kích hoạt Docker khi khởi động bằng trình quản lý dịch vụ của hệ điều hành, thường là `sudo systemctl enable --now docker`. Trên Windows/macOS, hãy bật cài đặt “khởi động khi đăng nhập” của Docker Desktop. Việc đăng xuất khỏi máy tính để bàn, chuyển sang chế độ ngủ hoặc daemon Docker bị dừng có thể làm gián đoạn quá trình thu thập dữ liệu. Một container bị dừng rõ ràng sẽ vẫn ở trạng thái dừng cho đến khi quý vị khởi động lại.

Trong cấu hình ví dụ, dung lượng của phân vùng /tmp được giới hạn ở mức 512 MiB. Thay vào đó, quá trình xuất dữ liệu sử dụng `temporary-exports/` của từng không gian làm việc trên phân vùng /data lưu trữ vĩnh viễn. Vui lòng dành dung lượng tại đó cho các tác vụ xuất dữ liệu đồng thời, sự gia tăng dung lượng của nhật ký/WAL, tệp phương tiện và bản sao lưu. Trình khởi chạy và Docker sử dụng tệp deploy/constraints.txt để cố định các phiên bản phụ thuộc thời gian chạy đã được xác nhận. Đây không phải là chuỗi cung ứng được khóa bằng băm: hình ảnh cơ sở Python và các gói phần mềm vẫn cần phải trải qua quá trình xác nhận phiên bản độc lập.

Xin đừng sử dụng lệnh `docker compose down -v` trừ khi quý vị có ý định xóa sổ nhật ký và các khóa. Báo cáo tình trạng container phản ánh tính khả dụng của máy chủ web, chứ không phải việc thu thập dữ liệu Telegram thành công. Vui lòng kiểm tra trạng thái bộ thu thập, tín hiệu hoạt động, các lỗi và các sự kiện phạm vi phủ sóng trên bảng điều khiển.

### Hồ sơ nhân chứng độc lập

Dịch vụ tùy chọn `witness` sẽ chạy một [chứng nhân độc lập](../WITNESS.md) trong container riêng của nó, với khóa và nhật ký riêng trong khối lượng `witness-data` và chỉ có mã thông báo chứng nhân chỉ đọc dành cho bộ thu thập. Quý vị hãy tạo mã thông báo trên trang **Chứng nhân** của bảng điều khiển, thêm mã thông báo này cùng với mã thông báo bot và kênh vào `.env`, sau đó khởi động cấu hình:

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

Dịch vụ này kết nối với bộ thu thập dữ liệu trong mạng Compose tại `http://tgwitness:8787` (`TGWITNESS_WITNESS_COLLECTOR` sẽ ghi đè lên địa chỉ này; ví dụ: `/profiles/<workspace ID>` dành cho một không gian làm việc khác). Đối với tệp chứng thực được lưu trữ trên một máy chủ riêng biệt do người khác quản lý, quý vị hãy sử dụng `deploy/compose/compose.witness.yaml` tại đó và thiết lập `TGWITNESS_WITNESS_COLLECTOR` thành địa chỉ HTTPS của bộ thu thập dữ liệu; tệp này chỉ chứa nội dung chứng thực.

## Cài đặt hình ảnh đã được phát hành

Tài liệu này sẽ được cung cấp sau khi [quy trình phát hành](#các-bản-phát-hành-tự-động-trên-github) hoàn tất thành công và cấu hình gói GHCR công khai được thiết lập. Tên/chủ sở hữu của kho lưu trữ không được mã hóa cứng trong cây nguồn này. Vui lòng sử dụng hình ảnh được hiển thị trong phần tóm tắt quy trình phát hành của phiên bản đó.

Sao chép `deploy/env.example` vào `.env`. Đặt `TGWITNESS_IMAGE` thành phiên bản đã được xuất bản, sử dụng đường dẫn kho lưu trữ **viết thường**, ví dụ:

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.7.1
TGWITNESS_PORT=8787
```

Vui lòng chạy tệp này một cách độc lập, thay vì sử dụng thẻ `compose.yaml`:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

Không cần mã nguồn, Python hay trình biên dịch trên máy chủ. Quy trình phát hành nhắm đến các container Linux AMD64 và ARM64, bao gồm cả máy ảo Linux của Docker Desktop. Vui lòng sử dụng thẻ phiên bản hoặc thẻ `ghcr.io/owner/repository@sha256:...` từ phần tóm tắt quy trình. Không có cấu hình nào cho việc di chuyển thẻ `latest` hay nâng cấp ứng dụng tự động. Các biến thể hình ảnh và mã nguồn sẽ sử dụng cùng một khối lượng dữ liệu khi tên dự án của chúng trùng khớp.

## Tự động kích hoạt HTTPS trên máy chủ

Vui lòng sử dụng một máy chủ chạy Docker, một tên miền do quý vị quản lý và bộ nhớ cục bộ lâu dài. Hãy định hướng các bản ghi A/AAAA của tên miền đến máy chủ; chỉ công bố bản ghi AAAA nếu máy chủ đó hỗ trợ IPv6. Cho phép kết nối TCP đến qua cổng 80 và 443, cũng như kết nối ra ngoài qua DNS/HTTPS để cấp phát chứng chỉ. Các dịch vụ khác không được sử dụng các cổng này trước đó.

Sao chép `deploy/env.example` vào `.env` và thiết lập tên máy chủ, không kèm theo lược đồ hoặc đường dẫn:

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

Bắt đầu quá trình biên dịch mã nguồn với lớp phủ HTTPS:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

Đối với hình ảnh đã được đăng tải, vui lòng sử dụng thẻ `deploy/compose/compose.image.yaml` làm tệp đầu tiên thay thế. Vui lòng giữ nguyên cả hai tham số `-f` để sử dụng cho các lệnh trạng thái, nhật ký, cập nhật và dừng sau này.

Caddy thực hiện việc lấy và gia hạn chứng chỉ, chuyển hướng HTTP sang HTTPS, đồng thời chuyển tiếp các yêu cầu đến bộ thu thập trên mạng Compose riêng tư. Trạng thái chứng chỉ được lưu trữ trên một khối lượng lưu trữ bền vững riêng biệt. Cổng máy chủ trực tiếp của bộ thu thập vẫn chỉ hoạt động ở chế độ loopback. Cấu hình Caddy được cung cấp không kích hoạt tính năng ghi nhật ký truy cập.

Mở `https://watch.your-domain.org` và nhập mã thông báo bảng điều khiển. Việc kiểm tra tính sẵn sàng không xác nhận việc cấp chứng chỉ hoặc khả năng kết nối từ bên ngoài. Nếu HTTPS chưa sẵn sàng, hãy kiểm tra DNS, các quy tắc tường lửa và:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

Hình ảnh Caddy được cung cấp nằm ngay sau thẻ `2-alpine`. Việc thực hiện lệnh pull sẽ làm mới hình ảnh đó; nếu quý vị cần các phiên bản hạ tầng cố định, vui lòng ghim một bản tóm tắt đã được kiểm thử vào hệ thống triển khai của quý vị.

## Các bản cập nhật và bản sao lưu

Bảo toàn tên dự án Compose và khối lượng dữ liệu qua các lần cập nhật. Trước tiên, hãy dừng trình thu thập dữ liệu và thực hiện sao lưu toàn bộ. Đối với phương thức triển khai dựa trên nguồn mặc định:

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

Mỗi lần hãy sử dụng một vị trí sao lưu mới, nằm ngoài kho lưu trữ, và bảo vệ nó như một tài liệu cần quyền truy cập tài khoản. Đường dẫn trong ví dụ chỉ mang tính minh họa; quý vị hãy sử dụng vị trí sao lưu riêng tư của mình. Sao chép toàn bộ thư mục, bao gồm các tệp ẩn, tất cả không gian làm việc, khóa, nhật ký và phương tiện truyền thông. Hãy sao lưu riêng chìa khóa chính của kho lưu trữ bên ngoài nếu đã được cấu hình. Tệp ZIP chứa bằng chứng không phải là bản sao lưu ứng dụng có thể khôi phục. Đối với HTTPS, hãy lưu giữ cả các khối lượng Caddy nếu quý vị cần duy trì trạng thái chứng chỉ/tài khoản của nó.

Để triển khai từ mã nguồn, quý vị vui lòng tải về các tệp bản phát hành mới nhất và thực thi lệnh sau:

```sh
docker compose up -d --build --wait
```

Để triển khai bằng hình ảnh, quý vị hãy thay đổi `TGWITNESS_IMAGE` thành phiên bản mong muốn, sau đó thực thi lệnh:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

Vui lòng sử dụng (các) tệp Compose của bản cài đặt để thực hiện các lệnh dừng/sao chép nêu trên. Vui lòng giữ nguyên `.env`, cấu hình tùy chỉnh và tên dự án. `down` giữ lại các khối lượng có tên; **`down -v` sẽ xóa chúng**. Không sao chép `.venv` giữa các hệ điều hành hoặc các phiên bản Python. Để cập nhật bản gốc, hãy dừng TgWitness, sao lưu toàn bộ thư mục dữ liệu của nó, thay thế các tệp nguồn và chạy `python start.py --setup-only` trước khi khởi chạy.

Vui lòng kiểm tra quyền truy cập bảng điều khiển, thông tin nhận dạng tài khoản, trạng thái quan sát và phạm vi phủ sóng sau khi cập nhật. Việc khởi động lại sẽ không khôi phục các bản cập nhật Telegram bị bỏ lỡ. Việc khôi phục về phiên bản trước có thể yêu cầu bản sao lưu trước khi cập nhật nếu phiên bản trong tương lai thay đổi định dạng lưu trữ.

## Các bản phát hành tự động trên GitHub

[Quy trình phát hành](../../.github/workflows/release.yml) sẽ sẵn sàng hoạt động sau khi dự án này được đẩy lên kho lưu trữ GitHub có bật tính năng Actions. Quy trình này sẽ được kích hoạt khi một bản phát hành GitHub được **công bố**, bao gồm cả bản phát hành trước. Việc đẩy bản nháp hoặc thẻ (tag) đơn thuần sẽ không dẫn đến việc phát hành các gói phần mềm.

1. Vui lòng thiết lập phiên bản gói phần mềm và nhật ký thay đổi, sau đó phát hành bản cập nhật được gắn thẻ bằng `v` cùng với phiên bản chính xác `pyproject.toml`, chẳng hạn như `v0.7.1`.
2. Quy trình làm việc này sẽ xác thực thẻ và thực thi các kiểm tra chung cho Python trên Windows/Linux/macOS, trình duyệt chung/nhập tài khoản/mã QR, gói nguồn cũng như các kiểm tra Docker. Việc cài đặt bản gốc mới cũng được thực hiện trên cả ba hệ điều hành này bằng Python 3.12.
3. Sau khi các bước kiểm tra này thành công, hệ thống sẽ tiến hành kiểm tra sơ bộ (smoke test) hình ảnh ARM64 trên QEMU, đăng tải các hình ảnh AMD64/ARM64 lên `ghcr.io/<lowercase-owner>/<lowercase-repository>:<version>`, đồng thời đính kèm tệp ZIP nguồn, tổng kiểm tra (checksum) và gói Python wheel vào bản phát hành. Một tác vụ riêng biệt trên Windows sẽ biên dịch và đính kèm tệp ZIP di động cùng tổng kiểm tra (checksum) của nó.
4. Sau lần xuất bản đầu tiên, quý vị hãy mở cài đặt gói GHCR và đặt quyền truy cập thành **Công khai** nếu có ý định thực hiện việc tải xuống hình ảnh ẩn danh. Chỉ riêng kho lưu trữ nguồn công khai không đảm bảo rằng gói container cũng sẽ công khai. Chính sách của tổ chức phải cho phép việc xuất bản gói. Quy trình làm việc sử dụng thẻ `GITHUB_TOKEN`; tuyệt đối không được lưu mật khẩu kho lưu trữ hoặc thông tin đăng nhập VPS trong kho lưu trữ.

Việc chuẩn bị tại địa phương này chưa đảm bảo thành công cho quy trình làm việc từ xa. Việc mô phỏng ARM64 chỉ là bước kiểm tra sơ bộ, không phải là quá trình kiểm định trên phần cứng gốc hay kiểm định Telegram trực tiếp. Tính năng này tự động hóa quá trình đóng gói bản phát hành; tuy nhiên, việc khởi động máy chủ vẫn yêu cầu lệnh Compose cùng các điều kiện tiên quyết về tên miền/máy chủ. Các máy chủ hiện có sẽ không được nâng cấp hoặc khởi động lại tự động khi có bản phát hành mới.

## Máy chủ từ xa

Vui lòng giữ dịch vụ kết nối với loopback và sử dụng đường hầm SSH, hoặc kết thúc kết nối HTTPS tại một máy chủ proxy ngược. Tệp Compose cơ bản chỉ hoạt động trong mạng nội bộ; lớp phủ tùy chọn `deploy/compose/compose.https.yaml` cung cấp Caddy cho một tên miền đã được cấu hình. Vui lòng không để mã thông báo bearer xuất hiện trong các URL và nhật ký proxy. Máy chủ proxy ngược nên giới hạn kích thước yêu cầu và tần suất kết nối. Không được để HTTP thuần túy tiếp xúc với Internet.

Các ví dụ về systemd, tác vụ đăng nhập trên Windows, trình duyệt người dùng trên macOS và Caddy được cung cấp trong [thư mục deploy/. Quý vị](../../deploy/README.md) vui lòng kiểm tra và điều chỉnh các đường dẫn tương ứng trước khi cài đặt. Đây chỉ là các mẫu được cung cấp sẵn, không phải là các cấu hình nền tảng được thực thi cục bộ. Trình khởi chạy thông thường sẽ không đăng ký bất kỳ dịch vụ nền hay tác vụ nào.

Trên hệ điều hành Windows, khi khởi chạy ở chế độ không hiển thị cửa sổ `pythonw.exe`, các dữ liệu chẩn đoán khởi động/máy chủ sẽ được lưu trữ tại `logs/server.log` trong thư mục dữ liệu (5 MiB mỗi tệp, kèm theo hai bản sao lưu luân phiên). Khi khởi chạy ở chế độ giao diện điều khiển, nhật ký giao diện điều khiển vẫn được lưu giữ. Tính năng ghi nhật ký truy cập HTTP bị vô hiệu hóa ở cả hai chế độ. Quý vị nên bảo vệ các tệp nhật ký cùng với thư mục dữ liệu và kiểm tra kỹ trước khi chia sẻ.

## Khởi động lại và các khoảng trống

Trạng thái quan sát được yêu cầu gần nhất sẽ được lưu lại. Nếu quá trình quan sát đang hoạt động, khi khởi động hệ thống sẽ cố gắng kết nối lại và tiếp tục theo dõi các nguồn đã chọn. Việc tạm dừng thủ công sẽ hủy bỏ ý định đó. Các trường hợp khởi động lại không thành công sẽ được ghi lại và hiển thị trên bảng điều khiển.

StringSession duy trì quyền truy cập nhưng không lưu giữ trạng thái cập nhật/thực thể bền vững của Telethon. Các cuộc trò chuyện sẽ được tải lại khi khởi động. Telegram/Telethon có thể khắc phục một số sự cố gián đoạn truyền tải trong quá trình chạy, nhưng TgWitness không đảm bảo khả năng phát lại bền vững khi khởi động lại quy trình. Mỗi lần khởi động sẽ ghi lại đầu nhật ký trước đó và ranh giới ngoại tuyến. Trình giám sát sẽ kiểm tra kết nối cứ sau 10 giây và thêm tín hiệu kiểm tra trạng thái hoạt động mỗi phút (**Tham số → Ghi lại trạng thái hoạt động mỗi**). Các sự gián đoạn ngắn có thể bị bỏ sót; việc kết nối truyền tải không đảm bảo việc truyền tải cập nhật hoàn toàn. Các bản chụp nhanh là những quan sát rõ ràng về lịch sử hiện tại, không bao giờ là việc sửa chữa khoảng trống.

Hàng đợi phương tiện được lưu trữ trong cơ sở dữ liệu SQLite của từng không gian làm việc. Một tin nhắn và tác vụ liên quan đến nó được ghi vào cơ sở dữ liệu theo cơ chế nguyên tử. Các tác vụ đang chạy bị gián đoạn sẽ được khôi phục để thử lại khi khởi động. Mỗi lần tải xuống có thời gian chờ cơ bản là 120 giây cộng với thời gian tính theo tốc độ 256 KiB/s tương ứng với kích thước tệp, và giới hạn từ 1–2.000 MiB cho mỗi loại tệp đính kèm; các thông số về thời gian chờ, tốc độ và số lần thử lại được thiết lập trong **phần** **Thông số**. Trình thu thập sẽ bỏ qua các tệp có kích thước không xác định. Việc tạm dừng sẽ giữ nguyên các tác vụ đang xếp hàng. Quá trình thử lại sử dụng bộ mô tả tệp ban đầu đã được ghi nhận, chứ không bao giờ sử dụng phiên bản mới nhất của một tin nhắn đã được chỉnh sửa sau đó. Các sự cố tạm thời có số lần thử lại giới hạn; việc tạm dừng do FloodWait đối với phương tiện truyền thông vẫn được duy trì sau khi khởi động lại. Việc khôi phục phương tiện truyền thông là độc lập với việc khôi phục cập nhật Telegram và không thể tái tạo các tệp đã biến mất.

## Sao lưu, khôi phục và dung lượng

Vui lòng dừng quá trình trước khi sao chép **toàn** **bộ thư mục dữ liệu**, bao gồm các tệp vault.key, signing.enc, credentials.enc, cơ sở dữ liệu SQLite/tệp WAL, tệp đa phương tiện, mã thông báo, điểm kiểm tra, cũng như tất cả các hồ sơ và thư mục con. Hãy khôi phục bản sao hoàn chỉnh trong khi dịch vụ đích đang bị dừng. Việc thiếu khóa vault hoặc không khớp khóa ký sẽ khiến quá trình khởi động thất bại; xin đừng tái tạo khóa để ép buộc truy cập.

Hãy đảm bảo các bản sao lưu bí mật được mã hóa và kiểm soát quyền truy cập. Các tệp ZIP chứa bằng chứng là các tài liệu xem xét có thể di chuyển, không phải là bản sao lưu ứng dụng hay bản sao lưu phiên Telegram. Hệ thống không tự động xóa dữ liệu sau thời gian lưu trữ. Quý vị cần lên kế hoạch về dung lượng đĩa cho tất cả tin nhắn, siêu dữ liệu thô, tệp đa phương tiện, các tệp xuất tạm thời và các bản sao lưu.

Bắt đầu xác minh và xuất các bản ghi luồng thay vì tải toàn bộ nhật ký. Quá trình xuất sẽ cố định một bản chụp nhanh đã đọc trong khi các ghi WAL mới vẫn có thể tiếp tục; các tác vụ xuất kéo dài có thể giữ lại các trang WAL, do đó dung lượng đĩa vẫn là yếu tố quan trọng. Các tệp ZIP được giới hạn ở mức 4 GiB khi giải nén để phù hợp với cài đặt mặc định của bên xác minh độc lập; **Tham số → “Largest signed ZIP” (Tệp ZIP có chữ ký lớn nhất)** sẽ nâng giới hạn này lên, và các tệp lưu trữ như vậy sẽ được xác minh bằng `verify.py --max-gib N`. Các định dạng khác không có giới hạn về số lượng sự kiện. Các trình duyệt được hỗ trợ sẽ truyền các đoạn phản hồi theo luồng vào tệp do người dùng chọn. Các trình duyệt khác sẽ lưu trữ tạm thời tối đa 128 MiB và chuyển các tệp có dung lượng lớn hơn trực tiếp đến CLI đã được xác thực:

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

Vui lòng sử dụng `--profile ID` từ **mục Xuất → ID Không gian làm việc** cho một không gian làm việc khác, `--format zip|jsonl|csv|html`, `--url https://your-server` cho máy chủ từ xa, hoặc `--max-mib` để thay đổi giới hạn truyền tải 5 GiB. Giao thức HTTP thuần túy chỉ được phép sử dụng cho kết nối vòng lặp. Các mã thông báo được truyền qua tiêu đề, các yêu cầu chuyển hướng sẽ bị từ chối, các tệp hiện có sẽ không bị ghi đè, và các tệp đang tải xuống chưa hoàn tất sẽ không được công bố như các tệp đã hoàn tất. Nếu TGWITNESS_TOKEN ghi đè lên mã thông báo được tạo, xin vui lòng sử dụng một tệp được bảo vệ riêng biệt chứa giá trị đang hoạt động đó: tệp panel-token.txt sẽ không bị ghi đè bởi giá trị ghi đè này. Giá trị SHA-256 của lệnh chỉ là tổng kiểm tra truyền tải; quý vị cần xác minh độc lập tệp ZIP đã được ký.

Các tệp xuất từ máy chủ vẫn được lưu giữ bên trong thư mục riêng tư `temporary-exports/` của từng không gian làm việc. Các phản hồi thành công sẽ tự động xóa các tệp của mình. Các quá trình xuất bị gián đoạn sẽ bị xóa khi khởi động lại không gian làm việc tiếp theo, khi khóa phiên bản độc quyền của nó vẫn được duy trì. Thư mục này là một phần của mô hình đe dọa/dung lượng lưu trữ; vui lòng sử dụng khối dữ liệu được mã hóa. Các hoạt động truyền tải dữ liệu quy mô sản xuất với dung lượng nhiều gigabyte vẫn cần được kiểm định trên hệ thống đích của quý vị.

Bảng điều khiển hiển thị các tệp phương tiện đang chờ xử lý/bị lỗi, tệp phương tiện đang chờ xử lý lâu nhất, dung lượng đĩa trống, các trường hợp tạm dừng yêu cầu Telegram và các nguồn chưa được xác nhận quyền truy cập. Các chẩn đoán này không phải là công cụ giám sát quá trình truyền tải từ đầu đến cuối hoàn chỉnh. Các không gian làm việc chia sẻ chung một quy trình; do đó, một tài khoản gây nhiễu vẫn có thể ảnh hưởng đến các tài khoản khác. Các vấn đề còn lại bao gồm: các tiến trình xử lý riêng biệt, chính sách lưu trữ/xoay vòng, khôi phục cập nhật bền vững, neo điểm kiểm tra từ xa, phân quyền vai trò và quy trình kiểm định triển khai đầy đủ.

## Các tùy chọn kết nối và bảo mật

Các tuyến kết nối được thiết lập riêng cho từng không gian làm việc và cần được cấu hình trước khi thực hiện ủy quyền. SOCKS5/HTTP CONNECT sử dụng phụ thuộc python-socks đã được ghim cố định. MTProxy sử dụng giao thức truyền tải trung gian ngẫu nhiên đang trong giai đoạn thử nghiệm của Telethon; các khóa bí mật TLS giả mạo không được hỗ trợ. Không có cấu hình chuyển đổi dự phòng trực tiếp tự động nào được thiết lập. Đây không phải là tuyến mạng áp dụng cho toàn hệ thống.

Đối với các cài đặt mới, biến môi trường TGWITNESS_VAULT_KEY_FILE phải trỏ đến một tệp khóa chủ ngẫu nhiên được bảo vệ riêng biệt. Vui lòng gắn tệp này ở chế độ chỉ đọc bên ngoài thư mục /data trong một container. Hãy lưu giữ riêng biệt siêu dữ liệu muối công khai trong tệp vault.external.json cho từng không gian làm việc cùng với khóa chủ. Các kho dữ liệu cục bộ hiện có cần được di chuyển theo kế hoạch; việc thiết lập biến này sẽ không tự động chuyển đổi chúng. Việc lưu trữ và xuất tin nhắn/tệp đa phương tiện không được mã hóa bởi ứng dụng. Vui lòng sử dụng các phân vùng được mã hóa và đảm bảo có đủ dung lượng lưu trữ tạm thời riêng tư khi cần thiết.

Các quy trình chi tiết: [kết nối/bảo mật](../CONNECTION-SECURITY.md) và [các chế độ hoạt động](../OPERATIONS.md).
