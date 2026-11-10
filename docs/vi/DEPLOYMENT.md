[TgWitness](../../README.md) / [Tài liệu hướng dẫn](../README.md) / [Thư mục](README.md)

![Triển khai và khôi phục](../assets/presentation/chapter-operate.svg)

[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · [Español](../es/DEPLOYMENT.md) · [Português (Brasil)](../pt/DEPLOYMENT.md) · [Türkçe](../tr/DEPLOYMENT.md) · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · [Bahasa Indonesia](../id/DEPLOYMENT.md) · **Tiếng Việt** · [简体中文](../zh/DEPLOYMENT.md)

# Triển khai và vận hành

## Chọn cách cài đặt

Với gói portable, hãy giải nén `TgWitness-<version>-windows-amd64-portable.zip` tải từ GitHub Releases. Với các cách khác, hãy tải xuống và giải nén tệp ZIP mã nguồn hoặc clone kho mã nguồn, rồi chạy lệnh tương ứng dưới đây từ thư mục dự án:

| Cách cài đặt | Khởi động | Chạy nền? |
| --- | --- | --- |
| Gói portable cho Windows | `TgWitness.cmd` | Không; hãy giữ cửa sổ mở. |
| Windows, cài đặt trực tiếp | `Start.cmd` | Không; để chạy nền, hãy dùng tác vụ khi đăng nhập (tùy chọn). |
| Linux/macOS, cài đặt trực tiếp | `sh start.sh` | Không; để chạy nền, hãy dùng systemd/launchd. |
| Docker trên mọi máy host được hỗ trợ | `docker compose up -d --build --wait` | Có, miễn là Docker daemon đang chạy. |
| Tập lệnh hỗ trợ Docker trên Windows | `scripts\Docker.cmd` | Có; tập lệnh chờ đến khi máy chủ web hoạt động bình thường. |
| Tập lệnh hỗ trợ Docker trên Linux/macOS | `sh scripts/docker-start.sh` | Có; tập lệnh chờ đến khi máy chủ web hoạt động bình thường. |

Với máy chủ đám mây mà bên thứ ba cần kiểm tra được — được tạo qua API của nhà cung cấp, không có SSH, chỉ truy cập được qua Cloudflare Tunnel — xem [triển khai có độ đảm bảo cao](../HIGH-ASSURANCE.md).

Khi khởi động bản cài đặt trực tiếp (native), một `.venv` riêng sẽ được tạo và các thành phần phụ thuộc đã ghim phiên bản sẽ được cài đặt. Docker build các thành phần này bên trong image, không cần Python trên máy host. Lần thiết lập đầu tiên cần kết nối Internet. Khi không tìm thấy Python 3.11+, `Start.cmd` sẽ hỏi trước khi cài Python 3.12 cho người dùng Windows hiện tại (qua winget, nếu không được thì dùng trình cài đặt từ python.org sau khi kiểm tra chữ ký Python Software Foundation của nó); tập lệnh không bao giờ yêu cầu quyền quản trị viên. Docker và các dịch vụ của hệ điều hành vẫn là điều kiện tiên quyết.

Bản cài đặt trực tiếp và bản portable dùng `data/live` trong thư mục của chúng. Docker dùng volume có tên `tgwitness-data` gắn tại `/data`. Đây là các bản cài đặt riêng biệt cho đến khi bạn chủ động di chuyển toàn bộ thư mục dữ liệu. Đừng kỳ vọng một container Docker mới sẽ tự động phát hiện các tài khoản của bản cài đặt trực tiếp.

## Yêu cầu cài đặt

Cài đặt trực tiếp cần Python 3.11 trở lên có `venv` và `ensurepip`, kết nối Internet cho lần cài đặt thành phần phụ thuộc đầu tiên, và một thư mục dự án có quyền ghi để chứa `.venv`. Bảng điều khiển đi kèm không cần Node.js hay bước build frontend. Hãy chạy trình khởi chạy từ tài khoản hệ điều hành thông thường của bạn; TgWitness không yêu cầu quyền quản trị viên/root.

- **Windows:** `Start.cmd` lần lượt kiểm tra `py -3`, rồi `python`, rồi các thư mục cài đặt mặc định theo người dùng và trong Program Files, và yêu cầu phiên bản 3.11 trở lên. Nếu không có lựa chọn nào dùng được, tập lệnh sẽ đề nghị cài đặt tự động cho người dùng hiện tại như mô tả ở trên. `py -3 start.py` cũng dùng được. Gói portable hoàn toàn không cần Python.
- **Linux:** `start.sh` thử `python3.13`, `python3.12`, `python3.11`, `python3` và `python`, và khi không có trình thông dịch nào đạt yêu cầu thì in ra lệnh cài đặt cho apt, dnf, pacman, zypper, apk hoặc Homebrew. Bản cài đặt trên Debian/Ubuntu có thể cần gói `python3-venv` khớp với trình thông dịch được chọn. Nếu Python mặc định của bản phân phối đã cũ, cần thay thế hoặc cài thêm Python 3.11+.
- **macOS:** hãy cài một bản phân phối Python 3.11+ hiện hành; đừng mặc định rằng trình thông dịch đi kèm hệ điều hành đáp ứng yêu cầu. Dùng `python3 start.py` từ thư mục dự án.
- **Docker:** dùng Docker Engine/Desktop với Compose v2.20 trở lên. Trên Windows, Docker Desktop phải dùng container Linux. Container tự cài các thành phần phụ thuộc Python của nó; máy host không cần cài Python riêng.

## Máy tính cục bộ

Dùng `Start.cmd` trên Windows hoặc `sh start.sh` trên Linux/macOS. `scripts\Setup.cmd` hoặc `sh start.sh --setup-only` sẽ chuẩn bị môi trường. Trình khởi chạy cài đặt các thành phần phụ thuộc ở lần dùng đầu tiên; các lần khởi chạy sau dùng lại môi trường đó. Cần kết nối Internet để thiết lập và thu thập dữ liệu từ Telegram, nhưng việc duyệt các bản ghi hiện có và tạo bản xuất vẫn hoạt động ngoại tuyến.

Sau khi thiết lập, chạy `python start.py --check` để kiểm tra các thành phần phụ thuộc cục bộ, Ed25519, bộ nhớ lưu trữ, cấu hình khóa và địa chỉ lắng nghe mà không khởi động trình thu thập. Dùng `--json` để có đầu ra có cấu trúc. Truyền vào `--data-dir`, `--host` và `--port` mà bạn định dùng. Lệnh kiểm tra không cài gói, không tạo sổ nhật ký và không kết nối Telegram; đây không phải là kiểm định về tính toàn vẹn hay phạm vi bao phủ. Khi khởi động, ứng dụng xác minh riêng các sổ nhật ký hiện có. `python start.py --help` cũng không kích hoạt việc cài đặt.

Sau khi dùng start.py, hãy chạy các lệnh phụ trợ bằng `.venv\Scripts\python.exe` trên Windows hoặc `.venv/bin/python` trên Linux/macOS, hoặc kích hoạt môi trường đó trước. Các ví dụ `python -m ...` dưới đây giả định môi trường đã được kích hoạt.

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

Biến môi trường: TGWITNESS_DATA, TGWITNESS_HOST, TGWITNESS_PORT, TGWITNESS_TOKEN. TGWITNESS_VAULT_KEY_FILE chọn chế độ khóa bên ngoài cho bản cài đặt mới; xem [Khóa chính bên ngoài](../SECURITY-MODEL.md#external-master-key). Nếu được cung cấp, TGWITNESS_TOKEN phải có ít nhất 24 ký tự; hãy dùng một giá trị ngẫu nhiên an toàn về mật mã. Nếu không có biến này, ứng dụng sẽ tạo một mã thông báo ngẫu nhiên 256 bit trong panel-token.txt. Giá trị ghi đè qua biến môi trường không ghi lại tệp đó. Hãy khởi động lại để thay mới thông tin xác thực.

Mỗi thư mục dữ liệu chỉ được đúng một tiến trình sở hữu. Khóa tệp của hệ điều hành, hoạt động trên mọi nền tảng, ngăn việc vô tình có nhiều tiến trình ghi đồng thời. Hãy dùng một worker Uvicorn. Bảng điều khiển có thể quản lý số lượng không gian làm việc tùy ý, với thư mục của các không gian làm việc bổ sung nằm trong profiles/<id>/. Với các instance dịch vụ riêng biệt, hãy dùng thư mục và cổng riêng. Các tệp SQLite WAL phải nằm trên bộ nhớ lưu trữ cục bộ bền vững, không nằm trên hệ thống tệp mạng. Không dùng chung một volume giữa các bản sao (replica).

## Gói portable cho Windows

Mỗi GitHub Release đi kèm `TgWitness-<version>-windows-amd64-portable.zip` và tệp `.sha256` của nó. Gói này chứa môi trường chạy Python 3.12 dạng nhúng (embeddable) chính thức từ python.org (checksum được ghim trong `tools/build_portable.py`), TgWitness cùng các thành phần phụ thuộc đã ghim phiên bản, và ba trình khởi chạy:

| Tệp | Mục đích |
| --- | --- |
| `TgWitness.cmd` | Khởi động bảng điều khiển; các tùy chọn bổ sung được chuyển tiếp, ví dụ `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | Khởi động bản demo với dữ liệu giả lập trong `data\demo` |
| `TgWitness-Check.cmd` | Chạy kiểm tra mức sẵn sàng mà không khởi động ứng dụng |

Từ điển hình thái học tiếng Nga và các hồ sơ màu PDF đã ghim phiên bản được đóng gói sẵn để dùng ngoại tuyến. Quá trình đóng gói chỉ cho phép các đường dẫn tệp đã biết của chúng bên trong các thư mục `data` của thành phần phụ thuộc; tệp không mong đợi trong các thư mục đó sẽ làm bản build thất bại.

Giải nén toàn bộ tệp lưu trữ vào một thư mục có quyền ghi, chẳng hạn `Documents\TgWitness`; không chạy từ bên trong tệp ZIP hoặc từ Program Files. Môi trường chạy dùng đường dẫn mô-đun tách biệt, nên các bản cài Python khác và `PYTHONPATH` không ảnh hưởng đến nó. Dữ liệu nằm trong thư mục `data` của gói. Để cập nhật, hãy dừng TgWitness, giải nén phiên bản mới vào một thư mục mới rồi sao chép thư mục `data` sang.

Tự build gói trên Windows 64 bit với Python 3.12:

~~~sh
python tools/build_portable.py
~~~

## Container

```sh
docker compose up -d --build --wait
```

Lệnh này tạo một volume bền vững có tên cho /data. Cổng web được ánh xạ tới 127.0.0.1:8787. Tiến trình chạy với UID 10001, đã loại bỏ các capability, hệ thống tệp gốc chỉ đọc, còn /data và /tmp có quyền ghi. `--wait` kiểm tra tình trạng máy chủ web trước khi trả về; việc ủy quyền Telegram và tình trạng phân phối dữ liệu được hiển thị trong bảng điều khiển. Các tập lệnh hỗ trợ đi kèm dùng thời gian chờ sẵn sàng 180 giây sau khi build. Lần tải các thành phần phụ thuộc đầu tiên có thể lâu hơn thế.

Cả hai tệp Compose cơ sở đều dùng tên dự án `tgwitness`, nên việc giải nén bản phát hành mới vào thư mục khác sẽ không âm thầm chọn một volume dữ liệu mới. Chỉ giữ một bản triển khai hoạt động cho dự án đó. Với các bản cài đặt độc lập, hãy dùng `docker compose -p NAME ...` với tên riêng và một cổng khác trên máy host, đồng thời giữ nguyên cả hai khi cập nhật. Với bản triển khai cũ dùng tên dự án khác, hãy tiếp tục dùng tên ban đầu của nó với `-p`; `docker compose ls` liệt kê các dự án hiện có.

Sao chép `deploy/env.example` thành `.env` và đổi `TGWITNESS_PORT` để dùng một cổng loopback khác. Ví dụ: `TGWITNESS_PORT=8788` đưa bảng điều khiển ra địa chỉ `http://127.0.0.1:8788`; container vẫn lắng nghe trên cổng 8787. `.env` được Git bỏ qua.

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

`restart: unless-stopped` khởi động lại trình thu thập sau khi bị sập hoặc khi Docker daemon khởi động lại. Trên máy chủ Linux, hãy bật Docker khởi động cùng hệ thống bằng trình quản lý dịch vụ của bản phân phối, thường là `sudo systemctl enable --now docker`. Trên Windows/macOS, hãy bật tùy chọn khởi động khi đăng nhập của Docker Desktop. Việc đăng xuất khỏi máy, chế độ ngủ hoặc Docker daemon bị dừng có thể làm gián đoạn việc thu thập. Container đã được dừng chủ động sẽ ở trạng thái dừng cho đến khi bạn khởi động lại.

Trong cấu hình mẫu, volume /tmp bị giới hạn ở 512 MiB. Thay vào đó, việc tạo bản xuất dùng thư mục `temporary-exports/` của từng không gian làm việc trên /data bền vững. Hãy dành dung lượng ở đó cho các bản xuất chạy đồng thời, sự tăng trưởng của sổ nhật ký/WAL, tệp phương tiện và bản sao lưu. Trình khởi chạy dùng deploy/constraints.txt để ghim các phiên bản thành phần phụ thuộc lúc chạy đã được kiểm định. Docker và các máy chủ độ đảm bảo cao cài đặt từ deploy/requirements.lock và deploy/build.lock với pip --require-hashes: mọi tệp gói phải khớp với một giá trị SHA-256 được ghi trong commit, nên tệp bị thay thế trên PyPI hoặc trên một bản mirror sẽ bị từ chối. Image cơ sở Python và các gói của hệ điều hành vẫn cần được kiểm định phát hành độc lập.

Không dùng docker compose down -v trừ khi bạn định hủy sổ nhật ký và các khóa. Tình trạng (health) của container phản ánh khả năng hoạt động của máy chủ web, không phải việc thu thập Telegram thành công. Hãy kiểm tra trạng thái trình thu thập, tín hiệu nhịp (heartbeat), lỗi và các sự kiện phạm vi bao phủ trong bảng điều khiển.

### Profile nhân chứng độc lập

Dịch vụ tùy chọn `witness` chạy một [nhân chứng độc lập](../WITNESS.md) trong container riêng, với khóa và sổ nhật ký riêng trong volume `witness-data`, và chỉ có một mã thông báo nhân chứng chỉ đọc để truy cập trình thu thập. Hãy tạo mã thông báo trong bảng điều khiển tại **Các công cụ khác → Tiện ích bổ sung → Nhân chứng độc lập**, thêm nó cùng mã thông báo bot và kênh vào `.env`, rồi khởi động profile:

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

Dịch vụ này kết nối tới trình thu thập trong mạng Compose tại `http://tgwitness:8787` (`TGWITNESS_WITNESS_COLLECTOR` ghi đè địa chỉ này, ví dụ `/profiles/<workspace ID>` cho một không gian làm việc khác). Với một nhân chứng chạy trên máy chủ riêng do người khác vận hành, hãy dùng `deploy/compose/compose.witness.yaml` trên máy chủ đó và đặt `TGWITNESS_WITNESS_COLLECTOR` thành địa chỉ HTTPS của trình thu thập; tệp đó chỉ chứa nhân chứng.

## Cài đặt image đã phát hành

Sao chép `deploy/env.example` thành `.env`. Đặt `TGWITNESS_IMAGE` thành phiên bản đã phát hành, dùng đường dẫn kho mã nguồn viết **chữ thường**, ví dụ:

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.9.2
TGWITNESS_PORT=8787
```

Chạy riêng tệp này, thay cho `compose.yaml`:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

Máy host không cần build từ mã nguồn, không cần Python hay trình biên dịch. Workflow phát hành nhắm tới container Linux AMD64 và ARM64, kể cả máy ảo Linux của Docker Desktop. Hãy dùng tag phiên bản hoặc `ghcr.io/owner/repository@sha256:...` từ phần tóm tắt của workflow. Không có tag `latest` thay đổi theo thời gian, cũng không có cơ chế tự động nâng cấp ứng dụng nào được cấu hình. Biến thể dùng image và biến thể dùng mã nguồn sẽ dùng chung volume dữ liệu khi tên dự án của chúng trùng nhau.

<a name="automatic-https-on-a-server"></a>

## HTTPS tự động trên máy chủ

Bạn cần một máy chủ có Docker, một tên miền do bạn kiểm soát và bộ nhớ lưu trữ cục bộ bền vững. Trỏ bản ghi A/AAAA của tên miền tới máy chủ; chỉ công bố bản ghi AAAA nếu máy chủ truy cập được qua IPv6. Cho phép kết nối vào qua TCP 80 và 443, và kết nối ra DNS/HTTPS để cấp chứng chỉ. Các cổng này không được đang bị dịch vụ khác chiếm dụng.

Sao chép `deploy/env.example` thành `.env` và đặt tên máy chủ (hostname), không kèm scheme hay đường dẫn:

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

Khởi động bản build từ mã nguồn với tệp overlay HTTPS:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

Với image đã phát hành, hãy dùng `deploy/compose/compose.image.yaml` làm tệp thứ nhất thay vào đó. Giữ cả hai tham số `-f` cho các lệnh xem trạng thái, xem log, cập nhật và dừng về sau.

Caddy lấy và gia hạn chứng chỉ, chuyển hướng HTTP sang HTTPS và chuyển tiếp yêu cầu tới trình thu thập trong mạng Compose riêng. Trạng thái chứng chỉ có volume bền vững riêng. Cổng trực tiếp của trình thu thập trên máy host vẫn chỉ mở trên loopback. Cấu hình Caddy đi kèm không bật ghi log truy cập.

Mở `https://watch.your-domain.org` và nhập mã thông báo bảng điều khiển. Trạng thái sẵn sàng của Compose áp dụng cho các container; việc cấp chứng chỉ và khả năng truy cập từ bên ngoài phụ thuộc vào DNS và tường lửa. Nếu HTTPS chưa sẵn sàng, hãy kiểm tra DNS, quy tắc tường lửa và:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

Image Caddy đi kèm theo tag `2-alpine`. Mỗi lần pull sẽ làm mới image đó; nếu cần phiên bản hạ tầng cố định, hãy ghim một digest đã kiểm thử trong bản triển khai của bạn.

## Cập nhật và sao lưu

Giữ nguyên tên dự án Compose và volume dữ liệu qua các lần cập nhật. Trước tiên, hãy dừng trình thu thập và tạo bản sao lưu đầy đủ. Với kiểu triển khai mặc định dựa trên mã nguồn:

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

Mỗi lần hãy dùng một vị trí sao lưu mới, nằm ngoài kho mã nguồn, và bảo vệ nó như dữ liệu cho phép truy cập tài khoản. Đường dẫn trong ví dụ chỉ mang tính minh họa; hãy dùng vị trí sao lưu riêng của bạn. Sao chép toàn bộ thư mục, bao gồm tệp ẩn, tất cả không gian làm việc, khóa, sổ nhật ký và tệp phương tiện. Nếu đã cấu hình khóa chính bên ngoài cho kho dữ liệu, hãy sao lưu nó riêng. Tệp ZIP bằng chứng không phải là bản sao lưu ứng dụng có thể khôi phục. Với HTTPS, hãy giữ cả các volume của Caddy nếu bạn cần giữ lại trạng thái chứng chỉ/tài khoản của nó.

Với triển khai từ mã nguồn, hãy lấy các tệp của bản phát hành mới và chạy:

```sh
docker compose up -d --build --wait
```

Với triển khai bằng image, hãy đổi `TGWITNESS_IMAGE` thành phiên bản mong muốn, rồi chạy:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

Với các lệnh dừng/sao chép ở trên, cũng hãy dùng (các) tệp Compose của bản cài đặt của bạn. Giữ nguyên `.env`, cấu hình tùy chỉnh và cùng tên dự án. `down` giữ lại các volume có tên; **`down -v` sẽ xóa chúng**. Không sao chép `.venv` giữa các hệ điều hành hoặc phiên bản Python khác nhau. Để cập nhật bản cài đặt trực tiếp, hãy dừng TgWitness, sao lưu toàn bộ thư mục dữ liệu của nó, thay thế các tệp mã nguồn và chạy `python start.py --setup-only` trước khi khởi động.

Sau khi cập nhật, hãy kiểm tra quyền truy cập bảng điều khiển, danh tính tài khoản, trạng thái quan sát và phạm vi bao phủ. Sau khi khởi động lại, TgWitness tiếp tục từ vị trí cập nhật Telegram đã lưu và yêu cầu các cập nhật bị bỏ lỡ trong thời gian cập nhật. Nếu một phiên bản trong tương lai thay đổi định dạng lưu trữ, việc quay lui (rollback) có thể cần đến bản sao lưu trước khi cập nhật.

## Máy chủ từ xa

Giữ dịch vụ lắng nghe trên loopback và dùng đường hầm SSH, hoặc kết thúc HTTPS tại một reverse proxy. Tệp Compose cơ sở chỉ dùng cục bộ; tệp overlay tùy chọn `deploy/compose/compose.https.yaml` cung cấp Caddy cho một tên miền đã cấu hình. Không để bearer token xuất hiện trong URL và log của proxy. Reverse proxy nên giới hạn kích thước yêu cầu và tần suất kết nối. Không để lộ HTTP thuần ra Internet.

Các ví dụ cho systemd, tác vụ khi đăng nhập Windows, user agent của macOS và Caddy có trong [deploy/](../../deploy/README.md). Hãy xem lại và điều chỉnh đường dẫn trong đó trước khi cài đặt. Đây là các mẫu được cung cấp sẵn, không phải kết quả kiểm định nền tảng đã chạy cục bộ. Trình khởi chạy thông thường không đăng ký dịch vụ nền hay tác vụ nào.

Trên Windows, khi khởi chạy không cửa sổ bằng `pythonw.exe`, thông tin chẩn đoán khởi động/máy chủ được lưu vào `logs/server.log` trong thư mục dữ liệu (5 MiB mỗi tệp, giữ hai bản xoay vòng). Khi khởi chạy từ console, log vẫn được ghi ra console. Ghi log truy cập HTTP bị tắt ở cả hai chế độ. Hãy bảo vệ log cùng với thư mục dữ liệu và xem lại trước khi chia sẻ.

## Khởi động lại và khoảng trống

Trạng thái quan sát được yêu cầu gần nhất được lưu bền vững. Nếu trước đó quan sát đang hoạt động, khi khởi động ứng dụng sẽ cố gắng kết nối lại và tiếp tục với các nguồn đã chọn. Tạm dừng thủ công sẽ xóa ý định đó. Lần khởi động lại thất bại sẽ được ghi lại và hiển thị trong bảng điều khiển.

TgWitness lưu vị trí cập nhật Telegram của tài khoản và của từng kênh (pts, qts, seq và date) trong kho dữ liệu của không gian làm việc và khôi phục ở lần khởi động tiếp theo. Sau đó ứng dụng khách yêu cầu các cập nhật bị bỏ lỡ trong lúc tiến trình dừng, và đợt kiểm tra lại định kỳ sẽ thu hồi các tin nhắn bị bỏ lỡ và ghi nhận những tin nhắn đã lưu mà Telegram không còn trả về. Danh sách hội thoại được tải lại khi khởi động. Mỗi lần khởi động đều ghi lại bản ghi mới nhất (head) của sổ nhật ký trước đó, ranh giới thời gian ngoại tuyến và vị trí cập nhật mà nó tiếp tục từ đó. Bộ giám sát kiểm tra kết nối mỗi 10 giây và thêm một tín hiệu nhịp (heartbeat) mỗi phút (**Các công cụ khác → Các tham số → Ghi nhận hoạt động mỗi**). Các lần mất kết nối và khoảng im lặng được ghi lại thành khoảng trống trong phạm vi bao phủ, kèm lý do. Ảnh chụp nhanh lịch sử được lưu thành các quan sát lịch sử hiện tại riêng biệt, bên cạnh các bản ghi trực tiếp.

Hàng đợi tệp phương tiện được lưu trong cơ sở dữ liệu SQLite của từng không gian làm việc. Tin nhắn và tác vụ của nó được ghi (commit) một cách nguyên tử. Các tác vụ đang chạy bị gián đoạn sẽ được khôi phục để thử lại khi khởi động. Mỗi lượt tải xuống có thời gian chờ cơ bản 120 giây, cộng thêm thời gian tính theo tốc độ 256 KiB/s cho kích thước tệp, và giới hạn 1–2000 MiB cho mỗi loại tệp đính kèm; thời gian chờ, tốc độ và số lần thử lại nằm trong **Các công cụ khác → Các tham số**. Trình thu thập bỏ qua các tệp không rõ kích thước. Tạm dừng vẫn giữ lại các tác vụ trong hàng đợi. Thử lại dùng bộ mô tả tệp (file descriptor) đã quan sát ban đầu, không bao giờ dùng phiên bản mới nhất của một tin nhắn được chỉnh sửa sau đó. Lỗi tạm thời có số lần thử lại giới hạn; các khoảng tạm dừng FloodWait khi tải tệp phương tiện vẫn được giữ sau khi khởi động lại. Việc khôi phục tệp phương tiện tách biệt với việc khôi phục cập nhật Telegram và không thể tái tạo các tệp đã biến mất.

## Sao lưu, khôi phục và dung lượng

Hãy dừng tiến trình trước khi sao chép **toàn bộ thư mục dữ liệu**, bao gồm vault.key, signing.enc, credentials.enc, các tệp cơ sở dữ liệu SQLite/WAL, tệp phương tiện, mã thông báo, điểm kiểm tra và tất cả thư mục con trong profiles/. Khôi phục bản sao đầy đủ trong khi dịch vụ đích đang dừng. Thiếu khóa kho dữ liệu hoặc khóa ký không khớp sẽ khiến khởi động thất bại; đừng tạo lại khóa để ép truy cập.

Hãy mã hóa và kiểm soát quyền truy cập đối với các bản sao lưu chứa thông tin bí mật. Tệp ZIP bằng chứng là tài liệu phục vụ xem xét, có thể mang sang nơi khác, chứ không phải bản sao lưu ứng dụng hay bản sao lưu phiên Telegram. Không có cơ chế tự động xóa theo thời hạn lưu giữ. Hãy dự trù dung lượng đĩa cho tất cả tin nhắn, siêu dữ liệu thô, tệp phương tiện, bản xuất tạm thời và bản sao lưu.

Việc xác minh khi khởi động và việc xuất dữ liệu đều đọc các bản ghi theo luồng thay vì nạp toàn bộ sổ nhật ký. Một lần xuất sẽ cố định một ảnh chụp nhanh để đọc (read snapshot) trong khi các thao tác ghi WAL mới vẫn có thể tiếp tục; các lần xuất chạy lâu có thể giữ lại các trang WAL, nên dung lượng đĩa vẫn quan trọng. Tệp ZIP bị giới hạn 4 GiB khi chưa nén để khớp với mặc định của trình xác minh độc lập; **Các công cụ khác → Các tham số → Tệp ZIP có chữ ký lớn nhất** cho phép nâng giới hạn này, và các tệp lưu trữ như vậy được xác minh bằng `verify.py --max-gib N`. Các định dạng khác không giới hạn số lượng sự kiện. Các trình duyệt được hỗ trợ truyền từng phần phản hồi theo luồng vào tệp do người dùng chọn. Các trình duyệt khác đệm tối đa 128 MiB và chuyển các lượt tải lớn hơn sang CLI có xác thực:

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

Dùng `--profile ID` lấy từ **Xuất dữ liệu → ID không gian làm việc** cho không gian làm việc khác, `--format zip|jsonl|csv|html`, `--url https://your-server` cho máy chủ từ xa, hoặc `--max-mib` để thay đổi giới hạn truyền 5 GiB. HTTP thuần chỉ được phép trên loopback. Mã thông báo được truyền trong header, chuyển hướng bị từ chối, tệp hiện có không bị ghi đè, và các lượt tải chưa hoàn tất không được đưa ra như tệp đã hoàn chỉnh. Nếu TGWITNESS_TOKEN ghi đè mã thông báo được tạo tự động, hãy dùng một tệp được bảo vệ riêng chứa giá trị đang có hiệu lực đó: giá trị ghi đè không ghi lại panel-token.txt. SHA-256 mà lệnh đưa ra chỉ là checksum của quá trình truyền; hãy xác minh độc lập tệp ZIP có chữ ký.

Bảng điều khiển hiển thị tệp phương tiện đang chờ/thất bại, tệp phương tiện chờ lâu nhất, dung lượng đĩa còn trống, các lần tạm dừng yêu cầu Telegram và những nguồn chưa xác nhận được quyền truy cập. Các thông tin chẩn đoán này không phải là công cụ giám sát phân phối đầu-cuối đầy đủ. Các không gian làm việc dùng chung một tiến trình; một tài khoản gây tải lớn vẫn có thể ảnh hưởng đến các tài khoản khác. Những việc còn lại gồm: tiến trình worker riêng, lưu giữ/xoay vòng, khôi phục cập nhật bền vững và kiểm định triển khai đầy đủ. Quyền truy cập bảng điều khiển theo phạm vi giới hạn được mô tả trong [truy cập và quyền hạn](../ACCESS.md); điểm kiểm tra độc lập được trình bày trong [hướng dẫn nhân chứng](../WITNESS.md).

Quy trình chi tiết: [kết nối/bảo mật](../CONNECTION-SECURITY.md) và [các chế độ vận hành](../OPERATIONS.md).
