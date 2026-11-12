[TgWitness](../../README.md) / [文档](../README.md) / [文件夹](README.md)

![入门](../assets/presentation/chapter-start.svg)

[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · [Español](../es/QUICKSTART.md) · [Português (Brasil)](../pt/QUICKSTART.md) · [Türkçe](../tr/QUICKSTART.md) · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · [Bahasa Indonesia](../id/QUICKSTART.md) · [Tiếng Việt](../vi/QUICKSTART.md) · **简体中文**

# TgWitness 快速入门

TgWitness 是一款独立应用程序，用于观察您的账户可以访问的 Telegram 群组和频道。它在本地运行，并使用自己的数据目录。

**初次使用**？连接账户前，请先[浏览演示](#explore-the-interface)。如需了解代理、见证人、导出或服务器设置，请[选择指南](../README.md)。[GitHub Actions 捕获](../SEALED-ACTIONS.md)（预览）会在您自己的 GitHub fork 中运行捕获，而不是在本地安装中运行。

<a name="install-and-start"></a>

## 安装与启动

引导式安装程序自带 Python，并会在安装前检查软件包哈希值和发布签名。再次运行即可更新现有安装。

**Linux / macOS：**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows（PowerShell 或命令提示符）：**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

在 Ubuntu 服务器上，请以 root 身份运行以安装后台服务；在桌面系统上，请以普通用户身份运行。在 Ubuntu 上，安装程序会输出面板地址和访问密钥；在 macOS 和 Windows 上，本地面板会在浏览器中打开。然后继续下文的**连接 Telegram**步骤。[安装、验证与更新](../INSTALLATION.md)介绍了服务器访问方式的选择、运行前检查脚本、更新和卸载。

### 其他方式

除安装程序外，也可以使用 GitHub 发行版、源代码或 Docker。便携版下载在发布构建公开后才会提供：

| 主机 | 无需预先安装 | 源代码：Python 3.11+ | Docker：Engine/Desktop，Compose 2.20+ |
| --- | --- | --- | --- |
| Windows | 解压从 GitHub Releases 获取的 `TgWitness-<version>-windows-amd64-portable.zip`，双击 `TgWitness.cmd` | 双击 `Start.cmd` | 双击 `scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

如使用源代码方式，请[下载并解压当前的 `main`](https://github.com/phishdestroy/TgWitness/archive/refs/heads/main.zip)，或克隆代码仓库：

```sh
git clone https://github.com/phishdestroy/TgWitness.git
cd TgWitness
```

如果找不到合适的 Python，`Start.cmd` 会提出为您的 Windows 用户安装 Python 3.12（通过 winget 或带签名的 python.org 安装程序）。如果缺少 Python，`start.sh` 会输出适用于您的 Linux 发行版或 macOS 的确切安装命令。首次从源代码启动时会自动创建 `.venv` 并安装依赖项。

Docker 会构建应用程序并在后台启动；主机上无需 Python。容器状态正常后，`scripts\Docker.cmd` 和 `scripts/docker-start.sh` 会输出面板地址和令牌。在所有受支持的主机上，等效的 Docker 命令如下：

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

打开 **http://127.0.0.1:8787**。使用 Docker 辅助脚本或第二条 Docker 命令输出的令牌；便携版或源代码安装则读取 **data/live/panel-token.txt**。然后继续下文的**连接 Telegram**步骤。原生安装和 Docker 安装使用相互独立的存储；启动 Docker 不会导入现有的原生安装日志。

如在服务器上运行，[部署](DEPLOYMENT.md)介绍了自动 HTTPS、重启、已发布的镜像、更新和备份。

<a name="explore-the-interface"></a>

## 浏览界面

1. 运行便携包中的 **TgWitness-Demo.cmd**、Windows 源代码文件夹中的 **scripts\Demo.cmd**，或在 Linux/macOS 上运行 `sh start.sh --demo`。从源代码启动时，会先创建 `.venv` 并安装依赖项。
2. 打开 **http://127.0.0.1:8787**。
3. 本地演示会自动打开示例日志。在本机直接访问时无需复制令牌。

演示消息均为虚构。演示模式无法连接真实的 Telegram 账户。

## 连接 Telegram

> [!WARNING]
> **请使用专用账户**。无论使用哪种客户端，只要 Telegram 认为请求量过大，就可能限制或永久封禁账户。请连接专为观察准备的账户，而不是个人账户或重要账户，并在专用账户上创建 API ID / API 哈希值。

1. 如果原生演示正在运行，请将其停止，然后运行 **Start.cmd** 或 `sh start.sh`。否则，请让上面已启动的正式安装继续运行。
2. 使用面板令牌登录。新工作区会打开[首次设置](../SETTINGS.md)。选择**仅下载**、**关注聊天**或**案件的证据**。
3. 查看连接检查结果。如有需要，请配置您自己的代理；设置完成后仍可使用连接设置。
4. 在 **Connect Telegram** 步骤中，选择一个电话号码、一个 QR 码、账户文件（TData、`.session`、StringSession、账户
   JSON）或完整的授权密钥。在系统提示时，完成 Telegram 确认、验证码及双重验证密码的输入。
5. 核对显示的账户，选择聊天并检查设置。在最后一个界面完成设置。选择**仅下载**时，**开始导出**会启动一次性导出，并打开“导出”页面显示进度；它不会开启持续观察。

设置完成后，可通过**聊天 → 选择**更改所选聊天。**设置**控制采集和文件；在标准或专家级别下，**更多工具 → 来源**提供详细的来源列表。[面板指南](../PANEL.md)介绍了六个主要部分及其上下文控件。

**API ID + 哈希值**为可选项：工作区会使用已保存或已导入的配对，或内置池中一个可用的配对。若要使用您自己的应用，请将一组 `API ID:API Hash` 粘贴到 API ID 字段。使用**授权密钥**时，请粘贴全部 512 个十六进制字符，并选择随附的 DC ID。用户 ID 为可选项，如填写则会进行核对。

API 凭据用于标识您的应用程序；它们本身并不能授权账户。私有群组无需公开用户名，但您的账户必须拥有访问权限。

对于已有账户，请参阅[账户与会话格式](../ACCOUNTS.md)：面板支持 Telethon StringSession、Telethon/Pyrogram SQLite、单账户 TData ZIP 以及受支持的账户 JSON。将会话及其配套 JSON 一起选中，然后点击**连接账户**。二维码登录同样可用，并支持相同的可选 API 设置。不支持 TDLib、机器人会话以及 CSV/JSON 格式的账户清单。

如有多个账户，请使用**账户 → 导入账户**，并选择它们受支持的会话文件。配套的 JSON 文件按基本文件名（basename）配对；每个导入的账户都会获得自己的工作区。请参阅[批量导入与账户分组](../ACCOUNTS.md#bulk-import-and-account-groups)。

如需添加另一个账户，请点击账户选择器旁的 **+**，或使用**账户 → 添加账户**。各工作区拥有独立的会话、日志、密钥、来源和队列。切换视图不会停止其他收集器。在此安装中，同一个 Telegram 账户不能分配给两个工作区。工作区数量没有固定上限；它们共享一个进程，因此容量取决于机器。

正式安装的面板令牌保护对您的 Telegram 授权和已保存资料的访问；它与 Telegram API 凭据相互独立。只有明确启动并直接访问的本地演示才会自动进入。远程访问或经代理访问的演示仍使用 `data/demo/panel-token.txt`。

## 查看与导出

- **日志**：按来源和事件类型搜索和筛选观察记录。
- 选择一个事件，即可查看其原始记录、归属信息和已保存的版本。
- 编辑详情显示可获得的修改前/修改后内容。删除详情显示最后捕获的内容（如有）；未知的操作者仍为未知。
- **导出**：签名 ZIP、JSONL、CSV 和离线 HTML。
- **完整聊天记录导出**（**聊天 → 导出聊天记录**，或**导出 → 捕获或导出单个聊天**）：将一个聊天的全部可见历史下载为签名包，其中包含 `chat.json`（Telegram 导出格式）和便于阅读的 `chat.html`。只要账户是成员，私聊也可以导出。这是当前快照，而不是对已删除或先前编辑过的消息的重建。使用 `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256` 验证副本。
- **保存检查点**：将已签名的日志边界保存在收集器之外。
- **下载已签名的运行收据**：保留收集器的程序/版本记录。
- **准备时间戳请求**：为时间戳机构准备离线请求；按照 [TIMESTAMP.md](../TIMESTAMP.md) 获取并验证响应。
- **验证日志**：检查事件签名和链式链接。ZIP 导出还会检查媒体。

受支持的浏览器会将大型导出直接保存到所选文件。其他浏览器最多缓冲 128 MiB。服务器运行期间，流式 CLI 支持下载更大的文件，而无需缓冲整个响应：

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

对于其他工作区，请添加 `--profile ID`，ID 可在**导出 → 工作区 ID**中找到。对于远程服务器，请添加 `--url https://your-server`。默认传输上限为 5 GiB；可用 `--max-mib` 更改。签名 ZIP 的内容另有默认 4 GiB 的未压缩验证上限（可在**更多工具 → 参数**中提高；此类存档请使用 `verify.py --max-gib N` 验证）。请使用可信的验证器副本和独立保存的密钥指纹验证存档；若要达到证据的最低要求，还需使用时间戳机构的根证书（`--tsa-ca`）。

## 检查安装

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` 会检测本地依赖项、签名支持、存储、密钥配置和监听地址。它不会安装任何内容，也不会连接 Telegram。端口被占用可能意味着另一个实例正在运行。请使用其他 `--port`，或先停止该实例。

启动器会安装到 `.venv` 中。除非该环境已激活，否则辅助命令 `python -m tgwitness...` 在 Windows 上必须使用 `.venv\Scripts\python.exe`，在 Linux/macOS 上必须使用 `.venv/bin/python`。

## 会话、保护与运行

已关闭且状态一致的 Telethon SQLite `.session` 可使用 `python -m tgwitness.sessions account.session --out account.tgwitness-session` 在本地转换，然后在**更多工具 → 账户 → 文件**中加载。也可以直接导入文件或使用二维码登录。有关登录格式、SOCKS5、HTTP CONNECT、MTProxy 和外部主密钥，请参阅 [CONNECTION-SECURITY.md](../CONNECTION-SECURITY.md)。

**暂停观察**会停止采集。**锁定**仅关闭浏览器访问。关闭标签页后，收集器进程仍会继续运行。停止进程会中断采集；历史快照无法重建所有错过的编辑或删除。有关事件策略、附件队列、账户隔离和重启行为，请参阅[采集的工作原理](../COLLECTION.md)。

会话和机密信息均经过加密。消息内容、媒体和导出文件需要存放在加密磁盘或加密卷上。请使用可信密钥验证日志签名，并单独保存检查点。请审查所选采集模式对应的捕获记录、外部时间回执和环境证明。

备份/恢复请阅读 [OPERATIONS.md](../OPERATIONS.md)，托管部署请阅读 [DEPLOYMENT.md](DEPLOYMENT.md)，服务示例请参阅 [deploy/](../../deploy/README.md)。已安装的面板还在 `/guide.html` 提供离线设置指南。

实际完成的验证和尚存的限制记录在 [VERIFICATION.md](../VERIFICATION.md) 和 [READINESS.md](../internal/READINESS.md) 中。
