[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · [Español](../es/QUICKSTART.md) · [Português (Brasil)](../pt/QUICKSTART.md) · [Türkçe](../tr/QUICKSTART.md) · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · [Bahasa Indonesia](../id/QUICKSTART.md) · [Tiếng Việt](../vi/QUICKSTART.md) · **简体中文**

# TgWitness 快速入门

TgWitness 是一款用于监控您账户可访问的 Telegram 群组和频道的独立应用程序。它在本地运行，并拥有独立的数据目录。

**初次访问？**在连接账户前，请先[探索演示版](#探索界面)。[选择指南](../README.md)，了解代理、见证人、数据导出或服务器设置的相关内容。

## 安装与启动

请选择一种方法。发布版本发布后，即可获取便携版下载：

| 主机 | 尚未安装任何内容 | 源代码：Python 3.11+ | Docker：Engine/Desktop 搭配 Compose 2.20+ |
| --- | --- | --- | --- |
| Windows | 从 GitHub 发布页面中提取 `TgWitness-<version>-windows-amd64-portable.zip`，双击 `TgWitness.cmd` | 双击`Start.cmd` | 双击`scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

若需获取源代码，请从 GitHub Releases 下载并解压源代码 ZIP 包，或克隆该代码库。`Start.cmd` 会在未检测到合适的 Python 环境（winget 或 python.org 签名安装程序）时，为您的 Windows 用户安装 Python 3.12。`start.sh` 会在缺少 Python 时，显示适用于您所用 Linux 发行版或 macOS 的精确安装命令。 首次运行源代码时，系统会生成`.venv`并自动安装依赖项。

Docker 会构建该应用程序并在后台启动它；无需在主机上安装 Python。当容器运行正常时，`scripts\Docker.cmd` 和 `scripts/docker-start.sh` 会显示控制面板地址和令牌。在所有受支持的主机上，相应的 Docker 命令如下：

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

打开 **http://127.0.0.1:8787**。使用 Docker 辅助程序或第二个 Docker 命令生成的令牌，或者在便携式或源代码安装中读取 **data/live/panel-token.txt** **文件**。请继续执行下方的**“连接 Telegram**”步骤。原生安装和 Docker 安装使用独立的存储空间；启动 Docker 不会导入现有的原生日志。

对于服务器，[部署](DEPLOYMENT.md)涵盖自动启用 HTTPS、重启、已发布图片、更新和备份。

## 探索界面

1. 在便携包中运行 **TgWitness-Demo.cmd**，在 Windows 源代码文件夹中运行 **scripts\Demo.cmd**，或在 Linux/macOS 上运行 `sh start.sh --demo`。从源代码启动时，系统会先创建 `.venv` 并安装依赖项。
2. 打开 **http://127.0.0.1:8787**。
3. 本地演示会自动打开示例日志。直接本地访问无需复制令牌。

演示消息均为虚构。演示模式无法连接真实的 Telegram 账号。

## 连接 Telegram

> [!WARNING]
> **请勿使用任何您无法承受损失的资源。**我们强烈建议不要关联个人或重要账户，也不要在您珍视的账户上生成 API ID / 哈希值。Telegram 会不按规律且往往永久封禁账户，无论使用何种客户端。测试运行是否顺利取决于 Telegram 本身，而非 TgWitness，且无法保证后续使用效果。

1. 如果原生演示程序正在运行，请将其停止，然后运行 **Start.cmd** 或 `sh start.sh`。否则，请保持上述已启动的实时安装继续运行。
2. 请使用与您的安装方式对应的面板令牌来打开面板。
3. 如果您需要代理，请在**“账户”→“设置”→“连接设置”→“更改连接路径**”中保存该设置。
4. 在**“账户**”中，输入您的手机号码并点击**“继续**”，选择**“二维码”→“显示二维码**”，或选择文件并点击**“连接账户**”。**API ID + 哈希**为可选项：工作区将使用其已保存或导入的配对，或来自内置池中的有效配对。 若要使用您自己的应用，请将一组 `API ID:API Hash` 粘贴到 API ID 字段中。如需完整的授权密钥，请选择**“授权密钥**”，粘贴全部 512 个十六进制字符，并选择提供的 DC ID。用户 ID 为可选项，若输入则会被勾选。
5. 完成您选择的登录方式：手机/验证码/双因素认证（2FA），通过已登录的 Telegram 应用确认二维码，或导入受支持的授权会话。
6. 请核对显示的账号 ID。开放**源代码**：您的聊天记录会自动加载；请手动添加您的群组。
7. 在**“选择要保留的更改**”下，选择事件类别或**“消息、编辑和删除**”预设，然后保存监控设置。
8. 分别选择附件设置，然后点击**“开始观察**”。

API 凭据用于识别您的应用程序；它们本身并不能授权账户。私人群组无需公开用户名，但您的账户必须具备访问权限。

对于现有账户，请参阅[账户及会话格式](../ACCOUNTS.md)：该面板支持 Telethon StringSession、Telethon/Pyrogram SQLite、单账户 TData ZIP 以及受支持的账户 JSON 格式。请同时选择一个会话及其配套的 JSON 文件，然后点击**“连接账户**”。您也可以通过二维码登录，API 设置可选。 不支持 TDLib、机器人及批量账户列表。

要添加另一个账户，请点击账户选择器旁边的**“+”号**，或打开**“账户”→“设置”→“连接设置”→“工作区**”，或使用**“账户”功能**。各个工作区拥有独立的会话、日志、密钥、数据源和队列。切换视图时，其他采集器将继续运行。在此安装环境中，同一个 Telegram 账户不能分配给两个工作区。 工作区数量没有限制；它们共享一个进程，因此容量取决于机器性能。

实时面板令牌用于保护您对 Telegram 授权和保存内容的访问权限；它与 Telegram API 凭据是分开的。只有明确启动并直接访问的本地演示版本才能自动获得访问权限。远程/代理演示版本仍使用 `data/demo/panel-token.txt`。

## 查看与导出

- **日志：**按来源和事件类型搜索和筛选观察记录。
- 选择一个事件，查看其原始记录、来源信息和已保存的版本。
- 编辑详情显示可用的“之前”和“之后”内容。删除详情显示最后捕获的内容（如有）；未知行为者仍为未知。
- **导出格式：**签名 ZIP、JSONL、CSV 和离线 HTML。
- **完整聊天记录导出**（来源 → 完整聊天记录导出）：将单个聊天室的全部可见历史记录下载为包含 `chat.json`（Telegram 导出格式）和可读 `chat.html` 的签名包。若账户为聊天室成员，则可导出私聊记录。此为当前快照，并非已删除或先前编辑过的消息的重建。请使用 `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256` 验证副本。
- **保存检查点：**将已签名的日志边界保留在收集器之外。
- **下载已签名的运行收据：**保留收集器的程序/版本记录。
- **准备时间戳请求：**向时间戳授权机构发起离线请求；按照 [TIMESTAMP.md](../TIMESTAMP.md) 中的说明获取并验证响应。
- **验证日志：**检查事件签名和链节。ZIP 导出功能还会检查媒体文件。

受支持的浏览器可将大型导出文件直接保存到指定文件中。其他浏览器最多仅能缓冲 128 MiB。在服务器运行期间，流式传输命令行界面（CLI）支持更大规模的下载，且无需缓冲整个响应：

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

若要添加另一个工作区，请通过**“导出”→“工作区 ID**”添加 `--profile ID`。若要添加远程服务器，请添加 `--url https://your-server`。默认传输限制为 5 GiB；`--max-mib` 可更改该限制。 已签名的 ZIP 内容默认设有 4 GiB 的解压后验证限制（通过**“参数”**可提高该限制；请使用 `verify.py --max-gib N` 验证此类存档）。请使用可信的验证器副本以及独立保存的密钥指纹/检查点来验证存档。

## 查看安装说明

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check`用于检测本地依赖项、签名支持、存储、密钥配置及监听地址。该工具不会安装任何内容，也不会连接到 Telegram。若端口已被占用，可能意味着已有另一个实例正在运行。请使用不同的 `--port`，或先停止该实例。

启动器将安装至`.venv`。辅助命令`python -m tgwitness...`必须在 Windows 系统上使用`.venv\Scripts\python.exe`，或在 Linux/macOS 系统上使用`.venv/bin/python`，除非该环境已激活。

## 会话、保护与操作

一个封闭且一致的 Telethon SQLite `.session` 数据库可通过 `python -m tgwitness.sessions account.session --out account.tgwitness-session` 在本地进行转换，随后加载到 Account 中。还支持直接文件导入和二维码登录。有关登录格式、SOCKS5、HTTP CONNECT、MTProxy 以及外部主密钥的信息，请参阅 [CONNECTION-SECURITY.md。](../CONNECTION-SECURITY.md)

**暂停监视会**停止数据采集。仅**锁定**会关闭浏览器访问权限。关闭标签页后，采集进程仍会继续运行。停止进程会中断数据采集；历史快照无法还原所有遗漏的编辑或删除操作。了解事件策略、附件队列、账户隔离及重启行为[的数据采集原理](../COLLECTION.md)。

会话和密钥均经过加密。消息内容、媒体文件及导出数据需存储在加密磁盘或卷上。签名仅能基于可信密钥验证数据完整性；无法验证消息源自 Telegram，也无法防止由控制收集器及其密钥的操作员伪造消息。

请阅读 [OPERATIONS.md](../OPERATIONS.md) 了解备份/恢复操作，阅读 [DEPLOYMENT.md](DEPLOYMENT.md) 了解托管方法，并访问 [deploy/](../../deploy/README.md) 查看服务示例。已安装的控制面板还包含一份离线设置指南，位于 `/guide.html`。

实际验证结果及现有局限性记录在 [VERIFICATION.md](../VERIFICATION.md) 和 [READINESS.md](../internal/READINESS.md) 中。
