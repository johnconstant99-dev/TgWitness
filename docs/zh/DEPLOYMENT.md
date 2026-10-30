[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · [Español](../es/DEPLOYMENT.md) · [Português (Brasil)](../pt/DEPLOYMENT.md) · [Türkçe](../tr/DEPLOYMENT.md) · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · [Bahasa Indonesia](../id/DEPLOYMENT.md) · [Tiếng Việt](../vi/DEPLOYMENT.md) · **简体中文**

# 部署与运维

## 选择安装方式

若使用便携包，请从 GitHub Releases 中解压 `TgWitness-<version>-windows-amd64-portable.zip`。若采用其他方法，请下载并解压源代码 ZIP 文件或克隆代码库，然后在项目目录下运行以下命令：

| 安装 | 开始 | 在后台运行吗？ |
| --- | --- | --- |
| Windows 便携版软件包 | `TgWitness.cmd` | 不，请保持窗口打开。 |
| Windows 原生版 | `Start.cmd` | 不需要；如需在后台运行，请使用可选的登录任务。 |
| 原生 Linux/macOS 版本 | `sh start.sh` | 不需要；请使用 systemd/launchd 进行后台运行。 |
| 在任何受支持的主机上运行 Docker | `docker compose up -d --build --wait` | 是的，只要 Docker 守护进程正在运行。 |
| Windows 上的 Docker 辅助工具 | `scripts\Docker.cmd` | 是的；该辅助程序会监听 Web 服务器的运行状态。 |
| Linux/macOS 上的 Docker 辅助工具 | `sh scripts/docker-start.sh` | 是的；该辅助程序会监听 Web 服务器的运行状态。 |

原生启动会创建一个私有`.venv`，并安装已固定的依赖项。Docker会在镜像内部构建这些依赖项，无需使用主机端的Python。首次设置需要互联网连接。 若未检测到 Python 3.11 及以上版本，`Start.cmd` 会先征得当前 Windows 用户的同意，再为其安装 Python 3.12（使用 winget；若 winget 不可用，则在验证 Python 软件基金会签名后使用 python.org 安装程序）；该过程绝不会请求管理员权限。Docker 和操作系统服务仍是必备条件。

原生和便携式安装会在其文件夹内使用 `data/live`。Docker 则使用位于 `/data` 的名为 `tgwitness-data` 的卷。除非您有意识地迁移整个数据目录，否则这些安装是相互独立的。请不要指望新的 Docker 容器能自动发现原生账户。

## 安装要求

原生安装需要 Python 3.11 或更高版本（包含 `venv` 和 `ensurepip`），首次安装依赖项时需要互联网连接，以及一个可供写入的项目目录（`.venv`）。捆绑的面板无需 Node.js 或前端构建。请使用您的常规操作系统账户运行启动器；TgWitness 不需要管理员/root 权限。

- **Windows：**`Start.cmd`会依次检查`py -3`、`python`，以及默认的用户级和Program Files安装文件夹，并要求 Python 3.11 或更高版本。如果以上路径均不可用，则会提供上文所述的自动用户级安装选项。`py -3 start.py`同样有效。便携版完全不需要 Python。
- **Linux：**`start.sh` 会依次尝试 `python3.13`、`python3.12`、`python3.11`、`python3` 和 `python`，若均不匹配，则会输出适用于 apt、dnf、pacman、zypper、apk 或 Homebrew 的安装命令。Debian/Ubuntu 系统可能需要安装与所选解释器匹配的 `python3-venv` 包。 发行版中较旧的默认 Python 必须被 Python 3.11+ 版本替换或补充。
- **macOS：**安装最新的 Python 3.11 及以上版本；请勿假设系统自带的解释器能满足要求。请从项目目录中使用 `python3 start.py`。
- **Docker：**请使用搭载 Compose v2.20 或更高版本的 Docker Engine/Desktop。在 Windows 系统上，Docker Desktop 必须使用 Linux 容器。该容器会自行安装所需的 Python 依赖项；主机无需单独安装 Python。

请为数据目录使用持久性本地存储。需根据消息、媒体文件、WAL增长、数据导出及备份等因素规划存储容量；目前尚无基于实证的、适用于所有工作负载的通用最低磁盘/内存配置标准。对于缺乏兼容依赖项轮（wheel）的 CPU 架构和 Python 版本，可能需要额外的构建工具并进行单独的兼容性验证。 “可移植”并不意味着支持所有操作系统或硬件。

已在本地验证 Windows 11/Python 3.12 环境。Linux/macOS/容器配置文件及持续集成（CI）已提供，但尚未在此开发主机上执行。具体验证范围请参阅 [VERIFICATION.md](../VERIFICATION.md)。

## 本地计算机

在 Windows 系统上使用 `Start.cmd`，在 Linux/macOS 系统上使用 `sh start.sh`。`scripts\Setup.cmd` 或 `sh start.sh --setup-only` 可用于准备运行环境。启动程序在首次使用时会安装依赖项；后续启动将复用该环境。设置和 Telegram 数据采集需要互联网连接，但浏览现有记录和生成导出文件可在离线状态下进行。

设置完成后运行 `python start.py --check`，可在不启动收集器的情况下检查本地依赖项、Ed25519、存储、密钥配置及监听地址。使用 `--json` 获取结构化输出。请传入相应的 `--data-dir`、`--host` 和 `--port`。此检查不会安装软件包、创建日志或连接 Telegram；它并非完整性或覆盖范围的验证。 启动时会单独验证现有的日志。`python start.py --help`同样不会进行安装。

选项：

运行 start.py 后，请在 Windows 系统上使用 `.venv\Scripts\python.exe`，在 Linux/macOS 系统上使用 `.venv/bin/python` 执行辅助命令，或者先激活该环境。下文中的 `python -m ...` 示例均假设该环境已处于活动状态。

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

环境变量：TGWITNESS_DATA、TGWITNESS_HOST、TGWITNESS_PORT、TGWITNESS_TOKEN。TGWITNESS_VAULT_KEY_FILE 用于在新安装中选择外部密钥模式；详见下文。 若提供 TGWITNESS_TOKEN，其长度必须至少为 24 个字符；请使用加密级随机值。若未提供，应用程序将在 panel-token.txt 文件中生成一个 256 位的随机令牌。环境变量覆盖不会重写该文件。请重启以轮换凭据。

数据目录只能由一个进程独占。跨平台操作系统文件锁机制可防止意外的并发写入。 请使用一个 Uvicorn 工作进程。控制面板可管理任意数量的工作区，额外的工作区目录位于 profiles/<id>/ 下。若需独立的服务实例，请使用独立的目录和端口。SQLite WAL 文件应存储在本地持久化存储中，而非网络文件系统。请勿在副本之间共享同一卷。

## Windows 便携版软件包

每个 GitHub 发布包都包含 `TgWitness-<version>-windows-amd64-portable.zip` 及其 `.sha256`。其中包含来自 python.org 的官方可嵌入式 Python 3.12 运行时（校验和固定在 `tools/build_portable.py` 中）、TgWitness 及其固定的依赖项，以及三个启动器：

| 文件 | 目的 |
| --- | --- |
| `TgWitness.cmd` | 启动面板；额外选项将被传递，例如 `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | 在 `data\demo` 处启动合成演示 |
| `TgWitness-Check.cmd` | 在不启动的情况下运行就绪性检查 |

将整个压缩包解压到可写入的文件夹中，例如 `Documents\TgWitness`；请勿直接在 ZIP 文件内或 Program Files 文件夹中运行。运行时使用隔离的模块路径，因此其他 Python 安装以及 `PYTHONPATH` 不会对其产生影响。 数据保存在包内的 `data` 文件夹中。若需更新，请先停止 TgWitness，将新版本解压到新文件夹，然后将 `data` 文件夹复制过去。

在 64 位 Windows 系统上使用 Python 3.12 自行构建：

~~~sh
python tools/build_portable.py
~~~

构建程序会验证运行时校验和，将受限依赖项安装到软件包中，使用嵌入式解释器运行就绪性检查，并将 ZIP 文件和校验和写入 `dist/`。

## 容器

```sh
docker compose up -d --build --wait
```

这将为 /data 创建一个命名持久卷。Web 端口映射至 127.0.0.1:8787。 该进程以 UID 10001 身份运行，且已剥离权限，根文件系统为只读，而 /data 和 /tmp 目录可写。`--wait` 在返回前会检查 Web 服务器的运行状态；它不会建立 Telegram 授权或消息投递。 提供的辅助程序在构建完成后采用 180 秒的就绪超时设置。初始依赖项的下载可能需要更长时间。

两个基础 Compose 文件均使用项目名称 `tgwitness`，因此将新版本解压到另一个目录时，系统不会自动选择新的数据卷。 请确保该项目仅有一个部署处于活动状态。对于独立安装，请使用唯一的 `docker compose -p NAME ...` 和不同的主机端口，并在更新时保留两者。对于使用不同项目名称的旧部署，请继续使用其原始名称并配合 `-p`；`docker compose ls` 列出了现有项目。

将 `deploy/env.example` 复制到 `.env`，并将 `TGWITNESS_PORT` 修改为使用不同的回环端口。例如，`TGWITNESS_PORT=8788` 将控制面板暴露在 `http://127.0.0.1:8788`；容器仍监听 8787 端口。`.env` 被 Git 忽略。

获取初始令牌：

~~~sh
docker compose exec tgwitness cat /data/panel-token.txt
~~~

常用命令：

```sh
docker compose ps
docker compose logs --tail 100 -f
docker compose stop
docker compose up -d --wait
```

`restart: unless-stopped` 用于在崩溃或 Docker 守护进程重启后重启收集器。 在 Linux 服务器上，请使用您所用发行版的系统服务管理器（通常为 `sudo systemctl enable --now docker`）启用 Docker 自动启动。在 Windows/macOS 上，请启用 Docker Desktop 的“登录时启动”设置。桌面注销、休眠或 Docker 守护进程停止都可能中断数据采集。被显式停止的容器将保持停止状态，直到您再次启动它。

在示例配置中，/tmp 分区的上限为 512 MiB。导出结构改用将每个工作区的 `temporary-exports/` 导出到持久化 /data 分区。 请在此处预留空间，以满足同时进行导出、日志/WAL增长、媒体文件及备份的需求。启动器和 Docker 通过 deploy/constraints.txt 文件锁定符合资格的运行时依赖项版本。这并非哈希锁定的供应链：Python 基础镜像和软件包工件仍需经过独立的发布资格认证。

除非您打算销毁日志和密钥，否则请勿使用 `docker compose down -v` 命令。容器健康状态报告反映的是 Web 服务器的可用性，而非 Telegram 抓取是否成功。请检查控制面板中的收集器状态、心跳、错误及覆盖事件。

### 独立见证者简介

可选的 `witness` 服务会在独立容器中运行一个[独立的见证](../WITNESS.md)节点，该节点在 `witness-data` 卷中拥有自己的密钥和日志，而收集器仅拥有一个只读的见证令牌。请在控制面板的“见证”页面创建该令牌，将其与机器人令牌和频道一起添加到 `.env`，然后启动该配置文件：

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

该服务通过 `http://tgwitness:8787` 访问 Compose 网络内的收集器（`TGWITNESS_WITNESS_COLLECTOR` 会覆盖该地址，例如 `/profiles/<workspace ID>` 对应另一个工作区）。若要使用由他人运行的独立服务器上的见证文件，请在该处使用 `deploy/compose/compose.witness.yaml`，并将 `TGWITNESS_WITNESS_COLLECTOR` 设置为收集器的 HTTPS 地址；该文件仅包含见证文件。

## 安装已发布的镜像

在[发布工作流](#github-自动发布)成功完成并配置好公开的 GHCR 包后，该内容即可使用。此源代码树中并未硬编码存储库的所有者/名称。请使用该发布版工作流摘要中显示的图片。

将 `deploy/env.example` 复制到 `.env`。将 `TGWITNESS_IMAGE` 设置为已发布的版本，并使用**小写形式的**仓库路径，例如：

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.7.0
TGWITNESS_PORT=8787
```

请单独运行此文件，而非 `compose.yaml`：

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

主机上无需源代码构建、Python 或编译器。发布工作流针对 Linux AMD64 和 ARM64 容器，包括 Docker Desktop 的 Linux 虚拟机。请使用工作流摘要中的版本标签或 `ghcr.io/owner/repository@sha256:...`。 未配置移动的 `latest` 标签或无人值守的应用程序升级。当项目名称相同时，镜像和源代码变体将使用相同的数据卷。

## 服务器上的自动 HTTPS 配置

请使用配备 Docker 的服务器、您控制的域名以及持久性本地存储。将域名的 A/AAAA 记录指向该服务器；仅当服务器支持 IPv6 时才发布 AAAA 记录。允许入站 TCP 80 和 443 端口，以及用于证书签发的出站 DNS/HTTPS 连接。 其他服务不得已占用这些端口。

将 `deploy/env.example` 复制到 `.env`，并设置主机名（不包含协议或路径）：

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

使用 HTTPS 覆盖层开始源代码构建：

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

对于已发布的图片，请改用`deploy/compose/compose.image.yaml`作为第一个文件。请保留两个`-f`参数，以便后续使用状态、日志、更新和停止命令。

Caddy 负责获取和续期证书，将 HTTP 请求重定向至 HTTPS，并将请求转发至私有 Compose 网络上的收集器。证书状态拥有独立的持久卷。收集器的直接主机端口仅限回环连接。提供的 Caddy 配置未启用访问日志记录。

打开 `https://watch.your-domain.org` 并输入面板令牌。准备就绪状态并不意味着证书已签发或外部可达性已确认。如果 HTTPS 尚未就绪，请检查 DNS、防火墙规则以及：

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

提供的 Caddy 镜像位于其 `2-alpine` 标签之后。拉取操作会刷新该镜像；若需固定基础设施版本，请在部署中固定一个经过测试的摘要。

## 更新与备份

在更新过程中保留 Compose 项目名称和数据集。首先停止收集器并进行完整备份。对于默认的基于源代码的部署：

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

每次请使用存储库之外的新备份目标，并将其作为账户访问材料加以保护。示例路径仅供参考；请使用您自己的私有备份位置。复制整个目录，包括隐藏文件、所有工作区、密钥、日志和媒体文件。 若已配置，请单独备份外部保险库主密钥。证据 ZIP 文件并非可恢复的应用程序备份。对于 HTTPS，若需保留其证书/账户状态，请同时保留 Caddy 卷。

若要进行源代码部署，请获取最新发布的文件并运行：

```sh
docker compose up -d --build --wait
```

若要部署镜像，请将 `TGWITNESS_IMAGE` 更改为所需版本，然后运行：

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

请也使用您安装环境中的 Compose 文件来执行前面的 stop/copy 命令。 请保留`.env`、自定义配置以及原有的项目名称。`down`用于保留命名卷；**`down -v`用于删除命名卷**。请勿在不同操作系统或 Python 版本之间复制`.venv`。若需进行原生更新，请先停止 TgWitness，备份其完整数据目录，替换源文件，并在启动前运行`python start.py --setup-only`。

更新后请检查面板访问权限、账户身份、监控状态及覆盖范围。重启不会恢复遗漏的 Telegram 更新。如果未来版本更改了存储格式，回滚可能需要使用更新前的备份。

## GitHub 自动发布

将该项目推送到启用了 Actions 的 GitHub 仓库后，[发布工作流](../../.github/workflows/release.yml)即可投入使用。当**发布** GitHub 版本（包括预发布版本）时，该工作流会自动运行。仅推送草稿或标签并不会发布软件包。

1. 设置软件包版本和变更日志，然后发布一个带有`v`标签且包含精确`pyproject.toml`版本的发布版本，例如`v0.7.0`。
2. 该工作流会验证标签，并运行共享的 Windows/Linux/macOS Python 环境、通用/账户导入/二维码浏览器、源代码包以及 Docker 检查。此外，还针对这三种操作系统使用 Python 3.12 进行了全新的原生安装测试。
3. 在通过上述检查后，系统会在 QEMU 环境下对 ARM64 镜像进行烟雾测试，将 AMD64/ARM64 镜像发布至 `ghcr.io/<lowercase-owner>/<lowercase-repository>:<version>`，并将源代码 ZIP 包、校验和及 Python wheel 文件附加到发布包中。另有专门的 Windows 任务负责构建并附加可移植 ZIP 包及其校验和。
4. 首次发布后，请打开 GHCR 包设置，若需匿名拉取镜像，请将可见性设为“**公开**”。仅将源代码仓库设为公开并不能保证容器包也会公开。组织政策必须允许发布包。该工作流使用 `GITHUB_TOKEN`；仓库中不应包含任何注册表密码或 VPS 凭据。

仅通过本地准备工作尚无法确保远程工作流的成功。ARM64 模拟仅为初步验证，并非原生硬件或实时 Telegram 环境的认证。此操作可自动完成发布打包；但启动服务器仍需使用 Compose 命令及其域名/主机先决条件。当发布新版本时，现有服务器不会自动升级或重启。

## 远程服务器

请将服务绑定至回环接口并使用 SSH 隧道，或在反向代理处终止 HTTPS 连接。基础 Compose 文件仅限本地使用；可选的 `deploy/compose/compose.https.yaml` 覆盖层为配置好的域名提供 Caddy 服务。请勿在 URL 和代理日志中暴露承载令牌。反向代理应限制请求大小和连接速率。 请勿将明文 HTTP 暴露到互联网上。

[deploy/](../../deploy/README.md) 目录中提供了 systemd、Windows 登录任务、macOS 用户代理和 Caddy 的示例。安装前请检查并调整其路径。这些仅为模板，并非本地执行的平台配置。普通启动器不会注册任何后台服务或任务。

在 Windows 系统上，无窗口模式 `pythonw.exe` 的启动会将启动/服务器诊断信息存储在数据目录下的 `logs/server.log` 中（每个文件 5 MiB，包含两个轮换备份）。控制台模式的启动会保留控制台日志。两种模式下均禁用 HTTP 访问日志记录。请将日志与数据目录一同保护，并在分享前进行审查。

## 重启与数据缺口

系统会保存上次请求的监控状态。如果监控处于活动状态，启动时会尝试重新连接并恢复已选定的信息源。手动暂停会清除该意图。重启失败的情况会被记录并显示在面板中。

StringSession 会保留授权信息，但不保留 Telethon 的持久化更新/实体状态。对话会在启动时重新加载。Telegram/Telethon 可在运行过程中恢复部分传输中断，但 TgWitness 不保证在进程重启后能够实现持久化重放。 每次启动时都会记录前一次日志头和离线边界。监视器每 10 秒检查一次连接状态，并每分钟添加一次心跳（**参数 → 存活记录间隔**）。短暂的中断可能无法被检测到；即使传输连接正常，也无法保证更新能完全送达。快照是明确的当前历史观测结果，绝非缺口修复。

媒体队列存储在每个工作区的 SQLite 数据库中。消息及其任务会以原子方式提交。中断的运行任务会在启动时恢复并重试。 每次下载设有 120 秒的基础超时，外加按 256 KiB/s 速率计算的文件大小所需时间，且每种附件类型有 1–2,000 MiB 的限制；超时、速度和重试次数可在**“参数”**中设置。收集器会跳过大小未知的文件。暂停操作会保留队列中的任务。 重试使用最初观察到的文件描述符，绝不会使用后续编辑消息的最新版本。临时故障的重试次数有限；媒体 FloodWait 暂停状态在重启后仍会保留。媒体恢复与 Telegram 更新恢复是分开的，且无法重建已消失的文件。

## 备份、恢复与容量

在复制**整个数据目录**（包括 vault.key、signing.enc、credentials.enc、SQLite 数据库/WAL 文件、媒体文件、令牌、检查点以及所有 profiles/ 子目录）之前，请先停止该进程。 请在目标服务停止运行时恢复完整副本。若缺失保险库密钥或签名密钥不匹配，将导致启动失败；请勿通过重新生成密钥来强制访问。

请对秘密备份进行加密并实施访问控制。证据 ZIP 文件是便于携带的审查素材，而非应用程序备份或 Telegram 会话备份。系统不会自动删除保留数据。请预留足够的磁盘空间，以存储所有消息、原始元数据、媒体文件、临时导出文件及备份。

启动时进行验证，并导出流记录而非加载整个日志。导出操作会锁定已读快照，同时新的 WAL 写入仍可继续；长时间运行的导出操作会保留 WAL 页面，因此磁盘容量依然重要。ZIP 文件的解压后大小上限为 4 GiB，以匹配独立验证器的默认设置； **通过“参数 → 最大签名 ZIP**”可提高上限，此类存档将通过 `verify.py --max-gib N` 进行验证。其他格式没有事件计数上限。支持的浏览器会将响应块流式传输到用户选定的文件中。其他浏览器最多缓冲 128 MiB，并将其余大文件传输重定向至经过身份验证的 CLI：

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

使用`--profile ID`（**来自“导出”→“工作区 ID”**）可切换至其他工作区，`--format zip|jsonl|csv|html`、`--url https://your-server`用于远程服务器，或使用`--max-mib`来更改 5 GiB 的传输限制。仅允许在回环连接中使用纯 HTTP。令牌通过请求头传输，拒绝重定向，现有文件不会被覆盖，且未完成的下载不会作为已完成文件发布。 如果 TGWITNESS_TOKEN 覆盖了生成的令牌，请使用一个单独受保护的文件来存储该有效值：panel-token.txt 不会被覆盖操作重写。该命令的 SHA-256 仅作为传输校验和；请独立验证已签名的 ZIP 文件。

服务器导出文件保存在每个工作区的私有 `temporary-exports/` 目录中。成功响应后，系统会清理这些文件。中断的导出任务将在下次工作区启动时被移除，届时该工作区将持有其专属实例锁。该目录属于存储威胁/容量模型的一部分；请使用加密数据卷。生产级别的多吉字节级数据传输仍需在目标系统上进行兼容性测试。

该面板显示待处理/失败的媒体文件、最旧的待处理媒体文件、可用磁盘空间、Telegram 请求暂停情况，以及访问状态未确认的来源。这些诊断信息并非完整的端到端交付监控。工作区共享一个进程；一个异常活跃的账户仍可能影响其他工作区。 独立工作进程、数据保留/轮换、持久化更新恢复、远程检查点锚定、角色管理以及完整的部署认证等工作仍待实现。

## 连接与安全设置选项

连接路径按工作区设置，应在授权前进行配置。SOCKS5/HTTP CONNECT 使用固定的 python-socks 依赖项。MTProxy 使用 Telethon 的实验性随机中间传输协议；不支持 Fake TLS ee 密钥。未配置自动直接回退机制。这不是全系统范围的网络路径。

对于新安装，TGWITNESS_VAULT_KEY_FILE 应指向一个单独受保护的随机主密钥文件。请在容器内的 /data 目录外以只读方式挂载该文件。请将每个工作区的 public vault.external.json 盐元数据与主密钥分别妥善保存。 现有本地保险库需要进行有计划的迁移；设置此变量不会自动将其转换。消息/媒体存储和导出内容未经过应用程序加密。请根据需要使用加密卷和足够的私有临时存储空间。

详细操作流程：[连接/安全](../CONNECTION-SECURITY.md)设置及[运行模式](../OPERATIONS.md)。
