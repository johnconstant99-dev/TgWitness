[TgWitness](../../README.md) / [文档](../README.md) / [文件夹](README.md)

![部署与恢复](../assets/presentation/chapter-operate.svg)

[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · [Español](../es/DEPLOYMENT.md) · [Português (Brasil)](../pt/DEPLOYMENT.md) · [Türkçe](../tr/DEPLOYMENT.md) · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · [Bahasa Indonesia](../id/DEPLOYMENT.md) · [Tiếng Việt](../vi/DEPLOYMENT.md) · **简体中文**

# 部署与运维

## 选择安装方式

如使用便携包，请解压从 GitHub Releases 获取的 `TgWitness-<version>-windows-amd64-portable.zip`。如使用其他方式，请下载并解压源代码 ZIP，或克隆代码仓库，然后在项目目录中运行下表中的相应命令：

| 安装方式 | 启动 | 是否在后台运行？ |
| --- | --- | --- |
| Windows 便携包 | `TgWitness.cmd` | 否；请保持窗口打开。 |
| 原生 Windows | `Start.cmd` | 否；如需后台运行，请使用可选的登录任务。 |
| 原生 Linux/macOS | `sh start.sh` | 否；如需后台运行，请使用 systemd/launchd。 |
| 任何受支持主机上的 Docker | `docker compose up -d --build --wait` | 是，只要 Docker 守护进程在运行。 |
| Windows 上的 Docker 辅助脚本 | `scripts\Docker.cmd` | 是；辅助脚本会等待 Web 服务器进入健康状态。 |
| Linux/macOS 上的 Docker 辅助脚本 | `sh scripts/docker-start.sh` | 是；辅助脚本会等待 Web 服务器进入健康状态。 |

如果云服务器需要能够接受第三方检查——通过服务商的 API 创建、不使用 SSH、只能经由 Cloudflare Tunnel 访问——请参阅[高保障部署](../HIGH-ASSURANCE.md)。

原生启动会创建私有的 `.venv`，并安装锁定版本的依赖项。Docker 在镜像内部构建这些依赖项，无需主机上的 Python。首次设置需要互联网连接。找不到 Python 3.11+ 时，`Start.cmd` 会先征求同意，再为当前 Windows 用户安装 Python 3.12（使用 winget；否则使用 python.org 安装程序，并先检查其 Python Software Foundation 签名）；它从不请求管理员权限。Docker 和操作系统服务仍是前提条件。

原生安装和便携版使用各自文件夹内的 `data/live`。Docker 使用挂载在 `/data` 的命名卷 `tgwitness-data`。在您有意迁移完整数据目录之前，它们是相互独立的安装。不要指望新的 Docker 容器会自动发现原生安装中的账户。

## 安装要求

原生安装需要带有 `venv` 和 `ensurepip` 的 Python 3.11 或更高版本、首次安装依赖项时的互联网连接，以及一个可写入的项目目录用于存放 `.venv`。内置面板不需要 Node.js，也不需要前端构建。请使用您的普通操作系统账户运行启动器；TgWitness 不需要管理员/root 权限。

- **Windows**：`Start.cmd` 依次检查 `py -3`、`python`，以及默认的按用户安装文件夹和 Program Files 安装文件夹，要求版本为 3.11 或更高。如果都不可用，它会提供上文所述的按用户自动安装。也可以使用 `py -3 start.py`。便携包完全不需要 Python。
- **Linux**：`start.sh` 会尝试 `python3.13`、`python3.12`、`python3.11`、`python3` 和 `python`；如果都不符合要求，会输出适用于 apt、dnf、pacman、zypper、apk 或 Homebrew 的安装命令。在 Debian/Ubuntu 上可能需要安装与所选解释器匹配的 `python3-venv` 软件包。发行版自带的较旧默认 Python 必须替换为 Python 3.11+，或另行安装 Python 3.11+ 作为补充。
- **macOS**：请安装当前的 Python 3.11+ 发行版；不要假定系统自带的解释器满足要求。请在项目目录中使用 `python3 start.py`。
- **Docker**：请使用 Compose v2.20 或更新版本的 Docker Engine/Desktop。在 Windows 上，Docker Desktop 必须使用 Linux 容器。容器会自行安装 Python 依赖项；主机不需要另外安装 Python。

## 本地计算机

在 Windows 上使用 `Start.cmd`，在 Linux/macOS 上使用 `sh start.sh`。`scripts\Setup.cmd` 或 `sh start.sh --setup-only` 用于准备环境。启动器在首次使用时安装依赖项；之后的启动会复用该环境。设置和 Telegram 采集需要互联网连接，但浏览现有记录和创建导出可以离线进行。

设置完成后运行 `python start.py --check`，即可在不启动收集器的情况下检查本地依赖项、Ed25519、存储、密钥配置和监听地址。使用 `--json` 获取结构化输出。请传入计划使用的 `--data-dir`、`--host` 和 `--port`。该检查不会安装软件包、创建日志或连接 Telegram；它不是完整性或覆盖范围的鉴定。启动时会另行验证现有日志。`python start.py --help` 同样不会触发安装。

使用 start.py 之后，请在 Windows 上用 `.venv\Scripts\python.exe`、在 Linux/macOS 上用 `.venv/bin/python` 运行辅助命令，或者先激活该环境。下面的 `python -m ...` 示例均假定环境已激活。

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

环境变量：TGWITNESS_DATA、TGWITNESS_HOST、TGWITNESS_PORT、TGWITNESS_TOKEN。TGWITNESS_VAULT_KEY_FILE 为新安装选择外部密钥模式；见[外部主密钥](../SECURITY-MODEL.md#external-master-key)。如果提供 TGWITNESS_TOKEN，其长度至少为 24 个字符；请使用密码学安全的随机值。未提供时，应用会在 panel-token.txt 中生成一个 256 位随机令牌。通过环境变量覆盖不会改写该文件。如需轮换凭据，请重新启动。

一个数据目录只能由一个进程独占。跨平台的操作系统文件锁可防止意外的并发写入。请只使用一个 Uvicorn worker。面板可以管理任意数量的工作区，额外工作区的目录位于 profiles/<id>/ 下。如需运行相互独立的服务实例，请使用不同的目录和端口。SQLite WAL 文件应放在本地持久存储上，而不是网络文件系统上。不要在副本之间共享同一个卷。

## Windows 便携包

每个 GitHub Release 都附带 `TgWitness-<version>-windows-amd64-portable.zip` 及其 `.sha256`。其中包含来自 python.org 的官方可嵌入式 Python 3.12 运行时（校验和固定在 `tools/build_portable.py` 中）、TgWitness 及其锁定版本的依赖项，以及三个启动器：

| 文件 | 用途 |
| --- | --- |
| `TgWitness.cmd` | 启动面板；额外选项会原样传递，例如 `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | 在 `data\demo` 中启动使用合成数据的演示 |
| `TgWitness-Check.cmd` | 运行就绪检查，但不启动应用 |

锁定版本的俄语词形词典和 PDF 色彩配置文件已随包附带，供离线使用。打包时，依赖项的 `data` 目录中只允许出现这些文件的已知路径；这些目录中出现意外文件会导致构建失败。

请将整个压缩包解压到可写入的文件夹，例如 `Documents\TgWitness`；不要在 ZIP 内部或 Program Files 中运行。运行时使用隔离的模块路径，因此其他 Python 安装和 `PYTHONPATH` 不会影响它。数据保存在包内的 `data` 文件夹中。更新时，请停止 TgWitness，将新版本解压到新文件夹，然后把 `data` 文件夹复制过去。

在 64 位 Windows 上使用 Python 3.12 自行构建：

~~~sh
python tools/build_portable.py
~~~

## 容器

```sh
docker compose up -d --build --wait
```

这会为 /data 创建一个持久的命名卷。Web 端口映射到 127.0.0.1:8787。进程以 UID 10001 运行，已移除各项 capability，根文件系统为只读，/data 和 /tmp 可写。`--wait` 会在返回前检查 Web 服务器的健康状态；Telegram 授权和投递情况在面板中显示。附带的辅助脚本在构建后使用 180 秒的就绪超时。首次下载依赖项可能需要更长时间。

两个基础 Compose 文件都使用项目名称 `tgwitness`，因此将新版本解压到另一个目录时，不会在不知不觉中选用新的数据卷。该项目只应保留一个处于活动状态的部署。如需相互独立的安装，请使用唯一的 `docker compose -p NAME ...` 和不同的主机端口，并在更新时保留这两项设置。对于使用其他项目名称的旧部署，请继续通过 `-p` 使用其原始名称；`docker compose ls` 会列出现有项目。

将 `deploy/env.example` 复制为 `.env`，并修改 `TGWITNESS_PORT` 以使用其他回环端口。例如，`TGWITNESS_PORT=8788` 会在 `http://127.0.0.1:8788` 提供面板；容器仍监听 8787。`.env` 已被 Git 忽略。

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

`restart: unless-stopped` 会在崩溃或 Docker 守护进程重启后重新启动收集器。在 Linux 服务器上，请使用发行版的服务管理器设置 Docker 开机启动，通常为 `sudo systemctl enable --now docker`。在 Windows/macOS 上，请启用 Docker Desktop 的登录时启动设置。注销桌面会话、睡眠或 Docker 守护进程停止都可能中断采集。被明确停止的容器会一直保持停止状态，直到您再次启动它。

在示例配置中，/tmp 卷的上限为 512 MiB。导出文件改为在持久化 /data 上各工作区的 `temporary-exports/` 中生成。请在该处为同时进行的导出、日志/WAL 增长、媒体和备份预留空间。启动器使用 deploy/constraints.txt 固定经过鉴定的运行时依赖版本。Docker 和高保障服务器使用 pip --require-hashes 从 deploy/requirements.lock 和 deploy/build.lock 安装：每个软件包文件都必须与提交中记录的 SHA-256 一致，因此在 PyPI 或镜像源上被替换的文件会被拒绝。Python 基础镜像和操作系统软件包仍需要独立的发布鉴定。

除非您打算销毁日志和密钥，否则不要使用 docker compose down -v。容器健康状态反映的是 Web 服务器的可用性，而不是 Telegram 捕获是否成功。请在面板中检查收集器状态、心跳、错误和覆盖事件。

### 独立见证人 profile

可选的 `witness` 服务会在独立容器中运行一个[独立见证人](../WITNESS.md)，它在 `witness-data` 卷中拥有自己的密钥和日志，对收集器只持有一个只读的见证人令牌。请在面板的**更多工具 → 扩展功能 → 独立见证人**中创建该令牌，将它与机器人令牌和频道一起添加到 `.env`，然后启动该 profile：

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

该服务在 Compose 网络内通过 `http://tgwitness:8787` 访问收集器（可用 `TGWITNESS_WITNESS_COLLECTOR` 覆盖，例如对另一个工作区使用 `/profiles/<workspace ID>`）。如果见证人运行在由他人管理的另一台服务器上，请在该服务器上使用 `deploy/compose/compose.witness.yaml`，并将 `TGWITNESS_WITNESS_COLLECTOR` 设置为收集器的 HTTPS 地址；该文件只包含见证人。

## 安装已发布的镜像

将 `deploy/env.example` 复制为 `.env`。将 `TGWITNESS_IMAGE` 设置为已发布的版本，并使用**小写**的仓库路径，例如：

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.9.3
TGWITNESS_PORT=8787
```

单独使用此文件运行，而不是 `compose.yaml`：

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

主机上不需要从源代码构建，也不需要 Python 或编译器。发布工作流面向 Linux AMD64 和 ARM64 容器，包括 Docker Desktop 的 Linux 虚拟机。请使用工作流摘要中的版本标签或 `ghcr.io/owner/repository@sha256:...`。未配置会变动的 `latest` 标签，也未配置无人值守的应用升级。当项目名称相同时，镜像版和源代码版使用同一个数据卷。

<a name="automatic-https-on-a-server"></a>

## 服务器上的自动 HTTPS

请使用安装了 Docker 的服务器、由您控制的域名以及持久的本地存储。将域名的 A/AAAA 记录指向该服务器；只有在可通过 IPv6 访问服务器时才发布 AAAA 记录。允许入站 TCP 80 和 443，并允许用于签发证书的出站 DNS/HTTPS。这些端口不得已被其他服务占用。

将 `deploy/env.example` 复制为 `.env`，并设置主机名，不带协议前缀或路径：

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

使用 HTTPS 叠加配置启动源代码构建：

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

对于已发布的镜像，请改用 `deploy/compose/compose.image.yaml` 作为第一个文件。之后执行状态、日志、更新和停止命令时，请保留这两个 `-f` 参数。

Caddy 负责获取和续期证书，将 HTTP 重定向到 HTTPS，并将请求转发给私有 Compose 网络中的收集器。证书状态有自己的持久卷。收集器在主机上的直连端口仍只监听回环地址。附带的 Caddy 配置未启用访问日志。

打开 `https://watch.your-domain.org` 并输入面板令牌。Compose 的就绪状态针对的是容器；证书签发和外部可达性取决于 DNS 和防火墙。如果 HTTPS 尚未就绪，请检查 DNS、防火墙规则以及：

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

附带的 Caddy 镜像跟随其 `2-alpine` 标签。拉取会刷新该镜像；如需固定的基础设施版本，请在部署中固定一个经过测试的摘要（digest）。

## 更新与备份

更新时请保持 Compose 项目名称和数据卷不变。首先停止收集器并进行完整备份。对于默认的基于源代码的部署：

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

每次都请使用新的备份位置，放在仓库之外，并像保护账户访问凭据一样保护它。示例路径仅作说明；请使用您自己的私有备份位置。复制整个目录，包括隐藏文件、所有工作区、密钥、日志和媒体。如果配置了外部保险库主密钥，请单独备份。证据 ZIP 不是可用于恢复的应用备份。使用 HTTPS 时，如需保留 Caddy 的证书/账户状态，也请保留 Caddy 卷。

对于源代码部署，请获取新版本的文件并运行：

```sh
docker compose up -d --build --wait
```

对于镜像部署，请将 `TGWITNESS_IMAGE` 改为所需版本，然后运行：

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

前面的停止/复制命令同样要使用您安装所用的 Compose 文件。请保留 `.env`、自定义配置和相同的项目名称。`down` 会保留命名卷；**`down -v` 会删除它们**。不要在不同操作系统或 Python 版本之间复制 `.venv`。更新原生安装时，请停止 TgWitness，备份其完整数据目录，替换源代码文件，并在启动前运行 `python start.py --setup-only`。

更新后，请检查面板访问、账户身份、观察状态和覆盖范围。重启后，TgWitness 会从已保存的 Telegram 更新位置继续，并请求更新期间错过的更新。如果将来的版本更改了存储格式，回滚可能需要使用更新前的备份。

## 远程服务器

让服务保持绑定在回环地址上并使用 SSH 隧道，或者在反向代理处终止 HTTPS。基础 Compose 文件仅限本地使用；可选的 `deploy/compose/compose.https.yaml` 叠加配置会为已配置的域名提供 Caddy。不要让 bearer 令牌出现在 URL 和代理日志中。反向代理应限制请求大小和连接速率。不要将明文 HTTP 暴露到互联网。

[deploy/](../../deploy/README.md) 中提供了 systemd、Windows 登录任务、macOS 用户代理和 Caddy 的示例。安装前请检查并调整其中的路径。它们是附带的模板，而不是已在本地执行过的平台鉴定。常规启动器不会注册任何后台服务或任务。

在 Windows 上，以无窗口方式通过 `pythonw.exe` 启动时，启动/服务器诊断信息会保存在数据目录下的 `logs/server.log` 中（每个文件 5 MiB，保留两个轮换备份）。从控制台启动时仍将日志输出到控制台。两种模式下 HTTP 访问日志均处于禁用状态。请像保护数据目录一样保护日志，并在分享前进行检查。

## 重启与缺口

最后一次请求的观察状态会被持久保存。如果观察原本处于活动状态，启动时会尝试重新连接并恢复所选来源。手动暂停会清除这一意图。重启失败会被记录并显示在面板中。

TgWitness 将账户及每个频道的 Telegram 更新位置（pts、qts、seq 和 date）保存在工作区保险库中，并在下次启动时恢复。随后客户端会请求进程停止期间错过的更新，定期复查会找回错过的消息，并记录 Telegram 不再返回的已保存消息。启动时会重新加载对话列表。每次启动都会记录此前的日志头、离线边界以及恢复时所依据的更新位置。监控程序每 10 秒检查一次连接，并每分钟添加一次心跳（**更多工具 → 参数 → 存活记录间隔**）。断线和静默期会作为覆盖缺口连同原因一起记录。历史快照作为独立的当前历史观察记录，与实时记录并列存储。

媒体队列存储在每个工作区的 SQLite 数据库中。消息及其任务以原子方式提交。被中断的运行中任务会在启动时恢复并重试。每次下载的基础超时为 120 秒，另按 256 KiB/s 的速度根据文件大小增加时间，每种附件类型的上限为 1–2,000 MiB；超时、速度和重试次数位于**更多工具 → 参数**中。收集器会跳过大小未知的文件。暂停会保留队列中的任务。重试使用最初观察到的文件描述符，绝不会使用之后被编辑的消息的最新版本。临时故障的重试次数有限；媒体的 FloodWait 暂停在重启后依然有效。媒体恢复与 Telegram 更新恢复相互独立，无法重新创建已消失的文件。

## 备份、恢复与容量

复制**整个数据目录**之前请先停止进程，其中包括 vault.key、signing.enc、credentials.enc、SQLite 数据库/WAL 文件、媒体、令牌、检查点以及所有 profiles/ 子目录。请在目标服务停止时恢复完整副本。缺少保险库密钥或签名密钥不匹配会导致启动失败；不要通过重新生成密钥来强行访问。

包含机密的备份应加密并实施访问控制。证据 ZIP 是便于传递的审查材料，不是应用备份，也不是 Telegram 会话备份。系统不会按保留期限自动删除数据。请为所有消息、原始元数据、媒体、临时导出和备份规划磁盘空间。

启动验证和导出都以流式方式读取记录，而不是加载整个日志。导出会固定一个读取快照，同时新的 WAL 写入可以继续；长时间运行的导出可能会保留 WAL 页面，因此磁盘容量仍然重要。ZIP 的未压缩大小上限为 4 GiB，与独立验证器的默认值一致；**更多工具 → 参数 → 最大的签名 ZIP 文件**可提高该上限，此类存档使用 `verify.py --max-gib N` 验证。其他格式没有事件数量上限。受支持的浏览器会将响应分块流式写入用户选择的文件。其他浏览器最多缓冲 128 MiB，并将更大的传输引导至经过身份验证的 CLI：

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

对于其他工作区，使用来自**导出 → 工作区 ID**的 `--profile ID`；另可使用 `--format zip|jsonl|csv|html`；远程服务器使用 `--url https://your-server`；`--max-mib` 用于更改 5 GiB 的传输上限。仅允许在回环地址上使用明文 HTTP。令牌通过请求头传输，重定向会被拒绝，现有文件不会被覆盖，未完成的下载不会作为已完成文件发布。如果 TGWITNESS_TOKEN 覆盖了生成的令牌，请使用一个单独保护、包含当前有效值的文件：覆盖不会改写 panel-token.txt。该命令给出的 SHA-256 只是传输校验和；请独立验证签名 ZIP。

面板会显示排队中/失败的媒体、等待最久的媒体、可用磁盘空间、Telegram 请求暂停情况，以及访问权限尚未确认的来源。这些诊断并不构成完整的端到端投递监控。各工作区共享一个进程；某个负载过高的账户仍可能影响其他账户。独立的工作进程、保留/轮换、持久的更新恢复以及完整的部署鉴定仍有待完成。限定范围的面板访问记录在[访问与权限](../ACCESS.md)中；独立检查点见[见证人指南](../WITNESS.md)。

详细步骤：[连接/安全](../CONNECTION-SECURITY.md)和[运行模式](../OPERATIONS.md)。
