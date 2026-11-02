# Install, verify and update

[Project](../README.md) · [Quick start](QUICKSTART.md) · [Deployment](DEPLOYMENT.md)

## Install with one command

The guided installer includes a private Python runtime. Use the same address for
future installations: each publication updates the installer, hashes, signatures
and build information together.

**Linux / macOS (Bash):**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

On an Ubuntu server, run as root to install a background service. On a desktop,
run as your normal user.

**Windows (PowerShell or Command Prompt):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

No administrator is needed on Windows. The child PowerShell process leaves your
terminal open with the result. Python and dependencies stay in the installation.

On Ubuntu, choose **This computer**, **Temporary HTTPS link** or **Own domain**.
The installer prints the panel address and access key. For a temporary link, open
that HTTPS address in your browser and enter the key. With local access on a remote
server, use an SSH forward from your computer (`ssh -L 8787:127.0.0.1:8787 user@server`)
and open `http://127.0.0.1:8787`. On macOS and Windows, the local panel opens in your
browser; keep its terminal running.

Sign in to Telegram in the panel and choose what to collect. Installation alone
does not start Telegram collection.

## Where everything runs

`get.destroy.tools` is a **Cloudflare Worker serving static downloads**. It has no
TgWitness panel, Telegram session or user evidence database. It is not routed to
a project VPS. The application runs on the machine where you execute the command.

| Installation | Program | Data |
| --- | --- | --- |
| Ubuntu as root | `/opt/tgwitness` | System service: `/var/lib/tgwitness-<installation ID>`; use `tgwitness paths` for the exact path. |
| Linux / macOS user | `~/.local/share/tgwitness` | `data/live` under that installation. |
| Windows user | `%LOCALAPPDATA%\TgWitness` | `data\live` under that installation. |

Set `TGWITNESS_INSTALL_DIR` to choose another folder. Installed versions and data
are separate. The installer does not upload your accounts, messages or keys to
the download site. Choosing a Cloudflare tunnel sends panel traffic through
Cloudflare; using your own domain points to your own server.

Every installation includes **START-HERE.html** and **START-HERE.txt**, with local
paths, commands and links to the repository. Run `tgwitness guide` to open the guide.
On Windows, use `& "$env:LOCALAPPDATA\TgWitness\bin\tgwitness.cmd" guide` in PowerShell.

## Verify before running

The one-line command trusts HTTPS for its initial script. That script checks
SHA-256 and the project's RSA signature on the application and constraints before
installation. You can also download and verify the initial script first.

The public release key is [release-signing.pub](../deploy/installer/release-signing.pub).
Its SHA-256 is:

```text
039d98a658ccda14253e45a00335b4a68d840976d8ec18b8d4355cc7c458447d
```

Retain this fingerprint from a repository revision you trust. A checksum from
the same download server detects a mismatch; the independently trusted public
key is what authenticates a release signature.

Use a new, empty directory for the verification downloads below.

**Linux / macOS — run in a new, empty download directory** (requires curl and OpenSSL):

```sh
curl -fSLO https://get.destroy.tools/install.sh &&
curl -fSLO https://get.destroy.tools/install.sh.sig &&
curl -fSLO https://get.destroy.tools/release-signing.pub &&
test "$(openssl dgst -sha256 release-signing.pub | awk '{print $NF}')" = \
  '039d98a658ccda14253e45a00335b4a68d840976d8ec18b8d4355cc7c458447d' &&
openssl dgst -sha256 -verify release-signing.pub -signature install.sh.sig install.sh &&
bash install.sh
```

The `&&` chain stops before execution if a download, key fingerprint or signature
check fails. If publication happens between downloading the script and its
signature, download both again. Old installers keep their immutable package URLs.

**Windows — inspect the SHA-256 before running:**

```powershell
Invoke-WebRequest https://get.destroy.tools/install.ps1 -OutFile install.ps1 -UseBasicParsing
Get-FileHash .\install.ps1 -Algorithm SHA256
Invoke-RestMethod https://get.destroy.tools/SHA256SUMS.txt
```

Compare the hash with the `install.ps1` line. For an independent signature check,
use OpenSSL (for example, from Git Bash) and the same public-key fingerprint above:

```sh
curl -fSLO https://get.destroy.tools/install.ps1 &&
curl -fSLO https://get.destroy.tools/install.ps1.sig &&
curl -fSLO https://get.destroy.tools/release-signing.pub &&
test "$(openssl dgst -sha256 release-signing.pub | awk '{print $NF}')" = \
  '039d98a658ccda14253e45a00335b4a68d840976d8ec18b8d4355cc7c458447d' &&
openssl dgst -sha256 -verify release-signing.pub -signature install.ps1.sig install.ps1 &&
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1
```

Windows installation itself verifies package signatures with .NET and does not
require OpenSSL. These are detached RSA-3072 / SHA-256 signatures, not Authenticode.
The [manifest](https://get.destroy.tools/manifest.json) records the software version,
exact Git commit, immutable release ID and each artifact's SHA-256. The page links
to the corresponding source. The manifest and checksum list also have detached
signatures (`manifest.json.sig` and `SHA256SUMS.txt.sig`).

## Update an existing installation

**A new publication updates the download site; installed programs update when you
run the installer again.** There is no unattended updater or automatic restart of a
running collection. The current installer channel is **preview**; it follows
published, checked builds from `main`, whose commit can be newer than the last
numbered GitHub release. The page's version comes from `pyproject.toml`; its commit
and build ID distinguish updates within the same preview version.

Use the same installation folder and OS user as before. Back up the complete data
directory with collection stopped; `tgwitness paths` identifies it. A signed export
is not a complete installation backup.

**Ubuntu root installation at `/opt/tgwitness`:**

```sh
curl -fsSL https://get.destroy.tools/install.sh | TGWITNESS_INSTALL_DIR=/opt/tgwitness bash -s -- --no-start
```

After a successful installation:

```sh
/opt/tgwitness/bin/tgwitness restart
/opt/tgwitness/bin/tgwitness status
/opt/tgwitness/bin/tgwitness open
```

For a Linux/macOS user installation, use its original `TGWITNESS_INSTALL_DIR` or
the default and run the first installation command again. Close a foreground
panel before updating and start it again afterwards. For a configured Linux user
service, run its `tgwitness restart` command.

**Windows:** close the running panel, run the Windows installation command again,
then open `bin\tgwitness.cmd` in the same installation. The installer retains data,
sessions, access settings and signing keys. It switches the launcher only after
the new environment passes its checks; failed installation leaves the previous
launcher in place. Keep the pre-upgrade backup for storage-format changes.

## Everyday commands on Ubuntu

| Command | Result |
| --- | --- |
| `tgwitness open` | Current panel URL and access key. |
| `tgwitness paths` | Exact program, data and guide paths. |
| `tgwitness guide --print` | Offline operating instructions. |
| `tgwitness status` / `tgwitness logs` | Availability / service logs. |
| `tgwitness stop` / `tgwitness start` | Stop / resume the service; retain data. |
| `tgwitness token rotate` | Replace the administrator key and end browser sessions. |
| `tgwitness tunnel off` | Disable the public quick tunnel; retain the local panel. |
| `tgwitness tunnel on` / `tgwitness tunnel restart` | Create a quick-tunnel link / replace its address. |

See [Access](ACCESS.md) for colleague tokens, sessions and IP restrictions, and
[installer publishing](../deploy/installer/README.md#automatic-publication-from-github)
for the GitHub-to-Cloudflare release workflow.

## Remove TgWitness

There is no uninstaller: you stop the panel and delete its folders. Deleting the data
folder destroys journals, signing keys, Telegram sessions and saved files for good.
Before that:

1. Export what you need (**Exports → Download signed ZIP**) and keep the signing key
   fingerprint and checkpoints outside this machine. To keep the workspace itself, copy
   the whole data folder with collection stopped.
2. Delete servers created under **Extras → Server 24/7** from **Your servers** or with
   `python -m tgwitness.cloud destroy`; the provider bills them until they are deleted.
3. End each account's session in Telegram under **Settings → Devices**. Deleting the
   files does not sign the session out on Telegram's side.

**Ubuntu root installation.** Note the data folder, stop the service, then remove the
service, the folders and the shortcut:

```sh
/opt/tgwitness/bin/tgwitness paths
/opt/tgwitness/bin/tgwitness stop
systemctl list-unit-files 'tgwitness-*'
systemctl disable tgwitness-<ID>
rm /etc/systemd/system/tgwitness-<ID>.service
systemctl daemon-reload
rm -rf /opt/tgwitness /var/lib/tgwitness-<ID> /usr/local/bin/tgwitness
```

**Linux or macOS user installation.** Close the panel. A configured Linux user service
is stopped with `systemctl --user disable --now tgwitness-<ID>`; its unit is in
`~/.config/systemd/user/`. Then delete `~/.local/share/tgwitness` (or your
`TGWITNESS_INSTALL_DIR`) and the `~/.local/bin/tgwitness` shortcut.

**Windows.** Close the panel and delete `%LOCALAPPDATA%\TgWitness` (or your
`TGWITNESS_INSTALL_DIR`). The installer adds no service, scheduled task or shortcut.
