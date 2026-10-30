**English** · [Русский](ru/DEPLOYMENT.md) · [Українська](uk/DEPLOYMENT.md) · [Español](es/DEPLOYMENT.md) · [Português (Brasil)](pt/DEPLOYMENT.md) · [Türkçe](tr/DEPLOYMENT.md) · [العربية](ar/DEPLOYMENT.md) · [فارسی](fa/DEPLOYMENT.md) · [اردو](ur/DEPLOYMENT.md) · [हिन्दी](hi/DEPLOYMENT.md) · [Bahasa Indonesia](id/DEPLOYMENT.md) · [Tiếng Việt](vi/DEPLOYMENT.md) · [简体中文](zh/DEPLOYMENT.md)

# Deployment and operations

## Choose an installation

For the portable package, extract `TgWitness-<version>-windows-amd64-portable.zip` from
GitHub Releases. For the other methods, download and extract the source ZIP or clone the
repository, then run the following from the project directory:

| Installation | Start | Runs in the background? |
| --- | --- | --- |
| Windows portable package | `TgWitness.cmd` | No; keep the window open. |
| Native Windows | `Start.cmd` | No; use the optional logon task for background use. |
| Native Linux/macOS | `sh start.sh` | No; use systemd/launchd for background use. |
| Docker on any supported host | `docker compose up -d --build --wait` | Yes, while the Docker daemon runs. |
| Docker helper on Windows | `scripts\Docker.cmd` | Yes; the helper waits for web-server health. |
| Docker helper on Linux/macOS | `sh scripts/docker-start.sh` | Yes; the helper waits for web-server health. |

For a cloud server that a third party should be able to check — created through the
provider's API, without SSH, reached only through a Cloudflare Tunnel — see
[high-assurance deployment](HIGH-ASSURANCE.md).

Native startup creates a private `.venv` and installs the pinned dependencies.
Docker builds them inside the image, without requiring host Python. First-time
setup needs Internet access. When no Python 3.11+ is found, `Start.cmd` asks before
installing Python 3.12 for the current Windows user (winget, otherwise the python.org
installer after checking its Python Software Foundation signature); it never requests
administrator privileges. Docker and OS services remain prerequisites.

Native and portable installations use `data/live` inside their folder. Docker uses the `tgwitness-data` named volume
at `/data`. These are separate installations until you deliberately migrate the
complete data directory. Do not expect a new Docker container to discover native
accounts automatically.

## Installation requirements

Native installation needs Python 3.11 or later with `venv` and `ensurepip`, Internet
access for the first dependency installation, and a writable project directory for
`.venv`. The bundled panel needs no Node.js or frontend build. Run the launcher from
your normal OS account; administrator/root privileges are not required by TgWitness.

- **Windows:** `Start.cmd` checks `py -3`, then `python`, then the default per-user and
  Program Files install folders, and requires version 3.11 or later. If none works, it
  offers the automatic per-user installation described above. `py -3 start.py` also works.
  The portable package needs no Python at all.
- **Linux:** `start.sh` tries `python3.13`, `python3.12`, `python3.11`, `python3` and
  `python`, and prints the install command for apt, dnf, pacman, zypper, apk or Homebrew
  when none qualifies. Debian/Ubuntu installations may require the
  `python3-venv` package matching the selected interpreter. A distribution's older
  default Python must be replaced or supplemented with Python 3.11+.
- **macOS:** install a current Python 3.11+ distribution; do not assume an OS-provided
  interpreter meets the requirement. Use `python3 start.py` from the project directory.
- **Docker:** use Docker Engine/Desktop with Compose v2.20 or newer. Docker Desktop
  must use Linux containers on Windows. The container installs its
  own Python dependencies; the host does not need a separate Python installation.

Use persistent local storage for the data directory. Plan capacity from messages,
media, WAL growth, exports and backups; there is no evidence-based universal minimum
disk/RAM specification for every workload. CPU architectures and Python versions
without compatible dependency wheels may require additional build tools and their
own qualification. "Portable" is not a claim of universal OS or hardware support.

Windows 11/Python 3.12 is locally verified. Linux/macOS/container definitions and CI
are supplied but have not been executed on this development host. See
[VERIFICATION.md](VERIFICATION.md) for the exact scope.

## Local computer

Use `Start.cmd` on Windows or `sh start.sh` on Linux/macOS. `scripts\Setup.cmd` or
`sh start.sh --setup-only` prepares
the environment. The launcher installs dependencies on first use; later launches
reuse the environment. Internet access is needed for setup and Telegram collection,
but browsing existing records and creating exports work offline.

Run `python start.py --check` after setup to inspect local dependencies, Ed25519,
storage, key configuration and the listening address without starting a collector.
Use `--json` for structured output. Pass the intended `--data-dir`, `--host` and
`--port`. The check does not install packages, create a journal or connect Telegram;
it is not an integrity or coverage qualification. Startup separately verifies
existing journals. `python start.py --help` also avoids installation.

Options:

After using start.py, run auxiliary commands with `.venv\Scripts\python.exe` on
Windows or `.venv/bin/python` on Linux/macOS, or activate that environment first.
The `python -m ...` examples below assume the environment is active.

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

Environment variables: TGWITNESS_DATA, TGWITNESS_HOST, TGWITNESS_PORT, TGWITNESS_TOKEN.
TGWITNESS_VAULT_KEY_FILE selects external-key mode for a new installation; see below.
TGWITNESS_TOKEN, if supplied, must contain at least 24 characters; use a cryptographically
random value. Without it, the app generates a 256-bit random token in panel-token.txt.
The environment override does not rewrite that file. Restart to rotate credentials.

Exactly one process may own a data directory. A cross-platform OS file lock prevents
accidental concurrent writers. Use one Uvicorn worker. The panel can manage any number of
workspaces, with additional workspace directories under profiles/<id>/.
For separate service instances, use separate directories and ports. SQLite WAL files belong on local persistent
storage, not a network filesystem. Do not share one volume between replicas.

## Windows portable package

Each GitHub Release carries `TgWitness-<version>-windows-amd64-portable.zip` and its
`.sha256`. It contains the official embeddable Python 3.12 runtime from python.org
(checksum pinned in `tools/build_portable.py`), TgWitness and its pinned dependencies,
and three launchers:

| File | Purpose |
| --- | --- |
| `TgWitness.cmd` | Start the panel; extra options are passed through, e.g. `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | Start the synthetic demo in `data\demo` |
| `TgWitness-Check.cmd` | Run the readiness check without starting |

Extract the whole archive to a writable folder such as `Documents\TgWitness`; do not run
it from inside the ZIP or from Program Files. The runtime uses an isolated module path,
so other Python installations and `PYTHONPATH` do not affect it. Data stays in the
package's `data` folder. To update, stop TgWitness, extract the new version to a new
folder and copy the `data` folder across.

Build it yourself on 64-bit Windows with Python 3.12:

~~~sh
python tools/build_portable.py
~~~

The builder verifies the runtime checksum, installs the constrained dependencies into
the package, runs the readiness check with the embedded interpreter and writes the ZIP
and checksum to `dist/`.

## Container

```sh
docker compose up -d --build --wait
```

This creates a named persistent volume for /data.
The web port is mapped to 127.0.0.1:8787. The process runs as UID 10001 with dropped
capabilities, a read-only root filesystem, and writable /data and /tmp.
`--wait` checks web-server health before returning; it does not establish Telegram
authorization or delivery. The supplied helpers use a 180-second readiness timeout
after building. Initial dependency downloads can take longer than that.

Both base Compose files use the project name `tgwitness`, so extracting a new release
into another directory does not silently select a new data volume. Keep only one
deployment active for that project. For independent installations, use a unique
`docker compose -p NAME ...` and a different host port, and retain both on updates.
For an older deployment using a different project name, continue using its original
name with `-p`; `docker compose ls` lists existing projects.

Copy `deploy/env.example` to `.env` and change `TGWITNESS_PORT` to use a different loopback
port. For example, `TGWITNESS_PORT=8788` exposes the panel at
`http://127.0.0.1:8788`; the container still listens on 8787. `.env` is Git-ignored.

Retrieve the initial token:

~~~sh
docker compose exec tgwitness cat /data/panel-token.txt
~~~

Useful commands:

```sh
docker compose ps
docker compose logs --tail 100 -f
docker compose stop
docker compose up -d --wait
```

`restart: unless-stopped` restarts the collector after a crash or Docker daemon
restart. On a Linux server, enable Docker at boot using your distribution's service
manager, commonly `sudo systemctl enable --now docker`. On Windows/macOS, enable
Docker Desktop's start-at-sign-in setting. Desktop sign-out, sleep, or a stopped
Docker daemon can interrupt collection. An explicitly stopped container stays
stopped until you start it again.

The /tmp volume is capped at 512 MiB in the example configuration. Export construction
uses each workspace's `temporary-exports/` on persistent /data instead. Reserve space
there for simultaneous exports, journal/WAL growth, media and backups.
The launcher and Docker use deploy/constraints.txt to pin qualified runtime dependency
versions. This is not a hash-locked supply chain: the Python base image and package
artifacts still require independent release qualification.

Do not use docker compose down -v unless you intend to destroy the journal and keys.
Container health reports web-server availability, not successful Telegram capture.
Inspect the panel's collector state, heartbeat, errors, and coverage events.

### Independent witness profile

The optional `witness` service runs an [independent witness](WITNESS.md) in its own
container, with its own key and journal in the `witness-data` volume and only a read-only
witness token for the collector. Create the token on the panel's **Witness** page, add it
with a bot token and channel to `.env`, then start the profile:

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

The service reaches the collector inside the Compose network at `http://tgwitness:8787`
(`TGWITNESS_WITNESS_COLLECTOR` overrides it, for example `/profiles/<workspace ID>` for
another workspace). For a witness on a separate server, run by someone else, use
`deploy/compose/compose.witness.yaml` there with `TGWITNESS_WITNESS_COLLECTOR` set to the collector's HTTPS
address; that file contains only the witness.

## Install a published image

This becomes available after a successful [release workflow](#automated-github-releases)
and public GHCR package configuration. The repository's owner/name is not hardcoded
into this source tree. Use the image shown in that release's workflow summary.

Copy `deploy/env.example` to `.env`. Set `TGWITNESS_IMAGE` to the published version, using
the **lowercase** repository path, for example:

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.7.0
TGWITNESS_PORT=8787
```

Run this file on its own, instead of `compose.yaml`:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

No source build, Python, or compiler is needed on the host. The release workflow
targets Linux AMD64 and ARM64 containers, including Docker Desktop's Linux VM.
Use a version tag or `ghcr.io/owner/repository@sha256:...` from the workflow summary.
No moving `latest` tag or unattended application upgrade is configured. The
image and source variants use the same data volume when their project name matches.

## Automatic HTTPS on a server

Use a server with Docker, a domain you control, and persistent local storage.
Point the domain's A/AAAA records at the server; publish AAAA only if IPv6 reaches
it. Allow inbound TCP 80 and 443 and outbound DNS/HTTPS for certificate issuance.
Other services must not already own these ports.

Copy `deploy/env.example` to `.env` and set a hostname, without a scheme or path:

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

Start the source build with the HTTPS overlay:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

For a published image, use `deploy/compose/compose.image.yaml` as the first file instead. Keep
both `-f` arguments for later status, logs, update, and stop commands.

Caddy obtains and renews a certificate, redirects HTTP to HTTPS, and forwards
requests to the collector on the private Compose network. Certificate state has
its own persistent volume. The collector's direct host port remains loopback-only.
The supplied Caddy configuration does not enable access logging.

Open `https://watch.your-domain.org` and enter the panel token. Compose readiness
does not confirm certificate issuance or external reachability. If HTTPS is not
ready, inspect DNS, firewall rules, and:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

The supplied Caddy image follows its `2-alpine` tag. Pulling refreshes that image;
pin a tested digest in your deployment if you need fixed infrastructure versions.

## Updates and backups

Preserve the Compose project name and data volume across updates. First stop the
collector and make a complete backup. For the default source-based deployment:

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

Use a new backup destination each time, outside the repository, and protect it as
account-access material. The example path is illustrative; use your private backup
location. Copy the entire directory, including hidden files, all workspaces, keys,
journals, and media. Back up an external vault master key separately if configured.
An evidence ZIP is not a restorable application backup. For HTTPS, also preserve
the Caddy volumes if you need to retain its certificate/account state.

For a source deployment, obtain the new release files and run:

```sh
docker compose up -d --build --wait
```

For an image deployment, change `TGWITNESS_IMAGE` to the desired version, then run:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

Use your installation's Compose file(s) for the preceding stop/copy commands too.
Keep `.env`, custom configuration, and the same project name. `down` keeps named
volumes; **`down -v` deletes them**. Do not copy `.venv` between operating systems
or Python versions. For native updates, stop TgWitness, back up its full data
directory, replace source files, and run `python start.py --setup-only` before launch.

Check panel access, account identity, observation state, and coverage after an
update. Restarting does not reconstruct missed Telegram updates. A rollback may
require the pre-update backup if a future version changes storage formats.

## Automated GitHub releases

The [release workflow](../.github/workflows/release.yml) is ready to use after this
project is pushed to a GitHub repository with Actions enabled. It runs when a
GitHub Release is **published**, including a prerelease. Drafts and tag pushes
alone do not publish packages.

1. Set the package version and changelog, then publish a release tagged with `v`
   plus the exact `pyproject.toml` version, such as `v0.7.0`.
2. The workflow validates the tag and runs the shared Windows/Linux/macOS Python,
   general/account-import/QR browser, source-package, and Docker checks. Fresh native installation is also
   exercised on all three operating systems using Python 3.12.
3. After those checks pass, it smoke-tests an ARM64 image under QEMU, publishes
   AMD64/ARM64 images to `ghcr.io/<lowercase-owner>/<lowercase-repository>:<version>`,
   and attaches the source ZIP, checksum, and Python wheel to the release. A separate
   Windows job builds and attaches the portable ZIP and its checksum.
4. After the first publication, open the GHCR package settings and set visibility
   to **Public** if anonymous image pulls are intended. A public source repository
   alone does not guarantee a public container package. Organization policies must
   permit package publication. The workflow uses `GITHUB_TOKEN`; no registry
   password or VPS credentials belong in the repository.

Remote workflow success has not been established by this local preparation. ARM64
emulation is a smoke check, not native-hardware or live Telegram qualification.
This automates release packaging; starting a server still requires the Compose
command and its domain/host prerequisites. Existing servers are not silently
upgraded or restarted when a release is published.

## Remote server

Keep the service bound to loopback and use an SSH tunnel, or terminate HTTPS at a
reverse proxy. The base Compose file is local-only; the optional
`deploy/compose/compose.https.yaml` overlay supplies Caddy for a configured domain.
Keep the bearer token out of URLs and proxy logs. A reverse proxy should limit
request size and connection rates. Do not expose plain HTTP to the Internet.

Examples for systemd, a Windows logon task, a macOS user agent and Caddy are provided
in [deploy/](../deploy/README.md). Review/adapt their paths before installation.
They are supplied templates, not locally executed platform qualifications. No
background service or task is registered by the normal launcher.

On Windows, a windowless `pythonw.exe` launch stores startup/server diagnostics in
`logs/server.log` under the data directory (5 MiB per file, two rotated backups).
Console launches retain console logging. HTTP access logging is disabled in both
modes. Protect logs with the data directory and review them before sharing.

## Restart and gaps

The last requested observation state is persisted. If observation was active,
startup attempts to reconnect and resume selected sources. Manual pause clears
that intention. A failed restart is recorded and shown in the panel.

StringSession retains authorization but not Telethon's durable update/entity state.
Dialogs are reloaded on start. Telegram/Telethon can recover some transport interruptions
while running, but TgWitness does not claim durable replay across process restarts.
Every startup records the preceding journal head and the offline boundary.
The monitor checks connectivity every 10 seconds and adds a heartbeat every minute
(**Parameters → Liveness record every**).
Brief interruptions can be missed; a connected transport does not guarantee complete
update delivery. Snapshots are explicit current-history observations, never gap repair.

The media queue is stored in each workspace's SQLite database. A message and its job
are committed atomically. Interrupted running jobs are recovered for retry on start.
Each download has a 120-second base timeout plus time at 256 KiB/s for its size, and a
1–2,000 MiB limit per attachment type; timeout, speed and retries are under **Parameters**. The collector
skips files whose size is unknown. Pausing retains queued work. Retry uses the original
observed file descriptor, never the latest version of a subsequently edited message.
Temporary failures have bounded retries; media FloodWait pauses survive restart.
Media recovery is separate from Telegram update recovery and cannot recreate vanished files.

## Backup, restore, and capacity

Stop the process before copying the **entire data directory**, including vault.key,
signing.enc, credentials.enc, SQLite database/WAL files, media, token, checkpoints,
and all profiles/ subdirectories. Restore
the complete copy while the destination service is stopped. Missing vault keys or
signing-key mismatch cause startup to fail; do not regenerate keys to force access.

Keep secret backups encrypted and access-controlled. Evidence ZIPs are portable
review artifacts, not application backups or Telegram-session backups.
There is no automatic retention deletion. Plan disk space for all messages, raw
metadata, media, temporary exports, and backups.

Startup verification and export stream records instead of loading the whole journal.
An export pins a read snapshot while new WAL writes can continue; long-running exports
can retain WAL pages, so disk capacity still matters. ZIPs are capped at 4 GiB
uncompressed to match the independent verifier's default; **Parameters → Largest signed ZIP**
raises the cap, and such archives are verified with `verify.py --max-gib N`. Other formats have no event-count cap.
Supported browsers stream response chunks to a user-selected file. Other browsers
buffer at most 128 MiB and direct larger transfers to the authenticated CLI:

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

Use `--profile ID` from **Exports → Workspace ID** for another workspace,
`--format zip|jsonl|csv|html`, `--url https://your-server` for a remote server, or
`--max-mib` to change the 5 GiB transfer limit. Plain HTTP is allowed only for
loopback. Tokens travel in headers, redirects are refused, existing files are
not overwritten, and incomplete downloads are not published as finished files.
If TGWITNESS_TOKEN overrides the generated token, use a separately protected file
containing that active value: panel-token.txt is not rewritten by the override.
The command's SHA-256 is only a transfer checksum; independently verify the signed ZIP.

Server export files remain inside each workspace's private `temporary-exports/`.
Successful responses clean up their files. Interrupted exports are removed at the
next workspace startup with its exclusive instance lock held. This directory is part
of the storage threat/capacity model; use an encrypted data volume. Production-scale
multi-gigabyte transfers still require qualification on your target system.

The panel displays queued/failed media, oldest pending media, free disk, Telegram
request pauses, and sources whose access is unconfirmed. These diagnostics are not
a complete end-to-end delivery monitor. Workspaces share a process; a noisy account can
still affect others. Separate worker processes, retention/rotation, durable update
recovery, remote checkpoint anchoring, roles, and full deployment qualification remain.

## Connection and protection options

Connection routes are per workspace and should be configured before authorization.
SOCKS5/HTTP CONNECT use the pinned python-socks dependency. MTProxy uses Telethon's
experimental randomized intermediate transport; Fake TLS ee secrets are unsupported.
No automatic direct fallback is configured. This is not a system-wide network route.

For new installations, TGWITNESS_VAULT_KEY_FILE points to a separately protected random
master-key file. Mount it read-only outside /data in a container. Preserve the public
vault.external.json salt metadata with each workspace and the master key separately.
Existing local vaults require a planned migration; setting this variable does not
silently convert them. Message/media storage and exports are not application-encrypted.
Use encrypted volumes and sufficient private temporary storage where needed.

Detailed procedures: [connection/security](CONNECTION-SECURITY.md) and
[operating modes](OPERATIONS.md).
