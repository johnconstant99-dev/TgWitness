# One-command installation

This directory contains the installer templates and the static download page.
The builder packages the checked application, embeds SHA-256 hashes in the
installers and creates an immutable release directory. Hosting needs only static
HTTPS: a separate virtual host on the API server or Cloudflare Workers assets.

The intended public address is `https://get.destroy.tools`. Connect and verify
that hostname before putting the commands in the main installation instructions.

| System | Command after the host is live |
| --- | --- |
| Linux / macOS | `curl -fsSL https://get.destroy.tools/install.sh \| bash` |
| Windows Command Prompt or PowerShell | `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 \| iex"` |

The Windows command runs in a child PowerShell process, so your terminal stays
open with the result and launch instructions. If you prefer curl, use this
alternative in Command Prompt; it leaves any existing `install.cmd` untouched:

```bat
if exist install.cmd (echo install.cmd already exists. Choose another folder.) else (curl -fsSL https://get.destroy.tools/install.cmd -o install.cmd && call install.cmd && del install.cmd)
```

The installer brings its own Python 3.12 through a pinned uv build. It installs
the panel and MCP into a private environment, then prints the launch command.
It does not start a service, connect Telegram accounts or alter an existing
source checkout. On Unix, `TGWITNESS_NO_LINK=1` suppresses the optional
`~/.local/bin/tgwitness` shortcut. Shell profiles are not edited.

Default locations are `~/.local/share/tgwitness` and `%LOCALAPPDATA%\TgWitness`.
Set `TGWITNESS_INSTALL_DIR` for a different location. Program versions and data
are separate; the launcher switches only after the new environment passes its
checks. An installation failure keeps the previous launcher. Run `--plan` for
Bash or `-Plan` for Windows to inspect the destination without installing.

## Build and check

Use a clean application checkout and Python 3.11+ with setuptools and wheel:

```sh
python tools/build_installer.py --base-url https://get.destroy.tools
python tools/check_installer.py
# Linux/macOS: actual runtime and dependency downloads, private temporary install.
python tools/check_installer.py --install
```

The output is `dist/installer-site/`. Each release path contains a wheel,
dependency constraints, installer copies, SHA-256 sidecars and a manifest linking
the build to its source commit. `install.cmd` pins the PowerShell child's hash.
The wheel inventory and RECORD are checked against the checkout before release.

The install acceptance check maps only the unpublished download origin to the
generated local files. uv, managed Python and package downloads use real HTTPS.
It never starts the panel or opens a real account.

## On the existing API server

1. Put the built static directory in a separate location, for example
   `/var/www/tgwitness-installer`. Retain older `releases/` directories: previously
   downloaded installers refer to their immutable paths.
2. Add a separate virtual host for `get.destroy.tools`. Adapt
   [nginx.conf.example](nginx.conf.example) to the existing web server; preserve
   the API's host and upstream configuration.
3. Point the subdomain to the server and configure a valid HTTPS certificate.
   The example is an HTTP virtual host intended for certificate provisioning;
   it is not a complete HTTPS deployment by itself.
4. Check the web-server configuration before reloading. Fetch all three public
   scripts, compare them with the built checksums, then perform a fresh install.

Do not send these requests to a generic API or SPA fallback. A missing download
must return 404, and the wheel must be served as a binary file. The installers
reject downloads whose hashes do not match.

## Cloudflare alternative

The same output works as Workers static assets. Set the hostname in
[wrangler.toml](wrangler.toml), authenticate Wrangler for the `destroy.tools`
zone and deploy that configuration. The custom domain creates its DNS routing
and TLS through Cloudflare. No application server or Telegram credentials are
needed by this host.

Keep account IDs and API tokens in the operator environment or GitHub secrets.
The repository's installer workflow builds and checks an artifact; it does not
change DNS or deploy without a separate hosting step.

## What the checks establish

SHA-256 checks the bytes of uv, the application wheel, dependency constraints
and the CMD bootstrap's child script. These hashes are embedded in the delivered
installer. This is HTTPS distribution with integrity checks, **not an issuer
signature or an Authenticode-signed Windows installer**. Python/dependency
resolution uses the pinned toolchain and dependency versions. Do not describe
the checksum manifest as a signed release.
