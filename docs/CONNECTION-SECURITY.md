[TgWitness](../README.md) / [Documentation](README.md) · [Deployment and recovery](DEPLOYMENT.md)

![Deployment & recovery](assets/presentation/chapter-operate.svg)

# Connection, proxies and data protection

This document describes TgWitness 0.8.0 behavior and its limits. Authentication,
source access, network connectivity and capture completeness are separate states.
For sign-in steps, file formats, and multiple accounts, start with
[accounts and session formats](ACCOUNTS.md). For event policies and restart
behavior, see [how collection works](COLLECTION.md).

## Guided connection setup

In **Connection**, the administrator can choose **This account**, **An account
group** or **All accounts**, then select a route. **Review selection** lists the
affected accounts. **Prepare and check** tests the proposed route without changing
the saved one. **Apply checked connection** checks again, pauses observation if
necessary, saves the route and resumes observation that was already running.
It never starts collection in a previously idle account. History downloads remain
paused and can be resumed separately. Pause active exports before switching.

Group changes keep accounts with their own route by default. Clear that option
only when the preview lists the changes you intend. Application reports each
account's result; it is not an all-or-nothing transaction across databases. A
failed switch restores that account's previous settings. A failure to resume is
shown explicitly. Previews expire after ten minutes and changes to connection
settings or group membership require a new check.

| Route | What TgWitness manages |
| --- | --- |
| Direct | Connections from the host; an external host VPN is not detected or enforced. |
| VPN | One full-tunnel WireGuard profile per account, carried by a local userspace SOCKS5 process. No host interface or driver is installed. |
| My proxy | SOCKS5, HTTP CONNECT or MTProxy credentials. A URL can fill the SOCKS5/HTTP fields. Selecting several accounts shares this entered proxy. |
| Public MTProto | The existing pool assigns Telegram routes. External requests are disabled until a separate suitable proxy is configured in the advanced settings. |
| WARP | A separate local tunnel for each selected account, with WARP registration and a WireGuard profile kept in that account's vault. |

The current-route check uses a fresh unauthenticated Telegram transport, not the
account's session. For HTTP-capable routes it also requests Cloudflare's HTTPS
trace through that route and displays its reported exit IP, country, WARP state
and check time. The measured latency is the Telegram connection setup time,
not an ICMP ping. WARP preparation fails unless the trace reports WARP active.
These preflight checks report route connectivity and the observed exit. Review
captured records through the archive's acquisition and verification results. A
running local process alone is not a successful exit check.

### Portable WARP and WireGuard

This is an **unofficial WARP integration** using
[wgcf 2.3.1](https://github.com/ViRb3/wgcf/releases/tag/v2.3.1) and
[wireproxy 1.1.3](https://github.com/windtf/wireproxy/releases/tag/v1.1.3).
The administrator explicitly accepts setup before the first download or WARP
registration. Those setup connections go directly to GitHub and Cloudflare and
reveal the machine's IP. Ordinary account traffic keeps its existing route until
application. Cloudflare chooses the exit address and country; separate tunnels
can share an exit address. Country selection, periodic IP rotation and a host-wide
VPN kill switch are not provided by this feature.

Supported helper downloads: Linux and macOS x86-64/ARM64, and Windows x86-64.
Artifacts are checked against SHA-256 hashes bundled in the reviewed source,
and cached executables are checked again before launch. No helper is added to
PATH, installed as a system service, or given a public listener. All files live
under the workspace's `portable-routes/` directory and encrypted vault entries.
The loopback SOCKS5 listener requires independently generated credentials.

Private profiles and WARP account credentials are encrypted with the existing
workspace vault. While running, the helper needs an owner-only plaintext config;
it is removed on a normal stop. A host crash can leave this file behind in the
owner-only data folder. This does not encrypt the disk or protect against its
administrator. The supervisor closes the tunnel if the panel's parent pipe
disappears. A failed tunnel never enables a direct fallback. Panel restart
restores a selected tunnel; failed starts retry with a bounded delay. **Stop
tunnel** also pauses observation and persists the stopped state. **Start tunnel**
starts the tunnel; resume observation separately when ready.

Uploaded WireGuard profiles must contain one Interface and one Peer, full IPv4
and IPv6 routes, and no hooks, includes, environment substitutions or extra
listeners. Public endpoint addresses are resolved and pinned before startup.
Use an external VPN or SOCKS5 gateway for OpenVPN/IPsec and private endpoints.

## Authentication methods

**API ID and API hash identify an application; they do not replace account login.**
They are optional in TgWitness. Precedence: a pair entered in the form, then one from an
imported account JSON, then the pair saved in the workspace, then the built-in pool of 50
public pairs, tried in random order with automatic rotation when Telegram refuses one. Only the
Telegram Desktop pair (2040) is sent with a matching Telegram Desktop client description.
Your own pair from API Development Tools at [my.telegram.org](https://my.telegram.org)
can be used with all of your accounts; each account still has its own authorization.

| Method | Requirements | TgWitness support |
| --- | --- | --- |
| Phone, code, optional 2FA | Account access; API pair optional | Panel login |
| Auth Key HEX + DC ID | Full 512-character key and DC 1–5 | Direct **Auth key** tab; optional User ID checked before authorization is saved |
| Telethon StringSession | A valid session string | Panel login |
| Telethon SQLite `.session` | Closed, consistent copy | Direct panel import of schemas 7/8; optional offline CLI |
| Pyrogram SQLite `.session` | Closed production user session | Direct panel import of schemas 2/3 |
| Telegram Desktop TData ZIP | One modern account; local passcode if protected | In-memory conversion with checksum/decryption checks |
| Account JSON | Supported API/session/key fields | Metadata alone fills API credentials; a session/key or phone/QR login is still needed |
| QR login | Confirmation from an authorized Telegram app | Local QR generation, expiry/retry, optional 2FA |
| TDLib / Pyrogram StringSession | Other library-specific formats | Unsupported |
| Bot token | A bot with its own access/update model | Not used by this collector |

Telegram chooses code delivery, including whether to send SMS. An API hash cannot repair
a revoked session or replace a forgotten 2FA password. TgWitness does not persist
login codes or the Telegram 2FA password to disk.

For a private source, the account must already have access. A group username is
unnecessary. A proxy or session import grants neither membership nor administrator
rights. The chat's settings decide whether members see history from before they joined.

## Import a Telethon session file

Telethon SQLite, Pyrogram SQLite, and Telegram Desktop TData use different formats.
The panel detects and converts the supported structures; renaming a file is not
conversion. Select one session and its companion JSON under **Files**, then press **Connect account**. Up to four matching files and
8 MiB total are accepted. See [format limits](ACCOUNTS.md) for TData/JSON details.
There is no passcode recovery. Phone/2FA or QR login creates a separate authorization.

The optional Telethon-only command-line path remains available:

1. Stop the client using the original session and make a consistent copy. The
   converter rejects files with an unfinished WAL/journal. Close the original
   client properly instead of deleting those files to bypass the check.
2. From the TgWitness environment, run:

```sh
python -m tgwitness.sessions account.session --out account.tgwitness-session
```

3. Under **Add account → Files**, load the result or
   paste its string, and continue.
4. Check the displayed numeric account ID, select sources and start observation.

**The converted file is an unencrypted account-access secret.** Keep it in protected
storage and never commit it or send it to a third-party conversion service. TgWitness
saves the authorized session in its encrypted vault. Copying a session does not
create a separate authorization: do not run concurrent clients with cloned auth keys
and assume independent update delivery.

Conversion transfers authorization, not original messages, the entity cache or a
durable update cursor. It does not fix update recovery across process restarts.

## MTProto, Telethon and proxies

MTProto is Telegram's protocol. Telethon is the Python client library TgWitness uses.
MTProxy is a Telegram transport proxy; SOCKS5 and HTTP CONNECT provide general
tunnels. None replaces account authentication.

Save the route for each workspace in **Account → Settings → Connection settings → Change connection route** before
signing in. New workspaces default to **Automatic MTProxy · public lists** with **Hide the address**.
Existing workspaces that explicitly used Direct retain a mode permitting it.

## IP modes

The route chooses the connection. The IP mode, **IP protection** in the panel's Account
section, determines when the server's address may be exposed. These controls do not
install a VPN or route all machine traffic.

| Mode | Telegram | External requests |
| --- | --- | --- |
| Hide the address (`hide`) | Use a proxy; wait if none works. No direct fallback. | Require SOCKS5/HTTP; refuse requests without an applicable proxy. |
| Direct as a last resort (`fallback`) | Automatic MTProxy may use Direct after the configured delay, then return to a working proxy. | Prefer a configured external proxy or the account's SOCKS5/HTTP route; otherwise Direct is allowed. |
| Server behind a tunnel or VPN (`tunnel`) | Direct routes and immediate automatic-pool fallback are permitted. | Direct is permitted when no applicable proxy is configured. |

The tunnel or VPN mode assumes you manage that network separately. Without a working
tunnel, destinations can see the server's own address. Select the mode according
to your actual network, not the name of the option.

### Choose a route

| Route | Settings | Boundary |
| --- | --- | --- |
| Automatic MTProxy | Built-in lists or an operator catalog | Maintains a working Telegram route; direct fallback depends on the IP mode |
| Direct | Tunnel or VPN mode | Telethon uses the host's network route |
| SOCKS5 | Host, port, optional username/password | python-socks, remote destination DNS enabled |
| HTTP CONNECT | Host, port, optional username/password | Plain HTTP CONNECT; TLS to the proxy itself is not implemented |
| MTProxy | Host, port, secret | Experimental Telethon transport; 32 hex digits or `dd` + 32 hex digits |

Fake TLS `ee` secrets are rejected. Telethon 1.45's normalization can strip a prefix
and domain, but that does not implement Fake TLS. Paste `tg://proxy?server=…&port=…&secret=…`
or `https://t.me/proxy?server=…&port=…&secret=…` and choose **Fill fields from link**.
This validates and fills the fields without connecting or saving; review and save the
route separately. Manual fields remain available. See [Telegram proxy links](https://core.telegram.org/api/links#proxy-links).

### Public proxies supplied by your installation

The built-in list combines four sources:
[SoliSpirit/mtproto](https://github.com/SoliSpirit/mtproto),
[zakky8/mtproto-proxy-pro](https://github.com/zakky8/mtproto-proxy-pro),
[kort0881/telegram-proxy-collector](https://github.com/kort0881/telegram-proxy-collector)
and [3yed-61/MTP-Collector](https://github.com/3yed-61/MTP-Collector).
The bundled snapshot contains endpoint facts, source attribution and download dates.
Listings are inputs; the connectivity checks below decide which proxies are used.

**Automatic MTProxy** checks Telegram transport connectivity, keeps a working proxy
and switches to another when it fails. Workspaces prefer different proxies when enough
working entries are available; proxies can share an exit address. Failed proxies
rest before another attempt. If none works, the IP mode determines whether collection
must wait or may use a direct connection. Changing proxies does not change the account
or erase its journal. Route choices and changes are recorded in the signed journal.

While automatic routes are active, lists refresh hourly and transport checks run
every ten minutes by default. These intervals are configurable. **Update public lists**
requests a refresh; viewing the list alone does not change a saved manual route.

**Telegram traffic and HTTPS requests use different routes.** List downloads use a
separate HTTPS connection and the supplied external-request route.
`TGWITNESS_PROXY_FEED_PROXY` explicitly overrides that route with an HTTP/SOCKS5 proxy;
both collector Compose variants forward it. The background pool follows the main workspace.
No Telegram session, API credentials, panel token or bot token is sent to feed providers.
Provider names, snapshot dates and the download route appear under **Where the list comes from**.

An MTProxy carries Telegram traffic only. Workspace HTTP operations such as timestamps,
notifications, off-site copies and source checks use a separate SOCKS5/HTTP proxy when
configured, then the account's SOCKS5/HTTP route. Without either, Hide the address refuses the
request; the other modes permit Direct. External requests can be disabled. An explicitly
configured feed-download proxy remains a separate operator override.
The independent witness service keeps its own route.

For operator-managed private services, the existing server environment setting
`TGWITNESS_ALLOW_PRIVATE_DESTINATIONS=1` permits private destinations and keeps
proxy-side hostname resolution. It cannot be enabled from the panel. Public-only
mode rejects `.onion` destinations before querying the public resolver; Tor onion
services require that explicit private-destination setting and a suitable proxy.
This DNS behavior applies to external HTTP operations, not Telegram's transport.
Cloudflare documents the [JSON DNS endpoint](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/).

<details>
<summary><strong>Automatic pool parameters</strong></summary>

Under **Parameters → Automatic MTProxy**, configure the failure threshold, cooldown,
planned rotation, proxy sharing and permitted fallback delay.

| Control | Default |
| --- | --- |
| Disconnects before replacement | 3 within 10 minutes |
| Proxies tried per connection attempt | 3 |
| First / maximum rest after failure | 10 minutes / 6 hours |
| Planned rotation | Disabled; switch on failure |
| Accounts per proxy | 0: prefer separate entries, share when needed. Set 1 to wait for an exclusive entry. |
| Delay before permitted Direct fallback | 10 minutes; Hide the address still refuses Direct |
| Feed refresh / transport checks | 60 / 10 minutes; main workspace values apply to the shared pool |

Different proxies can share an exit address. Telegram's limits apply on every route.

</details>

To replace the public list with your own operator catalog, configure the override below.
It disables external subscriptions entirely, including when its `proxies` array is empty.

Copy [the empty catalog](../deploy/proxies.config.example) to `proxy-config/proxies.json`
and add your deployed public endpoints:

```json
{"format": "tgwitness-proxy-catalog-v1", "proxies": [
  {"id": "project-eu", "label": "Project EU",
   "link": "tg://proxy?server=REPLACE_HOST&port=443&secret=REPLACE_SECRET"}
]}
```

The example values must be replaced. Up to 32 distinct entries are accepted. The
authenticated listing returns labels/hosts/ports without shared secrets; selecting one
saves its credentials into the workspace vault. Availability remains untested until an
explicit transport test. A malformed catalog leaves manual configuration available.

Native launch: set `TGWITNESS_PROXY_CATALOG` to the local JSON path. Docker:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.proxies.yaml up -d --build
```

The overlay mounts `proxy-config` read-only; files must be readable by container UID 10001.
That directory is excluded from Git, Docker build context and source archives. This
catalog configures the collecting accounts; [the witness bot](WITNESS.md) uses its own
HTTP/SOCKS5 route, not MTProxy.

Direct fallback is governed by the IP mode above. Pause observation before
changing a route. Saving disconnects old clients and cancels unfinished login; a
new client uses the saved route. The account's journal/session binding remains.
Settings replace the previous route: re-enter proxy credentials when editing it.

Credentials are encrypted in `network.enc`. The API does not return the username,
password or secret. Signed records contain the route type and whether credentials
are present, excluding the endpoint and secrets. The operator can see the endpoint
in the panel. Secret fields clear after saving, locking or switching workspaces.

**Test Telegram connection**, also available before login, opens and closes a temporary
unauthorized Telegram connection through the route. It does not contact an IP-check
website. Success establishes transport connectivity, not group access, complete
delivery or anonymity.

The proxy applies to the Telegram client's connections, including Telegram DC media
downloads. Browser, pip, SSH and manually invoked TSA tools have separate routes.
The proxy hostname may be resolved locally. `rdns` affects destination hostnames;
Telegram often supplies numeric DC IPs.

SOCKS5 and plain HTTP CONNECT do not themselves encrypt proxy credentials or the
client-to-proxy tunnel. MTProto separately protects Telegram traffic. Use an
appropriate secure channel to the proxy on an untrusted network. Private groups
are cloud chats protected by MTProto in transit; end-to-end Secret Chats are a separate chat
type, recorded by the [Secret Chat module](PSEUDO-SECRET.md).

## Encryption and signatures

| Layer | Implemented | Operator responsibility |
| --- | --- | --- |
| Telegram traffic | Telethon MTProto | Platform trust, route and availability |
| Web panel | Bearer token, loopback default, request limits | HTTPS or SSH tunnel for remote access |
| Secrets | Fernet for API credentials, session, proxy credentials and signing private key | Protect the decryption key and running host |
| Vault key | Local key, or external master key for a new installation | Separate protected storage and key backup |
| Messages and attachments | Plaintext application storage | Encrypted disk/volume |
| ZIP/JSONL/CSV/HTML | Integrity checks, no content encryption | Protect exported copies and transfers |
| Provenance and time | Signed journal, process receipt, RFC 3161 tools | Trusted key, independent checkpoints/TSA and custody procedure |

**Storage protection** in Account shows these states. The panel token is an
access secret, not an encryption password. It grants administrator access;
[issued tokens](ACCESS.md) can be scoped to accounts and chats. Workspaces share
the host process and are not isolated tenants.

BitLocker, LUKS, FileVault or a managed encrypted volume can protect storage under
their respective threat models. An administrator of an unlocked running machine
can still read data. Include SQLite WAL/SHM, media, temporary exports, swap, backups
and browser downloads in storage planning. A Docker volume is not encrypted merely
because it is a volume. TgWitness does not implement SQLCipher or object encryption.

## External master key

For a **new** installation, place the master key outside the data directory.
This does not automatically migrate an existing local-key vault. Prepare a key
directory accessible only to the service identity, then run:

```sh
python -m tgwitness.security create-master-key /private/keys/tgwitness-master.key
export TGWITNESS_VAULT_KEY_FILE=/private/keys/tgwitness-master.key
python -m tgwitness --data-dir /private/observations/new-case
```

PowerShell, using the installed project environment:

```powershell
python -m tgwitness.security create-master-key E:\PrivateKeys\tgwitness-master.key
$env:TGWITNESS_VAULT_KEY_FILE = 'E:\PrivateKeys\tgwitness-master.key'
python -m tgwitness --data-dir E:\PrivateData\new-case
```

In Docker, mount the file read-only outside `/data`, for example at
`/run/secrets/tgwitness-master.key`, and set the environment variable to that path.
The service UID must be able to read it. Pass the path, not the key bytes, through
environment/configuration files.

Each workspace receives a random public salt and its own Fernet key derived through
HKDF-SHA256. `vault.external.json` stores derivation metadata, not the master key.
A missing/wrong key fails startup without silently replacing it. Retain both the
salt metadata and master key for recovery.

All workspaces derive from the same master key; its compromise affects the entire
installation. The running process can decrypt secrets. This is not an HSM or
password KDF. Arbitrary human passwords are not accepted in place of a random key.

Keep the existing key for existing installations until a deliberate migration is
implemented and verified. Deleting `vault.key` or replacing a master key can destroy
access to sessions/signing keys. Keep encrypted backups and keys separately and
test recovery in an isolated instance.
