# Security and data handling

This page describes access，storage and network protection in a local or server workspace．
For collection on a GitHub runner or in an Intel TDX confidential VM，see the
[verification modes](EVIDENCE.md#verification-scope)，which add checks of the collection environment．
Account connections，notifications，timestamps，off-site copies and witnesses have their own routing settings．

| Area | In short |
| --- | --- |
| Access | Administrator key plus scoped access to accounts/chats, seven permissions and revocable sessions; localhost by default |
| Secrets at rest | Session, API pair, signing key and proxy settings are encrypted with Fernet |
| Messages and media | Stored unencrypted: use disk encryption and strict permissions |
| Integrity | SHA-256 hash chain and an Ed25519 signature on every record |
| Local trust boundary | The host administrator controls the workspace and its signing key；independent checkpoints retain an earlier journal boundary |

For vulnerability reports, see the [security policy](../.github/SECURITY.md).

## Access model

The main panel token grants full control. Other people can receive their own
[scoped access](ACCESS.md): chosen workspaces and chats, permissions, expiry,
IP restrictions, sign-in limits and revocable sessions. A chat-limited access
cannot perform whole-workspace operations even if their permission is ticked.
Workspaces share a process and do not isolate data from the host administrator.

The panel listens on localhost by default. Browser sign-in exchanges an access
token for a session credential; the browser sends it as a bearer token. It is kept
in sessionStorage rather than an authentication cookie. Lock/sign-out clears the
browser session. Closing a browser or ending a session does not stop collection.

Issued tokens and session credentials are kept as hashes in the encrypted vault.
Revocation ends the associated sessions; permission changes affect subsequent
requests. Downloaded files cannot be recalled. The administrator can limit their
own browser sessions too, but scripts using the main panel token directly retain
full access and bypass those browser-session limits.

Failed authentication is rate-limited by client address. IP restrictions use the
address seen by the application; check reverse-proxy behavior before relying on
it. Witness credentials remain separate read-only checkpoint/health credentials.

### Demo access

`/api/demo-access` is a deliberately unauthenticated bootstrap for an explicitly
started, isolated synthetic demo. It issues a separate process-lifetime capability,
never the real panel token or a TGWITNESS_TOKEN override. Issuance and use require a
loopback peer and Host, no forwarded headers, and no cross-origin request. Additional
workspaces or an authorized session disable this path. Live workspaces never issue
the capability. The demo cannot connect accounts or change collection settings.

## Panel content and exports

The panel uses no external fonts, analytics, CDN resources, or embedded remote media.
Telegram-sourced text is inserted as text, not HTML. Downloaded attachments are
served as binary attachments. JSONL exports preserve original strings; HTML escapes
them; CSV cells that could become formulas are prefixed with an apostrophe.

Exports exclude authentication and signing secrets, but deliberately contain
collected source metadata, identifiers, and possibly personal or sensitive content.
Telegram access hashes and file references can occur in raw source metadata.

## Secrets at rest

Telegram API credentials，the session and signing key are encrypted with Fernet．
For local messages and media，encryption is provided by the host's disk or volume；
the workspace stores ordinary files．Exports can use a password-protected AES-256 ZIP，
and off-site copies use AES-256-GCM．

The vault key defaults to the protected data directory．Use an external master-key file
below to store it separately．On Unix，new private-key files use mode 0600 and new data
directories use 0700；on Windows，set the directory ACL for the service account and
authorized administrators．Existing directory permissions are retained．

### External master key

For a new data directory, TGWITNESS_VAULT_KEY_FILE can supply an external random
master key. HKDF-SHA256 and a separate random salt derive a different Fernet key
for each workspace. vault.external.json must be retained for recovery. Missing or
wrong master keys fail closed. Existing local vaults are not silently migrated.
The panel displays the selected key-storage mode．Disk encryption protects the local
message and media files in either mode；see
[connection and data protection](CONNECTION-SECURITY.md) for setup details．

## Proxies and network routes

Proxy configuration is encrypted in the vault. Passwords and MTProxy secrets are
not returned by the API or written to evidence records. Each workspace chooses
its Telegram route and an [IP mode](CONNECTION-SECURITY.md#ip-modes).

**Hide the address** refuses direct Telegram fallback and requires a proxy for external
HTTP requests. The explicitly selected fallback mode permits direct Telegram
access after its delay; tunnel/VPN mode permits direct routes. Choosing tunnel
mode does not install or verify a VPN. These settings do not control all machine
traffic, browsers, package managers or local proxy-host DNS resolution.

MTProxy carries Telegram traffic only. External requests can use a separate
SOCKS5/HTTP proxy, the workspace's SOCKS5/HTTP route, or an allowed direct route;
they can also be disabled. The independent witness has its own transport settings.
Ordinary SOCKS5/HTTP CONNECT authentication is not encrypted by those proxy
protocols themselves. Fake TLS MTProxy secrets remain unsupported.

## Sign-in and session imports

Converted .tgwitness-session files contain a plaintext authorization secret until
loaded and stored in the vault. The offline CLI accepts reviewed Telethon schemas.
Panel import additionally accepts Pyrogram SQLite, modern single-account TData ZIP,
and documented JSON inputs. It is authenticated, limited to four files / 8 MiB,
and processes uploads in memory without archive extraction or saving original files.
Normalized credentials are returned only to the requesting authenticated browser;
they are saved in the encrypted vault after successful Telegram authorization.
Protect originals and converted files, and avoid concurrent clients cloning an authorization.

TData processing verifies container checksums, local decryption hashes, and structure
lengths. A supplied Desktop local passcode is used transiently and is not stored.
This bounded parser does not establish that every Desktop version is compatible.
QR images are generated locally, contain short-lived Telegram login tokens, and
are never sent to an external rendering service. Lock, workspace switch, new login,
and route changes cancel pending QR attempts. Reload/closing a tab may leave an
attempt pending until expiry. A successful QR login still enforces account binding.
Ordinary API bodies remain limited to 16 KiB; the authenticated import route accepts
up to 12 MiB of encoded JSON, enforcing the smaller decoded-file limit separately.

Login codes and Telegram two-step verification passwords are not persisted. Phone number/code-hash state is
held in memory during authorization. Telegram sessions grant account access; never
upload a data directory, session, token, vault key, or private signing key to GitHub.

## Logs and transport

The default API validation response is replaced so it does not echo credential
values. Application access logging is disabled. Do not configure a reverse proxy
to log Authorization headers or request bodies. HTTP carries tokens and login
secrets in plaintext: use HTTPS or an SSH tunnel whenever leaving localhost.

## Integrity limits

Local verification checks record signatures，the hash chain，attachments and the export manifest．
The administrator holds the local signing key and can create another signed journal；
an independently retained checkpoint detects replacement of the prefix it covers．
Keep the key fingerprint and checkpoints with the recipient or an independent witness．

For independently checked collection，choose [GitHub Actions capture](SEALED-ACTIONS.md)
or [Intel TDX deployment](HIGH-ASSURANCE.md#confidential-vm-on-phala-cloud-intel-tdx)．
Their verifiers check workflow provenance or hardware measurements in addition to archive integrity．
Optional timestamps and encrypted off-site copies provide time anchors and recoverable copies；
the [evidence format](EVIDENCE.md#verification-scope) describes the checks for each mode．

## If you suspect a problem

Preserve the original data directory and use a separate copy for analysis．
Report the affected version，operation and reproducible steps through the
[security policy](../.github/SECURITY.md)，keeping account data and credentials private．
