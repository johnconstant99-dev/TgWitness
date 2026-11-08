# System map

Open **Workspace → System map** to inspect the current installation. The page is
available to the main administrator. It refreshes every five seconds while visible;
hidden tabs pause reads. Failed reads retain the last snapshot with a stale indicator.

The main canvas connects panel access, the collector environment, individual account
routes and their Telegram targets. External HTTP requests have a separate branch to
GitHub, S3 and time services. The vault, signed journal and independent witness form
the evidence path below the accounts. Select a node to open its details without leaving
the map. Overview, Telegram, Evidence and External services focus the relevant paths.

Drag to pan, use the zoom controls or expand the map. On narrow screens the initial
view centers the collector at a readable scale; the percentage control fits the whole
map. Account search and pagination keep larger installations usable. The lower tabs
contain network observations, actual port bindings, key locations and available layers.

Select an account to follow its configured route, connected socket, Telegram session
target and external-request policy. The proxy pool includes the last observed healthy
and cooldown counts. Source ports come from the socket; the page does not allocate
ports or change routes. The connection-settings button opens the selected account.

The host boundary contains this application process and its workspaces. A container
marker identifies the current container environment, not a Docker inventory. Computer
and server choices reflect saved setup preferences. Cloudflare configuration comes
from the recorded deployment, and does not establish current tunnel health. A missing
observation is labelled explicitly. The map does not assert host-wide Telegram-only
egress, kernel enforcement or zero traffic leakage without telemetry for those checks.

## Storage and independent records

The storage view distinguishes encrypted credentials and signing-key files from the
signed journal and media, which are not encrypted by the application. It shows whether
the vault key is local or derived from an external master key. Keys themselves are never
returned. Addresses and directory paths are hidden in the interface until requested.

Service cards reflect the selected account, or all accounts when none is selected.
They include timestamps, encrypted S3 replication, media storage, independent witnesses,
drand rounds, Cloudflare Gateway DNS records, Telegram session records, proxy lists,
source verification, notifications, the operator bot, webhooks, archive
analysis and separately configured recorders. Available but disabled services remain
visible. Configuration, observed delivery, stale or failed health and startup attestation
records are distinct. A witness poll is an incoming checkpoint read; it is not proof
that the witness retained or independently verified that checkpoint.

## Network observations

The application maintains a bounded diagnostic buffer of up to 2,000 observations.
The page displays the latest 200, with timestamps, component attribution, destination
host and port, purpose and observation type. Related socket attempts and HTTP results
link back to their application request. The visible filtered window can be downloaded.

- The application HTTP client records request starts, responses, HTTP status and
  failures. Proxy-list downloads, DNS-over-HTTPS, timestamp requests, S3 operations
  and other calls through this client use the same observation boundary.
- Python audit events record socket connection attempts, DNS lookup requests,
  UDP send attempts and standard-library HTTP sends. An attempt does not establish
  a successful connection or delivery. Standard-library HTTP response status is not
  captured by that audit event.
- Purpose is attributed from the originating application component. Workspace identity
  is included only when available; shared or unattributed activity stays visible.
- MTProto route pulses reflect changes in existing RPC counters or update timestamps.
  They do not represent individual packets, bytes, bandwidth or all Telegram retries.
- URL paths, queries, credentials, headers and bodies are excluded. Destinations may
  still contain private hostnames or addresses; this is administrator-only information.

The buffer starts when the observer attaches to this application process. It is not
persisted or signed, and resets with the process. It does not observe other processes,
containers, cloudflared, VPN helpers, rclone traffic, OS resolver internals or host
firewall decisions. Those components require separate telemetry. Missing records are
not evidence of absent network traffic. The page does not contact configured services
to refresh its status, start a recorder or change network policy.

The website example uses a fixed synthetic snapshot, labelled as a demo. Its values
are not measurements of an installed system. Animation illustrates direction in that
example; the live page pulses only when its observed activity changes. Motion can be
paused and respects reduced-motion preferences.
