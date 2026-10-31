# Architecture

One Python process hosts the FastAPI panel and any number of isolated workspaces,
each with a Telethon user-account client.
SQLite holds an append-only signed event journal and mutable operational settings.
An encrypted vault holds API credentials, the StringSession, and signing key.
The frontend is plain bundled HTML/CSS/JavaScript: no Node build, CDNs, or runtime
frontend downloads are needed.

| Module | Responsibility |
| --- | --- |
| collector.py | Authorization, dialog selection, updates, snapshots, media queue, connection monitoring |
| interactions.py / telegram_client.py | Explicit panel actions, signed receipts, persistent request IDs and task-local callback/join retry policy |
| message_content.py | Observable message comparison, excluding transport access metadata |
| workers.py | Wait for export file workers before cancellation cleanup |
| store.py | WAL transactions, ordered event chain, query filters, operational settings |
| security.py | Private-file creation, encrypted vault, Ed25519 signing, single-process lock |
| evidence.py | Complete-journal export, derivatives, checkpoints, attachment verification |
| verify.py | Standalone, read-only verifier (stdlib + cryptography): archives, coverage, witness journals and channel posts, profile files |
| app.py | Authenticated API, lifecycle, request validation, static panel |
| profiles.py | Multiple account collectors, shared access controller, per-workspace lifecycle |
| access.py | Scoped grants, permission checks, IP restrictions, session limits and administrator console |
| proxy_catalog.py | Public feed snapshots, transport checks, shared proxy pool and health-based selection |
| provenance.py | Signed acquisition-run identity, code and dependency measurements |
| network.py | Validated per-workspace routes; redacted status and evidence; Telethon transport options |
| sessions.py | Offline read-only conversion of reviewed Telethon SQLite schemas |
| account_import.py | In-memory detection and normalization of supported account files and JSON |
| tdata.py | Bounded modern TData ZIP reader, checksum/decryption validation, no extraction |
| doctor.py | Local readiness checks without collection, login or package installation |
| download.py | Authenticated streaming export download with bounded reads and no overwrites |
| monitoring.py | Validated per-workspace event policy and per-type attachment rules, shared by handlers, status and signed receipts |
| scope.py | Observation scope (chosen chats, Telegram folder, whole account), source types, exclusions, recheck tiers |
| dossier.py | People profiles per chat built from saved records: facts with record references, avatar SHA-256/pHash, mention extraction |
| witness_api.py | Read-only witness tokens and the signed journal head they may fetch |
| witness.py | Independent witness process: own key and journal, head checks, signed channel posts, export |
| alerts.py | Apprise notifications and the panel's notification list |
| logging_config.py | Console logging and rotating server diagnostics for windowless launches |
| static/ | Responsive interface, local access gate, filters, details, exports, account setup |
| demo.py | Clearly labeled synthetic journal, isolated from real collection |

Observation handlers are registered before connecting. Live collection is gated by
the active client identity, explicit running state, enabled sources or the observation
scope (folder or whole-account modes add a new chat as a source on its first update), and event
policy. Rejected and superseded clients cannot contribute live updates. Raw reactions and membership updates
preserve visibility limits. Incoming message content and its durable media job are
committed together. Jobs preserve the original TL descriptor and bind its hash to
the signed message observation. Sender/editor/deleter semantics are separated.

Each workspace accepts one account and has its own directory and signing identity.
The main workspace remains at the root for compatibility; additional workspaces live in
profiles/<id>/. One bearer token controls the whole installation; workspaces are not
separate authorization tenants. Process locks protect directories; database locks
serialize event insertion. Each append commits synchronously
to SQLite WAL with FULL synchronous mode. Event update/delete triggers prevent
ordinary application edits; filesystem administrators remain inside the trust boundary.

API authorization is a bearer token. Login operations are serialized and time-bounded.
Account uploads use a dedicated 12 MiB encoded-body limit and an 8 MiB decoded-file
limit; normal API requests retain the 16 KiB limit. Conversion runs in a worker
thread, keeps uploads in memory, and returns normalized input to the authenticated
browser. QR login has a per-workspace candidate, short-lived identifier, waiter task,
and explicit cancellation. Only accepted authorization becomes the active client.
Telegram FloodWait is returned with a Retry-After value; credentials and raw RPC
error messages are not exposed in API errors. Exports run outside the async event
loop and are serialized per workspace. They stream a stable read snapshot, and can
coexist with continuing WAL writes. Workspace collectors share the process/event loop.

Current history snapshots and live updates can overlap. Both are separate observations,
labeled by source; duplicates are not silently collapsed. No inference from missing
IDs, fabricated deleted text, forced member enumeration, or automatic group joining
is implemented.

For the operator-facing explanation, see [how collection works](COLLECTION.md)
and [accounts and session formats](ACCOUNTS.md).

Network configuration lives in the encrypted vault. Applying a route closes old
clients and cancels unfinished login; later connections use that route with no
direct fallback. A new external-key installation derives each workspace's Fernet key
with HKDF-SHA256 from a master key file and a stored random salt. This protects
secrets separately from the data directory, not plaintext journal/media contents.

Local demo entry uses a separately generated process capability, never the configured
panel token. Issuance and acceptance require explicit demo mode, a synthetic root
without additional workspaces or an authorized session, loopback peer/Host, no proxy
forwarding headers, and no cross-origin browser request. Live APIs retain bearer
authentication and reject collection changes in demo mode.
