[TgWitness](../../README.md) / [addons](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-capture-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-capture-static.svg">
  <source media="(max-width: 640px)" srcset="../../docs/assets/presentation/section-capture-mobile.svg">
  <img src="../../docs/assets/presentation/section-capture.svg" width="1200" alt="TgWitness / Independent capture">
</picture>

# Optional independent capture

[Configuration examples](config/README.md) · [Container files](deploy/README.md) ·
[Package source](../../tgwitness_capture/README.md)

For the owned official Telegram Web browser，required video，guarded actions and the GitHub-hosted procedure，see [Official client witness](../../docs/OFFICIAL-WITNESS.md)．That mode uses `compose.official.yaml` and a fresh temporary profile．The generic recorders described below retain their existing behavior．

This preview adds two independently operated recorders. It is a separate Python
package and optional Compose deployment, controlled from **Extras → Independent capture**
or each recorder's standalone English panel. The ordinary application does not start
recorders or receive their signing keys or client sessions. Both recorders start with
capture **disabled**, including after a restart. Video is separately selectable and
off by default. See the [main-panel connection guide](../../docs/OPTIONAL-CAPTURE.md).

[Desktop panel](../../docs/assets/optional-capture.png) · [Mobile panel](../../docs/assets/optional-capture-mobile.png)
(synthetic SQLite fixture, no real account).

| Function | Implemented behavior |
| --- | --- |
| Browser | Attach to an existing Chromium CDP endpoint, manually select one tab, preserve viewport PNG, rendered MHTML and derived text |
| Changes | Poll the selected tab's rendered text and URL; capture changes and periodic states; no claim to observe every DOM, WebSocket or Telegram event |
| AyuGram | Read one configured SQLite database using Online Backup, including visible WAL transactions; preserve complete consistent snapshots and schema fingerprints |
| Video | Optional FFmpeg screen input, silent H.264 segments; sign closed segments while recording; preserve an unfinished tail separately on failure |
| Integrity | SHA-256-linked events signed with Ed25519, content-addressed originals, independently pinned verification, separately retained checkpoints |
| External witness | Separate process, data directory and key; challenge-bound polling with a read-only token; signed receipts, rollback/equal-length-fork checks |
| Export | Signed ZIP, originals, JSONL journal and searchable HTML report; offline CLI verifier; no dependency on a running collector |

Database snapshots do **not** yet interpret the AyuGram message schema or reconstruct
a complete account history. AyuGram itself must already be configured to retain
edits/deletions. The actual installed client's version and schema need validation.
The recorder does not install or log in to AyuGram. The GUI and network route of that
client remain operator managed; the supplied AyuGram profile starts only its recorder.

## Local installation

Use a dedicated Python 3.11+ environment. From the repository root:

```sh
python -m venv .venv-capture
# Activate .venv-capture using your shell's usual activation command.
python -m pip install --require-hashes -r deploy/build.lock
python -m pip install --require-hashes -r addons/capture/requirements.lock
python -m pip install --no-deps --no-build-isolation ./addons/capture
```

The lock is a subset of the project's reviewed browser lock. Regenerate it with
`python addons/capture/lock_from_project.py` after updating that lock and inspect
dependency closure when changing the package requirements. No browser download is
needed to attach to a separately installed Chromium. FFmpeg is needed only for video.

Copy the relevant example configuration into a private directory and adjust it:

```sh
python -m tgwitness_capture serve --data data/browser-recorder --config /private/browser.json --port 8791
python -m tgwitness_capture serve --data data/ayugram-recorder --config /private/ayugram.json --port 8792
```

Use distinct data directories, profiles, sessions, keys and routes. Two containers
on the same host still share the kernel and administrator; separate VMs or hosts
provide stronger separation. Two sessions of one Telegram account still depend on
the same account. Compare the records with their acquisition routes, retained
checkpoints and the environment checks available for each recorder.

For a local browser adapter, launch a **separate profile** with
`--remote-debugging-port=9222 --user-data-dir=/private/capture-browser-profile` and
configure `browser_cdp_url` for that endpoint. Keep CDP on loopback or a private
namespace: it grants control over the logged-in browser. Do not expose port 9222.
Configure the browser's separate proxy before login; the local launcher does not
automatically create a WARP tunnel or enforce your host firewall.

For AyuGram, set `ayugram_db` to its actual `ayudata.db` and supply `client_version`.
The source database is opened read-only. A live WAL database needs its WAL and SHM
files readable too. Do not use `immutable=1` to bypass WAL. A failed backup is recorded
as a failure; the adapter never migrates the source or copies an incomplete `.db`
and pretends it is complete. Do not point it at a Telegram authorization database.

## Controls and login

Open `http://127.0.0.1:8791` or `:8792`, then enter that recorder's
`control-token.txt`. The browser holds this token in memory only. The token identifies
a shared control capability, not an individually authenticated human; the configured
operator label is self-reported. `witness-token.txt` can only read checkpoints.

1. Leave capture off while entering phone numbers, codes, passwords or scanning QR.
2. Finish login in the independently operated source client.
3. In the browser recorder, find the tabs and explicitly select the target tab.
4. Select pages/screenshots or database snapshots and start capture.
5. Enable video only for a chosen procedure. Pause **before** further login activity.
6. Pause, retain a checkpoint independently, then export a fixed journal boundary.

Closing the panel does not stop capture. Every service restart returns to disabled;
the previous unclean shutdown and retained pending files are identified at startup.
Pausing waits for in-flight work. The journal contains settings, capture failures and
heartbeats; a heartbeat alone does not mean a new page was successfully preserved.
There is no operator keystroke logger or automatic secret redaction. An enabled
capture can include visible secrets, so input credentials only during a pause.

### Open an address in isolation

`POST /api/open` with `{"url": "https://…", "wait_seconds": 5, "purpose": "…"}` opens the
address in a new tab of the recorder's own browser, waits, and saves a viewport PNG,
rendered MHTML and text. The signed `capture.opened` event also records the final URL,
HTTP status, server address and TLS issuer as the browser reported them. A preceding
`capture.open_requested` event and, on failure, `capture.failed` keep the attempt visible.
Only `http` and `https` addresses without credentials are accepted. This does not need
capture to be enabled and does not change the selected tab. `GET /api/object/SHA256`
returns a stored artifact by its hash.

Pages opened this way see the recorder's network route and browser profile, never the
observing Telegram account. A Telegram Web address shows what that browser profile is
logged in to; prepare it during a pause like any other login. In the main panel the
documentation drawer offers this as **Open in isolation**; the panel accepts the result
only if the pinned recorder signed it after the latest verified checkpoint.

Behind HTTPS set `public_origin` to the exact external origin, e.g.
`https://browser-capture.example.org`. Keep the backend private. Cross-origin control
requests are refused; the server does not trust arbitrary forwarded headers.

## Optional Docker profiles

The standalone [Compose file](compose.yaml) is never included in the main
`compose.yaml`. No service starts without an explicit profile. Run commands from
the repository root with `--project-directory .`.

For the browser profile, set separate `CAPTURE_NEKO_PASSWORD` and
`CAPTURE_NEKO_ADMIN_PASSWORD` values of at least 16 characters. Copy
[upstream-proxy.example.conf](deploy/upstream-proxy.example.conf) outside the checkout,
replace the upstream proxy host/port and set `CAPTURE_PROXY_CONFIG` to its absolute
path. The example deliberately has an invalid upstream and disallows direct fallback.
Do not commit proxy credentials. Set `CAPTURE_NEKO_IMAGE` to a reviewed image digest
before relying on reproducible deployment; the preview defaults to a mutable tag.

```sh
docker compose --project-directory . -f addons/capture/compose.yaml --profile capture-browser up -d --build
docker compose --project-directory . -f addons/capture/compose.yaml exec browser-recorder cat /data/control-token.txt
```

Neko is on local port 8081; the recorder is on 8791. Chromium uses an internal Docker
network and a dedicated Squid forwarder with `never_direct allow all`. Only that
forwarder has an egress network. CDP remains inside the browser network namespace;
the recorder shares that namespace but not the browser profile or signing-key volume.
The original profile is mounted only into the browser, and the signing key only into
the recorder. Neko's upstream Chromium configuration uses `--no-sandbox`; this preview
retains that requirement. Use a dedicated VM for untrusted browsing and validate the
deployed isolation before treating it as a security boundary.

The GUI's WebRTC transport is distinct from the browser's target-site proxy. Local
bindings are the default. Remote access needs HTTPS and a deliberately configured
WebRTC/NAT or fallback transport; an HTTP tunnel alone does not establish UDP media.
The X11 recording adapter assumes display `:99.0` and 1280×720; adjust `video_input_args`
if the pinned Neko image differs. No X11 socket is mounted from the host desktop.
Video is silent; this version does not promise audio or a complete frame-by-frame
record of actions. The alternative Neko Broadcast ingestion is not implemented here.

For an already running, separately logged-in AyuGram client, set
`CAPTURE_AYUGRAM_DB_DIRECTORY` to the directory containing its database and live
sidecars, readable by container UID 10001. Set `CAPTURE_AYUGRAM_CONFIG` for a custom
database name or client version. Avoid mounting more authorization files than needed.

```sh
docker compose --project-directory . -f addons/capture/compose.yaml --profile capture-ayugram up -d --build
docker compose --project-directory . -f addons/capture/compose.yaml exec ayugram-recorder cat /data/control-token.txt
```

That recorder listens on local port 8792 and has its own volume and internal network.
Its source client's proxy/WARP route is separate from the browser gateway and must be
configured and tested on that client. The observer records the supplied route label;
it does not attest that the client actually used it. Stop profiles independently with
the same Compose command and `stop`; retain the named volumes.

## Independent verification and witness

Keep the SHA-256 fingerprint of each recorder key outside its export. Check the ZIP
using a trusted installation of this package, without running any web server:

```sh
python -m tgwitness_capture verify capture-browser.zip --fingerprint TRUSTED_SHA256 --checkpoint retained-checkpoint.json
```

Without a supplied fingerprint, `key_pinned` is false even when the embedded signature
is internally valid. A local checkpoint is not an independent timestamp. A shorter
valid prefix is detected only if the verifier has a retained boundary beyond it.
`--require-final-anchor` rejects any exported events after the supplied boundary.
For the exact final boundary, pause, fetch the checkpoint, and export without another
control action. The subsequent `export.created` event lies outside that export.

On a separate machine, retain challenge-bound checkpoints every minute:

```sh
python -m tgwitness_capture witness --data data/browser-witness --url https://browser-capture.example.org --token-file /private/browser-witness-token.txt --fingerprint TRUSTED_RECORDER_SHA256
python -m tgwitness_capture verify capture-browser.zip --fingerprint TRUSTED_RECORDER_SHA256 --receipt independently-retained-receipt.json --witness-fingerprint TRUSTED_WITNESS_SHA256
```

Remote witness connections require HTTPS and never follow redirects with credentials.
`--once` performs one observation. Keep witness keys and receipts independently;
running the witness on the same host/operator does not create organizational
independence. The witness checks fresh heads, rollback and equal-length conflicts;
without intermediate records it cannot prove that every longer head extends the last
one. The ZIP verifier checks an included receipt against the actual journal prefix.
Witness times are local clock assertions, not RFC 3161 tokens. A dedicated RFC 3161
integration is not included in this preview.

## Storage, reports and limits

Artifacts are immutable objects named by SHA-256; repeated bytes have one stored
object but retain separate observation events. The journal commits with SQLite WAL
and FULL synchronization after artifact fsync. Interrupted video tails stay in
`pending/` and are never silently signed as complete. Preserve pending data for
recovery; it is not included as verified material in a normal export.

An export contains only referenced artifacts, a signed manifest, `events.jsonl` and
`report.html`. It never copies the recorder directory, keys, tokens or browser profile.
Captured pages and the configured AyuGram database can themselves contain sensitive
content. Work with copies and inspect material before sharing it. This version has
no automatic retention deletion and does not redact signed originals.

Extract a verified ZIP, then open `report.html`. It offers event search, original PNG
previews, metadata and links to originals. HTML/MHTML is downloaded, not executed by
the authenticated panel. Printing the HTML produces an **unsigned derivative PDF**;
there is no native signed-PDF export in this add-on. WACZ, ArchiveWeb.page live
resource signing, rrweb playback and automatic import into TgWitness are not part of
this preview. Original signed packages can be independently retained and reviewed.

Default limits: 512 MiB per artifact, 8 GiB per verified archive, 100,000 archive
members, 2 MiB per journal event. Oversize files fail explicitly. Frequent PNGs may
cost more storage than compressed video; measure with your sources. Polling and
periodic backups can miss transient states and do not reconstruct unobserved history.

## Validation

Capture regressions are maintained in the private validation workspace.

Real Chromium tests use only a localhost synthetic page. Video tests use FFmpeg's
synthetic source; set `CAPTURE_TEST_FFMPEG` to an installed executable if needed.
Tests cover signatures, changed/missing materials, truncated-prefix anchoring,
WAL snapshots, controls, authentication, independent keys, restart defaults and
closed video segments. They do not qualify a real Telegram account or AyuGram release.
The Docker/Neko/proxy stack requires a Linux acceptance run: verify manual login,
capture after viewers disconnect, proxy failure with no direct target access,
X11 permissions, restarts and disk-full behavior before production use.
