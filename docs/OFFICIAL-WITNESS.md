[TgWitness](../README.md) / [Documentation](README.md) · [Independent capture](OPTIONAL-CAPTURE.md)

![Independent capture](assets/presentation/chapter-capture.svg)

# Official client witness

The official-client preview owns a fresh Chromium browser running [Telegram Web A](https://web.telegram.org/a/). It offers a passive view or sequential scrolling, records the visible procedure with FFmpeg, and signs rendered observations and video segments. The collector makes no Telegram API calls of its own and imports no Telegram session. The official client still uses Telegram's own protocol internally.

| Mode | What it preserves | Scope |
| --- | --- | --- |
| Official Web, passive | Visible messages, screenshots, rendered pages, silent video | One selected visible chat, with manual bounded scrolling |
| Official Web, paced | The same evidence, with sequential scrolling and variable pauses | One selected visible chat, bounded by time, steps and storage |
| API account export | Structured account history and selected attachments | Takeout or regular API, selected chats or the whole visible account |
| Trusted Live local | Official Desktop chat JSON, video and frame-linked operator annotations | Separate local preview, manual setup, without the GitHub attestation of this Web mode |

Official Web observation does not replace a complete Desktop account export. Choose the existing [account export](ACCOUNT-EXPORT.md) when completeness across selected chats is required. For manually operated Desktop collection, see [Trusted Live](TRUSTED-LIVE.md), which preserves a single-chat JSON export and has a different trust boundary. This Web mode does not expose arbitrary clicking, typing, profile visits, media downloads or Telegram Desktop automation. Only currently rendered fields are extracted, missing fields remain unavailable, and disappearing DOM elements are not reported as message deletions.

<details>
<summary>On this page</summary>

- [Run through GitHub Actions](#run-through-github-actions)
- [Local Linux deployment](#local-linux-deployment)
- [Network and account behavior](#network-and-account-behavior)
- [Evidence and limits](#evidence-and-limits)
- [Validation](#validation)

</details>

## Run through GitHub Actions

1. Open the [capture helper](https://phishdestroy.github.io/TgWitness/sealed.html), save the recipient key and enable Actions in your fork.
2. Run **Sealed chat capture** with `client=official_web`, your public `recipient` and the session duration.
3. Choose `official_egress=proxy`（the default）and supply `official_proxy` as `http://host:port` or `socks5://host:port`, without credentials. For authentication, create repository Actions secrets `OFFICIAL_PROXY_USERNAME` and `OFFICIAL_PROXY_PASSWORD`. Alternatively, explicitly choose `official_egress=direct` and leave `official_proxy` empty to use the runner's public IP. Direct mode needs no proxy or WARP, exposes the runner address to Telegram, and is labelled in the panel, signed settings and verification report. An optional `official_expected_ip` requires that observed exit address in either mode. The route cannot change during collection.
4. Decrypt `connection.tgwsealed` in the helper and open the temporary panel. Choose passive or paced observation, then open the official client. Scan the QR code using your trusted Telegram device; enter a two-step password only if the official login form requests it. Phone-code entry is not provided in this preview.
5. Read the visible chat list and select a chat. Download **expected settings** before recording and retain that file independently. The source cannot be changed after recording starts.
6. Start recording, then pause or finish from the panel. Finish seals the video before attempting the official logout flow. If logout cannot be confirmed, revoke this temporary session from Telegram **Settings → Devices** on your trusted device.
7. Download and decrypt `sealed-result`. Verify with an independently trusted installation and GitHub CLI：

```sh
python -m tgwitness.sealed_verify evidence.zip --bundle attestation.jsonl --repo OWNER/TgWitness --expected-selection official-settings.json --confirm-drand
```

The approved workflow starts a fresh browser and signing key on a GitHub-hosted runner, closes the collector before attestation, and encrypts the result to the recipient. A modified workflow or unapproved collector revision does not satisfy the verifier policy. GitHub and the official Telegram website remain trusted, this is not a TEE. The observer can select the source and timing, so independent expected settings and review of coverage remain necessary.

## Local Linux deployment

Install Docker Compose and use a host that permits Chromium user namespaces. The recorder runs without host administration capabilities and with Chromium sandboxing enabled. The supplied seccomp profile permits the nested namespace sandbox to perform `chroot`. Do not disable Chromium sandboxing to bypass a host configuration error.

Copy [the recorder configuration](../addons/capture/config/official.example.json) and [the upstream configuration](../addons/capture/config/official-upstream.example.json) into a private directory. Set the real upstream address and, if needed, its credentials in the upstream file, which is mounted only into the proxy bridge. Use mode `0600` for secret files. Set `OFFICIAL_CAPTURE_CONFIG` and `OFFICIAL_UPSTREAM_CONFIG` to those paths, then run from the repository root：

```sh
docker compose --project-directory . -f addons/capture/compose.official.yaml --profile official up --build -d
docker compose --project-directory . -f addons/capture/compose.official.yaml --profile official exec official-recorder cat /data/control-token.txt
```

Open `http://127.0.0.1:8794` and enter the token locally. Do not paste it into an issue or chat. Capture starts disabled. The browser profile exists only in temporary container storage, the persistent volume contains evidence and recorder keys. Use a different Compose project name and private upstream configuration for each account, for example the Compose option `-p case-one`. A local administrator can still alter the environment, so local signatures alone do not prove operator independence.

The main application's **Extras → Independent capture** can connect to this recorder as a browser recorder. Once its pinned identity is checked, the panel links to the official-client controls and hides incompatible generic browser settings.

## Network and account behavior

In the default proxy mode, the recorder has only an internal Docker network. A separate CONNECT bridge sends requests through exactly one configured HTTP or SOCKS5 upstream, including authenticated SOCKS5 through the bridge. It does not connect directly when the upstream fails. Explicit direct mode instead gives the browser a normal outbound Docker network and records `explicit-direct` in the signed procedure; it provides no IP hiding or Cloudflare network assurance. Both modes reject an unavailable exit check, an initial address mismatch or an observed address change, and check again approximately every thirty seconds. This probe does not prove the path of every packet. A supplied upstream itself must enforce any promised Cloudflare routing or dedicated address. Separate GitHub runs can have different public IPs.

An ordinary Cloudflare Tunnel or Quick Tunnel is panel ingress, not a WARP exit. Shared WARP does not promise a fixed public IP; [dedicated Cloudflare egress addresses](https://developers.cloudflare.com/cloudflare-one/traffic-controls/egress-policies/dedicated-egress-ips/) require the corresponding Enterprise feature. This preview does not automatically provision a Cloudflare WARP connector, Gateway DNS policy or an independently verified network witness, and its report keeps Cloudflare assurance `INCOMPLETE`. Do not interpret a configured proxy label as that verification.

Official Web still opens a new Telegram session and may emit read receipts or online status. Variable pauses and sequential actions do not guarantee an unrestricted account or undetectable automation. The guard blocks composer input, reactions, bot buttons, context menus and arbitrary control requests, and stops on unexpected dialogs, origin changes or loss of authorization. The client itself and the host remain within the stated trust boundary.

## Evidence and limits

Recording starts after login and source selection. Screenshots, MHTML, derived visible text and rendered message metadata are hashed into the signed journal. FFmpeg closes roughly ten-second silent H. 264 segments, which are signed as they become available. The verifier rejects missing or reordered segments and marks interrupted or unclean endings as incomplete. No account password, login code or QR screenshot is deliberately exported. If authorization reappears, a guard cover stops observation, but this is not a claim about every possible future Telegram UI layout.

The video overlay includes the recorder's UTC clock. By default, the recorder also fetches the pinned public drand chain through the same proxy, records fresh rounds and displays the round number. A failed or stale beacon stops observation.`--confirm-drand` queries the public relay independently; offline signature verification alone leaves this check incomplete. Drand supplies a not-before bound, not proof that a session ran continuously or was recorded at a claimed upper time. For an independently retained upper bound, use the [separate checkpoint witness](../addons/capture/README.md#independent-verification-and-witness) or the outer GitHub attestation, within their respective trust limits.

For a local ZIP, verify the independently retained recorder identity and expected settings：

```sh
python -m tgwitness_capture verify official-evidence.zip --fingerprint RECORDER_SHA256 --expected-settings official-settings.json --confirm-drand
```

The report lists procedure completion, environment attestation and Cloudflare verification separately. `--require-complete` rejects a visual session as a full-account export. Video records the observed process, signed files detect later changes, and the acquisition record identifies the captured material and observation intervals.

## Validation

Automated acceptance exercises a real sandboxed Chromium, the guarded panel at desktop and mobile sizes, proxy failures, source/settings mismatch, signed archive verification and interrupted video. Linux CI additionally runs the actual isolated Docker image with Xvfb and FFmpeg, checks denied direct IPv4 and IPv6 connections, and verifies the recorded segments. The Telegram public QR page and the official Web A source were inspected for selector compatibility. These tests use synthetic authenticated chat fixtures, they do not certify an authenticated live-account run or future compatibility with every Telegram UI change.
