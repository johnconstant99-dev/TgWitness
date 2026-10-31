<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/wiki-proxies-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/wiki-proxies-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/wiki-proxies-mobile.svg">
  <img src="../assets/presentation/wiki-proxies.svg" width="1200" alt="Choose the connection. Set the route before connecting your account.">
</picture>

# Proxies and connection routes

**01 · CONNECT AND CAPTURE** · [All guides](Home.md) · [Get help](../../.github/SUPPORT.md)

<details>
<summary>On this page</summary>

- [Choose a route](#choose-a-route)
- [Save and test](#save-and-test)
- [Public lists](#public-lists)
- [Pool dashboard and custom sources](#pool-dashboard-and-custom-sources)
- [Other network traffic](#other-network-traffic)

</details>



Each account workspace has its own Telegram route. Its IP mode determines when it may use the host's direct network connection.

## Choose a route

Open **Account → Settings → Connection settings → Change connection route**.

| IP mode | When a proxy is unavailable |
| --- | --- |
| Hide IP | Wait for a working proxy; no direct Telegram fallback |
| Allow fallback | Permit Direct after the configured delay; return to a proxy when one works |
| Tunnel / VPN | Permit Direct through the host network; this option does not install or verify a VPN |

New workspaces use automatic MTProxy with Hide IP behavior. The pool checks entries,
retains working routes and moves accounts away from failing proxies.

| Route | Inputs |
| --- | --- |
| Automatic MTProxy | Public lists or an operator catalog |
| Direct | No proxy; requires tunnel/VPN mode |
| SOCKS5 / HTTP CONNECT | Host, port and optional username/password |
| MTProxy | Host, port and compatible secret |
| Telegram proxy link | A supported `tg://proxy` or `https://t.me/proxy` link |
| Included public list | Select a listed server, then save |

MTProxy accepts compatible hexadecimal/base64url keys and the `dd` form. Fake TLS `ee` secrets are unsupported.

## Save and test

1. Pause observation before changing an active account's route.
2. Select or enter the route.
3. Save the connection settings. This cancels unfinished sign-in attempts.
4. Run **Test Telegram connection**.
5. Sign in if necessary, restart observation and check a new controlled message.

Direct fallback depends on the selected IP mode. A successful transport test is not proof of authorization, anonymity or complete collection.


<picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture>

## Public lists

A snapshot from four public sources is bundled. The active pool refreshes lists and
checks transport in the background; failed downloads keep the last usable entries.
**Update public lists** requests a refresh without rewriting a manual route.

Under **Parameters → Automatic MTProxy**, configure rotation, failure thresholds,
cooldowns, sharing and retry intervals. Separate proxies are preferred when enough
work. A sharing limit of one makes an account wait instead of sharing an entry;
different entries do not guarantee different exit addresses.

Open **Where the list comes from** for providers, saved dates and download-route information. Public availability changes; an entry is not an endorsement or a promise that the server is reachable.

An operator can provide a local catalog using `TGWITNESS_PROXY_CATALOG`. Feed downloads can use `TGWITNESS_PROXY_FEED_PROXY`. These are separate from the account's Telegram route.

## Pool dashboard and custom sources

**Account → Settings → Connection settings → Proxy servers** shows servers, measured ping, check status,
country when available, source and workspace usage. Filter the table and press
**Use** to save an entry for the selected workspace. Pause observation first.

Under **Lists and sources**, the administrator can disable bundled lists, add HTTPS
list URLs, upload files or paste proxy links. These sources belong to the whole
installation, so a list added once is available in every workspace. Individual
routes remain separate. Unsupported Fake TLS entries are skipped.

An optional GitHub token enables authenticated downloads and code search for more
lists during refresh. It is stored encrypted and sent only to HTTPS GitHub hosts.
Country lookup is optional; it sends proxy server IPs to a geolocation service
through the configured outside route. Ping and country are observations, not trust
ratings. **Check all now** updates results without changing a saved manual route.

## Other network traffic

MTProxy carries Telegram traffic only. External requests use a separate SOCKS5/HTTP
proxy when configured, then the workspace's SOCKS5/HTTP route. Without either,
Hide IP refuses the request; the other modes permit Direct. External requests can
be disabled. An explicit feed-download proxy overrides the feed route; the
independent witness keeps its own settings. These controls do not route your browser.

Proxy credentials are saved in the encrypted vault. Ordinary HTTP CONNECT and SOCKS authentication do not themselves provide TLS protection to the proxy.

**Next:** [Troubleshooting](Troubleshooting.md) · [Connection reference](../CONNECTION-SECURITY.md) · [Operator catalog example](../../deploy/proxies.config.example)
