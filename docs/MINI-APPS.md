[TgWitness](../README.md) / [Documentation](README.md) · [Investigation](INVESTIGATION.md)

![Investigation](assets/presentation/chapter-investigate.svg)

# Mini applications

A Telegram mini application opens a web page inside the client. The button that
opens it carries an address, and the page itself references further addresses.
TgWitness lists the buttons it has already recorded and, on request, fetches one
page and reports the addresses written into it.

## List the buttons in a chat

```sh
curl -sS "http://127.0.0.1:8000/api/webapp?chat_id=-1001234567890&limit=200" \
  -H "Authorization: Bearer $TGWITNESS_TOKEN"
```

This reads saved journal records only; it contacts nobody. Accesses limited to
chosen chats see their own chats.

## Fetch one page

```sh
curl -sS -X POST http://127.0.0.1:8000/api/webapp/inspect \
  -H "Authorization: Bearer $TGWITNESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://app.example/start"}'
```

Only the main administrator can fetch, and only through the workspace route for
requests outside Telegram. When that route is turned off, or when Hide IP mode is
on without a proxy, the request is refused instead of falling back to a direct
connection. Addresses that resolve inside the local network are refused.

The response lists each referenced address with its host, path, scheme, whether
it shares the page's origin and where it was written: an HTML attribute, a CSS
`url()`, a dynamic `import()`, a `fetch`/`axios`/`WebSocket` call or a plain
string literal. `third_party_hosts` separates hosts other than the page's own,
and `sockets` lists `ws://` and `wss://` addresses. Reading stops after 4 MiB or
500 addresses, and `truncated` says when that happened.

Addresses found this way become URL and domain indicators in reports, listed
under the source **mini app**.

## What this records

One response, fetched at one moment, from this workspace's address. A mini
application can serve different addresses later, to another visitor, or after
its operator changes it. A referenced address is not confirmed to exist and was
not contacted. Asking Telegram for the launch address is an account action and is
recorded as `webapp.launch_requested`; each fetch is recorded as
`webapp.inspected` together with the addresses it found.
