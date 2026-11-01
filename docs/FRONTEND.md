# Panel development

The panel uses native ES modules and plain DOM controls. There is no frontend
build step. Run `python start.py` for the local panel; browser checks create their
own temporary workspaces and do not connect Telegram accounts.

## Source language and localization

English is the canonical source language for the interface, documentation, demo
and release notes. Design and review new behavior in English first, including its
complete browser flows. Russian and other languages are additional translations.
Keep English strings as translation keys and English as the fallback. Respect an
explicit language choice and supported browser preferences; a translation update
must not change the project's source language or force that locale on users.

## Modules and ownership

| Location | Owns |
| --- | --- |
| `tgwitness/static/app.js` | Bootstrap, session boundary and adapters for existing controllers |
| `static/router.js` | History paths, workspace query, journal filters, deep links and Back/Forward |
| `static/core/view-host.js` | Active view, request cancellation and retained view roots |
| `static/core/time.js` | UTC/local display and relative time |
| `static/views/` | Sources, Parameters, Accounts, Access, System log, Exports and chat-list controls |
| `static/components/` | Health, notices, journal controls, local form drafts and connection feedback |

Paths in this table after the first row are relative to `tgwitness/`.
Controllers receive their API, translation and permission functions explicitly.
They do not reach into another controller's form or assume that a classic-script
binding is a property of `window`.

Only the active view root is attached to the document. Other roots are detached
and retained in memory so that drafts, listeners and local controls survive a
round trip. This is not full code splitting: `index.html` still supplies the
initial view markup, and `app.js` still contains legacy controllers.

## Navigation and requests

- `/?ws=default` opens the saved/default view. Named routes include `/chats`,
  `/chats/:chatId`, `/journal`, `/journal/event/:seq`, `/sources`, `/parameters`,
  `/accounts`, `/access`, `/integrations`, `/exports` and `/extras/:card`.
- Journal query parameters carry kind, source, search, dates and the system-event
  switch. A route describes a view; it grants no access. The API checks permissions
  and workspace/chat scope on every request.
- Static demo links use a `route` query parameter because GitHub Pages cannot
  serve arbitrary panel paths. The server enumerates document routes; missing API
  and asset paths must not fall back to HTML.
- A view's `enter(context)` receives an abort signal and a `current()` guard.
  On leaving, stop its reads and subscriptions. Before applying a response, check
  both the request and workspace generation. Export and collection jobs can
  continue after their view closes; their display subscriptions cannot.
- Hidden tabs suspend periodic UI reads. A connection retry repeats only a status
  read, never a mutation. Do not retry a POST after an ambiguous network failure.

## Forms and evidence

Background updates patch keyed rows and status nodes. They must not recreate a
form, replace a focused control or discard an unsaved value. For save responses,
compare the submitted snapshot with the current draft: accept normalization when
there is no newer edit; otherwise retain that edit. Clear write-only credentials
from both the visible field and the saved Discard baseline. Keep newly issued
access and MCP tokens, and form credentials, out of browser storage. The active
panel sign-in token uses tab-scoped `sessionStorage` to survive reloads and is
removed on lock; it must not become a persistent draft or a `localStorage` value.

Use `tr()` for UI text, including labels supplied through controller callbacks.
Keep `tools/i18n_keys.py` aware of dynamic label catalogs. New module files belong
in the wheel and static-demo asset inventories as well as the source archive.

The panel reads signed records. Display grouping, filters, export-download history
and local drafts are not journal edits. Keep the original signed record available
and verify archives independently with `python -m tgwitness.verify`.

## Remaining extraction

1. Move the existing authenticated request helpers into `core/api.js`, preserving
   their cancellation, timeout, workspace and error contracts. Start with one
   controller and run its stale-response tests before moving other callers.
2. Extract session/workspace state into `core/store.js` with narrow subscriptions.
   Keep draft state inside its controller. Avoid a global render on every update.
3. Move remaining chat, journal and integration controllers out of `app.js` behind
   the same context adapters. Do not combine this with backend or evidence changes.
4. Once no caller needs eager markup, load view templates on first use. Keep
   translated content, demo packaging and direct-route loading covered by tests.

## Checks

Run from the repository root in the project environment:

```sh
python -m ruff check .
python tools/check_router_browser.py
python tools/check_polling_browser.py
python tools/check_sources_browser.py
python tools/check_journal_browser.py
python tools/check_controls_browser.py
python tools/check_publication.py --git-index
node tools/check_writeonly_drafts.mjs
```

Browser scripts use synthetic data and check both the rendered panel and API
boundaries. The CI browser jobs list the full acceptance set. Screenshots are
review artifacts, not production assets; do not add generated journals, sessions
or screenshots of real accounts to the repository.
