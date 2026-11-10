![TgWitness handbook](../assets/presentation/wiki-brand.svg)

# Share access to an investigation

**04 · RUN AND PROTECT** · [All guides](Home.md) · [Full access reference](../ACCESS.md)

Let someone look at one chat or help with a case without giving them your main token.
Limit it to certain workspaces and chats and pick what they can do.

## Issue a token

1. **More tools → Access → Give someone access** (as admin, Standard or Expert level).
2. Name it, pick workspaces, a group or single chats.
3. Permissions: a reviewer only needs **View**, add **Export** for downloads.
4. Expiry, session and IP limits if you want.
5. Create it and copy the token (shown once). Send it privately with the panel URL.
6. Check what they see in a separate browser session.

| Need | Configure |
| --- | --- |
| Review one conversation | Select that chat; keep `view` |
| Download a case | Select the required chats; enable `export` |
| Manage collection | Select whole workspaces; enable `sources` and `collect` |
| Discuss the case on Case Board | Select the chats; enable `board.read`, add `board.write` to post |
| Cover a whole account group | Select the group; accounts added to it later are included |
| End one connection | **Open sessions → End session** |
| Withdraw access completely | Revoke the entry under **Granted access** |

Collection scope is what gets recorded, access scope is what someone can see and do.
They're independent.

## Keep the scope precise

Chat-limited access can't open account settings, log in as the account or download the
whole journal, no matter what boxes are ticked. **All workspaces** and group access include
accounts added later. Case Board notes follow the same chat scope.

Changes apply from the next request. Revoking ends open sessions but can't pull back files
already downloaded. Ending a session doesn't stop collection.

<details>
<summary><strong>IP limits, session expiry and the administrator console</strong></summary>

Allow certain addresses/subnets, lock access to the first sign-in IP, limit sign-ins and
parallel sessions, set an end date. Timeout counts inactivity, and an open panel polling
counts as active. Behind a reverse proxy, check the client IP the app sees before trusting IP rules.

The admin console shows live activity across workspaces. Signed `access.*` records keep
access changes and sessions, never the tokens. The main token is still full admin.

</details>

**Next:** [Permissions and examples](../ACCESS.md#choose-the-permissions) · [Accounts](Accounts.md) · [Proxies](Proxies.md)
