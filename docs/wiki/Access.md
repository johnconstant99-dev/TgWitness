![TgWitness handbook](../assets/presentation/wiki-brand.svg)

# Share access to an investigation

**04 · RUN AND PROTECT** · [All guides](Home.md) · [Full access reference](../ACCESS.md)

Let someone review one chat or work on a case without handing over your main panel
token. Access can be limited to named workspaces and chats, with separate permissions
for reading, exporting, collecting, interacting, settings and account management.

## Issue a token

1. As the administrator, open **Access → Give someone access**.
2. Name the access and choose its workspaces and chats.
3. Choose permissions. For a reviewer, keep **View** only; add **Export** for downloads.
4. Set an expiry, session limits and IP restrictions if needed.
5. Create the access and copy the token shown once. Send it privately with the panel URL.
6. Check the recipient's view in a separate browser session.

| Need | Configure |
| --- | --- |
| Review one conversation | Select that chat; keep `view` |
| Download a case | Select the required chats; enable `export` |
| Manage collection | Select whole workspaces; enable `sources` and `collect` |
| End one connection | **Open sessions → End session** |
| Withdraw access completely | Revoke the entry under **Accesses** |

Collection scope controls what is recorded. Access scope controls what someone can
read and do. Changing one does not change the other.

## Keep the scope precise

Chat-limited access cannot open account-wide settings, sign in as the Telegram
account or download the full workspace journal. Additional permission checkboxes
do not remove that boundary. **All workspaces** includes accounts added later.

Changes apply on subsequent requests. Revocation ends open sessions but cannot
recall downloaded files. Closing a session leaves collection running.

<details>
<summary><strong>IP limits, session expiry and the administrator console</strong></summary>

Allow specific addresses/subnets, bind an access to its first sign-in address,
limit successful sign-ins and parallel sessions, or set an end date. Session timeout
measures inactivity; polling from an open panel counts as activity. Behind a reverse
proxy, verify the client address shown by the application before relying on IP rules.

The administrator's console shows current-process activity across workspaces.
Signed `access.*` records retain access changes and session events without the tokens.
The main panel token still grants unrestricted administrator access.

</details>

**Next:** [Permissions and examples](../ACCESS.md#choose-the-permissions) · [Accounts](Accounts.md) · [Proxies](Proxies.md)
