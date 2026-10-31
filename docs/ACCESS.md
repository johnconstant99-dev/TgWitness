# Share a case. Keep control of the workspace.

Give a reviewer access to one chat, an analyst permission to export a case, or an
operator control of selected accounts. Each person gets their own token. The main
panel token stays with the administrator.

[Account setup](ACCOUNTS.md) · [Connection routes](CONNECTION-SECURITY.md) · [Security model](SECURITY-MODEL.md)

## Two scopes, two different jobs

**Collection scope** decides what an account records: selected chats, a Telegram
folder or the whole account. **Access scope** decides which of those recorded
accounts and chats another person can see and use. Giving access does not join a
Telegram chat, start collection or grant Telegram account permissions.

An access can open selected workspaces, selected chats within them, or all
workspaces. **All workspaces, including ones added later** also covers future
accounts. Select workspaces explicitly when a case should stay limited to them.

## Give someone access

1. Sign in as the main administrator and open **Access**.
2. Under **Give someone access**, enter a name you will recognize in the log.
3. Choose the workspaces and, where needed, the individual chats.
4. Select what this person may do. **View** is always included.
5. Set the expiry, sign-in/session limits and allowed addresses as needed.
6. Press **Create access**. Copy the token now: it is shown only once.
7. Send the panel address and token privately. The recipient enters that token
   on the normal sign-in page; they do not need your main panel token or a Telegram session.

Open the panel with the issued token in a separate browser session and check the
visible chats and permitted actions before handing it over.

## Choose the permissions

| Permission | What it allows |
| --- | --- |
| `view` | Read permitted chats, captured messages, profiles, files and filtered journal records. Always included. |
| `export` | Export permitted chat history and dossiers. Whole-workspace evidence exports require access to the whole workspace. |
| `sources` | Manage sources, snapshots and profile capture. Chat-limited access can act only on allowed chats; account-wide source discovery and scope settings stay closed. |
| `collect` | Start or stop a collector. Requires whole-workspace access because collection affects the account. |
| `interact` | Perform supported Telegram interactions within the access scope. Chat-limited access cannot use account-wide link previews. |
| `settings` | Change collection settings, timestamps, notifications, off-site copies and parameters. Requires whole-workspace access. |
| `account` | Sign in or out of Telegram and manage connection routes. Requires whole-workspace access. |

Permissions and scope are checked together. Ticking a permission does not open
other chats or unlock a workspace-wide operation for a chat-limited access.
For a parallel export, the access must cover the exported chat in every selected
account. An issued access cannot create new accesses, manage other people's
sessions or open the administrator console.

### Three useful setups

| Person | Scope | Permissions |
| --- | --- | --- |
| Reviewer | One case's recorded chats | `view` |
| Analyst preparing a handover | The chats to investigate and export | `view`, `export`; add `interact` only if they should act through Telegram |
| Collection operator | Selected whole workspaces | `view`, `sources`, `collect`; add `settings` or `account` only when needed |

These are examples you configure with the permission checkboxes, not fixed roles.

## Limits and sessions

| Setting | How it works |
| --- | --- |
| Parallel sessions | Limit simultaneous sessions to 1–100. At the limit, refuse the next sign-in or end the oldest session. |
| Sign-ins allowed | Limit successful uses of the token to start sessions. Existing sessions are not ended just because the last allowed sign-in was used. |
| Valid until | An absolute expiry for the access. Expired access cannot sign in or keep making requests. |
| Minutes without activity | Session inactivity timeout, from 5 minutes to 30 days. Successful requests extend it; an open panel may keep itself active by polling. |
| Allowed addresses | Accept specific IP addresses or CIDR subnets. Leave empty to allow any address unless first-sign-in binding is enabled. |
| Bind to the first sign-in | The first successful sign-in fixes the permitted address for that access. |

The IP is the client address seen by the application. Behind a reverse proxy or
tunnel, check the address shown in **Open sessions** before relying on IP rules:
several users may otherwise appear to share the proxy's address.

## Change or withdraw access

Edit an entry under **Accesses** to change its scope, permissions or limits.
Scope and permission changes are checked on subsequent requests, including
requests from sessions that are already open. Revoking an access ends its sessions
and makes the issued token unusable. **Open sessions** also lets the administrator
end an individual session without revoking the whole access.

Revocation cannot recall files that someone already downloaded. Signing out,
locking the panel or ending a session does not stop a running collector.

## What the administrator can see

**Log since this start** combines process logs with journal activity from every
workspace: sign-ins, refusals, route changes and operator actions. It is an
in-memory console for the current process, not a permanent copy of every message.
Frequent message events stay in the journal rather than filling the console.

Issuing, changing and revoking access, and starting or ending sessions, also create
signed `access.*` journal records. Tokens are not included in those records.
Issued tokens and session credentials are retained as hashes in the encrypted vault.

<details>
<summary><strong>Main administrator and trust boundary</strong></summary>

The main panel token remains unrestricted. Browser sign-ins with it create sessions
subject to the administrator's configured session limits. Scripts sending the
main token directly retain full access and are not counted as browser sessions.

This is application-level access control in one installation. All workspaces share
the server process; this is not isolation from the host administrator. Keep the main
token, Telegram sessions, signing keys and data directory private. A witness token
is a separate checkpoint/health credential, not a panel access token.

</details>
