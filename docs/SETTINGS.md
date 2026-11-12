[TgWitness](../README.md) / [Documentation](README.md) · [Getting started](QUICKSTART.md)

![Getting started](assets/presentation/chapter-start.svg)

# First setup and settings

[Accounts](ACCOUNTS.md) · [Connection](CONNECTION-SECURITY.md) · [Access](ACCESS.md)

A new workspace opens `/first-run`. The first screen asks what you want to do:
**Just download**, **Follow chats** or **Evidence for a case**. The choice sets the
goal and the interface level: Simple for Just download, Standard for the other two. The level sets how many fields each form shows; every page stays in the menu.
**More options** on the same screen sets the level, theme and time zone explicitly;
the language list is in the wizard header. The next screens cover the connection,
Telegram and chats. Connection routes stay folded while the automatic check works
and open when it fails. A five-stage progress bar returns to completed stages.
Each answer is saved on the server as soon as it changes, so a reload continues the
same step. The last screen lists the answers and lets you go back to any of them.

Language, IANA time zone, theme and level are stored per operator and per workspace.
The defaults are the browser language, the device time zone, the system theme and the
Simple interface. Changing the language keeps the panel session. Times in the signed
journal never change.

`/settings` edits the same records as the wizard. Search covers the main fields,
parameters and the extended forms; a hidden field can be opened without changing the
level. Levels only change what is shown: the server checks permissions on its own.
Collection settings and the first connection belong to the workspace administrator.

| Level | Fields | Sidebar |
| --- | --- | --- |
| Simple | Only the essentials | Home, Chats, Journal, Exports, Accounts and Settings |
| Standard | Common settings with explanations | Adds Case Board, Sources, Access and Documentation under More tools |
| Expert | All fields, limits and technical details | Also adds System map, Network topology, Extras, Ask the archive, Parameters, Account, System log and Integrations under More tools |

Section names stay the same at every level. Open Appearance at the bottom of the
sidebar to change the level. The [panel guide](PANEL.md) describes each section.

## Goals

| Goal | Collection | Files | Outside services | Server address |
| --- | --- | --- | --- | --- |
| Just download | One-time export starts from the final setup screen; continuous collection stays off | Photos up to 20 MB | Off | Automatic |
| Follow chats | Continuous | Photos and videos up to 60 seconds / 20 MB | Timestamps and problem notifications | Automatic |
| Evidence for a case | Continuous | All files up to 1 GB | Timestamps, drand, notifications | No, hide it |

Off-site copy, the witness bot and the code check are recommended for evidence.
Storage and notification addresses need a destination first. A feature that talks
to an outside service asks to allow requests outside Telegram; turning that off
offers to switch off timestamps, notifications and the off-site copy with it.

Changing the goal shows the difference first, and manual changes can be kept. A field
that differs from the goal is marked **Changed by you** and can be restored. The
settings revision keeps a reviewed difference from being applied over a change made
in another tab.

## Connection

**Automatic** tries WARP, then public MTProxy servers, then a direct connection, the
last only when the server's address may be shown. Automatic and WARP can install
hash-checked components and register the server with Cloudflare; without that consent
Automatic skips WARP. WARP uses the existing wgcf/wireproxy manager and a local SOCKS5
port; the system routing table is not changed.

**Bulk import** asks for the route before any session reaches Telegram: WARP (default),
public MTProxy or direct. The session check uses the same kind of route, and every
imported account gets its own WARP tunnel before its first sign-in.

Your own proxy accepts `tg://proxy`, `socks5://`, `http://` and `https://`. An HTTPS
proxy's certificate is checked before credentials are sent to it.

A connection check is valid for five minutes and is bound to the route, the policy and
the wizard answers; changing any of them needs a new check. **Continue without
checking** is available and does not replace the Telegram sign-in. The chosen route
is rechecked in the background, and Automatic runs its chain again after a lost
connection. When no public proxy answers, the count turns red with WARP and recheck
actions.

## Account groups

Accounts in a group share their settings. Open **Accounts → Groups and shared
settings → Shared settings**, or **Group settings** on an account's Settings page.

The group shares the goal, saved files, timestamps, drand, problem notifications,
off-site copy, requests outside Telegram, IP mode, what to record, the recheck
schedule, notification rules, report settings, parameters and the connection route.
Notification destinations, proxy credentials and sign-in stay per account, as do
starting and pausing collection.

- Every member follows the group. Settings marks a value 🔗 **From the group** or
  ✏️ **Own value**; **Return to the group value** puts it back.
- A change lists the accounts it reaches (**Applies to 2 of 3 accounts**) and asks per
  account before replacing an own value. Unticked accounts keep theirs.
- A parameter the group does not share stays **Not shared: each account keeps its
  own value** until you press **Share this value**.
- **Copy settings from one account** takes the chosen account's values as the group's.
- An account moved into a group is asked **Take the group's values?** Otherwise it keeps
  its own values, marked ✏️. Accounts added later start with the group's values.
- An observing account keeps its IP mode until it is paused.

Each change is recorded in the signed journal of the main workspace and of every
member it reaches. Deleting a group keeps its accounts and their current values.

The group page `/groups/<id>` shows the members, what needs attention and the chats
several accounts see. See [account groups](ACCOUNTS.md#bulk-import-and-account-groups).

## Existing workspaces

A workspace with a session or an earlier completed setup does not get the wizard.
Its values are not replaced by a goal when the page loads. Hiding a field does not
turn the feature off or delete its value.

The size and time estimate reads up to three selected chats and up to 20 messages from
each. It is an estimate: it does not predict Telegram limits, the speed of a given
server or the files in every chat.
