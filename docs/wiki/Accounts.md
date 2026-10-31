<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/wiki-accounts-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/wiki-accounts-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/wiki-accounts-mobile.svg">
  <img src="../assets/presentation/wiki-accounts.svg" width="1200" alt="Connect your workspace. Choose an account, sign in and confirm its identity.">
</picture>

# Accounts and workspaces

**01 · CONNECT AND CAPTURE** · [All guides](Home.md) · [Get help](../../.github/SUPPORT.md)

<details>
<summary>On this page</summary>

- [Choose a sign-in method](#choose-a-sign-in-method)
- [Connect and confirm](#connect-and-confirm)
- [Add or remove a workspace](#add-or-remove-a-workspace)
- [Import accounts and share settings](#import-accounts-and-share-settings)

</details>



Use a dedicated Telegram user account. Each workspace keeps its own authorization, journal, signing key, sources, proxy settings and attachment queue. The administrator can [issue access](Access.md) to selected workspaces and chats, with separate permissions for viewing, exporting and operations.

## Choose a sign-in method

| You have | Use |
| --- | --- |
| Phone number and access to login codes | **Account → Phone**; complete code and 2FA if requested |
| An account already open in a Telegram app | **Account → QR code**; approve the displayed code in that app |
| A supported saved session | **Account → Files**; select the session and companion JSON together |
| A complete authorization key | **Account → Auth key**; provide the 512 hex characters and its DC ID |

Supported imports include Telethon StringSession, reviewed Telethon/Pyrogram SQLite formats, documented account JSON and modern single-account TData ZIP. TDLib directories and CSV account inventories are unsupported. JSON metadata alone may require phone or QR login.

API ID and API hash identify an application; they are not an account login. TgWitness can reuse saved/imported credentials or a pair from its built-in pool. You may supply your own pair under **API ID + Hash**.

## Connect and confirm

1. Select the intended workspace.
2. If needed, set its [proxy route](Proxies.md) before login.
3. Complete a sign-in method.
4. Check the displayed Telegram account ID.
5. Open **Sources**, select a controlled chat and start observation.
6. Confirm a new message arrives in the journal.

A connection test checks transport. Authorization and access to a particular chat are separate checks.


<picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture>

## Add or remove a workspace

Use the **+** beside the account selector or **Accounts → Add account**. There is no fixed workspace cap; all collectors share one process and the machine's resources. An account cannot be assigned to two workspaces in this installation.

Switching the selected workspace leaves the other collectors running. **Lock** clears browser access; **Pause** stops observation.

Deleting an additional workspace stops its collector and removes local sessions, journal and keys. If deletion fails, the workspace remains unavailable with **Deletion incomplete**; close programs holding its files and retry. The main workspace cannot be deleted through the panel. Separately exported or backed-up material is not removed with a workspace.

## Import accounts and share settings

**Accounts → Import accounts** accepts multiple accounts at once. Match companion
files by basename, such as `alpha.session` + `alpha.json`. Choose a group and start
the queue. Each account accepts up to four files, 8 MiB total; a TData ZIP must
contain one account. Each account gets a separate workspace; failed logins are rolled back,
and duplicates are rejected. Locking or switching stops the remaining queue.

Groups keep the account list organized. Open **Shared settings**, choose a template
and select the settings to copy, then press **Apply to members**. Settings are copied
once; sessions, signing keys, evidence and proxy credentials stay separate. An
observing account keeps its IP mode until paused. Deleting a group preserves its
accounts. See [session formats and limits](../ACCOUNTS.md).

**Next:** [Collection](Collection.md) · [Session formats and limits](../ACCOUNTS.md) · [Backup](Backup-and-Recovery.md)
