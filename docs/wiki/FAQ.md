<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/wiki-faq-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/wiki-faq-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/wiki-faq-mobile.svg">
  <img src="../assets/presentation/wiki-faq.svg" width="1200" alt="Straight to the answer. Accounts, capture, evidence and everyday operation.">
</picture>

# Frequently asked questions

**05 · FIND AN ANSWER** · [All guides](Home.md) · [Get help](../../.github/SUPPORT.md)

<details>
<summary>On this page</summary>

- [Does TgWitness recover messages deleted before it started?](#does-tgwitness-recover-messages-deleted-before-it-started)
- [What does archive verification check?](#what-does-archive-verification-check)
- [Is every Telegram event guaranteed to arrive?](#is-every-telegram-event-guaranteed-to-arrive)
- [Can I use a bot token instead of a user account?](#can-i-use-a-bot-token-instead-of-a-user-account)
- [Do I need my own API ID and API hash?](#do-i-need-my-own-api-id-and-api-hash)
- [Can several people have separate access permissions?](#can-several-people-have-separate-access-permissions)
- [Are messages and attachments encrypted on disk?](#are-messages-and-attachments-encrypted-on-disk)
- [Does Lock stop collection?](#does-lock-stop-collection)
- [Why can two accounts show different histories?](#why-can-two-accounts-show-different-histories)
- [Does a public proxy failure switch me to a direct connection?](#does-a-public-proxy-failure-switch-me-to-a-direct-connection)
- [Are an evidence export and a backup interchangeable?](#are-an-evidence-export-and-a-backup-interchangeable)
- [Is a witness on my server independent?](#is-a-witness-on-my-server-independent)
- [Is Linux, macOS or Docker support already fully qualified?](#is-linux-macos-or-docker-support-already-fully-qualified)
- [How do I report a problem or contribute?](#how-do-i-report-a-problem-or-contribute)

</details>

## Does TgWitness recover messages deleted before it started?

No. You might see a deletion with no content behind it. Loading history only gets what
the account can see right now, not old versions.

<a name="does-a-valid-signature-prove-telegram-sent-the-message"></a>

## What does archive verification check?

Record signatures, the journal chain, the file manifest and attachment hashes. Give it a
key fingerprint and checkpoint kept elsewhere and it also checks the expected key and an
earlier journal state. An independent witness adds more checkpoints, and
[GitHub Actions capture](../SEALED-ACTIONS.md) also checks the archive's provenance against
the approved workflow and collector version.

[Verification steps](Exports-and-Verification.md) · [Technical trust model](../SECURITY-MODEL.md)


<picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture>

## Is every Telegram event guaranteed to arrive?

No. Permissions, network drops, Telegram itself and restarts all get in the way. Rechecks
help, but look at the coverage report.

## Can I use a bot token instead of a user account?

No, the collector needs a user account. Bot tokens are only for the optional witness.

<picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture>

## Do I need my own API ID and API hash?

No. The built-in pool works fine, saved or imported credentials are reused. An API pair
only identifies the app, it gives no access to anyone's account.

## Can several people have separate access permissions?

Yes. Create a token under **Access**, pick workspaces, chats and permissions, add limits
if you want. The main panel token stays unrestricted. See [access and permissions](Access.md).

<picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture>

## Are messages and attachments encrypted on disk?

Sessions, credentials and keys are, in the vault. The journal and files aren't, so use
disk encryption. Exports can get a password.

## Does Lock stop collection?

No, it only closes the browser panel. **Pause observation** stops collecting. Closing the
tab doesn't stop anything either.

<picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture>

## Why can two accounts show different histories?

Different access, join dates, visibility. Each workspace keeps its own observations and
key, so always say which workspace a record came from.

## Does a public proxy failure switch me to a direct connection?

Not with **Hide the address**. **Direct as a last resort** goes direct after a delay,
**Server behind a tunnel or VPN** allows direct. Outside requests and the witness have
their own rules. See [connection routes](Proxies.md).

<picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture>

## Are an evidence export and a backup interchangeable?

No. An export leaves out login and signing secrets on purpose. A backup is the whole
stopped data directory plus any external vault key.

## Is a witness on my server independent?

Not really. It has its own process and key, but you still control the server. Real
independence means someone else runs it.

<picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture>

## Is Linux, macOS or Docker support already fully qualified?

Check the [verification record](../VERIFICATION.md). Having a launcher or a CI job isn't
the same as having tested every platform live.

## How do I report a problem or contribute?

[Support](../../.github/SUPPORT.md) for help and bugs, [Contributing](../../.github/CONTRIBUTING.md)
for code, [Security](../../.github/SECURITY.md) for vulnerabilities.
