[TgWitness](../README.md) / [Documentation](README.md) · [Deployment and recovery](DEPLOYMENT.md)

![Deployment & recovery](assets/presentation/chapter-operate.svg)

# A live showcase of selected public channels

**More tools → Access → Public showcase** creates a separate, read-only page using the existing
access-token system. It reads the installation's saved observations. It does not
start a collector, sign in to Telegram or acquire a channel for a visitor.

## Publish a page

1. Save a source profile for each public channel you want to show. A channel must
   have a public username in its latest saved profile; groups and private chats
   are not eligible.
2. Open **More tools → Access → Public showcase** (or `/showcase-manage.html`) as the administrator.
3. Select channels across up to 16 workspaces, enter the public page title, and
   choose a link lifetime of 1, 7 or 30 days. Internal workspace labels are not
   published. Up to 64 channels can be included.
4. Review the selected channels' text for publication, then click **Preview selected
   records**. The preview uses the same server-side projection as the visitor page.
5. Click **Create showcase link**. Copy the link while it is visible. Open it in a
   separate browser to review the recipient's page before distributing it.

The link contains an access token in its URL fragment. The page removes the
fragment before making API requests and exchanges it for a browser session.
Anyone holding the link can open the selected material until expiry or revocation.
New links allow 100 concurrent sessions, each lasting at most one hour. Existing
Access controls can also enforce address restrictions and sign-in limits through
the grant API. Normal reviewer access is a different mode and still includes the
original permitted messages and files.

## What visitors see

| Visible | Kept private |
| --- | --- |
| Selected public channel titles, usernames and profile observation dates | Account identities, internal workspace labels and unselected sources |
| Captured text and each saved edit | Structured sender IDs, names, usernames, phone numbers and profile values |
| Deletion observations with the previously saved text, if available | Attachments, avatars, thumbnails, filenames and original payloads |
| Markers saying an author/profile or attachment was recorded | Forwarding and reply metadata, network routes, IP addresses and credentials |
| Selected-channel event counts, current collection switches, heartbeat and checkpoint interval | Collection controls and ordinary evidence-export APIs |
| Signing fingerprint, journal checkpoint and consistency proof | Signing keys and Telegram sessions |

**Public message text is not automatically anonymized.** A name, mention, phone
number or link written into the message remains part of that text. `Redacted`
applies to the structured author/profile fields. Review the actual selected content
before publishing it, including preserved edits and deletions.

Eligibility reflects the **latest saved source profile**, not a live Telegram lookup.
If a subsequent profile no longer has a public channel username, new requests
exclude the channel. Refresh source profiles when public visibility changes.
Readers may already have saved material they previously received.

The original signed records stay unchanged. The displayed projection is signed
separately and carries hashes referencing its original records. The projection
signature authenticates the displayed statement, and the referenced original records
keep their own signatures.

## Check signatures and continuity

Expand **Fingerprint & signed checkpoint** and download a snapshot. After a page
refresh, the download includes the preceding browser snapshot and a Merkle
consistency proof between their journal boundaries. Automatic refresh is once a
minute while the page is visible and showing its first page of observations.

With TgWitness installed, verify the downloaded file offline:

```sh
python -m tgwitness.showcase_verify showcase.json --fingerprint TRUSTED_COLLECTOR_SHA256
```

The fingerprint must come from a separately trusted reference. To compare against
a snapshot you retained yourself, use `--previous earlier.json`; this overrides
the previous snapshot carried inside the download. The current proof must begin
at that retained boundary. Authenticated clients can request that proof using
`GET /api/showcase/{workspace_id}?challenge=<32-hex-random>&from_count=<retained-count>`.
A shorter journal returns HTTP 409 instead of silently resetting the boundary.

The signed checkpoint commits to the **whole collector journal**, including its
record count and opaque head hash. Displayed message counts apply only to the
selected public channels. The page never lists the other journal's contents.
These are event counts, not unique-message counts. The settings describe the
current configuration, not every earlier recording interval.

Signature and consistency verification can detect changes relative to a retained
boundary. Recount the reported events from the corresponding archive and review
the acquisition intervals and retained witness checkpoints together.
Use the [evidence verifier](TRUST.md),
[independent witness](WITNESS.md) and [tested-scale record](VERIFICATION.md).
Synthetic installations are visibly labelled as synthetic.

## Revoke or host the page

Use **Revoke** in the showcase manager or the existing **Access** section to close
the link and end all its sessions. The visitor clears displayed records when a
request detects that access has ended. Expiry and permissions are checked on every
request. Showcase grants cannot be converted to ordinary panel access in place;
create a new grant to change modes.

Serve the page through the installation's existing HTTPS address. Publishing a
link does not open a new port, create a tunnel or change DNS. The HTML and API
remain on the user's installation. A showcase visitor cannot use the ordinary
message, profile, media, export or management APIs with this access.
