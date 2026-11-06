[TgWitness](../README.md) / [Documentation](README.md) · [Deployment and recovery](DEPLOYMENT.md)

![Deployment & recovery](assets/presentation/chapter-operate.svg)

# Storage and recovery

The panel separates three tasks:

| Task | What it does |
| --- | --- |
| Keep a backup | Copy the signed journal, checkpoints, preserved files and queued exports to the configured S3 destination. |
| Free local space | Copy selected older attachments to S3 or an rclone cloud remote, read them back in full, verify the encrypted bytes, then remove the verified local copy. |
| Keep an evidence copy | Configure S3 Object Lock and check the returned retention status. The service must confirm the requested mode and date. |

Freeing space never deletes or rewrites the signed journal. Each attachment keeps
its original SHA-256 and a recovery receipt. Optional gzip compression takes place
before authenticated encryption. Cloud filenames do not contain Telegram names,
chat IDs or original attachment names. One attachment may be up to 32 GiB.

An upload response alone is not permission to delete a file. TgWitness downloads
the complete encrypted object and verifies its size and SHA-256, saves the receipt,
then checks the local bytes again immediately before removal. An upload failure,
different readback or cancelled transfer leaves the local file in place. If an
enabled evidence backup has not yet copied that file, removal also waits for it.

<details>
<summary>On this page</summary>

- [When the disk is filling up](#when-the-disk-is-filling-up)
- [Connect a destination](#connect-a-destination)
- [Keep the recovery file](#keep-the-recovery-file)
- [Recover after losing the installation](#recover-after-losing-the-installation)
- [Operator bot and completion notices](#operator-bot-and-completion-notices)

</details>

## When the disk is filling up

Attachment downloads already pause below **Parameters → Attachments → free disk
space** (1 GiB by default), keeping their queue. Text observations continue. This
does not depend on notification settings. Disabling notifications does not disable
the download reserve or storage safeguards.

For earlier intervention, enable **Run automatically**, choose **Remove the local
file to free space**, and enable **Start an extra offload pass when disk space is
low**. The optional rule starts below 5120 MiB free and continues in batches until
10240 MiB is free by default. Both thresholds are configurable. It uses the same
destination, minimum file age, batch limit, full readback verification and evidence
backup prerequisites as a manual pass. It never enables a destination on its own.
Checks run every 30 seconds; an error or no progress delays another pressure pass
for five minutes. The pressure state and retry time survive a restart. Scheduled
passes still use their normal interval when the pressure rule is inactive.

The panel shows free space, the packing reserve, whether the pressure rule is
armed, and files skipped for lack of temporary space. Packing and restoration
check their peak temporary-space requirement before starting and check available
space while writing. The reserve is the configured download reserve, with a
64 MiB minimum for storage operations. These checks are not a filesystem quota;
another process can still consume space between checks.

Gzip compression is lossless and applies to remote objects; it does not shrink the
active journal or create local archives. JPEG/video/ZIP files may barely shrink or
grow slightly. The current packing pipeline may temporarily need approximately
twice the attachment size plus the reserve when compression is enabled. Choose a
start threshold early enough for your largest files. A file too large to prepare
is kept and reported; smaller files and previously verified remote copies can
still free space. A verified copy can be offloaded without another local packing
file. Restoration also needs temporary space and can be refused until space is
available.

If nothing eligible can be moved, or no destination is configured, TgWitness
cannot reclaim space automatically. The signed journal is never pruned or
rewritten by storage management. It still needs space for new text observations.

## Connect a destination

In **Extras → Storage & disk space → Manage storage**, choose the task and destination,
save it, then select **Test upload & download**. The test uploads a small random probe and reads it
back. It does not use Telegram content.

For S3, use the provider's actual endpoint, region and bucket. Wasabi, Backblaze,
Cloudflare R2 and other compatible services use the same S3 settings. A compatible
API alone does not imply support for Object Lock. Governance mode may allow an
authorized administrator to bypass retention; Compliance mode has different
constraints. Read the returned Object Lock status before relying on retention.

For an rclone destination, create one remote using rclone's provider setup and
paste that remote's `[name]` section into the panel. The installed helper supports
MEGA, Google Drive, OneDrive, Dropbox, Box, pCloud and the other providers shown in
the selector. Credentials are saved in this workspace's encrypted vault. OAuth
refreshes are saved back into the vault. Credentials are not added to journal
events or included in recovery downloads.

The helper is installed within the workspace, with a pinned version and SHA-256.
It is not added to the system PATH. Configuration files and working files are
temporary files within that workspace. Command-based and local-file remotes are
refused. rclone currently requires an explicitly selected **Direct** route for
external requests. Use native S3 storage for a workspace SOCKS5 or HTTP route;
rclone does not silently bypass an unavailable route.

## Keep the recovery file

Choose **Save recovery file** after copying files and keep it somewhere
separate from the installation. It contains the decryption key and signed object
receipts, so treat it as a private key backup. Keep the original remote configuration
and destination credentials separately as well. A recovery file taken before a
later copy does not contain that later file's receipt.

The signing-key fingerprint should already be recorded independently. A signature
checked only against the key supplied inside the same file does not establish whose
recovery file it is.

To repair missing storage receipts in an existing workspace, open **Recover files
from a saved recovery file** and select the file. The panel checks the signature and requires the same workspace
signing key. It refuses to replace a different storage key. Then choose **Restore
all files**. Restoration pauses the automatic storage rule so the next scheduled
pass cannot immediately remove the restored files again. Re-enable the rule when
finished with the local copies.

Restoration verifies the ciphertext, authenticates decryption, decompresses if
needed and checks the original plaintext SHA-256 before placing a file in `media/`.
A corrupt remote object never replaces a local file. An existing local file with
different bytes is kept for review rather than overwritten.

## Recover after losing the installation

Install TgWitness on another machine. Use the private recovery file, the separately
recorded fingerprint and the original destination credentials:

```sh
python -m tgwitness.storage recover \
  --recovery storage-recovery.json \
  --fingerprint TRUSTED_WORKSPACE_SHA256 \
  --credentials original-rclone.conf \
  --output recovered-attachments
```

For S3, `--credentials` points to a private JSON file with `access_key` and
`secret_key`; the signed recovery file supplies the destination settings.
The command uses a direct external connection and downloads the pinned helper
when an rclone remote needs it. It refuses an existing output directory.

Recovered original bytes are written to `recovered-attachments/media/`, named by
their SHA-256. `recovery-log.jsonl` is an unsigned record of recovery operations.
The command does not recreate a lost signed journal or its signing key. Keep a
full workspace backup for those. A storage recovery file is not a full workspace
backup.

## Operator bot and completion notices

The Telegram bot belongs to the operator. Create it through BotFather and set its
token, destination chat and explicit allowed Telegram user IDs in the panel. Both
the sender and the chat must match. Forwarded messages and commands from other
bots are ignored.

`/status` and `/stats` are available in the default status-only mode. Optional
control mode adds `/pause`, `/resume` and `/copy`. `/copy` requests the configured
storage task; it does not mean that a remote upload already finished. Commands
cannot supply arbitrary URLs, files or shell programs.

Use the separate notification settings for alerts and task completion. Completion
notices distinguish an account export with gaps from a complete export, and show
history and storage counts. Message excerpts are not included unless separately
enabled in notification settings. The service picker is generated from the actual
installed Apprise catalog rather than a fixed set of provider examples.
