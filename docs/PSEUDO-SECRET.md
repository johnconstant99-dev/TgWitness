[TgWitness](../README.md) / [Documentation](README.md)

# Secret Chats: installation and recording

The published application includes the Secret Chat backend, collector integration,
API routes and **Sources → Pseudo-secret** interface. Install the optional
`secret-chats` protocol dependency in the environment running TgWitness, then enable
the module for the chosen account. Both the module and automatic incoming acceptance
are off by default.

TgWitness becomes an endpoint for the chats it creates or accepts. It records
messages, available attachments, timer changes and deletion notices in the signed
journal. Previously saved content remains available after a later deletion notice.

## Package availability

On 8 November 2026, the published installer package was checked at source
[`b35f8e18f3d1`](https://github.com/phishdestroy/TgWitness/commit/b35f8e18f3d13c329af12e0036f50e0c8f340a2c),
release `b35f8e18f3d1-1ff85ec98bb2`, version 0.9.1 preview.
The [immutable wheel](https://get.destroy.tools/releases/b35f8e18f3d1-1ff85ec98bb2/tgwitness-0.9.1-py3-none-any.whl)
and its dependency lock passed SHA-256 and RSA release-signature verification.
The packaged backend and interface matched that source revision byte for byte.
The package also contains the API registration and collector hooks.

The protocol library is installed separately through the `secret-chats` extra;
it is not in the default dependency lock. The extra pins
[KiaroSama/Telethon-Secret-Chat](https://github.com/KiaroSama/Telethon-Secret-Chat)
to `d87bf037b90060383c7b704d8a06ebb98c621c6f`.
See [pyproject.toml](../pyproject.toml) for the dependency declaration and
[installation](INSTALLATION.md) for runtime locations.

For a source installation, use the same Python environment as the application:

```sh
python -m pip install ".[secret-chats]"
```

This package inspection establishes which files and dependency declarations ship.
The [validation record](VERIFICATION.md) identifies the separate runtime checks.
The earlier 6 November guide described a development snapshot; it no longer
describes the package above.

## Use the interface

Open **Sources → Pseudo-secret**, enable the module for the account and connect it.
Incoming requests wait for acceptance unless automatic acceptance is enabled.
Starting, accepting, sending and closing use the account's interaction permissions
and read-only protection.

| Action | Preserved result |
| --- | --- |
| Start a chat by username or user ID | Outgoing request; the peer accepts it on their device. |
| Accept a request | TgWitness becomes the receiving endpoint. |
| Send or receive a message | `secret_chat.message` with its direction, content and supplied timer. |
| Receive a file | Decrypted bytes stored by SHA-256 and a `secret_chat.file` receipt; included in the evidence export. |
| Receive a timer or deletion notice | A separate action record alongside retained messages and files. |
| Review the chat | Conversation, file receipts, notices and key visualization. |

Existing Secret Chats on another device retain their device-specific keys. An
imported cloud session does not transfer those keys. Secret-chat key material and
counters use the workspace vault; preserved messages and decrypted files use the
normal workspace storage protections.

## Persistence and interaction controls

The integrated implementation uses durable journal lookup for duplicate detection,
keeps attachment jobs pending after a failed download, and routes closing through
the same interaction guard as other remote actions. These replace the three paths
reported in the historical 6 November development-snapshot audit.

Decrypted messages whose journal write fails are held in the vault for retry.
Attachment size and free-disk checks defer downloads while keeping their jobs.
The module reuses the account's existing connection; it does not send read, typing
or screenshot notifications. See [secret_chats.py](../tgwitness/secret_chats.py),
[API routes](../tgwitness/api/secret_chats.py) and
[access policy](../tgwitness/access.py).

The [historical audit](../website/validation/audit/REPORT.md) retains its original
snapshot findings. Current availability and implementation should be read from
the package revision above and the [current capabilities](STATUS.md).

## Interface demonstration

The website scenario uses fictional requests, messages and files to demonstrate
the panel workflow. It is an interface example; protocol and acquisition checks
have their own dated results in the validation record.
