[TgWitness](../README.md) / [Documentation](README.md)

![Project reference](assets/presentation/chapter-project.svg)

# Current capabilities

[Start, scale and evidence](OVERVIEW.md) explains the one-command installation,
temporary GitHub capture, investigation options and published measurements.

Source version：**0.9.1 preview**. The [installer](https://get.destroy.tools/)
includes the exact source revision in its signed manifest. Tagged packages are
available under [Releases](https://github.com/phishdestroy/TgWitness/releases).

| Workflow | Guide |
| --- | --- |
| Live messages, edits, deletion notices and attachments | [Collection](COLLECTION.md) |
| Standard/Takeout history with resumable cursors | [Full history](BACKFILL.md) |
| Secret Chats created or accepted by TgWitness; optional protocol dependency | [Secret Chats](PSEUDO-SECRET.md) |
| Account and chat export, file policies and minimized sharing copies | [Account export](ACCOUNT-EXPORT.md) |
| Signed journals, checkpoints and standalone verification | [Evidence](EVIDENCE.md) |
| Separate witness with online Merkle continuity checks | [Witness](WITNESS.md) |
| Official-client capture and session video | [Trusted Live](TRUSTED-LIVE.md) |
| GitHub capture with a session time budget and encrypted delivery | [GitHub capture](SEALED-ACTIONS.md) |
| Intel TDX collection and independent quote verification | [High assurance](HIGH-ASSURANCE.md) |

[Choose a collection method](COLLECTION-MODES.md) for scope, output and recovery behavior.
[Secret Chat installation and package check](PSEUDO-SECRET.md) records the shipped
integration, optional protocol dependency and account-level controls.
[Development history and scale](OVERVIEW.md#testing-history-and-duration) puts the
public release timeline and selected measurements in context.
[Actions](https://github.com/phishdestroy/TgWitness/actions) records automated checks
for each revision; [Verification](VERIFICATION.md) records completed deployment and
live-account tests. See the [changelog](CHANGELOG.md) for changes.

The optional forensics helpers match complete MTProto frames against the journal offline:
the frame helper verifies payload digests and message identifiers against journal references.
Frames are supplied explicitly; a PCAP file travels in the bundle as an attachment.
The frame-match result is reviewed together with the acquisition path, capture records and custody.
