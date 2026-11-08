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
| Account and chat export, file policies and minimized sharing copies | [Account export](ACCOUNT-EXPORT.md) |
| Signed journals, checkpoints and standalone verification | [Evidence](EVIDENCE.md) |
| Separate witness with online Merkle continuity checks | [Witness](WITNESS.md) |
| Official-client capture and session video | [Trusted Live](TRUSTED-LIVE.md) |
| GitHub capture with a session time budget and encrypted delivery | [GitHub capture](SEALED-ACTIONS.md) |
| Intel TDX collection and independent quote verification | [High assurance](HIGH-ASSURANCE.md) |

[Choose a collection method](COLLECTION-MODES.md) for scope, output and recovery behavior.
[Secret Chat development status](PSEUDO-SECRET.md) describes the separate implementation,
its simulated website interface and the defects that remain before integration.
[Actions](https://github.com/phishdestroy/TgWitness/actions) records automated checks
for each revision; [Verification](VERIFICATION.md) records completed deployment and
live-account tests. See the [changelog](CHANGELOG.md) for changes.

The optional forensics helpers accept complete MTProto frames for offline digest matching;
generic PCAP import is unqualified and rejected. These matches do not establish Telegram
origin, capture completeness, a viewer's identity or prior viewing; raw PCAP attachments are retained without verification.
