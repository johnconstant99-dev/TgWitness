# Work the archive

**Find the message. Check the source. Build the case.**

[Interactive guide](https://phishdestroy.github.io/TgWitness/docs/archive/) · [Investigations](Investigations.md) · [Export and verify](Exports-and-Verification.md)

These features are in the current `main` branch. Use a source checkout; the 0.7.0
portable preview predates them.

## Bring in the history

In **Sources**, review enabled chats, start observation and choose **Load full
history**. Pause or resume as needed. After a restart, resume explicitly.
Check each source and the attachment queue, then keep the signed progress report.
[History guide](../HISTORY.md).

## Search and review

Open **Ask the archive**, choose chats and a period, then search a phrase, domain
or message ID. Search is local. Open the saved records behind the results.

For AI analysis, configure a provider, review **Data sent to the model**, remove
unwanted excerpts and approve the request. Check the citations before saving a
report. Your notes and revisions stay separate from captured events.
[Analysis and reports](../ANALYSIS.md).

## Connect your tools

| Task | Where | Guide |
| --- | --- | --- |
| Read the archive from an AI client | **Integrations → MCP** | [Scoped access and client setup](../MCP.md) |
| Recognize saved images or audio | **Recognize attachment** on a `media.saved` record | [Local OCR / transcription](../MEDIA-ANALYSIS.md) |
| Send events to another service | **Integrations → Outgoing webhooks** | [HMAC, retries and n8n](../WEBHOOKS.md) |

MCP is served at the panel's `/mcp` route. Choose a client, permitted tools,
workspaces and expiry in Integrations; copy the shown-once token and config.
**Check connection** reports the protocol and tools without reading messages.
Setup drafts survive background refreshes. Use `TGWITNESS_MCP_TOKEN` for the
`tgwitness.mcp_server` stdio bridge. The panel provides an exact install command
if the optional SDK is missing. [Installation and client setup](../MCP.md).

OCR/transcription needs the local Docker worker.
Webhook receivers verify the signature and deduplicate `event_id` before acting.

## Hand over the case

Save the analytical report beside the signed evidence ZIP. The report contains
your conclusions and source references; the ZIP contains the record to verify.
[Verification steps](Exports-and-Verification.md).
