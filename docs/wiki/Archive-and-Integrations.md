# Work the archive

**Find the message. Check the source. Build the case.**

[Interactive guide](https://phishdestroy.github.io/TgWitness/docs/archive/) · [Investigations](Investigations.md) · [Export and verify](Exports-and-Verification.md)

## Bring in the history

**More tools → Sources → Chats in scope**: check the enabled chats, pause observation, hit **Load full
history**. Pause and resume whenever, after a restart resume by hand. Check sources and the
download queue, keep the signed progress report. [History guide](../HISTORY.md).

## Search and review

**Journal** searches saved records locally, filter by source, event type or period. Open the
records behind the hits. **Best match · word forms** ranks results and finds other forms of a
word, exact phrases, domains in hidden links and buttons, @usernames, and Chinese without spaces
(preview). [Full-text search](../SEARCH.md).

For AI, set up a provider in **More tools → Integrations** and open **More tools → Ask the archive**. Pick chats and a
period, look at **Data sent to the model**, drop what you don't want sent, approve. Check the
citations before saving a report. Your notes never mix with captured events.
[Analysis and reports](../ANALYSIS.md).

## Connect your tools

| Task | Where | Guide |
| --- | --- | --- |
| Read the archive from an AI client | **More tools → Integrations → MCP** | [Scoped access and client setup](../MCP.md) |
| Search, count or export from scripts and agents | `tgwitness search`, `stats`, `export` | [Command line](../CLI.md) (preview) |
| Recognize saved images or audio | **Recognize attachment** on a `media.saved` record | [Local OCR / transcription](../MEDIA-ANALYSIS.md) |
| Send events to another service | **More tools → Integrations → Outgoing webhooks** | [HMAC, retries and n8n](../WEBHOOKS.md) |

MCP lives at the panel's `/mcp`. In Integrations pick the client, tools, workspaces and
expiry, copy the token and config (shown once). **Check connection** lists tools without
reading messages. For the stdio bridge `tgwitness.mcp_server` use `TGWITNESS_MCP_TOKEN`; if
the SDK is missing the panel shows the install command. [Client setup](../MCP.md).

The same token works with the command line: set `TGWITNESS_URL` and `TGWITNESS_MCP_TOKEN`, then run
`tgwitness search … --json`. With collection stopped, `--data-dir` reads the workspace directly.
Only the command line can export messages, and only with a connection that allows it.
[Command line](../CLI.md).

OCR/transcription needs the local Docker worker. Webhook receivers should check the
signature and dedupe on `event_id`.

## Hand over the case

Put the analysis report next to the signed ZIP. The report is your conclusions with
references, the ZIP is what gets verified. [Verification steps](Exports-and-Verification.md).
