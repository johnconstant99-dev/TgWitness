# Archive analysis

Open **Ask the archive** in the panel. The workspace selector chooses the account;
the form chooses chats and the observation period. Search runs locally, without
AI. An exact phrase or domain narrows retrieval; a message ID requests saved
versions. Review the returned excerpts and open their journal records or context.
There is no vector database or automatic Telegram action.

## Providers and consent

AI starts disabled in every workspace. Only the main administrator can configure
the model, endpoint, encrypted API key, context/output limits, timeout and daily
request budget. The key is never returned to the browser. Keep a blank key field
to retain the current key, or explicitly remove it.

Ollama uses its documented [`/api/chat` endpoint](https://docs.ollama.com/api/chat)
with non-streaming JSON output. Its default address is `http://127.0.0.1:11434` on
the TgWitness server. The operator can change it using
`TGWITNESS_AI_LOCAL_ENDPOINT`; this is not a model-controlled address. Install
the selected model yourself. TgWitness does not download it automatically.

The compatible provider expects a base URL ending in `/v1` and the
[Chat Completions protocol](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create):
`messages`, JSON response mode, `max_completion_tokens`, and
`choices[0].message.content`. Services lacking these fields are not supported.
Connection testing sends synthetic text and counts toward the request budget.

Every request uses the workspace's configured outside route. A blocked route or
Telegram-only MTProxy is an error; there is no direct retry. A deliberately
configured local Ollama address permits a private destination, while still using
the chosen route. For other private services the existing server-level private
destination opt-in applies. The panel displays the actual configured endpoint.

Before generation, **Data sent to the model** shows the request: question,
checked excerpts, event kinds, observation times and coverage markers. Telegram
sessions, raw fields, provider keys, attachment bytes and the full journal are
not part of that context. Uncheck unwanted sources, then explicitly approve
processing. External providers may retain submitted content under their own
policies. Local execution means the endpoint is local; it is not a guarantee
about an independently configured service's behavior.

There are at most two concurrent provider requests globally and one per
workspace. A preview expires after ten minutes and can generate one answer.
The provider's reported token counts are shown; a cost estimate appears only
when both input and output tariffs have been configured. Failed attempts also
consume the daily request budget. No automatic retries spend additional budget.

## Sources and limits

Retrieval examines saved message text with a bounded lexical search. It returns
up to 24 sources and marks truncated excerpts or incomplete result sets. The
period refers to **observation time**, not a claim that Telegram history is
complete. Workspace-wide coverage events are withheld from chat-scoped access.
Missing data is described as not found in the available archive.

The model receives no tools. Its source IDs are resolved against the selected
records, hashes are rechecked, and quoted strings must occur in those records.
Unknown IDs, changed quotes and uncited claims reject the answer. The application
creates links; model-generated URLs are not used as citations. These checks
establish source existence and quote accuracy, not the truth of an inference.
Review inferences against the records before relying on them.

## Reports

Save a reviewed answer as a separate analytical report. It includes the model
summary, observed chronology, extracted links and handles, edit/deletion records,
coverage limits, and source event hashes. The provider, model, endpoint, time and
prompt-template version accompany it. No identities are automatically merged.

Analyst revisions and notes are stored separately from the model summary. Reports
live in encrypted derived files, with an index outside the signed event stream;
the original events and media do not change. Only the owner or administrator can
open a report, and source access is checked again. Download also requires export
permission. Version 1 does not sign reports or imply that model conclusions are
verified evidence. Limits: 100 reports per workspace and 100 analyst revisions
per report.

For manual OCR and transcripts, see [media processing](MEDIA-ANALYSIS.md).
For client access, see [MCP](MCP.md).
