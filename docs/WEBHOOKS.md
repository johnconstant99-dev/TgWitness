# Structured outgoing webhooks

**Current main:** use a source checkout; the 0.7.0 portable preview predates this feature.

[Workflow guide](https://phishdestroy.github.io/TgWitness/docs/archive/) · [Wiki](wiki/Archive-and-Integrations.md)

Open **Integrations → Outgoing webhooks** in the selected workspace. Add an HTTPS
receiver, choose collector/media/export events, and optionally select chats for
new observations and changes. Message text is off by default. Enabling excerpts
adds at most 1,000 characters to message-change events; raw Telegram fields and
credentials are never sent.

Copy the HMAC secret once into the receiver's protected configuration. It is
encrypted in TgWitness's vault and cannot be retrieved from the panel. Remove
and recreate a destination to rotate it. **Send synthetic test** queues a test
with no chat content; refresh delivery status to see its outcome.

Delivery extends the existing notification loop alongside Apprise. It uses the
workspace's outside route and existing private-destination restrictions. There
is no direct fallback or redirect following. URLs must not contain credentials,
query strings or fragments; private addresses require the server-level network
opt-in, not a setting a panel user can bypass.

## Payload and signature

Schema: [`tgwitness.webhook/1`](../integrations/webhook.schema.json). Every payload
contains `event_id`, `timestamp`, `workspace`, `type`, `synthetic`, and counters.
Journal-based events include their sequence and hash. Full-export completion and
synthetic tests are delivery events, with no invented signed journal reference.
Telegram deletion notices and `missing_on_recheck` remain distinct types.

The `X-TgWitness-Signature` header is `t=UNIX_SECONDS,v1=HEX_HMAC_SHA256`.
Compute HMAC over the exact bytes `timestamp + "." + raw_request_body`, using
the displayed secret as UTF-8 bytes. Compare signatures in constant time before
parsing or acting on the body. Reject timestamps more than five minutes from
your clock. The timestamp is refreshed on each delivery attempt.

Use `event_id` as an idempotency key in durable storage, with an atomic unique
constraint before side effects. A valid signature alone does not prevent a
recent request from being replayed. Keep processed IDs for at least the entire
retry window; retain them longer if the receiver can reprocess stored events.

## Retries

Deliveries are queued durably before HTTP requests. They use at-least-once
semantics: a lost acknowledgement or restart may deliver an event again with the
same ID. There are eight attempts with exponential backoff, starting at 15
seconds and capped at one hour. Success requires a 2xx response. Exhausted jobs
leave a visible error; delivery is not guaranteed after retries end.

The queue holds 1,000 deliveries. When full, scanning journal events pauses and
resumes after space is available. A full-export completion that cannot be queued
sets a visible queue error. Up to five deliveries are attempted per notification
pass, and the latest 100 attempt records are retained. Removing a destination
also removes its pending deliveries.

## n8n example

Import [the example workflow](../integrations/n8n-tgwitness.json). It is inactive
and contains no secrets or downstream actions. Set `TGWITNESS_WEBHOOK_SECRET` in
the n8n worker environment, allow that environment access, and allow the `crypto`
builtin for the Code node. The example uses the Webhook node's raw-body option,
checks signature/freshness, and acknowledges validated events. This matches
the node's [documented implementation](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/Webhook/Webhook.node.ts).

Before adding SIEM writes or notifications, add durable idempotency storage
keyed by `event_id`. Restrict n8n workflow editing and execution-log retention
according to the data you elected to send. TgWitness adds no inbound commands.
