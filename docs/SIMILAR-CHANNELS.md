[TgWitness](../README.md) / [Documentation](README.md) · [Investigation](INVESTIGATION.md)

![Investigation](assets/presentation/chapter-investigate.svg)

# Similar channels

Telegram keeps a list of channels it considers similar to a given channel and
offers it to readers. TgWitness can walk that list from one or more starting
channels and record what Telegram returned.

A suggestion is produced by Telegram from its own usage signals. Treat the result
as a lead list: a shared operator, owner, author or purpose is established from
the channels' own records.

## Run a walk

```sh
curl -sS -X POST http://127.0.0.1:8000/api/channel-graph \
  -H "Authorization: Bearer $TGWITNESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"seeds": [-1001234567890], "depth": 2, "per_source": 20, "total": 100,
       "min_participants": 500, "require_username": true, "pause_seconds": 1}'
```

Only the main administrator can start a walk, and the account must be connected.
Each seed must be a chat this account has already read, so resolve the channel in
the panel first.

| Setting | Meaning | Range |
| --- | --- | --- |
| `seeds` | Channels the walk starts from | 1–50 chat IDs |
| `depth` | How many suggestion steps to follow; `1` reads the seeds only | 0–4 |
| `per_source` | Suggestions kept from one channel | 1–200 |
| `total` | Channels in the whole result, including the seeds | 1–2000 |
| `min_participants`, `max_participants` | Subscriber range to keep | any order-consistent pair |
| `require_username` | Drop channels without a public username | off by default |
| `skip_restricted` | Drop channels Telegram marks as restricted | off by default |
| `pause_seconds` | Wait between requests | 0–60 |

Filters shape the result, not the record: the journal keeps every channel
Telegram suggested and reports how many were dropped and why.

## What the journal keeps

`graph.started` records the seeds and the settings. One `graph.suggestions`
record per visited channel holds what Telegram returned, how many were kept and
the channel IDs and usernames. `graph.source_unavailable` marks a seed the
account cannot read. `graph.finished` closes the run with the totals and the
reason it stopped.

A walk stops early and says so when it reaches `total`, or when Telegram asks the
account to wait. A flood-wait answer is recorded as `telegram.backoff`, the
account-wide pause is honoured, and `stopped` reads `rpc_backoff`.

## Result

The answer is a `tgwitness-channel-graph-v1` object with `nodes` (chat ID, title,
username, subscriber count, Telegram flags, discovery depth and source) and
`edges` (which channel suggested which). Each node keeps the flags Telegram
supplied, including `scam`, `fake`, `verified` and `restricted`.
