# Follow the message. Understand the evidence.

TgWitness preserves what a collecting account observed, links those observations
into a signed journal and lets another person verify an export against a trusted
key and an earlier retained checkpoint.

The [local documentation website](internal/PUBLISHING.md#preview-the-website-locally) adds
interactive examples at `/docs/concepts/`, a checkpoint decision explorer at
`/docs/witness/`. All example messages,
counts and delays are fictional. Hashes in the chain sandbox are calculated with
SHA-256 in the browser. Nothing is sent to Telegram.

## A message changes; observations accumulate

```mermaid
sequenceDiagram
    participant T as Telegram
    participant C as Collector
    participant J as Signed journal
    T->>C: New message: Meet at 10:00
    C->>J: Append message.new
    T->>C: Edit: Meet at 11:00
    C->>J: Append message.edited
    T->>C: Deletion notice
    C->>J: Append message.deleted
    Note over J: Original + edit + deletion observation remain
```

This simplified sequence assumes Telegram delivered each update and the selected
account could see it. Operational events also share the journal. A deletion notice
does not supply the deleter or an exact deletion time. Repeated deliveries are
separate observations; there is no journal-wide duplicate suppression.

## What a hash covers

![Observe, encode, hash and sign: each new event includes the preceding hash.](assets/presentation/evidence-chain-animated.svg)

Read the formula from the inside out: **C** turns the nine fields into exact bytes;
**SHA-256** produces their digest; **hex** is how that digest is stored. The previous
hash is already inside the event. **unhex** turns the stored hash back into the 32
bytes that Ed25519 signs.

[Static chain diagram](assets/presentation/evidence-chain-static.svg)

Let $C(e_i)$ be the canonical UTF-8 JSON of the nine event fields. The first
`previous_hash` is 64 zero characters. Each later record includes the preceding
record's hexadecimal hash:

$$
h_i = \operatorname{hex}(\operatorname{SHA256}(C(e_i)))
$$

$$
\sigma_i = \operatorname{Ed25519.Sign}(sk,\operatorname{unhex}(h_i))
$$

The signature covers the 32 raw digest bytes. The hash input contains exactly
`seq`, `observed_at`, `source_at`, `kind`, `chat_id`, `message_id`, `actor_id`,
`payload` and `previous_hash`. Object keys are sorted; whitespace and ASCII
escaping are omitted; NaN and infinity are rejected. See the
[exact encoding](EVIDENCE.md#event-canonicalization).

```mermaid
flowchart LR
    Z[64 zero characters] --> A[Record 1 / hash h1]
    A --> B[Record 2 includes h1 / hash h2]
    B --> C[Record 3 includes h2 / hash h3]
    C -. retain elsewhere .-> W[Signed checkpoint: count 3, head h3]
```

| Change to the supplied journal | What detects it |
| --- | --- |
| Alter record 2 while leaving its saved hash | Recomputed event hash differs; its signature no longer covers the changed event |
| Rebuild the altered record and every later hash | The original signatures fail; a retained checkpoint at the affected boundary also disagrees |
| Remove the tail but keep the remaining prefix intact | An earlier retained checkpoint beyond the supplied prefix reveals that the export is too short |
| Re-sign a replacement journal with another key | A separately trusted key fingerprint rejects the replacement identity |

![Changing a saved field changes its digest; rebuilding hashes does not restore the original signatures.](assets/presentation/evidence-tamper-animated.svg)

**Try the logic on record 2:** change `Meet at 11:00` to `Meet at 12:00` in the
saved event. Its recomputed hash no longer matches. Recalculating the later chain
can repair its links, but cannot make the original signatures cover the new digests.
An observed Telegram edit, by contrast, becomes a new journal record.

[Static change diagram](assets/presentation/evidence-tamper-static.svg)

Hash links alone do not prevent someone from recalculating a replacement chain.
Trust comes from checking signatures under an independently trusted key and
comparing with references retained outside the collector.

## What an earlier checkpoint adds

![Retain count 3 and head h3; a later export of 4 records is checked at position 3.](assets/presentation/evidence-checkpoint-animated.svg)

**The reference stays still while the journal grows.** If the checkpoint says
“3 records, head h3”, a four-record export can pass by matching h3 at position 3.
Its newest head is h4, which is expected to differ. An export of only two records fails.

[Static checkpoint diagram](assets/presentation/evidence-checkpoint-static.svg)

After verifying the checkpoint signature, require:

$$
N_{\mathrm{export}} \ge N_{\mathrm{checkpoint}}
\qquad\text{and}\qquad
h_{\mathrm{export}}[N_{\mathrm{checkpoint}}] = H_{\mathrm{checkpoint}}
$$

An export may extend beyond a checkpoint. It must agree at the retained boundary.
The real verifier also checks every event's sequence, previous link, hash and
signature. Comparing only the final stored head would miss an altered interior
record whose saved hash was not updated.

## Where a witness belongs

```mermaid
flowchart LR
    subgraph A[Host A]
        C[Collector / account session / key A]
        E[Read-only checkpoint endpoint]
        C --> E
    end
    subgraph B[Host B]
        W[Witness / pinned collector key / own key B]
        J[Separate signed witness journal]
        W --> J
    end
    W -->|Request a check| E
    E -->|Signed answer| W
    W -->|Bot API / own token| T[Channel with signed TGW1 posts]
```

The witness records rollback, a different head at the same count, changed keys,
invalid answers and missing responses. A larger count alone does not establish
that every earlier record remains unchanged; compare the export with retained
checkpoints. A witness on another host avoids sharing the collector's host outage;
a separate operator gives additional independence.

The witness attests to the collector's reported journal state. It does not
independently observe all Telegram messages. See [witness setup](WITNESS.md).

## Test delivery against known actions

Use a controlled group, distinct collecting accounts and a fresh marker. Send,
edit and delete deliberately, checking capture between stages. Define the expected
actions and a cutoff before inspecting the results.

$$
R = \frac{|\mathrm{observed}\cap\mathrm{expected}|}{|\mathrm{expected}|}
\qquad\qquad
\Delta t = t_{\mathrm{receipt}} - t_{\mathrm{action}}
$$

Only matched expected actions count; duplicate receipts do not increase the
numerator. The denominator must be nonzero. A missing receipt has no measured
delay. Document clock uncertainty; use your own controlled deletion action time,
because Telegram does not provide the exact deletion time. A result such as 5/6
(83.3%) describes the test actions, not the completeness of all Telegram traffic.

## Pick a workflow

The [complete investigation walkthrough](INVESTIGATION.md) follows an incident
across a channel, group, bot and private chat:

1. Enable whole-account Investigation mode and inventory every accessible chat.
2. Acquire journal snapshots, per-chat full history and preserved attachments.
3. Keep live changes and any deliberate panel interactions with their receipts.
4. Follow numeric sender IDs, reply relationships, repeated destinations and file
   hashes through cited records and people profiles.
5. Reconstruct a cross-chat timeline with both timestamps and explicit gaps.
6. Compare other account workspaces while keeping their origins and keys separate.
7. Assemble and verify the signed journals, profiles and history exports with case notes.

The website's `/docs/cases/` guide includes an interactive case map and variants
for bot disputes, removed messages and participants changing names. Case notes
and cross-workspace analysis are external; the application does not automatically
generate a global investigation graph or a merged case archive.

[Completed validation and remaining work](VERIFICATION.md) ·
[Export and verify](EVIDENCE.md#investigation-handoff) ·
[Start with one account](QUICKSTART.md)
