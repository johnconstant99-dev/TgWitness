# Self-destructing media in the API journal

The API collector saves available photos，videos，voice messages and files with
`ttl_seconds` through a dedicated priority-zero worker．It starts independently
of ordinary attachments and the messages-first history setting．The default
**Include self-destructing media from excluded types** setting bypasses type and duration
exclusions，while retaining configured file-size ceilings，disk reserves，serial
Telegram RPCs and full FloodWait deadlines．It does not turn metadata-only or
hash-only capture into a file download．Turn the setting off to apply ordinary
type rules．

The signed message observation retains the original Telegram media descriptor，
TTL and availability．A positive TTL is distinguished from Telegram's
`0x7FFFFFFF` view-once value；a chat's `ttl_period` is an auto-delete setting，
not evidence of a view-once attachment．The saved file is content-addressed by
SHA-256，with its size and reference to the signed message observation．

- `media.saved` with `ephemeral_media.outcome=saved` means bytes were preserved．
- An absent or empty photo／document with a positive TTL produces `media.skipped`
  with `outcome=unavailable` and `availability=unavailable_at_observation`．This
  records the self-destructing-media marker supplied by Telegram，not why the
  file disappeared or whether anyone viewed it．
- Policy exclusions，unknown／excessive size，download errors and cancellation
  retain an explicit not-saved outcome and a warning that another chance is
  not guaranteed．Transient failures retain the normal retry outcome．
- Offline intervals remain `coverage.gap` records．They do not invent unseen
  media，its content or its time of delivery．

Downloads use the original observed descriptor without an initial message
recheck．If Telegram rejects an expired file reference，a refresh must identify
the same attachment；an absent or changed attachment is never substituted．

The API client's request boundary rejects message-history，message-content，
discussion，mention，reaction and story read acknowledgments，including wrapped
and batched requests．This does not control another signed-in device or the
official Web／Desktop client．Neither a preserved file nor the absence of a
collector read receipt proves that the human recipient viewed or did not view
it．Reports explicitly retain that distinction．

This priority worker belongs to live monitoring and the single-chat journal．
Account-wide exports retain their separate configured attachment processing；
official-client capture remains limited to what the official UI exposes．
No mode guarantees retrieval after Telegram makes media unavailable．

Telegram documents the independent [content read acknowledgment](https://core.telegram.org/method/messages.readMessageContents)
and [history read acknowledgment](https://core.telegram.org/method/messages.readHistory)，
and the optional media／TTL fields for [photos](https://core.telegram.org/constructor/messageMediaPhoto)
and [documents](https://core.telegram.org/constructor/messageMediaDocument)．
