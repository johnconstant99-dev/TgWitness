[TgWitness](../README.md) / [Documentation](README.md)

# Investigation mode

A workspace for documenting a conversation: what the investigator did, what
the other side answered, and a package a prosecutor can read and check. The mode
lives in the **Documentation** drawer of the panel, opened from **More tools → Documentation**
(from the main sidebar while a session is recording). The signed journal underneath
is unchanged; everything here cites it.

<details>
<summary>On this page</summary>

- [What the mode records](#what-the-mode-records)
- [Subject cards](#subject-cards)
- [Conversation plans](#conversation-plans)
- [Machine translation](#machine-translation)
- [Watchlists](#watchlists)
- [Online watch](#online-watch)
- [Codes in images](#codes-in-images)
- [What a client and an upload time show](#what-a-client-and-an-upload-time-show)
- [Cover and authority](#cover-and-authority)
- [Account control](#account-control)
- [Report settings](#report-settings)
- [Screen recording](#screen-recording)
- [Documents for court](#documents-for-court)
- [What stays out](#what-stays-out)

</details>

## What the mode records

Start a record for one or more chats. From then on every step writes itself:
panel actions, replies with the delay before them, edits, deletion notices,
pages opened in the isolated browser, searches, changes to the investigating
account, and AI drafts. Notes are added with `M` and carry labels: important,
conclusion, open question, **decision and rationale**, and the hiding labels
18+, obscene language, violence and personal data.

Hidden content is never cut. It is sealed with AES-256-GCM and the keys are
handed over separately, so a court copy stays complete while a shared copy does
not expose it.

Every step cites the journal record and its SHA-256. Fixing the document signs
it and writes the statement hash into the journal.

## Subject cards

When a record starts, and on demand from the chat divider, TgWitness takes a
profile snapshot of the bot, person, channel or group: display name, every
@username, the numeric ID, Telegram's own BOT, VERIFIED, SCAM and FAKE labels,
bio, bot description and commands, member count, creation date and the profile
photo. The card opens the report.

A later snapshot lists what changed since the previous one, which is how a
username or avatar swap mid-case becomes part of the record. Parts Telegram
refuses are listed as unavailable instead of being reported as a change.

## Conversation plans

A plan is what the investigator needs to obtain from one chat. Templates cover
the payment route, the infrastructure and the people behind it, or the plan can
start empty. Each goal is open, obtained or dropped and can cite journal records
as the evidence that closed it.

Prepared messages sit under the goals. Sending one is a normal panel action with
its usual confirmation and pacing. The plan marks a message as sent by the panel
receipt, by identical text, or by similar text when the operator edited the
wording before sending; a step can also be linked to a sent message by hand. The
basis for each match is shown, and a similar-text match displays what was
actually sent next to what was planned.

Reply times are measured passively from the message dates Telegram supplies.
There are no timers and nothing is sent on a schedule.

The plan also shows the other side's activity by hour and weekday in a chosen
time zone, the longest silences, and their writing style: alphabet, message
length, emoji, frequent words, whether they start lowercase or skip final
punctuation.

If an AI provider is configured, **Write in their style** drafts the next
message. Before anything leaves the workspace the panel shows the exact request,
the model and the endpoint, and asks for consent. Each generation is journaled
with the number of messages sent, the model and a hash of the request. A draft
becomes a message only when the investigator sends it, and a sent message that
matches a draft is marked in the report with the record number and the
similarity.

## Machine translation

Foreign-language messages can be translated through the configured AI provider.
The preview shows which messages leave the workspace. The translation appears
under the original, never replacing it, labelled with the source language,
target language, model and journal record. Messages already in the target
language are skipped. Hidden messages are never translated or shown.

## Watchlists

Lists of terms the investigator wants to hear about: a word or phrase, a
pattern, a wallet, a @username, a Telegram ID, a domain, a phone number or a
link. A list can be limited to chosen chats.

Matching covers message text and edits, the real target behind a hidden link,
bot button labels and their URLs, decoded codes from images, and recognised text
from OCR and transcription. Wallets and domains are compared after the same
normalisation the rest of the system uses, so a subdomain counts for its domain
and a TON address matches in any of its spellings. A word matches as a whole
word. Patterns that can hang on a long message are refused when they are added.

Scanning is incremental; adding a term offers a pass over everything saved so
far, and the same match is never recorded twice. Each match is a `watchlist.hit`
record pointing at the record it was found in, and appears in the report stating
that it is a term the investigator chose, not a finding about the author. A
short excerpt is stored only when the list asks for it. Lists can import and
export plain lines and raise alerts through the destinations already configured.

## Online watch

Accounts added by @username or numeric ID are checked on a chosen interval
between one minute and one hour. A username is resolved to the numeric ID once,
so a later rename does not break the watch. One batched request covers every
watched account.

Only changes are written unless the list is set to record every check. The watch
builds a pattern: states, time seen online by hour and weekday in a chosen time
zone, and recent online stretches.

Asking Telegram is an action by the investigating account and every check is
journaled. A person who hides last seen shows only a coarse state such as
*recently*, and an exact time of going offline is given only when they allow it.
Each check records the state Telegram showed at that moment.

## Codes in images

Saved images can be scanned for QR codes. A decoded payment code becomes a
wallet, an amount and a token tied to the message it arrived in. Reading codes
needs the optional extra `tgwitness[qr]`; without it the panel says so instead
of guessing.

Identifier extraction validates what it finds. EVM addresses are checked against
EIP-55 and an address with a broken checksum is not reported as a wallet. TON
addresses are reduced to their raw form so one account is one indicator. XRP
Ledger addresses are checksum-checked. Transaction hashes are recognised when
the chain is stated by the `0x` form or when the surrounding words make the
intent clear, otherwise they are left alone. Payment links are parsed for the
chain, amount and token, and for a token transfer the recipient is recorded,
not the token contract.

## What a client and an upload time show

Round videos and voice messages carry traces of the program that produced them:
the file name of a round video, its recording size, and the encoder named in the
OpusTags header of a voice message. The dossier counts which clients a person
appears to use. This is a guess from how the file was encoded, never a statement
by Telegram about someone's device, and a forwarded or re-uploaded file carries
the encoder of whoever made it first.

Telegram records when a file was uploaded to its servers and when the message
carrying it was sent. A gap of more than two minutes is reported with the exact
number of seconds, which is how a recording presented as live turns out to have
existed beforehand. It does not say who made the file.

Telegram also sends hints about the other side for a chat, including the month
the account was registered, the country of its phone number and the last time
the name or photo changed. These are recorded as Telegram states them. The hint
flags, such as the one about contact exceptions, are recorded too, with the note
that Telegram does not say why a hint appeared, so a flag on its own proves
nothing.

## Cover and authority

Personas describe the account as the other side sees it, who controls it and the
legend. Authorisations record the reference number, type, issuing authority,
validity period, the chats they cover and optionally the SHA-256 of the signed
paper.

From these the undercover activity record is built: the first contact in each
chat, the number of separate conversations under a configurable gap of 24 hours
by default, every outgoing message with the operator who requested it and
whether it came from an AI draft, and persona changes during the period.
Activity outside a validity period or outside the listed chats is flagged, as
are messages with no recorded operator and the absence of any authorisation.

TgWitness records and flags. It does not decide whether an authorisation was
required or sufficient.

## Account control

The **Account** tab of the drawer manages the investigating account by hand: first and last
name, @username, bio and profile photo, thirteen privacy settings grouped by
who sees the profile and who can reach it, and account-wide options such as
hiding read time.

Exceptions work as they do in Telegram: lists of people who are always or never
allowed, added by @username. Exceptions set elsewhere are kept untouched when a
setting changes; if one cannot be preserved, the setting is left alone and the
reason is shown.

Nothing reaches Telegram until the change bar is applied, and the confirmation
lists exactly what will change. Every change is journaled with the values before
and after and appears in the report.

The exposure check reads the privacy rules and the profile as Telegram returns
them to the account and changes nothing. It marks each setting that is wider than
the recommended value: last seen, phone number, finding the account by phone,
profile photos, bio, birthday, links in forwards, calls, peer-to-peer calls that
can reveal the IP address, and adding the account to groups. A public username, a
bio and the Premium badge are listed as notices. **Go offline right after each
panel action** sets the account offline after every action and journals the
result. Read receipts are never sent by the collector.

## Report settings

Presets cover a court copy, a short briefing and an internal copy, and each
section can be switched on or off: subject cards, notes, conclusions,
translations, journal references, indicators and the reading guide. Theme, time
zone, hash display, detail and screenshots are configurable.

The court preset cannot drop the reading guide or the journal references.

## Screen recording

When the isolated recorder is capturing the screen, each step and note keeps its
offset in the recording, and the report shows the moment next to the time. The
case package carries subtitles in WebVTT and SRT with step captions and notes,
so the recording can be played with the record beside it or burned in with
FFmpeg. A second recording takes over from its own start.

## Documents for court

The case package is a BagIt bag. Besides the report, the slides, the verification
page, the signed original, the files and the indicators, it carries a `court/`
folder:

- **Certification of authenticity**, pre-filled in the shape of a Rule
  902(13)/(14) certificate: the document and its revision, the signing key
  fingerprint, the observed period and time sources, the accounts and chats, the
  process in plain words, the SHA-256 of every file in the package, the
  disclosed limitations, and blank fields for the declarant. It states that a
  certification establishes authenticity only and that the adverse party must be
  given notice. The declarant reviews and completes the template before signing.
- **Exhibit index**, numbering every cited file with its hash, size, type, the
  steps that cite it and their journal records, as CSV and HTML.
- **Annex for official requests**: numeric IDs, usernames with the times they
  were observed, Telegram's labels, and message references, with notes on the
  data categories a provider is usually asked for and on Telegram's published
  disclosure scope.
- **Undercover activity record**, when there are personas, authorisations or
  outgoing messages.

Hidden content never reaches any of these files.

## What stays out

Investigation mode is off under the **Evidence for a case** goal, where the
workspace stays a witness and performs no Telegram actions. Conversation plans,
watchlists, the online watch and translation refuse to run there.

Scoped access sees only its chats. Account-wide records, including the
investigating account's own changes, are not shown to an access limited to
chosen chats.
