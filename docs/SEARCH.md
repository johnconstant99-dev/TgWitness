[TgWitness](../README.md) / [Documentation](README.md) · [Investigation](INVESTIGATION.md)

![Investigation](assets/presentation/chapter-investigate.svg)

# Full-text search

[Archive analysis](ANALYSIS.md) · [Local OCR and transcription](MEDIA-ANALYSIS.md) · [Wiki](wiki/Archive-and-Integrations.md)

**Preview.** In **Journal**, choose **Best match · word forms** next to the search
field. Results are ranked with BM25 and match other forms of the same word:
*перевод* finds *переводом* and *переводы*, *transfer* finds *transfers*, a Chinese
phrase is found without spaces. **Newest first · exact text** keeps the previous
substring search over the whole record.

The index is derived data. It is rebuilt from the signed journal, is never signed
itself and never enters an export. The original records do not change.

<details>
<summary>On this page</summary>

- [Search syntax](#search-syntax)
- [Languages](#languages)
- [Where the index lives](#where-the-index-lives)
- [Results and the signed journal](#results-and-the-signed-journal)
- [Recognized text](#recognized-text)
- [Access](#access)
- [Ask the archive and MCP](#ask-the-archive-and-mcp)
- [Dependencies](#dependencies)
- [Benchmark](#benchmark)

</details>

## Search syntax

| Write | Finds |
| --- | --- |
| `перевод карта` | Records containing both words, in any form |
| `"переводом на карту"` | The exact phrase, in this order |
| `бонус OR подарок` | Either word |
| `перевод -казино` | Records without the excluded word |
| `example.com` | The domain and its subdomains, also in hidden links and button URLs |
| `@username`, `t.me/username` | Mentions and links of the account, and messages it sent |
| `#tag` | The hashtag |
| `+79991234567`, a wallet address, an e-mail address | The same value in text or links |
| `from:@username`, `from:123456` | Messages from that sender |
| `chat:-1001234567890` | One chat; it can only narrow your own access |
| `id:42` | Saved versions of message 42 |
| `since:2026-01-01 until:2026-01-31` | Observation period; a date without a time covers the whole day |
| `kind:edited` | Only edits (`new`, `snapshot`, `edited`, `recovered`) |
| `source:ocr`, `source:transcription`, `source:all` | Recognized text instead of, or with, messages |

Prepositions and other function words are ignored when other words are present.
Look-alike letters mixed into a word (a Latin *a* inside a Cyrillic word), fullwidth
and decorative Unicode letters and invisible characters are normalized.

## Languages

The language is detected per record from its script and letters:

| Script | Matching |
| --- | --- |
| Cyrillic | Russian and Ukrainian lemmas with [pymorphy3](https://github.com/no-plagiarism/pymorphy3). Without the optional Ukrainian dictionary a light Ukrainian stemmer is used |
| Latin | English Snowball stemmer; diacritics are ignored |
| Chinese, Japanese, Korean, Thai, Lao, Khmer, Myanmar | Overlapping character pairs: any phrase is found without spaces. Chinese queries are split into words with jieba |
| Other scripts | Exact words |

The Ukrainian dictionary (`pymorphy3-dicts-uk`) is distributed under GPL-3.0, so it is
not installed by default. Install it with `pip install "tgwitness[uk-dictionary]"`;
the index notices the new analyzer and rebuilds itself.

## Where the index lives

| Mode | Storage | Use |
| --- | --- | --- |
| On disk (default) | `search/fulltext.sqlite3` in the workspace directory | Large archives; survives restarts |
| In memory only | Nothing on disk; rebuilt at every start | No derived copy of message text on disk |
| Off | No index; **Newest first · exact text** remains | Minimal installations |

The main administrator chooses the mode under **Journal → Filters → Search index**
for each workspace. `TGWITNESS_FULLTEXT=disk|memory|off` sets the default for
workspaces without their own choice. Switching to memory or off deletes the file.
The index file has the same protection as the journal: it sits in the private data
directory. Backups and off-site copies leave it out.

New records are indexed in the background within seconds; a search also indexes a
short backlog first, so a record saved a moment ago is found. An existing journal is
indexed after the update without blocking the panel; until then, results cover the
indexed records and the journal shows the progress. **Rebuild index** starts again
from the first record.

```sh
python -m tgwitness index status --data-dir data/live
python -m tgwitness index rebuild --data-dir data/live --json
```

`rebuild` needs the panel to be stopped (exit code 3 otherwise). With `--json`,
standard output carries only the result; progress goes to standard error.

## Results and the signed journal

The index stores the sequence number and hash of the last journal record it covers
and checks them against the journal when it opens. A replaced, restored or edited
journal causes a rebuild. Every response reports this position, and every hit is
read back from the signed journal by its sequence number: the index decides which
records to show and in what order, never their content. Chat access is applied to
the journal's own chat field, not to index content.

## Recognized text

OCR and transcripts stay in their encrypted artifacts. Their index exists only in
memory and is rebuilt when a recognition job completes. A hit appears on its
`media.saved` record, labelled as machine recognition with the engine, model and an
excerpt; it is never presented as text sent in Telegram. The same index serves
**Search recognized text**, which still also matches plain substrings.

## Access

Chat-scoped access finds only records from its chats, including recognized text of
their attachments. `chat:` and other filters can only narrow that set. Index status
shown to scoped access omits journal totals. Only the main administrator can change
the mode or rebuild the index.

## Ask the archive and MCP

**More tools → Ask the archive** retrieves its sources from this index when it is complete: the
best matches across the selected chats, with a saved text counted once. Up to 24
sources are sent; long texts are cut around their match and marked as truncated.
Questions about recent changes, saved versions of one message, and searches while
the index is still building use the previous chronological retrieval. The preview
shows which method was used.

MCP clients can call `search_messages` with `ranked=true` and page with
`next_offset`. Scoped connections receive only their chats.

Ranked pagination covers at most the first 1,000 results, regardless of page size. Narrow the query, chat or period to inspect further matches. Newest-first searches order messages, OCR and transcription results before selecting each page.

## Dependencies

| Package | Licence | Why |
| --- | --- | --- |
| pymorphy3, pymorphy3-dicts-ru, DAWG2-Python | MIT | Russian and Ukrainian lemmas; dictionaries are loaded locally |
| snowballstemmer | BSD-3-Clause | English stems, pure Python |
| jieba | MIT | Chinese query segmentation, pure Python (source distribution only) |
| pymorphy3-dicts-uk (optional) | GPL-3.0 | Full Ukrainian dictionary |

SQLite FTS5 with the `unicode61` tokenizer is required; it is part of the SQLite in
current Python builds. Without it, best-match search reports that it is unavailable.

## Benchmark

`python tools/bench_fulltext.py --messages 1000000 --work <empty directory>`
creates a deterministic signed journal of mixed Russian, Ukrainian, English,
Chinese and Japanese messages with links and handles in 200 chats, builds the index
and times typical searches (50 results, median of 7 runs).

Measured on Windows 11, Intel Core i9-13900K, 128 GB RAM, Python 3.12.10, SQLite
3.49.1, data on an exFAT drive, analyzer `fulltext-v1+pymorphy3-ru+light-uk+snowball-en`:

| Measure | Result |
| --- | --- |
| Signed journal | 1,000,000 messages, 1.50 GiB, written in 19 minutes |
| Index build from the journal | 71 s, about 14,141 messages per second |
| Index file | 58 MiB, 3.8% of the journal |
| Search right after a new record | 8 ms median, 9 ms p95 |
| Previous substring search, same journal | `перевод` 3.2 s, `银行转账` 2.6 s, `verify-account.example` 2.6 s |

| Search | Matching records | Best match, median | p95 | Newest first, median |
| --- | --- | ---: | ---: | ---: |
| Common word, word forms: `перевод` | 134,403 | 82 ms | 85 ms | 7 ms |
| Two words: `оплата карта` | 28,996 | 43 ms | 43 ms | 14 ms |
| Rare word: `розыгрыш подарок` | 28,881 | 42 ms | 47 ms | 13 ms |
| Exact phrase: `"переказ коштів на картку"` | not counted | 35 ms | 36 ms | 6 ms |
| Domain with subdomains: `verify-account.example` | 12,435 | 17 ms | 17 ms | 3 ms |
| @username: `@support_desk_bot` | 10,331 | 15 ms | 16 ms | 3 ms |
| Chinese without spaces: `银行转账` | 17,691 | 23 ms | 24 ms | 3 ms |
| Japanese: `リンク` | 16,603 | 23 ms | 25 ms | 3 ms |
| English stem: `withdrawal` | 27,775 | 26 ms | 26 ms | 2 ms |
| OR and exclusion: `бонус OR подарок -казино` | 268,034 | 190 ms | 193 ms | 19 ms |
| Chat filter: `chat:-1000000000007 перевод` | 652 | 9 ms | 9 ms | 6 ms |
| Period filter: `since:2026-01-01 until:2026-01-31 выплата` | 115,732 | 155 ms | 156 ms | 81 ms |

An exact phrase is checked literally on candidates in rank order until the page is
full, so its total is not counted. Times grow with the number of matching records;
narrowing the chat or period makes broad searches faster. The synthetic corpus repeats
a small vocabulary, so common words match far more records than in real chats.
