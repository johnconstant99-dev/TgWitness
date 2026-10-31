# Load available history into the workspace

**Unreleased:** available on the history acquisition development branch, after 0.7.0.

In **Sources**, review the enabled chats, start observation, then choose **Load full
history**. The run fixes that list of sources and reads their available past messages
into Chats and the signed observation journal. Media uses the existing attachment
settings and durable download queue. This is separate from the per-chat signed
JSON/HTML export.

For account-wide collection, select **Whole account**, start observation to load its
source list, and review that list before starting history. The dialog-list limit still
applies (1,000 by default, adjustable in Parameters). A successful run does not prove
that every account dialog was listed. Chats discovered or enabled later need another run.

## Pause, restart and partial results

- **Pause history** stops reading. **Continue history** resumes from the last committed
  message in each source; restarting the app also leaves the run paused until resumed.
  Restart observation first. Resuming requires the same Telegram account.
- The message observation, attachment job and cursor commit in one transaction.
  A resumed run does not repeat its already committed observations. Live capture or
  a separate, explicitly started run may independently observe the same message.
- Each source fixes an upper message ID on its first read. Newer messages belong to
  live observation, not to that source's remaining historical pages.
- Inaccessible sources and sources disabled during acquisition remain visible as
  failed or skipped. Other sources continue; the overall result is incomplete.
- FloodWait delays respect the saved account backoff. Transport timeouts and low disk
  space pause the run with its cursor intact. Resume after resolving the cause.
- **End this history run** preserves saved observations. It does not remove them or
  cancel already queued attachment downloads. A new run reads enabled sources anew.

History completion describes history reads only. Attachments may remain pending,
fail, or be excluded by the configured policy. Check media receipts in the journal
and the attachment queue; only a completed receipt with preserved bytes constitutes
a saved attachment. The history operation is an explicit snapshot request and is
separate from switches that select categories of future live events.

## Transfer and verify

Save the **signed progress report**, then use **Export evidence** to download the
journal and saved attachments. A later evidence export may include additional records;
the report binds its counters to the journal prefix at the time it was created.
Run the verifier from a trusted checkout of this version:

```sh
python tgwitness/verify.py tgwitness-history-report.json --evidence evidence.zip --fingerprint TRUSTED_FINGERPRINT
```

Keep the expected signing-key fingerprint independently. The verifier checks the
report signature, the evidence archive, the report checkpoint, source plan, account
and counts of saved/unavailable messages. Without `--evidence`, it checks only the
signed report and its internal consistency. Progress phases, titles, cursors and
attachment summaries are signed collector statements, not independently reconstructed
by this report checker. The evidence verifier still checks the archived media bytes.

Neither signing nor finishing the available history proves Telegram origin, an atomic
snapshot, or historical completeness. Messages can change while reading; deleted
messages, unseen intermediate edits and Secret Chats are not recovered. An operator
controlling the signing key can fabricate a journal before outside commitments exist.
Use separately retained checkpoints or an independent witness for the documented
tamper-detection properties.

The acquisition cursor is local workspace state. Restoring an evidence ZIP alone does
not restore a pending acquisition job or Telegram session. Keep the workspace backup
if continuation of the original job is required.
