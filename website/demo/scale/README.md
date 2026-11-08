# Collection measurements

This renderer displays signed progress receipts supplied through `run.json` or
`window.TGWITNESS_RUN` in `run-data.js`. File previews use the embedded snapshot.
No measurement data is included. Public datasets contain aggregate counters and
checkpoints, without message text, source IDs or account identifiers.
`window.TGWITNESS_CAMPAIGN` adds a signed total with each run's final receipt;
individual durations and rates remain separate.

Set `window.TGWITNESS_RECORDED = true` in `run-data.js` for a historical dataset.
It loads the embedded receipts without requesting `run.json` or starting polling.
Without this flag, HTTP previews retain the existing periodic refresh behavior.

The timeline selects actual signed samples and updates counters, worker states
and the linked receipt hash together. Replay uses original sample times at the
chosen playback speed; displayed throughput always uses the original duration.
Counts are not interpolated. Reduced-motion mode keeps manual timeline controls.
Interval throughput is the message delta divided by the measured time delta;
the average divides messages by elapsed time from the start. Journal events are
counted separately. Worker-state bars show up to 160 actual samples at their
recorded times; states between samples are unknown. Workers are not account IDs.

The browser verifies receipt signatures and supplied journal checkpoints.
The supplied signing keys identify the measurement. Review the stated workload,
acquisition intervals and linked verification records with those results. The browser does
not replay private journals. Missing deletion statistics remain unavailable.

`window.TGWITNESS_VERIFICATION_PACK` or `run.verification_pack` may supply a signed
envelope with `statement_json`, `statement`, `public_key`, `signature` and `sha256`.
Its statement uses `tgwitness-scale-verification-pack-v1`, `receipt_chain_head`,
`campaign_receipt_sha256` (null for a single run), `filename`, `bytes` and `sha256`.
The download is enabled only after receipt and metadata verification, using the
run's supplied key. The filename must be a ZIP basename in the same directory.
The displayed archive hash lets the recipient check the downloaded bytes.

Keep operational receipts and source messages outside the repository. Public
examples must use fictional data. Keep synthetic browser regressions in the
private validation workspace and run them in an authorized test environment.
