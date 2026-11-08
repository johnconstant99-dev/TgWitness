# Collection measurements

This renderer displays signed progress receipts supplied through `run.json` or
`window.TGWITNESS_RUN` in `run-data.js`. File previews use the embedded snapshot.
Optional excerpts use `window.TGWITNESS_SAMPLES`. No measurement data is included.
`window.TGWITNESS_CAMPAIGN` adds a signed total with each run's final receipt;
individual durations and rates remain separate.

The timeline selects actual signed samples and updates counters, worker states
and the linked receipt hash together. Replay uses original sample times at the
chosen playback speed; displayed throughput always uses the original duration.
Counts are not interpolated. Reduced-motion mode keeps manual timeline controls.
Fixed excerpts are separate from replay and expose their full event hashes.

The browser verifies receipt signatures and supplied journal checkpoints.
The supplied signing keys identify the measurement; they do not establish an
independent audit, message authorship or complete collection.

Keep operational receipts and source messages outside the repository. Public
examples must use fictional data. Run the synthetic browser regressions with
`python -m pytest tools/test_scale_demo.py -q` in an authorized test environment.
