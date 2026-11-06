# Release checks

1. Run the required installation, browser, export, verification and security checks
   on the candidate revision. Retain the results in CI artifacts.
2. Run the relevant scenarios from [live acceptance](LIVE_ACCEPTANCE.md) when changing
   Telegram acquisition, authorization or recovery. Record the tested revision and environment.
3. Build packages from that revision, verify hashes and provenance, then check installation
   and backup restore. Preserve published tags and assets.
4. Publish matching instructions, installer metadata and website files using
   [the release procedure](RELEASE.md).

[Collection modes](../COLLECTION-MODES.md) describes the available workflows.
[Actions](https://github.com/phishdestroy/TgWitness/actions) contains revision-specific
results, and [Verification](../VERIFICATION.md) records completed live tests.
