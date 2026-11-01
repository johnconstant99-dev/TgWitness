# CI execution and queue isolation

The original `tgwitness-ci` runner executes one job at a time. In the measured
[Checks run](https://github.com/phishdestroy/TgWitness/actions/runs/41331263417),
five jobs took 9m45s end to end. The Docker job ran for 1m36s after waiting 8m07s.
The [Wiki job](https://github.com/phishdestroy/TgWitness/actions/runs/41329432245)
ran for 13s after waiting 12m40s behind the website and application checks.

## Routing

| Work | Runner |
| --- | --- |
| Source, dependency and lint checks | Fresh GitHub-hosted Ubuntu |
| Linux Python installation/readiness | Fresh GitHub-hosted Ubuntu |
| Browser and panel suites | Separate GitHub-hosted Ubuntu runners |
| Wiki archive | Fresh GitHub-hosted Ubuntu |
| Docker checks | Existing `tgwitness-ci` Linux runner |
| Website and release publishing jobs | Their existing runner selections |
| Release validation | Reuses the Checks routing above; Windows and macOS stay hosted |
| Sealed collection, provenance, Scorecard and PR checks | Their existing GitHub-hosted runners |

Independent jobs can now overlap without waiting for the single project runner.
Each hosted job gets its own machine and workspace. The browser suites keep
their existing limit of two independent tests at a time. No test, assertion,
permission, timeout or trigger is removed to obtain the speedup. The existing
dependency-keyed pip cache applies to hosted jobs; browser installation remains
version-specific. Dependency downloads and runner startup remain part of cold
run time.

The project server retains its warm Docker layers and serial Docker execution.
Its shared image tags are not exposed to a second Docker worker. This change
requires no SSH access, additional server, new persistent runner credentials,
repository variable or new secret. The project runner remains dedicated to
reviewed repository code. Dispatch workflows only on reviewed refs. Hosted PR
and attestation jobs remain independent of it.

Measure end-to-end duration, individual job duration and queue time separately.
Confirm different runner IDs and overlapping start/finish times for the hosted
jobs. A site or release job can still delay the Docker job on the project runner;
this change removes the unrelated Python/browser/Wiki work from that queue.
Manual Checks opt into the Windows/macOS matrix through `full_platforms`;
release validation requests that full matrix.

## Rollback

Revert this PR to restore the original runner selection. There is no server-side
installation or repository setting to undo. Do not cancel an unrelated release
or sealed capture when checking the changed routing.
