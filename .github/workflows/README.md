![GitHub Actions](../../docs/assets/presentation/folder-github-workflows.svg)

# GitHub Actions

[Project](../../README.md) · [Documentation](../../docs/README.md) · [Wiki](../../docs/wiki/Home.md) · [Support](../SUPPORT.md)

| Workflow | Purpose |
| --- | --- |
| [`checks.yml`](checks.yml) | Hosted Python, source and browser checks; Docker on the project runner; full platform matrix on request |
| [`evidence-checks.yml`](evidence-checks.yml) | Reusable hosted check called by PR and main gates: signed journal/witness boundaries, replica recipients, 25 narrative languages and saved profiles |
| [`pr-check.yml`](pr-check.yml) | Read-only GitHub-hosted PR/merge-queue gate: lint, synthetic installation and notification redirect checks, pinned dependency audits |
| [`security-audit.yml`](security-audit.yml) | CodeQL on main, pull requests and merge queue; nightly/manual default-branch dependency and built-container scans |
| [`pages.yml`](pages.yml) | Public website build and Pages workflow |
| [`release.yml`](release.yml) | Release preparation and configured release jobs |
| [`installer.yml`](installer.yml) | Build, sign and install-check the current application; publish verified static downloads to Cloudflare when configured |
| [`installer-acceptance.yml`](installer-acceptance.yml) | First-run Ubuntu local-panel and temporary-tunnel acceptance, with synthetic data |
| [`wiki.yml`](wiki.yml) | Downloadable wiki bundle built on hosted Ubuntu |

Read each workflow's `on:` triggers and `permissions:` before changing it. The wiki
bundle workflow prepares artifacts; publishing the separate GitHub Wiki is described
in the [wiki maintenance guide](../../docs/internal/WIKI.md).

Use [local tooling](../../tools/README.md) to inspect outputs before enabling or
triggering publication.

The [installer publication guide](../../deploy/installer/README.md#automatic-publication-from-github)
describes the CI secret and variables, immutable-download retention and public
verification. Installer version labels come from `pyproject.toml`; the manifest
records the exact commit and build ID. No version number needs editing in the
one-line installation commands. Publication updates the download site; it does
not restart or update users' running collectors.

The `tgwitness-ci` runner handles only reviewed main-branch, maintainer-dispatched
and published-release jobs. Pull-request code is checked on GitHub-hosted runners;
the CodeQL job uses `build-mode: none` and does not execute the checked-out source.
The project runner still requires isolation and maintenance.

Independent Python, source, browser and Wiki jobs use fresh GitHub-hosted
runners. Docker checks, website builds and selected release jobs retain the
repository's `tgwitness-ci` Linux runner. See
[CI execution and queue isolation](../../docs/internal/CI-PARALLELISM.md) for
routing and measurements, and [runner operations](../../docs/internal/CI-RUNNER.md)
for triggers, artifact retention, host replacement and troubleshooting.

Checks runs its fixed browser and panel check lists in separate processes, at most
two at a time. A failed check does not skip the remaining scripts; per-check logs
(capped at 4 MiB), JSON results and durations are retained, with a ten-minute
per-check timeout and bounded cleanup. A deliberately detached descendant may
survive best-effort process-tree termination, but cannot hold the runner open.
Write-only form checks remain a separate step. Small dependency, lint and source
gates share one fresh virtual environment; independent gates still run after a
failure. Browser jobs install the constrained `dev,mcp` dependencies once. The
self-hosted runner retains its native pip cache and the default BuildKit layer
cache used by Compose. Hosted checks use dependency-keyed pip caching, and each
browser job installs Chromium and its OS dependencies on its own machine.
No virtual environment is restored across jobs. Site checks run independently
after the strict build. These changes reduce repeated setup and sequential work;
overall completion still depends on runner queues, load and individual checks.

The evidence suite invokes pytest explicitly for its `test_*.py` modules, so a
module without a `__main__` block cannot pass just by being imported. The source
archive check compares narrative resource paths with wheel package-data declarations
and retains the example configuration and golden fixtures. Unlisted local JSON
files remain excluded. The main container job runs the APK retry/corruption test
inside the built Wolfi image with networking disabled. This test is not represented
as passing on a Windows host.

Passing the evidence workflow is a technical regression result. It does not mark
T15's translations as reviewed or satisfy the outstanding T7/T13 release requirements.

The PR gate runs on fresh GitHub-hosted Ubuntu runners. It uses no repository
secrets, persists no checkout credentials, and never calls the Checks workflow
that can execute Docker on the project runner. There is no `pull_request_target`
execution path. All action references
in the new security workflows use full commit hashes. Enable the two PR job
checks in the repository's branch rules to make them required: `Lint and synthetic
smoke` and `Locked dependency audit` from the `PR checks` workflow. Confirm their
check-run names after the first real PR run, require them on `main`, and require
an up-to-date branch (or merge queue). Adding a failing workflow alone does not
block merging or change those rules automatically.

The audit runs nightly at 07:23 UTC and supports manual dispatch, only on the
default branch in both cases. GitHub may delay scheduled runs during high load.
Only its CodeQL and Trivy jobs receive `security-events: write` to upload SARIF.
CodeQL covers Python, JavaScript/TypeScript and GitHub Actions. Trivy builds the
runtime, sealed collector and media-worker images locally and checks both OS and
installed library packages; it publishes no image. High/critical vulnerabilities
fail the container job, including findings without a published fix. Dependency
audits fail on any reported advisory or collection error and retain JSON results.
These scans identify known advisories and supported code patterns; they do not
prove the absence of vulnerabilities or replace the browser/evidence checks.

Dependabot checks Python's root `pyproject.toml`, Actions, and the actual Docker/
Compose directories weekly. Minor/patch version updates and security updates
have separate groups. Version-update PR limits are 3 for Python and 2 each for
Actions and Docker; GitHub separately limits security-update PRs. No auto-merge
is configured. This publication has no maintained npm manifest, so there is no
empty npm job or configuration for the removed witness-controller package.

Do not assume Dependabot updates the custom hash locks or the project's
constraints files. Maintainers must review `deploy/constraints.txt` and
`deploy/constraints-mcp.txt`, regenerate the runtime, build, audit, browser,
MCP and site locks with `python tools/lock_requirements.py` (requires `uv`),
and commit the results with dependency changes. PR checks run the offline
`python tools/lock_requirements.py --check` input-consistency guard before
installation. CI installs third-party tooling from the separate hash locks,
then installs reviewed local source without resolving dependencies and runs
`pip check`. The scheduled dependency audit checks exact runtime, build, MCP,
audit, browser, site and media worker pins without resolving or installing
the audited project. Keep the approved sealed
release/attestation policy separate from an ordinary dependency refresh.

The chosen scanners are pip-audit for the Python manifests, CodeQL for source,
and Trivy for built images. Additional Semgrep, Bandit or OSV jobs are deliberately
omitted to avoid overlapping reports and maintenance without demonstrated extra
coverage. Scanner versions and action pins should be reviewed along with normal
dependency updates. See the [Dependabot options](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference),
[CodeQL workflow options](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options),
and [Trivy action](https://github.com/aquasecurity/trivy-action) for their actual scopes.

Results are retained in each workflow run and its artifacts．
