# Contributing to TgWitness

Contributions to TgWitness should preserve the distinction
between an observed Telegram update, an inference, and an unknown fact. Read the
[evidence model](../docs/EVIDENCE.md) before changing collection or export behavior.

## Development setup

Use Python 3.11 or newer and an isolated environment:

```sh
python -m venv .venv
```

Activate it with `.venv\Scripts\Activate.ps1` in PowerShell or
`source .venv/bin/activate` in a POSIX shell, then run:

```sh
python -m pip install -c deploy/constraints.txt -e ".[dev]"
python -m ruff check .
python -m playwright install chromium
python tools/check_browser.py
```

On Linux, `python -m playwright install --with-deps chromium` also installs the
browser's system dependencies and may need administrator access. To use an installed
browser instead of the Playwright download, set `TGWITNESS_BROWSER_CHANNEL=chrome` or
`msedge`. The browser acceptance harness uses synthetic accounts and fake
Telegram transport. Do not connect a personal account for an ordinary regression test.

After a visible UI change, refresh the README images from synthetic data and review
them before committing:

```sh
python tools/capture_screenshots.py          # review set in test-results/screens
python tools/capture_screenshots.py --docs   # docs/assets used by the README
```

## Public project website

Edit `website/`, run `python tools/build_site.py`, then `python tools/check_site.py`.
The site check uses only a local static server and fictional screenshots; it needs
Playwright Chromium but no Telegram credentials. Preview and publishing instructions
are in [the publishing guide](../docs/internal/PUBLISHING.md). Keep public assets separate from
account data, and preserve the no-JavaScript fallback and keyboard navigation.

## Wiki and user support

Edit the English pages in `docs/wiki/` and run `python tools/build_wiki.py`.
The builder prepares a separate GitHub Wiki bundle and checks local link targets.
Keep procedures consistent with the technical references; use fictional examples.
The [wiki maintenance guide](../docs/internal/WIKI.md) covers page additions, checks and publication.
Use [SUPPORT.md](SUPPORT.md) for help requests and documentation issue reporting.

## Reporting issues

Include the TgWitness version, OS/Python/browser versions, steps to reproduce,
expected behavior and observed behavior. Prefer a synthetic example. Explain
whether a finding came from a fake transport or a real Telegram account without
sharing that account's identifiers or source content.

Do not attach account data directories, session files, panel tokens, API credentials,
private keys or real evidence exports. Report vulnerabilities through the process
in [SECURITY.md](SECURITY.md), rather than a public issue with exploit details.

## Pull requests

Keep each change focused and explain its effect on existing journals and collectors.
Add a regression when fixing data integrity, authentication, collection or an
asynchronous UI error. Run the relevant checks and state exactly what was tested.
Screenshots should use demo data. Do not claim live-service or platform qualification
from a fake transport or an unexecuted CI definition.

Existing signed observations must remain verifiable. Search/display normalization
must not rewrite signed payloads. New collection settings must record their effect
on coverage. Changes to defaults, dependencies, user workflows or limits need matching
documentation and a changelog entry.

## Preparing a public source archive

```sh
python tools/build_source.py
```

The archive in `dist/` contains allowlisted source/documentation files and a
`SOURCE_SHA256SUMS` manifest. A separate SHA-256 file accompanies the ZIP. Runtime
data, environments, logs, build output and account secrets are excluded by the
packager; files of unexpected types inside source directories are also excluded.
Review the selected source itself before release: an allowlist cannot detect every
secret pasted into a source file. This command does not publish anything.

GitHub Actions checks package installation across the configured Python/platform
matrix, synthetic browser workflows, source packaging and the container package.
The workflow definitions are not a claim
that those remote jobs have run. See [release readiness](../docs/internal/READINESS.md).
