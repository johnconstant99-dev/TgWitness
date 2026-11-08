# Contributing to TgWitness

Contributions to TgWitness should preserve the distinction
between an observed Telegram update, an inference, and an unknown fact. Read the
[evidence model](../docs/EVIDENCE.md) before changing collection or export behavior.

## Coding agents

Start with the repository-wide [AGENTS.md](../AGENTS.md) and the
[code, documentation and validation map](../docs/AGENT-GUIDE.md).
Claude and Gemini entry files point to the same rules.

Write original documentation, interface text, commit messages and pull requests
in English. Keep any requested translations separate and identify the English
source. Check the current branch, other development branches and recorded revisions
before concluding that a feature was never implemented. Distinguish implemented,
merged, released and demonstrated behavior.

Respect the operator's execution limits. A source-editing workspace is not
automatically a runtime or test host. When local execution is restricted, edit
files and use static checks only; run applications, builds, browser tests,
benchmarks, dependency installation and background services only when explicitly
authorized for that host. Use the approved CI or test environment for execution.
Do not resume stopped work automatically or connect Telegram accounts as part of
an ordinary code or documentation task.

Preserve other sessions' changes. Stop only processes started by the agent, using
their recorded process IDs; never terminate every Python, Node or browser process.
Report which checks actually ran and where. A passing mock or demo does not prove
live Telegram support. Keep private workspace instructions, credentials and local
machine details out of published files.

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
```

Browser acceptance runs in the private validation environment with synthetic accounts
and fake Telegram transport. Do not connect a personal account for an ordinary regression test.

After a visible UI change, use the private capture tools to refresh README images
from synthetic data and review the generated assets before committing them.

## Validation

Regression tests, fixtures and validation runners are maintained privately and are
excluded from the public repository and source archive. Preserve the local validation
workspace when preparing a release. Record the revision and checks actually completed;
public source alone does not include the private validation harness.
Use an authorized test host and synthetic accounts; live-service checks require explicit scope.

## Public project website

Edit `website/`, run `python tools/build_site.py`, then validate the result in the
authorized browser environment using fictional data. Preview and publishing instructions
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
Add a private regression when fixing data integrity, authentication, collection or an
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
data, tests, fixtures, validation runners, environments, logs, build output and account secrets are excluded by the
packager; files of unexpected types inside source directories are also excluded.
Review the selected source itself before release: an allowlist cannot detect every
secret pasted into a source file. Run `python tools/publication_guard.py --git-index`
to check public file selection, local documentation links, known secret formats and
the staged content. Neither command publishes anything.

ZIP metadata is fixed for repeatable builds from identical input bytes and the same
Python/zlib toolchain. Preserve checkout line endings when comparing archives.
Private release validation checks repeatability, exact source bytes, private-file
exclusions and preservation of the previous ZIP after a failed write.

Workflow definitions are not evidence that validation ran for a revision.
See [release readiness](../docs/internal/READINESS.md).
