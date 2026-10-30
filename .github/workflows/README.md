![GitHub Actions](../../docs/assets/presentation/folder-github-workflows.svg)

# GitHub Actions

[Project](../../README.md) · [Documentation](../../docs/README.md) · [Wiki](../../docs/wiki/Home.md) · [Support](../SUPPORT.md)

| Workflow | Purpose |
| --- | --- |
| [`checks.yml`](checks.yml) | Linux checks on the project runner; full Windows/macOS matrix on request |
| [`pages.yml`](pages.yml) | Public website build and Pages workflow |
| [`release.yml`](release.yml) | Release preparation and configured release jobs |
| [`wiki.yml`](wiki.yml) | Downloadable wiki bundle |

Read each workflow's `on:` triggers and `permissions:` before changing it. The wiki
bundle workflow prepares artifacts; publishing the separate GitHub Wiki is described
in the [wiki maintenance guide](../../docs/internal/WIKI.md).

Use [local tooling](../../tools/README.md) to inspect outputs before enabling or
triggering publication.

Routine jobs use the repository's `tgwitness-ci` Linux runner. Full platform
checks and Windows release packages still use GitHub-hosted Windows/macOS
machines. See [runner operations](../../docs/internal/CI-RUNNER.md) for triggers,
artifact retention, host replacement and troubleshooting.
