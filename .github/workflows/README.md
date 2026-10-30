![GitHub Actions](../../docs/assets/presentation/folder-github-workflows.svg)

# GitHub Actions

[Project](../../README.md) · [Documentation](../../docs/README.md) · [Wiki](../../docs/wiki/Home.md) · [Support](../SUPPORT.md)

| Workflow | Purpose |
| --- | --- |
| [`checks.yml`](checks.yml) | Automated project checks |
| [`pages.yml`](pages.yml) | Public website build and Pages workflow |
| [`release.yml`](release.yml) | Release preparation and configured release jobs |
| [`wiki.yml`](wiki.yml) | Downloadable wiki bundle |

Read each workflow's `on:` triggers and `permissions:` before changing it. The wiki
bundle workflow prepares artifacts; publishing the separate GitHub Wiki is described
in the [wiki maintenance guide](../../docs/internal/WIKI.md).

Use [local tooling](../../tools/README.md) to inspect outputs before enabling or
triggering publication.
