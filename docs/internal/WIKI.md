# Maintain and publish the wiki

The English wiki source lives in [docs/wiki](../wiki/Home.md). It is reviewed with the application source. The GitHub Wiki bundle is generated from an explicit page list in `tools/build_wiki.py`.

## Build locally

From the project root, with Python 3.11+:

~~~sh
python tools/build_wiki.py
~~~

Outputs:

- `dist/wiki/`: 17 English pages, `_Sidebar.md`, `_Footer.md` and their `assets/`.
- `dist/TgWitness-<version>-wiki.zip`: the same pages and assets, ready to copy into a wiki clone.
- The matching `.zip.sha256` file.
- `dist/wiki-manifest.json`: destination repository, source branch and file hashes.

The builder reads allowlisted source files only. It converts local wiki links to GitHub Wiki page URLs and documentation links to repository URLs. Inline images and links to full-size or static diagrams are bundled under `assets/` and linked through the Wiki, so they travel with it rather than depending on unauthenticated raw URLs from a private source repository. Code blocks are preserved. Missing/private link targets and unexpected output files stop the build.

For a fork or a different source branch:

~~~sh
python tools/build_wiki.py --repository OWNER/REPOSITORY --branch main
~~~

In Actions, the repository defaults to `GITHUB_REPOSITORY`. The branch defaults to `main`. Review project-specific links in the issue-template configuration when making a fork.

## Publish for the first time

GitHub stores a wiki in a separate Git repository. Enable Wikis in the repository settings and create its first page through the Wiki tab before cloning it. See [GitHub's wiki editing instructions](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages).

Build the bundle, authenticate your Git client, then clone the intended wiki next to this source checkout:

~~~sh
git clone https://github.com/phishdestroy/TgWitness.wiki.git ../TgWitness.wiki
~~~

Copy the built pages and assets into that clone. In PowerShell:

~~~powershell
Copy-Item -Path .\dist\wiki\*.md -Destination ..\TgWitness.wiki\
Copy-Item -Path .\dist\wiki\assets -Destination ..\TgWitness.wiki\ -Recurse -Force
~~~

On Linux/macOS:

~~~sh
cp dist/wiki/*.md ../TgWitness.wiki/
cp -R dist/wiki/assets ../TgWitness.wiki/
~~~

Review and publish:

~~~sh
git -C ../TgWitness.wiki status --short
git -C ../TgWitness.wiki diff
git -C ../TgWitness.wiki add -- "*.md" assets/
git -C ../TgWitness.wiki commit -m "Update TgWitness wiki"
git -C ../TgWitness.wiki push
~~~

For an existing wiki clone, pull its latest changes before copying. Review newly added files as well as the diff. The copy step does not remove unrelated wiki pages; review obsolete pages separately.

GitHub uses the special `_Sidebar.md` and `_Footer.md` names for navigation. See [GitHub's sidebar and footer documentation](https://docs.github.com/en/communities/documenting-your-project-with-wikis/creating-a-footer-or-sidebar-for-your-wiki).

After pushing, open Home, test sidebar navigation, confirm images load and inspect the commands on Getting Started and Server and Docker.

## Update a page

1. Edit the corresponding file in `docs/wiki/`.
2. Keep detailed behavior consistent with the technical references in `docs/`.
3. For a new page, update the builder's explicit page list, Home and `_Sidebar.md`.
4. Run the checks below, build, inspect the rendered Markdown and publish the reviewed result.

~~~sh
python -m pytest --noconftest -q tests/test_wiki.py
python tools/check_publication.py
python tools/build_wiki.py
~~~

The **Wiki bundle** Actions workflow builds downloadable artifacts with read-only repository permissions. It does not push to the separate wiki repository. Source archives also include the wiki source, support guide and publishing instructions.
