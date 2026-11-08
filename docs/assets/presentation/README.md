[TgWitness](../../../README.md) / [assets](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="./section-assets-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="./section-assets-static.svg">
  <source media="(max-width: 640px)" srcset="./section-assets-mobile.svg">
  <img src="./section-assets.svg" width="1200" alt="TgWitness / Visual assets">
</picture>

# Presentation assets

README, Wiki and documentation artwork. Screenshots use demo records.

| Files | Use |
| --- | --- |
| `casework-hero*`, `casework-handbook*` | Project and Wiki covers |
| `readme-nav-*` | README buttons, with shorter phone labels |
| `readme-features*`, `readme-feature-*` | Export, investigation and saved-version animations |
| `readme-workspace-*.webp` | Demo recording in both themes, plus phone crops and stills |
| `casework-chain*`, `casework-checkpoint*`, `evidence-*` | Evidence diagrams |
| `casework-assurance*` | Local, audited VM and Phala / Intel TDX deployment checks |
| `readme-services*`, `readme-card-*` | Alerts and encrypted S3 copies |
| `readme-handbook*`, `wiki-*` | Handbook routes and chapter covers |
| `identity-meta-*` | Version, languages, test and licence badges |
| `folder-*`, `readme-button-*`, `*divider*` | Folder headers, links and separators |
| `chapter-*` | Compact, static category headers for reference pages; editable SVG text and paths |
| `section-*` | Animated directory covers, narrow-screen layouts and reduced-motion stills |
| `preview-github.png`, `preview-social.png` | Sharing images |

## Rebuild

Run from the repo root. The SVG renderers need `fonttools` and local Manrope / Space
Grotesk font files. Font licences: [Manrope](OFL-Manrope.txt), [Space Grotesk](OFL-SpaceGrotesk.txt).

```sh
python website/render_casework.py --display-font /path/to/SpaceGrotesk.ttf --text-font /path/to/Manrope.ttf
python website/render_readme_navigation.py --font /path/to/Manrope.ttf
python website/render_readme_panels.py --font /path/to/Manrope.ttf
python website/render_wiki_headers.py --font /path/to/Manrope.ttf
python website/render_identity.py --font /path/to/Manrope.ttf
python website/render_directory_headers.py --font /path/to/Manrope.ttf
```

`render_identity.py` reads the version and language counts from source.
After a version change, use `--metadata-only` to refresh its badges, update the
README alt text and `docs/STATUS.md`, then run `python tools/publication_guard.py`.

Directory covers use layered illustrations: reference pages, capture frames,
linked components, server racks and project artwork. The main cover connects
signed journal entries to a separately retained checkpoint and an evidence archive.
The assurance diagram compares deployment choices and follows the TDX checks from
Intel's root to the journal. Headings stay fixed; motion belongs to the illustrations.
All lettering is outlined and every SVG is self-contained.
Each `<picture>` selects a `-static.svg`
version for `prefers-reduced-motion: reduce`. Keep those sources before the regular
mobile source: the narrow static version first, then the wide static version,
then the animated narrow version at `max-width: 640px`.

The README demo uses its dark recording in both page themes, matching the diagrams.
Its source conditions select only width and motion: GitHub's theme handling
replaces compound color-scheme conditions and can select the wrong crop or still.

To refresh the demo recording, build the site and run
`python website/capture_readme.py` with Playwright and Pillow installed.
Use `python website/render_presentation.py` for the sharing PNGs.

Check both themes and a narrow viewport before replacing images. Keep the still
variants: `<picture>` selects them for reduced motion. Keep useful alt text too.
SVG captions use outlined glyphs, so they don't depend on the reader's fonts.

The [diagram reference](../../SHOWCASE.md) shows the evidence illustrations.
The Wiki builder copies linked assets into its own repository.

The compact `chapter-*` headers use system fonts, contain no scripts or external
resources, and are shared by related pages. Their illustrations identify a topic;
they do not present measurements. Keep page titles and navigation as Markdown.
