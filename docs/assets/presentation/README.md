![TgWitness](brand.svg)

# Presentation assets

README, Wiki and documentation artwork. Screenshots use demo records.

| Files | Use |
| --- | --- |
| `casework-hero*`, `casework-handbook*` | Project and Wiki covers |
| `readme-nav-*` | README buttons, with shorter phone labels |
| `readme-features*`, `readme-feature-*` | Export, investigation and saved-version animations |
| `readme-workspace-*.webp` | Demo recording in both themes, plus phone crops and stills |
| `casework-chain*`, `casework-checkpoint*`, `evidence-*` | Evidence diagrams |
| `readme-services*`, `readme-card-*` | Alerts and encrypted S3 copies |
| `readme-handbook*`, `wiki-*` | Handbook routes and chapter covers |
| `identity-meta-*` | Version, languages, test and licence badges |
| `folder-*`, `readme-button-*`, `*divider*` | Folder headers, links and separators |
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
```

`render_identity.py` reads the version and language counts from source.

To refresh the demo recording, build the site and run
`python website/capture_readme.py` with Playwright and Pillow installed.
Use `python website/render_presentation.py` for the sharing PNGs.

Check both themes and a narrow viewport before replacing images. Keep the still
variants: `<picture>` selects them for reduced motion. Keep useful alt text too.
SVG captions use outlined glyphs, so they don't depend on the reader's fonts.

The [diagram reference](../../SHOWCASE.md) shows the evidence illustrations.
The Wiki builder copies linked assets into its own repository.
