"""Build compact, responsive README buttons in the existing casework palette.

Usage: python website/render_readme_navigation.py --font /path/to/Manrope.ttf
Text uses outlined glyphs; the font licence is retained in docs/assets/presentation.
"""
import argparse

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_case_assets import save
from render_readme import Drawing


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", required=True)
    args = parser.parse_args()
    fonts = {600: instantiateVariableFont(TTFont(args.font), {"wght": 600}, inplace=True)}
    entries = (
        ("demo", "Explore the demo", "Demo"),
        ("download", "Get TgWitness", "Download"),
        ("handbook", "Read the handbook", "Handbook"),
        ("export", "Chat export", "Export"),
        ("investigate", "Investigation", "Investigate"),
        ("history", "Saved versions", "Versions"),
        ("setup", "Setup guide", "Setup"),
        ("account", "Telegram account", "Account"),
        ("deploy", "Docker & servers", "Servers"),
        ("people", "People & dossiers", "People"),
        ("bots", "Bot investigation", "Bots"),
        ("archive", "Search, AI & MCP", "Archive"),
        ("cloud", "Sealed cloud mode", "Cloud"),
    )
    for name, desktop, mobile in entries:
        for narrow in (False, True):
            width, height = (108, 46) if narrow else (240, 48)
            if name in {"people", "bots", "archive", "cloud"}:
                width = 170 if narrow else 360
            title = mobile if narrow else desktop
            d = Drawing(fonts, width, height, desktop)
            fill = "#16364e" if name == "demo" else "#0d1d2e"
            d.add(f'<rect x=".75" y=".75" width="{width-1.5}" height="{height-1.5}" '
                  f'rx="9" fill="{fill}" stroke="#39546a" stroke-width="1.5"/>')
            size = 14 if narrow else 16
            face = fonts[600]
            glyphs, cmap = face.getGlyphSet(), face.getBestCmap()
            length = sum(glyphs[cmap[ord(char)]].width for char in title) * size / face["head"].unitsPerEm
            d.text(title, (width-length)/2, 28 if narrow else 30, size, "#edf5fc", 600)
            if not narrow:
                d.add(f'<path d="M{width-26} 20h7v7m-7 0 7-7" fill="none" '
                      'stroke="#dfbd86" stroke-width="1.5"/>')
            save(d, "readme-nav-" + name + ("-mobile" if narrow else "") + ".svg", desktop)


if __name__ == "__main__":
    main()
