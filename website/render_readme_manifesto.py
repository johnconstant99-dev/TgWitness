"""Render the README manifesto's opening card without changing the authors' text.

Usage: python website/render_readme_manifesto.py --font /path/to/Manrope.ttf
Uses the existing outlined-font renderer and retained Manrope OFL licence.
"""
import argparse

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_case_assets import save
from render_readme import Drawing

TITLE = "No signature makes a Telegram message true — ours included."
CAPTION = (
    "We preserve what the account saw, link it so that a change shows, "
    "and hand you the verifier."
)
INK, GOLD, MUTED = "#edf5fc", "#dfbd86", "#b5c7d9"


def render(fonts, mobile=False):
    width, height = (600, 466) if mobile else (1200, 330)
    x = 36 if mobile else 52
    d = Drawing(fonts, width, height, TITLE)
    d.add(f'''<defs>
<linearGradient id="paper" x1="0" y1="0" x2="1" y2="1">
  <stop stop-color="#10263c"/><stop offset="1" stop-color="#080f1c"/>
</linearGradient>
<radialGradient id="glow">
  <stop stop-color="#dfbd86" stop-opacity=".09"/>
  <stop offset="1" stop-color="#dfbd86" stop-opacity="0"/>
</radialGradient>
<clipPath id="card"><rect x="1" y="1" width="{width-2}" height="{height-2}" rx="20"/></clipPath>
</defs>
<g clip-path="url(#card)">
  <rect x="1" y="1" width="{width-2}" height="{height-2}" rx="20" fill="url(#paper)"/>
  <ellipse cx="{width-60}" cy="50" rx="380" ry="310" fill="url(#glow)"/>
</g>
<rect x="1" y="1" width="{width-2}" height="{height-2}" rx="20" fill="none" stroke="#30495f"/>
<path d="M{x} 48h48" stroke="{GOLD}" stroke-width="3" stroke-linecap="round"/>
''')
    if mobile:
        for text, y, color in (
            ("No signature makes", 126, INK),
            ("a Telegram message", 188, INK),
            ("true", 250, INK),
        ):
            d.text(text, x, y, 49, color, 700, -1.2)
        d.text("— ours included.", 148, 250, 49, GOLD, 700, -1.2)
        rule_y = 288
        lines = (
            "We preserve what the account saw,",
            "link it so that a change shows,",
            "and hand you the verifier.",
        )
        for i, text in enumerate(lines):
            d.text(text, x, 337 + i * 42, 32, MUTED, 500, -.2)
    else:
        d.text("No signature makes a Telegram", x, 116, 54, INK, 700, -1.3)
        d.text("message true", x, 181, 54, INK, 700, -1.3)
        d.text("— ours included.", 423, 181, 54, GOLD, 700, -1.3)
        rule_y = 221
        d.text("We preserve what the account saw, link it so that a change shows,", x, 263, 25, MUTED)
        d.text("and hand you the verifier.", x, 297, 25, MUTED)
    d.add(f'<path d="M{x} {rule_y}H{width-x}" stroke="#30495f"/>'
          f'<path d="M{x} {rule_y}h48" stroke="{GOLD}"/>')
    save(d, "readme-manifesto" + ("-mobile" if mobile else "") + ".svg", CAPTION)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", required=True)
    args = parser.parse_args()
    fonts = {w: instantiateVariableFont(TTFont(args.font), {"wght": w}) for w in (500, 700)}
    for mobile in (False, True):
        render(fonts, mobile)


if __name__ == "__main__":
    main()
