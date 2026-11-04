"""Render the README card explaining capture and record verification."""
import argparse

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_case_assets import save
from render_readme import Drawing

TITLE = "Capture the conversation. Verify the record."
CAPTION = (
    "Save messages, edits and files. Check signatures and checkpoints. "
    "Review the capture process."
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
            ("Capture the", 126, INK),
            ("conversation.", 188, INK),
            ("Verify the record.", 250, GOLD),
        ):
            d.text(text, x, y, 49, color, 700, -1.2)
        rule_y = 288
        lines = (
            "Save messages, edits and files.",
            "Check signatures and checkpoints.",
            "Review the capture process.",
        )
        for i, text in enumerate(lines):
            d.text(text, x, 337 + i * 42, 32, MUTED, 500, -.2)
    else:
        d.text("Capture the conversation.", x, 116, 54, INK, 700, -1.3)
        d.text("Verify the record.", x, 181, 54, GOLD, 700, -1.3)
        rule_y = 221
        d.text("Save messages, edits and files. Check signatures and checkpoints.", x, 263, 25, MUTED)
        d.text("Review the capture process.", x, 297, 25, MUTED)
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
