"""Render the README operator notice banner: a failed GDPR check without consequences."""
import argparse

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_case_assets import save
from render_readme import Drawing

TITLE = "GDPR, violated. Doctors, unpunished."
DESCRIPTION = ("Operator notice banner: a GDPR check in which the reporters were leaked, the black boxes hid nothing, "
               "the answer took 106 days and more than 5,000 pages are missing, with no consequences for the doctors. ")
INK, RED, ROSE, MUTED, NAVY = "#edf5f9", "#d4574a", "#e8a598", "#9db3c3", "#18364b"
ROWS = (("Reporters protected", "leaked"), ("Black boxes", "hid nothing"),
        ("Waiting for an answer", "106 days"), ("Complete data", "5,000+ pages short"))
STYLE = ("<style>" + "".join(
    f"@keyframes r{i}{{0%,{6 + 8 * i}%{{opacity:0;transform:translateX(-10px)}}{10 + 8 * i}%,94%{{opacity:1;transform:none}}100%{{opacity:0}}}}"
    f".r{i}{{animation:r{i} 12s ease-out infinite}}" for i in range(4))
    + "@keyframes tot{0%,44%{opacity:0}49%,94%{opacity:1}100%{opacity:0}}.tot{animation:tot 12s ease-out infinite}"
    "@keyframes st{0%,56%{opacity:0;transform:scale(2.1)}61%{opacity:1;transform:scale(.92)}64%,94%{opacity:1;transform:scale(1)}100%{opacity:0;transform:scale(1)}}"
    ".stamp{transform-box:fill-box;transform-origin:center;animation:st 12s ease-in-out infinite}"
    "@keyframes live{0%,100%{opacity:.35}50%{opacity:1}}.live{animation:live 3s ease-in-out infinite}</style>")


def measure(fonts, value, size, weight, spacing=0):
    font = fonts[weight]
    glyphs, cmap = font.getGlyphSet(), font.getBestCmap()
    scale = size / font["head"].unitsPerEm
    return sum(glyphs[cmap[ord(char)]].width * scale + spacing for char in value) - spacing


def text(d, value, x, y, size, weight, color, anchor="start", spacing=0):
    shift = {"start": 0, "middle": .5, "end": 1}[anchor] * measure(d.font, value, size, weight, spacing)
    d.text(value, round(x - shift, 2), y, size, color, weight, spacing)


def group(d, name, animated):
    d.add(f'<g class="{name}">' if animated else "<g>")


def card(d, animated):
    d.add('<g transform="rotate(-2 215 131)" filter="url(#shadow)">'
          '<rect width="430" height="262" rx="10" fill="url(#paper)" stroke="#d8e6eb"/>')
    text(d, "GDPR CHECK", 24, 38, 16, 800, NAVY, spacing=2)
    text(d, "FAILED", 406, 38, 13, 800, RED, "end", 1.6)
    d.add('<path d="M24 52h382" stroke="#a7bdc9"/>')
    for i, (label, verdict) in enumerate(ROWS):
        y = 78 + 26 * i
        group(d, f"r{i}", animated)
        d.add(f'<path d="M24 {y - 9}l8 8M32 {y - 9}l-8 8" stroke="{RED}" stroke-width="2.2" stroke-linecap="round"/>')
        text(d, label, 42, y, 14, 600, NAVY)
        text(d, verdict, 406, y, 14, 800, RED, "end")
        d.add("</g>")
    d.add('<path d="M24 174h382" stroke="#7a98aa" stroke-dasharray="4 5"/>')
    group(d, "tot", animated)
    text(d, "Consequences for the Doctors", 24, 199, 15, 800, NAVY)
    text(d, "none", 406, 199, 15, 800, RED, "end")
    d.add("</g>")
    group(d, "stamp", animated)
    d.add(f'<g transform="rotate(-4 215 233)"><rect x="125" y="211" width="180" height="44" rx="6" fill="#fbe9e6" '
          f'fill-opacity=".72" stroke="{RED}" stroke-width="3.2"/>')
    text(d, "IMPUNITY", 215, 241, 20, 800, RED, "middle", 3)
    d.add("</g></g></g>")


def pill(d, x, width, label, animated):
    live = ' class="live"' if animated else ""
    d.add(f'<rect x="{x}" y="226" width="{width}" height="26" rx="13" fill="#112c32" stroke="#3c5f63"/>'
          f'<circle{live} cx="{x + 13}" cy="239" r="3" fill="#e5bf83"/>')
    text(d, label, x + 23, 243, 10, 700, INK, spacing=1.2)


def banner(fonts, mobile, animated):
    width, height = (640, 480) if mobile else (1200, 340)
    d = Drawing(fonts, width, height, TITLE)
    d.add('<defs><linearGradient id="surface" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#0c1c2a"/><stop offset="1" stop-color="#07131d"/></linearGradient>'
          f'<radialGradient id="ambient"><stop stop-color="{RED}" stop-opacity=".18"/><stop offset="1" stop-color="{RED}" stop-opacity="0"/></radialGradient>'
          '<linearGradient id="paper" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#f0f5f3"/><stop offset="1" stop-color="#c2d4dc"/></linearGradient>'
          '<pattern id="grid" width="28" height="28" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r=".65" fill="#8eafc4" opacity=".16"/></pattern>'
          '<filter id="shadow" x="-.2" y="-.2" width="1.4" height="1.5"><feDropShadow dx="0" dy="12" stdDeviation="10" flood-color="#02070d" flood-opacity=".4"/></filter>'
          f'<clipPath id="frame"><rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="16"/></clipPath></defs>'
          + (STYLE if animated else "")
          + f'<rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="16" fill="url(#surface)" stroke="#3d5668"/>'
          f'<g clip-path="url(#frame)"><rect width="{width}" height="{height}" fill="url(#grid)"/>'
          f'<ellipse cx="{width * .8:g}" cy="{height / 2:g}" rx="380" ry="280" fill="url(#ambient)"/></g>'
          f'<path d="M36 1h100" stroke="{ROSE}" stroke-width="2"/>')
    text(d, "PHISHDESTROY / TGWITNESS · OPERATOR NOTICE", 36, 42, 11, 700, ROSE, spacing=1.5)
    if mobile:
        text(d, "GDPR, violated.", 33, 94, 38, 800, INK, spacing=-1)
        text(d, "Doctors, unpunished.", 33, 136, 38, 800, RED, spacing=-1)
        text(d, "Leaked reporters, broken redaction,", 36, 170, 16, 500, MUTED)
        text(d, "106 days of stalling. No consequences.", 36, 192, 16, 500, MUTED)
        d.add('<g transform="translate(140 214) scale(.84)">')
        card(d, animated)
        d.add("</g>")
    else:
        text(d, "GDPR, violated.", 33, 108, 46, 800, INK, spacing=-1.2)
        text(d, "Doctors, unpunished.", 33, 160, 46, 800, RED, spacing=-1.2)
        text(d, "Leaked reporters, broken redaction, 106 days of stalling. No consequences.", 36, 198, 16, 500, MUTED)
        for x, size, label in ((36, 104, "106 DAYS"), (150, 122, "36 SECONDS"), (282, 160, "0 CONSEQUENCES")):
            pill(d, x, size, label, animated)
        d.add('<g transform="translate(736 30)">')
        card(d, animated)
        d.add("</g>")
    d.add(f'<path d="M36 {height - 39}H{width - 36}" stroke="#334d60"/>')
    text(d, "TGWITNESS / OPERATOR NOTICE", 36, height - 16, 9, 600, MUTED, spacing=1.2)
    text(d, "READ THE OPERATOR NOTICE →", width - 36, height - 16, 10, 700, ROSE, "end", 1.2)
    kind = "Animated illustration; static and mobile variants are available." if animated else "Static illustration for reduced motion."
    save(d, "readme-gdpr-impunity" + ("-mobile" if mobile else "") + ("" if animated else "-static") + ".svg", DESCRIPTION + kind)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", required=True, help="Path to the OFL-licensed Manrope variable TTF")
    args = parser.parse_args()
    fonts = {w: instantiateVariableFont(TTFont(args.font), {"wght": w}) for w in (500, 600, 700, 800)}
    for mobile in (False, True):
        for animated in (True, False):
            banner(fonts, mobile, animated)
    print("Rendered the operator notice banner with outlined lettering.")


if __name__ == "__main__":
    main()
