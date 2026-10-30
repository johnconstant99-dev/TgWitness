"""Render the technical repository banners used across the PhishDestroy family.

Pass the Space Grotesk variable TTF with --font. Outlined text, SVG motion and
separate mobile/still compositions; no network access or application imports.
"""
import argparse

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_readme import Drawing
from render_case_assets import save


def field(d, still):
    w, h = d.width, d.height
    d.add(f'''<defs>
<radialGradient id="glow"><stop stop-color="#17344c" stop-opacity=".6"/><stop offset="1" stop-color="#050b12" stop-opacity="0"/></radialGradient>
<pattern id="grid" width="80" height="80" patternUnits="userSpaceOnUse"><path d="M80 0H0V80" fill="none" stroke="#1c384b" stroke-width="1"/></pattern>
<linearGradient id="scan" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="{w}" y2="0"><stop stop-color="#83caff" stop-opacity="0"/><stop offset=".55" stop-color="#83caff" stop-opacity=".38"/><stop offset="1" stop-color="#83caff" stop-opacity="0"/></linearGradient>
<linearGradient id="trace" gradientUnits="userSpaceOnUse" x1="40" y1="0" x2="{w-40}" y2="0"><stop stop-color="#7fc6ff"/><stop offset="1" stop-color="#d0b17c" stop-opacity=".25"/></linearGradient>
</defs>
<rect width="{w}" height="{h}" fill="#050b12"/>
<ellipse cx="{w*.78}" cy="{h*.24}" rx="{w*.65}" ry="{h*.9}" fill="url(#glow)"/>
<rect width="{w}" height="{h}" fill="url(#grid)" opacity=".55"/>
<path d="M2 0V{h}" stroke="#7fbde9" stroke-width="4"/>
<path d="M0 .5H{w-.5}V{h-.5}H0" fill="none" stroke="#29445c"/>
<path d="M{w-24}1h23v23M1 {h-24}v23h23" fill="none" stroke="#91bedc" stroke-opacity=".7"/>
<g fill="none" stroke="#80b9e3" stroke-opacity=".14">
<circle class="orbit" cx="{w-30}" cy="25" r="130" stroke-dasharray="85 20 4 70"/>
<circle cx="{w-30}" cy="25" r="190"/>
<circle cx="{w-30}" cy="25" r="250" stroke-dasharray="2 9"/>
</g>''')
    for index, y in enumerate((60, h*.39, h*.69, h-47)):
        d.add(f'<circle class="signal s{index}" cx="32" cy="{y}" r="4" fill="#83c9fb"/>'
              f'<circle class="halo s{index}" cx="32" cy="{y}" r="9" fill="none" stroke="#83c9fb" stroke-opacity=".2"/>')
    if not still:
        d.add(f'<path class="scan" d="M0 0H{w}" stroke="url(#scan)" stroke-width="2"/>')
        d.add(f'''<style>
.scan{{animation:scan 11s linear infinite}}
.orbit{{transform-box:fill-box;transform-origin:center;animation:orbit 45s linear infinite}}
.travel{{stroke-dasharray:90 1310;animation:travel 9s linear infinite}}
.signal,.halo,.step{{animation:signal 8s ease-in-out infinite}}
.s1{{animation-delay:-2s}}.s2{{animation-delay:-4s}}.s3{{animation-delay:-6s}}
@keyframes scan{{from{{transform:translateY(0)}}to{{transform:translateY({h}px)}}}}
@keyframes orbit{{to{{transform:rotate(360deg)}}}}
@keyframes travel{{to{{stroke-dashoffset:-1400}}}}
@keyframes signal{{0%,100%{{opacity:.35}}50%{{opacity:1}}}}
</style>''')


def banner(font, *, mobile=False, wiki=False, still=False):
    width, height = ((720, 680) if mobile else (1440, 590))
    if wiki:
        height = 590 if mobile else 430
    title = "TgWitness — Follow the trail. Preserve the evidence."
    if wiki:
        title = "TgWitness — Work the case. Keep the record."
    d = Drawing(font, width, height, title)
    field(d, still)
    x = 65 if mobile else 86
    d.text("PHISHDESTROY / TGWITNESS" if wiki else "PHISHDESTROY", x, 62, 15, "#8abddd", 600, 2)
    if wiki:
        d.text("THE INVESTIGATION HANDBOOK", x, 111, 14 if mobile else 16, "#769bb9", 500, 1.5)
        d.text("Work the case.", x-4, 216 if mobile else 205, 70 if mobile else 104, "#e6f2fd", 700, -2)
        d.text("Keep the record.", x-4, 302 if mobile else 310, 70 if mobile else 104, "#94c4e8", 700, -2)
        if mobile:
            for y, line in ((384,"Your first capture."),(418,"Your next lead."),(452,"Your signed handoff.")):
                d.text(line, x, y, 25, "#9eb9d1", 500)
            d.add('<path d="M65 510H660" stroke="#28465d"/><path class="travel" d="M65 510H660" stroke="url(#trace)" stroke-width="2"/>')
        else:
            d.text("Your first capture. Your next lead. Your signed handoff.", x, 374, 25, "#9eb9d1", 500)
            d.add('<path d="M86 404H1354" stroke="#28465d"/><path class="travel" d="M86 404H1354" stroke="url(#trace)" stroke-width="2"/>')
    else:
        if mobile:
            d.text("YOUR TELEGRAM", x, 108, 15, "#769bb9", 500, 1.4)
            d.text("INVESTIGATION WORKSPACE", x, 133, 15, "#769bb9", 500, 1.4)
        else:
            d.text("YOUR TELEGRAM INVESTIGATION WORKSPACE", x, 119, 17, "#769bb9", 500, 2)
        d.text("TGWITNESS", x-5, 236 if mobile else 263, 88 if mobile else 155, "#e6f2fd", 700, -3)
        line_y = 261 if mobile else 291
        d.add(f'<path d="M{x} {line_y}H{width-60}" stroke="#29485f"/>'
              f'<path class="travel" d="M{x} {line_y}H{width-60}" stroke="url(#trace)" stroke-width="2"/>')
        d.text("Follow the trail.", x, 319 if mobile else 357, 36 if mobile else 40, "#e6f2fd", 600, -.8)
        d.text("Preserve the evidence.", x if mobile else 402, 367 if mobile else 357, 36 if mobile else 40, "#94c4e8", 600, -.8)
        if mobile:
            d.text("Conversations. Connections.", x, 420, 24, "#9eb9d1", 500)
            d.text("A record you can verify.", x, 453, 24, "#9eb9d1", 500)
        else:
            d.text("Conversations. Connections. A record you can verify.", x, 405, 25, "#9eb9d1", 500)
        labels = ("CAPTURE", "CONNECT", "PRESERVE", "VERIFY")
        for index, label in enumerate(labels):
            sx = (65 + index%2*310) if mobile else (86 + index*327)
            sy = (525 + index//2*65) if mobile else 511
            d.text(f"0{index+1}", sx, sy, 14, "#d0b17c", 600)
            d.text(label, sx+35, sy, 17, "#b2cce0", 600, 1.6)
            d.add(f'<path class="step s{index}" d="M{sx} {sy+14}h220" stroke="#72b7eb" stroke-opacity=".55"/>')
        if mobile:
            d.text("FOLLOW THE SOURCES. KEEP THE CONTEXT.", x, 648, 13, "#7394ae", 500, 1)
        else:
            d.text("FOLLOW THE SOURCES. KEEP THE CONTEXT.", x, 564, 14, "#7394ae", 500, 1.5)
    name = "technical-wiki" if wiki else "technical-hero"
    name += "-mobile" if mobile else ""
    name += "-static" if still else ""
    save(d, name + ".svg", "PhishDestroy technical banner: a dark grid, stable outlined typography, moving traces and observation signals.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", required=True)
    args = parser.parse_args()
    font = {weight: instantiateVariableFont(TTFont(args.font), {"wght":weight}, inplace=False) for weight in (500,600,700)}
    for mobile in (False, True):
        for wiki in (False, True):
            for still in (False, True):
                banner(font, mobile=mobile, wiki=wiki, still=still)
    print("Rendered eight technical banners: README/Wiki, desktop/phone, animated/still.")


if __name__ == "__main__":
    main()
