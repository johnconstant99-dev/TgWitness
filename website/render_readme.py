"""Build the README's self-contained SVG cover and navigation.

Requires fonttools and the Manrope variable TTF (see the retained OFL licence).
Animated WebP exports also require Playwright Chromium and Pillow.
Usage: python website/render_readme.py --font /path/to/Manrope.ttf
No network, application data or raster artwork is used.
"""
import argparse
from html import escape
from io import BytesIO
import os
from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/assets/presentation"


class Drawing:
    def __init__(self, font, width, height, title):
        self.font = font
        self.width, self.height, self.title = width, height, title
        self.parts = []

    def add(self, svg):
        self.parts.append(svg)

    def text(self, value, x, y, size, color="#eef4fc", weight=500, spacing=0):
        font = self.font[weight]
        glyphs = font.getGlyphSet()
        cmap = font.getBestCmap()
        units = font["head"].unitsPerEm
        scale = size / units
        paths, offset = [], 0
        for char in value:
            name = cmap[ord(char)]
            pen = SVGPathPen(glyphs)
            glyphs[name].draw(pen)
            if pen.getCommands():
                paths.append(f'<path transform="translate({offset:.2f} 0)" d="{pen.getCommands()}"/>')
            offset += glyphs[name].width + spacing / scale
        self.add(f'<g aria-label="{escape(value, quote=True)}" fill="{color}" '
                 f'transform="translate({x} {y}) scale({scale:.6f} {-scale:.6f})">'
                 + "".join(paths) + "</g>")

    def write(self, name, description):
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.width}" height="{self.height}" '
               f'viewBox="0 0 {self.width} {self.height}" role="img" aria-labelledby="title desc">'
               f'<title id="title">{escape(self.title)}</title><desc id="desc">{escape(description)}</desc>'
               + "".join(self.parts) + "</svg>\n")
        (OUT / name).write_text(svg, encoding="utf-8")


def cover(font, mobile=False, still=False):
    width, height = (600, 392) if mobile else (1200, 318)
    d = Drawing(font, width, height, "TgWitness — Your Telegram observation workspace")
    d.add(f'<defs><linearGradient id="background" x2="1" y2="1"><stop stop-color="#111e31"/>'
          '<stop offset="1" stop-color="#09121f"/></linearGradient>'
          '<radialGradient id="glow"><stop stop-color="#285590" stop-opacity=".25"/>'
          '<stop offset="1" stop-color="#285590" stop-opacity="0"/></radialGradient></defs>'
          f'<rect x=".5" y=".5" width="{width-1}" height="{height-1}" rx="20" fill="url(#background)" stroke="#2c3c52"/>'
          f'<ellipse cx="{width*.75}" cy="{height*.4}" rx="{width*.4}" ry="{height*.8}" fill="url(#glow)"/>')
    mark = (ROOT / "tgwitness/static/mark.svg").read_text(encoding="utf-8")
    mark = mark.replace('viewBox="0 0 48 48"', 'x="36" y="32" width="34" height="34" viewBox="0 0 48 48"')
    d.add(mark)
    d.text("PHISHDESTROY  /  SELF-HOSTED", 84, 54, 13, "#a8bbd2", 600, 1)
    d.text("TgWitness", 34, 152 if mobile else 161, 79 if mobile else 88, weight=700, spacing=-3)
    if mobile:
        d.text("Your Telegram", 38, 196, 25, "#b6cce6")
        d.text("observation workspace.", 38, 230, 25, "#b6cce6")
        d.add('<path d="M38 262H562" stroke="#2c3c52"/>')
        labels = [("01", "Capture", 38), ("02", "Investigate", 217), ("03", "Verify", 422)]
        for index, (num, label, x) in enumerate(labels):
            d.text(num, x, 299, 13, "#77b7ff", 600)
            d.text(label, x, 333, 24, weight=600)
            if not still:
                values = ";".join("1" if step == index else ".15" for step in (0,1,2,0))
                d.add(f'<rect x="{x}" y="351" width="110" height="3" rx="1.5" fill="#77b7ff" class="trace">'
                      f'<animate attributeName="opacity" values="{values}" keyTimes="0;.333;.667;1" calcMode="discrete" dur="6s" repeatCount="indefinite"/></rect>')
        d.add('<path d="M151 321h31m-6-5 6 5-6 5M356 321h31m-6-5 6 5-6 5" fill="none" stroke="#708ba9" stroke-width="1.5"/>')
    else:
        d.text("Your Telegram observation workspace.", 40, 207, 25, "#b6cce6")
        d.add('<path d="M40 246H568" stroke="#2c3c52"/>')
        d.text("CAPTURE", 40, 281, 13, "#a8bbd2", 600, 1.8)
        d.text("INVESTIGATE", 222, 281, 13, "#a8bbd2", 600, 1.8)
        d.text("VERIFY", 453, 281, 13, "#a8bbd2", 600, 1.8)
        d.add('<path d="M175 275h21m-5-4 5 4-5 4M406 275h21m-5-4 5 4-5 4" fill="none" stroke="#708ba9" stroke-width="1.4"/>')
        d.text("THE OBSERVATION JOURNAL", 714, 44, 12, "#a8bbd2", 600, 1.3)
        d.add('<path d="M684 95V245" stroke="#3e5e80" stroke-width="2"/>')
        records = [(68, "01", "Message captured", "NEW"), (144, "02", "Another version retained", "EDIT"),
                   (220, "03", "Deletion notice recorded", "DELETE")]
        for index, (y, num, label, state) in enumerate(records):
            d.add(f'<rect x="711" y="{y}" width="449" height="62" rx="10" fill="#142339" stroke="#314960"/>'
                  f'<path d="M684 {y+31}h27" stroke="#3e5e80" stroke-width="2"/>'
                  f'<circle cx="684" cy="{y+31}" r="5" fill="#0c1726" stroke="#77b7ff" stroke-width="2"/>')
            d.text(num, 731, y+37, 14, "#8cabc9", 600)
            d.text(label, 767, y+37, 18, weight=500)
            d.text(state, 1082 if state != "DELETE" else 1062, y+36, 12, "#94c5fc", 600, .6)
            if not still:
                values = ";".join(".9" if step == index else "0" for step in (0,1,2,0))
                d.add(f'<rect class="trace" x="711" y="{y}" width="449" height="62" rx="10" fill="none" stroke="#8ac1ff" stroke-width="2">'
                      f'<animate attributeName="opacity" values="{values}" keyTimes="0;.333;.667;1" calcMode="discrete" dur="6s" repeatCount="indefinite"/></rect>')
        if not still:
            d.add('<path class="trace" d="M684 99V251" stroke="#a1d0ff" stroke-width="3" stroke-linecap="round" '
                  'stroke-dasharray="14 138"><animate attributeName="stroke-dashoffset" from="152" to="0" dur="6s" repeatCount="indefinite"/></path>')
    if not still:
        d.add('<style>@media(prefers-reduced-motion:reduce){.trace{display:none}}</style>')
    suffix = "-mobile" if mobile and still else "-mobile-motion" if mobile else "-static" if still else ""
    d.write(f"repository-cover{suffix}.svg", "Capture, investigate and verify observations. The journal diagram is illustrative; it contains no account data.")


def button(font, name, title, subtitle, primary=False):
    d = Drawing(font, 248, 64, title + " — " + subtitle)
    d.add('<rect x=".5" y=".5" width="247" height="63" rx="9" '
          f'fill="{"#245fd4" if primary else "#142033"}" stroke="{"#4284ee" if primary else "#364b64"}"/>')
    d.text(title, 20, 28, 16, weight=700)
    d.text(subtitle, 20, 48, 11.5, "#dbe9ff" if primary else "#a9bed7", 500)
    d.add('<path d="M218 26l6 6-6 6m-9-6h15" fill="none" stroke="#dbe9ff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>')
    d.write(f"repository-{name}.svg", title + ". " + subtitle)


def animate():
    """Render a deterministic six-second image loop; no video player or network."""
    from PIL import Image
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel=os.environ.get("TGWITNESS_BROWSER_CHANNEL") or None)
        page = browser.new_page(reduced_motion="no-preference", device_scale_factor=1)
        page.route("http://**/*", lambda route: route.abort())
        page.route("https://**/*", lambda route: route.abort())
        for source, name, width, height in (("repository-cover.svg", "repository-cover.webp", 1200, 318),
                                            ("repository-cover-mobile-motion.svg", "repository-cover-mobile.webp", 600, 392)):
            page.set_viewport_size({"width": width, "height": height})
            page.set_content('<body style="margin:0;background:transparent">' + (OUT / source).read_text(encoding="utf-8"))
            page.locator("body>svg").evaluate("el=>el.pauseAnimations()")
            frames = []
            for frame in range(72):
                page.locator("body>svg").evaluate("(el,t)=>el.setCurrentTime(t)", frame / 12)
                frames.append(Image.open(BytesIO(page.screenshot(omit_background=True))).convert("RGBA"))
            target = OUT / name
            frames[0].save(target, save_all=True, append_images=frames[1:], duration=[83,83,84]*24,
                           loop=0, quality=89, method=6, minimize_size=True)
            with Image.open(target) as result:
                assert result.is_animated and result.n_frames > 1 and result.info["loop"] == 0
            print(f"{name}: {target.stat().st_size:,} bytes; 6-second loop")
        browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", type=Path, required=True)
    parser.add_argument("--animate", action="store_true", help="Also render the two animated WebP covers")
    args = parser.parse_args()
    fonts = {weight: instantiateVariableFont(TTFont(args.font), {"wght": weight}) for weight in (500, 600, 700)}
    cover(fonts)
    cover(fonts, still=True)
    cover(fonts, mobile=True, still=True)
    cover(fonts, mobile=True)
    button(fonts, "demo", "Open the demo", "Explore fictional records", primary=True)
    button(fonts, "setup", "Set up TgWitness", "Connect a dedicated account")
    button(fonts, "modes", "Modes & evidence", "Choose scope and verification")
    if args.animate:
        animate()
    print("Built four SVG covers and three navigation assets.")


if __name__ == "__main__":
    main()
