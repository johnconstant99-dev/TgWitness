"""Render the casework presentation with outlined local fonts and SVG motion."""
import argparse

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_readme import Drawing, ROOT
from render_case_assets import save
from render_directory_headers import art_defs, box, line, label as art_label, check, route

INK = "#edf5fc"
MUTED = "#a0b6cb"
BLUE = "#8ccfff"
GOLD = "#dfbd86"
GREEN = "#98d8c0"
def canvas(font, width, height, title, still=False, corners=True):
    d = Drawing(font, width, height, title)
    d.add(f'''<defs>
<linearGradient id="paper" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#0c1c2e"/><stop offset="1" stop-color="#070f1b"/></linearGradient>
<radialGradient id="light"><stop stop-color="#335578" stop-opacity=".4"/><stop offset="1" stop-color="#16314e" stop-opacity="0"/></radialGradient>
<pattern id="dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r=".7" fill="#88bbdd" opacity=".18"/></pattern>
<clipPath id="canvas"><rect x="1" y="1" width="{width-2}" height="{height-2}" rx="20"/></clipPath>
</defs>
<g clip-path="url(#canvas)">
<rect x="1" y="1" width="{width-2}" height="{height-2}" rx="20" fill="url(#paper)" stroke="#2d4359"/>
<rect x="1" y="1" width="{width-2}" height="{height-2}" rx="20" fill="url(#dots)"/>
<ellipse cx="{width*.78}" cy="{height*.4}" rx="{width*.5}" ry="{height*.8}" fill="url(#light)"/>
</g>
''')
    if corners:
        d.add(f'<path d="M22 57V23h34M{width-56} {height-23}h34v-34" fill="none" stroke="#81bada" stroke-width="2"/>')
    if not still:
        d.add('''<style>
.focus{animation:focus 12s ease-in-out infinite}.delay-1{animation-delay:-8s}.delay-2{animation-delay:-4s}
.trace{stroke-dasharray:22 180;animation:trace 6s linear infinite}
.scan{animation:scan 8s ease-in-out infinite}
.cursor{animation:cursor 2.4s ease-in-out infinite}
@keyframes focus{0%,100%{stroke-opacity:.3}18%,32%{stroke-opacity:1}50%,85%{stroke-opacity:.3}}
@keyframes trace{to{stroke-dashoffset:-404}}
@keyframes scan{0%,100%{transform:translateX(0);opacity:.2}50%{transform:translateX(170px);opacity:.8}}
@keyframes cursor{0%,100%{opacity:.35}50%{opacity:1}}
</style>''')
    return d


def rule(d, y, x=40, right=None):
    right = right or d.width-40
    d.add(f'<path d="M{x} {y}H{right}" stroke="#30495f"/><path d="M{x} {y}h58" stroke="{GOLD}" stroke-width="2"/>')


def mark(d, x, y):
    svg=(ROOT/'tgwitness/static/mark.svg').read_text(encoding='utf-8')
    svg=svg.replace('viewBox="0 0 48 48"',f'x="{x}" y="{y}" width="36" height="36" viewBox="0 0 48 48"')
    d.add(svg.replace('id="g"','id="app-mark-gradient"').replace('url(#g)','url(#app-mark-gradient)'))


def main_cover(display, text, mobile, still):
    width, height = (640, 700) if mobile else (1200, 450)
    title = "Messages change. Keep the evidence."
    d = canvas(display, width, height, title, True, corners=False)
    d.add('<defs><linearGradient id="headline" x2="1" y2=".3">'
          '<stop stop-color="#9dbbff"/><stop offset="1" stop-color="#92e0cc"/>'
          '</linearGradient></defs>')
    if not still:
        d.add('''<style>
.readme-stage{animation:readme-stage 12.6s ease-in-out infinite}
.stage-1{animation-delay:-8.4s}.stage-2{animation-delay:-4.2s}
@keyframes readme-stage{0%,26%,100%{opacity:1}33%,93%{opacity:.13}}
@media(prefers-reduced-motion:reduce){.readme-stage{animation:none;opacity:1}}
</style>''')
    mark(d, 40, 32)
    d.text("TgWitness", 89, 60, 29, INK, 700, -.8)
    d.text("TELEGRAM INVESTIGATIONS", 40, 101, 13 if mobile else 12, BLUE, 600, 1.4)
    d.text("Messages change.", 37, 167 if mobile else 169, 58 if mobile else 55, INK, 700, -1.8)
    d.text("Keep the evidence.", 37, 231 if mobile else 230, 58 if mobile else 55, "url(#headline)", 700, -1.8)
    d.font = text
    d.text("Capture conversations. Keep the changes.", 40, 280, 25 if mobile else 21, MUTED)
    d.text("Share a record others can verify.", 40, 316, 25 if mobile else 21, MUTED)
    if not mobile:
        d.add('<path d="M40 357H584" stroke="#30495f"/>')
        for i, (label, x) in enumerate((("CAPTURE", 40), ("INVESTIGATE", 225), ("VERIFY", 449))):
            d.text(f"0{i+1}", x, 396, 12, GREEN, 600)
            d.text(label, x+27, 396, 13, MUTED, 600, .8)
        d.add('<path d="M170 391h22m-5-4 5 4-5 4M392 391h22m-5-4 5 4-5 4" '
              'fill="none" stroke="#6689aa" stroke-width="1.5"/>')
    x, y, w = (32, 353, 576) if mobile else (654, 99, 506)
    d.add(f'<rect x="{x}" y="{y}" width="{w}" height="279" rx="18" '
          'fill="#102136" stroke="#38516a"/>')
    d.add(f'<circle cx="{x+24}" cy="{y+26}" r="3.5" fill="{GREEN}"/>')
    d.text("ONE MESSAGE. ITS RECORDED HISTORY.", x+38, y+31, 15 if mobile else 11, MUTED, 600, .7)
    records = (("MESSAGE OBSERVED", "Meet at 14:00.", BLUE),
               ("EDIT PRESERVED", "Meet at 15:00.", GOLD),
               ("DELETION OBSERVED", "Saved versions remain.", GREEN))
    for i, (label, message, color) in enumerate(records):
        yy = y+49+i*72
        d.add(f'<rect x="{x+16}" y="{yy}" width="{w-32}" height="64" rx="10" '
              'fill="#152b42" stroke="#30485f"/>')
        d.add(f'<rect class="readme-stage stage-{i}" x="{x+16}" y="{yy}" width="{w-32}" '
              f'height="64" rx="10" fill="none" stroke="{color}" stroke-width="1.5"/>')
        d.text(f"0{i+1}", x+30, yy+39, 15, color, 600)
        d.text(label, x+66, yy+22, 13 if mobile else 11, color, 600, .6)
        d.text(message, x+66, yy+49, 23 if mobile else 21, INK, 600)
        d.add(f'<path d="m{x+w-50} {yy+30} 6 6 12-14" fill="none" '
              f'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')
    d.text("FICTIONAL EXAMPLE / SIGNED OBSERVATIONS", x+18, y+310, 16 if mobile else 11, MUTED, 500, .4)
    name = "casework-hero" + ("-mobile" if mobile else "") + ("-static" if still else "") + ".svg"
    save(d, name, title + " A fictional message changes from 'Meet at 14:00' to 'Meet at 15:00'. After a deletion notice, its captured versions remain in the signed journal. Capture, investigate and verify.")


def hero(display, text, mobile=False, still=False, wiki=False):
    if not wiki:
        return main_cover(display, text, mobile, still)
    width,height=(720,710) if mobile else (1440,550)
    if wiki:height=650 if mobile else 410
    title="Work the case. Keep the record." if wiki else "Follow the trail. Preserve the evidence."
    d=canvas(display,width,height,title,still)
    x=40 if mobile else 54
    mark(d,x,30)
    d.text("PHISHDESTROY / TGWITNESS",x+48,56,17,MUTED,600,1.2)
    d.text("INVESTIGATION HANDBOOK" if wiki else "TELEGRAM INVESTIGATION WORKSPACE",x,103,17,BLUE,600,1.6)
    if wiki:
        d.text("Work the case.",x-3,185 if mobile else 188,66 if mobile else 82,INK,700,-2)
        d.text("Keep the record.",x-3,260 if mobile else 278,66 if mobile else 82,BLUE,700,-2)
    else:
        d.text("TGWITNESS",x-4,207 if mobile else 218,95 if mobile else 108,INK,700,-3)
        d.text("Follow the trail.",x,268 if mobile else 289,39 if mobile else 42,INK,600,-.6)
        d.text("Preserve the evidence.",x,319 if mobile else 344,39 if mobile else 42,BLUE,600,-.6)
    d.font=text
    if not wiki and not mobile:
        d.text("Conversations. Connections.",x,371 if mobile else 403,25,MUTED)
        d.text("A record you can verify.",x,406 if mobile else 440,25,MUTED)
    elif wiki:
        d.text("Your first capture. Your next lead.",x,310 if mobile else 333,23,MUTED)
        d.text("Your signed handoff.",x,343 if mobile else 366,23,MUTED)
    sx,sy,sw=(40,365,640) if mobile else (830,80,555)
    if wiki:sx,sy,sw=(40,380,640) if mobile else (850,53,530)
    gap=(95 if mobile else 104) if not wiki else 69
    card_h=(76 if mobile else 84) if not wiki else 56
    rail=f'M{sx-15} {sy+card_h/2}V{sy+gap*2+card_h/2}'
    d.add(f'<path d="{rail}" fill="none" stroke="#35546d" stroke-width="2"/>')
    if not still:
        d.add(f'<circle r="5" fill="{GOLD}"><animateMotion path="{rail}" dur="6s" repeatCount="indefinite"/></circle>')
    labels = (("01 / CAPTURE", "Meet at 16:00",BLUE),("02 / SAVED EDIT", "Meet at 17:30",GOLD),("03 / DELETION OBSERVED", "The captured content stays.",GREEN))
    for i,(label,message,color) in enumerate(labels):
        yy=sy+i*gap
        if i:
            d.add(f'<path d="M{sx+23} {yy-gap+card_h}V{yy}" stroke="#44687d" stroke-width="2"/>'
                  f'<path class="trace" d="M{sx+23} {yy-gap+card_h}V{yy}" stroke="{GOLD}" stroke-width="3"/>')
        d.add(f'<rect x="{sx}" y="{yy}" width="{sw}" height="{card_h}" rx="10" fill="#102238" stroke="#3a5268"/>'
              f'<rect class="focus delay-{i}" x="{sx}" y="{yy}" width="{sw}" height="{card_h}" rx="10" fill="none" stroke="{color}" stroke-width="2"/>')
        d.text(label,sx+21,yy+23,14,color,600,1.1)
        d.text(message,sx+21,yy+(48 if wiki else 59),21 if wiki else 25,INK,600)
        if not wiki:
            d.add(f'<path d="m{sx+sw-44} {yy+43} 7 7 13-16" fill="none" stroke="{color}" stroke-width="2.5"/>')
    by=sy+gap*2+card_h+27
    d.add(f'<path d="M{sx+23} {by-27}v20h{sw-46}" fill="none" stroke="#44687d"/>'
          f'<circle class="cursor" cx="{sx+sw-23}" cy="{by-7}" r="4" fill="{GREEN}"/>')
    d.text("ILLUSTRATIVE RECORD / SIGNED OBSERVATIONS",sx,by+21,12,MUTED,600,1)
    if not wiki and not mobile:
        rule(d,height-57,x,width-x)
        for i,label in enumerate(["CAPTURE","CONNECT","PRESERVE","VERIFY"]):
            xx=x+i*((width-2*x)/4)
            d.text(f"0{i+1}",xx,height-25,13,GOLD,600)
            d.text(label,xx+27,height-25,14 if mobile else 16,MUTED,600,1)
    name="casework-handbook" if wiki else "casework-hero"
    save(d,name+("-mobile" if mobile else "")+("-static" if still else "")+".svg",title+". Illustrative message, edit and deletion observation; not a live account or screenshot.")


def diagram_header(d,kicker,title,subtitle,mobile):
    d.text(kicker,32,37,14,BLUE,600,1.2)
    d.text(title,32,85,30 if mobile else 36,INK,700,-.6)
    d.text(subtitle,32,121,20 if mobile else 22,MUTED)


def chain(text,mobile=False,still=False):
    w,h=(640,920) if mobile else (1200,428)
    d=canvas(text,w,h,'A change adds a record. It does not erase one.',still,corners=False)
    diagram_header(d,'THE SIGNED OBSERVATION JOURNAL','A change adds a record.','It does not erase one.',mobile)
    data=[('01 / MESSAGE.NEW','Meet at 10:00','previous_hash = 000...000','h1',BLUE),('02 / MESSAGE.EDITED','Meet at 11:00','previous_hash = h1','h2',GOLD),('03 / MESSAGE.DELETED','Deletion observed','previous_hash = h2','h3',GREEN)]
    for i,(label,message,previous,digest,color) in enumerate(data):
        x,y,cw,ch=(32,159+i*180,576,150) if mobile else (32+i*386,155,364,150)
        d.add(f'<rect x="{x}" y="{y}" width="{cw}" height="{ch}" rx="10" fill="#102238" stroke="#3b526a"/>'
              f'<path class="focus delay-{i}" d="M{x+15} {y+1}h{cw-30}" stroke="{color}" stroke-width="3"/>')
        d.text(label,x+20,y+29,15,color,600,.5)
        d.text(message,x+20,y+72,28 if mobile else 26,INK,600)
        d.text(previous,x+20,y+111,20 if mobile else 16,MUTED)
        d.text(digest+' / Ed25519 signed',x+20,y+137,17 if mobile else 15,GREEN)
        if i<2:
            path=f'M{x+30} {y+ch+3}v24m-5-6 5 6 5-6' if mobile else f'M{x+cw+3} {y+75}h17m-6-5 6 5-6 5'
            d.add(f'<path class="cursor" d="{path}" fill="none" stroke="{GOLD}" stroke-width="2"/>')
    y=716 if mobile else 332
    rule(d,y,32,w-32)
    d.text('h[i] = hex(SHA256(C(e[i])))',32,y+37,25 if mobile else 24,BLUE,600)
    d.text('s[i] = Ed25519.Sign(sk, unhex(h[i]))',32 if mobile else 556,y+(76 if mobile else 37),23 if mobile else 24,GREEN,600)
    d.text('Ed25519 signs the 32 digest bytes.',32,y+(119 if mobile else 69),20 if mobile else 17,MUTED)
    if mobile:d.text('Verify with a separately trusted key.',32,883,20,MUTED)
    save(d,'casework-chain'+('-mobile' if mobile else '')+('-static' if still else '')+'.svg','Illustrative records. Each event includes the previous hash. SHA-256 hashes canonical JSON, and Ed25519 signs the digest bytes. C is canonical encoding. Review signatures together with the acquisition record and coverage.')


def checkpoint(text,mobile=False,still=False):
    w,h=(640,830) if mobile else (1200,442)
    d=canvas(text,w,h,'Keep an independent point of comparison.',still,corners=False)
    diagram_header(d,'THE INDEPENDENT REFERENCE','A longer journal can still match' if mobile else 'A longer journal can match an earlier checkpoint.','an earlier checkpoint.' if mobile else 'Compare the retained boundary, not just the newest head hash.',mobile)
    x,y,cw=32,160,576 if mobile else 548
    d.add(f'<rect x="{x}" y="{y}" width="{cw}" height="170" rx="10" fill="#102238" stroke="#3b526a"/>')
    d.text('EXPORTED JOURNAL / 4 RECORDS',x+20,y+30,15,BLUE,600,.7)
    for i,label in enumerate(['h1','h2','h3','h4']):
        xx=x+22+i*126
        d.add(f'<rect x="{xx}" y="{y+57}" width="99" height="59" rx="7" fill="#0b192a" stroke="{GOLD if i==2 else "#3b526a"}"/>')
        d.text(label,xx+30,y+96,26,GOLD if i==2 else INK,600)
        if i<3:d.add(f'<path d="M{xx+100} {y+87}h25" stroke="{GOLD}"/>')
    d.text('Compare at record 3.',x+20,y+148,20,MUTED)
    x,y=(32,363) if mobile else (612,160)
    d.add(f'<rect x="{x}" y="{y}" width="{cw}" height="170" rx="10" fill="#112b2b" stroke="#42665c"/>'
          f'<rect class="focus" x="{x}" y="{y}" width="{cw}" height="170" rx="10" fill="none" stroke="{GREEN}"/>')
    d.text('RETAINED ELSEWHERE',x+20,y+30,15,GREEN,600,.7)
    d.text('count = 3  /  head = h3',x+20,y+80,29,INK,600)
    d.text('Checkpoint signature verified',x+20,y+120,21,MUTED)
    d.text('against the pinned collector key.',x+20,y+149,21,MUTED)
    y=587 if mobile else 373
    d.text('4 >= 3   AND   export.hash[3] = h3',32,y,26 if mobile else 27,GREEN,600)
    d.text('MATCH',32 if mobile else 1040,y+(49 if mobile else 0),24,GREEN,700,1)
    if mobile:
        d.text('A 2-record export fails: 2 < 3.',32,695,23,INK,600)
        d.text('The verifier also checks every record.',32,742,20,MUTED)
        d.text('A matching boundary alone is not enough.',32,775,20,MUTED)
    else:d.text('A 2-record export fails: 2 < 3. The verifier also checks every supplied record.',32,415,19,MUTED)
    save(d,'casework-checkpoint'+('-mobile' if mobile else '')+('-static' if still else '')+'.svg','Illustrative four-record export matches a separately retained checkpoint at record three after signature verification. A two-record export is too short. A matching boundary does not replace checking every event.')


def assurance_modes(text, mobile=False, still=False):
    width, height = (640, 1460) if mobile else (1200, 745)
    d = canvas(text, width, height, "Choose what backs the record.", still, corners=False)
    art_defs(d, still)
    diagram_header(d, "DEPLOYMENT / VERIFIABLE ASSURANCE", "Choose what backs the record.",
                   "One signed journal. Three deployment choices.", mobile)
    cards = (
        ("01", "Local", "Your machine or Docker", BLUE,
         ("Journal + file integrity", "Trusted collector fingerprint", "Retained checkpoint"),
         "Checks the saved observations"),
        ("02", "Audited VM", "Provider + tunnel records", GOLD,
         ("Provider-side access records", "Source + server identity", "Tunnel and firewall checks"),
         "Adds deployment context"),
        ("03", "Phala / Intel TDX", "Confidential virtual machine", GREEN,
         ("Intel quote + fresh challenge", "Measured OS + pinned app", "Key bound to signed statement"),
         "Adds hardware-backed measurements"),
    )
    for index, (number, title, subtitle, color, facts, scope) in enumerate(cards):
        x, y, cw, ch = (32, 151+index*258, 576, 238) if mobile else (32+index*386, 155, 364, 310)
        d.add(f'<g transform="translate({x} {y})">')
        box(d, 0, 0, cw, ch, "url(#card-dark)", "#405d71", 12)
        line(d, f"M17 1h{cw-34}", color, 2)
        art_label(d, number+" / DEPLOYMENT", 20, 28, 10, color)
        d.add('<g class="float-a">')
        if index == 0:
            box(d, 21, 60, 99, 66, "#0b2130", "#7799b0", 6)
            line(d, "M62 127v11m-23 0h48M36 81h44m-44 13h64m-64 13h36", color, 2)
            check(d, 92, 110, color, .7)
        elif index == 1:
            for yy in (61, 88, 115):
                box(d, 22, yy, 100, 23, "#122b3a", "#8f835f", 4)
                line(d, f"M34 {yy+8}h44m-44 7h29", color, 1.5)
                d.add(f'<circle cx="108" cy="{yy+12}" r="2.5" fill="{color}" class="live"/>')
        else:
            for n in range(5):
                off = 39+n*17
                line(d, f"M{off} 57v12m0 63v12M16 {off+29}h12m99 0h12", "#6c9a8b", 2)
            box(d, 28, 69, 99, 63, "#183f3d", "#80c0a8", 7)
            art_label(d, "TDX", 48, 109, 25, GREEN, 700)
            if not still:
                d.add('<rect x="28" y="69" width="99" height="63" rx="7" fill="none" stroke="#b5f6d7" stroke-width="2" opacity="0"><animate attributeName="opacity" values="0;.8;0" dur="4s" repeatCount="indefinite"/></rect>')
        d.add('</g>')
        art_label(d, title, 150, 84, 26 if mobile else 19, INK, 700)
        art_label(d, subtitle, 150, 110, 17 if mobile else 11, MUTED)
        for i, fact in enumerate(facts):
            fx, fy = (150, 137+i*23) if mobile else (22, 178+i*27)
            art_label(d, fact, fx, fy, 20 if mobile else 16, INK, 500)
        line(d, f"M20 {ch-42}h{cw-40}", "#39566a", 1)
        art_label(d, scope, 20, ch-17, 16 if mobile else 12, color)
        d.add('</g>')
    yy = 969 if mobile else 512
    art_label(d, "INSIDE THE TDX CHECK", 32, yy, 13, GREEN)
    art_label(d, "From Intel's root to the collected record.", 32, yy+34, 23 if mobile else 25, INK)
    stages = (("Intel root", "Certificates + revocation"),
              ("TDX quote", "Signature + freshness"),
              ("OS + app", "Recomputed measurements"),
              ("Collector key", "Signed statement binding"),
              ("Journal", "Attested process starts"))
    for i, (title, detail) in enumerate(stages):
        x, y, cw, ch = (32, yy+59+i*64, 576, 52) if mobile else (32+i*232, yy+64, 208, 81)
        if i:
            path = f"M{width/2} {y-12}v12" if mobile else f"M{x-24} {y+40}h24"
            route(d, path, still, GREEN, -i)
        box(d, x, y, cw, ch, "#0d2531", "#456c67", 7)
        art_label(d, title, x+16, y+(23 if mobile else 31), 18, INK)
        art_label(d, detail, x+(220 if mobile else 16), y+(32 if mobile else 58), 16 if mobile else 12, MUTED)
        if not still:
            d.add(f'<rect x="{x}" y="{y}" width="{cw}" height="{ch}" rx="7" fill="{GREEN}" opacity="0"><animate attributeName="opacity" values="0;.14;.14;0;0" keyTimes="0;.07;.16;.24;1" dur="10s" begin="{-10+i*1.7}s" repeatCount="indefinite"/></rect>')
    if mobile:
        art_label(d, "Attestation measures the collection environment.", 32, height-62, 18, MUTED)
        art_label(d, "Review the acquisition record and recorded coverage.", 32, height-31, 17, MUTED)
    else:
        art_label(d, "Attestation verifies the measured collection environment and its recorded identity.", 32, height-31, 17, MUTED)
    save(d, "casework-assurance"+("-mobile" if mobile else "")+("-static" if still else "")+".svg",
         "Local verification checks journal and files against trusted inputs. An audited VM adds provider and access records. Optional Phala Intel TDX checks the quote, measured OS and application, and collector identity. Review these results together with the capture records and recorded coverage.")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--display-font',required=True)
    p.add_argument('--text-font',required=True)
    args=p.parse_args()
    def fonts(path):return {w:instantiateVariableFont(TTFont(path),{'wght':w},inplace=False) for w in (500,600,700)}
    display,text=fonts(args.display_font),fonts(args.text_font)
    for mobile in (False,True):
        for still in (False,True):
            for wiki in (False,True):hero(display,text,mobile,still,wiki)
            for draw in (chain,checkpoint,assurance_modes):draw(text,mobile,still)
    print('Rendered 20 casework covers and evidence diagrams.')


if __name__=='__main__':main()
