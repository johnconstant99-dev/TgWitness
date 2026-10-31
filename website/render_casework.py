"""Render the casework presentation with outlined local fonts and SVG motion.

No network or application access. Use --display-font SpaceGrotesk.ttf and
--text-font Manrope.ttf; both font licences are retained with the assets.
"""
import argparse

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from render_readme import Drawing, ROOT
from render_case_assets import save

INK = "#edf5fc"
MUTED = "#a0b6cb"
BLUE = "#8ccfff"
GOLD = "#dfbd86"
GREEN = "#98d8c0"
RED = "#f0a6a9"


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


def hero(display, text, mobile=False, still=False, wiki=False):
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
    save(d,'casework-chain'+('-mobile' if mobile else '')+('-static' if still else '')+'.svg','Illustrative records. Each event includes the previous hash. SHA-256 hashes canonical JSON, and Ed25519 signs the digest bytes. C is canonical encoding. Signatures do not establish Telegram origin or complete capture.')


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
            for draw in (chain,checkpoint):draw(text,mobile,still)
    print('Rendered 16 casework covers and evidence diagrams.')


if __name__=='__main__':main()
