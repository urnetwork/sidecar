"""Generate the README's service cards, services-light.svg and services-dark.svg, next to this file.

Run: python3 services_svg.py  (needs Pillow and macOS system fonts to measure line wrapping)."""
import os
from xml.sax.saxutils import escape
from PIL import ImageFont

OUT = os.path.dirname(os.path.abspath(__file__))
os.makedirs(OUT, exist_ok=True)

CARDS = [
    ('Encrypted storage', 'evs', 'storage',
     "Git repos and file trees, encrypted on your device: paths, names, messages and contents. "
     "Stock git still works, and subscribers hear of changes in real time."),
    ('Group keys', 'gkm · MLS', 'key',
     "Each repo is an MLS group with post-quantum hybrid keys. Members' devices hold the keys, "
     "agents get wrapped copies, and removing anyone rotates them."),
    ('Agent record', 'mcp · record', 'terminal',
     "One MCP server for Claude Code, Codex, Cursor and any harness. Every session and changed "
     "file lands in your encrypted vault, every approval as a signed receipt."),
    ('Email and burners', 'mail', 'mail',
     "Your own mail server, with unlimited aliases and burner addresses. Inbound TLS ends on your "
     "indexer, outbound TLS runs to the recipient, and the edges keep nothing."),
    ('Public HTTPS', 'tlsedge', 'globe',
     "Publish a local app at app.<net>.ur.network with an automatic certificate. The edge routes "
     "by SNI and never decrypts, and the key stays on your machine."),
    ('Private network', 'bridge', 'network',
     "A stable private address and name for every device and agent. Subnet routes and port "
     "forwards are granted by your access policy and carried end to end."),
    ('Sockets and sharing', 'sockets', 'plug',
     "Listen on a name instead of a port, and each dial reaches one listener, chosen by load. "
     "File-share links work a set number of times."),
    ('Teams and access', 'teams · acl', 'shield',
     "Members, roles, SSO, and enrollment by QR code or MDM. A deny-by-default policy is signed "
     "into your encrypted config and evaluated on every device."),
    ('Encrypted search', 'search · v1', 'search',
     "Each repo keeps an encrypted index its committers update. Search mail, notes and code, or "
     "find agents working on a task, and the server never sees your queries."),
]

# Icons drawn on a 24-unit grid, stroked.
ICONS = {
    'storage': '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5"/>'
               '<path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3"/>',
    'key': '<circle cx="8" cy="15" r="4.5"/><path d="M11.2 11.8L20 3"/><path d="M16.5 6.5l3 3"/><path d="M14 9l2 2"/>',
    'terminal': '<rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M7.5 10l3 3-3 3"/><path d="M13 16h4"/>',
    'mail': '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M3.5 7l8.5 6 8.5-6"/>',
    'globe': '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
    'network': '<circle cx="5.5" cy="6" r="2.5"/><circle cx="18.5" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/>'
               '<path d="M8 6h8"/><path d="M6.8 8.2l3.9 7.6"/><path d="M17.2 8.2l-3.9 7.6"/>',
    'plug': '<path d="M9 3v4"/><path d="M15 3v4"/><rect x="6.5" y="7" width="11" height="6" rx="1.5"/>'
            '<path d="M12 13v3.5a3 3 0 0 1-3 3H7"/>',
    'shield': '<path d="M12 3l7 3v5c0 4.6-3 8.3-7 10-4-1.7-7-5.4-7-10V6z"/><path d="M9 12l2 2 4-4"/>',
    'search': '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
}

THEMES = {
    'light': dict(card='#ffffff', stroke='#d0d7de', title='#1f2328', body='#4b535d', tag='#0e6b73',
                  tile='#e2f1f1', icon='#0e6b73', shadow=True),
    'dark': dict(card='#151b23', stroke='#3d444d', title='#f0f6fc', body='#b4bcc6', tag='#5bc0c8',
                 tile='#102f2f', icon='#5bc0c8', shadow=False),
}

W, COLS, MARGIN, GAP = 1000, 3, 6, 16
CW = (W - 2 * MARGIN - (COLS - 1) * GAP) / COLS      # card width
PAD = 22
BODY_PX, BODY_LH, TITLE_PX, TAG_PX = 19, 27, 22, 14
FAMILY = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, 'Liberation Sans', sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"

# Measure with the widest likely renderer fonts, so wrapped lines fit everywhere.
fonts = [ImageFont.truetype(p, BODY_PX) for p in
         ('/System/Library/Fonts/SFNS.ttf', '/System/Library/Fonts/Supplemental/Arial.ttf',
          '/System/Library/Fonts/Helvetica.ttc')]
tfonts = [ImageFont.truetype(p, TITLE_PX) for p in
          ('/System/Library/Fonts/SFNS.ttf', '/System/Library/Fonts/Supplemental/Arial Bold.ttf')]


def width(text, fs):
    return max(f.getlength(text) for f in fs)


def wrap(text, maxw):
    lines, cur = [], ''
    for word in text.split():
        cand = (cur + ' ' + word).strip()
        if width(cand, fonts) <= maxw:
            cur = cand
        else:
            lines.append(cur)
            cur = word
    lines.append(cur)
    return lines


TEXT_W = (CW - 2 * PAD) * 0.94                      # safety margin for other fonts
wrapped = [wrap(c[3], TEXT_W) for c in CARDS]
MAXL = max(len(w) for w in wrapped)
HEAD = 92                                           # icon row and title
CH = PAD + HEAD + (MAXL - 1) * BODY_LH + 6 + PAD    # card height
ROWS = (len(CARDS) + COLS - 1) // COLS
H = round(2 * MARGIN + ROWS * CH + (ROWS - 1) * GAP)


def svg(theme):
    t = THEMES[theme]
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
           f'role="img" aria-labelledby="t d">',
           '<title id="t">sidecar services</title>',
           '<desc id="d">' + escape('; '.join(f'{c[0]}: {c[3]}' for c in CARDS)) + '</desc>']
    if t['shadow']:
        out.append('<defs><filter id="s" x="-5%" y="-5%" width="110%" height="115%">'
                   '<feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#1f2328" flood-opacity="0.08"/>'
                   '</filter></defs>')
    for i, (title, tag, icon, _) in enumerate(CARDS):
        col, row = i % COLS, i // COLS
        x = MARGIN + col * (CW + GAP)
        y = MARGIN + row * (CH + GAP)
        filt = ' filter="url(#s)"' if t['shadow'] else ''
        out.append(f'<g transform="translate({x:.1f} {y:.1f})">')
        out.append(f'<rect width="{CW:.1f}" height="{CH}" rx="16" fill="{t["card"]}" stroke="{t["stroke"]}"{filt}/>')
        # icon tile
        out.append(f'<rect x="{PAD}" y="{PAD}" width="48" height="48" rx="12" fill="{t["tile"]}"/>')
        out.append(f'<g transform="translate({PAD + 9} {PAD + 9}) scale(1.25)" fill="none" stroke="{t["icon"]}" '
                   f'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{ICONS[icon]}</g>')
        # title and tag
        out.append(f'<text x="{PAD + 62}" y="{PAD + 21}" font-family="{FAMILY}" font-size="{TITLE_PX}" '
                   f'font-weight="700" fill="{t["title"]}">{escape(title)}</text>')
        out.append(f'<text x="{PAD + 62}" y="{PAD + 42}" font-family="{MONO}" font-size="{TAG_PX}" '
                   f'fill="{t["tag"]}">{escape(tag)}</text>')
        # body
        by = PAD + HEAD
        spans = ''.join(f'<tspan x="{PAD}" dy="{0 if k == 0 else BODY_LH}">{escape(line)}</tspan>'
                        for k, line in enumerate(wrapped[i]))
        out.append(f'<text y="{by}" font-family="{FAMILY}" font-size="{BODY_PX}" fill="{t["body"]}">{spans}</text>')
        out.append('</g>')
    out.append('</svg>')
    return '\n'.join(out) + '\n'


for theme in THEMES:
    p = f'{OUT}/services-{theme}.svg'
    open(p, 'w').write(svg(theme))
    print(p, os.path.getsize(p), 'bytes')
print('canvas', W, 'x', H, '| card', round(CW), 'x', CH, '| max lines', MAXL)
for c, w in zip(CARDS, wrapped):
    print(f'{c[0]:22s} {len(w)} lines; widest {max(width(l, fonts) for l in w):.0f}/{TEXT_W:.0f}')
print('title widths', {c[0]: round(width(c[0], tfonts)) for c in CARDS}, 'space', round(CW - PAD - 62 - PAD))
