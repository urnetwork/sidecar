"""Extract headings, D-/Q-/R- items and Interfaces blocks from the section files.
Usage: python3 -I extract.py <design_dir> <out_json>
"""
import re, sys, json, pathlib

base = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
secs = sorted((base / 'sections').glob('*.md'))

ITEM_RE = re.compile(r'^\*\*(?P<id>[DQ]-[A-Z]+-\d+[a-z]?)(?P<label>[^*]*)\*\*')
REQ_RE = re.compile(r'^\|\s*(?P<id>R-[A-Z]+-\d+[a-z]?)\s*\|')
HEAD_RE = re.compile(r'^(?P<hashes>#{1,6})\s+(?P<text>.*?)\s*$')

def code_mask(lines):
    mask = [False] * len(lines)
    infence, mark = False, None
    for k, l in enumerate(lines):
        s = l.lstrip()
        if not infence and (s.startswith('```') or s.startswith('~~~')):
            infence, mark = True, s[:3]; mask[k] = True; continue
        if infence:
            mask[k] = True
            if s.startswith(mark):
                infence = False
    return mask

data = []
for f in secs:
    num = int(f.name.split('-')[0])
    code = f.stem.split('-', 1)[1]
    lines = f.read_text().split('\n')
    mask = code_mask(lines)
    heads, items, reqs = [], [], []
    starts = []
    cur_sub = None
    for k, l in enumerate(lines):
        if mask[k]:
            continue
        m = HEAD_RE.match(l)
        if m:
            heads.append({'line': k + 1, 'level': len(m.group('hashes')), 'text': m.group('text')})
            cur_sub = m.group('text')
            starts.append(('h', k))
            continue
        m = ITEM_RE.match(l)
        if m:
            starts.append(('i', k, m.group('id'), m.group('label').strip(), cur_sub))
            continue
        m = REQ_RE.match(l)
        if m:
            reqs.append({'id': m.group('id'), 'line': k + 1, 'text': l})
    # item spans: until next start
    for idx, st in enumerate(starts):
        if st[0] != 'i':
            continue
        k = st[1]
        end = starts[idx + 1][1] if idx + 1 < len(starts) else len(lines)
        block = lines[k:end]
        # split into paragraphs
        paras, cur = [], []
        for l in block:
            if l.strip() == '':
                if cur: paras.append(cur); cur = []
            else:
                cur.append(l)
        if cur: paras.append(cur)
        iid = st[2]
        keep = []
        endkey = '*Decider:*' if iid.startswith('Q-') else '*Why:*'
        found = False
        for p in paras:
            keep.append(p)
            if any(endkey in l for l in p):
                found = True
                break
        if not found:
            # keep first paragraph plus following list/italic-label paragraphs
            keep = [paras[0]]
            for p in paras[1:]:
                if p[0].lstrip().startswith(('-', '*Options', '*Evidence', '*Recommendation', '*Blocks', '*Decider', '*Why', '*Decision', '*Residual')):
                    keep.append(p)
                else:
                    break
        text = '\n\n'.join('\n'.join(p) for p in keep)
        items.append({'id': iid, 'label': st[3], 'line': k + 1, 'sub': st[4], 'text': text})
    data.append({'file': f.name, 'num': num, 'code': code, 'heads': heads, 'items': items, 'reqs': reqs,
                 'nlines': len(lines)})
out.write_text(json.dumps(data, indent=1))
tot_d = tot_q = 0
for d in data:
    nd = sum(1 for it in d['items'] if it['id'].startswith('D-'))
    nq = sum(1 for it in d['items'] if it['id'].startswith('Q-'))
    tot_d += nd; tot_q += nq
    nodec = [it['id'] for it in d['items'] if it['id'].startswith('Q-') and '*Decider:*' not in it['text']]
    nowhy = [it['id'] for it in d['items'] if it['id'].startswith('D-') and '*Why:*' not in it['text']]
    print(f"{d['num']:2} {d['code']:7} D={nd:3} Q={nq:3} R={len(d['reqs']):3} Q-no-decider={nodec} D-no-why={nowhy}")
print('total D', tot_d, 'Q', tot_q)
