"""Validate the assembled DESIGN.md against the section files and the task's checks (seventh assembly).

Usage: python3 -I validate7.py <design_dir> <asm_dir> <design_md> <research_dir_abs> [<out_json>]
Writes <out_json> (default <asm_dir>/v7/validate.json) and prints a summary. Uses v7/extract.json, v7/cites.json,
v7/words.json, v7/text_checks.json and v7/hits_class.json (from extract.py, cites6.py, wordcount2.py, text_checks6.py,
v7/supersede_grep7.py with v7/hitmap7.py and v7/classify7.py), and owner/DECISIONS.md.
Changes from validate6.py: the v7 inputs; the grep's STATED readings counted apart; the owner record's Q- ids read
from whole entries as well as headings, and every item a 2026-11-04 entry names checked for "Decided by owner
2026-11-04"; mentions of the items decided since the 2026-11-04 peer review checked outside their own items; and the
generated text (front matter and appendices) grepped for open-question and withdrawn-figure phrasing.
"""
import json, re, runpy, sys, pathlib, collections

design = pathlib.Path(sys.argv[1]); asm = pathlib.Path(sys.argv[2])
doc_path = pathlib.Path(sys.argv[3]); research_dir = pathlib.Path(sys.argv[4])
out_json = pathlib.Path(sys.argv[5]) if len(sys.argv) > 5 else asm / 'v7' / 'validate.json'
V7 = asm / 'v7'
C = runpy.run_path(str(asm / 'common.py'))
doc = doc_path.read_text()
lines = doc.split('\n')
mask = C['code_mask'](lines)
EX = json.loads((V7 / 'extract.json').read_text())
out = {}

# ---------------------------------------------------------------- 1. ids unique (definitions in the section files)
defs = collections.defaultdict(list)
for f in sorted((design / 'sections').glob('*.md')):
    sl = f.read_text().split('\n'); m = C['code_mask'](sl)
    for k, l in enumerate(sl):
        if m[k]:
            continue
        mm = re.match(r'^\*\*([DQ]-[A-Z]+-\d+)[^*]*\*\*', l)
        if mm:
            defs[mm.group(1)].append(f"{f.name}:{k+1}")
        mm = re.match(r'^\|\s*(R-[A-Z]+-\d+)\s*\|', l)
        if mm:
            defs[mm.group(1)].append(f"{f.name}:{k+1}")
        mm = re.match(r'^- \*\*(I-\d+)[ .(]', l)
        if mm:
            defs[mm.group(1)].append(f"{f.name}:{k+1}")
dups = {k: v for k, v in defs.items() if len(v) > 1}
fam = collections.Counter(k.split('-')[0] for k in defs)
# own-section check: D-/Q-/R- CODE matches the file's CODE
wrong_sec = [(k, v) for k, v in defs.items() if k[0] in 'DQR' and k.split('-')[1] not in v[0].split(':')[0]]
inv = sorted(int(k.split('-')[1]) for k in defs if k.startswith('I-'))
# references to undefined ids anywhere in the doc (outside code)
undefined = collections.Counter()
for k, l in enumerate(lines):
    if mask[k]:
        continue
    for m in re.finditer(r'(?<![\w-])([DQR]-[A-Z]+-\d+|I-\d+)(?![\w])', l):
        if m.group(1) not in defs:
            undefined[m.group(1)] += 1
out['ids'] = {'counts': dict(fam), 'duplicates': dups, 'defined_outside_own_section': wrong_sec,
              'invariants': f"I-{inv[0]}..I-{inv[-1]}, {len(inv)} defined" if inv else 'none',
              'undefined_references': dict(undefined)}

# ---------------------------------------------------------------- 2. §N references resolve
heads = set()
for (k, lvl, title) in C['headings'](doc):
    m = re.match(r'^(\d+(?:\.\d+)*)\.?\s', title)
    if m and lvl in (2, 3, 4):
        heads.add(m.group(1).rstrip('.'))
EXTERNAL = re.compile(r'(RFC\s?\d+(?:,)?\s*$|RFC\s?\d+\s+(?:Appendix\s+\w+\s+)?$|U\.S\.C\.\s*$|CONVENTIONS(?:\.md)?\s*$|OUTLINE(?:\.md)?\s*$|APPLY(?:\.md)?\s*$|'
                      r'\.md\s*$|\]\([^)]*\)\s*$|\]\s*$|SUBPROTOCOL\.md\s*$|Art\.\s*\d+\s*$|DSA\s*$|PLAN\s*$|17\s*$|18\s*$|'
                      r'draft-[\w-]+\s*$|SP\s*800-\d+\w*\s*$|ISO[\w ]*$|BCP\s*\d+\s*$)')
refs, unresolved, external = 0, [], collections.Counter()
for k, l in enumerate(lines):
    for m in re.finditer(r'§\s?(\d+(?:\.\d+)*)', l):
        refs += 1
        num = m.group(1)
        if num in heads:
            continue
        pre = l[max(0, m.start() - 40):m.start()]
        if EXTERNAL.search(pre):
            external[re.sub(r'.*?([A-Za-z.\]]+\S*)\s*$', r'\1', pre)[-24:]] += 1
            continue
        # the RFC 9420 feature table in §10.4 and similar rows cite RFC sections by number only
        unresolved.append({'line': k + 1, 'ref': '§' + num, 'context': l[max(0, m.start() - 80):m.end() + 40], 'in_code': mask[k]})
# Known non-section references, checked by hand: §0 is the owner directive (front matter: "the directive ... or §0");
# the others are RFC or U.S.C. subsections whose standard name sits earlier in the sentence or table.
KNOWN = {'§0': 'owner directive (front matter)', '§12.4.3': 'RFC 9420 §12.4.3 (§10.4 feature table)',
         '§4.5.3.2.7': 'RFC 5321 §4.5.3.2.7', '§3123': '18 U.S.C. §3123', '§512': '17 U.S.C. §512',
         '§2258': '18 U.S.C. §2258A', '§2703': '18 U.S.C. §2703(f) preservation'}
known = [dict(u, reading=KNOWN[u['ref']]) for u in unresolved if u['ref'] in KNOWN]
unresolved = [u for u in unresolved if u['ref'] not in KNOWN]
out['section_refs'] = {'references': refs, 'unresolved': unresolved, 'known_external': known,
                       'external_context_counts': dict(external)}

# ---------------------------------------------------------------- 3. [R:key] links
rl = re.findall(r'\[R:([a-z0-9-]+)\]\(([^)]*)\)', doc)
# The research sheets moved to design/design-research/ on 2026-11-05; accept that root and the earlier one.
bad_r = [(k, t) for k, t in rl if not (research_dir / pathlib.Path(t).name).exists() or not re.match(r'(?:design/)?design-research/', t)]
unconv = []
for k, l in enumerate(lines):
    if mask[k]:
        continue
    for p in re.split(r'(`[^`]*`)', l):
        if p.startswith('`'):
            continue
        for m in re.finditer(r'\[R:([a-z0-9-]+)\](?!\()', p):
            unconv.append({'line': k + 1, 'key': m.group(1)})
out['r_links'] = {'links': len(rl), 'distinct': sorted(set(k for k, t in rl)), 'broken': bad_r, 'unconverted': unconv}

# ---------------------------------------------------------------- 4. X1-X20 owning items
OWNER = {'X1': 13, 'X2': 11, 'X3': 8, 'X4': 12, 'X5': 12, 'X6': 15, 'X7': 14, 'X8': 6, 'X9': 4, 'X10': 5, 'X11': 20,
         'X12': 10, 'X13': 19, 'X14': 18, 'X15': 23, 'X16': 20, 'X17': 12, 'X18': 17, 'X19': 11, 'X20': 16}
CO = {'X3': {7}, 'X10': {20}, 'X11': {6}, 'X13': {11}, 'X17': {2}}
xo = {x: [] for x in OWNER}; xother = []
for d in EX:
    for it in d['items']:
        if not it['id'].startswith('Q-'):
            continue
        m = re.match(r'^\*\*Q-[A-Z]+-\d+[^*]*\*\*\s*(?:Cross-cutting[^.]*\.\s*)?\[(X\d+)[^\]]*\]', it['text'])
        if m:
            x = m.group(1)
            if d['num'] == OWNER[x]:
                xo[x].append(it['id'])
            else:
                xother.append({'x': x, 'item': it['id'], 'section': d['num'], 'co_owner': d['num'] in CO.get(x, set())})
out['x_items'] = {'owning': xo, 'missing': [x for x, v in xo.items() if not v], 'tagged_outside_owner': xother}

# ---------------------------------------------------------------- 5. anchors: TOC and every internal link
sl = C['Slugger']()
anchors = set(sl.slug(t) for (k, lvl, t) in C['headings'](doc))
anchors |= set(re.findall(r'<a id="([^"]+)"></a>', doc))
toc_start = doc.index('## Contents'); toc_end = doc.index('\n## 1. ')
toc_links = re.findall(r'\]\(#([^)]+)\)', doc[toc_start:toc_end])
all_links = re.findall(r'\]\(#([^)]*)\)', doc)
out['anchors'] = {'toc_links': len(toc_links), 'toc_missing': [a for a in toc_links if a not in anchors],
                  'internal_links': len(all_links), 'internal_missing': sorted(set(a for a in all_links if a not in anchors))}
# every ## and ### heading of sections and appendices is in the TOC
want = [sl2 for (k, lvl, t) in C['headings'](doc) for sl2 in [t] if lvl in (2, 3) and (re.match(r'^\d+\.', t) or t.startswith('Appendix'))]
out['anchors']['sections_and_appendices'] = sum(1 for (k, lvl, t) in C['headings'](doc) if lvl == 2 and (re.match(r'^\d+\.', t) or t.startswith('Appendix')))
rel = [m for m in re.findall(r'\]\(((?!#|https?:)[^)]+)\)', doc)]
out['anchors']['relative_links_missing'] = sorted(set(r for r in rel if not (doc_path.parent / r.split('#')[0]).exists()))

# ---------------------------------------------------------------- 6. owner decisions cited
cites = json.loads((V7 / 'cites.json').read_text())
od_links = sorted(set(int(x) for x in re.findall(r'\]\(#od-(\d+)\)', doc)))
SUPERSEDED = {1, 2, 16, 18, 21, 24, 28, 29, 31, 35, 51, 54, 60, 89, 90, 107, 114, 116, 117, 136, 137, 138, 139}  # APPLY.md §2 plus entries 112-145 (in whole or in part)
uncited = cites['uncited']
out['owner_decisions'] = {'cited_distinct': len(cites['cited']), 'uncited_1_145': uncited,
                          'uncited_not_superseded': [n for n in uncited if n not in SUPERSEDED],
                          'uncited_superseded': [n for n in uncited if n in SUPERSEDED],
                          'linked_targets_missing': [n for n in od_links if f'od-{n}' not in anchors],
                          'linked_distinct': len(od_links),
                          'rows': len(re.findall(r'<a id="od-\d+"></a>', doc))}

# ---------------------------------------------------------------- 7. section text checks
tc = json.loads((V7 / 'text_checks.json').read_text())
out['text'] = {'reviewer_ids': tc['reviewer_ids'], 'bare_placeholders': tc['bare_placeholders']}

# ---------------------------------------------------------------- 8. word counts
out['words'] = json.loads((V7 / 'words.json').read_text())

# ---------------------------------------------------------------- 9. sections verbatim (after the three transforms)
verb = []
for f in sorted((design / 'sections').glob('*.md'), key=lambda p: int(p.name.split('-')[0])):
    num = int(f.name.split('-')[0])
    src = f.read_text().strip('\n')
    start = doc.index(f"\n## {num}. ") + 1
    nxt = re.search(r'\n## (?:\d+\. |Appendix )', doc[start + 5:])
    body = doc[start:start + 5 + nxt.start()] if nxt else doc[start:]
    body = re.sub(r'\[R:([a-z0-9-]+)\]\((?:design/)?design-research/\1\.md\)', r'[R:\1]', body)
    body = re.sub(r'\[(owner decisions? \d+)\]\(#od-\d+\)', r'\1', body, flags=re.I)
    body = re.sub(r'\[(\d+)\]\(#od-\d+\)', r'\1', body)
    if body.strip('\n') != src:
        a, b = body.strip('\n').split('\n'), src.split('\n')
        diff = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), min(len(a), len(b)))
        verb.append({'file': f.name, 'first_diff_line': diff + 1,
                     'doc': a[diff][:160] if diff < len(a) else None, 'src': b[diff][:160] if diff < len(b) else None})
out['sections_verbatim'] = {'mismatches': verb}

# ---------------------------------------------------------------- 10. tables: consistent column counts
bad_tables = []
k = 0
while k < len(lines):
    if not mask[k] and lines[k].startswith('|') and k + 1 < len(lines) and re.match(r'^\|[-:| ]+\|\s*$', lines[k + 1]):
        ncol = len(re.split(r'(?<!\\)\|', lines[k].strip().strip('|')))
        j = k + 2
        while j < len(lines) and lines[j].startswith('|'):
            n = len(re.split(r'(?<!\\)\|', re.sub(r'`[^`]*`', 'x', lines[j]).strip().strip('|')))
            if n != ncol:
                bad_tables.append({'line': j + 1, 'expected': ncol, 'got': n, 'text': lines[j][:120]})
            j += 1
        k = j
    else:
        k += 1
out['tables'] = {'bad_rows': bad_tables}

# ---------------------------------------------------------------- 11. Appendix G vs §2.8 (a pointer, FRONT-35)
t2 = (design / 'sections' / '02-TRUST.md').read_text()
i = t2.index('**The list**'); j = t2.index('```yaml', i); kk = t2.index('\n```', j + 7)
yaml = t2[j + 7:kk]
yrows, cur = collections.OrderedDict(), None
for l in yaml.split('\n'):
    m = re.match(r'^([a-z]+-\d+):\s*$', l)
    if m:
        cur = m.group(1); yrows[cur] = False; continue
    if re.match(r'^\s+withdrawn:', l) and cur:
        yrows[cur] = True
hdr = re.search(r'metadata_list\.yml (v\d+), updated (\d{4}-\d\d-\d\d)', yaml)
if not hdr:
    _vv = re.search(r'metadata_list\.yml (v\d+);', yaml)
    hdr = _vv and re.search(r'^# (' + _vv.group(1) + r'), updated (\d{4}-\d\d-\d\d)', yaml, re.M)
g0 = doc.index('## Appendix G.'); g1 = doc.index('## Appendix H.')
gtext = doc[g0:g1]
gmis = []
if hdr.group(1) not in gtext or hdr.group(2) not in gtext:
    gmis.append('version or date differs from §2.8')
if f"has {len(yrows)} rows, {sum(yrows.values())} of them withdrawn" not in gtext:
    gmis.append('row census differs from §2.8')
for rid, w in yrows.items():
    if w and rid not in gtext:
        gmis.append(f'withdrawn row {rid} not named')
stmt = re.search(r'Statement \(D-TRUST-4\): \*(.*?)\*', t2).group(1)
for phrase in ("never receive plaintext content or keys, in any mode", "rpt.bringyour.com"):
    if phrase not in stmt:
        gmis.append(f'§2.8 statement lacks "{phrase}"')
if 'platform report listener' not in gtext or 'never receive plaintext content or keys, in any mode' not in gtext:
    gmis.append('pointer text lacks the statement or its exception')
out['appendix_g'] = {'form': 'pointer to §2.8 (FRONT-35)', 'yaml_version': hdr.group(1), 'yaml_date': hdr.group(2),
                     'yaml_rows': len(yrows), 'withdrawn': [r for r, w in yrows.items() if w], 'mismatches': gmis,
                     'pipe_rows_in_appendix': len(re.findall(r'^\| ', gtext, re.M))}
grows = {}

# ---------------------------------------------------------------- 12. superseded-option grep (classification is manual)
hits = json.loads((V7 / 'hits_class.json').read_text())
out['supersede_grep'] = {'hits': len(hits), 'keys': len(set((h['family'], h['file'], h['line']) for h in hits)),
                         'by_family': dict(collections.Counter(h['family'] for h in hits)),
                         'live': [{k: h[k] for k in ('family', 'file', 'line', 'match', 'reading')} for h in hits if h['live']],
                         'gap': [{k: h[k] for k in ('family', 'file', 'line', 'match', 'reading')} for h in hits if h.get('gap')],
                         'stated': [{k: h[k] for k in ('family', 'file', 'line', 'match', 'reading')} for h in hits if h.get('stated')],
                         'by_source': dict(collections.Counter(h.get('source', '') for h in hits)),
                         'unclassified': [h for h in hits if h['reading'] == 'UNCLASSIFIED']}

# ---------------------------------------------------------------- 13. §23.6 covers every open item
p6 = re.search(r'### 23\.6 .*?(?=\n### )', (design / 'sections' / '23-PHASE.md').read_text(), re.S).group(0)
listed = set(re.findall(r'Q-[A-Z]+-\d+', p6))
for m in re.finditer(r'(Q-[A-Z]+)-(\d+), -(\d+)', p6):
    listed.add(f"{m.group(1)}-{m.group(3)}")
PEERC = '**Closed by peer review 2026-11-04:**'


def qst(it):
    lab, t = it['label'], it['text']
    if 'withdrawn' in lab:
        return 'withdrawn'
    if 'closed' in lab:
        return 'closed'
    d, c = t.find('Decided by owner'), t.find(PEERC)
    if d >= 0 and (c < 0 or d < c):
        return 'decided'
    return 'peer-closed' if c >= 0 else 'open'


openq, peerq = [], []
for d in EX:
    for it in d['items']:
        if it['id'].startswith('Q-'):
            st = qst(it)
            if st == 'open':
                openq.append(it['id'])
            elif st == 'peer-closed':
                peerq.append(it['id'])
out['phase_blockers'] = {'open': openq, 'not_in_23_6': [q for q in openq if q not in listed],
                         'peer_closed': len(peerq), 'peer_closed_not_in_23_6': [q for q in peerq if q not in listed]}

# ---------------------------------------------------------------- 14. glossary size
c0 = doc.index('## Appendix C.'); c1 = doc.index('## Appendix D.')
out['glossary'] = {'words': len(doc[c0:c1].split()), 'terms': doc[c0:c1].count('\n- **')}

gen_bad = []
sec_spans = []
for f in sorted((design / 'sections').glob('*.md'), key=lambda p: int(p.name.split('-')[0])):
    num = int(f.name.split('-')[0])
    st = doc.index(f"\n## {num}. ") + 1
    nx = re.search(r'\n## (?:\d+\. |Appendix )', doc[st + 5:])
    sec_spans.append((st, st + 5 + nx.start() if nx else len(doc)))
pos = 0
for k, l in enumerate(lines):
    inside = any(a0 <= pos < b0 for a0, b0 in sec_spans)
    if not mask[k] and not inside:
        t = re.sub(r'`[^`]*`', '', l)
        t = re.sub(r'<a id="[^"]+"></a>', '', t)
        for m in re.finditer(r'<[A-Za-z/!?][^>\n]*>?', t):
            gen_bad.append({'line': k + 1, 'text': m.group(0)[:40], 'ctx': t[max(0, m.start() - 60):m.end() + 20]})
    pos += len(l) + 1
out['generated_bare_angles'] = gen_bad
out['od_link_date_fragments'] = [doc[max(0, m.start() - 60):m.end() + 20] for m in re.finditer(r'\d-\[\d+\]\(#od-\d+\)|\]\(#od-\d+\)-\d', doc)]

# ---------------------------------------------------------------- 15. owner record: Q- ids each decision names are not open
decs = (design / 'owner' / 'DECISIONS.md').read_text()
entries = {}
for m in re.finditer(r'^(\d{1,3})\. \*\*(.*?)\*\*', decs, re.M):
    entries[int(m.group(1))] = m.group(2)
qstatus = {it['id']: qst(it) for d in EX for it in d['items'] if it['id'].startswith('Q-')}
named_open = []
for n, head in sorted(entries.items()):
    for q in re.findall(r'Q-[A-Z]+-\d+', head):
        if qstatus.get(q) == 'open':
            named_open.append({'decision': n, 'q': q})
        if q not in qstatus:
            named_open.append({'decision': n, 'q': q, 'issue': 'no such item'})
open_items = [q for q, st in qstatus.items() if st == 'open']
qf = json.loads((V7 / 'qfields.json').read_text())
out['owner_record'] = {'entries': len(entries), 'entry_numbers_ok': sorted(entries) == list(range(1, 200)),
                       'q_named_by_decisions': sum(len(re.findall(r'Q-[A-Z]+-\d+', h)) for h in entries.values()),
                       'named_but_open': named_open,
                       'open_items': open_items,
                       'open_owner_decider': [q for q in open_items if qf.get(q, {}).get('decider', '').startswith('owner')]}
# Seventh assembly: Q- ids named anywhere in an entry (its body included, such as entry 140's correction naming
# Q-EVS-9), and every item a 2026-11-04 entry's heading names reading "Decided by owner 2026-11-04".
bodies = {}
_starts = [(int(m.group(1)), m.start()) for m in re.finditer(r'^(\d{1,3})\. \*\*', decs, re.M)]
for (n, s), nxt in zip(_starts, _starts[1:] + [(None, len(decs))]):
    body = decs[s:nxt[1]]
    h2 = re.search(r'^## ', body, re.M)
    bodies[n] = body[:h2.start()] if h2 else body
items_text = {it['id']: it['text'] for d in EX for it in d['items']}
body_named_open = sorted({(n, q) for n, b in bodies.items() for q in re.findall(r'Q-[A-Z]+-\d+', b) if qstatus.get(q) == 'open'})
body_named_missing = sorted({(n, q) for n, b in bodies.items() for q in re.findall(r'Q-[A-Z]+-\d+', b) if q not in qstatus})
not_dated_0304 = []
for n in range(112, 146):
    for q in re.findall(r'Q-[A-Z]+-\d+', entries.get(n, '')):
        if qstatus.get(q) == 'decided' and 'Decided by owner 2026-11-04' not in items_text[q]:
            not_dated_0304.append({'decision': n, 'q': q})
        elif qstatus.get(q) not in ('decided', None):
            not_dated_0304.append({'decision': n, 'q': q, 'status': qstatus.get(q)})
out['owner_record'].update({
    'q_named_in_bodies': len(set(q for b in bodies.values() for q in re.findall(r'Q-[A-Z]+-\d+', b))),
    'body_named_open': [list(x) for x in body_named_open], 'body_named_missing': [list(x) for x in body_named_missing],
    'entries_112_145_items_not_dated_2026_11_04': not_dated_0304,
    'q_evs_9_cites_140': bool(re.search(r'\*\*Decided by owner 2026-11-04 \(owner decision 140, record corrected\):\*\*',
                                        items_text.get('Q-EVS-9', ''))),
    'decider_lines_in_sections': sum(f.read_text().count('*Decider:*') for f in (design / 'sections').glob('*.md')),
})

# ---------------------------------------------------------------- 17. items decided since the peer review, mentioned elsewhere
LATE = ['Q-EVS-8', 'Q-MCP-6', 'Q-OPS-9', 'Q-KEYS-15', 'Q-OPS-10', 'Q-EVS-9']
OPENISH = re.compile(r'\bopen\b|pending|until the owner|owner to |undecided|asks the owner|awaits|\(proposed; Q-')
late = {q: {'mentions': 0, 'flagged': []} for q in LATE}
for f in sorted((design / 'sections').glob('*.md')):
    for k, l in enumerate(f.read_text().split('\n')):
        for q in LATE:
            for m in re.finditer(rf'(?<![\w-]){re.escape(q)}(?!\d)', l):
                if l.startswith(f'**{q}'):
                    continue  # the item itself
                late[q]['mentions'] += 1
                ctx = l[max(0, m.start() - 90):m.end() + 90]
                if OPENISH.search(ctx):
                    late[q]['flagged'].append({'file': f.name, 'line': k + 1, 'ctx': ctx})
out['late_items'] = late

# ---------------------------------------------------------------- 18. generated text: open-question and withdrawn-figure phrasing
GEN_PATS = {
    'open_phrase': r'\b(is|are|remains?|still) open\b|open for the owner|open owner question|\bwaits? for the owner\b',
    'q_evs_9': r'Q-EVS-9',
    'kib_10_15': r'10\s*[-–]\s*15 ?KiB',
    'sizing_145': r'490\s*[-–]\s*650|\b4\s*[-–]\s*5 sets\b|four to five (sets|clusters)',
    'pending': r'(if|until|unless|once|when) the owner (answers|decides|confirms|picks|chooses)|pending (the )?owner|\(proposed; Q-|left to peer review',
}
gen_hits = []
pos = 0
for k, l in enumerate(lines):
    inside = any(a0 <= pos < b0 for a0, b0 in sec_spans)
    pos += len(l) + 1
    if inside or mask[k]:
        continue
    for fam, pat in GEN_PATS.items():
        for m in re.finditer(pat, l, flags=re.I):
            gen_hits.append({'family': fam, 'line': k + 1, 'match': m.group(0),
                             'ctx': re.sub(r'\]\([^)]*\)', ']', l[max(0, m.start() - 110):m.end() + 110])})
out['generated_grep'] = gen_hits

# ---------------------------------------------------------------- 18b. decision-link style in generated text
# A sentence opening with a lowercase "[owner decision N]" link, and a list merged across a boundary such as
# "owner decisions 138, and 139 leaves" (a linked number after ", and " that the source did not list).
lc_start, merged = [], []
pos = 0
for k, l in enumerate(lines):
    inside = any(a0 <= pos < b0 for a0, b0 in sec_spans)
    pos += len(l) + 1
    if inside or mask[k]:
        continue
    for m in re.finditer(r'(?:^|[.!?]\s+|\|\s*)\[owner decisions? \d+\]', l):
        lc_start.append({'line': k + 1, 'ctx': l[max(0, m.start() - 60):m.end() + 40]})
    for m in re.finditer(r'\[\d+\]\(#od-\d+\), and \[\d+\]\(#od-\d+\)', l):
        merged.append({'line': k + 1, 'ctx': re.sub(r'\]\([^)]*\)', ']', l[max(0, m.start() - 80):m.end() + 40])})
out['od_link_style'] = {'lowercase_sentence_start': lc_start, 'comma_and_lists': merged}

# ---------------------------------------------------------------- 19. APPLY.md §6-§8: each section listed for 112-136 cites it
CODES = {c: i + 1 for i, c in enumerate('CTX TRUST ARCH REPO CORE PROTO TEAM ACL SOCK KEYS EVS DNS TLS SMTP MAIL MCP '
                                         'BRIDGE SDK OPS QUOTA ABUSE TEST PHASE'.split())}
apply_txt = (design / 'owner' / 'APPLY.md').read_text()
cited_by = {int(k): set(v) for k, v in cites['cited'].items()}
apply_rows, apply_missing = 0, []
for m in re.finditer(r'^\| (1[1-3]\d) \| [^|]* \| ([A-Z, ]+) \|', apply_txt, re.M):
    n = int(m.group(1))
    for code in [c.strip() for c in m.group(2).split(',')]:
        apply_rows += 1
        if CODES[code] not in cited_by.get(n, set()):
            apply_missing.append({'decision': n, 'section': f"§{CODES[code]} {code}"})
for m in re.finditer(r'^\| ([A-Z]+)(?: \(§[^)]*\))? \| ', apply_txt[apply_txt.index('## 8. '):apply_txt.index('## 9. ')], re.M):
    code = m.group(1)
    if code in CODES:
        apply_rows += 1
        if CODES[code] not in cited_by.get(136, set()):
            apply_missing.append({'decision': 136, 'section': f"§{CODES[code]} {code}"})
out['apply_sections'] = {'pairs_checked': apply_rows, 'missing': apply_missing}

# ---------------------------------------------------------------- 20. registers: coverage and word limits (20, 25, 15 words)
_regf = asm / 'data_registers10.py'
_regf = _regf if _regf.exists() else asm / 'data_registers9.py'
REG = runpy.run_path(str(_regf if _regf.exists() else asm / 'data_registers6.py'))
_dids = [it['id'] for d in EX for it in d['items'] if it['id'].startswith('D-')]
_qids = [it['id'] for d in EX for it in d['items'] if it['id'].startswith('Q-')]
_w = lambda s: len(s.split())
out['registers'] = {
    'd_missing': [i for i in _dids if i not in REG['D']], 'q_missing': [i for i in _qids if i not in REG['Q']],
    'd_extra': [i for i in REG['D'] if i not in _dids], 'q_extra': [i for i in REG['Q'] if i not in _qids],
    'd_over_20': [(i, _w(REG['D'][i])) for i in _dids if i in REG['D'] and _w(REG['D'][i]) > 20],
    'q_question_over_25': [(i, _w(REG['Q'][i][0])) for i in _qids if i in REG['Q'] and _w(REG['Q'][i][0]) > 25],
    'q_rec_over_15': [(i, _w(REG['Q'][i][1])) for i in _qids if i in REG['Q'] and _w(REG['Q'][i][1]) > 15],
    'stale_d': REG.get('STALE_D', {}), 'stale_q': REG.get('STALE_Q', {}),
}

# ---------------------------------------------------------------- 16. decisions-by-number rows and dates
# From 198 the design-records tracks number the build's owner answers as they fold them, so a later number can carry
# the bulk acceptance's earlier date; each such decision's date is listed here.
LATE_DATES = {198: '2026-11-10', 199: '2026-11-10'}
idx_rows = re.findall(r'^\| <a id="od-(\d+)"></a>\d+ \| (2026-11-(?:0[34569]|10)) \|', doc, re.M)
out['decision_rows'] = {'rows': len(idx_rows), 'numbers_ok': [int(n) for n, d in idx_rows] == list(range(1, 200)),
                        'dates_ok': all(d == ('2026-11-03' if int(n) <= 111 else '2026-11-04' if int(n) <= 145 else '2026-11-05' if int(n) <= 187 else '2026-11-06' if int(n) <= 196 else '2026-11-09' if int(n) == 197 else LATE_DATES.get(int(n))) for n, d in idx_rows),
                        'known_gaps_heading': '### Known gaps' in doc,
                        'closed_by_peer_review_text': len(re.findall(r'closed by peer review', doc))}

out_json.write_text(json.dumps(out, indent=1, ensure_ascii=False))
summary = {
    'ids': {'counts': out['ids']['counts'], 'duplicates': len(dups), 'outside_own_section': len(wrong_sec), 'invariants': out['ids']['invariants'],
            'undefined_refs': out['ids']['undefined_references']},
    'section_refs': {'refs': refs, 'unresolved': len(unresolved), 'known_external': len(known), 'external_by_context': sum(external.values())},
    'r_links': {'links': len(rl), 'broken': len(bad_r), 'unconverted': len(unconv)},
    'x_missing': out['x_items']['missing'], 'x_tagged_outside': out['x_items']['tagged_outside_owner'],
    'toc': {'links': len(toc_links), 'missing': len(out['anchors']['toc_missing'])},
    'internal_links_missing': out['anchors']['internal_missing'][:20], 'relative_missing': out['anchors']['relative_links_missing'],
    'uncited_decisions': cites['uncited'], 'od_rows': out['owner_decisions']['rows'], 'od_links_missing': out['owner_decisions']['linked_targets_missing'],
    'reviewer_ids': len(tc['reviewer_ids']), 'bare_placeholders': len(tc['bare_placeholders']),
    'verbatim_mismatches': verb[:5], 'bad_table_rows': bad_tables[:10],
    'appendix_g': {'yaml_rows': len(yrows), 'mismatches': gmis[:10]},
    'phase_blockers_missing': out['phase_blockers']['not_in_23_6'], 'glossary': out['glossary'],
    'supersede': {'hits': len(hits), 'keys': out['supersede_grep']['keys'], 'live': len(out['supersede_grep']['live']), 'gap': len(out['supersede_grep']['gap']),
                  'stated': len(out['supersede_grep']['stated']), 'unclassified': len(out['supersede_grep']['unclassified']),
                  'by_source': out['supersede_grep']['by_source']},
    'generated_bare_angles': out['generated_bare_angles'][:10],
    'od_link_date_fragments': out['od_link_date_fragments'][:10],
    'owner_record': {k: v for k, v in out['owner_record'].items() if k != 'open_items'},
    'decision_rows': out['decision_rows'],
    'late_items': {q: {'mentions': v['mentions'], 'flagged': len(v['flagged'])} for q, v in late.items()},
    'generated_grep': dict(collections.Counter(h['family'] for h in gen_hits)),
    'apply_sections': out['apply_sections'],
    'od_link_style': {k: len(v) for k, v in out['od_link_style'].items()},
    'registers': {k: (len(v) if isinstance(v, (list, dict)) else v) for k, v in out['registers'].items()},
}
print(json.dumps(summary, indent=1, ensure_ascii=False))
