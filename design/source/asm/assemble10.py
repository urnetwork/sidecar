"""Assemble DESIGN.md (seventh assembly, 2026-11-05) from the 23 edited section files plus generated front matter,
the owner-decisions section and Appendices A-H.

Usage: python3 -I assemble7.py <design_dir> <asm_dir> <out_design_md> <research_rel_dir>
Reads (never writes) the section files. Writes <out_design_md> and <asm_dir>/v7/assemble_log.json.
Inputs in asm_dir: common.py; data_front8.py, data_registers7.py, data_appx7.py and data_glossary7.py, each falling
back to its *6 predecessor when a builder wrote no *7 file; v7/extract.json (extract.py), v7/qfields.json (fields.py),
v7/cites.json (cites6.py). Appendix G is a pointer to §2.8 (FRONT-35) with a row census computed from §2.8's
metadata_list.yml, checked against data_appx7.py's APPX_G.
Section bodies change in three ways only: [R:key] becomes a link to <research_rel_dir>/key.md; headings are
normalized ("## N." then "###" subsections); "owner decision N" links to row N of the decisions-by-number table.
Changes from assemble6.py: the *7 inputs; the Appendix B lead's zero-open wording; the appendix lead paragraphs
from data_appx7.py's INTRO; §4.6's connect rows from its CONNECT; Appendix H's "Cited in" column from its
RESEARCH_CITES; and cross-checks of data_registers7.py's QSTATUS and WITHDRAWN_D against the section text.
"""
import json, re, runpy, sys, pathlib, collections

design = pathlib.Path(sys.argv[1])
asm = pathlib.Path(sys.argv[2])
out_path = pathlib.Path(sys.argv[3])
research_rel = sys.argv[4].rstrip('/')
MAXD = 192
VDIR = asm / 'v7'


def load_data(stem):
    """data_<stem>7.py, or data_<stem>6.py when no seventh-build file exists."""
    for v in ('10', '9', '8', '7', '6'):
        p = asm / f'data_{stem}{v}.py'
        if p.exists():
            log_inputs[stem] = p.name
            return runpy.run_path(str(p))
    raise FileNotFoundError(stem)


log_inputs = {}
C = runpy.run_path(str(asm / 'common.py'))
F = load_data('front')
R = load_data('registers')
A = load_data('appx')
G = load_data('glossary')
EX = json.loads((VDIR / 'extract.json').read_text())
QF = json.loads((VDIR / 'qfields.json').read_text())
CITES = json.loads((VDIR / 'cites.json').read_text())
code_mask, HEAD_RE = C['code_mask'], C['HEAD_RE']

log = {'inputs': log_inputs, 'heading_changes': [], 'r_links': 0, 'od_links_sections': 0, 'od_links_generated': 0}
if 'CHECK' in F:
    log['front_check'] = F['CHECK']

# ------------------------------------------------------------------ helpers
NUM = r'\d{1,3}(?!\d)(?:\s*[-–]\s*\d{1,3}(?!\d))?(?![.]\d)(?!:\d)(?!-\d)'
OD_CITE = re.compile(r'(\b[Oo]wner\s+decisions?\s+)(' + NUM + r'(?:(?:\s*,\s*(?:and\s+)?|\s+and\s+)' + NUM + r')*)')


def link_od_segment(seg, counter):
    def rep_list(m):
        head, lst = m.group(1), m.group(2)

        def rep_num(n):
            k = int(n.group(0))
            if 1 <= k <= MAXD:
                counter[0] += 1
                return f"[{k}](#od-{k})"
            return n.group(0)
        if re.fullmatch(r'\d+', lst.strip()) and 1 <= int(lst) <= MAXD:
            counter[0] += 1
            return f"[{head}{int(lst)}](#od-{int(lst)})"
        return head + re.sub(r'\d+', rep_num, lst)
    return OD_CITE.sub(rep_list, seg)


def link_od(line, counter):
    """Link 'owner decision N' outside inline code spans."""
    parts = re.split(r'(`[^`]*`)', line)
    for i, p in enumerate(parts):
        if p.startswith('`') and p.endswith('`') and len(p) >= 2:
            continue
        parts[i] = link_od_segment(p, counter)
    return ''.join(parts)


def esc(text):
    """Escape '<' that would open an HTML tag (e.g. <net>) outside inline code, for generated text only."""
    parts = re.split(r'(`[^`]*`)', str(text))
    for i, p in enumerate(parts):
        if not (p.startswith('`') and p.endswith('`') and len(p) >= 2):
            parts[i] = re.sub(r'<(?=[A-Za-z/!?])', '&lt;', p)
    return ''.join(parts)


def od_placeholders(text):
    """@@OD:a@@, @@OD:b@@ and @@OD:c@@ -> 'owner decisions a, b and c'; a single one -> 'owner decision a'."""
    run = re.compile(r'@@OD:(\d+)@@((?:(?:, and |, | and )@@OD:\d+@@)*)')

    def rep(m):
        nums = [m.group(1)] + re.findall(r'@@OD:(\d+)@@', m.group(2))
        seps = re.findall(r'(, and |, | and )@@OD:', m.group(2))
        if len(nums) == 1:
            return f"owner decision {nums[0]}"
        s = nums[0]
        for sep, n in zip(seps, nums[1:]):
            s += sep + n
        return f"owner decisions {s}"
    return run.sub(rep, text)


def gen(text):
    """Generated text: placeholders, escaping, decision links, research links."""
    counter = [0]
    t = esc(od_placeholders(str(text)))
    t = link_od(t, counter)
    t = C['convert_r_links'](t, research_rel)
    log['od_links_generated'] += counter[0]
    return t


def cell(s):
    s = gen(str(s).replace('\n', ' '))
    return re.sub(r'(?<!\\)\|', r'\\|', s)


def table(header, rows):
    out = ['| ' + ' | '.join(header) + ' |', '|' + '|'.join(['---'] * len(header)) + '|']
    for r in rows:
        out.append('| ' + ' | '.join(cell(c) for c in r) + ' |')
    return '\n'.join(out)


# ------------------------------------------------------------------ sections
def normalize_section(num, text, fname):
    lines = text.split('\n')
    mask = code_mask(lines)
    first = True
    for k, l in enumerate(lines):
        if mask[k]:
            continue
        m = HEAD_RE.match(l)
        if not m:
            continue
        hashes, title = m.group(1), m.group(2)
        if first:
            want, first = '##', False
            if not re.match(rf'^{num}\.\s', title):
                log['heading_changes'].append({'file': fname, 'line': k + 1, 'issue': 'first heading is not "## N."'})
        elif re.match(rf'^{num}\.\d+\.\d+(\s|$)', title):
            want = '####'
        elif re.match(rf'^{num}\.\d+(\s|$)', title):
            want = '###'
        else:
            want = hashes if len(hashes) >= 3 else '###'
        if hashes != want:
            log['heading_changes'].append({'file': fname, 'line': k + 1, 'from': hashes, 'to': want, 'text': title})
            lines[k] = f"{want} {title}"
    rc, oc = [0], [0]
    for k, l in enumerate(lines):
        if not mask[k]:
            l = C['convert_r_links'](l, research_rel, rc)
            lines[k] = link_od(l, oc)
    log['r_links'] += rc[0]
    log['od_links_sections'] += oc[0]
    return '\n'.join(lines).strip('\n')


sec_files = sorted((design / 'sections').glob('*.md'), key=lambda p: int(p.name.split('-')[0]))
assert len(sec_files) == 23, len(sec_files)
sections = []
for f in sec_files:
    num = int(f.name.split('-')[0])
    sections.append({'num': num, 'file': f.name, 'body': normalize_section(num, f.read_text(), f.name)})
raw_by_num = {int(f.name.split('-')[0]): f.read_text() for f in sec_files}

items_by_id = {}
for d in EX:
    for it in d['items']:
        items_by_id[it['id']] = (d['num'], it)

DECIDED = re.compile(r'\*\*Decided by owner (2026-11-0\d) \(([^)]*)\):\*\*')
AMENDED = re.compile(r'\*\*Amended by owner (2026-11-0\d) \(([^)]*)\)[^*]*:\*\*')


PEERC = '**Closed by peer review 2026-11-04:**'


def q_status(it):
    lab, t = it['label'], it['text']
    if 'withdrawn' in lab:
        return 'withdrawn'
    if 'closed' in lab:
        return 'closed'
    d = t.find('Decided by owner')
    c = t.find(PEERC)
    if d >= 0 and (c < 0 or d < c):
        return 'decided'
    if c >= 0:
        return 'peer-closed'
    return 'open'


def q_decider(qid, st):
    if st == 'withdrawn':
        return '—'
    if st in ('closed', 'peer-closed'):
        return 'peer review'
    if st == 'decided':
        return 'owner'
    raw = QF.get(qid, {}).get('decider', '')
    return 'owner' if raw.startswith('owner') else ('peer review' if raw.startswith('peer review') else raw or '—')


status = {i: q_status(it) for i, (n, it) in items_by_id.items() if i.startswith('Q-')}


def sub_ref(num, prefix):
    return f"@@SUB:{num}:{prefix}@@"


def qlink(qid):
    n = items_by_id[qid][0]
    return f"[{qid}]({sub_ref(n, 'Open questions')})"


def link_qids(text):
    return re.sub(r'(?<![\w\[-])(Q-[A-Z]+-\d+)(?![\w\]])',
                  lambda m: qlink(m.group(1)) if m.group(1) in items_by_id else m.group(1), text)


# ------------------------------------------------------------------ counts for the front matter
ndec = [i for i in items_by_id if i.startswith('D-')]
counts = collections.Counter(status.values())
open_ids = [i for i in status if status[i] == 'open']
n_open_owner = sum(1 for i in open_ids if q_decider(i, 'open') == 'owner')
n_open_peer = sum(1 for i in open_ids if q_decider(i, 'open') == 'peer review')
assert n_open_owner == 0 or F['OPEN_OWNER'], 'open owner questions exist but the front matter lists none'
assert sorted(r[0] for r in F['OPEN_OWNER']) == sorted(i for i in open_ids if q_decider(i, 'open') == 'owner'), 'OPEN_OWNER differs from the sections'
_WORD = {0: 'none', 1: 'one', 2: 'two', 3: 'three', 4: 'four', 5: 'five', 6: 'six'}
repl = {
    '@@ND@@': str(len(ndec)),
    '@@NDW@@': str(sum(1 for i in ndec if 'withdrawn' in items_by_id[i][1]['label'])),
    '@@NQ@@': str(len(status)), '@@NQDEC@@': str(counts['decided']), '@@NQOPEN@@': str(counts['open']),
    '@@NQOWN@@': str(n_open_owner), '@@NQPEER@@': str(n_open_peer), '@@NQCLOSED@@': str(counts['closed']),
    '@@NQPEERC@@': str(counts['peer-closed']), '@@NQOWNWORD@@': _WORD.get(n_open_owner, str(n_open_owner)),
    '@@NQW@@': str(counts['withdrawn']),
}
log['counts'] = {k.strip('@'): v for k, v in repl.items()}


def fill(s):
    for k, v in repl.items():
        s = s.replace(k, v)
    return s


# ------------------------------------------------------------------ front matter
parts = []
parts.append(F['TITLE'])
parts.append(gen(F['STATUS']))
parts.append(gen(F['SCOPE']))
for k in ('DIRECTIVE', 'RULES', 'BRANCH', 'HOW'):
    parts.append('\n'.join(gen(fill(l)) for l in F[k].split('\n')))

# ------------------------------------------------------------------ owner decisions section
od = ['## Owner decisions', link_qids(gen(F['DECISIONS_INTRO']))]
od.append('### Cross-cutting decisions X1-X20')
od.append(gen(F['X_INTRO']))
xrows = []
for (x, q, dec, sec, qid, res) in F['X_ROWS']:
    xrows.append([x, q, dec, sec, link_qids(qid), link_qids(res)])
od.append(table(['X', 'Question', 'Decision', 'Owning §', 'Q id', 'Residual'], xrows))
od.append('### Open owner questions')
od.append(link_qids(gen(F['OPEN_INTRO'])))
log['open_owner_in_sections'] = sorted(i for i in open_ids if q_decider(i, 'open') == 'owner')
if F['OPEN_OWNER']:
    od.append(table(['Q id', 'Question', 'Options', 'Recommendation', 'Blocks', 'Needed by'],
                    [[qlink(r[0])] + list(r[1:]) for r in F['OPEN_OWNER']]))
od.append('### Closed by peer review')
od.append(link_qids(gen(F['PEER_INTRO'])))
for (qid, *_rest) in F['PEER']:
    assert status[qid] == 'peer-closed', qid
log['peer_closed_missing_from_table'] = sorted(set(i for i in status if status[i] == 'peer-closed') - set(r[0] for r in F['PEER']))
assert not log['peer_closed_missing_from_table'], log['peer_closed_missing_from_table']
log['open_peer_in_sections'] = sorted(i for i in open_ids if q_decider(i, 'open') == 'peer review')
assert not log['open_peer_in_sections'], 'open peer-review items need a table'
od.append(table(['Q id', 'Question', 'Closed by peer review 2026-11-04', 'Needed by'],
                [[qlink(r[0])] + list(r[1:]) for r in F['PEER']]))
od.append('### Owner decisions by number')
od.append(gen(F['INDEX_INTRO']))
idx_rows = []
cited = {int(k): v for k, v in CITES['cited'].items()}
assert [r[0] for r in F['INDEX']] == list(range(1, MAXD + 1)), 'INDEX must hold rows 1..MAXD'
for (n, settles, dec) in F['INDEX']:
    impl = ', '.join(f"§{s}" for s in cited.get(n, [])) or '—'
    idx_rows.append([f"@@ANCHOR:od-{n}@@{n}", F['DATES'][n], link_qids(gen(settles)), dec, impl])
od.append(table(['#', 'Date', 'Settles', 'Decision', 'Implemented in'], idx_rows))
if F['KNOWN_GAPS']:
    od.append('### Known gaps')
    od.append(gen(F['KNOWN_GAPS_INTRO']))
    od.append(table(['Where', 'Text', 'Owner decision', 'Note'], [[link_qids(r[0]), link_qids(r[1]), r[2], link_qids(r[3])] for r in F['KNOWN_GAPS']]))
parts.append('\n\n'.join(od))

TOC_MARK = '@@TOC@@'
parts.append(TOC_MARK)
for s in sections:
    parts.append(s['body'])

# ------------------------------------------------------------------ Appendix A
nDw = int(repl['@@NDW@@'])
rows = []
for d in EX:
    for it in d['items']:
        if not it['id'].startswith('D-'):
            continue
        summ = R['D'][it['id']]
        if 'withdrawn' in it['label']:
            summ = '**Withdrawn.** ' + summ
        elif it['label'] != '(proposed).':
            summ = summ + ' *(' + it['label'].strip('().').strip() + ')*'
        if it['id'] in R['STALE_D']:
            summ = summ + ' *(' + R['STALE_D'][it['id']] + '; [Known gaps](#known-gaps))*'
        rows.append([it['id'], summ, f"[§{d['num']}]({sub_ref(d['num'], 'Decisions proposed')})"])
nDd = sum(1 for i in ndec if 'decided' in items_by_id[i][1]['label'])
# data_registers7.py's WITHDRAWN_D: every withdrawn item, each summary naming the decisions its section stub names
if 'WITHDRAWN_D' in R:
    _wd_sec = sorted(i for i in ndec if 'withdrawn' in items_by_id[i][1]['label'])
    assert sorted(R['WITHDRAWN_D']) == _wd_sec, ('WITHDRAWN_D differs from the sections', _wd_sec)
    for _i, _by in R['WITHDRAWN_D'].items():
        _nums = re.findall(r'\d+', _by)
        _stub = items_by_id[_i][1]['text']
        for _n in _nums:
            assert re.search(rf'\b{_n}\b', R['D'][_i]), ('withdrawn summary lacks its decision', _i, _n)
            assert re.search(rf'[Oo]wner decisions?[^.]*\b{_n}\b', _stub), ('section stub lacks the decision', _i, _n)
    log['withdrawn_d_checked'] = len(R['WITHDRAWN_D'])
appa = ['## Appendix A. Decision register',
        gen(f"Every D- item, in section order: {len(ndec)} items, {nDw} of them withdrawn and {nDd} decided by the owner. "
            "The decision column is a summary of 20 words or fewer; the item in its section's \"Decisions proposed\" "
            "subsection is authoritative. A withdrawn item names the owner decision that superseded it."),
        table(['Id', 'Decision', '§'], rows)]
parts.append('\n\n'.join(appa))

# ------------------------------------------------------------------ Appendix B


def status_cell(qid, it):
    st = status[qid]
    if st == 'decided':
        ms = DECIDED.findall(it['text'])
        if ms:
            inner = '; '.join(f"{i}, {d}" if d != '2026-11-03' else i for d, i in ms)
        else:
            inner = 'owner decision'
        out = f"decided ({inner})"
        am = AMENDED.findall(it['text'])
        if am:
            out += '; ' + '; '.join(f"amended ({i}, {d})" for d, i in am)
    elif st == 'closed':
        out = 'closed by the 2026-11-03 design review'
    elif st == 'peer-closed':
        out = 'closed by peer review 2026-11-04'
    else:
        out = st
    if qid in R['STALE_Q']:
        out += f"; {R['STALE_Q'][qid]} ([Known gaps](#known-gaps))"
    return out


rows = []
for d in EX:
    for it in d['items']:
        if not it['id'].startswith('Q-'):
            continue
        qid = it['id']
        q, rec = R['Q'][qid]
        rows.append([f"[{qid}]({sub_ref(d['num'], 'Open questions')})", q, status_cell(qid, it), rec, q_decider(qid, status[qid])])
# data_registers7.py's QSTATUS: the same status, cell and decider as computed here from the section text
if 'QSTATUS' in R:
    _mine = {i: (status[i], status_cell(i, items_by_id[i][1]), q_decider(i, status[i])) for i in status}
    import json as _json
    (asm / 'v7' / 'qstatus_computed.json').write_text(_json.dumps({k: list(v) for k, v in _mine.items()}, indent=1))
    _diff = {i: (R['QSTATUS'].get(i), _mine[i]) for i in _mine if tuple(R['QSTATUS'].get(i, ())) != _mine[i]}
    assert not _diff and set(R['QSTATUS']) == set(_mine), ('QSTATUS differs from the sections', _diff)
    log['qstatus_checked'] = len(_mine)
n_dec_04 = sum(1 for i, (n, it) in items_by_id.items() if i.startswith('Q-') and status[i] == 'decided' and 'Decided by owner 2026-11-04' in it['text'])
log['q_decided_0304'] = n_dec_04
_open_who = 'all for the owner' if n_open_peer == 0 else ('all for peer review' if n_open_owner == 0 else f"{n_open_owner} for the owner and {n_open_peer} for peer review")
if counts['open'] == 0:
    # Seventh assembly: no Q- item is open, so the lead says so once, at the end of the count list.
    _b_counts = (f"{counts['decided']} were decided by the owner ({n_dec_04} of them by the 2026-11-04 entries), "
                 f"{counts['peer-closed']} were closed by peer review on 2026-11-04, {counts['closed']} were closed by "
                 f"the 2026-11-03 design-review round, not by human peer review, so reviewers may reopen them (§3.11), "
                 f"and {counts['withdrawn']} were withdrawn; none is open.")
    _b_rec = "The recommendation column, 15 words or fewer, gives each item's outcome."
else:
    _open_txt = (f"{counts['open']} is open for the owner" if counts['open'] == 1 and n_open_peer == 0 else f"{counts['open']} are open, {_open_who}")
    _b_counts = (f"{counts['decided']} were decided by the owner ({n_dec_04} of them by the 2026-11-04 entries), "
                 f"{counts['peer-closed']} were closed by peer review on 2026-11-04, {_open_txt}, {counts['closed']} were "
                 f"closed by the 2026-11-03 design-review round, not by human peer review, so reviewers may reopen them "
                 f"(§3.11), and {counts['withdrawn']} were withdrawn.")
    _b_rec = ("The recommendation column, 15 words or fewer, gives the section's recommendation for an open item and the "
              "outcome for any other.")
appb = ['## Appendix B. Open-questions register',
        gen(f"Every Q- item, in section order: {len(status)} items. " + _b_counts + " The question is a summary of 25 "
            "words or fewer. The status of a decided item gives the owner decisions that settled it, as its section cites "
            "them, with the date for a 2026-11-04 entry. " + _b_rec + " The decider of a closed item is peer review, "
            "which may reopen one the design-review round closed."),
        table(['Id', 'Question', 'Status', 'Recommendation', 'Decider'], rows)]
parts.append('\n\n'.join(appb))

# ------------------------------------------------------------------ Appendix C (list form, one sentence per term)


def gkey(t):
    return re.sub(r'[^a-z0-9]', '', t.lower().replace('`', '')) or t


gl = sorted(G['GLOSSARY'], key=lambda r: (gkey(r[0]), r[0]))
appc = ['## Appendix C. Glossary',
        gen("Each term is defined once, with the section that owns it, updated to the edited sections and owner decisions 1-149; "
            "withdrawn terms that sections still name are marked, and How to review lists the id families.")]
appc.append('\n'.join(f"- **{gen(t)}** ({gen(w)}): {gen(dfn)}" for t, dfn, w in gl))
parts.append('\n\n'.join(appc))
log['glossary_terms'] = len(gl)

# ------------------------------------------------------------------ appendix lead paragraphs (data_appx7.py's INTRO)
_INTRO6 = {
    'D': ("Messages on the sidecar subprotocol (connect subprotocol id 21842), from §6.11's `MessageType` catalog and the "
          "sections' Interfaces subsections. `Envelope.type` is service << 8 \\| message; §6 assigns numbers and owners define "
          "the messages. ControlId messages ride `PushHint` on a topic (§6.8) and are hints: clients resync over HTTPS on any gap. "
          "Services 0x11 (§8), 0x18 (§16) and 0x19 (§17) define no messages. Each statement carried in `Signed` has a "
          "`SignedType` in §6.11's registry, service << 8 \\| n, which the signature covers."),
    'E': ("Compiled from the sections' Interfaces subsections, §4.6, §19.4, §19.5 and §19.7. Routes are documented in "
          "connect/api/bringyour.yml and classified in server/api/route_authz.go (§7); migrations continue from 926, each "
          "group pending under `sidecar_pending` until its own milestone's Gn-out registers it (§19.7). evs and gkm keep no "
          "Postgres rows: their durable state is objects in the file cluster (owner decision 2), placed per repo on one "
          "metadata cluster (owner decision 145), and Redis holds only their soft state (owner decision 136)."),
    'E_CONNECT': ("§4.6's rows for connect's `sidecar` branch, verbatim (X9). Dispositions follow owner decision 22, plus "
                  "decisions 85 (C14 into M4), 86 (C18) and 176 (C19). Each change is generic, additive, off by default and "
                  "wire-compatible, and merges to connect `main` first (D-REPO-5)."),
    'F': ("Every statement in sidecar/design/PLAN.md (381 lines), traced to the sections that carry it. Status values: kept, refined, "
          "amended, superseded by the owner directive, departed (with the Q- item and owner decision that settled it), and n/a. "
          "Built from the PLAN review's table and updated to the edited sections' \"Departures from PLAN.md\" subsections, which "
          "give the arguments; \"owner N\" in the status column cites owner decision N."),
    'H': ("The research fact sheets of 2026-11-03 that the sections cite as `[R:key]`, copied to "
          "[{research_rel}/]({research_rel}/). Each cites code as repo/path:LINE and external sources by URL with dates."),
}
INTRO = dict(_INTRO6, **A.get('INTRO', {}))

# ------------------------------------------------------------------ Appendix D
appd = ['## Appendix D. Subprotocol message index',
        gen(INTRO['D']),
        table(['Message', 'Number', 'Direction', 'Purpose', '§'], [list(r) for r in A['MESSAGES']]),
        '### Carried inside other messages, objects or HTTPS',
        table(['Message', 'Carried in', 'Purpose', '§'], [list(r) for r in A['CARRIED']])]
parts.append('\n\n'.join(appd))
log['messages_rows'] = len(A['MESSAGES'])
log['carried_rows'] = len(A['CARRIED'])

# ------------------------------------------------------------------ Appendix E
conn_rows, in46 = [], False
for l in raw_by_num[4].split('\n'):
    if l.startswith('### 4.6 '):
        in46 = True
        continue
    if in46 and l.startswith('### '):
        break
    m = re.match(r'^\|\s*(C\d+[ab]?)\s*\|(.*)\|\s*$', l)
    if in46 and m:
        cells = [c.strip() for c in re.split(r'(?<!\\)\|', m.group(2))]
        conn_rows.append([m.group(1)] + cells)
if 'CONNECT' in A:
    assert [list(r) for r in A['CONNECT']] == conn_rows, "data_appx7.py's CONNECT differs from §4.6"
log['connect_rows'] = len(conn_rows)
conn_table = ['| # | Change | Disposition |', '|---|---|---|']
oc = [0]
for r in conn_rows:
    conn_table.append('| ' + ' | '.join(link_od(C['convert_r_links'](c, research_rel), oc) for c in r) + ' |')
appe = ['## Appendix E. API routes, tables, services, and connect changes',
        gen(INTRO['E']),
        '### API routes',
        table(['Route', 'Auth', 'Purpose', '§'], [list(r) for r in A['ROUTES']]),
        '### Tables, Redis keys and object families',
        table(['Table, key or object family', 'Owner service', 'Purpose', 'Migration group', '§'], [list(r) for r in A['TABLES']]),
        '### Services and config',
        table(['Service', 'Hosted as', 'Role', '§'], [list(r) for r in A['SERVICES']]),
        '### Connect changes (C1-C19)',
        gen(INTRO['E_CONNECT']),
        '\n'.join(conn_table)]
parts.append('\n\n'.join(appe))
log['routes_rows'], log['tables_rows'], log['services_rows'] = len(A['ROUTES']), len(A['TABLES']), len(A['SERVICES'])

# ------------------------------------------------------------------ Appendix F
appf = ['## Appendix F. PLAN.md traceability',
        gen(INTRO['F']),
        table(['PLAN lines', 'Statement', 'Sections', 'Status', 'Note'], [list(r) for r in A['PLAN_TRACE']])]
parts.append('\n\n'.join(appf))
log['plan_rows'] = len(A['PLAN_TRACE'])

# ------------------------------------------------------------------ Appendix G (FRONT-35: a pointer to §2.8)
_t2 = raw_by_num[2]
_i = _t2.index('**The list**'); _j = _t2.index('```yaml', _i); _k = _t2.index('\n```', _j + 7)
_yaml = _t2[_j + 7:_k]
_ver = re.search(r'metadata_list\.yml (v\d+), updated (\d{4}-\d\d-\d\d) for ([^(]*?) \(', _yaml)
if not _ver:
    # v8 onward: "metadata_list.yml v8; v7 was updated ..." and later "# v8, updated <date> for <scope> (".
    _vv = re.search(r'metadata_list\.yml (v\d+);', _yaml)
    _ver = _vv and re.search(r'^# (' + _vv.group(1) + r'), updated (\d{4}-\d\d-\d\d) for ([^(]*?) \(', _yaml, re.M)
assert _ver, 'metadata_list.yml header not found'
_rows = collections.OrderedDict(); _cur = None
for _l in _yaml.split('\n'):
    _m = re.match(r'^([a-z]+-\d+):\s*$', _l)
    if _m:
        _cur = _rows.setdefault(_m.group(1), False)
        _cur_id = _m.group(1)
        continue
    if re.match(r'^\s+withdrawn:', _l):
        _rows[_cur_id] = True
_fam = collections.OrderedDict()
for _r, _w in _rows.items():
    _fam.setdefault(_r.split('-')[0], []).append(int(_r.split('-')[1]))


def _span(p, ns):
    ns = sorted(ns)
    assert ns == list(range(1, len(ns) + 1)), (p, ns)
    return f"{p}-1" if len(ns) == 1 else (f"{p}-1 and {p}-2" if len(ns) == 2 else f"{p}-1 to {p}-{len(ns)}")


_spans = [_span(p, ns) for p, ns in _fam.items()]
_wd = [r for r, w in _rows.items() if w]
log['appendix_g'] = {'version': _ver.group(1), 'date': _ver.group(2), 'rows': len(_rows), 'withdrawn': _wd}
_census = (f"The list has {len(_rows)} rows, {len(_wd)} of them withdrawn: " + ', '.join(_spans[:-1]) + f" and {_spans[-1]}; "
           + ', '.join(_wd[:-1]) + f" and {_wd[-1]} are withdrawn and keep their ids, so citations resolve.")
_gtext = (f"§2.8 holds `metadata_list.yml` ({_ver.group(1)}, updated {_ver.group(2)} for {_ver.group(3)}), the list the "
          "product promises: URnetwork's servers never receive plaintext content or keys, in any mode, and see only the "
          "values it names (D-TRUST-4), with one bounded exception, the platform report listener (§2.8). This appendix no "
          "longer copies it, so the two cannot drift. " + _census)
if 'APPX_G' in A:
    assert A['APPX_G']['text'] == _gtext, "data_appx7.py's APPX_G differs from the census computed here"
appg = ['## Appendix G. Server-visible metadata list', gen(_gtext)]
parts.append('\n\n'.join(appg))

# ------------------------------------------------------------------ Appendix H
if 'RESEARCH_CITES' in A:
    _hrows = [[f"[R:{k}]({research_rel}/{k}.md)", desc, ', '.join(f"§{s}" for s in A['RESEARCH_CITES'][k]) or '—']
              for k, desc in A['RESEARCH']]
    _hhead = ['Fact sheet', 'Description', 'Cited in']
else:
    _hrows = [[f"[R:{k}]({research_rel}/{k}.md)", desc] for k, desc in A['RESEARCH']]
    _hhead = ['Fact sheet', 'Description']
apph = ['## Appendix H. Research sources',
        gen(INTRO['H'].format(research_rel=research_rel)),
        table(_hhead, _hrows)]
parts.append('\n\n'.join(apph))

doc = '\n\n'.join(parts) + '\n'

# ------------------------------------------------------------------ anchors and the table of contents
doc = doc.replace(TOC_MARK, '## Contents\n\n@@TOCBODY@@')
sl = C['Slugger']()
anchors = [(lvl, title, sl.slug(title)) for (k, lvl, title) in C['headings'](doc)]


def find_sub(num, prefix):
    for lvl, title, a in anchors:
        if lvl == 3 and re.match(rf'^{num}\.\d+ {re.escape(prefix)}', title):
            return a
    return None


def sub_rep(m):
    a = find_sub(int(m.group(1)), m.group(2))
    if a is None:
        log.setdefault('unresolved_sub', []).append(m.group(0))
        return '#'
    return '#' + a


doc = re.sub(r'@@SUB:(\d+):([^@]+)@@', sub_rep, doc)
doc = re.sub(r'@@ANCHOR:([a-z0-9-]+)@@', r'<a id="\1"></a>', doc)

first = {}
for lvl, title, a in anchors:
    first.setdefault(title, a)
toc = []
fm = ['Owner directive', 'Owner rules', 'Branch policy', 'How to review']
toc.append('- Front matter: ' + ' · '.join(f"[{t}](#{first[t]})" for t in fm))
toc.append(f"- [Owner decisions](#{first['Owner decisions']})")
ods = ['Cross-cutting decisions X1-X20', 'Open owner questions', 'Closed by peer review', 'Owner decisions by number']
if F['KNOWN_GAPS']:
    ods.append('Known gaps')
toc.append('  - ' + ' · '.join(f"[{t}](#{first[t]})" for t in ods))
for i, (lvl, title, a) in enumerate(anchors):
    m2 = re.match(r'^(\d+)\.\s', title)
    if lvl == 2 and m2:
        cur = int(m2.group(1))
        toc.append(f"- [{title}](#{a})")
        subs = [(t, aa) for (l2, t, aa) in anchors if l2 == 3 and re.match(rf'^{cur}\.\d+\s', t)]
        if subs:
            toc.append('  - ' + ' · '.join(f"[{t}](#{aa})" for t, aa in subs))
for i, (lvl, title, a) in enumerate(anchors):
    if lvl == 2 and title.startswith('Appendix '):
        toc.append(f"- [{title}](#{a})")
        subs = []
        for (l2, t, aa) in anchors[i + 1:]:
            if l2 <= 2:
                break
            if l2 == 3:
                subs.append((t, aa))
        if subs:
            toc.append('  - ' + ' · '.join(f"[{t}](#{aa})" for t, aa in subs))
toc = [re.sub(r'\[([^\]]*)\]', lambda m: '[' + m.group(1).replace('<', '&lt;') + ']', l) for l in toc]
doc = doc.replace('@@TOCBODY@@', '\n'.join(toc))
assert '@@' not in doc, doc[doc.index('@@') - 200:doc.index('@@') + 200]
assert 'unresolved_sub' not in log, log['unresolved_sub']

out_path.write_text(doc)
log['anchors'] = len(anchors)
log['words_total'] = len(doc.split())
log['lines_total'] = doc.count('\n')
log['od_links_connect'] = oc[0]
(VDIR / 'assemble_log.json').write_text(json.dumps(log, indent=1))
print(json.dumps(log, indent=1)[:3000])
