"""Heuristic grep of the section files for superseded options and for decided questions that still read as open
(seventh assembly). Usage: python3 -I v7/supersede_grep7.py <design_dir> <out_json>

supersede_grep6.py's families, unchanged. Task families: MinIO or IP pools (owner decisions 124, 145); a 14 d or weekly
packing window (owner decision 136's 24 h); 3.84 TB drives (owner decisions 136, 138); Postgres or Redis as durable
evs or gkm state (owner decisions 2, 136); off-site copies (owner decision 94); audit gates (owner decision 99); edge
termination (the directive); and any decided or closed question still marked open. Extra families for decisions
136-145: the PM963 in the initial deployment (139), `subs/` lease objects (136), 2 TB drives (138), the 64 MiB packing
trigger (136), a 1,000-device cap (144), a rebalance (145), and D-EVS-22 still proposed (141).
New in the seventh assembly: 'kib_10_15', owner decision 140's first "about 10-15 KiB" of drive writes a push, which
its record as corrected on 2026-11-04 withdraws (Q-EVS-9); 'sizing_145', owner decision 145's recorded ~490-650
pushes/s a set and 4-5 sets in year two, which §19.9 and Q-OPS-10 revise; and 'none_open', statements that no
question is open, which must now hold.
Every line is scanned, fenced code included; a line may hit several families. Classification is by hand
(v7/classify7.py).
"""
import re, sys, json, pathlib, collections

base = pathlib.Path(sys.argv[1])
# Q- ids that are decided, closed or withdrawn in their sections (computed below from the item lines)
status = {}
for f in sorted((base / 'sections').glob('*.md')):
    text = f.read_text()
    for m in re.finditer(r'^\*\*(Q-[A-Z]+-\d+)([^*]*)\*\*(.*)$', text, re.M):
        qid, lab, rest = m.group(1), m.group(2), m.group(3)
        if 'withdrawn' in lab:
            status[qid] = 'withdrawn'
        elif 'closed' in lab:
            status[qid] = 'closed-0303'
        elif 'Decided by owner' in rest and ('Closed by peer review' not in rest or rest.index('Decided by owner') < rest.index('Closed by peer review')):
            status[qid] = 'decided'
        elif 'Closed by peer review 2026-11-04' in rest:
            status[qid] = 'closed-peer'
        else:
            status[qid] = 'open'
SETTLED = sorted(q for q, s in status.items() if s != 'open')
QIDS = '|'.join(re.escape(q) for q in SETTLED)

FAMILIES = {
    # task families
    'pools': r'\bpools?\b|multi-pool|\bpooled\b',
    'window_14d_weekly': r'\b14 ?d\b|\b14 days?\b|14-day|\bweekly\b|\bonce a week\b|\ba week\b|one week|week-old|7-day window|\bseven days\b',
    'tb_3_84': r'3\.84',
    'pg_redis_durable': r'(Postgres|PostgreSQL|Redis)[^.\n]{0,80}\b(evs|gkm|path index|ref CAS|file storage|storage state|epoch|heads?|leases?|commit|system of record)\b|\b(evs|gkm)\b[^.\n]{0,60}(Postgres|PostgreSQL|Redis)',
    'offsite': r'off-site|offsite|\bB2\b|\bR2\b|second site|cross-site',
    'audit_gate': r'\bAR[1-3]\b|external(ly)? audit|independent(ly)? audit|audited|audit before|before (the )?claim|security review',
    'edge_termination': r'(edge|tlsedge|mxedge|smtpedge|load balancer|\blb\b|haproxy|nginx)[^.\n]{0,60}terminat\w*|terminat\w*[^.\n]{0,60}(edge|tlsedge|mxedge|smtpedge)|termination mode|edge-terminat\w*|encrypt-on-receipt',
    'decided_q_open': r'(pending|if|until|unless|awaiting|asks?|open|undecided|confirm\w*|answers?|left to|for)\W{0,3}(the owner\W{0,3}|peer review\W{0,3})?(\w+\W{0,3}){0,3}\b(' + QIDS + r')\b|\b(' + QIDS + r')\b\W{0,3}(\(peer review\)|\(owner\)|pending|open|undecided|\([a-d]\)\s+(would|is chosen|if))',
    'owner_or_peer_pending': r'(if|until|unless|once|when) the owner (answers|decides|confirms|picks|chooses|takes)|owner (to confirm|must confirm)|owner confirms|awaits? the owner|pending (the )?owner|\*Decider:\* owner|for the owner to|left to peer review|for peer review|peer review (decides|to decide|will decide)|open (owner )?questions? (remain|is open)|\(proposed; Q-',
    # extra families for owner decisions 136-145
    'pm963': r'PM963',
    'subs_objects': r'\bsubs/',
    'tb_2': r'\b2 ?TB\b|2×2 ?TB|2 × 2 ?TB',
    'mib64_trigger': r'64 MiB',
    'device_cap_1000': r'1,001st|1,000[- ]device|1,000 member devices|member-device cap|device cap',
    'rebalance': r'rebalanc\w*',
    'evs22_proposed': r'D-EVS-22[^.\n]{0,40}proposed|proposed[^.\n]{0,40}D-EVS-22',
    # seventh assembly: owner decision 140's corrected record, 145's revised sizing, and "none open" statements
    'kib_10_15': r'10\s*[-–]\s*15 ?KiB',
    'sizing_145': r'490\s*[-–]\s*650|\b4\s*[-–]\s*5 sets\b|four to five (sets|clusters)',
    'none_open': r'no (owner )?questions? (is|remains?) open|none (is|remains?) open|no Q- item is open|every (X item and )?owner question',
}
out = []
for f in sorted((base / 'sections').glob('*.md')):
    lines = f.read_text().split('\n')
    for k, l in enumerate(lines):
        for fam, pat in FAMILIES.items():
            for m in re.finditer(pat, l, flags=re.I):
                s = max(0, m.start() - 170); e = min(len(l), m.end() + 170)
                out.append({'family': fam, 'file': f.name, 'line': k + 1, 'col': m.start(), 'match': m.group(0)[:80],
                            'snippet': l[s:e]})
pathlib.Path(sys.argv[2]).write_text(json.dumps({'status': status, 'hits': out}, indent=1, ensure_ascii=False))
print(collections.Counter(h['family'] for h in out), len(out))
print('status', collections.Counter(status.values()))
