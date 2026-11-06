"""Owner-decision citations per section: 'owner decision N' and 'owner decisions N, M-K and L', code blocks included.
A range spanning more than MAXSPAN decisions (such as "owner decisions 1-145") is a summary, not a citation of each
decision: it is recorded under summary_ranges and counts toward neither "implemented in" nor the uncited check.
Usage: python3 -I cites6.py <design_dir> <out_json>
"""
import re, sys, json, pathlib, collections
base = pathlib.Path(sys.argv[1])
MAXD = 194
MAXSPAN = 10
summary = []
NUM = r'\d{1,3}(?!\d)(?:\s*[-–]\s*\d{1,3}(?!\d))?(?![.]\d)(?!:\d)(?!-\d)'
CITE = re.compile(r'([Oo]wner)\s+(?:#\s*)?(decisions?)\s+(' + NUM + r'(?:(?:\s*,\s*(?:and\s+)?|\s+and\s+)' + NUM + r')*)')
def expand(s):
    out = []
    for part in re.split(r'\s*,\s*(?:and\s+)?|\s+and\s+', s.strip()):
        m = re.match(r'(\d+)\s*[-–]\s*(\d+)$', part.strip())
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if b - a + 1 > MAXSPAN:
                summary.append((CUR[0], a, b))
                continue
            out.extend(range(a, b + 1))
        elif part.strip().isdigit():
            out.append(int(part.strip()))
    return out
cited = collections.defaultdict(set)
bad = []
count = collections.Counter()
CUR = [None]
for f in sorted((base / 'sections').glob('*.md')):
    num = int(f.name[:2])
    CUR[0] = num
    t = f.read_text()
    for m in CITE.finditer(t):
        for n in expand(m.group(3)):
            if 1 <= n <= MAXD:
                cited[n].add(num); count[n] += 1
            else:
                bad.append({'file': f.name, 'match': m.group(0)})
res = {'cited': {n: sorted(cited[n]) for n in sorted(cited)}, 'uncited': [n for n in range(1, MAXD + 1) if n not in cited],
       'bad': bad, 'counts': dict(count), 'summary_ranges': summary}
pathlib.Path(sys.argv[2]).write_text(json.dumps(res, indent=1))
print('distinct cited', len(cited), 'uncited', res['uncited'], 'bad', bad[:10])
