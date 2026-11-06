"""Words per section outside fenced code blocks (tables and headings included), against the ceilings.
Usage: python3 -I wordcount2.py <design_dir> <out_json>
"""
import sys, json, pathlib, runpy
base = pathlib.Path(sys.argv[1])
C = runpy.run_path(str(pathlib.Path(__file__).parent / 'common.py'))
CEIL = {'CTX': 2200, 'TRUST': 3000, 'ARCH': 3000, 'REPO': 2800, 'CORE': 3500, 'PROTO': 3800, 'TEAM': 3500,
        'ACL': 3800, 'SOCK': 3000, 'KEYS': 4500, 'EVS': 5000, 'DNS': 3000, 'TLS': 3800, 'SMTP': 4500,
        'MAIL': 4500, 'MCP': 3500, 'BRIDGE': 3800, 'SDK': 3000, 'OPS': 3500, 'QUOTA': 2500, 'ABUSE': 2500,
        'TEST': 2500, 'PHASE': 2500}
rows = []
for f in sorted((base / 'sections').glob('*.md')):
    code = f.stem.split('-', 1)[1]
    lines = f.read_text().split('\n')
    mask = C['code_mask'](lines)
    n = sum(len(l.split()) for k, l in enumerate(lines) if not mask[k])
    ncode = sum(len(l.split()) for k, l in enumerate(lines) if mask[k])
    ceil = CEIL[code]
    rows.append({'num': int(f.name[:2]), 'code': code, 'words': n, 'code_words': ncode, 'ceiling': ceil,
                 'over': n - ceil, 'over_pct': round(100.0 * (n - ceil) / ceil, 1)})
pathlib.Path(sys.argv[2]).write_text(json.dumps(rows, indent=1))
for r in rows:
    flag = 'OVER' if r['over'] > 0 else 'ok'
    print(f"{r['num']:2} {r['code']:7} {r['words']:5} / {r['ceiling']:5} {r['over']:+5} ({r['over_pct']:+5}%) code={r['code_words']} {flag}")
print('total', sum(r['words'] for r in rows))
