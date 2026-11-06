"""Section text checks (sixth assembly): reviewer, register and brief ids, and bare angle-bracket placeholders outside code.
Usage: python3 -I text_checks6.py <design_dir> <out_json>
"""
import re, sys, json, pathlib, runpy
base = pathlib.Path(sys.argv[1])
C = runpy.run_path(str(pathlib.Path(__file__).parent / 'common.py'))
REVIEWER = re.compile(r'\b(RUL|CR|CONS|SEC|E2EE|ARCHR|GRD|READ|PLAN|CRITIC|DEC|STRUCT|META|FRONT|VERIFY|CHECK)-\d+\b|\bcritic (item |issue |#)?\d+\b|\bR\d+\b(?!-)|\bR-\d+\b|\bT[1-6]-\d{2}\b|\bT[1-6]\.\d+\b', re.I)
DOCS = re.compile(r'\b(RECONCILE|PEERQ|CRITIC\d*|CHECK\d|VERIFY-[A-Z0-9]+|T[1-6]-(BRIEF|REGISTER)|INDEX\.md|OWNER\.md)\b')
out = {'reviewer_ids': [], 'bare_placeholders': [], 'html_tags': []}
for f in sorted((base / 'sections').glob('*.md')):
    lines = f.read_text().split('\n')
    mask = C['code_mask'](lines)
    for k, l in enumerate(lines):
        if mask[k]:
            continue
        stripped = re.sub(r'`[^`]*`', '', l)
        for m in list(REVIEWER.finditer(stripped)) + list(DOCS.finditer(stripped)):
            out['reviewer_ids'].append({'file': f.name, 'line': k + 1, 'id': m.group(0), 'ctx': stripped[max(0, m.start()-60):m.end()+40]})
        for m in re.finditer(r'<[A-Za-z/!?][^>\n]*>?', stripped):
            out['bare_placeholders'].append({'file': f.name, 'line': k + 1, 'text': m.group(0)[:60], 'ctx': stripped[max(0, m.start()-50):m.end()+30]})
pathlib.Path(sys.argv[2]).write_text(json.dumps(out, indent=1))
print({k: len(v) for k, v in out.items()})
for k in ('reviewer_ids', 'bare_placeholders'):
    for x in out[k][:40]:
        print(k, x)
