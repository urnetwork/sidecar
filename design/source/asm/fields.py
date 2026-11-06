import json, re, sys
data = json.load(open(sys.argv[1]))
out = {}
for d in data:
    for it in d['items']:
        if not it['id'].startswith('Q-'): continue
        t = it['text'].replace('\n', ' ')
        b = re.search(r'\*Blocks:\*\s*(.*?)(?=\*Decider:\*|$)', t)
        dc = re.search(r'\*Decider:\*\s*(.*?)\s*$', t)
        blocks = b.group(1).strip().rstrip('.').strip() if b else ''
        dec = dc.group(1).strip().rstrip('.') if dc else ''
        out[it['id']] = {'blocks': blocks, 'decider': dec, 'sec': d['num']}
json.dump(out, open(sys.argv[2], 'w'), indent=1)
import collections
print(collections.Counter(v['decider'] for v in out.values()))
for k, v in out.items():
    n = len(v['blocks'].split())
    if n > 14: print(k, n, '|', v['blocks'])
