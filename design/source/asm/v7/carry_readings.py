"""Carry the superseded-option readings forward to a fresh grep, so only new hits need reading.

Usage: python3 -I v7/carry_readings.py <hits.json> <hits_class.json> <out.json> [<new_readings.json> <source_tag>]

<hits.json> is v7/supersede_grep7.py's output for today's sections. A hit keeps the reading of a classified hit
with the same family and the same line text. A hit with no such reading takes one from <new_readings.json>, a
list of {file, line, family, verdict, reading} keyed by file, line and family; otherwise it is written as
UNCLASSIFIED, which validate10.py reports. Verdicts, as v7/classify7.py used them:
  ok       the line presents no superseded option as the design;
  live     section text that contradicts an owner decision (a decided question that reads as open counts here);
  gap      text that contradicts another section's current design;
  stated   text that openly revises a figure in an owner decision's record while keeping the decision.
Read every UNCLASSIFIED hit against owner/DECISIONS.md, add a reading, and run this again before a review gate.
"""
import json, sys, collections

hits = json.load(open(sys.argv[1]))['hits']
old = json.load(open(sys.argv[2]))
out_path = sys.argv[3]
new = {}
tag = 'hand'
if len(sys.argv) > 4:
    for r in json.load(open(sys.argv[4])):
        new[(r['file'], r['line'], r['family'])] = r
    tag = sys.argv[5] if len(sys.argv) > 5 else tag

by_text = {(o['family'], o['snippet'].strip()): o for o in old}
out, counts = [], collections.Counter()
for h in hits:
    base = {k: h[k] for k in ('family', 'file', 'line', 'col', 'match', 'snippet')}
    o = by_text.get((h['family'], h['snippet'].strip()))
    if o:
        base.update({k: o.get(k, False) for k in ('reading', 'live', 'gap', 'stated')})
        base['source'] = o.get('source', 'carried')
        counts['carried'] += 1
    elif (h['file'], h['line'], h['family']) in new:
        r = new[(h['file'], h['line'], h['family'])]
        v = r['verdict']
        prefix = {'live': 'LIVE: ', 'stale_q': 'LIVE: ', 'gap': 'GAP: ', 'stated': 'STATED: '}.get(v, '')
        base.update({'reading': prefix + r['reading'], 'live': v in ('live', 'stale_q'), 'gap': v == 'gap',
                     'stated': v == 'stated', 'source': tag})
        counts['new'] += 1
    else:
        base.update({'reading': 'UNCLASSIFIED', 'live': False, 'gap': False, 'stated': False, 'source': 'unread'})
        counts['unclassified'] += 1
    out.append(base)
json.dump(out, open(out_path, 'w'), indent=1, ensure_ascii=False)
print(dict(counts), 'live', sum(o['live'] for o in out), 'gap', sum(o['gap'] for o in out))
