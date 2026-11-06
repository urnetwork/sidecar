# Appendix C glossary, ninth assembly (2026-11-05): data_glossary7.py plus the v1 additions' terms (v8glossary.json):
# versionless objects, the search index, the indexer, the team directory, remote search and history drops, with the
# entries those additions made stale rewritten. One sentence per term, citing its defining section; at most 5,000 words.
import runpy, pathlib, json
_here = pathlib.Path(__file__).parent
_G7 = runpy.run_path(str(_here / 'data_glossary7.py'))
_g = json.loads((_here / 'v8glossary.json').read_text())
_del = set(_g['delete'])
GLOSSARY = [r for r in _G7['GLOSSARY'] if r[0] not in _del]
GLOSSARY = [(t, *_g['replace'][t]) if t in _g['replace'] else (t, d, s) for t, d, s in GLOSSARY]
GLOSSARY += [tuple(a) for a in _g['add']]
assert len({t for t, _, _ in GLOSSARY}) == len(GLOSSARY), 'duplicate glossary terms'
assert sum(len((t + ' ' + d).split()) for t, d, _ in GLOSSARY) <= 5000, 'glossary over 5,000 words'
