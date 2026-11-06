# Appendix C glossary, tenth assembly (2026-11-06): data_glossary9.py plus the final meta review's terms
# (v10glossary.json, from the reconciler's orders/ASM.md, section 3). The cap rises from 5,000 to 5,250 words for this
# assembly: every new entry defines a term the new section text uses.
import runpy, pathlib, json
_here = pathlib.Path(__file__).parent
_G9 = runpy.run_path(str(_here / 'data_glossary9.py'))
_g = json.loads((_here / 'v10glossary.json').read_text())
_del = set(_g['delete'])
assert all(any(t == d for t, _, _ in _G9['GLOSSARY']) for d in _del), 'deleting a missing term'
assert all(any(t == r for t, _, _ in _G9['GLOSSARY']) for r in _g['replace']), 'replacing a missing term'
GLOSSARY = [r for r in _G9['GLOSSARY'] if r[0] not in _del]
GLOSSARY = [(t, *_g['replace'][t]) if t in _g['replace'] else (t, d, s) for t, d, s in GLOSSARY]
GLOSSARY += [tuple(a) for a in _g['add']]
assert len({t for t, _, _ in GLOSSARY}) == len(GLOSSARY), 'duplicate glossary terms'
WORDS = sum(len((t + ' ' + d).split()) for t, d, _ in GLOSSARY)
assert WORDS <= 5250, ('glossary over 5,250 words', WORDS)
