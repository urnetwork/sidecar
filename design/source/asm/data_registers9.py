"""Registers for the v1 additions (2026-11-05): layered over data_registers7.py. Entries come from
v8reg.json (written from the register writers' output) when present; until then, placeholders let a trial build run."""
import runpy, pathlib, json
_here = pathlib.Path(__file__).parent
_R7 = runpy.run_path(str(_here / 'data_registers7.py'))
globals().update({k: v for k, v in _R7.items() if not k.startswith('_')})
D = dict(_R7['D']); Q = dict(_R7['Q'])
_reg = _here / 'v8reg.json'
if _reg.exists():
    _r = json.loads(_reg.read_text())
    D.update(_r.get('D', {}))
    Q.update({k: tuple(v) for k, v in _r.get('Q', {}).items()})
_miss = json.loads((_here / 'v7' / 'missing_registers.json').read_text())
for _i in _miss['D']:
    D.setdefault(_i, 'TRIAL placeholder.')
for _i in _miss['Q']:
    Q.setdefault(_i, ('TRIAL placeholder?', 'TRIAL placeholder.'))
_qs = _here / 'v7' / 'qstatus_final.json'
if _qs.exists():
    QSTATUS = {k: tuple(v) for k, v in json.loads(_qs.read_text()).items()}
else:
    QSTATUS = None
    del QSTATUS
