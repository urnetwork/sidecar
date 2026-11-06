"""Registers after the final meta review (2026-11-06): layered over data_registers9.py. Entries from v10reg.json
(the reconciler's orders/ASM.md, section 2, with four summaries shortened to 20 words); question status from
v10/qstatus_final.json."""
import runpy, pathlib, json
_here = pathlib.Path(__file__).parent
_R9 = runpy.run_path(str(_here / 'data_registers9.py'))
globals().update({k: v for k, v in _R9.items() if not k.startswith('_')})
D = dict(_R9['D']); Q = dict(_R9['Q'])
_r = json.loads((_here / 'v10reg.json').read_text())
D.update(_r['D'])
Q.update({k: tuple(v) for k, v in _r['Q'].items()})
QSTATUS = {k: tuple(v) for k, v in json.loads((_here / 'v10' / 'qstatus_final.json').read_text()).items()}
