"""Front matter, close-out of the second round (2026-11-05): layered over data_front7.py. Adds owner decisions 146-149,
which settle the four findings the final checks left partial (SL-N1, WR-N1, ST-N1, AU-N2)."""
import runpy, pathlib
_P7 = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_front7.py'))
globals().update({k: v for k, v in _P7.items() if not k.startswith('__')})

INDEX = list(_P7['INDEX']) + [
    (146, "SL-N1 (second-round finding)",
     "The erasure closure allowance is per eraser, in pro.yml, with a floor §21's abuse controls cannot go below, so "
     "erasure always stays possible at the storage limit and one admin cannot use up other members' erasures."),
    (147, "WR-N1 (second-round finding)",
     "Phones keep their newest 64 KiB of authorization-log entries and serve proofs (§7.9 stands); a phone holder "
     "serves the proof, and the witness_bound_hours outcome applies only to a gap wider than the kept entries."),
    (148, "ST-N1 (second-round finding)",
     "Removal folds never blind-delete index entries: they write If-Match tombstones that keep the path's version, "
     "garbage-collected past the fold horizon, so re-created paths continue their versions and stale pushes fail."),
    (149, "AU-N2 (second-round finding)",
     "A scoped admission by a binding the compromise cascade restored activates through the 72 h recovery window with "
     "admin veto; the cascade re-seals device keychains sealed to a voided binding and re-enrolls exposed backups."),
]
assert [r[0] for r in INDEX] == list(range(1, 150))
DATES = dict(_P7['DATES'])
DATES.update({n: '2026-11-05' for n in range(146, 150)})
_ANCHOR = "This section lists the cross-cutting decisions"
assert _ANCHOR in _P7['DECISIONS_INTRO']
DECISIONS_INTRO = _P7['DECISIONS_INTRO'].replace(
    _ANCHOR,
    "On 2026-11-05 the owner decided the four findings the second-round checks left partial (146-149: SL-N1, WR-N1, "
    "ST-N1 and AU-N2). " + _ANCHOR)
