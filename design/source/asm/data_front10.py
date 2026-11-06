"""Front matter after the final meta review (2026-11-06): layered over data_front9.py. Adds owner decisions 185-191:
the presence countersignature (185, 187, 189), unlimited P0 writes outside the wear bound (186, 190), and the search
pair's accounting windows (188, 191)."""
import runpy, pathlib
_P9 = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_front9.py'))
globals().update({k: v for k, v in _P9.items() if not k.startswith('__')})

INDEX = list(_P9['INDEX']) + [
    (185, "Presence countersignature",
     "A `compromise` SidecarRevoke, and a KeyRevoke of a presence key, carry that key's countersignature whenever "
     "the signer registered a live presence key; api and every member device verify it."),
    (186, "Write governor",
     "P0 writes are never queued or refused; FI-14's wear bound exempts them, disclosed with P0 dashboards and "
     "alarms, amending @@OD:140@@ for P0 only."),
    (187, "Presence countersignature",
     "The countersignature of @@OD:185@@ also covers revoking another device for any reason, Suspend of another "
     "device, and RecoveryVeto."),
    (188, "Q-PROTO-4",
     "The five-page promise of @@OD:176@@ holds: C19 accounts the search pair in 55-minute windows, reporting a "
     "256 KiB floor at each window's end, with a Ping a minute while foregrounded."),
    (189, "Presence countersignature",
     "The countersignature also covers SidecarAdmit, AdmissionConfirm and OwnerConfirm of untagged sidecars, "
     "AdminSet changes, MemberRevoke, RecoveryBind and RecoveryRebind."),
    (190, "Q-EVS-24",
     "After a P0 storm the other classes resume at once: the write bucket floors at zero, so P0's excess is "
     "forgiven and counted, not repaid (@@OD:186@@)."),
    (191, "Q-PROTO-4",
     "A search that finds its indexer session lost re-establishes it at once; connect-5 discloses that its contract "
     "keeps the search's time, narrowing @@OD:188@@."),
    (192, "Presence countersignature",
     "A `DelegationRevoke` that parks other devices (`since_n` > 0) also carries the countersignature: the final meta "
     "review's extension, following @@OD:187@@'s intent, ratified as written."),
]
# Owner decision 188 amends 176's summary (the reconciler's ASM.md, 1.2).
_i176 = [r[0] for r in INDEX].index(176)
INDEX[_i176] = (176, INDEX[_i176][1],
                "Connect rounds the byte reports of phone-to-indexer search contracts up to 128 KiB, hiding up to five "
                "search pages an hour. Amended by @@OD:188@@.")
assert [r[0] for r in INDEX] == list(range(1, 193))
DATES = dict(_P9['DATES'])
DATES.update({185: '2026-11-05', 186: '2026-11-05', 187: '2026-11-05', 188: '2026-11-06', 189: '2026-11-06',
              190: '2026-11-06', 191: '2026-11-06', 192: '2026-11-06'})
_ANCHOR = "This section lists the cross-cutting decisions"
assert _ANCHOR in _P9['DECISIONS_INTRO']
DECISIONS_INTRO = _P9['DECISIONS_INTRO'].replace(
    _ANCHOR,
    "On 2026-11-05 and 2026-11-06, with the owner's SDK fixes and the final meta review, the owner extended the "
    "presence countersignature (185, 187, 189), kept P0 writes unlimited outside the wear bound with their excess "
    "forgiven (186, 190), and kept "
    "@@OD:176@@'s five-page promise through accounting windows (188, 191). " + _ANCHOR)

STATUS = ("Status: draft for peer review, revised 2026-11-04 after the first peer review (see "
          "[DESIGN-REVIEW-RESPONSE.md](DESIGN-REVIEW-RESPONSE.md)), on 2026-11-05 with the v1 additions of owner "
          "decisions 150-184 (versionless objects, the search index, CLI and MCP search, the indexer, the team directory "
          "and history drops), and on 2026-11-06 after the final meta review "
          "([DESIGN-REVIEW-META.md](DESIGN-REVIEW-META.md)), with owner decisions 185-191. Nothing described here is "
          "implemented.")

# Implementation handoff (2026-11-06): the branch policy said the documents join the repo on the `sidecar` branch,
# but §4.3 and §4.11 put them on `main`, where they are; only code starts on `sidecar` (§4.8).
_BR_OLD = "DESIGN.md and design-research/ join it on the `sidecar` branch (§4.11)."
_BR_NEW = ("Its documents, DESIGN.md and `design/design-research/` among them, are on `main`; code starts on the "
           "`sidecar` branch (§4.11).")
assert BRANCH.count(_BR_OLD) == 1, 'branch policy text moved'
BRANCH = BRANCH.replace(_BR_OLD, _BR_NEW)

# Id families after the final meta review: filled in from the reconciler's IDS.md before the build.
_ID_FIX = [("FI-1 to FI-27 (", "FI-1 to FI-30 ("), ("FS-1 to FS-98 (", "FS-1 to FS-125 ("),
           ("I-EVS-1 to I-EVS-15 (", "I-EVS-1 to I-EVS-17 ("),
           ("RV1-RV3 (restore invariants", "RV1-RV4 (restore invariants"),
           ("WK1-WK4 (wake invariants", "WK1-WK5 (wake invariants")]
for _a, _b in _ID_FIX:
    assert sum(_v.count(_a) for _k, _v in globals().items() if not _k.startswith('_') and isinstance(_v, str)) == 1, _a
for _k, _v in list(globals().items()):
    if not _k.startswith('_') and isinstance(_v, str):
        for _a, _b in _ID_FIX:
            _v = _v.replace(_a, _b)
        globals()[_k] = _v
