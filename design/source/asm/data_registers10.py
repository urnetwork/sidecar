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
# QD-425 (2026-11-16): a share is served while the sharing sidecar runs (§9.9), and D-SOCK-16's row names its expiry.
assert Q['Q-CTX-4'][1].count("while `ur share` runs") == 1 and 'expiry' not in D['D-SOCK-16'], 'share rows moved'
Q['Q-CTX-4'] = (Q['Q-CTX-4'][0], Q['Q-CTX-4'][1].replace("while `ur share` runs", "while the sharing sidecar runs"))
D['D-SOCK-16'] = ("`ur share`, a live sharer: blinded `share/<token>` socket, fragment secret, durable use count, expiry "
                  "(24 h default, 30 days most).")
# §10's fold (2026-11-16): a drop key's 90-day life and renewal (owner decision 357), trees streamed from disk (366),
# and gen/ as where a generation is created, a gen pack holding it later (QD-280).
assert D['D-KEYS-8'].startswith('Drop keys in each signed GenRotate') and 'alone holds a generation' in D['D-KEYS-15'], 'KEYS rows moved'
D['D-KEYS-8'] = "Drop keys in signed GenRotates, 90-day and renewed, give write-only deposits to covering generations; one repo per key domain."
D['D-KEYS-14'] = ("Groups scale by 10.6's sizes: self-update interval, KF5 resync, GroupInfo on demand above 16 leaves, daily acks, "
                  "streamed on-disk trees.")
D['D-KEYS-15'] = "`gkm/<group_id>/gen/<g>`, created If-None-Match by the rotator, alone creates a generation; MLS commits never raise it."
# §14's fold (2026-11-16): pins per recipient domain and MX host (owner decision 438), parts of one record (433), and the
# key schedule proven once under a hiding commitment (433).
assert D['D-SMTP-2'].endswith('pinned hosts are never downgraded.') and '2-minute parts' in D['D-SMTP-20'], 'SMTP rows moved'
D['D-SMTP-2'] = ("STARTTLS is mandatory; an unauthenticated MX needs the user's per-domain consent; no domain goes below its "
                 "pin on a host.")
D['D-SMTP-20'] = ("DATA mode proves every message octet in one-record parts within 2 h, up to `smtp_data_proof_bytes`; larger "
                  "mail gets a DSN.")
D['D-SMTP-22'] = "14.5's relation proves the MX's replies and Z1 once, under a hiding key commitment; BDAT bodies stream unopened."
