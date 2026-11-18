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
# §15's fold (2026-11-16): the in-tree fork's two changes and ARC in-house (owner decision 446), and the scripted
# census's rank-weighted bar (439).
assert D['D-MAIL-3'].startswith('Receivers run emersion/go-smtp') and D['D-MAIL-9'].startswith('Owner accepts the M7 census'), 'MAIL rows moved'
D['D-MAIL-3'] = "Receivers run emersion/go-smtp, forked in-tree with 15.5's two upstreamable changes, and verify with mox over DoH, ARC in-house."
D['D-MAIL-9'] = "Owner accepts the scripted M7 census's loss before burners launch; proposed bar: under 5% of rank-weighted sign-up senders lack SNI."
# §16's fold (2026-11-16): a harness process's runs share taint (owner decision 448), and MCP's evs tools never touch
# the config repo or a mailbox's vault family (QD-205, owner decision 440).
assert D['D-MCP-16'].startswith('Run taint is a monotone') and D['D-MCP-17'].startswith("MCP's evs tools never write"), 'MCP rows moved'
D['D-MCP-16'] = "Run taint: a monotone, fsynced bit written before untrusted data leaves, shared by a harness process's runs; missing reads tainted."
D['D-MCP-17'] = "MCP's evs tools never touch config, secret or directory repos, nor write `mailcfg`; MCP signs no authority statement."
# §17's fold (2026-11-16): the config head's bridge ledger and unformed generations' void (owner decisions 473, 478),
# the start gate (474), and Q-BRIDGE-8 decided as recommended (484).
assert D['D-BRIDGE-6'].startswith('Bridge rules are signed config-repo statements') and D['D-BRIDGE-18'].startswith(
    'Only a verified state opens') and Q['Q-BRIDGE-8'][1].startswith('(a) on demand'), 'BRIDGE rows moved'
D['D-BRIDGE-6'] = ("Signed config-repo bridge statements; gates see only reach rules and BridgeRows; the head's ledger "
                   "freezes each body's verdict.")
D['D-BRIDGE-18'] = ("Only a verified state opens private destinations; states persist, never lowered by unsigned input; "
                    "starts replay judged denials first.")
Q['Q-BRIDGE-8'] = (Q['Q-BRIDGE-8'][0], "(a), owner decision 484: on demand, as §17.4 says; setup files no address.")
# §18's fold (2026-11-16): the page Worker's loader starts sidecar.wasm with gcstoptheworld=1 (owner decision 492),
# and the forwarding leg's budget rises to 7.5 MiB with the replaying config head reader on it (491).
assert D['D-SDK-19'].startswith('The page Worker builds the root') and Q['Q-SDK-7'][1].startswith('(a): +6 MiB'), 'SDK rows moved'
D['D-SDK-19'] = ("The page Worker builds the root `-tags sidecar_http`, linking no connect, its `Id` a twin; its loader "
                 "sets gcstoptheworld=1.")
Q['Q-SDK-7'] = (Q['Q-SDK-7'][0], "(a), amended by owner decision 491: +7.5 MiB stripped, 54 MiB ceiling, 10 MiB compiles.")
# §19's fold (2026-11-16): lego v4.35.2 runs and W5's swap waits (owner decisions 494, 502), the report intake in
# mxedge-platform (QD-151), the restore hold in sidecar.yml (QD-076), the pager service (498), the rdb filter's scratch
# server (QD-357), the read rule (511), and the limit read as rated write IOPS (QD-414).
assert D['D-OPS-12'].startswith('A builder job renews') and D['D-SMTP-11'].startswith('The engine is smtpedgeservice'), 'OPS rows moved'
D['D-OPS-9'] = "Adopt 19.8's SLOs and page classes, paging out of hours from M3 through a commercial pager; budget burn stops rollouts."
D['D-OPS-10'] = "Gates, the placement target, the restore hold and the owner's switches live in `config/<env>/sidecar.yml`."
D['D-OPS-12'] = "Platform certificates renew at two thirds of lifetime by ARI on lego v4.35.2, v5 the target; W5's swap waits."
D['D-OPS-16'] = "Redis backup bundles leave out sidecar key families, filtered from each node's rdb in a scratch server before sealing."
D['D-OPS-20'] = ("Both clusters run an in-house `urnetwork/minio` build: commits only before deadlines, keys released once settled, "
                 "503 without a read quorum.")
D['D-SMTP-11'] = ("The engine is smtpedgeservice in server/cli/smtpedge, its report intake in mxedge-platform from M5; provers are "
                  "smtpproof.")
D['D-EVS-33'] = "One write budget per metadata cluster (0.8 DWPD, 50% write IOPS) but P0; P1 prepays P2's wallet; heaviest refused first."
# §20's fold (2026-11-16): Team periods granted at their anchor (owner decision 514) and local pre-checks dark by
# QuotaLimits.enforced (520).
assert D['D-QUOTA-8'].startswith('Taskworker rolls usage') and D['D-QUOTA-2'].startswith('Limits and prices'), 'QUOTA rows moved'
D['D-QUOTA-2'] = "Limits and prices come only from pro.yml with overrides; limits and local pre-checks ship dark; a missing price withholds overage."
D['D-QUOTA-8'] = "Taskworker rolls usage into daily rows for pre-aggregated daily Stripe meters, and grants each Team period at its anchor."
# §22's and §23's fold (2026-11-16): Q-OPS-11, the segment placement's home and lead time (owner decision 550).
assert 'Q-OPS-11' not in Q, 'Q-OPS-11 exists'
Q['Q-OPS-11'] = ("When does the segment placement get a design and a home, and what is its lead time?",
                 "(a) a tracked item, 26-week lead; its design due 8 weeks after M3's exit.")
# The fold of DESIGN-DETAILS.md sections 1, 11 and 15 (2026-11-17): full index entries only (owner decision 584), and
# merges that read no head beside the roll-up's promotion (385).
assert D['D-EVS-46'].startswith('Each writer appends to a staged head') and D['D-EVS-47'].startswith(
    'Merges and roll-ups are functions of base files'), 'EVS index rows moved'
D['D-EVS-46'] = "Writers append full entries to a staged head ≤16,208 B, sealing into ≤8 reused slots that merges absorb into shards."
D['D-EVS-47'] = "Merges, reading no head, and roll-ups are functions of base files; a lock-fenced roll-up moves its bucket into all."
# The fold of DESIGN-DETAILS.md sections 2 and 14 (2026-11-17): segment GC waits for evacuation's horizon and raises no
# fence (owner decision 203), and evacuation deletes only a dead record's own slots, by their origin (399).
assert D['D-EVS-25'].endswith('die only after ref fences.') and D['D-EVS-34'].endswith('GC fences idle refs first.'), 'EVS GC rows moved'
D['D-EVS-25'] = "Orphans are found without the log: evacuation settles batch records, deleting dead records' own slots; GC waits for its horizon."
D['D-EVS-34'] = "Segment uploads write nothing to the metadata cluster: a MAC'd receipt rides the push; GC waits for evacuation's horizon."
# The fold of DESIGN-DETAILS.md section 10 (2026-11-17): the drop job marks past evacuation's horizon and deletes only
# objects the horizon has passed, by a DELETE naming each (owner decision 397).
assert D['D-EVS-64'].endswith('deletes objects over 25 h old.'), 'EVS drop row moved'
D['D-EVS-64'] = "Commit fences listed versions; past evacuation's horizon the job marks, verifies separately and deletes objects the horizon has passed."
# The fold of DESIGN-DETAILS.md sections 8 and 9 (2026-11-17): every path-epoch due batched (owner decision 585).
assert D['D-EVS-12'].startswith("11.6-11.7's token tree, re-keyed at once on removal"), 'EVS path epoch row moved'
D['D-EVS-12'] = "11.6-11.7's token tree, re-keyed by a signed map within 24 h of every removal or, deferred, once a source drops."
