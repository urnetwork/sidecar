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
# Section 8's fold: the journal's outcomes read from the ref's history, and its two new items.
assert D['D-EVS-28'].endswith('a durable push-id journal.') and 'D-EVS-68' not in D and 'D-EVS-69' not in D, 'EVS git rows moved'
D['D-EVS-28'] = ("Publishes through git's proc-receive hook: per-ref statuses, no atomic pushes, an intent journal "
                 "whose outcomes the ref's history gives.")
D['D-EVS-68'] = "A git-mode push carries what readers lack: commits and odd trees as bytes, history blobs, and " \
                "named source versions."
D['D-EVS-69'] = ("Local git refs move only by applying evs's versions in order; divergent local commits go to a "
                 "published conflict branch.")
# The fold of DESIGN-DETAILS.md sections 5 and 6 (2026-11-17): rows keep every confirmation, so rows-only gates build
# a cascade's closure as readers do (section 5), and a group's one repo through its owner marker (owner decision 201),
# section 6.8's D-KEYS-28, numbered D-KEYS-27 here since 6.8's D-KEYS-27, the roster rule of MLS commits, waits with
# QD-1040's MLS deferral.
assert D['D-TEAM-26'].startswith('A compromise `SidecarRevoke` parks') and 'D-KEYS-27' not in D, 'TEAM and KEYS rows moved'
D['D-TEAM-26'] = "A compromise `SidecarRevoke` parks what the device signed from `since_n` on until reconfirmed; rows keep every confirmation."
D['D-KEYS-27'] = "A group belongs to one repo: its owner marker, created first, is the only binding gkm resolves it by."
# The fold of DESIGN-DETAILS.md section 4 (2026-11-17): the posture applies denials at once and opens only on a
# compiled state (owner decisions 216, 487), and the leg is a computed closure whose size make size holds.
assert D['D-SDK-13'].startswith('The forwarding role compiles its own rules') and D['D-SDK-20'].startswith(
    'Forwarding is `sidecar/device` plus'), 'SDK forwarding rows moved'
D['D-SDK-13'] = "The forwarding role compiles its rules, applies denials at once, opens only on compiled states, and signs its delegations."
D['D-SDK-20'] = "Forwarding is `sidecar/device` plus the root's computed forwarding closure; `make check` holds its list, `make size` its stripped size."
# The fold of DESIGN-DETAILS.md section 12 (2026-11-17): the engine's one order, commit, publish, close.
assert D['D-BRIDGE-21'].startswith('A revocation swaps policy before'), 'BRIDGE engine row moved'
D['D-BRIDGE-21'] = "Engine order: commit, publish, close; flows register rule and policy generation before dialing and recheck before the first byte."
# The design-defer-doc fold (2026-11-18): Q-EVS-3's prefix rules are Later (owner decision 586).
assert Q['Q-EVS-3'][1] == "Separate repos in v0; sidecar-enforced prefix rules in v1.", 'Q-EVS-3 row moved'
Q['Q-EVS-3'] = (Q['Q-EVS-3'][0], "Separate repos at launch; sidecar-enforced prefix rules are Later (owner decision 586).")
# The dr4-late-sweep fold (2026-11-18): sockets' routes take service tokens (owner decision 588).
assert D['D-SOCK-10'].startswith('Host the engine as server/cli/sockets with Client-class routes'), 'D-SOCK-10 row moved'
D['D-SOCK-10'] = "Host the engine as server/cli/sockets, its routes under service tokens of audience sockets, keeping registration load off api."
# The dr4-late-sweep fold (2026-11-18): presence keys with no attestation (owner decision 608).
assert D['D-MCP-19'] == "Presence evidence follows 16.6's profiles: WebAuthn with UP and UV per use; Secure Enclave keys labeled asserted.", 'D-MCP-19 row moved'
D['D-MCP-19'] = "Presence evidence follows 16.6's profiles: WebAuthn with UP and UV per use, and Secure Enclave keys; one label, presence."
# The dr4-late-sweep fold (2026-11-18): MLS Later, every group key by wraps in v0 (owner decision 610).
for _k, _start, _new in [
        ('D-KEYS-1', 'MLS distributes key-encryption keys', "v0 distributes every group key by KeyDelivery wraps; in-house MLS is Later, its code dark (owner decisions 43, 610)."),
        ('D-KEYS-2', 'One MLS group per repo', "Every reader holds per-generation wraps in v0; MLS, Later, gives member devices leaves up to 1,000 (owner decision 610)."),
        ('D-KEYS-3', 'Member commits are PrivateMessage', "With MLS, Later: PrivateMessage member commits add only generation and auth pin in clear; v0 has no commits."),
        ('D-KEYS-12', 'MLS is 10.4', "With MLS, Later: 10.4's subset on ciphersuite 0x0010, migrating through GroupForm if IANA assigns another value."),
        ('D-KEYS-14', "Groups scale by 10.6", "With MLS, Later: 10.6's sizes, KF5 resync, GroupInfo above 16 leaves, daily acks, streamed trees; v0 delivers per holder."),
        ('D-KEYS-18', 'At most 16 leaves', "With MLS, Later: at most 16 leaves the epoch carries sealed GroupInfo; KF1 writes owner marker and wraps first."),
        ('D-KEYS-23', "The team directory's group", "The directory's readers hold wraps in v0; with MLS, Later, its group follows the config group's leaves rule."),
]:
    assert D[_k].startswith(_start), (_k, 'row moved')
    D[_k] = _new
assert Q['Q-KEYS-9'][1].startswith('MLS in v0'), 'Q-KEYS-9 row moved'
Q['Q-KEYS-9'] = (Q['Q-KEYS-9'][0], "Wraps alone in v0, MLS Later (owner decision 610, amending owner decision 1).")
# The dr4-late-sweep fold (2026-11-18): C19's windows withdrawn (owner decision 609).
assert D['D-PROTO-22'].startswith("A marked pair's reports are withheld"), 'D-PROTO-22 row moved'
D['D-PROTO-22'] = "Superseded by owner decision 609: the remote-search pair's contracts are accounted like any peer's."
WITHDRAWN_D = dict(WITHDRAWN_D)
WITHDRAWN_D['D-PROTO-22'] = 'owner decision 609'
assert D['D-SDK-27'].startswith('At foreground, apps Hello'), 'D-SDK-27 row moved'
D['D-SDK-27'] = "Apps Hello an own indexer when a search needs it, keeping no warm pair; failover waits 3 s."
assert Q['Q-PROTO-4'][1].startswith('(b), owner decisions 176, 188, 191'), 'Q-PROTO-4 row moved'
Q['Q-PROTO-4'] = (Q['Q-PROTO-4'][0], "(b), then owner decision 609: the pair is accounted like any peer's, with no windows.")
# The dr4-late-sweep fold (2026-11-18): sidecar's server-hosted packages (owner decisions 593, 594).
assert D['D-REPO-3'].startswith("Engines live in sidecar over operator-core's Env"), 'D-REPO-3 row moved'
D['D-REPO-3'] = "Engines live in sidecar over operator-core's Env; sidecar owns its SQL and server-hosted packages (owner decisions 19, 251, 594)."

# Owner decision 141's file-mode amendment, approved 2026-11-20.
D['D-EVS-22'] = ("Git-mode refs require their tip. File-mode refs admit disjoint writes and optionally require "
                 "the signed base version and chain.")
Q['Q-EVS-8'] = (Q['Q-EVS-8'][0], "Git requires its tip. File mode admits disjoint writes by default and supports "
                "an exact-head precondition.")
