# Appendix C glossary, sixth assembly (2026-11-04). Starts from data_glossary4.py (the readability review's terms,
# review/READ.md Table 5, as the second to fourth assemblies updated them) and updates it to the sections as last
# edited (19:51), to owner decisions 136-145 and to FRONT.md's FRONT-17 to FRONT-30: entries whose design changed
# are rewritten, withdrawn terms the sections no longer name are dropped, and the terms the peer review introduced
# (heads, batches, pins, generations, path epochs, placement, the governor, the authorization log, fault
# schedules) are added. The id-family entries (C1-C18, F1-F10, M0-M9 and the like) are dropped, since How to
# review lists every family with its section. One sentence per term; at most 5,000 words. Loaded with runpy.
# (term, definition, defined in)
import runpy, pathlib

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_glossary4.py'))
GLOSSARY = list(_P['GLOSSARY'])

_DELETE = {
    # withdrawn: the drop key rides the signed GenRotate (FRONT-23)
    'DropKeyStatement',
    # id families, listed under How to review
    'C1-C18', 'EX1-EX8', 'F1-F10', 'H1, H3', 'I-1..I-18', 'KF1-KF7', 'M0-M9', 'MG0-MG9', 'S1-S10', 'T1-T6',
    'TB1-TB3', 'TL1-TL4', 'W1-W11', 'X1-X20', 'Y1, Y2',
    # generic terms the owning sections define where they are used
    'assured stage', 'chunking', 'credit', 'stream', 'relay', 'subject', 'Feedback-ID', 'ECH', 'backup ticket',
    'sidecar infrastructure', 'sidecar subprotocol',
}

_REPLACE = {
    'AclRows': ('AclRows', "The id-only policy rows compiled at each base and carried in ProjectionRows for server gates.", '§8.8'),
    'BridgeState': ('BridgeState', "A sidecar role's compiled bridge rules, names and anchor for its keyless device role.", '§17.8'),
    'commit before write': ('commit before write', "The rule that once a repo's key holders shrink, evs refuses writes until a covering generation is claimed.", '§10.6'),
    'Delegation': ('Delegation', "A signed config record letting CI or a tag owner admit sidecars in a scope; its agents read by its key, dropped when one is revoked, not reaped.", '§7.9'),
    'device role': ('device role', "The keyless half of the sidecar, the package `sidecar/device`, routing bridge flows in network processes.", '§18.4'),
    'drop key': ('drop key', "A per-generation public key, in its generation's signed GenRotate, letting depositors write what only readers can read.", '§10.5'),
    'ephemeral sidecar': ('ephemeral sidecar', "A sidecar reaped 30-36 minutes after its last disconnect or poll, which counts as a removal.", '§7.7'),
    'erasure': ('erasure', "Destroying chosen entries' keys in every representation by an ERASE push, so their ciphertext becomes unreadable.", '§11.12'),
    'EvsPush': ('EvsPush', "A push's signed statement, at most 1 KiB in its log page; its payload rides its batch record.", '§11.8'),
    'fair share': ('fair share', "The per-network split of a metadata cluster's write budget by `store_weight`, refusing the heaviest network first.", '§11.13'),
    'file cluster': ('file cluster', "The new MinIO clusters at one site: HDD segments at EC:8 and PM9A3 metadata clusters at EC:4, added whole.", '§19.6'),
    'generation (g)': ('generation (g)', "One version of a repo's key RK_g, existing only as a signed GenRotate, rotated on a shrink and every 30 days.", '§10.5'),
    'HeadCheck': ('HeadCheck', "A peer RPC comparing auth pins, generations, ref heads, shared MLS epochs and vetoes with another admitted sidecar.", '§6.4'),
    'window (head)': ('window (head)', "The 64-byte entries for a ref's recent versions in its head, settling push ids until folded into `idx/`.", '§11.8'),
    'index entry': ('index entry', "A path's `idx/` object in one path epoch, holding folded committed versions.", '§11.7'),
    'keychain': ('keychain', "The local store of a sidecar's keys, sealed under its network's root key R_n.", '§5.9'),
    'MailDeposit': ('MailDeposit', "A received message under its own key, slotted to the mailbox's newest drop key, with its sealed reception evidence.", '§15.7'),
    'owner-bound repo': ('owner-bound repo', "A member's vault, mailbox or secret repo, read only by its consented devices, EvsShares and a visible audit reader.", '§11.12'),
    'pack': ('pack', "A segment-cluster object of a repo's history older than 24 h, written at 256 KiB or at 7 days.", '§11.13'),
    'path epoch': ('path epoch', "A period under one path key; a key-holder shrink makes a new one due, at once for a device removal or compromise.", '§11.6'),
    'pin': ('pin', "A value a client refuses to see go backward: an auth pin, a generation, a ref's version and chain, or a key.", '§10.4'),
    'projection': ('projection', "The signed id-only view of the config repo that server gates read, published as a base entry of the authorization log.", '§7.9'),
    'reconciler': ('reconciler', "gkm's taskworker job for epoch retention, hints and staged-wrap GC.", '§10.6'),
    're-seed': ('re-seed', "Restoring evs and gkm from devices' copies after a site loss; readers accept a lower head under a signed EvsReseed.", '§19.10'),
    'repo kind': ('repo kind', "A repo's fixed type: general, record, config, team_record, mailcfg, vault, mailbox or secret.", '§11.12'),
    'root key': ('root key (R_n)', "A network's random local key sealing its files, wrapped by the instance unlock key and that network's recovery key.", '§5.9'),
    'shared ref': ('shared ref', "A ref several writers update: by tip CAS in git mode, by path-level CAS in file mode.", '§11.8'),
    'Signed': ('Signed', "The typed signature envelope, its `type` among the signed bytes, for every statement others act on.", '§6.9'),
    'write gate': ('write gate', "The head CAS's check that a commit's authorization and generation pins pass §10.6's predicate.", '§11.8'),
    'readers(repo)': ('readers(repo)', "The sidecars policy lets read a repo: member devices as its MLS leaves, everyone else through wraps.", '§8.12'),
    'cold spare': ('cold spare', "A spare chassis and drives at the site, so a second host failure meets the 4 h RTO.", '§19.6'),
    'ReaderKey, ReaderWrap': ('ReaderKey, ReaderWrap', "An agent's X-Wing reader key and a signed wrap of RK_g to it, for reading without a leaf.", '§10.5'),
    'OwnerConfirm': ('OwnerConfirm', "A member device's or recovery key's acceptance of a device an admin admitted under that member.", '§8.8'),
    'admin_refused': ('admin_refused', "An immutable mint-time mark on enrollment- or sidecar-minted clients, whose tokens admin routes refuse.", '§7.4'),
    'agent': ('agent', "A harness process working through a sidecar, labeled on the sidecar's client, holding no key.", '§5.5'),
    'CSR proxy': ('CSR proxy', "certs' path by which a device gets a certificate for its own key from a CSR.", '§13.8'),
    'self_admit': ('self_admit', "The config setting, on by default, letting a member's own device admit its new devices.", '§7.9'),
    'abuse_case': ('abuse_case', "The record joining one abuse report to a network, with its actions and appeal.", '§21.8'),
    'action_id': ('action_id', "The id linking one outward action's proposal, approval and execution in the record.", '§16.8'),
    'DATA circuit': ('DATA circuit', "The preamble proof for SMTP DATA, built beside BDAT and part of D-SMTP-16's gate.", '§14.5'),
    'GKM': ('GKM', "Group key management: gkm, the MLS delivery service plus wrapped key generations.", '§10.6'),
    'direct MX': ('direct MX', "A Team option pointing MX straight at the team's own always-on receivers, bypassing mxedge.", '§15.4'),
    'abuse limit': ('abuse limit', "A rate or count cap equal on every tier, never sold, tightened per network by §21.", '§20.9'),
    'pager': ('pager', "§19.8's out-of-hours rota: infrastructure page classes from M3, plus registrar, registry and law-enforcement notices from M5.", '§19.8'),
    'admission': ('admission', "A config-repo statement, signed by an admin or a scoped signer and chained to the genesis, admitting a sidecar.", '§7.9'),
    'key slot': ('key slot', "A small object of up to 64 sealed per-entry keys; erasure removes them.", '§11.6'),
}


_ADD = [
    ('authorization log', "One hash-chained log per network, `proj/<network_id>/<n>/_`, ordering every projection base and statement; its position is the projection version.", '§7.9'),
    ('auth pin (AuthPin)', "(n, A_n): an authorization-log position and its chain digest, carried by pushes, heads, commits, approvals and HeadCheck.", '§7.9'),
    ('leaves rule', "A network's first 1,000 live member devices are its config group's leaves; later ones read it by wraps.", '§7.9'),
    ('GenRotate', "The signed statement creating generation g at `gkm/<group_id>/gen/<g>`, with its commitment, auth pin and drop key.", '§10.5'),
    ('key holders', "The parties a generation is wrapped to: leaves, uncovered agents, live Delegations and recovery keys.", '§10.5'),
    ('control contract', "The `control`-class contract any two admitted sidecars get for Hello, Ping and HeadCheck only (D-PROTO-18).", '§6.4'),
    ('PollResponse', "The long-poll's 200 body: a cursor plus hints or a reset, never an empty 204.", '§6.8'),
    ('head', "A ref's commit point, `head/<repo>/<ref>`: version, chain, pins and window, changed only by If-Match.", '§11.8'),
    ('git mode, file mode', "A ref's mode, fixed at creation: git-mode refs commit only on their tip (owner decision 141), file-mode refs land disjoint paths.", '§11.7'),
    ('batch', "An immutable `pb/` object, at most 256 KiB, of one evs process's push records, deleted whole after 25-26 h.", '§11.8'),
    ('evacuation', "Hourly work moving history older than 24 h from batches into packs, or small repos' NVMe parcels.", '§11.13'),
    ('placement', "A repo's metadata cluster, fixed at creation by a create-only `place/<repo_id>` on the first cluster (owner decision 145).", '§11.8'),
    ('ERASE push', "A committed push on a repo's `erasure` ref that destroys every key of the slots it names, in every representation.", '§11.12'),
    ('write budget, governor', "Each metadata cluster's ceiling of 0.8 DWPD and 50% of rated IOPS, which taskworker's governor publishes as `{nvb_<set>}` (owner decision 140).", '§11.13'),
    ('WindowDelegation', "The subject's signed delegation of a bridge link's window client, which the host verifies before admitting flows.", '§17.9'),
    ('barrier', "A named point in a protocol step where a fault schedule holds an actor, so interleavings replay exactly.", '§22.8'),
    ('fault schedule (FS-n)', "A deterministic script of actor steps, barriers, injected store results and clock moves, checked against FI-1 to FI-14 after every step.", '§22.8'),
]

_seen, _orig, _out = set(), set(), []
for t, dfn, w in GLOSSARY:
    _orig.add(t)
    if t in _DELETE:
        continue
    if t in _REPLACE:
        t, dfn, w = _REPLACE[t]
    _out.append((t, dfn, w))
    _seen.add(t)
_missing = [k for k in list(_REPLACE) + list(_DELETE) if k not in _orig]
assert not _missing, _missing
for row in _ADD:
    assert row[0] not in _seen, row[0]
    _out.append(row)
import re as _re
GLOSSARY = [(t, _re.sub(r'\s*\((?:owner decisions? [^)]*|D-[A-Z]+-\d+)\)', '', d), w) for t, d, w in _out]
