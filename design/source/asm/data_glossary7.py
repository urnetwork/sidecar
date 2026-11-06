# Appendix C glossary, seventh assembly (2026-11-05). Starts from data_glossary6.py (the readability review's terms,
# review/READ.md Table 5, as the second to sixth assemblies updated them) and updates it to the sections as last
# edited (2026-11-05 00:02: the peer-review fix round, then the re-verification fix round) and to owner decisions
# 1-145, entry 140's record corrected (Q-EVS-9 closed).
# - Rewritten where the design changed: the small head and its window entries, batches (group commit), parts, BASE,
#   path epochs, placement, the write gate, the write budget and its governor, the file cluster, re-seeding, the auth
#   pin and its chain, the authorization log, genesis, admissions, Delegations, the leaves rule, ephemeral reaping,
#   generations and gen/, GenRotate, the ladder's wraps, C_g, reader keys, readers(repo), the control contract, the
#   out-of-hours rota (was "pager", owner decision 143) and G0's density rule.
# - Added, for terms the sections now lean on: fold (lazy index folding), upload receipt, parcel, fence (head), FORK,
#   P0-P2 (the write classes), metadata cluster (growth by whole clusters, owner decision 145), DelegationWrap (the
#   Delegation's reader key), soft state, and RV1-RV3 and WK1-WK4, named apart from RS1-RS3 and W1-W11.
# - Merged, where two entries defined one mechanism: erasure and ERASE push, deposit and deposit ref, DANE and TLSA,
#   CT and CT watch, burner and burner label, admission and SidecarAdmit/SidecarRevoke, socket registration and lease,
#   owned and shared ref, write gate and commit before write, privacy harness and its canary.
# - Dropped, as their sections define them where used: expansions of external standards (ARI, ARF, DPoP, HPKE,
#   MTA-STS, PROXY header, REQUIRETLS, RUA, TLS-RPT, JIT provisioning) and terms the sections name once or twice
#   (CSR proxy, evidence channel, lethal trifecta, mlsinterop/, UrMlsCredential).
# - Cites corrected where the defining subsection is elsewhere (AUTHZ1, child client, DeviceAdmit, outbox, write gate);
#   "no-egress sidecar" renamed to the sections' "declared no-egress".
# - A few unchanged definitions shortened, meaning kept, to stay within 5,000 words.
# One sentence per term, citing its defining section; at most 5,000 words. Loaded with runpy.
# (term, definition, defined in)
import runpy, pathlib, re as _re

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_glossary6.py'))
GLOSSARY = list(_P['GLOSSARY'])

_DELETE = {
    # merged into the entry _REPLACE gives the other half of the pair
    'commit before write', 'ERASE push', 'deposit ref', 'TLSA', 'CT watch', 'burner label',
    'SidecarAdmit, SidecarRevoke', 'lease (socket)', 'shared ref', 'canary (privacy)',
    # expansions of external standards
    'ARI', 'ARF', 'DPoP', 'HPKE', 'MTA-STS', 'PROXY header', 'REQUIRETLS', 'RUA', 'TLS-RPT', 'JIT provisioning',
    # named once or twice, and defined there
    'CSR proxy', 'evidence channel', 'lethal trifecta', 'mlsinterop/', 'UrMlsCredential',
}

_REPLACE = {
    # cites corrected; one renamed
    'AUTHZ1': ('AUTHZ1', "The gap whereby admin routes accept client tokens, so an agent-readable token administers the network.", '§5.7'),
    'DeviceAdmit': ('DeviceAdmit', "Withdrawn: a member-signed admission, subsumed by config-repo admissions.", '§10.12'),
    'child client': ('child client', "A client whose `source_client_id` is the device's client, exempt from top-level client caps.", '§20.8'),
    'outbox': ('outbox', "A queue in a member's mailbox through which phones send via a prover host.", '§14.4'),
    'no-egress sidecar': ('declared no-egress', "A sidecar declaring no internet egress, exempt from client caps.", '§20.8'),
    'DATA circuit': ('DATA circuit', "The preamble proof for SMTP DATA, built beside BDAT and part of the outbound mail gate.", '§14.5'),
    # evs: the small head and its window, batches, parts, flags, path epochs, placement, the gate and budget
    'head': ('head', "A ref's commit point, `head/<repo>/<ref>`, under ~9 KiB: version, chain, pins, path epoch, fence and window, changed only by If-Match.", '§11.8'),
    'window (head)': ('window (head)', "The head's 64-byte entries for its newest 64-127 versions, settling push ids and path checks until paged out to `log/`.", '§11.8'),
    'batch': ('batch', "An immutable `pb/` object of at most 256 KiB, group-committing one evs process's push records within 20 ms, evacuated after 25-26 h.", '§11.8'),
    'EvsPushPart': ('EvsPushPart', "One of up to 1,024 parts of a push over 1 MiB or 1,024 entry writes, committed by the push's seal.", '§11.8'),
    'BASE': ('BASE', "An admin push flag re-listing a ref's live set while keeping every push statement, for record-class retention.", '§11.8'),
    'owned ref': ('owned ref, shared ref', "A ref only its owner sidecar writes, append-only in record repos, or one any `rw` writer updates by its mode's CAS.", '§11.8'),
    'path epoch': ('path epoch', "A period under one path key; a REMOVE generation makes a new one due, at once for a device removal or compromise.", '§11.6'),
    'placement': ('placement', "A repo's metadata cluster, fixed at creation by a create-only `place/<repo_id>` on the first cluster and cached for good.", '§11.8'),
    'write gate': ('write gate (commit before write)', "The rule that a key-holder shrink or expiry blocks a repo's writes until a covering generation is claimed.", '§10.6'),
    'write budget, governor': ('write budget, governor', "Each metadata cluster's limit of 0.8 DWPD and 50% of write IOPS, whose allowances taskworker's governor publishes from measured drive bytes.", '§11.13'),
    'evacuation': ('evacuation', "Hourly work moving history older than 24 h from batches into packs or parcels.", '§11.13'),
    'erasure': ('erasure, ERASE push', "Destroying chosen entries' keys everywhere by a committed push on the repo's `erasure` ref naming their slots.", '§11.12'),
    'deposit': ('deposit, deposit ref', "Write-only data under a repo's drop key, on a ref per depositor, that only readers open and consume.", '§11.12'),
    'file cluster': ('file cluster', "One site's MinIO system of record: an HDD segment cluster at EC:8 and NVMe metadata clusters at EC:4.", '§19.6'),
    're-seed': ('re-seed', "Restoring a network from devices' copies after a site loss; readers accept a lower head under a signed EvsReseed.", '§19.10'),
    # authorization: the pin and its chain, the log, the config repo, admissions, Delegations, leaves, reaping
    'auth pin (AuthPin)': ('auth pin (AuthPin)', "(n, A_n): an authorization-log position and its chain digest, naming a state in statements, heads, commits and HeadCheck.", '§7.9'),
    'authorization log': ('authorization log', "One hash-chained log per network, `proj/<network_id>/<n>/_`, of projection bases, statements and api's ticks; its position is the projection version.", '§7.9'),
    'genesis': ('genesis', "The owner's first device's signed Genesis record, the network's trust anchor, whose hash invites and auth keys carry.", '§7.9'),
    'config repo': ('config repo', "The per-network evs repo of signed authority records, policy and settings that every admitted sidecar reads.", '§7.9'),
    'admission': ('admission (SidecarAdmit, SidecarRevoke)', "The config statements, chained to the genesis and signed by an admin or scoped signer, admitting and revoking sidecars.", '§7.9'),
    'Delegation': ('Delegation', "A signed config record whose key, seeded in pre-approved auth keys, admits up to max_admits tagged agents for at most 90 days.", '§7.9'),
    'leaves rule': ('leaves rule', "A network's first 1,000 live member devices are its config group's leaves; later ones read it by wraps, committing no Add or Remove.", '§7.9'),
    'ephemeral sidecar': ('ephemeral sidecar', "A sidecar reaped 30-36 minutes after its last poll and disconnect, or at once on `POST /sidecar/close`; a reap is a removal.", '§7.7'),
    # keys: generations and gen/, the ladder and its wraps, readers, the control contract
    'generation (g)': ('generation (g)', "One version of a repo's key RK_g, existing only at `gkm/<group_id>/gen/<g>`, rotated on a shrink or expiry and every 30 days.", '§10.5'),
    'GenRotate': ('GenRotate', "The signed record whose create-only PUT, after its wraps, claims generation g, with its commitment, auth pin and drop key.", '§10.5'),
    'Gen_g, GenLink_g, GenWrap_e': ('GenLink_g, GenWrap_e, LeafWrap', "The ladder link by which RK_g opens RK_{g-1}, and RK_g's wraps under KEK_e, per epoch or in the GenRotate.", '§10.5'),
    'C_g': ('C_g', "The commitment to RK_g that its GenRotate signs and heads' generation pins carry.", '§10.5'),
    'ReaderKey, ReaderWrap': ('ReaderKey, ReaderWrap', "A reader's signed X-Wing key and a signed wrap of RK_g to it, for reading without a leaf.", '§10.5'),
    'readers(repo)': ('readers(repo)', "The sidecars policy lets read a repo: member devices as its MLS leaves, others, config overflow included, through wraps.", '§8.12'),
    'control contract': ('control contract', "The `control`-class contract any two admitted sidecars get for Hello, Ping, HeadCheck and HeadCheckProof only.", '§6.4'),
    # operations and gates
    'pager': ('out-of-hours rota (pager)', "Two people on one pager service for §19.8's page classes from M3, and registrar, registry and law-enforcement notices from M5.", '§19.8'),
    'G0, Gn-in, Gn-out': ('G0, Gn-in, Gn-out', "The review gates: G0, peer review under the density rule before code, and each milestone's entry and exit reviews.", '§23.8'),
    # merged pairs elsewhere
    'DANE': ('DANE, TLSA', "TLS keys published as TLSA records in a DNSSEC-signed zone, which make senders send SNI.", '§15.5'),
    'CT': ('CT, CT watch', "Certificate Transparency's public logs of every certificate, which sidecars watch for certificates no network device requested.", '§13.8'),
    'burner': ('burner, burner label', "A generated address `<name>@<blabel>.<net>.<root>`, `<blabel>` its word-number label, under the network's wildcard MX.", '§15.9'),
    'registration (socket)': ('registration, lease (socket)', "A listener's 45 s lease on a name, with its weight and load, renewed every 15 s.", '§9.5'),
    'privacy harness': ('privacy harness', "The test harness asserting servers never receive plaintext or keys, by searching their stores for planted canaries.", '§22.7'),
    # shortened to make room, meaning kept
    '21842 (0x5552)': ('21842 (0x5552)', "The one connect subprotocol id carrying all sidecar traffic; 21843-21851 are held.", '§6.4'),
    'abstract socket': ('abstract socket', "A name `<net>:<name>` many clients may listen on, each dial reaching one listener.", '§9.4'),
    'barrier': ('barrier', "A named point in a protocol step where a fault schedule holds an actor, so interleavings replay.", '§22.8'),
    'cold spare': ('cold spare', "A spare chassis and drives on site, so a second host failure meets the 4 h RTO.", '§19.6'),
    'drop key': ('drop key', "A per-generation public key in the signed GenRotate, letting depositors write what only readers can read.", '§10.5'),
    'fault schedule (FS-n)': ('fault schedule (FS-n)', "A deterministic script of actor steps, barriers, store faults and clock moves, checked against FI-1 to FI-14.", '§22.8'),
    'MailDeposit': ('MailDeposit', "A received message under its own key, slotted to the mailbox's newest drop key with sealed reception evidence.", '§15.7'),
    'pack': ('pack', "A segment-cluster object of a repo's history older than 24 h, written at 256 KiB or 7 days.", '§11.13'),
    'projection': ('projection', "The signed id-only view of the config repo that server gates read, published as an authorization-log base.", '§7.9'),
    'R, W, O (tool tiers)': ('R, W, O (tool tiers)', "MCP tool tiers: read, in-network write, and outward actions needing approval.", '§16.5'),
}

_ADD = [
    ('fold', "Lazily writing committed window versions into their paths' `idx/` entries off the reply path, adding no head write.", '§11.7'),
    ('upload receipt', "evs's MAC'd reply to a segment upload, replacing a metadata write, which the adopting push presents within 24 h.", '§11.13'),
    ('parcel', "An `hp/` object holding a small repo's evacuated records on NVMe until they pack at 256 KiB or 7 days.", '§11.13'),
    ('fence (head)', "A head write raising `fence` but no version, ending every earlier-arrived attempt, so a refusal after it stays true.", '§11.8'),
    ('FORK', "The alarm, stopping sealing where it applies, when a peer's or the server's state conflicts with a sidecar's pin.", '§6.4'),
    ('P0, P1, P2 (write classes)', "The write budget's classes: P0 (revocations, lifecycle, Removes), never refused; P1 (pushes), queued per network; P2 (folds, evacuation, GC), which P1 prepays.", '§11.13'),
    ('metadata cluster', "One 8-drive NVMe set at EC:4 in one MinIO pool; the tier grows only by adding clusters, each taking new repos.", '§19.9'),
    ('DelegationWrap', "A signed wrap of RK_g to a Delegation's reader key, through which its agents read until the Delegation ends or a non-reap revocation of one drops the key.", '§10.5'),
    ('soft state', "Rebuildable Redis state outside the rdb bundles (leases, acks, push sequences, verified caches), never a commit point.", '§19.7'),
    ('RV1-RV3', "The restore invariants: only the run's own edits, exact bytes or nothing, no stale preview; not RS1-RS3.", '§16.7'),
    ('WK1-WK4', "The wake invariants: one slot per script, delivery unless acked or coalesced, no hint lost with a queue entry, content-free payloads; not W1-W11.", '§18.7'),
]

_seen, _orig, _out = set(), set(), []
for t, dfn, w in GLOSSARY:
    _orig.add(t)
    if t in _DELETE:
        continue
    if t in _REPLACE:
        t, dfn, w = _REPLACE[t]
    assert t not in _seen, t
    _out.append((t, dfn, w))
    _seen.add(t)
_missing = [k for k in list(_REPLACE) + list(_DELETE) if k not in _orig]
assert not _missing, _missing
assert not set(_REPLACE) & _DELETE
for row in _ADD:
    assert row[0] not in _seen, row[0]
    _out.append(row)
    _seen.add(row[0])
GLOSSARY = [(t, _re.sub(r'\s*\((?:owner decisions? [^)]*|D-[A-Z]+-\d+)\)', '', d), w) for t, d, w in _out]
