# Appendix C glossary, third assembly (2026-11-04). Starts from data_glossary2.py (the readability review's terms,
# review/READ.md Table 5, as the second assembly updated them) and updates it to the sections as last edited and to
# owner decisions 112-125: entries that described pending answers now state the decision, and terms the edited
# sections introduce are added. One sentence per term. Loaded with runpy. (term, definition, defined in)
import runpy, pathlib

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_glossary2.py'))
GLOSSARY = list(_P['GLOSSARY'])

_REPLACE = {
    "BDAT": ("BDAT", "The SMTP CHUNKING command, which M9's preamble proofs cover alongside DATA (owner decision 125).", "§14.5"),
    "DATA circuit": ("DATA circuit", "The preamble proof for the SMTP DATA command, built alongside BDAT and part of D-SMTP-16's gate (owner decision 125).", "§14.5"),
    "DeviceAdmit": ("DeviceAdmit", "Withdrawn: a member-signed admission, subsumed by config-repo admissions that a member's own device may sign (owner decisions 3, 112).", "§10.4"),
    "ReaderKey, ReaderWrap": ("ReaderKey, ReaderWrap", "An agent's X-Wing reader key and a signed wrap of RK_g to it, by which non-member sidecars read without an MLS leaf (owner decision 114).", "§10.5"),
    "RS1-RS3": ("RS1-RS3", "recURd's three release stages: record and reach, the team layer and TLS edge, and inbox and assurance.", "§23.4"),
    "witnessed_at": ("witnessed_at", "When a witness last confirmed a sidecar's pins (D-TRUST-10).", "§2.14"),
    "cold spare": ("cold spare", "A spare chassis and drives kept at the site so a second host failure still meets the 4 h RTO (owner decision 116).", "§19.6"),
    "file cluster": ("file cluster", "The two new MinIO clusters at one site: NVMe metadata at EC:4 and HDD segments at EC:8 (owner decisions 20, 21, 94, 116).", "§19.6"),
    "Delegation": ("Delegation", "A signed config record letting CI or a tag owner admit sidecars within a scope, with a reader key so its agents read at once.", "§7.9"),
    "HeadCheck": ("HeadCheck", "A peer RPC comparing config, projection and shared MLS pins with another sidecar.", "§6.4"),
    "readers(repo)": ("readers(repo)", "The sidecars policy lets read a repo: member devices as its MLS leaves, other sidecars through ReaderWraps.", "§8.12"),
    "self_admit": ("self_admit", "The config setting, on by default, that lets a member's own device admit the member's new devices (owner decision 112).", "§7.9"),
    "write gate": ("write gate", "The repo object's rule refusing writes until a removal's Remove or rotation lands.", "§11.8"),
    "AdminSet": ("AdminSet", "The config-repo record of the Owners, Admins, Network admins and IT admins who sign config records, with the threshold k of Owners and Admins.", "§7.9"),
    "member": ("member", "A user in a network with one role: Owner, Admin, Network admin, IT admin, Billing admin, Auditor or Member.", "§7.5"),
}
_ADD = [
    ("OwnerConfirm", "The config statement by which a member's consented device or recovery key accepts a device an admin admitted under that member.", "§8.8"),
    ("owner consent", "The rule that only a member's consented devices, admitted or confirmed by the member's own keys, read that member's owner-bound repos.", "§8.5"),
    ("owner-bound repo", "A vault or mailbox bound to one member, read only by that member's consented devices, its EvsShares and a visible audit reader.", "§11.12"),
    ("EvsShare", "A statement by which an owner's consented device lets another subject read an owner-bound repo.", "§8.8"),
    ("EvsPushPart", "One of up to 1,024 hashed parts of a push over 1 MiB, bound by its Signed EvsPush and committed by one head PUT.", "§11.8"),
    ("fair share", "The per-network split of metadata-cluster operations by tier weight (`store_weight`) that evs and gkm enforce, shedding the heaviest first.", "§11.13"),
    ("witness", "Another reader device whose HeadCheck agrees with a writer's pins, bounding how long a server can hide a Remove; who qualifies is Q-TRUST-9's.", "§2.14"),
    ("edge login", "The member sign-in for a published service: a 60 s, nonce-bound ID token for one origin, then a same-origin session.", "§7.8"),
]

_seen = set()
_out = []
for t, dfn, w in GLOSSARY:
    if t in _REPLACE:
        t, dfn, w = _REPLACE[t]
    _out.append((t, dfn, w))
    _seen.add(t)
_missing = [k for k in _REPLACE if k not in _seen]
assert not _missing, _missing
for row in _ADD:
    assert row[0] not in _seen, row[0]
    _out.append(row)
GLOSSARY = _out
