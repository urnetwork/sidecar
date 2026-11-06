# Appendix C glossary, fourth assembly (2026-11-04). Starts from data_glossary3.py (the readability review's terms,
# review/READ.md Table 5, as the second and third assemblies updated them) and updates it to the sections as last
# edited (10:48) and to owner decisions 126-135: entries that described pending answers now state the decision, and
# terms the edited sections introduce are added. One sentence per term. Loaded with runpy. (term, definition, defined in)
import runpy, pathlib

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_glossary3.py'))
GLOSSARY = list(_P['GLOSSARY'])

_REPLACE = {
    "witness": ("witness", "Any other admitted reader sidecar, agents included, whose HeadCheck agrees with a writer's pins (owner decision 129).", "§2.14"),
    "hold (preservation)": ("hold (preservation)", "A legal hold pausing only the server's TTL sweeps and GC for in-scope objects, never users' shredding (owner decision 133).", "§21.9"),
    "tls_label": ("tls_label", "A received message's label: validated (owner decision 135) or opportunistic.", "§15.7"),
    "block (overlay)": ("block (overlay)", "A network's IPv4 /16 for overlay addresses, random from 100.64.0.0/10 or chosen there or in RFC 1918 (owner decision 132).", "§17.4"),
    "head window": ("window (head)", "The last 64-127 versions a ref's head object records, settling recent push ids.", "§11.8"),
    "Delegation": ("Delegation", "A signed config record letting CI or a tag owner admit sidecars within a scope, with a reader key for its agents.", "§7.9"),
    "ReaderKey, ReaderWrap": ("ReaderKey, ReaderWrap", "An agent's X-Wing reader key and a signed wrap of RK_g to it, so non-member sidecars read without a leaf (owner decision 114).", "§10.5"),
    "AdminSet": ("AdminSet", "The config-repo record of the config-signing roles (Owners, Admins, Network and IT admins) and the threshold k.", "§7.9"),
    "EvsPushPart": ("EvsPushPart", "One of up to 1,024 hashed parts of a push over 1 MiB, committed by one head PUT.", "§11.8"),
    "cold spare": ("cold spare", "A spare chassis and drives at the site, so a second host failure still meets the 4 h RTO (owner decision 116).", "§19.6"),
    "owner-bound repo": ("owner-bound repo", "A vault or mailbox bound to one member, read only by its consented devices, EvsShares and a visible audit reader.", "§11.12"),
    "OwnerConfirm": ("OwnerConfirm", "The statement by which a member's consented device or recovery key accepts a device an admin admitted under that member.", "§8.8"),
    "owner consent": ("owner consent", "The rule that only a member's consented devices read that member's owner-bound repos (owner decision 126).", "§8.5"),
    "edge login": ("edge login", "The member sign-in for a published service: a 60 s, nonce-bound, one-origin ID token, then a same-origin session.", "§7.8"),
    "DeviceAdmit": ("DeviceAdmit", "Withdrawn: a member-signed admission, subsumed by config-repo admissions (owner decisions 3, 112).", "§10.4"),
    "fair share": ("fair share", "The per-network split of metadata-cluster operations by tier weight (`store_weight`), shedding the heaviest network first.", "§11.13"),
}
_ADD = [
    ("witness_bound_hours", "The `ServiceSettings` bound (default 72 h, 24-168 h) at which unwitnessed shared-group writers stop (owner decision 129).", "§7.9"),
    ("recovery window", "The 72 h in which any admin device may veto a recovery-signed authority statement (owner decision 127).", "§7.9"),
    ("admission_alarm", "The alarm a member's devices raise for an admission under that member they did not sign.", "§5.6"),
    ("mail_operators.yml", "The versioned list of DANE- or MTA-STS-enforcing operators behind the validated label (D-MAIL-13).", "§15.12"),
    ("pager", "From M5, the out-of-hours pager for registrar, registry and law-enforcement emergency notices (owner decision 134).", "§19.8"),
]

_seen = set()
_orig = set()
_out = []
for t, dfn, w in GLOSSARY:
    _orig.add(t)
    if t in _REPLACE:
        t, dfn, w = _REPLACE[t]
    _out.append((t, dfn, w))
    _seen.add(t)
_missing = [k for k in _REPLACE if k not in _orig]
assert not _missing, _missing
for row in _ADD:
    assert row[0] not in _seen, row[0]
    _out.append(row)
GLOSSARY = _out
