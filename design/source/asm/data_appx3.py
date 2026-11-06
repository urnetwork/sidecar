# Appendix D, E, F and H data for DESIGN.md, third assembly (2026-11-04). Starts from data_appx2.py (loaded with
# runpy) and applies what the sections edited since the second assembly change: §8.8's statements, §7.9's records,
# §10.14's gkm routes (GroupInfo on demand, ReaderKeys and wraps under owner decision 114), §11.8 and §11.19
# (multi-part pushes, D-EVS-20; fair share, D-EVS-21), §13.15's ports (owner decision 121), §19.7's MG7 (now with
# `mail_direct_mx`), and the PLAN.md:61, :147, :221 and :346-350 rows (owner decisions 114-116, 122).
import runpy, pathlib

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_appx2.py'))


def _replace(rows, key, new):
    out, hit = [], False
    for r in rows:
        if r[0] == key:
            hit = True
            if new is not None:
                out.append(new)
        else:
            out.append(r)
    if not hit:
        raise KeyError(key)
    return out


# ------------------------------------------------------------------ Appendix D
MESSAGES = list(_P['MESSAGES'])

CARRIED = list(_P['CARRIED'])
CARRIED = _replace(CARRIED, '`ReaderWrap`',
    ('`ReaderKey`, `ReaderWrap`', 'gkm over HTTPS (`/gkm/reader-key`, `gkm/<group_id>/wrap/<g>/<sidecar_id>`)',
     "An agent's signed X-Wing reader key, and a writer's signed wrap of RK_g to it, so non-member sidecars read without a leaf (owner decision 114)", '§10.5'))
CARRIED = _replace(CARRIED, '`EvsPush`',
    ('`EvsPush`, `EvsPushPart`', '`POST /evs/v1/repos/<id>/push`, `/push/<push_id>/<k>`',
     'Signed manifest delta: token paths, base versions, locators, sealed commit metadata; a push over 1 MiB or 1,024 entry writes travels in up to 1,024 hashed parts that `part_sha256` binds (D-EVS-20)', '§11.8'))
CARRIED = _replace(CARRIED, '`Genesis`, `AdminSet`, `MemberAdmit`, `MemberRevoke`, `SidecarAdmit`, `SidecarRevoke`, `Delegation`, `DelegationRevoke`',
    ('`Genesis`, `AdminSet`, `MemberAdmit`, `MemberRevoke`, `SidecarAdmit`, `SidecarRevoke`, `SponsorSet`, `KeyRegister`, `KeyRevoke`, `Delegation`, `DelegationRevoke`, `ServiceSettings`',
     'the config repo (`protocol/config.proto`)',
     "The customer key authority's signed records; a Delegation carries a reader key, and ServiceSettings holds `team_mail`, `stale_leaf_days` and `self_admit`", '§7.9'))
CARRIED = _replace(CARRIED, '`Projection`, `ProjectionDelta`',
    ('`Projection`, `ProjectionDelta`', '`proj/<network_id>/<version>/_`, `proj/<network_id>/<version>/d/<seq>/_`; `/network/config/projection\\|delta`',
     'The signed id-only view of the config repo that server gates read, with its deltas', '§7.9'))
CARRIED = _replace(CARRIED, '`RepoCreate`, `RepoGrant`, `Suspend`, requested grants',
    ('`GrantActivate`, `GrantRevoke`, `Suspend`, `Unsuspend`, `EvsShare`, `OwnerConfirm`, `RepoCreate`, `RepoAdmin`, `RepoGrant`, `RepoRevoke`, `AuditOptIn`', 'config-repo deltas',
     "Approved runtime grants and their revocation, the one-switch suspension, an owner's shares and confirmations of admin-admitted devices, repo creation, admins and grants, and the audit reader", '§8.8'))

# ------------------------------------------------------------------ Appendix E: routes
ROUTES = list(_P['ROUTES'])
ROUTES = _replace(ROUTES, '`POST /gkm/key-packages`, `/gkm/key-packages/claim`, `/gkm/reader-key`',
    ('`POST /gkm/key-packages`, `/gkm/key-packages/claim`, `/gkm/reader-key`', 'Client (gkm token)',
     "Upload and claim member devices' KeyPackages; register an agent's ReaderKey (owner decision 114)", '§10.14'))
ROUTES = _replace(ROUTES, '`GET /gkm/groups/<id>/epochs?after=`; `POST /gkm/groups/<id>/epochs/<n>`',
    ('`GET /gkm/groups/<id>/epochs?after=`; `POST /gkm/groups/<id>/epochs/<n>`', 'Client (gkm token)',
     'Epoch objects in order, with their sizes; submit a commit (200, 409 with the winner, 403, 429)', '§10.14'))
ROUTES = _replace(ROUTES, '`GET /gkm/groups/<id>/gen?since=`, `/group-info`, `/wraps/<g>`, `/drop-key`; `GET /gkm/welcomes`',
    ('`GET /gkm/groups/<id>/gen?since=`, `/wraps/<g>`, `/drop-key`, `/group-info?want=<epoch>`; `GET /gkm/welcomes`', 'Client (gkm token)',
     'Generations, wraps, drop keys, sealed GroupInfo on demand (an older one also hints wrap-pending, KF5), pending Welcomes', '§10.14'))
ROUTES = _replace(ROUTES, '`PUT /evs/v1/repos/<id>/segments/<sid>`; `POST /evs/v1/repos/<id>/push`, `/path-epoch`',
    ('`PUT /evs/v1/repos/<id>/segments/<sid>`; `POST /evs/v1/repos/<id>/push`, `/push/<push_id>/<k>`, `/path-epoch`', 'Client (evs token; path-epoch admin)',
     'Upload segments; commit a push, in parts when over 1 MiB (D-EVS-20); rotate the path key', '§11.19'))

# ------------------------------------------------------------------ Appendix E: tables, Redis keys, object families
TABLES = list(_P['TABLES'])
TABLES = _replace(TABLES, '`mail_network`, `mail_host_key`, `mail_direct_mx`',
    ('`mail_network`, `mail_host_key`, `mail_direct_mx`', 'mxedge',
     'Mail-enabled networks; receiver host keys (`mx` or `mx.<scope>`); Team direct-MX receivers', 'MG7', '§15.15'))
TABLES = _replace(TABLES, 'Objects `repo/`, `head/`, `log/`, `push/`, `idx/`, `slot/`, `subs/`, `pmap/`, `pidx/` (metadata cluster); `seg/`, `pack/` (segment cluster)',
    ('Objects `repo/`, `head/`, `log/`, `push/`, `idx/`, `slot/`, `subs/`, `pmap/`, `pidx/` (metadata cluster); `seg/`, `pack/` (segment cluster)', 'evs (file cluster)',
     'Repo records with the write gate and lease counter, commit points, history pages, signed pushes and their parts, path index, key slots, subscription leases, path maps, pack indexes, segments, packed history; no Postgres rows (owner decision 2)', '—', '§11.8'))
TABLES = _replace(TABLES, 'Objects `gkm/repo/...`, `gkm/<group>/epoch/<n>`, `gkm/kp/...`, `gkm/rk/...`, Welcomes, `gen/`, `group-info`, wraps, acks, `gkm/recovery/...`',
    ('Objects `gkm/repo/...`, `gkm/<group>/epoch/<n>`, `gkm/kp/...`, `gkm/rk/...`, Welcomes, `gen/`, `group-info`, wraps, acks, `gkm/recovery/...`', 'gkm (metadata cluster)',
     "GroupForm chains, epoch objects (one accepted commit each), KeyPackages and claims, agents' ReaderKeys (owner decision 114), joins, generations, wraps, daily acks, recovery wraps; no Postgres rows", '—', '§10.6'))

# ------------------------------------------------------------------ Appendix E: services and config
SERVICES = list(_P['SERVICES'])
SERVICES = _replace(SERVICES, 'tlsedge',
    ('tlsedge', "`server/cli/tlsedge` behind W1's `ssl_preread` split on TCP 443, and unsplit on 8443, 8883 and 5671 (owner decision 121; W7); `config/<env>/tlsedge.yml`",
     'Layer-4 SNI router running K platform clients', '§13.15'))
SERVICES = _replace(SERVICES, 'evs',
    ('evs', '`server/cli/evs`, `evs.bringyour.com` (W2; segments on `streamable_paths`); engine `sidecar/evsservice`; `<tier>.sidecar:` with `store_weight` in pro.yml',
     "Stateless storage over the file cluster's metadata and segment buckets, sharing store operations per network by tier weight (D-EVS-21)", '§11.19, §19.4'))
SERVICES = _replace(SERVICES, 'smtpedge',
    ('smtpedge', '`server/cli/smtpedge`, g1 1 on 2 sending hosts, `exposed: false`, `cap_net_admin`; engine `smtpedgeservice`; prover and verifier module `smtpproof`; `config/<env>/smtpedge.yml`',
     "Outbound edge from M9; outbound 25 from its hosts' shared lb addresses, PTR names under bringyour.com (owner decision 124; §19.4)", '§14.14, §19.4'))

# ------------------------------------------------------------------ Appendix F
PLAN_TRACE = list(_P['PLAN_TRACE'])


def _trace(lines_key, stmt_prefix, new):
    global PLAN_TRACE
    for k, r in enumerate(PLAN_TRACE):
        if r[0] == lines_key and r[1].startswith(stmt_prefix):
            PLAN_TRACE[k] = new
            return
    raise KeyError((lines_key, stmt_prefix))


_trace('61', '"The file blobs are stored in minio in a new file cluster."',
       ('61', '"The file blobs are stored in minio in a new file cluster."', '§19.6 (D-OPS-4, D-OPS-14); §11.13; §19.15', 'kept (Q-OPS-1, owner 18, 116)',
        'Two MinIO clusters at one site, 4 hosts of 16 × 16 TB HDD at EC:8 plus an NVMe tier at EC:4 (owner decisions 20, 21, 94, 116), a cold spare, no off-site copy'))
_trace('147', '"ACLs as MLS Groups',
       ('147', '"ACLs as MLS Groups ... Read/write participants are leaves"', '§10.4 (D-KEYS-2, D-KEYS-11); §8.12 (D-ACL-17); §7.16, §8.16, §10.13',
        'amended (Q-ACL-9, owner 60, 114)', 'Member devices are leaves; tagged, ephemeral, CI and cloud agents read and write through per-generation wraps'))
_trace('221', '"the storage server/sequencer acts strictly',
       ('221', '"the storage server/sequencer acts strictly as an oblivious blob store and ordering authority ... no group secrets, epoch keys, or plaintext FEKs"', '§2.9 I-1; §10.6; §10.13',
        'narrowed by the owner directive (Q-KEYS-12, owner 115)', "gkm holds ciphertext plus 10.6's header values, confirmed by owner decision 115; member commits are PrivateMessage (D-KEYS-3)"))
_trace('346-350', '"Community / Pro / Team',
       ('346-350', '"Community / Pro / Team [$100/month+usage based overage]"', '§20.4, §20.5 (D-QUOTA-1); §20.9; §20.13', 'departed (Q-QUOTA-1, owner 27, 122)',
        'Team is $100 for 5 billable seats, then $20 a seat; overage only on transfer and storage, at existing rates (owner decision 122); sends, entries and endpoints are hard caps'))

# ------------------------------------------------------------------ Appendix H
RESEARCH = list(_P['RESEARCH'])
