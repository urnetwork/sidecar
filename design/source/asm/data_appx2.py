# Appendix D, E, F and H data for DESIGN.md, updated 2026-11-04 to the edited section files.
# Starts from the previous assembly's data_appx.py (loaded with runpy) and applies the changes the edited
# sections make: §6.11 (SmtpProof at M9), §7.17 (no client-child route; GET /network/clients), §10.14 (recovery
# bindings moved to the config repo), §11.8 and §11.19 (restore, pmap/, pidx/, pack/, hold/), §12.8 and §15.15
# (direct MX, mail_direct_mx, smtp/25/mx), §18.15 and §19.7 (wake keys, MG2 quota state), §19.5 (W10, W11) and
# the Departures subsections (PLAN.md:74, :104, :147, :148, :221, :28, :31). Loaded with runpy.
import runpy, pathlib

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_appx.py'))


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
MESSAGES = _replace(MESSAGES, '`SmtpProof`, `SmtpProofResult`',
    ('`SmtpProof`, `SmtpProofResult`', '0x1605, 0x1606', 'sidecar ↔ smtpedge (RPC), M9',
     'The ZK preamble proof that outbound mail waits for (owner decision 35)', '§14.5'))
MESSAGES = _replace(MESSAGES, '`GkmHint`',
    ('`GkmHint`', '0x1301', 'ControlId → client (topics `gkm`, `gkm:<group_id>`)',
     'Commit, pending change, Welcome, KeyPackages low, or wrap pending (a GenWrap, ReaderWrap or sealed GroupInfo is missing)', '§10.14'))
MESSAGES = _replace(MESSAGES, '`MailHint`',
    ('`MailHint`', '0x1702', 'ControlId → client (topic `mail`)', 'A deposit is waiting, or a receiver is needed', '§15.15'))

CARRIED = list(_P['CARRIED'])
CARRIED = _replace(CARRIED, '`RecoveryBinding`, recovery wraps',
    ('`RecoveryBind`, recovery wraps', 'the config repo (§7.9); `/gkm/recovery/<member_id>/wraps`',
     "A member's signed, rotatable recovery-key binding, and the wraps of repo-key generations to that key", '§7.9, §10.8'))
CARRIED = _replace(CARRIED, '`ReaderWrap`',
    ('`ReaderWrap`', 'gkm over HTTPS', 'A signed X-Wing wrap of RK_g to a non-leaf reader, only if the owner answers Q-ACL-9 (a)', '§10.5'))
CARRIED.append(('`EvsPathMap`', '`pmap/<repo>/<ref>/<p>/<part>/_`', "Signed old-to-new token-path moves for a path epoch, with names re-sealed", '§11.6'))

# ------------------------------------------------------------------ Appendix E: routes
ROUTES = list(_P['ROUTES'])
ROUTES = _replace(ROUTES, '`POST /network/client-child`', None)
ROUTES = _replace(ROUTES, '`/scim/v2/<network_id>/…`',
    ('`/scim/v2/<network_id>/...`', 'Public (SCIM bearer)', 'SCIM provisioning, Team v1', '§7.17'))
ROUTES = _replace(ROUTES, '`POST /account/api-key`',
    ('`POST /account/api-key`', 'Network (existing route)', 'Gains scopes and expiry', '§7.17'))
_i = [r[0] for r in ROUTES].index('`POST /account/api-key`')
ROUTES.insert(_i, ('`GET /network/clients`', 'Network (existing route)', 'Gains `acl_enforcing`, so the console lists legacy clients (owner decision 106)', '§7.17, §8.10'))
ROUTES = _replace(ROUTES, '`GET\\|POST /gkm/recovery/<member_id>/bindings`; `GET\\|POST\\|DELETE /gkm/recovery/<member_id>/wraps`',
    ('`GET\\|POST\\|DELETE /gkm/recovery/<member_id>/wraps`', 'Client (gkm token)', 'Recovery wraps; the bindings are config-repo records (§7.9)', '§10.14'))
ROUTES = _replace(ROUTES, '`PUT\\|GET\\|DELETE /evs/v1/repos/<id>`; `POST /evs/v1/repos/<id>/reseed`',
    ('`PUT\\|GET\\|DELETE /evs/v1/repos/<id>[?now=1]`; `POST /evs/v1/repos/<id>/restore`, `/reseed`', 'Client (evs token; restore and reseed admin)',
     'Create, read, soft-delete (or shred at once) a repo; restore within 7 days; re-seed after site loss', '§11.12, §11.19'))
ROUTES = _replace(ROUTES, '`POST /dns/key-record`',
    ('`POST /dns/key-record`', 'Service token with §8 `listen` on `sock:smtp/25/mx` or `smtp/25/mx.<scope>`',
     "TLSA at `_25._tcp.mx` (or a scope's) for the caller's attested mail-host key", '§12.8'))
_i = [r[0] for r in ROUTES].index('`POST /mail/enable`; `GET /mail/status`')
ROUTES.insert(_i + 1, ('`POST`, `DELETE /mail/direct-mx`', 'Network, Admin role, Team only; an I-8 outward action',
                       'Name at most two always-on receivers as a direct MX, verified by mxedge first; DELETE restores the router', '§12.8, §15.4'))

# ------------------------------------------------------------------ Appendix E: tables, Redis keys, object families
TABLES = list(_P['TABLES'])
TABLES = _replace(TABLES, '`network_service_usage` (13 months), `service_debit_journal`',
    ('`network_quota_state`, `network_service_usage` (13 months), `service_debit_journal`', 'api',
     'Stored bytes, `storage_over` and spent time per network; daily usage per network and meter; debits until applied', 'MG2', '§20.14'))
TABLES = _replace(TABLES, '`network_quota_state`', None)
TABLES = _replace(TABLES, '`mail_network`, `mail_host_key`',
    ('`mail_network`, `mail_host_key`, `mail_direct_mx`', 'mxedge',
     'Mail-enabled networks; receiver host keys (`mx` or `mx.<scope>`); Team direct-MX receivers',
     'MG7 (§19.7 omits `mail_direct_mx`)', '§15.15'))
TABLES = _replace(TABLES, '`dns_root`, `dns_label`, `network_dns_zone`, `network_dns_record`, `dns_zone_journal` (7 d), `network_dns_custom_host`',
    ('`dns_root`, `dns_label`, `network_dns_zone`, `network_dns_record`, `dns_zone_journal` (7 d), `network_dns_custom_host`', 'dns',
     'Roots and serials, labels (never deleted), zones, records, journal, custom hosts', 'MG5', '§12.14'))
TABLES = _replace(TABLES, 'Redis `{scp_<clientId>}` (ver, hint, n), `{wake_<sidecarId>}`',
    ('Redis `{scp_<clientId>}` (ver, hint, n, live), `{wake_<sidecarId>}`, `{wake_<clientId>}` (tok, counters), `{wakeq_<shard>}`',
     'connect residents, api, owning services, the push sender', 'Push topic versions and hints (1 h); live markers; wake tokens, limits and the wake queue', '—', '§6.16, §18.15, §19.4'))
TABLES = _replace(TABLES, 'Redis `{dns}`',
    ('Redis `{dns}serial:<root>`', 'dns', 'Zone serial projection', '—', '§12.14'))
TABLES = _replace(TABLES, 'Objects `repo/`, `head/`, `log/`, `push/`, `idx/`, `slot/`, `subs/` (NVMe set); `seg/` (HDD set)',
    ('Objects `repo/`, `head/`, `log/`, `push/`, `idx/`, `slot/`, `subs/`, `pmap/`, `pidx/` (metadata cluster); `seg/`, `pack/` (segment cluster)', 'evs (file cluster)',
     'Repo records and the write gate, commit points, history pages, signed pushes, path index, key slots, subscription leases, path maps, pack indexes, segments, packed history; no Postgres rows (owner decision 2)', '—', '§11.8'))
TABLES = _replace(TABLES, 'Objects `proj/<network_id>/<version>[/<seq>]`, `rev/`',
    ('Objects `proj/<network_id>/<version>/_`, `proj/<network_id>/<version>/d/<seq>/_`, `rev/`, `hold/`', 'api writes; evs, gkm and gates read (metadata cluster)',
     'Config projections and deltas; signed revocation objects; preservation holds', '—', '§7.9, §11.8, §21.9'))
TABLES = _replace(TABLES, 'Objects `gkm/repo/…`, `gkm/<group>/epoch/<n>`, KeyPackages, Welcomes, `gen/`, wraps, acks, `gkm/recovery/…`',
    ('Objects `gkm/repo/...`, `gkm/<group>/epoch/<n>`, `gkm/kp/...`, `gkm/rk/...`, Welcomes, `gen/`, `group-info`, wraps, acks, `gkm/recovery/...`', 'gkm (metadata cluster)',
     'GroupForm chains, epoch objects (one accepted commit each), KeyPackages and claims, ReaderKeys under Q-ACL-9 (a), joins, generations, wraps, recovery wraps; no Postgres rows', '—', '§10.6'))

# ------------------------------------------------------------------ Appendix E: services and config
SERVICES = list(_P['SERVICES'])
SERVICES = _replace(SERVICES, 'tlsedge',
    ('tlsedge', "`server/cli/tlsedge` behind W1's `ssl_preread` split on TCP 443, plus 8443 and 8883 pending Q-TLS-8; `config/<env>/tlsedge.yml`",
     'Layer-4 SNI router running K platform clients', '§13.15'))
SERVICES = _replace(SERVICES, 'taskworker (existing)',
    ('taskworker (existing)', 'jobs; the push sender loop over `{wakeq_<shard>}`',
     'certs; gkm reconciler; domain recheck, invite and SCIM expiry, ephemeral reaper, webhooks, `rev/` deletion, audit TTL; evs GC, packing, path-epoch copies, shredding and reconciliation; usage rollups and Stripe meters; abuse worker; APNs and FCM sender',
     '§7.17, §10.14, §11.19, §18.7, §19.4, §20.14, §21.16'))
SERVICES = _replace(SERVICES, 'warp',
    ('warp', 'W1-W11', 'The SNI split, per-service zones, TCP 25 roles, certificate reload, packaging, router rules, query-free logs, TCP 53 twins, the recurd.dev redirect, `rpt.bringyour.com` records', '§19.5'))

# ------------------------------------------------------------------ Appendix F
PLAN_TRACE = list(_P['PLAN_TRACE'])


def _trace(lines_key, stmt_prefix, new):
    global PLAN_TRACE
    for k, r in enumerate(PLAN_TRACE):
        if r[0] == lines_key and r[1].startswith(stmt_prefix):
            PLAN_TRACE[k] = new
            return
    raise KeyError((lines_key, stmt_prefix))


_trace('28', '"and also run in the background in the extension as a web worker"',
       ('28', '"and also run in the background in the extension as a web worker"', '§18.8 (D-SDK-6); §18.14', 'departed in timing (Q-SDK-1, owner 26)',
        "The extension's Worker follows ur.io's page Worker (M4) and its native companion (M8); Firefox's is session-scoped"))
_trace('31', '"The initial goal for the sdk',
       ('31', '"The initial goal for the sdk is to expose the features of the new services"', '§18.14; §23.13', 'departed (§23.13)',
        "sdk exposure arrives with M8's app hosts, after M4's dark seams (Q-PHASE-1)"))
_trace('74', '"which clients, groups, and networks can reach',
       ('74', '"which clients, groups, and networks can reach another client, group, network, or abstract socket"', '§8.4-§8.6 (D-ACL-1, D-ACL-2); §8.16, §9.14',
        'departed in part (Q-BRIDGE-6, owner 86)', 'Other networks reach a listener by IP through a §17 share; application sockets are dialed only within their network (§9.4)'))
_trace('104', '"SMTP server runs locally and terminates',
       ('104', '"SMTP server runs locally and terminates a public mail.<me>.ur.network"', '§15.4, §15.5 (D-MAIL-1 to D-MAIL-4); §12.13, §15.14',
        'departed (Q-MAIL-3, owner 32)', 'The mail host is `mx.<net>.<root>`; the receiver is still the local server, reached through mxedge'))
_trace('147', '"ACLs as MLS Groups',
       ('147', '"ACLs as MLS Groups ... Read/write participants are leaves"', '§10.4 (D-KEYS-2, D-KEYS-11); §8.12; §7.16, §8.16, §10.13',
        'kept (owner 60); Q-ACL-9 open', 'Every reading sidecar is a leaf; Q-ACL-9 (a), pending, would give tagged, ephemeral and cloud readers wraps'))
_trace('148', '"Files are encrypted with random FEKs',
       ('148', '"Files are encrypted with random FEKs wrapped by the current epoch key"', '§10.5; §11.6; §10.13', 'refined (Q-KEYS-4)',
        'Per-object keys are wrapped under RK_g, which the epoch KEK wraps'))
_trace('221', '"the storage server/sequencer acts strictly',
       ('221', '"the storage server/sequencer acts strictly as an oblivious blob store and ordering authority ... no group secrets, epoch keys, or plaintext FEKs"', '§2.9 I-1; §10.6; §10.13',
        'narrowed by the owner directive (Q-KEYS-12)', "gkm holds ciphertext plus 10.6's header values; member commits are PrivateMessage (D-KEYS-3)"))
_trace('80', '"Run ur.network as its own dns zone"',
       ('80', '"Run ur.network as its own dns zone"', '§12.4 (D-DNS-1); §12.6 (D-DNS-3); §12.13', 'kept (Q-DNS-1, owner 13)',
        'A user-content-only root on a self-hosted dns edge that replaces Route 53 for ur.network (owner decisions 69, 71)'))
_trace('353', '"[all of these count towards transfer balance]"',
       ('353', '"[all of these count towards transfer balance]"', '§20.6 (D-QUOTA-4); §17.15, §20.13', 'refined (Q-QUOTA-2, owner 10)',
        'Traffic bytes count, relayed same-network and bridge bytes included; capacities are quotas; direct P2P bytes after C3 do not count'))
_trace('346-350', '"Community / Pro / Team',
       ('346-350', '"Community / Pro / Team [$100/month+usage based overage]"', '§20.4, §20.5 (D-QUOTA-1); §20.9; §20.13', 'departed (Q-QUOTA-1, owner 27)',
        'Team is $100 for 5 billable seats, then $20 a seat; overage only on transfer and storage; sends, entries and endpoints are hard caps'))
_trace('61', '"The file blobs are stored in minio in a new file cluster."',
       ('61', '"The file blobs are stored in minio in a new file cluster."', '§19.6 (D-OPS-4, D-OPS-14); §11.13; §19.15', 'kept (Q-OPS-1, owner 18)',
        "Two MinIO clusters at one site, 4 hosts of 16 × 16 TB HDD plus NVMe (owner decisions 20, 21, 94), no off-site copy; Q-OPS-1's residual open"))

# ------------------------------------------------------------------ Appendix H
RESEARCH = list(_P['RESEARCH'])
