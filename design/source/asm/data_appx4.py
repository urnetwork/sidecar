# Appendix D, E, F and H data for DESIGN.md, fourth assembly (2026-11-04). Starts from data_appx3.py (loaded with
# runpy) and applies what the sections edited since the third assembly change: HeadCheck's witnesses (§6.4, owner
# decision 129), SmtpProof's two modes (§6.11, §14.5, owner decision 125), §7.9's records (RecoveryRebind,
# witness_bound_hours), §8.8's AuditOptOut, §5.15's, §12.8's, §13.15's and §15.15's routes and tables, §8.17's and
# §15.15's Redis keys, §15.15's operator list, §19.8's pager, §20.14's stripe.yml path, and the PLAN.md:80, :90 and
# :355 rows (owner decisions 122, 123, 125). Subsection numbers are unchanged since the third assembly.
import runpy, pathlib

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_appx3.py'))


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
MESSAGES = _replace(MESSAGES, '`HeadCheck`, `HeadCheckResult`',
    ('`HeadCheck`, `HeadCheckResult`', '0x0007, 0x0008', 'peer ↔ peer',
     "Compare config and projection pins with any other admitted reader sidecar, agents included, and shared MLS epochs with member devices, exposing withholding, rollback and forks; sets `witnessed_at` (owner decision 129)", '§6.4'))
MESSAGES = _replace(MESSAGES, '`SmtpProof`, `SmtpProofResult`',
    ('`SmtpProof`, `SmtpProofResult`', '0x1605, 0x1606', 'sidecar ↔ smtpedge (RPC), M9',
     'The ZK preamble proofs, BDAT and DATA, that outbound mail waits for (owner decisions 35, 125)', '§14.5'))

CARRIED = list(_P['CARRIED'])
CARRIED = _replace(CARRIED, '`RecoveryBind`, recovery wraps',
    ('`RecoveryBind`, `RecoveryRebind`, recovery wraps', 'the config repo (§7.9); `/gkm/recovery/<member_id>/wraps`',
     "A member's signed recovery-key binding and its successor, and the wraps of repo-key generations to that key", '§7.9, §10.8'))
CARRIED = _replace(CARRIED, '`Genesis`, `AdminSet`, `MemberAdmit`, `MemberRevoke`, `SidecarAdmit`, `SidecarRevoke`, `SponsorSet`, `KeyRegister`, `KeyRevoke`, `Delegation`, `DelegationRevoke`, `ServiceSettings`',
    ('`Genesis`, `AdminSet`, `MemberAdmit`, `MemberRevoke`, `SidecarAdmit`, `SidecarRevoke`, `SponsorSet`, `KeyRegister`, `KeyRevoke`, `Delegation`, `DelegationRevoke`, `ServiceSettings`',
     'the config repo (`protocol/config.proto`)',
     "The customer key authority's signed records; a Delegation carries a reader key, and ServiceSettings holds `team_mail`, `stale_leaf_days`, `self_admit` and `witness_bound_hours`", '§7.9'))
CARRIED = _replace(CARRIED, '`GrantActivate`, `GrantRevoke`, `Suspend`, `Unsuspend`, `EvsShare`, `OwnerConfirm`, `RepoCreate`, `RepoAdmin`, `RepoGrant`, `RepoRevoke`, `AuditOptIn`',
    ('`GrantActivate`, `GrantRevoke`, `Suspend`, `Unsuspend`, `EvsShare`, `OwnerConfirm`, `RepoCreate`, `RepoAdmin`, `RepoGrant`, `RepoRevoke`, `AuditOptIn`, `AuditOptOut`', 'config-repo deltas; the audit records in heads',
     "Approved runtime grants and their revocation, the one-switch suspension, an owner's shares and confirmations of admin-admitted devices (owner decision 126), repo creation, admins and grants, and the audit reader", '§8.8'))

# ------------------------------------------------------------------ Appendix E: routes
ROUTES = list(_P['ROUTES'])
ROUTES = _replace(ROUTES, '`POST /network/auth-client`',
    ('`POST /network/auth-client`', 'OwnClient (existing)', 'Mint a client token, the pairing child included', '§5.15'))
ROUTES = _replace(ROUTES, '`POST /dns/key-record`',
    ('`POST /dns/key-record`', "Service token with §8 `listen` on `sock:smtp/25/mx` or `smtp/25/mx.<scope>`; a member scope takes only its member's consented devices (owner decision 126)",
     "TLSA at `_25._tcp.mx` (or a scope's) for the caller's attested mail-host key; owners notified", '§12.8'))
ROUTES = _replace(ROUTES, '`GET /tls/certs`',
    ('`GET /tls/certs`', 'Client', 'Certificates, attestations and queued custom-domain CSRs, for the CT watch', '§13.15'))
ROUTES = _replace(ROUTES, '`POST /mail/enable`; `GET /mail/status`',
    ('`POST /mail/enable`; `GET /mail/status`', 'Client', "Turn on §12's mail records, the wildcard MX included, and the MTA-STS publish; status", '§15.15'))
ROUTES = _replace(ROUTES, '`POST`, `DELETE /mail/direct-mx`',
    ('`POST`, `DELETE /mail/direct-mx`', 'Network, Admin role, Team only; an I-8 outward action',
     'Name at most two always-on receivers as a direct MX, verified by mxedge first; DELETE restores the router', '§15.4, §15.15'))

# ------------------------------------------------------------------ Appendix E: tables, Redis keys, object families
TABLES = list(_P['TABLES'])
TABLES = _replace(TABLES, '`sidecar_identity`, `sidecar_identity_binding`',
    ('`sidecar_identity`, `sidecar_identity_binding`', 'api', 'Durable sidecar identity and append-only, never-reaped bindings, deleted with their network', 'MG1', '§5.15'))
TABLES = _replace(TABLES, '`network_acl_head`, `network_acl_ack` (7 d); `network_client.acl_subject_client_id`',
    ('`network_acl_head`, `network_acl_ack` (7 d); `network_client.acl_subject_client_id`', 'api',
     'Newest verified projection version and `has_document`, deleted with the network; propagation acks; policy subject per client', 'MG2', '§8.17'))
TABLES = _replace(TABLES, '`network_tls_cert`, `network_tls_suspension`, `tls_connection_record` (hourly partitions, 24 h), `tls_connection_day` (13 months)',
    ('`network_tls_cert`, `network_tls_suspension`, `tls_connection_record` (hourly partitions, 24 h), `tls_connection_day` (13 months)', 'certs, tlsedge',
     "Certificates for device keys, suspensions, connection records (dropped once any §21.9 hold has copied its network's rows; owner decision 133) and daily counts", 'MG5', '§13.15'))
TABLES = _replace(TABLES, 'Redis `{acl_<networkId>}v`',
    ('Redis `{acl_<networkId>}v`', 'api', 'Signals a new projection base or delta to gate caches; 48 h after its last change', '—', '§8.17'))
TABLES = _replace(TABLES, 'Redis `{mxr_<net>}`, `{mxc_<hash>}`',
    ('Redis `{mxr_<net>}`, `{mxc_<hash>}`', 'mxedge',
     'Route projection of mail-enabled labels, aliases, scopes and custom MX hosts; the fleet\'s closed-handshake memory, one key per sender /24 or /48 (1 h)', '—', '§15.15'))

# ------------------------------------------------------------------ Appendix E: services and config
SERVICES = list(_P['SERVICES'])
SERVICES = _replace(SERVICES, 'mxedge',
    ('mxedge', '`server/cli/mxedge` in two blocks, router and platform listener, on TCP 25 of different lb interfaces (W4); `config/<env>/mxedge.yml`; platform-mail key and feed credential in vault; the embedded `mail_operators.yml` (D-MAIL-13)',
     'Inbound SNI splice; terminating listener for `rpt.bringyour.com`', '§15.15'))
SERVICES = _replace(SERVICES, 'config',
    ('config', '`config/<env>/sidecar.yml`, `config/all/pro.yml`, `config/<env>/stripe.yml`, `config/<env>/dns.yml`, `config/<env>/abuse.yml`, `db.yml` and `redis.yml` caps',
     'Dark gates and `urnetwork-edge`; tiers, limits, prices and `sidecar_abuse:`; Team price ids; zones; abuse feeds and reviewer and pager routing', '§19.11, §20.14, §21.16'))
_i = [r[0] for r in SERVICES].index('monitor (existing)')
SERVICES.insert(_i + 1, ('pager', "§19.8's out-of-hours rota, from M5", 'Pages only for registrar, registry and law-enforcement emergency notices; 24/7 on-call from v1 (owner decision 134)', '§19.8, §21.8'))

# ------------------------------------------------------------------ Appendix F
PLAN_TRACE = list(_P['PLAN_TRACE'])


def _trace(lines_key, stmt_prefix, new):
    global PLAN_TRACE
    for k, r in enumerate(PLAN_TRACE):
        if r[0] == lines_key and r[1].startswith(stmt_prefix):
            PLAN_TRACE[k] = new
            return
    raise KeyError((lines_key, stmt_prefix))


_trace('80', '"Run ur.network as its own dns zone"',
       ('80', '"Run ur.network as its own dns zone"', '§12.4 (D-DNS-1); §12.6 (D-DNS-3); §12.13', 'kept (Q-DNS-1, owner 13)',
        'A user-content-only root on a self-hosted dns edge that replaces Route 53 for ur.network (owner decisions 69, 71), with two NS at the one site (owner decision 123)'))
_trace('90', '"Each encryopted connect must present the raw header',
       ('90', '"Each encryopted connect must present the raw header ... routing path, message ID, which is verified in the stream using a zk proof"', '§14.5 (D-SMTP-3, D-SMTP-16, D-SMTP-20); §14.13',
        'departed (Q-SMTP-1, owner 35, 99, 125)', "Unsound as written; outbound mail waits for 14.5's sound BDAT and DATA proofs (M9); the routing path becomes the edge's trace"))
_trace('355', '"Encrypted Storage 1GB, 20GB, 200GB"',
       ('355', '"Encrypted Storage 1GB, 20GB, 200GB"', '§20.4; §11.13 (D-EVS-16); §20.13', 'departed in unit (§20.13; owner 122)',
        "GiB, pro.yml's binary unit and owner decision 122's price unit, 7.4% above PLAN's GB"))

# ------------------------------------------------------------------ Appendix H
RESEARCH = list(_P['RESEARCH'])
