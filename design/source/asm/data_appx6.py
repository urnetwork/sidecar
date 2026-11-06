# Appendix D, E, F and H data for DESIGN.md, sixth assembly (2026-11-04). Starts from data_appx4.py (loaded with
# runpy) and applies what the sections edited since the fourth assembly change, with FRONT.md's FRONT-31 to
# FRONT-34: §6.11's HeadCheckProof messages and the withdrawn EvsHeadCheck numbers; typed `Signed`; the
# authorization log (§7.9) replacing projection deltas; GenRotate, DelegationWrap and the gen/ claim (§10.5,
# §10.14); evs's batches, receipts, leases, placement and ERASE pushes (§11.6, §11.8, §11.12, §11.19); the
# Redis soft state of owner decision 136; §19.6's PM9A3 metadata clusters (owner decisions 136-140, 145); and the
# routes, tables and keys §5-§21's Interfaces subsections add. Each row follows its section's edited Interfaces
# subsection, which governs. FRONT-34's `up/` family is omitted: D-EVS-34 removed upload markers, and no section
# defines it.
import runpy, pathlib

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_appx4.py'))


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


def _insert_after(rows, key, new):
    i = [r[0] for r in rows].index(key)
    return rows[:i + 1] + [new] + rows[i + 1:]


# ------------------------------------------------------------------ Appendix D: numbered messages
MESSAGES = list(_P['MESSAGES'])
MESSAGES = _replace(MESSAGES, '`Error`',
    ('`Error`', '0x0006', 'peer ↔ peer',
     'RPC error code (UNIMPLEMENTED, UNAUTHENTICATED, TOO_LARGE, VERSION, RESOURCE_EXHAUSTED, ...) with a retry hint; every code but ErrorCode starts at UNSPECIFIED 0, a protocol error (D-PROTO-20)', '§6.5'))
MESSAGES = _replace(MESSAGES, '`HeadCheck`, `HeadCheckResult`',
    ('`HeadCheck`, `HeadCheckResult`', '0x0007, 0x0008', 'peer ↔ peer',
     "Compare auth pins, generations, ref heads and vetoes with any other admitted sidecar, agents included, over a `control` contract, and shared MLS epochs with member devices, exposing withholding, rollback and forks; sets `witnessed_at` (owner decision 129)", '§6.4'))
MESSAGES = _insert_after(MESSAGES, '`HeadCheck`, `HeadCheckResult`',
    ('`HeadCheckProofRequest`, `HeadCheckProof`', '0x0009, 0x000A', 'peer ↔ peer (RPC)',
     "The authorization-log entries after the requester's position (at most 64 KiB), asked for when api does not serve them; a valid chain from the requester's pin is proof of withholding", '§6.4'))
MESSAGES = _replace(MESSAGES, '`PushReset`',
    ('`PushReset`', '0x0101', 'ControlId → client',
     'All topic versions when a resident starts (at most 48 per message); a partial reset advances no applied version (D-PROTO-20)', '§6.8'))
MESSAGES = _replace(MESSAGES, '`StreamOpen`, `StreamAccept`, `StreamReject`',
    ('`StreamOpen`, `StreamAccept`, `StreamReject`', '0x0201-0x0203', 'peer ↔ peer',
     'Open a credit-controlled stream (metadata, ticket, early data); accept; reject with `StreamRejectCode` retry, busy, denied, invalid or quota (1-5; 0 unspecified)', '§6.7, §9.6'))
MESSAGES = _replace(MESSAGES, '`MembershipChanged`, `ApprovalRequested`, `AuthorityHeadChanged`',
    ('`MembershipChanged`, `ApprovalRequested`, `AuthorityHeadChanged`', '0x1201-0x1203', 'ControlId → client (topic `team`)',
     'Membership changes, approval requests, and a new config head or authorization-log entry', '§7.17'))
MESSAGES = _replace(MESSAGES, '`GkmHint`',
    ('`GkmHint`', '0x1301', 'ControlId → client (topics `gkm:<group_id>`, `gkm`)',
     "A commit on `gkm:<group_id>`, versioned epoch × 2^24 + generation; pending change, Welcome, KeyPackages low or wrap pending (a GenWrap, wrap or sealed GroupInfo is missing) on the per-client `gkm` topic", '§10.14'))
MESSAGES = _replace(MESSAGES, '`EvsHeadCheck`, `EvsHeadCheckResult`',
    ('`EvsHeadCheck`, `EvsHeadCheckResult`', '0x1402, 0x1403', '—',
     'Withdrawn; 0x1402-0x1403 stay reserved, never reused (ref pins ride HeadCheck)', '§6.11'))
MESSAGES = _replace(MESSAGES, '`SmtpPreamble`, `SmtpPreambleResult`, `SmtpOutcome`',
    ('`SmtpPreamble`, `SmtpPreambleResult`, `SmtpOutcome`', '0x1601-0x1603', 'sidecar ↔ smtpedge (stream)',
     "Preamble frames ahead of the raw TLS; the edge's answer (UNSPECIFIED 0 to TRY_LATER 7); the send outcome", '§14.5'))
MESSAGES = _replace(MESSAGES, '`SmtpProof`, `SmtpProofResult`',
    ('`SmtpProof`, `SmtpProofResult`', '0x1605, 0x1606', 'sidecar ↔ smtpedge (RPC), M9',
     "The ZK preamble proofs π1-π3 and, in DATA mode, one per later body part, which also prove the MX's replies; outbound mail waits for them (owner decisions 35, 125)", '§14.5'))
MESSAGES = _replace(MESSAGES, '`CoreHint`',
    ('`CoreHint`', '0x1A01', 'ControlId → client (topic `core`)',
     'A revocation hint, verified against the config, and forced resync; also the content-free wake topic', '§5.15'))

# ------------------------------------------------------------------ Appendix D: carried messages
CARRIED = list(_P['CARRIED'])
CARRIED = _replace(CARRIED, '`Signed`',
    ('`Signed`, `WebAuthnEvidence`', 'every statement others act on (`protocol/bridge/signed.proto`)',
     'Signature envelope by the §5 identity key (or a presence key, with its WebAuthn evidence) over "urnetwork-sidecar-v1/" + purpose + 0x00 + `type` + body: `Signed.type` (field 6) is in the signed bytes, and §6.11\'s `SignedType` registers each (purpose, type), which `VerifySigned` checks', '§6.9, §6.11'))
CARRIED = _insert_after(CARRIED, '`Signed`, `WebAuthnEvidence`',
    ('`GroupHead`, `GenHead`, `RefHead`', 'inside `HeadCheck`', "A shared group's epoch, a repo's generation {g, C_g} and a ref's version and chain, compared at most 16 of each a message", '§6.5, §11.8'))
CARRIED = _insert_after(CARRIED, '`GroupHead`, `GenHead`, `RefHead`',
    ('`PollResponse`', '`GET /sidecar/sync/poll` (200)', 'A cursor plus hints or a reset, never an empty 204', '§6.8'))
CARRIED = _replace(CARRIED, '`SignedSocketTicket`',
    ('`SignedSocketTicket`', '`StreamOpen.ticket`', 'Single-use 30 s Ed25519 grant naming dialer, listener, name or token path, the authorization-log position that allowed it, grant and its expiry', '§9.6'))
CARRIED = _replace(CARRIED, '`DropKeyStatement`',
    ('`GenRotate`, `LeafWrap`', '`gkm/<group_id>/gen/<g>`, created If-None-Match by the rotator; `GET /gkm/groups/<id>/gen`, `/drop-key`',
     "The signed statement creating generation g, the only place a generation exists: its commitment, cause, auth pin, key-holder digest, GenLink, an optional wrap for every leaf, and the drop key for deposit kinds", '§10.5'))
CARRIED = _replace(CARRIED, '`ReaderKey`, `ReaderWrap`',
    ('`ReaderKey`, `ReaderWrap`, `DelegationWrap`', 'gkm over HTTPS (`/gkm/reader-key`; `gkm/<group_id>/wrap/<g>/<c8>/<recipient>`)',
     "An agent's signed X-Wing reader key; a signed wrap of RK_g to it, or to a live Delegation's reader key, so sidecars without a leaf read at once (owner decisions 114, 144)", '§10.5'))
CARRIED = _replace(CARRIED, '`EvsPush`, `EvsPushPart`',
    ('`EvsPush`, `EvsPushPart`, `EvsUploadReceipt`, `EvsSealLease`', '`PUT .../segments/<sid>?push=`; `POST /evs/v1/repos/<id>/push`, `/push/<push_id>/<k>`, `/push/<push_id>/lease`',
     "A push's signed statement (at most 1 KiB, in its log page), its payload in a batch record; a push over 1 MiB or 1,024 entry writes travels in up to 1,024 hashed parts (D-EVS-20); evs's MAC'd segment receipts, so uploads write nothing to the metadata cluster (D-EVS-34); a git-mode seal lease of at most 2 min", '§11.6, §11.8'))
CARRIED = _insert_after(CARRIED, '`EvsPush`, `EvsPushPart`, `EvsUploadReceipt`, `EvsSealLease`',
    ('`EvsReseed`; ERASE pushes', "a repo's log; the repo's `erasure` ref", "A repo admin's signed statement letting readers accept a re-seeded head below their pin; a committed push destroying every key of the slots it names, in every representation", '§11.6, §11.12'))
CARRIED = _replace(CARRIED, '`MailDeposit`',
    ('`MailDeposit`, `MailAuthEvidence`', 'evs deposit refs', "A received message under its own key, slotted to the drop key of the mailbox's newest GenRotate, with the receiver's sealed reception-time authentication evidence, bound to the message hash, time and receiver", '§15.5, §15.7'))
CARRIED = _replace(CARRIED, '`Genesis`, `AdminSet`, `MemberAdmit`, `MemberRevoke`, `SidecarAdmit`, `SidecarRevoke`, `SponsorSet`, `KeyRegister`, `KeyRevoke`, `Delegation`, `DelegationRevoke`, `ServiceSettings`',
    ('`Genesis`, `AdminSet`, `MemberAdmit`, `MemberRevoke`, `SidecarAdmit`, `SidecarRevoke`, `SponsorSet`, `KeyRegister`, `KeyRevoke`, `Delegation`, `DelegationRevoke`, `ServiceSettings`',
     'the config repo (`protocol/config.proto`; what a device verifies in `protocol/bridge/auth.proto`)',
     "The customer key authority's signed records; `SidecarAdmit` carries `capabilities.read_only` (D-TEAM-24), `SidecarRevoke` a compromise cascade from `since_ms` (D-TEAM-26), a Delegation a reader key, and ServiceSettings `team_mail`, `stale_leaf_days`, `self_admit`, `witness_bound_hours` and `scim_signer`", '§7.9'))
CARRIED = _insert_after(CARRIED, '`Genesis`, `AdminSet`, `MemberAdmit`, `MemberRevoke`, `SidecarAdmit`, `SidecarRevoke`, `SponsorSet`, `KeyRegister`, `KeyRevoke`, `Delegation`, `DelegationRevoke`, `ServiceSettings`',
    ('`AuthorityProposal`, `AuthorityCosign`, `RecoveryVeto`', 'authorization-log statements', "k-of-n and recovery-signed statements as a first signer's proposal plus each further signer's cosign, and an admin device's veto in a recovery window (owner decisions 110, 127)", '§7.9'))
CARRIED = _replace(CARRIED, '`Projection`, `ProjectionDelta`',
    ('`AuthEntry`, `AuthPin`, `ProjectionHeader`, `ProjectionRows`, `StatementHeader`, `ApiTick`', '`proj/<network_id>/<n>/_`, `projrows/<network_id>/<rows_sha256>/_`; `GET /network/config/projection?after=`, `POST /network/config/projection\\|delta`',
     "The authorization log: one hash-chained entry per position n (a signed base with its rows, a statement, or api's tick), (n, A_n) the pin; every statement begins with a StatementHeader (network, the signer's pin, nonce, expiry)", '§7.9'))
CARRIED = _replace(CARRIED, '`AclRows`, `BridgeRows`',
    ('`AclRows`, `BridgeRows`', 'inside `ProjectionRows`', 'Compiled reach rules between sidecar ids, and egress modes, for server gates', '§8.8, §17.8'))
CARRIED = _replace(CARRIED, '`GrantActivate`, `GrantRevoke`, `Suspend`, `Unsuspend`, `EvsShare`, `OwnerConfirm`, `RepoCreate`, `RepoAdmin`, `RepoGrant`, `RepoRevoke`, `AuditOptIn`, `AuditOptOut`',
    ('`GrantActivate`, `GrantRevoke`, `Suspend`, `Unsuspend`, `EvsShare`, `OwnerConfirm`, `RepoCreate`, `RepoAdmin`, `RepoGrant`, `RepoRevoke`, `RepoDelete`, `RepoRestore`, `AuditOptIn`, `AuditOptOut`', 'authorization-log statements; the audit records in heads',
     "Approved runtime grants (each with its StatementHeader; `GrantActivate` once per `grant_id`) and their revocation, the one-switch suspension, an owner's shares and confirmations of admin-admitted devices (owner decision 126), repo creation, admins, grants, deletion and restore, and the audit reader", '§8.8'))
CARRIED = _replace(CARRIED, '`BridgeState`',
    ('`BridgeState`, `Pending`, `BridgeIdentity`, `BridgeShareKey`', "the sidecar role → device role channel (`protocol/bridge/bridge.proto`)",
     "A sidecar role's compiled bridge rules, names, anchor, the identities and share keys its host admits, and its daemon listeners, for the keyless device role; `Pending` moves a device from legacy to pending", '§17.8, §18.6'))
CARRIED = _insert_after(CARRIED, '`BridgeState`, `Pending`, `BridgeIdentity`, `BridgeShareKey`',
    ('`WindowDelegation`', "C13's seal on a bridge link's contracts", "The subject's signed delegation of one window client to one target, which the host verifies against the subject's pinned identity key or a share's ShareKey before admitting IP flows", '§17.9'))
CARRIED = _replace(CARRIED, '`RecordEntry`, `ApprovalRequest`, `ApprovalDecision`, `ReachReceipt`, `Coverage`',
    ('`RecordEntry`, `ApprovalRequest`, `ApprovalDecision`, `ApprovalCancel`, `ReachReceipt`, `Coverage`', 'sealed evs records (`record.proto`); `POST /approval/cancel`',
     "recURd's record primitives; a decision binds its spender and pin, and each use is reserved before its effect (D-MCP-11, D-MCP-12)", '§16.8'))

# ------------------------------------------------------------------ Appendix E: routes
ROUTES = list(_P['ROUTES'])
ROUTES = _replace(ROUTES, '`POST /network/auth-client`',
    ('`POST /network/auth-client`', 'OwnClient (existing)', "Mint a client token, the pairing child included; a `strict_exp` bearer adds a DPoP proof (§7.4)", '§5.15'))
ROUTES = _replace(ROUTES, '`GET /auth/refresh`',
    ('`GET /auth/refresh`', 'Client (existing)', 'Refresh the client token, with DPoP for `strict_exp` bearers; one new error, `restore_required`', '§5.15'))
ROUTES = _replace(ROUTES, '`POST /sidecar/bind`',
    ('`POST /sidecar/bind`', 'Client', 'Append a sidecar identity binding; also re-registration after a restore', '§5.15'))
ROUTES = _replace(ROUTES, '`GET /sidecar/sync/poll?cursor=`',
    ('`GET /sidecar/sync/poll?cursor=`', 'Client', 'Long-poll fallback for push, ≤25 s; 200 `PollResponse`', '§6.16'))
ROUTES = _insert_after(ROUTES, '`POST /sidecar/wake`',
    ('`POST /sidecar/close`', "Public: a 128-bit close capability minted with the ephemeral client, in a text/plain body", "An ephemeral page's best-effort unload beacon, reaping that client at once (D-SDK-17)", '§6.16, §18.8'))
ROUTES = _replace(ROUTES, '`GET /network/config/projection?after=`; `POST /network/config/projection`, `/delta`',
    ('`GET /network/config/projection?after=`; `POST /network/config/projection`, `/delta`', 'Client',
     'Read authorization-log entries; publish a base or a statement, which api sequences into the log', '§7.17'))
ROUTES = _insert_after(ROUTES, '`GET /network/config/projection?after=`; `POST /network/config/projection`, `/delta`',
    ('`POST /network/config/reseed`', 'Client (member devices; reseed mode only)', "Resume the authorization log from member devices' verbatim entries after a site loss", '§7.9, §7.17'))
ROUTES = _replace(ROUTES, '`POST /acl/ack`',
    ('`POST /acl/ack`', 'Client', 'Acknowledge an authorization-log position (propagation)', '§8.17'))
ROUTES = _replace(ROUTES, '`POST /socket/registrations`',
    ('`POST /socket/registrations`', 'Client (sidecar-classified, on the `strict_exp` allowlist)', 'Replace the full registration set, in pages of at most 1,024 entries behind a per-client bucket; returns statuses, server time, keys', '§9.15'))
ROUTES = _replace(ROUTES, '`POST /gkm/groups/<id>/welcome/<n>`, `/wraps`, `/group-info`, `/ack`',
    ('`POST /gkm/groups/<id>/gen/<g>`', 'Client (gkm token)', 'Claim generation g with its GenRotate: 201, or 412 with the winner', '§10.14'))
ROUTES = _insert_after(ROUTES, '`POST /gkm/groups/<id>/gen/<g>`',
    ('`POST /gkm/groups/<id>/wraps/<g>/<c8>`; `/welcome/<n>`, `/group-info`, `/ack`', 'Client (gkm token)', 'Staged or late ReaderWraps and DelegationWraps; Welcomes, sealed GroupInfo, acks (Redis soft state)', '§10.14'))
ROUTES = _replace(ROUTES, '`GET /gkm/groups/<id>/gen?since=`, `/wraps/<g>`, `/drop-key`, `/group-info?want=<epoch>`; `GET /gkm/welcomes`',
    ('`GET /gkm/groups/<id>/gen?since=`, `/wraps/<g>`, `/drop-key?since=<g>`, `/group-info?want=<epoch>`; `GET /gkm/welcomes`', 'Client (gkm token; drop-key also `deposit`)',
     'Generations, wraps, the newest GenRotate for depositors (up to 64 after since), sealed GroupInfo on demand (an older one also hints wrap-pending, KF5), pending Welcomes', '§10.14'))
ROUTES = _replace(ROUTES, '`GET\\|POST\\|DELETE /gkm/recovery/<member_id>/wraps`',
    ('`GET\\|POST\\|DELETE /gkm/recovery/<member_id>/wraps`', "Client (gkm token); GET also under an unadmitted client's `recovery:<member_id>` scope, for that member's own wraps", 'Recovery wraps; the bindings are config-repo records (§7.9)', '§10.14'))
ROUTES = _replace(ROUTES, '`PUT\\|GET\\|DELETE /evs/v1/repos/<id>[?now=1]`; `POST /evs/v1/repos/<id>/restore`, `/reseed`',
    ('`PUT\\|GET\\|DELETE /evs/v1/repos/<id>[?now=1]`; `POST /evs/v1/repos/<id>/restore`, `/reseed`', 'Client (evs token; restore and reseed admin)',
     'Create, read, soft-delete (or shred at once) a repo, each only after its projected RepoDelete or RepoRestore; restore within 7 days (409 SHREDDING past it); re-seed after site loss', '§11.12, §11.19'))
ROUTES = _replace(ROUTES, '`PUT /evs/v1/repos/<id>/segments/<sid>`; `POST /evs/v1/repos/<id>/push`, `/push/<push_id>/<k>`, `/path-epoch`',
    ('`PUT /evs/v1/repos/<id>/segments/<sid>?push=<push_id>`; `POST /evs/v1/repos/<id>/push`, `/push/<push_id>/<k>`, `/push/<push_id>/lease`, `/path-epoch`', 'Client (evs token, `rw`; deposits to the caller\'s deposit ref)',
     "Upload a segment for an `EvsUploadReceipt`; commit a push with its statement, payload and receipts, in parts when over 1 MiB (D-EVS-20); a git-mode seal lease; rotate the path key; refusals carry the push id", '§11.19'))
ROUTES = _insert_after(ROUTES, '`POST /dns/acme-challenge`; `GET /dns/ready?serial=`',
    ('`POST /network/dns/label-reclaim`', 'Network, DNS permission', "After a Postgres restore only: re-bind an ownerless `retiring` name to the caller's network", '§12.8, §19.10'))
ROUTES = _insert_after(ROUTES, '`GET /abuse/status`',
    ('`POST /approval/cancel`', 'Client (sidecar-classified)', 'Cancel a server-gated decision with a signed `ApprovalCancel` (D-MCP-11)', '§16.14'))
# keep §16's route beside the other §16-§18 rows: move it after the bridge share route
_r = [r for r in ROUTES if r[0] == '`POST /approval/cancel`'][0]
ROUTES = [r for r in ROUTES if r[0] != '`POST /approval/cancel`']
ROUTES = _insert_after(ROUTES, '`POST`, `DELETE /mail/direct-mx`', _r)
ROUTES = _replace(ROUTES, '`GET\\|PUT /network/bridge/share/<share_id>`',
    ('`GET\\|PUT /network/bridge/share/<share_id>`', 'Client (a sidecar of either network)', "Read both sealed share tables and the accept status, or replace one's own at a higher version", '§17.16'))
ROUTES = _replace(ROUTES, '`GET /abuse/status`',
    ('`GET /abuse/status`', 'Client (sidecar-classified, on the `strict_exp` allowlist)', "The caller's own abuse state", '§21.16'))

# ------------------------------------------------------------------ Appendix E: tables, Redis keys, object families
TABLES = list(_P['TABLES'])
TABLES = _replace(TABLES, '`network_auth_key`, `network_admin_event`',
    ('`network_auth_key`, `network_admin_event`, `admin_token_use`', 'api', "Auth keys; the hash-chained admin log (400 d); `ur-cli`'s admin-token uses", 'MG1', '§7.17'))
TABLES = _replace(TABLES, '`network_acl_head`, `network_acl_ack` (7 d); `network_client.acl_subject_client_id`',
    ('`network_acl_head`, `network_acl_ack` (7 d); `network_client.acl_subject_client_id`', 'api',
     'Newest verified authorization-log position n and A_n with `has_document`, deleted with the network; propagation acks; policy subject per client', 'MG2', '§8.17'))
TABLES = _replace(TABLES, '`network_bridge_share`',
    ('`network_bridge_share`', 'api', "Both networks' sealed target and alias tables per share, with the accept status", 'MG6', '§17.16'))
TABLES = _replace(TABLES, '`dns_root`, `dns_label`, `network_dns_zone`, `network_dns_record`, `dns_zone_journal` (7 d), `network_dns_custom_host`',
    ('`dns_root`, `dns_label`, `network_dns_zone`, `network_dns_record`, `dns_zone_journal` (7 d), `network_dns_custom_host`', 'dns',
     "Roots and serials, labels (never deleted), zones, records, journal, custom hosts with each one's CAA mode", 'MG5', '§12.14'))
TABLES = _replace(TABLES, '`smtp_send` (daily partitions), `smtp_complaint`, `smtp_halt`, `smtp_dkim_key`, `smtp_dmarc_daily`',
    ('`smtp_send` (daily partitions), `smtp_complaint`, `smtp_halt`, `smtp_dkim_key`, `smtp_dmarc_daily`', 'smtpedge',
     'Send records (30 d), complaints, halts, DKIM keys, DMARC aggregates counted once per report', 'MG9', '§14.14'))
TABLES = _replace(TABLES, '`mail_network`, `mail_host_key`, `mail_direct_mx`',
    ('`mail_network`, `mail_host_key`, `mail_direct_mx`, `mail_connection_record` (hourly partitions, 24 h)', 'mxedge',
     'Mail-enabled networks; receiver host keys (`mx` or `mx.<scope>`); Team direct-MX receivers; router sessions without sender or burner label', 'MG7', '§15.15'))
TABLES = _insert_after(TABLES, '`sidecar_push_token`',
    ('`network_client_lease`', 'api', "An ephemeral client's poll lease and close-capability hash, read by the reaper, deleted with its client", 'MG1 (§18.15)', '§18.15'))
TABLES = _replace(TABLES, '`network_quota_state`, `network_service_usage` (13 months), `service_debit_journal`',
    ('`network_quota_state`, `network_service_usage` (13 months), `service_debit_journal`, `service_usage_batch` (24 h)', 'api',
     'Stored bytes, `storage_over` and spent time per network; daily usage per network and meter; debits until applied; usage batches by id', 'MG2', '§20.14'))
TABLES = _replace(TABLES, '`transfer_balance.tier`; `stripe_meter_report` (13 months)',
    ('`transfer_balance.tier` and its `team_credit` index; `stripe_meter_report` (13 months)', 'api',
     "Tier, and the draw-order index (built concurrently); Stripe meter reports with version, attempts and next send", 'MG6', '§20.14'))
TABLES = _replace(TABLES, '`abuse_case`, `abuse_action`, `abuse_appeal`, `network_abuse_state`, `abuse_legal_hold`, `abuse_access_log`, `legal_request`',
    ('`abuse_case`, `abuse_action`, `abuse_appeal`, `network_abuse_state`, `abuse_legal_hold`, `abuse_access_log`, `legal_request`', 'api',
     'Abuse cases and legal process; each hold with its statutory kind and deadline', 'MG5', '§21.16'))
TABLES = _insert_after(TABLES, '`abuse_case`, `abuse_action`, `abuse_appeal`, `network_abuse_state`, `abuse_legal_hold`, `abuse_access_log`, `legal_request`',
    ('`approval_use`', 'api', "One reserved use of a server-gated decision, in the gated effect's transaction (1 d after not_after)", 'MG5', '§16.14'))
TABLES = _insert_after(TABLES, '`approval_use`',
    ('The sidecar dump', 'xops (planetoid pulls its `pg-sidecar` stream)', "A daily off-site dump of the tables 19.7's groups create, the newest 14 generations, which the main dumps exclude (D-OPS-18)", '—', '§19.6'))
TABLES = _replace(TABLES, 'Redis `{scp_<clientId>}` (ver, hint, n, live), `{wake_<sidecarId>}`, `{wake_<clientId>}` (tok, counters), `{wakeq_<shard>}`',
    ('Redis `{scp_<clientId>}` (ver, hint, n, live, tok, ack, hb), `{scp_0}tokgen`, `{wake_<sidecarId>}`, `{wake_<clientId>}` (counters), `{wakeq_<shard>}`', 'connect residents, api, owning services, taskworker, the push sender',
     "Push topic versions and hints (1 h); live markers, the token projection and acks; the poll lease (300 s); the re-projection sentinel; wake limits, rate counters (1 h) and the wake queue", '—', '§6.16, §18.15, §19.4'))
TABLES = _replace(TABLES, 'Redis `{acl_<networkId>}v`',
    ('Redis `{acl_<networkId>}v`, `{acl_<networkId>}e`', 'api (the only writer of `e`)', "Signals a new log entry to gate caches (48 h after its last change); the verified projection cache that gates read through (owner decision 136)", '—', '§7.9, §8.17'))
TABLES = _insert_after(TABLES, 'Redis `{acl_<networkId>}v`, `{acl_<networkId>}e`',
    ('Redis `{dpop_<client_id>}`', 'api', 'DPoP jtis for `strict_exp` bearers, 120 s', '—', '§7.17'))
TABLES = _replace(TABLES, 'Redis `{tes_<network_id>}`, `{tes_<network_id>}n`',
    ('Redis `{tes_<network_id>}`, `{tes_<network_id>}n`, `{tcb_<ca>_<registered_domain>}`', 'tlsedge; certs', "Kill switch and its trigger; certs' 7-day new-set order budget per CA and registered domain, rebuilt from `network_tls_cert`", '—', '§13.15'))
TABLES = _insert_after(TABLES, 'Redis `{sq_<network_id>}`',
    ('Redis `{gka_<group_id>}`', 'gkm', "Acks: each leaf's newest applied epoch, at most daily; soft state, after whose loss gkm deletes no epoch for 30 d (owner decision 136)", '—', '§10.14'))
TABLES = _insert_after(TABLES, 'Redis `{gka_<group_id>}`',
    ('Redis `{evsq_<repo_id>}`, `{evsl_<repo_id>}`, `{evsh_<repo_id>}`, `{nvb_<set>}`', 'evs; taskworker publishes `{nvb_}`',
     "The push sequence; subscription leases per path epoch; the verified head cache (10 min); each metadata set's write-budget allowance (15 s), all soft state (owner decision 136)", '—', '§11.19, §19.6'))
TABLES = _replace(TABLES, 'Objects `repo/`, `head/`, `log/`, `push/`, `idx/`, `slot/`, `subs/`, `pmap/`, `pidx/` (metadata cluster); `seg/`, `pack/` (segment cluster)',
    ('Objects `place/`, `repo/`, `head/`, `log/`, `pb/`, `idx/`, `slot/`, `hp/`, `pmap/`, `pidx/`, `spidx/` (reserved) on each repo\'s metadata cluster; `seg/`, `pack/` (segment cluster)', 'evs (file cluster)',
     'Placement (first cluster only), repo records and lifecycle, commit points, history pages, push batches, the folded path index, key slots, small repos\' parcels, path maps, pack indexes, segments, packed history; no Postgres rows (owner decisions 2, 145)', '—', '§11.8'))
TABLES = _replace(TABLES, 'Objects `proj/<network_id>/<version>/_`, `proj/<network_id>/<version>/d/<seq>/_`, `rev/`, `hold/`',
    ('Objects `proj/<network_id>/<n>/_`, `projrows/<network_id>/<rows_sha256>/_`, `rev/`, `hold/`', 'api writes; evs, gkm and gates read (first metadata cluster)', 'The authorization log and its bases\' rows; signed revocation objects; preservation holds', '—', '§7.9, §11.8, §21.9'))
TABLES = _replace(TABLES, 'Objects `gkm/repo/...`, `gkm/<group>/epoch/<n>`, `gkm/kp/...`, `gkm/rk/...`, Welcomes, `gen/`, `group-info`, wraps, acks, `gkm/recovery/...`',
    ('Objects `gkm/repo/...`, `gkm/<group_id>/epoch/<n>`, `gkm/<group_id>/gen/<g>`, `group-info`, Welcomes, `gkm/<group_id>/wrap/<g>/<c8>/<recipient>`, `gkm/recovery/...`, `gkm/kp/...`, `gkm/rk/...`', "gkm (the repo's metadata cluster; per-sidecar objects on the first)",
     'GroupForm chains, epoch objects (one accepted commit each), generations (GenRotate, kept for the repo\'s life), joins, staged wraps, recovery wraps, KeyPackages and claims, agents\' ReaderKeys; no Postgres rows', '—', '§10.6'))

# ------------------------------------------------------------------ Appendix E: services and config
SERVICES = list(_P['SERVICES'])
SERVICES = _replace(SERVICES, 'api (existing)',
    ('api (existing)', '`api.bringyour.com`: `/network/*`, `/sidecar/*`, `/acl/*`, `/approval/*`, `/tls/*`, `/smtp/*`, `/mail/*`, `/abuse/*`',
     "New routes; the authorization-log sequencer and verifier, the only writer of `{acl_}e`, gate caches; certs' routes; only the OAuth issuer mounts signing keys", '§7.17, §19.4'))
SERVICES = _replace(SERVICES, 'evs',
    ('evs', '`server/cli/evs`, `evs.bringyour.com` (W2; segments on `streamable_paths`); engine `sidecar/evsservice`; `<tier>.sidecar:` with `store_weight` in pro.yml; receipt keys',
     "Stateless storage over the segment bucket and one bucket per metadata cluster, placing each repo at creation (owner decision 145) and spending §11.13's write budget by per-network fair share (D-EVS-33)", '§11.19, §19.4'))
SERVICES = _replace(SERVICES, 'gkm',
    ('gkm', '`server/cli/gkm` from v0, `gkm.bringyour.com`; engine `gkmservice`; reconciler in taskworker',
     "MLS delivery service and wrapped key store over each repo's metadata cluster, acks in Redis", '§10.14, D-OPS-2'))
SERVICES = _replace(SERVICES, 'tlsedge',
    ('tlsedge', '`server/cli/tlsedge` behind W1\'s `ssl_preread` split on TCP 443, with the generated custom-host map, and unsplit on 8443, 8883 and 5671 (owner decision 121; W7); `config/<env>/tlsedge.yml`',
     'Layer-4 SNI router running K platform clients', '§13.15'))
SERVICES = _replace(SERVICES, 'taskworker (existing)',
    ('taskworker (existing)', 'jobs; the push sender loop over `{wakeq_<shard>}`; the write-budget governor per metadata cluster',
     "certs; gkm reconciler; domain recheck, invite and SCIM expiry, ephemeral reaper, webhooks, `rev/` deletion, audit TTL; evs GC, evacuation, packing, path-epoch copies, shredding and reconciliation; the `{nvb_<set>}` allowance; usage rollups and Stripe meters; abuse worker; APNs and FCM sender", '§7.17, §10.14, §11.19, §18.7, §19.4, §19.6, §20.14, §21.16'))
SERVICES = _replace(SERVICES, 'pager',
    ('pager', "§19.8's out-of-hours rota on one pager service: two people, 30-minute acknowledgment", "Page-class infrastructure alerts from M3 (owner decision 143), plus registrar, registry and law-enforcement emergency notices from M5 (owner decision 134); 24/7 on-call from v1", '§19.8, §21.8'))
SERVICES = _replace(SERVICES, 'config',
    ('config', '`config/<env>/sidecar.yml` (gates, `place_new`, `preview_networks`, `reseed`), `config/all/pro.yml`, `config/<env>/stripe.yml`, `config/<env>/dns.yml`, `config/<env>/abuse.yml`, `db.yml` and `redis.yml` caps',
     'Dark gates, the placement target and `urnetwork-edge`; tiers, limits, prices and `sidecar_abuse:`; Team price ids; zones; abuse feeds and reviewer and pager routing', '§19.11, §20.14, §21.16'))
SERVICES = _replace(SERVICES, 'xops',
    ('xops', "`file-clusters` with §19.6's XFS and MinIO settings, the storage hosts' diskstats exporter, the sidecar dump and planetoid's `pg-sidecar` stream",
     'File cluster hosts and drive counters; the daily off-site sidecar table dump, kept 14 generations (D-OPS-18)', '§19.6, §19.16'))
SERVICES = _replace(SERVICES, 'sdk',
    ('sdk', '`sdk/sidecar.go`; `EnableBridge`; `CheckOrigin` on connect\'s H1 upgrader; the key origin `https://sidecar.ur.io` in `cors_origins`; extension `offscreen` and `nativeMessaging`',
     'The app and extension seams; the device role in `sidecar/device`; the page Worker\'s `sidecar_http` leg; native-host manifests', '§18.15'))
_i = [r[0] for r in SERVICES].index('xops')
SERVICES.insert(_i, ('file cluster', 'MinIO from the final upstream source on 4 LAN hosts: a 1,024 TB raw HDD segment cluster at EC:8 and metadata clusters of 8 × PM9A3 1.92 TB at EC:4, added whole',
                     'The system of record for evs and gkm; the metadata tier grows only by whole clusters, never pools (owner decisions 94, 116, 136-140, 145)', '§19.6, §19.9'))

# ------------------------------------------------------------------ Appendix F
PLAN_TRACE = list(_P['PLAN_TRACE'])


def _trace(lines_key, stmt_prefix, new):
    global PLAN_TRACE
    for k, r in enumerate(PLAN_TRACE):
        if r[0] == lines_key and r[1].startswith(stmt_prefix):
            PLAN_TRACE[k] = new
            return
    raise KeyError((lines_key, stmt_prefix))


_trace('9-22', 'The `sidecar/` layout block',
       ('9-22', 'The `sidecar/` layout block', '§4.4 (D-REPO-2); §4.15', 'kept',
        'Adds `<svc>service/`, `device/`, `protocol/bridge/`, sidecartest/, testdata/, mlsinterop/ and smtpproof/; `cli/` and `smtpproof/` are nested modules'))
_trace('13', '"all service code goes in the root of the module named sidecar"',
       ('13', '"all service code goes in the root of the module named sidecar"', '§4.4, §4.15; §14.13 (D-SMTP-11); §18.14 (D-SDK-20)', 'departed (Q-REPO-5, owner 104; Q-SDK-5)',
        'Server-only engines live in `sidecar/<svc>service` child packages, the X7 prover in the nested module `smtpproof`, and the device role in the leaf package `sidecar/device` (Q-SDK-5, closed by peer review)'))
_trace('14', '"the core Sidecar struct that holds an authenticated jwt',
       ('14', '"the core Sidecar struct that holds an authenticated jwt, connect client, api, and encryption key"', '§5.4 (D-CORE-1, D-CORE-10, D-CORE-14)', 'refined',
        "The jwt is the sidecar's own client token; the encryption key is its network's keychain root key R_n"))
_trace('31', '"integrate them ... into the existing sdk device',
       ('31', '"integrate them ... into the existing sdk device (e.g. ip addr, port forward) by introducing abstractions that the Sidecar struct implements"', '§17.10; §18.6 (D-SDK-3); §17.15, §18.14', 'departed (Q-SDK-2, Q-SDK-5)',
        '`device.Bridge`, in the leaf package `sidecar/device`, not the whole Sidecar, implements `deviceBridge`'))
_trace('57', '"The storage service speaks git over https."',
       ('57', '"The storage service speaks git over https."', '§11.11 (D-EVS-15, D-EVS-28); §11.7 (D-EVS-22); §11.18', 'refined (Q-EVS-2, Q-EVS-8, owner 24, 141)',
        "Met at the sidecar's local git server (http and ssh) and git-remote-ur; evs speaks an HTTPS object API, and git-mode refs commit only on their tip"))
_trace('61', '"The file blobs are stored in minio in a new file cluster."',
       ('61', '"The file blobs are stored in minio in a new file cluster."', '§19.6 (D-OPS-4, D-OPS-14, D-OPS-19); §19.9 (D-OPS-17); §11.8, §11.13; §19.15', 'kept (Q-OPS-1, Q-OPS-10, owner 18, 116, 136-140, 145)',
        'MinIO at one site: a segment cluster of 4 hosts × 16 × 16 TB HDD at EC:8 and a metadata cluster of 8 × PM9A3 1.92 TB at EC:4 under a drive-write budget, growing only by whole clusters with each repo placed at creation; a cold spare, no off-site copy'))
_trace('90', '"Each encryopted connect must present the raw header',
       ('90', '"Each encryopted connect must present the raw header ... routing path, message ID, which is verified in the stream using a zk proof"', '§14.5 (D-SMTP-3, D-SMTP-16, D-SMTP-20, D-SMTP-22); §14.13',
        'departed (Q-SMTP-1, owner 35, 99, 125)', "Unsound as written; outbound mail waits for 14.5's sound BDAT and DATA proofs (M9), which also prove the MX's replies; the routing path becomes the edge's trace"))
_trace('147', '"ACLs as MLS Groups',
       ('147', '"ACLs as MLS Groups ... Read/write participants are leaves"', '§10.4 (D-KEYS-2, D-KEYS-11); §8.12 (D-ACL-17); §7.9 (D-TEAM-18); §7.16, §8.16, §10.13', 'amended (Q-ACL-9, Q-KEYS-15, owner 60, 114, 144)',
        "Member devices are leaves, except past the config group's first 1,000; tagged, ephemeral, CI and cloud agents read and write through per-generation wraps"))
_trace('148', '"Files are encrypted with random FEKs',
       ('148', '"Files are encrypted with random FEKs wrapped by the current epoch key"', '§10.5; §11.6; §10.13', 'refined (Q-KEYS-4)',
        "Per-object keys are wrapped under RK_g, which the epoch KEK or a holder's wrap delivers"))

# ------------------------------------------------------------------ Appendix H
RESEARCH = list(_P['RESEARCH'])
