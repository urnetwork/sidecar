# Tenth assembly (2026-11-06): data_appx9.py with Appendix G reading the v8 header.
# Appendix D, E, F, G and H data for DESIGN.md, seventh assembly (2026-11-05). Starts from data_appx6.py (loaded
# with runpy) and re-derives each appendix from the sections as edited by the peer-review fix round and the
# re-verification fix round, after owner decision 140's record was corrected and Q-EVS-9 closed (§11.17).
# Sources: the Interfaces subsections (with §12.8's route table), §2.8, §4.6's connect-change table and §19.7's
# migration groups; where a row needs more, the subsection that owns the value (§6.11, §7.9, §11.12, §16.8,
# §17.8, §19.6, §19.11). Each row follows its section's current text, which governs.
#
# Unchanged since the sixth assembly, and checked against the current text: §6.11's MessageType catalog and
# SignedType registry, every proto message set (83 messages; only two comments changed), the object families of
# §11.8 and §10.6, §19.7's Redis tags, every "Departures from PLAN.md" subsection, §2.8's census (v5, 90 rows,
# 5 withdrawn) and the nine research sheets with their 54 citations.
#
# What changed:
#   D  0x18 and 0x19 name their SignedType ranges, and carried rows name the ranges §6.11's registry assigns
#      them; GroupForm is the one gkm write a repo re-seeded as deleted takes; EvsPush's random per-statement
#      slot ids; ERASE's 409 NOTHING_TO_ERASE and P1 queue; SidecarAdmit's not_after for agents only; the
#      authorization log's fold; GrantRevoke, Suspend and Unsuspend declared in protocol/bridge/auth.proto;
#      EvsPathMap's key gains its `<map>` segment (§11.8); rows the earlier assemblies lacked: §17.8's bridge
#      statements (rule ids derived from effect_key), §9.9's `ur share` header (§9.15 lists it), and
#      RecordHeader and RetentionPolicy beside the other record primitives.
#   E  routes: the ephemeral mint's close capability (auth-client, enroll, /sidecar/close), the poll's lease
#      write, §7.9's append limits on the log routes, reseed by member devices other than read_only ones and
#      two-member adoption, GroupForm and evs re-seed of a deleted repo, DELETE as admin, evs's refusal classes,
#      ERASE through slots/delete, subscriptions as Redis leases, registration pages, the MTA-STS publish's
#      stand-in grant, §12.8's stored-result rule, `mail_send`, `QuotaLimits`. Tables and keys:
#      network_acl_head's restore replay, network_client_lease in MG1 with seen_time and close_sha256,
#      approval_use as §12.8's DNS gate, the dump's schedule and exclusions, `{acl_}q`, `{acl_}e`'s 10 min ttl,
#      `{scp_}hb` as the lease-write gate, `{tcb_}` as a sorted set, `{gka_}`'s 31 d, `{nvb_}`'s allowances and
#      reports. Services: api, sockets, connect residents, monitor, config (sidecar.yml's keys), file cluster,
#      xops. Connect changes: C5 gains EgressDecision.IdleTimeout; CONNECT is read from §4.6 at load time,
#      verbatim, and INTRO['E_CONNECT'] links owner decisions 85 and 86 as well as 22.
#   F  the Departures subsections are unchanged, and no row cites Q-EVS-9 or an item whose status changed;
#      PLAN.md:55 gains owner decision 136's Redis leases (§11.10), and PLAN.md:5, :25 and :104 put their
#      placeholders in code spans.
#   G  APPX_G, computed from §2.8 at load time (and by appendix_g(text) for any other copy).
#   H  RESEARCH unchanged; RESEARCH_CITES, computed at load time, gives the sections citing each sheet.
# INTRO holds each appendix's lead paragraph, updated to these sources.
import runpy, pathlib, re, collections

_HERE = pathlib.Path(__file__).resolve().parent
_P = runpy.run_path(str(_HERE / 'data_appx6.py'))
_SECTIONS = _HERE.parent / 'sections'


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


def _insert_before(rows, key, new):
    i = [r[0] for r in rows].index(key)
    return rows[:i] + [new] + rows[i:]


def _section(num):
    hits = sorted(_SECTIONS.glob(f'{num:02d}-*.md'))
    assert len(hits) == 1, (num, hits)
    return hits[0].read_text()


# ------------------------------------------------------------------ lead paragraphs
INTRO = {
    'D': ("Messages on the sidecar subprotocol (connect subprotocol id 21842), from §6.11's `MessageType` catalog and "
          "the sections' Interfaces subsections. `Envelope.type` is service << 8 \\| message; §6 assigns numbers and "
          "owners define the messages. ControlId messages ride `PushHint` on a topic (§6.8) and are hints: clients "
          "resync over HTTPS on any gap. Services 0x11 (§8), 0x18 (§16) and 0x19 (§17) define no messages. Each "
          "statement carried in `Signed` has a `SignedType` in §6.11's registry, service << 8 \\| n, which the "
          "signature covers. The keyless device role parses only `protocol/bridge`'s `signed.proto`, `auth.proto` "
          "and `bridge.proto` (§4.4)."),
    'E': ("Compiled from the sections' Interfaces subsections and the tables they point to (§12.8's routes), with "
          "§2.8, §4.6, §19.4, §19.5, §19.6 and §19.7. Routes are documented in connect/api/bringyour.yml and classified in "
          "server/api/route_authz.go (§7); migrations continue from 926, each group pending under `sidecar_pending` "
          "until its own milestone's Gn-out registers it (§19.7). evs and gkm keep no Postgres rows: their durable "
          "state is objects in the file cluster (owner decision 2), placed per repo on one metadata cluster (owner "
          "decision 145), and Redis holds only their soft state (owner decision 136)."),
    'E_CONNECT': ("§4.6's rows for connect's `sidecar` branch, verbatim (X9). Dispositions follow owner decisions 22, "
                  "85 and 86 (C14 into M4, C18 in M6), under D-REPO-5: each change is generic, additive, off by "
                  "default and wire-compatible, tested in connect and merged to connect `main` first."),
    'F': ("Every statement in sidecar/design/PLAN.md (381 lines), traced to the sections that carry it. Status values: kept, "
          "refined, amended, superseded by the owner directive, departed (with the Q- item and owner decision that "
          "settled it), and n/a. Built from the PLAN review's table and updated to the edited sections' \"Departures "
          "from PLAN.md\" subsections, which give the arguments; \"owner N\" in the status column cites owner "
          "decision N."),
    # INTRO['H'] takes .format(research_rel=...), the research directory relative to DESIGN.md.
    'H': ("The research fact sheets of 2026-11-03 that the sections cite as `[R:key]`, copied to "
          "[{research_rel}/]({research_rel}/). Each cites code as repo/path:LINE and external sources by URL with "
          "dates."),
}

# ------------------------------------------------------------------ Appendix D: numbered messages (§6.11)
MESSAGES = list(_P['MESSAGES'])
MESSAGES = _replace(MESSAGES, '(service 0x18)',
    ('(service 0x18)', '—', '—',
     "§16 defines no messages in v0; records use §11's hints, and its statements are `SignedType` 0x1801-0x1804", '§16.14'))
MESSAGES = _replace(MESSAGES, '(service 0x19)',
    ('(service 0x19)', '—', '—',
     "§17 defines none: bridge rules ride the config repo (owner decision 5), its statements and `WindowDelegation` "
     "being `SignedType` 0x1901-0x1908; `BridgeSlice` is withdrawn", '§17.16'))

# ------------------------------------------------------------------ Appendix D: carried messages
# The carried-in cell names a SignedType range only where §6.11's registry comment names the statement itself:
# 0x10xx §9 tickets, 0x11xx §8 acl statements, 0x12xx §7 config records and log statements, 0x13xx §10's GenRotate,
# ReaderKey, ReaderWrap and DelegationWrap, 0x14xx §11's EvsPush and EvsReseed, 0x18xx §16, 0x19xx §17.
CARRIED = list(_P['CARRIED'])
CARRIED = _replace(CARRIED, '`SignedSocketTicket`',
    ('`SignedSocketTicket`', '`StreamOpen.ticket` (`SignedType` 0x10xx)',
     'Single-use 30 s Ed25519 grant naming dialer, listener, name or token path, the authorization-log position that '
     'allowed it, grant and its expiry', '§9.6'))
CARRIED = _insert_after(CARRIED, '`SignedSocketTicket`',
    ('`ur share` header', '`share/<token>` streams: fixed-width fields, not protobuf',
     "The getter's version, 256-bit secret, get id and resume offset; the sharer's status (ok, spent or changed), "
     "size and SHA-256, then the bytes; served uses never exceed the share's count (D-SOCK-16)", '§9.9'))
CARRIED = _replace(CARRIED, '`GenRotate`, `LeafWrap`',
    ('`GenRotate`, `LeafWrap`', '`gkm/<group_id>/gen/<g>`, created If-None-Match by the rotator; `GET '
                                '/gkm/groups/<id>/gen`, `/drop-key`; `SignedType` 0x13xx',
     'The signed statement creating generation g, the only place a generation exists: its commitment, cause, auth pin, '
     'key-holder digest, GenLink, an optional wrap for every leaf, and the drop key for deposit kinds', '§10.5'))
CARRIED = _replace(CARRIED, '`ReaderKey`, `ReaderWrap`, `DelegationWrap`',
    ('`ReaderKey`, `ReaderWrap`, `DelegationWrap`', 'gkm over HTTPS (`/gkm/reader-key`; '
                                                    '`gkm/<group_id>/wrap/<g>/<c8>/<recipient>/<k8>`); `SignedType` 0x13xx',
     "A reader's signed X-Wing key, valid 7 days; a KeyDelivery of RK_g to it, or to a live Delegation's reader "
     "key, naming the key it seals to, so sidecars without a leaf read at once (owner decisions 114, 144)", '§10.5'))
CARRIED = _replace(CARRIED, '`RecoveryBind`, `RecoveryRebind`, recovery wraps',
    ('`RecoveryBind`, `RecoveryRebind`, recovery wraps', 'the config repo (§7.9; `SignedType` 0x12xx); '
                                                         '`/gkm/recovery/<member_id>/wraps`',
     "A member's signed recovery-key binding and its successor, and the wraps of repo-key generations to that key",
     '§7.9, §10.8'))
CARRIED = _replace(CARRIED, '`AuthorityProposal`, `AuthorityCosign`, `RecoveryVeto`',
    ('`AuthorityProposal`, `AuthorityCosign`, `RecoveryVeto`', 'authorization-log statements (`SignedType` 0x12xx)',
     "k-of-n and recovery-signed statements as a first signer's proposal plus each further signer's cosign, and an "
     "admin device's veto in a recovery window (owner decisions 110, 127)", '§7.9'))
CARRIED = _replace(CARRIED, '`EvsPathMap`',
    ('`EvsPathMap`', '`pmap/<repo>/<ref>/<p>/<map>/<part>/_`, `<map>` its `path_map_sha256`',
     "Signed old-to-new token-path moves for a path epoch, with names re-sealed, bound to the source head it maps; "
     "the committed map stays with the ref's history", '§11.6, §11.8'))
CARRIED = _replace(CARRIED, '`GroupForm`',
    ('`GroupForm`', '`POST /gkm/repos/<id>/forms`',
     "Creates or re-forms a repo's MLS group, chaining groups; the only gkm write a repo re-seeded as deleted takes "
     "(§19.10)", '§10.6'))
CARRIED = _replace(CARRIED, '`EvsPush`, `EvsPushPart`, `EvsUploadReceipt`, `EvsSealLease`',
    ('`EvsPush`, `EvsPushPart`, `EvsUploadReceipt`, `EvsSealLease`',
     '`PUT .../segments/<sid>?push=`; `POST /evs/v1/repos/<id>/push`, `/push/<push_id>/<k>`, `/push/<push_id>/lease`; '
     '`SignedType` 0x14xx',
     "A push's signed statement (at most 1 KiB, in its log page), its payload in a batch record; a push over 1 MiB or "
     "1,024 entry writes travels in up to 1,024 hashed parts (D-EVS-20); the ids of the slots it introduces are random "
     "per statement, kept only by a retry of that statement; evs's MAC'd segment receipts, so uploads write nothing to "
     "the metadata cluster (D-EVS-34); a git-mode seal lease of at most 2 min", '§11.6, §11.8'))
CARRIED = _replace(CARRIED, '`EvsReseed`; ERASE pushes',
    ('`EvsReseed`; ERASE pushes', "a repo's log; the repo's `erasure` ref; `SignedType` 0x14xx",
     "A repo admin's signed statement letting readers accept a re-seeded head below their pin; a committed push "
     "destroying every key of the slots it names, in every representation, refused when the slots hold none of "
     "those keys (409 NOTHING_TO_ERASE) and queued as P1 past 60 a minute per network", '§11.6, §11.12'))
_GENESIS = ('`Genesis`, `AdminSet`, `MemberAdmit`, `MemberRevoke`, `SidecarAdmit`, `SidecarRevoke`, `SponsorSet`, '
            '`KeyRegister`, `KeyRevoke`, `Delegation`, `DelegationRevoke`, `ServiceSettings`')
CARRIED = _replace(CARRIED, _GENESIS,
    (_GENESIS, 'the config repo (`protocol/config.proto`, `SignedType` 0x12xx; what a device verifies in '
               '`protocol/bridge/auth.proto`)',
     "The customer key authority's signed records; `SidecarAdmit` carries `capabilities.read_only` (D-TEAM-24) and a "
     "not_after for agents only, never for a member device, `SidecarRevoke` a compromise cascade from `since_ms` "
     "(D-TEAM-26), a Delegation a reader key, and ServiceSettings `team_mail`, `stale_leaf_days`, `self_admit`, "
     "`witness_bound_hours` and `scim_signer`", '§7.9'))
_AUTHLOG = '`AuthEntry`, `AuthPin`, `ProjectionHeader`, `ProjectionRows`, `StatementHeader`, `ApiTick`'
CARRIED = _replace(CARRIED, _AUTHLOG,
    (_AUTHLOG, '`proj/<network_id>/<n>/_`, `projrows/<network_id>/<rows_sha256>/_`; `GET /network/config/projection?after=`, `POST /network/config/projection\\|delta`',
     "The authorization log: one hash-chained entry per position n (a signed base with its rows, a statement, or "
     "api's tick), (n, A_n) the pin; every statement begins with a StatementHeader (network, the signer's pin, nonce, "
     "expiry); a base folds the statements and ticks through its folded_through, which a config writer advances once "
     "the unfolded tail spans 1,024 entries or 24 h", '§7.9'))
_GRANTS = ('`GrantActivate`, `GrantRevoke`, `Suspend`, `Unsuspend`, `EvsShare`, `OwnerConfirm`, `RepoCreate`, '
           '`RepoAdmin`, `RepoGrant`, `RepoRevoke`, `RepoDelete`, `RepoRestore`, `AuditOptIn`, `AuditOptOut`')
CARRIED = _replace(CARRIED, _GRANTS,
    (_GRANTS, "authorization-log statements (`acl.proto`, `SignedType` 0x11xx; `GrantRevoke`, `Suspend` and `Unsuspend` in "
              "`protocol/bridge/auth.proto`, which the device role applies); the audit records in heads",
     "Approved runtime grants (each with its StatementHeader; `GrantActivate` once per `grant_id`) and their "
     "revocation, the one-switch suspension, an owner's shares and confirmations of admin-admitted devices (owner "
     "decision 126), repo creation, admins, grants, deletion and restore, and the audit reader", '§8.8'))
_BRIDGE = ('`BridgeBlock`, `BridgeAddress`, `BridgeRoute`, `BridgeMap`, `BridgeEgress`, `BridgeAlias`, '
           '`BridgeWithdraw`')
CARRIED = _insert_before(CARRIED, '`BridgeState`, `Pending`, `BridgeIdentity`, `BridgeShareKey`',
    (_BRIDGE, "admin-signed config heads (the block, standing rules) and authorization-log statements "
              "(`protocol/bridge/bridge.proto`; `SignedType` 0x1901-0x1907)",
     "The overlay block, addresses, approved routes and port maps, egress modes, share aliases and withdrawals, ids "
     "visible and bodies sealed; a decision's rule id is derived by SHA-256 from its use's `effect_key`, so a retry "
     "files one id and a decision activates at most its `uses` rules (§7.9)", '§17.8'))
CARRIED = _replace(CARRIED, '`WindowDelegation`',
    ('`WindowDelegation`', "C13's seal on a bridge link's contracts (`SignedType` 0x1908)",
     "The subject's signed delegation of one window client to one target, which the host verifies against the "
     "subject's pinned identity key or a share's ShareKey before admitting IP flows", '§17.9'))
_RECORDS = ('`RecordHeader`, `RecordEntry`, `RetentionPolicy`, `ApprovalRequest`, `ApprovalDecision`, '
            '`ApprovalCancel`, `ReachReceipt`, `Coverage`')
CARRIED = _replace(CARRIED, '`RecordEntry`, `ApprovalRequest`, `ApprovalDecision`, `ApprovalCancel`, `ReachReceipt`, `Coverage`',
    (_RECORDS, 'sealed evs records (`record.proto`; `SignedType` 0x1801-0x1804); `POST /approval/cancel`',
     "recURd's record primitives; a decision binds its spender and pin, and each use is reserved before its effect "
     "(D-MCP-11, D-MCP-12); an entry's key slot lies outside its signed header, so re-slotting re-signs nothing",
     '§16.8'))

# ------------------------------------------------------------------ Appendix E: routes
ROUTES = list(_P['ROUTES'])
ROUTES = _replace(ROUTES, '`POST /network/auth-client`',
    ('`POST /network/auth-client`', 'OwnClient (existing)',
     "Mint a client token, the pairing child included; a `strict_exp` bearer adds a DPoP proof (§7.4); an ephemeral "
     "mint also returns its close capability once (§7.8)", '§5.15'))
ROUTES = _replace(ROUTES, '`GET /sidecar/sync/poll?cursor=`',
    ('`GET /sidecar/sync/poll?cursor=`', 'Client',
     "Long-poll fallback for push, ≤25 s; 200 `PollResponse`; an ephemeral client's polls also refresh its lease "
     "row, writing it at most once per 300 s while Redis answers (§18.8)", '§6.16'))
ROUTES = _replace(ROUTES, '`POST /sidecar/close`',
    ('`POST /sidecar/close`', "Public: the 128-bit close capability minted with the ephemeral client (§7.7), in a "
                              "text/plain body",
     "An ephemeral page's best-effort unload beacon from the key-origin document, reaping that client at once when "
     "the capability matches its lease row's `close_sha256` (D-SDK-17)", '§6.16, §18.8'))
ROUTES = _replace(ROUTES, '`POST /network/enroll`',
    ('`POST /network/enroll`', 'Public',
     'Enroll with an auth key; an ephemeral mint also returns its close capability once (§7.8)', '§7.17'))
ROUTES = _replace(ROUTES, '`GET /network/config/projection?after=`; `POST /network/config/projection`, `/delta`',
    ('`GET /network/config/projection?after=`; `POST /network/config/projection`, `/delta`', 'Client',
     "Read authorization-log entries; publish a base or a statement, which api sequences into the log within §7.9's "
     "per-network append limits, answering 429 beyond them (revocations, `Suspend`, `BridgeWithdraw` and "
     "`RecoveryVeto` exempt)", '§7.9, §7.17'))
ROUTES = _replace(ROUTES, '`POST /network/config/reseed`',
    ('`POST /network/config/reseed`', 'Client (member devices other than read_only ones; reseed mode only)',
     "Resume the authorization log after a site loss from member devices' verbatim runs and pins: api checks links, "
     "signatures and signer rules against the restored `network_acl_head` and adopts each entry once devices of two "
     "members hold it, never re-sequencing", '§7.9, §7.17'))
ROUTES = _replace(ROUTES, '`POST /gkm/groups`; `GET /gkm/groups/<id>`; `POST /gkm/repos/<id>/forms`',
    ('`POST /gkm/groups`; `GET /gkm/groups/<id>`; `POST /gkm/repos/<id>/forms`', 'Client (gkm token)',
     'Create groups; GroupForm create and re-form, the only gkm write a repo re-seeded as deleted takes (§11.12)',
     '§10.14'))
ROUTES = _replace(ROUTES, '`POST /gkm/key-packages`, `/gkm/key-packages/claim`, `/gkm/reader-key`',
    ('`POST /gkm/key-packages`, `/gkm/key-packages/claim`, `/gkm/reader-key`; `GET /gkm/reader-key/<sidecar_id>`',
     "Client (gkm token: uploads under any of the sidecar's own, claims under rw; §10.6's scopes)",
     "Upload and claim member devices' KeyPackages; register a ReaderKey, valid 7 days, at most once per 24 h after "
     "the first, and read any sidecar's, a public record (owner decision 114)", '§10.14'))
ROUTES = _replace(ROUTES, '`POST /gkm/groups/<id>/wraps/<g>/<c8>`; `/welcome/<n>`, `/group-info`, `/ack`',
    ('`POST /gkm/groups/<id>/wraps/<g>/<c8>`; `/welcome/<n>`, `/group-info`, `/ack`', 'Client (gkm token)',
     'Staged or late ReaderWraps and DelegationWraps (201, 412 with the winner, 403, 409 for a stale kind, '
     'generation or key, 429); Welcomes, sealed GroupInfo, acks (Redis soft state)', '§10.14'))
ROUTES = _replace(ROUTES, '`GET /gkm/groups/<id>/gen?since=`, `/wraps/<g>`, `/drop-key?since=<g>`, '
                          '`/group-info?want=<epoch>`; `GET /gkm/welcomes`',
    ('`GET /gkm/groups/<id>/gen?since=`, `/wraps/<g>?recipient=&want=<k8>&since=`, `/drop-key?since=<g>`, '
     '`/group-info?want=<epoch>`; `GET /gkm/welcomes`', 'Client (gkm token; drop-key also `deposit`)',
     "Generations; the caller's deliveries of g, the object at want first and its prefix on a miss, which hints "
     "wrap-pending (§10.6's late wraps); the newest GenRotate for depositors (up to 64 after since), sealed "
     'GroupInfo on demand (an older one also hints wrap-pending, KF5), pending Welcomes', '§10.14'))
ROUTES = _replace(ROUTES, '`PUT\\|GET\\|DELETE /evs/v1/repos/<id>[?now=1]`; `POST /evs/v1/repos/<id>/restore`, `/reseed`',
    ('`PUT\\|GET\\|DELETE /evs/v1/repos/<id>[?now=1]`; `POST /evs/v1/repos/<id>/restore`, `/reseed`',
     'Client (evs token; DELETE, restore and reseed `admin`)',
     "Create, read, soft-delete (or shred at once) a repo, DELETE and restore only after their projected RepoDelete "
     "or RepoRestore (else 409 STATEMENT_MISSING); restore within 7 days (409 SHREDDING past it); re-seed after a site "
     "loss, a repo soft-deleted under 7 days coming back deleted (§19.10)", '§11.12, §11.19'))
_PUSH = ('`PUT /evs/v1/repos/<id>/segments/<sid>?push=<push_id>`; `POST /evs/v1/repos/<id>/push`, '
         '`/push/<push_id>/<k>`, `/push/<push_id>/lease`, `/path-epoch`')
ROUTES = _replace(ROUTES, _PUSH,
    (_PUSH, "Client (evs token, `rw`; deposits to the caller's deposit ref)",
     "Upload a segment for an `EvsUploadReceipt`; commit a push with its statement, payload and receipts, in parts "
     "when over 1 MiB (D-EVS-20); a git-mode seal lease; rotate the path key; every refusal carries the push id: "
     "409 and 412 refuse, 429 waits refuse nothing, 503 leaves the outcome unknown", '§11.19'))
ROUTES = _replace(ROUTES, '`POST /evs/v1/repos/<id>/slots/delete`',
    ('`POST /evs/v1/repos/<id>/slots/delete`', 'Client (evs token, `admin`)',
     "Erase key slots: an ERASE push on the repo's `erasure` ref, refused when the slots hold none of the keys it "
     "names (409 NOTHING_TO_ERASE)", '§11.12, §11.19'))
ROUTES = _replace(ROUTES, '`POST\\|GET\\|DELETE /evs/v1/subscriptions`',
    ('`POST\\|GET\\|DELETE /evs/v1/subscriptions`', 'Client (evs token, `r`)',
     'Token-prefix subscription leases, kept as Redis soft state (owner decision 136)', '§11.10, §11.19'))
ROUTES = _replace(ROUTES, '`POST /socket/registrations`',
    ('`POST /socket/registrations`', 'Client (sidecar-classified, on the `strict_exp` allowlist)',
     "Replace the full registration set, in pages of at most 1,024 entries over key ranges under one `set_version`, "
     "each taking a per-client bucket token; returns statuses, server time, keys", '§9.15'))
ROUTES = _replace(ROUTES, '`POST /mail/enable`; `GET /mail/status`',
    ('`POST /mail/enable`; `GET /mail/status`', 'Client',
     "Turn on §12's mail records, the wildcard MX included, and the MTA-STS system publish, for which each receiver's "
     "`smtp/25/mx` listen grant stands in for `tls/` grants (§9.10); status", '§15.15'))
ROUTES = _replace(ROUTES, '`POST /dns/records`',
    ('`POST /dns/records`', "Service token (aud `dns`); §8.10's gate for §8 `admin` on `dns:<host>` (I-8)",
     "The same for sidecars and §16's tools; under a decision, a retry under its `Idempotency-Key: <effect_key>` gets "
     "the stored result while its `approval_use` row lasts, else §16.6's spend check consumes a use in the write's "
     "transaction (D-MCP-11, D-MCP-12)", '§12.8'))
ROUTES = _replace(ROUTES, '`POST /smtp/dkim-keys`',
    ('`POST /smtp/dkim-keys`', 'Client with `mail_send`', "Publish DKIM selectors: the network's and replying burners'",
     '§14.14'))
ROUTES = _replace(ROUTES, '`GET /sidecar/limits`',
    ('`GET /sidecar/limits`', 'Client', '`QuotaLimits` for local pre-checks', '§20.14'))

# ------------------------------------------------------------------ Appendix E: tables, Redis keys, object families
TABLES = list(_P['TABLES'])
TABLES = _replace(TABLES, '`network_acl_head`, `network_acl_ack` (7 d); `network_client.acl_subject_client_id`',
    ('`network_acl_head`, `network_acl_ack` (7 d); `network_client.acl_subject_client_id`', 'api',
     "Newest verified authorization-log position n and A_n with `has_document`, deleted with the network and, after a "
     "Postgres restore, advanced from verified `proj/` entries before the exchange and `CreateContract` reopen (§19.10); "
     "propagation acks; policy subject per client", 'MG2', '§8.17'))
TABLES = _replace(TABLES, '`mail_network`, `mail_host_key`, `mail_direct_mx`, `mail_connection_record` (hourly partitions, 24 h)',
    ('`mail_network`, `mail_host_key`, `mail_direct_mx`, `mail_connection_record` (hourly partitions, 24 h)', 'mxedge',
     "Mail-enabled networks; receiver host keys (`mx` or `mx.<scope>`); Team direct-MX receivers; router sessions in "
     "10 s batches, without sender address or burner label, dropped once any §21.9 hold has copied its network's rows",
     'MG7', '§15.15'))
TABLES = _replace(TABLES, '`network_client_lease`',
    ('`network_client_lease`', 'api',
     "One row per ephemeral client, inserted at its mint: `seen_time`, its newest poll, written at most once per 300 s "
     "while Redis answers, and its close capability's SHA-256; read by the reaper, deleted with its client", 'MG1', '§6.16, §18.15'))
TABLES = _replace(TABLES, '`approval_use`',
    ('`approval_use`', 'api',
     "One reserved use of a server-gated decision with its stored result, in the gated write's own transaction (§12.8's "
     "DNS gate), so a retry under its `effect_key` gets that result; kept 1 d after not_after", 'MG5', '§12.8, §16.14'))
TABLES = _replace(TABLES, 'The sidecar dump',
    ('The sidecar dump', 'xops (planetoid pulls its `pg-sidecar` stream)',
     "A daily dump, 02:30-02:50 UTC, of the tables §19.7's groups create but those whose §2.8 ttl is at most 7 d, "
     "which no dump holds; planetoid pulls it first, at 04:00 UTC; the newest 14 generations at each place; the main "
     "dumps exclude the groups' tables (D-OPS-18)", '—', '§19.6'))
_SCP = ('Redis `{scp_<clientId>}` (ver, hint, n, live, tok, ack, hb), `{scp_0}tokgen`, `{wake_<sidecarId>}`, '
        '`{wake_<clientId>}` (counters), `{wakeq_<shard>}`')
TABLES = _replace(TABLES, _SCP,
    (_SCP, 'owning services (evs included), connect residents, api, taskworker, the push sender',
     "Push topic versions and hints (1 h); live markers, the token projection and acks; poll markers, which gate the "
     "lease row's `seen_time` write (300 s); the re-projection sentinel; wake limits, rate counters (1 h) and the wake "
     "queue", '—', '§6.16, §18.15, §19.4'))
TABLES = _replace(TABLES, 'Redis `{acl_<networkId>}v`, `{acl_<networkId>}e`',
    ('Redis `{acl_<networkId>}v`, `{acl_<networkId>}e`, `{acl_<networkId>}q`', 'api (the only writer of `e` and `q`)',
     "Signals a new log entry to gate caches (48 h after its last change); the verified projection cache that gates "
     "read through (10 min after the network's last append; owner decision 136); §7.9's append-limit counts (25 h)",
     '—', '§7.9, §8.17'))
_TES = 'Redis `{tes_<network_id>}`, `{tes_<network_id>}n`, `{tcb_<ca>_<registered_domain>}`'
TABLES = _replace(TABLES, _TES,
    (_TES, 'tlsedge; certs',
     "Kill switch and its trigger; certs' new-set order budget per CA and registered domain, a sorted set of the last "
     "7 days' orders checked and added to in one script, rebuilt from `network_tls_cert` on loss", '—', '§13.15'))
TABLES = _replace(TABLES, 'Redis `{gka_<group_id>}`',
    ('Redis `{gka_<group_id>}`', 'gkm',
     "Acks: each leaf's newest applied epoch, at most daily (31 d after its last write, and deleted with its group at a "
     "shred); soft state, after whose loss gkm deletes no epoch for 30 d (owner decision 136)", '—', '§10.14'))
_EVSR = 'Redis `{evsq_<repo_id>}`, `{evsl_<repo_id>}`, `{evsh_<repo_id>}`, `{nvb_<set>}`'
TABLES = _replace(TABLES, _EVSR,
    (_EVSR, 'evs; taskworker publishes `{nvb_}`, and every evs, gkm and taskworker process reports into it',
     "The push sequence; subscription leases per path epoch; the verified head cache (10 min); each metadata set's "
     "write-budget calibration, bucket level and P1 and P2 allowances (A1, A2), with the processes' 5 s reports (15 s), "
     "all soft state (owner decision 136)",
     '—', '§11.19, §19.6'))
_PROJ = 'Objects `proj/<network_id>/<n>/_`, `projrows/<network_id>/<rows_sha256>/_`, `rev/`, `hold/`'
TABLES = _replace(TABLES, _PROJ,
    (_PROJ, 'api writes; evs, gkm and gates read (first metadata cluster)',
     "The authorization log, kept from §7.9's retention point, and its bases' rows; signed revocation objects; "
     "preservation holds", '—', '§7.9, §11.8, §21.9'))
_GKMO = ('Objects `gkm/repo/...`, `gkm/<group_id>/epoch/<n>`, `gkm/<group_id>/gen/<g>`, `group-info`, Welcomes, '
         '`gkm/<group_id>/wrap/<g>/<c8>/<recipient>`, `gkm/recovery/...`, `gkm/kp/...`, `gkm/rk/...`')
TABLES = _replace(TABLES, _GKMO,
    ('Objects `gkm/repo/...`, `gkm/<group_id>/epoch/<n>`, `gkm/<group_id>/gen/<g>`, `group-info`, Welcomes, '
     '`gkm/<group_id>/wrap/<g>/<c8>/<recipient>/<k8>`, `gkm/recovery/...`, `gkm/kp/...`, `gkm/rk/...`',
     "gkm (the repo's metadata cluster; per-sidecar objects on the first)",
     "GroupForm chains, epoch objects (one accepted commit each), generations (GenRotate, kept for the repo's "
     "life), joins, staged and late key deliveries, recovery wraps, KeyPackages and claims, ReaderKeys; no Postgres "
     "rows", '—', '§10.6'))

# ------------------------------------------------------------------ Appendix E: services and config
SERVICES = list(_P['SERVICES'])
SERVICES = _replace(SERVICES, 'api (existing)',
    ('api (existing)', '`api.bringyour.com`: `/network/*`, `/sidecar/*`, `/acl/*`, `/approval/*`, `/tls/*`, `/smtp/*`, `/mail/*`, `/abuse/*`',
     "New routes; the authorization-log sequencer and verifier within §7.9's append limits, the only writer of "
     "`{acl_}e` and `{acl_}q`, gate caches; after a Postgres restore, the replay of verified `proj/` entries before the "
     "exchange reopens; certs' routes; only the OAuth issuer mounts signing keys", '§7.17, §19.4, §19.10'))
SERVICES = _replace(SERVICES, 'sockets',
    ('sockets', '`server/cli/sockets`, `sockets.bringyour.com`; vault ticket keys; `sockets_control_qps` in `config/<env>/sidecar.yml`',
     'Abstract socket registry, scheduler and Find, behind a per-client token bucket (D-SOCK-15)', '§9.15'))
SERVICES = _replace(SERVICES, 'connect residents (existing)',
    ('connect residents (existing)', "server/connect, behind `EnableSidecarPush` and `sidecar.yml`'s `push` gate",
     'Publish push hints from ControlId', '§6.16'))
SERVICES = _replace(SERVICES, 'monitor (existing)',
    ('monitor (existing)', '—',
     "The dns canary; 443 probes; file-cluster set states, the next cluster's 30-day projection and a multi-pool "
     "warning; the off-site dump's 26 h check", '§12.14, §13.15, §19.6, §19.9'))
SERVICES = _replace(SERVICES, 'config',
    ('config', '`config/<env>/sidecar.yml` (gates, `reseed`, `place_new`, `drained`, `preview_networks`, '
               '`sockets_control_qps`, `urnetwork_edge`), `config/all/pro.yml`, `config/<env>/stripe.yml`, '
               '`config/<env>/dns.yml`, `config/<env>/abuse.yml`, `db.yml` and `redis.yml` caps',
     "Dark gates, re-seed mode, the placement target, the lb interfaces dns edges leave out, control-plane bounds and "
     "the `urnetwork-edge` network's id; tiers, limits, prices and `sidecar_abuse:`; Team price ids; zones; abuse "
     "feeds and reviewer and pager routing", '§19.11, §20.14, §21.16'))
SERVICES = _replace(SERVICES, 'file cluster',
    ('file cluster', "D-OPS-20's in-house build in the `urnetwork/minio` fork (owner decision 195): MinIO from the final "
                     "upstream source, with PR #21653's conditional-write fix, on 4 LAN hosts: a 1,024 TB raw HDD "
                     "segment cluster at EC:8 and metadata clusters of 8 × PM9A3 1.92 TB at EC:4, added whole",
     "The system of record for evs and gkm, whose Blobs client cancels a request unanswered 10 s after its last byte; "
     "the metadata tier grows only by whole clusters, never pools (owner decisions 94, 116, 136-140, 145)", '§19.6, §19.9'))
SERVICES = _replace(SERVICES, 'xops',
    ('xops', "`file-clusters` with §19.6's XFS and MinIO settings, the storage hosts' diskstats exporter, the sidecar "
             "dump, the main dump's exclude list and planetoid's `pg-sidecar` stream",
     'File cluster hosts and drive counters; the daily off-site sidecar table dump, kept 14 generations, which the main '
     'dumps exclude (D-OPS-18)', '§19.6, §19.16'))


# ------------------------------------------------------------------ Appendix E: connect changes (§4.6, verbatim)
def connect_rows(t4):
    """§4.6's C1-C19 rows as (id, change, disposition), cells verbatim, from 04-REPO.md's text."""
    rows, on = [], False
    for l in t4.split('\n'):
        if l.startswith('### 4.6 '):
            on = True
            continue
        if on and l.startswith('### '):
            break
        m = re.match(r'^\|\s*(C\d+[ab]?)\s*\|(.*)\|\s*$', l)
        if on and m:
            cells = [c.strip() for c in re.split(r'(?<!\\)\|', m.group(2))]
            assert len(cells) == 2, (m.group(1), cells)
            rows.append((m.group(1), cells[0], cells[1]))
    return rows


_T4 = _section(4)
CONNECT = connect_rows(_T4)
assert [r[0] for r in CONNECT] == ['C1', 'C2', 'C3', 'C4', 'C5', 'C6a', 'C6b', 'C7', 'C8', 'C9', 'C10', 'C11', 'C12',
                                   'C13', 'C14', 'C15', 'C16', 'C17', 'C18', 'C19'], [r[0] for r in CONNECT]
assert 'Dispositions follow owner decisions 22, 85 (C14 into M4), 86 (C18) and 176 (C19), under D-REPO-5' in _T4, \
    "§4.6's lead changed: update INTRO['E_CONNECT']"

# ------------------------------------------------------------------ Appendix F
PLAN_TRACE = list(_P['PLAN_TRACE'])


def _trace(lines_key, stmt_prefix, new):
    hits = [k for k, r in enumerate(PLAN_TRACE) if r[0] == lines_key and r[1].startswith(stmt_prefix)]
    if len(hits) != 1:
        raise KeyError((lines_key, stmt_prefix, hits))
    PLAN_TRACE[hits[0]] = new


# PLAN.md:55's leases are Redis soft state since owner decision 136 (§11.10), which the earlier row omitted.
_trace('55', '"subscribe/unsubscribe for changes',
       ('55', '"subscribe/unsubscribe for changes to a dir and subpath ... notified ... via a subprotocol message"',
        '§11.10 (D-EVS-14); §6.8', 'kept (Q-EVS-1, owner 2, 136)',
        'Server-side token-prefix leases, kept as Redis soft state (owner decision 136); `EvsHeadChanged` hints carry '
        'only server-held fields'))
# Placeholders in code spans (APPLY.md §4), so no renderer drops them.
_trace('5', '"the server repo',
       ('5', '"the server repo, where horizontally scaled services ... integrated into the overall architecture"',
        '§4.5 (D-REPO-3); §19.4 (D-OPS-1)', 'refined (Q-REPO-1, owner 19)',
        "Engines live in sidecar's `<svc>service` packages; server implements their stores and hosts them as "
        "`server/cli/<svc>`"))
_trace('25', '"A network has a dns zone',
       ('25', '"A network has a dns zone `<me>.ur.network`"', '§12.5 (D-DNS-2); §12.4 (D-DNS-1); §12.13',
        'departed (Q-DNS-2, owner 14; Q-DNS-1, owner 13)', 'An opaque immutable label; network_name only as an opt-in alias'))
_trace('104', '"SMTP server runs locally',
       ('104', '"SMTP server runs locally and terminates a public `mail.<me>.ur.network`"',
        '§15.4, §15.5 (D-MAIL-1 to D-MAIL-4); §12.13, §15.14', 'departed (Q-MAIL-3, owner 32)',
        'The mail host is `mx.<net>.<root>`; the receiver is still the local server, reached through mxedge'))


# ------------------------------------------------------------------ Appendix G (a pointer to §2.8, with a census)
def appendix_g(t2):
    """Census of §2.8's metadata_list.yml: version, date, scope, rows, withdrawn rows, id spans and the lead text."""
    i = t2.index('**The list**'); j = t2.index('```yaml', i); k = t2.index('\n```', j + 7)
    yaml = t2[j + 7:k]
    ver = re.search(r'metadata_list\.yml (v\d+), updated (\d{4}-\d\d-\d\d) for ([^(]*?) \(', yaml)
    if not ver:
        # v8 onward: "metadata_list.yml v8; v7 was updated ..." and later "# v8, updated <date> for <scope> (".
        _v = re.search(r'metadata_list\.yml (v\d+);', yaml)
        ver = _v and re.search(r'^# (' + _v.group(1) + r'), updated (\d{4}-\d\d-\d\d) for ([^(]*?) \(', yaml, re.M)
    assert ver, 'metadata_list.yml header not found'
    rows, cur = collections.OrderedDict(), None
    for l in yaml.split('\n'):
        m = re.match(r'^([a-z]+-\d+):\s*$', l)
        if m:
            cur = m.group(1)
            assert cur not in rows, ('duplicate row', cur)
            rows[cur] = False
            continue
        if cur and re.match(r'^\s+withdrawn:', l):
            rows[cur] = True
    fam = collections.OrderedDict()
    for r in rows:
        fam.setdefault(r.split('-')[0], []).append(int(r.split('-')[1]))

    def span(p, ns):
        ns = sorted(ns)
        assert ns == list(range(1, len(ns) + 1)), (p, ns)
        return f"{p}-1" if len(ns) == 1 else (f"{p}-1 and {p}-2" if len(ns) == 2 else f"{p}-1 to {p}-{len(ns)}")
    spans = [span(p, ns) for p, ns in fam.items()]
    wd = [r for r, w in rows.items() if w]
    census = (f"The list has {len(rows)} rows, {len(wd)} of them withdrawn: " + ', '.join(spans[:-1])
              + f" and {spans[-1]}; " + ', '.join(wd[:-1]) + f" and {wd[-1]} are withdrawn and keep their ids, so "
              "citations resolve.")
    text = (f"§2.8 holds `metadata_list.yml` ({ver.group(1)}, updated {ver.group(2)} for {ver.group(3)}), the list the "
            "product promises: URnetwork's servers never receive plaintext content or keys, in any mode, and see only "
            "the values it names (D-TRUST-4), with one bounded exception, the platform report listener (§2.8). This "
            "appendix no longer copies it, so the two cannot drift. " + census)
    return {'version': ver.group(1), 'date': ver.group(2), 'scope': ver.group(3), 'rows': len(rows),
            'withdrawn': wd, 'families': {p: len(ns) for p, ns in fam.items()}, 'spans': spans, 'census': census,
            'text': text}


APPX_G = appendix_g(_section(2))

# ------------------------------------------------------------------ Appendix H
RESEARCH = list(_P['RESEARCH'])
_cites = collections.defaultdict(set)
for _f in sorted(_SECTIONS.glob('*.md')):
    for _m in re.finditer(r'\[R:([a-z0-9-]+)\]', _f.read_text()):
        _cites[_m.group(1)].add(int(_f.name[:2]))
RESEARCH_CITES = {k: sorted(_cites[k]) for k, _ in RESEARCH}
assert set(_cites) == set(k for k, _ in RESEARCH), ('cited sheets differ from RESEARCH', sorted(_cites))

# ------------------------------------------------------------------ owner decision 197 (2026-11-09)
# Every app's VPN component runs only forwarding, self-contained with its own key (§17.8-§17.10, §18.4, §18.6): the
# rows that named the keyless device role, a channel from the sidecar role, or Android's background receiver follow
# the sections.
INTRO['D'] = INTRO['D'].replace(
    "The keyless device role parses only `protocol/bridge`'s `signed.proto`, `auth.proto` and `bridge.proto` (§4.4).",
    "`sidecar/device` parses only `protocol/bridge`'s `signed.proto`, `auth.proto` and `bridge.proto` (§4.4).")
assert '`sidecar/device` parses only' in INTRO['D'], 'Appendix D lead moved'
CARRIED = _replace(CARRIED, _GRANTS,
    (_GRANTS, "authorization-log statements (`acl.proto`, `SignedType` 0x11xx; `GrantRevoke`, `Suspend` and `Unsuspend` in "
              "`protocol/bridge/auth.proto`, which `sidecar/device`'s posture applies); the audit records in heads",
     "Approved runtime grants (each with its StatementHeader; `GrantActivate` once per `grant_id`) and their "
     "revocation, the one-switch suspension, an owner's shares and confirmations of admin-admitted devices (owner "
     "decision 126), repo creation, admins, grants, deletion and restore, and the audit reader", '§8.8'))
CARRIED = _replace(CARRIED, '`BridgeState`, `Pending`, `BridgeIdentity`, `BridgeShareKey`',
    ('`BridgeState`, `Pending`, `BridgeIdentity`, `BridgeShareKey`',
     "the compiler to `device.Bridge`, in process (`protocol/bridge/bridge.proto`)",
     "The compiler's bridge rules, names, anchor, the identities and share keys its host admits, and its daemon "
     "listeners, for `device.Bridge`, compiled by a daemon's sidecar role or an app's forwarding role (owner decision "
     "197); `Pending`, from enrollment or forwarding's setup, moves a device from legacy to pending", '§17.8, §18.6'))
CARRIED = _replace(CARRIED, '`WindowDelegation`',
    ('`WindowDelegation`', "C13's seal on a bridge link's contracts (`SignedType` 0x1908)",
     "The subject's signed delegation of one window client to one target, which the host verifies against the "
     "subject's pinned identity key, its live forwarding Delegation's key (owner decision 197) or a share's ShareKey "
     "before admitting IP flows", '§17.9'))
SERVICES = [r if r[0] != 'sdk' else
            (r[0], r[1], r[2].replace("the device role in `sidecar/device`",
                                      "forwarding in every app's VPN component, over `sidecar/device` (owner decision 197)"), r[3])
            for r in SERVICES]
assert any('forwarding in every app' in r[2] for r in SERVICES if r[0] == 'sdk'), 'sdk services row moved'
_trace('13', '"all service code goes in the root',
       ('13', '"all service code goes in the root of the module named sidecar"',
        '§4.4, §4.15; §14.13 (D-SMTP-11); §18.14 (D-SDK-20)', 'departed (Q-REPO-5, owner 104; Q-SDK-5)',
        'Server-only engines live in `sidecar/<svc>service` child packages, the X7 prover in the nested module '
        '`smtpproof`, and forwarding\'s packet side in the leaf package `sidecar/device` (Q-SDK-5, closed by peer review), '
        'linked in apps\' VPN components with only the root\'s forwarding files (owner decision 197)'))
_trace('28', '"the sidecar will be used directly by the apps',
       ('28', '"the sidecar will be used directly by the apps"', '§18.4 (D-SDK-1); §18.14',
        'departed (Q-SDK-2, owner 87, 197)',
        'Desktop apps use `ur daemon`; iOS runs the sidecar in the app; every app\'s VPN component runs only '
        'forwarding, with its own key'))
ROUTES = _replace(ROUTES, '`POST /network/auth-client`',
    ('`POST /network/auth-client`', 'OwnClient (existing)',
     'Mint a client token, the pairing child and a sidecar\'s `forward_only` forwarding client included (§18.6; owner '
     'decision 197); a `strict_exp` bearer adds a DPoP proof (§7.4); an ephemeral mint also returns its close '
     'capability once (§7.8)', '§5.15'))
