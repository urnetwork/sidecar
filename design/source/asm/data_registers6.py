# Register data for Appendices A and B, sixth assembly (2026-11-04), from the section files as last edited
# (2026-11-04 19:51). Starts from data_registers4.py (loaded with runpy) and replaces the summaries of the items that
# changed since the fourth assembly (v4 extract -> v6 extract: 144 changed, 79 new) where the change touches the
# summary, and adds the 73 new D- and 6 new Q- items. Scripts run under python3 -I.
#
# D: id -> decision summary (<= 20 words). Withdrawn and decided status come from the section label.
# Q: id -> (question <= 25 words, recommendation-or-outcome <= 15 words).
# STALE_D, STALE_Q: items whose section text lags an owner decision (none found); shown with a note.
import runpy, pathlib

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_registers4.py'))
D = dict(_P['D'])
Q = dict(_P['Q'])

D.update({
# §2
'D-TRUST-3': "No sidecar before the P0's first stage and 7-day sidecar-token expiry; until stage 2, sidecars enroll only in `preview_networks`.",
'D-TRUST-7': "Retention follows §2.11 and §2.8's ttl column; sidecar tables get a daily off-site 14-day dump; sidecar Redis leaves the bundles.",
# §3
'D-ARCH-3': "Flows F1-F10 implement the directive and owner decisions 1-145, are redrawn when one changes, and are §22.7's scenarios.",
# §4
'D-REPO-1': "Use §4.7's go.mod, §4.9's proto naming, an unversioned development path and the `/v2026` release rewrite connect and sdk use.",
'D-REPO-2': "Root: client code and MLS; engines in `<svc>service`; device role in `device/`; test peers in `mlsinterop/`; cli/, smtpproof/ nested modules.",
# §5
'D-CORE-1': "PLAN.md:14's fields: its own client JWT, a connect client per generation (none under `sidecar_http`), the APIs, its network's root key.",
'D-CORE-8': "The core reimplements sdk's refresh schedule; a refused refresh ends the client generation; only a verified SidecarRevoke revokes.",
'D-CORE-10': "A random root key per network seals local files, wrapped by the instance unlock key and that network's recovery key.",
'D-CORE-12': "macOS wraps the unlock key in the data protection keychain via purego, from a bundled `ur`.",
'D-CORE-14': "Local roots are per network under one instance unlock key, so one network's recovery code opens no other's keys.",
'D-CORE-15': "Only store state `Absent`, with no recorded sidecar_id, creates a root key; a lost item asks before a new identity.",
# §6
'D-PROTO-5': "Push follows §6.8: ControlId hints, a long-poll answering 200 `PollResponse`, and wakes for unacked wake-class hints.",
'D-PROTO-7': "Statements others act on carry a typed Signed envelope whose signed bytes name the message type.",
'D-PROTO-14': "Sidecars compare pins by scheduled HeadCheck, any admitted reader witnessing, reconcile, and refuse lower or conflicting values (owner decision 129).",
'D-PROTO-17': "HeadCheck compares auth pins, generations, ref heads, shared MLS epochs and vetoes, reconciles, and counts only same-pin peers as witnesses.",
'D-PROTO-18': "Any two admitted sidecars of a network get a `control` contract carrying only Hello, Ping, HeadCheck and HeadCheckProof.",
'D-PROTO-19': "C13 seals the server-authenticated subject, source network, contract class and WindowDelegation on every contract; only the dialer's network escrows.",
'D-PROTO-20': "§6's codes are frozen enums with 0 UNSPECIFIED, a protocol error; polls return `PollResponse`; partial resets advance nothing.",
# §7
'D-TEAM-1': "P0 stage 1, before any sidecar, refuses child and admin-refused tokens on 37 routes, confining `strict_exp` bearers to an allowlist.",
'D-TEAM-4': "Team SSO is OIDC only, with identities keyed (idp_id, sub) to block IdP-asserted and pre-registration takeover.",
'D-TEAM-5': "Auth keys replace urn_ keys for `ur connect --token`; a pre-approved key's Delegation secrets ride a client-only bundle.",
'D-TEAM-7': "ur-cli tokens last 1 h, need code-matched consent, and are DPoP-bound to one command's method, path and body.",
'D-TEAM-10': "Removal denies at the server at once; evs refuses writes until a generation covering it is claimed.",
'D-TEAM-12': "Records freeze as Signed statements; k of n for authority, a recovery key counting as one after its vetoable window.",
'D-TEAM-14': "Sidecar-held child and admin-refused tokens expire after 7 days under `strict_exp`, renewing only with the ClientKey proof.",
'D-TEAM-16': "Consented devices admit their member's devices unless `self_admit` is off, recovery keys too; admins alone add no owner-bound reader.",
'D-TEAM-17': "One authorization log per network; positions rise, entries chain by hash; HeadCheck compares (n, A_n); unwitnessed writers stop at `witness_bound_hours`.",
'D-TEAM-18': "The first 1,000 live member devices are config leaves; later ones and agents hold wraps; a change's signer commits it.",
'D-TEAM-19': "One hash-chained authorization log per network orders bases and statements; its position is the projection version, (n, A_n) the pin.",
'D-TEAM-20': "Every log statement carries a StatementHeader; off-chain, stale beyond 4,096 positions, expired or repeated statements are refused.",
'D-TEAM-21': "k-of-n and recovery-signed statements are an AuthorityProposal plus AuthorityCosigns; recovery-signed ones wait 72 h without a RecoveryVeto.",
'D-TEAM-22': "A pre-approved auth key carries its Delegation's seeds only in a client-only `#<bundle>`; api refuses an `auth_key` containing `#`.",
'D-TEAM-23': "JIT links an IdP identity to an existing user only after that user logs in with its existing credential.",
'D-TEAM-24': "`SidecarAdmit.capabilities.read_only` limits a device to reading, sign-out, MLS maintenance, receipts and HeadCheck; never one of k.",
'D-TEAM-25': "SCIM removals deny at once and turn cryptographic only when an admin device or `scim_signer` daemon signs the MemberRevoke.",
'D-TEAM-26': "A compromise `SidecarRevoke` parks every admission and OwnerConfirm the device signed since `since_ms` until reconfirmed.",
# §8
'D-ACL-1': "One HuJSON source in the config repo and one compiler, run by every sidecar and by each base's writer.",
'D-ACL-7': "Requested grants activate within `maxExpiry` only on approvals over the rule's `evidence`, harness evidence in tainted runs only if named.",
'D-ACL-15': "Policy reaches servers only as AclRows in §7.9's ProjectionRows, compiled at each base; grant chains ride the authorization log.",
'D-ACL-16': "Server gates evaluate the newest verified base and later entries, cached per (network, n), refreshed by INCR and polling.",
'D-ACL-17': "Member devices are leaves (config by §7.9's rank, data repos up to 1,000); everyone else reads through ReaderWraps.",
'D-ACL-19': "Subjects are classed before expansion; an ephemeral sidecar's evs access is only grants naming it, deposits and EvsShares to it.",
'D-ACL-20': "`autogroup:untagged` is untagged non-sidecars; writers compile the implicit document into the projection whenever `has_document` is false.",
'D-ACL-21': "evs and gkm honor `r`, `rw` or `admin` only while the subject holds that access in their newest verified state.",
'D-ACL-22': "One consent predicate, §8.5's `consented(d, M)`; a JIT member's first device enrolls from the admitting admin device's invite.",
# §9
'D-SOCK-15': "Per-client token buckets bound Find and registration-page work, never name counts or established use; spend checks precede signing.",
'D-SOCK-16': "`ur share` is a live sharer: a blinded `share/<token>` socket, a fragment secret and a durable use count.",
# §10
'D-KEYS-2': "One MLS group per repo, a leaf per reading member device up to 1,000; others, config overflow included, hold ReaderWraps.",
'D-KEYS-3': "Member commits are PrivateMessage, adding only the generation and auth pin in clear; only external commits are PublicMessage.",
'D-KEYS-5': "GKM keeps no state of its own; it orders, claims, delivers and retains through conditional writes on its repo's cluster.",
'D-KEYS-6': "Commit before write: a log entry shrinking a repo's key holders closes evs's gate until a covering generation is claimed.",
'D-KEYS-8': "Drop keys in each signed GenRotate give write-only deposits to covering generations; each key domain is its own repo.",
'D-KEYS-10': "M2's entry fixes MLS wire fields, its exit freezes them on §22.10's interop artifact; the security page discloses unaudited MLS.",
'D-KEYS-11': "Tagged, ephemeral, CI and cloud sidecars read and write through ReaderWraps; live Delegations get DelegationWraps (owner decision 114).",
'D-KEYS-13': "After a site loss, repo admins' or owners' consented devices re-seed each group from their keychains under a ladder-linked GroupForm.",
'D-KEYS-14': "Groups scale by 10.6's sizes: self-update interval, KF5 resync, GroupInfo on demand above 16 leaves, daily acks, trees on disk.",
'D-KEYS-15': "`gkm/<group_id>/gen/<g>`, created If-None-Match by the rotator, alone holds a generation; MLS commits never raise it.",
'D-KEYS-16': "KeyHolders: leaves, uncovered agents, live Delegations, recovery keys; a Delegation's key drops at revocation, `not_after` or an agent's non-reap revocation.",
'D-KEYS-17': "Drop keys ride each signed GenRotate for deposit kinds; depositors seal only to generations covering every known shrink and expiry.",
'D-KEYS-18': "At most 16 leaves, the epoch object carries sealed GroupInfo; above 16, recovery and resync need one leaf online.",
'D-KEYS-19': "`gkm:<group_id>` is versioned epoch × 2^24 + generation; work hints go on the acting sidecars' per-client `gkm` topic.",
'D-KEYS-20': "Retention keeps a group's newest epoch, moves `group-info` before deleting the epoch it names, and keeps gen/ for life.",
'D-KEYS-21': "gkm acks are Redis soft state; the reconciler deletes only once acks span 30 days; big GroupInfos only on request.",
# §11
'D-EVS-8': "Owned refs sync in real time; shared git-mode refs serialize by tip CAS, file-mode refs by path-level CAS; nothing auto-resolves.",
'D-EVS-11': "Kinds are fixed at creation; vault, mailbox and secret readers are only consented owner devices, EvsShares and the audit reader.",
'D-EVS-12': "11.6-11.7's token tree; a signed, head-bound map re-keys it at once on removal or compromise, else within 24 h.",
'D-EVS-13': "Stateless evs: objects on each repo's placed cluster; only the head If-Match commits; everything else is immutable or rebuildable.",
'D-EVS-14': "Subscriptions are token-prefix leases per path epoch in Redis soft state; hints carry server-held fields, versioned by the push sequence.",
'D-EVS-16': "Stored bytes: object sizes plus batch-resident records, counted nightly, moved by usage batches; at the limit, payload-adding pushes stop.",
'D-EVS-17': "Owner devices mirror record-class repos and the config in full, slots included, and re-seed evs after site loss, slots last.",
'D-EVS-18': "The write gate is the head CAS: a commit's authorization and generation pins pass §10.6's predicate against evs's newest state.",
'D-EVS-19': "Deletion is a `repo/` state machine following the access log; restore and shred share one CAS; `shredding` precedes key destruction.",
'D-EVS-21': "11.13 budgets metadata writes in drive bytes and IOs; leases, push sequence and acks live in Redis; per-network fair share.",
'D-EVS-22': "Refs have a mode fixed at creation: git-mode refs commit only on their tip; file-mode refs use path-level CAS.",
'D-EVS-23': "A push id names one statement; retries return its version; unknown outcomes resolve from the head, else a ref fence.",
'D-EVS-24': "Log pages hold ≤1 KiB signed statements; head readers verify every one after their pin and each read entry's.",
'D-EVS-25': "Orphans are found without the log: hourly evacuation resolves batch records; unadopted segments or maps die only after ref fences.",
'D-EVS-26': "Erasure is a committed ERASE push destroying every key of every representation: retained versions, derived-field chains and the deposit.",
'D-EVS-27': "Segments are addressed by content id; locators reserve two kinds and `spidx/` is reserved, so packing needs no format change.",
'D-EVS-28': "The local tier publishes through git's proc-receive hook with per-ref statuses, no atomic pushes and a durable push-id journal.",
'D-EVS-29': "The head holds the commit point and a window of 64-byte entries, ~9 KiB at most: one block a drive.",
'D-EVS-30': "evs group-commits push, part and seal records into immutable minute batches of ≤256 KiB, evacuated whole after 25-26 h.",
'D-EVS-31': "`idx/` holds only committed versions, folded lazily; reads and the CAS merge the unfolded window.",
'D-EVS-32': "Hourly, history older than 24 h packs onto HDD once 256 KiB, else into NVMe parcels packed within 7 d.",
'D-EVS-33': "evs, gkm and taskworker share each metadata cluster's write budget, 0.8 DWPD and 50% of IOPS, via per-network fair queues.",
'D-EVS-34': "Segment uploads write nothing to the metadata cluster: a MAC'd receipt rides the push; GC fences idle refs first.",
# §12
'D-DNS-6': "System records follow 12.7, with no wildcard CNAME; an entry is one user RRset; replying burner labels copy the wildcard.",
'D-DNS-9': "Custom domains: a verified TXT, a one-time `_acme-challenge` CNAME, a CAA accounturi pin; CNAME hosts are weak mode.",
'D-DNS-11': "A `<blabel>` with a child owner carries an atomic copy of the wildcard's MX, A and AAAA, served from `*`.",
# §13
'D-TLS-2': "Ingress is 13.4's gated, probed SNI split on shared lb addresses, custom hosts by a generated map; port 80 redirects.",
'D-TLS-5': "The sidecar's TLS front enforces 13.7, dispatching on the registration's mode, never ALPN's absence; 421 and origin rules are mandatory.",
'D-TLS-11': "A Team custom domain's customer ACME account serves its ordering desktops; the CAA pin excludes URnetwork only in strong mode.",
'D-TLS-12': "Active custom hosts reach tlsedge via the split's generated map, reloaded at most every 15 min.",
'D-TLS-13': "Dispatch binds the registration's mode: `http` through the HTTP front, `raw` only for `public` or pinned `link`; ALPN never decides.",
# §14
'D-SMTP-8': "Abuse attribution has three confidence levels; only high and medium halt, a medium join needing the MAC network's verifying `d=`.",
'D-SMTP-12': "Abuse reports are parsed header-only, aggregates by D-SMTP-23's bounded parser, then sealed unparsed to the network mail key or dropped.",
'D-SMTP-20': "DATA mode proves every message octet in 2-minute parts within 2 h, up to `smtp_data_proof_bytes`; larger mail gets a DSN.",
'D-SMTP-22': "14.5's relation also proves the MX's authenticated replies; parts name the records they cover, and BDAT bodies stream unopened.",
'D-SMTP-23': "DMARC and TLS-RPT aggregates are parsed within bounds, counted once per report, and compared with proven sends per recipient.",
# §15
'D-MAIL-3': "Receivers run emersion/go-smtp with 15.5's upstreamable ServeConn, forked if declined, and verify with mox over DoH on arrival.",
'D-MAIL-5': "Receivers deposit each message to the newest GenRotate's drop key and answer 250 once durable; erasure takes every copy.",
'D-MAIL-10': "Reports and role mail reach rpt.bringyour.com's terminating platform listener, which accepts only platform recipients and persists no plaintext.",
'D-MAIL-14': "Receivers seal reception-time authentication evidence in the deposit; readers label, score and forward from it, never from later DNS.",
# §16
'D-MCP-8': "Restore is the run_restore tool, writing only the run's attributed edits, rechecked against its preview, recorded, approved when tainted.",
'D-MCP-9': "A harness prompt counts as a daemon-signed `harness` decision under harness_ok, never for authority, in tainted runs only if named.",
'D-MCP-11': "Each approval use is reserved durably before its effect; components are idempotent per `effect_key`; an uncertain use stays consumed.",
'D-MCP-12': "Decisions bind their spender and projection pin; every spender runs 16.6's spend check, and an approval activates one grant.",
'D-MCP-13': "Results are version-aware, so every promised MCP version reads the same tagged data.",
'D-MCP-14': "Only approval-capable devices give `device` evidence or disable `harness_ok`.",
'D-MCP-15': "Restore points are local and exact; changes carry edit, shell or foreign attribution; restore writes only attributed edits.",
'D-MCP-16': "Run taint is a monotone, fsynced bit written before untrusted data leaves the daemon; a missing file means tainted.",
'D-MCP-17': "MCP's evs tools never write config or `mailcfg`; MCP signs no authority statement; `CanonicalAction` carries every field approvers render.",
'D-MCP-18': "Read receipts are budgeted deposits made before decryption; a first read that cannot deposit fails closed.",
'D-MCP-19': "Presence evidence follows 16.6's profiles: WebAuthn with UP and UV per use; Secure Enclave keys labeled asserted.",
# §17
'D-BRIDGE-4': "The C5 egress hook applies 17.6's order, relying on C6a, C13, C15 and, for shares, C18.",
'D-BRIDGE-5': "Links run Required to a fixed target with one window client, relay-only until C3, never count-capped; targets sidecar-owned until C16.",
'D-BRIDGE-7': "Revocations reset both ends at once; edits keep pinned pairs on serving links and drain removed advertisers for minutes.",
'D-BRIDGE-9': "HA is active-active by weighted rendezvous over healthy advertisers; a down mark moves no pin and keeps the last advertiser.",
'D-BRIDGE-12': "The sdk exports hosted addresses, granted prefixes, aliases and an RFC 1918 block minus the physical path's local /32s.",
'D-BRIDGE-14': "C18 reaches the hook only on sidecar-owned share hosts, mapping foreign flows by verified share and network to its targets.",
'D-BRIDGE-17': "A host admits native IP flows only from window clients whose customer-signed `WindowDelegation` it verified, or a pinned ShareKey's.",
'D-BRIDGE-18': "Only a verified state opens a private destination: legacy, pending and enforcing states persist, never lowered by unsigned input.",
'D-BRIDGE-19': "A provider never dials its own daemon listeners, with or without a document (17.6's rule 0).",
'D-BRIDGE-20': "Hosts use the lower /17, aliases the upper /17 first-fit; a share too wide or without room is refused.",
'D-BRIDGE-21': "A revocation swaps policy before `CloseFlows`; flows register rule and policy generation before dialing and recheck before the first byte.",
# §18
'D-SDK-6': "Browser sidecars phase per 18.8: Workers are member devices, the page Worker read-only, the quick burner a wrapped reader.",
'D-SDK-9': "Apps decide approvals, admissions, alarms and vetoes through `SidecarApprovals`; control mode signs only confirmed `device` evidence for others.",
'D-SDK-13': "The device role takes rules only from its BridgeState and anchored deltas, restoring its persisted posture before the first packet.",
'D-SDK-14': "Transport rejections are generation-bound and map to Unenrolled with a reason; only a verified `SidecarRevoke` maps to Revoked.",
'D-SDK-15': "`SidecarKeyStore` returns status codes and a `SidecarSecret` struct, since gobind carries no error type.",
'D-SDK-16': "Wakes follow 18.7: a slot-local script, a separate token-holder enqueue, client acks from connect's frame ack, a deferred live check.",
'D-SDK-17': "Ephemeral clients are reaped with no open connection once their poll lease and newest disconnect pass 35 min.",
'D-SDK-18': "Browser keys, tokens and the Worker live in a key origin that ur.io pages frame and message by exact origin.",
'D-SDK-19': "The page Worker builds the root with `-tags sidecar_http`, linking no connect package.",
'D-SDK-20': "The device role lives in `sidecar/device`, importing only connect and `sidecar/protocol/bridge`.",
# §19
'D-OPS-4': "The file clusters are LAN-only, unshared and without presigned URLs.",
'D-OPS-5': "Off-site copy of the file clusters; superseded by owner decision 94; D-OPS-18 covers Postgres-held sidecar rows.",
'D-OPS-6': "Migrations follow 19.7: a group stays pending under `sidecar_pending` until its own Gn-out registers it.",
'D-OPS-7': "Redis holds only rebuildable state; switches go to Postgres first; the clusters stay the only commit point.",
'D-OPS-9': "Adopt 19.8's SLOs and page classes, paging out of hours from M3; error-budget burn stops rollout steps.",
'D-OPS-10': "Gates and the placement target live in `config/<env>/sidecar.yml`.",
'D-OPS-14': "Durability is 19.6's quorum writes, protection states, cold spare and daily off-site sidecar dump; site loss takes 19.10's restore.",
'D-OPS-17': "Size the metadata tier by measured drive writes, objects and bytes; owner decision 136's triggers order the next metadata cluster.",
'D-OPS-18': "The tables 19.7's groups create get a daily off-site dump from MG0's Gn-out, excluded from the main dumps.",
'D-OPS-19': "Metadata sets run 19.6's XFS and MinIO settings; storage hosts export drive write counters and SMART wear to the budget.",
# §20
'D-QUOTA-3': "Capacity except storage counts exactly; storage nightly from stored sizes, moved by usage batches; rates in one atomic Lua script.",
'D-QUOTA-4': "Service contracts escrow nothing; edges bill by lease, relayed contracts by reservation and close report, evs by usage batches.",
'D-QUOTA-8': "Taskworker rolls usage into daily network_service_usage rows, each sent to a pre-aggregated daily Stripe meter, so re-sends replace.",
'D-QUOTA-9': "One comparator, `escrowDrawLess`, orders every draw and return of transfer balances, with `team_credit` last.",
# §21
'D-ABUSE-6': "Legal process and holds follow 21.9 (owner decisions 93, 133), each hold with its statutory kind and deadline.",
# §22
'D-TEST-9': "Freezes pass 22.10's gates in D-PHASE-7's two steps; nothing is audited (owner decision 99).",
'D-TEST-10': "Every state machine of §7-§21 is tested by deterministic fault schedules against FI-1 to FI-14, beside TLA+ and Porcupine checks.",
'D-TEST-11': "§22.8's `nvme` run gates M2's exit and format 1: ≤43 KiB a push per drive, ≤50% of rated IOPS.",
# §23
'D-PHASE-4': "23.7's M0 lead-time items and §10.4's MLS subset with its X-Wing KAT start in M0.",
'D-PHASE-7': "Each frozen format freezes twice: its specification at its milestone's Gn-in, its final bytes at its Gn-out, on 22.10's evidence.",
})

Q.update({
# §1
'Q-CTX-2': ("Which runtime serves browser surfaces besides the extension?",
            "The extension's sidecar.wasm in a page Worker admitted read-only, labeled as served code."),
'Q-CTX-4': (Q['Q-CTX-4'][0], "(a) §9: a blinded `share/<token>` socket while `ur share` runs (D-SOCK-16)."),
# §3
'Q-ARCH-8': (Q['Q-ARCH-8'][0], "(c) a reap rotates only keys no live Delegation still delivers; headless sidecars deposit only."),
# §4
'Q-REPO-3': (Q['Q-REPO-3'][0], "(a) yes: `protocol/` and `protocol/bridge` import nothing else from sidecar, test-enforced."),
'Q-REPO-5': (Q['Q-REPO-5'][0], "(b) child packages; (d) a nested prover module, cli/ nested too."),
# §5
'Q-CORE-4': (Q['Q-CORE-4'][0], "(b) in v0: DPoP by the ClientKey on refresh, exchange and auth-client; (c) later."),
'Q-CORE-6': (Q['Q-CORE-6'][0], "One Sidecar per network per daemon, sharing unlock and MCP, never a client or key."),
# §7
'Q-TEAM-10': (Q['Q-TEAM-10'][0], "(a) yes, scoped, unless `self_admit` is off; its signer commits the Add or first wrap."),
# §10
'Q-KEYS-11': (Q['Q-KEYS-11'][0], "(a) 30 days, then until recent ackers apply; never the newest epoch."),
'Q-KEYS-15': ("How many member devices may one network hold, given the config group's 1,000-leaf cap?",
              "(b) no cap: config readers past the first 1,000 member devices read by wraps."),
# §11
'Q-EVS-6': (Q['Q-EVS-6'][0], "(c): head readers replay signed statements of at most 1 KiB from their pin."),
'Q-EVS-8': ("Do git-mode refs commit only on their tip, narrowing owner decision 2's disjoint landing to file-mode refs?",
            "(a) tip CAS for git-mode refs; file-mode refs keep disjoint landing."),
'Q-EVS-9': ("Must the design meet owner decision 140's ~10-15 KiB a push, when the head's If-Match overwrite alone writes ~14 KiB?",
            "(a) meet the binding 0.8 DWPD and 50% IOPS limits, with §22.8's 43 KiB gate."),
# §15
'Q-MAIL-2': (Q['Q-MAIL-2'][0], "Always-on receivers, plus the iOS app in the foreground, which is no reliable receiver."),
# §16
'Q-MCP-3': (Q['Q-MCP-3'][0], "(c) the harness prompt, labeled harness, where evidence allows; tainted runs per Q-MCP-6."),
'Q-MCP-6': ("May harness evidence approve an outward action in a tainted run, when any same-uid process can produce it?",
            "(c) no by default; harness counts only where a `requests` rule names it."),
# §17
'Q-BRIDGE-2': (Q['Q-BRIDGE-2'][0], "(c): a fixed client per target with a WindowDelegation; own-client links later."),
# §18
'Q-SDK-5': (Q['Q-SDK-5'][0], "(b): the leaf package `sidecar/device` over `protocol/bridge` (D-SDK-20)."),
# §19
'Q-OPS-1': (Q['Q-OPS-1'][0], "One-site MinIO clusters, store-ordered; PM9A3 metadata sets, a write budget, growth by whole clusters."),
'Q-OPS-2': ("Should small objects pack, given Y2's HDD mix of ~32,000 drive operations a second against ~8,000-12,800?",
            "(b) in v0; content-id addressing reserved, so small-segment packing is a switch."),
'Q-OPS-3': (Q['Q-OPS-3'][0], "Moot; storage left Postgres; D-OPS-18 dumps Postgres-held sidecar rows daily."),
'Q-OPS-5': (Q['Q-OPS-5'][0], "(a) staged, N and N+1 compatible, with stop rules and a rollback drill."),
'Q-OPS-9': ("Do page-class infrastructure alerts page out of hours from M3, so the 4 h RTO and SLOs hold at all hours?",
            "(a) a two-person rota with 30-minute acknowledgment from M3."),
'Q-OPS-10': ("How does the metadata tier grow past one set, when a multi-pool PUT checks preconditions only in its chosen pool?",
             "(b) only by whole metadata clusters, repos placed at creation by `place/<repo_id>`."),
# §20
'Q-QUOTA-3': (Q['Q-QUOTA-3'][0], "(a) post-paid Stripe meters, a credit line drawn last (D-QUOTA-9); benchmark gates M6."),
'Q-QUOTA-6': (Q['Q-QUOTA-6'][0], "(a) yes, reserved at CreateContract and debited by close report, from M2."),
# §22
'Q-TEST-1': (Q['Q-TEST-1'][0], "(a): `sidecartest` builds on connect's exported API; T3 cross-checks on server."),
'Q-TEST-2': (Q['Q-TEST-2'][0], "(a) and (b): Redis Cluster and erasure-coded MinIO locally and in T3, plus a lint."),
'Q-TEST-6': (Q['Q-TEST-6'][0], "(b): no `oneof` in envelope, stream or push messages, by a descriptor lint."),
})

STALE_D = {}
STALE_Q = {}
