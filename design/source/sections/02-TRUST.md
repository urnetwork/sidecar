## 2. Trust model and threat model

### 2.1 Purpose and scope

This section sets the adversary model, trust boundaries, server visibility, key custody, the "private from us" statement and metadata list, and invariants I-1..I-20 for every section; §5-§18 own mechanisms, §21 abuse, §22 tests.

### 2.2 Requirements

| id | requirement | source |
|---|---|---|
| R-TRUST-1 | Storage and the sequencer hold no group secret or key | PLAN.md:221 |
| R-TRUST-2 | Servers see only ciphertext and published small header values, except D-SMTP-19's report and role-mail intake (mx-4; D-TRUST-4); "end-to-end encrypted" comes with a malicious-server threat model and the unaudited-cryptography disclosure | sidecar/design/pitch5.html:745, :927-933; owner directive; owner decision 119 |
| R-TRUST-3 | Signed membership stops a breached server from adding a reader | sidecar/design/pitch5.html:745; owner decision 3 |
| R-TRUST-4 | TLS keys stay in the listening sidecar; tlsedge never terminates | sidecar/design/pitch5.html:699; X1 |
| R-TRUST-5 | With a policy, agents reach only granted ranges and exit only through customer exits; sidecar-bound agent tokens last ≤1 h and stay out of agents' environments | sidecar/design/pitch5.html:689; sidecar/FEEDBACK-SYSTEM.md:139; owner decision 120 |
| R-TRUST-6 | Untrusted content cuts egress. New recipients need approval. One switch revokes reach | sidecar/design/improve.md:126-127; sidecar/design/pitch5.html:729 |
| R-TRUST-7 | Admins see actions, not transcripts; session contents open only when shared, while in a team network a run's who, what and where reach teammates by default; authors see admin reads | sidecar/design/pitch5.html:640; owner decisions 126, 170 |
| R-TRUST-8 | Client tokens never administer networks. Revocation is forward-only | [R:server-identity] §3 item 3; PLAN.md:327 |

### 2.3 What exists today

- **Encryption.** connect defaults to Off (connect/transfer_encrypt.go:788), the sdk to Opportunistic (sdk/device_local_provider.go:258), and ControlId traffic is never encrypted (connect/transfer_encrypt.go:3671-3686).
- **AUTHZ1** (§7.3): on non-Embed networks any client token mints a network login through `/auth/code-create`, and same-user processes read the network credential in `.auth_state` (sdk/local_state_auth.go:28-36) and in the extension's `chrome.storage.local` (extension/src/background/index.ts:134).
- **Missing:** members, signed membership, customer keys, a metadata list, and ur.network's DS, CAA and SPF records (dig, 2026-11-03).

### 2.4 Assets and boundaries

Assets: content (files, sessions, mail, burner logins), keys and credentials, authority (config repo, approvals, record), names, metadata, shared reputation, availability.

```text
TB1 device:  sidecar daemon (keys, plaintext), harness and agents as one OS user (owner decision 47);
             an app's VPN component, a network process, with only forwarding's keys and the config's
             contents (owner decision 197; §18.6);
             for a cloud agent (owner decision 49), the sandbox operator (the VM host, its snapshot store
             and its egress proxy), whose VM snapshot holds the keys and whose TLS-terminating proxy would
             see service tokens, is inside the device boundary, like the OS;
             web: script running in a decrypting page's origin is inside the plaintext boundary (EX7);
             keys and tokens stay in §18.8's key origin;
             the daemon stops tool misuse, not same-user reads; other users and the LAN are outside
TB2 members: trusted for granted content; admins admit alone and change authority under k of n
             (owner decision 110), but add no reader to a member's owner-bound repos without that
             member's consent (owner decision 126); admin vs author key domain (X20); a member whose
             device is designated as a network-scope search indexer sees the queries members' phones
             send it over the team repos it answers, as an owner's indexer sees those over a repo the
             owner shared (owner decisions 175, 178); no device is designated by default (owner
             decision 177)
TB3 servers: behind connect e2e (I-3); untrusted for content and authority
outside:     CAs, CT logs and search, DoH resolvers, IP-listing feeds, mailbox providers, Stripe,
             APNs/FCM, model providers, other tenants (§2.8 ext-*)
```

### 2.5 Server visibility matrix

| Service (§2.8 rows) | Where encryption ends; what stays sealed |
|---|---|
| connect, tlsedge, certs (connect-*, tls-*, cert-*) | At each sidecar (I-3, X1) |
| smtpedge, mxedge (smtp-*, mx-*) | At the destination MX or the receiver (X6, X7); mx-4 excepted (§2.8's statement) |
| evs, gkm (evs-*, gkm-*) | On readers' devices; names, contents, keys; gkm sees members and wrap recipients as sidecar ids (owner decisions 72, 114, 115, 144, 182) |
| api, sockets, dns (api-*, sock-*, dns-*) | No content passes; policy text and internal names stay sealed (owner decisions 67, 72); DNS records are public |

### 2.6 Key custody

| Key | Holder | Who can misuse it |
|---|---|---|
| ClientKey, identity and local root keys; tokens, auth codes | Device keychain (§5); device files; a browser's key origin (§18.8) | Holder, same-user agents and a cloud agent's sandbox operator; tokens administer until the P0's stages (§7.4) |
| AdminSet (Owner, Admin, Network and IT admin), approval, presence and recovery keys | Holders' devices (§7, §16); recovery codes offline (owner decision 62) | Holder; authority statements need k signers, target excluded, k = 1 when n ≤ 2 (owner decision 110); a recovery code counts as one of k after a vetoable 72 h (owner decision 127) and admits its member's devices, with an admin cosign when `self_admit` is off, and under a binding the compromise cascade restored only after that vetoable 72 h (owner decision 149; §7.9) |
| MLS secrets, repo and path keys, the socket-name key | Readers' devices; agents', and in the config and team directory groups member devices past a network's first 1,000, by X-Wing wraps (owner decisions 114, 144, 182; §10); each member's recovery key by RecoveryWraps (owner decision 62); wraps as ciphertext | Readers; every admitted sidecar, agents included, reads the config's policy, AdminSet, the emails policy names, `K_sock` and share signers' seeds (owner decisions 6, 67; below), and in a team the directory (owner decision 171); removed readers for generations held and path tokens until rotation (evs-11); holders of a Delegation's reader key (its agents, reaped ones and ephemeral ones past their own `not_after` included, and copies of its auth key) until the key drops at DelegationRevoke, `not_after`, a revocation for any reason but reaped or a `Suspend` of one of its agents, or a compromise revocation whose cascade voids it, and a copy of the whole auth key, which holds the signing seed, admitting fresh agents, each with its own wraps once the key has dropped, until the Delegation ends (§7.9's delegation row, §10.5); a recovery code's holder with its member's login or the operator's help, for every generation wrapped to it, at once and whatever the window or a veto, until `RecoveryRebind{reason: compromise}` or a cascade void of its binding (§7.9) |
| An app's forwarding key, forwarding reader key and forwarding clients' keys (§5.5, §18.6; owner decision 197) | Its VPN component's own store (§5.9), generated there and never exported | That process, or a compromise of it: forwarding as its sidecar through that sidecar's grants, and the config generations wrapped to its reader key, until its forwarding Delegation ends at a `DelegationRevoke`, a newer one or its sidecar's revocation (§7.9); never mail, another evs repo, an MLS leaf secret, or the sidecar's identity, client, reader or recovery keys |
| A bridge share's ShareKey and ShareSigner seeds (§17.9) | The ShareKey in the accepting network's approving admin's owner-bound `secret`; each config generation's seed in its `BridgeShareSigner` config file | The secret's readers (§8.5), a removed one until the share is revoked; every config reader, agents included, one its network's policy denies too on an operator-minted contract (§8.11), a removed one until a later ShareCert reaches the host, at most 7 days (§2.10) |
| TLS, DKIM and mail-host keys | Each listening, sending or receiving device (D-TLS-6, owner decision 36, D-MAIL-4) | Holder; receivers see their hosts' mail in transit |
| Platform keys: JWT, OAuth, key history, ACME, DNSSEC, registrar, platform mail, evs receipt MACs | api's issuer, certs, the dns edge, mxedge, evs, vault | Insiders or hijackers: tokens, EX1, EX2, EX6 and URnetwork's mail |
| Release signing keys | Offline two-person key over `SHA256SUMS`; code signing (§4.10) | Holders; the build pipeline |

### 2.7 Client-id-to-key binding and ghost members

The server creates client ids and serves their keys (`/key/<id>`, server/api/route_authz.go:248), so a malicious one could add a ghost peer, substitute a key at first contact, or pass off its own KeyPackage or external commit as a member's new device (RFC 9750 §8.4.3).

Mitigations (owner decisions 3, 5, 110, 112, 113): config-repo admissions chain to the genesis key that invites and auth keys carry (§7.9), so clients refuse underived peers, readers, rules and membership commits, leaving a breached server only denial or delay; `Hello` bindings and safety numbers stop first-contact substitution (EX5, EX6).

### 2.8 "Private from us"

Statement (D-TRUST-4): *URnetwork's servers never receive plaintext content or keys, in any mode, except `rpt.bringyour.com`'s report and role-mail listener, which terminates TLS, parses headers and aggregate report data only (D-SMTP-23), seals the raw bytes to the network mail key and persists no plaintext (mx-4, §14.8). They see the values listed below. URnetwork builds no prospective collection (owner decision 93) but could be compelled to record these values from now on (§21.9).*

An active or compelled operator keeps:

- **EX1.** Certificates in URnetwork zones (owner decision 39); CT watch (D-TRUST-6); CAA `accounturi` excludes Team custom domains in strong mode only (customer A and AAAA, or an ALIAS flattening only those), and a weak-mode custom host (a CNAME into an operator zone) stays exposed (§12.8); the canary probe that catches an ALIAS also flattening CAA is URnetwork's own (certs), the ordering desktops repeating only the walk, so against a compelled operator such an ALIAS is as exposed as weak mode, the CT watch (D-TLS-8) its remaining control.
- **EX2.** Forged TLSA, CAA, MX, DKIM or MTA-STS records in URnetwork-signed zones (owner decision 69); zone watch (D-TRUST-9).
- **EX3.** Interception of inbound mail from senders validating neither DANE nor MTA-STS, undetected; labeled "opportunistic" unless REQUIRETLS or a listed enforcing operator makes it "validated" (owner decisions 98, 135; §15.5), a match mxedge can fake (§2.18); an operator listed only for MTA-STS makes burner mail "validated" though burner domains publish no policy; the operator list is an operator-reputation inference, and REQUIRETLS records only the final hop's requirement, never that URnetwork did not read the message (§15.5).
- **EX4.** A send the user allowed to an unauthenticated MX (owner decision 38), labeled "readable by an active URnetwork edge".
- **EX5.** Trust on first use of a genesis key no invite or auth key carried (owner decision 5); safety numbers; a code-only recovered device, which has no admitter, commits, wraps, seals or signs nothing until the config head its RecoveryWrap, or under a binding a cascade void restored the ReaderWrap it is given (§7.9's restored order), opens chains to a genesis its RecoveryBind's `genesis_sig` signs under the key its code derives (§7.9's anchor), so the recovery public keys every config reader and rotator holds let no server fake that genesis; a server can forge the wrap or the ReaderKey gkm serves, but not a head that chains to that genesis.
- **EX6.** connect key substitution at first contact until M2's admission check (§6.4); first-use pins.
- **EX7.** Code URnetwork ships: signed releases (owner decision 77) and labeled decrypting web pages (owner decision 76); undetected; any script in a decrypting page's origin reads views while it runs (§18.8).
- **EX8.** URnetwork login as the `members` audience authority (owner decision 42); undetected (§13.7).

**Exposure bound** (owner decision 129): a writer learns of a withheld Remove at its first HeadCheck with a device that holds it, or with a peer that relays it as `proven` or `unverified` within 8 hops of a holder (D-TRUST-10, §6.4); with the withholding proof it stops at once, and without it the pin stays UNVERIFIED, so, as with no consistent witness, the writer stops sealing shared-group content at `ServiceSettings.witness_bound_hours` (default 72 h, 24-168 h). Exposure is unbounded across a split, where the server leaves no HeadCheck path of up to 8 hops between a holder and the writer, including when every device that holds the Remove is offline, and in own groups, where writers only alarm: personal networks, and with them the v0 pilot (owner decision 102), have no bound.

**Also disclosed:**
- Burner linkability (§15.9).
- No fork detection without a shared pin.
- I-10's no-policy allow-all, in product copy too (owner decision 120).
- §2.18's unaudited cryptography.
- A head reader's trust in evs for which writer-signed version is current at its first pin, for a path it never read and, after a re-pin past §11.9's 4 MiB catch-up budget (shown as `verified since <time>`), for every path, HeadCheck confirming the pin, not those versions (§11.9).
- A shredded repo's statements and ciphertext in shared batches up to 26 h past key destruction (§11.12).
- P0 safety work runs at once whatever its volume (owner decision 186), so a wave of it on one metadata cluster, legal within every network's rates, holds that cluster's evacuation from when it empties the write budget's bucket until the wave ends (§11.13; owner decision 190): each bound in this list that rests on hourly evacuation, the 26 h ones, stretches meanwhile (§11.21).
- Erasure paced, at the storage limit or while spent, by each eraser's daily closure allowance, which §21 never cuts below its floor: an entry's own keys go at once, while its derived fields (`i/` entries and search-index copies) stay openable to their key holders, masked from search, for up to the wait §11.13 and §15.7 state from the erasure's closure bytes, not a fixed time per message, and longer while a ref's full erasure set holds back the erasure's CUT (§11.12's cut row); an erasure whose eraser's device is lost waits for another device that may finish it (§11.12's reconcile row; owner decision 146).
- Versionless content (§11.7): a writer may turn versioning off for a path, except in config and mailcfg repos, on git-mode and creates-only refs and, through a repo admin's lock, in a locked repo, after which each replaced version's content is purged about a minute after its replacement (staged content with its batch, at most 26 h; evs-12), beyond recall, while its signed statement keeps its hash, padded size, time and signer; the setting shows the server which paths are versionless and which hold the search index (owner decision 168); under a hold, versionless content that existed at placement stays until the hold ends.
- Dropped history (§11.7, §11.13): a repo admin may drop a path's history on a file-mode ref outside config and mailcfg repos, after a 7-day window in which any repo admin can cancel, or at once with `now`; in an owner-bound repo only its owner drops or cancels (owner decisions 126, 183); each dropped version's statement keeps its hash, time and signer, and its content goes beyond recall; inline content stays as unserved ciphertext in packs until compaction, and in slot-keyed repos is unreadable at once; under a hold the content stays until the hold ends, while the drop reads, lists and bills as finished (owner decision 184); deleted blocks persist on the drives until overwritten (evs-28).
- Search (§11.14, §16.10): no query or result reaches a server; an ephemeral sidecar's first sync of a repo's index and any device's fetch of a repo's all partition at "search more" show evs that and when the device searched, never what (desktops and indexers, syncing in the background, show neither); each opened hit, and each candidate `ur search --verify fetch` opens, is an ordinary document read, so their set shows evs a query-dependent access pattern (evs-26); an app host's "search more" that a designated indexer answers goes end to end to that device, which sees the query (another member's device only for team repos or a repo that member shared, the app naming that member first), while relays see when each search and page runs, in fixed sizes, connect's stored reports show each window's fixed floor rather than its pages, its contract rows a search's time only when the search fails over or re-establishes a session lost in the foreground, and evs sees nothing (connect-5; owner decisions 175, 176, 178, 188, 191).
- The team directory (§16.11): in a team network every admitted sidecar, agents and the audit reader included, reads each member's run titles, projects and branches unless the member opts out (owner decision 170), and the name and description of every general and record repo unless its owner marks it private or revokes its announcement (owner decision 181), a revocation hiding the name from honest readers at once and destroying its copies' keys once a directory admin's device runs its erasure request, so a modified reader can open them until then; evs learns per sidecar when its runs start, end and move, and per access request which requester asked which approvers' devices (evs-27).

Feedback (sidecar/FEEDBACK-SYSTEM.md:11) and hosted models are out of scope.

**The list** (the only TTL table; I-18):

```yaml
# metadata_list.yml v9; v7 was updated 2026-11-05 for owner decisions 112-184 and the peer review's formats and fixes (§6,
# §7.9, §10, §11). v6 adds to v5 (2026-11-04) connect-1's ShareCert, api-6's push-token slot sentinels, api-7's
# {acl_}q, cascade signers, recovery bindings, restored bindings' recovery windows and orphaned networks, api-13's
# per-eraser closure counters, evs-1's secret kind and orphans, evs-3's creation block, fence time, deleted flag
# and marker collection, evs-4's closure uploads, evs-9's count rule, evs-11's entry states, removal markers, their
# collection and leak bound, evs-12's CLOSURE, source paths and path-epoch tail, evs-24's cache times, gkm-7's gen
# packs, dns-1's canaries and replaced snapshots, ops-2's dump rule and ext-3's reception-time lookups.
# v7 adds evs-1's format 2, evs-3's versionless flag, evs-4's kind-5 segments and their purge, evs-5's versionless
# slots, evs-11's versioning settings and markers' carried ids, evs-12's staged segments, removal lists and purge
# candidates, evs-19's purge rule, evs-22's staged bytes, api-7's versioning locks and indexer designations, and
# evs-26, the search index's view, which adds no store. For owner decisions 167-184 it adds connect-5, remote
# search's relay view; evs-26's remote-search clause; evs-27, the team directory; evs-28, the drop job's state;
# evs-1's directory kind; evs-3's DROP bit; evs-4's and evs-5's drop deletions; evs-7's drop routes; evs-9's drop
# deltas; evs-11's drop mark; evs-12's DROP records; evs-14's DROP statements; evs-19's held drops; and api-7's
# autogroup:dst-owner and EvsShare.expires. v7 also adds evs-10's {nvb_<cluster>}, each segment cluster's drive
# operations a second and capacity, and makes every row strict YAML: a value holding a colon and space is
# double-quoted, so parsers read the same text.
# v8, updated 2026-11-06 for owner decisions 185-191 and the final meta review (2026-11-05), adds api-6's token
# revisions, tombstones and {scp_}tokrev; api-7's Delegation ends, admission counts and revocations' since_n, and
# presence countersignatures (key id, signature, WebAuthn evidence with its flags, counter and client data, and the
# act's size, index and inclusion path); connect-1's report times and connect-5's §6.10 windows (owner decisions
# 188, 191); dns-1's custom-host map versions and lb interface reports; evs-3's refusal records, refused_ms and
# placeholder heads, and an index ref's index_epoch; evs-10's write-budget accounts, wallet, per-process reports and
# P0 figures, P0's forgiven excess among them, the bucket saved 48 h; evs-12's CUT flag and index_epoch; evs-22's
# batches held past 26 h while P0 holds the bucket empty; evs-24's per-ref push sequence; evs-26's CUTs,
# erasure sets, INDEX_EPOCH refusals and rare in-place roll-up rewrites; evs-27's erasure requests, decision
# rewrites and moved-stream reads; ext-3's per-message lookup bound; gkm-4's 7-day ReaderKeys; gkm-7's key digests,
# delivery kinds and late deliveries' pins; and gkm-8's binding prefixes.
# v9, updated 2026-11-09 for owner decision 197 (the apps' network extensions), adds api-4's forward_only mark,
# api-7's forwarding Delegations with their sidecar and host client, and connect-1's delegations signed by a
# forwarding key.
# Each row gives service, store (tables, Redis families, object families, logs or memory),
# sees, why, ttl, and owner: the section that designs the value and states its ttl. Withdrawn rows keep
# their ids so citations resolve. Public: this list ships in DESIGN.md on the public sidecar repo (owner
# decisions 117, 118; §4.11) as D-TRUST-4's versioned document.
# File cluster: evs and gkm keep all durable state as objects in unversioned buckets, with no Postgres rows
# (owner decision 2); Redis holds only rebuildable soft state and verified caches (owner decision 136: evs-8,
# evs-24, gkm-10, api-7's {acl_}e); no backup of key slots or wraps (owner decision 90); no off-site copy
# (owner decision 94); the metadata tier grows by whole clusters, never pools, each repo placed on one at
# its creation (owner decision 145; evs-25).
# Postgres: sidecar tables, with the network, user and client rows they name, go to their own daily off-site
# dump, kept 14 days, tables whose ttl here is at most 7 d excluded, so a row outlives its ttl, or its hold,
# by at most 14 d; tables that exist today also sit in the main dumps for about 4 months (ops-2, D-TRUST-7).
# Redis: sidecar families (§19.7) stay out of the rdb bundles (D-OPS-16); other families sit in them for
# about 8 months (ops-3).
# Holds (owner decision 133; api-14, evs-19): a preservation hold keeps one network's in-scope rows and
# objects that exist at placement until its kind's deadline: 90 d, renewable once, or 1 year for a §2258A
# report (api-14). TTL sweeps, GC, drop jobs and gkm's reconciler skip them, and copied_rows copies what drops
# or is overwritten on its own: rows of partitions that drop whole (tls-3, smtp-3, mx-2) and the in-scope Redis
# soft state existing at placement (evs-8's lease fields, gkm-10's acks). It collects nothing new, and
# users' shredding (--now, the 7-day timer, per-entry erasure) always proceeds, a hold keeping only the
# ciphertext a shred leaves (§11.12); a drop is no user's shredding, and its deletions wait with no sign of the
# hold (owner decision 184; evs-19).
# gkm rows give §10.6's visible values, as owner decision 115 confirmed them.
connect-1:
  service: connect (relays, residents) and api's contract service
  store: transfer_contract, contract_close, contract_close_report (existing); the Redis contract-hole projection (existing)
  sees: source and destination client ids; contract ids; ProvideMode (Network, Service, FriendsAndFamily); roles, principal, source subject and source network, the contract class (control or data; §6.4) and the subject's WindowDelegation (subject, window client and key, target, expiry, share, its signer, the subject's identity key or its forwarding Delegation's key, and a share's ShareCert with its config generation, ShareSigner key and expiry, §17.9), all sealed in every mode (C13); per-party close reports (client, contract, bytes and the time each was received, a checkpoint at each idle receive-sequence exit among them), which pair the two clients; the contract-hole projection's client pairs
  why: route, authorize, settle and meter transfers; issue Service only for Find-recorded pairs (§6.10.1), and control contracts between any two admitted sidecars for witnesses (§6.4); debit relayed bytes (owner decision 10)
  ttl: contracts expire within 60 min; paid ones (shares) reaped 7 d after payout, unpaid ones (Network, Service) at 300 d (server/model/subscription_model.go:47-52); close-report evidence 35-91 d (server/db_contract_close_evidence.go:94); projection keys with their contract, and in ops-3's bundles
  owner: §6.10
connect-2:
  service: connect relays (residents)
  store: memory
  sees: per frame, the outer source and destination client ids, size, timing, sequence and acks; per-peer handshake certificates and public keys; sidecar payloads only as ciphertext (Required, I-3); ControlId frames unsealed (connect-4)
  why: carry and acknowledge transfers; set up e2e sessions (§6.9)
  ttl: relay memory while in flight; no frame or dial record (§21.9)
  owner: §6.9
connect-3:
  service: lb, connect residents
  store: memory; network_client_connection and network_client_location (existing; server/db_migrations.go:603-615, :689-697)
  sees: client IP and port of each transport (H1 wss, H3, DNS-tunneled carriers); per transport, as for every client today, a row with client and connection ids, connect and disconnect times, the resident's host, service and block, a SHA-256 of the client's /29 or /56 under a fixed pepper (server/ip.go:84-97), its port, IP version and family intent, and the location and network type its address maps to
  why: carry the transport; connection state and location; the ephemeral reaper's disconnect time (api-4)
  ttl: addresses in memory while connected, never logged in the clear (I-13, R-OPS-4), the lb's access log holding no client address; rows until 8 h after disconnect (server/taskworker/work/network_client_work.go:93), and in ops-2's main dumps about 4 months; URnetwork can invert the hash, whose pepper never rotates
  owner: §19.8
connect-4:
  service: connect residents; api (sync routes, long-poll)
  store: Redis {scp_<clientId>} ver (hash), hint (stream, MAXLEN ~256) and n (counter); long-poll cursors in memory
  sees: per client, topic versions and hints for core, team, sock, tls, mail, dns, gkm, gkm:<group_id> and evs:<repo_id>, each hint at most 256 B of server-held ids, kinds and versions or client-sealed bytes, never content; PushReset (at most 48 versions); which client syncs which topic, and when
  why: real-time push (X8 (b), owner decision 17); resync after gaps (§6.8)
  ttl: Redis keys 1 h (EXPIRE 3600 NX), outside the Redis bundles (D-OPS-16); versions live in their owners' stores; a poll cursor for one 25 s hold
  owner: §6.8
connect-5:
  service: connect relays (residents) and api's contract service, for §11.14's remote search (owner decision 175)
  store: none new; what connect-2's relay memory and connect-1's contract rows and close reports hold for the Network contracts, both directions, between an app host and an indexer it asks
  sees: per frame, the app host's and the indexer's client ids, size, timing and acks, every search request a 4,016 B body and every reply the requester's steps times 16,384 B, failures after parsing included, and a Ping and a Pong each minute while the app host is in the foreground; so when each "search more" and each further page runs, how many pages a search takes, and how long the indexer took to answer; from connect-1, for a pair that §6.11's bit 1 marks, its §6.10 windows, each direction's first contract created when the app host comes to the foreground, when the previous window ends while it is there, or when a search fails over to an indexer it had not warmed, and any other contract of a window created at a session re-establishment, which is at the search itself when a search finds the session lost before the next keepalive (owner decision 191), or at overflow; and one report a contract in both directions, sent at the window's end or at a suspended app's next run, of exactly 256 KiB on the window's first contract and 0 on the others (owner decisions 176, 188), so a window with up to five pages reports as one with none whatever its scheduled background, and 256 KiB plus 128 KiB steps when a sixth exchange, a second HeadCheckProof, or a stream or other RPC on a data contract overflows it; the floor itself shows api, since reports of exactly 256 KiB, or 256 KiB plus 128 KiB steps, mark the pair, that this app host's remote-search mode lets it ask that device and that the device serves search, which api-7 keeps sealed in the IndexerSet; never a query, term, filter, repo named, hit, snippet or result count, all sealed end to end (I-3, I-19)
  why: phones ask a designated indexer (owner decisions 175, 178) instead of downloading all partitions, which evs-26 would otherwise show
  ttl: relay memory while in flight (connect-2); contract rows and close reports as connect-1 (unpaid Network contracts 300 d, close-report evidence 35-91 d)
  owner: §11.14
api-1:
  service: api
  store: account, sign-in and payment tables (existing); network_idp_identity
  sees: user id, verified email or phone, sign-in methods, IdP identities (idp_id, sub), payment methods and balances, tier, verification state (network_verified, §21.7)
  why: sign-in, SSO, billing; the verification gate for public names and internet mail (owner decision 96)
  ttl: the account's life; IdP identities until removed (§7.11); existing tables also sit in the main dumps about 4 months (ops-2)
  owner: §7.6
api-2:
  service: api, dns
  store: network (existing; network_name), network_name_reclaim (existing), network_team, dns_label
  sees: network_id, network_name and its reclaim tombstones; the opaque label and the opt-in alias (owner decision 14), each with kind and state (live, retiring, tombstoned); team settings
  why: naming and routing (§12.5); takeover protection (I-14)
  ttl: labels and aliases never deleted (tombstoned), a changed alias retiring 90 d first (D-DNS-10); released names held 24 h (§7.12); team settings for the network's life (§7.5)
  owner: §12.5
api-3:
  service: api
  store: network_member, network_invite, network_idp, network_domain, network_scim_change
  sees: members (member_id, user, email, role, reauth_deadline, pending JIT state); invitations (hashed token, email, role, expiry); IdP configuration (issuer, client, vault-encrypted secret); verified domains and their daily checks; SCIM changes awaiting an admin (Team v1)
  why: sign-in, roles and SSO (§7.5, §7.6); groups, tags, device names and admissions live only in the config repo (owner decision 46)
  ttl: members until removed; invitations until accepted or expired, at most 30 d; IdP rows until removed; domains while verified, dropped after 7 failed days; SCIM changes at most 7 d
  owner: §7.6
api-4:
  service: api; connect (contract gate); taskworker (the ephemeral reaper)
  store: network_client (existing), network_client_owner, network_client.acl_subject_client_id, network_client_lease; proxy_device_config (existing hosted mark)
  sees: each client's id, network, parent (source_client_id), device_spec, create and auth times; owner rows (owner user, member, sponsor, auth key, tagged, ephemeral, admin_refused, strict_exp, acl_enforcing, declares_no_egress, forward_only); acl_subject_client_id; each ephemeral client's lease (seen_time, its newest poll, written at most once per 300 s) and the SHA-256 of its close capability; the hosted-device mark
  why: enrollment and token refusal (§7.4), contract gates (§8.10), client counting (§20.8); reaping ephemeral clients by their newest disconnect (connect-3) and lease, or at once by a close beacon's capability (§18.8)
  ttl: the client's life (top-level clients deactivated after 30 idle days and deleted 30 days later, children after 30 days unseen, §5.3); ephemeral clients, with no connection open, 30-36 min after their last poll and 35-36 min after their last disconnect (a 35 min threshold checked every 60 s), or at once on a close beacon (§7.7, §18.8); owner and lease rows go with their client
  owner: §7.7
api-5:
  service: api
  store: sidecar_identity, sidecar_identity_binding
  sees: sidecar_id, network_id, identity public key and algorithm, status, create and revoke times; append-only bindings (generation, client_id, client public key, dual signatures, time); identity lookups (GET /sidecar/identity/<sidecar_id>, caller and target)
  why: durable identity across the reaper; peer binding checks (§5.5, §6.4); git committer resolution (owner decision 81)
  ttl: never reaped; deleted with their network; lookups only in ops-1's logs
  owner: §5.15
api-6:
  service: api; connect residents; owning services; the push sender (taskworker)
  store: sidecar_push_token (with slot, the Redis hash slot of the client's {scp_} tag, rev, the row's revision, and removed_time; a removed token's row kept as a tombstone); Redis {scp_<clientId>}tok, {scp_<clientId>}tokrev, {scp_<clientId>}ack, {scp_<clientId>}live, {scp_<clientId>}hb, {wake_<clientId>} counters, {wake_<sidecarId>}, {wakeq_<shard>}, {tokgen_<n>} (taskworker's 16,384 per-slot sentinels)
  sees: each client's APNs or FCM token and platform, its row's revision and, after the client's removal, when it was removed; per Redis hash slot, the run_id of the master that served it at its last reconcile; wake requests (POST /sidecar/wake, caller and target device of one member); whether a client's resident is live, and whether its stack acked each wake-class hint; whether an HTTP-only client polled in the last 300 s; wake triggers (client, topic, version, hint id, due time); per wake the platform, token, topic class (mail, team, evs, core) and version, send time and vendor result
  why: content-free phone wakes from v0 (owner decision 88; §18.7, §19.4); the liveness of HTTP-only hosts, whose poll marker gates the reaper's lease row (api-4; §6.8, §7.10)
  ttl: tokens until replaced, or removed by an empty POST, on APNs 410 or FCM UNREGISTERED or with their client, each removal leaving a tombstone row (client_id, rev, slot; no token) and its tokrev, kept while the client lives and deleted 24 h after its removal; live markers 90 s, poll markers 300 s; no wake event stored (§18.7); token projections while the token lives; sentinels with no TTL, compared by taskworker's 60 s pass and rewritten when it reconciles their slot, outside the rdb bundles (D-OPS-16); acks 1 h; counters and the hourly wake key at most 1 h, triggers dropped after 60 s, metrics by platform, topic and result only (§19.4)
  owner: §18.7
api-7:
  service: api (verifier, token exchange) and every gate (CreateContract, sockets, tlsedge, certs, dns, smtpedge, mxedge, evs, gkm)
  store: proj/<network_id>/<n>/_ and projrows/<network_id>/<sha256>/_ (the first metadata cluster); network_acl_head; Redis {acl_<networkId>}v, {acl_<networkId>}e (owner decision 136's verified read cache, n -> AuthEntry bytes from the newest base on) and {acl_<networkId>}q (the append limiter's counters; §7.9)
  sees: "the authorization log's signed id-only entries (position, chain digest, kind, time), whose base headers carry the config head hash, folded_through, rows hash and threshold, and rows (members with roles and their recovery bindings newest first (key hash, reason) for the membership's life, sidecar admissions with identity keys, admission, revocation and park positions, the signer and position of each admission, AdmissionConfirm, OwnerConfirm, Delegation, recovery binding and key registration (§7.9's cascade), capabilities and each member device's live_since (the config leaf rank), member or keyed tag ids, ephemeral flags, expiry and sponsors, Delegations' signing and reader public keys, tag ids, max_admits and admissions, expiry, key drops and ends, and a forwarding Delegation's sidecar and host client id and key (owner decision 197), registered presence and SSH public keys with member and purpose, Team scope labels) and their AclRows (has_document; keyed tag and group atoms mapped to member and sidecar ids; rules with targets, actions, ports, the CIDRs of ip targets, socket token paths, public names, audiences, publish rules' application modes (http or raw) and raw link grants' client-certificate SPKI SHA-256, which a requested grant's GrantActivate also shows (§8.4, §13.7, §16.6), and expiries; request rules with approver atoms (autogroup:dst-owner among them) and counts, expiry bounds and evidence channels; repos with kind, owner member, the owner's consented sidecar ids, folded access log with its versioning lock (its rules stay sealed), each EvsShare's signer, position and expiry, and holders_shrunk_at; BridgeRows egress modes; the audit reader and its AuditOptIn); statements with their types, headers (signer's pin, nonce, expiry) and signatures, presence countersignatures with evidence and act path: scoped admissions by a member's consented device or recovery key (owner decisions 112, 126), revocations (reason, and since_n for a compromise or a leak), OwnerConfirms and AdmissionConfirms, recovery bindings and rebinds as ids (member, signer, reason, the new and replaced recovery Ed25519 keys' hashes), the rest, X-Wing key and genesis signature included, sealed, authority proposals, cosigns and vetoes, recovery-signed ones and a restored binding's admission proposals included (owner decisions 127, 149), grant activations and revocations, suspensions and unsuspensions, EvsShares, repo access-log statements, SponsorSets, key registrations, indexer designations as ids (signer, subject, scope, retire; services sealed; owner decision 150), and bridge statements as ids (kind, signer, subject, rule id, expiry; an approved route's advertiser and rules) with sealed bodies; a team directory approval's grant only as its RepoGrant, EvsShare or GrantActivate, naming no request (§16.11); api's ticks: reaped ephemeral sidecar ids and activated proposal ids; admissions under a member outside its consented ids show its parked devices (owner decision 126); together, the reach graph; each network's newest position and statement and base counts per minute and day for the append limits; the config repo itself only as evs ciphertext"
  why: one order for every authorization change; server gates without policy text or names, owner consent included (owner decisions 5, 72, 126; §7.9, §8.8); the cache, written only by api after each append and checked by readers against their pins, spares cluster reads and decides nothing
  ttl: entries from §7.9's retention point, min(the previous base, the newest base's folded_through + 1), for the network's life, re-uploaded verbatim by devices after a site loss at unchanged positions (§7.9, §19.10); a network newer than both dumps at a Postgres restore takes the deleted-network path, its proj/ and projrows/ objects deleted with the last of its repos' shreds (§19.10); older entries, and rows no retained base names, 30 d after the newer base; network_acl_head with its network; {acl_}v 48 h after its last change; {acl_}e 10 min after the network's last append; {acl_}q 25 h
  owner: §7.9
api-8:
  service: api
  store: network_admin_event, network_audit_webhook
  sees: admin events (per-network seq, actor, action, target, result, request id, hash chain; no client IP), DNS user and key writes included; SIEM webhook endpoints and deliveries
  why: audit (§7.11)
  ttl: 400 d; deliveries retried 24 h; webhook settings until removed
  owner: §7.11
api-9:
  service: api; CreateContract
  store: network_acl_share, network_bridge_share
  sees: "invites (hashed 256-bit code, uses, 7-day window, inviting and accepting networks); bridge shares (share_id, both network ids, target and alias tables sealed under a key the code derives and the server cannot, versions, accept status: active, refused as too large or refused for no space, §17.9); the paying (dialing) network"
  why: two-sided consent; FriendsAndFamily contracts with source-pays escrow (§8.11, §17.9; owner decisions 11, 86)
  ttl: an invite until its uses run out or its window closes; a bridge share until revoked (§17.16)
  owner: §8.11
api-10:
  service: api and the server gates (sockets, dns, certs, tlsedge, smtpedge)
  store: memory at the gate; approval_use; inside api-7's statements
  sees: server-gated ApprovalDecisions (approval id, request hash, payload hash, decision, uses, expiry, approver member, evidence channel (device, presence or harness), SSHSIG, evidence hash, signer key, the requester sidecar id (the bearer's own) and the approver's projection pin) with the canonical action's fields that gate already sees (host, port, audience, expiry), each carried by a GrantActivate or presented with its action; ApprovalCancels (approval id, signer); per use, in approval_use, its index, effect key (a hash, the action's Idempotency-Key), state (done or cancelled), result and time; run and agent ids, recipients and previews stay sealed
  why: server gates for outward actions, each use consumed once, in the effect's own transaction (§8.10, §16.6; owner decision 75)
  ttl: decisions in gate memory only, a requested grant's also inside its GrantActivate (api-7; §8.10); approval_use rows (ids, hashes, state and result only) 1 d after the decision's not_after; the action's admin event, where §7.11 logs one (api-8)
  owner: §8.10
api-11:
  service: api (issuer auth.bringyour.com)
  store: network_auth_key, network_oauth_client, account_api_key (scopes, expiry, creator), auth_code (api_key_id), admin_token_use; Redis {dpop_<client_id>} (proof jti); api's service log
  sees: auth keys (hashed secret, creator, tags, expiry, uses, ephemeral, pre-approved); network OAuth clients (hashed secret, scopes); API-key scopes, expiry and creator; token exchanges (client, subject client, sidecar, member, audience, scope such as repo:<id>:rw, projection version, act, the DPoP key); DPoP proofs' jti and key thumbprints; admin tokens (member, scopes, command digest, 1 h) and their uses (jti, member, command digest, result, time); edge logins for members audiences (member, network, published origin, time, nonce)
  why: authenticate and scope access (§7.8); proof of possession (§7.4); evs and gkm capabilities (owner decision 2); members-audience logins (owner decision 42)
  ttl: credentials until revoked or expired (auth keys at most 90 d, API keys 365 d, legacy API keys until revoked); auth codes die with their api_key_id; tokens never stored; {dpop_} jti keys 120 s; admin_token_use rows 1 h after the token's exp; exchanges and edge logins only in api's 7-day service log (ops-1)
  owner: §7.8
api-12:
  withdrawn: bridge rules, the overlay /16, LAN prefixes and port maps live in the config repo (owner decision 5); gates see api-7's ids and egress modes
api-13:
  service: api, taskworker; the edges (leases); evs (usage batches); CreateContract (relayed reservations)
  store: transfer_balance.tier, network_sidecar_limit, network_quota_state, network_service_usage, service_debit_journal, service_usage_batch, stripe_meter_report (with version, attempts and next_time); Redis {sq_<network_id>}; lease reservations, and relayed sidecar contracts' reservations made at CreateContract (§20.6), in escrow's per-balance Redis reservations (existing)
  sees: each network's tier; limit overrides (key, value, a reason citing an ops change or §21 case); quota state (stored bytes, storage_over, spent time); daily usage per network and meter (edge leases, evs transfer, relayed bytes, seats); debit journal rows (usage, balance, meter, bytes, batch, applied); usage batches (batch id, producer, window start, applied time); Stripe meter reports (network, meter, day, identifier, value, state, version, attempts, next send); rate counters, among them each erasing sidecar's closure bytes for the day (owner decision 146); edge leases (network, meter, 64 MiB reservations, 16 MiB on Community); per relayed contract its reservation, grant and settled bytes
  why: quotas, transfer-balance debits (owner decision 10), Team billing (owner decision 92; §20)
  ttl: counters 48 h; daily usage and meter reports 13 months; debit rows until applied; usage batches 24 h; overrides until lifted; quota state until its network is deleted; leases and relayed reservations until closed, settled or expired
  owner: §20.14
api-14:
  service: api (abuse role), the taskworker abuse worker
  store: abuse_case, abuse_action, abuse_appeal, network_abuse_state, abuse_legal_hold, abuse_access_log, legal_request
  sees: abuse cases (category, target host, label or network, join keys, reporter class), actions (kills, halts, suspensions, cap tightening) and appeals with reviewers' reasons; each network's standing; holds (network, kind, scope, case, expiry) and their copied_rows, the in-scope records that drop or are overwritten on their own, namely rows of partitions that drop whole (tls-3, smtp-3, mx-2) and the Redis soft state existing at placement (evs-8's lease fields, gkm-10's acks); legal requests (instrument, country, accounts, productions, sealing orders); every abuse-role read; reporters' third-party data only until the join (§21.8)
  why: abuse handling, legal process and preservation (§21; owner decision 133)
  ttl: "cases, actions and appeals 13 months after the case closes; legal requests, productions and the access log 3 years; holds, with their copied rows, until their kind's deadline: 90 d plus one 90 d renewal, or 1 year for a §2258A report (§21.9); standing only while current"
  owner: §21.10
api-15:
  service: api
  store: network_acl_ack
  sees: per client, the projection version it applied and when (POST /acl/ack)
  why: propagation targets and drift alarms (§8.9)
  ttl: 7 d
  owner: §8.9
sock-1:
  service: sockets
  store: Redis {sg_<network_id>_<h16(name)>} (listener fields m, r, i and e; version v) and its lease-ordered ZSET (suffix ix)
  sees: network_id; the name as a token path (16 B a segment, HMAC under a key from the config repo's K_sock, owner decision 67) or, for tls/, smtp/ and ur/, in plaintext; per listener the sealed name, client_id, listen_id, protocol, version, ALPN, application mode (http or raw, and a raw endpoint's authentication mode), weight, max_streams, flags (exclusive, affinity, serving, draining), reported in-flight and issued counts, ejection state and its Signed claim (the sidecar's identity key); the group version
  why: Find, scheduling and sampling (§9.5-§9.8)
  ttl: 45 s lease renewed by heartbeat; ejections at most 300 s; a K_sock rotation's 10 min dual registration links old and new token paths; outside the Redis bundles (D-OPS-16)
  owner: §9.5
sock-2:
  service: sockets
  store: memory; per-dialer fields in sock-1's hash
  sees: each Find's dialer client and network (edges add their K client ids), token path or edge name, affinity key (tlsedge's keyed /24 or /48 hash, never stored), the authorization log position that allowed it (§7.9), chosen listeners, grant id, issued tickets and the failed tickets a retry reports; each dialer's issued share and exclusions; reported accept timeouts; per-source registration and Find rates for the control-plane bound (memory; D-SOCK-15)
  why: admission, scheduling and outlier ejection (§9.6, §9.7)
  ttl: the request; tickets 30 s; dialer shares and exclusions at most 300 s; no per-dial record (D-SOCK-9)
  owner: §9.6
sock-3:
  service: sockets writes; CreateContract reads
  store: Redis {svc_<listener_client_id>}
  sees: Service-contract pairs, field the dialer client (an edge's platform client, or a sidecar dialing ur/), value the grant expiry
  why: CreateContract issues Service only for a pair Find recorded (§6.10.1, C9)
  ttl: the grant's expiry, at most 24 h (ur/ 60 min), refreshed per Find; deleted on revocation or the last edge unlisten
  owner: §9.6
sock-4:
  service: sockets
  store: Redis {sn_<network_id>}names
  sees: a network's registered token paths and edge names, with sealed names, for listing
  why: GET /socket/list; clients unseal names locally (owner decision 67)
  ttl: entries leave with their leases
  owner: §9.8
sock-5:
  service: sockets
  store: Redis {sc_<client_id>}set
  sees: a client's set_version and registered entries
  why: idempotent full-set calls; removal on the client's removal signal (§9.5, §9.8)
  ttl: 5 min after the client's last call
  owner: §9.8
evs-1:
  service: evs; gkm reads it
  store: repo/<repo> (metadata cluster)
  sees: repo_id; kind (general, record, config, team_record, mailcfg, vault, mailbox, secret; directory, one per team network); owner member of an owner-bound kind; state (keying, active, deleted, shredding, shredded, each with time, signer and deletion id); object format (1, or 2 from a repo's first push carrying a format-2 value, such as a versionless file or a DROP; §11.6); sealed display name; its network, from the projection
  why: lifecycle, kind rules, the lifecycle check every push reads, deletion and restore (owner decision 82)
  ttl: "the repo's life; a deleted repo, a repo of a network newer than both dumps at a Postgres restore included (§19.10), is shredded after 7 d, or at once with now, under a preservation hold too: slot/, then its gkm objects, {gka_} acks and recovery wraps, then every other object (a hold defers only this step, over unreadable ciphertext that evacuation still moves from shared batches into packs and parcels), none of which a fold, evacuation or gkm write that began earlier re-creates; then repo/<repo> becomes a shredded tombstone for the network's life (owner decision 133; §11.12)"
  owner: §11.8
evs-2:
  service: evs
  store: the ref_id inside head/, log/, idx/, pmap/ and pidx/ keys, pb/ records and {evsl_} lease fields; EvsPush fields
  sees: ref ids, HMAC-SHA256 of the ref name under a key from RK_1 (never names; guessable names testable by holders of RK_1, §11.5); each ref's kind (shared, owned, deposit), mode (git, file), owner sidecar_id and overlay base; deposit refs' ids, the first 16 B of SHA-256(repo_id ‖ sidecar_id), which name their depositor
  why: ownership and ref rules; record refs refuse FORCE and DELETE; git-mode refs commit only on their tip (owner decision 141; §11.8)
  ttl: as the ref's head and history (evs-3, evs-12, evs-14)
  owner: §11.6
evs-3:
  service: evs; taskworker writes evacuation and GC fences, source drops and collection windows (§11.6, §11.7, §11.13)
  store: head/<repo>/<ref> (metadata cluster); a verified copy in Redis {evsh_<repo_id>} for 10 min (evs-24)
  sees: "the commit point; version v, chain C_v, sealed ref name, overlay base, whether a committed DELETE left it a tombstone (deleted), path epoch with its listed sources, any due epoch and a mapper's creation block with its end (block_until_ms); the authorization pin (AuthPin: projection version n and chain A_n, §7.9) and generation pin (group, generation, C_g) of the newest commit; a window of the last 64-127 versions' entries (push id, statement hash prefix, the batch place of its statement and payload, an 8-byte digest of its changed token paths, flags, one marking a push that replaced or removed versionless versions and one a DROP push; at most 255 while folds lag); the chain before the window, the newest folded version (folded_through) and the time of its last write; the fence counter, the writer's clock at the newest evacuation or GC fence (fence_ms), and any seal lease; up to 8 refusal records, each a refused push id's first 8 bytes, its statement hash's first 2, the refusal's code and when the record lapses (until: the statement's time bound plus 1 s), and the writer's clock at the newest refusal fence (refused_ms); for a refused push that would have created its ref, a placeholder head at version 0 holding only those records; on a ref holding a search index, its index_epoch, the version of its newest CUT (§11.12); the marker collection (EvsCollect: done, the removal version through which markers are collected; the latest window's through, its newest removal version, and until_ms, its end, 30 s after it opens; §11.7)"
  why: If-Match commits; readers trust only committed push ids; hints to subscribers (§11.8, §11.10); collection windows keep folds from writing over the markers taskworker is deleting, so no DELETE removes a newer entry (owner decision 148; §11.7); the DROP bit lets evs refuse pushes citing a version a drop in the window lists (owner decision 173; §11.8); refusal records keep a refusal true for every later attempt of its push id, however late it reaches evs (§11.8's outcomes); the index epoch refuses an index push built before an erasure's CUT (§11.12, §11.14)
  ttl: the ref's life, a DELETE leaving a tombstone head and a refused creation a placeholder head, which stays as a tombstone does; a refusal record until the first head write after it lapses; older versions page into log/ (evs-14)
  owner: §11.8
evs-4:
  service: evs; the segment cluster
  store: seg/<repo>/<segment_id> (segment cluster)
  sees: segment id (SHA-256 of its bytes), Padmé-padded size up to 8 MiB, 32 B public header (format, flags, repo_id, generation), uploader client and sidecar, upload time, whether it came as an erasure's closure upload (?closure=1); upload receipts (repo, segment id, padded size, upload time, uploader sidecar, whether its header is a kind-5 header), MAC'd by evs, held by the client and returned with its push; the ranges each client reads, which for the search index's files show evs-26's view; kind-5 (versionless) segments, each one record of one version of one path, its 48 B header also naming its introducing push, uploaded with a receipt or written at evacuation from a staged copy in its push's batch (evs-22), and when each is deleted, about a minute after its version's replacement commits, which the change history already dates; which kind-1 segments only executed drops' listed versions name, and when the drop's job deletes each (evs-28)
  why: storage, quota, GC (§11.6, §11.13)
  ttl: "while a retained push names it, then 7 d; an upload no committed push adopted: deleted 25-49 h after its upload, once its repo's idle refs are fenced; a kind-5 segment until about a minute after the push replacing its version commits, at most ~26 h when its committing process failed (evacuation's sweep), at its marker's collection when its removing push did not list it (evs-11), or, existing at a hold's placement, until the hold ends (§11.13); a kind-1 segment that only executed drops' listed versions name, though their pushes stay: deleted after its drop's window (7 d, or about 25 min with now) once over 25 h old, unless a hold covering the repo keeps it until the hold ends or a pack until compaction, and never served once the job's delete set names it (§11.13)"
  owner: §11.13
evs-5:
  service: evs
  store: slot/<repo>/<slot_id> (metadata cluster)
  sees: slot id, up to 64 wrapped object keys (ciphertext), size up to 8 KiB, times; deposit keys HPKE-wrapped to the drop key; ERASE statements (signer, slot ids and key indexes, time); in slot-keyed repos (record-class repos, group inboxes), slots that only one versionless path's versions name, each holding that path's one key, and their deletion; slots that only executed drops' listed versions name, and their deletion by the drop's job (evs-28)
  why: per-entry erasure for record-class repos and mail (owner decision 61); a drop's slot deletions (owner decision 173)
  ttl: until erased (rewritten at once without the erased keys, under a preservation hold too; owner decision 133), consumed (a deposit's, by its CONSUME; evs-6) or shredded with the repo; a refused or dead push's new slots until evacuation finds it dead, at most about 26 h after its batch (§11.8, §11.13); never backed up (owner decision 90); owner devices' mirrors keep sealed copies until their next sync after an erasure (§11.13); a versionless path's slot until about a minute after no retained version names it (its removal, or a fresh key at a CLOSURE, a rekey or its first write after a reader's removal; §11.7), at most ~26 h when its committing process failed, at its marker's collection when its removing push did not list it (evs-11), or, existing at a hold's placement, until the hold ends (§11.13); a slot that only executed drops' listed versions name, as evs-4's kind-1 segments (§11.13)
  owner: §11.12
evs-6:
  service: evs
  store: deposit-ref entries in evs-11's, evs-12's, evs-4's and evs-5's objects
  sees: deposits (entries under random ids, padded size, time, the depositor through its deposit ref, MailDeposit headers sealed), each with a slot; receipt deposits by readers of owner-bound repos, at most 4 KiB each and 256 a day per repo (§16.8); the CONSUME that deletes them and their slots
  why: write-only deposits from receivers and headless agents (§11.12, §15.7); read receipts (§16.8)
  ttl: until a reader with rw consumes them; unconsumed deposits are lost with the site (§2.18)
  owner: §11.12
evs-7:
  service: evs
  store: evs's service log
  sees: request log; caller ids, route, repo and ref ids, ranges and slots read, bytes, status, time; for the search index's files, evs-26's view; drop dry runs and drop listings by route, DROP pushes and their cancels as pushes (evs-28)
  why: rate limits, abuse, debugging; attests audit-member reads (§16.8)
  ttl: 7 d
  owner: §11.8
evs-8:
  service: evs
  store: Redis {evsl_<repo_id>} (holder, ref, path epoch, prefix -> expiry) and {evsl_<repo_id>}v
  sees: per client, the repos, refs, path epochs and up to 16 token prefixes it follows
  why: change notification (PLAN.md:55; owner decision 2)
  ttl: 7 d after the last renewal, each lease renewed once it is over 24 h old, never on a reconnect (§11.10); soft state outside the rdb bundles, re-created by holders after a loss (owner decision 136); a hold's copy excepted (api-14)
  owner: §11.10
evs-9:
  service: evs and taskworker's drop jobs report; api stores
  store: api-13's rows, through ServiceHost.Quota.ReportUsage
  sees: in 60 s usage batches, transfer bytes per caller network and stored-byte deltas per repo network, a drop job's as it deletes included; the over-limit list evs reads every 5 s
  why: soft storage quotas and transfer debits (owner decisions 2, 10; §20.6)
  ttl: as api-13; stored bytes counted nightly by §20.7's stored rule (§11.13)
  owner: §11.13
evs-10:
  service: "the file cluster (MinIO: the metadata clusters and the segment cluster); taskworker's write-budget governor"
  store: every object in every bucket; Redis {nvb_<set>} and {nvb_<cluster>}
  sees: every evs, gkm, place/, proj/, projrows/, rev/ and hold/ object key with its size, checksum, times and access pattern, on an NVMe metadata cluster (one 8-drive PM9A3 set at EC:4, owner decisions 116, 136-139; a repo's objects on the cluster its place/ names, owner decision 145) or the HDD segment cluster (EC:8; owner decision 116); requests come only from evs, gkm, api and taskworker over the LAN, never from clients (D-OPS-4); per metadata set, the write budget's bucket level, floored at zero, calibration, allowance and accounts, its prepaid P2 wallet, each process's 5 s report (queued P1 and P2 priced bytes, credit moved and spent, P0 bytes by kind) and the P0 figures, P0's forgiven excess among them, and liabilities §19.8 exports, and per segment cluster, its drive operations a second and measured capacity (§19.6's hdd row), all from drive counters and process totals, with no network or repo id
  why: durable ciphertext storage (X13; owner decisions 18, 21, 94, 116); drive endurance (owner decision 140; §11.13)
  ttl: each object's own row; deletes and overwrites keep no prior version (unversioned buckets); no off-site copy (owner decision 94); request logs as ops-1; {nvb_} 15 s, but the write budget's saved bucket level, wallet and counter readings 48 h after the loop's last write
  owner: §19.6
evs-11:
  service: evs; taskworker's path-epoch copy and marker collection (§11.6, §11.7)
  store: idx/<repo>/<ref>/<p>/<t1>/.../<tn>.e (metadata cluster)
  sees: "path index; tokens t_i = HMAC-SHA256(K_path_p, t_(i-1) ‖ name_i)[:16], so keys show the tree's shape (depth, fan-out, files per directory) and per-file change history, and one path has one token on every ref of a repo within a path epoch; each entry's up to four committed versions, folded from committed pushes (the newest with its inline body), and no pending versions (entry version, push id, base version, previous push id and committed version, layout, time, kind, padded size, versioning setting (0 kept, 1 versionless, 2 the search index's; owner decision 168), sealed fields, chain locators (kind 5, staged or not, for versionless versions) and slot ids, or an inline body up to 16 KiB); a DROP's fold leaving a path's entry only its through_version, with the drop mark {drop_id, through_version}, which path-epoch copies carry; for each path a removal at r removes, a removed directory's current-epoch entries below it included, a removed-entry marker {removing push id, r, the path's version: one past its last} (§11.7), with, for a versionless file its removing push did not list, the kind-5 segment and slot ids its collection deletes; while the head lists sources, each entry's state in its object metadata, which reads HEAD at a path's prefixes: carried (from the source it names), fresh (new to the current epoch since the cut-over) or removed (its marker); per directory a name table of child tokens, kinds, a carried row's source epoch (§11.6) and individually sealed names padded to 64 B steps; at most 4,096 children and 448 KiB of name table"
  why: one-round-trip head reads, sparse fetch, prefix LIST, token-prefix subscriptions (owner decision 2); markers, written If-Match (If-None-Match on a 404) only over an entry holding an older version, so no repeated, queued or late removal fold writes over a newer entry, and a creation's entry version is max(its push's effective base version, a standing removal's) + 1, an overlay's base counting its chain's base versions (§11.7), so a path's versions never restart (owner decision 148); the drop mark keeps a listed version from being cited again (owner decision 173)
  ttl: the path's life; a marker until a re-creation's fold replaces it or, once folded_through >= r + 64 (a base range past the removal, so no push based before it can commit) and the head lists no source, taskworker's nightly pass deletes it in a collection window (evs-3; §11.7); a source epoch's markers are deleted unmoved when its copy ends (§11.6); up to four folded committed versions, older ones dropping at the next fold (§11.7). Never names or cross-repo equality (K_path is per repo); holders of a K_path, a removed reader included, can test guessed names created before the next path epoch, no source-epoch token of a later name reaching the server (§11.6)
  owner: §11.7
evs-12:
  service: evs
  store: push, part, seal and reseed records in pb/ batches (metadata cluster; evs-22), then in pack/ (evs-16) or hp/ (evs-23)
  sees: "Signed EvsPush cleartext (repo_id, ref_id, ref kind and mode, owner sidecar_id, push_id, base version and chain, changes of token path, base entry version and entry hash, at most 1,024 entry writes a part, sealed-metadata hash, generation, path epoch, projection version and chain (the auth pin), the generation pin (group id, generation, commitment), a Merkle root and count over the changes with covering token prefixes when they are not inline, the new-objects hash (segment ids with padded sizes and upload days, new slot ids, listed in the payload), a PATH_EPOCH's map source version and chain and tail hash, while sources stand a source-paths hash, an ERASE's or CLOSURE's erased-list hash (a CLOSURE's equals the ERASE's that follows it, so evs links the re-keyed path to that erasure), a DROP's drop_sha256, signer sidecar_id, client_id, time, flags FORCE, DELETE, BASE, IMMUTABLE, CONSUME, PATH_EPOCH, ERASE, CLOSURE, DROP or CUT, an index push's or CUT's index_epoch (the version of the newest CUT it follows), path-map hash, part count and part hashes); per part (up to 1,024), its EvsPushPart and the head version evs checked it at; cleartext entry versions; a PATH_EPOCH payload's tail moves (old and new token paths), which link created paths across epochs as evs-15's maps do; while sources stand, the payload's source paths: each change's token path in every listed source that may hold it, never for a name created since the cut-over (§11.6); sealed commit metadata; inline records; repo admins' EvsReseed statements (repo, ref, re-seeded version and chain, incident id; §19.10); with evs-3 and evs-14, the push DAG and per-file change history (token, time, uploader, padded size); which records one evs process wrote together within 20 ms; per entry version its versioning setting and kind-5 locators; the new-objects list's staged marks and the staged segments' bytes (ciphertext, one record padded to at most 16 KiB each); removals listing each versionless file below a removed directory or deleted ref; each record's purge candidates (segment and slot ids, derived by evs); DROP payload bodies (drop id, action, a cancel's drop id and version, not_before_ms, preview id, and per path lineage its token path in each epoch with their map parts, through_version, boundary, count and list hash) with their listed entry hashes, names and reasons sealed in commit metadata"
  why: commits, multi-part pushes, history, GC, audit, re-seeding (§11.8)
  ttl: "history, the repo's life by default; record-class repos per §16.8's retention through BASE; in batches 25-26 h, then packed hourly once a repo's aged material reaches 256 KiB, else held in parcels until 7 d (owner decision 136; evs-23); dead and duplicate records, and a shredded repo's unless a hold keeps them (evs-19), until their batch is evacuated: at most 26 h after the batch was written; staged bytes leave with their batch, at most 26 h, written to seg/ (evs-4) while their version is retained, else dropped, never into packs or parcels; a replaced versionless version's statement and entry version stay as history; a dropped version's statement stays as history, and its entry version stays served unless its chain names an inline record, in which case both stay stored, never served again, until compaction (§11.13)"
  owner: §11.8
evs-13:
  service: evs, gkm
  store: memory (verified per request)
  sees: capability tokens (aud evs or gkm, scope repo:<id> with role deposit, r, rw or admin, or recovery:<member_id> for an unadmitted device's own recovery wraps at gkm (§7.8), projection version, client, subject client, sidecar and member ids, act), 15 min, verified offline against api's svc- keys; during a site-loss restore (sidecar.yml's reseed), only admin tokens for the re-seed routes, to sidecars the restored rows list under their network's admins (§7.8, §19.10)
  why: authorization without Postgres (owner decision 2; §7.8, §11.8)
  ttl: 15 min; never stored; issuance as api-11
  owner: §11.8
evs-14:
  service: evs
  store: log/<repo>/<ref>/<n> (metadata cluster)
  sees: "history pages; versions 64n to 64n+63: their Signed EvsPush statements, DROP pushes and their cancels included, and each version's window entry (as evs-3), and C at the page's ends"
  why: settle push ids past the head's window; history for replaying readers (§11.8)
  ttl: history, the ref's life; packed with evs-12's records after 24 h, or with a small repo's other aged material at 7 d (owner decision 136; evs-16)
  owner: §11.8
evs-15:
  service: evs
  store: pmap/<repo>/<ref>/<p>/<map_sha256>/<part>/_ (metadata cluster)
  sees: Signed EvsPathMap parts (repo, ref, path epoch, part numbers, the source head each map covers, moves of old token path to new token path with names re-sealed, and every live path's token in each source epoch), up to 8 MiB each, and their signer; they link every moved path's tokens across epochs
  why: path-key rotation on removal (owner decision 2 item 9; §11.6); keyed by the map's hash, so a mapper whose source left the window uploads a fresh map
  ttl: the committed map, the ref's history; the epoch's other maps deleted once it commits, and an uncommitted one by the nightly pass 25-49 h after its upload (§11.6)
  owner: §11.6
evs-16:
  service: evs; taskworker packs
  store: pack/<repo>/<pack_id> (segment cluster)
  sees: packs of log pages and push, part and seal records, older than 24 h, packed hourly once a repo's aged material reaches 256 KiB, else once its oldest is 7 d old (owner decision 136), with their SHA-256; reads by range
  why: keep history older than 24 h off the metadata cluster (owner decision 136; §11.13, §19.6)
  ttl: history
  owner: §11.13
evs-17:
  service: evs
  store: pidx/<repo>/<ref>/<v_first>-<pack_or_parcel_id> (metadata cluster)
  sees: a pack's or parcel's offsets for the versions and log pages it holds, the record kinds it holds, and the segment ids its records introduce
  why: find packed or parceled history (§11.13); one entry per container, so a pack's entries never collide with its parcels'
  ttl: as its pack or parcel; a parcel's entries go with it, after its pack's entries exist (§11.13)
  owner: §11.13
evs-18:
  service: api writes; evs and gkm read
  store: rev/<network_id>/<kind>/<subject_id>/_ (the first metadata cluster)
  sees: revocation objects for a client, sidecar or member; a JWS under api's svc- keys with subject, not_before, reason and time
  why: void 15-minute tokens on removal, deactivation, suspension or revocation (owner decision 2; §7.8)
  ttl: 20 min after its last write; after a site loss api re-creates live ones from its tombstones (§19.10)
  owner: §7.8
evs-19:
  service: api writes; evs, gkm and taskworker read
  store: hold/<network_id>/<case_id>/_ (the first metadata cluster)
  sees: preservation holds mirrored from abuse_legal_hold (network, kind, scope, case id, expiry)
  why: the server's TTL sweeps, retention, GC and gkm's reconciler skip held networks' in-scope objects, and evacuation moves their batch records, a shredding repo's included, into packs and parcels that nothing deletes while the hold stands; user-initiated shredding (--now, the 7-day timer, slot erasure) always proceeds, and the versionless purge keeps in-scope content that existed at placement while purging content created since (owner decision 133); a drop is no user-initiated shredding, and holds keep its deletions waiting, silently (owner decision 184; §21.9)
  ttl: "its kind's deadline: 90 d, renewable once, or 1 year for a §2258A report (api-14)"
  owner: §21.9
evs-20:
  withdrawn: no upload markers; evs MACs a receipt the client returns with its push (evs-4; §11.13)
evs-21:
  service: evs, taskworker
  store: spidx/<repo>/<n>/_ (metadata cluster)
  sees: offsets of segments moved into a pack (reserved, empty in v0)
  why: packed segments stay addressable by id (§11.13)
  ttl: as its pack
  owner: §11.13
evs-22:
  service: evs; taskworker evacuates
  store: pb/<yyyymmddhh>/<mm>/<instance>-<seq> (metadata cluster)
  sees: batches; per batch the writing evs process's id, sequence and time, and evs-12's records with each one's repo, ref, push id, signer, type (push, part, seal, reseed) and offsets; which records one process wrote within 20 ms; inside records, staged versionless segments and purge candidates (evs-12); the batch format (1, or 2 when it holds either)
  why: "group commit: one write per batch instead of per push (owner decision 140; §11.8)"
  ttl: until hourly evacuation, at most 26 h, a bound §11.13's write budget keeps under load by serving evacuation of batches past 25 h first within P2, except while P0 holds the bucket empty (owner decision 186), when evacuation waits and batches stay until the wave ends, evacuation then restarting, oldest first, as the bucket refills (owner decision 190); deleted whole (§11.13)
  owner: §11.8
evs-23:
  service: taskworker writes; evs reads
  store: hp/<repo>/<parcel_id> (metadata cluster)
  sees: a small repo's records and log pages older than 24 h, with their offsets
  why: keep small repos' aged history on NVMe until it reaches 256 KiB or 7 d, without tiny HDD objects (owner decision 136)
  ttl: until packed, 7 d after its oldest record's commit plus at most an hour; shredded with the repo
  owner: §11.13
evs-24:
  service: evs
  store: Redis {evsq_<repo_id>} (push sequence), {evsh_<repo_id>} (verified head cache)
  sees: each repo's push sequence; copies of its heads (evs-3), their ETags and cache times, and the sequence value each ref's last commit raised, which GET .../refs?moved_after= reads (§11.9)
  why: hint versions without a repo/ write per push; fewer cluster reads (owner decision 136; §11.10)
  ttl: the sequence 30 d after its last commit, restarting above every earlier value after a loss; a head copy served only within 10 min of its own cache time, the hash expiring 10 min after the repo's last write; outside the rdb bundles (D-OPS-16)
  owner: §11.10
evs-25:
  service: evs creates it; evs and gkm resolve and cache it
  store: place/<repo_id> (the first metadata cluster)
  sees: which metadata cluster holds a repo's objects and its gkm group's, set once at the repo's creation (If-None-Match decides a race)
  why: the metadata tier grows by whole clusters while each repo keeps one commit point (owner decision 145; §11.8, §19.6)
  ttl: as repo/<repo> (evs-1)
  owner: §11.8
evs-26:
  service: evs (pushes, head reads, listings and range reads, §11.8, §11.9) and its service log (evs-7)
  store: none new; what evs-3's head windows, evs-12's push records, evs-11's entries, evs-4's segments and range reads and evs-7's request log hold for the search index's files, which their versioning value 2 (owner decision 168) makes recognizable (evs-11)
  sees: from pushes, which paths hold each repo's index (one versionless directory per indexed file-mode ref, or the ur/index ref), each indexed push's staged head overwrite, whose padded size step shows roughly how much text it indexed, a shard rewrite per ~128 KiB of entries, a bulk removal and shard rewrites once a bucket length (the roll-up, rarely with one newer bucket's file rewritten in place), CUTs and CLOSUREs at erasure (a CUT's staged rewrite of its ref's erasure set, whose padded size steps with the documents its pending erasures hold, and a 409 INDEX_EPOCH for each index push it outdates), and on ur/index companion pushes trailing content pushes by up to a minute on 1 KiB blocks, else five minutes (owner decision 172); from reads, per client, which index files of which repos and refs it reads, at which versions and ranges, and when; so which repos it keeps searchable, whether it keeps a repo's all partition (desktops and indexers at each roll-up they do not reproduce; phones in background windows on Wi-Fi while charging, and a browser tab while open on Wi-Fi while charging, where its browser reports both (§18.4)), and, for an ephemeral sidecar's first sync of a repo or any fetch of all at "search more" that no indexer answered (a phone or browser tab that has not kept all, an ephemeral sidecar or a cloud agent), that its person or agent searched, and when; a "search more" an indexer answers shows evs nothing (connect-5); the documents it opens soon after, and the candidates `ur search --verify fetch` opens, as ordinary reads whose set follows the query; nothing else of a query, term, candidate, result or result count, since index files are fetched by sync position, all whole in a fixed order, documents only when opened, and nothing is compressed across documents (I-19)
  why: search runs only on devices, over whole downloaded partitions, so no server takes part in a query (owner decisions 151, 154, 166)
  ttl: as evs-3, evs-4, evs-11, evs-12 and evs-7 (7 d); nothing beyond them
  owner: §11.14
evs-27:
  service: evs (pushes, head reads, listings, range reads) and its service log (evs-7)
  store: none new; what evs-3, evs-4, evs-5, evs-8, evs-11, evs-12 and evs-7 hold for a team's directory repo
  sees: from the directory's format 2 (before it, announce entries in each writer's stream show the same timing), per announcing sidecar one card path, and per general or record repo, and any repo announced explicitly, one repo path, an announcement or a private marker padded alike, each token stable within a path epoch, a new repo's path first written by its creating device just after the creation, so linkable to it; each card version's signer, time and padded size in 2 KiB steps, so when each sidecar's runs start, end, change claims and renew (hourly while a run moves) and when its worker item renews (daily), never which run, title, project or branch; a revocation as a repo path's rewrite (before format 2, a newer announce entry) and an erasure_request entry in the revoker's stream, then a CLOSURE and ERASE on the directory's erasure ref (before format 2, ERASEs of the earlier entries) that a directory admin's device signs, as it signs every directory erasure, whose erased keys and rewritten index files show which writers' entries or documents named the repo; per access request, a notice created, rewritten at each decision, a denial's as an approval's, and removed under a token prefix that every request to one target shares, with the leases of that target's approvers' clients on it and of the requester's clients on its own path, so which requester asked which approvers, when, which approvers' devices decided it and when, and when it closed; request, decision, erasure request and coordination entries as stream records (signer, time, padded size); which clients read the directory, and when, with each sync's moved-stream listing and the streams it read (§11.9); nothing of an announcement's or a request's content or reason, and of a repo path's repo or a request's target only what the roles api-7 shows for the path's signers or the request's approvers narrow, though an approval's grant, which api-7 shows at the decision (RepoGrant, EvsShare) or at the requester's activation (GrantActivate), shows the approval and links the notice's prefix to its repo or worker
  why: one team directory (owner decisions 170, 171, 181); approvers are notified by lease (§11.10)
  ttl: as evs-3, evs-4, evs-5, evs-8, evs-11, evs-12 and evs-7; entries by the directory's retention, announce entries 30 d after a newer entry or file for their item or the item's expiry, a live repo item's newest copy kept, and the rest 400 d, expiry erasing their keys (§16.11)
  owner: §16.11
evs-28:
  service: evs appends; taskworker runs the dry runs and jobs (§11.13)
  store: drops/<repo>/_ (the repo's metadata cluster, at most 64 KiB); dropscan/<repo>/<id>/<f> (segment cluster; f one of snap, cand, mark, del, held); Redis {evsd_<repo_id>}
  sees: "per drop: its id, ref, DROP push id, version and place, not_before_ms, state (pending, cancelled, executing with phase and progress, held, observed, done, refused with reason), freed and held bytes, and the dry run it names; per dry run: the token paths and lists it was asked about, its snapshot and results (candidate segment and slot ids with sizes, which of them other versions name, inline and packed bytes); per job: its owner instance and lease, the drops it covers, its snapshots (each ref's version), cursor, counters, and candidate, mark, delete and held sets"
  why: a resumable deletion job and a dry run for the drop-history action, after its cancellable window, with no metadata write per push (owner decisions 173, 183)
  ttl: drops/ entries 30 d after their drop ends; dropscan/ files 30 d after their job or dry run ends; {evsd_} hints until taken, outside the rdb bundles; all three deleted with the repo at its shred (§11.12's phase 5)
  owner: §11.13
gkm-1:
  service: gkm
  store: gkm/repo/<repo_id>/<seq>; gkm/<group_id>/epoch/0 (metadata cluster)
  sees: GroupForm chain (repo_id, group_id, previous group, generation, signer); epoch 0 (network_id, cipher suite 0x0010 (owner decision 44), creator)
  why: one accepted commit per epoch; re-forming
  ttl: life of the repo
  owner: §10.6
gkm-2:
  service: gkm
  store: gkm/<group_id>/epoch/<n> (metadata cluster)
  sees: epoch objects; group_id, epoch, content type, generation, auth pin, size, time, uploader sidecar_id; the commit as PrivateMessage ciphertext; GenWrap
  why: ordering; the write gate
  ttl: 30 d, then until every leaf acking in the last 30 d has applied it; never the newest epoch
  owner: §10.6
gkm-3:
  withdrawn: no roster delta in the clear (owner decision 59); membership shows only as sidecar ids in gkm-4, gkm-5, gkm-7 and gkm-10, as in api-7
gkm-4:
  service: gkm
  store: gkm/kp/<sidecar_id>/<ref>, gkm/kp/<sidecar_id>/<ref>.claim, gkm/rk/<sidecar_id> (the first metadata cluster)
  sees: "KeyPackages (init and leaf HPKE keys, signature key, credential: sidecar_id, identity key, suite, not_after, admission hash, signature); claims (group, claimer, target); ReaderKeys (owner decision 114)"
  why: asynchronous adds; wrapped readers
  ttl: KeyPackages until claimed, or 90 d; claims 90 d; ReaderKeys until replaced or past their not_after, at most 7 d
  owner: §10.6
gkm-5:
  service: gkm
  store: gkm/<group_id>/welcome/<n> (the repo's metadata cluster), gkm/welcome/<sidecar_id>/<ref> (the first)
  sees: Welcome objects and pointers; recipient sidecar_ids and KeyPackageRefs in the clear; secrets and GroupInfo encrypted
  why: deliver joins
  ttl: until every recipient has acked, at most 90 d
  owner: §10.6
gkm-6:
  service: gkm
  store: gkm/<group_id>/epoch/<n> (external commits)
  sees: external commits, for resync and recovery only (PublicMessage); the joiner's leaf and credential, its removed old leaf, their ExternalInit and Remove proposals and their UpdatePath's public keys and encrypted path secrets
  why: offline catch-up and recovery
  ttl: as gkm-2
  owner: §10.6
gkm-7:
  service: gkm
  store: "gkm/<group_id>/gen/<g>, gkm/<group_id>/genpack/<k> (§10.16's gen packs, from §19.9's gen trigger: gen/<256k+1> to gen/<256k+256> verbatim, those gen/ objects then deleted), gkm/<group_id>/group-info, gkm/<group_id>/wrap/<g>/<c8>/<recipient>/<k8> (metadata cluster)"
  sees: key ladder; GenRotates (group, generation, parent and own commitments, cause, auth pin, time, holders hash, signer; GenLink and leaf-wrap ciphertexts; the drop public key where the kind takes deposits); GroupInfo pointers and, above 16 leaves, sealed GroupInfo; staged and late wraps (group, generation, commitment, recipient sidecar_id or delegation_id and the SHA-256 of the key sealed to, staged or late, a late one's auth pin and time, ciphertext, signer; owner decisions 114, 144, 182)
  why: ladder, resync, deposits; wrapped readers
  ttl: life of the repo, a gen pack's GenRotates as gen/'s; GroupInfo until superseded; wraps until the next generation's exist, staged wraps of a lost claim 24 h, a recipient's wrap to an older key 30 d after one to a newer key exists
  owner: §10.6
gkm-8:
  service: gkm
  store: gkm/recovery/<member_id>/<group_id>/<g>/<c8>/<b8> (metadata cluster)
  sees: recovery wraps (member_id, group_id, generation, an 8-byte prefix of the binding's Ed25519 key hash, which the authorization log already shows, HPKE ciphertext); the bindings are §7.9's RecoveryBind config records, not gkm objects
  why: recovery after losing every device
  ttl: until a RecoveryRebind replaces them or the repo is deleted; staged ones of a lost claim 24 h
  owner: §10.6
gkm-9:
  service: gkm
  store: gkm's service log
  sees: request log; client, route, group, time, bytes (GroupInfo requests included)
  why: rate limits, abuse
  ttl: 7 d
  owner: §10.6
gkm-10:
  service: gkm
  store: Redis {gka_<group_id>}
  sees: acks in Redis {gka_<group_id>}; group_id, sidecar_id, newest applied epoch, time; written at most daily
  why: retention
  ttl: overwritten by the leaf's next ack; 31 d after its last write; deleted with its group's gkm objects at a shred (§11.12); soft state outside the rdb bundles, lost with Redis, after which gkm deletes no epoch for 30 d; a hold's copy excepted (api-14)
  owner: §10.6
tls-1:
  service: lb (stream split, port 80 redirect), tlsedge
  store: memory; a 30 s negative cache; the lb's generated custom-host split map (active custom hostnames, public through SNI and CT; §13.4)
  sees: per TCP 443 connection (and 8443, 8883 and 5671; owner decision 121) the SNI, which the lb's ssl_preread split and tlsedge read (owner decision 34), the whole ClientHello (ALPN list, ECH presence, size), the accepting port, setup timing, record sizes and bytes per direction, the chosen listener; on port 80, the Host and request line of plaintext requests, answered with a redirect to https
  why: route by SNI without terminating (X1); caps; absorb scans; no plaintext path to tlsedge (§13.4, §13.5)
  ttl: connection memory; negative cache 30 s; the lb writes no access-log line for *.<root> names (I-13); tls-3 holds the only records
  owner: §13.5
tls-2:
  service: lb, tlsedge
  store: memory
  sees: visitor IP and port (PROXY v1 or v2 from the lb); per-process cap keys per /64 or /32, with /48 and /24 aggregates (HMAC under a per-process key rotated daily)
  why: caps (§13.9); the keyed /24 or /48 affinity key to Find (sock-2); TlsEdgeOpen.client_ip to the listener over a sealed stream
  ttl: memory, never logged (I-13); cap keys rotate daily
  owner: §13.4
tls-3:
  service: tlsedge
  store: tls_connection_record (hourly partitions), tls_connection_day
  sees: connection records (network_id, host from SNI, connection_id, start, duration, bytes, a /24 or /48 hash under a daily-rotated key, I-13); daily counts per network and host
  why: abuse joins by connection_id (§21.8), the keyed hash linking one visitor's connections within a day; per-host bytes (§13.6, §13.9)
  ttl: records dropped at 24 h, after any §21.9 hold has copied out its network's rows (owner decision 133); daily counts 13 months; URnetwork can invert the hash until its key rotates
  owner: §13.15
tls-4:
  service: tlsedge, api, the abuse worker
  store: network_tls_suspension; Redis {tes_<network_id>} and its trigger {tes_<network_id>}n; lease spends (api-13); the published-names list, drawn from api-7
  sees: payload bytes per network (meter tls lease spends); kill-switch entries (a host or all the network's hosts, reason, until); the published-names list, active publish grants (host, port, label or alias, audience, expiry), which §21.6 checks hourly against Web Risk
  why: billing (owner decision 10); takedown and abuse checks without inspection (owner decision 41; §13.9, §21.6)
  ttl: lease spends as api-13; a suspension until its case lifts it or its until time passes, then deleted with its keys, the case keeping the action (api-14); a name leaves the list when its grant expires or is revoked (Community publishes at most 7 d)
  owner: §13.9
cert-1:
  service: certs (taskworker), api
  store: network_tls_cert; Redis {tcb_<ca>_<registered_domain>} (a sorted set of the last 7 days' new-set orders)
  sees: cert_id, network_id, client_id, sidecar_id, identifier-set hash, SPKI hash, the identity-key attestation, the CSR (public key and names), CA, account URI, profile, serial, validity, ARI window, state and successor; Team custom-domain chains and queued CSRs (v1); each CA's and registered domain's new-set orders of the last 7 days
  why: order, renew and revoke certificates for device-held keys (owner decision 39; §13.8)
  ttl: 30 d after expiry or revocation; budget entries 7 d, the key 7 d after its newest order, rebuilt from network_tls_cert on loss
  owner: §13.8
cert-2:
  service: CAs (Let's Encrypt, GTS, ZeroSSL) and public CT logs
  store: external, public
  sees: every SAN, that is <net>.<root>, *.<net>.<root>, live aliases and Team scope labels (owner decision 40), and Team custom domains' names; never hosts under a wildcard; URnetwork's ACME accounts; DNS-01 lookups through dns-2
  why: CA rules
  ttl: permanent and public
  owner: §13.8
dns-1:
  service: dns (API blocks and edges)
  store: dns_root, network_dns_zone, network_dns_record, dns_zone_journal, network_dns_custom_host, dns_custom_host_map, dns_custom_host_map_applied; Redis {dns}serial:<root>; edge snapshots, and after a reload the snapshot it replaced; a restore's incident record and admin events (api-8)
  sees: system and user records (A, AAAA, CNAME, TXT, MX, SRV, wildcards), DKIM selectors and keys, TLSA per receiver key, CAA, null MX, direct-MX addresses, replying burners' selector records and the MX, A and AAAA copies at their labels, until the PSL listing (owner decision 79; §12.7), challenge TXT values, strong-mode probes' CAA canaries (the customer's pin plus a nonce; §12.8), custom-host maps with each custom host's CAA mode (strong or weak), full-chain check result, map version and readiness (§12.8); the map's versions and digests, and each lb interface's reported version, digest and nginx master and its route probes' results (§13.4); the sending lb addresses, listed in _spf.<root> and named in their reverse zones by PTRs under bringyour.com (owner decision 124); zone suspensions (network, reason, until) and host suspensions (network, host; §12.9); the journal of diffs; serials; each user or key write also as an admin event (api-8); after a restore, the RRsets (network_id, owner, type) that differ between an edge's replaced snapshot and the restored zone, and the custom hosts W1's regeneration adds or drops (§12.6)
  why: serve the zones and the sending addresses' reverse zones; takedown (§21); DNS data is public by nature (CONVENTIONS §0)
  ttl: records while published, withdrawn at once when their network is deleted (§12.5); PTRs while smtpedge.yml lists their address; challenges and canaries at most 1 h; journal 7 d; custom-host map versions 7 d, and interface reports while the interface is in the lb inventory; suspensions until Restore or their until time; {dns}serial projects dns_root (§19.7); a replaced snapshot until the restore step has its diff, at most 24 h after the reload, and deleted at once after a reload that is not a restore's; a restore's lists 400 d, in its incident record as in admin events (api-8)
  owner: §12.6
dns-2:
  service: the dns edge
  store: memory
  sees: every query it answers; query name (labels, aliases, hosts, mx and TLSA owners, burner labels in MX lookups, §15.9; challenge names CAs validate; the sending addresses' reverse names, owner decision 124), type, class, EDNS options (client subnet ignored, never stored), the DNSSEC OK bit, UDP or TCP, resolver IP and port; RRL state per resolver /24 or /56
  why: authoritative service; response-rate limiting (§12.6)
  ttl: memory per query; RRL state for its window; no query or resolver address logged (I-13)
  owner: §12.9
smtp-1:
  service: smtpedge
  store: memory, then smtp-3
  sees: the proven preamble (from M9, owner decision 35); recipient domain, recipient count, Message-ID, header-From domain (a network, burner or verified Team domain), DKIM selector with d=, message byte count, retry-of send id, flags (BULK, REQUIRETLS, BURNER)
  why: the send gate, halts, connection and recipient quotas (owner decision 30), MX choice, abuse joins (§14.5, §14.7)
  ttl: "connection memory, then the send record (smtp-3: recipient domain, proven counts, retry-of, a Message-ID hash); the rest only in memory (D-SMTP-10)"
  owner: §14.5
smtp-2:
  service: smtpedge
  store: memory
  sees: per connection the network and sidecar (from the ticket), the sending IP (one of its host's shared lb addresses, owner decision 124) and its helo_name (that address's PTR name, already public by FCrDNS), the recipient domain's MX, TLSA and A lookups, MX host and IP, banner and pre-TLS EHLO and STARTTLS replies, TLS version and suite, SNI (the MX host), the MX's certificate (TLS 1.2's in clear with its ServerKeyExchange, TLS 1.3's under the server handshake secret the sidecar discloses; E2), the DNSSEC chain, proofs π1 to π3 and, in DATA mode, one per later body part (owner decision 125), the length and timing of every client and server record it relays (client records unpadded, Z3, so each command's length, every RCPT TO's included; server records a part's public inputs, Z7), bytes, result, the self-reported SmtpOutcome; the issued send_id, X-UR-Ref and Feedback-ID (a keyed network token, constant for burners); no key that opens application data, so no MX reply's plaintext inside TLS (D-SMTP-21, D-SMTP-22)
  why: send, verify proofs, attribute, rate-limit (§14.4, §14.5)
  ttl: connection memory; record lengths, the disclosed secret and proofs never stored (D-SMTP-10); then smtp-3, without the MX IP
  owner: §14.5
smtp-3:
  service: smtpedge
  store: smtp_send (daily partitions)
  sees: send records; send_id, network, client, sending IP, recipient domain, MX host, times, bytes, Message-ID hash, X-UR-Ref id, proven counts, TLS version and level, result, retry-of
  why: attribution, halts, RUA reconciliation, downgrade audit (§14.8)
  ttl: 30 d (daily partitions dropped)
  owner: §14.14
smtp-4:
  service: smtpedge
  store: Redis {smq_<networkId>}; smtp_halt; edge memory
  sees: per network the day's connection and recipient counts and reservations, bursts and concurrency; halt flags and smtp_halt rows (network or burner label, trigger, start); Community breaker totals and per-destination-domain counters, with no network; concurrency per sending address and destination /24
  why: quotas (§14.7); halts (owner decision 37; §14.8)
  ttl: counters 48 h; halts 24 h; smtp_halt rows 13 months (§14.14); breaker and destination counters for their hourly windows; concurrency only in memory
  owner: §14.7
smtp-5:
  service: smtpedge (report intake)
  store: smtp_complaint (with sealed_report), smtp_dmarc_daily
  sees: reports parsed header-only, and aggregate attachments (DMARC XML, TLS-RPT JSON, gzip) parsed under size, ratio, entity and depth bounds, each report_id counted once (§14.8); reporter, type, arrival, the attribution fields (domain, DKIM d= and s= with result, Message-ID hash, X-UR-Ref, Feedback-ID) and join result; the last-hop Received IP and time for the join only; RUA and TLS-RPT aggregates per network, day and reporter (header_from domains, burner labels included, counts and results for URnetwork's sending addresses); sealed report copies
  why: attribution, halts and breakers (§14.8, §21.5)
  ttl: complaint rows and aggregates 13 months (§14.14); sealed copies 30 d (owner decision 78); Received IPs, other third-party IPs and bodies never stored
  owner: §14.8
smtp-6:
  service: smtpedge, dns
  store: smtp_dkim_key; the selectors' DNS records (dns-1)
  sees: DKIM public keys and opaque selectors per sending sidecar, which reveal how many devices send (owner decision 36); replying and forwarding burners' selectors until the PSL listing (owner decision 79)
  why: publish DKIM (§12.7, §14.6); check signatures in reports (§14.8)
  ttl: 30 d after the selector leaves DNS (7 d after rotation, at once on removal; §14.14)
  owner: §14.6
mx-1:
  service: mxedge (router)
  store: memory; Redis {mxc_<HMAC_k(prefix)>}
  sees: sender IP and port (PROXY v1), the destination interface, pre-TLS EHLO or HELO name, forward-confirmed PTR, STARTTLS, SNI (the network's mail host, an alias's or scope's, or a custom MX host, which names the network), the ClientHello (held up to 30 s for a wake), IP-listing categories from the local feed mirror, timing, size, result; cap state per sender /64 or /32, its /48 and /24 aggregates and network; any plaintext MAIL, RCPT, DATA or BDAT before STARTTLS, refused; MailIngress, which carries sender IP, EHLO, PTR and listings to the receiver sealed
  why: route by SNI without terminating TLS (X6); banner rejects, caps and the 451 rule (owner decisions 33, 111)
  ttl: connection memory, caps in memory; after a closed handshake a keyed hash of the sender's /24 or /48 for 1 h under a daily key, storing no address
  owner: §15.4
mx-2:
  service: mxedge
  store: mail_connection_record (hourly partitions; §15.4, §15.15)
  sees: connection records; receiving network, time, size, result; no sender address, no burner label
  why: abuse joins and per-network caps
  ttl: records dropped at 24 h, after any §21.9 hold has copied out its network's rows (owner decision 133); then only api-13's daily lease usage, a hold's copy excepted (api-14)
  owner: §15.4
mx-3:
  service: mxedge, dns
  store: mail_network, mail_host_key, mail_direct_mx; Redis {mxr_<net>}
  sees: mail-enabled networks; mail host keys (host mx or mx.<scope>, receiver sidecar_id, SPKI hash, state, publish and retire times); direct-MX receivers and addresses (Team); the route projection of mail-enabled labels, aliases, Team scopes and custom MX hosts; no burner table and no per-network address (owner decisions 32, 34)
  why: route by SNI; verify direct MX (owner decision 33)
  ttl: mail_network until mail is turned off or its network deleted; host keys 30 d after retirement; direct-MX rows until DELETE or their receiver's removal; {mxr_} projects them (§19.7)
  owner: §15.15
mx-4:
  service: mxedge (platform listener)
  store: memory, then smtp-5 and api-14
  sees: mail to URnetwork at rpt.bringyour.com's platform listener (D-MAIL-10); sessions it terminates, SNI or not, with sender IP, EHLO, MAIL FROM and RCPT (<token>@rpt.bringyour.com, abuse@ and postmaster@ on <root>); messages parsed for headers and aggregate report data only (D-SMTP-23; §14.8)
  why: URnetwork is the recipient of reports and role mail (§21.8)
  ttl: the envelope only in memory; raw bytes sealed to the network's mail key for 30 d or dropped unread; fields as smtp-5 and api-14; enclosed message bodies and attachments never decoded
  owner: §15.4
ops-1:
  service: every service
  store: Mimir metrics, Loki logs (config/main/grafana.yml:31-38)
  sees: metrics by route template, result, code, cluster and tier; logs with opaque ids only; lb access logs without client addresses, sidecar routes logging $uri, not $request (W8)
  why: operations (§19.8)
  ttl: metrics 90 d, logs 7 d; never network, client, repo, host, alias or IP labels
  owner: §19.8
ops-2:
  service: Postgres dumps
  store: the sidecar dump (daily; edge-6's archive and planetoid; 14 generations each; tables with ttls of at most 7 d excluded); the main dumps (edge-6, planetoid)
  sees: encrypted dumps of the Postgres rows above; sidecar tables in their own dump, with the network, user (sign-in rows included) and client rows they name, so a restore keeps the ids of networks, members and sidecars newer than the main dump (D-OPS-18); tables that exist today (accounts, networks, clients, contracts) in the main dumps, with off-site copies on planetoid
  why: durability (§19.6; D-OPS-18)
  ttl: sidecar dump generations 14 d, so a row outlives its ttl by at most 14 d, and tables with ttls of at most 7 d none; existing tables about 4 months, 9 generations (xops/main/ansible/host_files/by-us-fmt-5-edge-6/db-archive/README.md:201-203)
  owner: §19.6
ops-3:
  service: Redis backups
  store: rdb bundles
  sees: snapshots of existing Redis families, contract and escrow state among them; sidecar families (§19.7) filtered out before sealing (D-OPS-16)
  why: durability of existing services (§19.3)
  ttl: about 8 months (xops/main/ansible/inventory.yml:193-195); sidecar keys never
  owner: §19.6
ext-1:
  service: Cert Spotter, crt.sh
  store: external
  sees: CT searches for each network's label, aliases and custom domains, from the querying device's egress IP, with an optional Team key
  why: CT watch (D-TLS-8, D-TRUST-6)
  ttl: the provider's
  owner: §13.8
ext-2:
  withdrawn: no third-party DNS provider; URnetwork self-hosts (owner decisions 69, 71; dns-2)
ext-3:
  service: DoH resolvers
  store: external
  sees: domains, MX, TLSA, DKIM selectors and MTA-STS names sidecars look up; receivers' reception-time lookups for each message, at most 64 (SPF, DKIM and ARC keys, DMARC, the sender's forward-confirmed PTR; D-MAIL-14, §15.5), and any re-check a reader shows apart; the device IP
  why: reception-time evidence for §15.5's labels (D-MAIL-14), independent MX checks (TL3) and the zone watch (§14.4, D-TRUST-9)
  ttl: the provider's
  owner: §14.4
ext-4:
  service: the IP-listing feed operator (a commercial feed, such as Spamhaus)
  store: external
  sees: mxedge's licensed mirror pulls every 5 min (URnetwork's address and credential); no sender IP, since listings match locally
  why: IP reputation (owner decision 111)
  ttl: the operator's
  owner: §15.4
ext-5:
  service: mailbox providers
  store: external
  sees: network and burner mail from the shared lb addresses, with HELO and PTR names under bringyour.com (owner decision 124); the DMARC aggregate and feedback reports they generate about it
  why: delivery, deliverability, abuse loops (§14.6, §14.8)
  ttl: the provider's
  owner: §14.8
ext-6:
  service: Google Web Risk
  store: external
  sees: list updates, and full-hash lookups for the hash prefixes of published hosts and user record names that match a local prefix
  why: phishing checks (§21.6)
  ttl: the provider's
  owner: §21.6
ext-7:
  service: Stripe
  store: external
  sees: Team subscriptions, payments, seats and daily transfer-overage and storage GiB per network and meter, under SHA-256 identifiers of network, meter and day
  why: Team billing (owner decisions 92, 122; §20.9)
  ttl: Stripe's
  owner: §20.9
ext-8:
  service: APNs, FCM
  store: external
  sees: device push tokens, the app, wake times and priority; payloads of a topic class and version only, never an id
  why: content-free phone wakes from v0 (owner decision 88; §18.7)
  ttl: the vendor's
  owner: §18.7
ext-9:
  withdrawn: no off-site copy in v0 (owner decision 94)
ext-10:
  service: AWS SES and members' mailbox providers
  store: external
  sees: account mail URnetwork sends to Owners' and Admins' sign-in addresses, security notices of new credentials, IdPs, domains, Delegations and admin-set changes included (§7.8)
  why: alert owners to changes they did not make (R-TEAM-12)
  ttl: the providers'
  owner: §7.8
```

### 2.9 Security invariants

- **I-1.** No server receives or derives a key to evs content or names, MLS secrets, or repo or path keys; PLAN.md:53's "stored in GKM" means wrapped (PLAN.md:221).
- **I-2.** Client content and keys reach servers only as ciphertext, in every mode, except at `rpt.bringyour.com`'s report and role-mail listener, as §2.8's statement bounds it (mx-4).
- **I-3.** Sidecars, and edges toward them, run `EncryptionModeRequired` and check a peer's identity binding before trusting its bytes (§6); pushes (X8) carry only server-held state or client-sealed bytes.
- **I-4.** Every statement a client acts on is signed and checked against the network's config repo (owner decisions 3, 5); servers store, order and deliver statements, originating only denials. An owner-bound repo gains readers only by its owner's consent (§8.5) or as owner decision 63's audit member, and owners' devices alarm on admissions under them they did not sign (owner decision 126). A statement §7.9's presence row covers, a revocation, `Suspend` or veto of another device, a presence key's registration or removal, or an admission, confirmation, AdminSet change, member removal or recovery binding (owner decision 189), signed by a sidecar that registered a live presence key, carries that key's countersignature, which api and every member device verify (owner decisions 185, 187).
- **I-5.** Receivers also check every grant that exposes their data, sockets or LAN.
- **I-6 (P0).** No credential a sidecar or agent holds administers the network or mints a network login; owner decision 45's later stages extend this to device-client tokens (§7.4); a sidecar-held token reaches only §7.4's sidecar routes.
- **I-7.** No network or service credential enters an agent's context (MCP output, environment, logs), same-user file reads aside (owner decision 47).
- **I-8.** Outward actions (§5.4) need approval by another approval-capable device (§16.6), a registered presence key or, lacking both, the harness prompt, recorded with its evidence type (owner decision 75).
- **I-9.** A run that has read untrusted content (outside mail, imports, web tools' output, tainted runs' writes, flagged entries and the team directory's prose; §16.6, §16.10, §16.11), or lacks full hook coverage, loses send, forward and publish until a person approves on another approval-capable device or with a presence key; a harness prompt counts only where its `requests` rule names harness (owner decision 142; §16).
- **I-10.** With an ACL document, only a rule opens a provider's loopback, LAN, link-local or overlay addresses to Network sources (owner decision 50); without one, untagged sources keep today's disclosed allow-all (connect/ip_security.go:567-569; owner decisions 105, 120), minus the provider's own daemon listeners (§17.6), and tagged ones get §8.5's implicit rules. No URnetwork-run client, the hosted ProxyDevice included (server/proxy/proxy_device.go:1302), holds Network rights in a customer network.
- **I-11.** Mail an active URnetwork could read (EX3, EX4) is labeled per message, and each sent message records its §14.4 level.
- **I-12.** Inline packet and frame paths never block or query PostgreSQL, and fail closed (connect/CODESTYLE.md:106-107).
- **I-13.** URLs, generated names and logs carry opaque ids, never paths, repo names, aliases, recipients, subjects, or search queries, hits or snippets; client IPs are never logged or stored in the clear; tls-3's and mx-1's keyed hashes are the only address hashes the sidecar services add, and connect-3 lists the existing connection rows' peppered ones.
- **I-14.** A released name routes nothing to its new owner while the old owner's certificates, MX records, mail retries or sockets may still be honored (X5).
- **I-15.** A removal, ephemeral reaping included, revokes the party's certificate, DKIM and TLSA records and tokens and starts a new key generation in each repo where it held a key that no live Delegation still delivers (lazy rewrap, owner decision 64; §10.5); a Delegation-admitted agent's reap, or an ephemeral one's own `not_after`, leaves its Delegation's key reading until the key drops at DelegationRevoke, `not_after`, a revocation for any reason but reaped or a `Suspend` of one of its agents, or a compromise revocation whose cascade voids it, each of which retires that key at its position, the Delegation's other agents reading on by their own wraps unless a compromise revocation or a DelegationRevoke's since_n parks them (owner decision 114; §7.9, §10.5). All members see every removal; a member's also rotates path keys at once (§11.6).
- **I-16.** Heads, manifests, MLS epochs, generations, the authorization log and the config repo carry signed monotonic versions; clients refuse lower or conflicting ones, alarm, and confirm them with a witness (D-TRUST-10). After a site loss only a repo admin's EvsReseed lowers a head, and the authorization log resumes from devices' verbatim entries at unchanged positions and digests (§7.9, §19.10).
- **I-17.** Off loopback, git over http, IMAP and SMTP submission serve only TLS, git also ssh (D-TRUST-8; owner decisions 84, 130); local servers authenticate callers, HTTP targets check Host, and the daemon's control channel is a Unix socket or pipe.
- **I-18.** Server-visible metadata changes update §2.8 before release; §22.7's guard fails builds with a column, Redis key family, object key family or proto field the list lacks.
- **I-19.** No server receives a query or term, or learns a candidate or result beyond the documents a device opens. Devices search the whole index partitions they hold, or an app host sends its query end to end over the sidecar subprotocol, only to a designated indexer §11.14's rule lets answer it, in requests and replies whose sizes no query, scope or result sets; that indexer searches the partitions and text it holds and fetches nothing for the query. Index files are fetched only by sync position (whole files, and all's shards in a fixed order), and a document only when it is opened, by a person, an agent's read or `ur search --verify fetch`, which opens its candidates (§11.14, §16.10, §18.4).
- **I-20.** A team directory holds only a run's who, what and where (§16.11); prompts past the title, tool calls and their names and outputs, touched paths, diffs and model calls stay in the owner-bound vault unless its member shares them (owner decisions 126, 170).

### 2.10 Threats and mitigations

| Adversary | Threat | Mitigation | Residual |
|---|---|---|---|
| Prompt-injected agent (P0); compromised harness (Q-TRUST-2) | Mints a network login from a token, `.auth_state` or the extension's stored `by_jwt`; sends or shares out; plants config; removes hooks; compromised, acts as its device | I-6 to I-9, D-TRUST-3, config review (sidecar/design/improve.md:129); removal (I-15) | Harness-prompt approvals, which a same-uid process can forge (§16.6), in untainted runs or under rules naming harness (owner decision 142); a compromised device until removed, and what it, or any device it admitted directly, through another device or through a recovery key it bound, signed from the cut-off position on: its compromise revocation parks what they admitted and voids their Delegations, recovery bindings, key registrations and shares, a binding a void restores admitting only through the vetoable 72 h window, while the grants, approvals, suspensions and unsuspensions, access-log statements, SponsorSets, MemberAdmits and config heads they signed stand until revoked, the revoking device listing them for its person and admins (§7.9); keychain backups sealed to a voided binding, which its code opens, until each device whose backups may hold such a sealing is revoked for compromise and enrolled anew (owner decision 149; §5.9) |
| Agent, member device, LAN host, web page, network attacker | Reaches a provider's LAN or loopback, local listeners, or a `members` front with a member's cookie; sniffs listeners; strips STARTTLS | I-10, I-17; §13.7's Fetch Metadata rule; STARTTLS both ways (owner decisions 33, 38) | Without an ACL document, member devices and untagged sidecars reach LANs and loopback (owner decision 120), never the provider's daemon listeners (§17.6); LAN hosts reach granted forwards; browsers lacking Fetch Metadata send the cookie on cross-origin GETs; EX3 |
| Foreign network via a share | Reaches private destinations behind the provider's NAT (owner decision 86) | C18's per-flow check on C13's sealed source network (§17.9) | Shared NAT state; share delegations, on contracts the operator can mint, from a sidecar the accepting network removed until a later ShareCert reaches the host (at most 7 days), from a reaped Delegation-admitted agent while it reads that config, and from a removed ShareKey holder until the share is revoked (§17.9); and, on such a contract, from any current reader of the accepting network's config, one its policy denies included, within the inviting network's grant (§8.11) |
| Curious, compromised or compelled operator; a CA or registrar | Ghost member, peer or grant; key substitution; rollback, fork, withholding; EX1-EX4; logging from now on | I-3 to I-5, I-15, I-16; D-TRUST-6, D-TRUST-9, CAA, registrar lock (§19); labels; canary (sidecar/design/pitch5.html:933) | EX3, EX5; §2.8's exposure bound |
| Operator colluding with a recovery-code thief | Hides the recovery proposal from every admin device for 72 h; with the code and the operator's ciphertext, reads at once every generation wrapped to that member's recovery key, whatever the window | The window; vetoes appended or gossiped in HeadCheck (§7.9); `RecoveryRebind{reason: compromise}` | The proposal undetected until first sight (`recovery_unseen`), and its device until admins revoke it; what the code reads until `RecoveryRebind{reason: compromise}`, and keychain backups sealed before it, whose devices the member revokes for compromise (§7.9) |
| Rogue or compromised admin | Mints a device under member M to read M's owner-bound repos (vault, mailbox, secret), or to announce and request as M in the team directory; makes a member a config signer | I-4's consent rule (owner decision 126): other Adds park for M (§10.7), a parked device's directory writes count for nothing and it holds no directory admin scope (§7.8, §16.11), and M's devices alarm (§5.4); k of n for config-signing roles (§7.9) | The device's team-repo grants until revoked; k = 1 when n ≤ 2 |
| A reaped Delegation-admitted agent, an ephemeral one past its own `not_after`, or a copy of a Delegation's reader seed | Reads later generations of the Delegation's reach: the config, a team's directory and its tag repos | The key drops, at its position, at DelegationRevoke, a revocation for any reason but reaped or a `Suspend` of one of its agents, or a compromise revocation whose cascade voids the Delegation, and at `not_after` (≤ 90 d, 30 d for CI by default) (§7.9, §10.5) | Reads until then (owner decision 114) |
| A copy of a whole reusable auth key (its bundle's signing seed too), with an operator that supplies any bearer or client | Admits fresh agents under its Delegation, each reading by its own ReaderWrap once the shared key has dropped, so revoking or suspending one agent does not stop it | api and every reader refuse its admissions from the Delegation's end: DelegationRevoke, whose `since_n` parks what it admitted since a leak, a compromise revocation of one of its agents, which ends it the same way, its void, `not_after` or `max_admits`, which rows count for its life (§7.9's delegation row); the revoke plan names the agent, the shared key and the admission authority apart (§7.10) | Agents it admitted before `since_n`, until revoked; with neither a DelegationRevoke nor a compromise revocation, admissions until `not_after` or `max_admits` |
| Revoked member or stolen device | Reads new data; uses kept keys and tokens | I-15, I-16, at-rest encryption (§5), deactivation (server/session/by_jwt.go:678-700), 7-day sidecar tokens, 7-day ReaderKeys (§10.5) | Cached data; a passive keychain copy (its bytes, opening only what the operator serves, a stale ReaderKey advertisement included) reads every generation sealed before the device's next path commit and its newest copied ReaderKey's not_after, so content up to about 37 days after the copy (60 above 50 leaves) while the device runs, its leaf deriving later epochs' KEKs while it does not, and every earlier one; an active clone, using the copy's identity key or ClientKey, signs fresh ReaderKeys and KeyPackages and reads and acts as the device until a `SidecarRevoke{reason: compromise}` from a since_n before the copy and a new enrollment (§7.9's cascade, §10.8); a removed member opens files untouched since removal until rewritten or `ur evs rekey` (§10.5) |
| A writer of a repo (an agent, a member device) | Writes index files that omit a document's postings, so search misses it, that plant postings and display fields, or that name a diff base the index lacks or a tombstone its path never had | Hosts with the text re-extract each new document's trigram set and fields, check each tombstone against its path's history and reproduce merges and roll-ups, alarming `index_mismatch` with the signer and using their own result (§11.14); indexers check every repo they read (owner decision 150); an unresolvable diff chain is `index_malformed`, its document reported not yet searchable, never absent; phones label unchecked hits possible and compare an opened document with its doc-table row | A phone with no desktop or indexer online misses a hidden document until one checks |
| Script injected into https://ur.io (XSS, an extension) | Reads decrypted views while running | §18.8's key origin, exact-origin messages, CSP | Views during the injection (EX7) |
| Thief holding a member's unlocked device, running modified software | Revokes or suspends the member's other devices, parking for a compromise what they admitted, vetoes its recovery windows, swaps the device's presence keys to drop the check, admits a device with no key to act from, or rebinds the member's recovery code, locking the member out | §7.9's presence row: those statements, and a presence key's registration and removal, carry the countersignature of a live presence key the signing device registered, with UV, which api and every member device verify (owner decisions 185, 187, 189); the member's other devices revoke the stolen one for compromise | A device that registered no presence key signs on its person's confirmation alone (D-CORE-13); a thief who knows the device's passcode or its security key's PIN; statements the row does not cover, none of which admits, confirms or empowers a signer or rebinds a recovery code (owner decision 189) |
| Compromised network process (an app's VPN component: network extension, VPN service, app service) | Misroutes or exposes tunnel bytes; signs `WindowDelegation`s as its sidecar; reads the config | Only forwarding runs there (owner decisions 87, 197): its forwarding key signs nothing but its sidecar's delegations, its forwarding clients are `forward_only` (§7.4), and its reader key opens the config alone; hosts check every flow against their own state; `DelegationRevoke`, or the sidecar's revocation, ends it; state verified against the anchor | Routing integrity on that device; its sidecar's bridge reach and the config's contents until revoked, as every admitted sidecar reads it; no mail, evs data, MLS, identity or recovery key; on Android, the app's process while the service shares it (§18.16) |
| Sandbox operator of a cloud agent (owner decision 49) | Snapshots the VM; a TLS-intercepting proxy reads bearer tokens | Inside TB1; tokens unrenewable and unexchangeable without the ClientKey (§7.4); Required-mode content | Keys in snapshots, read as §10.5's passive copy or used as an active clone until a compromise revocation and a new enrollment; ≤ 15 min service and ≤ 7 d client tokens |
| Any team directory writer, an agent or a tainted run included | Plants instructions in announcement, request or decision prose that reaches every team agent unread | Prose untrusted whoever wrote it; agents get stubs of attested and identifier fields, and `untrusted: include` taints the run first (I-9, owner decision 142; §16.11) | Capped identifier fields, such as a branch name, reach agents between the untrusted-data markers, labeled with their writer |
| A member, agent or compromised device | Floods approvers with access requests, or words a reason to win one | Agents' and tagged sidecars' requests need their member's or sponsor's endorsement first, by device or presence in a tainted run (owner decision 142); per-requester and per-target limits (§20.4); approver screens render only daemon-built fields, the reason as untrusted text (§16.11) | Requests within the limits until revoked; a person persuaded to approve |
| A directory reader who cannot read a repo | Learns its name while it is private or unannounced | Private markers, which carry no name; a run in an unannounced repo names only its id and `private`; a revocation's erasure request has a directory admin's device erase every copy that holds the name (owner decision 181; §16.11) | A config label names a repo to every admitted sidecar (§8.8); readers keep a name they synced before its revocation, and a modified reader can open the copies until a directory admin's device runs the erasure, which `ur status` shows pending |
| Any team directory writer, an agent, a device parked for consent or a compromised device included | Destroys other writers' entries by ERASE, CLOSURE or slot deletion, or moves an index ref's epoch by a CUT; replaces or removes another's card, repo file or notice | evs takes the directory's ERASE, CUT and CLOSURE pushes, closure uploads and slot deletions only at `admin`, which §7.8 mints only to its consented, not-read-only admins, refusing them below it before any commit or slot rewrite (§11.12, I-EVS-16); a repo owner's revocation erases through a directory admin's device (§16.11); streams take creates only from their writer; readers ignore and alarm on any other cards-ref version, naming the signer for revocation | A cards-ref breach denies until the rightful writer's repair, since the purge deletes the version it replaced: a card until its sidecar's next sync, a repo file until a repo admin's device re-signs it, a notice until its requester or decider rewrites it (§16.11's repair row); a compromised directory admin erases and cuts, as in any repo |
| A team search indexer's holder: an admin, a member an admin designated, or a rogue admin who designates its own device | Reads members' "search more" words over the team repos it answers, and keeps them with a modified client | No designation by default (owner decision 177); own indexers first; owner-bound repos only on the owner's consented devices (owner decision 126); the app names each answering member before its first query; one other device at a time; a per-device setting (`own`, `off`); designations signed, listed in every config and by `ur indexer ls`; `ur indexer add`'s warning on hosts with harness hooks | Once one is designated, members whose phones keep the default `on` mode disclose their team-repo search words and times to that device's holder and, under TB1, to its same-user processes |
| A compromised or faulty indexer | Omits, invents or alters hits it returns to a phone | Hits name doc_key and version; the phone checks a hit's text when it opens it and keeps its own confirmed hits, alarming on one the checked span omits; disproved possible matches only collapse; each reply's pinned heads are checked as HeadCheck checks them (§6.4); alarms name the indexer, and three mismatches in a day skip it for 24 h (§11.14) | Older documents a phone has no local means to see stay hidden until another device checks |
| A relay or compelled operator | Times each remote search, counts its pages, and keeps per-contract byte totals | Fixed request and reply sizes; windows opened at foreground and held by a keepalive; each window's reports, both directions, withheld to its end and fixed at a 256 KiB floor covering five exchanges and the pair's scheduled background at its maximum (owner decisions 176, 188; §6.10) | When each search and page runs, the indexer's answer time, windows of six or more exchanges or with unscheduled traffic (a second HeadCheckProof, a stream or other RPC), a failover's window opening at its search, the contract of a search that re-establishes a session lost in the foreground (owner decision 191), and which pairs are requester and search indexer, from reports at the floor (connect-5) |
| A compromised member device | Floods an indexer with searches, or probes repos through it | Per-requester rates and the indexer's own budget (§11.14, D-CORE-17); the indexer answers only repos the requester reads in its own evaluation | Load up to the requester's rate until it is revoked; nothing it could not read |
| A network, or many, revoking, shredding or erasing within their own rates, by intent or in a wave | Drive one metadata cluster's P0 work past its write budget: 100 large Teams there, each shrinking every 5 minutes, ask ~2.9 TiB a day a drive of rotations, about twice the refill | Per-class rates per uploader, group and network; while it takes the refill, that cluster's pushes shed and its other classes held to what the write budget's bucket still holds, all restarting as it ends and ramping up as the bucket refills (§11.13); P0's excess forgiven, counted and shown against the drives' rating (owner decision 190); §19.8's P0 page within an hour and §19.10's runbook: capacity, placement, the networks driving it (owner decision 186) | While it lasts, that cluster's drives write past 0.8 DWPD and their 1 DWPD rating, and its other networks' pushes and evacuation stop; each wave's forgiven excess stays as wear, ~0.23 drive-writes for 6 hours of the one above (§11.21) |

### 2.11 Metadata retention

Principles (D-TRUST-7): abuse joins use opaque tokens that resolve only to a network and a time; no third-party data is kept beyond I-13's keyed hashes; protocol state dies with its customer's data; legal holds name accounts, are counted publicly and pause only server sweeps, GC and drops' deletions, silently (owner decision 184), not users' shredding (owner decision 133; §21.9).

### 2.12 X17: trust consequences

Decided (owner decisions 15, 108): recURd uses the main services; a dedicated issuer would need per-network binding every verifier checks (§7).

### 2.13 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Honest-but-curious server | Simpler | Contradicts sidecar/design/pitch5.html:932 | Rejected (D-TRUST-1) |

### 2.14 Decisions proposed

**D-TRUST-1 (proposed).** The adversary is a malicious, possibly compelled server; the promises hold against an active operator, apart from §2.8's capabilities. *Why:* sidecar/design/pitch5.html:932; connect admits the gap (connect/DESIGNNOTES3.md:381-400).

**D-TRUST-2 (proposed).** I-1..I-20 bind every section; one that cannot meet an invariant raises a Q- item naming it. *Why:* promises fail at the weakest component.

**D-TRUST-3 (proposed).** No sidecar ships before the P0's first stage (owner decision 45) and the 7-day expiry of sidecar-held tokens (D-TEAM-14; owner decisions 103, 131), nor a desktop sidecar before its second stage, which waits for the app and extension releases that stop persisting the network credential in `.auth_state` and the extension's `chrome.storage.local` (§18.7, §18.15), so M1-M2's desktop daemons run only in test networks on machines without the app or the extension. Until stage 2 is live in an environment, `POST /network/enroll` and `/network/auth-client` refuse `strict_exp` clients outside `config/<env>/sidecar.yml`'s `preview_networks`, and `ur` refuses to enroll, and an enrolled daemon alarms, on a host where either store holds a readable network credential (§5.6, §7.4). *Why:* code-create plus `reject_expired: false` make any readable token a lasting admin credential, and same-user agents read both stores (owner decision 47).

**D-TRUST-4 (proposed).** §2.8's statement and list become a versioned public document, kept true by I-18. *Why:* sidecar/design/pitch5.html:745, :932.

**D-TRUST-5 (proposed).** Membership and the communication graph are published; sidecar/design/mocks/team-management.html:814 and :917 change (owner decision 72). *Why:* relays and server gates see both.

**D-TRUST-6 (proposed).** Publishing sidecars watch CT for certificates no network device attested (§13.8, D-TLS-8), showing failures as degraded. *Why:* URnetwork passes validation for its names (EX1).

**D-TRUST-7 (proposed).** Retention follows §2.11 and §2.8's `ttl` column; sidecar tables leave the 4-month main dumps for their own daily off-site 14-day dump, and sidecar Redis families the 8-month bundles (ops-2, ops-3). *Why:* retained fields can be subpoenaed; no backup may outlive a published ttl.

**D-TRUST-8 (proposed).** Git, SMTP submission, IMAP and forwards bind all interfaces unless `--listen` narrows them (owner decision 84); off loopback, git over http, IMAP and SMTP submission serve only TLS, git also ssh (owner decision 130); forwards are disclosed as LAN-exposed. *Why:* otherwise Basic auth, SMTP AUTH and IMAP cross the LAN in cleartext.

**D-TRUST-9 (proposed).** Sidecars with a mail host or published name watch their zone's records through two public resolvers, alarming on changes they did not request (owner decision 98). *Why:* only an outside view detects forgery (EX2).

**D-TRUST-10 (proposed).** I-16's witness is any other admitted reader sidecar, agents included, not revoked, parked or suspended in the counting device's state, whose hourly `HeadCheck`, after reconciliation, holds the same pin while neither side sends a `proven` or `unverified` pin and the counting device holds no UNVERIFIED one (owner decision 129; §6.4), shown as `witnessed_at`. Without one, writers alarm at 24 h and, in groups with another member's devices, stop at `ServiceSettings.witness_bound_hours` (default 72 h, 24-168 h; §7.9); rotations, Removes and revocations, which only shrink exposure, never stop. A device holding verified proof that api withholds a newer pin, or an auth fork, stops at once and sends that pin as `proven`, serving any withholding proof, so each peer that verifies the proof stops at once and relays it in turn; a pin a peer can confirm neither from api nor by a proof, a relayed fork's included, is UNVERIFIED: the peer alarms, counts no witness and sends the pin as `unverified` with its path (the claimant, then each relayer), and each receiver holds it UNVERIFIED and relays it in turn until it reaches that pin or a sidecar on the path is revoked or parked. *Why:* the stop bounds how long a server hides a Remove from a writer that a chain of up to 8 HeadCheck hops links to a holder of it (§6.4), at once where every hop verifies a proof and at the bound where one lacks it; across a split it bounds nothing (§2.8); stopping own groups would halt a laptop paired only with a foreground-only phone.

### 2.15 Open questions

**Q-TRUST-1.** What admission posture stops ghost members, peers and server-written grants? **Decided by owner 2026-11-03 (owner decision 3):** a customer key authority from v0 (with owner decisions 5, 110, 112, 113 and 126-128; §7.9), subsuming member-signed admission. *Residual:* none.

**Q-TRUST-2.** Is the harness inside the device trust boundary? **Decided by owner 2026-11-03 (owner decision 47):** yes; its compromise is a device compromise (§2.10). *Residual:* none.

**Q-TRUST-3.** May URnetwork obtain certificates in its own zones? **Decided by owner 2026-11-03 (implied by owner decision 59):** yes, published and watched through CT (EX1). *Residual:* none.

**Q-TRUST-4.** May web pages decrypt with served code? **Decided by owner 2026-11-03 (owner decision 76):** yes, labeled (EX7). *Residual:* none.

**Q-TRUST-5.** Does release integrity gate "end-to-end encrypted"? **Decided by owner 2026-11-03 (owner decision 77):** no; signed releases only (EX7). *Residual:* none.

**Q-TRUST-6.** Should recURd get its own issuer and keys (X17)? **Decided by owner 2026-11-03 (implied by owner decision 108):** not initially (§2.12). *Residual:* none.

**Q-TRUST-7.** Without an ACL document, should providers refuse loopback, LAN, link-local and overlay destinations to sidecar sources (I-10)? **Decided by owner 2026-11-04 (owner decision 120):** (a) no; allow-all stays, disclosed (§2.18), and sidecar/design/pitch5.html:689 holds once a network has a policy. *Residual:* none.

**Q-TRUST-8.** May product copy claim "end-to-end encrypted" without external review (owner decision 99)? **Decided by owner 2026-11-04 (owner decision 119):** (a) yes, now, with §2.18's unaudited-cryptography disclosure on the security page; sidecar/design/pitch5.html:931 changes. *Residual:* none.

**Q-TRUST-9.** Cross-cutting (§6, §16, §23). Who is D-TRUST-10's witness, and when do shared-group writers stop without one? **Decided by owner 2026-11-04 (owner decision 129):** (c), now D-TRUST-10: agents witness too, and writers stop at a published per-network bound. *Residual:* §2.8's: no bound across a split the server makes, or in own groups.

### 2.16 Departures from PLAN.md

- **PLAN.md:59**'s second sentence and **:84**'s termination clause: superseded by owner directive 2026-11-03 (X2, §11; X1, §13); :59's git identity stands (owner decision 81).
- **PLAN.md:119:** rules sit on the server only as signed ciphertext that devices evaluate (owner decisions 5, 6, 72; §8.16).
- **Not PLAN.md.** Owner decision 84 keeps cli/UI.md:11's 0.0.0.0 default (D-TRUST-8); owner decisions 77, 99 and 119 change sidecar/design/pitch5.html:930-931, owner decision 120 limits :689 to networks with a policy, and owner decision 170 narrows :640 to session contents in team networks.

### 2.17 Interfaces

- **Provides:** the threat model, key custody, the statement, exposure bound and list (`metadata_list.yml`, Appendix G), invariants, and §2.18's disclosure text.
- **Consumes:** owners' server-visible tables and key families (§6-§21); §6.4's `HeadCheck`; §7's P0, route allowlist, authorization log and config repo; §13's CT watch; §16's approvals; §17.6's listener guard; §18.8's key origin; §22's tests.
- **Subprotocol messages:** none.
- **API routes:** none.
- **Tables:** none.
- **Services and config:** `metadata_list.yml` (§22.7); `ServiceSettings.witness_bound_hours` (§7.9); `preview_networks` in `config/<env>/sidecar.yml` (D-TRUST-3, §7.4).
- **Assumptions about other sections:** §5.4, §7.9, §8.5, §10.9 and §18.5 carry I-4's consent and alarm; §7.9's AdminSet holds every config-signing role, and its `ServiceSettings` the bound §6.4 applies; §6.4 relays `proven` pins with their proofs and `unverified` pins with their paths, and counts no witness while the counting device holds an UNVERIFIED pin or from a revoked, parked or suspended peer, as FS-17's relay cases test; §7.4's stage 2 waits for the app and extension releases that §18.7 and §18.15 schedule (D-TRUST-3); §7.9's compromise cascade parks what the revoked device admitted, directly, through another device or through a recovery key it bound, voids their Delegations, recovery bindings, KeyRegisters and EvsShares, ends the Delegation that admitted a revoked agent, parking the agents it admitted from since_n (§7.9's delegation row), lets a binding a void restores admit only through the vetoable recovery window, shown as `recovery_window` (§5.6, §18), and lists for admins what they signed that stands; §5.9 re-seals keychain.wrap at each cascade change of a member's binding, with no HPKE copy while none is current, and §5.9 and §7.9 revoke for compromise and enroll anew each device whose backups may hold a sealing to a voided binding (owner decision 149); §7.9 logs recovery bindings and rebinds with only their ids in the clear, and its recovery anchor rests on `genesis_sig`, which only the code produces; §12.6 deletes replaced snapshots and §19.10 sends a network newer than both dumps down the deleted-network path, as dns-1, api-7 and evs-1 state; §11, §15, §18 and §19 provide §2.18's mirrors; §7.9 designs owner decision 136's projection cache `{acl_<networkId>}e`, which only api writes, and §8.9's gates read through it; §7.9 and §19.10 resume the authorization log after a site loss; §11.8 and §19.6 define `place/` and placement (owner decision 145); §15.15 names mx-2's `mail_connection_record`, whose rows §21.9's `copied_rows` covers, and §13.15 and §19.7 cert-1's `{tcb_}`; §19.6's object table, §19.7's tables and Redis tags and §22.7's guard carry every family §2.8 names, `projrows/`, `place/`, `genpack/`, `drops/`, `dropscan/`, `network_client_lease`, `{dpop_}`, `{acl_}e`, `{acl_}q`, `{tokgen_}` and `{evsd_}` included; §11.14, §16.10 and §18.4 fetch index files only by sync position and documents only when opened (I-19), and §22 asserts that a "search more" issues the same requests whatever the query, and a remote one the same frame sizes and no evs request; §11.14 pads every remote-search body and fetches nothing for a remote search, §6.4's control contracts carry SEARCH where no data contract reaches the indexer (D-PROTO-21), and §4.6's C19 withholds every report of a requester-indexer pair that §6.11's bit 1 marks to each §6.10 window's end and reports both directions at its fixed floor, and §18.7's foreground keeps the window with a keepalive (connect-5); §16.11 provides I-20's boundary from M6; §11.13 and §20.7 serve, list and bill a held drop as a finished one (owner decision 184).

### 2.18 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A sidecar ships before §7's P0, or agents use an app's device token on AppAdmin routes before stage 3 | Medium | Critical | D-TRUST-3; stage 3 after app migration (owner decision 45) |
| Unaudited cryptography: in-house MLS on draft ciphersuite 0x0010, post-quantum against passive adversaries only, the key ladder and its Ed25519 authority signatures, which a future forgery would make retroactive (§10.5), the storage format and path tokens, later the ZK mail proofs (owner decision 99) | Medium | Critical | mlswg vectors, differential tests (owner decision 43), fuzzing (owner decision 101); the security page discloses this row (owner decision 119) |
| Without an ACL document, untagged sidecars reach providers' LAN, loopback, link-local and overlay addresses (owner decision 120) | High | High | Disclosed; any tier may write a policy (owner decision 73) |
| A reaped or ephemerally expired Delegation-admitted agent, or a leaked reader seed, reads the config and tag repos until the Delegation's key drops; a leaked whole auth key also admits fresh agents, each with its own wraps, until the Delegation ends (owner decision 114) | Medium | High | Disclosed; `not_after` ≤ 90 d, 30 d for CI, replaced at each CI secret rotation and after a key drop; a `Suspend` or any non-reap revocation of one of its agents drops the key, and DelegationRevoke or a compromise revocation of one of them ends the Delegation, parking what it admitted from `since_n` (§7.9, §10.5); the revoke plan shows the three apart (§7.10) |
| A site or Hurricane Electric outage stops both nameservers: every ur.network name, ACME DNS-01, DANE and, from M7, inbound mail (owner decision 123) | Medium | Critical | Accepted; paged at all hours from M5 (owner decision 143); an outage past a sender's retry window (14 h to 5 d, §15.3) bounces its mail |
| "Validated" (owner decision 135) trusts mxedge's reported sender address and the author's DKIM domain, not the delivering hop, so an intercepting mxedge can mislabel mail, and burner mail from an operator listed only for MTA-STS is "validated" with no policy applied | Low | High | Disclosed (EX3); REQUIRETLS is exact only as the final hop's requirement; the versioned operator list is a reputation inference (§15.5) |
| Site loss (owner decision 94) erases what no device mirrors: unconsumed deposits, unmirrored team records, recovery-code-only members' access to repos no surviving writer device holds, iOS-only users' mail bodies, general repos no device syncs, and an erasure only lost devices held | Low | Critical | Mirrors on designated indexers (none by default, owner decision 177; `ur status` names each unmirrored record-class repo) and other owner devices (owner decisions 90, 150), phones' mailbox-vault and burner mirrors (§15.16), re-seeding (§19.10); a stale mirror can return an erased key only if no surviving device holds the ERASE (§11.12) |
| A writer, agent or compromised device turns versioning off and overwrites files, each overwritten version's content gone a minute later | Medium | Medium | History written while versioning was on stays (owner decision 158) unless a repo admin drops it, after a 7-day window any repo admin can cancel or at once with `now` (owner decisions 173, 183); config and mailcfg repos and git-mode refs refuse it; a repo admin's lock (§8.8); statements keep every version's hash, size, time and signer; listings and approvals show the setting (§11.7, §16.8) |
| A rogue or compromised repo admin drops history | Low | High | The 7-day window, with notices on every repo admin's devices, any admin's cancel and a lock voiding a pending drop; in owner-bound repos only the owner's consented devices (owner decision 126); `now` skips the window, as RepoDelete's does (owner decisions 82, 183) |
| A drop's inline content outlives it in packs | Certain until compaction | Low | Never served again; slot-keyed repos shred it at once; disclosed (§2.8) |
| A thief holding a member's unlocked device that registered no presence key, or who knows its passcode or its security key's PIN, revokes or suspends the member's other devices, vetoes its recovery, admits or confirms a device the thief holds, or rebinds the member's recovery code | Low | High | Disclosed; `ur login` and the apps offer a platform presence key, after which §7.9's presence row requires its countersignature on those statements (owner decisions 142, 185, 187, 189) |

### 2.19 Phasing

- **Each invariant with its mechanism.** M1: I-1 to I-3, I-12, I-13, and I-6 and I-7 with the P0's first stage (§7.4). M2: I-4, I-16 with D-TRUST-10's bound, device-removal I-15, members' I-5. M3: I-8, I-9. M4: I-5, I-10 (§17). M5: I-5 (§9), I-14, CT and zone watches, TTL sweeps, holds. M6: member-removal I-15, I-20 (§16.11), two-approver policies, the audit reader. M7, M9: I-11, mail-host zone watches. I-17 per listener, I-18 at each Gn-out (§23.8), I-19, as amended for remote search, at M10's Gn-out (owner decision 169); connect-5, evs-27 and evs-28 before their mechanisms release (I-18).
- **Later:** key transparency, a release log, ECH, web code transparency.
- **Blocking:** D-TRUST-3 gates every sidecar release; "end-to-end encrypted" appears with D-TRUST-4's document, the canary and §2.18's disclosure on the security page, no audit gating it (owner decision 119).
