## 3. Architecture overview and end-to-end flows

### 3.1 Purpose and scope

This section assembles §1-§23 into one picture: a component map, the repo graph, planes, runtime topologies, thirteen end-to-end flows and a service summary. It designs nothing; every step cites its owner. The flows show only the directive (CONVENTIONS §0) and the owner's decisions ("owner decision N", front matter): 1-150, of 2026-11-03 to 2026-11-05, decide every X item and, with 141-145, the five owner questions the peer review raised (Q-EVS-8, Q-MCP-6, Q-OPS-9, Q-KEYS-15, Q-OPS-10), and F2 and F11 add the 2026-11-05 decisions on versionless objects (158, 161) and on the index and search (151-157, 166); F12 adds a phone's search through an indexer (175-178, 188, 191) and F13 the team directory (170, 171, 179-182). Owner decisions 167-184 answered every v1 question, 185 the SDK fixes' and 186-191 the final meta review's; owner decision 197 put only forwarding in apps' VPN components (3.6, F7), and its design raised the two owner questions open now (Q-BRIDGE-8, Q-SDK-7); F11's index cadence follows owner decision 172 and 3.15's milestone for format 2 owner decision 169. Drafts' disagreements became Q-ARCH-1 to -9, closed by the 2026-11-03 design-review round (3.11).

### 3.2 Requirements

| id | requirement | source |
|---|---|---|
| R-ARCH-1 | Component map, repo graph, planes, topologies and flows, citing owners; contradictions recorded; nothing new | OUTLINE §3 |
| R-ARCH-2 | sidecar imports only connect; server and sdk import sidecar; new pieces live in sidecar | PLAN.md:5-7; owner rule 1 |
| R-ARCH-3 | Storage, the TLS edge and mail see only ciphertext plus small header values, except mail to URnetwork at `rpt.bringyour.com`'s report and role-mail listener | CONVENTIONS §0; D-TRUST-4 |
| R-ARCH-4 | Apps use the sidecar directly; the extension runs it as a web worker | PLAN.md:28 |
| R-ARCH-5 | Flows and their scenarios show only the owner's decisions, and an open question's recommendation only marked proposed | owner decision record (front matter); D-PHASE-2 |

### 3.3 What exists today

Nothing is built (§4.3); owners cite the code they build on. The map rests on:

| Fact | Owner |
|---|---|
| The only server push is the resident's ControlId client on Redis key events; frames fit 16 KiB; encryption defaults to Off, and the sdk provider runs Opportunistic | §6.3 |
| Network mode needs a shared network and grants allow-all egress, so edges and shares need other modes | §6.10 |
| Client tokens still reach AppAdmin routes such as `/auth/code-create` (AUTHZ1) | §7.3 |
| The lb has no SNI routing, port 25 or TCP 53 (public UDP 53 is connect's WhoDis) and caps bodies at 16 MiB; ur.network is on Route 53, signed but with no DS | §12.3, §13.3, §15.3, §19.3 |
| MinIO: one saturated shared host, an archived upstream, no conditional-PUT fix; across pools, a PUT checks its precondition only in the pool it picks by free space | §11.3, §19.3, §19.6 |

### 3.4 Component map

```text
CUSTOMER DEVICES                     URNETWORK (bringyour.com; server/cli/<svc>, §19.4)            OUTSIDE
harness --stdio--> ur relay          api: enroll, token exchange, /sidecar/*, push tokens, the signed
 --unix socket--> ur daemon --HTTPS-->  id projection for the gates, cert orders (§5, §7, §8, §13, §18)
 sidecar.Sidecar per network (§5):   sockets (§9); evs (§11) and gkm (§10), stateless over the
  evs, gkm, sockets, mail, tls,        file cluster (§19.6): NVMe metadata clusters (v0: one set of
  bridge; mcp, with the team           8 PM9A3), each repo and its group on one from creation
  directory's tools (§16.11);          (place/<repo_id>), and the HDD segment cluster
  search (§16), with remote          dns (§12) on dns edge hosts: TCP and UDP 53, DNSSEC <------ resolvers
  search, asking (app hosts) and     taskworker: certs (§13) --ACME DNS-01--------------------> LE, GTS
  serving (indexers) (§11.14)          push sender (§18, §19) -------------------------------> APNs, FCM
 config repo in evs (§7, §8):        connect residents: hints from ControlId (§6.8)
  admissions, policy, bridge rules   lb hosts' shared addresses:
 repo keys (§10): member devices       TCP 443, SNI split --> tlsedge (§13) <---------------- visitors
  are MLS leaves (in config and the    TCP 8443, 8883, 5671 unsplit --> tlsedge <------------ visitors
  team directory, the first 1,000);    TCP 25 in --> mxedge (§15) <------------------------ sender MTAs
  agents hold wraps                    smtpedge (§14) --TCP 25 out from lb IPv4---------> destination MX
 sdk.Sidecar in apps (§18)           Postgres via PgBouncer: no file-storage state; Redis Cluster: soft
 forwarding in apps' VPN components    state only (leases, push sequence, verified head and projection
 extension, ur.io pages: wasm (X14)    caches, gkm acks; owner decision 136)
 sidecar traffic: id 21842, e2e,
  Required, relay-only (§6)
```

### 3.5 Repo graph and planes

```text
sidecar ---------> connect                (only import; §4 D-REPO-1, D-REPO-4)
sdk -------------> sidecar root, protocol; its forwarding files only sidecar/device, protocol/bridge
                                          and the root's forwarding files (§18.10, D-SDK-20)
server ----------> sidecar root, sidecar/<svc>service engines, sdk, connect (owner decisions 19, 104)
apps, extension -> sdk bindings           (§18 D-SDK-2)
warp, config, vault, build, minio: no Go import (§19; owner decision 195)
connect: X9 rows per owner decisions 22, 85, 86, 176 (§4.6)
```

| Plane | Carrier | Endpoints | Protection (owner) |
|---|---|---|---|
| Control | HTTPS | sidecar → api, sockets, gkm, evs, dns, certs | client JWT, or a 15-min single-audience token evs and gkm verify offline (§7 D-TEAM-8; owner decision 2) |
| Push | ControlId frames on id 21842, or an HTTPS long-poll; APNs and FCM wakes | resident publishers → clients; §19's sender → phones | hints of server-held state or client-sealed bytes; wakes carry a topic and version (I-3; §6 D-PROTO-5, D-PROTO-8; owner decisions 17, 88) |
| Peer data | id 21842 RPC, streams | sidecar ⇄ sidecar, edge ⇄ sidecar | Required, relay-only; Network within a network, its `control` class carrying only HeadCheck and, to a search indexer, remote search (§6 D-PROTO-18, D-PROTO-21; owner decision 175), Service (C9) for edges, FriendsAndFamily for shares; every byte debited (§6 D-PROTO-6, D-PROTO-10; owner decisions 10, 11) |
| IP data | connect IP path | sender → target provider | Required links; targets serve only sealed flows; cross-network flows as FriendsAndFamily (§17 D-BRIDGE-5; C18, owner decision 86) |
| Bulk storage | HTTPS segments and objects | sidecar → evs, gkm → file cluster | ciphertext plus the keyed token tree, per-file change history, padded sizes and the push DAG (§11 D-EVS-1; owner decision 2); gkm, ciphertext plus §10.6's ids and sizes (owner decision 115) |
| Public edges | TCP 443, 8443, 8883, 5671 and 25 in, 25 out; TCP and UDP 53 | visitors, MTAs, resolvers ⇄ edges | TLS ends in the sidecar (X1, X6, X7; §13-§15), except at `rpt.bringyour.com`'s report and role-mail listener, which parses headers and aggregate report data only, seals the raw bytes and persists no plaintext (D-TRUST-4, §2.8 mx-4; §15 D-MAIL-10); DNS is public and signed (owner decisions 69, 109) |

### 3.6 Runtime topologies

| Topology | Sidecar process | Client (X10, owner decision 4) | Components, carrier | Refs |
|---|---|---|---|---|
| Laptop CLI, harnesses | one `ur daemon` per `--instance`, one Sidecar per network (owner decision 23); `ur mcp` relays over a peer-uid Unix socket | top-level; child after app pairing (§5.8) | all; `ur tun` on Linux | §5 D-CORE-9; §16 D-MCP-2 |
| iOS app | sidecar role in the app, while open; in the network extension only forwarding, self-contained with its own key (`sidecar/device` and the root's forwarding files) | child | evs, mail, dial; listens only while open, so never an indexer (owner decisions 12, 150; §15.6); forwarding whenever the VPN runs | §18.4, D-SDK-1; owner decisions 87, 197 |
| Android | sidecar role in the app, while open; in the VPN service only forwarding, as on iOS | child | as iOS (owner decision 197) | §18.4; §15.6 |
| Desktop apps | `ur daemon`; app in remote mode; the network extension or app service runs only forwarding, as on iOS | child after pairing (§5.8) | all; forwarding in the VPN component | owner decisions 87, 197 |
| Extension, ur.io pages (X14) | slimmed `sidecar.wasm` in an offscreen document, meanwhile native messaging to `ur daemon`; ur.io pages run it read-only from the key origin `sidecar.ur.io`, labeled | top-level, admin-refused, no egress | evs, mail, dial, never listens; HTTPS only until C4's WebSocket carrier | §18.8, D-SDK-18; §7 D-TEAM-24; owner decisions 26, 76 |
| Cloud agent | `ur daemon` in the VM, through the sandbox's HTTP CONNECT proxy (C8) | tagged, ephemeral; reads the config and, in a team network, the team directory, announcing itself and its runs there while admitted (§16.11; owner decision 170), and otherwise only deposits unless a grant or EvsShare names it (§8.6's ceiling); a reap removes its own key; its Delegation's key reads until DelegationRevoke, `not_after` or a key drop (§10.5) | evs by wraps, never an MLS leaf (owner decision 114), records, MCP; §18.9's rungs | §7.7; §18 D-SDK-7; owner decisions 6, 49 |
| Indexer (owner decision 150) | an always-on `ur daemon` (desktop, NAS or VPS) run from its unit (§5.8); never an app, which runs its sidecar only while open (owner decision 197), a browser, or an ephemeral or read_only sidecar | as its host's row | the services its `IndexerSet` names (§7.9, D-TEAM-27): receiving mail (owner decisions 12, 58); mirroring record-class repos and, on an admin's indexer, the config (§11.13; §16 D-MCP-10); in v1, rolling index buckets up once per bucket length, backfilling unindexed pushes, verifying other writers' index files and keeping all partitions current (§11.14; owner decision 157); at network scope, mirroring the team directory on an admin's indexer, rolling its index up and removing revoked sidecars' cards (§16.11); as a designated search indexer, answering its network's app hosts' remote searches over the repos it reads, which no phone does (§11.14; owner decision 175); embedding (Later); other services that need an always-on device, such as `scim_signer` (§7.6) | §11.14; §15.6; §16.10, §16.11 |
| Server | api, evs, gkm and sockets on lb hosts; the three edges on the lb's shared addresses; dns on dns edge hosts; certs, §10's reconciler and the push sender in taskworker; on 4 new hosts at one site (2 PM9A3 1.92 TB NVMe and 16 × 16 TB HDD each), the metadata cluster, more at §19.9's triggers, and the segment cluster; soft state in Redis | edges: platform clients in `urnetwork-edge`, Service mode | — | §19.4, §19.6, D-OPS-2; owner decisions 18, 20, 21, 34, 71, 94, 116, 136-140, 145 |

**Indexers** (owner decision 150). An indexer is a device its network designates, by an `IndexerSet` in the config repo, as an always-on point device for the background services its row lists; a network may designate several, and has none until an Owner or Admin designates one at network scope, or a member's consented device at member scope (owner decision 177); owner decision 12's always-on receivers and a Team's receivers (owner decision 58) are indexers chosen for mail (§15.6). Always-on stays a device property, and the name is unrelated to evs's server-side path index (§11.8). A designation grants no key, grant or read, so an indexer serves only what its admission, tags and grants reach; it decides who runs a service first, never who may read, and for search it also bounds which devices a phone asks (owner decisions 175, 178). With none designated or online, mail reaches whichever receivers run and otherwise waits on sender retries (§15.6); the first writer committing after a search bucket expires rolls it up, a day after expiry where an indexer serves the repo, and the next capable writer backfills (§11.14); each device fetches all partitions under its own policy (§18.4), and a phone's "search more" downloads all and shows possible matches (owner decision 155); any member device removes revoked sidecars' directory cards after 24 h (§16.11); `ur status` names each unmirrored record-class repo (§11.13); and SCIM removals wait for an admin device (§7.6).

### 3.7 End-to-end flows

Each flow implements the owner decisions its header names (D-ARCH-3, D-ARCH-4). Actors are columns; numbered notes give details and owners; Appendix C defines terms.

**F1. Enroll a sidecar** (X3, X8, X10, X12: owner decisions 3-6, 17, 110, 112-114, 126-128, 144). Actors: the user or an auth key; the new daemon; api; its connect resident; evs and gkm; the admission's signer, which commits the Add from its config leaf or, if wrapped, writes the wrap.

```text
   user         daemon       api          resident     evs, gkm     signer
1  |--login---->|            |            |            |            |
2  |            |[keys]      |            |            |            |
3  |            |--enroll--->|            |            |            |
4  |            |--bind----->|            |            |            |
5  |            |--connect--------------->|            |            |
6  |            |            |            |            |<--admit----|
7  |            |--KeyPackages, or a ReaderKey-------->|            |
8  |            |<--Welcome, or a wrap-----------------|<--Add/wrap-|
9  |            |--read config------------------------>|            |

1  `ur login` (PKCE or the device grant, then one single-use auth key), `ur connect --token
   ur-authkey-...`, or an sdk host minting a child of the device client; the key or invite carries the
   config repo's genesis head, the trust anchor; without one, the daemon trusts the genesis on first
   use and shows its safety number (§5.6; §18 D-SDK-1; owner decision 5)
2  the daemon generates the ClientKey seed, the identity key and sidecar_id, one set per network it
   joins (§5 D-CORE-5, D-CORE-6; owner decision 23)
3  POST /network/enroll (an sdk host uses /network/auth-client): the ClientKey and, by default, a
   no-egress declaration, so the sidecar counts in sidecar_clients, not concurrent_clients; the token
   carries the admin-refused mark, never administers the network and expires in 7 days, a rule for
   sidecar-held tokens only, and its refresh and token exchange carry a DPoP proof by the ClientKey
   (§7 D-TEAM-1, D-TEAM-5, D-TEAM-14; §7.4; §20.8; I-6; owner decisions 4, 45, 103, 131). Names and
   tags live only in the config repo (owner decision 46)
4  POST /sidecar/bind: the SidecarIdentityBinding, signed by both keys; without the mark the daemon
   does not start (§5 D-CORE-5, D-CORE-7)
5  Required, relay-only, id 21842; provides {Network}, adding Service only while it holds a tls/ or
   smtp/ registration and FriendsAndFamily only while it holds an inbound share (§6 D-PROTO-1,
   D-PROTO-6, D-PROTO-10); PushReset from ControlId, or the HTTPS long-poll (owner decision 17; §6.8)
6  a SidecarAdmit delta (§7.9): one admin signature admits after a safety-number check (owner
   decision 110); the member's consented device or recovery key admits that member's new untagged
   device alone, unless self_admit is off (owner decision 112); a tag owner's device or an auth key's
   Delegation admits for its tags. A device of an AdminSet member is an authority statement: k of n
   Owners and Admins sign it, the member's existing device counting as one, and a recovery key counts
   as one only after a 72 h window in which any admin device may veto, so a personal network (k = 1)
   recovers alone (owner decisions 110, 112, 127). An admin-only admission under member M adds no
   reader to M's owner-bound repos until M's device signs OwnerConfirm, and M's devices alarm on
   admissions under M that they did not sign (owner decision 126; §8.5). A network's first device
   instead creates the config repo, signing its genesis with the owner's identity key (owner
   decisions 3, 5; §7.9's bootstrap)
7  once admitted, a member's device uploads KeyPackages and a ReaderKey under a 15-min aud-gkm token,
   stored as gkm objects; an agent (tagged, ephemeral, CI or cloud) uploads only a ReaderKey (§7
   D-TEAM-8; §10.5, KF2; owner decisions 2, 114)
8  the device that signed the admission commits what it requires, the config group's Add or a first
   wrap, even if it writes no config; any writer leaf may too, and members reject an Add without the
   signed admission (owner decisions 113, 128; §7.9). Writing config records stays admin-only (owner
   decision 5). The first 1,000 live member devices by rank are the config group's leaves, which
   their admission records drive, and later ones read the config by wraps, as agents do, staying
   leaves of their data repos; a newly live device ranks last, so one that stays live never loses
   entitlement, while one parked or suspended, then restored before its Remove commits, ranks last
   too and, if that leaves it past the first 1,000, the next leaf commit removes it for lost
   entitlement as it reads on by wraps (§7.9's move; §10.9). A wrapped device commits no config-group
   Add or Remove: signing an admission, it writes the new device's first wrap. A recovery-admitted
   device first passes §7.9's anchor check of its genesis, committing, wrapping, sealing and signing
   nothing before it, and alarming and acting no further if it fails (§2.8 EX5); then it self-joins
   by external commit or, if wrapped, reads by its RecoveryWrap, then by wraps (owner decisions 128,
   144; §7.9's leaves, D-TEAM-18). An agent gets no leaf and reads at once by its Delegation's reader
   key, or by a ReaderWrap (owner decisions 5, 60, 114; §10.5, §10.9). A new leaf waits until a
   committing leaf is online; the Welcome arrives through gkm (§10 KF2)
9  the daemon reads the config through evs as in F2, checks every head back to the genesis through the
   admin set, and evaluates its own rules locally; it accepts no inbound stream before then, since
   peers' admissions live there. Until the network writes a policy, an untagged sidecar keeps today's
   same-network reach, LAN and loopback included, and product copy discloses it (owner decisions 105,
   120). The server's gates see only the signed id projection (owner decisions 5, 6, 72)
```

**F2. Write a file and notify subscribers** (X2, X13, X19: owner decisions 2, 18, 21, 24, 94, 136, 140, 141, 145, 158, 161). Actors: a harness; the writing daemon; evs; the file cluster; the subscriber's connect resident; a subscribed reader.

```text
   harness      writer       evs          cluster      resident     reader
1  |--push----->|            |            |            |            |
2  |            |[seal]      |            |            |            |
3  |            |--PUT seg-->|--seg------>|            |            |
4  |            |--push----->|--pb/, head>|            |            |
5  |            |<--version--|--hint------------------>|            |
6  |            |            |            |            |--PushHint->|
7  |            |            |<--read-------------------------------|

1  git push to the daemon's local git server (`ur mount`, http or ssh, authenticated), which binds all
   interfaces by default (`--listen` narrows), serving plaintext only on loopback and TLS or ssh beyond
   it (owner decisions 84, 130; D-TRUST-8), and refuses new commits whose committer is not this
   sidecar, except a signed import (§11.11); `git-remote-ur` serves ur://<net>/<repo> wherever a
   sidecar runs (owner decisions 24, 81)
2  path tokens t = HMAC-SHA256(K_path, t_parent || name)[:16], with names in a sealed per-directory
   table; each file is a checkpoint+diff chain or, with versioning off on a file-mode ref, its newest
   checkpoint or chunk set (§11.7), under XChaCha20-Poly1305 with keys from RK_g, the repo key of
   generation g, which member devices get through the repo's one MLS group and agents by wrap, padded
   by Padme (owner decisions 2, 60, 114, 158; §10.5; §11)
3  PUT seg/<repo>/<id> (at most 8 MiB, for chains over 16 KiB; a versionless record padding to at
   most 16 KiB rides in the push instead, §11.7) under a 15-min capability token (aud evs, scope
   repo:<id>:rw) that evs verifies offline; evs streams the segment to the HDD cluster and answers a
   MAC'd upload receipt, writing nothing to the metadata cluster (owner decisions 2, 21; §11
   D-EVS-34; §19.6)
4  the push: a manifest delta {token path, base version, locators}, sealed commit metadata and the
   head, Signed by the identity key, with its upload receipts; evs appends the push to its
   group-commit batch (pb/) and swaps head/<repo>/<ref> by If-Match on the repo's metadata cluster,
   fixed at creation by a create-only place/<repo_id> on the first cluster (owner decision 145),
   index entries folding later from committed pushes, and the content of versionless versions the
   push replaced or removed purged by evs a minute after it commits (owner decision 161; §11.13); a
   push over 1 MiB or 1,024 entry writes travels in hashed parts that one seal and that head swap
   commit. evs commits only by the head's If-Match; git-mode refs commit on their tip, so a lost race
   is a stock non-fast-forward, and file-mode refs land disjoint pushes (§11.7). Every metadata write
   spends §11.13's NVMe write budget, which refuses the heaviest network first (owner decisions 2,
   140, 141; §11 D-EVS-5, D-EVS-20, D-EVS-22, D-EVS-30, D-EVS-31, D-EVS-33)
5  200 {version}; evs matches the statement's changed token paths against the repo's leases in Redis
   (owner decision 136) and triggers one hint per matching subscriber through the resident's Redis
   keyspace path; usage goes to §20 as asynchronous events (owner decisions 2, 17; §6.8)
6  from ControlId: PushHint on topic evs:<repo_id>, a hint only; phones also get a content-free wake
   (owner decisions 17, 88; §6.8; §18)
7  the reader fetches the head summary, the statements since its pin, the changed index entries and
   segment ranges through evs (2-3 GETs on the cluster, plus one range GET per uncached statement
   since its pin; the head usually from a verified cache, owner decision 136), accepts the head only
   if its signer is in the repo's writer set, checks every statement since its pin and the one behind
   each entry it reads, and pins the head (§11.9); HeadCheck confirms the pin with a witness, any
   admitted reader, agents included (owner decisions 2, 7, 129; I-16; D-TRUST-10)
```

**F3. Add a member to a repo** (X12 and grants: owner decisions 1, 7, 8, 43, 44, 59, 60, 113-115, 126). Actors: an admin device, which admits, grants and commits first (a repo admin may grant instead, and any writer leaf may commit); api; gkm; the new member's device; evs.

```text
   admin        api          gkm          new dev      evs
1  |            |<--enroll----------------|            |
2  |--admit------------------------------------------->|
3  |--grant------------------------------------------->|
4  |--claim KP-------------->|            |            |
5  |--commit---------------->|            |            |
6  |            |            |--Welcome-->|            |
7  |            |            |            |--read----->|

1  member N accepts the invitation, which carries the config repo's genesis (§7.5; owner decision 5);
   N's first device enrolls as in F1 steps 1-5 and, as N's first device, carries N's consent (owner
   decision 126; §8.5)
2  one admin signature admits N and the device in the config repo, and the device joins the config
   group as in F1 steps 6-9 (owner decisions 3, 5, 110)
3  a repo admin, or a config writer (owner decision 8's network admins), signs RepoGrant{repo, N,
   reader, expiry} into the repo's access log: its RepoCreate, RepoAdmin, RepoGrant and RepoRevoke
   chain, carried as config deltas (§8.8); N's devices then get repo:<id>:r capability tokens (owner
   decisions 7, 8; §11). In an owner-bound repo, such as a vault or mailbox, admins add no reader but
   owner decision 63's visible audit member; only the owner's consented device shares it, by EvsShare
   (owner decision 126; §8.5, §8.8)
4  the granting device checks each of N's devices against the config repo's admissions, then claims
   their KeyPackages (§10 D-KEYS-4)
5  its leaf commits the Add, or any writer leaf does after 15 s plus jitter: the signed grant, not the
   committer, carries the authority, and members reject an Add without it (owner decision 113;
   §10.9). The commit is a PrivateMessage whose clear authenticated_data carries only
   GkmCommitHeader{generation, auth pin}, with no roster delta (owner decision 59; §10 D-KEYS-3),
   plus the Welcome, GenWrap (the newest RK_g under the new epoch's key) and, at 16 leaves or fewer,
   a sealed GroupInfo; gkm sees only §10.6's values, which owner decision 115 confirmed, and writes
   gkm/<group>/epoch/<n+1> with If-None-Match: *, so the first commit wins (owner decision 2).
   Members derive the roster change from the config repo (§10.9). A grant to an agent instead gets a
   ReaderWrap from any holder but a read_only one, writers hinted first, with no commit (owner
   decision 114; §10.9)
6  the device processes the Welcome, unwraps RK_g, checks it against the commitment C_g, and walks the
   ladder back to RK_1 (§10.5)
7  it subscribes and reads as in F2 steps 5-7. A device N enrolls later joins through the next online
   writer leaf, hinted pending on the per-client gkm topic of the repo's writers (§6.8; owner
   decision 113; §10.7 KF2)
```

**F4. Publish a local HTTPS service** (X1, X4, X5: CONVENTIONS §0; owner decisions 13, 14, 34, 39-42, 121).

```text
   visitor      tlsedge      sockets      certs        listener     approver
1  |            |            |            |            |--request-->|
2  |            |            |            |<--CSR------|            |
3  |            |            |<--register--------------|            |
4  |--:443----->|            |            |            |            |
5  |            |--Find----->|            |            |            |
6  |            |--StreamOpen------------------------->|            |
7  |<=========== TLS ends in the listener ============>|            |

1  `ur bridge public-tls app:3000` requests {dns:app, sock:tls/443/app}; public exposure needs an
   admin's approval through §16.6's channels; Community publishes need a verified account and last at
   most 7 days, renewable (owner decisions 41, 74, 75, 96; §8 D-ACL-7; §13.9-13.10). Hosts are one
   label or @, below a scope sublabel where needed (Q-TLS-6 (a); owner decision 40)
2  POST /tls/cert-order: a CSR for {*.<net>.<root>, <net>.<root>} from this device's own P-256 key plus
   a Signed attestation; certs orders under URnetwork's ACME accounts and writes the DNS-01 record to
   the self-hosted dns (owner decisions 39, 40, 69; §13 D-TLS-6, D-TLS-7)
3  register tls/443/app with AppMode http (45 s lease, 15 s heartbeat), or tls/<port>/app on 8443,
   8883 or 5671 (owner decisions 68, 121); the name stays plaintext, since SNI and DNS expose it, while
   CT shows only the wildcard (owner decision 67; §9 D-SOCK-3; §13.6, §13.8)
4  the visitor reaches the lb's shared addresses; the ssl_preread SNI split sends *.<root> to tlsedge
   with PROXY v1, and bringyour.com names to the http listeners, while 8443, 8883 and 5671 go
   unsplit to tlsedge; app.<net>.<root> maps to (network_id, tls/443/app) (owner decisions 13, 34,
   121; §13.4; §19 W7)
5  Find returns a primary and a backup ticket, bound to one of tlsedge's K platform clients, and records
   the pair that authorizes the Service contract (§9 D-SOCK-4, D-SOCK-12)
6  a Required stream in Service mode (C9): StreamOpen{ticket, TlsEdgeOpen, the ClientHello as early
   data}; a Service lease debits the bytes (owner decisions 10, 11; §6.7; §13 D-TLS-4; §20)
7  the listener admits the ticket and checks its local policy (§9.6), then answers TLS with the device
   key; its front, chosen by the registration's AppMode and never by a missing ALPN, enforces the 421
   rule and the audience, by default network members through URnetwork login, counting that session
   only on same-origin requests and top-level navigations (owner decision 42; §13 D-TLS-5, D-TLS-13;
   §13.7). tlsedge splices bytes it cannot read
```

**F5. Send mail** (X7: CONVENTIONS §0; owner decisions 35, 36, 38, 124, 125; ships at M9). Actors: a mail client or agent; the daemon, as local mail server; sockets; smtpedge; the destination MX.

```text
   client       daemon       sockets      smtpedge     MX
1  |--submit--->|            |            |            |
2  |            |--Find----->|            |            |
3  |            |--preamble-------------->|--STARTTLS->|
4  |            |<--result----------------|            |
5  |            |<============ handshake, spliced ====>|
6  |            |--pi1-pi3 (+ DATA parts)>|[verify]    |
7  |            |<========= records after each proof =>|
8  |            |--outcome--------------->|            |

1  `mail_send`, or the local submission port (§5.8) with AUTH, which binds all interfaces by default
   (`--listen` narrows), serving plaintext only on loopback and TLS beyond it (owner decisions 84,
   130; D-TRUST-8; §15.10); a new recipient needs an approval through §16.6's channels (owner decision
   75; §16 D-MCP-4); same-network recipients get a direct deposit (§15 D-MAIL-8). The flow ships only
   once the BDAT and DATA proofs of steps 6-7 are sound, fast enough on desktops and interop-tested
   (owner decisions 35, 99, 125)
2  Find ur/smtpedge, a platform name in urnetwork-edge that any enrolled client may Find (§9
   D-SOCK-11); the stream is Required, in Service mode (§14 D-SMTP-1)
3  SmtpPreamble{recipient domain and count, Message-ID, From domain, DKIM selector, size}; smtpedge
   checks halts, abuse standing, the daily outbound-connection quota, `mail send` and the From domain
   (owner decisions 30, 37, 96; §14.5-14.8); it resolves the MX with DNSSEC, dials from the lb's shared
   IPv4 addresses, whose PTR names under bringyour.com its HELO repeats, with no IP pools or per-IP
   warm-up (owner decisions 34, 124), and runs EHLO and STARTTLS itself; no STARTTLS, no send (§14
   D-SMTP-2, D-SMTP-3)
4  SmtpPreambleResult{send_id, X-UR-Ref, Feedback-ID, mx_host, DNSSEC chain}
5  the daemon's handshake (SNI = MX host) passes through the splice; it authenticates the MX by DANE
   (TL1, validating step 4's chain), MTA-STS (TL2) or an independent lookup (TL3), and refuses an
   unauthenticated MX unless the user allowed that domain (owner decision 38; §14.4)
6  every SmtpProof part binds the session keys to the observed handshake: pi1 covers EHLO; pi2 the
   EHLO reply, which fixes BDAT or DATA mode (BDAT only after CHUNKING), and the envelope (MAIL, one
   RCPT per recipient and, in DATA mode, DATA); pi3 the envelope replies (in DATA, the 354) and the
   header block, with the DKIM-Signature by this sidecar's own key, plus in BDAT the BDAT command and
   the final QUIT record, the body streaming unopened under §14.5's count bound, or in DATA the first
   body part, each later part having its own proof; DATA proves at most smtp_data_proof_bytes (about
   1 MiB on an M1), so a larger message to an MX without CHUNKING gets a DSN before MAIL and a
   too_large outcome for that recipient domain alone, which CheckSend predicts once the domain's mode
   is known (owner decisions 35, 36, 125; §14.5, D-SMTP-20, D-SMTP-22)
7  smtpedge forwards each client record only after the proof covering it verifies (§14.5)
8  SmtpOutcome; a record entry lists every recipient (§16.8). If the MX is on mxedge's router
   interfaces, smtpedge splices to mxedge over the host LAN and TLS still runs sidecar to sidecar
   (§14.4, D-SMTP-13; Q-ARCH-3 (a))
```

**F6. Receive mail, online and offline** (X6: CONVENTIONS §0; owner decisions 12, 32-34, 111, 135, 150, 177).

```text
   sender       mxedge       sockets      receiver     evs          reader
1  |--TCP 25--->|            |            |            |            |
2  |            |--Find----->|            |            |            |
3  |            |--StreamOpen------------>|            |            |
4  |<========== TLS ends here ===========>|            |            |
5  |            |            |            |--deposit-->|            |
6  |            |            |            |            |<--ingest---|
   |no receiver online:
2' |            |--wake (mail hint)------>|            |            |
3' |<--close----|  the sender retries; mxedge holds nothing

1  TCP 25 reaches mxedge's router on a new port of every lb interface but rpt.bringyour.com's two
   (§19.5 W4); it answers 220, EHLO and STARTTLS itself, rejects at the banner only high-confidence
   botnet and exploit listings from a commercial feed, and refuses plaintext transactions with 530
   (owner decisions 33, 34, 111; §15 D-MAIL-2). Those two reach mxedge's platform listener, D-TRUST-4's
   one exception: SNI or not, it terminates TLS, accepts only mail to URnetwork itself (abuse@ and
   postmaster@ on <root>, §14.8's reports), parses headers and aggregate report data only, seals the
   raw bytes and persists no plaintext (§2.8 mx-4; §15 D-MAIL-10)
2  route by SNI alone: mx.<net>.<root>, which every burner shares through the wildcard MX; DANE TLSA
   at _25._tcp.mx.<net>.<root> in the signed zone makes DANE senders send SNI; Find smtp/25/mx checks
   the listen grant (owner decisions 32, 34; §15 D-MAIL-1; §9)
3  a Required stream in Service mode: StreamOpen{ticket, MailIngress, the ClientHello} (§15.5; §6.10)
4  the receiver, a mail indexer where the network designates one (a desktop daemon, NAS or VPS),
   else whichever receiver runs, an app only while open and never as an indexer, answers with its own
   key and no second 220; RCPT is checked against the signed mailcfg, and a burned label gets 550
   (owner decisions 12, 32, 150, 177, 197; §15 D-MAIL-3, D-MAIL-4; §15.6)
5  the receiver checks SPF, DKIM, ARC and DMARC as received, within §15.5's per-message bounds, and
   seals that result (MailAuthEvidence, at most 8,192 B) with the message to the mailbox's drop key;
   a check a bound cut is no result and refuses nothing; 250 only once the deposit is durable (§15
   D-MAIL-5, D-MAIL-14)
6  a reader scores the message from the sealed reception-time result and writes the mailbox by CAS; it
   labels the message validated if the sender set REQUIRETLS, or if the SNI host has TLSA in our signed
   zone and the sender, identified by FCrDNS or aligned DKIM d=, is on the versioned list of DANE- or
   MTA-STS-enforcing operators, else opportunistic (owner decisions 98, 135; §15.5, §15.7)
2' no receiver online: mxedge sets a mail hint and holds the ClientHello up to 30 s while §19's
   sender pushes a content-free wake (owner decision 88; §15.6; §18)
3' still none, or no SNI: the router closes in the handshake, a temporary failure; the sender retries
   for 14 h (SES) to 5 d (Postfix), and the edge holds nothing (§15 D-MAIL-1; §15.6)
```

**F7. Reach a subnet behind another client** (X18, X9's C5, C6a, C13, C14 and C18, and rules: owner decisions 5, 22, 28, 50, 74, 85, 86, 120, 132).

```text
   sender       api, evs     target       LAN host     approver
1  |            |            |--request--------------->|
2  |            |<--rule-----|<--decision--------------|
3  |<--config---|--config--->|            |            |
4  |[classify]  |            |            |            |
5  |--link------------------>|            |            |
6  |            |            |[hook]      |            |
7  |            |            |--dial----->|            |

1  the target asks to expose 192.168.1.0/24 (`ur bridge expose`)
2  an approver signs an I-8 decision through §16.6's channels, and the target's daemon spends it: it
   files into the authorization log, by §7.9's POST /network/config/delta, a BridgeRoute delta that
   carries the approval under the rule id §17.8 derives from the use's effect_key, so a retry files
   one id; under an admin's standing grant in a config head, the delta needs no decision (owner
   decisions 5, 74; §16.6; §17.7, §17.8)
3  sender and target read the new log entry through api and the config head as in F2, verify the
   route's approval as §8.8 verifies a GrantActivate's, and evaluate the rule locally; the server's
   contract gate sees only reach(sender, target), as ids (owner decisions 6, 72)
4  a packet to 192.168.1.20 meets BridgeTable.Classify right after sendRoute.Load
   (sdk/device_local.go:5707; §17 D-BRIDGE-2); overlay addresses come from the network's random IPv4
   /16, by default in 100.64/10, and a chosen block must lie in 100.64/10 or RFC 1918 (owner
   decisions 28, 132); private names <client-name>.<net>.<root> resolve on the device (C14; owner
   decision 85)
5  a link to the fixed target: Network mode, Required, relay-only, one window client, whose
   WindowDelegation, signed by the sender's identity key, or in an app's VPN component by its
   forwarding key (owner decision 197), the contract signer seals unchanged (C13;
   §17.9); the target serves only sealed flows; the contract gate checks reach, and relayed bytes are
   debited (owner decision 10; §17 D-BRIDGE-5; §8 D-ACL-4)
6  the target's LocalUserNat flow meets EgressHook (C5) once per flow, keyed on the verified
   WindowDelegation's principal, checked against C13's seal (D-BRIDGE-17; sdk providers before C16
   use the seal): pass, map or deny; no flow reaches the target's own daemon listeners; in a network
   with a policy, LAN, loopback, link-local and overlay destinations need a rule, and without one
   today's allow-all stays, disclosed (owner decisions 50, 105, 120; §17 D-BRIDGE-4, D-BRIDGE-19)
7  the target dials the LAN host, and replies return on the flow; a revocation resets both ends; an
   edit moves no live pair off a link that still serves it, unless the sender's pin table is full,
   and drains a removed advertiser or address for max(drain_seconds, 600 s) for TCP and
   max(drain_seconds, 5 min) otherwise (§17 D-BRIDGE-7). A cross-network invite takes the same path
   over a FriendsAndFamily share link (C18; owner decision 86): its WindowDelegation is signed by the
   source network's current ShareSigner and carries that generation's ShareCert, which the host
   verifies under the share's pinned ShareKey, refusing a generation below the newest it has
   verified (§17.9's share signers; D-BRIDGE-17)
```

**F8. A harness recording work through MCP** (X20 and approvals: owner decisions 25, 74, 75, 80, 126, 142).

```text
   harness      daemon       evs          approver
1  |--ur mcp--->|            |            |
2  |--hooks---->|            |            |
3  |            |--records-->|            |
4  |--O tool--->|--request-->|            |
5  |            |            |--hint----->|
6  |            |<--decision--------------|
7  |<--result---|            |            |
8  |            |--coverage->|            |

1  the harness spawns `ur mcp --agent a` (bare `ur` does the same when stdin is not a terminal), which
   relays to the daemon over a Unix socket that checks the peer uid; tools take a `network` argument
   defaulting from the project's `.ur` file, else the daemon's only network, and refuse otherwise
   (§5.8; owner decisions 23, 57, 84; §5 D-CORE-9; §16 D-MCP-2)
2  hooks call `ur hook` (at most 300 ms, fail open) and the daemon tails the transcript; it redacts
   secrets, then seals (§16 D-MCP-5)
3  vault entries form a signed per-writer chain with a key slot per entry, written as in F2; each
   RecordEntry is sealed whole, and owned refs in record repos refuse FORCE and DELETE (owner decisions
   25, 61; §16 D-MCP-6; Q-ARCH-9 (a)). A device the author has not consented to only deposits into
   the author's vault (owner decision 126; §8.5). Team-record entries go by drop key (§10 D-KEYS-8)
4  an outward (O) tool, such as tls_publish or mail_send to a new recipient, writes an ApprovalRequest
   and returns pending (§16 D-MCP-4)
5  an evs hint and a content-free phone wake notify the approver (owner decision 88; §16.8)
6  the approver's identity key on another device, or a presence key, signs the ApprovalDecision; a
   single-device user approves in the harness's own prompt, which in a tainted run counts only where
   the matching `requests` rule names harness evidence, or with a presence prompt. The record labels
   the evidence type, a network policy may demand stronger evidence, and high risk adds an SSHSIG; no
   approval comes by email (owner decisions 75, 80, 142; §16.6)
7  the daemon executes only if the decision's hash matches its own canonical payload and the decision
   names this sidecar, reserving the use before the effect (§16 D-MCP-4, D-MCP-11, D-MCP-12); once
   the run is tainted, no standing grant or approved recipient passes, and it refuses as stale a
   decision whose request was untainted, Authorize filing a tainted request, though a use reserved
   before the taint completes (§16.6's TS1; §5.4); a requested grant activates once, as a
   `GrantActivate` carrying the decision under its fixed `grant_id` (§16.6, §8.8; §8 D-ACL-7; owner
   decisions 3, 74)
8  at run end, a coverage entry lists every gap (§16.8)
```

**F9. Remove a member** (X3 and X12 as in F1 and F3; owner decisions 59, 64, 83, 113, 114, 128, 129, 144). Actors: an admin; api; the removed member's devices; gkm; a remaining writer leaf; evs.

```text
   admin        api          removed      gkm          writer       evs
1  |--remove--->|            |            |            |            |
2  |--revocation, into the config repo----------------------------->|
3  |            |--cut off-->|            |            |            |
4  |            |            |            |--pending-->|            |
5  |            |            |            |<--commit---|            |
6  |            |            |            |            |--write---->|

1  member-remove, remove-client or SCIM deprovisioning: one api transaction removes the member,
   deactivates the member's own clients, revokes their tokens and logs an admin event; tagged agents
   the member enrolled stay, with their tags' grants, and admins may reassign their sponsorship (owner
   decision 83; §7.10, D-TEAM-10)
2  the admin's device signs the revocation into the config repo, where members read it; one admin
   signature suffices, except that removing an AdminSet member, or their devices, is an authority
   statement needing k of n, the target never counting (owner decisions 3, 5, 110; §7.9). Its
   projection v' closes the write gate of every repo the member read (§11.8)
3  api, sockets and the edges refuse the tokens at once; evs and gkm, which verify tokens offline,
   honor the signed revocation object in the cluster and drop the subject's scope with their newest
   verified projection, and tokens lapse within 15 min (§7.8, §8.9); connect closes the clients within
   90 s; their listeners, publishes, forwards, DKIM selectors and certificates end (owner decisions 2,
   36; §13.8; I-15)
4  gkm hints pending on the per-client gkm topic of each group's writers, the revoking device first
   (owner decision 113; §6.8; §10.6, KF4)
5  a writer leaf commits the Remove with a path, as a PrivateMessage whose clear authenticated_data
   carries only GkmCommitHeader (generation, auth pin), with no roster delta; members derive the
   change from the config repo at v' and reject a Remove without the signed revocation (owner
   decisions 59, 113; §10.9); then any writer rotates, claiming gen/<g+1> after staging its wraps
   (§10.5). In the config group the revocation's signer, when it is a leaf, may commit the Remove even
   if not a config writer (owner decision 128). No wrapped device commits a Remove: agents never do,
   and in the config group neither do member devices past its first 1,000, so a wrapped signer
   rotates and the next leaf commit removes the target (owner decisions 114, 144; §7.9); an agent's
   revocation is a new generation not wrapped to it, which any writer writes (owner decision 114). gkm
   stores the commit and the gen/ claim with If-None-Match: * (owner decision 2; §10 KF4)
6  the gate reopens at g+1: writes use generation g+1 and a rotated path key with an old-to-new token
   map, and the first write to each file is a full checkpoint (owner decisions 2, 64); new names in
   general, config and mailcfg repos wait until that map lands (§11.6). The removed party keeps what
   it already decrypted (§10.8). Until a writer, agents included, claims g+1, pushes get 412 (§11.8);
   until a writer leaf commits the Remove, no leaf wrap uses an epoch that holds the removed leaf
   (§10.5). A server withholding the Remove delays it within §2.8's exposure bound, which a split it
   makes by dropping traffic defeats: shared-group writers without a consistent witness alarm at 24 h
   and stop at witness_bound_hours (default 72 h), while rotations, Removes and revocations never stop
   (owner decision 129; D-TRUST-10)
```

**F10. Burner lifecycle** (X6 residual Q-MAIL-3: owner decision 32; launch at M8, receive-only until F5 ships: owner decisions 34, 35).

```text
   app          evs          receiver     mxedge       smtpedge
1  |[label]     |            |            |            |
2  |--mailcfg-->|--hint----->|            |            |
3  |            |            |<--mail-----|            |
4  |--reply, as F5, once outbound ships--------------->|
5  |--burn----->|--hint----->|            |            |
6  |            |            |--550 RCPT->|            |

1  the app's sidecar role generates <blabel>, a word-number label such as otter-4821, that avoids the
   network's published hosts and burned labels; the address is <name>@<blabel>.<net>.<root>, and an
   alias in place of <net> shows the network's name (owner decision 32; §15.9)
2  the label goes into the signed mailcfg, written as in F2, and receivers learn it from the hint; the
   wildcard MX *.<net>.<root> -> mx.<net>.<root> covers it, so it has no DNS record, no quota use and
   no server state (§15 D-MAIL-7)
3  inbound mail arrives as in F6 with SNI mx.<net>.<root>, so mxedge routes by network, and the
   receiver checks RCPT against mailcfg (§15.5)
4  a reply goes as in F5 from <name>@<blabel>.<net>.<root>, flagged BURNER, with Received and client
   headers removed (§15.10); smtpedge checks that the From domain lies in the network's zone; until
   <root> is on the PSL, a burner that replies gets its own DKIM selector and MX records, which
   publish its label: guessable and visible in DKIM headers, not walkable under §12.6's compact denial
   (owner decision 79 accepted walkable; owner decision 35; §15.9-15.10)
5  burn is local: the label is marked burned in mailcfg and never reissued (owner decision 32)
6  receivers answer 550 5.1.1 for it from then on; for a receive-only burner nothing changes in DNS or
   on the server. Correspondents can link a network's burners through <net> (owner decision 32;
   §15.9)
```

**F11. Search, and find agents working on a task** (owner decisions 10, 23, 63, 126, 142, 150 and 151-157, 166, 170-172; v1). Actors: the writer, another agent (in a team network, another member's); evs; the network's indexer, if one is designated; the searching daemon with its index cache; an agent in a harness.

```text
   writer       evs          indexer      daemon       agent
1  |--claim---->|            |            |            |
2  |            |--hint------------------>|            |
3  |            |<--sync latest-----------|            |
4  |            |            |            |<--search---|
5  |            |            |            |--page 1--->|
6  |            |<--roll-up--|            |            |
7  |            |<--all, by position------|            |
8  |            |            |            |--groups--->|
9  |            |<--read, receipt first---|<--open-----|

1  the writer's run claims its task (record_append, kind claim: its text and targets): in a team
   network the claim joins the run's announcement in the team directory, indexed in the push that
   writes its card (§16.11; owner decisions 170, 171); in a personal network it is a vault entry whose
   index entry follows on the vault's ur/index in the writer's next companion push, at most a minute
   later on 1 KiB XFS blocks, else five minutes (owner decision 172); a head keeps one entry per
   document (§11.14; §16.8, §16.10; owner decisions 151, 153)
2  in a personal network as F2 steps 5-6, a daemon that follows a record stream only for search
   holding a whole-ref lease on its ur/index (§11.10); in a team network the daemon instead syncs the
   directory at each search or view, coalesced to 30 s, every 15 min while it serves a harness
   session, else hourly (§5.4; §16.11, §18.4)
3  the daemon replays the ref's statements after its pin and fetches the changed index files into its
   sealed cache, checking each against its entry version's content_sha256, by sync position, never by
   query; from the directory's changed cards it derives their writers' index heads, fetching a head,
   and alarming, only where the derived one differs from its entry version's content_sha256 (§5
   D-CORE-16; §11.14; §16 D-MCP-20)
4  search_agents("rate limiter", since 7d): the scope is the session's network (`.ur`), every repo this
   sidecar reads by §8's local evaluation, the team directory included (§16.11), less secret, config,
   mailcfg and deposit-only repos, unconsented owner-bound repos and repos whose index is off (owner
   decisions 23, 126; §16 D-MCP-21)
5  phase 1: both latest buckets at once, the newest version winning by document key; doc-table fields
   confirm header matches, and the daemon's plaintext confirms the rest where it holds it, else they
   stay possible; hits group by (sidecar, agent label), active groups first, then the newest;
   untrusted hits and the directory's announcements, requests and decisions return as stubs, so the
   run stays untainted (I-9; owner decision 142; §16 D-MCP-22 to D-MCP-24, D-MCP-29)
6  once per bucket length the indexer, else the first writer after the bucket expires, rolls the
   expired bucket into all under a per-ref lock and drops it; the expired bucket answers until the
   roll-up lands (owner decisions 150, 153, 157)
7  desktops and indexers fetch the changed all shards in the background; an ephemeral or cloud daemon
   fetches every all shard it lacks, whole and youngest first, only for `more`; downloads debit the
   transfer balance (owner decisions 10, 154)
8  phase 2's hits follow phase 1's under the same cursor, so a returned page is never revised (§16
   D-MCP-25)
9  opening a hit is a read as in F2 step 7, which checks a possible hit; an EvsShare or audit reader of
   an owner-bound repo deposits a read receipt first (§16 D-MCP-18; owner decisions 63, 126)
```

**F12. A phone's "search more" answered by an indexer** (owner decisions 10, 126, 150, 151-155, 175-178; v1). Actors: an app host's sidecar, the phone; connect relays; a designated search indexer, the member's own or, for team repos, a network-scope one; evs.

```text
   phone        relays       indexer      evs
1  |--Hello, HeadCheck------>|            |
2  |[search own]|            |            |
3  |--SearchRequest--------->|            |
4  |            |            |[verify]    |
5  |<--SearchReply-----------|            |
6  |[merge]     |            |            |
7  |--next page------------->|            |
8  |--read, on open---------------------->|

1  at foreground, where the network designates a search indexer (none by default, owner decision 177)
   and the phone's mode is on, its default, the phone sends Hello to its first-choice own search
   indexer, or to another member's once that member's notice is answered, on the pair's Network
   contract: data where reach allows, else the `control` class, which carries SEARCH only to a sidecar
   advertising Hello feature bit 0; it checks the indexer's designation, admission and identity
   binding in its own state, and runs HeadCheck if due (§6.4, D-PROTO-21; §18.7, D-SDK-27)
2  keystrokes search the phone's own buckets and any cached all (§11.14); nothing leaves the phone
3  "search more": the scope by §16.10's rules, its repos split by §11.14's eligibility, own indexers
   first; an owner-bound repo goes only to its owner's consented devices (owner decision 126), and a
   team repo that no own indexer serves to one network-scope search indexer, another member's device
   only after the app has named that member once (§18.4's notice); each request is one 4,016 B body
   naming at most 64 repos (owner decision 175)
4  the indexer checks the requester and each repo in its own state (§8.5, §8.12), pins its cached
   snapshot and verifies candidates newest first against the text it holds, inside its remote budget
   and outside every MCP session and run, fetching nothing from evs, api or gkm (§5.8, D-CORE-17;
   I-19)
5  one 16 KiB step, failures after parsing included: verified hits, each repo's coverage and pinned
   (v, C_v), and checked_through_ms
6  the phone compares equal-version chains as HeadCheck does, merges by doc key, keeps its own
   confirmed hits, collapses possible matches the checked span disproves, and labels the hits that
   indexer verified "verified by <device>" (§11.14; §18.5)
7  each further page, on scroll, in the same sizes; relays see only each request's and reply's time and
   fixed size, connect reports the pair's bytes per window, in both directions, at a fixed floor that
   up to five pages leave unchanged (§6.10), and every byte debits the transfer balance (owner
   decisions 10, 176, 188; §4.6 C19; §2.8 connect-5)
8  opening a hit is a read as in F2 step 7, whose text the phone checks, a mismatch alarming and naming
   the indexer; with no designated indexer answering, the default, step 3 falls back to a download of
   all as in F11 step 7, by sync position under §18.4's metered rule, and owner decision 155's
   possible matches
```

**F13. Announce, find and request** (owner decisions 8, 74, 75, 126, 142, 161, 169-171, 179-182; v1). Actors: member A's daemon and run; evs; member B's daemon and agent; the repo admin's device.

```text
   A's daemon   evs          B's daemon   B's agent    repo admin
1  |--announce->|            |            |            |
2  |            |<--sync-----|            |            |
3  |            |            |<--find-----|            |
4  |            |            |<--request--|            |
5  |            |<--file-----|            |            |
6  |            |--hint, wake------------------------->|
7  |            |<--grant, decision--------------------|
8  |            |--decided-->|            |            |
9  |--ended---->|            |            |            |

1  at SessionStart A's daemon announces A's run within 10 s, `claims` being auto in a team network
   unless A opted out, per member or project, and renews it hourly while the run moves: an `announce`
   entry in A's directory stream at M6, A's card on the `cards` ref from the directory's format 2
   (§16.11); it carries the run's who (member, sidecar, agent label, harness), what (its redacted
   title, claims and state) and where (the repo id and, if the repo is announced, its name and branch,
   else `private`), and nothing else of the session leaves A's vault (owner decisions 126, 170, 171;
   I-20)
2  B's daemon syncs the directory by sync position (I-19) at each search or view, coalesced to 30 s,
   every 15 min while it serves a harness session, else hourly (§5.4, §18.4); it reads it through the
   directory's own MLS group, in which the first 1,000 live member devices are leaves and later ones
   and agents read by wraps (owner decision 182; §10.4), and ignores, with an alarm, any item not
   signed and pushed under §16.11's path rules by an admitted writer, consented where it is a member
   device (I-EVS-14)
3  B's agent looks for active runs on its task: `directory_list` at M6, a local filter over the folded
   state, and `search_agents` from M10 (owner decision 169); both return directory stubs, attested and
   identifier fields without prose, so B's run stays untainted (I-9; owner decision 142)
4  B's agent calls `directory_request` for read on A's repo, which the directory announced at its
   creation (owner decision 181) or shows only by its id and `private`; as an O-tier tool it passes
   §5.4's Authorize, which builds an `access_request` action and waits for member B's endorsement:
   harness evidence in an untainted run, device or presence in a tainted one (owner decisions 74, 75,
   142)
5  B's daemon files the request entry in B's directory stream, then a notice under the repo's prefix
   q/<repo_id>/, which names no approver (§16.11)
6  evs hints the repo admin's devices, which lease that prefix (§11.10); §18.7 wakes their phones from
   M8, and a desktop raises SidecarEvent access_request (§5.4)
7  a person, on /dev/tty or in an app and never through MCP, signs the RepoGrant into the repo's access
   log, the decision entry and the notice's rewrite to decided (owner decision 8; §8.8); an owner-bound
   repo's requests reach only its owner, whose consented device decides by EvsShare (owner decision
   126). A request to a worker asks to dial the services it announces (owner decision 179), and its
   owner, or a tagged sidecar's sponsor, approves as autogroup:dst-owner (owner decision 180; §8.4)
8  B's daemon reads the decision, verifies the grant at its log position and records the outcome in
   B's vault; KF3 then seats the subject's devices in the repo's group, member devices as leaves and
   agents by wraps (§10.7), and an approved worker request activates once, as a GrantActivate (§16.6)
9  at SessionEnd A's daemon marks the run ended, or handed off: a newer announce entry at M6, a card
   rewrite from format 2, whose replaced version is purged a minute later (owner decision 161);
   readers show the run ended for 24 h
```

### 3.8 Service summary

| Service | Owner (X) | Sidecar code | Server service | Client |
|---|---|---|---|---|
| Core, daemon | §5 (X10) | `sidecar.go`, `identity_`, `daemon_`, `indexer_` (3.6) | api | `Sidecar`, `ur daemon` |
| Subprotocol, push | §6 (X8) | `envelope_`, `rpc_`, `stream_`, `push_`, `codec_`, `protocol/`; `pushservice/` | connect residents | `Subprotocol` |
| Teams, SSO, authority | §7 | `protocol/config.proto`, which imports the records `sidecar/device` verifies from `protocol/bridge/` (D-SDK-20) | api, oauth | `ur login`, `ur admin`, `ur indexer` |
| Access control | §8 (X3) | `acl_` | gates on the id projection | `AclEngine` |
| Sockets | §9 | `socket_`; `socketsservice/` | sockets | `Listen`, `Dial` |
| Group keys | §10 (X12) | `mls_`, `gkm_`; `gkmservice/` | gkm; reconciler in taskworker | `GkmClient` |
| Storage | §11 (X2, X19) | `evs_`; `evsservice/` | evs | `EvsClient`, local git |
| DNS | §12 (X4, X5, X17) | `dns_`; `dnsservice/` | dns | record API |
| TLS, certs | §13 (X1) | `tls_`; `tlsedgeservice/`, `certsservice/` | tlsedge, certs | `tls` |
| Outbound mail | §14 (X7) | `smtp_`; `smtpedgeservice/`; the prover apart | smtpedge | `SmtpSender` |
| Inbound mail | §15 (X6) | `mail_`; `mxedgeservice/` | mxedge | `mail` |
| MCP, record, search | §16 (X20) | `mcp/`, `record_`, `directory_`, `search_` | none | `ur mcp`, `ur hook`, `ur search`, `ur agents`, `ur directory` (§16.11) |
| Bridge | §17 (X18) | `bridge_`; `device/` (D-SDK-20) | connect C5, C6a, C13, C14, C18 | `device.Bridge`, the forwarding role (owner decision 197) |
| SDK | §18 (X14) | none | api push tokens; push sender (§19) | `sdk.Sidecar` |

§4 owns X9, §19 X13, §20 X11 and X16, and §23 X15.

### 3.9 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Hosted sidecar (X14 b) | no install | keys and plaintext on servers | ruled out (owner directive 2026-11-03; owner decision 26) |
| Edge termination of customers' TLS or mail | filtering, coverage | plaintext at URnetwork | ruled out (owner directive 2026-11-03) |
| Server-compiled ACL slices | per-client rules only | a breached server could forge rules | superseded (owner decisions 3, 5, 6) |
| Bulk evs over the exchange | one transport | contract per pair; 16 KiB frames | rejected (§6, §11) |

Owners weigh the rest: a sidecar on the device client (§5.11), a sealed client index (§11.16), agents as MLS leaves (§8.13), per-network addresses (§15.11), and Redis or MinIO pools for the metadata tier (§19.12; owner decisions 136, 145).

### 3.10 Decisions proposed

**D-ARCH-1 (proposed).** This document writes `<root>` for X4's user-name root (ur.network; owner decision 13), `<net>` for X5's immutable network label (owner decision 14; PLAN.md:25's `<me>`), which an opt-in alias may replace in user-facing names, `<host>` for a zone-relative host and `<blabel>` for a burner's generated label, so a burner domain is `<blabel>.<net>.<root>`, served by the mail host `mx.<net>.<root>` (owner decision 32); `<me>` appears only inside PLAN quotations. The front matter carries it. *Why:* one value, one spelling; no mechanism changes.

**D-ARCH-2 (proposed).** The architecture has the six planes of 3.5 and no others; a new carrier needs an owner's decision, as the dns edge and phone wakes had (owner decisions 71, 88). *Why:* §6 D-PROTO-3, D-PROTO-5, D-PROTO-6 and §11 D-EVS-1 already split traffic this way, and §19 and §22 need one map.

**D-ARCH-3 (proposed).** F1-F13 implement the directive and the owner decisions each names, and are redrawn when a decision changes. They are §22.7's scenarios: S1-S3 are F1-F3, S4 is F9, S5-S9 are F4-F8, S10 is F10, S11 is F11, S12 is F12 and S13 is F13, with S3 and S4 in device form (§10 KF2, KF4) from M2 and member form at M6. *Why:* OUTLINE §22 asks for tests "mirroring §3", and tests of superseded flows test the wrong system.

**D-ARCH-4 (proposed).** Each flow names the owner decisions it implements. G0's assembly check (§23.8) maps every owner decision to the section text that implements it, and fails on a decision without such text, a citation of a withdrawn D- item, a decided question shown as open, or a Q- option the owner has not chosen presented as the design, unless it is an open question's recommendation marked "(proposed; Q-...)". *Why:* the owner's decisions arrived in rounds while sections were drafted and reviewed; only a mechanical check keeps the body, the decision list and §22's scenarios in step.

### 3.11 Open questions

None open. The 2026-11-03 design-review round, not human peer review, closed these, so peer reviewers may reopen them.

**Q-ARCH-1 (closed 2026-11-03).** Q-PROTO-3 (b), adopted by owner decision 11: Service mode (C9) for edges, FriendsAndFamily (C13) for shares; applied in §6.10.1.

**Q-ARCH-2 (closed 2026-11-03).** (a), confirmed by owner decision 39: certs proxies CSRs and alone writes DNS-01 in URnetwork zones; an `accounturi` pin appears only in Team customers' own CAA records; applied in §12.8, §13.8.

**Q-ARCH-3 (closed 2026-11-03).** (a): smtpedge splices mail for an MX on mxedge's router interfaces to mxedge over the host LAN, TLS still sidecar to sidecar; applied in §14.4.

**Q-ARCH-4 (withdrawn).** The directive is a requirement (CONVENTIONS §0); ruled-out modes appear only as Alternatives or Departures rows. Q-MAIL-7 goes with it.

**Q-ARCH-5 (closed 2026-11-03).** (a), with wakes in v0 (owner decision 88); applied in §18 (tokens, payloads), §19 (sender) and §2.8.

**Q-ARCH-6 (closed 2026-11-03).** (a), confirmed by owner decision 4: no sidecar shares the device client, which runs Opportunistic; applied in §5.5 and Q-PROTO-2.

**Q-ARCH-7 (closed 2026-11-03).** (a), at M4 (owner decision 85): C14's `UpgradeMux.SetLocalZone` and a `ur tun` resolver answer private names; applied in §12.9, §17.

**Q-ARCH-8 (closed 2026-11-03).** (c): an ephemeral reap is §7.10's removal; it starts a new generation only where the agent held a key that no live Delegation still delivers (§10.5; owner decision 114); headless sidecars read the config and otherwise only deposit, by §8.5's kind defaults, unless a grant or EvsShare names them, which §8.6's ceiling enforces for ephemeral ones (owner decision 6); applied in §7.7, §8.

**Q-ARCH-9 (closed 2026-11-03).** (a): RecordEntries are sealed whole, record repos' owned refs refuse FORCE and DELETE, and readers find gaps by chain pins; applied in §11.8, §16.8.

Disagreements raised elsewhere are settled there: Q-EVS-3, Q-TLS-6, Q-MCP-5 and Q-MAIL-8 closed in the same round, and owner decisions 2, 34, 70, 75 and 86 decided Q-EVS-1, Q-MAIL-1, Q-DNS-6, Q-MCP-3 and Q-BRIDGE-6.

### 3.12 Departures from PLAN.md

None introduced here; Appendix F traces every PLAN.md line. Departures that shape this map:

| PLAN.md | Departure |
|---|---|
| :59 plaintext paths; :84 edge termination | superseded by the directive; residuals by owner decisions 2, 34, 39-41 |
| :13 all service code in the root | server-only engines in child packages (owner decision 104) |
| :57 git over https | local git server and `git-remote-ur` (owner decision 24) |
| :82 a client on each network | platform clients in Service mode (owner decisions 11, 59) |
| :104 `mail.<me>.ur.network` | `mx.<net>.<root>` (owner decision 32) |
| :119 rules stored on the server, sent per client | a signed, encrypted config each device reads whole; servers enforce an id-only projection (owner decisions 5, 6, 72) |
| :147 readers and writers are leaves | member devices are, except past the first 1,000 in the config and the team directory; agents read and write by per-generation wraps (owner decisions 114, 144, 182) |
| :90-97 first-N-bytes proof | made sound for BDAT and DATA; outbound waits for it (owner decisions 35, 99, 125) |
| :28, :31 apps and device | app or daemon hosts the sidecar; network processes run only forwarding, with its own key (owner decisions 87, 197) |

### 3.13 Interfaces

- **Provides:** the maps, planes, topologies with the indexer's definition and fallbacks (3.6), F1-F13 (§22.7's scenarios, D-ARCH-3), the service summary, the closure register (3.11) and the decision trace (D-ARCH-4).
- **Consumes:** §1-§23 and the owner's decision record (front matter).
- **Subprotocol messages, API routes, Tables, Services and config:** none new.
- **Assumptions about other sections:**
  - Owners carry what the flows cite: §5.8 the `.ur` file, the submission port and pairing (F5, F8, 3.6); §7.9 admissions, authority and the recovery anchor, with the records `sidecar/device` verifies in `protocol/bridge/`, and forwarding Delegations (F1, F7, F9, 3.8); §8.5 owner consent and §8.8 access logs (F1, F3, F7, F8); §7.10, §8.12 and §10.9 the committers of owner decisions 113, 114, 128 and 144 (F1, F3, F9); §11.11 new-commit identity (F2); §14.5's proof parts and §14.16 TL1 at M9 (F5); §17.9's `WindowDelegation` and share signers (F7); §12, §13 and §15 the host `mx.<net>.<root>` (F6, F10).
  - §10.6's gkm checks and §10.9's table accept, from a non-writer signer in the config group, an agent's first wrap, a Remove and the rotation it requires, under the gkm `rw` scope §7.8 gives member devices in the config group, and a recovery-admitted device's external commit, and follow §7.9's `leaves` and `move` rows, where a wrapped signer only wraps or rotates and a lost entitlement is a Remove input (owner decisions 128, 144; F1, F9).
  - evs and gkm keep each repo's metadata on the cluster its `place/<repo_id>` names, and §11.10's leases, the push sequence and the head cache in Redis (owner decisions 136, 145; F2, F3).
  - §5.9 keeps the index cache, and §16.10 states the scope, taint, paging and grouping rules F11 cites; §11.14's index provides buckets and all, roll-ups by the indexer or the first writer after expiry, and entry versions naming each index file's plaintext hash; §7.9's `IndexerSet` designates 3.6's indexers, none by default (owner decisions 150, 151-157, 166, 177).
  - §11.14 states remote search's eligibility, fixed sizes and merge rules, §18.4 its notice and setting and §18.7 the foreground Hello; §6.4's control contracts carry SEARCH, and §4.6's C19 reports a requester-indexer pair that §6.11's bit 1 marks per §6.10's windows, both directions, at a fixed floor (owner decisions 175-178, 188; F12). §16.11 states the directory's announcements and requests in their M6 and M10 forms, §8.4 `autogroup:dst-owner`, and §10.4 the directory's group under §7.9's leaves rule (owner decisions 170, 171, 179-182; F13).
  - §22.7 draws S1-S13 from F1-F13 and ties its `GkmCommitHeader` assertion to S3 and S4; §23 schedules §11's v0b (the local git server) with v0a at M2 (F2) and orders the flows (owner decision 9).

### 3.14 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Sections lag the directive or the owner's decisions, so §22's scenarios test superseded flows | High | High | decision citations in flows; D-ARCH-4's check at G0 (§23.8); I-18 |
| A removed leaf stays in a repo's MLS tree until a writer leaf commits its Remove (owner decision 114) | Medium | Low | agents' rotations reopen the gate meanwhile, and no leaf wrap uses an epoch that holds it (§10.5); hints wake writer leaves |
| Outbound mail waits on sound BDAT and DATA preamble proofs | High | High | burner email launches receive-only (F6, F10); both proofs sit on the mail team's critical path (owner decisions 9, 35, 125) |
| A site or Hurricane Electric outage stops every flow and both nameservers; losing the site loses server-held data | Medium; Low | Critical | accepted (owner decisions 94, 123); an out-of-hours rota pages from M3 (owner decision 143); mail senders retry (§15.3); devices re-seed from local copies and Postgres rows from D-OPS-18's daily off-site dump (§19.10); record repos and their slots mirror to an indexer where one is designated (owner decisions 90, 150, 177) |
| P0 safety work (revocations and their rotations, Removes, shreds, erasures) runs at once whatever its volume (owner decision 186), so a wave of it on one metadata cluster, legal within every network's rates (100 large Teams each shrinking every 5 minutes ask ~2.9 TiB a day a drive, about twice the refill), wears its drives past 0.8 DWPD and their 1 DWPD rating, stops its pushes and evacuation while it lasts, past the 26 h NVMe bound, keeps its forgiven excess as wear (owner decision 190), and outruns the M2 sizing, which bounds wear only at the admitted mix | Low | High | §11.13's per-class rates, and the cluster's pushes and evacuation restarting as the wave ends, ramping up as the write budget's bucket refills; §19.8's P0 page within an hour and §19.10's runbook: capacity, placement, the networks; §11.21 |
| Repos stay on the cluster placed at creation until a later move tool, so the first metadata cluster's writes can outgrow its set (owner decision 145) | Medium | High | §11.13's write budget refuses the heaviest network first (owner decision 140); new repos go to the next cluster from §19.9's triggers; §19.9's cohorts row tracks each cluster's own growth, builds the move tool before the earliest projected exhaustion and, until it exists, holds a full cluster to maintenance (507 CLUSTER_FULL) |

### 3.15 Phasing

§23 orders milestones (X15): after the shared M0-M2, recURd and mail run as two tracks (owner decision 9). F1 needs §5 and §7's P0 with 7-day sidecar tokens (M1; owner decisions 45, 103, 131), then the config repo (M2; owner decisions 3, 5, 112-114, 128, 144); F2 needs §10, §11's v0a and v0b and the PM9A3 metadata set, whose benchmark gates format 1 on drive writes per push (M2; owner decision 140), then the production cluster (M3); F8 adds §16 (M3). Member-level F3 and F9 arrive with Team at M6 (owner decision 102); their device forms (§10 KF2, KF4) run from M2. F7 needs C5, C6a, C13 and C14 (M4), Linux first, and C18 for cross-network invites (M6). F4 needs C9, the dns edge, the 443 SNI split and ports 8443, 8883 and 5671 (M5; owner decision 121). F6 needs mxedge on port 25, DNSSEC and TLSA (M7), with phone wakes from M8's app hosts (owner decision 88). F10 launches burner email receive-only at M8, once the owner accepts M7's census loss (owner decision 34; D-MAIL-9). F5 and burner replies wait for M9's sound BDAT and DATA proofs (owner decisions 35, 125). F11 and F2's versionless steps need §11's format 2, with the index, at M10 (owner decisions 163, 169), behind its computed drive-write gate (owner decision 174); F11 reaches other members' claims in the team directory and the team record's run cards once M6's exist. F12's serving side ships at M10, its app-host steps at the later of M10's and M8's exits and its team-indexer steps at the later of M10's and M6's; F13 runs at M6 on format 1's record streams, its phone wakes from M8 and its cards and search steps at M10 (D-PHASE-11). Edges and mail start dark in main (owner decision 91). recURd needs F1, F2 and F8, then F7; burner email needs F6 and F10, then F5.
