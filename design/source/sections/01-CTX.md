## 1. Context, goals, and requirements

### 1.1 Purpose and scope

This section defines the sidecar infrastructure, its consumers, goals, and non-goals, and holds the R-CTX catalog and PLAN.md's tier table. It designs no mechanism and owns no X item; trust is §2, pricing §20, milestones §23.

### 1.2 Requirements

From [R:product] §2.2 and PLAN.md, as the directive and the cited owner decisions amend them; source keys and placeholders follow the front matter.

| Id | Requirement | Source | Owner |
|---|---|---|---|
| R-CTX-1 | `github.com/urnetwork/sidecar`, public from 2026-11-04, imports only connect; server and sdk import it; new pieces live there | PLAN.md:5-7; owner decision 118 | §4 |
| R-CTX-2 | `sidecar.Sidecar` holds an authenticated JWT, connect client, api, and encryption key | PLAN.md:14 | §5 |
| R-CTX-3 | `ur` speaks stdio MCP by default (help on a terminal), as a userspace subprocess of any harness | PLAN.md:17-20; PM:17; owner decision 57 | §16 |
| R-CTX-4 | One daemon serves many harnesses; runs in cloud containers without TUN or root; dials only allow-listable endpoints | UI:10-19; MK2:537; EXT:172-174; owner decision 49 | §5; §18.9 |
| R-CTX-5 | `sdk/sidecar.go` exposes key controls and joins the device (ip addr, port forward); the extension runs it as a web worker | PLAN.md:28-31; owner decision 26 | §18 |
| R-CTX-6 | A sidecar subprotocol carries peer and service messages; services push in real time | PLAN.md:15-16,55,119 | §6 |
| R-CTX-7 | A sidecar is a network client, enrolled interactively or headless; the free tier runs "any number of agents" | RA:929-930; P5:844; owner decision 4 | §5 |
| R-CTX-8 | A client token cannot administer the network or mint a network login | derived (`server/api/route_authz.go:123`) | §7 |
| R-CTX-9 | Agent tokens last at most 1 h, bind to the sidecar's key, and never enter the agent's environment | FB:139 | §5 |
| R-CTX-10 | Many users per network: roles, invitations, device approval, auth keys, tags; SSO on Team | PLAN.md:5,363; TM:384-1124 | §7 |
| R-CTX-11 | Once written, deny-by-default policy over clients, groups, networks, and sockets, signed into the encrypted config repo that every admitted sidecar evaluates; servers enforce its signed id-only projection; grants carry approver and expiry; one switch revokes an agent's reach | PLAN.md:74,119; P5:680,729; owner decisions 3, 5, 6, 72, 105 | §7, §8 |
| R-CTX-12 | MLS-managed keys: one group per directory, member devices its leaves, agents on per-generation X-Wing wraps; a network's member devices past the first 1,000 read its config and team directory groups by wraps; key generations wrapped in GKM; one accepted Commit per epoch; no server holds group secrets or plaintext keys; lazy rewrap by checkpoint | PLAN.md:44-53,155-161,221; owner decisions 59, 60, 64, 114, 144, 182 | §10 |
| R-CTX-13 | One directory is one git repo served by the sidecar; git identity is the client id; paths, names, messages, and contents are encrypted; the server sees only §11.5's header values | PLAN.md:53-59; directive; owner decisions 2, 24, 81 | §11 |
| R-CTX-14 | Diffs plus a checkpoint every N commits for versioned files, versionless ones keeping only their head (R-CTX-34); head read without a clone; subpath subscriptions; per-agent branches, tip compare-and-swap on git-mode refs, plain-git export | PLAN.md:55,63; MK2:513-531; owner decisions 141, 158 | §11 |
| R-CTX-15 | Blobs, and all durable evs and gkm state, in a new MinIO file cluster: an HDD segment cluster, and NVMe metadata clusters added whole under a drive write budget, each repo and its gkm group placed on one at creation; only rebuildable soft state in Redis | PLAN.md:61; owner decisions 2, 94, 116, 136-140, 145 | §19 |
| R-CTX-16 | Vault and change set: every session and changed file, any harness or tool path, under the developer's keys, secrets redacted; restores are previewed, confined to the run's changes, and recorded | PLAN.md:107-109; P5:617-622 | §16 |
| R-CTX-17 | Two key domains: session contents for their author unless shared, actions and approvals for admins, while in a team network a run's who, what and where reach teammates by default (R-CTX-38); without the author's signed consent, admins add to the author's repos only the visible audit member, whose reads the author sees | P5:579,640; owner decisions 63, 126, 170 | §8.5, §10 |
| R-CTX-18 | Record primitives: signed append-only entries, approval and reach receipts, run coverage, retention, erasure | P5:892-904,941; owner decision 25 | §16 |
| R-CTX-19 | Listen on an abstract `<net>:<name>`; a dial reaches one listener, chosen by load | PLAN.md:69; owner decision 65 | §9 |
| R-CTX-20 | `<root>` (PLAN.md's ur.network) is its own zone, for user content only; each network owns `<net>.<root>`; Team adds custom domains | PLAN.md:25,80,364; owner decisions 13, 14 | §12 |
| R-CTX-21 | The lbs pass `*.<root>` names to tlsedge, which routes them unterminated, by SNI, to a listening sidecar, where TLS ends; certificates are automatic | PLAN.md:80-84; directive; owner decisions 34, 39 | §13 |
| R-CTX-22 | Public names are explicit, authenticated by default, short-lived; the certificate key stays in the sidecar | P5:698-699; owner decisions 41, 42 | §13 |
| R-CTX-23 | SMTP edge: daily caps; end-to-end TLS to the MX behind a ZK-verified preamble (routing path, Message-ID); abuse reports join back to the sending network for tiered, domain-scoped halts (§14.8) | PLAN.md:87-97; owner decisions 30, 35, 37, 99 | §14 |
| R-CTX-24 | A local SMTP server on a receiver, reliably on a mail indexer (R-CTX-33), terminates `mx.<net>.<root>` (PLAN.md:104's `mail.<me>.ur.network`), stores mail encrypted, and sends through the edge; with no receiver online, mail waits on sender retries; the edge holds nothing | PLAN.md:104; directive; owner decisions 12, 32, 34, 150 | §15 |
| R-CTX-25 | Ids and burners: unlimited aliases and groups; burner addresses `<name>@<blabel>.<net>.<root>` under the network's wildcard MX, linkable through `<net>`; password, one-time auth, URL, notes | UI:68-73; MM:918; owner decisions 29, 32 | §15 |
| R-CTX-26 | Outside mail is untrusted; first mail to a new recipient awaits an I-8 approval, never an email reply; group fan-out | P5:707,736; RA:1584; owner decisions 75, 80, 142 | §15, §16 |
| R-CTX-27 | Route a client's subnets to that client; rewrite destination ip:port when IP-providing for the same network; a stable private address per sidecar in the network's random /16, which admins may cycle, or choose in 100.64.0.0/10 or RFC 1918 | PLAN.md:115-117; P5:686; owner decisions 4, 28, 132 | §17 |
| R-CTX-28 | With a policy, agents reach only granted ranges and model servers, and leave only through customer-run exits; without one, sidecar sources keep today's same-network reach, LAN, loopback, link-local and overlay included, disclosed in product copy | P5:689,774-781; owner decisions 50, 105, 120 | §8, §17 |
| R-CTX-29 | Servers hold only ciphertext plus a published metadata list | P5:745,932; directive | §2 |
| R-CTX-30 | Tier limits (§1.8) only through `config/all/pro.yml` and `model.Pro()`; traffic bytes count toward the transfer balance, capacities are quotas | PLAN.md:346-364; owner decisions 10, 27 | §20 |
| R-CTX-31 | `ur share add` makes a link that `ur share get` redeems at most `--count` times; file transfer counts toward the transfer balance | UI:35-38,97 | §9 (D-SOCK-16) |
| R-CTX-32 | Each service is added vertically, through sidecar to server | PLAN.md:36 | §23 |
| R-CTX-33 | A network designates indexers, its always-on point devices for background services: receiving mail, mirroring record-class repos, search-index roll-ups and verification, keeping the all search partition synced, answering phones' searches (R-CTX-37), embedding later, and other services that need an always-on device; none by default, several may serve, a Team's receivers are indexers chosen for mail, and a designation grants no access | owner decisions 12, 58, 150, 177 | §3.6, §7.9 |
| R-CTX-34 | Versioning per object: a file version is versioned (every version kept, as diffs) or versionless (only the head kept, whole). A replaced versionless version's content is purged once its replacement is certain, after about a minute for readers in flight, and versions written while versioning was on stay unless a repo admin drops the path's history (R-CTX-39). Each network has a default rule, versioning off above 64 MiB on the platform default, which admins edit, applied when a path is created (owner decision 167). No versionless file in config or mailcfg repos or on git-mode refs; a repo admin may lock a repo versioned. Large files in git go through git-lfs on a versionless store, collected once no ref tip and no commit of the last 30 days (per repo) references them | owner decisions 158, 160-165, 167 | §11 |
| R-CTX-35 | An encrypted search index, always versionless, in every repo but config, mailcfg and secret ones (D-EVS-43), locked repos included (owner decision 168), on unless a repo admin turns it off, and always on in the team directory (owner decision 171). Each committer adds its document-level trigram delta to the current bucket, in its push or, for git-mode refs and record streams, a companion push at most once a minute per writer on 1 KiB XFS blocks, else once every 5 minutes (owner decision 172), binaries skipped. Devices download it whole and search locally (I-19): two buckets of a per-repo window (30 days by default, 7-365) at once, an all partition in the background or on "search more", the newest version winning; an indexer (R-CTX-33), else a writer, rolls each expired bucket into all. Desktops and indexers keep all synced and verify against local text; phones and pages fetch it on "search more" or on Wi-Fi while charging, each device able to override, and show possible matches; once an indexer is designated, a phone's "search more" asks it instead (R-CTX-37). An erasure removes a document's postings | owner decisions 151-157, 159, 160, 168, 171, 172 | §11, §15, §16, §18 |
| R-CTX-36 | `ur search`, `ur agents` and MCP search tools: scope (repo, network, all), filters (agent, time, kind, path prefix, field) and "search more"; agents found by task, hits grouped by agent; hits labeled confirmed, possible or near; the daemon's per-network index cache (§5.9); only repos the caller may read, owner-bound ones under the owner's consent; untrusted hits' text only on request, the run tainted first (I-9) | owner decisions 126, 166 | §16 |
| R-CTX-37 | Once its network designates an indexer that may answer (none by default), a phone's "search more" asks it end to end while it is online and gets verified hits: an owner-bound repo only on its owner's consented device, replies padded to 16 KiB steps and the pair's reported bytes a fixed floor a window, so up to five pages report as none, another member's device only after the app names that member; otherwise the phone downloads all and searches its own index, with possible matches | owner decisions 175-178, 188 | §4.6, §6.10, §11.14, §18.4 |
| R-CTX-38 | One team directory per team network announces runs, workers and repos, each with who, what and where: runs by default, members opting out per member and project; every general and record repo at creation, unless its owner marks it private, and an owner may revoke an announcement. Members and their agents request access to repos and workers through it, access to a worker being reach to the services it announces, approved by the worker's owner or a tagged worker's sponsor. Session contents stay in the vault; the directory is its own MLS group under the config group's leaves rule | owner decisions 170, 171, 179-182 | §16.11 |
| R-CTX-39 | In v1 a repo admin, or in an owner-bound repo only its owner, can drop a path's history on a file-mode ref outside config and mailcfg repos: a signed action pending 7 days, in which any of them can cancel, unless `now` skips the wait; it deletes only content that the dropped versions alone name, keeps every statement and the head, and under a preservation hold defers its deletions silently | owner decisions 126, 173, 183, 184 | §11.7, §11.13 |

### 1.3 What exists today

Nothing in this design is built. The sidecar repo holds documents and no code, in two commits on `main` (2b5b0ab, 2026-11-03; 708bb45, 2026-11-05, which moved the business documents under `design/` and added DESIGN.md, its reviews, README.md, the research sheets and the search-index report and notes), published as it is, history included, from 2026-11-04 (owner decisions 117, 118; §4.3, §4.11); `sdk/sidecar.go` does not exist. The server has one `admin_user_id` per network, no members, roles, or policy, and only the `free` and `pro` tiers (`server/db_migrations.go:351-358`; `server/model/pro.go:429`; §20.3). §6.3, §13.3, §14.3, and §19.3 describe connect and the edges today.

### 1.4 The sidecar infrastructure and its consumers

Consumers (PLAN.md:5-31; D-CTX-1):

| Consumer | Runtime | Needs |
|---|---|---|
| recURd: `ur` CLI and stdio MCP beside a harness (PLAN.md:17-20) | Go binary | every service |
| recURd: ur.io/recurd and the team console (TM:7; RA:710-718; owner decision 15) | browser sidecar (Q-CTX-2) | team, policy and record reads |
| recURd: phone tab (MM:416) | sdk | record reads, agent chat |
| Burner email: app tab, password manager (MM:463-668; UI:66-85) | sdk | mail, evs |
| Burner email: ur.io quick tools (UI:159-165) | browser sidecar | mail, evs |
| Apps: device ip addr, port forward (PLAN.md:31) | sdk | bridge |
| Apps: extension worker (PLAN.md:28) | `sidecar.wasm` Worker (§18.8) | per §18 |

### 1.5 Features and promises mapped to PLAN.md services

§3.8 and the R-CTX owners map recURd's seven features (PM:11-17) onto PLAN.md's services, and §7.11 takes the admin audit trail (P5:640,898; TM:1021-1029).

### 1.6 Needs PLAN.md does not cover

| Need | Source | Taken by |
|---|---|---|
| Agent identity and directory | RA:918-971,1854 | §7, §12 |
| Agent chat from web and phone; a broadcast "global mic"; agent-to-agent mail | RA:736-744,1304; MM:739-745 | §15, §16 |
| QR and MDM join | TM:648-771 | §7.8 |
| Every receipt names its relay | EXT:176-180 | §16.8 `ReachReceipt.relays` |
| Global harness config with per-agent overrides, re-synced on save | RA:986-1009 | §16.7 |
| Versionless objects; an encrypted per-repo search index; search in `ur` and MCP | owner decisions 151-166 | §11, §15, §16, §18 (R-CTX-34 to R-CTX-36) |
| A team directory of runs, workers and repos, with requested access; a phone's search through an indexer; an admin drop-history action | owner decisions 170, 171, 173, 175-184 | §4.6, §7.9, §8, §10, §11.7, §11.12-§11.14, §16.11, §18 (R-CTX-37 to R-CTX-39) |

### 1.7 Goals, non-goals, and promises that bind the infrastructure

Goals: one substrate for both products and the apps; every PLAN.md service designed to implementable depth, PLAN.md positions visible unless superseded (§1.14); servers see only ciphertext and the metadata list (R-CTX-29); runs where consumers run; scales horizontally on warp.

Non-goals: a harness, agent, model host, or eval product (PM:21,47; MK2:618-620); a token (P5:934; owner decisions 15, 108); app, console, or extension UI (PLAN.md:28), including OS password-manager registration (MM:465); a general exit for agent traffic; the feedback service (D-CTX-4); record semantics and exports (RECORD.md; owner decision 25); the instruction-file writer (P5:629) and run cost.

Promises (D-CTX-3):

| Promise | Binds | Conflict |
|---|---|---|
| "Private from us"; sessions "stay with their author unless shared"; storage "hold[s] no key" (P5:579,745) | R-CTX-13, R-CTX-17, R-CTX-29, R-CTX-38 | none for session contents (directive; owner decision 126); in a team network a run's who, what and where reach teammates unless its member opts out (owner decision 170) |
| "The relay carries only ciphertext"; the "certificate key stays in the sidecar"; mail "encrypted on arrival" (P5:681,699,708) | sidecar traffic, R-CTX-21, R-CTX-22, R-CTX-24 | none (directive; D-PROTO-6) |
| Owner decision 72's policy wording, replacing TM:814 | R-CTX-11 | none (owner decisions 3, 5, 6) |
| "end-to-end encrypted" (P5:928) | R-CTX-29 | claimed now, without P5:930-931's audit and reproducible builds; the security page discloses the unaudited cryptography (owner decisions 77, 99, 119) |
| Agents "reach only granted ranges, and leave only through exits you run" (P5:689) | R-CTX-28 | holds once a network writes a policy; the allow-all before it is disclosed (owner decision 120) |

### 1.8 Tiers and limits as PLAN.md states them

PLAN.md:348-364, verbatim:

```text
Community
Pro
Team [$100/month+usage based overage]


[all of these count towards transfer balance]

Encrypted Storage   1GB, 20GB, 200GB
Send Emails/day       5   200 20000
DNS entries           5   200 2000
TLS edge              1   20  200
IP and port forward   [unlimited]
recurd                [all]


Team management including SSO [only team]
Custom domain   [only team]
```

Owner decision 27 keeps these quotas, with Team at $100 a month for 5 billable seats, then $20 per extra seat (§20.4); overage, on transfer and storage only, uses existing rates (owner decision 122). §20.3 gives the code's `free` and `pro` limits today, and §20.8 counts sidecars. pitch5 sells Solo, Team, and Assured (P5:844-846).

### 1.9 The owner's decision list

Owner decisions 1-150 settle every X item and every owner question raised before the v1 additions, the five raised in the 2026-11-04 peer review included (owner decisions 141-145: Q-EVS-8, Q-MCP-6, Q-OPS-9, Q-KEYS-15, Q-OPS-10); that review closed the Q- items left to it (Appendix B). Owner decisions 151-166 (2026-11-05) add versionless objects, the encrypted search index and search in `ur` and MCP, all in v1 (R-CTX-34 to R-CTX-36); owner decisions 167-184 (2026-11-05) answer the v1 questions (Q-PROTO-4, §6; Q-ACL-11, §8; Q-KEYS-16, §10; Q-EVS-19 to Q-EVS-23, §11; Q-MCP-7 to Q-MCP-9, §16; Q-SDK-6, §18; Q-ABUSE-7, §21; Q-PHASE-9 and Q-PHASE-10, §23.12) and add a phone's search through an indexer (R-CTX-37), the team directory (R-CTX-38) and the drop-history action (R-CTX-39). Owner decision 185 (2026-11-05) answers the SDK fixes' question, and owner decisions 186-191 (2026-11-05 and 2026-11-06) the final meta review's (Q-EVS-24, §11, whose answer owner decision 190 refines; Q-PROTO-4's answer, §6, which owner decisions 188 and 191 amend; the presence countersignature's reach, §7). Owner decision 197 (2026-11-09) puts only IP and port forwarding in every app's VPN component, always on and self-contained (§17, §18), and its design raised the two owner questions open now: Q-BRIDGE-8 (§17) and Q-SDK-7 (§18). The front matter lists each decision with its implementing sections.

### 1.10 Glossary seed

Terms are defined once, in Appendix C. The one most sections share is the **indexer**: a device its network designates as an always-on point device for background services, such as receiving mail and mirroring record-class repos; a network has none until an Owner, an Admin or a member designates one (R-CTX-33; §3.6; owner decisions 150, 177).

### 1.11 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| One substrate (PLAN.md:5-31) | One identity, storage, edge, abuse pipeline | Burners linkable per network (owner decision 32); one mail reputation, shared with api and connect ingress (owner decisions 29, 124) | Adopt |
| A stack per product | Isolates reputation | Duplicates everything; contradicts PLAN.md | Reject (owner decisions 15, 108) |
| A hosted sidecar for browser surfaces | One runtime for every page | Keys and plaintext on URnetwork servers | Ruled out (directive; owner decision 26) |

### 1.12 Decisions proposed

**D-CTX-1 (proposed).** The sidecar infrastructure is the `sidecar` module and `ur` CLI, the new server services (§3.8) with team management and access control, and `sdk/sidecar.go`; consoles, app UI, harnesses, and model hosting are outside it. *Why:* PLAN.md:5-31; owner rule 6.

**D-CTX-2 (proposed).** R-CTX's Owner column, with Appendix F's trace of each PLAN.md line, is the traceability root; section tables gain no R-CTX column. *Why:* Appendix F's join makes a per-section column redundant.

**D-CTX-3 (proposed).** The §1.7 promises are requirements as the directive and the owner's decisions amend them, and product copy follows each amendment (owner decisions 119, 120, 170); owning sections record departures from PLAN.md. *Why:* owner rule 8.

**D-CTX-4 (proposed).** The feedback service (FB) is out of scope; R-CTX-9 is the one FB requirement this design takes. *Why:* FB has its own spec.

**D-CTX-5 (proposed).** Model access is a bridge forward plus a per-sidecar, per-model grant (§17, §8); model-name routing and per-request signing (P5:779) stay out of scope. *Why:* both need an HTTP proxy that PLAN.md lacks.

### 1.13 Open questions

**Q-CTX-1.** Must the server services be self-hostable (P5:576,903)? **Decided by owner 2026-11-03 (implied by owner decision 48):** at the later assured stage; engines reach URnetwork-only infrastructure only through `ServiceHost` interfaces (D-REPO-3), and v0 ships no bundle. *Residual:* none.

**Q-CTX-2.** Which runtime serves browser surfaces besides the extension? **Decided by owner 2026-11-03 (implied by owner decision 76):** the extension's `sidecar.wasm` (owner decision 26), in a page Worker admitted read-only and labeled as served code (§2.8 EX7; §18.8), ephemeral for the quick burner (Q-SDK-4). *Residual:* none.

**Q-CTX-3.** What is a recURd team in URnetwork terms? **Decided by owner 2026-11-03 (implied by owner decision 59):** a new team network (owner decision 55) plus each member's personal network, one daemon hosting a `Sidecar` per network (owner decision 23; §7.5). *Residual:* none.

**Q-CTX-4.** Cross-cutting (§9, §11). Who designs `ur share` (R-CTX-31)? **Closed by peer review 2026-11-04:** (a), §9 (D-SOCK-16): a blinded `share/<token>` socket served while the sharing sidecar runs, a 256-bit secret in the link's fragment, a durable use count under §16's reserve-before-effect discipline (D-MCP-11), an expiry (24 h by default, at most 30 days; `ur share rm` ends one early), bytes on the transfer balance; (b) would change format 1, which freezes at M2. *Residual:* none.

### 1.14 Departures from PLAN.md

None in §1; Appendix F traces every departure.

### 1.15 Interfaces

- **Provides:** the R-CTX catalog, consumers, scope boundary (D-CTX-1), §1.7's amended promises, PLAN.md's tier table.
- **Consumes:** the directive (CONVENTIONS §0), the owner's decisions, and §2.18's disclosures.
- **Subprotocol messages, API routes, Tables, Services and config:** none.
- **Assumptions about other sections:** §2 publishes the metadata list; §9 designs R-CTX-31's `ur share` (D-SOCK-16); §1.6's owners confirm their rows; §5, §11, §15, §16 and §18 confirm R-CTX-34 to R-CTX-36; §4, §11 and §18 confirm R-CTX-37, §16 R-CTX-38, and §11 R-CTX-39.

### 1.16 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Promises published before the design meets them cost trust | High | Critical | key authority from v0 (owner decision 3); the security page's disclosures (§2.18; owner decisions 119, 120) |
| Scope creep from 63 product needs ([R:product] §2.2) slips the schedule | High | High | R-CTX is the scope; additions need a Q- item |

### 1.17 Phasing

No build work here. Owner decision 9 runs recURd and mail with burner as two tracks after the shared M0-M2 (§23.5). Versionless objects, the search index and its CLI and MCP tools ship in v1 as storage format 2, whose numbers format 1 reserves at M2 (owner decision 163); format 2 is §23.4's milestone M10, on track A beside M6 (owner decision 169), with the drop-history action (owner decision 173) and a phone's search through an indexer (owner decision 175); the team directory (owner decision 171) ships at M6 on format 1's record streams, its cards and index with M10 (§16.11; D-PHASE-11).
