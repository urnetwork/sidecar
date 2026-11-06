# DESIGN.md writing conventions (shared by every section writer)

The document being written is `/Users/brien/urnetwork/sidecar/DESIGN.md`: the technical design of the **sidecar infrastructure**, which underlies the **recURd** product (the private record of agent work) and the **burner email** product (consumer, in the URnetwork apps). It starts from the owner's `/Users/brien/urnetwork/sidecar/PLAN.md`. Nothing is implemented. The owner's goal is to settle **every architecture and design question before implementation**. Peer reviewers will read this document before any code is written. A section that hides an unresolved question has failed. A section that states a crisp question, with options and a recommendation, has succeeded.

## 0. OWNER DIRECTIVE (2026-11-03, overrides PLAN.md where they conflict): end-to-end encryption is a must

The owner's words: **"End to end encryption is a must. The storage, tls edge, mail must only see encrypted bytes and some small header values like sni and spam headers."**

This is binding on every section. It is a requirement, not an open question. Consequences:

- **TLS edge (X1 is DECIDED):** TLS terminates in the sidecar. `tlsedge` routes by SNI (passthrough). It never holds a user's TLS private key, and there is no edge-termination mode. PLAN.md:84 ("so that the tls edge can do its own certificate termination") is superseded. Record it under Departures as "superseded by owner directive 2026-11-03", not as an open question. Residual questions for §13: certificate issuance with device-held keys (DNS-01 through §12, or TLS-ALPN-01 answered by the device through passthrough), a team's devices sharing a wildcard key vs per-device sublabels, the lb SNI split, and abuse handling without content inspection.
- **Storage (X2 is DECIDED in principle):** the evs and gkm servers see only encrypted bytes plus small header values. Paths, file names, commit messages, author fields beyond the authenticated client id, and contents are encrypted. PLAN.md:59 ("The file paths are not encrypted ... following the git-crypt model") is superseded. Residual questions for §11: exactly which small header values the server needs (object ids, sizes or padded sizes, key-generation ids, ref names, opaque path tokens for subpath subscriptions and head reads). Are opaque deterministic path tokens acceptable, given that they leak equality and structure, or must subscriptions and head reads work on coarser units? The published metadata list must enumerate every header value.
- **Mail (X6 and X7 are DECIDED in principle):** mail infrastructure sees only encrypted bytes plus small header values such as SNI and spam-relevant headers.
  - Outbound: TLS runs end to end from the sidecar's mail server to the destination MX through `smtpedge`. The edge sees only encrypted bytes plus PLAN's small plaintext preamble of declared header values (routing path, Message-ID, and the values used for spam and abuse attribution). Edge-terminated submission and an SES relay are ruled out. Residual questions for §14: how to make the preamble trustworthy (PLAN's ZK proof is unsound as written; give a sound binding or another verification, and say what ships before it); refusing destinations without STARTTLS; DKIM keys on devices.
  - Inbound: TLS for inbound mail terminates on a device or a customer-run sidecar, never at a URnetwork edge. Encrypt-on-receipt at the edge (Proton-style transient plaintext) is ruled out. The edge may see SNI, the connecting IP, the EHLO name, and other small header values needed for spam and abuse handling. Residual questions for §15:
    - routing when the sender sends no SNI (DANE-EE TLSA records with DNSSEC make SNI mandatory for DANE senders and need no public CA; per-network destination IPs, e.g. IPv6; per-network or per-burner MX labels);
    - senders without STARTTLS (refuse?);
    - offline behavior (the edge can hold only ciphertext; deferral; an always-on customer sidecar);
    - spam filtering on the device plus edge IP reputation;
    - the burner shared-domain problem: a shared domain cannot have one certificate held by every user, so burners need per-network or per-burner labels or another E2E scheme.
- **Everything else in the same spirit:**
  - connect traffic between sidecars runs with e2e encryption required, not Opportunistic or Off (§6).
  - gkm sees only encrypted MLS handshake data plus small headers (group id, epoch).
  - DNS data is public by nature and is not covered, but must reveal as little as possible (opaque labels, wildcards).
  - Any server component that would see plaintext content is a design error. Do not raise it as an option.

## 1. Owner rules (hard constraints, do not re-litigate)

1. Code placement. The sidecar repo (`github.com/urnetwork/sidecar`, new) holds the new CLI and components. The **new pieces live in the sidecar repo**, including any MLS implementation. The server repo adds horizontally scaled services that support those components and integrates them into the overall architecture. It also takes the enhancements to network/team client management and access control. The sidecar components are exposed in the sdk.
2. Dependency direction. `sidecar` depends on `connect`, never on `server` or `sdk`. `server` and `sdk` import `sidecar`.
3. The message repo (`github.com/urnetwork/message`) and `connect/MESSAGEREVIEW.md` are being deleted. Never use them, cite them, or propose reusing their code.
4. Branches. All sidecar work happens on a branch named `sidecar` in every repo it touches.
5. Layout from PLAN.md:
   ```
   sidecar/
     go.mod        # all service code goes in the root of the module named sidecar
     sidecar.go    # the core Sidecar struct: authenticated jwt, connect client, api, encryption key
     protocol/     # the sidecar subprotocol protobufs
     mcp/          # stdio mcp server
     cli/main.go   # cli that speaks stdio mcp by default
   ```
6. Scope. The apps are out of scope ("This plan does not include the apps"). The apps use the sidecar directly, and the extension runs it in the background as a web worker. Design the seams they use, not their UI.
7. Product facts: recURd is not tokenized, and it uses the URnetwork network for worldwide reach.
8. PLAN.md statements are **requirements by default**. If you find a technical problem with one, keep the PLAN position visible and explain the problem with evidence. Propose the alternative as an open question for the owner. Never silently override PLAN.md, and never silently drop a PLAN.md item in your scope.

## 2. Section template (use these subsections, in this order; omit one only if truly empty)

```
## N. Title

### N.1 Purpose and scope           (2-5 sentences; what this section owns and what it leaves to which other section)
### N.2 Requirements                (table: id | requirement | source (PLAN.md:line, product source, or derived))
### N.3 What exists today           (code we build on, with repo/path:line citations; what is missing)
### N.4 ... N.k Design              (the substance: mechanisms, data formats, algorithms, APIs, failure handling, security)
### N.k+1 Alternatives considered   (table: option | pros | cons | verdict)
### N.k+2 Decisions proposed        (D- items)
### N.k+3 Open questions            (Q- items)
### N.k+4 Departures from PLAN.md   (each with the Q- item that asks the owner; "None" if none)
### N.k+5 Interfaces                (Provides / Consumes / Subprotocol messages / API routes / Tables / Services and config)
### N.k+6 Risks                     (risk | likelihood | impact | mitigation)
### N.k+7 Phasing                   (what is v0 (first usable), v1, later; what blocks what)
```

## 3. Identifiers

- Decisions: `**D-CODE-n (proposed).** <decision>. *Why:* <rationale>.`
- Open questions: `**Q-CODE-n.** <question> *Options:* (a) ... (b) ... *Recommendation:* ... *Blocks:* <what cannot proceed until answered> *Decider:* owner | peer review.`
- Requirements: `R-CODE-n` in the requirements table.
- Number from 1 within your section. Use only your own CODE. To reference another section, write `§N` or its ids, e.g. `(§9, D-SOCK-2)`.
- Section numbers and CODEs are fixed by OUTLINE.md.

## 4. Naming registry (use exactly; if you must change one, keep it and raise a Q- item)

| Concept | Name |
|---|---|
| Sidecar repo / Go module / root package | `github.com/urnetwork/sidecar` / package `sidecar` |
| Subpackages | `sidecar/protocol` (protobufs), `sidecar/mcp` (stdio MCP server), `sidecar/cli` (main) |
| CLI binary | `ur` (command set sketched in `/Users/brien/urnetwork/cli/UI.md`) |
| Core type | `sidecar.Sidecar` in `sidecar.go`; SDK wrapper `Sidecar` in `sdk/sidecar.go` |
| Zone | `ur.network` |
| Per-network zone | `<net>.ur.network`. `<net>` is the network's DNS label. §12 defines how it derives from `network_name` |
| Per-network mail host | `mail.<net>.ur.network` |
| Hostname published by a network | `<host>.<net>.ur.network` |
| Abstract socket address | `<net>:<name>` (PLAN.md writes "network:name"). §9 defines the exact grammar |
| Storage unit | **evs repo**: one directory = one git repo = one encryption domain (PLAN.md) |
| Storage backend | the **file cluster**: a new minio cluster for evs blobs (PLAN.md) |
| Group key management | **GKM**: holds evs session keys and the MLS group state and ordering (PLAN.md names GKM). §10 defines it |
| New server services (logical names; §19 maps them to warp service blocks) | `evs` (storage: git over https, head API), `gkm` (group keys / MLS delivery service), `sockets` (abstract socket registry and scheduler), `dns` (authoritative DNS for ur.network), `tlsedge` (public TLS edge), `smtpedge` (outbound SMTP edge). Inbound mail ingress and certificate issuance are named by §15 and §13; the defaults are `mxedge` and `certs`, unless they fold into another service |
| Existing server services | `api`, `connect`, `taskworker`, `proxy`, `gossip`, `alt`, `mcp`, `monitor` (per connect/CODESTYLE.md) |
| Tiers | Community, Pro, Team (PLAN.md pricing notes) |
| Products | recURd (always styled this way), burner email, URnetwork apps |
| The subprotocol | "the sidecar subprotocol". §6 assigns its id(s), envelope, and message catalog |

## 5. Style

- Write like the owner's design docs (`connect/SUBPROTOCOL.md`, `server/IDP.md`): plain declarative sentences, specific numbers, cite code as `repo/path/file.go:LINE` (relative to `/Users/brien/urnetwork`). Say what is known, what is proposed, and what is unknown. No marketing language, no filler, no hedging adjectives.
- Go API sketches follow `connect/CODESTYLE.md`: acronyms as words (`Id`, `Api`, `Http`, `Tls`, `Smtp`, `Dns`, `Mcp`, `Evs`, `Mls`, `Jwt`), receiver `self`, usage+type field names (`activeClientIds`), `stateLock`. Proto sketches are proto3. SQL sketches are PostgreSQL. Diagrams are ASCII in fenced `text` blocks.
- Server rules from CODESTYLE.md that bind designs: migrations apply before code deploys and must stay compatible with the running release; inline per-packet work never queries PostgreSQL (use bounded Redis projections or local state).
- Tables over paragraphs for comparisons. Keep each section within its word budget (OUTLINE.md). Dense beats long.
- Cite research fact sheets as `[R:key]` (files in the research directory). Cite external facts with URLs, and give dates for fast-moving facts (rate limits, prover costs).
- Mark each statement as fact (cited), proposal (D-), or open (Q-). Do not present a guess as fact.

## 6. Interfaces subsection format

```
### N.x Interfaces
- **Provides:** <capabilities other sections use>
- **Consumes:** <capability> (§k)
- **Subprotocol messages:** `MessageName` (direction; purpose)
- **API routes:** `METHOD /path` (auth; purpose)
- **Tables:** `table_name` (owner service; purpose)
- **Services and config:** <service names, config files, ports>
- **Assumptions about other sections:** <anything you assumed that another section must confirm>
```

## 7. Cross-cutting decisions registry (X-items)

These are the big conflicts and choices the research surfaced. Each has ONE owning section. The owning section must resolve it as a Q- item whose text starts with the X id (e.g. `**Q-TLS-1.** [X1] Where does TLS terminate?`). It must give the options, the evidence, and a recommendation. Every other section that depends on it cites the X id (e.g. "per X1 (§13)") and states which option it assumes. The assembler puts the X list at the top of DESIGN.md as the owner's decision list. Do not invent new X ids. If you find a new cross-cutting conflict, raise a normal Q- item and say "cross-cutting" in it.

| X | Decision | Owner § | Evidence summary |
|---|---|---|---|
| X1 | **DECIDED by owner 2026-11-03 (§0): TLS terminates in the sidecar (SNI passthrough); tlsedge never holds a user key.** Residual: certificate issuance with device-held keys, wildcard sharing across a team's devices, the lb SNI split, abuse without inspection | §13 | owner directive; [R:ext-edge], [R:product] |
| X2 | **DECIDED in principle by owner 2026-11-03 (§0): storage sees only encrypted bytes plus small header values; paths, names, messages, and content are encrypted (PLAN.md:59 superseded).** Residual: the exact header values (object ids, sizes, key-generation ids, ref names, opaque path tokens) and how subpath subscriptions and head reads work without plaintext paths | §11 | owner directive; [R:ext-storage-crypto] |
| X3 | Policy authority: access rules stored and compiled on the server (PLAN.md:119) vs a customer-held key authority that signs membership and policy (team-management mock, Tailscale report) vs phased | §8 (with §7) | [R:product], [R:server-identity] |
| X4 | Which registrable domain carries user names: ur.network (PLAN.md) vs a dedicated user-content domain. ur.network carries platform names, has a 'Personal VPN' category, is not on the PSL, and expires 2027-07-02 | §12 | [R:ext-edge], [R:server-platform] |
| X5 | The network's DNS label: the friendly, mutable, reclaimable network_name (PLAN's <me>) vs an immutable or opaque label with the name as an alias. Covers CT leakage, renames, and takeover | §12 | [R:server-identity], [R:ext-edge] |
| X6 | **DECIDED in principle by owner 2026-11-03 (§0): inbound mail TLS terminates on a device or customer-run sidecar; the edge sees only encrypted bytes plus SNI, connecting IP, EHLO, and spam-relevant header values; no encrypt-on-receipt at the edge.** Residual: routing without SNI (DANE-EE with DNSSEC, per-network IPs, per-network or per-burner MX labels), senders without STARTTLS, offline behavior (ciphertext-only queueing or deferral), burner shared-domain routing | §15 | owner directive; [R:ext-email-zk] |
| X7 | **DECIDED in principle by owner 2026-11-03 (§0): outbound mail is end-to-end TLS through smtpedge, which sees only ciphertext plus PLAN's small plaintext preamble of declared header values; edge-terminated submission and SES relay are ruled out.** Residual: making the preamble trustworthy (PLAN's ZK proof is unsound as written; a sound binding, ORIGO-like, or another check), what ships before it, refusing non-STARTTLS destinations, DKIM keys on devices | §14 | owner directive; [R:ext-email-zk] |
| X8 | Server-to-client push channel: platform service clients with a new no-escrow contract relationship vs ControlId-sourced subprotocol frames (amends SUBPROTOCOL.md decision 6) vs a new top-level connect control message | §6 | [R:connect-transport], [R:server-platform] |
| X9 | Which connect changes are allowed on connect's sidecar branch: exported reserved-id registration, per-registration filters, subprotocol source checks, a browser WebSocket transport, a per-flow egress hook for DNAT, logical lanes | §4 (each section lists its needs) | [R:connect-transport], [R:connect-ip], [R:sdk-clients] |
| X10 | Sidecar client identity: a top-level client (counts toward the free tier's 2 concurrent clients, enforced since 2026-11-03) vs a child client (SourceClientId; exempt, hidden) vs sharing the device's client id. "Solo must run any number of agents" (pitch5) | §5 (with §20) | [R:server-identity], [R:sdk-clients] |
| X11 | Paying for sidecar traffic: same-network Network-mode contracts are free and unmetered, cross-network needs Public with escrow, yet PLAN says "all of these count towards transfer balance". A service-usage debit, a no-escrow service relationship for edges and platform clients, or both | §20 (with §6) | [R:connect-transport], [R:server-identity] |
| X12 | MLS: fork an MIT Go implementation into the sidecar repo (thomas-vilte/mls-go, tmc/mls) vs write a narrow implementation; ciphersuite (classical 0x0001/0x0003 vs post-quantum); group granularity (per repo vs per network with per-repo exporter context); what "GKM" and "one session key stored in GKM" mean given epoch rotation and new-member history | §10 | [R:ext-storage-crypto] |
| X13 | The "new file cluster": a second MinIO deployment (upstream archived; the deployed build lacks the conditional-PUT fix; today's single host is saturated) vs another S3-compatible store; the capacity and durability target; where ref CAS ordering lives (Postgres?) | §19 (with §11) | [R:server-platform], [R:ext-storage-crypto] |
| X14 | The extension's sidecar runtime: a true WASM connect client in a worker (needs a browser WebSocket transport, header-free auth, a worker loader; sdk.wasm is ~75 MB) vs a hosted sidecar in server (like ProxyDevice) vs a native companion over native messaging | §18 | [R:sdk-clients] |
| X15 | Build order: recURd design partners want vault, change set, and reach first, with email last; the burner email product needs mail first | §23 | [R:product] |
| X16 | Pricing and quota conflicts: Team at $100/month plus usage (PLAN) vs $20-40/seat (pitch5); storage 1/20/200 GB (PLAN) vs 1/100 GB (cli/UI.md); email 5/200/20000 (PLAN) vs replies-only and 2000 (cli/UI.md); Pro is a boolean and Team does not exist in the server | §20 | [R:product], [R:server-identity] |
| X17 | recURd on dedicated recurd.dev infrastructure (connect/EXTENDERUPDATE.md §13.1) vs network-only; affects naming roots (recurd.dev vs ur.network), the allow-listable enterprise edge, and the OIDC issuer | §12 (with §2) | [R:product] |
| X18 | Bridge overlay addressing: no client has a virtual IP today; candidate ranges (RFC1918/ULA vs 100.64/10) collide with app tun exclusions or leak to public exits (100.64/10 counts as public in connect) | §17 | [R:connect-ip], [R:sdk-clients] |
| X19 | evs git compatibility: standard smart HTTP usable by third-party git clients vs a sidecar remote helper (git-remote-ur) plus an object API. Deployed encrypted-git systems (Keybase, gcrypt) use helpers. Git protocol v2 has no push command; go-git v6's server is limited; the lb caps bodies at 16 MB | §11 | [R:ext-storage-crypto], [R:server-platform] |
| X20 | The recURd record (signed ledger, approval and reach receipts, per-run coverage, two key domains, retention): PLAN.md does not cover it. Which infrastructure primitives this design provides, and whether the record itself is in this document or a separate one | §16 | [R:product] |

## 8. Key facts every writer must know (verified by research; cite [R:key]; re-verify anything you lean on)

- connect frames must fit one 16 KiB transport message (code), not 8 KiB (SUBPROTOCOL.md is stale). There is no fragmentation. Pack overhead is ~180 B encrypted, plus ~1.1 KB when a contract frame rides along. Oversized frames can close the carrier [R:connect-transport].
- The public subprotocol registration accepts ids 1024-65535 only. Reserved-id registration is unexported. There is one codec per id per client. Handlers run inline and must not block. Sends to ControlId are refused [R:connect-transport].
- Ordering is reliable only within one send sequence. A 60 s ack timeout tears down the sequence. A transfer ack is not application delivery. There is no stream or socket abstraction in connect. connect.Tun (gVisor TCP) exists [R:connect-transport].
- Same-network contracts use ProvideMode Network: free, no escrow, the destination must provide Network. Cross-network contracts are Public, with escrow from the payer. FriendsAndFamily is never computed by the server [R:connect-transport], [R:server-identity].
- Per-peer e2e sessions use TLS 1.3 (X25519MLKEM768) with AES-256-GCM. connect's default encryption mode is Off; the sdk provider uses Opportunistic. ControlId traffic is never e2e-encrypted. Residents see outer ids, sizes, and timing [R:connect-transport].
- The only real-time server push today is the resident's ControlId client sending control frames, triggered by Redis keyspace events. Server services already run their own connect clients with platform-network JWTs [R:connect-transport], [R:server-platform].
- Identity: network then one admin_user_id then clients. There are no members, roles, groups, tags, or policy tables. Tokens are the network token, the urn_ API key (no scope, no expiry), and the client token (30-day; aud api+connect). AUTHZ1 gap: on non-Embed networks, the AppAdmin routes, including /auth/code-create, still accept client tokens, so a sidecar token an agent can read is effectively an admin credential [R:server-identity].
- network_name: 5-50 bytes of [a-z0-9-], lowercased. No reserved list, no hyphen-position rule. Mutable via three inconsistent paths, reclaimable 24 h after a rename, freed at once on deletion. Some valid names collide with live ur.network platform labels (connect, gossip, grafana, ...) [R:server-identity], [R:ext-edge].
- Tiers: Pro is a boolean (an in-window transfer_balance row with pro=true). Free allows 2 concurrent top-level clients (enforced since 2026-11-03); Pro allows 1000. Child clients (SourceClientId) are exempt. The transfer balance is a byte ledger debited only by contract settlement [R:server-identity].
- Migrations go in server/db_migrations.go; the next version is 926+. Limits go through config/all/pro.yml and model.Pro(), with no hardcoded numbers. New routes are documented in connect/api/bringyour.yml, classified in route_authz.go, and mirrored in sdk [R:server-identity].
- Platform: a new service is server/cli/<svc> plus a services.yml block via warpctl. The lb nginx config is baked at image build. TCP 80/443 belong to the http block (no ssl_preread or SNI routing yet, though the module is compiled in). Public ports are TCP 80/443 and UDP 443/4053/53 (53 -> connect WhoDis). There is no SMTP port and no TCP 53. The lb body limit is 16 MiB, with 15 s/60 s stall timeouts. Client IPs are never logged [R:server-platform].
- Data stores: one Postgres primary behind PgBouncer in transaction pooling (no session advisory locks or LISTEN/NOTIFY). A 48-node Redis Cluster (co-access needs hash tags). MinIO is one shared host, saturated, from an archived upstream, lacking the conditional-PUT fix. BlobStore has no Delete or ranged read [R:server-platform], [R:ext-storage-crypto].
- DNS and certs: ur.network is on Route 53 (managed by warpctl), unsigned (no DNSSEC), with no SPF, DMARC p=none, and MX at Google Workspace. It is not on the PSL, and a listing needs >2 years of registration plus thousands of users; ur.network expires 2027-07-02. Let's Encrypt allows 50 new certs per registered domain per 7 days across ALL *.ur.network names. CT publishes every SAN. A taskworker ACME pipeline (x/crypto/acme, CSR from a client-held key) exists [R:ext-edge], [R:ext-email-zk], [R:server-platform].
- Email: outbound-only today, via SES. Postfix and Exim send no SNI in STARTTLS unless DANE validates, so SNI routing of inbound SMTP needs a fallback. No proxy does STARTTLS passthrough. Sender retry windows run 14-48 h. DMARC aggregate reports carry no Message-ID. Yahoo CFL keys on DKIM d=; JMRP keeps headers. The PLAN ZK preamble is unsound as written (non-committing AEAD); ORIGO-like TLS 1.3 proofs cost 1.5-9.8 s with a 112 MB proving key and are unaudited. connect never sends TCP/25 to providers [R:ext-email-zk], [R:connect-ip].
- Storage crypto: the MLS exporter is not forward-secure, and new members cannot derive earlier epochs, so evs needs its own epoch-key history. RFC 9420 needs exactly one accepted Commit per epoch (a strongly consistent sequencer). No deployed MLS storage exists; PLAN's "almost universal" claim is refuted for MLS. Deployed encrypted git (Keybase, gcrypt) encrypts whole packs behind a remote helper with a signed manifest and a CAS head. git-crypt leaks names, messages, sizes, and equality. Go MLS candidates are all MIT and unaudited (thomas-vilte/mls-go interop-verified; tmc/mls new). Go 1.26 crypto/hpke includes PQ KEMs. No cgo, because the sdk wasm build is CGO_ENABLED=0 [R:ext-storage-crypto].
- Clients: gomobile binds only basic types (no uint16/32/64, maps, func params, generics, or non-sdk types). The sdk ships four surfaces: gomobile, the cgo C ABI, syscall/js wasm, and plain Go. The iOS packet tunnel has ~50 MiB jetsam, a 32 MiB Go soft limit, and ~4.69 MB of binary headroom. One connect client per client id (one resident). No browser context runs a connect client today: the ur.io page runs a 75 MB WASM DeviceRemote against a hosted DeviceLocal. MV3 service workers die after 30 s idle [R:sdk-clients].
- IP: there is no overlay or virtual IP. Tun addresses are random 10.a.b.h/24 (or 169.254/16) and fd00:7572:6e65::/48. Apps exclude RFC1918 and fc00::/7 from the tun. 100.64/10 counts as public in connect. Subnet routing inserts in DeviceLocal.sendPacket after sendRoute.Load. Port mapping inserts at the provider's LocalUserNat dial points. Network-source peers can already make providers dial LAN and loopback with no per-port ACL [R:connect-ip].
- Product: pitch5 promises "private from us" (servers hold only ciphertext plus a published metadata list), passthrough TLS with the key in the sidecar, policy under a customer key authority, and agents egressing only through customer-run exits. Burner addresses in the mock are `adjective-noun-NNNN@burner.ur` (.ur is not a TLD) next to `alias@<user>.ur.network` in cli/UI.md [R:product].
