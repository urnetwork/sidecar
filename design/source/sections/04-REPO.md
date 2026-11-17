## 4. Repositories, code placement, branches, and build

### 4.1 Purpose and scope

This section decides where code lives and how it is built, branched, versioned, published and shipped, including X9's connect changes, operator-core's host contract (owner decision 251), where the build's operations commands live (owner decision 274) and the checkout's documents. Components are §5-§18, deployment §19, tests §22, milestones §23.

### 4.2 Requirements

| id | requirement | source |
|---|---|---|
| R-REPO-1 | CLI and components in sidecar; services, team management and access control in server; sdk exposes the components | PLAN.md:5 |
| R-REPO-2 | Of first-party modules sidecar imports only connect and operator-core, never server or sdk; server and sdk import sidecar | PLAN.md:7; owner decision 251 |
| R-REPO-3 | go.mod, sidecar.go, protocol/, mcp/, cli/main.go; service code in the root | PLAN.md:9-21 |
| R-REPO-4 | New pieces, MLS included, in sidecar; all work on `sidecar` branches | owner rules 1, 4 |
| R-REPO-5 | No parent package imports a child; commits carry no AI attribution | connect/CODESTYLE.md:24-47, 80-83 |
| R-REPO-6 | Go 1.27.4, pinned siblings, rollout classes, no cgo in sidecar packages | server/README.md:5-14; sdk/js/Makefile:69; owner decision 272 |
| R-REPO-7 | Open source, signed releases, one calendar version; reproducible builds a goal, not a gate | sidecar/design/pitch5.html:930; build/README.md:3-7; owner decision 77 |
| R-REPO-8 | sidecar public from 2026-11-04 as it is; every touched repo merges `sidecar` into `main` at each exit review | owner decisions 117, 118 |

### 4.3 What exists today

- **Repos** (`gh repo view`, `git log`, 2026-11-05). sidecar holds two `main` commits and no code: `2b5b0ab` (2026-11-03, 119 documents) and `708bb45` (2026-11-05, the design checkpoint: the business documents moved under `design/` as renames, so their history follows, and DESIGN.md, its reviews, README.md with its images, the research sheets and the search-index report and notes added). INTERNAL and unlicensed before owner decision 118's flip, it is now PUBLIC, its README stating MPL-2.0, whose full text is the first `sidecar` commit (4.9); connect, sdk, server, sn (`urfoundation/sn`), build, warp and extension are PUBLIC too, config, vault and xops PRIVATE, mmm INTERNAL. None had a `sidecar` branch at that date; M0 opened one in each (4.8). operator-core (`github.com/urnetwork/operator-core`), which the owner created on 2026-11-15 for owner decision 251, holds no code yet.
- **Replaces and pins.** Replaces are not inherited, so server, sn and four sdk modules repeat them (server/go.mod:213-236; sn/go.mod:205-223; sdk/go.mod:107-115). server's lock pins complete commits of nine clean siblings on one `go` line (server/local/source-graph/source_graph_test.go:90, 113-143, 200-235); build pins its submodules as gitlinks (build/.gitmodules).
- **Release, hooks, CI:** `yyyy.m.d-code` versions (build/all/run.sh:1186-1195). connect and sdk declare unversioned modules (connect/go.mod:1; sdk/go.mod:1), which consumers require at v0.0.0 beside sibling replaces (server/go.mod:48, 213), and the release rewrites each to `/v2026` on a version branch (4.9). An unclassified service exits 64 (build/all/deploy-rollout.zsh:37-39). At that date all touched repos but sidecar, config and vault shared one commit-msg hook, which 4.9 copies into those three and minio. With no hosted CI, policy lives in Go tests, a leg per shipped build (sdk/dependency_boundary_test.go:81-92).

### 4.4 Repo tree and layering

```text
sidecar/            github.com/urnetwork/sidecar, package sidecar
  go.mod LICENSE NOTICE CODESTYLE.md README.md DESIGN.md DESIGN-REVIEW*.md FEEDBACK-SYSTEM.md RECORD.md
  Makefile dependencies.yml .githooks/ RELEASE-KEY.pub (4.10, once the release key exists)
  design/                               the business and input documents (PLAN.md, product.md, pitches,
                                        market notes, mocks/, reports/, design-research/, cold5/) and the
                                        README's assets (readme/, mocks/previews/) (4.11)
  research_notes/                       the research behind design/reports/ and the pitches (4.11)
  sidecar.go settings.go                Sidecar, Version, SidecarSettings
  identity_ keys_ state_ daemon_ api_   core
  indexer_                              an indexer's services: schedule, fallbacks, status (§3.6)
  envelope_ rpc_ stream_ push_ codec_   subprotocol (type Subprotocol, §6)
  host_                                 engine host interfaces (ServiceHost), aliasing operator-core's (4.5)
  acl_ socket_ mls_ gkm_ evs_ dns_ tls_ smtp_ mail_ bridge_ record_ directory_ search_   client and shared;
                                        search_remote_*.go is remote search (§11.14), evs_drop_*.go the
                                        drop-history client (§11.7)
  pushservice/ socketsservice/ gkmservice/ evsservice/ dnsservice/
  tlsedgeservice/ certsservice/ smtpedgeservice/ mxedgeservice/     server-only engines: import the root;
                                                                    only server imports them
  device/           package device: the forwarding role's packet side (§17's classify, hook, routes and zone,
                    §18.6's posture, verifying anchored revocation deltas); imports connect and protocol/bridge
                    only; an app's VPN component links it with the root's forwarding files (§18.10; owner
                    decision 197)
  protocol/         *.proto, *.pb.go, Makefile; config.proto (§7.9), acl.proto (§8.8) and directory.proto
                    (§16.11) import bridge/; search.proto (§11.14)
    bridge/         package bridge, std and protobuf only, sole home of every type device/ parses:
                    signed.proto  Signed, WebAuthnEvidence, SignedType (§6.9, §6.11), plus VerifySigned
                    auth.proto    AuthEntry, AuthPin, ProjectionHeader, StatementHeader and the rest of
                                  §7.9's log, Genesis, SidecarRevoke and MemberRevoke; §8.8's GrantRevoke,
                                  Suspend and Unsuspend
                    bridge.proto  BridgeState, BridgeIdentity, BridgeShareKey, Pending, BridgeRows,
                                  WindowDelegation, ShareCert and §17.8's statements
  mcp/              stdio MCP server
  cli/              nested module github.com/urnetwork/sidecar/cli: ur, also run as git-remote-ur (4.10);
                    requires the root and smtpproof
  sidecartest/      the in-process harness (§22.4); fakes and store conformance suites, until they move to
                    operator-core/coretest (4.18)
  testdata/         MLS vectors, the mlswg's 16 vector files committed under mls/mlswg/ with their SOURCE and
                    SHA256SUMS (§10.4; owner decision 263), transcripts, golden encodings
  mlsinterop/       nested test module of differential peers: tmc/mls and thomas-vilte/mls-go v1.6.0
                    (both MIT; §10.4), with no mlswg interop client, no code of the mlswg's module and no grpc
                    dependency; go-git, the git codec oracle (§22.6)
  smtpproof/        nested module: the X7 BDAT and DATA provers and the verifier (§14; owner decision 125),
                    which cli/ and server inject through root interfaces; the root never requires it
  third_party/      go-smtp/, the patched fork, and mox/, the subset its dkim, dmarc and spf packages need:
                    each a module under its upstream path with a URNETWORK.md naming the upstream tag and the
                    patch, reached only through 4.7's replaces (§15.5)

operator-core/      github.com/urnetwork/operator-core, package operator, its own repository
                    (owner decision 251): the core services' interfaces and the value types server and
                    sidecar share, no service implementation; imports connect, never sidecar, server or sdk
  go.mod LICENSE
  env.go            Env, the root factory of every service an extension holds (4.5)
  *.go              ServiceHost's interfaces, the db, the domain interfaces for server-owned data (networks,
                    clients, accounts), Engine, HttpEngine, StreamEngine and Extension; the value types moved
                    from server: Id (type Id connect.Id, with server.Id's marshalling), ByteCount, NanoCents,
                    the blob object records and the sentinel errors
  coretest/         nested module github.com/urnetwork/operator-core/coretest: in-memory fakes of those
                    interfaces and their conformance suites, which only test legs import
```

- Of this module's packages, the root imports only `protocol` and `protocol/bridge`, std-and-protobuf packages, as connect's root imports `connect/protocol` (Q-REPO-3). `protocol` imports `protocol/bridge`, never the reverse, so a type both use is declared only in `protocol/bridge` (4.9). The root never imports `device/`: `cli/` (`ur tun`, `ur bridge`) and sdk's `DeviceLocal` wire `device.Bridge` to the root's `BridgeState`, so Apple's network extensions, the `ios_extension` leg, link of the root only §18.10's forwarding files and of `protocol` only its config, acl, evs and gkm descriptors (D-SDK-20; owner decision 197). Beyond this repository the root's first-party imports are connect and operator-core's `operator` package, which imports connect (owner decision 251).
- **Build tags.** Desktop-only code (the OS tun, §17.10; installers; the macOS keychain, §5.10) lives in `cli/` or carries `!ios && !android && !sdk_mobile_bind`. Package connect links gVisor into every importer through its untagged tun.go (connect/tun.go:38-47), so root files that use package connect (client generations and `SidecarEnv`, `Subprotocol` and streams, remote search, sockets dial and listen, the bridge, tls and smtp listeners) carry `!sidecar_http`, as do the engine host interfaces (`host_*.go`), since no hosted server engine runs in the page Worker, whose search engine needs none. The rest, §5.4's events, actions, binding and `Sign` included, uses the root's `Id`, `Logger`, `MonitorValue` and `CallbackList`, and reaches api through the net/http `SidecarApi` (bearer plus DPoP signer), in both legs; connect-facing files convert at that boundary. The root's `Id` is an alias of operator-core's (4.5), which imports connect, on every leg but the `sidecar_http` one, where it stays the root's own `[16]byte` type, a build-tag twin of id.go (id_http.go) whose methods and encodings are identical to operator-core's and which a test holds to them: the page Worker runs no engine and takes no `Env`, so nothing on that leg needs operator-core, the leg links no connect package or gVisor, and §4.7 fails one that does (§18.10; owner decision 276, amending 251 for this one leg). `make size` then measures that leg at about 57.8 MB unstripped, so D-SDK-19's 41,943,040 B goal stays a recorded slip and its miss rule's 74,965,628 B gate stands (§18.10). The `ios_extension` leg links operator-core beside the connect it links through `device/`, and the owner revisited §18.10's 6 MiB extension budget (owner decision 215) with that leg's measurement, as owner decision 251 foresaw: with the replaying config head reader on the leg it rose to 7.5 MiB (owner decision 491).
- **The `ios_extension` leg's files.** `check/` seeds the leg from the Forwarder's files, every root `bridge_forward*` file among them, and regenerates its list (check/testdata/ios_extension_leg.txt), which is exactly the Forwarder's and the compiler's closure (§18.10; owner decision 197), so a Forwarder file tagged out by mistake fails closed. The seed rule is not narrowed for a file it takes wrongly: a file of the sidecar role never carries the Forwarder's prefix, so the role's forwarding setup is bridge_setup_forward.go and its port forwards bridge_daemon_forward.go, and a declaration the closure needs from a file tagged `!ios_extension` moves into a file of the closure, as `EvsGitEmptyTreeOid` moved to evs_git_object.go, the tag staying (owner decision 275).

### 4.5 Placement and the sidecar/server split

| Component | sidecar | server and other repos |
|---|---|---|
| Host contract (owner decision 251) | the `<svc>service` engines and any `Sidecar` core a server process runs take an `Env`; sidecar's stores, over the db it grants | operator-core: the interfaces and shared value types, fakes in `coretest`; server/core implements the `Env` |
| Core, subprotocol, MCP, `ur` (§5, §6, §16) | root, protocol/, mcp/, cli/ | api routes (§5, §7) |
| Push (§6.8, §18.7; owner decisions 17, 88, 104) | `push_`; `pushservice`: publishers, long-poll, wake sender | connect residents, api, taskworker, respectively |
| Access control (§8; owner decisions 3, 5, 6) | `acl_`: parser and compiler, run by each device for itself and by the writer of each config head for `AclRows`; gates use only the `AclRows` evaluator | the signed id-only projection: storage, routes, gates |
| sockets (§9) | `socket_`, `socketsservice` | server/cli/sockets |
| gkm (§10) | `mls_`, `gkm_`, `gkmservice` | server/cli/gkm from v0 (D-OPS-2); reconciler in taskworker |
| evs (§11) | `evs_`, `evsservice` | server/cli/evs; GC, packing, drop jobs and the metadata write budget's loop in taskworker (§19.4) |
| File cluster (§19.6; owner decision 195) | `ServiceHost.Blobs`, an interface only | `urnetwork/minio`, a public fork, holds D-OPS-20's build and MinIO's AGPL source; no module here imports it, and server's Blobs client is minio-go, Apache-2.0 (server/blob.go) |
| dns (§12) | `dns_`, `dnsservice` | server/cli/dns on the dns edge (owner decision 71) |
| tlsedge, certs (§13) | `tls_`, `tlsedgeservice`, `certsservice` | server/cli/tlsedge; taskworker |
| smtpedge (§14) | `smtp_`, `smtpedgeservice`, `smtpproof` | server/cli/smtpedge |
| mail, mxedge (§15) | `mail_`, `mxedgeservice` | server/cli/mxedge |
| bridge (§17) | `bridge_` (the compiler builds `BridgeState`, in the daemon or an app's VPN component); `device/` (the forwarding role's packet side); `protocol/bridge` | sdk DeviceLocal imports `device/` (sdk/device_local.go:5707, 5800); connect C5, C18 |
| Operations commands (owner decision 274) | none: 4.7's license list and layering let no command here link server's model or an engine package | server/sidecarctl, one binary for every operations command this build adds (`certs swap` and `renew`, `dns census`, `restoring`, `restore` and `ceremony`, `evs purge-turn-on`, `sidecar restore`, `network sidecar-limit`, the abuse commands), beside the model code its commands call and under server's own dependency, license and layering rules; `bringyourctl`'s and `warpctl`'s existing commands stay where they are, and the customer-facing `ur admin` commands in `ur` |

The host contract is operator-core's `Env` (operator-core/env.go), the root factory of every service an extension uses (owner decision 251). An extension holds service instances that an `Env` creates, never a package-level service function or global service state, unlike server's own shared-namespace functions (`server.Db`, `server.Tx`, its Redis and blob helpers), on purpose. server/core implements it, wrapping server's existing services, those functions and the sidecarhost, evshost, dnshost, mxedgehost and quotahost packages, and passes it to sidecar's server-hosted code, the `<svc>service` engines and any `Sidecar` core a server process runs, which take the `Env` or the instances they need. Device-side code (`ur daemon`, the apps, their VPN components) takes no `Env` and keeps its own settings and local stores.

```go
// operator-core/env.go, package operator: what a hosting process supplies. Engines never import server, so
// go-redis, minio-go, pgx and prometheus stay out of sidecar and operator-core.
type Env interface { // each accessor answers its service or a typed not-granted error, never a nil
	Db() (Db, error)                             // granted only where the process allows: evs and gkm get none
	Redis() (Redis, error)                       // cas, incr, scripts, TTLs, hash-tagged keys; evs and gkm keep
	                                             // only soft state they rebuild there (owner decision 136);
	                                             // keyspace events only via the shared subscriber, never per
	                                             // client, the pattern that melted the cluster on 2026-07-15
	                                             // (server/model/peer_model.go:32-37)
	Blobs() (BlobStore, error)                   // the segment bucket and each metadata cluster's bucket, by
	                                             // cluster id, the first holding place/ (owner decision 145):
	                                             // If-Match and If-None-Match puts, streamed put, ranged get,
	                                             // prefix list, delete (X13)
	Authenticator() (Authenticator, error)       // jwt -> Principal (server/session)
	Quota() (Quota, error)                       // reserve, commit, release (§20)
	Metrics() (Metrics, error)                   // prometheus in server
	Tasks() (Tasks, error)                       // once-keyed jobs (taskworker)
	Push() (Push, error)                         // server to client (X8)
	ServiceClient() (ServiceClientSource, error) // jwt and urls for the engine's connect client
	// and ServiceHost's other members, Clock (below), ClockCheck (§19.6), Gates (ServiceGates, §19.11's
	// gates, which server implements over CurrentSidecarConfig), Budget (§11.13's write budget) and Abuse
	// (§21.7), beside the domain interfaces through which server-owned data (networks, clients, accounts)
	// reaches an extension
}

// The injected clock, on every leg. ServiceHost.Clock and SidecarSettings.Clock hold it, nil meaning real
// time; the root's Clock and sidecartest.Clock alias it.
type Clock interface {
	Now() time.Time
	After(timeout time.Duration) <-chan time.Time
	AfterFunc(timeout time.Duration, function func()) (stop func() bool)
}

// What each engine a server/cli/<svc> hosts hands back. The host wraps it with readiness, /status, stats and
// PROXY-unwrapped listeners and serves the shape it is handed, never asking by type assertion; pushservice's
// types run inside existing services instead. An engine package states its shape, as
// var _ operator.HttpEngine = (*EvsEngine)(nil); smtpedge, which listens on nothing (§14.9), is an Engine.
type Engine interface {
	Ready() bool // its stores reachable and its state loaded, §19.4's ready column
	Drain()      // takes no new work; returns once work in flight ends or its own bound passes
	Close()
}
type HttpEngine interface {
	Engine
	Handler() http.Handler // one handler for every route of the service
}
type StreamEngine interface { // tlsedge, mxedge
	Engine
	Serve(listener net.Listener) error // once per listener, each on its own goroutine
}
```

Each process grants the db only where its role allows. evs and gkm get none and keep durable state only in `Blobs` (owner decisions 2, 19, 21): a repo's metadata objects and its gkm group's live on the metadata cluster that the repo's create-only `place/<repo_id>` on the first cluster names, which the engines resolve and cache (owner decision 145; §11.8). The db mirrors server's helpers (server/db.go) as instance methods: callback-style `Db` and `Tx` whose implementation owns retries (serialization failures, lock timeouts), the isolation and read-before-begin options, `Query`, `Exec` and `Batch`, `Rows` that scan into standard types and `Id`, named args and temp tables, all in operator-core's own types with no pgx type; server/core adapts server's pgx helpers to it. Sidecar owns its SQL: its stores (`SmtpEdgeStore`, …) live in sidecar over the granted db and touch only sidecar's own tables, server's T3 harness testing them over server/core's db (§22.4); server-owned data reaches them through operator-core's domain interfaces; and sidecar's operator-core `Extension`, its migrations and its engines' constructors over an `Env`, is what server/core iterates, running the migrations, so hosting another extension is one import and one registration.

operator-core's `Id` is server.Id moved: `type Id connect.Id`, with server.Id's database/sql, JSON and Hash marshalling and its parsing, formatting and comparison delegating to connect. Its pgx codec stays in server/core; `server.Id` and the root's `Id` alias it, the root's on every leg but the page Worker's, which keeps a twin (4.4; owner decision 276); the generators stay where they are, server's `NewId` over `connect.NewId` and the root's on crypto/rand. Its JSON decode refuses everything server.Id or the root's `Id` refused before the seam: server.Id's null and length refusals keep server's words, and an unquoted value, a separator other than a dash and bad hex answer `ErrInvalidId` without echoing input (I-13), every refusal matching `operator.ErrInvalidId`; a well-formed id decodes as before, encodings are byte-identical, and the Scanner and Valuer stay server's exactly, so server accepts fewer malformed inputs than it did, none of which a conforming encoder produces (owner decision 276). The other value types server shared move with it (`ByteCount`, `NanoCents`, the blob object records, the sentinel errors); server-internal types stay in server.

Until the build's review phase moves the call sites (4.18), sidecar and server keep Go type aliases of the moved types and sidecar keeps `ServiceHost`, so other sections' `ServiceHost.<member>` names stay valid, each naming the `Env` accessor of that name, and sidecar's stores and migrations stay in server, which implements them over Postgres.

### 4.6 Connect changes (X9)

Dispositions follow owner decisions 22, 85 (C14 into M4), 86 (C18) and 176 (C19), under D-REPO-5 (Q-REPO-2).

| # | Change | Disposition |
|---|---|---|
| C1 | Export reserved-id registration (connect/subprotocol.go:545, 558) | Rejected: §6 uses public id 21842 |
| C2 | Provide-mode and size filters (SUBPROTOCOL.md §6) | Rejected: handlers see `peer.ProvideMode` and length |
| C3 | Drop ControlId-sourced subprotocol frames unless opted in (connect/subprotocol.go:590-651); P2P carriers accept only their adjacent peer as source under `ClientSettings.P2pPeerSourceOnly`, which `Client.run` enforces, since `MatchesReceive` never sees a frame, so an opted-in client is never the endpoint of a multihop stream (connect/SUBPROTOCOL.md §11.3); default clients are unchanged | M1 |
| C4 | Browser WebSocket H1 carrier (`GOOS=js`), in-band auth, Origin allowlist (§18.8) | Later, after §18's HTTPS-only worker (owner decision 26) |
| C5 | `connect.EgressHook` (`ResolveEgress`, §17.6) in `LocalUserNat`: pass, map or deny per flow, with C13's subject and `Sealed` on `EgressFlow`; `EgressDecision.IdleTimeout` replaces, for that flow, the NAT-wide idle (read at connect/ip.go:3244 and :3255 for the shared lifecycle, :3873, :7027 and connect/ip_icmp.go:854; 0 keeps it), so bridge flows hold §17.5's idles without raising the host's other flows; flows register their rule tag and policy generation before the dial, so `CloseFlows` fences dials in progress (D-BRIDGE-21) | M4 |
| C6a | 100.64/10 non-public for §17 (connect/ip_security.go:892-908), with its own drop reason instead of an Incident, which calls `ReportAbuse` (connect/ip.go:10242-10244), behind `CfaaSecurityPolicySettings.DropSharedAddressSpace`, false by default, a check of its own beside `isPublicUnicast` (§17.6) | M4, after shadow counts |
| C6b | A `Tun` forwarder for a tun-less router | Rejected: not needed (§17.10) |
| C7 | Caller lane key for non-IP sends (connect/transfer_logical_lane.go:11-37) | Deferred: `TransferKey` lanes suffice |
| C8 | HTTP CONNECT and `HTTPS_PROXY` for platform transports and API dials; SOCKS5 only today (connect/net.go:333-363) | M4 (§5, §16, §18; owner decision 49) |
| C9 | `ProvideMode` Service = 6 (enum 0-5, connect/protocol/transfer.proto:354-361) for edge streams: subprotocol only, no IP, escrow or payout; minted only for §9's Find-recorded pairs (§6.10.1) | M5 |
| C10 | Push MessageType | Rejected: X8 (b) needs none (owner decision 17) |
| C11 | New routes in connect/api/bringyour.yml | M1 for the spec's entries (§7, §8, §11), marked `x-status: planned` and `x-internal: true`, then with each route's own task: every other new route enters the spec in the change of the task that first serves it, which lifts `planned` |
| C12 | connect/SUBPROTOCOL.md: stale 8 KiB (:89); item 6 (:372) as owner decision 17 amends it; id 21842; C3 | M1 |
| C13 | In every mode, seal into `StoredContract` (connect/protocol/transfer.proto:631-638) `source_subject_client_id`, which the server fills from the source client's stored `network_client.acl_subject_client_id` (D-ACL-3), never a client-supplied value, with `source_network_id`, the contract class and, for a window client, the subject's `WindowDelegation` (§17.9); a companion contract inherits its forward contract's subject, source network and class and seals no `WindowDelegation`, which is the forward contract's alone (owner decision 301); expose them on `Peer` (connect/transfer.go:608-619) and `EgressFlow` | M4 (§8.10, §9, §17; D-PROTO-19) |
| C14 | `UpgradeMux.SetLocalZone`, consulted before the Blocker in `handleDns` (connect/ip_mux_upgrade.go:1661) and `resolveDnsTcpQuery` (:716) | M4 (owner decision 85); `ur tun` uses §17's resolver |
| C15 | `Peer` exposes the session's verified peer client key read-only, unexported today (connect/transfer_encrypt.go:1152-1157). With it, in a change of its own, `EncryptionSettings.GateReceiveOnSignedIdentity`, off by default: on, `unwrapFrame` opens nothing for a session whose signed-identity state is pending, rejected or store-unavailable and returns a distinct gated result, and `Client.run` drops that frame with no ack and counts it, never calling `NotifyUndecryptableWrap`, whose nack would drive a re-handshake; a pending peer's frames recover by the sender's resend once the gate clears. Sidecar clients and §17.5's bridge window clients set it on, other Required clients staying off until their own production rollout | M1 (§6, D-PROTO-13) |
| C16 | Sticky Required: an Opportunistic client with a session to a peer never falls back to plaintext for that contract (connect/transfer_encrypt.go:477-483); its receive gate latches at this side's seal, and before M8 turns it on for app-device hosts the plaintext an Opportunistic peer has in flight at the seal is measured: if the loss is visible, the gate latches at the peer's first sealed frame, bounded by `TlsTimeout` from this side's seal (owner decision 224) | M4 (§17, §18); until then app devices are not bridge targets |
| C17 | A `js` connect build without gVisor or the IP stack: a connect-only js/wasm main imports 42 gvisor packages (2026-11-03; sizes in §18.10) | Decided after §18's spike, for the extension's streaming Worker only; the page Worker uses §18.10's `sidecar_http` leg |
| C18 | FriendsAndFamily flows to private destinations, which today admit only Network sources at the source's multi client (connect/ip_security.go:385-390; connect/ip_remote_multi_client.go:6691) and the provider (connect/ip.go:10307; connect/ip_security.go:567-576). The provider hands them to a C5 hook keyed on C13's `source_network_id`; the source admits only §17's alias-mapped destinations | M6 (owner decision 86); hooks only on sidecar-owned Required targets with a cross-network route grant; off in sdk providers |
| C19 | A per-peer accounting mode, off by default, for §6.10's remote-search windows. While a peer is in it, connect withholds every report, checkpoint or close, of a window's contracts with that peer, in both directions, until the window ends 55 minutes after its first contract's creation, 5 minutes before that contract's signed expiration. It then moves the sequences off them, as at expiry, and, while the mode holds, onto a new contract it takes at once with its successor requested then, which opens the next window whatever frame first rides it (§6.10), and sends one `CloseContract` a contract (connect/transfer_contract_manager.go:2344-2350): R(T) on the window's first and 0 on the others, T being the client's counted bytes, acked and unacked, over the window's contracts in that direction (§6.10), and R(T) the floor F = 256 KiB while T ≤ F, else F plus 128 KiB steps. The sidecars of a pair that a Hello or HelloResult carrying the requester feature bit marks (§6.11) set the mode for each other through connect's per-peer setter, since a `Peer` exposes no contract id (connect/transfer.go:608-619), each first retiring the contracts it already sends on to the other. A window's first contract is the lowest contract id among that direction's window contracts a frame rode, adopted by lane through `AdoptPeerWindowContract`, and the sidecar feeds the window's end rule through `NotePeerWindowActivity(peerId)` on each Ping, Pong, Hello and HelloResult (§6.10's first and end rows), with no wire change. A window with up to five search pages then reports as one with none, whatever the pair's scheduled background (§6.10, §11.14; §2.8 connect-5) | M10 (owner decisions 176, 188) |
| C20 | `DohCache.ForwardDnssec(ctx, qType, domain)` sets EDNS0's DO bit on `Forward`'s query (connect/net_http_doh.go) and returns the raw response: generic, additive and off by default. Over it a device fetches MX, TLSA, DS and DNSKEY RRsets with their RRSIGs and validates them to its embedded root anchors, which is what §15.5's `strict_chain` rests on (§2.8 ext-3) | M7 (owner decision 269) |

### 4.7 Module, dependencies, enforcement, consumption

```text
module github.com/urnetwork/sidecar
go 1.27.4
tool google.golang.org/protobuf/cmd/protoc-gen-go
replace github.com/urnetwork/connect => ../connect
replace github.com/urnetwork/operator-core => ../operator-core
replace github.com/pion/sctp => ../connect/sctp
replace github.com/urnetwork/glog => ../glog
replace gvisor.dev/gvisor => ../gvisor
replace github.com/emersion/go-smtp => ./third_party/go-smtp
replace github.com/mjl-/mox => ./third_party/mox
```

```text
development (every sidecar branch and main)
  sidecar/go.mod            module github.com/urnetwork/sidecar        root: core, protocol/, mcp/,
                                                                       device/, <svc>service/, sidecartest/
  sidecar/cli/go.mod        module github.com/urnetwork/sidecar/cli    ur and git-remote-ur; requires the root
                                                                       and smtpproof; injects provers
  sidecar/smtpproof/go.mod  module github.com/urnetwork/sidecar/smtpproof   provers and the verifier, which
                                                                       server injects into smtpedgeservice
  sidecar/mlsinterop/go.mod test-only differential peers
  operator-core/go.mod      module github.com/urnetwork/operator-core  its own repository (owner decision 251):
                                                                       the host contract; requires connect
  operator-core/coretest/go.mod  .../operator-core/coretest            fakes and conformance suites; test
                                                                       legs only
  sidecar/third_party/go-smtp, mox   modules under their upstream paths (github.com/emersion/go-smtp,
                                                                       github.com/mjl-/mox): the patched fork
                                                                       and the subset, never required by path
  replaces   a nested module repeats the root's sibling replaces one level up, plus this repository's own, the
             two forks' as ../third_party/go-smtp and ../third_party/mox
  consumers  require v0.0.0 with ../sidecar (server and sn also ../sidecar/smtpproof), as for connect, and
             operator-core v0.0.0 with ../operator-core, which sidecar's root brings into every consumer's
             module graph; server, sn and the four sdk modules repeat the forks' replaces as
             ../sidecar/third_party/go-smtp and ../sidecar/third_party/mox
```

- **Imports:** besides this repository's modules, connect with its replaced forks and operator-core are the only first-party modules a sidecar module requires (owner decision 251), operator-core/coretest only in the test leg; never proxy or the userwireguard it requires (proxy/go.mod:9-10), so `ur proxy add` (cli/UI.md:39-41) runs in `cli/` on §17's userspace `connect.Tun`.
- **Third-party:** `dependencies.yml` lists each module with SPDX id, reason and leg (client, engine, cli, test), operator-core's on every leg and operator-core/coretest's on the test leg alone. Allowed: MIT, BSD-2/3-Clause, Apache-2.0, ISC, MPL-2.0 and X11, read as MIT's text plus only its no-advertising clause, which lets src.agwa.name/tlshacks, connect's ClientHello parser on every connect leg, through as a license of its own with no per-module exception (owner decision 271); refused: GPL family, SSPL, BUSL, custom, unlicensed. Initial: protobuf v1.36.11, x/crypto, docopt-go, pires/go-proxyproto, go-sdk v1.7.0 for mcp/ and go-winio v0.6.2 for §5.8's pipe (server/go.mod:30, 67), purego v0.11.2 for the macOS Keychain (Apache-2.0), wireguard's tun (MIT) for `cli/`'s OS tun (§17.10); in the test leg, `mlsinterop/`'s peers [R:ext-storage-crypto].
- **Patched libraries.** §15's mail libraries need changes their upstreams do not carry, so each lives in `third_party/` as a module under its upstream path, behind the replaces above, with a URNETWORK.md naming the upstream tag and the patch, as server/third_party/pgx does. `third_party/go-smtp` keeps D-MAIL-3's `ServeConn(conn, ServeConnOptions{AfterStartTls: true})` and adds `ServeTlsConn(conn *tls.Conn) error` over it. The release fixture builds the root at its tag with no replaces (4.9), which links upstream go-smtp, so the root names no fork-only symbol: mail_smtp_serve.go reaches `ServeTlsConn` only through a local interface assertion on `*smtp.Server`, which fails against upstream's server, and `mailSmtpServe` then refuses, closed. `third_party/mox` holds only the packages `dkim`, `dmarc` and `spf` need, with `mlog`'s three counters removed so prometheus stays out of every leg, and both of mox's license files; `dependencies.yml` lists github.com/mjl-/mox as `MIT AND MPL-2.0` and github.com/mjl-/adns. Upstream's mox API is a superset, so it needs no seam and `mailAuthVerifiers` stays the one (§15.5). If an upstream takes its patch the replaces and the assertion go; upstreaming is an external action.
- **Versions:** shared modules match connect, sdk and server, because an uncoordinated bump fails server's `-mod=readonly` build (server/README.md:12); protobuf follows §18.10; golang.org/x/text follows §11.14's normalizer 1: one module version on every leg, at least v0.43.0, which every module of connect, sdk, sdk/build, server and sn now requires, so no bump is owed; what remains is `make check`'s rule below, and from M10 any x/text bump is a new normalizer and a rebuild (§11.14). The floor is v0.43.0 because v0.40.0 and gomobile's v0.41.0, which connect, sdk and sdk/build held on 2026-11-05, have an NFC that wrongly composes 19,960 two-rune strings (every two-rune string checked under go1.27.3, 2026-11-05), U+05D2 U+0307 into U+105C9 and U+10044 U+0307 into U+1E0A among them, which v0.43.0 normalizes correctly under the same reported Unicode version, 17.0.0 (v0.40.0 and v0.41.0 key recomposition on runes clipped to 16 bits, .gomodcache/golang.org/x/text@v0.40.0/unicode/norm/forminfo.go:217).
- **Go.** Every go.mod of connect, sidecar, sdk, server and sn names go 1.27.4, moved from 1.27.3 in one coordinated change for GO-2026-6859, an HTTP/1 server crash in net/http that `make check`'s govulncheck rule fails; `check/` accepts no advisory, the build images' Go base and server's lock.yml `go` line follow, with a re-pin, and the toolchain comes through the module proxy, checked against Go's checksum database. D-TEST-15's one-toolchain rule holds, since x/text chooses its tables by go1.27, which a patch release does not change. Two measurement harnesses stay on go1.27.3 so their frozen baselines stay comparable: server's competition evaluator (server/connect/sim-latency's image digest, GOVERSION guards and toolchain-policy test, server/competitionagent and server/cli/competitionsubeval) and the tests repo's perf runner (tests/runner/perf, whose h1 diagnostic requires a go1.27.3 producer and preflight manifest). Neither depends on a bumped module, so both still build; on these branches the evaluator image cannot build server's module and a perf run fails its h1 preflight, until the owner re-qualifies both on go1.27.4, at the latest before sidecar merges to `main` (owner decision 272).
- **`make check`** (Go tests, also at release):

```text
fails on
  deps      server, sdk, sn or an unlisted module in a leg's go list -deps; operator-core/coretest on a leg
            but the test leg (owner decision 251); the root module requiring any module of this repository;
            from M10, a leg selecting a golang.org/x/text other than normalizer 1's (Versions, above)
  layering  the root importing a package of this module other than protocol and protocol/bridge; protocol
            importing beyond std, protobuf and protocol/bridge, or protocol/bridge beyond std and protobuf; a
            client package importing a <svc>service
  legs      the ios_extension leg's root files leaving §18.10's forwarding list, or its protocol descriptors
            beyond that list's (owner decisions 197, 275); a root file of the sidecar_http js leg importing a
            connect package (from M1), or the leg linking one, its Id being the root's own twin (owner decision
            276); net/rpc or template packages on ios, android or js
  cgo       CgoFiles, except keychain_darwin.go in §5.10's darwin fallback leg
  hygiene   replaces other than 4.7's; registry conflicts; stale generated code; a release leg built with
            sidecar_testhooks (§22.4); a direct wall-clock call in a non-test file of the root, a <svc>service,
            mcp/ or device/, outside a dated exception list, id.go first (§22.8); govulncheck findings
legs        sdk's table (sdk/dependency_boundary_test.go's messagingBoundaryLegs), which lists every target
            sdk/build/Makefile binds, each with the tags gomobile adds for it: android/arm and android/amd64
            beside android/arm64, iossimulator/arm64 beside ios/arm64 (gomobile's ios tag), macos/amd64 beside
            macos/arm64, each built as gomobile builds the macOS slices, GOOS=ios with its macos tag, on which
            desktop files also select (§18.10's tags; owner decision 493), the extension bind's slices
            likewise, gomobile's CGO_ENABLED=1, sdk_mobile_bind and ios_extension included; check/ mirrors the
            table and fails a row of sdk's with no leg here, adding no gomobile target of its own (owner
            decision 277); the sidecar_http js leg (GOOS=js GOARCH=wasm -tags sidecar_http over the root and
            protocol, which §18.10's main imports); the CLI's six release targets, from cli/
runs        every leg compiles, 32-bit android/arm among them; tests run on each leg the host can run, and a
            leg it cannot run reports as §22.4's T1 says
```

- **Consumers:** server, sn (sn/go.mod:207), build/all/acceptance and four sdk modules add the require and replace above, server and sn also for `smtpproof`, and operator-core's beside them, since a replace is not inherited (owner decision 251); server, sn and the sdk modules repeat the two forks' replaces, and sdk's `license.yml` is regenerated in the same change; lock.yml, a pinned entry for sidecar and one for operator-core (source_graph_test.go:145-151) and `./cli/<svc>` (service_compile_test.go:13); build/.gitmodules, a `sidecar` and an `operator-core` submodule; run.sh, 4.9's release steps, operator-core's after connect's and sidecar's after it and before sdk's, and `warpctl build` per service (:3398-3477); deploy-rollout.zsh, a class per service (:23-40). server's competition graph and sn's release gates take sidecar too, as 4.8 states (owner decision 267).

### 4.8 Branches and cross-repo pinning

- **Branches.** Every repo the work touches gets a `sidecar` branch at M0 (§23.4; owner decision 196), on its normal remote, public where the repo is (owner decision 118); the extension and apps only if the owner opts in. `urnetwork/minio`, the new fork that holds D-OPS-20's build, is a sibling checkout with its own `sidecar` branch, and the owner creates its GitHub repo before any push (owner decision 195). operator-core, whose GitHub repo the owner created, is a sibling checkout too, its `sidecar` branch opened with the seam (owner decision 251). The `tests` repo has one as well, opened from `main` locally, so its fixtures can change with the build. `main` stays production-ready (build/README.md:5); in minio, whose upstream calls it `master`, that branch plays `main` (owner decision 270).
- **Pins.** server@sidecar's lock and build@sidecar's submodules pin the same `sidecar` commits of sidecar and operator-core, which server's source-graph tests confirm.
- **Merge, never rebase.** A rebase orphans pinned commits and skips the commit-msg hook (connect/.githooks/commit-msg:17-18). Merge `main` in weekly and before each gate, in the order connect, operator-core, sidecar, sdk, sn, server, warp/config/vault/xops/mmm/minio, build, tests, re-pinning each time. minio's weekly merge in is a no-op while its upstream stays archived; xops pins a commit of the fork in place of playbook-minio-clusters.yml's `minio_commit`, and that commit is on the public fork before a host runs it, as owner decision 195 keeps the AGPL source in one public place (owner decision 270).
- **To `main`** at each milestone's Gn-out (§23.8): every touched repo, server and sdk included, in that order, once the pinned set passes its checks, migrations are additive and release-compatible (connect/CODESTYLE.md:85-89), connect's default-off changes lead and the code is dark (D-OPS-10). Branch migrations stay pending until their own Gn-out registers them (D-OPS-6), so one track's merge never applies the other track's group, and M3's pilot runs on production (owner decision 118; §23.9).
- **What a Gn-out merges** (owner decision 268). Each gate's pinned commit set is recorded when its local checks are reported, and an approved Gn-out merges that set, never the tip, in the order above; a later milestone's merge brings the rest, and a group's migration registration (D-OPS-6) is the one commit on top of the set. Before any recorded commit reaches connect's `main`, the merge runs `check/`'s `TestX9ReadyForMain` for the gate, which refuses a landed change that no default-off test pins, a row due by the gate whose marker has not landed, and C19's marker while connect's own tests hold no FS-125 sweep (4.17). C19's window accounting is on connect's `sidecar` branch from before M1, off by default, so that sweep is built ahead of its milestone, before M1's Gn-out, and every Gn-out merge of connect, with the sdk, sidecar and server merges behind it in the order, waits for it; no gate merges default-off C19 code unswept, and no hand-picked commit set replaces the recorded one.
- **The closed source graphs** (owner decision 267). server's competition and sn's release gates each list the repositories they build from, and both take sidecar in one change landing with M0's Gn-out, before server and sn merge to `main`: sn's as a fourteenth release repository with a new `sidecar_go_source_hash`, the competition's as an eleventh repository, `sidecar`, last in every list and keyed `sidecar` in sim-latency.yml, with an additive migration. The evaluator takes it through new producer releases, as minimum-work and work-coverage were added: six programs beside the historical ones (evaluator-sidecar.sh, evaluator-minimum-work-sidecar.sh, evaluator-work-coverage-sidecar.sh and a prepare-round-baseline program for each), new dependency maps, and a selector `source_graph_policy` in the round's settings, the preparation config, the completion receipt and the future-epoch policy, whose value `sidecar/1` means the eleven repositories and whose omission the ten, an empty, null or unknown value refused. The historical producers and their pins stay byte for byte, but for one entry the owner named: the controller's pin of evaluator-work-coverage.sh is corrected to the tree's file, the ten-repository competition's qualified release, from which the sidecar producer is cut. sim-latency's source ledger stays strict: once the eleven-repository release is in use every epoch and generation pins sidecar and a ledger of the ten is refused, so the release opens only with a new ledger, at a season boundary or by an explicit re-baseline, never midway through a season. The owner qualifies the release on the evaluator hosts together with 4.7's go1.27.4 re-qualification; until then the evaluator stays at ten repositories and fails closed on a server commit that needs sidecar, so server's `main` is not a competition epoch's source in between.

### 4.9 Generation, targets, versions, license, style

- **Protobuf:** `protocol/Makefile` runs `protoc -I=. --go_out=. --go_opt=paths=source_relative protocol/*.proto protocol/bridge/*.proto` from the repo root, so files register as `protocol/<name>.proto` and `protocol/bridge/<name>.proto` in package `urnetwork.sidecar`; sdk and server link connect's and sidecar's packages, and a duplicate path or name panics at init (protobuf@v1.36.11/reflect/protoregistry/registry.go:42, 128, 152), so `config.proto`, `acl.proto` and `directory.proto` import the types 4.4 lists for `protocol/bridge`, never redeclare them. `tool` pins protoc-gen-go v1.36.11, and output is committed. The sections' `proto` fences are the wire: protocol's fence test holds every declaration to its fence in DESIGN.md and RECORD.md, and a field the code declares ahead of a fold sits in that test's additions lists (protocol/design_unfenced_test.go) until a design-records fold writes it into its fence and, in the same commit, drops its line there, touching only those entries; a fence never moves ahead of the code (owner decision 273, beside 252's rule for a new row or §4 id).
- **Mobile, wasm, C ABI:** gomobile binds only sdk (§18.3). `make size` gates from v0: the `ios_extension` leg (`device/`, `protocol/bridge` and the root's forwarding files; D-SDK-20) fails if sidecar adds over §18.10's budget, 7.5 MiB stripped (owner decisions 197, 215, 491), and the `sidecar_http` js leg is measured unstripped from M2 against §18.10's 41,943,040 B goal and miss rule (D-SDK-19). No C ABI: desktop apps use the `ur` daemon (§5) or sdk's generated ABI (sdk/cgo/gen/gen.go).
- **Versions.** Development paths stay unversioned, as connect's and sdk's do; the release runs their steps (build/all/run.sh), which §22.4's release fixture checks:

```text
branch     v<version> in each repo (:1302)
operator-core  its own repository's step, after connect's and before sidecar's, rewritten to
           .../operator-core/v2026 and tagged as connect is, coretest with it (owner decision 251)
root       go mod edit -module .../sidecar/v2026 (:1540-1543); quoted import paths in Go files and Makefiles
           rewritten (:1560-1566); the tree moved into v2026/, nested modules left in place (go_mod_fork,
           :1639-1683); tag v2026.M.D-<code> (:1781-1786)
kept       go_mod_fork's named arguments stay at the repository's top beside v2026/, as server's
           connect/sim-latency/baseline does: the documents (design/, research_notes/, DESIGN*.md, HANDOFF.md,
           FEEDBACK-SYSTEM.md) and third_party/, whose two forks are modules of their own (owner decision 278);
           LICENSE, NOTICE and README.md move with the module. The root's fork replaces are rebased to
           ../third_party/X, cli's and mlsinterop's ../third_party/X stand, so cli's go mod tidy finds them,
           smtpproof's becomes ../../third_party/X, and consumers' ../sidecar/third_party/X keep resolving;
           check/'s release pattern mirrors the names. The root's module zip leaves the forks out either way
smtpproof  the same as its own module: .../sidecar/smtpproof/v2026, tag smtpproof/v2026.M.D-<code>; in every
           repo its paths are rewritten before the root's subpackage pass, which skips lines already carrying
           /vN (:1564-1566)
cli        requires both tags, builds ur, never tagged as a module
version    the release sed fills Version with ${WARP_VERSION}, as for sdk (sdk/sdk.go:737; :1964), so
           ur --version prints the + form; artifact names and tags use ${EXTERNAL_WARP_VERSION}
generated  .pb.go files are committed, never regenerated on the release branch; descriptors keep
           protocol/<name>.proto and protocol/bridge/<name>.proto, so one module identity registers each
           descriptor once
fixture    the tags, operator-core's among them, served through GOPROXY=file:// with GOWORK=off, an empty
           module cache and no replaces, over a tree that holds third_party/:
           root, protocol and an engine package, the first <svc>service it finds, import at the tag, ur
           builds from cli/, go list -m all shows one sidecar path, each descriptor registers once, and
           sdk's go mod graph holds no smtpproof or prover dependency. Stripping every replace proves module
           paths and nothing about the forks: the root at its tag links upstream go-smtp, whose server
           mail_smtp_serve.go refuses, closed (4.7), while ur as run.sh builds it keeps go_mod_edit_gvisor's
           pin and the rebased sctp replace, which go version -m shows
```

- **License and style.** The full MPL-2.0 text, copyright 2026 BringYour, Inc., is the first `sidecar` commit and reaches `main` at M0's Gn-out; GitHub reads connect's abbreviated notice (connect/LICENSE:1-3) as "Other". operator-core carries the same license and copyright (owner decision 251). CODESTYLE.md adopts connect's plus the leaf, host and dependency rules; `.githooks/commit-msg` is copied byte for byte into sidecar, config, vault and minio before their first `sidecar` commit.

### 4.10 CLI distribution

| OS | Artifacts and signing | Path |
|---|---|---|
| macOS | one `.pkg` and one `.tar.gz` per architecture, no universal binary, of a Developer ID bundle, `ur.app`, id `network.ur.cli`, with a provisioning profile and hardened runtime (D-CORE-12), claiming both app groups, `6BGU69Q742.group.network.ur` and `6BGU69Q742.group.com.bringyour.urnetwork`, so a direct-download app reaches the daemon's app-group socket; notarized and stapled (run.sh's notarize step) | `/usr/local/lib/ur/ur.app`, with `/usr/local/bin/ur` and `/usr/local/bin/git-remote-ur` as links to its executable |
| Linux | `.deb`, `.rpm`, `.pkg.tar.zst` (nfpm) and `.tar.gz`, direct downloads through `install.sh`'s verified path, with no apt or yum repository, GPG key or repository host (owner decision 213; updates: proposed, Q-REPO-6) | `/usr/bin/ur`; the script uses `/usr/local/bin/ur` |
| Windows | `.zip` holding `ur.exe`, a copied `git-remote-ur.exe`, `LICENSE` and a README naming the folder and the PATH step, with no `wintun.dll` (owner decision 222); winget later; signtool SHA-256 with a timestamp (windows/app/SIGNING.md:17), the step failing when no signing thumbprint is set, unlike windows/app/build.ps1 | `%LOCALAPPDATA%\Programs\URnetwork\ur.exe` |

- **`git-remote-ur`** ships beside `ur` in every package as a link to the same binary, which dispatches on argv[0] (a copy in the Windows zip); git runs it for `ur://` URLs from PATH (gitremote-helpers(7); §11.11), so Windows users add the zip's directory to PATH. **`git-credential-ur`** ships the same way: a local credential helper that `ur mount add` and `ur mount share` configure (§11.11's binding).
- **Artifacts.** `ur-<version>-<os>-<arch>.tar.gz` and `.pkg`, `ur_<version>_<arch>.deb`, `ur-<version>.<rpmarch>.rpm`, `ur-<version>-<pkgarch>.pkg.tar.zst` and `ur-<version>-windows-<arch>.zip`, following build/all/linux/README.md's spellings: 14 files for the six targets.
- **Build.** `CGO_ENABLED=0 -trimpath` with `GOEXPERIMENT=greenteagc` and `-ldflags "-w -s"`, as run.sh's `sn_cli_release` builds release binaries, from `cli/`'s module, archive times from `SOURCE_DATE_EPOCH` (server/cli/api/Makefile:1, 4); macOS's keychain goes through purego (D-CORE-12).
- **Release integrity.** Signing is the gate (owner decision 77), and a release is promoted, not every build signed (owner decision 264). Every release runs a VirusTotal scan (run.sh's `virustotal`) and builds `ur`'s artifacts and an unsigned `SHA256SUMS` as ordinary assets of its GitHub release, run.sh waiting for no one. When both holders of the offline two-person Ed25519 key (§2.6) pick a release, they SSH-sign its sums offline, under namespace and identity `ur-release`, and a commit on mmm publishes `SHA256SUMS`, `SHA256SUMS.sig` and `latest.json` under `https://ur.io/recurd/ur/`; `latest.json` is listed in the signed sums, and `ur-promote.zsh` never moves it backward. No private key touches the build host, a repo or vault. The public key is published at `sidecar/RELEASE-KEY.pub` and `https://ur.io/recurd/release-key.pub`; before the key exists neither file does, and `install.sh` refuses. `install.sh` on ur.io (mmm's branch from M0, §23.4; owner decisions 15, 16, 196) pins the key, reads `latest.json`, verifies signature and checksum (`ssh-keygen -Y verify`, OpenSSH 8.1+), fetches the artifacts from the GitHub release and refuses on any failure. What holds: GitHub alone cannot ship a client, but ur.io serves both the script and its pin, so ur.io alone can, to a new script install (§2.8 EX7), and a fresh install cannot tell an older signed pair from the newest, so ur.io could roll a new install back to an older signed release. `install.sh` prints the key's fingerprint and the repository path that publishes it, so a careful user can compare, and nothing more is built; notarization and Authenticode remain second checks on the macOS and Windows artifacts. From M4 the sums also list the key origin's loader and `sidecar.wasm`, which `sidecar.ur.io` serves only from a promoted build (§18.8; owner decision 221).
- **Proving key sets (owner decision 266).** `smtpproof`'s proving keys and setup transcripts, about 0.9 GiB a key set, ship in no package: a prover host fetches its key set as §14.5 says, with no token and no account. §2.8's smtp-7 lists what that path's host sees, the fetching address above all, which marks a prover host (owner decision 253). The proof's 20 shapes are cut to what M7's census justifies before the first production setup.
- **Harness configs (§16)** use `ur`'s absolute path, since GUI-launched hosts lack the shell PATH ([MCP debugging](https://modelcontextprotocol.io/docs/2025-03-26/tools/debugging.md)). v0 has no self-updater.

### 4.11 The documents in the sidecar checkout

The checkout holds documents only, on `main` (§4.3): at the root, README.md (its images in `design/readme/` and `design/mocks/previews/`), DESIGN.md with its reviews (DESIGN-REVIEW1.md to DESIGN-REVIEW3b.md and DESIGN-REVIEW-RESPONSE.md), FEEDBACK-SYSTEM.md and `research_notes/`; under `design/`, the business and input documents: PLAN.md, product.md, the pitches (pitch1.html to pitch5.html, with PDFs of the last three), the market notes (market.md, market2.md, gap.md, improve.md, improvements4.md, sentiment2.md), two overview PDFs, a saved IETF draft (d.html), mocks/, reports/ (among them the Tailscale, agent-work-record and 2026-11-05 search-index reports), design-research/ (the sheets behind DESIGN.md's research links) and cold5/'s outreach drafts. All of it is public as it is, history included, the move into `design/` kept as renames (owner decisions 117, 118), so DESIGN.md's citations (`sidecar/design/pitch5.html`, `sidecar/design/market2.md`, `sidecar/design/reports/Encrypted repo search index formats.md`) resolve publicly, and its research links point into `design/design-research/`. Code starts on the `sidecar` branch (§4.8). The `ur` command sketch, cli/UI.md, sits outside every repository; a copy goes to `design/UI.md`, and its spellings then replace the build's own for the pass-change and lock commands, `--replace`, the recovery login and the daemon's `--port`, each a one-line rename; until the copy is there the build keeps the spellings §5 states (owner decision 265).

### 4.12 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Scrub, then publish a filtered clone (D-REPO-8 as drafted) | Business material stays private | A second repository, a rewrite and a path allowlist | Rejected (owner decision 117) |
| `/v2026` in development paths | One identity in every build | Breaks connect's and sdk's convention and consumers' v0.0.0 requires; the rewrite already publishes `/v2026` | Rejected (D-REPO-1) |
| `cli/` in the root module | One module | The root requires `smtpproof`, whose requirements then enter every consumer's graph, sdk's legs included | Rejected (D-REPO-2; owner decision 104) |
| Host interfaces declared in sidecar (`ServiceHost`), each engine's store implemented by server | No new repository | Sidecar's SQL and migrations live in server; each extension declares a host of its own | Rejected (D-REPO-3; owner decision 251) |
| The root keeps its own `Id` on every leg, operator-core's converting to it | The page Worker links no connect package | Two id types at every boundary between sidecar, operator-core and server | Not taken, but for the page Worker's leg, which meets no such boundary and keeps a twin (owner decisions 251, 276) |
| Package-level service functions, as server has (`server.Db`, `server.Tx`) | No factory to pass | One shared namespace per process, so no host can give an extension instances of its own | Rejected (owner decision 251) |
| Sign every release's `SHA256SUMS` | Every release installable through `install.sh` | An offline two-person signature cannot gate a pipeline that runs unattended and almost daily | Rejected: promotion (owner decision 264) |
| The operations commands in a module of this repository (`sidecar/sidecarctl`) | Beside the engines they operate | 4.7's license list and layering let no command here link server's model or an engine package, so `dns census`, `evs purge-turn-on` and `sidecar restore` could not be built | Rejected: server/sidecarctl (owner decision 274) |
| Narrow the `ios_extension` leg's seed rule, or untag a file, when the rule takes a file wrongly | No rename or move | A Forwarder file tagged out by mistake no longer fails closed | Rejected (owner decision 275) |
| The mlswg's vectors fetched at test time, none committed | No unlicensed bytes in the repository | A fetch in every test run, and a history rewrite for the files already landed | Rejected (owner decision 263) |

§23.10 rejects D-REPO-9's private mirrors (owner decision 118).

### 4.13 Decisions proposed

**D-REPO-1 (proposed).** Use §4.7's go.mod, its two patched mail libraries as modules under `third_party/` behind replaces, §4.9's proto naming, an unversioned development path, and the release rewrite to `/v2026` that connect and sdk use (§4.9), which keeps `third_party/` beside the rewritten tree (owner decision 278). *Why:* §4.3's replace and lock rules, protobuf's init-time panic, and the release convention; Go accepts a v2026 tag only on a `/v2026` path, which only the release tree has.

**D-REPO-2 (proposed).** Use §4.4's tree: MLS in root `mls_*` files (owner decision 43), server-only engines in `<svc>service` packages (owner decision 104), the forwarding role's packet side in the leaf `device/` over `protocol/bridge`, which alone declares the types it parses, linked in apps' VPN components with only the root's forwarding files (D-SDK-20; owner decision 197), connect-facing and engine-host root files under `!sidecar_http` (D-SDK-19), test peers only in `mlsinterop/`; `cli/` and `smtpproof/` are nested modules the root never requires; the core services' interfaces and the value types server and sidecar share in the operator-core repository's `operator` package, which imports connect, with their fakes and conformance suites in its test-only `coretest` module (owner decision 251). *Why:* CODESTYLE groups files by prefix (connect/CODESTYLE.md:49-62); owner rule 1; a message declared twice panics at init, and importing connect links gVisor; test peers must not raise consumers' versions, and a root requirement reaches every consumer's module graph; server imports sidecar, so what both need lives in a module below both.

**D-REPO-3 (proposed).** Engines live in sidecar and take operator-core's `Env`, the root factory of every service they hold, which server/core implements over server's services; server hosts each one, and sidecar owns its SQL over the db an `Env` grants, registering its migrations through operator-core's `Extension` (§4.5; Q-REPO-1; owner decision 251). *Why:* logic and its persistence stay in sidecar, URnetwork-only infrastructure stays behind interfaces (owner decision 48), and service instances from one factory, never a shared namespace, let any host supply an extension's services.

**D-REPO-4 (proposed).** Enforce §4.7 with `make check` and §4.9's v0 `make size` gate; ship no binding or C ABI. *Why:* no hosted CI exists, sidecar must be checked as the bindings build it, and a cgo file would enter gomobile's macOS slice.

**D-REPO-5 (proposed).** X9 changes are generic, additive, off by default and wire-compatible, tested in connect and merged to connect `main` first. *Why:* connect serves every client.

**D-REPO-6 (proposed).** Consumers wire sidecar and operator-core as §4.7 lists, the forks' replaces included, server's competition graph and sn's release gates take sidecar (owner decision 267), and branches follow §4.8, a Gn-out merging its gate's recorded commit set (owner decision 268). *Why:* the gates fail closed, pins must stay reachable (owner rule 4), and migration versions are positions.

**D-REPO-7 (proposed).** License, style, hook and distribution per §4.9 and §4.10, with sums the two holders sign offline when they promote a release (owner decision 264). *Why:* the open-source promise, the owner's commit rule, and GitHub alone must not be able to ship a client; ur.io, which serves both `install.sh` and its pin, alone can, to a new script install, which §4.10 and §2.8's EX7 state.

**D-REPO-8 (withdrawn).** Superseded by owner decision 117: no scrub, archive, filtered clone or path allowlist; the repo keeps its documents and history.

**D-REPO-9 (withdrawn).** Superseded by owner decision 118: no private mirrors; every `sidecar` branch uses its repo's normal remote and merges to `main` at each Gn-out.

### 4.14 Open questions

**Q-REPO-1.** How do PLAN.md:5-7's repos split a service? **Decided by owner 2026-11-03 (owner decision 19):** (a), a sidecar engine that server hosts and backs with its stores (D-REPO-3). **Amended by owner 2026-11-15 (owner decision 251):** the engine takes operator-core's `Env`, which server/core implements over server's services; sidecar owns its SQL over the db an `Env` grants and registers its migrations through operator-core for server/core to run, and server-owned data reaches it through operator-core's domain interfaces (4.5). *Residual:* none.

**Q-REPO-2.** [X9] Which connect changes may land on connect's `sidecar` branch? **Decided by owner 2026-11-03 (owner decision 22):** (b), §4.6's dispositions, as owner decisions 85, 86 and 176 amend them. *Residual:* C17, for the extension's streaming Worker only, after §18's spike.

**Q-REPO-3.** May `protocol/` be an exception to connect/CODESTYLE.md:26? **Decided by owner 2026-11-03 (owner decision 52):** (a), with a `make check` test that `protocol/` and `protocol/bridge` import nothing else from sidecar (§4.7). *Residual:* none.

**Q-REPO-4.** When does sidecar go public, and with which documents? **Decided by owner 2026-11-04 (owner decisions 117, 118):** now, as it is (§4.11), superseding the scrub and later publication of owner decisions 51 and 107; nothing waits for publication (§4.8). *Residual:* none.

**Q-REPO-5.** Should server-only engines live in the root (PLAN.md:13)? **Decided by owner 2026-11-03 (owner decision 104):** (b), child packages, and (d), a nested module for the X7 prover (§4.4); `cli/` is a nested module too, so the root never requires the prover (§4.7). *Residual:* none.

**Q-REPO-6.** How do Linux users update `ur`, now that v1 ships no apt or yum repository, so `apt upgrade` and `dnf upgrade` never reach it (owner decision 213)? *Options:* (a) they re-run `install.sh`, whose verified path checks the offline key's signature, or fetch the next `.deb` or `.rpm`, so no update reaches a Linux host by itself; (b) apt and yum repositories later, signed at promotion by a second offline two-person GPG key, their trees under ur.io/recurd through mmm; (c) a self-updater in `ur` that checks the same signed `SHA256SUMS`. *Recommendation:* (a) for v1, the owner deciding at v1's exit review whether Linux users need (b). *Blocks:* nothing before v1's channels (M6). *Decider:* owner.

### 4.15 Departures from PLAN.md

- **PLAN.md:13** ("all service code goes in the root"): engines live in `<svc>service` child packages and the X7 prover in a nested module, so no mobile or wasm build links them (owner decision 104; Q-REPO-5), and the forwarding role's packet side in the leaf `device/`, so the iOS extension links of the root only its forwarding files (Q-SDK-5, closed by peer review; D-SDK-20; owner decision 197).
- **PLAN.md:9-21** (the tree) stands; `cli/` carries its own go.mod so the prover's requirements stay out of consumers' module graphs (owner decision 104).

### 4.16 Interfaces

- **Provides:** the tree and modules, operator-core's `Env` with its db, domain interfaces, engine contract and `Extension` (`ServiceHost` and the aliases until the review phase's sweep), the X9 rows, the checks, §4.8's and §4.11's rules, §4.9's release rewrite, and §4.10's install paths (§11, §16).
- **Consumes:** server/core's `Env` over server's services and host packages (owner decision 251); §6 (X8; §6.4's requester feature bit, §6.11's marked pair and §6.10's windows, which C19 keys on), §10 (X12), §11 (X19; placement; §11.14's normalizer 1, which x/text follows), §13 (X1), §17 (X18; C5's dial fence and per-flow idle, `WindowDelegation`, C18's alias map), §18 (X14; `sidecar_http`, `device/`), §19's gates and pending migrations (D-OPS-6), §22.4's `sidecar_testhooks` and release fixture, §23's milestones.
- **Subprotocol messages, API routes, tables:** none (routes: C11).
- **Services and config:** §4.5's server column, server/sidecarctl included; operator-core's repository and `sidecar` branch; lock.yml; build/.gitmodules; run.sh; `ur-promote.zsh`; deploy-rollout.zsh; dependencies.yml; on ur.io, `install.sh`, `recurd/ur/`, `recurd/release-key.pub` and the key set path.
- **Assumptions about other sections:** §6 adds no protobuf `service` blocks; §6, §9-§15 and §19 follow §4.5's placement, their engines taking an `Env` and, from the review phase's move, keeping their SQL in sidecar, which §22.4's T3 tests over server/core's db (owner decision 251); §6.9, §7.9, §8.8 and §17 declare what `device/` parses only in `protocol/bridge`'s `signed.proto`, `auth.proto` (§8.8's `GrantRevoke`, `Suspend` and `Unsuspend` included) and `bridge.proto`, which `config.proto`, `acl.proto` and `directory.proto` import (4.4); §5.4 and §18.10 keep connect out of the `sidecar_http` leg, whose `Id` is the root's own twin (owner decision 276), and §18.10 excludes `host_*.go` (4.4); §15.5 reaches the forks only as 4.7 states, and §14.5 fetches its key sets as 4.10 states; §10, §11 and §19 keep each repo's metadata on the cluster its `place/` object names (owner decision 145); §5.8 and §11.11 define `git-remote-ur`'s daemon mode; §17, §2.10 and §22 cover C18, and §2.8's connect-5 and §20.6 state what C19 leaves visible and costs; §23.9 merges every touched repo at each Gn-out.

### 4.17 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Engine or root code bloats the iOS extension, which since owner decision 197 links the root's forwarding files | Medium | High | `<svc>service` packages; the leaf `device/` and the `ios_extension` leg's file and descriptor lists; `make size` at the budget owner decision 491 set |
| With the root's `Id` an alias of operator-core's, operator-core enters the iOS extension's leg; the page Worker's `sidecar.wasm`, which keeps a twin `Id` and links no connect, still measures about 57.8 MB unstripped against D-SDK-19's 41,943,040 B goal | High | Medium | The extension's leg re-measured, the owner revisiting owner decision 215's budget with it (owner decision 251), which owner decision 491 raised to 7.5 MiB; the goal's slip recorded under the miss rule's 74,965,628 B gate, and a test holding the twin to operator-core's `Id` (owner decision 276) |
| ur.io serves a new script install an altered `install.sh` with its own pin, or an older signed release | Low | High | `install.sh` prints the key's fingerprint and the repository path that publishes it; `latest.json` is in the signed sums and `ur-promote.zsh` never moves it backward; §2.8's EX7 names the case; notarization and Authenticode on macOS and Windows |
| Branches drift from mains that release almost daily | High | Medium | Weekly and per-milestone merges; pending migration groups (D-OPS-6) |
| A secret or AI-attributed message on a public branch stays served by hash (https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository, read 2026-11-03) | Low | Medium | The hook in every clone (connect/.githooks/commit-msg:23-27); `--scan` before each push and at each Gn-out (§23.8); secrets only in vault |
| A Go release breaks purego, leaving macOS pass-only | Low | High | Pinned version; a Keychain round trip in `make check`; cgo fallback |
| A tagged consumer resolves two sidecar module paths or registers a descriptor twice | Low | High | 4.9's rewrite; §22.4's release fixture |
| C19 misreports a remote-search window, or a window's background passes its allowance, so its pages show to a 128 KiB step | Low | Low | One floor value and §6.10's table; FS-125's sweep in connect's own tests before any Gn-out merge of connect to `main`, M1's included, which `TestX9ReadyForMain` refuses without it (D-REPO-5; owner decision 268); only traffic past the scheduled background at its maximum overflows |

### 4.18 Phasing

- **v0, before code (M0):** LICENSE, the hook, the root's and `cli/`'s go.mod, dependencies.yml and `make check` on sidecar's `sidecar` branch, merged at M0's Gn-out (DESIGN.md and the documents are on `main` already, 708bb45); M0's branches; the lock entry, the release step and its fixture.
- **The operator-core seam (owner decision 251), now:** operator-core with ServiceHost's interfaces moved over, the `Env`, the db interface and the shared value types, Go type aliases left in sidecar and server so existing code compiles unchanged, and server/core building the `Env` over the existing host packages; new code takes the `Env`. In the build's review phase, the pass of reviews and fixes after the draft of M0-M10: the call sites, sidecar's SQL and migrations moving from server into sidecar, and the fakes' move into `coretest`.
- **v0, first usable:** §4.6's M1, M4 and M5 rows; the first hosted engine; signed `ur` packages; the `make size` gate; `sidecar_http`'s import rule (M1) and size measure (M2); `device/` and its `ios_extension` rule, with the root's forwarding files (M4; owner decision 197).
- **v1:** C18 (M6); C20 (M7; owner decision 269); C19's window accounting (M10; owner decisions 176, 188), with 4.7's x/text rule on ahead of M10's index code, every module being on v0.43.0 already; Homebrew and winget; no apt or yum repository, `.deb` and `.rpm` staying direct downloads (owner decision 213; Q-REPO-6). **Later:** C4 with §18's worker, and C17 for that streaming Worker if its spike needs it.
- **Blocking:** M0's `make check` blocks the first consumer pin; C13 blocks C18; C19 blocks M10's Gn-out, since §2.8's connect-5 assumes it, and FS-125's sweep in connect's tests blocks every Gn-out merge of connect from M1's on (owner decision 268); C20 blocks M7's `strict_chain`.
