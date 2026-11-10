## 4. Repositories, code placement, branches, and build

### 4.1 Purpose and scope

This section decides where code lives and how it is built, branched, versioned, published and shipped, including X9's connect changes and the checkout's documents. Components are §5-§18, deployment §19, tests §22, milestones §23.

### 4.2 Requirements

| id | requirement | source |
|---|---|---|
| R-REPO-1 | CLI and components in sidecar; services, team management and access control in server; sdk exposes the components | PLAN.md:5 |
| R-REPO-2 | sidecar imports connect only; server and sdk import sidecar | PLAN.md:7 |
| R-REPO-3 | go.mod, sidecar.go, protocol/, mcp/, cli/main.go; service code in the root | PLAN.md:9-21 |
| R-REPO-4 | New pieces, MLS included, in sidecar; all work on `sidecar` branches | owner rules 1, 4 |
| R-REPO-5 | No parent package imports a child; commits carry no AI attribution | connect/CODESTYLE.md:24-47, 80-83 |
| R-REPO-6 | Go 1.27.3, pinned siblings, rollout classes, no cgo in sidecar packages | server/README.md:5-14; sdk/js/Makefile:69 |
| R-REPO-7 | Open source, signed releases, one calendar version; reproducible builds a goal, not a gate | sidecar/design/pitch5.html:930; build/README.md:3-7; owner decision 77 |
| R-REPO-8 | sidecar public from 2026-11-04 as it is; every touched repo merges `sidecar` into `main` at each exit review | owner decisions 117, 118 |

### 4.3 What exists today

- **Repos** (`gh repo view`, `git log`, 2026-11-05). sidecar holds two `main` commits and no code: `2b5b0ab` (2026-11-03, 119 documents) and `708bb45` (2026-11-05, the design checkpoint: the business documents moved under `design/` as renames, so their history follows, and DESIGN.md, its reviews, README.md with its images, the research sheets and the search-index report and notes added). INTERNAL and unlicensed before owner decision 118's flip, it is now PUBLIC, its README stating MPL-2.0, whose full text is the first `sidecar` commit (4.9); connect, sdk, server, sn (`urfoundation/sn`), build, warp and extension are PUBLIC too, config, vault and xops PRIVATE, mmm INTERNAL. None has a `sidecar` branch.
- **Replaces and pins.** Replaces are not inherited, so server, sn and four sdk modules repeat them (server/go.mod:213-236; sn/go.mod:205-223; sdk/go.mod:107-115). server's lock pins complete commits of nine clean siblings on one `go` line (server/local/source-graph/source_graph_test.go:90, 113-143, 200-235); build pins its submodules as gitlinks (build/.gitmodules).
- **Release, hooks, CI:** `yyyy.m.d-code` versions (build/all/run.sh:1186-1195). connect and sdk declare unversioned modules (connect/go.mod:1; sdk/go.mod:1), which consumers require at v0.0.0 beside sibling replaces (server/go.mod:48, 213), and the release rewrites each to `/v2026` on a version branch (4.9). An unclassified service exits 64 (build/all/deploy-rollout.zsh:37-39). All touched repos but sidecar, config and vault share one commit-msg hook. With no hosted CI, policy lives in Go tests, a leg per shipped build (sdk/dependency_boundary_test.go:81-92).

### 4.4 Repo tree and layering

```text
sidecar/            github.com/urnetwork/sidecar, package sidecar
  go.mod LICENSE NOTICE CODESTYLE.md README.md DESIGN.md DESIGN-REVIEW*.md FEEDBACK-SYSTEM.md RECORD.md
  Makefile dependencies.yml .githooks/
  design/                               the business and input documents (PLAN.md, product.md, pitches,
                                        market notes, mocks/, reports/, design-research/, cold5/) and the
                                        README's assets (readme/, mocks/previews/) (4.11)
  research_notes/                       the research behind design/reports/ and the pitches (4.11)
  sidecar.go settings.go                Sidecar, Version, SidecarSettings
  identity_ keys_ state_ daemon_ api_   core
  indexer_                              an indexer's services: schedule, fallbacks, status (§3.6)
  envelope_ rpc_ stream_ push_ codec_   subprotocol (type Subprotocol, §6)
  host_                                 engine host interfaces (ServiceHost)
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
  sidecartest/      fakes, store conformance suites
  testdata/         MLS vectors, transcripts, golden encodings
  mlsinterop/       nested test module of differential peers: tmc/mls and thomas-vilte/mls-go v1.6.0
                    (both MIT) and the mlswg interop client (§10.4); go-git, the git codec oracle (§22.6)
  smtpproof/        nested module: the X7 BDAT and DATA provers and the verifier (§14; owner decision 125),
                    which cli/ and server inject through root interfaces; the root never requires it
```

- Of this module's packages, the root imports only `protocol` and `protocol/bridge`, std-and-protobuf packages, as connect's root imports `connect/protocol` (Q-REPO-3). `protocol` imports `protocol/bridge`, never the reverse, so a type both use is declared only in `protocol/bridge` (4.9). The root never imports `device/`: `cli/` (`ur tun`, `ur bridge`) and sdk's `DeviceLocal` wire `device.Bridge` to the root's `BridgeState`, so Apple's network extensions, the `ios_extension` leg, link of the root only §18.10's forwarding files and of `protocol` only its config, acl, evs and gkm descriptors (D-SDK-20; owner decision 197).
- **Build tags.** Desktop-only code (the OS tun, §17.10; installers; the macOS keychain, §5.10) lives in `cli/` or carries `!ios && !android && !sdk_mobile_bind`. Package connect links gVisor into every importer through its untagged tun.go (connect/tun.go:38-47), so root files that use package connect (client generations and `SidecarEnv`, `Subprotocol` and streams, remote search, sockets dial and listen, the bridge, tls and smtp listeners) carry `!sidecar_http`, as do the engine host interfaces (`host_*.go`), since no hosted server engine runs in the page Worker, whose search engine needs none. The rest, §5.4's events, actions, binding and `Sign` included, uses the root's own `Id` ([16]byte), `Logger`, `MonitorValue` and `CallbackList`, and reaches api through the net/http `SidecarApi` (bearer plus DPoP signer), in both legs; connect-facing files convert at that boundary, and §4.7 fails the `sidecar_http` leg on any connect or gVisor package (§18.10).

### 4.5 Placement and the sidecar/server split

| Component | sidecar | server and other repos |
|---|---|---|
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

```go
// host_service.go: supplied by the hosting process; engines never import server, so go-redis,
// minio-go and prometheus stay out of sidecar.
type ServiceHost struct {
	Authenticator Authenticator       // jwt -> Principal (server/session)
	Quota         Quota               // reserve, commit, release (§20)
	Metrics       Metrics             // prometheus in server
	Tasks         Tasks               // once-keyed jobs (taskworker)
	Redis         Redis               // cas, incr, scripts, TTLs, hash-tagged keys; evs and gkm keep only soft state
	                                  // they rebuild there (owner decision 136); keyspace events only via the shared
	                                  // subscriber, never per client, the pattern that melted the cluster on
	                                  // 2026-07-15 (server/model/peer_model.go:32-37)
	Blobs         BlobStore           // the segment bucket and each metadata cluster's bucket, by cluster id, the
	                                  // first holding place/ (owner decision 145): If-Match and If-None-Match
	                                  // puts, streamed put, ranged get, prefix list, delete (X13)
	Push          Push                // server to client (X8)
	ServiceClient ServiceClientSource // jwt and urls for the engine's connect client
}

// Each engine that a server/cli/<svc> hosts; server wraps it with readiness, /status, stats and
// PROXY-unwrapped listeners. pushservice's types run inside existing services instead.
type Engine interface {
	Handler() http.Handler // or Serve(net.Listener) for stream engines
	Ready() bool
	Drain()
	Close()
}
```

evs and gkm keep durable state only in `Blobs` (owner decisions 2, 19, 21): a repo's metadata objects and its gkm group's live on the metadata cluster that the repo's create-only `place/<repo_id>` on the first cluster names, which the engines resolve and cache (owner decision 145; §11.8). Other engines take a store (`SmtpEdgeStore`, …) that server/model implements beside the migrations.

### 4.6 Connect changes (X9)

Dispositions follow owner decisions 22, 85 (C14 into M4), 86 (C18) and 176 (C19), under D-REPO-5 (Q-REPO-2).

| # | Change | Disposition |
|---|---|---|
| C1 | Export reserved-id registration (connect/subprotocol.go:545, 558) | Rejected: §6 uses public id 21842 |
| C2 | Provide-mode and size filters (SUBPROTOCOL.md §6) | Rejected: handlers see `peer.ProvideMode` and length |
| C3 | Drop ControlId-sourced subprotocol frames unless opted in (connect/subprotocol.go:590-651); P2P carriers accept only their peer as source (connect/transport_p2p.go:2345-2347) | M1 |
| C4 | Browser WebSocket H1 carrier (`GOOS=js`), in-band auth, Origin allowlist (§18.8) | Later, after §18's HTTPS-only worker (owner decision 26) |
| C5 | `connect.EgressHook` (`ResolveEgress`, §17.6) in `LocalUserNat`: pass, map or deny per flow, with C13's subject and `Sealed` on `EgressFlow`; `EgressDecision.IdleTimeout` replaces, for that flow, the NAT-wide idle (read at connect/ip.go:3252, :3873, :6984 and connect/ip_icmp.go:854; 0 keeps it), so bridge flows hold §17.5's idles without raising the host's other flows; flows register their rule tag and policy generation before the dial, so `CloseFlows` fences dials in progress (D-BRIDGE-21) | M4 |
| C6a | 100.64/10 non-public for §17 (connect/ip_security.go:892-908), with its own drop reason instead of an Incident, which calls `ReportAbuse` (connect/ip.go:10242-10244) | M4, after shadow counts |
| C6b | A `Tun` forwarder for a tun-less router | Rejected: not needed (§17.10) |
| C7 | Caller lane key for non-IP sends (connect/transfer_logical_lane.go:11-37) | Deferred: `TransferKey` lanes suffice |
| C8 | HTTP CONNECT and `HTTPS_PROXY` for platform transports and API dials; SOCKS5 only today (connect/net.go:333-363) | M4 (§5, §16, §18; owner decision 49) |
| C9 | `ProvideMode` Service = 6 (enum 0-5, connect/protocol/transfer.proto:354-361) for edge streams: subprotocol only, no IP, escrow or payout; minted only for §9's Find-recorded pairs (§6.10.1) | M5 |
| C10 | Push MessageType | Rejected: X8 (b) needs none (owner decision 17) |
| C11 | New routes in connect/api/bringyour.yml | M1 (§7, §8, §11) |
| C12 | connect/SUBPROTOCOL.md: stale 8 KiB (:89); item 6 (:372) as owner decision 17 amends it; id 21842; C3 | M1 |
| C13 | In every mode, seal into `StoredContract` (connect/protocol/transfer.proto:631-638) `source_subject_client_id`, which the server fills from the source client's stored `network_client.acl_subject_client_id` (D-ACL-3), never a client-supplied value, with `source_network_id`, the contract class and, for a window client, the subject's `WindowDelegation` (§17.9); companion contracts inherit the seals; expose them on `Peer` (connect/transfer.go:608-619) and `EgressFlow` | M4 (§8.10, §9, §17; D-PROTO-19) |
| C14 | `UpgradeMux.SetLocalZone`, consulted before the Blocker in `handleDns` (connect/ip_mux_upgrade.go:1661) and `resolveDnsTcpQuery` (:716) | M4 (owner decision 85); `ur tun` uses §17's resolver |
| C15 | `Peer` exposes the session's verified peer client key read-only, unexported today (connect/transfer_encrypt.go:1152-1157) | M1 (§6, D-PROTO-13) |
| C16 | Sticky Required: an Opportunistic client with a session to a peer never falls back to plaintext for that contract (connect/transfer_encrypt.go:477-483) | M4 (§17, §18); until then app devices are not bridge targets |
| C17 | A `js` connect build without gVisor or the IP stack: a connect-only js/wasm main imports 42 gvisor packages (2026-11-03; sizes in §18.10) | Decided after §18's spike, for the extension's streaming Worker only; the page Worker uses §18.10's `sidecar_http` leg |
| C18 | FriendsAndFamily flows to private destinations, which today admit only Network sources at the source's multi client (connect/ip_security.go:385-390; connect/ip_remote_multi_client.go:6691) and the provider (connect/ip.go:10307; connect/ip_security.go:567-576). The provider hands them to a C5 hook keyed on C13's `source_network_id`; the source admits only §17's alias-mapped destinations | M6 (owner decision 86); hooks only on sidecar-owned Required targets with a cross-network route grant; off in sdk providers |
| C19 | A per-peer accounting mode, off by default, for §6.10's remote-search windows. While a peer is in it, connect withholds every report, checkpoint or close, of a window's contracts with that peer, in both directions, until the window ends 55 minutes after its first contract's creation, 5 minutes before that contract's signed expiration. It then moves the sequences off them, as at expiry, and, while the mode holds, onto a new contract it takes at once with its successor requested then, which opens the next window whatever frame first rides it (§6.10), and sends one `CloseContract` a contract (connect/transfer_contract_manager.go:2344-2350): R(T) on the window's first and 0 on the others, T being the client's counted bytes over the window's contracts in that direction, and R(T) the floor F = 256 KiB while T ≤ F, else F plus 128 KiB steps. The sidecars of a pair that a Hello or HelloResult carrying the requester feature bit marks (§6.11) set the mode for each other through connect's per-peer setter, since a `Peer` exposes no contract id (connect/transfer.go:608-619), each first retiring the contracts it already sends on to the other. A window with up to five search pages then reports as one with none, whatever the pair's scheduled background (§6.10, §11.14; §2.8 connect-5) | M10 (owner decisions 176, 188) |

### 4.7 Module, dependencies, enforcement, consumption

```text
module github.com/urnetwork/sidecar
go 1.27.3
tool google.golang.org/protobuf/cmd/protoc-gen-go
replace github.com/urnetwork/connect => ../connect
replace github.com/pion/sctp => ../connect/sctp
replace github.com/urnetwork/glog => ../glog
replace gvisor.dev/gvisor => ../gvisor
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
  replaces   a nested module repeats the root's sibling replaces one level up, plus this repository's own
  consumers  require v0.0.0 with ../sidecar (server also ../sidecar/smtpproof), as for connect
```

- **Imports:** besides this repository's modules, connect and its replaced forks are the only first-party modules a sidecar module requires, never proxy or the userwireguard it requires (proxy/go.mod:9-10), so `ur proxy add` (cli/UI.md:39-41) runs in `cli/` on §17's userspace `connect.Tun`.
- **Third-party:** `dependencies.yml` lists each module with SPDX id, reason and leg (client, engine, cli, test). Allowed: MIT, BSD-2/3-Clause, Apache-2.0, ISC, MPL-2.0; refused: GPL family, SSPL, BUSL, custom, unlicensed. Initial: protobuf v1.36.11, x/crypto, docopt-go, pires/go-proxyproto, go-sdk v1.7.0 for mcp/ and go-winio v0.6.2 for §5.8's pipe (server/go.mod:30, 67), purego v0.11.2 for the macOS Keychain (Apache-2.0), wireguard's tun (MIT) for `cli/`'s OS tun (§17.10); in the test leg, `mlsinterop/`'s peers [R:ext-storage-crypto].
- **Versions:** shared modules match connect, sdk and server, because an uncoordinated bump fails server's `-mod=readonly` build (server/README.md:12); protobuf follows §18.10; golang.org/x/text follows §11.14's normalizer 1: one module version on every leg, at least server's and sn's v0.43.0 (server/go.mod:59; sn/go.mod:191), so connect and sdk bump together from v0.40.0 (connect/go.mod:33, sdk/go.mod:97) and gomobile's v0.41.0 (sdk/build/go.mod:96), whose NFC wrongly composes 19,960 two-rune strings (every two-rune string checked under go1.27.3, 2026-11-05), U+05D2 U+0307 into U+105C9 and U+10044 U+0307 into U+1E0A among them, which v0.43.0 normalizes correctly under the same reported Unicode version, 17.0.0 (v0.40.0 and v0.41.0 key recomposition on runes clipped to 16 bits, .gomodcache/golang.org/x/text@v0.40.0/unicode/norm/forminfo.go:217).
- **`make check`** (Go tests, also at release):

```text
fails on
  deps      server, sdk, sn or an unlisted module in a leg's go list -deps; the root module requiring any module
            of this repository; from M10, a leg selecting a golang.org/x/text other than normalizer 1's
            (Versions, above)
  layering  the root importing a package of this module other than protocol and protocol/bridge; protocol
            importing beyond std, protobuf and protocol/bridge, or protocol/bridge beyond std and protobuf; a
            client package importing a <svc>service
  legs      the ios_extension leg's root files leaving §18.10's forwarding list, or its protocol descriptors
            beyond that list's (owner decision 197); the sidecar_http js leg's deps including any connect or
            gVisor package (from M1); net/rpc or template packages on ios, android or js
  cgo       CgoFiles, except keychain_darwin.go in §5.10's darwin fallback leg
  hygiene   replaces other than 4.7's; registry conflicts; stale generated code; a release leg built with
            sidecar_testhooks (§22.4); govulncheck findings
legs        sdk's (sdk/dependency_boundary_test.go:81-92), gomobile's CGO_ENABLED=1, sdk_mobile_bind and
            ios_extension included; the sidecar_http js leg (GOOS=js GOARCH=wasm -tags sidecar_http over the
            root and protocol, which §18.10's main imports); the CLI's six release targets, from cli/
```

- **Consumers:** server, sn (sn/go.mod:207) and four sdk modules add the require and replace above, server also for `smtpproof`; lock.yml, a pinned entry (source_graph_test.go:145-151) and `./cli/<svc>` (service_compile_test.go:13); build/.gitmodules, a `sidecar` submodule; run.sh, 4.9's release step after connect's and before sdk's, and `warpctl build` per service (:3398-3477); deploy-rollout.zsh, a class per service (:23-40).

### 4.8 Branches and cross-repo pinning

- **Branches.** Every repo the work touches gets a `sidecar` branch at M0 (§23.4; owner decision 196), on its normal remote, public where the repo is (owner decision 118); the extension and apps only if the owner opts in. `urnetwork/minio`, the new fork that holds D-OPS-20's build, is a sibling checkout with its own `sidecar` branch, and the owner creates its GitHub repo before any push (owner decision 195). `main` stays production-ready (build/README.md:5).
- **Pins.** server@sidecar's lock and build@sidecar's submodules pin the same `sidecar` commits, which server's source-graph tests confirm.
- **Merge, never rebase.** A rebase orphans pinned commits and skips the commit-msg hook (connect/.githooks/commit-msg:17-18). Merge `main` in weekly and before each gate, in the order connect, sidecar, sdk, sn, server, warp/config/vault/xops/mmm, build, re-pinning each time.
- **To `main`** at each milestone's Gn-out (§23.8): every touched repo, server and sdk included, in that order, once the pinned set passes its checks, migrations are additive and release-compatible (connect/CODESTYLE.md:85-89), connect's default-off changes lead and the code is dark (D-OPS-10). Branch migrations stay pending until their own Gn-out registers them (D-OPS-6), so one track's merge never applies the other track's group, and M3's pilot runs on production (owner decision 118; §23.9).

### 4.9 Generation, targets, versions, license, style

- **Protobuf:** `protocol/Makefile` runs `protoc -I=. --go_out=. --go_opt=paths=source_relative protocol/*.proto protocol/bridge/*.proto` from the repo root, so files register as `protocol/<name>.proto` and `protocol/bridge/<name>.proto` in package `urnetwork.sidecar`; sdk and server link connect's and sidecar's packages, and a duplicate path or name panics at init (protobuf@v1.36.11/reflect/protoregistry/registry.go:42, 128, 152), so `config.proto`, `acl.proto` and `directory.proto` import the types 4.4 lists for `protocol/bridge`, never redeclare them. `tool` pins protoc-gen-go v1.36.11, and output is committed.
- **Mobile, wasm, C ABI:** gomobile binds only sdk (§18.3). `make size` gates from v0: the `ios_extension` leg (`device/`, `protocol/bridge` and the root's forwarding files; D-SDK-20) fails if sidecar adds over §18.10's budget, 4 MiB (proposed; Q-SDK-7; owner decision 197), and the `sidecar_http` js leg is measured unstripped from M2 against §18.10's 41,943,040 B goal and miss rule (D-SDK-19). No C ABI: desktop apps use the `ur` daemon (§5) or sdk's generated ABI (sdk/cgo/gen/gen.go).
- **Versions.** Development paths stay unversioned, as connect's and sdk's do; the release runs their steps (build/all/run.sh), which §22.4's release fixture checks:

```text
branch     v<version> in each repo (:1302)
root       go mod edit -module .../sidecar/v2026 (:1540-1543); quoted import paths in Go files and Makefiles
           rewritten (:1560-1566); the tree moved into v2026/, nested modules left in place (go_mod_fork,
           :1639-1683); tag v2026.M.D-<code> (:1781-1786)
smtpproof  the same as its own module: .../sidecar/smtpproof/v2026, tag smtpproof/v2026.M.D-<code>; in every
           repo its paths are rewritten before the root's subpackage pass, which skips lines already carrying
           /vN (:1564-1566)
cli        requires both tags, builds ur, never tagged as a module
version    the release sed fills Version, as for sdk (sdk/sdk.go:737; :1964)
generated  .pb.go files are committed, never regenerated on the release branch; descriptors keep
           protocol/<name>.proto and protocol/bridge/<name>.proto, so one module identity registers each
           descriptor once
fixture    the tags served through GOPROXY=file:// with GOWORK=off, an empty module cache and no replaces:
           root, protocol and an engine package import at the tag, ur builds from cli/, go list -m all shows
           one sidecar path, each descriptor registers once, and sdk's go mod graph holds no smtpproof or
           prover dependency
```

- **License and style.** The full MPL-2.0 text, copyright 2026 BringYour, Inc., is the first `sidecar` commit and reaches `main` at M0's Gn-out; GitHub reads connect's abbreviated notice (connect/LICENSE:1-3) as "Other". CODESTYLE.md adopts connect's plus the leaf, host and dependency rules; `.githooks/commit-msg` is copied byte for byte into sidecar, config, vault and minio before their first `sidecar` commit.

### 4.10 CLI distribution

| OS | Artifacts and signing | Path |
|---|---|---|
| macOS | `.pkg` and `.tar.gz` of a Developer ID `ur` bundle with a provisioning profile and hardened runtime (D-CORE-12), notarized and stapled (run.sh:2644-2673) | `/usr/local/bin/ur`, linked into the bundle |
| Linux | `.deb`, `.rpm`, `.pkg.tar.zst` (nfpm) and `.tar.gz`, direct downloads through `install.sh`'s verified path, with no apt or yum repository, GPG key or repository host (owner decision 213) | `/usr/bin/ur`; the script uses `/usr/local/bin/ur` |
| Windows | `.zip`, winget later; signtool SHA-256 with a timestamp (windows/app/SIGNING.md:17) | `%LOCALAPPDATA%\Programs\URnetwork\ur.exe` |

- **`git-remote-ur`** ships beside `ur` in every package as a link to the same binary, which dispatches on argv[0] (a copy in the Windows zip); git runs it for `ur://` URLs from PATH (gitremote-helpers(7); §11.11), so Windows users add the zip's directory to PATH.
- **Build.** `CGO_ENABLED=0 -trimpath` from `cli/`'s module, archive times from `SOURCE_DATE_EPOCH` (server/cli/api/Makefile:1, 4); macOS's keychain goes through purego (D-CORE-12).
- **Release integrity.** Signing is the gate (owner decision 77): a VirusTotal scan (run.sh:2257-2298), then a `SHA256SUMS` SSH-signed by an offline two-person Ed25519 key (§2.6), whose public key the repo and ur.io publish. `install.sh` on ur.io (mmm's branch from M0, §23.4; owner decisions 15, 16, 196) pins the key, verifies signature and checksum (`ssh-keygen -Y verify`, OpenSSH 8.1+) and refuses on any failure.
- **Harness configs (§16)** use `ur`'s absolute path, since GUI-launched hosts lack the shell PATH ([MCP debugging](https://modelcontextprotocol.io/docs/2025-03-26/tools/debugging.md)). v0 has no self-updater.

### 4.11 The documents in the sidecar checkout

The checkout holds documents only, on `main` (§4.3): at the root, README.md (its images in `design/readme/` and `design/mocks/previews/`), DESIGN.md with its reviews (DESIGN-REVIEW1.md to DESIGN-REVIEW3b.md and DESIGN-REVIEW-RESPONSE.md), FEEDBACK-SYSTEM.md and `research_notes/`; under `design/`, the business and input documents: PLAN.md, product.md, the pitches (pitch1.html to pitch5.html, with PDFs of the last three), the market notes (market.md, market2.md, gap.md, improve.md, improvements4.md, sentiment2.md), two overview PDFs, a saved IETF draft (d.html), mocks/, reports/ (among them the Tailscale, agent-work-record and 2026-11-05 search-index reports), design-research/ (the sheets behind DESIGN.md's research links) and cold5/'s outreach drafts. All of it is public as it is, history included, the move into `design/` kept as renames (owner decisions 117, 118), so DESIGN.md's citations (`sidecar/design/pitch5.html`, `sidecar/design/market2.md`, `sidecar/design/reports/Encrypted repo search index formats.md`) resolve publicly, and its research links point into `design/design-research/`. Code starts on the `sidecar` branch (§4.8).

### 4.12 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Scrub, then publish a filtered clone (D-REPO-8 as drafted) | Business material stays private | A second repository, a rewrite and a path allowlist | Rejected (owner decision 117) |
| `/v2026` in development paths | One identity in every build | Breaks connect's and sdk's convention and consumers' v0.0.0 requires; the rewrite already publishes `/v2026` | Rejected (D-REPO-1) |
| `cli/` in the root module | One module | The root requires `smtpproof`, whose requirements then enter every consumer's graph, sdk's legs included | Rejected (D-REPO-2; owner decision 104) |

§23.10 rejects D-REPO-9's private mirrors (owner decision 118).

### 4.13 Decisions proposed

**D-REPO-1 (proposed).** Use §4.7's go.mod, §4.9's proto naming, an unversioned development path, and the release rewrite to `/v2026` that connect and sdk use (§4.9). *Why:* §4.3's replace and lock rules, protobuf's init-time panic, and the release convention; Go accepts a v2026 tag only on a `/v2026` path, which only the release tree has.

**D-REPO-2 (proposed).** Use §4.4's tree: MLS in root `mls_*` files (owner decision 43), server-only engines in `<svc>service` packages (owner decision 104), the forwarding role's packet side in the leaf `device/` over `protocol/bridge`, which alone declares the types it parses, linked in apps' VPN components with only the root's forwarding files (D-SDK-20; owner decision 197), connect-facing and engine-host root files under `!sidecar_http` (D-SDK-19), test peers only in `mlsinterop/`; `cli/` and `smtpproof/` are nested modules the root never requires. *Why:* CODESTYLE groups files by prefix (connect/CODESTYLE.md:49-62); owner rule 1; a message declared twice panics at init, and importing connect links gVisor; test peers must not raise consumers' versions, and a root requirement reaches every consumer's module graph.

**D-REPO-3 (proposed).** Engines live in sidecar behind §4.5's `ServiceHost` and stores, and server hosts each one (Q-REPO-1). *Why:* logic stays in sidecar, persistence beside the migrations, and URnetwork-only infrastructure behind interfaces (owner decision 48).

**D-REPO-4 (proposed).** Enforce §4.7 with `make check` and §4.9's v0 `make size` gate; ship no binding or C ABI. *Why:* no hosted CI exists, sidecar must be checked as the bindings build it, and a cgo file would enter gomobile's macOS slice.

**D-REPO-5 (proposed).** X9 changes are generic, additive, off by default and wire-compatible, tested in connect and merged to connect `main` first. *Why:* connect serves every client.

**D-REPO-6 (proposed).** Consumers wire sidecar as §4.7 lists, and branches follow §4.8. *Why:* the gates fail closed, pins must stay reachable (owner rule 4), and migration versions are positions.

**D-REPO-7 (proposed).** License, style, hook and distribution per §4.9 and §4.10, with offline-signed sums. *Why:* the open-source promise, the owner's commit rule, and no single origin may ship a client.

**D-REPO-8 (withdrawn).** Superseded by owner decision 117: no scrub, archive, filtered clone or path allowlist; the repo keeps its documents and history.

**D-REPO-9 (withdrawn).** Superseded by owner decision 118: no private mirrors; every `sidecar` branch uses its repo's normal remote and merges to `main` at each Gn-out.

### 4.14 Open questions

**Q-REPO-1.** How do PLAN.md:5-7's repos split a service? **Decided by owner 2026-11-03 (owner decision 19):** (a), a sidecar engine that server hosts and backs with its stores (D-REPO-3). *Residual:* none.

**Q-REPO-2.** [X9] Which connect changes may land on connect's `sidecar` branch? **Decided by owner 2026-11-03 (owner decision 22):** (b), §4.6's dispositions, as owner decisions 85, 86 and 176 amend them. *Residual:* C17, for the extension's streaming Worker only, after §18's spike.

**Q-REPO-3.** May `protocol/` be an exception to connect/CODESTYLE.md:26? **Decided by owner 2026-11-03 (owner decision 52):** (a), with a `make check` test that `protocol/` and `protocol/bridge` import nothing else from sidecar (§4.7). *Residual:* none.

**Q-REPO-4.** When does sidecar go public, and with which documents? **Decided by owner 2026-11-04 (owner decisions 117, 118):** now, as it is (§4.11), superseding the scrub and later publication of owner decisions 51 and 107; nothing waits for publication (§4.8). *Residual:* none.

**Q-REPO-5.** Should server-only engines live in the root (PLAN.md:13)? **Decided by owner 2026-11-03 (owner decision 104):** (b), child packages, and (d), a nested module for the X7 prover (§4.4); `cli/` is a nested module too, so the root never requires the prover (§4.7). *Residual:* none.

### 4.15 Departures from PLAN.md

- **PLAN.md:13** ("all service code goes in the root"): engines live in `<svc>service` child packages and the X7 prover in a nested module, so no mobile or wasm build links them (owner decision 104; Q-REPO-5), and the forwarding role's packet side in the leaf `device/`, so the iOS extension links of the root only its forwarding files (Q-SDK-5, closed by peer review; D-SDK-20; owner decision 197).
- **PLAN.md:9-21** (the tree) stands; `cli/` carries its own go.mod so the prover's requirements stay out of consumers' module graphs (owner decision 104).

### 4.16 Interfaces

- **Provides:** the tree and modules, `ServiceHost`, the X9 rows, the checks, §4.8's and §4.11's rules, §4.9's release rewrite, and §4.10's install paths (§11, §16).
- **Consumes:** §6 (X8; §6.4's requester feature bit, §6.11's marked pair and §6.10's windows, which C19 keys on), §10 (X12), §11 (X19; placement; §11.14's normalizer 1, which x/text follows), §13 (X1), §17 (X18; C5's dial fence and per-flow idle, `WindowDelegation`, C18's alias map), §18 (X14; `sidecar_http`, `device/`), §19's gates and pending migrations (D-OPS-6), §22.4's `sidecar_testhooks` and release fixture, §23's milestones.
- **Subprotocol messages, API routes, tables:** none (routes: C11).
- **Services and config:** §4.5's server column; lock.yml; build/.gitmodules; run.sh; deploy-rollout.zsh; dependencies.yml.
- **Assumptions about other sections:** §6 adds no protobuf `service` blocks; §6, §9-§15 and §19 follow §4.5's placement; §6.9, §7.9, §8.8 and §17 declare what `device/` parses only in `protocol/bridge`'s `signed.proto`, `auth.proto` (§8.8's `GrantRevoke`, `Suspend` and `Unsuspend` included) and `bridge.proto`, which `config.proto`, `acl.proto` and `directory.proto` import (4.4); §5.4 and §18.10 keep connect types out of the `sidecar_http` leg's files, and §18.10 excludes `host_*.go` (4.4); §10, §11 and §19 keep each repo's metadata on the cluster its `place/` object names (owner decision 145); §5.8 and §11.11 define `git-remote-ur`'s daemon mode; §17, §2.10 and §22 cover C18, and §2.8's connect-5 and §20.6 state what C19 leaves visible and costs; §23.9 merges every touched repo at each Gn-out.

### 4.17 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Engine or root code bloats the iOS extension, which since owner decision 197 links the root's forwarding files | Medium | High | `<svc>service` packages; the leaf `device/` and the `ios_extension` leg's file and descriptor lists; `make size` at Q-SDK-7's budget |
| Branches drift from mains that release almost daily | High | Medium | Weekly and per-milestone merges; pending migration groups (D-OPS-6) |
| A secret or AI-attributed message on a public branch stays served by hash (https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository, read 2026-11-03) | Low | Medium | The hook in every clone (connect/.githooks/commit-msg:23-27); `--scan` before each push and at each Gn-out (§23.8); secrets only in vault |
| A Go release breaks purego, leaving macOS pass-only | Low | High | Pinned version; a Keychain round trip in `make check`; cgo fallback |
| A tagged consumer resolves two sidecar module paths or registers a descriptor twice | Low | High | 4.9's rewrite; §22.4's release fixture |
| C19 misreports a remote-search window, or a window's background passes its allowance, so its pages show to a 128 KiB step | Low | Low | One floor constant and §6.10's table; FS-125's sweep in connect's own tests before the merge to `main` (D-REPO-5); only traffic past the scheduled background at its maximum overflows |

### 4.18 Phasing

- **v0, before code (M0):** LICENSE, the hook, the root's and `cli/`'s go.mod, dependencies.yml and `make check` on sidecar's `sidecar` branch, merged at M0's Gn-out (DESIGN.md and the documents are on `main` already, 708bb45); M0's branches; the lock entry, the release step and its fixture.
- **v0, first usable:** §4.6's M1, M4 and M5 rows; the first hosted engine; signed `ur` packages; the `make size` gate; `sidecar_http`'s import rule (M1) and size measure (M2); `device/` and its `ios_extension` rule, with the root's forwarding files (M4; owner decision 197).
- **v1:** C18 (M6); C19's window accounting (M10; owner decisions 176, 188) and 4.7's x/text bump, ahead of M10's index code; Homebrew and winget; no apt or yum repository, `.deb` and `.rpm` staying direct downloads (owner decision 213). **Later:** C4 with §18's worker, and C17 for that streaming Worker if its spike needs it.
- **Blocking:** M0's `make check` blocks the first consumer pin; C13 blocks C18; C19 blocks M10's Gn-out, since §2.8's connect-5 assumes it.
