## 9. Abstract socket listeners and the scheduler

### 9.1 Purpose and scope

This section owns PLAN.md's abstract socket listener (PLAN.md:67-69): the `<net>:<name>` grammar and name blinding, registration, find-listener and accept (PLAN.md:82), the scheduler, the `sockets` service, the Go API, `ur share`, and gate, quota, overload and metrics hooks. §6 owns streams and contract modes, §7 and §8 the config repo, policy and projection (X3), §13 the TLS front, §14 and §15 mail, §17 forwards and invites. Each connection reaches one listener; group fan-out is §15's.

### 9.2 Requirements

| Id | Requirement | Source |
|---|---|---|
| R-SOCK-1 | Publish that a client listens on `network:name` | PLAN.md:69 |
| R-SOCK-2 | Reach one of many listeners via a fair scheduler "similar to socket reuse on linux" | PLAN.md:69 |
| R-SOCK-3 | The TLS edge does find-listener and accept | PLAN.md:82 |
| R-SOCK-4 | Reach controlled by client, group, network | PLAN.md:74 |
| R-SOCK-5 | Renames and reclaims never move or capture registrations | `server/controller/account_controller.go:13` |
| R-SOCK-6 | Service off the data path; load-aware for uneven listeners | derived |
| R-SOCK-7 | TLS edge 1/20/200 by tier; forwards unlimited | PLAN.md:358-359 |
| R-SOCK-8 | One naming rule for §13-§15; Go adapters; CLI and MCP hooks | PLAN.md:17-20; derived |
| R-SOCK-9 | Internal names hidden from servers; gates read only the signed projection | owner decisions 3, 67, 72 |
| R-SOCK-10 | `ur share add` makes a link that `ur share get` redeems at most `--count` times; file transfer counts toward the transfer balance | cli/UI.md:35-38, :97; R-CTX-31 |

### 9.3 What exists today

- No repo has a listener registry, accept handshake, scheduler or client-to-client stream ([R:connect-transport] §2.10); sdk listeners are "future work" (`sdk/SOCKET.md:7`).
- Substrate: ids ≥1024 and inline non-blocking handlers (`connect/subprotocol.go:46-50`, `:78`); 16 KiB frames and a 60 s ack timeout (`connect/transfer.go:1722-1724`, `:904`); receivers get the source id and `Peer{ProvideMode, Roles, Principal}` (`:608-619`); residents drop forwards not from their client (`server/connect/resident.go:4950`).
- Precedents: HMACed contracts (`connect/transfer_contract_manager.go:291-317`); Redis 8.10.2 hash-field TTLs (`xops/main/ansible/playbook-redis-clusters.yml:634`); Lua helpers (`server/redis.go:955-966`).
- Removal revokes, deletes provide keys and sets `{X}c_removed` for the client and its active descendants (`server/model/network_client_model.go:1485-1612`, `server/model/client_close_model.go:54-66`); connect consumes the flag (`server/connect/key_event_subscriber.go:129`). The 30-day idle marker skips it (`server/model/network_client_model.go:4315-4340`); idle clients hold no lease. Child tokens fail once an ancestor is inactive (`server/session/by_jwt.go:678-699`).
- warp lbs proxy to same-host blocks with `least_conn` (`warp/warpctl/config.go:1644-1665`) on every lb host (`warp/services/services.go:521-551`).

### 9.4 Addresses and namespaces

```text
address = [ net ":" ] name     ; no net: the caller's network; ur/ names: urnetwork-edge
net     = dns-label            ; a §12 label or alias (X5)
name    = seg *7( "/" seg )    ; 1-8 segments, <= 112 bytes: <net>:<name> fits §6's 128 B target (10-char label)
seg     = 1*63( %x61-7A / DIGIT / "-" / "_" / "." ) / "@"   ; not "." or ".."
                               ; uppercase ASCII folds to lowercase; other bytes are refused
; reserved first segments: tls, smtp, c (retired: invites use §17's IP path, owner decision 86), ur, sys,
; share (9.9's `ur share` only, blinded), single characters and "_"-prefixed segments; new namespaces
; need a §9 amendment
```

- **Canonical key `(network_id, name)`.** §12 resolves `<net>` per call (legacy names only interactively, D-DNS-2), and stored state holds the id, so renames move nothing.
- **Blinding (Q-SOCK-4, D-SOCK-13).** Edge names (`tls/`, `smtp/`, `ur/`), public anyway (SNI, DNS, MX), reach the service in plaintext; others only as the token paths below, like evs paths (owner decision 2), sealed for listings; the service refuses other plaintext names. The keys derive from `K_sock`, the config repo's 32-byte socket-name key, which every admitted sidecar reads (§7.9; agents and overflow member devices by wrap, owner decisions 114, 144).
- **Rotation.** `K_sock` follows §11.6's path-epoch triggers: a member's or member device's removal and compromise retirements at once; other key-holder shrinks and authorization expiries (§7.9's expiry identities) at most daily (a reap of an agent its live Delegation covers is none). Only config writers change it (§8.8), so it rotates in the next writer head, republishing the projection; without a writer online it waits, and member devices alarm 24 h after the trigger. Listeners register both paths for 10 min.

```text
keys   K_tok = HKDF-SHA256(K_sock, salt network_id, info "urnetwork-sidecar-v1/socket-token"), 32 B; K_seal the
       same with info "urnetwork-sidecar-v1/socket-seal"
token  t_0 = network_id (16 B); t_i = HMAC-SHA256(K_tok, t_{i-1} || seg_i)[:16], seg_i lowercased;
       name_token = t_1 || ... || t_n, as in §8's AclRows
seal   sealed_name = nonce[24] || XChaCha20-Poly1305(K_seal, nonce, pt = name || 0x00 to 112 B,
       ad = network_id || name_token): 152 B, a random nonce per seal; names hold no 0x00
open   a lister tries the newest K_sock, then within a rotation's 10 min overlap the previous one, strips the
       0x00 padding and keeps a name only if it re-derives name_token
```

| Namespace (owner) | Form, example (`acme` is an alias) | Listen; dialer | Stream protocol |
|---|---|---|---|
| TLS endpoint (§13) | `tls/<port>/<host>`, `acme:tls/443/blog` | approved `listen`, and `publish` on `dns:<host>` (§13.9); tlsedge | `tls`, passed through (X1, D-TLS-1) |
| Inbound mail (§15) | `smtp/<port>/<host>`, `acme:smtp/25/mx` | approved `listen`; mxedge | `smtp-starttls`, ending in the receiver (X6) |
| Platform (§13-§15) | `ur/<service>`, `ur/smtpedge` | `urnetwork-edge` clients; any enrolled client, authorized by the service (§14.5), not §8 | per service |
| Application | any other, `acme:db/primary` (blinded) | `listen`; `dial` within the network (other networks use IP, §6.4) | the listener's |
| Share (9.9) | `share/<token>` (blinded) | `listen` by `ur share add`, `exclusive`; `dial` by `ur share get`, within the network | 9.9's share header |

`ur/` Finds cross networks, as the names resolve to `urnetwork-edge`. `<host>` is `@` or one LDH label (`blog`, `api-dev`), as a wildcard certificate covers one label; a v1 Team scope (Q-TLS-3; owner decisions 40, 58) adds `<label>.<scope>` hosts within one 63-byte segment (`smtp/`: `mx.<scope>`), and deeper names are refused. Custom domains (§12) alias such hosts. `<port>` has no leading zeros: `tls/` takes §13's 443, 8443, 8883 and 5671 (owner decision 121), `smtp/` 25. Owners register `ValidateListen` (quota, certificate, port, host depth, the scope against the projection and, in a member scope, its consented devices, §8.5; owner decision 126; for `tls/`, a `raw` application mode only under a publish grant whose audience is `public` or `link`, §13.7) and `FirstListen`/`LastUnlisten` (DNS) hooks.

### 9.5 Registration

A registration is a lease on `(network_id, name, listener_client_id)`, at most one per client and name, since one connect client serves a client id (§5).

```go
// POST /socket/registrations (JSON, connect/api/bringyour.yml): the client's full set, so listen,
// heartbeat, drain and unlisten are one idempotent call; a set over 1,024 entries goes as pages
type SocketRegistrationsArgs struct {
    SetVersion    uint64                `json:"set_version"`   // per client, increasing; a set's pages share
                                                                // it; older sets are refused
    KeyStart      []byte                `json:"key_start"`     // this page is the whole set within name keys
    KeyEnd        []byte                `json:"key_end"`       // [key_start, key_end); empty: unbounded
    Registrations []*SocketRegistration `json:"registrations"` // <= 1,024, sorted by name key (name, or
                                                                // name_token for blinded names)
}
type SocketRegistration struct {
    Name       string      `json:"name"`        // tls/, smtp/ and ur/ names only (9.4)
    NameToken  []byte      `json:"name_token"`  // other names: the token path, 16 B a segment
    SealedName []byte      `json:"sealed_name"` // with name_token: 9.4's 152 B seal
    ListenId   *connect.Id `json:"listen_id"`   // random per Listen; older tickets refused
    Protocol   string      `json:"protocol"`    // default "tcp"; one protocol per group
    Version    int         `json:"version"`
    Alpn       []string    `json:"alpn"`        // tls/: ALPN ids served
    AppMode    string      `json:"app_mode"`    // tls/: "http" (default; h2, http/1.1 or no ALPN reach §13.7's
                                                 // HTTP front, D-TLS-13) or "raw"; other names: ""
    Weight     int         `json:"weight"`      // default 100, 1-1000: relative share
    MaxStreams int         `json:"max_streams"` // default 256: hard cap at the listener
    Exclusive  bool        `json:"exclusive"`   // refuse later registrations
    Affinity   bool        `json:"affinity"`    // honor affinity keys (9.7)
    Serving    bool        `json:"serving"`     // default true; false keeps the lease, takes no tickets
    Draining   bool        `json:"draining"`    // no new tickets; issued ones accepted
    Inflight   int         `json:"inflight"`    // load report
    Claim      []byte      `json:"claim"`       // §6 Signed by the identity key, purpose socket-registration, over
                                                 // (network_id, name or token path, listen_id, protocol, app_mode);
                                                 // Find returns it with tickets for the dialer's check (9.6)
}
```

- **Pages.** A call carries at most 1,024 entries and takes one bucket token (9.10); a larger set, unlimited in size (owner decision 66), goes as pages over consecutive key ranges under one `set_version`. Each page is the whole set within its range (an entry outside it refuses the page), so entries it lacks there unlisten at once, and an eager report sends only its own page.
- **Re-check.** Each call re-checks the projection (9.10) and quota per entry and recreates missing state, so Redis loss heals in one heartbeat; an entry answered `revoked` closes with its streams.
- **Lease.** Heartbeats every 15 s ± 20% carry load, and eager reports follow in-flight moves ≥ max(8, 25% of `max_streams`), at most every 2 s; leases are 45 s hash-field TTLs whose expiry stops tickets, not streams.
- **Unlisten** stops tickets at once (a racing ticket gets `retry`, the `tcp_migrate_req` analog); **drain** ends at zero in-flight or after 30 s (cloudflared's default, [R:ext-edge] §2.8), resetting the rest.

```proto
message SocketHint {             // §6 0x1001, topic `sock`: the client calls registrations at once, and the
                                 // answer is authoritative; version: a per-client sequence from the service
                                 // clock (ms), which Redis loss cannot lower
  SocketHintKind kind = 1;
  bytes listen_id = 2;
}
enum SocketHintKind {
  SOCKET_HINT_KIND_UNSPECIFIED = 0;
  SOCKET_HINT_REVOKED = 1;       // a grant was revoked or §21 suspended the name
  SOCKET_HINT_DRAIN = 2;         // forced drain
}
```

### 9.6 Find and accept

The service never contacts the listener; the dialer presents a Find ticket in the §6 OPEN (D-SOCK-4).

```text
dialer               sockets service               listener L1 / L2
  | POST /socket/find --> | projection: dial? pick (9.7) |
  | <-- [ticket L1, ticket L2]                         |
  | §6 OPEN{ticket L1, early data} ---------------> L1 admits
  | <------------------------------- ACCEPT | REJECT(code)
  | retry/busy/5 s timeout: OPEN{ticket L2} ------> L2
  | both fail: Find with the failed tickets (<= 3 Finds)
```

**Find** runs in order, and a refusal signs nothing (D-SOCK-15):

```text
step  check (service)                                                           refusal
1     the calling client's control-plane bound (9.10)                           unavailable, retry_after_ms
2     the newest verified projection allows the dial (9.10), checked before     denied
      the group is read, so refusals hide names
3     the paying network (§20.6: the listener's for edge Finds, else the        quota
      caller's) is not spent in §20.7's OverLimit set, re-read every 5 s
4     pick (9.7)                                                                no_listener; busy
5     sign the primary and backup tickets; edge and ur/ Finds write the {svc_} pair
```

```proto
message SocketTicket {           // signed: <= 370 B with a 112-byte name or an 8-segment token path
  bytes ticket_id = 1;           // 16 random bytes, single use
  bytes network_id = 2;
  string name = 3;               // tls/, smtp/ and ur/ names only
  bytes listener_client_id = 4;
  bytes listen_id = 5;           // 16 B
  bytes dialer_client_id = 6;    // edges: one of the caller's K clients
  bytes dialer_network_id = 7;
  uint64 issue_time_millis = 8;
  uint64 expire_time_millis = 9; // issue + 30 s
  uint64 policy_version = 10;    // §7.9 log position n that allowed it, at or after any GrantActivate
  bytes grant_id = 11;           // projection or requested grant: receipts, revocation
  bool backup = 12;
  uint64 grant_expire_time_millis = 13; // streams end here; 0: none; ur/: issue + 60 min
  bytes name_token = 14;         // other names: the token path (9.4)
  reserved 15;                   // withdrawn policy_delta_seq
}
message SignedSocketTicket {     // in StreamOpen.ticket (<= 512 B); §6's Signed format, purpose socket-ticket
  string key_id = 1;             // a service key; fixes the algorithm (Ed25519)
  bytes ticket = 2;              // SocketTicket
  bytes signature = 3;
}
```

**Edge Finds.** A `urnetwork-edge` caller sends its K client ids, and each ticket's `dialer_client_id` is `ids[h(listener_client_id) mod K]`, so a listener's edge streams share one client (§13.6). Edge and `ur/` Finds set §6.10.1's pair, field `<dialer_client_id>` of `{svc_<listener_client_id>}`, to the grant expiry, its TTL capped at 24 h (`ur/`: 60 min) and refreshed per Find; revocation or the last edge unlisten deletes it.

**Listener admission** runs in order; step 6 is owner decision 6's local evaluation:

```text
step  check                                                                         refusal (StreamRejectCode)
1     the signature verifies under a key from registration responses                invalid
2     listener_client_id is this client; listen_id is current                       invalid; retry
3     dialer_client_id is the Required session's source, always; it passed §6.4's   invalid
      Hello check unless dialer_network_id is urnetwork-edge (edges send no Hello),
      and an edge ticket names a tls/ or smtp/ name
4     unexpired by local clock plus the server_time offset; ticket_id unseen,       invalid
      kept until expiry
5     in-flight below max_streams; §20 has not stopped new streams (§20.6)          busy; quota
6     its own evaluation of the config repo, at the ticket's log position or        denied
      later (§7.9), allows the dial
7     ACCEPT, keeping the ticket as reach evidence (§16); the stream ends at
      grant_expire_time_millis or revocation
```

**Dialer.** Before OPEN, a sidecar dialer checks the ticket's claim against the listener's Hello binding and the listener's `listen` grant in its own config (owner decision 3). Each attempt waits 5 s: `retry`, `busy` and timeouts try the next ticket, `denied` stops, `quota` waits `retry_after_ms`, `invalid` refetches once. These are §6.7's `StreamRejectCode`, one to one: `retry` 1, `busy` 2, `denied` 3, `invalid` 4, `quota` 5; 0, unspecified, is a protocol error, taken as `invalid` (§6.11). The next Find carries the failed tickets, which the service verifies, so only holders report. A report excludes the listener for that dialer; ejection for all needs reporters from 2 networks within 30 s, and edges report only accept timeouts. Both last 30 s per consecutive ejection, up to 300 s, for at most half a group (Envoy's defaults, https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/outlier_detection.proto).

### 9.7 The scheduler

Each Find runs weighted power of two choices (P2C; owner decision 65), which stays effective on stale load where least-loaded herds (Mitzenmacher, IEEE TPDS 11(1), 2000, https://www.eecs.harvard.edu/~michaelm/abstracts/tpds2000.html):
1. Filter to live, `serving` listeners not draining, ejected or excluded for this dialer, matching protocol, version and ALPN (an offered id the listener serves, or none, which §13.7 dispatches by `AppMode`), with `est < max_streams`; if none remain, ignore ejections and exclusions. Without affinity, groups above 64 listeners filter a random 64 (`ZRANDMEMBER`, Redis ≥6.2, https://redis.io/docs/latest/commands/zrandmember/), bounding a Find's cost.
2. Sample two distinct candidates in proportion to `weight`.
3. Pick the lower `(est + 1) / weight`; the other is the backup.
4. `est = reported_inflight + issued`, where `issued` sums, over dialers, each dialer's primary tickets since the listener's last report, each counted for at most 30 s (unredeemed tickets expire), and clamped per dialer at c = max(4, ⌊10% of `max_streams`⌋). The clamp bounds the estimate only: Find never refuses or delays a ticket for it, so a dialer's tickets are limited by step 1's `est < max_streams`, its control-plane bucket (9.10) and the listener's admission (9.6, step 5).

- **Affinity (opt-in).** A rendezvous hash of `affinity_key` skips listeners above 1.25 × mean `est` (https://arxiv.org/abs/1608.01350); tlsedge sends a keyed hash of the visitor's /24 or /48, never stored.
- **Fairness.** Weighted sampling reaches every listener, and no dialer moves `est` by more than c. A dialer that takes tickets and opens nothing cannot make a listener look fuller than c streams to others. In turn, one dialer's burst of short connections counts at most c above the last report, so P2C can send that burst to one listener past its real load until the listener's next report: an eager one once in-flight moves by max(8, 25% of `max_streams`), at most every 2 s, else the 15 s heartbeat (9.5). The listener's `max_streams` answers the excess `busy`, and the backup ticket takes it. Saturation returns `busy` without a server queue, and dialers back off with jitter.
- **Throughput.** One Find issues one primary ticket for one stream, so a sidecar dialer opens at most `sockets_control_qps` new streams a second per sockets process (50, burst 500; 9.10), and an edge process W2's 2,000 (§19.5), whatever c is. A listener takes at most `max_streams` over its mean stream time: a 256-stream listener with 100 ms streams takes about 2,560 a second. A lone sidecar dialer is therefore bound by its bucket, never by c: connection throughput is the lesser of the dialers' buckets and `max_streams` over the mean stream time, never concurrent-stream capacity alone (§22.5's one-dialer case).

### 9.8 The sockets service

Stateless processes keep all state in Redis Cluster, with no Postgres tables; §2.8's sock-1 to sock-5 give fields and TTLs, and `sock` hints are connect-4.

```text
{sg_<network_id>_<h16(name)>}  group HASH: per listener m: registration, r: in-flight, i: issued, e: ejection;
                               per dialer shares and exclusions; v: version; ZSET …ix orders the leases;
                               h16 is the first 16 hex digits of SHA-256
{svc_<listener_client_id>}     Service pairs (9.6)
{sn_<network_id>}names         the listing index; entries leave with their leases
{sc_<client_id>}set            each client's set, ordered by name key for pages (9.5); expires 5 min after
                               the client's last call
```

Hash tags are per group (D-SOCK-7). A Find is one group-key script (check `v`, filter or sample, read two loads, increment one) plus a `{svc_}` write per edge ticket; counters are advisory, the listener cap authoritative. `server/cli/sockets` runs on every lb host, since each lb proxies only to its own; 100,000 listeners make about 6,700 registration calls/s. Only the service signs (vault `secret_files`, 30-day rotation with overlap; keys at `GET /socket/keys`). Each process caches each network's newest base and the entries after it from api (§8.9) and, on `{X}c_removed` (`server/model/client_close_model.go:64`), a projection revocation or a §21 suspension, deletes entries and pairs and sends `SocketHint`.

### 9.9 Client API

```go
// package sidecar, files socket_*.go (§4 places the engine); §18 wraps it for gomobile
type SocketAddress struct {
    NetworkId    *connect.Id // set once resolved
    NetworkLabel string      // "" is the caller's network
    Name         string
}
type SocketListenSettings struct { // defaults as in 9.5
    Protocol   string
    Version    int
    Alpn       []string
    AppMode    string         // tls/: "http" (default) or "raw" (9.5)
    Weight     int
    MaxStreams int
    Exclusive  bool
    Affinity   bool
    Decision   *bridge.Signed // ApprovalDecision for tls/ and smtp/ (§5.4's gate)
}
type SocketDialSettings struct {
    Protocol      string
    MinVersion    int
    Alpn          []string
    AffinityKey   []byte
    AcceptTimeout time.Duration // default 5 s
}
func ParseSocketAddress(text string) (*SocketAddress, error)
// Listen on tls/ and smtp/ calls §5.4's Authorize (I-8), which may return *ApprovalPendingError.
func (self *Sidecar) Listen(ctx context.Context, address string, settings *SocketListenSettings) (*SocketListener, error)
func (self *Sidecar) Dial(ctx context.Context, address string, settings *SocketDialSettings) (*SocketConn, error)
// *SocketListener implements net.Listener (Accept, Close, Addr). Close unlistens at once;
// accepted conns stay open, and a pending Accept returns net.ErrClosed.
func (self *SocketListener) AcceptSocket(ctx context.Context) (*SocketConn, error)
func (self *SocketListener) Drain(ctx context.Context) error // returns at zero in-flight or ctx end (like http.Server.Shutdown), then closes
func (self *SocketListener) SetServing(serving bool)         // e.g. false while the local target refuses
// *SocketConn implements net.Conn; Close sends FIN and stops reading (the peer reads io.EOF).
// Deadlines are local (os.ErrDeadlineExceeded, Timeout() true); the stream survives them.
// RemoteAddr is the dialer's network and client id, Network() "ur"; edge client IPs arrive in-band (§13).
func (self *SocketConn) CloseWrite() error // FIN
func (self *SocketConn) Abort() error      // reset
func (self *SocketConn) Ticket() *SocketTicket
// Errors are *net.OpError{Net: "ur"} wrapping one of these. All but ErrSocketReset are Find's errors too,
// in 9.6's step order; no_listener, busy, quota and unavailable carry retry_after_ms.
var (
    ErrSocketNoListener  error // syscall.ECONNREFUSED
    ErrSocketBusy        error // syscall.ECONNREFUSED
    ErrSocketDenied      error // syscall.EACCES
    ErrSocketReset       error // syscall.ECONNRESET
    ErrSocketUnavailable error
    ErrSocketQuota       error
)
```

CLI (added to cli/UI.md): `ur socket`; `ur socket listen <addr> [<ip>:]<port>` (to a local port; `serving=false` while it refuses; prints `ur approve <id>` for outward names); `ur socket dial <addr> [--listen=[<ip>:]<port>]` (a local forward: 0.0.0.0/:: unless `<ip>` is given, without the TLS-only rule; D-TRUST-8, owner decisions 84, 130; else stdin/stdout (`ssh -o ProxyCommand`); `ur socket ls [<net>]` (unseals names locally); `ur socket drain <addr>`. `ur bridge public-tls` (cli/UI.md:47) is `listen tls/443/<host>`; §16.5 maps the MCP tools.

**Share (D-SOCK-16).** `ur share add <path> [--count=n] [--expires=d]` hashes the file, writes the record below, listens `exclusive` on `share/<token>` (`<token>`: 16 random bytes, lowercase base32) and prints the link `<net>:share/<token>#<k>`, whose fragment `k` is base64url(the sharer's `sidecar_id` ‖ a 256-bit secret). `--expires` defaults to 24 h, and `ur share add` refuses more than 30 days, the longest ordinary grant (owner decision 74), so every share ends. `ur share get <link> <out>` dials from a sidecar of the sharer's network, the only one an application name reaches (§6.4), and before OPEN refuses a listener whose verified `sidecar_id` is not `k`'s. `ur share` blocks and lists live shares with their remaining uses and expiry; `ur share rm <token>` ends one early (`--expires` and `rm` added to cli/UI.md). Records survive restarts, but a share is served only while the sharing sidecar runs (the daemon stays up while one is live, §5.8), as the CLI and `ur status` say. Both ends need §8's `listen` and `dial` on `share/`, which the implicit document gives untagged subjects; bytes count toward the network's transfer balance like any same-network stream (§20.6).

```text
record  <state>/net/<network_id>/share/<token>, local file class `share` (§5.9), append-only; each record
        is fsynced before the step it guards (§16's reserve-before-effect ledger, D-MCP-11)
  Share{token, path, size, mtime, sha256, secret, uses (0: unlimited), expire_millis}   at add, after hashing
  Reserve{get_id, use_index, getter_sidecar_id, millis}   Done{get_id, millis}   Remove{millis}
get     getter -> version[1] = 1 ‖ secret[32] ‖ get_id[16] ‖ u64be offset
        (get_id random, kept with <out>.part until a clean close)
        sharer, under the share's mutex, first match:
          the secret differs (constant time), a Remove exists,     reset; no use spent
            or the sharer's clock is at or past expire_millis
          the file's size or mtime differs from Share             status changed
          get_id is reserved by this getter                       resume at offset; spent after its Done
          count(Reserve) < uses, or uses = 0                      append Reserve, fsync: the linearization point
          otherwise                                               status spent
        sharer -> status[1] (0 ok, 1 spent, 2 changed); ok adds u64be size ‖ sha256[32], then bytes [offset, size)
        getter: SHA-256 over [0, size) equals sha256; it renames <out>.part to <out> and sends done[1] = 1,
        and the sharer appends Done
end     a Remove, a Done for each of `uses` Reserves, or expire_millis (by timer, and at start for a sharer
        offline then): reset the share's streams, unlisten and delete the record
```

Served uses never exceed `uses`, counted by Reserves, and no get starts, resumes or keeps streaming at or past `expire_millis`; a crash or a lost stream never frees a Reserve (burn on uncertainty), and only its own getter resumes it.

### 9.10 ACL, quotas, abuse, identity, metrics

- **Gates (X3, D-SOCK-14).** The service checks each registration and Find against the network's newest verified id-only projection (§7.9, §8.9; owner decisions 5, 72): `listen` and `dial` rules over subjects and token paths, `tls/` publish and `smtp/` listen grants, grant ids and expiries. Requested grants count once their GrantActivate enters the authorization log (§7.9; owner decision 74); edge listens need one or a standing grant (I-8). Edge Finds run as `autogroup:public` on `tls/` (§13.5) and check the receiver's `listen` on `smtp/` (§15.4). For §13.9's system publish `tls/443/mta-sts`, each receiver's own approved `smtp/25/mx` listen grant stands in for the `tls/` listen and publish grants at registration, Find and admission, and its expiry or revocation ends that receiver's publish. Without a policy document, the implicit one gives untagged subjects `dial` and `listen` on every application name, disclosed (owner decisions 105, 120). Both ends re-derive the grant (9.6), and revocation resets its streams.
- **Quotas.** `tls_endpoints` (PLAN.md:358) counts active publish grants per (host, port) at activation (§20.7); `ValidateListen` refuses a `tls/` listen without one, except the system publish, which takes no unit (§13.9).
- **Overload protection, no caps** (Q-SOCK-2, owner decision 66). Established streams and forwards are unlimited; the transfer balance alone limits use. System-protection bounds, equal for every network and tier, keep a byte-free client from pinning Redis or the signing key (D-SOCK-15): a per-process token bucket per calling client over Finds and registration pages of at most 1,024 entries (`sockets_control_qps`, default 50 calls/s, burst 500; 9.5) answers `unavailable` with `retry_after_ms` before any sampling or signing, and Find's spend check (9.6) answers `quota` before signing, the listener's step 5 staying the authoritative stop. No count of names, listeners or streams is capped. Processes serve calls in per-network fair-share order, shedding the heaviest network only when saturated; 9.7 bounds group and dialer costs, and §19 sets per-address lb limits (W2) and per-edge-process Find limits, which replace the bucket for `urnetwork-edge` callers.
- **Hijack.** `listen` grants, `exclusive` and the `ur/` rule prevent group hijack (the SO_REUSEPORT same-UID analog), except under a blanket `listen` grant (9.16).
- **Removal (X10).** Besides 9.8's deletion, connect closes the client's transports (code 4005, `server/CLIENTCLOSE.md` §4), so dialers use backup tickets; a child listener is removed with its parent (9.3) and fails its next call once its parent is otherwise inactive.
- **Metrics** (`urnetwork_sockets_*`): `find_total{result}`, `find_seconds`, `registrations`, `registration_calls_total{result}`, `failure_reports_total{reason}`, `exclusions_total`, `ejections_total`; no network, name, client or IP labels.

### 9.11 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Service pushes to the listener first (X8) | Early refusal | A non-e2e ControlId push per connection (§6.8) | Rejected |
| Per-listener MAC ticket (contract pattern) | Cheap verify | Server holds the keys; no receipt | Rejected |
| 4-tuple hash (SO_REUSEPORT) | Stateless, sticky | Load-blind; aborts a closing socket's queue without `tcp_migrate_req` ([R:ext-edge] §2.10) | Opt-in affinity |
| Presence-only liveness | No heartbeats | Residents outlive disconnects ~5 min (`server/CLIENTCLOSE.md`); no load data | Rejected |
| Edge-delegated ticket keys | Edges survive a sockets outage | Keys on edge hosts; C9 still needs Redis | Later |
| Plaintext application names | Server-side globs | URnetwork reads every internal name | Rejected (owner decision 67) |
| One HMAC per whole name | Hides depth | No server-side prefix grants | Rejected |
| `ur share` as an evs object sealed under a link-fragment key | Works while the sharer is offline | Changes format 1, which freezes at M2 | Rejected (D-SOCK-16) |

### 9.12 Decisions proposed

**D-SOCK-1 (proposed).** Key sockets on `(network_id, name)`, resolving `<net>` per call. *Why:* names are mutable and reclaimable.

**D-SOCK-2 (proposed).** Use 9.4's namespaces and host forms, refusing deeper names. *Why:* one rule for §13-§15; a wildcard covers one label, and owner decision 40's scopes add one.

**D-SOCK-3 (proposed).** Registrations are 45 s leases renewed every 15 s by the full set, in pages of at most 1,024 entries (9.5), carrying load. *Why:* one idempotent path; Redis loss heals in one interval.

**D-SOCK-4 (proposed).** Find returns single-use 30 s Ed25519 tickets (primary, backup) carrying the grant expiry; the service never contacts listeners. *Why:* push stays off the connection path; tickets are reach evidence.

**D-SOCK-5 (proposed).** Schedule by weighted P2C on `(est + 1) / weight` with listener caps, opt-in affinity, a per-dialer clamp on each dialer's share of `est`, which never refuses or delays a ticket, and 64-listener samples. *Why:* load-aware, stale-tolerant and bounded; a clamp that stopped issuance would hold a lone short-connection dialer to c tickets per report, about 25 per 15 s on a 256-stream listener, since short connections never move in-flight enough for an eager report (meta review CC-06).

**D-SOCK-6 (proposed).** Dial with a 5 s accept timeout, the backup ticket, then ≤3 Finds carrying failed tickets; ejection needs reporters from 2 networks. *Why:* bounded latency; a lying reporter harms only itself.

**D-SOCK-7 (proposed).** Keep state in Redis Cluster with per-group hash tags and field TTLs. *Why:* warp has no key routing; per-network tags create hot nodes.

**D-SOCK-8 (proposed).** Adopt 9.9's `net.Listener`/`net.Conn` API with syscall-compatible errors. *Why:* existing Go code and retry logic work unchanged.

**D-SOCK-9 (proposed).** Delete registrations on `{X}c_removed`; keep no per-dial record beyond §2.8's sock-2 fields (≤300 s) and sock-3 pairs (≤24 h). *Why:* reuses the removal signal; minimal metadata.

**D-SOCK-10 (proposed).** Host the engine as `server/cli/sockets` with Client-class routes, sidecar-classified (§7.4). *Why:* registration load stays off `api`.

**D-SOCK-11 (proposed).** Platform services listen as `ur/<service>` in `urnetwork-edge`, authorized by the service. *Why:* sidecars reach smtpedge through the same Find and Service path.

**D-SOCK-12 (proposed).** Edge tickets bind one of the caller's K clients, and edge Finds write the `{svc_}` pair authorizing C9 until the grant ends; source equality holds for edge tickets too, and only the Hello check is waived (9.6). *Why:* step 3 stays exact; contracts outlive the ticket, not the grant.

**D-SOCK-13 (proposed).** Send names outside `tls/`, `smtp/` and `ur/` only as 9.4's HMAC token paths, sealed for listings, under the config repo's `K_sock`, rotated on §11.6's triggers. *Why:* owner decision 67, built like evs paths (owner decision 2); prefix grants still work.

**D-SOCK-14 (proposed).** Gate registrations and Finds on the signed id-only projection (§7.9, §8); listener and dialer each re-derive the grant from the config repo. *Why:* owner decisions 3, 6 and 72: a breached server can only deny or delay.

**D-SOCK-15 (proposed).** System protection bounds registration and Find work, never the number of names or established use: a per-client token bucket charges each Find and each registration page of at most 1,024 entries, larger sets going as pages (9.5), and a spend check precedes signing (9.6, 9.10). *Why:* owner decision 66 allows system-protection bounds but no count caps; an authenticated byte-free client otherwise pins Redis and the signing key.

**D-SOCK-16 (proposed).** `ur share` is a live sharer: a blinded `share/<token>` socket, a fragment-borne 256-bit secret, a durable use count and an expiry (24 h by default, at most 30 days), on the transfer balance, available while the sharing sidecar runs (9.9). *Why:* R-CTX-31; no link outlives its expiry, even with unlimited uses; an evs object under a link key would change format 1, which freezes at M2.

### 9.13 Open questions

**Q-SOCK-1.** Is load-aware weighted P2C, with opt-in affinity, an acceptable reading of PLAN.md:69's "similar to socket reuse on linux"? **Decided by owner 2026-11-03 (owner decision 65):** yes, as 9.7 designs, with drain and retry. *Residual:* none.

**Q-SOCK-2.** Do abuse caps contradict "IP and port forward [unlimited]" (PLAN.md:359)? **Decided by owner 2026-11-03 (owner decision 66):** yes, so none apply; the transfer balance alone limits use, and 9.10 keeps overload protection. *Residual:* none.

**Q-SOCK-3.** Which relationship carries cross-network streams (X11, §20)? **Decided by owner 2026-11-03 (implied by owner decision 59):** Q-PROTO-3 (b), accepted with owner decision 11: Service (C9) for edges, authorized by 9.6's pair; shares ride §17's IP path as FriendsAndFamily (owner decision 86). *Residual:* none.

**Q-SOCK-4.** Should application names be blinded from the server? **Decided by owner 2026-11-03 (owner decision 67):** yes, as 9.4's token paths under the config repo's `K_sock` (D-SOCK-13); public edge names stay plaintext, and clients resolve names locally. *Residual:* none.

### 9.14 Departures from PLAN.md

- The scheduler is load-aware, not a 4-tuple hash (Q-SOCK-1, owner decision 65).
- Internal names reach the server blinded (Q-SOCK-4, owner decision 67).
- PLAN.md:74: other networks reach a listener by IP through a §17 share, not a §9 dial (§8.16; Q-BRIDGE-6, owner decision 86).
- PLAN.md:82's tls edge "opens a client on a network": edges are `urnetwork-edge` platform clients in Service mode (§13.14, Q-TLS-5; owner decisions 11, 59).

### 9.15 Interfaces

- **Provides:** the grammar, namespaces and token paths; registry, scheduler, tickets, admission; the control-plane bounds; `{svc_}` pairs; hooks; `SocketHint`; the Go API, `ur socket` and `ur share`.
- **Consumes:** §6 streams, `StreamRejectCode`, `Signed`, the Hello check, topic `sock`, Required mode; §4 C9; §5 identity keys, `Authorize`, local file classes; §7.9's authorization log and projection (§8's rows and audiences, statements, revocations); the config repo's `K_sock` and policy; §12 resolution; §13-§15 edge dialers, hooks; §16's reserve-before-effect ledger (D-MCP-11); §19, §20 limits and `OverLimit`; §21 suspensions.
- **Subprotocol messages:** `SocketHint` (0x1001, ControlId→client, topic `sock`; revocation, forced drain); `SignedSocketTicket` in `StreamOpen.ticket`; `StreamRejectCode` `retry|busy|denied|invalid|quota` (1-5; 0 unspecified) in `StreamReject.code`; on `share/` streams, 9.9's fixed-width share header.
- **API routes** (`/socket/*` is sidecar-classified, on §7.4's `strict_exp` allowlist): `POST /socket/registrations` (Client; 9.5, pages of ≤1,024 entries; statuses, `server_time`, keys); `POST /socket/find` (Client; 9.6, errors 9.9; platform callers add K client ids); `GET /socket/list` (Client, same network; token paths, edge and sealed names); `GET /socket/keys` (Public).
- **Tables:** none (9.8's Redis keys, behind `SocketStore`).
- **Services and config:** `server/cli/sockets`; vault ticket keys; pro.yml `tls_endpoints`; `sockets_control_qps` and `urnetwork_edge` (the `urnetwork-edge` network id) in `config/<env>/sidecar.yml` (§6.10.1, §19.11).
- **Assumptions about other sections:**
  - §4.5's engine stores include `SocketStore`, with field TTLs and an atomic pick-and-increment.
  - §7.9's projection lists Team scopes (9.4); §11.6 keeps the path-epoch triggers 9.4 cites, authorization expiries batched with shrinks.
  - §13.7 dispatches on `AppMode` (D-TLS-13) and defines a raw endpoint's `link` check; §20.7's `OverLimit` lists spent networks within 5 s.
  - §22.5 tests 9.5's pages (a 3,000-name set as three pages, range-scoped unlisten, out-of-range and stale pages refused, one interval rebuilding the set after Redis loss); fixed vectors for 9.4's `K_tok` and `K_seal`, tokens and 152 B seals, a moved or mismatched seal dropped; and 9.9's share: no get or resume at or past `expire_millis`, a live stream reset there, a sharer restarted past it serving nothing, `--expires` over 30 days refused, and uses never exceeded across a crash after a Reserve; and 9.7's clamp: one dialer's short connections to a 256-stream listener, none refused or delayed by it.

### 9.16 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A dead listener costs 5 s until skipped | Medium | Medium | Backup ticket; exclusion; 45 s lease |
| A leaked signing key forges tickets until rotation | Low | High | Vault; rotation; both ends' checks refuse unauthorized streams |
| Reconnect storms, uncapped groups or byte-free clients load the service | Medium | Medium | Jitter; `retry_after_ms`; sampling; the per-client bucket and pre-sign spend check (D-SOCK-15); fair queuing; shedding |
| The bucket delays a legitimate client making over 50 calls a second: opening that many streams, or renewing over about 768,000 names (750 pages per 15 s) | Low | Low | Burst 500; `retry_after_ms`; 45 s leases outlast a late page; `find_total` and `registration_calls_total{result}` show it; sidecar.yml tunes the bound |
| Edge names are public; token paths show structure; a dropped or expired reader, with server help, tests guessed names until `K_sock` rotates | High | Low | §2.8 rows; rotation and its alarm (9.4) |
| A blanket `listen` grant (§8.5's grant 1) lets any member's untagged device join an application group and take dials | Medium | Medium | `exclusive`; narrower `listen` rules |
| A sockets or Redis outage fails Finds (`unavailable`) and new edge connections; streams stay up | Low | High | Every lb host; failover; §19.10; SLO burn pages the out-of-hours rota (owner decision 143) |
| Dialers inflate `est` or report falsely | Medium | Medium | 9.7's per-dialer share cap, decay, two-network ejection |
| One dialer's burst of short connections reaches one listener past its real load until the listener's next report, since that dialer's tickets count at most c in `est` | Medium | Low | The listener's `max_streams` admission and the backup ticket; eager reports at most every 2 s (9.5, 9.7) |
| A leaked share link lets any sidecar of the network redeem its remaining uses until it expires | Medium | Medium | `--count`; `--expires` (24 h default); `ur share rm`; each Reserve names the getter |

### 9.17 Phasing

- **v0 (§23 M5):** the `sockets` service with 9.10's bounds; blinded application names; `tls/` with §13, `AppMode` included; tickets, P2C and 9.7's per-dialer clamp on `est`; `SocketHint`; the Go API; `ur socket` and `ur share`; MCP tools. Blocked by §6 streams, §5 identity, the config repo and projection (X3, M2) and §4's C9.
- **v0, mail track:** `smtp/` with §15 (M7); `ur/` once §14 passes D-SMTP-16's gate, DATA mode included (M9; owner decisions 35, 99, 125).
- **v1 (M6):** affinity, with §13; Team scope hosts (owner decisions 40, 55, 58), the `smtp/` ones with §15.
- **Later:** region-aware selection (one lb site today, [R:ext-edge] §5 R8), slow start, edge-delegated ticket keys, registration over push.
