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
- **Rotation.** `K_sock` rotates on the key-holder changes that make §11.6's path epochs due, in classes of its own: a member's or member device's removal and compromise retirements at once; other key-holder shrinks and authorization expiries (§7.9's expiry identities) at most daily (a reap of an agent its live Delegation covers is none). The path epochs themselves are all batched (owner decision 585), and these classes stay as they are. Only config writers change it (§8.8), so it rotates in the next writer head, republishing the projection; without a writer online it waits, and member devices alarm 24 h after the trigger. A rotating head keeps the previous key in the `socket/key` file with `rotated_at_ms` (§8.8). Listeners register both paths until `rotated_at_ms` + 10 min by their own clock, so §2.8 sock-1's 10 min holds even with no writer online, and a lister tries the previous key while the file holds it. The overlap is kept at the gates too: while the file holds a previous key, compile writes a second target under that key beside each `sock:` target, and the first writer head at or after `rotated_at_ms` + 10 min clears it; a requested grant's `sock:` entry is a literal token path with no second path, so it works while listeners register that path, through the overlap, and then its subject requests again (§8.8; owner decision 334).

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

`ur/` Finds cross networks, as the names resolve to `urnetwork-edge`. `<host>` is `@` or one LDH label (`blog`, `api-dev`), as a wildcard certificate covers one label; a v1 Team scope (Q-TLS-3; owner decisions 40, 58) adds `<label>.<scope>` hosts within one 63-byte segment (`smtp/`: `mx.<scope>`), and deeper names are refused. Custom domains (§12) alias such hosts. `<port>` has no leading zeros: `tls/` takes §13's 443, 8443, 8883 and 5671 (owner decision 121), `smtp/` 25. Owners register `ValidateListen` (quota, certificate, port, host depth, the scope against the projection and, in a member scope, its consented devices, §8.5; owner decision 126; for `tls/`, a `raw` application mode only under a publish grant whose audience is `public` or `link`, §13.7) and `FirstListen`/`LastUnlisten` hooks, which stay seams with no DNS consumer: a zone's `*` and `@` address records follow its grants, never its listeners (§12.7; owner decision 335).

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
    CertifiedNames []string          `json:"certified_names"` // tls/: the custom hosts and aliases mapped to this
                                                 // name for which the listener has an unexpired certificate
                                                 // installed; outside the signed claim, since they only route
    AcmeNames      []*SocketAcmeName `json:"acme_names"`      // tls/: the names it holds a pending TLS-ALPN-01
                                                 // challenge for, each {name, claim_seq}: the account lock's
                                                 // claim it answers under (§13.8)
}
```

- **Pages.** A call carries at most 1,024 entries and takes one bucket token (9.10); a larger set, unlimited in size (owner decision 66), goes as pages over consecutive key ranges under one `set_version`. Each page is the whole set within its range (an entry outside it refuses the page), so entries it lacks there unlisten at once, and an eager report sends only its own page.
- **Re-check.** Each call re-checks the projection (9.10) and quota per entry and recreates missing state, so Redis loss heals in one heartbeat; an entry answered `revoked` closes with its streams. The service judges a page on one verified state and stamps each lease with the listener's `sidecar_id`, the authorization log position it was admitted at and the page's `set_version`. A removal for cause leaves a tombstone in the group for 10 min, and an unlisten one for 60 s: a later write admitted below the tombstone's position, or from an older set, is refused, and the caller of a write fenced by a position its process has not reached is answered `unavailable` with `retry_after_ms`, its page's other entries applied (DESIGN-DETAILS.md section 13).
- **Certified and ACME names.** A `tls/` registration may list the custom hosts and aliases it is certified for and the names it holds an ACME claim for. §13.9's `ValidateListen` holds both to rows, a certified name to the sidecar's unexpired certificate row and an ACME name to the account lock's claim that sidecar holds, drops what the rows do not bear out and never refuses the entry for them, so a listener keeps its network names; a list past its count, a setting, is malformed (DESIGN-DETAILS.md section 17, 17.2.10).
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
4     pick (9.7), then the listener check: the service signs only for a         no_listener; busy;
      listener its own newest state allows, judged on its lease's stored        unavailable
      sidecar_id, removing one it refuses for cause, and gives no ticket for
      one admitted at a position above its own: unavailable when none of the
      picked can be judged (DESIGN-DETAILS.md section 13)
5     sign the primary and backup tickets; edge and ur/ Finds write the {svc_} pair, a tls/ or smtp/
      pair only at or above the floor a removal left
```

```proto
message SocketTicket {           // signed: <= 370 B with a 112-byte name and dialer_sidecar_id, or an 8-segment token path
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
  uint64 grant_expire_time_millis = 13; // streams end here; 0: none; ur/: issue + its service's grant
                                 // length, 60 min by default (ur/smtpedge: 125 min)
  bytes name_token = 14;         // other names: the token path (9.4)
  reserved 15;                   // withdrawn policy_delta_seq
  bytes dialer_sidecar_id = 16;  // 16 B, ur/ tickets alone: the dialer's sidecar, its listener's subject (owner
                                 // decision 560; ur/ tickets, below)
}
message SignedSocketTicket {     // in StreamOpen.ticket (<= 512 B); §6's Signed format, purpose socket-ticket
  string key_id = 1;             // a service key; fixes the algorithm (Ed25519)
  bytes ticket = 2;              // SocketTicket
  bytes signature = 3;
}
```

**Find's request.** `POST /socket/find` carries `protocol`, `min_version` and `alpn`, 9.7's filter, and, for a dial tlsedge resolved through the custom-host map or the alias table, `server_name`, the hello's server name, empty for a name under the network's own zone; §2.8's sock-2 lists them (DESIGN-DETAILS.md section 17, 17.2.10).

**`ur/` tickets (owner decision 560).** A `ur/` ticket names its dialer's sidecar in `dialer_sidecar_id = 16`, 16 bytes, which the service fills at Find from the `ur_sidecar_id` of the caller's service token, which it has already authenticated (9.8's service tokens; owner decision 588), and signs with the rest; `tls/`, `smtp/` and edge tickets leave it empty, edges naming no sidecar. smtpedge reads the stream's subject from the admitted ticket, with no client-to-sidecar lookup or cache, and judges §8's `mail_send` for it (§14.5), a `ur/` stream whose ticket names no dialer sidecar answering TRY_LATER, failing closed; every `ur/` listener may read its subject the same way. The field adds about 18 B, within `StreamOpen.ticket`'s 512 B.

**Edge Finds.** A `urnetwork-edge` caller sends its K client ids, and each ticket's `dialer_client_id` is `ids[h(listener_client_id) mod K]`, so a listener's edge streams share one client (§13.6). Edge and `ur/` Finds set §6.10.1's pair, field `<dialer_client_id>` of `{svc_<listener_client_id>}`, under one of two rules. A `tls/` or `smtp/` pair is written with a TTL of the lesser of the grant's remaining life and 15 min; a registration call that accepts an edge entry of the client renews its pairs, at most every 5 min a process; and a removal leaves a floor that refuses a write allowed at an older position, so a revoked, removed or dead listener's pairs end within 15 min whatever any sweep did (owner decision 338). A `ur/` pair lives its service's grant length, refreshed per Find: grant length is per `ur/` service, 60 min by default, and `ur/smtpedge`'s is 125 min, `grant_expire_time_millis` = issue + 125 min with a `{svc_}` TTL of 125 min, §14.4's 2 h of DATA plus 5 min for the ticket's 30 s, the pre-TLS exchange and `SmtpOutcome`. Contracts keep §6.10.1's rule and roll at their 60-minute deadline while the pair lives, and the edge's own timers still end the connection at §14.4's 30 min, or 2 h in DATA mode, so the longer grant adds no longer session. Revocation or the last edge unlisten deletes a pair.

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
      grant_expire_time_millis or revocation, its wait read again after a sleep or a
      clock step (§17.8; owner decision 798)
```

**Replay set (owner decision 694).** Step 4's seen ticket_ids are held in memory, per listener, each until its ticket expires. A listener draws a new listen_id at every Listen (9.5) and nothing stores one, so after a restart every listener is new: an open connect replays from before the restart (§6.9's session recovery) carries a ticket naming the old process's listen and meets step 2's retry, or no target before the daemon listens again, and its opener resets the stream on any reject after its open was answered. Within a process, listeners and their replay sets outlive a reconnect, so a replay onto the same listen meets step 4. A listener that ever keeps its listen_id across a restart must keep its replay set with it; the sockets component's restart test fails the day one does.

**Dialer.** Before OPEN, a sidecar dialer checks the ticket's claim against the listener's Hello binding and the listener's `listen` grant in its own config (owner decision 3). Each attempt waits 5 s: `retry`, `busy` and timeouts try the next ticket, `denied` stops, `quota` waits `retry_after_ms`, `invalid` refetches once. These are §6.7's `StreamRejectCode`, one to one: `retry` 1, `busy` 2, `denied` 3, `invalid` 4, `quota` 5; 0, unspecified, is a protocol error, taken as `invalid` (§6.11). The next Find carries the failed tickets, which the service verifies, so only holders report. A report excludes the listener for that dialer; ejection for all needs reporters from 2 networks within 30 s, read literally: reporters whose `dialer_network_id`s differ, so ejection and `ejections_total` act on `ur/` names only, and other namespaces rely on exclusion, the backup ticket and the 45 s lease; edges report only accept timeouts. Both last 30 s per consecutive ejection, up to 300 s, for at most half a group (Envoy's defaults, https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/outlier_detection.proto).

### 9.7 The scheduler

Each Find runs weighted power of two choices (P2C; owner decision 65), which stays effective on stale load where least-loaded herds (Mitzenmacher, IEEE TPDS 11(1), 2000, https://www.eecs.harvard.edu/~michaelm/abstracts/tpds2000.html):
1. Filter to live, `serving` listeners not draining, ejected or excluded for this dialer, matching protocol, version and ALPN (an offered id the listener serves, or none, which §13.7 dispatches by `AppMode`), with `reported_inflight < max_streams`, the listener's own report alone, `est` staying for step 3's comparison; if none remain, ignore ejections and exclusions. A dial with a server name matches only listeners certified for it; a dial offering `acme-tls/1` matches only listeners holding a claim for the name, whatever their load, and takes the one with the newest claim, with no backup and no draw; and a listener that lists only `acme-tls/1` matches no other dial (DESIGN-DETAILS.md section 17, 17.2.10). Without affinity, groups above 64 listeners filter a random 64 (`ZRANDMEMBER`, Redis ≥6.2, https://redis.io/docs/latest/commands/zrandmember/), bounding a Find's cost.
2. Sample two distinct candidates in proportion to `weight`.
3. Pick the lower `(est + 1) / weight`; the other is the backup.
4. `est = reported_inflight + issued`, where `issued` sums, over dialers, each dialer's primary tickets since the listener's last report, each counted for at most 30 s (unredeemed tickets expire), and clamped per dialer at c = max(4, ⌊10% of `max_streams`⌋). The clamp bounds the estimate only: Find never refuses or delays a ticket for it, so a dialer's tickets are limited by step 1's `reported_inflight < max_streams`, its control-plane bucket (9.10) and the listener's admission (9.6, step 5).

- **Affinity (opt-in).** A rendezvous hash of `affinity_key` skips listeners above 1.25 × mean `est` (https://arxiv.org/abs/1608.01350); tlsedge sends a keyed hash of the visitor's /24 or /48, never stored.
- **Fairness.** Weighted sampling reaches every listener, and no dialer moves `est` by more than c. A dialer that takes tickets and opens nothing cannot make a listener look fuller than c streams to others. In turn, one dialer's burst of short connections counts at most c above the last report, so P2C can send that burst to one listener past its real load until the listener's next report: an eager one once in-flight moves by max(8, 25% of `max_streams`), at most every 2 s, else the 15 s heartbeat (9.5). The listener's `max_streams` answers the excess `busy`, and the backup ticket takes it. Find's own `busy` means the listener said it is full: step 1 never filters on `est`, which would hold a listener with many dialers to about `max_streams` new streams per report interval. Saturation returns `busy` without a server queue, and dialers back off with jitter.
- **Throughput.** One Find issues one primary ticket for one stream, so a sidecar dialer opens at most `sockets_control_qps` new streams a second per sockets process (50, burst 500; 9.10), and an edge process W2's 2,000 (§19.5), whatever c is. A listener takes at most `max_streams` over its mean stream time: a 256-stream listener with 100 ms streams takes about 2,560 a second. A lone sidecar dialer is therefore bound by its bucket, never by c: connection throughput is the lesser of the dialers' buckets and `max_streams` over the mean stream time, never concurrent-stream capacity alone (§22.5's one-dialer case).

### 9.8 The sockets service

Stateless processes keep all state in Redis Cluster, with no Postgres tables; §2.8's sock-1 to sock-5 give fields and TTLs, and `sock` hints are connect-4.

```text
{sg_<network_id>_<h16(name)>}  group HASH: per listener m: registration, r: in-flight, i: issued, e: ejection,
                               x: a removal's tombstone (9.5);
                               per dialer shares and exclusions; v: version; ZSET …ix orders the leases;
                               h16 is the first 16 hex digits of SHA-256
{svc_<listener_client_id>}     Service pairs (9.6), with the floor their last removal left
{sn_<network_id>}names         the listing index; entries leave with their leases; one field, which a listing
                               skips, holds the newest revocation sweep's claim
{sc_<client_id>}set            each client's set, ordered by name key for pages (9.5); expires 5 min after
                               the client's last call
```

Hash tags are per group (D-SOCK-7). A Find is one group-key script (check `v`, filter or sample, read two loads, increment one) plus a `{svc_}` write per edge ticket; counters are advisory, the listener cap authoritative. `server/cli/sockets` runs on every lb host, since each lb proxies only to its own; 100,000 listeners make about 6,700 registration calls/s. Only the service signs (vault `secret_files`, a yearly rotation with overlap; keys at `GET /socket/keys`). The ticket key file is written by `sidecarctl sockets ticket-keygen -out <file> [-in <file>]` (§19.4): it reads the existing file if `-in` names one, adds a new Ed25519 key that expires RotationInterval (365 days) plus KeyOverlap (1 day) after its creation, drops expired keys, writes the file 0600, refusing to overwrite unless `-in` names the same file, and prints no key; the operator runs it once a year in each environment and places the file in vault, and the block rereads it every minute (owner decision 354, whose 30 days owner decision 590 makes 365: a leaked key could forge tickets for up to a year, but a forged ticket alone admits nothing, since 9.6's steps 3 and 6 still check the session's source and the listener's reading of the config). Every listed key verifies until its expiry, and the newest settled key signs while it outlives `SignMargin`: a key settles `SettleTime` (10 min) after the later of its `created_millis` and the first read in which this process saw it, a per-process map keeping each key's first sight, so however long the hand placement takes it only delays the switch, and no ticket names a key a listener has not been given; a restarted process sees every key as new, so for its first `SettleTime` the oldest live key that outlives `SignMargin` signs, one every listener already holds, and blocks may sign under different keys for up to a reread interval, each of which every listener verifies; the command prints no placement deadline (owner decision 562). Each process caches each network's newest base and the entries after it from api (§8.9) and acts on what narrows it. On `{X}c_removed` (`server/model/client_close_model.go:64`) every process refuses the client's leases from memory at once and removes them with its pairs; after an entry that can narrow, which every statement kind is but those that only grant or admit, one process a network and position, by a claim in `{sn_}names`, sweeps the network's leases against its state, removes for cause those it refuses, with the pairs of a listener left with no edge entry, and sends `SocketHint`; a §21 suspension is refused from the kill set in memory. A sweep that dies leaves nothing wrong: each lease it did not reach is judged at its listener's next heartbeat and at any Find that picks it, and its pair ends by its TTL (DESIGN-DETAILS.md section 13). A process acts on a network's state only while it has no evidence older than 5 s that the authorization log passed it; past that it answers `unavailable` for that network until it has verified the new entries, and with no such evidence its last verified state serves without limit (§8.9; owner decision 337).

**Service tokens (owner decision 588).** The `/socket/*` routes take the 15-minute service tokens that evs, gkm and dns take: sockets is an audience of §7.8's exchange, which grants it to an admitted sidecar's client with no scope, and the block verifies a token offline, with no SQL, against the svc- JWKS it mounts as they do (`oauth-jwks-svc.json`), through `sidecarhost`'s Authenticator. The token names its client, the sidecar it acts for in `ur_sidecar_id`, which is the caller's §8 subject, its subject client in `ur_subject_client_id` and, in a team, its `member_id`. A removed client, a revoked sidecar and a removed member are refused through §7.8's signed `rev/` objects, which the block reads for the token's three subjects on the first metadata cluster (`sidecar.RevocationChecker`, cached at most 5 s), and through the removal and projection events above; a token's 15 minutes bound the rest. A token that does not verify, another audience's, an expired one and one a `rev/` object voids answer 401, as does a client token presented in a service token's place; a block with no cluster, or whose `rev/` read fails, answers `unavailable`. A Find still makes no Postgres call, but the exchange does, so sockets stops taking sidecars' new registrations and Finds about 15 minutes into a Postgres outage, as evs and gkm stop new sessions, where the earlier check ran about an hour; each sidecar makes one more exchange every 15 minutes (§19.10). This reverses owner decisions 347 and 497, under which sockets checked Client-class tokens against a verify-only by_jwt keyring and a Redis revocation record with no Postgres, and what served them: the `sidecar_id` claim `POST /sidecar/bind` re-minted into by_client_jwt (§5.6), the record's member and user fields (owner decision 561), sock-5's valid-check time, `revocation_record_enabled` as a step of sockets' rollout, and `sidecarctl jwt export-jwks` with its file (owner decision 578). None of them is built, and neither owner step remains.

**Edge clients' tokens (owner decision 589).** `urnetwork-edge`'s platform clients, which no sidecar binds and no exchange serves, get theirs from api: `POST /internal/gate/edge-client` (§13.6) answers, beside each client's jwt and only once that jwt's mint has found the client active, a 15-minute service token of audience sockets naming the client, with `network_id` and `ur_client_id` and no sidecar, member or scope, signed under the svc- set as the exchange signs. `server.NewPlatformClientSource` keeps it beside the jwt and renews both, and the edge hosts present it to sockets: tlsedge's and mxedge's router's Finds the first client's, and smtpedge's `ur/smtpedge` registrations each client's own. A removed edge client is refused by its client `rev/` object, which its removal writes, and the route's checks of block, host, slot and index still bound what a stolen edge bearer can mint (§13.6). api's removal finds an edge client by sidecar.yml's `urnetwork_edge`, and while its process has no good read of the file, the file there but unreadable or unparsable with no earlier read to keep, by the device spec `edge`, which the mint sets: one query in the removal's own transaction, run only while that read is marked, owes the `rev/` object for each removed client on an edge device in the client's own network, so I-15 holds whatever the file reads, sockets keeping its own good read through a broken push; a user device that names itself `edge` owes a harmless extra `rev/` object when removed then (owner decision 641). sockets so takes service tokens alone. Since the mint reads Postgres, an edge's token is not renewed while Postgres is lost: the source holds the last one until it ends, and the edge's Finds and registrations are then refused until api answers again (§19.10).

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
    Expires    time.Duration  // tls/ and smtp/: how long the grant asked lasts, filed as an absolute expiry held
                              // to the requests rule's maxExpiry; 0 takes its expiresDefault (§8.6; owner decision 687)
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
func (self *SocketListener) GrantExpires() time.Time         // when the grant a tls/ or smtp/ listen registered under ends:
                                                             // its action's expiry where a decision on that action
                                                             // activated the grant; zero for a name whose listen asks no
                                                             // grant and for one a standing grant passed
                                                             // (owner decisions 687, 792)
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

CLI (added to cli/UI.md): `ur socket`; `ur socket listen <addr> [<ip>:]<port> [--expires=d]` (to a local port; `serving=false` while it refuses; prints `ur approve <id>` for outward names, whose grant asks `--expires` as `tls_publish` does, the rule's `expiresDefault` when it is omitted; once it listens, its line ends `until <time>`, in RFC 3339, the end of the grant it registered under, as `ur bridge` names a forward's end, or says that a standing grant covers an outward listen with no end, and neither for an application name; `ur socket` prints the end beside each listen, both from the daemon's socket status, whose `grant_expires_ms` `socket.listen`'s reply and `socket.local`'s listing carry, left out where a standing grant passed the listen or its name asks none; owner decision 687); `ur socket dial <addr> [--listen=[<ip>:]<port>]` (a local forward: 0.0.0.0/:: unless `<ip>` is given, without the TLS-only rule; D-TRUST-8, owner decisions 84, 130; else stdin/stdout (`ssh -o ProxyCommand`); `ur socket ls [<net>]` (unseals names locally); `ur socket drain <addr>`. `ur bridge public-tls` (cli/UI.md:47) is `listen tls/443/<host>`; §16.5 maps the MCP tools.

**Share (D-SOCK-16).** `ur share add <path> [--count=n] [--expires=d]` hashes the file, writes the record below, listens `exclusive` on `share/<token>` (`<token>`: 16 random bytes, lowercase base32) and prints the link `<net>:share/<token>#<k>`, whose fragment `k` is base64url(the sharer's `sidecar_id` ‖ a 256-bit secret). An omitted `--count` means one use, `--count=n` n, and `--count=0` unlimited uses until the expiry; with `uses` 0 only a Remove or `expire_millis` ends a share, since the end row's Done for each of `uses` Reserves cannot fire. `--expires` defaults to 24 h, and `ur share add` refuses more than 30 days, the longest ordinary grant (owner decision 74), so every share ends. `ur share get <link> <out>`, which also takes `-` for the link and then reads it from stdin, so that the link's reusable secret stays out of argv, `ps` and shell history (owner decision 336), dials from a sidecar of the sharer's network, the only one an application name reaches (§6.4), and before OPEN refuses a listener whose verified `sidecar_id` is not `k`'s. `ur share` blocks and lists live shares with their remaining uses and expiry; `ur share rm <token>` ends one early (`--expires` and `rm` added to cli/UI.md). Records survive restarts, but a share is served only while the sharing sidecar runs (the daemon stays up while one is live, §5.8), as the CLI and `ur status` say. Both ends need §8's `listen` and `dial` on `share/`, which the implicit document gives untagged subjects; bytes count toward the network's transfer balance like any same-network stream (§20.6).

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
end     a Remove, a Done for each of `uses` Reserves, or expire_millis (by timer, read again after a sleep or
        a clock step, §17.8 and owner decision 798, and at start for a sharer offline then): reset the
        share's streams, unlisten and delete the record
```

Served uses never exceed `uses`, counted by Reserves, and no get starts, resumes or keeps streaming at or past `expire_millis`; a crash or a lost stream never frees a Reserve (burn on uncertainty), and only its own getter resumes it.

### 9.10 ACL, quotas, abuse, identity, metrics

- **Gates (X3, D-SOCK-14).** The service checks each registration and Find against the network's newest verified id-only projection (§7.9, §8.9; owner decisions 5, 72): `listen` and `dial` rules over subjects and token paths, `tls/` publish and `smtp/` listen grants, grant ids and expiries. Requested grants count once their GrantActivate enters the authorization log (§7.9; owner decision 74); edge listens need one or a standing grant (I-8). Edge Finds run as `autogroup:public` on `tls/` (§13.5), passing under any publish grant for the host, whatever its audience: the gate reports the audience and judges neither it nor a raw link's pin, which the listener's front does from its own evaluation (§8.10, §13.7; owner decision 348), so a members visitor without a session reaches §7.8's edge login at the front and a link URL's token is traded for its cookie; they check the receiver's `listen` on `smtp/` (§15.4). For §13.9's system publish `tls/443/mta-sts`, each receiver's own approved `smtp/25/mx` listen grant stands in for the `tls/` listen and publish grants at registration, Find and admission, and its expiry or revocation ends that receiver's publish. Without a policy document, the implicit one gives untagged subjects `dial` and `listen` on every application name, disclosed (owner decisions 105, 120). Both ends re-derive the grant (9.6), and revocation resets its streams.
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
| Edge-delegated ticket keys | Edges survive a sockets outage | Keys on edge hosts; C9 still needs Redis | [Later](DESIGN-DEFER.md#sock-edge-delegated-ticket-keys) |
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

**D-SOCK-9 (proposed).** Delete registrations on `{X}c_removed`; keep no per-dial record beyond §2.8's sock-2 fields (≤300 s) and sock-3 pairs, a `tls/` or `smtp/` pair at most 15 min past its listener's last accepted registration and a `ur/` pair its service's grant length (owner decision 338). *Why:* reuses the removal signal; minimal metadata.

**D-SOCK-10 (proposed).** Host the engine as `server/cli/sockets`, its routes authorized by a 15-minute service token of audience `sockets` (§7.8, 9.8; owner decision 588, which reverses the Postgres-free check of Client-class tokens that owner decisions 347 and 497 gave them). *Why:* registration load stays off `api`, and sockets authenticates as evs, gkm and dns do.

**D-SOCK-11 (proposed).** Platform services listen as `ur/<service>` in `urnetwork-edge`, authorized by the service. *Why:* sidecars reach smtpedge through the same Find and Service path.

**D-SOCK-12 (proposed).** Edge tickets bind one of the caller's K clients, and edge Finds write the `{svc_}` pair authorizing C9 until the grant ends, a `tls/` or `smtp/` pair living at most 15 min past its listener's last accepted registration (owner decision 338); source equality holds for edge tickets too, and only the Hello check is waived (9.6). *Why:* step 3 stays exact; contracts outlive the ticket, not the grant.

**D-SOCK-13 (proposed).** Send names outside `tls/`, `smtp/` and `ur/` only as 9.4's HMAC token paths, sealed for listings, under the config repo's `K_sock`, rotated on §11.6's triggers. *Why:* owner decision 67, built like evs paths (owner decision 2); prefix grants still work.

**D-SOCK-14 (proposed).** Gate registrations and Finds on the signed id-only projection (§7.9, §8); listener and dialer each re-derive the grant from the config repo. *Why:* owner decisions 3, 6 and 72: a breached server can only deny or delay, within §2.8's exposure bound.

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
- **API routes** (Client class, authorized by a service token with aud `sockets`, 9.8; owner decision 588): `POST /socket/registrations` (Client; 9.5, pages of ≤1,024 entries; statuses, `server_time`, keys); `POST /socket/find` (Client; 9.6, errors 9.9; platform callers add K client ids); `GET /socket/list` (Client, same network; token paths, edge and sealed names); `GET /socket/keys` (Public).
- **Tables:** none (9.8's Redis keys, behind `SocketStore`).
- **Services and config:** `server/cli/sockets`; vault ticket keys; the svc- JWKS and the first metadata cluster's `rev/` objects, read only (9.8); pro.yml `tls_endpoints`; `sockets_control_qps` and `urnetwork_edge` (the `urnetwork-edge` network id) in `config/<env>/sidecar.yml` (§6.10.1, §19.11).
- **Assumptions about other sections:**
  - §4.5's engine stores include `SocketStore`, with field TTLs and an atomic pick-and-increment.
  - §7.9's projection lists Team scopes (9.4); §11.6's REMOVE generations are the key-holder changes 9.4 classes, authorization expiries among them, though §11.6 batches every path epoch.
  - §13.7 dispatches on `AppMode` (D-TLS-13) and defines a raw endpoint's `link` check; §20.7's `OverLimit` lists spent networks within 5 s.
  - §22.5's §9 row tests 9.5's pages, 9.4's vectors, 9.9's share and 9.7's clamp (owner decision 551).

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
| Dialers inflate `est` or report falsely | Medium | Medium | 9.7's per-dialer share cap and decay; step 1 filters on the listener's own report, so `est` never refuses; two-network ejection, for `ur/` names |
| One dialer's burst of short connections reaches one listener past its real load until the listener's next report, since that dialer's tickets count at most c in `est` | Medium | Low | The listener's `max_streams` admission and the backup ticket; eager reports at most every 2 s (9.5, 9.7) |
| A leaked share link lets any sidecar of the network redeem its remaining uses until it expires | Medium | Medium | `--count` (one use when omitted; with `--count=0` only `ur share rm` or the expiry ends it); `--expires` (24 h default); `ur share rm`; each Reserve names the getter; `ur share get -` reads the link from stdin |

### 9.17 Phasing

- **v0 (§23 M5):** the `sockets` service with 9.10's bounds; blinded application names; `tls/` with §13, `AppMode` included; tickets, P2C and 9.7's per-dialer clamp on `est`; `SocketHint`; the Go API; `ur socket` and `ur share`; MCP tools. Blocked by §6 streams, §5 identity, the config repo and projection (X3, M2) and §4's C9.
- **v0, mail track:** `smtp/` with §15 (M7); `ur/` once §14 passes D-SMTP-16's gate, DATA mode included (M9; owner decisions 35, 99, 125).
- **v1 (M6):** affinity, with §13; Team scope hosts (owner decisions 40, 55, 58), the `smtp/` ones with §15.
- **Later:** [region-aware selection](DESIGN-DEFER.md#sock-region-aware-selection) (one lb site today, [R:ext-edge] §5 R8), [slow start](DESIGN-DEFER.md#sock-slow-start), [edge-delegated ticket keys](DESIGN-DEFER.md#sock-edge-delegated-ticket-keys), [registration over push](DESIGN-DEFER.md#sock-registration-over-push).
- **Deferred:** DESIGN-DEFER.md holds an entry for each Later item, linked above, and for [this section's v1 set](DESIGN-DEFER.md#sock-v1) (owner decision 587).
