## 13. The TLS edge and certificates

### 13.1 Purpose and scope

This section owns the public path to published names: the lb's SNI split and ports, `tlsedge` and its connect identity, the sidecar's TLS front, certificates and the CT watch, endpoint counting, abuse hooks and `ur bridge public-tls`.

Under X1 (decided, §0), TLS ends only in the listening sidecar; `tlsedge` routes by SNI without a user key. §9 owns Find, §6 streams and contracts, §8 grants and owner consent, §12 records and the dns edge, §19 lb rendering, §20 payment and §21 abuse policy.

### 13.2 Requirements

| Id | Requirement | Source |
|---|---|---|
| R-TLS-1 | lbs forward network names (`*.<root>`) to tlsedge, unterminated | PLAN.md:81, :84 |
| R-TLS-2 | tlsedge opens a client on a network, finds a listener and accepts over the subprotocol | PLAN.md:82 |
| R-TLS-3 | Certificates are automatic for each listened endpoint | PLAN.md:84 |
| R-TLS-4 | Edge sees only encrypted bytes and small headers (SNI); key stays in the sidecar | owner directive 2026-11-03; sidecar/design/pitch5.html:699 |
| R-TLS-5 | Explicit, authenticated by default, short-lived; no agent control panels | sidecar/design/pitch5.html:698 |
| R-TLS-6 | TLS edge 1/20/200; usage counts toward transfer balance; custom domains Team only | PLAN.md:353, :358, :364 |
| R-TLS-7 | `ur bridge public-tls hostname:[local ip]:local port`; TLS only; Let's Encrypt | cli/UI.md:47, :106, :120 |
| R-TLS-8 | No client IP logged; removal revokes the device's certificate; CT watched | §2 I-13, I-15, D-TRUST-6 |
| R-TLS-9 | Shared lb addresses; TCP 443, 8443, 8883 and 5671 | owner decisions 34, 68, 121 |

### 13.3 What exists today

**lb.** Each interface runs its own nginx (vault/main/services.yml:338-475): http servers bind `443 ssl` (warp/warpctl/config.go:1857-1863) and key their limits on `$binary_remote_addr` (:1496-1545); stream servers send PROXY v1 (:2508-2510), idle out at 15 min (:1383) and take `tcp_stream_port_services` (warp/services/services.go:558). `ssl_preread` is compiled in, unused (warp/lb/Dockerfile:58). Host networking rewrites IP `listen`s, not `unix:` ones (warp/nginx.go:354), behind per-interface DNAT (warp/warpctl/run.go:3126-3136).

**ACME.** The extender chain orders by DNS-01 with the client's CSR, revokes, caps weekly orders with Retry-After holds and renews at two thirds of the lifetime, lacking ARI (server/taskworker/work/extender_measurement_acme.go:34-36, :232-335; extender_measurement_work.go:384-392).

**Missing:** the split, tlsedge, certs, the front, a CT watch, ARI, the Service mode (§4 C9) and an in-place lb reload (warp/nginx.go:51-79 only drains nginx, on SIGQUIT or SIGTERM).

### 13.4 Ingress: the SNI split, ports, PROXY, port 80

```text
visitor --TCP 443--> any lb interface (shared, owner decision 34): nginx stream server, ssl_preread
    SNI under <root>, or an active custom host --PROXY v1--> tlsedge --POST /socket/find--> sockets (§9)
    other SNI, or none --PROXY v1--> unix socket --> http servers (platform names, as today)
tlsedge ==§6 stream, Required, Service mode==> listening sidecar (TLS ends here) --> [local ip]:local port
```

**The split (Q-TLS-1, owner decision 34).** A stream server takes TCP 443 on every interface, ahead of the http servers (§19 W1):

```nginx
# stream {}. Exact names win, then the longest wildcard, so platform names left under <root> keep
# working until §12.4's move. warpctl refuses to render a <root> name absent from §12.5's reserved
# list; W1's generator refuses a custom host under <root> or a platform domain.
map $ssl_preread_server_name $tls_split_upstream {
    hostnames;
    ur.network        lb-https;  # the apex, which redirects to ur.io (§12.4)
    <platform-name>   lb-https;  # generated: each name the http servers serve under <root>; none after
                                 #   §12.4's move. www is reserved (§12.5): tlsedge answers it
                                 #   unrecognized_name.
    *.ur.network      stream-service-block-tlsedge-443;
    include /run/warp-lb/tls-custom-hosts.map;  # generated: one "<host>.<domain>
                                 #   stream-service-block-tlsedge-443;" per active custom host (§12.8),
                                 #   and one for the map version's probe name (custom hosts, below)
    default           lb-https;  # platform names, unknown SNI, hellos without SNI
}
upstream lb-https { server unix:/run/warp-lb/https.sock; }
server {
    listen 443 reuseport backlog=65535;
    listen [::]:443 reuseport backlog=65535;
    ssl_preread on;
    preread_timeout 10s;         # tlsedge's ClientHello deadline (13.5)
    proxy_protocol on;           # PROXY v1 to both branches
    proxy_pass $tls_split_upstream;
    # proxy_buffer_size: 16k by default, two buffers per session; the gate sizes it. connect's H1
    # transport, which carries pushes and relayed sidecar traffic, passes here; H3 keeps UDP 443.
}

# http {}. Every 443 listen moves to the socket (options on the first server only, as today): host
# networking rewrites IP listens (warp/nginx.go:338-431), and `pass` cannot carry preread bytes
# ([R:ext-edge] §2.7). realip restores $remote_addr and $remote_port from PROXY
# (src/http/modules/ngx_http_realip_module.c:238-239 at the lb's pinned nginx commit), so the
# interface's 450/min zone, net_connections cap and exclude_subnets keep their per-visitor key and
# X-UR-Forwarded-For is unchanged; without it, every visitor would share one key.
listen unix:/run/warp-lb/https.sock ssl proxy_protocol backlog=65535;
set_real_ip_from unix:;          # only the stream server reaches the socket
real_ip_header proxy_protocol;
```

**Custom hosts (D-TLS-12; Team, v1).** `network_dns_custom_host`'s active rows (§12.8, a strong-mode host entering only once certs' walk and probe pass, 13.8) say what the lb should route; whether each lb interface does is a separate, reported state.
- **Versions.** Each change to the active rows, §12.6's restore step included, raises the custom-host map's version in its transaction, its digest being the SHA-256 of the version's sorted host list, and an entering host keeps that version as its `map_version`.
- **Loading.** Beside each lb interface's nginx, §19 W1's `lbmap` loads the newest version: before nginx serves 443 at start, and otherwise 5 s after the first unapplied version, at most once per 15 min, since each reload keeps the old workers, with their connections, for up to `worker_shutdown_timeout` (60 min; warp/warpctl/config.go:1181). It renders `tls-custom-hosts.map` and the port-80 redirect's custom names from that version's rows, plus one line sending the version's probe name, `<digest[0:12]>.map.probe.invalid` (RFC 6761 §6.4), to tlsedge, runs `nginx -t`, reloads, and reports the version loaded with its nginx master's pid and start time (`POST /dns/internal/custom-host-map/applied`, §12.8); a failed render, test or reload keeps the prior map and is reported. Its long-polls repeat the report, and an interface whose `lbmap` has not polled for 2 min, or whose nginx master has changed since its report, has loaded no version.
- **Route probes.** Every 10 s each dns edge sends each interface, on 443 as a visitor would, ClientHellos offering ALPN `ur-route-probe` then `http/1.1` for the probe name of the version that interface reported, and, once per reported version, for up to 16 hosts it added (§12.6). tlsedge answers each `unrecognized_name` with no Find (13.5), while the http branch would select `http/1.1` and present a platform certificate (warp/warpctl/config.go:1851-1887). An interface is current for a version once it reported that version or a later one loaded, an edge's probe of the reported version's probe name passed within the last 2 min, and the latest probe of each added host probed for the reported version passed, a failing host probe repeating every 10 s until one passes.
- **Ready.** A host is ready once every lb interface that §12.6's probe passes is current for its `map_version`. `GET /network/dns` shows a host that is not as pending, naming those interfaces, and `GET /dns/zone` shows a sidecar the hosts it publishes or administers the same way (§12.8), and devices start a TLS-ALPN-01 order, a renewal's included, only while it is ready (13.8); DNS-01 orders never wait. Readiness is an operational target, about 15 min and paged past 20 min (§19.8), not a timer.
- **Map-stale.** An interface that is not current for every version older than 20 min is map-stale: the dns edges drop it from user-name answers as they drop a failed one, never all (§12.6), and it pages until it is current again. A strong-mode host with static addresses misses that drop, as it misses every health drop (§12.8), and a host added meanwhile stays pending, naming the interface.

Until the reload, tlsedge answers a host that left the active rows `unrecognized_name` from §12's map (13.5). *Invariant:* a ready custom host's ClientHello reaches tlsedge on every interface that §12.6's probe passes, and platform, user, unknown and absent SNI route as before (§22.8 FS-35, FS-122).

**Gate.** Before any interface flips, §22 benches split against unsplit nginx on one test interface at the observed peak and at `concurrent_clients` (786,432; vault/main/services.yml:357): ≤5% less throughput on connect's H1 transport, ≤1 ms more p99 for connect and api, head-to-hint p99 ≤2 s, ≤15% more CPU per Gbit/s, memory within headroom. Nothing flips until it passes.

**Rollout** (§19 W1). `warpctl deploy main lb <version> <block>` (warp/warpctl/main.go:66-68) flips interfaces to the split one at a time. Each first runs it drained, out of DNS answers by sidecar.yml's `drained`, the one list `warpctl dns` and the dns edges both read, `warpctl dns` leaving the interface out of the `<env>-lb` sets while keeping its health checks, so only probes and the gate's bench reach it; it then rejoins and is held 24 h against unsplit ones on the gate's metrics. Until launch, only internal and design-partner networks publish (owner decision 91).

**Probes.** An interface that does not answer a hello for the reserved `probe.edge.<root>` with tlsedge's `unrecognized_name` leaves user-name answers (§12.6); monitor's verified handshake and §19 W7's HTTPS checks with SNI drop a broken one from platform answers. From M5 a failing probe pages at any hour (owner decision 143). The `probe.edge.<root>` hello cannot test the custom-host map, since the `*.<root>` wildcard routes it whatever the map holds; the dns edges' route probes (custom hosts, above) do, and from M6 a map-stale interface leaves user-name answers and pages too.

**Ports.** 8443, 8883 and 5671 (owner decision 121) go unsplit to tlsedge as permanent stream ports (§19 W7), since no platform name uses them (vault/main/services.yml:339-341); tlsedge takes the port from its accepting listener, as DNAT rewrites PROXY's destination.

**PROXY.** tlsedge's listener (§4.5) takes PROXY v1 or v2 only from the lb, dropping connections without it: `tlsedgeservice.NewProxyHeaderListener` holds pires/go-proxyproto on the engine leg, server/cli/tlsedge applies it, and server/cli/mxedge may call it, since server may import both engines. The visitor address feeds caps, §9's affinity key (a keyed /24 or /48 hash) and `TlsEdgeOpen.client_ip`; logs drop IP literals (server/scrub.go:112; §19.4).

**Port 80** stays with the http servers: a generated server for `*.<root>` and the active custom hosts redirects to `https://` and logs nothing (I-13), so no plaintext reaches tlsedge and HTTP-01 is never served.

### 13.5 tlsedge: the connection path

1. Read the PROXY header and TLS records until the ClientHello completes; a bounds-checked parser (`tlsedgeservice/clienthello.go`, after connect/ip_sni.go:331-462) extracts SNI, ALPN and ECH presence; a hello that does not parse gets `decode_error` and a close. `ReadClientHello`, `ParseClientHello`, `NormalizeSni` and `WriteTlsAlert` export from `tlsedgeservice`, and server/mxedgehost passes them into `MxEdgeDeps` as functions, so no engine imports another (§15.4). A hello whose ALPN list includes `ur-route-probe` gets `unrecognized_name` at once, whatever its SNI, with no lookup, Find or record: it is 13.4's route probe.
2. Normalize the SNI (lowercase, no trailing dot, LDH) and map it with the listener's port to `(network_id, tls/<port>/<host>)` through §12's label map, held in memory by `TlsEdgeStore`: a full snapshot at start, then `model.DnsLabelMapSince` every 5 s, so a withdrawn name stops mapping within 10 s, read through tlsedge's restricted Postgres role off the path (§19.4), a process that cannot load its first snapshot staying not ready and a running one keeping its last through a Postgres outage, so no connection path touches Postgres (I-12; owner decision 495); (`<host>.<x>.<root>`, or `<x>.<root>` as `@`, `<x>` a label or live alias) or custom-host map; deeper names match only v1 scope hosts, `<label>.<scope>` (Q-TLS-3).
3. Check, in memory, the kill switch, the caps (13.9) and a 30 s negative cache of `no_listener` and `denied`, which absorbs scans, keyed on (name, port, sorted offered ALPN set), so one scanner's bogus ALPN cannot refuse every visitor to a name. A network's limits load in the background through `ServiceHost.Quota.Limits`, cached per network; until they arrive it gets Community's caps, never a refusal, and the kill switch waits on none of it.
4. Call Find (§9.6) as `autogroup:public` with the offered ALPN ids in hello order, as many as keep the encoded `TlsEdgeOpen` within 512 B, the list `TlsEdgeOpen` carries, an affinity key and the process's K client ids; Find applies §8 `MayPublish` (for 13.9's system publish, the receiver's `smtp/25/mx` listen grant, §9.10) and `MayDial` and returns primary and backup tickets, each naming the tlsedge client that opens it.
5. From that client, send `StreamOpen{target, metadata: TlsEdgeOpen, ticket, early_data}` with the hello's first 2,048 B (§6.7), the rest of a longer (PQ) hello following at once in StreamData within the initial window, not after the accept. §9's retries finish before the visitor's first byte, showing only as delay; tlsedge blames a listener only for an accept timeout, never for a visitor's reset.
6. Splice under §6 credit; FIN maps to StreamClose, RST to StreamReset.
7. On failure, send a plaintext alert before any ServerHello and close: `unrecognized_name` for unknown, unpublished, denied or killed names, which are indistinguishable; `decode_error` for a hello that does not parse; `internal_error` for no listener, busy, quota, a cap, the gate off, an unready map or overload. A Find that finds no listener for the offered ALPN keeps `internal_error`, since no application byte moves and FS-34 holds; 13.7's `no_application_protocol` covers hellos that reach the front. tlsedge never presents a certificate.

```proto
message TlsEdgeOpen {              // StreamOpen.metadata, edge -> listener (§6 0x1501), <= 512 B
  bytes client_ip = 1;             // 4 or 16 B, from PROXY; edge memory only
  uint32 client_port = 2;
  string server_name = 3;          // normalized SNI
  repeated string alpn = 4;        // offered by the visitor, in hello order, cut to keep this message <= 512 B;
                                   // informational: the listener decides from the real hello, so a hello whose
                                   // only matching id was cut finds no listener
  uint32 client_hello_byte_count = 5;
  bytes connection_id = 6;         // 16 random B; joins abuse reports for 24 h
  uint64 expire_time_millis = 7;   // the ticket's grant_expire_time_millis; streams end here
}
```

A listener trusts `TlsEdgeOpen` only when admission step 3 passes and the ticket's `dialer_network_id` is `urnetwork-edge` (§9.6).

```yaml
# config/<env>/tlsedge.yml (sketch; endpoint and visitor caps are pro.yml's, 13.9)
clients: 4                                          # K (13.6)
max_connections: 50000                              # per process (13.9)
blocks: 4                                           # required, >= 1: the lb hosts running tlsedge, each host's
                                                    #   g1 block once and its beta block not at all; caps divide
                                                    #   by it (13.9); it has no default, and tlsedge refuses to
                                                    #   start without it
proxy_header: {timeout_s: 2, max_bytes: 2048}
client_hello: {timeout_s: 10, max_bytes: 16384}
find: {timeout_s: 2, max_finds: 3}                  # D-SOCK-6
accept: {ticket_timeout_s: 5, setup_timeout_s: 15}
idle_timeout_s: 900                                 # the lb's proxy_timeout
drain_s: 600                                        # a deploy's old process drains, then resets, on its own slot's
                                                    #   clients (13.6); streams end at grant expiry
```

§22 targets (p95): setup adds ≤300 ms warm and ≤1.5 s cold, contract round trip and e2e handshake included.

### 13.6 tlsedge as a connect client

Each tlsedge process runs K connect clients in the platform network `urnetwork-edge` (§4's `ServiceClientSource`), Required and relay-only toward sidecars (D-PROTO-6), so `TlsEdgeOpen` rides only sealed streams; Find's tickets pin each listener's edge streams to one of them, spreading load across K inline readers (§9.6; [R:connect-transport] §2.4).

**Edge clients (owner decisions 428, 577).** An edge block, tlsedge, mxedge's router or smtpedge, mounts no vault and no network-level token: it holds the `edge` class's bearer for api's internal gate surface (§8.9), 256 random bits with current and previous values in its `secret_files`, read once at start, api holding only its SHA-256, the block's file and api's line both written by a `sidecarctl` command the owner runs (§19.4; owner decision 638). `POST /internal/gate/edge-client`, which takes only that class, answers a short-lived client jwt, beside it the 15-minute sockets token the edge's Finds and registrations present (§9.8; owner decision 589), and the url the pool needs for one client of `urnetwork-edge`, whose id api derives from (environment, host, block, slot, index) by a fixed, documented derivation and creates on first use; it refuses a host the environment's config does not name, an index at or past the block's K and a slot at or past the slot count, 4. `server.NewPlatformClientSource` asks for each of its K indexes at start and refreshes each jwt before it lapses, the jwt's life and the refresh point being settings, so a restart reuses its ids and the edge keeps no state. Each client's connect identity is as stable as its id, by derivation (owner decision 689): the source also answers a 32-byte seed per client, HKDF-SHA256 of the block's current edge bearer with info `urnetwork-edge-client-identity-v1`, 0x00 and the client id's 16 bytes, which only the block can make, since api holds the bearer only as its SHA-256, and `EdgeClientPool` derives from the seed, each by HKDF-SHA256 under a label of its own, the client key seed, an Ed25519 sequence certificate on a fixed template, its serial from the seed and its validity RFC 5280's for a certificate with no well-defined expiry, the same bytes at every start since Ed25519 signs deterministically, and the Service provide secret key, which the platform installs before the client can receive. A restart, or a deploy into a used slot, so presents the client key, certificate and HMAC key the id had, and listeners' cached contracts, certificate commitments and key pins stay valid, which is connect's restart path, the one the sdk takes, so a restart files no bad-contract audit against a healthy listener; mxedge's router and smtpedge share the pool and keep theirs alike. The bearer adds no root of trust, since it already mints these clients; a rotated bearer is a new identity for each client once, the first start after it recovering on connect's own timeouts; and the seed and what derives from it stay in the process, never logged (I-7). Every process of an edge service on a host holds its own slot: the beta and g1 blocks of tlsedge, and of mxedge's router, run side by side on every lb host (§19.4) and pass the same environment, host and block, so warp gives each new process (`WARP_SLOT`, beside `WARP_BLOCK`) a slot that no running process of that service on the host holds, listing them by the `warp.env` and `warp.service` labels, not the name prefix, which mxedge-platform's containers share, and server's `EdgeClientKeySettings` and warp's `DeploySlotSettings` both count 4 slots (owner decision 577). The beta and g1 processes, and a deploy's old and new process of each, so hold different clients: the new process connects its own K while the old one drains its streams for `drain_s` (13.5), each counting only its own toward readiness; `urnetwork-edge` holds at most four times K clients a block and host, and a stolen edge bearer mints only its environment's fixed edge clients. taskworker's reap of idle top-level clients (`RemoveDisconnectedNetworkClients`) leaves the clients of sidecar.yml's `urnetwork_edge` out of its idle marking, so an edge slot unused for 30 days can still be deployed into and the mint finds its derived clients active; the set stays bounded by the config, an operator's removal still ends a client, and a host dropped from the config keeps its clients until an operator removes them (owner decision 591). The marking holds off while taskworker's process has no good read of sidecar.yml: a config that came from a failed first read, the file there but unreadable or unparsable with no earlier read to keep, marks nothing in that run, the reap's other passes running as before, while an absent file still lets the marker run, since the environment then has no `urnetwork_edge` to protect. The marker so fails in the direction that loses nothing, as the reader's gates do, sidecar.yml stays the only source for the edge network, and ordinary idle clients wait for the first good read, minutes against a 30-day threshold (owner decision 622).

Contracts in both directions use §6.10.1's Service mode (C9; owner decision 11), issued only while §9's Find-recorded pair lives.

A sidecar provides Service only while it holds a `tls/` or §15 `smtp/` registration, or while it holds a `ur/` stream, from a `ur/` ticket's open until its last `ur/` stream ends (§6.10.1 item 2; owner decision 298), within §6.7's edge-peer budget; above half of GOMEMLIMIT, new streams open at 64 KiB windows. Sidecars get `TlsHint` (orders, issuance, revocation) on topic `tls`, and suspensions through `sock` (§9.5).

**Accounting (X11, owner decision 10).** tlsedge spends §20.6 leases (meter `tls`) for the listening network (PLAN.md:353); bytes per host exist only in 13.9's 24 h records. An empty balance refuses new connections (Find `quota`) and resets open streams with QUOTA.

### 13.7 The sidecar's TLS front

The `tls` component (§5; files `tls_*.go`) accepts streams for its `tls/` registrations and runs `crypto/tls` over the `SocketConn` (§9). It alone enforces §8's `audience`, which a modified sidecar skips (§21.4).

| Concern | Rule |
|---|---|
| Versions | TLS 1.2 and 1.3; X25519MLKEM768 first |
| Slow visitors | Handshake within 10 s; first HTTP request within 30 s; one visitor /64 or /32 holds at most 1/8 of the endpoint's concurrency |
| Dispatch (D-TLS-13) | By the signed registration's `AppMode` (§9.5), never by ALPN's absence. `http` (default): `h2`, `http/1.1` or no ALPN reach the HTTP front; any other id fails the handshake with `no_application_protocol` (RFC 7301 §3.2). `raw`: a decrypted TCP forward for the declared ids or none, registered only under `public`, where the local service authenticates, or `link`, where the front requires a client certificate whose SPKI SHA-256 equals the publish grant's `link_spki_sha256` (§8.4), over TLS 1.3 so the edge never sees it. `acme-tls/1` reaches only the TLS-ALPN-01 responder. Whatever the ALPN, no application byte reaches the local service before its audience check (§22.8 FS-34) |
| 421 | Host and `:authority` must equal the SNI (RFC 9113 §9.1.1), since browsers coalesce a network's hosts on one wildcard and address set |
| HTTP/3 | None; upstream `Alt-Svc` h3 entries are stripped |
| Visitor address | To the local service only on request (PROXY v2 or `Forwarded`) |
| Audience (owner decision 42) | `members` (default): §7.8's edge login, checked against the front's config (§7.9; issuer trust: §2.8 EX8). `members-device` adds a §6 `Signed` (purpose `edge-login`) over origin and nonce by a member's consented device (§8.5), via the app or extension (§18). `link`: a signed link, reusable until its grant ends, traded for a cookie (below; `raw`: the pinned client certificate). `public`: explicit, e.g. webhooks. Members on URnetwork may also reach a service over the overlay by §17's own rules, its private name or overlay address (§12.9) with a §17.6 map or route grant to the local port, which adds no listener, audience or authentication path and passes no front, tlsedge or edge login (v1, with M6's `ur tun` on macOS and Windows) |
| Other origins (§12.4) | Session cookies (`__Host-ur-session`, a `link` cookie) count only on `Sec-Fetch-Site: same-origin` or `none`, or top-level GET or HEAD navigations (`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`); without Fetch Metadata, only with no `Origin` or the host's. Other requests, from the network's other hosts too, arrive anonymous (edge login under `members`). Browsers without Fetch Metadata (before March 2023: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site) still send them on other origins' GETs (§2.10) |
| Reach receipts (owner decision 25) | §16.8's `ReachReceipt` per publish grant, visitor, server name and 5 min: the SNI, in `server_name` (owner decision 465), and a keyed `client_ip` hash (v1), HMAC-SHA256(k, family ‖ the /32 or /64 prefix's address bytes)[:16], k = HKDF-SHA256 of the front's session root, salt the network_id, info `urnetwork-sidecar-v1/tls-front-reach`, stable across windows and restarts, since it names a visitor only inside the author's sealed record (owner decision 431) |
| Control panels | Refused and recorded for the daemon's API or MCP port and for targets that answer like agent UIs (§16's list) |
| Interstitial | A one-time browser notice on Community `public` endpoints ([R:ext-edge] §2.8), never on 13.9's system publish |

**Link tokens (owner decision 422).** A link is a `TlsLinkToken` (below) in a §6 `Signed` (`SIGNED_TLS_LINK` 0x1503, purpose `tls-link`) by the publishing device's identity key, `expire_time_millis` at most the grant's expires, at `https://<host>/.well-known/ur/link?t=<base64url(Signed)>`. The front verifies the signature against the projection, that the signer is the sidecar the grant names, that `grant_id` is active and that `host` equals the SNI, then sets `__Host-ur-link` (HttpOnly, Secure, SameSite=Lax, 12 h, capped by the token's expiry) holding the same token and answers 302 to `/` with `Referrer-Policy: no-referrer`. Any listener of the grant honors it with no shared state, and a GrantRevoke or the grant's expiry ends every link of the grant.

**Members-device logins (owner decision 431).** The statement is a `TlsEdgeLogin` (below; `SIGNED_TLS_EDGE_LOGIN` 0x1502, purpose `edge-login`), `origin` as the front writes it, `https://<sni>` with `:<port>` only where the port is not 443, and `nonce` 32 random bytes the front draws, with no network_id. After the ID token checks out, the callback seals `{nonce, member_id, expiry, return path}` into `__Host-ur-device-pre` (`DeviceLoginLifetime`, 10 min) and answers 302 to `/.well-known/ur/device`, whose GET answers `{origin, nonce}` and whose same-origin POST of field `s`, the base64url `Signed`, completes the login with 303 to where the visitor began; the nonce leaves the pending set only once a statement verifies, so a login completes once. The signer is `AclState.ConsentedFor(signer, member)`, and not read_only, suspended or revoked. `__Host-ur-session` gains the device's sidecar_id: a device session counts on a `members` endpoint, a `members` session never on a `members-device` one, and consent and membership are checked on every request. `Sidecar.SignTlsEdgeLogin(origin, nonce)` answers the encoded `Signed` under the sidecar's consented untagged admission, and §18's `SignEdgeLogin` decodes base64url and passes the asking page's own origin, never one the page names; a remote-mode app reaches it through §5.8's Confirm method `tls.edge_login.sign`, which TLS owns and the daemon answers only for a confirmed call (owner decision 489). Members reach a service over the overlay by §17's rules alone, as the audience row says.

```proto
// sidecar/protocol/tls.proto: the front's two statements, each the body of a §6 Signed by a device's identity key;
// neither reaches a server, each traveling between the visitor and the front inside TLS
message TlsLinkToken {           // SIGNED_TLS_LINK 0x1503, purpose tls-link, by the publishing device (link tokens)
  bytes grant_id = 1;            // the publish grant's rule_id
  string host = 2;               // the link's host, which the front holds to the SNI
  uint64 expire_time_millis = 3; // at most the grant's expires
  bytes nonce = 4;               // random, so two links of one grant differ
}
message TlsEdgeLogin {           // SIGNED_TLS_EDGE_LOGIN 0x1502, purpose edge-login, by a member's consented device
  string origin = 1;             // https://<sni>, with :<port> only where the port is not 443, as the front writes it
  bytes nonce = 2;               // 32 random B the front draws, taken once
}
```

### 13.8 Certificates

| Property | Choice |
|---|---|
| Identifier set | `{*.<net>.<root>, <net>.<root>}`: every one-label host, `mx.<net>` included (§15); CT shows only the opaque `<net>` (X5). Network-level devices add each live alias's pair, which §12 answers once a device holds it. A Team scope's devices (member or tag, Q-TLS-3; its mail receivers too) hold only `{*.<scope>.<net>.<root>, <scope>.<net>.<root>}` (owner decisions 40, 58); a member scope's set goes only to its member's consented devices (§8.5; owner decision 126); certs takes a scope, and the member or tag whose devices hold its set, only from the verified projection, which carries an Owner's or Admin's signed declaration of it, never from a hostname or a grant naming a scoped host, and a label keeps its first member or tag, so no declaration hands a scope's set to another member or tag while [a reassignment's consent rule](DESIGN-DEFER.md#acl-team-scope-reassignment) waits (§8.8's Team scopes; owner decision 678) |
| Key | P-256 per listening device, sealed in its keychain (§5): never exported, in evs or on a server. One certificate per device, so I-15 is one revocation. Rotated every 180 days, on suspicion, or on request |
| Ordering (Q-TLS-2) | `POST /tls/cert-order`: the CSR plus a `Signed` attestation (purpose `tls-key`, `SIGNED_TLS_KEY_ATTESTATION` 0x1501, §6.9) by the device's identity key, of `TlsKeyAttestation {network_id, sidecar_id, spki_sha256, identifier_set_sha256, issue_time_millis}`, `identifier_set_sha256` the SHA-256 over the set's lowercase ASCII names, a wildcard written `*.x`, sorted bytewise, each followed by one 0x00 byte. certs checks the caller's §8 grant (13.15), orders under URnetwork's ACME accounts, deactivated on compromise, and alone writes DNS-01 records (§12). Every account key is in vault before any CA knows it, and certs never writes a key: it reads one YAML file per CA from taskworker's `secret_files` (`ca`, `private_key`, an optional `next_private_key`, `key_create_time`, `eab_key_id`, `eab_mac_key`, `contact`), and once `key_create_time` is a year old, the rollover age a setting, and the file holds a `next_private_key`, it signs RFC 8555 §7.3.5's key change with both keys and orders with the next from then on. Restarted with both keys in the file, it finds the account under whichever key the CA holds, so the operator promotes `next_private_key` to `private_key`, with a new `key_create_time`, at leisure, and the account's URI, which the CAA row pins, never changes; without a next key nothing rolls over, and certs reports the account due but not ready (`rollover_due_cas`; §19.10; owner decision 432) |
| Challenge | DNS-01 in URnetwork zones, the only wildcard method; never HTTP-01. Orders wait for `GET /dns/internal/ready`, which answers `stale`, `ready` or `canary_failing` (§12.6), and `CertsDns.CanaryClean` reads that answer: `stale` as below, and `canary_failing`, a §12.6 canary that is not clean, keeps an order waiting with no rewrite and no new serial, since CAs validate DNSSEC once the DS exists (CA/B SC-085v2, from 2026-03-15) and LE allows 5 failed authorizations per identifier per hour; a strong-mode probe counts `canary_failing` as ready, and the delegated challenge route passes all three answers on (§12.8); api hands a desktop's delegated challenge to certs' worker on taskworker as a bounded command with a restart-safe receipt per domain and claim, a `network_tls_custom_challenge` row kept the challenge's hour, the worker writing it and answering the real serial, which only the posting sidecar's GET reads (§12.8 step 3; owner decision 680). A set's two names, and an alias set's beside the network's, validate at one `_acme-challenge` name holding at most two values (§12.7), so certs admits at most one order at a time of an identifier set, or of any set sharing one of its challenge names: a pass leaves a queued row waiting (`set_under_way`, `name_under_way`) while another row of its set is `ordering` or `waiting_dns`, or any of its names, its CSR's DNS names with a leading `*.` trimmed, is held by a row under way or one the pass admitted, so a second order opens no CA order, spends no budget unit and writes nothing at the name until the first has issued; the solver writes an order's two values in one write; and where dns refuses a challenge write past `dns_challenges_per_name_hour` it holds that name's orders, as a CA's on its 429, until the time dns's Retry-After names, or `NameWritesHold` (1 h) without one, a held name's rows waiting (`name_writes`), the hold the process's alone (owner decision 713) |
| Custom domains (Team, v1; owner decision 39) | One ACME account per domain, pinned by the customer's CAA `issue "letsencrypt.org; accounturi=<uri>"`. CAA discovery follows a CNAME and stops at the first non-empty RRset (RFC 8659 §3), so the pin excludes URnetwork only in strong mode, where the host has customer A/AAAA or a customer-side ALIAS that synthesizes only A and AAAA (§12.8). certs walks the whole discovery chain and publishes §12.8's canary CAA, with a per-check nonce, at the ALIAS target, a host owner `<host>.<net>.<root>` and never `@`, an apex host's too: at setup, the host pending until walk and probe pass (§12.8), and again at half the lifetime of the host's newest registered chain, before the desktops renew at two thirds. Only a CAA-flattening ALIAS returns the nonce at the host. The ordering desktops repeat the walk, not the canary, before each order: the walk does not rest on certs, but the canary does, so a compelled operator can pass a CAA-flattening ALIAS (§2.8 EX1; 13.16). A strong-mode host whose walk reaches an operator-controlled name (`custom_host_caa_operator_alias`) or returns the nonce is refused at setup and takes §12.8's failure effect at renewal. A host CNAMEd into an operator zone is weak mode, its setup disclosing §2.8 EX1's operator-issuance exception. An admin's desktop makes the account key in a `secret` repo of its own, one per domain (§11.12's owner-bound kind; never the config repo, owner decision 6, nor the admin's vault, since an `EvsShare` opens a whole repo), and shares it by `EvsShare` with the desktops holding the domain's publish grants (owner decision 126); every MCP evs tool and `ur://evs` resource refuses the kind (§16.6). They order with acmez (TLS-ALPN-01, only while `GET /dns/zone` shows the host ready (13.4), or §12.8's delegated DNS-01), for mobile devices too, registering chains at `POST /tls/cert-register`; one must be online by two thirds of the lifetime. When the key repo's holders shrink, or its owner leaves, a network admin's ordering desktop changes the account key (RFC 8555 §7.3.5) under the account's lock: the new key is committed to a secret repo the remaining holders read before the CA is asked to require it, and the row's key sequence moves last; the pin is kept. Until that request a removed holder still signs as the account (below) |
| CAA | At `<root>`: `issue` and `issuewild` for `letsencrypt.org`, `pki.goog` (GTS, Google Trust Services; https://developers.google.com/public-key-infrastructure/faq/configure-caa) and `sectigo.com` (ZeroSSL; https://help.zerossl.com/hc/en-us/articles/360060119753), each with every URnetwork account URI and `validationmethods=dns-01`. No per-label URnetwork `accounturi` |
| CA, profile | LE `tlsserver`: 45 days, 25 names, 7 h authorization reuse (https://letsencrypt.org/docs/profiles/, 2026-10-04). GTS (100 new orders per hour per project), then ZeroSSL (unlimited 90-day certificates; [R:ext-edge] §2.4), when LE refuses on a limit, and first for ephemeral sidecars (CI, cloud agents) |
| Renewal | ARI (RFC 9773) via acmez v3 in the engine (Apache-2.0; https://github.com/mholt/acmez), using the stored CSR so devices may be offline; else at two thirds of the lifetime |
| Revocation | A device's certificate on removal (§5); a network's on takedown or deletion; an alias's when §12.5 retires it (I-14); `keyCompromise` on compromise. LE ended OCSP ([R:server-platform] §5), so the kill switch and 45-day lifetimes carry the load |
| Lost rows | After a restore the certificate manager compares `GET /tls/certs` with its local chain and re-orders a live chain with no row: `POST /tls/cert-order` with a fresh attestation and `replaces` naming the old leaf's ARI id, so the limits skip it; `replaces` rides the request and no row stores it, and `ValidateListen` refuses until the new row exists (§19.10). An old certificate with no row may raise a peer's CT alarm, the safe direction |
| Code | The CAA walk is pure code in the root behind `TlsCaaResolver`; for desktops acmez and its resolver sit in `cli/`, injected as provers are, so neither reaches an sdk leg, and certs keeps acmez on the engine leg; dependencies.yml lists acmez for engine and cli only |

```text
certs' DNS writes: an order's _acme-challenge TXT, or a strong-mode probe's CAA canary (§12.8)
  write    POST /dns/internal/acme-challenge or /dns/internal/caa-canary, committed at serial s; 503
           while a restore runs --> retry with backoff
  wait     GET /dns/internal/ready?serial=s: ready --> the order asks the CA to validate, or the probe
           starts its 10-min window; canary_failing --> an order keeps waiting, with no rewrite and no
           new serial, and a probe takes it as ready; stale (a restore, §12.6; final for s) --> write
           again, the same TXT or the canary under a new nonce, and wait on the new serial
  verdict  a probe's pass counts only if /dns/internal/ready?serial=s still answers ready after its
           last query; stale --> write again and restart the window, since the restored edges may lack
           the canary
  handoff  a desktop's delegated DNS-01 (§12.8 step 3) reaches the write only as a worker command api
           files with the claim it captured, its receipt a network_tls_custom_challenge row deleted
           after the challenge's hour; a retry recovers its receipt, an interrupted write is settled
           before another is charged against the name's ten an hour, and a confirmed stale permits
           the next write of the same digest (owner decision 680)
  lost     the write takes no idempotency key, each write taking a new serial: one whose answer was
           lost is looked for in the DNS journal, above the root's serial kept at its dispatch,
           before it is written again, and adopted with its serial; only a settle time past the
           dispatch with no such commit owes it again, so a lost write that commits later costs one
           more of the ten, of the same value, never a wrong one (owner decision 680)
```

```proto
// sidecar/protocol/tls.proto: the ordering row's attestation, and certs' hint (13.15)
message TlsKeyAttestation {      // the body of a Signed, SIGNED_TLS_KEY_ATTESTATION 0x1501, purpose tls-key, by the
                                 //   device's identity key: this key, for these names
  bytes network_id = 1;
  bytes sidecar_id = 2;
  bytes spki_sha256 = 3;         // of the DER SubjectPublicKeyInfo
  bytes identifier_set_sha256 = 4;  // the ordering row's hash of the identifier set
  uint64 issue_time_millis = 5;
}
message TlsHint {                // §6 0x1502, topic tls: the client refetches GET /tls/certs, so a hint is never
                                 //   authoritative
  TlsHintKind kind = 1;
  bytes cert_id = 2;             // the 16-byte row id
}
enum TlsHintKind { TLS_HINT_KIND_UNSPECIFIED = 0; TLS_HINT_ORDER = 1; TLS_HINT_ISSUED = 2; TLS_HINT_REVOKED = 3; }
```

**CT watch (D-TLS-8).** Each listening sidecar queries Cert Spotter (`issuances?domain=<net>.<root>&include_subdomains=true&match_wildcards=true`, https://sslmate.com/help/reference/ct_search_api_v1) and crt.sh for its zone and custom domains every ~6 h (jittered; optional Team key), alarming on a certificate no device attested in `GET /tls/certs` or one an identity pinned under 24 h before issuance attested. Failures show "CT watch degraded"; keyless queries are best effort and never ride a URnetwork proxy (§2.8 ext-1). `ur daemon` runs it for every network it hosts, and so does the sdk's desktop class, through a component factory beside sdk/sidecar_tls.go; the sdk's foreground-only classes (iOS, Android) run none, their network's daemons keeping it, and D-TRUST-9's zone watch runs on the same hosts, so a network whose only devices are phones has neither (owner decision 731).

**Budget.** LE allows 50 new certificates per registered domain per 7 days across accounts (https://letsencrypt.org/docs/rate-limits/, 2026-08-05): each network's or scope's first certificate spends a unit of `<root>`'s shared budget, a set's further devices being admitted as a repeated set once its first order has issued (the Challenge row; owner decision 713), a repeated set gets 5 per 7 days (refill 1 per 34 h, no overrides), and ARI renewals skip all limits. certs (`certsservice`, taskworker chains) reimplements the extender pattern, which sidecar cannot import: a `network_tls_cert` queue, a weekly new-set cap below the CA's, counted in Redis `{tcb_}` (13.15), Retry-After holds, the row written before the order; a row keeps its issued chain, which `GET /tls/cert-order/<id>` answers after a restart or to a device that was offline, a requested revocation's reason (`keyCompromise` from `POST /tls/cert-revoke`, `cessationOfOperation` for §21.6's takedowns) until the sweep's revocation reaches the CA, and `state_time`, the time of its latest state; rows stay 30 days, a setting, past expiry, read from `not_after`, or past revocation or failure, read from `state_time`, from which the rebuild of a lost `{tcb_}` key may read an order's admission (cert-1; owner decision 254); budget entries 7 days. certs backs a URnetwork-zone name whose authorizations keep failing at a CA off, doubling from a start to a day, both settings, so it fails at most about once a day there, which Let's Encrypt's daily refill of the 1,152 consecutive failures after which it pauses a name for an account hands back, and one broken name no longer holds LE's new orders for every other network; the backoff survives a restart in `network_tls_name_backoff` (cert-1), and a success at that CA resets it (owner decision 430).

**Custom-domain orders (Team, v1; owner decisions 424-427).** A custom-domain certificate names exactly one custom host and carries one device's key, so a host's devices share the CA's exact-set limit: its first 4 devices are certified at once, one certificate kept back for a compromised key, and each further device 34 h after the one before, both settings, and a device without a certificate for a custom host is not routed that host's visitors. URnetwork's orders for a customer's registered domain are held at the server to a bucket of 25 new certificates, one back each 6 h 43 min (`CertsCustomSettings`' `DomainCap` and `DomainRefill`), half the CA's assumed 50 in 7 days, counted before any request reaches the CA, ARI renewals outside it; a value the customer's admin sets per domain is a later product setting. The CA's numbers (a 45-day lifetime, 7 h authorization reuse, 50 certificates a registered domain in 7 days, 5 an exact set in 7 days with one back each 34 h, 300 new orders an account in 3 h, 5 failed authorizations an hour, an ARI renewal counting against no limit) stay assumptions held as `CertsCustomSettings` defaults, which the owner corrects from the CA's rate-limits and profiles pages; if the ARI exemption fails in any part, a host's ceiling of about 21 certified devices becomes the product's stated limit. Budgets are rows of spends replayed as buckets, never counters: a bucket's replay starts full at its key's latest quiet window, the newest instant t at or before now with no spend of the key in (t − cap × refill, t], where the CA's bucket is full whatever came before, and replays the spends after it, or, where no such instant lies within the retained spends, starts empty at the retention's start; spends are kept 16 d (`SpendRetention`), and a grant reads all of its key's, at most a few dozen rows for the set and domain buckets. So the level never reads above the truth, and it is exact for any number of a host's devices while the host's busy stretch is shorter than the retention less one window, 214 h: after a burst of four each device comes 34 h after the one before, the 10th at 8.5 d and the 11th after a window's pause, and a refused claim's wait, (need − level) × refill, is answered by a grant (owner decision 571). Every custom certificate is a `network_tls_cert` row first, in states of its own (`custom_queued`, `custom_ordering`, `custom_issued`, `custom_revoking`) that no other certs pass takes: `POST /tls/cert-register` takes a chain only for a queued row whose account lock the caller holds, so a desktop's own CSR is queued by `POST /tls/cert-order` like a phone's and claimed like any row. The lock is one an account, since the CA may hand two newOrders for one host the same order and the key change needs the same exclusion. An ordering desktop touches the CA for an account only while it holds that lock, `network_tls_account`'s sequence, holder and lease on the database's clock and no other, one order in flight an account, and every server write it makes names the sequence its claim returned, a write under an older one refused. It sends one newOrder a grant and finalizes only an order whose URL the server recorded under that sequence; a takeover resumes the recorded order and starts another only when the CA itself calls it invalid or gone, never on a timeout or a 5xx, so a row yields at most one certificate, and a holder that must give a live order up kills it by deactivating its authorizations, since an order left recorded keeps its row first in line. The server grants each newOrder in the claim's transaction, after checking and spending the account's budgets (the exact-set, registered-domain, new-order and failed-authorization limits, each a setting, one certificate of the exact set kept back), and records a CA's 429 as a hold on the account row that every desktop honors (DESIGN-DETAILS.md section 17, 17.2.6 to 17.2.8; `details/CertOrder.tla`, §22.8). An ordering desktop answers TLS-ALPN-01 for a custom host only where it holds an approved port 443 publish grant on the host's owner, 13.9's gate taking no exception; without one it uses the customer's DNS-01 CNAME for that host or leaves the row to a desktop that holds the grant, and a row no online desktop can serve waits and raises `tls_custom_queue_stalled` after 24 h, a setting. Before asking the CA to validate, a desktop probes its own challenge through public DNS and the edge, twice, and a failed probe asks the CA nothing. A 429 on an ordinary order holds ordinary orders and lets ARI renewals through, and one on an ARI renewal holds everything. The plan orders revocations, the row in flight, replacements of revoked certificates, renewals by expiry, then first certificates, the least-served host first. A device presents the newest installed certificate whose row is `custom_issued`, falling back to its predecessor, and for a custom name with none it fails the handshake, never presenting another certificate. A renewal is a successor row the server queues with the stored CSR, so a phone need not wake for it, at a uniform point of the certificate's ARI window, or at two thirds of its life where the CA gave none, and its order carries `replaces`; ordering desktops keep the windows fresh from the CA's renewalInfo. A revocation is marked by the server, which from that commit certifies the name for that listener no longer, and sent by an ordering desktop under the account key, spending no budget and waiting on no hold (DESIGN-DETAILS.md section 17, 17.2.11, 17.2.12). A row that ends while an order is recorded for it goes to `custom_revoking`, and the account orders nothing until that order is killed at the CA or its certificate revoked. The account key is held by an admin's devices and the ordering desktops it is shared with, each keeping the key file's last good bytes in its local secret store; any holder orders, but only a network admin's ordering desktop changes the key or writes the account row. The change is due the moment the key repo's holders shrink or its owner leaves, and the first admin desktop online makes it within one poll, under the account's lock, committing the new key where the remaining holders read it before the CA is asked to require it, the account row's key sequence moving last, so at every instant some holder reads whichever key the CA accepts and an order in flight resumes under the new key (DESIGN-DETAILS.md section 17, 17.2.13); a desktop that sees it due and may not make it raises `tls_account_rollover_due`, and fewer than two admins' desktops seen in 7 days is a warning. Until the CA takes the change, a removed holder still signs as the account (13.16).

### 13.9 Endpoints, caps, metering, abuse

**Endpoint (PLAN.md:358).** An endpoint is an active publish grant per (host, port); custom-domain aliases count, listeners and certificates do not, and §20.7 counts `tls_endpoints` at grant activation. Each `tls/` registration passes `ValidateListen` (§9.4's owner hook):

```text
ValidateListen(tls/<port>/<host>) refuses
  host     unmappable (13.5); mta-sts, except the system publish below; a member-scope host from a
           device its member did not consent to (§8.5); a host ScreenName refuses, or sends to review
           with no reviewer's allow on its case (§21.6), screened at each registration through a short
           per-process cache of the verdict, so a refusal needs no change to the signed GrantActivate
  port     other than 443, 8443, 8883 and 5671
  client   URnetwork-run (D-TLS-1)
  network  no network_verified (§21.7)
  grant    no active approved publish grant for (host, port) (§8.10, I-8); an AppMode other than its
           app_mode; raw under an audience other than public or link; a raw link grant without
           link_spki_sha256 (13.7)
  time box a grant with no expires, or more remaining life than its cap, in a network at Community
           (7 d) or in probation or restricted state (24 h); Pro and Team may hold standing names, and
           a network whose tier fell keeps a standing grant until §20.7's 14-day clock ends
  cert     no unexpired certificate row, except an acme-tls/1-only registration before its first order;
           a custom host or alias is listed for a listener only while its sidecar holds an unexpired
           certificate row for it: a certified or ACME name the rows do not bear out is dropped, and
           the registration stands
  facts    an unknown fact, of the ones above that TlsListenFactsSource brings (§8.9)
system publish tls/443/mta-sts (§15.5): AppMode http, audience public, no tls/ grant of its own
  only     a receiver (an approved smtp/25/mx listen grant, §15.4) holding an unexpired certificate row
           for the network's pair, in a network with network_verified (§21.7) and a mail_network row
           (§15.15)
  grant    that listen grant stands in for the tls/ listen and publish grants as §9.10's gates say
  serving  the receiver's mail component answers; no interstitial, tls_endpoints unit or expiry of its own
```

Caps protect the devices, which do the handshakes: endpoint caps are tier quotas, visitor caps `sidecar_abuse:` limits equal on every tier (§20.4, D-QUOTA-7); §21 tightens either per network.

| Cap | Community / Pro / Team | Where |
|---|---|---|
| Concurrent per endpoint | 256 / 2,048 / 8,192 | ⌈cap ÷ blocks⌉, at least 1, per process, no shared counter, blocks being tlsedge.yml's count of lb hosts running it (13.5) |
| New per endpoint | 50 / 200 / 1,000 per s | token bucket per process |
| Bandwidth per endpoint | 20 / 200 / 1,000 Mbit/s | token bucket in the splice, ⌈cap ÷ blocks⌉ |
| Per visitor /64 (IPv6) or /32 (IPv4), per process | 64 concurrent (`tls_visitor_concurrent`), 20 per s (`tls_visitor_new_per_s`); `tls_visitor_aggregate_multiple` (4) times those per /48 or /24 | HMAC under a per-process key rotated daily |

**Visitor hashes.** Cap keys stay per process (§2.8 tls-2). tls-3's visitor hash and Find's affinity key use a fleet-shared daily key: 32 random bytes in Redis `{vhk}tls:<yyyymmdd>` (UTC), created by the first process with `SET NX EX 90000` and read by every process each minute and at the date change. `k_record` and `k_affinity` derive from it by HKDF-SHA256 with infos `urnetwork-sidecar-v1/tls-visitor-record` and `urnetwork-sidecar-v1/tls-visitor-affinity`, and the hash is HMAC-SHA256(k, family byte ‖ the /24 or /48 prefix)[:16], so one visitor links across processes for a day. A process that cannot reach Redis uses a random key of its own for that day, the closed direction. mxedge's daily key has the same shape under `{vhk}mx:<yyyymmdd>` (§15.4), so tls-3's rows and `{mxc_}` keys never join.
| Per process | 50,000 connections | tlsedge.yml; §19 derives §9's platform Find limit from it |

**Abuse hooks** (owner decision 41; §21 sets policy), none inspecting content:
- **Kill switch.** `POST /tls/suspend` writes `network_tls_suspension` (§19.7), then one MULTI sets `{tes_<network_id>}` (`<host or *>` → reason, until) and INCRs its trigger (D-PROTO-12). tlsedge, on the shared key-event subscriber (§4.5), refuses new connections and resets open ones within 5 s, reloading from Postgres every 60 s; Find refuses too, and §8 suspension and revocation follow (§21.6). Row and keys go only when the case lifts it or `until` passes; a reload drops a kill only once neither its row nor its key holds it, so a Postgres restore lifts none, and §19.10's abuse step re-applies the kills and lifts mailed after the dump (§21.10).
- **Time box, verification.** Publishes follow §8's `expires`: 24 h by default, at most 7 days on Community, 24 h on probation (§21.7); standing names only in Pro and Team documents (§8.5). They need §21.7's `network_verified`, so anonymous-only networks publish nothing (owner decisions 41, 96).
- **Published names, CT.** Active publish grants (host, port, label, expiry) form the list §21.6 checks hourly against Web Risk: taskworker reads ACL's `AclState.PublishedNames(now)`, every rule allowing publish grouped by host and port, `PublishGrant`'s agreement rule deciding audience and expiry and disagreeing rules listed as the closed audience, through a gate cache of its own, installed as `model.SetTlsPublishedNamesSource`'s source, a name's label and aliases coming from `network_edge_label` and the verified domains, so the check reports what the gates enforce; a process with no source answers unavailable, which the hourly check takes as a failed pass (owner decision 423); reviewers open reported URLs as visitors, a case keeping a URL's path and query until its first review ends (§21.8; owner decision 207), joining connections by `connection_id` for 24 h; §21's worker screens CT under `<root>` (§21.8), and D-TLS-8 covers mis-issuance.

Server-visible fields are §2.8's tls-1 to tls-4, cert-1, cert-2, api-11 and api-7's publish rules (audience, `app_mode`, a raw link's `link_spki_sha256`); tls-3's records leave tlsedge in 10 s batches.

### 13.10 `ur bridge public-tls`

`ur bridge public-tls <host>:[<local ip>:]<local port>` (cli/UI.md:47; local ip 127.0.0.1 by default):

1. Check `<host>` against §9.4's grammar, §7.7's client names and 13.9's system host.
2. Pass §5's `Authorize` (I-8). Without an active approved grant, file §8's request `{dst: [dns:<host>, sock:tls/<port>/<host>], allow: [publish, listen], audience, app_mode, link_spki_sha256, expires}` (§8.5 example 5; the pin only for a raw `link`), print `ur approve <id>` and its approval channels (§16.6; in a tainted run, harness evidence only where the rule names it, owner decision 142), and wait.
3. Get the device certificate if missing, probe the target (13.7), then `Listen("tls/<port>/<host>", alpn, app mode)`.
4. Print the URL (raw `link`: the client-certificate file), expiry, audience and "passthrough: key on this device".

Flags: `--port` (443, or a listed port), `--expires`, `--audience`, `--alpn`, `--tcp` (`AppMode` raw, with `--audience public`, or `link`, which writes a client key and certificate whose `link_spki_sha256` the request carries), `--proxy-protocol`. The MCP tool `tls_publish` passes the same gate (§16.5).

### 13.11 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Edge termination, in a TEE or not, and edge interstitials (PLAN.md:84) | WAF, edge auth, warnings | Plaintext and keys on servers | Ruled out (owner directive 2026-11-03) |
| One network key shared through evs | One certificate per network | Keys leave devices; reissue per removal | Rejected (D-TLS-6; owner decision 40) |
| Per-host certificates, or TLS-ALPN-01 in our zones | Isolation | Every host in CT and the budget | Custom domains only |
| Unknown SNI to tlsedge, platform names listed | No lb reload per custom host | Every scan and foreign name loads tlsedge; an unlisted platform name breaks | Rejected (D-TLS-12) |

### 13.12 Decisions proposed

**D-TLS-1 (proposed).** Passthrough only: tlsedge holds no user key or user-name certificate and mounts no vault, and no URnetwork-run client (platform, proxy, hosted DeviceLocal) listens on `tls/`. *Why:* the owner directive; a URnetwork `*.<root>` key would cover every network.

**D-TLS-2 (proposed).** Ingress is 13.4's gated, probed SNI split on the shared lb addresses; port 80 only redirects; active custom hosts route to tlsedge through the split's generated map (D-TLS-12). *Why:* owner decision 34 leaves no other addresses; the gate and probes catch split faults.

**D-TLS-3 (proposed).** tlsedge is 13.5's layer-4 router. *Why:* it sees only SNI, ALPN and bytes (R-TLS-4), and retries stay invisible.

**D-TLS-4 (proposed).** tlsedge runs K platform clients per process on Service contracts (13.6). *Why:* clients do not grow with networks, and the edge holds no Network privilege.

**D-TLS-5 (proposed).** The front enforces 13.7; dispatch keys on the registration's application mode, never on ALPN's absence (D-TLS-13). *Why:* under passthrough only the sidecar can; coalescing and the shared site (§12.4) make the 421 and origin rules mandatory.

**D-TLS-6 (proposed).** Every device holds its own P-256 key and a certificate for its network's or scope's set, a member scope's only on that member's consented devices (13.8). *Why:* no shared key, minimal CT exposure, and member isolation one admin cannot break (owner decisions 40, 126).

**D-TLS-7 (proposed).** certs proxies CSRs, queues orders, puts ephemeral sidecars on GTS or ZeroSSL first and alone writes DNS-01 in URnetwork zones (13.8); overrides are requested at least 6 weeks ahead. *Why:* a shared budget needs one queue, CI runs would exhaust a set's 5 per 7 days, and mobile builds need no ACME client.

**D-TLS-8 (proposed).** Sidecars watch CT through two sources and check attestations against pinned identity keys (13.8). *Why:* URnetwork can always pass DNS-01 in its zones (§2.8 EX1), so detection is the remaining control.

**D-TLS-9 (proposed).** Endpoint counting, caps, the kill switch, the time box and 24 h records follow 13.9. *Why:* PLAN.md:358 needs a unit, and these controls work without inspection.

**D-TLS-10 (proposed).** TCP 443, 8443, 8883 and 5671 (owner decisions 68, 121), with no h3 or published ECH configs; tlsedge routes on SNI and ignores GREASE ECH. *Why:* QUIC SNI cannot be preread while connect owns UDP 443 ([R:server-platform] §2.4), and ECH routing needs split mode, which Go's server lacks ([R:ext-edge] §2.7).

**D-TLS-11 (proposed).** A Team custom domain's one customer ACME account is shared by its ordering desktops, which order for every device (13.8); its CAA pin excludes URnetwork only in strong mode, and a strong-mode host is refused at setup, and takes §12.8's failure effect at renewal, when its CAA walk passes through an operator-controlled name (certs and the desktops check) or it returns certs' canary. *Why:* the customer's pin excludes URnetwork (owner decision 39) only while CAA discovery stays under customer authority (RFC 8659 §3), and one account needs no CAA edit per device.

**D-TLS-12 (proposed).** Active custom hosts route to tlsedge through the split's generated map, reloaded at most once per 15 min (13.4); unknown SNI keeps the platform default. Each map has a version; each lb interface reports the version it loaded, which the dns edges route-probe as a visitor would; a host is ready for TLS-ALPN-01 only once every interface that §12.6's probe passes is current for its version; and an interface more than 20 min behind leaves user-name answers and pages. *Why:* a downstream map cannot correct an upstream dispatch, and each reload holds old workers for up to an hour; a wait is not readiness, since an lb that missed or failed a reload, or restarted with an old map, kept sending a host to the platform branch while probes of `<root>` names passed (meta review K02).

**D-TLS-13 (proposed).** Dispatch binds the signed registration's application mode (13.7): `http` takes `h2`, `http/1.1` and no ALPN through the HTTP front, and `raw` registers only under `public` or a certificate-pinned `link`; ALPN omission never selects a less-restrictive path. *Why:* ALPN negotiates a protocol, not an audience (RFC 7301).

### 13.13 Open questions

**Q-TLS-1.** [X1] Where does TLS end, and how does TCP 443 split? **Decided by owner 2026-11-03 (owner decision 34):** in the listening sidecar (§0), via (a), 13.4's `ssl_preread` split on the shared lb addresses. *Residual:* none.

**Q-TLS-2.** [X1] Who orders certificates for device-held keys? **Decided by owner 2026-11-03 (owner decision 39):** (c), certs' CSR proxy in URnetwork zones; on Team custom domains, the customer's own CAA-pinned account (D-TLS-11), which excludes URnetwork only in strong mode (13.8). *Residual:* none.

**Q-TLS-3.** [X1] How do a team's devices share the wildcard? **Decided by owner 2026-11-03 (owner decision 40):** (a), per-device keys and certificates, plus scope sublabels `*.<scope>.<net>.<root>` past the 1-per-34 h refill or for isolation, with hosts `<label>.<scope>` (13.8); no shared key. *Residual:* none.

**Q-TLS-4.** [X1] Is abuse handling without inspection enough? **Decided by owner 2026-11-03 (owner decision 41):** (c), 13.9's hooks plus a verified account before any Community publish. *Residual:* none.

**Q-TLS-5.** Cross-cutting (X11): a tlsedge client per served network (PLAN.md:82), or platform clients? **Decided by owner 2026-11-03 (implied by owner decisions 11 and 59):** platform clients on Service contracts (13.6). *Residual:* none.

**Q-TLS-6 (closed 2026-11-03).** (a): `tls/` and `smtp/` hosts are `@` or one LDH label, as a wildcard covers one, plus Team scope hosts (Q-TLS-3); applied in 13.10 and §9.4.

**Q-TLS-7.** Cross-cutting (§8, §7.8): what does "authenticated by default" (sidecar/design/pitch5.html:698) mean? **Decided by owner 2026-11-03 (owner decision 42):** `members` by default, else `members-device`, `link` or explicit `public`, plus members' overlay access (13.7); `raw` endpoints take only `public` or `link` (D-TLS-13). *Residual:* none.

**Q-TLS-8.** Cross-cutting (cli/UI.md:121): may names publish ports other than 443? **Decided by owner 2026-11-03 (owner decision 68):** (b), a short fixed list of permanent ports on the shared addresses. **Decided by owner 2026-11-04 (owner decision 121):** 8443 (a second HTTPS service per host), 8883 (MQTT over TLS) and 5671 (AMQP over TLS), permanent lb ports to tlsedge (§19 W7); mail ports, plaintext-before-TLS protocols and control-plane defaults (2376, 6443) stay excluded. *Residual:* none.

### 13.14 Departures from PLAN.md

- **PLAN.md:84** ("so that the tls edge can do its own certificate termination"): superseded by owner directive 2026-11-03. Certificates stay automatic but go to the listening sidecar (D-TLS-1, D-TLS-6).
- **PLAN.md:82** ("opens a client on a network"), read as one client per served network: D-TLS-4 departs, as owner decisions 11 and 59 approve (Q-TLS-5).
- **Outside PLAN.md:** cli/UI.md:105's `<sub>.<you>` depth (Q-TLS-6, Q-TLS-3) and :121's any-port `hostname:port`, narrowed to a fixed list (Q-TLS-8).

### 13.15 Interfaces

- **Provides:** tlsedge; the split, its custom-host map with versions, interface reports and readiness, gate, probe and route probes (§12, §19); certs (13.8, D-TLS-7); `TlsEdgeOpen`, `TlsHint`; the `tls` component, its `AppMode` dispatch and publish receipts (13.7, §16); `tls/` hooks with the MTA-STS system publish (13.9; §9, §15); mail-host and off-loopback listener certificates (§15; D-TRUST-8, owner decision 130); the kill switch, published-names list and CT hook (§21); lease spends (§20).
- **Consumes:** §4 C9, `ServiceHost`, acmez v3; §5 keychain, `Signed`, `Authorize`; §6 streams, Service, topic `tls`; §7 membership, edge login, client names; §8 grants (`audience`, `app_mode`, `link_spki_sha256`), approvals, consent, `EvsShare`; §9 Find, hooks, the signed `AppMode`; §11 owner-bound repos; §12 label and custom-host maps (with CAA mode), records, probe, pending custom hosts, DNS-01 and canary-CAA writes, ready and its `stale` answer across a restore, `canary.<root>`; §15 `mail_network`, receivers' `smtp/25/mx` grants; §16 `ReachReceipt`, approval channels; §19 W1 (drained rollout, map and port-80 reloads), W7, monitor, §19.8's pager, §19.10's abuse step; §20 leases, caps; §21 `network_abuse_state`, `network_verified`, `ScreenName`, holds.
- **Subprotocol messages:** `TlsEdgeOpen` (0x1501; StreamOpen metadata, edge→listener); `TlsHint` (0x1502; push `tls`, whose version is the writer's clock in ms, per client, with no durable sequence; §6.8): `{TlsHintKind kind = 1; bytes cert_id = 2}`, kinds 1 order, 2 issued, 3 revoked, `cert_id` the 16-byte row id; the client refetches `GET /tls/certs`, so a hint is never authoritative.
- **API routes** (api; bringyour.yml, route_authz.go):
  - `POST /tls/cert-order` (service token, aud `certs`; caller holds a §8 `tls/` or `smtp/` grant, which api's subject asks the gate in one call, `AclGateView.HoldsPublicGrant(networkId, subject, now)`, true when a rule in force gives the subject publish with listen on any `tls/` name or listen on `smtp/25/mx`; until that call lands, api grants a caller the view allows listen on `smtp/25/mx`, or one `PublishGrant` grants, in http or raw mode, a host and port `AclState.PublishedNames` lists for the network, each `*` asked as the letter `x` and a dotted Team scope host skipped until M6, every answer the gate's own, the closed direction (owner decision 429); CSR, attestation); `GET /tls/cert-order/<id>` (state, retry_after, chain, ARI window).
  - `POST /tls/cert-register` (service token, aud `certs`, as every custom-domain route here; a custom domain's chains, v1, each only for a queued row whose account lock the caller holds, under that claim's sequence, its leaf carrying the row's key and exactly its one name); `GET /tls/certs` (Client; certificates, attestations and queued custom-domain CSRs; `?work=1`, which an ordering desktop asks with its `certs` service token, only accounts and waiting rows, so a desktop's poll carries no chains).
  - `POST /tls/custom-claim` (service token, aud `certs`; an ordering desktop, a sidecar holding an active approved publish grant on a `tls/` name of the owner of an active custom host of the domain, takes or renews the account's lock for one row, purpose `order` or `revoke`, or, a network admin's desktop only, for a key change, `rollover`; the answer carries the claim's sequence, its lease, the row, the recorded order's URL to resume or the grant of one newOrder, its budgets checked and spent in that transaction, and the predecessor's leaf where the order names it in `replaces`; refused 403 `orderer`, 404 `no_account`, 409 `key_seq`, `locked`, `in_flight` or `state`, and 429 `budget` or `hold` with `retry_after_ms`, never waiting on the lock); `POST /tls/custom-progress` (service token, aud `certs`; what the holder learned at the CA, applied only while the lock's sequence is its claim's, else 409 `claim`: `order_recorded`, `order_invalid`, `authz_failed`, `rate_limited`, `not_exempt`, `release`, `failed` and `revoked`, and with no claim `ari`, the certificates' renewal windows, and `rollover_due`); `POST /tls/custom-account` (service token, aud `certs`; a network admin's desktop creates the account row or begins, ends, aborts or repairs a key change: `create`, `roll_begin`, `roll_end`, `roll_abort`, `repair`). Durations on these routes are milliseconds from the answer, never a time of day, so no desktop clock is compared with the server's (DESIGN-DETAILS.md section 17, 17.2.5; v1).
  - Bodies are JSON from 13.8 and §2.8's cert-1: a stored field cert-1 lacks needs its row first (I-18), and a request-only value, such as `replaces`, is stored nowhere.
  - `POST /tls/custom-challenge` (service token, aud `certs`; the caller holds an active §8 publish grant on a host mapped under the domain; `{domain, value}`, the value the 43-character base64url DNS-01 digest) and `GET /tls/custom-challenge/<id>` (the id the serial the POST answered, read only by the sidecar whose receipt holds it, any other caller reading 404; §12.8's ready answers, `stale` and `canary_failing` included): a custom domain's delegated DNS-01 at its `<acme_token>.acme.<root>`, which certs alone writes, through its worker on taskworker (§12.8 step 3; owner decision 680; v1).
  - `POST /tls/cert-revoke` (OwnClient: a client token revokes its own client's certificates; Network admin for any of its network's, meaning a personal network's owner's token, a team member's token whose role holds `devices`, a role that cannot be read holding nothing, or an API key whose scopes reach `devices`, since revoking a device's certificate is part of removing the device; an OAuth identity or admin token revokes nothing there; owner decision 429); `POST /tls/suspend` (§21), a model call inside api and taskworker, its route built only once a caller outside them exists (owner decision 417).
- **Tables** (migrations ≥926): `network_tls_cert` (certs; orders and certificates, with §2.8 cert-1's fields, among them the issued chain, a requested revocation's reason and `state_time timestamp NOT NULL`, set with every state change, in MG5's CREATE; owner decision 254); `network_tls_custom_challenge` (certs; a delegated DNS-01's receipt, one a domain and claim, which api captures and certs' worker completes with its write's serial, deleted after the challenge's hour, in MG5; owner decision 680); `network_tls_suspension(network_id, host, reason, until)`; `tls_connection_record` (hourly partitions, dropped at 24 h once a §21.9 hold has copied out its network's rows, owner decision 133); `tls_connection_day` (13 months). Redis: `{tes_<network_id>}` and trigger `{tes_<network_id>}n`; certs' budget `{tcb_<ca>_<registered_domain>}`, a sorted set of the last 7 days' new-set orders, checked against the cap and added to in one script (server/ip_ratelimit.go:105's sliding window), expiring 7 days after its newest order and rebuilt from `network_tls_cert` on loss.
- **Services and config:** `server/cli/tlsedge` blocks behind the split and the port list (TCP 443, 8443, 8883 and 5671; nothing on 80); the lb's generated `/run/warp-lb/tls-custom-hosts.map` and port-80 names, and `lbmap`, which generates and loads them beside each interface's nginx (13.4); certs as taskworker chains, routes in api, each install left out unless sidecar.yml's `certs` switch is on (§19.11), so certs fails closed through M5's Gn-out and the first real CA order is the owner's act: api's with the engine, the Postgres store, the `certs` authenticator and a reader of a caller's identifier set, identity key and grant from its network's verified projection through `AclGateView`, once ACL's gate cache runs in api, and taskworker's with the engine, its DNS client, its ACME client on the account files and its hint writer, reading `certs.yml`, the account files its `account_file` names and `internal-certs.yml` from `secret_files` (owner decision 429); `config/<env>/tlsedge.yml` (13.5; caps in pro.yml); certs' account and EAB keys in vault (13.8).
- **Assumptions about other sections:** §11.12's `secret` kind holds a custom domain's account key, and §16.6 refuses every MCP evs tool and `ur://evs` resource on it, which §22.7's actions suite tests (13.8); gates read §8.5's consent from the projection, as §15.5 assumes; §21.9's holds name tls-3 rows; §22.7's scope-certificate check covers unconsented devices; §22.5's §13 row tests 13.9's refusals and system publish; §9.10's gates let a receiver's `smtp/25/mx` listen grant stand in for `tls/443/mta-sts`'s grants at registration, Find and admission (13.9); §12.8 keeps a strong-mode custom host pending and unmapped until certs' walk and probe pass, refuses it at setup when its walk reaches an operator name or its answers return certs' canary, and defines that failure's effect at renewal; the canary admits at most the customer's account, carries its nonce in a non-critical property (RFC 8659 §4.1), sits beside a copy of `*`'s records (RFC 4592 §2.2) at a host owner, an apex host's included, never a network's, alias's or scope's `@`, whose CAA would govern that zone's device set (RFC 8659 §3), is checked after the 60 s negative TTL and takes 13.8's `stale` handling, the re-check before a pass included; FS-32 runs the CAA-flattening and the address-only ALIAS again at an apex host whose pin sits at `<domain>`; §19 W1's `lbmap` renders the custom-host map and the port-80 names from one version's rows, before nginx serves at start and otherwise at most once per 15 min, and reports the version each interface loaded (13.4); §12.6's edges route-probe each interface's reported version and drop map-stale interfaces; §19.10's abuse step re-applies, from §21.10's off-site record, the kills and lifts mailed after a restored dump; §19.7 and §2.8 cert-1 name `{tcb_}`.

### 13.16 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| The shared budget runs out before the override, a team adds devices faster than 1 per 34 h, or CI runs drain a set's 5 per 7 days | High | High | X4, early override, queue, fallback CAs (ephemeral sidecars first), Team scopes (Q-TLS-3) |
| Phishing on a user name flags `<root>` or gets a shared lb address listed, also stopping smtpedge's mail from it (owner decision 124) | Medium | Critical | X4, kill switch, verified publishers, Web Risk (§21.6), M5's registrar and registry pager (owner decisions 134, 143) |
| The split slows connect's H1 transport or fails fleet-wide | Low | High | 13.4's gate, drained rollout, probes paging at any hour (owner decision 143), rollback |
| Custom-host reloads pile up old lb workers, each holding its connections up to 60 min and then cutting them (warp/warpctl/config.go:1181) | Low | Medium | Team-only provisioning changes, coalesced to at most one reload per 15 min (13.4) |
| An lb interface misses or fails a custom-host reload, or restarts with an old map, so a host's SNI reaches the platform branch there while `<root>` probes pass | Low | Medium | 13.4's versions and route probes: a host is ready, and TLS-ALPN-01 starts, only once every interface is current for its version; a map-stale interface leaves user-name answers and pages; a static-address host stays pending, naming it (§12.8) |
| A flood at user names saturates the shared interfaces, platform included ([R:ext-edge] §5) | Medium | High | 13.9's caps, kill switch, router ACLs, upstream help (§19) |
| A dns-edge signing fault after the DS, or a site or Hurricane Electric outage that also stops the lbs ([R:ext-edge] §5; accepted, owner decision 123), fails DNS-01 and CAA | Medium | High | Orders pause on §12.6's canary, which pages at any hour (owner decision 143); renewal at day 30 of 45 leaves 15 days |
| Compelled mis-issuance enables MITM of a name, of a weak-mode custom host, or of a strong-mode one behind a CAA-flattening ALIAS, which only URnetwork's own canary checks (13.8) | Low | High | Two-source CT watch (D-TLS-8), the remaining control for those hosts; customer CAA in strong mode (13.8) |
| Same-user agents read the device key and impersonate names | High | High | Accepted (owner decision 47); removal revokes (I-15) |
| A custom domain's certificates lapse with no ordering desktop online | Medium | Medium | Two ordering desktops; warnings from half-life name the host and device; fewer than two ordering desktops seen in 7 days is itself a warning, as fewer than two admins' desktops is (owner decision 425) |
| A removed holder of a custom domain's account key signs as the account, revoking its certificates or deactivating or taking the account, until the CA takes the key change (accepted, owner decision 425) | Low | High | The change is due at once and made by the first admin desktop online within one poll; `tls_account_rollover_due` where a desktop may not make it; only the CA's key change ends the exposure |
| The CA's limits differ from `CertsCustomSettings`' assumed defaults; if an ARI renewal counts against a limit, a host keeps at most about 21 certified devices (owner decision 424) | Medium | Medium | The owner corrects the defaults from the CA's pages; a wrong number costs waits and refused requests, never a certificate too many, since a 429 becomes a hold |
| Raw clients lack TLS 1.3 or client certificates for a `link` endpoint | Medium | Low | `public` with the service's own authentication; members' overlay access (§17) |

### 13.17 Phasing

**v0** (§23 M5): the split after its gate and drained rollout, its custom-host map empty; tlsedge and Service contracts; certs with LE, GTS, ZeroSSL, ARI and per-device keys; the front with `members` login and `AppMode` dispatch (FS-34); desktop `ur bridge public-tls`; the CT watch; ports 443, 8443, 8883 and 5671; app listeners with §18 and the MTA-STS system publish with §15 (both M8), an app's listener running through the `tls` component's `Sidecar.ListenTls`, whose `TlsListenSettings.Expires` asks the grant's lifetime as §9.9's `SocketListenSettings.Expires` does, a negative one refused before anything is ordered, and whose `TlsListener.GrantExpires` is when the grant its `tls/` registration registered under ends, which §18.5's `ListenExpires` and `GetGrantExpiresMillis` carry (owner decisions 687, 792); and the app's sidecar role reads its streams' grant ends again after a sleep or a clock step through the sdk's `Sidecar.CheckClock()`, `urnet_sidecar_check_clock` in the C ABI, which the app calls when it comes to the foreground and at a clock change, beside its VPN component's `DeviceLocal.CheckClock` (§17.8; owner decision 803), as sdk-sidecar-check-clock built it (sdk 2be48a93), the apps' calls coming with the app phase. It waits on §9's `tls/` and Find, §6 streams, C9, §12's dns edge, §19's W1, §7.8's edge login, §21's kill-switch policy and the LE override's lead time.

**v1** (§23 M6): Team custom domains (with §12's custom-host-add, the split's custom-host map with its versions, interface reports and readiness, and strong-mode CAA checks; FS-32, FS-35, FS-122), Team scopes, affinity, `members-device`, overlay access for members by §17's maps and grants alone, with M6's `ur tun` on macOS and Windows (§17), and publish reach receipts (§16).

**Later:** [ECH split mode](DESIGN-DEFER.md#tls-ech-split-mode), [h3 on edge UDP 443](DESIGN-DEFER.md#tls-h3-edge), [the PSL listing](DESIGN-DEFER.md#dns-psl-listing) (§12), [anycast](DESIGN-DEFER.md#tls-anycast). DESIGN-DEFER.md holds an entry for each, and for [this section's v1 set](DESIGN-DEFER.md#tls-v1) (owner decision 587).
