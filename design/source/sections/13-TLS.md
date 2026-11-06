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
- **Loading.** Beside each lb interface's nginx, §19 W1's `lbmap` loads the newest version: before nginx serves 443 at start, and otherwise 5 s after the first unapplied version, at most once per 15 min, since each reload keeps the old workers, with their connections, for up to `worker_shutdown_timeout` (60 min; warp/warpctl/config.go:1181). It renders `tls-custom-hosts.map` and the port-80 redirect's custom names from that version's rows, plus one line sending the version's probe name, `<digest[0:12]>.map.probe.invalid` (RFC 6761 §6.4), to tlsedge, runs `nginx -t`, reloads, and reports the version loaded with its nginx master's pid and start time (`POST /dns/custom-host-map/applied`, §12.8); a failed render, test or reload keeps the prior map and is reported. Its long-polls repeat the report, and an interface whose `lbmap` has not polled for 2 min, or whose nginx master has changed since its report, has loaded no version.
- **Route probes.** Every 10 s each dns edge sends each interface, on 443 as a visitor would, ClientHellos offering ALPN `ur-route-probe` then `http/1.1` for the probe name of the version that interface reported, and, once per reported version, for up to 16 hosts it added (§12.6). tlsedge answers each `unrecognized_name` with no Find (13.5), while the http branch would select `http/1.1` and present a platform certificate (warp/warpctl/config.go:1851-1887). An interface is current for a version once it reported that version or a later one loaded, an edge's probe of the reported version's probe name passed within the last 2 min, and the latest probe of each added host probed for the reported version passed, a failing host probe repeating every 10 s until one passes.
- **Ready.** A host is ready once every lb interface that §12.6's probe passes is current for its `map_version`. `GET /network/dns` shows a host that is not as pending, naming those interfaces, and devices start a TLS-ALPN-01 order, a renewal's included, only while it is ready (13.8); DNS-01 orders never wait. Readiness is an operational target, about 15 min and paged past 20 min (§19.8), not a timer.
- **Map-stale.** An interface that is not current for every version older than 20 min is map-stale: the dns edges drop it from user-name answers as they drop a failed one, never all (§12.6), and it pages until it is current again. A strong-mode host with static addresses misses that drop, as it misses every health drop (§12.8), and a host added meanwhile stays pending, naming the interface.

Until the reload, tlsedge answers a host that left the active rows `unrecognized_name` from §12's map (13.5). *Invariant:* a ready custom host's ClientHello reaches tlsedge on every interface that §12.6's probe passes, and platform, user, unknown and absent SNI route as before (§22.8 FS-35, FS-122).

**Gate.** Before any interface flips, §22 benches split against unsplit nginx on one test interface at the observed peak and at `concurrent_clients` (786,432; vault/main/services.yml:357): ≤5% less throughput on connect's H1 transport, ≤1 ms more p99 for connect and api, head-to-hint p99 ≤2 s, ≤15% more CPU per Gbit/s, memory within headroom. Nothing flips until it passes.

**Rollout** (§19 W1). `warpctl deploy main lb <version> <block>` (warp/warpctl/main.go:66-68) flips interfaces to the split one at a time. Each first runs it drained, out of DNS answers, so only probes and the gate's bench reach it; it then rejoins and is held 24 h against unsplit ones on the gate's metrics. Until launch, only internal and design-partner networks publish (owner decision 91).

**Probes.** An interface that does not answer a hello for the reserved `probe.edge.<root>` with tlsedge's `unrecognized_name` leaves user-name answers (§12.6); monitor's verified handshake and §19 W7's HTTPS checks with SNI drop a broken one from platform answers. From M5 a failing probe pages at any hour (owner decision 143). The `probe.edge.<root>` hello cannot test the custom-host map, since the `*.<root>` wildcard routes it whatever the map holds; the dns edges' route probes (custom hosts, above) do, and from M6 a map-stale interface leaves user-name answers and pages too.

**Ports.** 8443, 8883 and 5671 (owner decision 121) go unsplit to tlsedge as permanent stream ports (§19 W7), since no platform name uses them (vault/main/services.yml:339-341); tlsedge takes the port from its accepting listener, as DNAT rewrites PROXY's destination.

**PROXY.** tlsedge's listener (§4.5) takes PROXY v1 or v2 only from the lb, dropping connections without it. The visitor address feeds caps, §9's affinity key (a keyed /24 or /48 hash) and `TlsEdgeOpen.client_ip`; logs drop IP literals (server/scrub.go:112; §19.4).

**Port 80** stays with the http servers: a generated server for `*.<root>` and the active custom hosts redirects to `https://` and logs nothing (I-13), so no plaintext reaches tlsedge and HTTP-01 is never served.

### 13.5 tlsedge: the connection path

1. Read the PROXY header and TLS records until the ClientHello completes; a bounds-checked parser (`tlsedgeservice/clienthello.go`, after connect/ip_sni.go:331-462) extracts SNI, ALPN and ECH presence; anything else: alert and close. A hello whose ALPN list includes `ur-route-probe` gets `unrecognized_name` at once, whatever its SNI, with no lookup, Find or record: it is 13.4's route probe.
2. Normalize the SNI (lowercase, no trailing dot, LDH) and map it with the listener's port to `(network_id, tls/<port>/<host>)` through §12's cached label map (`<host>.<x>.<root>`, or `<x>.<root>` as `@`, `<x>` a label or live alias) or custom-host map; deeper names match only v1 scope hosts, `<label>.<scope>` (Q-TLS-3).
3. Check, in memory, the kill switch, the caps (13.9) and a 30 s negative cache of `no_listener` and `denied`, which absorbs scans.
4. Call Find (§9.6) as `autogroup:public` with the ALPN list, an affinity key and the process's K client ids; Find applies §8 `MayPublish` (for 13.9's system publish, the receiver's `smtp/25/mx` listen grant, §9.10) and `MayDial` and returns primary and backup tickets, each naming the tlsedge client that opens it.
5. From that client, send `StreamOpen{target, metadata: TlsEdgeOpen, ticket, early_data}` with the hello's first 2,048 B (§6.7), the rest of a longer (PQ) hello following at once in StreamData within the initial window, not after the accept. §9's retries finish before the visitor's first byte, showing only as delay; tlsedge blames a listener only for an accept timeout, never for a visitor's reset.
6. Splice under §6 credit; FIN maps to StreamClose, RST to StreamReset.
7. On failure, send a plaintext alert before any ServerHello and close: `unrecognized_name` for unknown, unpublished or denied names, which are indistinguishable; `internal_error` for no listener, busy, quota or overload. tlsedge never presents a certificate.

```proto
message TlsEdgeOpen {              // StreamOpen.metadata, edge -> listener (§6 0x1501), <= 512 B
  bytes client_ip = 1;             // 4 or 16 B, from PROXY; edge memory only
  uint32 client_port = 2;
  string server_name = 3;          // normalized SNI
  repeated string alpn = 4;        // offered by the visitor
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
proxy_header: {timeout_s: 2, max_bytes: 2048}
client_hello: {timeout_s: 10, max_bytes: 16384}
find: {timeout_s: 2, max_finds: 3}                  # D-SOCK-6
accept: {ticket_timeout_s: 5, setup_timeout_s: 15}
idle_timeout_s: 900                                 # the lb's proxy_timeout
drain_s: 600                                        # deploys drain, then reset; streams end at grant expiry
```

§22 targets (p95): setup adds ≤300 ms warm and ≤1.5 s cold, contract round trip and e2e handshake included.

### 13.6 tlsedge as a connect client

Each tlsedge process runs K connect clients in the platform network `urnetwork-edge` (§4's `ServiceClientSource`), Required and relay-only toward sidecars (D-PROTO-6), so `TlsEdgeOpen` rides only sealed streams; Find's tickets pin each listener's edge streams to one of them, spreading load across K inline readers (§9.6; [R:connect-transport] §2.4).

Contracts in both directions use §6.10.1's Service mode (C9; owner decision 11), issued only while §9's Find-recorded pair lives.

A sidecar provides Service only while it holds a `tls/` or §15 `smtp/` registration, within §6.7's edge-peer budget; above half of GOMEMLIMIT, new streams open at 64 KiB windows. Sidecars get `TlsHint` (orders, issuance, revocation) on topic `tls`, and suspensions through `sock` (§9.5).

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
| Audience (owner decision 42) | `members` (default): §7.8's edge login, checked against the front's config (§7.9; issuer trust: §2.8 EX8). `members-device` adds a §6 `Signed` (purpose `edge-login`) over origin and nonce by a member's consented device (§8.5), via the app or extension (§18). `link`: a URL token traded for a cookie (`raw`: the pinned client certificate). `public`: explicit, e.g. webhooks. Members on URnetwork may use the overlay (v1, §17) |
| Other origins (§12.4) | Session cookies (`__Host-ur-session`, a `link` cookie) count only on `Sec-Fetch-Site: same-origin` or `none`, or top-level GET or HEAD navigations (`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`); without Fetch Metadata, only with no `Origin` or the host's. Other requests, from the network's other hosts too, arrive anonymous (edge login under `members`). Browsers without Fetch Metadata (before March 2023: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site) still send them on other origins' GETs (§2.10) |
| Reach receipts (owner decision 25) | §16.8's `ReachReceipt` per publish grant, visitor and 5 min: SNI and a keyed `client_ip` hash (v1) |
| Control panels | Refused and recorded for the daemon's API or MCP port and for targets that answer like agent UIs (§16's list) |
| Interstitial | A one-time browser notice on Community `public` endpoints ([R:ext-edge] §2.8), never on 13.9's system publish |

### 13.8 Certificates

| Property | Choice |
|---|---|
| Identifier set | `{*.<net>.<root>, <net>.<root>}`: every one-label host, `mx.<net>` included (§15); CT shows only the opaque `<net>` (X5). Network-level devices add each live alias's pair, which §12 answers once a device holds it. A Team scope's devices (member or tag, Q-TLS-3; its mail receivers too) hold only `{*.<scope>.<net>.<root>, <scope>.<net>.<root>}` (owner decisions 40, 58); a member scope's set goes only to its member's consented devices (§8.5; owner decision 126) |
| Key | P-256 per listening device, sealed in its keychain (§5): never exported, in evs or on a server. One certificate per device, so I-15 is one revocation. Rotated every 180 days, on suspicion, or on request |
| Ordering (Q-TLS-2) | `POST /tls/cert-order`: the CSR plus a `Signed` attestation (purpose `tls-key`, §6.9) by the device's identity key. certs checks the caller's §8 grant, orders under URnetwork's ACME accounts (account and EAB keys in its `secret_files`, rolled over yearly per RFC 8555 §7.3.5, deactivated on compromise) and alone writes DNS-01 records (§12) |
| Challenge | DNS-01 in URnetwork zones, the only wildcard method; never HTTP-01. Orders wait for `GET /dns/ready`, handling `stale` as below, and a clean §12.6 canary, since CAs validate DNSSEC once the DS exists (CA/B SC-085v2, from 2026-03-15) and LE allows 5 failed authorizations per identifier per hour |
| Custom domains (Team, v1; owner decision 39) | One ACME account per domain, pinned by the customer's CAA `issue "letsencrypt.org; accounturi=<uri>"`. CAA discovery follows a CNAME and stops at the first non-empty RRset (RFC 8659 §3), so the pin excludes URnetwork only in strong mode, where the host has customer A/AAAA or a customer-side ALIAS that synthesizes only A and AAAA (§12.8). certs walks the whole discovery chain and publishes §12.8's canary CAA, with a per-check nonce, at the ALIAS target, a host owner `<host>.<net>.<root>` and never `@`, an apex host's too: at setup, the host pending until walk and probe pass (§12.8), and again at half the lifetime of the host's newest registered chain, before the desktops renew at two thirds. Only a CAA-flattening ALIAS returns the nonce at the host. The ordering desktops repeat the walk, not the canary, before each order: the walk does not rest on certs, but the canary does, so a compelled operator can pass a CAA-flattening ALIAS (§2.8 EX1; 13.16). A strong-mode host whose walk reaches an operator-controlled name (`custom_host_caa_operator_alias`) or returns the nonce is refused at setup and takes §12.8's failure effect at renewal. A host CNAMEd into an operator zone is weak mode, its setup disclosing §2.8 EX1's operator-issuance exception. An admin's desktop makes the account key in a `secret` repo of its own, one per domain (§11.12's owner-bound kind; never the config repo, owner decision 6, nor the admin's vault, since an `EvsShare` opens a whole repo), and shares it by `EvsShare` with the desktops holding the domain's publish grants (owner decision 126); every MCP evs tool and `ur://evs` resource refuses the kind (§16.6). They order with acmez (TLS-ALPN-01, only while `GET /network/dns` shows the host ready (13.4), or §12.8's delegated DNS-01), for mobile devices too, registering chains at `POST /tls/cert-register`; one must be online by two thirds of the lifetime. A holder's or the repo owner's removal rolls the key over (RFC 8555 §7.3.5) into a remaining holder's repo, keeping the pin |
| CAA | At `<root>`: `issue` and `issuewild` for `letsencrypt.org`, `pki.goog` (GTS, Google Trust Services; https://developers.google.com/public-key-infrastructure/faq/configure-caa) and `sectigo.com` (ZeroSSL; https://help.zerossl.com/hc/en-us/articles/360060119753), each with every URnetwork account URI and `validationmethods=dns-01`. No per-label URnetwork `accounturi` |
| CA, profile | LE `tlsserver`: 45 days, 25 names, 7 h authorization reuse (https://letsencrypt.org/docs/profiles/, 2026-10-04). GTS (100 new orders per hour per project), then ZeroSSL (unlimited 90-day certificates; [R:ext-edge] §2.4), when LE refuses on a limit, and first for ephemeral sidecars (CI, cloud agents) |
| Renewal | ARI (RFC 9773) via acmez v3 in the engine (Apache-2.0; https://github.com/mholt/acmez), using the stored CSR so devices may be offline; else at two thirds of the lifetime |
| Revocation | A device's certificate on removal (§5); a network's on takedown or deletion; an alias's when §12.5 retires it (I-14); `keyCompromise` on compromise. LE ended OCSP ([R:server-platform] §5), so the kill switch and 45-day lifetimes carry the load |

```text
certs' DNS writes: an order's _acme-challenge TXT, or a strong-mode probe's CAA canary (§12.8)
  write    POST /dns/acme-challenge or /dns/caa-canary, committed at serial s; 503 while a restore
           runs --> retry with backoff
  wait     GET /dns/ready?serial=s: ready --> the order, with §12.6's monitor canary clean, asks the
           CA to validate, or the probe starts its 10-min window; stale (a restore, §12.6; final for
           s) --> write again, the same TXT or the canary under a new nonce, and wait on the new serial
  verdict  a probe's pass counts only if /dns/ready?serial=s still answers ready after its last
           query; stale --> write again and restart the window, since the restored edges may lack
           the canary
```

**CT watch (D-TLS-8).** Each listening sidecar queries Cert Spotter (`issuances?domain=<net>.<root>&include_subdomains=true&match_wildcards=true`, https://sslmate.com/help/reference/ct_search_api_v1) and crt.sh for its zone and custom domains every ~6 h (jittered; optional Team key), alarming on a certificate no device attested in `GET /tls/certs` or one an identity pinned under 24 h before issuance attested. Failures show "CT watch degraded"; keyless queries are best effort and never ride a URnetwork proxy (§2.8 ext-1).

**Budget.** LE allows 50 new certificates per registered domain per 7 days across accounts (https://letsencrypt.org/docs/rate-limits/, 2026-08-05): each network's or scope's first certificate spends a unit of `<root>`'s shared budget, a repeated set gets 5 per 7 days (refill 1 per 34 h, no overrides), and ARI renewals skip all limits. certs (`certsservice`, taskworker chains) reimplements the extender pattern, which sidecar cannot import: a `network_tls_cert` queue, a weekly new-set cap below the CA's, counted in Redis `{tcb_}` (13.15), Retry-After holds, the row written before the order; rows stay 30 days past expiry or revocation, budget entries 7 days.

### 13.9 Endpoints, caps, metering, abuse

**Endpoint (PLAN.md:358).** An endpoint is an active publish grant per (host, port); custom-domain aliases count, listeners and certificates do not, and §20.7 counts `tls_endpoints` at grant activation. Each `tls/` registration passes `ValidateListen` (§9.4's owner hook):

```text
ValidateListen(tls/<port>/<host>) refuses
  host     unmappable (13.5); mta-sts, except the system publish below; a member-scope host from a
           device its member did not consent to (§8.5)
  port     other than 443, 8443, 8883 and 5671
  client   URnetwork-run (D-TLS-1)
  grant    no active approved publish grant for (host, port) (§8.10, I-8); an AppMode other than its
           app_mode; raw under an audience other than public or link; a raw link grant without
           link_spki_sha256 (13.7)
  cert     no unexpired certificate row, except an acme-tls/1-only registration before its first order
system publish tls/443/mta-sts (§15.5): AppMode http, audience public, no tls/ grant of its own
  only     a receiver (an approved smtp/25/mx listen grant, §15.4) holding an unexpired certificate row
           for the network's pair, in a network with network_verified (§21.7) and a mail_network row
           (§15.15)
  grant    that listen grant stands in for the tls/ listen and publish grants at registration, Find
           and admission (§9.10); its expiry or revocation ends that receiver's publish
  serving  the receiver's mail component answers; no interstitial, tls_endpoints unit or expiry of its own
```

Caps protect the devices, which do the handshakes: endpoint caps are tier quotas, visitor caps `sidecar_abuse:` limits equal on every tier (§20.4, D-QUOTA-7); §21 tightens either per network.

| Cap | Community / Pro / Team | Where |
|---|---|---|
| Concurrent per endpoint | 256 / 2,048 / 8,192 | cap ÷ blocks per process, no shared counter |
| New per endpoint | 50 / 200 / 1,000 per s | token bucket per process |
| Bandwidth per endpoint | 20 / 200 / 1,000 Mbit/s | token bucket in the splice, cap ÷ blocks |
| Per visitor /64 (IPv6) or /32 (IPv4), per process | 64 concurrent, 20 per s; 4× those per /48 or /24 | HMAC under a per-process key rotated daily |
| Per process | 50,000 connections | tlsedge.yml; §19 derives §9's platform Find limit from it |

**Abuse hooks** (owner decision 41; §21 sets policy), none inspecting content:
- **Kill switch.** `POST /tls/suspend` writes `network_tls_suspension` (§19.7), then one MULTI sets `{tes_<network_id>}` (`<host or *>` → reason, until) and INCRs its trigger (D-PROTO-12). tlsedge, on the shared key-event subscriber (§4.5), refuses new connections and resets open ones within 5 s, reloading from Postgres every 60 s; Find refuses too, and §8 suspension and revocation follow (§21.6). Row and keys go only when the case lifts it or `until` passes; a reload drops a kill only once neither its row nor its key holds it, so a Postgres restore lifts none, and §19.10's abuse step re-applies the kills and lifts mailed after the dump (§21.10).
- **Time box, verification.** Publishes follow §8's `expires`: 24 h by default, at most 7 days on Community, 24 h on probation (§21.7); standing names only in Pro and Team documents (§8.5). They need §21.7's `network_verified`, so anonymous-only networks publish nothing (owner decisions 41, 96).
- **Published names, CT.** Active publish grants (host, port, label, expiry) form the list §21.6 checks hourly against Web Risk; reviewers open reported URLs as visitors, joining connections by `connection_id` for 24 h; §21's worker screens CT under `<root>` (§21.8), and D-TLS-8 covers mis-issuance.

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
- **Subprotocol messages:** `TlsEdgeOpen` (0x1501; StreamOpen metadata, edge→listener); `TlsHint` (0x1502; push `tls`).
- **API routes** (api; bringyour.yml, route_authz.go):
  - `POST /tls/cert-order` (service token, aud `certs`; caller holds a §8 `tls/` or `smtp/` grant; CSR, attestation); `GET /tls/cert-order/<id>` (state, retry_after, chain, ARI window).
  - `POST /tls/cert-register` (Client; a custom domain's chains, v1); `GET /tls/certs` (Client; certificates, attestations and queued custom-domain CSRs).
  - `POST /tls/cert-revoke` (OwnClient; Network admin for any); `POST /tls/suspend` (internal, §21).
- **Tables** (migrations ≥926): `network_tls_cert` (certs; orders and certificates, with §2.8 cert-1's fields); `network_tls_suspension(network_id, host, reason, until)`; `tls_connection_record` (hourly partitions, dropped at 24 h once a §21.9 hold has copied out its network's rows, owner decision 133); `tls_connection_day` (13 months). Redis: `{tes_<network_id>}` and trigger `{tes_<network_id>}n`; certs' budget `{tcb_<ca>_<registered_domain>}`, a sorted set of the last 7 days' new-set orders, checked against the cap and added to in one script (server/ip_ratelimit.go:105's sliding window), expiring 7 days after its newest order and rebuilt from `network_tls_cert` on loss.
- **Services and config:** `server/cli/tlsedge` blocks behind the split and the port list (TCP 443, 8443, 8883 and 5671; nothing on 80); the lb's generated `/run/warp-lb/tls-custom-hosts.map` and port-80 names, and `lbmap`, which generates and loads them beside each interface's nginx (13.4); certs as taskworker chains, routes in api; `config/<env>/tlsedge.yml` (13.5; caps in pro.yml); certs' account and EAB keys in vault (13.8).
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
| A custom domain's certificates lapse with no ordering desktop online | Medium | Medium | Two ordering desktops; warnings from half-life |
| Raw clients lack TLS 1.3 or client certificates for a `link` endpoint | Medium | Low | `public` with the service's own authentication; members' overlay access (§17) |

### 13.17 Phasing

**v0** (§23 M5): the split after its gate and drained rollout, its custom-host map empty; tlsedge and Service contracts; certs with LE, GTS, ZeroSSL, ARI and per-device keys; the front with `members` login and `AppMode` dispatch (FS-34); desktop `ur bridge public-tls`; the CT watch; ports 443, 8443, 8883 and 5671; app listeners with §18 and the MTA-STS system publish with §15 (both M8). It waits on §9's `tls/` and Find, §6 streams, C9, §12's dns edge, §19's W1, §7.8's edge login, §21's kill-switch policy and the LE override's lead time.

**v1** (§23 M6): Team custom domains (with §12's custom-host-add, the split's custom-host map with its versions, interface reports and readiness, and strong-mode CAA checks; FS-32, FS-35, FS-122), Team scopes, affinity, `members-device`, overlay access for members (§17), and publish reach receipts (§16).

**Later:** ECH split mode, h3 on edge UDP 443, the PSL listing (§12), anycast.
