# Fact sheet: public edge, DNS, certificates, tunnels (ext-edge)

Research date 2026-11-03. Scope: PLAN.md "DNS and TLS edge" and "Abstract socket listener". Code paths are relative to `/Users/brien/urnetwork`. "inference:" marks my reasoning. Where a design note and the code disagree, the code wins. `<edge>` is whichever registrable domain carries user names, `<label>` is a network's DNS label, and `<name>` is a listener name.

## 1. Summary

1. **The plan and the pitch disagree on where TLS ends.** PLAN wants the tlsedge to "do its own certificate termination" (`sidecar/PLAN.md:84`). pitch5 promises "TLS passthrough. The certificate key stays in the sidecar" (`sidecar/pitch5.html:699`). market2 says "private from us" fails at "a terminating TLS edge" (`sidecar/market2.md:338`). Today the LB terminates every hostname with static vault certificates (`warp/warpctl/config.go:1857-1888`).
2. **The LB is close to passthrough already.** The pinned nginx has `--with-stream_ssl_preread_module` (`warp/lb/Dockerfile:58`), and warpctl already emits `stream` servers with `proxy_protocol on` (TCP) or `v2` (UDP) (`warp/warpctl/config.go:2496-2510`).
3. **Let's Encrypt caps new certificates at 50 per registered domain per 7 days, shared across all accounts, and 5 per exact identifier set.** Renewals skip the first cap, and ARI renewals skip every cap ([LE, 2026-08-05](https://letsencrypt.org/docs/rate-limits/)). ur.network is not on the Public Suffix List (PSL), so all its names share one budget.
4. **Certificate Transparency publishes every SAN permanently, and scanners use it within minutes** ([IMC 2018](https://arxiv.org/abs/1809.08325)). A per-network wildcard hides listener names, but not the network label, and network labels are human-chosen today (`server/model/network_model.go:178-205`).
5. **The PSL is not a fix for rate limits.** Its rules exclude rate-limit workarounds and require more than 2 years of registration and thousands of users ([guidelines](https://github.com/publicsuffix/list/wiki/Guidelines)). URnetwork's PR #3465 was withdrawn on 2026-11-01, and ur.network expires on 2027-07-02 (RDAP).
6. **ur.network is already a platform domain.** api, connect, `*.connect`, mcp, gossip, grafana, the apex, www and `*.<lb-host>` are configured under it (`vault/main/services.yml:11-35,587-588,641-694,729,739`). Talos files it as "Personal VPN", and Google Safe Browsing has flagged whole shared domains for one tenant's phishing.
7. **Tailscale Funnel is the closest prior art.** The relay is a TCP proxy that doesn't decrypt, the node terminates TLS, and the node generates its own keys. Control only writes the DNS-01 TXT record (`SetDNS`). TLS-ALPN-01 is used for renewals and for bring-your-own (BYO) domains, and renewals follow ARI.
8. **ECH is RFC 9849 (March 2026), and its split mode fits passthrough.** But `ssl_preread` and HAProxy `req.ssl_sni` see only the outer SNI, a decoy. QUIC, SMTP STARTTLS and HTTP/2 connection coalescing also break naive SNI routing.
9. **SO_REUSEPORT hashes the 4-tuple, ignores load, and aborts a closing listener's queue unless `tcp_migrate_req` is set.** For remote listeners of uneven capacity, weighted power-of-two-choices (P2C) on in-flight streams, with explicit drain, fits better.
10. **Much of this exists in-house:** a DNS-01 ACME pipeline with caps (`server/taskworker/work/extender_measurement_acme.go:30-50`), LE, PSL and CAA runbooks (`mmm/lag.dev/ops/*.md`), and connect subprotocols.

## 1b. Answers to the four questions

**(a) Where TLS should terminate.**
- **In the listening sidecar on the user's device.** No URnetwork machine holds the key.
- **The path:**
  1. The LB forwards TCP 443 for `<edge>` names unterminated, with PROXY protocol.
  2. The tlsedge peeks at the ClientHello (SNI, ALPN), maps SNI to `network:name`, and picks a listener (see (d)).
  3. It runs the accept handshake, replays the buffered ClientHello, and splices bytes over a connect subprotocol stream.
- **Reading PLAN.md:84.** Take "its own certificate termination" to mean the tlsedge owns routing, ACME orchestration (TXT and CAA writes) and L4 policy. The key stays in the sidecar, as pitch5 promises.
- **Edge termination, if offered at all, is an explicit opt-in** (managed TLS, for example for a WAF or edge auth). It must be named in the publish record.
- **What moves into the sidecar:** auth-by-default, refusing agent control panels (`sidecar/pitch5.html:697`), warning pages, and HTTP 421.
- **What the edge still sees:** SNI, client IP, timing and byte counts. The threat model must say so. ECH split mode could later hide SNI from on-path observers, but not from the edge.

**(b) Certificate strategy.**
1. **A dedicated registrable domain for user names, not ur.network** (§5 R2), registered for 5 years or more.
2. **One wildcard per network, not per listener: `*.<label>.<edge>`.** `<label>` is opaque by default, a random or id-derived token like ts.net's tailnet names. Friendly labels (PLAN's `<me>`) are opt-in and labeled public.
3. **The key is P-256 and generated on a sidecar** (as `feature/acme/cert.go:596` does in Tailscale). It is shared with the network's listener devices only through E2E storage, so all replicas present one certificate. That stays clear of the 5-per-week exact-set limit.
4. **Prefer one ACME account per network**, with its key also in E2E storage.
   - The server only writes `_acme-challenge.<label>` TXT records, scoped by the network's JWT (Tailscale's `SetDNS` model).
   - Publish CAA at `<label>.<edge>`: `issue "letsencrypt.org; accounturi=<network acct>; validationmethods=dns-01"`, plus the same for `issuewild`. To issue silently, URnetwork would then first have to change CAA, and LE relies on a CAA check for up to 8 hours (`mmm/lag.dev/ops/caa.md:126-131`).
   - The sidecar watches its CAA record and CT for keys that aren't its own.
   - The fallback is a CSR proxy on a URnetwork account. It allows several CAs, but URnetwork's own issuance could then be caught only through CT.
5. **Rate limits.**
   - Only a network's first wildcard spends the 50.
   - Request a domain override, not an account override, weeks before launch. A domain override covers every account (`mmm/lag.dev/ops/letsencrypt.md:299-317`).
   - Renew by ARI with lego or acmez. `x/crypto/acme` has no ARI (`server/taskworker/work/extender_measurement_acme.go:33-35`).
   - Fallback CAs are GTS (100 new orders per hour per project) or ZeroSSL, both through EAB, and listed in CAA.
6. **Profiles.** Use `tlsserver` (45 days) now, because `classic` reaches 45 days on 2028-02-16. Use `shortlived` (160 hours, at most 25 names) for short-lived publishes.
7. **Custom domains (Team tier).** Use TLS-ALPN-01, answered by the sidecar through passthrough (Tailscale's BYO-Funnel path). A one-time `_acme-challenge` CNAME into our ACME zone covers wildcards and offline renewal. dns-persist-01 is frozen at LE, so don't depend on it.
8. **PSL later, for browser isolation**, once there are about 3,000 users, more than 2 years of registration and an abuse process. Until then, nothing in the platform sets cookies on `<edge>`, and sidecar auth cookies use the `__Host-` prefix.

**(c) DNS hosting.**
- **Leave the parent zones on Route 53.** ur.network, recurd.dev and the `<edge>` apex stay under `warpctl dns sync`, which already runs health-checked weighted LB sets (`warp/warpctl/dns.go:14-41`, `warp/warpctl/dns_route53.go:44-53`).
- **Delegate one dynamic zone to our own authoritative service.** The zone is `<edge>` or `n.<edge>`, and its answers are computed from the database:
  - per-label wildcard A/AAAA records, or a CNAME to the health-checked LB name;
  - challenge TXT records with a TTL of 60 s or less;
  - per-label CAA;
  - user records within the pricing caps (5, 200 or 2,000, `sidecar/PLAN.md:357`);
  - an SOA minimum of 60 s.
- **Software:** Go on miekg/dns, embedded CoreDNS, or PowerDNS (HTTP API, live signing).
- **One zone, not per-tenant zones.** PLAN's per-network zone (`sidecar/PLAN.md:25`) can be logical ownership inside one zone; real child zones add cost, throttles and DS work for no gain.
- **Hidden primary with at least one anycast secondary** over AXFR/IXFR and NOTIFY (NS1, Cloudflare Enterprise and others). Route 53 can't act as a secondary.
- **Launch unsigned, or with tested online signing.** CAs must validate DNSSEC since 2026-03-15, so a signing fault blocks issuance.

**(d) Listener scheduling.**
- **Per connection:**
  1. Filter to eligible listeners: granted, healthy, not draining, ALPN matches, region preferred.
  2. Pick two at random and take the one with the lower in-flight-to-capacity ratio (weighted P2C).
  3. Ramp new listeners up with slow start.
- **Retry.** On an accept timeout or refusal, try the other candidate. The ClientHello is still buffered at the edge, so the client never sees the retry.
- **Affinity is opt-in:** rendezvous hashing on the client IP prefix, with bounded load (c ≈ 1.25).
- **Drain.** `unlisten` drops a listener from selection at once. A racing accept gets "retry elsewhere", the analog of `tcp_migrate_req`. Existing streams get a grace period (cloudflared defaults to 30 s).
- **Joining a group requires authorization for `network:name`.** This mirrors SO_REUSEPORT's same-UID rule against port hijacking.

## 2. Facts with citations

### 2.1 Plan and positioning
- **PLAN:** "A network has a dns zone <me>.ur.network" (`sidecar/PLAN.md:25`); "load balancers forward *.ur.network to the tlsedge service" (`:81`); "does a find listener and accept handshake" (`:82`); "a fair scheduler similar to socker reuse on linux" (`:69`); "terminates a public mail.<me>.ur.network" (`:104`). Pricing: DNS entries 5/200/2,000, TLS edge 1/20/200, custom domains on Team only (`:357-364`).
- **pitch5:** "Explicit, authenticated by default, and short-lived. Agent control panels are refused" (`sidecar/pitch5.html:697`). **product.md** leaves open "whether the public TLS edge is authenticated" (`sidecar/product.md:35`).
- **EXTENDERUPDATE:** enterprise names go on `recurd.dev`, "never on ... ur.network" (`connect/EXTENDERUPDATE.md:160-166`). The private CA "was a cited reason the Public Suffix List rejected extender.bringyour.com" (`:189`). "default the enterprise edge to customer-owned domains" (`:233`).

### 2.2 Code and config today
- **TLS at the LB.**
  - The LB serves `listen 443 ssl reuseport backlog=65535` with one certificate per server block, read from `/srv/warp/vault/tls/...` (`warp/warpctl/config.go:1857-1888`, `:871-905`).
  - QUIC on 443 is off when a service streams UDP 443 (`:951-966,1867-1872`).
  - nginx is pinned to commit `11d11b5f`, "NGINX 1.31.4" (`warp/lb/Dockerfile:6,56-58`; `warp/lb/nginx_proxy_protocol_test.go:51`).
  - TCP stream ports use `proxy_protocol on` (PROXY v1); UDP uses `proxy_protocol v2` plus `reuseport` (`warp/warpctl/config.go:2477-2520`).
- **PROXY parsing in the server** uses `github.com/mailgun/proxyproto` for v1 and v2 (`server/connect/transport_pp.go:14-27,57-71`; `server/go.mod:27`). That repo was last pushed on 2023-04-07; `pires/go-proxyproto` was pushed on 2026-10-31 (GitHub API).
- **`TransportTls.GetTlsConfigForClient`** picks a static certificate by SNI. There is no ACME in that path (`server/tls.go:110`).
- **warpctl certificates.** `warpctl certs issue` runs `goacme/lego:v4.35.2` with DNS-01 through Route 53 or Cloudflare, with a fresh `.lego` home per run (`warp/warpctl/main.go:1786-1900`). The runbook adds that this means a new account each run and no ARI (`mmm/lag.dev/ops/letsencrypt.md:21-35`).
- **lag.dev ACME.**
  - It uses `x/crypto/acme` with DNS-01 and "no renewal information (ARI)", renewing at two thirds of lifetime. "Route 53 is in sync within about a minute" (`server/taskworker/work/extender_measurement_acme.go:30-50`).
  - A weekly cap guards bringyour.com's "50 new certificates a week ..., which its other names draw on too" (`server/taskworker/work/extender_measurement_work.go:384-392`).
  - The account exists, the cap went from 5 to 30 on 2026-10-31, and no override has been sent (`mmm/lag.dev/ops/letsencrypt.md:7-9`).
- **DNS sync.** `warpctl dns plan|sync` reconciles Route 53 or Cloudflare. LB sets are weighted and health-checked on port 80 every 10 s with a threshold of 3, in batches of 200 (`warp/warpctl/dns.go:14-41`; `dns_route53.go:44-53`).
- **Registrars.** ur.network and bringyour.com are on Route 53. ur.io, ur.xyz, vpn.dev, ww.dev and lag.dev are on Cloudflare. TTL is 60 (`vault/main/services.yml:3-10,51-53`).
- **ur.network, as observed on 2026-11-03:**
  - RDAP: expires 2027-07-02, awsdns nameservers, `delegationSigned: false` ([rdap.org](https://rdap.org/domain/ur.network)).
  - `dig @8.8.8.8`: the apex and `main-lb` resolve to 65.49.70.70, and `api.ur.network` is NXDOMAIN, even though it is configured. The SOA is `900 ... 86400`, so absent names are cached for up to 900 s.
- **Network names.**
  - 5–50 characters of `[a-z0-9-]` (`server/model/network_model.go:178-205`); generated names look like `word-word-NN` (`server/model/util.go:41-57`).
  - Leading or trailing `-` and `xn--` are not rejected (inference: invalid or misleading as DNS labels).
  - A released name can be reclaimed after 24 hours (`server/controller/account_controller.go:13,160-172`).
- **Reputation.** Talos lists ur.network as "Personal VPN", and ngrok's tunnel domains as "Computers and Internet" (`sidecar/research_notes/Sidecar pitch4 differentiation directions/L2-2.12-how-do-outside-in-security-controls-classify-urn.md:97,152,169`).

### 2.3 Let's Encrypt ([rate limits](https://letsencrypt.org/docs/rate-limits/), updated 2026-08-05)
- **Limits:**

  | Limit | Value |
  |---|---|
  | New accounts | 10 per IPv4 per 3 h; 500 per IPv6 /48 |
  | Orders | 300 per account per 3 h |
  | New certificates per registered domain (or IPv4, or IPv6 /64) | 50 per 7 days, "shared across all accounts", refilling one per 202 minutes |
  | Same identifier set | 5 per 7 days; adding a name makes a new set, which is "not treated as a renewal" |
  | Failed authorizations | 5 per identifier per hour; paused after 1,152 consecutive failures |

- **Registered domain** is determined by the PSL. Overrides exist only for orders and per-domain limits, and take "a few weeks".
- **Renewals.** A same-set order is exempt from the order and per-domain limits, but not from the failure and exact-set limits. ARI renewals are "exempt from all rate limits" if they name the certificate being replaced, share an identifier with it, and that certificate hasn't already been replaced.
- **Profiles** ([profiles](https://letsencrypt.org/docs/profiles/), 2026-10-04):

  | Profile | Lifetime | Max names | Authorization reuse | Pending authorization | Order lifetime |
  |---|---|---|---|---|---|
  | classic | 90 days | 100 | 30 days | | |
  | tlsserver | 45 days | 25 | 7 h | 1 h | 8 h |
  | shortlived | 160 h | 25 | 7 h | 1 h | 8 h |

  shortlived also allows IP addresses and needs no revocation information.
- **Timeline** ([LE 2025-12-02](https://letsencrypt.org/2025/12/02/from-90-to-45/)):
  - tlsserver went to 45 days on 2026-05-13.
  - classic goes to 64 days with 10-day authorization reuse on 2027-02-10.
  - classic goes to 45 days with 7-hour reuse on 2028-02-16.
  - "renewing at a hardcoded interval of 60 days will no longer be sufficient."
- **CA/B SC-081v3** (2025-04-11): maximum validity falls from 398 to 47 days, and SAN data reuse to 10 days, by March 2029 ([CA/B](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/)).
- **ARI** is RFC 9773, June 2025 ([RFC](https://www.rfc-editor.org/rfc/rfc9773)). Supported by lego v5.6.0 (`certificate/renewal.go`), acmez v3.1.7 (`acme/ari.go`) and Tailscale's [tempfork/acme](https://github.com/tailscale/tailscale/tree/main/tempfork/acme).
- **DNS-PERSIST-01** uses a record at `_validation-persist.<domain>` of the form `"letsencrypt.org; accounturi=...; policy=wildcard"` ([LE 2026-02-18](https://letsencrypt.org/2026/02/18/dns-persist-01.html)). On 2026-06-25 staff said: "We will not be deploying dns-persist-01 until" issue #64 is resolved ([forum](https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468)).
- **Challenges** ([challenge types](https://letsencrypt.org/docs/challenge-types/)):
  - HTTP-01 uses port 80 and can't issue wildcards.
  - TLS-ALPN-01 uses port 443 and can't issue wildcards.
  - DNS-01 allows wildcards, and LE follows CNAME or NS delegation of `_acme-challenge`.

### 2.4 Other CAs, CAA, MPIC, DNSSEC
- **ZeroSSL** requires EAB. It offers an "unlimited amount of 90-day SSL certificates" with wildcards ([ZeroSSL](https://zerossl.com/documentation/acme/)).
- **Google Trust Services.** EAB comes from `gcloud`, with one account per EAB secret, used within 7 days ([GTS](https://docs.cloud.google.com/certificate-manager/docs/public-ca-tutorial)). The quota is 100 new orders per hour per project ([quotas](https://docs.cloud.google.com/certificate-manager/docs/quotas)).
- **Buypass** stopped issuing TLS certificates after 2025-10-31 ([Buypass](https://www.buypass.com/products/tls-ssl-certificates/discontinues-issuance-of-tls-ssl-certificates)).
- **CAA at LE** ([CAA](https://letsencrypt.org/docs/caa/)): LE honors `accounturi` and `validationmethods`. The CAA record closest to the name wins, and CNAMEs are followed.
- **CAA caching.** The CA "issues ... within the TTL of the CAA record, or 8 hours, whichever is greater" (`mmm/lag.dev/ops/caa.md:126-131`, citing CP/CPS §4.2.1).
- **Multi-perspective validation** has run since February 2020 ([USENIX Sec 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/birge-lee)). DNS-01 is corroborated from at least two regional internet registries (`mmm/lag.dev/ops/letsencrypt.md:612-614`).
- **DNSSEC.** SC-085v2 requires DNSSEC validation (when present) of CAA and DCV lookups from 2026-03-15 ([CA/B](https://cabforum.org/2025/06/18/ballot-sc-085v2-require-validation-of-dnssec-when-present-for-caa-and-dcv-lookups)).

### 2.5 Public Suffix List
- **Rules** ([guidelines](https://github.com/publicsuffix/list/wiki/Guidelines)):
  - A `_psl` TXT record must hold the PR URL.
  - The domain needs more than 2 years of registration left, and must stay above 1.
  - "We do not accept entries whose sole purpose is to circumvent rate limits of third parties."
  - Projects "not serving more then thousands of users are quite likely to be declined."
  - "NO SERVICE LEVEL AGREEMENTS ON TIME."
- **PR #3465 (extender.bringyour.com)** was opened 2026-10-24 and withdrawn 2026-11-01. The reviewer raised 8 operators, the private "Extender Root" CA and the 2026-11-15 expiry, and asked what threat `__Host-` cookies don't already address ([PR](https://github.com/publicsuffix/list/pull/3465)).
- **Internal measurements** (`mmm/lag.dev/ops/psl.md:31-41,280-300`):
  - Reviewers in 2026 applied "more then 3000 distinct individuals ... active in the last 7 days."
  - The median merge took 9.8 days, and about 23% of PRs were merged.
  - Chrome refreshes its copy every 36–186 days; LE's Boulder bumps take 2 weeks to months.
- **Peers on the list** (VERSION 2026-10-31): ts.net and `*.c.ts.net`; ngrok.app, ngrok-free.app, ngrok.dev, ngrok-free.dev, ngrok.io, ngrok.pizza and ngrok.pro; trycloudflare.com; tunnelmole.net. zrok.io and loca.lt are absent ([data](https://publicsuffix.org/list/public_suffix_list.dat)).
- **Unlisted means same-site.** A user page can toss `Domain=` cookies, and `SameSite` cookies ride along (`mmm/lag.dev/ops/psl.md:44-62`). inference: listing ur.network itself would make app., api. and connect.ur.network cross-site.
- **Whole-domain Safe Browsing flags:**
  - statichost.eu was flagged on 2025-09-25 over customer phishing, and moved users to `statichost.page` with a PSL request ([statichost](https://www.statichost.eu/blog/google-safe-browsing/)).
  - `*.immich.cloud` was flagged in October 2025 over previews ([Immich](https://immich.app/blog/google-flags-immich-as-dangerous)).
  - `share.zrok.io` has also been flagged ([forum](https://openziti.discourse.group/t/issue-with-google-safe-browsing-flagging-share-zrok-io-subdomains-as-unsafe-phishing/6017)).

### 2.6 Certificate Transparency
- **Tailscale:** "the machine names are still published in the public ledger". Tailnet names keep organization names out, and both keys are generated locally: "Tailscale never sees them" ([HTTPS](https://tailscale.com/kb/1153/enabling-https)).
- **Speed and permanence.** CT data picks scan targets "only minutes after certificate issuance" ([Scheitle 2018](https://arxiv.org/abs/1809.08325)), and the records are permanent (`mmm/lag.dev/ops/privacy-review.md:36`).
- **Wildcard reach.** inference: `*.<label>.<edge>` covers exactly one label. A single `*.<edge>` key would serve every network's names, so it must never reach devices.

### 2.7 SNI passthrough mechanics
- **nginx ssl_preread** (1.11.5) reads SNI and ALPN "without terminating SSL/TLS" ([nginx](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html)).
- **nginx `pass`** (1.25.5) refuses UDP and "cannot pass connection with preread data" ([ngx_stream_pass_module.c](https://github.com/nginx/nginx/blob/master/src/stream/ngx_stream_pass_module.c), about lines 86-95). An SNI split on a shared IP therefore needs `proxy_pass` to a loopback listener using `proxy_protocol` and `set_real_ip_from`.
- **HAProxy** ([configuration.txt](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt), `req.ssl_sni`):
  - Pattern: `tcp-request inspect-delay` + `accept if { req.ssl_hello_type 1 }` + `use_backend`; `send-proxy-v2` carries the address and ALPN.
  - The manual warns that SNI "is not reliable enough to be used alone for allowing or denying access", and that only the first ClientHello is read.
  - With ECH it sees the "decoy" outer SNI, and it "will not work for explicit TLS ... SMTP (25/587)".
- **ECH:**
  - In RFC 9849 split mode, "the provider is not the origin server". It decrypts the outer hello and "forwards the ClientHelloInner to the appropriate backend server" ([RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html)).
  - The ECH config is published in the HTTPS/SVCB `ech` parameter ([RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html)).
  - Firefox has ECH on by default from version 119, with DoH ([Mozilla](https://support.mozilla.org/kb/understand-encrypted-client-hello)).
  - Go 1.24 has server-side ECH through `Config.EncryptedClientHelloKeys`, shared mode only ([Go 1.24](https://go.dev/doc/go1.24)).
  - inference: if we publish no `ech` config, clients send GREASE and the real SNI, so routing works.
- **HTTP/2 coalescing.** A connection "MAY be reused" for any origin its certificate covers, which "can result in requests being directed to the wrong origin server". The fix is a 421 response ([RFC 9113 §9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html)). inference: with one wildcard per network on shared edge IPs, a browser can send `b.<label>` requests down the connection that was routed to `a.<label>`'s device.
- **QUIC.** inference: nginx can't preread QUIC SNI, so user names are TCP-only, and sidecars must not advertise `Alt-Svc: h3`.
- **SMTP.** Postfix sends no SNI "absent DANE" ([postconf](https://github.com/vdukhovni/postfix/blob/master/postfix/proto/postconf.proto), `smtp_tls_servername`), so inbound mail can't be routed by SNI.
- **Go SNI sniffing.** `inetaf/tcpproxy` runs `tls.Server(...)` over the peeked bytes and captures `ServerName` in `GetConfigForClient` (`sni.go:83-115`, [tcpproxy](https://github.com/inetaf/tcpproxy), Apache-2.0).

### 2.8 Tunnel prior art
| Product | Names and certificates | Where TLS ends | Multiplexing | Several connectors | Abuse controls |
|---|---|---|---|---|---|
| Tailscale Funnel | `<machine>.<tailnet>.ts.net` (on the PSL); ports 443, 8443, 10000. DNS-01 through control `SetDNS` (`feature/acme/cert.go:633-661`); TLS-ALPN-01 for renewals and BYO domains (`:253-293`); ARI (`:170-250`); local account key (`certstore.go:116,377`) | The node: "Funnel relay servers do not decrypt" ([Funnel](https://tailscale.com/kb/1223/funnel)) | The relay TCP-proxies over the tailnet | Not documented | `funnel` node attribute; bandwidth limits |
| ngrok | `*.ngrok-free.dev` and others; custom domains by CNAME with automatic certificates ([domains](https://ngrok.com/docs/universal-gateway/domains/)) | Cloud, agent or upstream; end to end, "the ngrok cloud service can not see payload" ([TLS](https://ngrok.com/docs/universal-gateway/tls/)) | `muxado/v2` (ngrok-go go.mod) | Pools: nearest PoP, then "a random distribution", per connection for TLS; no retry ([pooling](https://ngrok.com/docs/universal-gateway/endpoint-pooling)) | Free-plan browser warning page ([ERR_NGROK_6024](https://ngrok.com/docs/errors/err_ngrok_6024)) |
| Cloudflare Tunnel | Customer CNAME; `*.trycloudflare.com` | Cloudflare | 4 connections over at least 2 data centers; QUIC with HTTP/2 fallback; `grace-period` 30 s ([params](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/cloudflared-parameters/run-parameters/)) | "geographically closest replica", "no traffic steering" ([availability](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-availability/)); 25 replicas per tunnel ([account limits](https://developers.cloudflare.com/cloudflare-one/account-limits/), via search summary) | trycloudflare abused for remote-access trojans ([Proofpoint 2024](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)) |
| zrok / OpenZiti | `*.share.<zone>`, wildcard certificate via Caddy DNS challenge (zrok `website/docs/self-hosting/deployment/docker.mdx:180-202`) | The public frontend | OpenZiti, with E2E libsodium for application data ([OpenZiti](https://netfoundry.io/docs/openziti/learn/core-concepts/security/connection-security/)) | | Safe Browsing flags |
| frp | `subDomainHost` / `customDomains`; `type="https"` routes by SNI, and frpc can terminate with `https2http` | Client or service | `transport.tcpMux` (fatedier/yamux) | `loadBalancer.group`, "dispatched ... randomly", with health checks ([README](https://github.com/fatedier/frp), v0.71.1) | Self-hosted |
| iroh | Public-key endpoint IDs, no DNS names | End to end; relays "cannot read any of the traffic" ([relays](https://docs.iroh.computer/concepts/relays)) | QUIC with relay fallback (v1.4.1, 2026-10-22) | | Public relays are rate-limited |
| localtunnel, Pinggy | Random subdomains; Pinggy runs `ssh -p 443 -R0:localhost:8000 free.pinggy.io` ([Pinggy](https://pinggy.io/docs/)) | inference: the front proxy | localtunnel uses a pool of TCP sockets (`lib/TunnelAgent.js:32,92`) | | Phishing through tunnels ([F-Secure](https://blog.f-secure.com/localhost-tunnellers-give-low-skilled-attackers-a-bad-way-to-set-up-phishing-infrastructure)) |

### 2.9 Authoritative DNS
- **Route 53** ([quotas](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html), [throttling](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/throttling-api-requests.html)):
  - 500 zones and 10,000 records per zone by default.
  - Requests per account: 50 burst, 10 per second sustained. Changes: 1,500 burst, 100 per second sustained, and an UPSERT counts as 2.
  - Each zone returns `PriorRequestNotComplete` while a change is pending.
  - $0.50 per zone per month (first 25), then $0.10 ([pricing](https://aws.amazon.com/route53/pricing/)).
  - No zone transfers ([re:Post](https://repost.aws/questions/QUC-kLqJFiTW6N6fb_aW93NQ/route53-zone-transfers-to-secondary-nameservers)).
- **Cloudflare:** API 1,200 requests per 5 minutes ([limits](https://developers.cloudflare.com/fundamentals/api/reference/limits/)); 200 records per new Free zone, 3,500 per Pro ([records](https://developers.cloudflare.com/dns/manage-dns-records/)); secondary DNS is Enterprise-only ([transfers](https://developers.cloudflare.com/dns/zone-setups/zone-transfers/)).
- **Self-hosted:** miekg/dns v1 "will only see specific fixes", and v2 is on codeberg ([miekg](https://github.com/miekg/dns)). CoreDNS `dnssec` signs on the fly with NSEC black lies ([CoreDNS](https://coredns.io/plugins/dnssec/)). PowerDNS live-signs ([PowerDNS](https://doc.powerdns.com/authoritative/dnssec/modes-of-operation.html)).
- **Wildcards.** An empty non-terminal "exists" and blocks a wildcard above it ([RFC 4592 §2.2](https://www.rfc-editor.org/rfc/rfc4592.html)). inference: `_acme-challenge.<label>` stops `*.<edge>` from matching names under `<label>`, so each label needs a `*.<label>` record or a synthesized answer.
- **Negative caching** lasts min(SOA TTL, minimum). Route 53's defaults are 900 and 86400, and the runbook sets both to 60 (`mmm/lag.dev/ops/route53.md:111-130`).
- **Customer domains:**
  - Cloudflare's delegated DCV uses `_acme-challenge.example.com CNAME example.com.<validation-url>`, and "Only one provider can hold DCV delegation at a time" ([Cloudflare](https://developers.cloudflare.com/ssl/edge-certificates/changing-dcv-method/methods/delegated-dcv/)).
  - acme-dns is a TXT-only REST API with per-registration credentials ([acme-dns](https://github.com/joohoi/acme-dns)).

### 2.10 SO_REUSEPORT and load balancing
- **socket(7)** ([man page](https://man7.org/linux/man-pages/man7/socket.7.html)): since Linux 3.9; "all of the processes binding to the same address must have the same effective UID." BPF selectors came in 4.5 (UDP) and 4.6 (TCP), `SK_REUSEPORT` in 4.19; an invalid index falls back to the hash.
- **Kernel source** ([sock_reuseport.c](https://github.com/torvalds/linux/blob/master/net/core/sock_reuseport.c)): selection is `reciprocal_scale(hash, num_socks)`, then a probe. Migration uses `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE`, or the hash when `tcp_migrate_req` is set.
- **On close,** queued and in-handshake connections "are aborted" unless `tcp_migrate_req=1` (default 0) ([ip-sysctl](https://docs.kernel.org/networking/ip-sysctl.html)).
- **Seen in-house:** a retiring parent on a shared port "could therefore keep accepting ... returning 502" (`server/monitor/tailer.go:572`; `server/net_unix.go:13-16`).
- **Cloudflare, 2017.** With SO_REUSEPORT, CPU spread evenly (13.2% vs 9.3%), but maximum latency was 144.55 ms against 72.65 ms with a shared queue while a worker was blocked. The epoll shared queue is "LIFO-like" ([Cloudflare](https://blog.cloudflare.com/the-sad-state-of-linux-socket-balancing/)).
- **Two choices.** Maximum load drops to log log n / log d + O(1) ([Mitzenmacher](https://www.eecs.harvard.edu/~michaelm/postscripts/tpds2001.pdf)).
- **Envoy's least-request** uses P2C, which "resists herding". With weights it uses `weight/(active+1)^bias`. A ring-hash change moves about 1/N of keys, and Maglev about twice that ([Envoy](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers)).
- **Bounded-load consistent hashing** gives a maximum load of 2 for n clients on n servers, with O(1) expected moves per change ([arXiv 1608.01350](https://arxiv.org/abs/1608.01350)).

### 2.11 Tailscale as a reference for the bridge and access control
- **Subnet routers:** advertised routes need approval (admin or `autoApprovers`); SNAT is on by default; HA is active-passive ([subnets](https://tailscale.com/kb/1019/subnets)).
- **4via6:** `fd7a:115c:a1e0:b1a:0:<site>:<ipv4>` with site IDs 0–65535 (`tailscale debug via 7 10.1.1.0/24` gives `…:0:7:a01:100/120`). Names look like `10-1-1-16-via-7`, and ACLs use the IPv6 form ([4via6](https://tailscale.com/kb/1201/4via6-subnets)).
- **App connectors** resolve domains over DoH and advertise the IPs as routes ([app connectors](https://tailscale.com/kb/1281/app-connectors)). **Exit nodes** need a grant on `autogroup:internet` ([exit nodes](https://tailscale.com/kb/1103/exit-nodes)).
- **Grants:** `src`, `dst`, `ip` (`*`, `80-443`, `tcp:443`), `app`, `via` (router tags only); deny by default ([syntax](https://tailscale.com/docs/reference/syntax/grants)). **MagicDNS** names follow renames ([MagicDNS](https://tailscale.com/kb/1081/magicdns)).

## 3. Constraints the design must respect
1. **sidecar imports only connect.** Edge library code (SNI sniffing, listener selection, the ACME and CSR client) goes in the sidecar repo. server only hosts services (`sidecar/PLAN.md:5-7`).
2. **No URnetwork component holds a user's TLS private key**, unless the user explicitly chose edge termination (`sidecar/pitch5.html:699`; `sidecar/market2.md:338`).
3. **LE limits:**
   - 50 new certificates per registered domain per 7 days, shared across accounts;
   - 5 per identifier set per 7 days;
   - 300 orders per account per 3 hours;
   - at most 25 names on tlsserver and shortlived;
   - 1-hour pending authorizations and 8-hour orders on the new profiles.
4. **CT is public and permanent, for every SAN,** `mail.<me>` included.
5. **The PSL is out of reach for now.** It needs more than 2 years of registration (ur.network expires 2027-07-02), thousands of active users and an abuse contact; it rejects rate-limit workarounds; and inclusion takes months.
6. **DNS labels need LDH validation beyond `ValidateNetworkName`:** no edge hyphens, no `xn--`, at most 63 characters. Platform names must be reserved: www, api, connect, mcp, gossip, grafana, the LB host labels (fuji, cosmic, fireside, crisp, gala, snow, jazz, honey) and `*-lb` (`vault/main/services.yml:11-35,641-739`).
7. **A name can be reclaimed 24 hours after release** (`server/controller/account_controller.go:13`). Either key DNS and certificates to an immutable label, or revoke on rename and hold the label longer than a certificate lives.
8. **nginx `pass` can't carry preread bytes.** The edge must accept PROXY v1 (TCP today) and v2. User names are TCP-only, with no h3.
9. **Never route by `req.ssl_sni` or `$ssl_preread_server_name` once `ech` configs are published.** Split mode needs a custom front.
10. **The sidecar's HTTP front must return 421 for any `:authority` or Host it doesn't serve on that connection.** Wildcard certificates on shared IPs make coalescing happen.
11. **DNSSEC validation (since 2026-03-15) and multi-perspective checks make DNS faults block issuance.** Keep the SOA minimum at or below 60 s.
12. **Route 53 can't absorb per-network records and challenge churn at scale:** 10 requests per second, 100 changes per second, serialization per zone, 10,000 records per zone.

## 4. Reusable pieces
1. **connect subprotocols:**
   - `RegisterSubprotocol` (`connect/subprotocol.go:553`) and `AddSubprotocolRawCallback` (`:540`);
   - `SendSubprotocol`, `SendSubprotocolWithTimeout` and `SendSubprotocolMulti` (`:895-947`); `SendSubprotocolBytes` (`:986`);
   - `QuerySubprotocols` (`:754`);
   - `SubprotocolId uint16` (`:46`), with ids below 1024 reserved (`:50`).

   SUBPROTOCOL.md promises "reliable, ordered, contract-accounted, end-to-end encrypted delivery" (`connect/SUBPROTOCOL.md:14-16`), with no fragmentation larger than a pack in v1 (`:111`).
2. **`NetworkPeer`, `NetworkPeersReset` and `NetworkPeersUpdate`** (`connect/protocol/transfer.proto:428-455`): a model for pushing listener presence and bridge rules.
3. **`addStreamServiceBlocks`** (`warp/warpctl/config.go:2477-2520`): `proxy_protocol on` and `v2`, on the pinned nginx with ssl_preread (`warp/lb/Dockerfile:6,58`).
4. **warpctl's DNS reconcilers** (`warp/warpctl/dns.go`, `dns_route53.go`, `dns_cloudflare.go`) for parent zones and delegation NS records.
5. **The server's ACME pipeline as a pattern**, not an import:
   - `extenderMeasurementAcme` (`server/taskworker/work/extender_measurement_acme.go:59-80`);
   - caps and Retry-After holds (`extender_measurement_work.go:58-124`);
   - setting the flag before ordering, because the CA logs to CT during issuance (`:571-572`).
6. **Runbooks** for the LE account and override, CAA, SOA, PSL and DNSSEC (`mmm/lag.dev/ops/letsencrypt.md`, `caa.md`, `route53.md`, `psl.md`, `dnssec.md`).
7. **`TransportTls.GetTlsConfigForClient`** (`server/tls.go:110`), for an opt-in edge-terminated mode.
8. **Go libraries:**
   - `github.com/pires/go-proxyproto` for PROXY v1 and v2;
   - the `inetaf/tcpproxy` SNI-sniff pattern;
   - `crypto/tls` `Config.EncryptedClientHelloKeys` (Go 1.24 and later; connect and server are on go 1.27.3, `connect/go.mod:3`).
9. **ACME clients with ARI:** `github.com/go-acme/lego` v5.6.0, `github.com/mholt/acmez` v3, and `tailscale.com/tempfork/acme`. Avoid bare `golang.org/x/crypto/acme` for renewals.
10. **Tailscale `feature/acme/cert.go`** (BSD-3), a template for the sidecar's certificate manager: choosing between dns-01 and tls-alpn-01, a pending TLS-ALPN certificate map (`storeACMETLSALPNCert`), and the ARI window.

## 5. Gaps, risks, surprises
- **R1. PLAN.md:84 (edge terminates) contradicts pitch5.html:699 (passthrough).** Settle it before tlsedge work starts.
- **R2. ur.network as the user domain:**
  - It is the platform namespace in config, and the sdk expects `api.ur.network` (`sdk/network_space_test.go:142-143`).
  - Talos lists it as "Personal VPN", so previews may be blocked inside companies.
  - A whole-domain Safe Browsing flag would hit the platform too.
  - A PSL listing would split the platform's own sites.
  - PLAN's `*.ur.network` forward collides with `*.connect.ur.network` and `*.<lb-host>.ur.network`.
- **R3. About 50 first certificates a week until a domain override lands.** The bringyour.com budget is already shared between warpctl and lag.dev (`mmm/lag.dev/ops/letsencrypt.md:83-104`). User certificates under ur.network would compete with warpctl's ur.network certificates the same way.
- **R4. The DNS operator can always pass DNS-01.** CT plus per-network CAA `accounturi` make our own issuance detectable, not impossible. The threat model must say so.
- **R5. Network names are human and can look like brands** ("paypal-support" passes validation). Without opaque labels, CT and DNS publish them. Friendly labels need a deny list.
- **R6. Passthrough limits abuse handling.** The edge can't inspect traffic or inject warning pages, and a modified sidecar can skip its own warning. What's left: L4 kill switch, caps, time-boxed publishes, tier gates (free gets 1 endpoint), revocation, and a separate domain to contain Safe Browsing fallout.
- **R7. Inbound SMTP can't be routed by SNI.** "Local Email server" needs edge-terminated SMTP with encryption on arrival (pitch5: "Outside mail is encrypted on arrival") or another routing key. That exception must be stated.
- **R8. One LB site, no anycast.** The `by-us-fmt-5-edge-*` hosts sit on HE ranges (`vault/main/services.yml:60-76`; inference). Self-hosted DNS becomes a DDoS target, so secondaries are needed from day one.
- **R9. Supply side:** dns-persist-01 is frozen and Buypass is gone. CAs other than LE need EAB, which we would have to mint per network. `mailgun/proxyproto` is stale, and warpctl pins lego v4.35.2 while v5 is current.
- **R10. Smaller:** `api.ur.network` is NXDOMAIN publicly; ur.network has a 900 s negative TTL and no DNSSEC; bringyour.com expires 2026-11-15 (`mmm/lag.dev/ops/psl.md:37`).

## 6. Open questions for the owner
1. Which registrable domain carries user names? If it's ur.network, do api, connect, mcp, gossip, grafana and `*.<lb-host>` move off it? If not, what is the new domain, and for how many years is it registered?
2. Is an edge-terminated mode (WAF, edge auth, agent-panel refusal) allowed at all? If so, how is it labeled and recorded against "cannot read"?
3. Is the DNS label the friendly network name (`<me>`), or an opaque, immutable label with an opt-in public alias?
4. Who owns the ACME account: each network (CAA-pinnable, and LE-only unless we mint EAB) or URnetwork (CSR proxy, several CAs, a weaker promise)?
5. Does one wildcard key cover the whole team, or does each member or device get a sublabel, so that "Sessions stay with their author" holds inside a team?
6. Does the tlsedge run one connect client per network (PLAN.md:82), or one edge identity with grants across networks?
7. For inbound mail, is edge-terminated SMTP with immediate encryption to the recipient acceptable? Is DANE, and so DNSSEC, wanted for `mail.<me>`?
8. What is the budget and timing for a secondary or anycast DNS provider, for the LE domain override, and for dedicated edge IPs (which avoid moving all platform HTTPS behind an ssl_preread split)?
