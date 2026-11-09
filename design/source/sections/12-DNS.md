## 12. DNS: the ur.network zone and per-network zones

### 12.1 Purpose and scope

This section owns public naming: the user root (X4), the network label (X5) and X17; the `dns` engine and dns edge; DNSSEC; zone content and reverse zones; the record API; DNS-01; custom domains; private names (with §17); takedown hooks (§21). §13 owns certificates and CAA, §14 and §15 mail record content, §19 the dns edge hosts, §20 quotas. Notation follows D-ARCH-1.

### 12.2 Requirements

| id | requirement | source |
|---|---|---|
| R-DNS-1 | `<root>` is its own zone; `*.<root>` reaches tlsedge; `mx.<net>.<root>` reaches the local mail server | PLAN.md:80-81,104; owner decision 32 |
| R-DNS-2 | A network owns the zone `<net>.<root>` and its entries | PLAN.md:25 |
| R-DNS-3 | DNS entries 5/200/2000; custom domains Team only | PLAN.md:357,364 |
| R-DNS-4 | DNS reveals as little as possible | CONVENTIONS §0 |
| R-DNS-5 | A released name routes nothing to a new owner | §2 I-14 |
| R-DNS-6 | Labels are issuable LDH labels; platform names are unclaimable | [R:server-identity] §2.2 |
| R-DNS-7 | Challenge TXT served within 60 s (p99); negative TTL ≤ 60 s | [R:ext-edge] §3; §19 |
| R-DNS-8 | Nothing collides with WhoDis on public UDP 53 | vault/main/services.yml:345-347 |
| R-DNS-9 | Mail policy records per network; the sending addresses' PTRs under bringyour.com | RFC 8461 §3.4; owner decision 124 |
| R-DNS-10 | Self-hosted DNS, signed online from the first deploy, on two NS at the one site | owner decisions 69, 71, 109, 123 |

### 12.3 What exists today

- ur.network: Route 53, expires 2027-07-02; signed by a KMS key shared with bringyour.com, no DS (RDAP 2026-11-03; mmm/lag.dev/ops/dnssec.md:25-27); MX at Google Workspace, `_dmarc` `p=none`, no SPF or CAA (dig 2026-11-03).
- The platform left ur.network on 2026-10-01: `api`, `connect` and `mcp` are NXDOMAIN, though warp and vault list them (apple/app/network/Shared/Config/NetworkConfig.swift:19-23; warp/services/services.go:396-438; vault/main/services.yml:3-35,641-739; config/main/tls.yml:2-6).
- Public UDP 53 on the lb interfaces is connect's WhoDis transport; no TCP 53 (vault/main/services.yml:345-347; server/connect/transport.go:2321).
- network_name: 5-50 of `[a-z0-9-]`, edge hyphens and `xn--` allowed, nothing reserved; one rename path holds the old name 24 h; deletion frees it (server/model/network_model.go:178-206; server/controller/account_controller.go:13,161-166; server/model/account_model.go:379).

### 12.4 Roots: the registrable domain (X4, X17)

A **root** is a user-content zone that `dns` signs and serves (`config/<env>/dns.yml`). v0's one root, `<root>` = ur.network, carries user content only (owner decisions 13, 16): burners live in network zones (owner decision 32), and recurd.dev only redirects to ur.io/recurd (§19; owner decision 15). Platform names, the report, lb and HELO hosts included (owner decision 124), live on bringyour.com; `<root>` keeps only `ns1`, `ns2` (glue), `_psl` (the PSL's proof), `canary` (12.6), `<token>.acme` (certs' challenge targets) and §14.6's `_spf`, keeping SPF checks in the signed zone.

Until `<root>` is on the Public Suffix List (PSL), its networks share one site (cookies, saved logins), one reputation (§21.6), one Let's Encrypt budget and one DMARC organization ([R:ext-edge] §2.5; mmm/lag.dev/ops/psl.md:51-56). Steps (D-DNS-1):
1. M0: renew to 2036 under registrar lock; the PSL wants over 2 years of term at listing.
2. Move platform names and company mail off ur.network, warp and tls.yml; the lb sends `*.<root>` to tlsedge (§13.4), and only the apex redirects to ur.io.
3. Serve the zone from the dns edge, switch NS (no DS exists) and delete the Route 53 zone.
4. Set `_dmarc.<root>` to `p=reject` once company mail has left.
5. Once eligible (~3,000 active users, `_psl`, an abuse contact), apply to the PSL and request recategorization (connect/EXTENDERUPDATE.md §10.1).

Until listed: no URnetwork cookies on the root, HSTS preload with `includeSubDomains`, exact-host autofill (§15, §18), and §13.7's rule for session cookies on same-site requests from other networks' pages.

### 12.5 The network label (X5)

**Label (owner decision 14).** 10 characters `[a-z][a-z0-9]{9}` from crypto/rand (~51 bits), allocated on first need, immutable, never reassigned, and not derived from network_id, whose ULID exposes creation time ([R:server-identity] §2.11). A draw that hits an existing row or fails `ScreenName`'s reserved or brand rules is redrawn (owner decision 97).

**Alias** (opt-in, "public forever (CT)"): the network_name, one per network: a copy of the label's records except challenges, live once §13's certificates name it. Labels and aliases share `dns_label`'s primary key (root, label) across kinds and states, so alias claims and `RenameNetwork` (§7.12) refuse any name a row holds, live, retiring or tombstoned.

**Validation** (aliases and new names, §7.12; every new name through `ScreenName`, §21.6): `ValidateNetworkName`; no edge `-` (Boulder refuses it); no `--` at positions 3-4 (no `xn--` or IDNA homographs); not reserved; not brand-confusable after mapping 0→o, 1→l, 3→e, 5→s and rn→m per `-` token ([R:ext-edge] §5). Team scope labels (v1; owner decisions 40, 58), from the signed projection (§8), also avoid reserved owners, hosts, client names (§7.7) and word-number labels. Reserved, versioned in the sidecar repo:

```text
www mail mx smtp imap pop dns ns ns1-ns9 edge acme canary rpt out mta-sts autoconfig autodiscover
  wpad isatap localhost
api app web connect mcp gossip grafana taskworker proxy alt monitor mmm lb auth login account admin
  status abuse postmaster security support billing evs gkm sockets tlsedge smtpedge mxedge certs
fuji cosmic fireside crisp gala snow jazz honey, plus every services.yml host label (a release check)
*-lb *-v4 *-v6 main-* beta-* canary-* community-* local-* by-*
ur urnetwork bringyour recurd burner, plus a curated list of the most-phished brands
```

**Census** (a read-only query in M0):

```sql
SELECT count(*) FILTER (WHERE network_name !~ '^[a-z0-9-]{5,50}$') AS pre_rule,
       count(*) FILTER (WHERE network_name ~ '(^-|-$)') AS edge_hyphen,
       count(*) FILTER (WHERE substr(network_name, 3, 2) = '--') AS dash34,
       count(*) FILTER (WHERE network_name = ANY($1) OR network_name ~ $2) AS reserved
FROM network;
```

**Renames, deletion and restore (D-DNS-10).** Renaming network_name changes nothing. A changed or released alias serves 90 days as `retiring` (outlasting 5-day sender retries) under CAA `issue ";"`, its certificates revoked (§13), then is tombstoned forever; deleting a network withdraws its records at once and tombstones label and alias, whose certificates are revoked or expire within 45 days. After a Postgres restore and 12.6's restore step (§19.10), taskworker re-reads CT for `<root>` names logged since the restored dump's time minus 7 d and inserts each name `dns_label` lacks as `retiring` with no network; `label-reclaim` (12.8) re-binds it to its network, and the rest tombstone after the 90 days, so I-14 holds across the gap.

### 12.6 Hosting: the self-hosted dns edge

```text
write (api or dns route), one transaction: under a decision, §16.6's gate first (12.8): a stored result
  for the request's effect_key answers it with no write, else the spend check, then the approval_use claim;
  lock the dns_root row (503 while restoring), serial+1, records + dns_zone_journal diff (+ the use's
  result), commit; then raise {dns}serial:<root> to that serial (a script that never lowers it), which
  wakes the feed (PgBouncer's transaction pooling bars LISTEN/NOTIFY)
dns API blocks (dns.bringyour.com): GET /dns/journal?root=&after=<applied> (long-poll <= 25 s); /dns/snapshot
  (the rows at one serial); a poll the journal cannot continue (after < serial, no row after+1: a
  7-day gap, a restore) answers reload, with restore_serial; every answer also names each lb interface's
  reported custom-host version, with its probe name and the hosts it added, and the map-stale
  interfaces (§13.4)
  rows and snapshots stay readable across releases N and N+1: N ignores fields N+1 adds, and writes
  N cannot read wait until N+1 serves 100% (§19.11)
dnsedge on ns1, ns2 (host-pinned; UDP and TCP 53; no proxy in front, so RRL sees resolver addresses):
  apply each diff atomically, in serial order --> zone in memory + local snapshot; a reload swaps in
    /dns/snapshot's; a replaced snapshot older than restore_serial is kept only until POST
    /dns/reload-diff takes its diff, at most 24 h, and any other is deleted at once
  serve a zone build or key set only once its self-check passes, else keep the previous one
  answer from memory, sign online, rate-limit; SOA serial = root serial
  probe each lb interface every 10 s (owner decision 34; server/services_lb_inventory.go:11-17,35):
    tlsedge's alert on 443, 8443, 8883 and 5671 (§13.4; owner decision 121);
    on 443 also the route probe of the custom-host version the interface reported (§13.4), posted
      to POST /dns/route-probes;
    the 25 banner on §19.5's router interfaces
    drop one after 3 failures, or while the journal names it map-stale (§13.4), never all, and the one
    §19.5's W1 drains
      --> answered from the healthy set at answer time, with no journal write: the A, AAAA at *, @,
          each copy of *'s records and each mx host on router interfaces (12.7)
certs: GET /dns/ready?serial=s --> stale while restoring or for s <= restore_serial (certs writes again
  at a new serial, §13.8); else API blocks read each running NS's SOA over TCP --> ready when all >= s
restore (§19.10, after the dumps load and the abuse step, before api's replay; Postgres comes back at dump
  age with an empty journal, while ns1 and ns2 serve newer zones until they reload):
  §19.10 sets dns_root.restoring as the dumps load, before api or the dns blocks serve: every dns write
    gets 503, so the CT replay (12.5) and api's replay of revocations (§7.10), their DKIM and TLSA
    deletions (I-15) included, commit after this step; until the transaction below, 12.9's SuspendZone,
    SuspendHost and Restore set only their rows, taking no serial, so the suspensions and lifts
    §19.10's abuse step re-places (§21.10) are in its snapshot
  read each NS's SOA over TCP; an NS that does not answer is stopped, and serves again only from a
    reload, its local snapshot taken as the replaced one
  one transaction: serial := restore_serial := max(restored serial, the SOAs read, {dns}serial:<root>)
    + 2^24, above every serial the lost primary issued, since the key lacks only raises that failed or
    that a Redis failover lost (RFC 1982 allows a jump below 2^31); raise the key
  each edge reloads at restore_serial and posts its diff (POST /dns/reload-diff); once every running
    NS answers that SOA, restoring := false; the step lists, by network_id, owner and type, each RRset
    but challenges' and canaries' in a posted diff, and raises the custom-host map's version 2^24 above
    the restored one, every host's map_version with it, so W1 loads the map from the restored rows
    (§19.5) and each host stays pending until every interface is current for the new version
    (§13.4), listing the hosts that adds or drops, in the incident and in each network's admin events
    (§7.11), both kept 400 d, flagging networks with an open §21 case
monitor, at the site and on 1 outside host: rewrite canary.<root> TXT each minute through the journal;
  validate it through each NS against the KSK as a configured trust anchor (Unbound trust-anchor);
  2 public resolvers check propagation only until the DS, then validate as well;
  DNSKEY window > 7 d; equal SOA serials
  --> incident alert (server/monitor/alert_classes.go:3-8); from M5, both NS failing or a canary
      signature failing pages §19.8's rota at any hour, 30 min to acknowledge (owner decision 143)
```

```yaml
# config/<env>/dns.yml (sketch)
roots: [ur.network]
reverse: from smtpedge.yml's sending addresses   # M9; HE's classless delegation; unsigned
delegated: Team customers' _domainkey.<domain> zones   # v1 (§14.6); not roots
ns: [ns1, ns2]                  # two hosts at the site; IPv4 and IPv6 from different gateway blocks
ttl: {challenge: 60, edge: 60, mx: 300, mx_host: 300, tlsa: 300, mail_policy: 3600, caa: 3600,
      user: 300, user_range: [60, 3600], soa_minimum: 60, ns: 86400, ptr: 3600}   # edge: A, AAAA at *, @
rrl: {ipv4_prefix: 24, ipv6_prefix: 56, slip: 2, classes: [answer, denial, error]}
signatures_per_second: <cap per host>   # cached answers first
edns_udp_size: 1232
any: minimal                    # RFC 8482
client_subnet: ignore           # RFC 7871; never echoed or stored
tcp: {connections_per_source: <cap>, idle_timeout_s: 10}
```

**Placement (D-DNS-3; owner decisions 69, 71, 123).** The `dns` engine (`sidecar/dnsservice`, miekg/dns) runs as server/cli/dns: API blocks serve §12.8's routes and the feed; the edge role, `dnsedge`, runs only on §19's dns edge hosts, whose own addresses leave the lb's UDP 53 to WhoDis (R-DNS-8), and deploys one host at a time (§19.11). Edges never query Postgres (I-12), so with the core down they keep serving and signing while writes and ACME wait. Both NS sit at the one site (12.15).

**Signing (D-DNS-5; owner decisions 69, 109)**, online from the first deploy:
- **Denial.** ECDSA P-256. Compact denial (RFC 9824; NXDOMAIN kept without DNSSEC) and wildcard answers signed as the queried name reveal neither which names exist nor which a wildcard covers.
- **Keys.** The KSK stays on an offline HSM, backed up in a second safe; a two-person quarterly ceremony pre-signs DNSKEY RRsets (current, next and standby ZSK) in 14-day windows, released one at a time. The current ZSK is a `secret_files` entry (warp/warpctl/run.go:172-204) mounted only on dns edges, rolled quarterly by pre-publication; the standby stays in vault.
- **DS.** Without one, validators treat the zone as insecure, so a fault harms no one and only the anchored monitors prove signing; the DS follows 30 clean canary days, before M7's TLSA, which §15.5's "validated" label checks (owner decision 135).

**Runbook (§19.10).** NS down or flooded: resolvers retry the other; HE null-routes a flooded address. ZSK leak: mount the standby and hold a ceremony; forgery ends with the old windows (≤ 14 days). Both KSK HSMs lost: a new KSK's DS before the last window expires.

### 12.7 Zone content

System records (TTLs per 12.6; writer dns unless noted; last column, the owning section):

```text
<net>.<root>:
*                  A, AAAA: healthy lb interfaces (12.6), never a CNAME           §13; with an edge grant (§8)
@, *               MX 10 mx.<net>.<root>                                          §15.9; covers every burner label
                   MX 0 . (null MX, RFC 7505)                                     §15; mail off
@                  A, AAAA as at *                                                §13; apex published
@                  TXT "v=spf1 -all"                                              §14.6
<empty non-term.>  a copy of *'s records, which it blocks (RFC 4592 §2.2),        §12
                   kept while it has children and no own records, in the same writes: blog for _sip._tcp.blog
_acme-challenge    TXT, <= 2 values; also under a live alias; writer certs        §13
<host>             CAA canary during a strong-mode probe (12.8), TTL 60,          §13.8
                   with a copy of *'s records where <host> has none; writer certs
mx                 A, AAAA: healthy router interfaces (12.6), or a direct MX's (12.8)   §15.4; mail on
_25._tcp.mx        TLSA 3 1 1 per receiver key; writer /dns/key-record            §15.5; mail on
b                  MX 10 mx.<net>.<root>; TXT "v=spf1 include:_spf.<root> -all"   §14.6; mail on
_dmarc             TXT "v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=s;
                        rua=mailto:<token>@rpt.bringyour.com"; never ruf or fo    §14.6
<sel>._domainkey   TXT DKIM per sending sidecar; writer /smtp/dkim-keys; rotation  §14.6
                   keeps the old one 7 d, removal (§7.10, I-15) deletes in the same write (owner decision 36)
<sel>._domainkey.<blabel>   a replying burner's, until the PSL listing             §14.6, §15.9
                   (owner decision 79)
<blabel>           a copy of *'s MX, A, AAAA, written in the same journal         D-DNS-11
                   write as its first _domainkey child (RFC 4592 §2.2.1) and
                   deleted with the last selector
_mta-sts           TXT "v=STSv1; id=<n>"                                          §15; mail on
_smtp._tls         TXT "v=TLSRPTv1; rua=mailto:<token>@rpt.bringyour.com"         §15
; a copy is one row that dnsedge answers with *'s current records and TTLs, so writes to * and
; health drops (12.6) reach it with no further write
; an alias zone and each Team scope <scope>.<net>.<root> (owner decisions 40, 58) repeat this set,
; with their own mx host and TLSA

<root>:
@                  SOA; NS ns1, ns2; CAA per §13.8 + iodef; below @, only         §12, §13.8
                   retiring names' issue ";" (12.5) and probes' canaries (12.8)
@                  TXT "v=spf1 -all"; MX 10 rpt.bringyour.com (abuse@, postmaster@)   §14.6, D-SMTP-19
@                  A, AAAA: lb interfaces, where a platform certificate redirects to ur.io   §13.4
_dmarc             TXT the same policy, adkim=s; aspf=s; + psd=y once company mail leaves   §14.6
                   ; strict, since burner From domains fall back to it (RFC 7489 §6.6.3) until the PSL listing
ns1, ns2           A, AAAA: the dns edges (glue)                                  §12.6
_psl, canary, <token>.acme                                                        12.4, 12.6, 12.8
_spf               TXT: the sending lb addresses (owner decision 124)             §14.6

reverse zones of the sending lb addresses (owner decision 124), delegated by HE (M9), unsigned:
<address>          PTR its HELO name under bringyour.com, from smtpedge.yml       §14.6
```

User records:

| Type | Owners | Rules |
|---|---|---|
| A, AAAA | `@`, hosts | Public unicast only: no RFC 1918, 100.64/10, loopback, link-local, 0/8, 198.18/15, documentation, multicast, ULA or DNS stand-ins (connect/net_http_doh.go:329,337); ≤ 8 per RRset |
| CNAME | hosts, alone at the owner | FQDNs outside tombstoned labels |
| TXT | not system owners; no SPF at `@` | printable ASCII, ≤ 1024 bytes |
| MX | hosts, never `@` or `*` | FQDN targets; ≤ 4 per RRset |
| SRV (proposed) | `_svc._proto.<host>` | FQDN targets |
| Wildcard (proposed) | `*.<host>` for A, AAAA, never CNAME | `*` itself is system-owned |
| Refused | NS, DS, DNAME, PTR, CAA, HTTPS/SVCB (no ECH or h3, §13) | |

- **Refused owners** (network and alias zones): `b`, `mx`, `mail`, `mta-sts`, system `_` owners, scope labels and word-number labels (`^[a-z]+-[0-9]{4}$`, kept for burners; owner decision 32).
- **Lint.** No journal row commits a CNAME beside other data at one owner, system records included (RFC 2181 §10.1).
- **Entries.** One user RRset is one `dns_entries` unit (§20.4); system, DKIM, challenge, alias and edge records are free; `tls_endpoints` bounds edge names.
- **Abuse caps** (pro.yml `sidecar_abuse:`; §21 tightens them): `dns_changes_per_hour` 60, `dns_challenges_per_name_hour` 10, `dns_dkim_selectors` 64 device selectors under `_domainkey.<net>.<root>`, burners' excluded (§14.6).

### 12.8 Record API, DNS-01, custom domains

| Route | Auth | Purpose |
|---|---|---|
| `GET /network/dns` | Network, read roles | label, alias, records, quota; each custom host's state, CAA mode and readiness, a pending one naming the lb interfaces not yet current for it (§13.4) |
| `POST /network/dns/records` | Network, DNS permission (§7.5) | `{expect_version, upserts, deletes}`, compare-and-swap |
| `POST /dns/records` | service token, aud `dns` (§7.8); §8.10's gate for §8 `admin` on `dns:<host>` (I-8) | the same, for sidecars and §16's tools; under a decision rather than a grant, the gate first answers a retry with the stored result of a use committed under its `Idempotency-Key: <effect_key>` while that `approval_use` row lasts, even past `not_after` or with a stale `expect_version`; otherwise it runs §16.6's spend check (D-MCP-12), which needs the request's upserts and deletes to equal its `CanonicalAction`'s `dns_*` fields, and consumes a use in the write's own transaction (§16 D-MCP-11; §2.8 api-10) |
| `POST /network/dns/alias-claim`, `/alias-release`, `/custom-host-add`, `/custom-host-remove` | Network, DNS permission; custom hosts Team only | alias; map `<host>.<domain>`, or an apex `<domain>`, to a host owner of the network, never a network's, alias's or scope's `@`, a strong-mode host staying `pending` until step 3's checks pass; each change to the active rows raises the custom-host map's version, which §19.5's W1 loads on every lb interface on §13.4's schedule, and a host is ready for TLS-ALPN-01 once every interface that 12.6's probe passes is current for its version (§13.4) |
| `POST /network/dns/label-reclaim` | Network, DNS permission | after a Postgres restore only: re-binds an ownerless `retiring` name (12.5) to the caller's network, given `("urnetwork-sidecar-v1/label-reclaim", name, network_id, nonce)` signed by the key of a CT-logged certificate naming it, the nonce being the restore's incident id (§19.10) |
| `POST /dns/acme-challenge`, `/dns/caa-canary`; `GET /dns/ready?serial=` | internal: certs | challenges ≤ 10 per name per hour; canaries per the probe (below); ready long-polls ≤ 25 s, `stale` across a restore (12.6) |
| `GET /dns/custom-host-map?applied=`; `POST /dns/custom-host-map/applied` | internal: each lb interface's `lbmap` (§19.5 W1) | the newest custom-host map (version, digest, hosts), long-polled ≤ 25 s until it differs from `applied`; then the version the caller's interface loaded, with its nginx master, or a failed render, test or reload (§13.4) |
| `POST /dns/route-probes` | internal: dns edges | each lb interface's route-probe result for the custom-host version it reported (12.6, §13.4) |
| `GET /dns/journal`, `/dns/snapshot`; `POST /dns/reload-diff` | internal: dns edges | the feed (12.6); after a reload across a restore, `{root, replaced_serial, serial, rrsets: [(owner, type)]}`, the RRsets that differ between the replaced snapshot and the new one, which 12.6's restore step maps to networks through `dns_label` |
| `POST /dns/key-record` | service token; §8 `listen` on `sock:smtp/25/mx` or `smtp/25/mx.<scope>`; a member scope takes only its member's consented devices (§8.5; owner decision 126) | TLSA at `_25._tcp.mx` (or `_25._tcp.mx.<scope>`) for the caller's attested key; owners notified |

DKIM comes only through §14's `POST /smtp/dkim-keys`, TLSA only through `/dns/key-record`; user and key writes add a `network_admin_event` (§7.11).

**Gates.** Upserts creating a public name (A, AAAA, CNAME, MX or SRV owners) and alias claims need §21.7's `network_verified`, else `QuotaRefusal{limit_key: verification}` (owner decision 96).

**Direct MX (owner decision 33; Team).** Once mxedge has verified each mail indexer of §15.4's `POST /mail/direct-mx` against 12.7's A rules and its `mail_host_key`, `mx.<net>.<root>`'s A and AAAA name their addresses and the TLSA set stays; `DELETE` restores the router interfaces. Its MX, A and TLSA stay in URnetwork's zone, so a direct MX does not exclude URnetwork (§2.8 EX2).

Custom domains, Team only (D-DNS-9):
1. Verify TXT `_urnetwork-challenge.<domain>` (§7.6 `network_domain`).
2. **Strong mode** (the default, and every apex): `<host>.<domain>` answers A and AAAA itself, statically with the lb addresses (§19.5; these miss 12.6's health drops) or through a customer-side ALIAS (flattening) of the host owner it maps to, `<host>.<net>.<root>` (an apex host's too; never `@`, whose CAA would govern the zone's device certificates, RFC 8659 §3), that keeps the queried name, synthesizes only A and AAAA, and answers every other type, CAA included, from the customer's zone. **Weak mode:** a CNAME into `<root>`, active at once, accepted only with §2.8 EX1's exception disclosed at setup: CAA discovery follows the CNAME and stops at the first non-empty set (RFC 8659 §3), so URnetwork could publish a CAA at the target admitting its own account.
3. The customer's CAA pins its own ACME account (`accounturi`, RFC 8657; owner decision 39; custody per §13.8); devices pass DNS-01 through a one-time CNAME `_acme-challenge.<domain>` → `<token>.acme.<root>`, where certs writes their challenges, or TLS-ALPN-01. A strong-mode host commits `pending`, unmapped with `effective_caa_chain_ok` false, while a certs taskworker chain walks its CAA discovery and runs the probe below: both passing make it active, and a walk meeting a name in a URnetwork zone, or a failed probe, refuses it (`custom_host_caa_operator_alias`), each as an admin event. certs repeats both on §13.8's schedule; a failure there clears `effective_caa_chain_ok` until a check passes and records §2.8 EX1's exception in an admin event that alarms the network's admins, the host staying mapped, exposed as a weak-mode one is. The ordering desktops repeat the walk before each order (§13.8).
4. §13.4's split sends each active custom host's SNI to tlsedge, which maps it via `network_dns_custom_host`; mail uses MX `mx.<net>.<root>`, §14.6's selectors (CNAMEd or delegated to `dns`) and the customer's `_dmarc` with `adkim=s`. In strict mode (§15.4; owner decision 98) the MX is the customer's `<mx>.<domain>` in its own signed zone, with TLSA at `_25._tcp.<mx>.<domain>` and A and AAAA to the router interfaces, mapped in `network_dns_custom_host` for mxedge (§2.8 mx-3). Only this path, with every MX host the recipient domain lists and its TLSA customer-signed, carries strict mode's exclusion of URnetwork; an MX host or TLSA in a URnetwork zone stays under §2.8 EX2.

```text
CAA probe (certs, for a strong-mode host once its walk passes; one probe per target at a time):
  publish  POST /dns/caa-canary: <host>.<net>.<root> CAA = the walk's effective set (the customer's
           pin) + 0 urcanary "<128-bit nonce>", TTL 60 (12.7), at serial s; then /dns/ready?serial=s
  query    repeat the walk's CAA queries at the authoritative servers of each zone it visits, RD=0,
           every 30 s for 10 min (ten times our 60 s negative TTL)
  verdict  the nonce in any answer (the ALIAS flattens CAA), or a canary the lint refuses (a CNAME
           at <host>) --> fail; else pass, once /dns/ready?serial=s answers ready again after the
           last query
  stale    at either ready (a restore, 12.6, whose edges may lack the canary) --> publish again
           under a new nonce and restart the window
  delete   the canary and its copy in one write, whatever the verdict; taskworker expires one older
           than 1 h, as it does challenges
```

CAs ignore unknown non-critical tags (RFC 8659 §3, §4.1), so the canary admits only the customer's pin, even flattened or cached.

### 12.9 Private names, visibility, capabilities, abuse hooks

**Private names (owner decision 85).** `<client-name>.<net>.<root>` maps §7.7's client names to §17's overlay addresses (X18), which lie in 100.64/10 or RFC 1918 (owner decision 132), so 12.7 refuses them in public records. C14's `UpgradeMux.SetLocalZone` answers them on app paths, fed in each app's VPN component by the names its forwarding role compiles into §17.8's `BridgeState` (§18.6; owner decision 197); §17's per-link resolver answers them under `ur tun`. A name in the table gets an answer for every qtype, A or NODATA (the overlay has no IPv6; browsers also ask HTTPS), so no query for it leaves the device; other names pass through. The table omits a client name equal to a live published host or record owner, which §7.7's signers also refuse.

```go
type LocalZone interface { // nil keeps today's behavior
	// owned with no addrs answers NODATA; !owned passes the query through
	Answer(host string, qtype uint16) (addrs []netip.Addr, ttl uint32, owned bool)
}
func (self *UpgradeMux) SetLocalZone(localZone LocalZone)
```

**Enumeration.** CT shows labels, aliases and scope labels, never hosts (§13.8); under compact denial, hosts and replying burners' labels (owner decision 79) can only be guessed, which RRL slows.

**Visibility and capabilities:** §2.8's dns-1, dns-2, EX1 and EX2. No third party serves the zone, edges log no query (I-13), and the zone and CT watches detect forgery (D-TRUST-9, D-TLS-8).

**Abuse (§21).** `SuspendZone(networkId, reason, until)`, `SuspendHost(networkId, host)` withhold records, MX included, and `Restore` returns them, within one write plus the TTL (≤ 3600 s), or, before 12.6's restore transaction, through rows its snapshot carries; tlsedge and mxedge read the same state.

### 12.10 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Route 53, or a hidden primary with anycast secondaries | anycast; flood absorption | third parties see every query | ruled out (owner decision 69) |
| An offline-signed zone with NSEC3 | no ZSK on public hosts | dictionary attacks on names; health answers need re-signing | rejected (owner decision 69) |
| A ZSK in a KMS or HSM | no key in host memory | a round trip per random-name query, which a flood exhausts | rejected |
| `*` CNAME to a shared edge name | one record | excludes the wildcard MX (RFC 2181 §10.1) | rejected |
| A CNAME from each custom host into `<root>` | one record; follows 12.6's health drops | CAA discovery follows it to a target URnetwork writes (RFC 8659 §3) | weak mode only, disclosed (D-DNS-9) |

### 12.11 Decisions proposed

**D-DNS-1 (proposed).** Roots are config; v0's only root is ur.network, for user content (owner decisions 13, 32). *Why:* changing the root later breaks every address.

**D-DNS-2 (proposed).** Labels are random, lazy, immutable and never reused; aliases are copies. `<net>` (§8, §9) resolves label, then alias; legacy network_name resolves only for interactive input. *Why:* a network_name another network later takes captures no grant.

**D-DNS-3 (proposed).** Only 12.6's self-hosted dns edge serves `<root>`, from two NS at the site (owner decisions 69, 71, 123). *Why:* no third party sees queries, and names resolve through core outages.

**D-DNS-4 (proposed).** TTLs follow 12.6. *Why:* ACME, failover and takedown need short caching.

**D-DNS-5 (proposed).** Online signing from the first deploy: compact denial, an offline KSK, 14-day DNSKEY windows, the DS after 30 clean days (12.6; owner decisions 69, 109). *Why:* nothing can be walked, and a leaked ZSK dies with its windows.

**D-DNS-6 (proposed).** System records follow 12.7, with no wildcard CNAME; an entry is one user RRset; a replying burner's label carries the wildcard's records (D-DNS-11). *Why:* strict DMARC keeps networks from passing as one another, and a wildcard CNAME would drop the burner MX.

**D-DNS-7 (proposed).** 12.7 refuses non-public addresses and the listed types and owners, and caps RRsets; SRV and `*.<host>` extend owner decision 70's own records. *Why:* it blocks rebinding and overlay leaks, protects §13-§15 and keeps burner labels under the wildcard.

**D-DNS-8 (proposed).** certs is the only DNS-01 writer, after checking the caller's §8 grant; writes are rate-limited, ready-checked and expire after 1 h. *Why:* least privilege, one issuance queue (D-TLS-7) and Let's Encrypt's failed-authorization limit.

**D-DNS-9 (proposed).** Custom domains use 12.8's verified TXT, one-time `_acme-challenge` CNAME and the customer's CAA `accounturi` pin (owner decision 39). A strong-mode host keeps its effective CAA under customer authority, through customer A/AAAA or an ALIAS that synthesizes only A and AAAA, never a CNAME into `<root>`, which certs checks by the walk and the canary probe before the host goes live and on §13.8's schedule; a CNAME host is weak mode, under §2.8 EX1. *Why:* devices pass DNS-01 without per-order edits, and CAA discovery follows a CNAME, or an ALIAS that also flattens CAA, to a target URnetwork writes (RFC 8659 §3), so only a customer-held chain keeps URnetwork from issuing.

**D-DNS-10 (proposed).** Labels and aliases are tombstoned forever; a changed alias retires over 90 days. *Why:* old certificates and mail retries cannot enable a takeover.

**D-DNS-11 (proposed).** A `<blabel>` with any child owner carries an explicit copy of the wildcard's MX, A and AAAA, written and removed atomically with its selectors; dnsedge answers the copy from `*`'s current records, health drops included (12.6, 12.7). *Why:* an empty non-terminal blocks the wildcard (RFC 4592 §2.2), so a replying burner's first selector would otherwise end its inbound mail, and copied addresses would keep serving a dropped interface.

### 12.12 Open questions

**Q-DNS-1.** [X4] Which registrable domain carries user names? **Decided by owner 2026-11-03 (owner decision 13):** (b1), ur.network for user content only, signed, strict-DMARC and PSL-listed when eligible (§12.4). *Residual:* none.

**Q-DNS-2.** [X5] What is a network's label? **Decided by owner 2026-11-03 (owner decision 14):** (a), opaque, random and immutable, with an opt-in alias equal to network_name (§12.5). *Residual:* none.

**Q-DNS-3.** [X17] Which roots and keys does recURd use? **Decided by owner 2026-11-03 (owner decisions 15, 108):** ur.io/recurd on the main bringyour.com services, with no dedicated keys; recurd.dev redirects there (§12.4). *Residual:* none.

**Q-DNS-4.** Which providers serve `<root>`? **Decided by owner 2026-11-03 (owner decisions 69, 71):** none: a self-hosted dns edge, signed online, with two NS on separate hosts at the site (§12.6; owner decision 123). *Residual:* none.

**Q-DNS-5.** Cross-cutting (§15, X6): when is the root signed? **Decided by owner 2026-11-03 (owner decision 109):** from the dns edge's first deploy (M5, main-dark), soaked before inbound mail relies on DANE (D-DNS-5). *Residual:* none.

**Q-DNS-6.** Does "owns all entries" (PLAN.md:25) let a network override system records or publish non-public addresses? **Decided by owner 2026-11-03 (owner decision 70):** (a): own A/AAAA, CNAME, TXT and extra MX records under quota; system records, NS/DNAME and private or loopback addresses refused (D-DNS-7). *Residual:* none.

**Q-DNS-7.** Cross-cutting (§19). Should one NS run outside the site before M7? **Decided by owner 2026-11-04 (owner decision 123):** (b), two NS at the one site only, though RFC 2182 §3.1 and §5 want one well removed. Every gateway block reaches the internet through Hurricane Electric (vault/main/services.yml:82-104), so a site or HE outage stops every `<root>` name and, from M7, inbound mail until restored, bouncing mail whose senders' retries (14 h to 5 d, §15.3) end first (12.15). *Residual:* none.

### 12.13 Departures from PLAN.md

- **PLAN.md:25 "`<me>.ur.network`".** The default label is opaque; the name becomes an opt-in alias (owner decision 14; Q-DNS-2).
- **PLAN.md:25 "owns all entries".** System records are fixed; some types, owners and addresses are refused (owner decision 70; Q-DNS-6).
- **PLAN.md:104 "`mail.<me>.ur.network`".** The mail host is `mx.<net>.<root>` (owner decision 32; Q-MAIL-3).
- **Not in PLAN.md.** A self-hosted dns edge replaces Route 53 for ur.network (owner decisions 13, 69, 71), consistent with PLAN.md:80.

### 12.14 Interfaces

- **Provides:** `ResolveNetworkLabel(root, text, interactive) (networkId, kind)` (§8, §9, §13, §15); certs' DNS-01 and canary-CAA routes; §13-§15's records and reverse zones, direct MX and the custom-host map with each host's state and CAA mode (§13.4, §13.8); label reclaim and the restore step, with its edges' diffs and abuse flags (§19.10, §21); suspension (§21); `LocalZone` (§17, §18); entry counts (§20).
- **Consumes:** §7's DNS permission, `network_domain`, `RenameNetwork`, admin events, client names; §8 grants, owner consent, scope labels, §8.10's gate; §13 certs and its CAA walk; §14, §15 record content, the direct-MX check; §16 decisions, the spend check and `approval_use` (D-MCP-11, D-MCP-12); §6 topic `dns`; §4 C14; §19 dns edge hosts, router interfaces, W1's reload and drain, the restore (§19.10), the rota (owner decision 143); §20 quotas; §21 `ScreenName`, `network_verified`, probation caps, open cases.
- **Subprotocol messages:** `DnsZoneChanged` (0x1B01, §6.11) on push topic `dns` (§6.8), versioned by the zone serial.
- **API routes:** §12.8.
- **Tables** (migrations 926+): `dns_root` (root, serial, restore_serial, restoring), `dns_label` (primary key (root, label); network_id, kind, state; never deleted; a restore's CT rows start without a network), `network_dns_zone`, `network_dns_record`, `dns_zone_journal` (diffs, 7 d), `network_dns_custom_host` (with `state enum{pending,active}`, `caa_mode enum{strong,weak}`, `effective_caa_chain_ok bool`, `map_version` and `ready_time`), `dns_custom_host_map` (version, digest, create time; 7 d) and `dns_custom_host_map_applied` (interface, reported version, digest, nginx master, poll time, the last passing route probe's version and time, and the latest probe result of each added host probed for the reported version; while the interface is in the lb inventory); Redis `{dns}serial:<root>`, the last committed serial.
- **Services and config:** `dns` (server/cli/dns; `sidecar/dnsservice`): API blocks on `dns.bringyour.com`, `dnsedge` on the dns edge hosts (UDP and TCP 53); `config/<env>/dns.yml`; vault (ZSKs, DNSKEY windows); two offline KSK HSMs; taskworker (challenge and canary-CAA expiry, the restore's CT replay); `monitor` (canary).
- **Assumptions about other sections:** §19.5 lists the router interfaces, publishes `rpt.bringyour.com`, its `_report` wildcard and the HELO names' A records (owner decision 124), serves recurd.dev's redirect, tells the dns edges which interface W1 drains, runs `lbmap` beside each lb interface's nginx and returns the hosts a restore's regeneration adds or drops (§13.4); §19.10 sets `dns_root.restoring` as the dumps load and runs its abuse step (§21.10), then 12.6's restore step, before api's replay and its labels step, starting a stopped NS only from a reload; §2.8 dns-1 holds the replaced snapshot and the restore's listings to 12.6's ttls; §13.8 re-checks custom hosts on its schedule and writes again on `stale`. §22 tests the zone lint (CNAMEs beside data, `ruf`, `fo`, report mail into `<root>`), cross-network burner DMARC, role mail without SNI, private names per qtype, FCrDNS, the member-scope key-record check, the anchored soak, a replying burner's MX and A across its first and last selector, a drained or failed interface leaving `*`, `@`, every copy and `mx` on both NS, an operator CAA at a custom host's target behind a CNAME or a CAA-flattening ALIAS, an apex host's included, refused while it is still pending (FS-32), a direct MX redirected by operator records (FS-33), a custom host's ClientHello through the split (FS-35), label reclaim after a restore (FS-41, FS-42) and FS-42's dns step: a post-restore write; challenges committed before the loss, above every SOA or not, reading stale; an NS that misses the SOA read reloading, uncounted by `/dns/ready` until it serves restore_serial; custom hosts added or removed after the dump leaving or rejoining the map, listed (M6); and the TLSA and DKIM selectors of sidecars revoked after it gone from both NS once api's replay ends (M7, M9).

### 12.15 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A site or Hurricane Electric outage, or a flood, stops both NS: every `<root>` name, ACME DNS-01, DANE and, from M7, inbound mail fail until restored; paged out of hours, 30 min to acknowledge, it can still outlast senders' retries (14 h to 5 d, §15.3), bouncing their mail | Medium | Critical | Accepted (owner decisions 123, 143); separate hosts and blocks; RRL |
| A signing fault or lost KSK breaks validation; CAs refuse issuance | Low | Critical | self-check, canary (paged from M5), soak, standby ZSK, backup HSM |
| A leaked ZSK, URnetwork or a registrar hijacker forges records | Low | High | zone watch (D-TRUST-9), CT watch, 14-day windows, registrar lock (12.4) |
| A weak-mode custom host, or an ALIAS that also flattens CAA, lets URnetwork publish the CAA that governs it; the canary probe is URnetwork's own, so a compelled operator can pass such an ALIAS at setup or renewal, leaving it as exposed as weak mode (§2.8 EX1) | Low | High | strong mode by default and for every apex; the probe refuses CAA flattening unless the operator is compelled (12.8); setup discloses §2.8 EX1; zone watches (D-TRUST-9) and the CT watch (D-TLS-8), the only control against a compelled operator |
| Safe Browsing flags, or a registrar holds, the whole root | Medium | Critical | takedown hooks; §19.8's pager carries registrar and registry notices from M5 (owner decisions 134, 143); PSL; nothing critical on the apex |
| The PSL declines or lags; Talos keeps "Personal VPN" | High | Medium | §12.4's interim rules; recategorization; custom domains |

### 12.16 Phasing

Milestones and the v0 and v1 sets are §23.4's.
- **v0:** renewal and census (M0); `ur tun`'s resolver (M4) and C14's seam, dark on app paths until §18's app hosts (M8; owner decision 85); the moved root signed without a DS, labels, edge, challenge, SPF, DMARC, null MX and user records, routes, gates, quotas, suspension, label reclaim and the restore step, the canary and its pages (M5); mail records, `b`, `mx`, TLSA and the DS (M7); replying burners' selectors and label copies, the reverse zones' PTRs (M9).
- **v1:** aliases, custom domains in both CAA modes, Team scopes (M6); direct MX and strict-mode MX hosts (M7); scope mail hosts with §15 (M8).
- **Later:** the PSL application once eligible, then §14.6's cut-over; bring-your-own NS; HTTPS/SVCB.
- **Blocking:** §19's dns edge hosts block M5; the soak blocks the DS and M7's DANE; §13.4's generated split map blocks M6's custom hosts; HE's reverse delegation blocks M9's PTRs.
