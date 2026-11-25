## 12. DNS: the ur.network zone and per-network zones

### 12.1 Purpose and scope

This section owns public naming: the user root (X4), the network label (X5) and X17; the `dns` engine and dns edge; DNSSEC; zone content and reverse zones; the record API; DNS-01; custom domains; private names, and the DNS-SD names devices answer for service discovery across hosts (12.9.1; with §17.7.1; owner decision 778); takedown hooks (§21). §13 owns certificates and CAA, §14 and §15 mail record content, §19 the dns edge hosts, §20 quotas. Notation follows D-ARCH-1.

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
| R-DNS-11 | DNS-SD names in a network's zone are answered on the device, from what the policy lets it reach, and never leave it | owner decision 778; R-DNS-4 |

### 12.3 What exists today

- ur.network: Route 53, expires 2027-07-02; signed by a KMS key shared with bringyour.com, no DS (RDAP 2026-11-03; mmm/lag.dev/ops/dnssec.md:25-27); MX at Google Workspace, `_dmarc` `p=none`, no SPF or CAA (dig 2026-11-03).
- The platform left ur.network on 2026-10-01: `api`, `connect` and `mcp` are NXDOMAIN, though warp and vault list them (apple/app/network/Shared/Config/NetworkConfig.swift:19-23; warp/services/services.go:396-438; vault/main/services.yml:3-35,641-739; config/main/tls.yml:2-6).
- Public UDP 53 on the lb interfaces is connect's WhoDis transport; no TCP 53 (vault/main/services.yml:345-347; server/connect/transport.go:2321).
- network_name: 5-50 of `[a-z0-9-]`, edge hyphens and `xn--` allowed, nothing reserved; one rename path holds the old name 24 h; deletion frees it (server/model/network_model.go:178-206; server/controller/account_controller.go:13,161-166; server/model/account_model.go:379).

### 12.4 Roots: the registrable domain (X4, X17)

A **root** is a user-content zone that `dns` signs and serves (`config/<env>/dns.yml`). v0's one root, `<root>` = ur.network, carries user content only (owner decisions 13, 16): burners live in network zones (owner decision 32), and recurd.dev only redirects to ur.io/recurd (§19; owner decision 15). Platform names, the report, lb and HELO hosts included (owner decision 124), live on bringyour.com; `<root>` keeps only `ns1`, `ns2` (glue), `_psl` (the PSL's proof), `canary` (12.6), `<acme_token>.acme` (certs' delegated challenge targets, one a verified custom domain, 12.8) and §14.6's `_spf`, keeping SPF checks in the signed zone.

Until `<root>` is on the Public Suffix List (PSL), its networks share one site (cookies, saved logins), one reputation (§21.6), one Let's Encrypt budget and one DMARC organization ([R:ext-edge] §2.5; mmm/lag.dev/ops/psl.md:51-56). Steps (D-DNS-1):
1. M0: renew to 2036 under registrar lock; the PSL wants over 2 years of term at listing.
2. Move platform names and company mail off ur.network, warp and tls.yml; the lb sends `*.<root>` to tlsedge (§13.4), and only the apex redirects to ur.io.
3. Serve the zone from the dns edge, switch NS (no DS exists) and delete the Route 53 zone.
4. Set `_dmarc.<root>` to `p=reject` once company mail has left.
5. Once eligible (~3,000 active users, `_psl`, an abuse contact), apply to the PSL and request recategorization (connect/EXTENDERUPDATE.md §10.1).

Until listed: no URnetwork cookies on the root, HSTS preload with `includeSubDomains`, exact-host autofill (§15, §18), and §13.7's rule for session cookies on same-site requests from other networks' pages.

### 12.5 The network label (X5)

**Label (owner decision 14).** 10 characters `[a-z][a-z0-9]{9}` from crypto/rand (~51 bits), allocated on first need, immutable, never reassigned, and not derived from network_id, whose ULID exposes creation time ([R:server-identity] §2.11). A draw that hits an existing row or fails `ScreenName`'s reserved or brand rules is redrawn (owner decision 97). A sidecar reads its network's label and alias from api's `GET /sidecar/label` (Client, sidecar-classified, under §7.4's `/sidecar/*`), which answers `{network_id, label, alias}` for its token's own network alone, allocating the label on first need, `alias` empty while there is none, and from M5 from 12.8's `GET /dns/zone` as well (owner decision 421). `dns_label` alone lands in MG2 (§19.7), with `model.EnsureNetworkLabelInTx` and `model.ResolveNetworkLabel`, pending until M2's Gn-out, so `<net>` in `.ur`, git-remote-ur, §9.4's addresses and `network:<net>` hold a real label from M2; draws before M5 run `ValidateDnsName`'s reserved and brand rules, which hold this section's list, curated brands included, and `ScreenName` joins at M5; the rest of `dns_*`, all DNS serving and aliases stay at M5 and M6. From M5 every label drawn comes with its zone (owner decision 690): `EnsureNetworkLabelInTx` writes the label's 12.7 set with mail off, null MX at `@` and `*`, `v=spf1 -all` at `@` and the strict `_dmarc`, through 12.6's write in the draw's transaction, so the draw takes a root serial in the label map's order and a running tlsedge routes it, §13.5's `DnsLabelMapSince` returning it, a label only read or named by a certificate order included; a writer that writes the label's zone in the same transaction, the edge, mail and record writes, draws without the set, its own write taking the serial, so each transition stays one journal write. A restoring root refuses the draw before anything is written, `GET /sidecar/label` answering 503; a root with no `dns_root` row, and a binary without MG5, still draw at serial 0; and every write in a network's zone stamps that network's names still at 0, so a label drawn before MG5 linked comes in at its zone's next write. A draw costs one journal write and about four system rows. DNS so answers for a label that was only read, which tells a resolver that already knows it that the label exists; R-DNS-4's concern is enumeration, which 12.6's compact denial still prevents, so a label nobody holds stays unguessable, and every label carries its spoofing records, null MX, SPF `-all` and DMARC reject, from the moment it exists.

**Alias** (opt-in, "public forever (CT)"): the network_name, one per network: a copy of the label's records except challenges, live once §13's certificates name it. Labels and aliases share `dns_label`'s primary key (root, label) across kinds and states, so alias claims and `RenameNetwork` (§7.12) refuse any name a row holds, live, retiring or tombstoned.

**Validation** (aliases and new names, §7.12; every new name through `ScreenName`, §21.6): `ValidateNetworkName`; no edge `-` (Boulder refuses it); no `--` at positions 3-4 (no `xn--` or IDNA homographs); not reserved; not brand-confusable after mapping 0→o, 1→l, 3→e, 5→s and rn→m per `-` token ([R:ext-edge] §5). Team scope labels (v1; owner decisions 40, 58), which an Owner or Admin declares in the config head's signed `ServiceSettings`, each keeping its first member or tag across its retirement too, [its reassignment](DESIGN-DEFER.md#acl-team-scope-reassignment) waiting for a consent rule, and which dns takes only from the verified projection, never from a hostname or a grant naming one (§8.8's Team scopes; owner decision 678), also avoid reserved owners, hosts, client names (§7.7) and word-number labels. The reserved block guards only the names directly below `<root>`, labels, aliases and scope labels, where such a word would pass for a platform name: inside a network's own zone a record owner or published host (§13), `<host>.<net>.<root>`, takes §21.6's brand rules and 12.7's owner table instead, so `www` and `api` there are the network's own, and `ScreenName` screens a host apart from a label (owner decision 419). Reserved, versioned in the sidecar repo:

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
  wakes the feed (PgBouncer's transaction pooling bars LISTEN/NOTIFY); from M5 a label's draw is such a
  write, of its zone's 12.7 set, and every write in a network's zone stamps that network's labels still
  at serial 0 with its serial, so the label map changes only in serial order (12.5; owner decision 690)
dns API blocks (dns.bringyour.com), every internal route under /dns/internal/ and taking one caller class's
  bearer (12.8): GET /dns/internal/journal?root=&after=<applied> (long-poll <= 25 s);
  /dns/internal/snapshot (the rows at one serial); a poll the journal cannot continue (after < serial, no
  row after+1: a 7-day gap, a restore) answers reload, with restore_serial; every answer also names each
  lb interface's reported custom-host version, with its probe name and the hosts it added, and the
  map-stale interfaces (§13.4)
  rows and snapshots stay readable across releases N and N+1: N ignores fields N+1 adds, and writes
  N cannot read wait until N+1 serves 100% (§19.11)
dnsedge on ns1, ns2 (host-pinned; UDP and TCP 53; no proxy in front, so RRL sees resolver addresses):
  apply each diff atomically, in serial order --> zone in memory + local snapshot; a reload swaps in
    /dns/internal/snapshot's; a replaced snapshot older than restore_serial is kept only until POST
    /dns/internal/reload-diff takes its diff, at most 24 h, and any other is deleted at once
  serve a zone build or key set only once its self-check passes, else keep the previous one
  answer from memory, sign online, rate-limit; SOA serial = root serial
  probe each lb interface every 10 s (owner decision 34; server/services_lb_inventory.go:11-17,35):
    tlsedge's alert on 443, 8443, 8883 and 5671 (§13.4; owner decision 121);
    on 443 also the route probe of the custom-host version the interface reported (§13.4), posted
      to POST /dns/internal/route-probes;
    the 25 banner on §19.5's router interfaces
    drop one after 3 failures, or while the journal names it map-stale (§13.4), never all, and the one
    §19.5's W1 drains
      --> answered from the healthy set at answer time, with no journal write: the A, AAAA at *, @,
          each copy of *'s records and each mx host on router interfaces (12.7)
certs: GET /dns/internal/ready?serial=s, checked in this order --> stale while restoring or for
  s <= restore_serial (certs writes again at a new serial, §13.8); else API blocks read each running NS's
  SOA over TCP and hold while any is below s, a running NS that does not answer included; then
  canary_failing while the canary is not clean (monitor, below), which holds an order with no rewrite and
  no new serial; else ready
running NS: dns_ns(root, ns, state running or stopped, stopped_time, reason), seeded from dns.yml; an NS
  is running whether or not it answers now; the restore step or `sidecarctl dns ns stop|start` writes
  stopped, and it leaves stopped only once it serves at or above restore_serial (owner decision 418)
restore (§19.10, after the dumps load and the abuse step, before api's replay; Postgres comes back at dump
  age with an empty journal, while ns1 and ns2 serve newer zones until they reload):
  §19.10 sets dns_root.restoring as the dumps load, before api or the dns blocks serve: every dns write
    gets 503, so the CT replay (12.5) and api's replay of revocations (§7.10), their DKIM and TLSA
    deletions (I-15) included, commit after this step; until the transaction below, 12.9's SuspendZone,
    SuspendHost and Restore set only their rows, taking no serial, so the suspensions and lifts
    §19.10's abuse step re-places (§21.10) are in its snapshot
  read each running NS's SOA over TCP; an NS that does not answer is written stopped, and serves again
    only from a reload, its local snapshot taken as the replaced one
  one transaction: serial := restore_serial := max(restored serial, the SOAs read, {dns}serial:<root>)
    + 2^24, above every serial the lost primary issued, since the key lacks only raises that failed or
    that a Redis failover lost (RFC 1982 allows a jump below 2^31); raise the key
  each edge reloads at restore_serial and posts its diff (POST /dns/internal/reload-diff); once every
    running NS answers that SOA, restoring := false; the step lists, by network_id, owner and type, each
    RRset but challenges' and canaries' in a posted diff, and raises the custom-host map's version,
    dns_root.custom_host_map_version, 2^24 above max(every network_dns_custom_host.map_version, every
    version in dns_custom_host_map_applied, 0), both tables being in the dump, every host's map_version
    with it, so W1 loads the map from the restored rows (§19.5) and each host stays pending until every
    interface is current for the new version (§13.4), listing the hosts that adds or drops, in the
    incident and in each network's admin events (§7.11), both kept 400 d, flagging networks with an open
    §21 case
monitor, at the site and on 1 outside host: the site's copy rewrites canary.<root> TXT each minute
  through POST /dns/internal/canary {root, value}: value <= 64 printable ASCII bytes, starting with its
  unix ms; TTL 60; one serial and journal row (model.DnsWriteInTx); answered {serial}, 503 while restoring;
  each copy validates it through each NS against the KSK as a configured trust anchor (Unbound
  trust-anchor), the outside copy also checking the value is under 180 s old, and posts POST
  /dns/internal/canary-report {root, source: site or outside, serial, ok}, ok only if the TXT validated
  through every running NS; only the site's copy writes, so no write credential leaves the site;
  dns_canary_verdict(root, source, serial, ok, report_time), primary key (root, source), overwritten in
  place; clean: the site row ok with report_time under 180 s old, and no outside row not ok under 180 s
  old; a missing site row reads as failing; a stale outside row alone holds no order and raises a
  visibility alert;
  2 public resolvers check propagation only until the DS, then validate as well;
  DNSKEY window > 7 d; equal SOA serials
  --> incident alert (server/monitor/alert_classes.go:3-8); from M5, both NS failing or a canary
      signature failing pages §19.8's rota at any hour, 30 min to acknowledge (owner decision 143), and
      one running NS failing SOA reads for 1 h pages it in business hours, since orders then wait (owner
      decision 418)
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
<host>             a copy of *'s records where the host's own rows hold no A,     §12
                   AAAA or CNAME, so a user's TXT, MX or SRV there no longer hides the edge's addresses;
                   the edge answers the host's own RRsets first and the copy's for the types it lacks, and a
                   host with a CNAME takes none (owner decision 714)
_acme-challenge    TXT, <= 2 values; also under a live alias; writer certs        §13
<host>             CAA canary during a strong-mode probe (12.8), TTL 60,          §13.8
                   with a copy of *'s records where <host> has none; writer certs
mx                 A, AAAA: healthy router interfaces (12.6), or a direct MX's (12.8)   §15.4; mail on
_25._tcp.mx        TLSA 3 1 1 per receiver key; writer /dns/key-record            §15.5; mail on
b                  MX 10 mx.<net>.<root>; TXT "v=spf1 include:_spf.<root> -all"   §14.6; mail on
_dmarc             TXT "v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=s;
                        rua=mailto:<report_token>@rpt.bringyour.com"; never ruf or fo   §14.6
<sel>._domainkey   TXT DKIM per sending sidecar; writer /smtp/dkim-keys; rotation  §14.6
                   keeps the old one 7 d, removal (§7.10, I-15) deletes in the same write (owner decision 36)
<sel>._domainkey.<blabel>   a replying burner's, until the PSL listing             §14.6, §15.9
                   (owner decision 79)
<blabel>           a copy of *'s MX, A, AAAA, written in the same journal         D-DNS-11
                   write as its first _domainkey child (RFC 4592 §2.2.1) and
                   deleted with the last selector
_mta-sts           TXT "v=STSv1; id=<n>"                                          §15; mail on, verified
_smtp._tls         TXT "v=TLSRPTv1; rua=mailto:<report_token>@rpt.bringyour.com"  §15
; a copy is one row that dnsedge answers with *'s current records and TTLs, so writes to * and
; health drops (12.6) reach it with no further write; every writer's transaction plans one at each owner
; below @ that * covers and whose own rows hold no A, AAAA or CNAME, so * keeps answering wherever an
; owner exists for another reason (owner decision 714)
; from M5 a label's draw writes this set with mail off, the null MX at @ and *, @'s SPF and _dmarc, in the
; draw's transaction, so every label has its zone and its spoofing records from the moment it exists,
; a label only read included (12.5; owner decision 690)
; an alias zone and each Team scope <scope>.<net>.<root> (owner decisions 40, 58) repeat this set,
; with their own mx host and TLSA, but a scope's set holds no _mta-sts until a scope publish exists,
; since no receiver serves a scope's MTA-STS policy (§13.9's system publish is tls/443/mta-sts on
; smtp/25/mx alone), scope mail keeping DANE for its TLS, as burner mail does (owner decision 715;
; DESIGN-DEFER.md's dns-scope-mta-sts entry)
; _mta-sts is published only for a network with network_verified, the zone's mail policy carrying it
; for no other, and a verification change reconciles the zone where it is written, at api's verification
; update (a sign-in, a client's auth, a payment) and at the zone's next write, so one no writer makes,
; a paid window's end or an Owner's removal through the config log, reaches it at the next of those
; (owner decision 630); the review phase adds the receivers' certificates as a condition
; (DESIGN-DEFER.md's dns-mta-sts-certificate-gate entry)

<root>:
@                  SOA; NS ns1, ns2; CAA per §13.8 + iodef; below @, only         §12, §13.8
                   retiring names' issue ";" (12.5) and probes' canaries (12.8)
@                  TXT "v=spf1 -all"; MX 10 rpt.bringyour.com (abuse@, postmaster@)   §14.6, D-SMTP-19
@                  A, AAAA: lb interfaces, where a platform certificate redirects to ur.io   §13.4
_dmarc             TXT the same policy, adkim=s; aspf=s; + psd=y once company mail leaves   §14.6
                   ; strict, since burner From domains fall back to it (RFC 7489 §6.6.3) until the PSL listing
                   ; its rua's local part is root, which no report token can equal (§14.6)
ns1, ns2           A, AAAA: the dns edges (glue)                                  §12.6
_psl, canary, <acme_token>.acme                                                   12.4, 12.6, 12.8
_spf               TXT: the sending lb addresses (owner decision 124)             §14.6

reverse zones of the sending lb addresses (owner decision 124), delegated by HE (M9), unsigned:
<address>          PTR its HELO name under bringyour.com, from smtpedge.yml       §14.6
```

**Edge address records (owner decision 335).** `*` and `@` A and AAAA are grant-driven. An edge grant is an active publish on `dns:<host>` in that zone, or the system publish: a network with a `mail_network` row and an approved `smtp/25/mx` listen grant, since `mta-sts.<net>.<root>` has no row of its own and resolves only through `*`. `*` has A and AAAA while the zone's set holds any host but `@`, or the system publish; `@` has them while the set holds `@`. After each accepted `POST /network/config/delta` or `POST /network/config/projection`, once the object PUT has committed, api recomputes the set from the state at that position and calls `model.DnsSyncEdgeRecords`, which makes one journal write per transition and none otherwise, in a transaction of its own, since §7.9 commits by conditional PUT and has no transaction to join. An hourly taskworker pass over §21.6's list reconciles both ways: it removes what expired and adds what a crash between the PUT and the write missed. §9.4's `FirstListen` and `LastUnlisten` have no DNS consumer, so whether a listener is up never shows in DNS.

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

- **Refused owners** (network and alias zones): `b`, `mx`, `mail`, `mta-sts`, system `_` owners, scope labels and word-number labels (`^[a-z]+-[0-9]{4}$`, kept for burners; owner decision 32); and the DNS-SD names devices answer themselves (12.9.1; owner decision 778): `_dns-sd._udp` and every owner below it, and a `_<service>._tcp` or `_<service>._udp` pair directly under `@` with every owner below it, so no public record hides behind a private answer.
- **Lint.** No journal row commits a CNAME beside other data at one owner, system records included (RFC 2181 §10.1).
- **Entries.** One user RRset is one `dns_entries` unit (§20.4); system, DKIM, challenge, alias and edge records are free; `tls_endpoints` bounds edge names.
- **Abuse caps** (pro.yml `sidecar_abuse:`; §21 tightens them): `dns_changes_per_hour` 60, `dns_challenges_per_name_hour` 10, `dns_dkim_selectors` 64 device selectors under `_domainkey.<net>.<root>`, burners' excluded (§14.6).

### 12.8 Record API, DNS-01, custom domains

| Route | Auth | Purpose |
|---|---|---|
| `GET /network/dns` | Network, read roles | label, alias, records, quota; each custom host's state, CAA mode and readiness, a pending one naming the lb interfaces not yet current for it (§13.4); each custom domain's owed DKIM CNAMEs, name and target, by api's own lookup at each read of whether the domain answers each published selector, never stored (§14.6; owner decision 656) |
| `POST /network/dns/records` | Network, DNS permission (§7.5) | `{expect_version, upserts, deletes}`, compare-and-swap |
| `POST /dns/records` | service token, aud `dns` (§7.8); §8.10's gate for §8 `admin` on `dns:<host>` (I-8) | the same, for sidecars and §16's tools; under a decision rather than a grant, the gate first answers a retry with the stored result of a use committed under its `Idempotency-Key: <effect_key>` while that `approval_use` row lasts, even past `not_after` or with a stale `expect_version`; otherwise it runs §16.6's spend check (D-MCP-12), which needs the request's upserts and deletes to equal its `CanonicalAction`'s `dns_*` fields, and consumes a use in the write's own transaction (§16 D-MCP-11; §2.8 api-10) |
| `POST /network/dns/alias-claim`, `/alias-release`, `/custom-host-add`, `/custom-host-remove` | Network, DNS permission; custom hosts Team only | alias; map `<host>.<domain>`, or an apex `<domain>`, to a host owner of the network, never a network's, alias's or scope's `@`, a strong-mode host staying `pending` until step 3's checks pass; each change to the active rows raises the custom-host map's version, which §19.5's W1 loads on every lb interface on §13.4's schedule, and a host is ready for TLS-ALPN-01 once every interface that 12.6's probe passes is current for its version (§13.4) |
| `POST /network/dns/label-reclaim` | Network, DNS permission | after a Postgres restore only: re-binds an ownerless `retiring` name (12.5) to the caller's network, given `("urnetwork-sidecar-v1/label-reclaim", name, network_id, nonce)` signed by the key of a CT-logged certificate naming it, the nonce being the restore's incident id (§19.10) |
| `GET /dns/zone` | service token, aud `dns` (§7.8); any admitted sidecar of the network | the label, allocated on first need, the alias, the zone version, and the caller's own view: the RRsets and custom-host states (state, CAA mode, readiness, pending interfaces) of the owners on whose `dns:<host>` it holds publish or admin, by §8's gate; never `GET /network/dns`'s whole body, which stays with the read roles §7.5 gives no Member |
| `POST /dns/label-reclaim` | service token, aud `dns` | `POST /network/dns/label-reclaim`'s tuple and signature for a sidecar, the token's network equal to the tuple's `network_id` |
| `POST /dns/internal/acme-challenge`, `/dns/internal/caa-canary`; `GET /dns/internal/ready?serial=` | internal: certs | challenges at most 2 values a name, TTL 60, ≤ 10 per name per hour (`dns_challenges_per_name_hour`), a write past them answered 429 with a Retry-After in seconds, when the name's oldest write in the window leaves it, to which certs holds the name's orders (§13.8; owner decision 713), gone after 1 h, at `_acme-challenge` owners and a custom domain's `<acme_token>.acme.<root>` (step 3); canaries per the probe (below); ready long-polls ≤ 25 s and answers `stale`, `ready` or `canary_failing` (12.6) |
| `GET /dns/internal/custom-host-map?applied=`; `POST /dns/internal/custom-host-map/applied` | internal: each lb interface's `lbmap` (§19.5 W1), naming its interface, which the API holds to the lb inventory | the newest custom-host map (version, digest, hosts), long-polled ≤ 25 s until it differs from `applied`; then the version the caller's interface loaded, with its nginx master, or a failed render, test or reload (§13.4) |
| `POST /dns/internal/route-probes` | internal: dns edges | each lb interface's route-probe result for the custom-host version it reported (12.6, §13.4) |
| `GET /dns/internal/journal`, `/dns/internal/snapshot`; `POST /dns/internal/reload-diff` | internal: dns edges | the feed (12.6); after a reload across a restore, `{root, replaced_serial, serial, rrsets: [(owner, type)]}`, the RRsets that differ between the replaced snapshot and the new one, which 12.6's restore step maps to networks through `dns_label` |
| `POST /dns/internal/canary`; `POST /dns/internal/canary-report` | internal: the site's monitor, both; the outside monitor, the report alone | 12.6's canary and its verdicts |
| `POST /dns/key-record` | service token; §8 `listen` on `sock:smtp/25/mx` or `smtp/25/mx.<scope>`; a member scope takes only its member's consented devices (§8.5; owner decision 126) | TLSA at `_25._tcp.mx` (or `_25._tcp.mx.<scope>`) for the caller's attested key; the body's repeated `retire_spki_sha256` retires, in the same transaction, the caller's own published keys of that host it names, which a receiver sends with a repeat of its new key once that key serves (§15.5; owner decision 443); owners notified |

DKIM comes only through §14's `POST /smtp/dkim-keys`, TLSA only through `/dns/key-record`; user and key writes add a `network_admin_event` (§7.11). Sidecars read their zone through `GET /dns/zone`, for §13.4's and §13.8's readiness, §16.5's `dns_records` and §6.8's `dns` refetch, and file a reclaim through `POST /dns/label-reclaim` (§19.10); `/network/dns*` stay the console's and network credentials'.

**Internal routes (owner decision 417).** Every internal route sits under `/dns/internal/`, where the lb answers 403 to any source off dns's allow list (§19.5 W8). Each caller class holds its own bearer, 256 random bits in one vault file per caller, current and previous values so a rotation needs no downtime, read once at start from `secret_files`: `internal-dnsedge-1.yml` and `internal-dnsedge-2.yml` on the dns edges, `internal-monitor.yml` and `internal-monitor-outside.yml` on the two monitors, `internal-certs.yml` in taskworker's and `internal-lbmap.yml` in the lb's (§19.4). The API block holds only their SHA-256, in `internal-verify.yml`, compares in constant time, and lets each route take only its class: the edges the feed, reload-diff and route-probes; the site's monitor canary and canary-report, the outside monitor canary-report alone; certs acme-challenge, caa-canary and ready; lbmap the custom-host map and its applied route. No secret is per interface, since playbook-edges.yml copies the whole vault to every edge host, and §13.4 counts an interface's report only once a dns edge's route probe of that version passes. An edge needs neither the issuer nor Postgres to keep serving (D-DNS-3).

**Gates.** Upserts creating a public name (A, AAAA, CNAME, MX or SRV owners) and alias claims need §21.7's `network_verified`, else `QuotaRefusal{limit_key: verification}` (owner decision 96). A name `ScreenName` sends to review is refused with `QuotaRefusal{limit_key: screen_review}` and the case's id, nothing stored in §12's tables and nothing reserved; once a reviewer's `screen_allow` action names the network and the name, the caller's retry passes, and on probation such a name is refused with no case (§21.6; owner decision 534).

**Direct MX (owner decisions 33, 639; Team).** Once mxedge has verified each mail indexer of §15.4's `POST /mail/direct-mx` against 12.7's A rules and its `mail_host_key` and posted the result to api, which repoints the zone itself, `mx.<net>.<root>`'s A and AAAA name their addresses and the TLSA set stays; `DELETE` restores the router interfaces. Its MX, A and TLSA stay in URnetwork's zone, so a direct MX does not exclude URnetwork (§2.8 EX2).

Custom domains, Team only (D-DNS-9):
1. Verify TXT `_urnetwork-challenge.<domain>` (§7.6 `network_domain`).
2. **Strong mode** (the default, and every apex): `<host>.<domain>` answers A and AAAA itself, statically with the lb addresses (§19.5; these miss 12.6's health drops) or through a customer-side ALIAS (flattening) of the host owner it maps to, `<host>.<net>.<root>` (an apex host's too; never `@`, whose CAA would govern the zone's device certificates, RFC 8659 §3), that keeps the queried name, synthesizes only A and AAAA, and answers every other type, CAA included, from the customer's zone. **Weak mode:** a CNAME into `<root>`, active at once, accepted only with §2.8 EX1's exception disclosed at setup: CAA discovery follows the CNAME and stops at the first non-empty set (RFC 8659 §3), so URnetwork could publish a CAA at the target admitting its own account.
3. The customer's CAA pins its own ACME account (`accounturi`, RFC 8657; owner decision 39; custody per §13.8); devices pass DNS-01 through a one-time CNAME at `_acme-challenge.<custom host>`, one for each custom host, since a custom certificate names its one host (§13.8), → `<acme_token>.acme.<root>`, where certs writes their challenges, or TLS-ALPN-01, which needs the ordering desktop to hold a publish grant on port 443 of the host's owner (owner decision 426; DESIGN-DETAILS.md section 17). `network_domain.acme_token` is 16 bytes from crypto/rand, lowercase base32 with no padding, minted by api when the domain first verifies (§7.6), fixed for the row's life and shown to admins in `GET /network/dns` as the CNAME's target. An ordering desktop posts the 43-character base64url DNS-01 digest to `POST /tls/custom-challenge` (§13.15), and certs, still the only writer, writes it there through `POST /dns/internal/acme-challenge` (owner decision 680): api authenticates the caller, captures the certificate row and sequence of the account claim the caller holds, the digest and the expiry, and hands them to certs' worker on taskworker as a bounded command with a restart-safe receipt per domain and claim; the worker, which alone holds certs' DNS credential (owner decision 417), rechecks ownership and authority, refusing a claim a newer holder took before dispatch, writes through its root-scoped DNS client and returns the real DNS serial, which the POST answers. A retry recovers the receipt, a confirmed `stale` permits the next write of the same digest, and an interrupted write is settled before another is charged against the ten writes a name an hour. The receipts are rows of `network_tls_custom_challenge` (MG5; §2.8 cert-1), one a domain and claim, each deleted once its challenge's hour from the capture has passed. The DNS write takes no idempotency key, since every write takes a new serial, which a rewrite after `stale` needs: a write whose acknowledgement was lost is looked for in the DNS journal, above the root's serial the worker kept at its dispatch, before anything is written again, and a commit there of the digest at the name is the write, adopted with its serial and not charged again. Only once a settle time, a setting longer than certs' DNS client waits for an answer, has passed since the dispatch with no such commit is the write owed again, so a write whose answer was lost and that commits after it costs the name's hourly limit one more write of the same value, never a wrong value (DESIGN-DETAILS.md section 17, 17.2.9). `GET /tls/custom-challenge/<id>`, whose id is the serial the POST answered, answers only the sidecar whose receipt holds that serial, any other caller reading 404, and passes on `ready`'s answers, `stale` and `canary_failing` included, so the desktop asks the CA only on `ready` and posts the value again on `stale`. DNS-01 orders never wait on map readiness (§13.4). A strong-mode host commits `pending`, unmapped with `effective_caa_chain_ok` false, while a certs taskworker chain walks its CAA discovery and runs the probe below: both passing make it active, and a walk meeting a name in a URnetwork zone, or a failed probe, refuses it (`custom_host_caa_operator_alias`), each as an admin event. certs repeats both on §13.8's schedule; a failure there clears `effective_caa_chain_ok` until a check passes and records §2.8 EX1's exception in an admin event that alarms the network's admins, the host staying mapped, exposed as a weak-mode one is. The ordering desktops repeat the walk before each order (§13.8).
4. §13.4's split sends each active custom host's SNI to tlsedge, which maps it via `network_dns_custom_host`; mail uses MX `mx.<net>.<root>`, §14.6's selectors (CNAMEd or delegated to `dns`) and the customer's `_dmarc` with `adkim=s`. In strict mode (§15.4; owner decision 98) the MX is the customer's `<mx>.<domain>` in its own signed zone, with TLSA at `_25._tcp.<mx>.<domain>` and A and AAAA to the router interfaces, mapped in `network_dns_custom_host` for mxedge (§2.8 mx-3). Only this path, with every MX host the recipient domain lists and its TLSA customer-signed, carries strict mode's exclusion of URnetwork; an MX host or TLSA in a URnetwork zone stays under §2.8 EX2. An active strict-mode MX host at or under a verified domain also makes the domain strict for outbound mail, so mapping or unmapping one moves its envelope between `b.<domain>` and `b.<net>.<root>`, whether or not `mail.strict` is signed yet, which an admin orders accordingly (§14.6; owner decision 655).
5. A downgrade's withholding (§20.7) sets each active TLS web host of a custom domain `withheld`, which takes it out of the custom-host map, raising its version, and out of tlsedge's routing, while its row, verification and CAA mode stay (D-QUOTA-6); a release after a renewal sets it `active` with `map_version` 0, so it re-enters the map at the next version and is pending until every interface is current, as a new host is, with no re-verification and no new CAA walk. certs' result never turns a withheld host active, and a strict-mode MX host is never withheld, mail hosts keeping MX, TLSA and routing; §14's From-domain gate withholds the domain's mail From beside it (owner decision 420).

```text
CAA probe (certs, for a strong-mode host once its walk passes; one probe per target at a time):
  publish  POST /dns/internal/caa-canary: <host>.<net>.<root> CAA = the walk's effective set (the
           customer's pin) + 0 urcanary "<128-bit nonce>", TTL 60 (12.7), at serial s; then
           /dns/internal/ready?serial=s
  query    repeat the walk's CAA queries at the authoritative servers of each zone it visits, RD=0,
           every 30 s for 10 min (ten times our 60 s negative TTL)
  verdict  the nonce in any answer (the ALIAS flattens CAA), or a canary the lint refuses (a CNAME
           at <host>) --> fail; else pass, once /dns/internal/ready?serial=s answers ready again
           after the last query
  canary   canary_failing counts as ready at both ready checks: §13.8 ties 12.6's canary to orders
           only, and these RD=0 queries validate no DNSSEC
  stale    at either ready (a restore, 12.6, whose edges may lack the canary) --> publish again
           under a new nonce and restart the window
  delete   the canary and its copy in one write, whatever the verdict; taskworker expires one older
           than 1 h, as it does challenges
```

CAs ignore unknown non-critical tags (RFC 8659 §3, §4.1), so the canary admits only the customer's pin, even flattened or cached.

### 12.9 Private names, visibility, capabilities, abuse hooks

**Private names (owner decision 85).** `<client-name>.<net>.<root>` maps §7.7's client names to §17's overlay addresses (X18), which lie in 100.64/10 or RFC 1918 (owner decision 132), so 12.7 refuses them in public records. C14's `UpgradeMux.SetLocalZone` answers them on app paths, fed in each app's VPN component by the names its forwarding role compiles into §17.8's `BridgeState` (§18.6; owner decision 197); §17's per-link resolver answers them under `ur tun`. A name in the table gets an answer for every qtype, A or NODATA (the overlay has no IPv6; browsers also ask HTTPS), so no query for it leaves the device; other names pass through, but for 12.9.1's DNS-SD names, which the device answers too. The table omits a client name equal to a live published host or record owner, which §7.7's signers also refuse.

```go
type LocalZone interface { // nil keeps today's behavior
	// owned with no addrs answers NODATA; !owned passes the query through
	Answer(host string, qtype uint16) (addrs []netip.Addr, ttl uint32, owned bool)
}
func (self *UpgradeMux) SetLocalZone(localZone LocalZone)
```

**Enumeration.** CT shows labels, aliases and scope labels, never hosts (§13.8); under compact denial, hosts and replying burners' labels (owner decision 79) can only be guessed, which RRL slows.

**Visibility and capabilities:** §2.8's dns-1, dns-2, EX1 and EX2. No third party serves the zone, edges log no query (I-13), and the zone and CT watches detect forgery (D-TRUST-9, D-TLS-8). DNS-SD answers come from each device's own discovery view (12.9.1), so no dns server, edge or upstream resolver sees one.

**Abuse (§21).** `SuspendZone(networkId, reason, until)`, `SuspendHost(networkId, host)` withhold records, MX included, and `Restore` returns them, within one write plus the TTL (≤ 3600 s), or, before 12.6's restore transaction, through rows its snapshot carries; tlsedge and mxedge read the same rows. A zone's suspension is its `network_dns_zone` row's reason and until. A host's is no flag on its records but a `network_dns_host_suspension(network_id, host, create_time)` row, carried in the journal and every snapshot as a withheld owner that dnsedge answers NODATA for every qtype, so `*` no longer covers the host. A suspension withholds a record by its `withheld_time`, keeping the row for `Restore`; each record also keeps its `create_time` and, for a challenge or canary, its `expire_time`.

#### 12.9.1 Service discovery names (DNS-SD)

A device answers DNS-SD (RFC 6763) in each zone of its `BridgeState.name_zones` itself, from the instances its discovery view holds, which §17.7.1's watches fill with what the policy lets it reach (owner decision 778), and never forwards a query for one of these names, so no browse or resolve reaches an upstream resolver or the dns edge:

```text
name (under <net>.<root>, or the alias zone)        answer
b._dns-sd._udp, db._dns-sd._udp                     PTR the zone: the browse domain RFC 6763 §11 enumerates
lb._dns-sd._udp, r._dns-sd._udp, dr._dns-sd._udp    NODATA: no automatic browse domain, so a default browse
                                                    stays in local., where §17.7.1's advertising proxy puts
                                                    the same instances, and no registration
_services._dns-sd._udp                              PTR each service type in the view (RFC 6763 §9)
_<service>._tcp, _<service>._udp, <sub>._sub.<type> PTR each instance of the type or subtype
<instance>.<type>                                   SRV 0 0 <port> <target>; TXT the instance's
<label>.<client-name>                               A the address the view holds; NODATA for AAAA and the rest
another name of these forms                         NXDOMAIN, or NODATA where the name exists
every answer and denial                             TTL 10 s, RFC 8766 §5.5.1's cap for clients without push;
                                                    a denial carries the zone's SOA, every interval 10 s and
                                                    its serial 1, since the device keeps no zone file, so a
                                                    resolver caches it no longer (RFC 2308 §3)
```

The reverse zone of the overlay block answers on the device too: `b._dns-sd._udp` and `db._dns-sd._udp` under the name RFC 6763 §11 derives from the tun's address and mask point at the zone, an assigned address's PTR names its private name, and every other name there is NXDOMAIN, so no reverse query for an overlay address leaves the device. `ur tun` sends the zones and the block's reverse zone to its resolver at `<block>.0.53` by the platform's split DNS: systemd-resolved's route-only domains (`~<net>.<root>`), a supplemental resolver per domain on macOS, NRPT rules on Windows. It never adds the zone to the search list, from which mDNSResponder learns its automatic browse domains (mDNSResponder's mDNSCore/uDNS.c), so a default browse never shows an instance twice. A client that names the zone browses it: `dns-sd -B _ipp._tcp <net>.<root>` on macOS, `avahi-browse -d <net>.<root>` where Avahi's wide-area browsing is on (avahi-daemon.conf's `enable-wide-area`), or `resolvectl query --type=PTR` on systemd-resolved.

A viewer's discovery view comes from §17.7.1's watches, whose messages are `DNS_SD_WATCH` (0x1B02) and `DNS_SD_WATCH_RESULT` (0x1B03) in §6.11's catalog, which types.proto and `sidecar/protocol/dns.proto` declare. The limits both ends share, `InstanceCount`, `AnswerByteCount`, `TxtByteCount`, the name's 63 octets and `WatchHoldTimeout`, are fields of protocol's `DnsSdWireSettings`, which §17.7.1's `BridgeDiscoverySettings` carries as its `Wire`, so their defaults stay in one place:

```proto
// sidecar/protocol/dns.proto (owner decision 778): DNS_SD_WATCH's and DNS_SD_WATCH_RESULT's bodies, peer to peer
// over a Required session on the pair's Network contract of class data, so no server reads a field
message DnsSdWatch {
  uint64 since = 1;                   // the host's view version the viewer holds; 0 for none
  uint32 hold_ms = 2;                 // at most WatchHoldTimeout (§17.7.1)
}
message DnsSdWatchResult {
  uint64 version = 1;
  bool serving = 2;                   // false where the host's settings publish nothing; a host whose own inputs,
                                      // its sealed settings and its device role's state, have not settled
                                      // answers UNAVAILABLE instead, which a viewer asks again soon
  repeated DnsSdInstance instances = 3;
  bool truncated = 4;                 // past InstanceCount or AnswerByteCount
}
message DnsSdInstance {               // each field the host's word, never trusted, and no MCP tool reads one
  string name = 1;                    // one label, at most 63 octets
  string service = 2;                 // _<service>._tcp or _udp
  repeated string subtypes = 3;
  uint32 port = 4;
  bytes txt = 5;                      // the TXT record's rdata, at most TxtByteCount
  string host_label = 6;              // the target's own label, as an LDH label (<label> above)
  fixed32 ipv4 = 7;                   // where this viewer reaches the instance, most significant octet first
  bool own = 8;                       // the host's own service
  uint32 ttl = 9;                     // seconds left
}
```

Between hosts the watch delivers each change within a round trip; on the device the advertising proxy's registrations change at once, and unicast clients ask again within 10 s. [DNS Push](DESIGN-DEFER.md#dns-push-notifications) (RFC 8765) is Later: it runs only over TLS whose server the client authenticates under DNS over TLS's Strict Privacy profile, by DANE where it can (RFC 8765 §7), and a resolver answering a private zone on the device has no identity a client can check that way; mDNSResponder, which without push polls a long-lived unicast browse every 15 minutes (mDNSResponder's mDNSCore/uDNS.h), sets up its push TLS in a library Apple does not publish.

On app paths C14's `LocalZone` owns the same names and answers each NODATA, since it carries addresses alone, so no DNS-SD query leaves an app's tunnel either; [answering them there](DESIGN-DEFER.md#dns-service-discovery-app-paths) waits for a `LocalZone` that carries records. What that loses differs by platform. A VPN's match domains join the search list unless `matchDomainsNoSearch` is set (developer.apple.com's NEDNSSettings), so Bonjour on iOS asks `lb._dns-sd._udp` in the zone, and a positive answer there would bring the network's instances into iOS apps' default browses, AirPrint's among them; Android's NsdManager browses `local.` alone (developer.android.com's NsdManager reference), so only an app that queries DNS itself, by `DnsResolver.rawQuery`, would find them.

### 12.10 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Route 53, or a hidden primary with anycast secondaries | anycast; flood absorption | third parties see every query | ruled out (owner decision 69) |
| An offline-signed zone with NSEC3 | no ZSK on public hosts | dictionary attacks on names; health answers need re-signing | rejected (owner decision 69) |
| A ZSK in a KMS or HSM | no key in host memory | a round trip per random-name query, which a flood exhausts | rejected |
| `*` CNAME to a shared edge name | one record | excludes the wildcard MX (RFC 2181 §10.1) | rejected |
| A CNAME from each custom host into `<root>` | one record; follows 12.6's health drops | CAA discovery follows it to a target URnetwork writes (RFC 8659 §3) | weak mode only, disclosed (D-DNS-9) |
| DNS-SD records in the public zone, or answered by the dns edges | every resolver finds them | overlay addresses and device names published; 12.7 refuses non-public addresses | rejected: devices answer them (12.9.1; owner decision 778) |
| DNS Push (RFC 8765) from the device's resolver now | a change reaches a unicast client at once | needs a TLS server identity the client verifies under Strict Privacy, by DANE where it can (RFC 8765 §7), which a resolver for a private zone on the device lacks | Later (12.9.1) |
| Answering `lb._dns-sd._udp`, so default browses take the zone | every app's default browse finds the network | on macOS and Linux it shows each instance twice, beside the advertising proxy's in `local.` | rejected: `b` and `db` only (12.9.1) |

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

**D-DNS-12 (proposed).** A device answers the DNS-SD names of each network zone, and of its block's reverse zone, from its own discovery view, with 10 s TTLs, and never forwards one; `b` and `db` name the zone as a browse domain, and `lb`, `r` and `dr` are empty; 12.7 refuses public owners at those names (12.9.1; owner decision 778). *Why:* a browse reveals what its device looks for (RFC 8882), the view holds only what the policy lets the device reach, and default browses stay in `local.` beside the advertising proxy.

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

- **Provides:** `ResolveNetworkLabel(root, text, interactive) (networkId, kind)` (§8, §9, §13, §15); api's `GET /sidecar/label` and a sidecar's own zone view and reclaim, `GET /dns/zone` and `POST /dns/label-reclaim` (12.5, 12.8); certs' DNS-01, canary-CAA and ready routes, ready answering `stale`, `ready` or `canary_failing`, and the canary's routes and verdicts (12.6); each NS's running state; §13-§15's records and reverse zones, direct MX and the custom-host map with each host's state and CAA mode (§13.4, §13.8); label reclaim and the restore step, with its edges' diffs and abuse flags (§19.10, §21); suspension (§21); `LocalZone` (§17, §18); entry counts (§20); `model.DnsSyncEdgeRecords`, which api calls after each accepted delta or projection, and taskworker's hourly reconcile of edge address records (12.7); the DNS-SD names devices answer, in `ur tun`'s resolver and, as NODATA, in `LocalZone`, with their watch messages (12.9.1).
- **Consumes:** §17.7.1's discovery view; §7's DNS permission, `network_domain`, `RenameNetwork`, admin events, client names; §8 grants, owner consent, scope labels, §8.10's gate; §13 certs and its CAA walk; §14, §15 record content, the direct-MX check; §16 decisions, the spend check and `approval_use` (D-MCP-11, D-MCP-12); §6 topic `dns`; §4 C14; §19 dns edge hosts, router interfaces, W1's reload and drain, the restore (§19.10), the rota (owner decision 143); §20 quotas; §21 `ScreenName`, `network_verified`, probation caps, open cases.
- **Subprotocol messages:** `DnsZoneChanged` (0x1B01, §6.11) on push topic `dns` (§6.8), versioned by the zone serial; `DnsSdWatch` and `DnsSdWatchResult` (`DNS_SD_WATCH` 0x1B02, `DNS_SD_WATCH_RESULT` 0x1B03; 12.9.1), peer RPC between sidecars on data-class contracts for §17.7.1's watches.
- **API routes:** §12.8.
- **Tables** (migrations 926+; `dns_label` in MG2, the rest in MG5, §19.7): `dns_root` (root, serial, restore_serial, restoring, custom_host_map_version bigint, restore_incident_id), `dns_label` (primary key (root, label); network_id, kind, state; never deleted; a restore's CT rows start without a network), `network_dns_zone` (with a zone suspension's reason and until, and its `report_token`, unique, §14.6), `network_dns_record` (with `create_time`, `expire_time` and `withheld_time`), `network_dns_host_suspension` (network_id, host, create_time; 12.9), `dns_zone_journal` (diffs, 7 d), `dns_canary_verdict` (root, source, serial, ok, report_time; primary key (root, source); 12.6), `dns_ns` (root, ns, `state enum{running,stopped}`, stopped_time, reason; seeded from dns.yml; owner decision 418), `network_dns_custom_host` (with `state enum{pending,active,withheld}`, `withheld` a web host a downgrade keeps out of the map (owner decision 420), `caa_mode enum{strong,weak}`, `effective_caa_chain_ok bool`, `map_version` and `ready_time`), `dns_custom_host_map` (version, digest, create time; 7 d) and `dns_custom_host_map_applied` (interface, reported version, digest, nginx master, poll time, the last passing route probe's version and time, and the latest probe result of each added host probed for the reported version; while the interface is in the lb inventory); Redis `{dns}serial:<root>`, the last committed serial.
- **Services and config:** `dns` (server/cli/dns; `sidecar/dnsservice`): API blocks on `dns.bringyour.com`, `dnsedge` on the dns edge hosts (UDP and TCP 53); `config/<env>/dns.yml`; vault (ZSKs, DNSKEY windows, each internal caller class's bearer, and their SHA-256 in `internal-verify.yml`, 12.8); two offline KSK HSMs; taskworker (challenge and canary-CAA expiry, the restore's CT replay); `monitor` (canary); `sidecarctl dns ns stop|start` (12.6; owner decision 274).
- **Assumptions about other sections:** §19.4 mounts each internal caller class's bearer and the API block's `internal-verify.yml`, and §19.5's W8 answers 403 on `/dns/internal/` outside dns's allow list (12.8); §19.8 pages a running NS that fails SOA reads for 1 h in business hours (12.6); §19.5 lists the router interfaces, publishes `rpt.bringyour.com`, its `_report` wildcard and the HELO names' A records (owner decision 124), serves recurd.dev's redirect, tells the dns edges which interface W1 drains, runs `lbmap` beside each lb interface's nginx and returns the hosts a restore's regeneration adds or drops (§13.4); §19.10 sets `dns_root.restoring` as the dumps load and runs its abuse step (§21.10), then 12.6's restore step, before api's replay and its labels step, starting a stopped NS only from a reload; §2.8 dns-1 holds the replaced snapshot and the restore's listings to 12.6's ttls; §13.8 re-checks custom hosts on its schedule and writes again on `stale`. §22 tests the zone lint (CNAMEs beside data, `ruf`, `fo`, report mail into `<root>`), cross-network burner DMARC, role mail without SNI, private names per qtype, FCrDNS, the member-scope key-record check, the anchored soak, a replying burner's MX and A across its first and last selector, a drained or failed interface leaving `*`, `@`, every copy and `mx` on both NS, an operator CAA at a custom host's target behind a CNAME or a CAA-flattening ALIAS, an apex host's included, refused while it is still pending (FS-32), a direct MX redirected by operator records (FS-33), a custom host's ClientHello through the split (FS-35), label reclaim after a restore (FS-41, FS-42) and FS-42's dns step: a post-restore write; challenges committed before the loss, above every SOA or not, reading stale; an NS that misses the SOA read written stopped and reloading, uncounted by `/dns/internal/ready` until it serves restore_serial; custom hosts added or removed after the dump leaving or rejoining the map, listed (M6); and the TLSA and DKIM selectors of sidecars revoked after it gone from both NS once api's replay ends (M7, M9).

### 12.15 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A site or Hurricane Electric outage, or a flood, stops both NS: every `<root>` name, ACME DNS-01, DANE and, from M7, inbound mail fail until restored; paged out of hours, 30 min to acknowledge, it can still outlast senders' retries (14 h to 5 d, §15.3), bouncing their mail | Medium | Critical | Accepted (owner decisions 123, 143); separate hosts and blocks; RRL |
| A signing fault or lost KSK breaks validation; CAs refuse issuance | Low | Critical | self-check, canary (paged from M5), soak, standby ZSK, backup HSM |
| A leaked ZSK, URnetwork or a registrar hijacker forges records | Low | High | zone watch (D-TRUST-9), CT watch, 14-day windows, registrar lock (12.4) |
| A weak-mode custom host, or an ALIAS that also flattens CAA, lets URnetwork publish the CAA that governs it; the canary probe is URnetwork's own, so a compelled operator can pass such an ALIAS at setup or renewal, leaving it as exposed as weak mode (§2.8 EX1) | Low | High | strong mode by default and for every apex; the probe refuses CAA flattening unless the operator is compelled (12.8); setup discloses §2.8 EX1; zone watches (D-TRUST-9) and the CT watch (D-TLS-8), the only control against a compelled operator |
| Safe Browsing flags, or a registrar holds, the whole root | Medium | Critical | takedown hooks; §19.8's pager carries registrar and registry notices from M5 (owner decisions 134, 143); PSL; nothing critical on the apex |
| The PSL declines or lags; Talos keeps "Personal VPN" | High | Medium | §12.4's interim rules; recategorization; custom domains |
| A unicast DNS-SD client keeps a withdrawn instance until its TTL runs out, or longer where its resolver raises short TTLs (RFC 8766 §5.5.1 warns of 30 s floors) | Medium | Low | 10 s TTLs; macOS and Linux apps that browse `local.` take the advertising proxy's registrations, which change at once (§17.7.1); DNS Push Later (12.9.1) |

### 12.16 Phasing

Milestones and the v0 and v1 sets are §23.4's.
- **v0:** renewal and census (M0); labels, `dns_label` and api's `GET /sidecar/label` (M2); `ur tun`'s resolver (M4) and C14's seam, dark on app paths until §18's app hosts (M8; owner decision 85); the moved root signed without a DS, labels, edge, challenge, SPF, DMARC, null MX and user records, routes, gates, quotas, suspension, label reclaim and the restore step, the canary and its pages (M5); mail records, `b`, `mx`, TLSA and the DS (M7); replying burners' selectors and label copies, the reverse zones' PTRs (M9).
- **v1:** aliases, custom domains in both CAA modes, Team scopes, 12.9.1's DNS-SD names in `ur tun`'s resolver with §17.7.1's discovery (M6; owner decision 778); `LocalZone` owning those names on app paths (M8); direct MX and strict-mode MX hosts (M7); scope mail hosts with §15 (M8).
- **Later:** [the PSL application](DESIGN-DEFER.md#dns-psl-listing) once eligible, then §14.6's cut-over; [bring-your-own NS](DESIGN-DEFER.md#dns-bring-your-own-ns); [HTTPS/SVCB](DESIGN-DEFER.md#dns-https-svcb-records); [a Team scope's MTA-STS publish](DESIGN-DEFER.md#dns-scope-mta-sts) (owner decision 715); [DNS Push for DNS-SD](DESIGN-DEFER.md#dns-push-notifications) and [DNS-SD answers on app paths](DESIGN-DEFER.md#dns-service-discovery-app-paths) (owner decision 778).
- **Deferred:** DESIGN-DEFER.md holds an entry for each Later item, linked above, and for [this section's v1 set](DESIGN-DEFER.md#dns-v1) (owner decision 587).
- **Blocking:** §19's dns edge hosts block M5; the soak blocks the DS and M7's DANE; §13.4's generated split map blocks M6's custom hosts; HE's reverse delegation blocks M9's PTRs.
