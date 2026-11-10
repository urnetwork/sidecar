## 19. Server services: deployment, data stores, operations

### 19.1 Purpose and scope

This section maps §9-§15, §18, §20 and §21's services to warp blocks, lb routes, addresses, stores and rollout classes. It owns X13 (the file clusters, decided: hardware, drive settings, telemetry, protection states, growth), the push sender, host clocks, the schema summary and dumps, dns edge hosts, paging, gates and runbooks; §10 owns gkm's sizes, §11 objects, placement and the write budget, §12-§14 DNS, the split and sending, §18.7 the wake trigger, §21 abuse review, §23 milestones.

### 19.2 Requirements

| id | requirement | source |
|---|---|---|
| R-OPS-1 | Horizontally scaled services in server | PLAN.md:5 |
| R-OPS-2 | "The file blobs are stored in minio in a new file cluster" | PLAN.md:61 |
| R-OPS-3 | Storage 1/20/200 GB per tier | PLAN.md:355 |
| R-OPS-4 | Servers see only ciphertext and small headers; client IPs are never logged | owner directive 2026-11-03; I-13 |
| R-OPS-5 | Migrations apply before code, compatible with the running release | connect/CODESTYLE.md:87-89 |
| R-OPS-6 | No PostgreSQL on packet paths; PgBouncer transaction pooling; Redis hash tags | connect/CODESTYLE.md:106 |
| R-OPS-7 | Services are built, pinned, rollout-classified and dark until enabled | build/all/deploy-rollout.zsh:24-39 |
| R-OPS-8 | Push without repeating the 2026-07-15 pubsub meltdown | PLAN.md:119; server/model/peer_model.go:31-36 |
| R-OPS-9 | One site, no off-site file-cluster copy; site loss recovers from devices; sidecar tables dumped daily off site, kept 14 days (ops-2) | owner decisions 89, 90, 94 |
| R-OPS-10 | Self-hosted DNS on new edge hosts at the site; no dedicated addresses for user traffic or mail | owner decisions 34, 69, 71, 123, 124 |
| R-OPS-11 | Business-hours abuse review in v0, with a pager for registrar, registry and law-enforcement emergencies from M5; infrastructure pages out of hours from M3; 24/7 review in v1 | owner decisions 95, 134, 143 |
| R-OPS-12 | The first metadata cluster: 8 × Samsung PM9A3 1.92 TB, 2 per host, EC:4 (~7.7 TB usable); every metadata drive within 0.8 DWPD and 50% of rated IOPS but for P0 work past the refill, which pages (19.8); growth only by adding clusters | owner decisions 136-140, 145, 186 |

### 19.3 What exists today

- A service is `server/cli/<svc>` plus a block in `vault/<env>/services.yml`'s top `versions[]` (warp/README.md:86-97); `beta 1 + g1 99` are lb upstream weights (warp/warpctl/config.go:1661).
- lb: 4 hosts, 10 interfaces, plus transparent ones on fireside and crisp (vault/main/services.yml:338-464), each keying one zone (450/min, burst 150, 50 connections) per `$binary_remote_addr` outside `exclude_subnets` (:66-80; warp/warpctl/config.go:1541-1599). http servers own TCP 80 and 443 with 16 MiB bodies (warp/warpctl/config.go:1301); nginx has `realip` and `ssl_preread` (warp/lb/Dockerfile:53-58). Stream ports send PROXY v1 (warp/warpctl/config.go:2506-2512) and yield router rules (warp/warpctl/vyos.go:238-300); host-pinned services own only UDP ports (warp/services/services.go:704-716).
- Postgres: one primary, no replica; the main dump reads a base-backup copy on edge-6, incremental against the base it keeps, every Sunday and Thursday at 06:00 UTC, its timer held since 2026-11-04 until the redesigned dump lands, one-off runs aside (xops/main/ansible/inventory.yml:152-182; on 2026-11-03 the newest dump anywhere was planetoid's of 10-03, :172-174), and keeps 9 generations (~4 months; :186-193); planetoid pulls daily and keeps 2 latest, 1 weekly and 1 monthly generations (host_files/planetoid/backup/README.md:3-6). edge-5 also pulls physical base backups of the primary, `main-pgbase-<date>` generations on its MinIO drives, by hand while `pg_basebackup_timer_enabled` is false (xops/main/ansible/playbook-pg-basebackup.yml:1-25). Redis: 48 masters, no replicas (xops/main/ansible/REDIS.md:3); rdb bundles kept ~8 months (inventory.yml:194-202).
- MinIO: edge-5, shared, at its request ceiling in the 2026-11-01 PUT surges (now capped at 1,024), without PR #21653 (inventory.yml:282-360; playbook-minio-clusters.yml:36-37).
- Host clocks: xops configures no clock sync on the hosts; warpctl sets NTP only on the routers (warp/warpctl/vyos.go:1236-1239).
- monitor notifies only through Slack (server/monitor/alert_slack.go:269); nothing pages.

### 19.4 Service blocks

Blocks are `beta 1 + g1 99` on every lb host unless noted.

| Service (§), blocks | Name, routes, ports | State; ready also needs | `secret_files` |
|---|---|---|---|
| api (existing) | `api.bringyour.com`: `/network/*`, `/sidecar/*`, `/acl/*`, `/approval/*`, `/tls/*`, `/smtp/*`, `/mail/*`, `/abuse/*` | — | the oauth issuer's signing keys; the first metadata cluster (`proj/`, `projrows/`, `rev/`, `hold/`) |
| evs (§11) | `evs.bringyour.com`: `/evs/*`, segments on `streamable_paths`; W2 | §11.8's objects; each cluster's sentinel readable | JWKS, redis, every cluster, from v1 with DELETE on the segment bucket for §11.13's purge, receipt MAC keys (current and previous) |
| gkm (§10) | `gkm.bringyour.com`: `/gkm/*`; W2 | §10.6's objects | JWKS, redis, metadata clusters |
| sockets (§9) | `sockets.bringyour.com`: `/socket/*`; W2 | Redis; ticket key; projection loaded | JWKS, redis, ticket keys |
| dns (§12): API; host-pinned `dnsedge` on each dns edge | `dns.bringyour.com`: §12.8's routes, journal feed; edges: UDP, TCP 53 | API: `dns_*`, `{dns}`; edge: current snapshot, verified key set | API: JWKS, pg, redis, DNSKEY windows; edge: current ZSK |
| tlsedge (§13) | behind W1's split on 443; 8443, 8883 and 5671 unsplit (W7; owner decision 121) | `{tes_}`, `{vhk}tls:`; K platform clients | platform credential |
| mxedge (§15): router; platform listener | TCP 25 (W4) | §15's tables, `{mxr_}`, `{mxc_}`, `{vhk}mx:` | redis, both blocks; platform and feed credentials; platform-mail key (listener only) |
| smtpedge (§14): g1 1 on 2 sending hosts; `exposed: false`, `cap_net_admin` | outbound 25 from its hosts' shared lb addresses by fwmark (warp/warpctl/config.go:2689; owner decision 124) | `smtp_*`, `{smq_}`; addresses bound | platform credential, X-UR-Ref keys |
| taskworker (existing) | — | the jobs §7, §10-§14, §20 and §21 list; the push sender | adds every cluster (GC, hourly evacuation and packing with v1's versionless sweep, shreds, gkm's reconciler, and from v1 §11.13's drop dry runs and jobs, P2 under D-OPS-21, with the segment-bucket DELETE it already holds) and the write budget's and HDD capacity's loops, ACME, EAB, Web Risk, APNs and FCM keys |

New blocks serve `GET /status` on port 80, mount `{vault: no, config: yes, site: no}`, run as user 65532, call `server.ScrubCommandLogs()` first and gate readiness on the column above (server/router/warp_handlers.go:214). Non-issuer blocks mount only their audience's public JWKS (§7.8), not today's signing keys (server/oauth/token.go:258-268).

**Push sender (owner decision 88).** A continuous taskworker loop delivers §18.7's triggers; nothing subscribes per client (R-OPS-8):

```text
input    each {wakeq_<shard>} stream, read through one consumer group, so an entry has one sender, and held by
         due time; an entry left unacknowledged is XAUTOCLAIMed after 30 s idle; entries older than 60 s, past
         §15.6's hold, are dropped and trimmed (clients resync, §6.8)
due      it MGETs {scp_<C>}ack, tok and tokrev: an ack at or past the entry's hint, or no token, drops the
         entry; otherwise it wakes, then XACKs (WK1-WK5, §18.7)
token    {scp_<C>}tok projects sidecar_push_token at the revision {scp_<C>}tokrev holds; api applies each
         change through §18.7's script, which refuses one older than tokrev or over 60 s past its TIME read;
         apps POST /sidecar/push-token at each launch; taskworker's 60 s pass reconciles each hash slot
         whose {tokgen_<n>} sentinel is absent or names another master's run_id, 90 s after it found it
         (§18.7's loss step), so one master lost or restarted from an old dump costs its slots that wait and
         ~2 s per million tokens, and re-applies the rows changed since 2 min before its last completed run
         began (§18.7's sweep); no Postgres read per hint
rate     per client, one wake per 10 s, plus one at the window's end if a hint arrived inside it; per APNs
         device 3 an hour (§18.7), per FCM device and topic 1 a minute; §6's hourly key for POST /sidecar/wake;
         counters under {wake_<C>}, each expiring within 1 h
errors   429 and 5xx: at most 3 retries with backoff; APNs 410 or FCM UNREGISTERED tombstones the row only
         while its revision equals the tokrev read with that token, then applies the tombstone (§18.7)
metrics  by platform, topic and result, never ids or tokens; sized for twice Y2's 6,000 hints/s
```

### 19.5 Load balancer, addresses, certificates

| # | Change | For |
|---|---|---|
| W1 | §13.4's SNI split on every lb interface (owner decision 34), realip from PROXY so zones key per visitor; each interface runs the split drained first, out of DNS answers (warpctl's Route 53 records; the dns edges' via sidecar.yml's `drained`), so only probes and §13.4's bench reach it, then rejoins, 24 h apart after §13.4's gate, and only once current for the newest custom-host version (§13.4); `lbmap`, a loop beside each lb interface's nginx, loads §13.4's custom-host map: it long-polls `GET /dns/custom-host-map` (§12.8) and, before nginx serves 443 at start, else 5 s after the first unapplied version and at most once per 15 min, since a reload keeps old workers up to 60 min, renders `tls-custom-hosts.map` and the port-80 redirect server from the newest version's rows with its probe line, runs `nginx -t`, reloads and reports the version loaded (§13.4), returning the hosts it adds or drops against the map it held, which the restore step lists (19.10); a failed render, test or reload keeps the prior map and is reported; the dns edges' route probes confirm each reported version (§12.6), and an interface not current for every version over 20 min old is map-stale, left out of the dns edges' user-name answers (never all) and paged (19.8); rollback: the prior lb version | tlsedge; platform HTTPS |
| W2 | Per-address zones: `route_rate_limits` (warp/services/services.go:737) takes exact paths, for sockets' registration and Find, 12,000/min, burst 3,000 (§9.5); a new whole-service form covers evs (3,000/min, burst 1,000) and gkm (1,200/min); edges are exempt at 2,000 Finds/s each (§13.9); store operations share per network (§11.13), with no tier caps (owner decision 66) | evs, gkm, sockets |
| W3 | No per-service body limit: ≤ 8 MiB segments fit (§11.6) | evs |
| W4 | TCP 25 `tcp_stream_port_services`: the router interfaces, every lb interface but `rpt.bringyour.com`'s two, to mxedge's router; those two, on two hosts, to its platform listener (§15.4) | mxedge |
| W5 | The lb reads `tls/current/<name>`, swapped before `nginx -s reload`; drop `ssl_stapling` (warp/warpctl/config.go:1254) | platform names |
| W6 | Per service: Makefile, Dockerfile, lock entry (server/cli/RUNTIME-PACKAGES.md:3-18), run.sh line, source graph, rollout class | all |
| W7 | 8443, 8883 and 5671 join `tcp_stream_port_services` to tlsedge on every lb interface (owner decision 121); router rules follow stream ports, 25 included; 53 goes to the dns edges, outbound 25 only from smtpedge's addresses; Route 53's checks move from port 80 (warp/warpctl/dns_route53.go:46-48) to HTTPS with SNI, so a broken split drops platform answers | edges, dns, smtpedge |
| W8 | Hosts with sidecar routes log `$uri`, not `$request` (warp/warpctl/config.go:1270-1273; I-13) | api, evs, gkm, sockets, dns |
| W9 | `external_tcp_ports`: a TCP twin of `external_udp_ports`, with the same DNAT and router rules | dns edges |
| W10 | `recurd.dev` and `www.recurd.dev` join warpctl's `domains` and mmm's `expose_aliases` (vault/main/services.yml:3-10, :580-592); from RS1, mmm 301s them to https://ur.io/recurd under a W5 certificate, as www.bringyour.com (mmm/mmm/nginx/nginx.conf.j2:448-450; owner decision 15). `sidecar.ur.io`, §18.8's key origin, joins them the same way, served under a W5 certificate at the lb as an unproxied record, never through Cloudflare, which terminates https://ur.io (mmm/mmm/nginx/nginx.conf.j2:65-66): `warpctl dns` refuses it proxied, a new name starting unproxied today (warp/warpctl/dns_cloudflare.go:259-261); its values live in vault, an external edit (owner decision 211) | recurd.dev, sidecar.ur.io |
| W11 | warpctl dns, which derives only A and AAAA today (warp/warpctl/dns_route53.go:112-147), publishes `rpt.bringyour.com` (A and AAAA: W4's two interfaces; MX 10 itself) and `*._report._dmarc.rpt.bringyour.com` TXT "v=DMARC1" (§14.6) from M5, and from M9 the sending addresses' HELO names under bringyour.com (A; owner decision 124) | report host, smtpedge |

**dns edges (D-OPS-15; owner decisions 69, 71, 123).** ns1 and ns2 are two hosts at the site, each with one IPv4 and one IPv6 address on gateway-1's and gateway-2's Hurricane Electric (HE) blocks (vault/main/services.yml:82-104) and transparent interfaces on their own router ports, like fireside's (:449-464). They run only `dnsedge` (UDP 53 by `external_udp_ports`, TCP 53 by W9, no nginx), so §12.6's RRL sees resolvers, and are probed from the off-site VPN host (xops/main/ansible/inventory.yml:267-276).

### 19.6 The file cluster (X13)

**Decided by the owner** (Q-OPS-1, Q-OPS-10; owner decisions 2, 18, 20, 21, 94, 116, 136-140, 145): MinIO from the final upstream source, archived since 2026-04-25 (https://github.com/minio/minio), with PR #21653's conditional-write fix (§11.3), is the system of record (Redis holds only soft state, 19.7); `ServiceHost.Blobs` (§4) lets SeaweedFS or Ceph RGW replace MinIO, and §22's suite gates every build. D-OPS-20's build of that source lives in `urnetwork/minio`, a public fork and sibling checkout with its own `sidecar` branch, which keeps MinIO's AGPL source in one public place; the owner creates the GitHub repo before any push (owner decision 195). One site, no off-site copy: a segment cluster and one metadata cluster on 4 LAN hosts apart from edge-5, each with its own endpoint, credentials and unversioned bucket, since MinIO places a bucket's writes in pools by free space (cmd/erasure-server-pool.go:392-411, :637-656); the metadata tier grows only by whole clusters (19.9).

```text
cluster   drives                                     parity  objects
metadata  2 x Samsung PM9A3 1.92 TB M.2 per host:    EC:4    a placed repo's §11.8 repo/ head/ log/ pb/ hp/ idx/ slot/
          one 8-drive set, 15.4 TB raw, ~7.7 TB              pmap/ pidx/ spidx/ and its group's §10.6 gkm/ objects,
          usable (owner decisions 136-139)                   pb/'s batches also carrying staged versionless segments
                                                             from v1 (§11.7), and v1's drops/<repo>/_ (§11.13's drop
                                                             table and running job); the first cluster alone
                                                             also holds §11.8's place/, §7's proj/, projrows/ and
                                                             rev/, §10.6's per-sidecar gkm/ and §21.9's hold/
segment   16 x 16 TB HDD per host (1,024 TB raw):    EC:8    seg/, kind-5 (versionless) segments from v1 included, each
          four 16-drive sets, 4 drives per host,             purged a minute after its version's replacement (§11.13);
          ~512 TB usable                                     §11.13's pack/, holding records and log pages older than
                                                             24 h, at least 256 KiB a pack or 7 d old (owner decision
                                                             136), not a MinIO warm tier's small PUT per push; from
                                                             v1, drop jobs' dropscan/<repo>/<id>/<f>, each deleted 30
                                                             d after its job or dry run ends (§11.13)
```

- **Parity** ("2 replicas" as 50%, owner decision 116): ~310 TB logical on HDD at 70% fill and 15% overhead. Writes need N/2+1 drives (cmd/erasure-metadata.go:557-558), surviving a host plus 3 HDDs or 1 NVMe drive, and an object reads while N/2 of its shards remain: any acknowledged one survives a drive; one whose write missed at most a host's share of drives (4 HDDs, 2 NVMe), as one written while a host was down, survives a host; only one whose every shard exists, written missing no drive or healed since, survives two:

```text
state      entered when                                     left when
protected  every drive online, no heal pending              -
degraded   a drive or host offline, or a heal pending       a full heal of the cluster's bucket (mc admin heal
           (MRF or scanner)                                 --recursive; cmd/admin-router.go:175-177) ends with
                                                            every drive online
at_risk    degraded and a further drive or host fails,      the failure is repaired and a full heal ends
           or a host offline for more than 4 h (the RTO)
monitor derives each set's state every 30 s from MinIO's drive and heal status (admin API), as the gauge
urnetwork_filecluster_set_state{cluster,set,state}, with no ids; a drive's rebuild alone (days per 16 TB)
leaves its set degraded, not at_risk; MinIO's partial-write queue holds 100,000 entries and drops new ones
when full (cmd/mrf.go:39, :94-97), so only a full heal restores everything a long outage missed
```

- **Cost per usable TB** (owner decision 122, reviewed yearly; §20): the hosts, HDDs, PM9A3s and cold spare, depreciated monthly, with the site's power and rack, over ~512 TB usable; each next metadata cluster, with any hosts it adds, joins it.
- **Load** (an engineering estimate, owner decision 116; §11.13's mix; drive work by inference):

```text
                                       year one                    year two
networks: Community, Pro, Team         20,000, 2,000, 100          100,000, 10,000, 1,000
stored, of the quota bound             20 of 80 TB                 140 of 500 TB (the bound does not fit)
pushes, hints a second                 200, 600                    2,000, 6,000
  the team directory (§16.11)          from M6, ~36 pushes a member-day (~1.5% of its members' own): a 5,000-member
                                       Team ~4.5 a second at its working mean, 6.7 at peak, 5.8 of them on its one
                                       cards ref and 0.9 on writers' own streams and ur/index (in M6's entry form
                                       6.1 on the streams and 0.17 on the cards ref), ~0.005 DWPD (0.6% of the 0.8
                                       budget; ~1.1% in M6's entry form); readers' requests and bytes by §16.11's
                                       cost table; §22.8's directory row (D-TEST-17)
NVMe GET, PUT, LIST, DELETE a second   ~2,400, ~670, ~25, ~240     ~21,000, ~5,000, ~250, ~740
NVMe writes, busiest drive             ~8.5 MiB/s: 0.40 DWPD,      ~69 MiB/s: 3.3 DWPD and ~21,000 IOPS (25%) were
                                       ~2,800 IOPS (3%)            it one set at ~5 records a batch; 3.7-4.0 DWPD
                                                                   at the ~1-1.6 records a batch of a set near
                                                                   capacity, five sets' worth (19.9)
  with v1's search index (§11.14)      ~8.9 MiB/s: 0.42 DWPD       ~72 MiB/s on one set: 3.4 DWPD at ~5 records a
  at owner decision 172's cadence      (0.35 on 1 KiB blocks),     batch, 3.9-4.2 near capacity (3.1-3.4 on 1 KiB
                                       ~2,900 IOPS (3.4%)          blocks); ~21,900 IOPS (26%)
NVMe reads, busiest drive              ~2,650 IOPS (0.3%)          ~23,500 (2.9%) on one set: GET/s + 10 x LIST/s
                                                                   uncached, so reads are not metered (§11.13)
HDD PUT, GET a second                  ~40, ~160                   ~400, ~1,600
  v1's search index PUT, DELETE        ~2-7 each                   ~20-70 each: ~650-2,250 drive operations (§11.14)
HDD drive operations a second          ~3,200                      ~32,000, against owner decision 20's ~8,000-12,800
  v1's versionless files               ~3 PUTs and ~3 DELETEs a second (~100 drive operations) per TiB a day
                                       of 4 MiB-chunk churn, the search index's in its row above; staged content
                                       replaced before evacuation never reaches the HDDs; evacuation's sweep
                                       re-checks each candidate, the page cache answering for an absent one
  v1's drop jobs (§11.13)              at most one per segment cluster, reading <= 32 MB/s and deleting <= 10
                                       objects a second: <= ~400-450 drive operations a second (reads ~64,
                                       deletes ~320), paused while the cluster's exceed 50% of its capacity
                                       (hdd, below; D-OPS-21); on NVMe ~0.3 MB a drive for a 10-minute job
basis    a PUT writes an xl.meta to every drive of its set (cmd/erasure-object.go:1399-1404) and a GET asks every
         drive (:728-758): an HDD operation is 16 drive operations, owner decision 20's 500-800 small PUTs a second
         are ~8,000-12,800, so Y2 needs the page cache for most GETs (Q-OPS-2); about 25,600 of Y2's ~32,000 drive
         operations are GETs, which packing does not reduce, and its PUTs alone (400 x 16 = 6,400) fill §11.13's 50%
         admission line (4,000-6,400) before any GET, the index's ~650-2,250 or a purge, so by this model year two's
         HDD load needs the segment placement and added HDD drive operations before it arrives, PUTs alone reaching
         the low end's line at about 250 a second (19.9's hdd trigger; §22.8's hdd row measures it); a small NVMe
         create writes ~9 KiB on each drive and an overwrite ~14 KiB, since MinIO writes the old xl.meta again
         (§11.3), so drive writes bind before IOPS (owner decision 140)
```

**Metadata drives and write budget (owner decisions 136-140; D-OPS-19).**

```text
drives    8 x PM9A3 1.92 TB (MZ1L21T9HCLS) in the first cluster: PCIe 4.0 x4, ~800k random-read and ~85k
          random-write IOPS (4K), 1 DWPD, power-loss protection (owner decision 138); dedicated to MinIO with
          separate boot media; before use, a SMART check (percentage used, media errors, available spare, data
          units written) and nvme id-ns showing the 512 B LBA format in use, which every namespace keeps, since
          -b size=1024 needs sectors of at most 1 KiB; every set homogeneous, with 2-4 PM9A3 cold spares and no
          PM963 (owner decision 139)
staging   M2's staging cluster on the production hosts' PM9A3 set only (19.11); format 2 buys no staging
          drives: its write cost is computed from §22.8's M2 price table and T3's operation counts with the
          index on in every eligible repo, and confirmed on production after its freeze while format 2 is
          dark to customers, the write budget's measured-over-priced ratio within 10% (D-TEST-13;
          owner decision 174); a miss costs the next metadata cluster sooner (19.9; owner decision 145) or
          a later format change
hosts     M.2 22110 slots or x4 adapters (Gen4 preferred) within each host's PCIe lanes, with airflow so drives
          never throttle; 2 x 25 GbE, since the HDD tier streams ~4 GB/s a host; RAM enough that the HDD sets'
          xl.meta working set stays in the page cache by year two (owner decision 136)
mkfs      XFS: -i maxpct=25 (~938M inodes a drive; owner decision 136); -b size=1024 or 4096 from §22.8's run;
          -m reflink=0,rmapbt=0 unless §22.8's run shows no gain; 512 B inodes and the default log (today's
          drives take mkfs defaults: xops/main/ansible/MINIO-MIGRATION.md:181)
mount     noatime, as today (playbook-minio-clusters.yml:104), since the scanner and LISTs read every
          directory; logbsize=256k; no online discard; fstrim daily
MinIO     unversioned metadata bucket with no lifecycle, replication or notifications; scanner speed=slow;
          MINIO_API_DELETE_CLEANUP_INTERVAL from §22.8's trash row, run with v1's versionless purges at year
          two's rate (30 s if it helps, else the 5 min default); MINIO_FS_OSYNC off; objects carry content-type
          application/octet-stream and no user metadata
deadline  the store request deadline §10.6 and §11.8 cite is 10 s on both clusters: the Blobs client cancels a
          request with no response 10 s after its last byte (a response body then streams), or earlier at the
          request's own deadline: evs's fold and taskworker's copy writes 15 s after issuing the head read they
          rely on (§11.7's stale row), taskworker's marker collection DELETEs 50 ms before until_ms by its
          clock (§11.7's collect row), and from v1 a drop job's DELETEs 50 ms before its lease's until_ms
          (§11.13); since MinIO keeps no server-side request deadline (requests_deadline is deprecated:
          internal/config/api/api.go:81-84), every request but a streamed segment PUT also carries its
          deadline, its own or 10 s after it is issued, as x-ur-deadline-ms (Unix ms by the sender's clock),
          which the in-house build enforces (settle, below); a push with one timed-out round stays well inside
          the lb's 30 s proxy_read_timeout (warp/warpctl/config.go:1320), and §11.12's shred waits, 20 s
          before keys and 10 min before the stragglers' pass, each outlast 5 s windows plus the deadline
settle    a PUT or DELETE must take effect before every later request on its key or never, and never once the
          store took it, or would begin a drive commit of it, past its deadline; the deployed build gives
          neither: a cancel ends the handler's waits (internal/ioutil/ioutil.go:121-137;
          internal/grid/muxclient.go:118-133) and stops a PUT on the handler's own drives before their commit
          rename (cmd/xl-storage.go:2891-2896), but not on other hosts' drives, whose storage RPCs carry no
          cancel (cmd/storage-rest-server.go:708; internal/grid/handlers.go:294), nor a DELETE on any drive
          (cmd/storage-rest-server.go:366; cmd/xl-storage-disk-id-check.go:638-639), and the handler releases the
          object's lock, which GET, PUT and DELETE take (cmd/erasure-server-pool.go:939, :1137;
          cmd/erasure-object.go:1264, :1555), while those run on, so a later request can read the key, or pass
          its precondition, before the cancelled write lands; holding the lock until every drive answered or met
          the 30 s drive timeout (internal/config/drive/drive.go:36-41) is not enough either, since a commit
          stalled after its last check lands after that release; the in-house build (D-OPS-20) therefore, for a
          set of N drives, whose writes need N/2 + 1 and reads N/2 (5 and 4 of 8, 9 and 8 of 16; Parity, above):
          (1) refuses a request whose x-ur-deadline-ms has passed when it holds the key's lock; (2) sends each
          drive commit (data or metadata rename, delete, heal, revert) the version the coordinator read from that
          drive under the lock, or its absence, with the drive's stamp for the key (how many commits its process
          had applied when it last applied one to the key, kept in memory for 2 min, with a value drawn at the
          process's start), and a deadline fixed before that read: the request's, or, for a streamed segment PUT,
          a heal or a revert, 40 s after its last byte or its start; the drive host, holding its own lock on the
          key from that check through the commit rename, applies it only while the drive still holds that version
          and that stamp, so only if no commit was applied to the key there since the read, and its clock is
          before the deadline, else answers stale and changes nothing; a DELETE of a key the drive lacks counts
          as committed and moves the stamp; (3) releases the key's lock once N/2 + 1 drives have committed the
          write (success; a later commit of it only adds a copy), or, once no more of its commits can begin
          (every drive answered, or its deadline passed), reverting every committed drive to its previous
          xl.meta, or a DELETE's copy in .minio.sys/settle/<id>-<hash of the key>/, ciphertext and xl.meta, which
          the settle sweep keeps at least 2 min and while the key is held, its interval checked to stay inside
          §11.12's 10 min stragglers' pass (§2.8 evs-10), each version's xl.meta naming its write by
          x-minio-internal-settle-id, the key lock's random id, by (2)'s check, as the deployed build undoes a
          write short of quorum on every drive that took it (cmd/erasure-object.go:1059-1079), once the drives
          that may still hold it, committed and not yet reverted or still committing, number under N/2, so that
          write can never be read and the version before it loses only the drives the write stalled on or could
          not revert; a DELETE, which leaves a drive in the one state every DELETE leaves, releases its key only
          once no drive may still hold it, each commit of it having answered and each that landed been reverted,
          and is never reverted after its release; until then the key is held: requests on it wait, then fail
          503; (4) keeps a dead coordinator's write locks, none expiring on a missed refresh, until a settler on
          another host, past the request's deadline, reads each drive's version for the key, asks its host
          whether a commit of the request still runs and settles by (3), a host that does not answer counting as
          still committing; (5) serves a drive from a restarted process only once the old one has exited, by an
          exclusive flock on the drive; (6) heals no version that fewer than N/2 drives hold onto others,
          removing it as dangling; a DELETE carrying x-ur-if-unmodified-ms is refused 412, under the key's lock
          and with nothing sent to a drive, when the object it finds was stored a second or more after that time,
          and a missing key answers 204 as upstream's does; orphan GC, the nightly pass's container deletes and
          the sweep send it, which is how GC deletes only the object it listed (§11.13; owner decisions 203,
          225); so one drive or host failing holds a key at most for a revert's round trip, and a key waits
          longer only while a PUT lacking N/2 + 1 drives could still reach N/2, or a DELETE lacking them has a
          commit unanswered, with a host among those drives unreachable, until that host answers or its drives
          are replaced (19.10, 19.17); §22.9's suite checks it (FS-114) per build, upgrade and cluster, reporting
          the lag from a cancel to a write's last drive answer, which no margin relies on, since a marker's
          collection DELETE (owner decision 148) and, from v1, the versionless purge's, the marker collection's
          kind-5 and slot DELETEs (§11.7, §11.13) and a drop job's (§11.13) are unconditional; on a cluster whose
          build has not passed it, taskworker opens no collection window, orphan GC deletes nothing and v1's
          purge and drop jobs delete nothing, keeping markers and candidates
list      a LIST is answered only when it is whole: the build asks every online drive of each set it reads,
          whatever list_quorum says, and answers 503 when three or more of a set's drives are offline, or one is
          while another heals, since a key on N/2 + 1 drives can then fall under the half of the asked drives a
          listing needs (§11.3); evacuation's horizon and every deletion decided on a LIST of pidx/ (§11.13) rest
          on it, so in the at_risk state on a metadata set (Parity, above), and with one host down on a 16-drive
          segment set, evacuation, the nightly pass and uncached pidx/ lookups wait (owner decision 226)
clocks    chrony on every host running evs, gkm, taskworker, a Redis master or MinIO, by whose clocks
          §11.10's push sequence restarts and the settle row's deadlines hold (edge-6 and edge-5:
          xops/main/ansible/REDIS.md:3-6; none synced today, 19.3), serving NTP only to its services network,
          which each container reaches at warp's --add-host name (warp/warpctl/run.go:2102); every second each
          of those processes, and each Redis host's exporter, queries it, taking as its offset the measured
          offset plus the reply's root distance (RFC 5905 §4's maximum error), since chronyd serves its
          estimate of true time and slews the system clock toward it
          (https://chrony-project.org/doc/4.6/chronyc.html, tracking), unknown after 3 s without a reply or
          with an unsynchronised one (leap 3, stratum 16); while it is unknown or over 50 ms, §11.8's evs
          answers pushes 503, opens no batch and issues no v1 purge DELETE (§11.13), taskworker raises no
          evacuation fence
          and GC deletes nothing, and a MinIO host takes no request carrying a deadline and begins no
          drive commit, the work waiting, since §11.8 bounds every clock that writes fence_ms or a refusal
          record's until, and the settle row every clock that sets or checks a deadline; each exports it,
          monitor warning past 25 ms
counters  each storage host exports, every 5 s, each metadata drive's /sys/block/<dev>/stat sectors written and
          writes completed (fields 7, 5) and each HDD's reads and writes completed (fields 1, 5), and hourly
          its NVMe SMART log (data units written, percentage used, available spare, media errors), as
          fluent-bit's diskstats input does on planetoid
          (xops/main/ansible/host_files/planetoid/fluent-bit/fluent-bit.conf:20); MinIO's per-drive
          writes_kb_per_sec cross-checks them
budget    per metadata cluster, a taskworker loop holding a Redis lease drains §11.13's write budget only by the
          busiest drive's measured bytes, P0's included, skipping a drive under heal; a write moves at least one
          512 B sector, so the refill also caps the other classes' sustained writes at ~33,000 a second, 39% of
          85k rated IOPS (§11.13), and writes completed feed monitor and §22.8, not the bucket; every 5 s it
          publishes {nvb_<set>} (15 s ttl: calibration, the bucket B, floored at zero, §11.13's allowance T as
          A_U for unfunded P2 and A1 for P1, and the funded P2 allowance A2 from the wallet W), splitting each
          across processes by what each evs, gkm, api and taskworker process reports in it every 5 s (§11.13's
          reports row), P0's bytes by kind among them, and counts by those kinds P0's forgiven excess, its bytes
          past what B held; it keeps B, W and the counter readings they were taken at in a state key rewritten
          every 5 s with a 48 h ttl, so a loop that takes the lease resumes them exactly, and with none (Redis
          lost) starts W and B at zero, which is conservative; heals, MRF and scanner writes are in the counters
hdd       per segment cluster, a taskworker loop holding a Redis lease publishes every 5 s, in {nvb_<cluster>}
          (15 s ttl), its drive operations a second (its HDDs' reads and writes completed over the last 5 s,
          heals and the scanner included) and its capacity, the rate §22.8's M3 hdd run achieved on it by the
          same counters; §11.13's per-network HDD admission, a drop job's pause (D-OPS-21), §22.8's M10 hdd
          run (19.11) and Q-OPS-2's switch each act past 50% of that capacity, with no network or repo id;
          admission refusals count in 19.8's urnetwork_evs_hdd_admission_refused_total{cluster}
wear      at 0.40 DWPD a PM9A3's rated 5-year endurance lasts ~12 years; at the budget's 0.8 DWPD, ~6; P0 work
          past the refill writes past the budget while it lasts (owner decision 186): §11.21's stress,
          ~1.66 DWPD, spends ~1.66 days of the 1 DWPD rating a day; P0's excess past what the bucket holds is
          forgiven, not repaid (owner decision 190; §11.13), so a drive's lifetime writes pass the refill's only
          by the bucket's depth and every storm's forgiven excess, which 19.8 counts and shows against the
          rating: a 6-hour storm at that stress adds ~0.23 drive-writes, and the ~420 that five years at the
          refill (0.768 DWPD) leave under the 1 DWPD rating cover ~1,800 such storms; 19.8 projects the rating's
          end from SMART's percentage used
heal      a 16 TB HDD in ~1.5-4 days; an NVMe drive by object count, hours to ~a day (owner decision 136);
          §22.8's M3 drill measures both; a drive absent at a DELETE returns still holding the object, which
          MinIO removes as dangling once more of its set's drives than its parity lack its xl.meta and every
          drive answers (cmd/erasure-healing.go:1029-1031, :1046-1049; cmd/erasure-object.go:914-917), and
          §22.9's suite checks per build that no heal resurrects a deleted object
```

**Durability (D-OPS-14; owner decisions 89, 90, 94, 116, 143).** A write returns only once N/2+1 drives of its set hold it, and nothing waits for a copy. A drive's failure therefore loses nothing acknowledged: RPO 0, inside owner decision 89's 5 min and 1 h targets, which cover drives and hosts only (owner decision 94). A host's keeps RPO 0 for objects whose write missed at most a host's share of drives, and a second host's only for objects whose every shard exists: written while their set was protected and missing no drive, or healed since (the parity rule above). Site loss is total for what no device or dump holds (19.10).

```text
failure                                  RPO                                       RTO
a drive, or one host                     0; for a host, only objects whose write   0; rebuilds run in the background
                                         missed at most a host's share of drives:
                                         any other can be unreadable until its
                                         drives return, and is lost if they are
                                         destroyed
a second host, or a host plus 4 HDDs     0 for objects whose every shard exists    reads continue; writes get 503
  or 2 NVMe drives of one set            (written while the set was protected      until 19.10's cold spare returns
                                         and missing no drive, or healed since);   a host: <= 4 h after the page
                                         any other can be unreadable until a       (19.8)
                                         host's drives return, and is lost if
                                         they are destroyed
past half a set, or the site             every object no device holds (owner       no target (owner decision 94):
                                         decisions 90, 94)                         new hardware, then 19.10
the Postgres primary                     sidecar rows, and the network, user and   no target: the platform's restore
                                         client rows they name, since the sidecar  (19.3), then 19.10's reconcile; new
                                         dump: <= 24 h plus its <= 20 min run      evs and gkm sessions stop within
                                         while each nightly run completes, a day   15 min until then (19.17)
                                         more per skipped or aborted run
                                         (D-OPS-18); other rows since the main
                                         dump (19.3)
the site, for Postgres rows              the same rows <= 26 h (planetoid's        with the re-seed
                                         copy), on the same condition; other rows
                                         since the main dump
```

No operator copy holds slots or wraps, so a committed erasure is immediate at the cluster (owner decision 90). Owner devices' sealed mirrors hold slots like any repo object, apply each erasure on its hint, and re-seed by 19.10. Repos no device mirrors, and deposits no depositor spools, die with the site (D-EVS-17, §16.8, §2.18). Sidecar tables leave the main dumps for D-OPS-18's daily dump (D-TRUST-7), and the Redis bundles leave out 19.7's families (D-OPS-16).

**Sidecar dump (D-OPS-18).**

```text
what     the tables 19.7's groups create (columns they add to existing tables stay in the main dump), minus
         every table whose §2.8 ttl is <= 7 d, the list following that column (today tls_connection_record,
         mail_connection_record, dns_zone_journal, network_acl_ack, network_scim_change, service_debit_journal,
         service_usage_batch and admin_token_use), which no dump holds, so their published ttls hold in backups
         too; the main dump's exclude list names every table the groups create; beside them, the network,
         network_user (with its network_user_auth_* login rows) and network_client rows those tables name,
         each named network's admin user included, so a network, member or sidecar newer than the main dump
         keeps its id and rows (19.10)
how      pg_dump -Fd -j4 of those tables, and COPY of the named rows in its exported snapshot (pg_dump
         --snapshot), from the primary as backup_dump (pg_read_all_data), every night, whatever the main dump
         does, since 19.10's postgres step reconciles the two; its snapshot pins the
         xmin horizon for minutes, not the 11-12 h a full dump of the primary would, which is why the main
         dump now reads a copy (xops/main/ansible/host_files/by-us-fmt-5-edge-6/db-archive/README.md); by
         inference ~10 min at year two (~130M network_service_usage rows at that README's ~278k rows/s per
         worker); it starts only while pgbackup-slot-guard's conditions are clear (disk, CPU, lag) and stops
         past 20 min; packed, gpg-encrypted and published like the main dump's generations, its sha256 and
         its exported snapshot's time beside it, as the main dump's backup-point.txt gives its copy's end
         (host_files/by-us-fmt-5-edge-6/db-archive/README.md:90-92, :122-124)
when     daily from MG0's Gn-out (M0), as MG0 creates the first table (network_client_owner; 19.11), starting
         at 02:30 UTC and ending by 02:50, at least 1 h before planetoid's daily pull, whose timer, 04:00 in
         planetoid's local time today (xops/main/ansible/MINIO-MIGRATION.md:553-554), is pinned to 04:00 UTC
         and takes pg-sidecar first, before the 1.2-1.4 TB main generations (inventory.yml:188) and the Redis
         bundles it pulls in that order today (host_files/planetoid/backup/remote-backup-archive.sh:1207-1237),
         so the site RPO and the 26 h check below hold whenever each run completes
where    edge-6's archive pool; planetoid pulls it into its own pg-sidecar stream
keep     the newest 14 generations at each place, and no weekly or monthly ones (D-TRUST-7)
copies   the primary's physical copies are backups too (D-TRUST-7): edge-6's pg-base, which the main dump
         reads, is refreshed by that dump's timer within 7 d or destroyed, the next run then making a full
         copy, and edge-5's main-pgbase-<date> by its timer or destruction within 7 d (19.3);
         tls_connection_record's and mail_connection_record's partitions are UNLOGGED, so pg_basebackup
         copies none of the 24 h edge records, which a primary crash loses, as a restore already does; every
         other table sits in a physical copy at most 7 d (ops-2; owner decision 210)
check    planetoid verifies each generation's sha256; monitor warns when the newest verified off-site
         generation is older than 26 h; each Gn-out from M3 restores the newest one into a scratch instance
RPO      these rows <= 24 h plus the run (<= 20 min) at a primary's loss (edge-6 intact), <= 26 h at the
         site's, while each nightly run completes, whatever the main dump's age; a skipped or aborted run adds
         a day and warns (19.8)
```

### 19.7 PostgreSQL and Redis

Each migration group is named for the milestone whose code first reads it ungated, code built dark against it earlier staying gated off (D-OPS-6); evs and gkm keep no rows (owner decision 2):

```text
group   tables, by owning section
MG0     §7's P0: network_client_owner; altered account_api_key and auth_code
MG1     §5: sidecar_identity, sidecar_identity_binding; §7: network_auth_key, network_admin_event,
        admin_token_use (ur-cli's admin tokens); §18: network_client_lease; §20: network_sidecar_limit
MG2     §8: network_acl_head, network_acl_ack, network_client.acl_subject_client_id;
        §20: network_quota_state, network_service_usage, service_debit_journal, service_usage_batch
MG3-4   none
MG5     §12: dns_*, network_dns_*; §13: network_tls_*, tls_connection_*; §16: approval_use (§12.8's DNS
        gate); §21's seven
MG6     §7's Team tables; §8: network_acl_share; §17: network_bridge_share;
        §20: transfer_balance.tier, transfer_balance's team_credit index (built concurrently; pending
        from M4's dark comparator, behind escrow_draw_order, 19.11), stripe_meter_report,
        team_subscription (owner decision 199)
MG7     §15: mail_network, mail_host_key, mail_direct_mx, mail_connection_record
MG8     §7: network_client_owner.forward_only (owner decision 197); §18: sidecar_push_token
MG9     §14: smtp_*
```

**Migrations (D-OPS-6).** Versions continue after main's last, 926 on 2026-11-04 (server/db_migrations.go:235); the catalog keys identities by slice position and aliases the slice in an `init` (server/db_migration_catalog.go:27-42), so a registered group never changes:

```text
pending   a group is registered in the migrations slice only by its own milestone's Gn-out commit (owner
          decision 118); until then it lives in server/db_migrations_sidecar_pending.go under build tag
          sidecar_pending, appended in the slice's initializer, since an init-time append would escape the
          catalog's alias
builds    local, T3 and canary set the tag; release legs never do; the pending file's initializer panics unless
          server.Env() is local or canary or the binary is a test (testing.Testing()), as evaluation credential
          overrides refuse anything but WARP_ENV=local (server/env.go:1148-1155)
promote   a Gn-out moves only its own group from the pending file into the slice, in order; canary databases
          rebuild after each merge
code      code reading a pending group's tables stays gated off (D-OPS-10) and unready without them (19.4)
```

- Groups add tables, nullable columns and new-table indexes; existing tables get `newOnlineSqlMigration` indexes (server/db_migrations.go:50-52). `acl_subject_client_id` turns NOT NULL through a validated `NOT VALID` check (precedent :5961-5969).
- Only `smtp_send` (daily, PK (send_day, send_id)), `tls_connection_record` and `mail_connection_record` (hourly) are partitioned, the last two's partitions UNLOGGED, so no physical copy holds them (19.6's copies row; owner decision 210). Cleanups wait for every database job (connect/CODESTYLE.md:88). Pools per process (config/main/db.yml): dns and smtpedge 4, others 2; locks stay transaction-scoped.

**Redis (D-OPS-7).** Tags: `{scp_}`, `{wake_}` (§6, 19.4), `{wakeq_}`, `{tokgen_}` (§18.7), `{dpop_}` (§7), `{acl_}` (§8.9's `{acl_<networkId>}v`; §7.9's `{acl_<networkId>}e`, the verified projection cache, which only api writes (owner decision 136), and `{acl_<networkId>}q`, the append limits' 25 h counter), `{sg_}`, `{sn_}`, `{sc_}`, `{svc_}` (§9), `{gka_}` (§10), `{evsq_}`, `{evsl_}`, `{evsh_}`, `{evsc_}`, v1's `{evsd_}`, `{nvb_}` (§11), `{evsn_}` (§20.7's nightly count; owner decision 198), `{dns}` (§12), `{tes_}`, `{tcb_}` (§13), `{smq_}`, `{smg_}`, `{smd_}` (§14), `{mxr_}`, `{mxc_}` (§15), `{vhk}` (§13.9, §15.4: the daily visitor-hash keys, 25 h), `{sq_}` (§20). Every key is rebuildable: it projects Postgres or a cluster (the head and projection caches for 10 min, certs' budget from `network_tls_cert`, tokens per slot by taskworker's sentinel pass, drop hints by the nightly LIST of `drops/` within a day), returns by re-registration (leases, acks), restarts above its old values (the push sequence) or expires within 48 h (the write budget's allowance in 15 s, and its saved bucket, wallet and counter readings 48 h after the loop's last write, a lost one restarting the bucket and the wallet at zero, which is conservative); switches and halts reach Postgres first and reload within 60 s. The hint listener follows slot owners (`RunRedisShardSubscription`); caps (config/main/redis.yml): sockets 64, evs 32, others 16.

### 19.8 Observability and SLOs

- **Metrics** (`urnetwork_<svc>_*`, server/grafana.go:1-21) keep 90 days, logs 7 (config/main/grafana.yml:31-38). Labels are route template, result, code, cluster and tier; logs are scrubbed (server/scrub.go:3-21) and carry opaque ids only (I-13, W8).
- **Versionless (v1):** `urnetwork_evs_versionless_purged_bytes_total{by="commit"|"sweep"}`, `urnetwork_evs_versionless_staged_total{outcome="dropped"|"written"}`, `urnetwork_evs_versionless_purge_queue` and `urnetwork_evs_versionless_sweep_deletes_total{result="deleted"|"absent"}`, told apart by a HEAD before each sweep DELETE, since MinIO answers a DELETE 204 either way (cmd/object-handlers.go:2678-2691); the committing processes should delete nearly all, so the sweep's `deleted` share warns past 1% in a day (below).
- **Drop history (v1):** `urnetwork_evs_drop_jobs{state}`, `urnetwork_evs_drop_scan_bytes_total{pass="preview"|"mark"|"verify"}`, `urnetwork_evs_drop_deletes_total{result="deleted"|"absent"|"packed"|"held"|"young"}` and `urnetwork_evs_drop_freed_bytes_total`; a job ending refused {verify} or {mismatch} pages as a storage-integrity alert. **HDD share:** `urnetwork_evs_hdd_admission_refused_total{cluster}` (19.6's hdd row). None carries a network or repo label.
- **Write budget (§11.13):** per metadata cluster, with no network or repo label: `urnetwork_evs_budget_issued_bytes_total{cluster,class,kind}` (class p0, p1, p2_funded or p2_unfunded; kind, for P0 only, revocation, log, lifecycle, shred, erasure, remove or rotation); `urnetwork_evs_budget_p0_refill_ratio{cluster}`, P0's measured bytes over the last hour against that hour's refill, the P0 page's input (below); `urnetwork_evs_budget_bucket_bytes{cluster}`, B, never below zero, with `urnetwork_evs_budget_p0_forgiven_bytes_total{cluster,kind}`, P0's forgiven excess, its bytes past what B held, by P0's kinds, shown in drive-writes against the ~420 that five years at the refill leave under the drives' rating (19.6's wear row; owner decision 190); `urnetwork_evs_budget_liability_bytes{cluster,class}` and `urnetwork_evs_budget_drain_seconds{cluster,class}` at the last hour's rate, the wallet and the funded and unfunded backlogs among them; the busiest drive's `urnetwork_filecluster_drive_dwpd{cluster,window}` over 24 h, 7 d and 30 d and `urnetwork_filecluster_drive_rating_days{cluster}`, the days until SMART's percentage used reaches 100 at the 30-day rate; `urnetwork_evs_path_epoch_moves_left{cluster}`, `urnetwork_evs_path_epoch_sources{cluster,n}`, `urnetwork_evs_path_epoch_deferred{cluster}` and `urnetwork_evs_path_epoch_sources_full_total{cluster}` (§11.6); and each cluster's `urnetwork_filecluster_exhaustion_days{cluster,resource}` (raw, inodes, wear, copy), with the first cluster's `urnetwork_filecluster_control_plane_bytes` (19.9's cohorts row).

**Alerts and on-call (owner decisions 95, 134, 143).** One rota reviews §21's machine actions in business hours; they act at once and hold until reviewed. From M3, a pager service reaches the same rota out of hours for the page classes below; from M5 it also carries §21.8's registrar, registry and law-enforcement notices. 24/7 review starts in v1.

```text
page class (any hour)                            from   acknowledge   then
a set at_risk (19.6), or a cluster refusing      M3     30 min        the cold spare within 1 h of the page
  writes                                                              (19.10); restored within 4 h
the Postgres primary down (the token exchange    M3     30 min        repair or restore (19.10)
  stops)
2% of a 30-day budget burned in 1 h              M3     30 min        roll back or switch off (D-OPS-10)
P0 past the refill: a metadata cluster's P0      M3     30 min        19.10's P0 row: capacity, placement, the
  bytes over the last hour above that hour's                          networks; P0 is never paced or refused
  refill (§11.13; owner decision 186)
both dns edges failing probes, or the canary     M5     30 min        §12.6's runbook
  signature failing
an interface's split probe failing (W1)          M5     30 min        that interface's prior lb version
an interface map-stale, or a custom host         M6     30 min        that interface's lbmap and reload logs;
  pending past 20 min (W1)                                            else drain it (W1), naming its hosts
registrar, registry, law-enforcement notices     M5     30 min        §21.8: removal orders and registrar or
                                                                      registry notices handled within 1 h by
                                                                      the rota; production orders go to
                                                                      counsel's out-of-hours contact
a drop job refused {verify} or {mismatch}        M10    30 min        19.10's drop rows: on {verify},
  (storage integrity)                                                 format2's drop to observe (19.11)
a file-cluster key held over 1 min by a write    M3     30 min        19.10's held-key row: the host back, or
  that cannot settle (19.6's settle row)                              its drives replaced
rota       two people on one pager service; the second is paged when the first has not acknowledged in 30 min;
           registrar, registry and law-enforcement notices page both at once
business   a metadata drive's 7-day mean over 0.75 DWPD pages in business hours only, since the write budget
           holds 0.8 but for P0's excess, which pages at once (above; 19.10), as does a cluster whose projected
           exhaustion (19.9's cohorts row) falls within its move tool's lead time, or which reaches its cohort
           limit, and as does a drive projected, at its 30-day rate, to spend its rated endurance before five
           years of service
warn       each service's, every cluster's and the push sender's failures; §14's downgrade, breaker and
           fail-open cases; a set degraded (19.6); shedding and HDD admission refusals (§11.13), and HDD
           refusals past 0.1% of a day's uploads; P0 over an hour past its warn line, which D-TEST-11 sets at
           four times the hourly share its run measures, at most half the refill; the write budget's bucket
           empty, P0's excess forgiven, for 5 minutes, or a busiest drive's last 24 h past 0.8 DWPD; a
           path-epoch copy drain past 24 h, a source standing 48 h or EPOCH_SOURCES_FULL lasting 10 min
           (§11.6); D-OPS-17's space, inode and wear marks; a metadata drive's 7-day mean over 0.5 DWPD; the
           write budget's bucket under 25%; SMART media errors or available spare under 10%; a multi-pool
           metadata cluster; a sidecar dump run skipped or aborted, or the newest verified off-site generation
           older than 26 h; a process's or Redis host's clock offset past 25 ms or unknown (19.6); v1's
           versionless sweep's `deleted` share past 1% in a day; v1's drop job executing an hour with no scan
           or delete progress while its cluster is under 50% of capacity and no candidate is young (19.10); 10%
           of a 30-day budget burned in 6 h
```

**SLOs (D-OPS-9),** over 30 days, at all hours (owner decision 143):

```text
evs               99.9% non-5xx; head -> hint p99 <= 2 s
gkm               99.9%; commit p99 <= 300 ms
sockets           99.95%; Find p99 <= 50 ms
tlsedge           99.9% of connections reach a listener; warm setup p95 <= +300 ms
mxedge, smtpedge  99.9% of splices, 99.5% of preambles
dns               write -> served at both NS p99 <= 60 s (R-DNS-7)
certs             renewed with 1/3 of their life left
wakes             p99 <= 2 s after their trigger
projections       per §8.9
file cluster      99.95%
```

### 19.9 Capacity and cost drivers

The metadata set, inferred from 19.6, §10.6 and §11.13:

```text
per drive, 24 h packing      year one                 year two                 basis
idx/ entries                 ~100M, ~520 GB           ~600M, ~3.1 TB           a live path each, plus a removed-entry
                                                                               marker per recent removal until the fold
                                                                               horizon passes it (owner decision 148;
                                                                               §11.13's object budget): 2.1 inodes, one
                                                                               block (owner decision 136's 150-850M
                                                                               inodes in year one)
pb/ batches                  ~18M, ~90 GB             ~110-180M, ~0.56-0.9 TB  25-26 h of pushes (§11.13), ~1 record a
                                                                               batch in year one and ~1-1.6 in year
                                                                               two: each evs process keeps one stream
                                                                               per cluster (§11.8), so at ~8 processes a
                                                                               stream carries ~25-60 pushes/s; from v1
                                                                               the search index's staged heads add
                                                                               ~12-20 GB a drive in year one and
                                                                               ~75-200 GB at year two (§11.14)
hp/ parcels                  ~0.6M, ~20 GB            ~6M, ~180 GB             small repos' history, at most 7 d after
                                                                               its commit plus an hour (§11.13), at 10
                                                                               records a parcel (§22.8 measures it)
slot/                        ~10M, ~50 GB             ~60M, ~310 GB            record-class and deposit pushes; from v1
                                                                               also one per versionless path in a
                                                                               slot-keyed repo, deleted with it
gkm/                         ~15M, ~70 GB             ~90M, ~450 GB            epoch/: 30 d, the newest per group kept:
                                                                               ~1.2-1.9 MB a 10-leaf group, ~26 MB a
                                                                               1,000-leaf one (§10.6); gen/: one object
                                                                               per rotation, kept for the repo's life
                                                                               (D-KEYS-20), unpacked until §10.16's gen
                                                                               packs (256 generations an object) start
                                                                               at the trigger below, from removals,
                                                                               reaps of agents no live Delegation covers
                                                                               and holder expiries (grants' expires,
                                                                               agents' and Delegations' not_after; one
                                                                               rotation covers every expiry due, §10.5),
                                                                               ~0.5 KB per GenRotate without deposits and
                                                                               ~1.7 KB with (§10.5's reap rule,
                                                                               D-KEYS-16); these counts hold only well
                                                                               under the ~5 and ~50 rotations/s upper
                                                                               bound, at which a year would add ~160M and
                                                                               ~1.6B objects, so §22.8's M2 count, 1 h
                                                                               requested grants included, enters the
                                                                               triggers' projection; a config or
                                                                               directory rotation adds a ~1.3 KB wrap
                                                                               per member device past the first 1,000
                                                                               (owner decisions 144, 182); directory
                                                                               rotations, which follow nearly every
                                                                               shrink of a Team's sidecars since the
                                                                               directory's writers push often, enter the
                                                                               triggers' projection beside config ones,
                                                                               each staging up to ~6,000 objects
                                                                               (~7.5 MB, ~50 MiB a drive) at §20.4's
                                                                               5,000 Team admissions, RecoveryWraps
                                                                               included, and a wrap per leaf more if its
                                                                               rotator is wrapped (§10.15)
head/, log/, proj/, the rest ~2.5M, ~16 GB            ~15M, ~100 GB            place/, projrows/, rev/, hold/ included
search index (§11.14)        ~2M, ~11 GB              ~11M, ~57 GB             v1: idx/ entries of the index's files
                                                                               (~20 a root); their staged heads are in
                                                                               pb/'s row
one PM9A3 set, 4 KiB blocks  ~40% raw, ~32% inodes    ~244-261% raw,           1 KiB blocks: ~31% and ~200-210% raw; a
                                                      ~194-208% inodes         small object takes ~44 KiB raw, a block on
                                                                               each of 8 drives plus inodes, and year one
                                                                               fits at 20-75% raw (owner decisions 136,
                                                                               138)
drive writes                 0.40 DWPD (0.31 on 1     3.7-4.0 DWPD (2.8-3.0)   §11.13's model until §22.8 measures it
                             KiB blocks)              on one set
  with v1's search index     0.42 DWPD (0.35)         3.9-4.2 DWPD (3.1-3.4)   §11.13's costs at owner decision 172's
                                                                               cadence: one companion push a minute on
                                                                               1 KiB blocks (in parentheses), one every
                                                                               5 minutes on 4 KiB, about +2 KiB a push
                                                                               there instead of +6
path-epoch copies            each REMOVE generation brings a path epoch (§11.6), at once for a member's removal or a
                             compromise, else batched to at most one per repo a day, whose copy moves each live idx/
                             entry at 3 operations, a create and a delete writing ~12.5 KiB a drive on 4 KiB blocks: ~13
                             GB for a 1M-file ref, ~17 h at 50 a second; a cluster's copies share 250 operations a
                             second, 21.6M a day, so its copy load, the live entries of each rotating ref times that
                             ref's epochs a day times 3, is planned under half of that, never by counting rotations
                             alone; past it batched epochs wait while two sources stand (§11.6), and the cohorts row
                             counts it; §22.8's fixture of 1 h requested grants on large repos counts rotations, full
                             checkpoints, copy operations and live entries per rotating ref a day for the triggers'
                             projection
sets needed in year two      endurance 4.7-5 (3.6-3.8 on 1 KiB), space at 50% 4.9-5.2 (~4-4.2), inodes at 40% 4.9-5.2:
                             five, six to keep every set under the inode trigger; capacity binds first; a set near
                             capacity holds ~1-1.6 records a batch and sustains ~400-450 pushes/s (~530-600 on 1 KiB),
                             not owner decision 145's ~490-650, which assumed batches shared across the whole load
                             (§11.13); §22.8's records per batch per cluster size the order; with v1's search index at
                             owner decision 172's cadence (§11.14), endurance 4.9-5.3 (4.0-4.3 on 1 KiB), space
                             ~5.0-5.4 and inodes ~5.0-5.3: five to six sets on either block size, capacity still
                             binding first, a set near capacity sustaining ~385-430 pushes/s (~475-535); the sizing
                             bounds wear only at the admitted mix: P0 work past the refill writes past it on the
                             cluster it hits, whatever the set count (§11.13; owner decision 186)
triggers                     the next metadata cluster at 50% raw, 40% inodes or a 0.5 DWPD 7-day mean on the
                             busiest drive (owner decision 136), or when monitor's 30-day trend projects one within
                             that cluster's lead time: at 19.6's estimate, at about 1.25x year one, or about 1.2x
                             with v1's search index on 4 KiB blocks; §10.16's gen packs on a cluster once that trend
                             puts its gen/ objects past 10% of its objects within the same lead time, which the
                             rotation upper bound would reach in weeks
costs                        NVMe drive writes and objects, HDD bytes, IPv4, the cold spare
```

`push` turns on in main only after §22.8's test at 2× Y2 hint rates.

**Growth (owner decision 145).**

```text
form      each next metadata cluster is its own MinIO deployment and bucket, with its own endpoint and
          credentials: one homogeneous 8-drive set at EC:4 in one pool (owner decisions 116, 139), its model
          chosen when its trigger fires; one sustains ~400-450 pushes/s (~530-600 on 1 KiB blocks) at the
          ~1-1.6 records a batch of a set near capacity, so year two needs five to six, sized from §22.8's
          records per batch per cluster
hosts     the second takes 2 drives per storage host in their free bays (owner decision 136); later ones go on
          new hosts at the site, 2 drives on each of 4, since five or six clusters on the storage hosts would
          need 10-12 M.2 drives and 40-48 PCIe lanes a host beside 2 x 25 GbE and the HDD HBA, all in one
          failure domain; a host takes another cluster's pair only with its slots or x4 adapters, lanes and
          airflow counted
place     sidecar.yml's place_new (19.11) names the cluster that takes new repos, the first when absent; ops
          sets it to a next cluster once that cluster passes §22's suite, and evs refuses creates (503) while it
          names a cluster evs cannot reach; §11.8's create writes place/<repo_id> on the first cluster with
          If-None-Match, which decides a creation race; evs and gkm resolve it once and cache it for the
          process's life, so a repo, its gkm group and all their objects keep one cluster and one commit
          point, which changes only with a later move tool
first     place/, proj/, projrows/, rev/, hold/ and per-sidecar gkm/ objects stay on the first cluster, so its
          share keeps growing with networks and sidecars after it stops taking repos, and every cluster's writes
          depend on it (rev/ checks, cold placement resolves; 19.10); their revocation writes are §11.13's P0
          and the rest queue per network, so its own cohort's load sheds its own heaviest networks first, and
          monitor tracks that share apart (cohorts, below)
cohorts   a cluster's repos (its cohort) keep growing after place_new moves on, and only a move tool (19.18)
          moves them; monitor tracks per cluster its raw space, inodes, busiest drive's 7-day DWPD and copy load
          (path-epoch copies, above), each with its 30-day slope, the first cluster's control-plane share apart,
          and projects each cluster's exhaustion, the first date its own growth reaches 80% raw, 70% inodes, a
          0.75 DWPD 7-day mean or its copy capacity; the move tool is built to land before the earliest such
          date, never by the estate's free space, the first cluster's repos its first move; until it exists, a
          cluster at 80% raw or 70% inodes takes only what §20.7's storage limit accepts: evs refuses
          payload-adding pushes and segment uploads for its repos with 507 CLUSTER_FULL and Retry-After, while
          deletion, erasure, shreds, CONSUME, BASE, drops and config and mailcfg pushes pass, and the rota is
          paged (19.8); FS-119 drills a saturating cohort beside a mostly empty cluster
pools     never on a metadata cluster: §22's conformance suite, run per build and per new cluster, refuses one
          with more than one pool (FS-63), and monitor warns on one
hdd       the segment cluster takes no pools either: a re-upload could pass If-None-Match in another pool and
          get a fresh receipt for a segment GC is deleting (§11.13; cmd/erasure-server-pool.go:637-656), so
          Q-OPS-2's HDD sets wait for §11.22's segment placement that keeps the receipt check and moves upload
          load, not only new repos; year two needs no added HDD space (19.6) but, by 19.6's model, added HDD
          drive operations, since its PUTs alone fill the 50% admission line, so the placement and the added
          capacity are ordered when §22.8's hdd row's admitted throughput, or monitor's 30-day trend of HDD
          drive operations, projects 50% of measured capacity within their lead time, and land before it;
          neither a higher line nor refused uploads count as fit
tests     §22: two creates of one id racing at place/, a retried create, a second cluster that never receives
          a placed repo's objects, FS-63's refusal
```

### 19.10 Failure modes and runbooks

```text
failure                    automatic behavior                                  operator
tlsedge, or the split on   §12.6's probe and W7's checks drop the interface     prior lb version; HE null-routes a flooded
  an interface                                                                  address
sockets, its Redis, or     streams continue; new edge and mail setups fail     restart; fail over
  mxedge                   (§9.8); senders retry for days
gkm                        reads, deposits and gated writes continue; joins    restart
                           and removals wait (§10 KF7)
evs killed with v1         evacuation's sweep deletes them within ~26 h        none
  purges queued            (§11.13; 19.8's sweep metric)
a dns edge, or a signing   resolvers retry the other NS; an edge keeps its      §12.6's runbook
  fault                    previous key set
Postgres primary           the token exchange stops, so evs and gkm refuse     repair, or restore the newest dumps, then
                           new sessions within 15 min; sockets and edges run   the reconcile steps below
                           from Redis
the push sender, APNs or   wakes stop; clients resync (§6.8)                   restart
  FCM
a host's clock or chronyd  while its offset is unknown or over 50 ms, evs      fix chrony's sources, or drain the host
                           there answers pushes 503, taskworker raises no
                           evacuation fence and GC deletes nothing, and
                           a storage host takes no request with a deadline
                           and begins no drive commit, its drives sitting out
                           writes (19.6, §11.8); a Redis host's offset only
                           warns
file cluster               19.6's tables; on saturation or an exhausted write  heal; on any return, a full heal (mc admin
                           budget, evs and gkm shed the heaviest network        heal --recursive), the set degraded until
                           (§11.13)                                            it ends; a second host: within 1 h of the
                                                                               page (19.8), move its drives into the cold
                                                                               spare chassis or fit spare drives; past
                                                                               half a set, re-seed (below); a drive over
                                                                               0.75 DWPD (7-day mean) or a budget shedding
                                                                               for an hour: confirm the counters, check
                                                                               for a heal or a runaway job, then order the
                                                                               next metadata cluster (19.9), or, on a
                                                                               cluster place_new no longer names, act on
                                                                               19.9's cohorts row: the move tool's date,
                                                                               then its cohort limit
a key held by a write      19.6's settle row: requests on the key wait, then   past 1 min (paged): bring the host back,
  that cannot settle       fail 503 (evs answers 503 unknown, gkm retries);    or replace its drives (the cold spare
                           the coordinator, or a settler on another host,      chassis or spare drives), after which
                           reverts what it can and releases once fewer than    the settler reads what they hold and
                           a read quorum of drives can hold a PUT, or none a   releases
                           DELETE
P0 past the refill         P0 runs at once, never paced or refused (owner      read 19.8's P0 bytes by kind; never pace or
  (19.8's page)            decision 186); while it takes the refill, pushes    refuse P0; order the next metadata cluster
                           are shed, and once it empties the bucket folds and  (19.9) and point place_new away from this
                           evacuation wait too; all restart as it ends,        one, and once the move tool exists move the
                           ramping up as the bucket refills, its excess        driving networks' repos (owner decision
                           forgiven (owner decision 190; §11.13)               145); contact those networks, found in the
                                                                               request logs (ops-1), referring one that
                                                                               does it deliberately to §21.8's review;
                                                                               record the drives' wear against their
                                                                               rating (19.6's wear row)
the first metadata         writes stop on every cluster, since each checks     as a file cluster; it pages as a cluster
  cluster                  rev/ there (§7.8), as do new repos, log appends     refusing writes (19.8)
                           and Adds; reads go on for repos whose placement
                           and authorization state a process holds
a drop job refused         it deletes nothing, stays refused and pages as a    {verify}: a bug; set format2's drop to
  {verify} or {mismatch}   storage-integrity alert (19.8)                      observe (19.11) and keep the job's
                                                                               dropscan/ files and drops/<repo>/_;
                                                                               {mismatch}: compare its signed list
                                                                               with resolve's, then likewise if
                                                                               resolve erred
a drop job stuck           another taskworker takes it once its lease lapsed   read its lease, phase and cursor in
                           30 s, resuming at its cursor (§11.13); a job waits  drops/<repo>/_; a wait for HDD load,
                           while its cluster is past 50% of capacity, under a  a hold, a deleted repo, an unsure
                           hold, while repo/ shows deleted, on an unsure       clock or a young candidate is by
                           clock, and while a candidate is under 25 h old      design
```

**Postgres-loss and site-loss recovery (D-OPS-14, D-OPS-18),** ordering §7.9's, §10.8's, §11.13's, §12.6's and §21.10's mechanisms; steps run in order, each idempotent, and a recovery's identity is its incident id; §22.8 drills both (FS-41, FS-42):

```text
postgres   ops            restore the newest main dump, then the newest sidecar dump, setting dns_root.restoring
                          as they load, before any block reads them (§12.6); the incident records both snapshot
                          times (19.6), and the network, network_user (login rows included) and network_client
                          rows follow the newer dump:
                          sidecar newer  its rows replace the main dump's copy of each id, a user's login rows
                                         as one set, and ids that dump lacks go in, so networks, members and
                                         sidecars newer than it keep their ids and rows, and a deactivation,
                                         password reset or removed login between the dumps holds; a network
                                         name or login another id holds in the main dump is listed, the
                                         network taking a random suffix and the login left out for a reset
                          main newer     it keeps every row it holds; sidecar rows whose network, member or
                                         client it lacks are dropped, as deleted since, and clients it holds
                                         created after the sidecar dump (their create_time,
                                         server/db_migrations.go:556), which lacks their owner rows, are
                                         deactivated to re-enroll (§7.4)
                          rows the sidecar dump does not name come back as the main dump holds them, a deletion
                          after the main dump's snapshot undone (19.3); a network newer than both is lost with its
                          rows, and taskworker takes each proj/ log whose network the restored rows lack down
                          the deleted-network path: each repo the log names marked deleted{deletion_id = the
                          incident id}, so §11.12 shreds it after 7 d, and the log's proj/ and projrows/
                          objects deleted with the last shred, all listed in the incident
abuse      abuse role     next, at any hour (19.8's rota), before any block reads the restored rows: §21.10's
                          step re-applies, in mail order, every unexpired action and every lift the abuse
                          mailbox holds from after the sidecar dump, each record opened with the mailboxes'
                          vault-held HPKE key (owner decision 208), so the dns step's snapshot withholds what
                          they suspend and the edges' first reloads keep every kill and halt; it re-places
                          holds placed after the dump from the legal-request mailbox, also outside Postgres,
                          and tells counsel; a hold whose objects the site took is void
dns        dns API        next, needing neither api nor the token exchange: §12.6's restore step, its
                          restore_serial above every serial the lost primary issued, each edge reloaded at it
                          and posting its diff, an NS that does not answer stopped until it reloads, its old
                          snapshot kept only for that diff, /dns/ready stale up to restore_serial, and the
                          RRsets and W1's custom hosts that changed listed in the incident and each network's
                          admin events, networks with open §21 cases flagged; restoring then clears, so later
                          dns writes commit above restore_serial
api        api            next, before api's public routes, the token exchange and CreateContract reopen:
                          verifies each network's proj/ entries past its restored network_acl_head as §7.9's
                          readers do, advancing the head (n, A_n, has_document), so a first policy document
                          filed after the dumps holds; re-applies §7.10's api effects, idempotent (§7.9), for
                          every removal or revocation recorded after the older dump's snapshot, in proj/
                          (behind the head too), projrows/' revoked_at, the restored network_admin_event rows
                          or a restored client's deactivate_time (server/db_migrations.go:3481), their DKIM and
                          TLSA deletions committing as ordinary dns writes; re-creates rev/ objects for those
                          under 20 min old (§7.8); and raises every sidecar_push_token row's rev by 2^32 and
                          its update_time to now, so §18.7's sweep re-applies each row above any revision the
                          lost primary applied (FS-42)
labels     taskworker     re-reads CT for <root> names logged since the sidecar dump's time minus 7 d; a
                          label or alias missing from dns_label goes in as retiring, owner unknown; a device
                          that signs (name, network_id, nonce = the incident id) with the key of a logged
                          certificate naming it re-binds it (POST /network/dns/label-reclaim); names nobody
                          re-binds tombstone after D-DNS-10's 90 days, so I-14 holds across the gap
rows       daemons        a refresh whose identity, binding or registration api lacks answers
                          restore_required; the daemon re-registers its identity and newest binding (api takes
                          them only once the projection, after a site loss the resumed log, admits that
                          identity key), then its mail host keys, TLS endpoints and push token
billing    taskworker     recomputes stripe_meter_report rows newer than the dump from network_service_usage
                          and re-sends them (§20.9's daily rows replace, never add); debits lost with the dump
                          go unbilled
--- site loss only ---
hardware   ops            new hardware with empty buckets passes §22's suite; reseed: true limits evs and gkm to
                          re-seed uploads and GroupForms for absent repos, and opens api's log upload (§7.9)
authority  token exchange re-seed mode (§7.8): until a network's log resumes, it mints only repo:<id>:admin,
                          for evs's /reseed and gkm's GroupForm, to the sidecars the restored rows list as that
                          network's Owners and Admins; other requests get restore_required
           member devices upload the log entries they keep verbatim (POST /network/config/reseed, §7.9); api
                          checks their links, signatures, signer rules and agreement with the restored
                          network_acl_head, never re-sequencing, and adopts an entry at tip+1 only once devices
                          of two members hold it (one member's where the run's base admits uploading devices of
                          one member only, read_only ones not counting), so no lone device fills a position
                          with a forged TICK; where none does, the log stops before it
           api            re-creates rev/ objects from its tombstones, and from each revocation as uploads and
                          the resumed log bring it, whichever is newer (§7.8)
           admin device   re-seeds the config repo, placed afresh (§11.8), from its mirror, which members
                          accept only at their pinned C_v, then publishes a base at tip+1 over it; api first
                          checks the adopted run's base as a new device's start against that repo, discarding a
                          run that fails, then appends the base and re-derives its ticks; the base resumes the
                          log at unchanged positions and digests (no reader FORKs) and names each repo live,
                          deleted (restorable) or shredded; signers re-submit statements no adopted entry holds
groups     repo admins'   place each repo they hold afresh (§11.8), writing repo/ deleted{...} first for one the
           devices        repos step re-seeds as deleted, and re-form its group under a GroupForm linked through
                          the ladder (D-KEYS-13); an owner-bound repo's group only by its owner's consented
                          device (§8.5; owner decision 126); writer leaves re-add member leaves, ReaderWraps and
                          RecoveryWraps, keeping recovery-code-only members (owner decisions 113, 114), for a
                          deleted repo only once it is restored (§10.8)
repos      devices        first the ERASE pushes (§11.12) each device signed in the last 30 days, then the signed
                          pushes, parts, segments (a versionless path's only for versions the device holds, staged
                          ones as uploads) and pack contents past the current head, in version order, and last,
                          after every ref's history, the slot objects, never re-signing (D-MCP-10); evs takes
                          re-seeds only for repos the projection lists live or restorable, refusing one whose
                          access log ends in RepoDelete past 7 d or with now and re-seeding one whose log ends in
                          an unrestored RepoDelete without now, under 7 d old, as deleted{deletion_id, its entry's
                          time}: placed so, it takes its history, group and slots through /reseed and its
                          GroupForm, which re-seed mode alone admits while deleted (§11.12), so access stays
                          refused while restore and the timer resume; it applies every ERASE it holds before it
                          serves a slot, and refuses slot keys an applied erasure covers; where every copy ends
                          below a reader's pin, a repo admin's EvsReseed {repo, ref, version, C_v, incident}
                          (§11.6) lets the reader accept the shorter history, showing the loss; a search index
                          (v1) that no device's mirror holds is rebuilt from text once its repo is re-seeded, by
                          an indexer serving the repo for search, else its next capable writer
                          (owner decision 177; §11.14)
drops      taskworker     runs each re-seeded repo's drops (v1) again from their signed state (not_before_ms,
                          cancels; §11.13), so listed content a stale mirror re-seeded is stored again only until
                          the re-run job deletes it
close      ops            after 30 days reseed turns off; admins learn which projected repos nothing
                          re-seeded, and which came back only below a surviving reader's pin, under an
                          EvsReseed, where a lost ERASE may let a stale mirror's slot keys return (§11.12's
                          residual), and which drops' listed content a stale mirror returned until the re-run
                          job deleted it; an ERASE no surviving device saw leaves nothing to name
```

### 19.11 Environments, gates, rollout

**local:** all, in server/local (postgres:18, redis:8; README.md:36), plus MinIO, Pebble ACME, an SMTP sink and a test dns edge. **canary:** evs, gkm and sockets beside web and api (vault/canary/services.yml:36-47), stores rebuilt per merge; no edges or mail. **main:** all, dark first, edges and mail for internal networks and design partners until launch (owner decision 91); T6 on test roots and LE staging (§12.4). **community:** none.

**Gates (D-OPS-10).** `config/<env>/sidecar.yml` is optional and inert when absent, like config/main/onboarding.yml:3-6:

```yaml
sidecar:
  evs: {enabled: false, writes: true, networks: [], percent: 0}
  format2: {enabled: false, networks: [], percent: 0, purge: observe, drop: observe}  # §11.6: networks whose
                             # pushes may carry format 2, each repo migrating at its first such push; purge: observe
                             # logs each candidate and deletes nothing, purge: on deletes, after D-TEST-12's soak (§22);
                             # drop: observe runs drop jobs through verify and deletes nothing (§11.13), drop: on
                             # deletes, after D-TEST-18's soak; until both are on and D-TEST-13's production check
                             # passes, the gate admits only listed internal networks and design partners (percent 0)
  gkm: {enabled: false, networks: [], percent: 0}   # sockets, tlsedge, mxedge, smtpedge alike
  dns: {enabled: false, writes: true}
  push: {enabled: false}     # §6 EnableSidecarPush
  wake: {enabled: false}     # 19.4's push sender
  bridge: {enabled: false}   # §17 EnableBridge
  escrow_draw_order: {enabled: false}  # §20.9 (D-QUOTA-9): every draw and return site (connect's CreateContract,
                             # the edges' leases, taskworker's closes); on only once M6's Gn-out registers
                             # MG6's index (19.7), never off while a team_credit balance is in window
  reseed: false              # 19.10, site loss only
  place_new: meta-1          # 19.9: the metadata cluster that takes new repos; absent, the first
  drained: []                # W1: lb interfaces the dns edges leave out of their answers
  preview_networks: []       # §7.4 (D-PHASE-3): networks that enroll sidecars before stage 2
  sockets_control_qps: {rate: 50, burst: 500}  # §9.10 (D-SOCK-15), per process and calling client; edges: W2's 2,000 Finds/s
  urnetwork_edge: <network_id>                 # §6.10.1, §9.6: the urnetwork-edge platform network's id
```

A network is in when listed or when hash(network_id) mod 100 < `percent`. A disabled service stays ready and answers 503 with Retry-After; `writes: false` is the incident switch. Services reread the file every 60 s; sidecars learn their set from §6's `core` topic.

**Classes (D-OPS-11).** Staged with `--only-older` (build/all/deploy-rollout.zsh:33): evs, gkm, sockets, dns (on Q-OPS-5's conditions), tlsedge, mxedge; single pass (:24): smtpedge, and `dnsedge` one host at a time. The staged list (:87) becomes `mmm lb taskworker api connect web app mcp dns gkm evs sockets tlsedge mxedge`.

**Order** (§23 sets milestones; groups merge per 19.7):
1. M0: MG0 (D-PHASE-3's early merge), with D-OPS-18's daily dump and the main dump's exclude list from its Gn-out, restore-drilled before M3's pilot; W5, on warp's `sidecar` branch (owner decision 196); W6; the hardware order (19.6; owner decisions 116, 136-139); HE's port-25 and reverse-delegation request (§14).
2. M1-M4: MG1-MG4; chrony on the evs, gkm, taskworker, Redis and storage hosts before evs serves (19.6); evs and gkm dark at M2 on a staging cluster on the production hosts, so they and their PM9A3 set arrive before M2's exit (D-TEST-11), rebuilt empty and SMART-rechecked before M3 under D-PHASE-7's data rule; then production (M3) with the write budget, the protection states and the pager (owner decision 143); W2, W8, publishers; W10 at RS1.
3. M5: dns edges (W9), signed from the first deploy (owner decision 109), then the ur.network move (owner decision 13); sockets, certs and tlsedge with W1, W7 and the LE override; the platform listener with W11; the pager's notice class (19.8).
4. M7: mxedge's router (W4); M8: the push sender; M9: smtpedge, once its PTR and HELO names resolve (W11).
5. M10: after M10's Gn-out the `format2` gate opens to internal networks and design partners (percent 0), purge and drop in observe; purge turns on after D-TEST-12's soak and drop after D-TEST-18's; D-TEST-13's production confirmation runs while the gate holds percent at 0 (owner decision 174); only then does the gate open by percent (§23.9). §22.8's M10 `hdd` run uses a bucket of its own on the production segment cluster in a low-load window, under 19.6's 50% drive-operation pause, its bucket emptied after.

### 19.12 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| MinIO pools for metadata growth | one endpoint; rebalance | a PUT checks its precondition only in the pool it picks (§11.3) | rejected (owner decision 145) |
| Redis as the metadata store of record | no NVMe wear | a failover loses acknowledged commits; no replicas | rejected (owner decision 136) |
| Every drive acknowledges each write | no degraded objects | one host's outage stops writes; MinIO has no such setting | rejected for 19.6's states |
| MinIO's warm tier for history past 24 h | no evacuation | a tiny HDD object per batch or log page | rejected for §11.13's packs |

### 19.13 Decisions proposed

**D-OPS-1 (proposed).** Host the engines and jobs per 19.4, the push sender in taskworker; only api's oauth issuer mounts signing keys. *Why:* hostile-facing processes hold only their own secrets.

**D-OPS-2 (proposed).** gkm is its own service, `server/cli/gkm`, from v0; its reconciler runs in taskworker. *Why:* api's daily deploys cannot stall MLS commits.

**D-OPS-3 (proposed).** Build W1, W2 and W4-W11; keep the 16 MiB limit. *Why:* 19.5's consumers need them.

**D-OPS-4 (proposed).** The file clusters are LAN-only, unshared and without presigned URLs. *Why:* conditional writes order evs and gkm; direct access exposes client IPs.

**D-OPS-5 (withdrawn).** Superseded by owner decision 94: no off-site copy of the file clusters; D-OPS-18 covers Postgres-held sidecar rows.

**D-OPS-6 (proposed).** Migrations follow 19.7: a group is pending under `sidecar_pending` until its own Gn-out registers it. *Why:* the catalog refuses renumbered identities, and two tracks share one `sidecar` branch.

**D-OPS-7 (proposed).** Redis holds only rebuildable state (19.7); switches go to Postgres first. *Why:* masters have no replicas, and the clusters stay the only commit point (owner decision 136).

**D-OPS-8 (proposed).** Metrics and logs carry no identifying labels, names or query strings (19.8). *Why:* I-13.

**D-OPS-9 (proposed).** Adopt 19.8's SLOs and page classes, which page out of hours from M3 (owner decision 143); budget burn stops rollout steps. *Why:* each percent step needs a stop rule, and owner decisions 89 and 116's 4 h RTO a responder at any hour.

**D-OPS-10 (proposed).** Gates and the placement target live in `config/<env>/sidecar.yml`. *Why:* §4.8 merges code dark, and a new cluster takes repos without a deploy.

**D-OPS-11 (proposed).** Classify and order releases per 19.11. *Why:* an unclassified service exits 64.

**D-OPS-12 (proposed).** A builder job renews platform certificates at two thirds of their lifetime (lego v5, ARI, RFC 9773), and W5 reloads them. *Why:* manual renewal (xops/certs/renew.md:3-20) fails at 45-day lifetimes, due 2028-02-16 (https://letsencrypt.org/2025/12/02/from-90-to-45/).

**D-OPS-13 (withdrawn).** Superseded by owner decision 34: no dedicated mail or tlsedge addresses.

**D-OPS-14 (proposed).** Durability is 19.6's, judged per object by the shards it holds: quorum writes, the protection states, the cold spare and D-OPS-18's daily sidecar dump off site. Postgres and site loss take 19.10's restore. *Why:* owner decisions 89, 90 and 94 leave devices and dumps as the only copies, and 116 adds the spare.

**D-OPS-15 (proposed).** Addresses and dns edges follow 19.4 and 19.5. *Why:* owner decisions 34, 69, 71, 123 and 124; RRL needs resolver addresses.

**D-OPS-16 (proposed).** The Redis bundles leave out 19.7's sidecar families: bringyour-backup.sh filters them from each node's rdb before sealing (xops/main/ansible/host_files/by-us-fmt-5-edge-6/backup/bringyour-backup.sh:8-13). *Why:* they rebuild or expire within 48 h; no backup may outlive a published ttl (D-TRUST-7).

**D-OPS-17 (proposed).** Size the metadata tier by drive writes, objects and bytes, which §22.8's runs measure per push, per object and in records per batch per cluster; owner decision 136's triggers (50% raw, 40% inodes, 0.5 DWPD), or monitor's projection of one within the lead time, order the next metadata cluster (owner decision 145), on new hosts after the second (19.9); each cluster that no longer takes repos is planned by its own cohort's projection (19.9's cohorts row), which dates the move tool. HDD sets join only through a segment placement that keeps §11.13's receipt check and moves upload load, never as a pool, ordered by 19.9's hdd trigger ahead of year two's HDD load, whose PUTs alone fill the 50% admission line by 19.6's model. *Why:* every drive takes every write, endurance binds before IOPS (owner decision 140), a pool checks preconditions only inside itself (19.9), and placed repos never move without the tool (owner decision 145), so free space elsewhere relieves no cohort; refused uploads are not throughput.

**D-OPS-18 (proposed).** The tables 19.7's groups create, with the network, user and client rows they name, have a daily, off-site dump from MG0's Gn-out, and the main dumps exclude those tables (19.6); the primary's physical working copies, edge-6's `pg-base` and edge-5's `main-pgbase-<date>`, are each refreshed or destroyed within 7 d, and the 24 h edge records' partitions are UNLOGGED (owner decision 210). *Why:* owner decisions 2 and 18 moved storage, not identity, naming, mail routing, abuse or billing, out of Postgres; owner decision 94 bars an off-site copy of the file clusters, not of these rows; and the named rows keep a network newer than the twice-weekly main dump attached to its rows, log and repos.

**D-OPS-19 (proposed).** The metadata set runs 19.6's XFS and MinIO settings, and each storage host exports its metadata drives' write counters and SMART wear, and its HDDs' operation counters, to monitor, §11.13's write budget and its HDD share (19.6). *Why:* the drives' endurance is the binding budget, and only drive counters measure it (owner decision 140); the HDD sets' operations bind before their space (Q-OPS-2).

**D-OPS-20 (proposed).** Both clusters run an in-house MinIO build, from the `urnetwork/minio` fork's `sidecar` branch (owner decision 195), with 19.6's deadline and settle rules: every request but a streamed segment PUT carries its deadline, which the build checks where it takes the key's lock and at each drive commit; each drive commit applies only while no commit was applied to its key on its drive since the coordinator read it under the lock; a PUT releases its key only once it holds a write quorum or can never reach a read quorum, and a DELETE only once it holds a write quorum or no drive holds anything of it, each reverting every drive that took it, another host settling a dead coordinator's write; a DELETE may name the LastModified of the object it means, as GC's do (owner decisions 203, 225); and a LIST is answered only when it is whole (owner decision 226). *Why:* in the deployed build a cancel reaches no drive on another host and the lock is released first, and even a lock held to the 30 s drive timeout releases a commit that stalled after its last check, so a cancelled or timed-out write can land after a later request on its key read it or passed its precondition, breaking §11.7's marker collection, v1's versionless purge and drop jobs (§11.13) and every conditional write's atomicity; absence is not a version, so a drive's contents alone cannot tell a commit from before a DELETE from one after it, nor one failed DELETE's leavings from another's; holding a key while such a write settles is the cost, paid only when a host fails during a write that has not reached its write quorum; a fork, not a patch series in warp, keeps MinIO's AGPL source in one public place.

**D-OPS-21 (proposed).** Drop jobs are P2 taskworker work, one per segment cluster at a time, each reading at most 32 MB/s and deleting at most 10 objects a second, paused while HDD drive operations exceed 50% of measured capacity (19.6). *Why:* owner decision 173's scan of every ref must not starve customers' reads or the HDD sets' heal and evacuation.

**D-OPS-22 (proposed).** Until the move tool exists, a metadata cluster at 80% raw or 70% inodes takes only what §20.7's storage limit accepts, refusing the rest 507 CLUSTER_FULL (19.9's cohorts row), and monitor projects each cluster's exhaustion from its own cohort's slopes, the first cluster's control plane apart, dating the move tool by the earliest. *Why:* a full cluster would refuse deletions and erasures too, and the estate's free space cannot take a placed cohort (owner decision 145).

### 19.14 Open questions

**Q-OPS-1.** [X13] What is the "new file cluster" (PLAN.md:61), and where does ordering live? **Decided by owner 2026-11-03 (owner decisions 18, 20, 21, 94):** (a), 19.6's MinIO clusters at one site, ordered by the store (owner decision 2). **Decided by owner 2026-11-04 (owner decisions 116, 136-140, 145):** 19.6's parity, cold spare, drives, write budget and Redis soft state, and growth by whole clusters; the load inputs stay an engineering estimate. *Residual:* none.

**Q-OPS-2.** Cross-cutting (§10.6, §11.13). Should small objects pack? Y2's HDD mix needs ~32,000 drive operations a second against ~8,000-12,800 (19.6). **Closed by peer review 2026-11-04:** (b) in v0, with (a) a switch: format 1 freezes content-id segment ids, the reserved `spidx/` family and lookup order, and reserved locator kinds 3 and 4, never a physical address; after §22.8's `hdd` row (M3), (a) turns on for segments under 1 MiB and older than 7 days, never kind-5 segments, which stay deletable one by one, once HDD drive operations pass 50% of measured capacity; ~25,600 of Y2's ~32,000 drive operations a second are GETs, which packing does not reduce, so the page cache serves most and (c) HDD sets per D-OPS-17 the rest, which must land before year two's load, since its PUTs alone (~6,400) fill the 50% admission line (19.6, 19.9's hdd trigger); history leaves the batches hourly, so each day everything older than 24 h leaves them (owner decision 136), and a small repo's parcels within 7 d; gkm's `gen/` takes §10.16's gen packs, which keep every generation for the repo's life (D-KEYS-20), count as gen/ for shreds, their 10-minute repeat and re-seeds, and hold no slot, so erasure is unchanged; they start on a cluster at 19.9's gen trigger, projected from §22.8's M2 count. *Residual:* 19.9's hdd trigger, from §22.8's admitted hdd run.

**Q-OPS-3.** Where does Postgres-held sidecar metadata live without a replica? **Decided by owner 2026-11-03 (implied by owner decisions 2, 18):** moot for storage, which left Postgres. **Closed by peer review 2026-11-04:** D-OPS-18 and 19.10's reconcile: the sidecar rows, which are not storage, and the network, user and client rows they name take a daily off-site dump, so they come back to ≤ 24 h at a primary's loss and ≤ 26 h at the site's while each nightly run completes, a day more per skipped run, whatever the main dump's age; the platform's other rows come back to the main dump's (19.3). *Residual:* none.

**Q-OPS-4.** Where are edges and mail tested? **Decided by owner 2026-11-03 (owner decision 91):** (b), dark in main for internal networks and design partners, no canary stage. *Residual:* none.

**Q-OPS-5.** Should `dns` deploy staged (`--only-older`, stopping at 25%) or in one pass like `dnsedge`? **Closed by peer review 2026-11-04:** (a), staged: N and N+1 read each other's journal rows and snapshots, N+1's unreadable writes gated until 100%; `dnsedge` single-pass, one host at a time, serving only self-checked snapshots; rollout stops on a canary-signature failure or an NS serial divergence; FS-52 rolls N+1 back to N in T3. *Residual:* none.

**Q-OPS-6.** Must backups delay erasure? **Decided by owner 2026-11-03 (owner decision 90):** (c), no backups of key metadata (19.6). *Residual:* none.

**Q-OPS-7.** What RPO and RTO apply, at how many sites? **Decided by owner 2026-11-03 (owner decisions 89, 94):** (a), one site; the targets cover drive and host failures (19.6), and site loss recovers from devices (19.10). *Residual:* none.

**Q-OPS-8.** Cross-cutting (§4.8, §23.9). How do migration groups reach server's `main` when M3 pilots on production? **Decided by owner 2026-11-04 (owner decision 118):** each group's SQL merges to `main` with its milestone's code at Gn-out (19.7), so M3 pilots on production. *Residual:* none.

**Q-OPS-9.** Cross-cutting (§12.6, §21.8). Do page-class infrastructure alerts page out of hours from M3, so owner decisions 89 and 116's 4 h RTO and 19.8's SLOs hold at all hours? **Decided by owner 2026-11-04 (owner decision 143):** (a), a two-person rota on one pager service from M3, with 30-minute acknowledgment and escalation, for 19.8's page classes only; owner decision 134's notices join the same pager at M5. The RTO and the SLOs hold at all hours, as §22.8's host drill (FS-50) measures. *Residual:* none.

**Q-OPS-10.** Cross-cutting (§10.6, §11.8). How does the metadata tier grow past one set, when a multi-pool PUT checks If-Match and If-None-Match only in the pool it picks by free space (§11.3)? **Decided by owner 2026-11-04 (owner decision 145):** (b), only by adding metadata clusters, never pools: each new repo and its gkm group are placed at creation by a create-only `place/<repo_id>` on the first cluster, whose If-None-Match decides a race (§11.8), and all their objects stay there. The triggers stay (19.9). Year two needs five to six clusters: batches are per evs process and cluster (§11.8), so at ~8 processes a set near capacity holds ~1-1.6 records a batch and sustains ~400-450 pushes/s (~530-600 on 1 KiB blocks) at ~27-43 KiB of drive writes a push (Q-EVS-9); owner decision 145's record first carried ~490-650 a set and four to five sets, which assumed batches shared across the whole load; per-cluster placement rules that out (19.9), and the record was corrected on 2026-11-05 to this sizing. *Residual:* none; a move tool is later (19.18).

### 19.15 Departures from PLAN.md

None: owner decisions 18, 94 and 145 keep MinIO, in new clusters (PLAN.md:61).

### 19.16 Interfaces

- **Provides:** 19.4-19.11's blocks, push sender, W items, addresses, clusters and their growth, the store request deadline and settle rule, host clocks and each process's offset, protection states, drive counters and SMART wear, the `{nvb_<set>}` allowances, accounts and wallet, the class liabilities, each cluster's cohort projection and limit, and each segment cluster's drive operations and capacity, the sidecar dump, recovery, gates (`format2`'s purge and drop modes included), pager, SLOs, runbooks.
- **Consumes:** engines (§4, §9-§15); §7.8's `rev/` and re-seed mode; §7.9's log, verified cache and site-loss resumption; §8.9; §10.6, §10.8, §10.16's gen packs; §11.8's placement and clock rule, §11.13's mix, write budget, HDD share, v1's purge, sweep and drop jobs and the search index's costs; §11.14's search index; §16.11's directory; §12.6's restore step and `/dns/reload-diff`; §13.4; §14.6; §15.4; §18.7; §20's jobs and draw order; §21's tables, `hold/`, intake and abuse mailbox (§21.10); §22's tests; X15 (§23).
- **Subprotocol messages:** none. **API routes:** none new. **Tables:** none owned; 19.7 summarizes; the push sender reads `{scp_<C>}tok`, `{scp_<C>}tokrev`, `{scp_<C>}ack` and `{wakeq_<shard>}`, and taskworker reconciles tokens per hash slot by `{tokgen_<n>}` and re-applies changed rows each pass (19.4; §18.7's steps 5 and 6).
- **Services and config:** services.yml blocks, two dns edge hosts; `sidecar.yml` (gates, `place_new`, `drained`, `preview_networks`, `sockets_control_qps`, `urnetwork_edge`); `db.yml` and `redis.yml` caps; vault JWKS, ZSK, APNs, FCM and feed credentials; receipt keys in evs's secret files; D-OPS-20's MinIO build from `urnetwork/minio`; xops's `file-clusters` with 19.6's XFS and MinIO settings, the storage hosts' diskstats exporter, chrony on the evs, gkm, taskworker, Redis and storage hosts with the Redis hosts' offset exporter, the daily sidecar dump, the main dump's exclude list and planetoid's pg-sidecar stream (D-OPS-18), the bundle filter (§4.8); the pager.
- **Assumptions about other sections:** §7.8's re-seed mode mints only `repo:<id>:admin` for evs's `/reseed` and gkm's GroupForm, which §11.12 also admits for a repo re-seeded as deleted; §7.9 resumes the log from member devices' verbatim entries, each adopted once two members' devices hold it, FS-41 checks that readers see no FORK, that one member's forged TICK takes no position and that a Team whose other members hold only read_only devices resumes, and FS-42 restores both dumps in each order of their snapshot times, keeping the newer one's rows, and checks that revocations between or after the dumps hold once api's replay ends, their TLSA (M7) and DKIM selectors (M9) gone, that a network newer than both takes the deleted-network path, that actions and lifts mailed after the dump hold (§21.10), and that a dns write, an ACME challenge, an NS that missed the SOA read and a custom host after the restore behave as 19.10's dns step says, which runs §12.6's restore step; §10.6, §11.7, §11.8 and v1's purge and drop jobs (§11.13) rely on 19.6's request deadline, which the Blobs client sends as x-ur-deadline-ms, and its settle rule, which §22's suite checks (FS-114); §11.13's HDD admission and drop jobs read 19.6's published HDD drive operations and capacity, and the versionless sweep HEADs each candidate before its DELETE (19.8); while 19.6's clock offset is unknown or over 50 ms, §11.8's evs answers pushes 503, and taskworker raises no evacuation fence and GC deletes nothing; §11.10's restarted push sequence relies on 19.6's chrony on the Redis hosts; §20.9's draw sites read `escrow_draw_order`; §11.8 places new repos on `place_new`, and §11.22 lists a segment placement that keeps the receipt check before any added HDD set (19.9); §11.13's accounts debit P1 admissions from A1 at full price, moving their deferred P2 work into the wallet W, funded P2 spending only W and P1 and unfunded P2 only T, while P0 issues at once, its measured bytes draining the bucket down to its floor at zero, past which they are its forgiven excess (owner decision 190), and no other class issues while the bucket is empty; §10.6's acks and §11.10's leases and push sequence live in Redis; §18.7's trigger feeds `{wakeq_<shard>}`, and its sentinel pass re-projects the slots of a master lost or restarted; §21.8 feeds 19.8's pager; §22.8 measures §11.13's mix, §10.6's sizes, bytes per object and push, records per batch per cluster, and rotations and path-epoch copies, expiry-driven ones included, and its `hdd` row the segment cluster's capacity by 19.6's HDD counters; HE allows port 25.

### 19.17 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| The MinIO source stalls with an open CVE | Medium | Medium | LAN only, pinned source, conformance suite |
| Drive writes, objects or inodes outrun the metadata cluster before the next one lands, at about 1.25× year one (1.2× with v1's search index on 4 KiB blocks), or `gen/` objects, kept for their repo's life, grow near their bound (19.9) | Medium | High | §11.13's write budget sheds the heaviest network; 19.9's projected triggers, with §22.8's M2 count of rotations and path-epoch copies, expiry-driven ones included; §10.16's gen packs at 19.9's gen trigger; D-OPS-17; Q-OPS-2 |
| A P0 storm, legal safety work past the refill (100 large Teams on one cluster each shrinking every 5 minutes ask ~2.9 TiB a day a drive, about twice it), runs at once (owner decision 186): the cluster's busiest drive writes past 0.8 DWPD and the PM9A3's 1 DWPD rating while it lasts, every push there is shed and evacuation waits once P0 empties the bucket, so batches stay on NVMe past 26 h until the storm ends, its forgiven excess stays as wear, ~0.23 drive-writes a 6-hour storm at that stress, and the M2 sizing bounds no such wear | Low | High | P0's per-class rate limits; pushes and evacuation restarting as the storm ends, ramping up as the bucket refills, and each storm's forgiven excess counted against the ~420 drive-writes of rating that five years at the refill leave, ~1,800 such storms (§11.13; owner decision 190); 19.8's P0 page within an hour and 19.10's runbook: capacity, place_new, the networks driving it; FS-117 |
| Measured costs hold a set below ~400 pushes/s (~530 on 1 KiB blocks) at the ~1-1.6 records a batch of a set near capacity, so year two needs more than six clusters (19.9) | Medium | Medium | §22.8's records per batch per cluster order them within the lead time; 1 KiB blocks; §11's later per-cluster batcher |
| v1's search index adds ~2 KiB a push on 4 KiB blocks and ~4 on 1 KiB, cutting a set near capacity to ~385-430 pushes/s (~475-535) and putting 2× year one at ~42-45 KiB a push on 4 KiB blocks, at D-TEST-11's 43 (§11.13) | Medium | Medium | owner decision 172's cadence; 1 KiB blocks (~34-37 KiB a push at 2× year one); D-TEST-13's computed gate, confirmed on production after the freeze (owner decision 174); the write budget sheds the heaviest network |
| The first metadata cluster fails: writes stop on every cluster, since each checks `rev/` there, as do new repos, log appends and Adds (19.10) | Low | High | EC:4 with the cold spare; it pages as a cluster refusing writes; processes keep reading repos they hold placement and state for |
| Placement moves only new repos, so a cluster's repos (its cohort), or the first cluster's control plane, can outgrow it before a move tool exists while new clusters stand mostly empty (owner decision 145) | Medium | High | triggers stop new repos with over a third of the budget and half the space left; shedding; 19.9's cohorts row projects each cluster's own exhaustion and builds the move tool before the earliest, and until then holds a cluster at 80% raw or 70% inodes to maintenance (507 CLUSTER_FULL); FS-119 drills it |
| A pool on a metadata cluster breaks conditional writes (§11.3) | Low | Critical | no pools (owner decision 145); §22's suite refuses one (FS-63); monitor warns |
| A cancelled or timed-out write lands after a later request on its key read it or passed its precondition, as the deployed MinIO allows (19.6's settle row), so a CAS loses its atomicity, or §11.7's collection or v1's purge (§11.13) deletes a live object | Low | Critical | D-OPS-20's build: deadlines checked where a request takes its key and at each drive commit, each commit applied only if no commit reached its key on that drive since its coordinator read it, and a key released only at a write quorum or once the write can never be read, a DELETE's once no drive holds it, a dead coordinator's write settled from another host; §22.9's suite and FS-114 per build, upgrade and new cluster, with commits held past 30 s and the coordinator killed; StoreSettle.tla; collection, purge and drops wait on a build that has not passed |
| A write that cannot settle holds its key: a PUT lacking a write quorum that could still reach a read quorum, or a DELETE lacking one with a commit unanswered, with a host among its drives unreachable, keeps requests on the key waiting, then failing 503 (evs answers unknown), until the host answers or its drives are replaced (19.6's settle row) | Low | Medium | it needs a write mid-commit as a host fails after committing; reverts reach every reachable drive at once; ordinary drive and host failures hold no key; paged past 1 min (19.8); 19.10's held-key row |
| A second failure lands while a set is degraded, before its heal ends | Medium | High | `at_risk` pages; full heal on every return; M3's drill measures heal time |
| Y2's HDD load passes the 50% admission line: by 19.6's model its PUTs alone (~6,400 drive operations a second) fill it before any GET, and HDD sets cannot be pools (19.9) | High by the model | High | §22.8's hdd row runs the mix with admission on, reporting admitted throughput and refusals (M3); 19.9's hdd trigger lands the segment placement and the added capacity before that load; §11.13's HDD share past 50% of 19.6's published capacity; Q-OPS-2 (a) |
| Site loss destroys data no device holds | Low | Critical | mirrors (D-EVS-17), spools, D-OPS-18's dump, §22.8's drill |
| The Postgres primary is lost: the token exchange, and with it new evs and gkm sessions, stops until the platform's restore and 19.10's reconcile end, with no RTO target, and a few hours of that spend many months of the 99.9% SLOs' 43 min per 30 days (19.8) | Low | High | paged at any hour (19.8); FS-42 drills the reconcile per Gn-out from M3; sockets and edges keep running from Redis (19.10) |
| The out-of-hours rota misses a page | Low | High | two-person rota with escalation at 30 min; FS-50's drill per Gn-out from M3 |
| The split slows connect's H1 path or fails fleet-wide | Low | High | §13.4's bench, drained per-interface rollout, probes |
| A site or HE outage, or a flood, stops both NS, ACME DNS-01, DANE and inbound mail; paged out of hours, it can still outlast senders' retries (14 h to 5 d, §15.3) (accepted, owner decisions 123, 143) | Medium | Critical | separate blocks and hosts, RRL |
| A sending address's listing also hits api and connect ingress (accepted, owner decision 124) | Medium | High | per-domain and per-network reputation (§14, §21); delisting |

### 19.18 Phasing

- **v0 (M0-M5, M7-M9):** 19.11's order, dark first; D-OPS-20's MinIO build on both clusters; one PM9A3 set of 8 drives and 2-4 spares, with 19.6's settings, counters, write budget and HDD capacity; the sidecar dump from MG0's Gn-out, with a restore drill and a re-seed drill before M3's pilot; infrastructure paging from M3 (owner decision 143); business-hours abuse review, plus M5's notice pager (owner decision 134).
- **v1 (M6):** MG6, then `escrow_draw_order` on (§20.9); the team directory (§16.11), whose pushes enter 19.6's load and 19.9's projection; 24/7 review.
- **v1 at M10 (owner decision 169):** 19.11's `format2` gate with its purge and drop modes, each observe then on, with their metrics (19.8), the sweep (§11.13) and D-OPS-21's bounds; storage format 2's search index (§11.14), whose load enters 19.9's projection from D-TEST-13's computed cost, confirmed on production after the freeze (owner decision 174).
- **Later:** Q-OPS-2 (a) at its triggers; §10.16's gen packs at 19.9's gen trigger; the next metadata cluster at 19.9's triggers, a tracked year-one item (D-OPS-17; owner decision 145), and later ones on new hosts; a tool that moves placed repos between clusters, keeping one commit point, built by 19.9's cohorts row before the earliest projected cohort exhaustion; a segment placement before any HDD set, ordered by 19.9's hdd trigger ahead of year two's HDD load; a second site or an off-site copy, from operating data (owner decisions 89, 94).
- **Blocking:** the hardware's lead time (ordered in M0; the hosts and their PM9A3 set before M2's exit, for staging, and production at M3); §22.8's M2 drive-write run, which gates format 1 (D-TEST-11); the production cluster's write budget with its class liabilities in monitor, §22.8's `hdd` capacity and admitted-mix run, FS-119's cohort drill, the rota and the sidecar dump's restore drill (M3); the dns edge hosts and the pager's notice class (M5); HE's port 25 and reverse delegation (M9); the next metadata cluster's lead time, which sets 19.9's projection window.
