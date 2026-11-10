## 20. Tiers, quotas, metering, and billing

### 20.1 Purpose and scope

This section owns tiers, prices, limits with their enforcement points and counters, the stored-byte count (with §11.13), client counting (X10, with §5), the payer of sidecar traffic (X11), Team billing and the escrow draw order, downgrade, and pricing conflicts (X16). §6.10.1 owns contract modes; §9-§17 own mechanisms and abuse-cap defaults, which §21 tightens.

### 20.2 Requirements

| id | requirement | source |
|---|---|---|
| R-QUOTA-1 | Community, Pro, and Team "$100/month+usage based overage", with 20.4's PLAN.md quotas | PLAN.md:348-358; owner decisions 27, 122 |
| R-QUOTA-2 | Forwarding unlimited; recURd on every tier; SSO and custom domains Team only | PLAN.md:359-364; owner decision 66 |
| R-QUOTA-3 | "all of these count towards transfer balance", file transfer included | PLAN.md:353; cli/UI.md:97; owner decision 10 |
| R-QUOTA-4 | One person runs "any number of agents", free; pitch5's "Agents are never metered" changes (20.13) | sidecar/design/pitch5.html:844, :849; owner decisions 4, 10, 27 |
| R-QUOTA-5 | Limits and prices only via pro.yml and `model.Pro()`; unusable values never lock clients out; enforcement ships dark; networks without a feature cost no query | config/all/pro.yml:1-6, :23-30, :46-57; server/model/subscription_model.go:1727-1731; owner decision 122 |
| R-QUOTA-6 | Team by card to ~25 seats, invoiced above; active people only; read-only seats free | sidecar/design/improvements4.md:251 |
| R-QUOTA-7 | evs keeps no Postgres or durable Redis state; usage batches give soft quotas, recounted nightly from stored object sizes; replaced versionless content counts only until purged | owner decisions 2, 136, 165 |

### 20.3 What exists today

| Fact | Citation |
|---|---|
| Two tiers via `Tier(pro bool)`; Pro iff an in-window `transfer_balance.pro=true`, cached 60 s and 5 s. Free: 2 concurrent top-level clients, 30 GiB/day; Pro: 1,000, 10 TiB/month, $5 ($0.50 regional); data packs $3/TiB | server/model/pro.go:429; server/model/pro_model.go:15-30, :54-55; config/all/pro.yml:86-107, :173-175, :211-224 |
| Concurrent-client enforcement is off until after the 2026-11-06/07 app release; on, it also refuses a 101st active top-level client; the peer list turns off above 100 top-level clients active in 14 days; provide-intent clients are exempt from all three; children never count | config 5daa281; config/all/pro.yml:54-57; server/model/network_client_model.go:46-51, :757-779; server/model/network_client_limit_model.go:73-91; server/model/peer_model.go:413, :450-487 |
| Escrow and the Redis admission keyset draw a payer's balances by end time, start time and balance id, settlement's read by end time, none by `grant_kind` (NULL on older balances); only settlement debits, paying providers from each balance's revenue in that order; Network and FriendsAndFamily escrow nothing; Redis reservations over-admit on loss and lease 24 h | server/model/subscription_model.go:1782-1796, :3967-3987; server/model/subscription_redis_selection.go:377-394; server/db_migrations.go:9578; server/model/subscription_settlement_calculation.go:85-102; server/controller/connect_controller.go:1241-1250, :1296-1318; server/model/subscription_redis_admission.go:19-24, :38 |

Missing: Team, seats, sidecar limits, a service debit, metered billing.

### 20.4 The tier table (X16)

Decided (Q-QUOTA-1); canonical for tier numbers and prices. Quotas and the limits derived from them (`smtp_*`, `mail_*`, §13.9's endpoint caps, `store_weight`, `evs_drops_per_day`) grow with the tier; `sidecar_abuse:` caps do not (D-QUOTA-7).

| Item | PLAN.md | Other source | Community/Pro/Team |
|---|---|---|---|
| Team price | $100/mo + usage | $20–40/seat, inferred (P5:845, :879) | $100/mo for 5 billable seats, then $20/seat; Auditor, Billing admin, agents free; overage at existing rates (20.9) |
| `storage` | 1/20/200 GB | 1/100 GB (UI:87-89) | 1/20/200 GiB (20.13); Team overage to 2 TiB |
| `smtp_connections_per_day` | 5/200/20000 emails | replies only, 2000 (UI:76-78) | 5/200/20,000 connections, hard (owner decision 30) |
| `dns_entries` | 5/200/2000 | "Unlimited subdomains" (UI:105) | 5/200/2,000; edge names free |
| `tls_endpoints` | 1/20/200 | "Team layer" (P5:695) | 1/20/200; Community: ≤7-day publishes, verified accounts (owner decision 41) |
| recURd | all | ledger, SSO, exports Team (P5:845) | every tier; member features need Team |

```yaml
# config/all/pro.yml, proposed; model.Pro() reads it. Comments give Community / Pro / Team.
enforce_sidecar_limits: false           # 20.5
evs_unpaid_read_rate: 1mib              # per second: a spent network reads its own repos (20.6)
free:                                   # pro: and team: carry the same sidecar: keys
  sidecar:
    storage: 1gib                       # and the table's other keys
    sidecar_clients: 20                 # 20 / 200 / 2,000 connected at once (20.8)
    config_admissions: 50               # 50 / 500 / 5,000 admissions in the config (§7.9), member devices
                                        # and agents alike, with no member-device cap; whichever device
                                        # admits a page Worker, an admin's included, revokes its member's
                                        # stale page Workers, and the member's own device those it sees,
                                        # freeing their admissions (§7.10, §18.8), and from 90% of the cap
                                        # admins' devices list members' older page Workers to revoke
                                        # (§7.10's cleanup row); ~2,000 members at ~2.5
                                        # each fill a Team's 5,000 (§16.11); the first 1,000 live member
                                        # devices by §7.9's rank are the MLS leaves of the config group and
                                        # the team directory's, later ones and agents read both by wraps
                                        # (D-KEYS-2, D-KEYS-23; owner decisions 114, 144, 182)
    config_statements_per_min: 60       # §7.9's authorization log appends, counted in {acl_<networkId>}q:
    config_statements_burst: 600        # 60 statements a minute in bursts to 600, every tier
    config_statements_per_day: 2000     # 2,000 / 2,000 / 20,000
    config_bases_per_min: 1             # 1 base a minute and 200 a day, every tier; 429 with retry_after_ms
    config_bases_per_day: 200           # beyond any of these, §7.9's exemptions aside
    store_weight: 1                     # 1 / 4 / 16: weight in §11.13's fair share of the metadata write
                                        # budget, priced in drive bytes (owner decision 140)
    evs_drops_per_day: 20               # 20 / 100 / 1,000 drop-history actions a network a UTC day (§11.7),
                                        # 429 past it; cancels never count, so drops cannot block them
    acl_rules: 50                       # 50 / 500 / 5,000 rules in a policy head (§8.8)
    acl_groups: false                   # false / true / true
    acl_requests: true                  # every tier: publishes and forwards depend on requests
    acl_approvers_two: false            # false / false / true (owner decision 74)
    acl_network_shares: false           # false / true / true (§17.9)
    smtp_bytes_per_day: 5mib            # 5 MiB / 1 GiB / 20 GiB, observed (§14.7)
    smtp_recipients_per_message: 5      # 5 / 50 / 100 per message (one message per connection)
    smtp_recipients_per_day: 25         # 25 / 1,000 / 100,000: five per counted connection (§14.7)
    smtp_message_bytes: 5mib            # 5 / 25 / 35 MiB, per connection
    smtp_burst: 5                       # 5 / 50 per 10 min / 2,000 per h
    smtp_concurrent_connections: 1      # 1 / 4 / 32
    mail_inbound_message_bytes: 25mib   # 25 / 50 / 50 MiB (§15.7)
    mail_burners_active: 10             # 10 / 500 / none; the sidecar applies both burner
    mail_burner_creates_per_day: 3      # 3 / 50 / none; keys locally (no server state, §15.9)
    tls_endpoint_concurrent: 256        # 256 / 2,048 / 8,192 (§13.9)
    tls_endpoint_new_per_s: 50          # 50 / 200 / 1,000
    tls_endpoint_mbit_per_s: 20         # 20 / 200 / 1,000
team:                                   # owner decisions 27, 122; pro:'s concurrent_clients, data
                                        # (10tib) and data_period (D-QUOTA-1), and sidecar: as above
  price_usd: {base: 100, seat: 20}      # Stripe holds only price ids (20.9)
  included_seats: 5                     # in the base; Auditor and Billing admin never count (20.5)
  storage_overage_max: 2tib             # metered above sidecar.storage (200gib), refused above this
  credit_line: 10tib                    # the team_credit balance that transfer overage draws, last (20.9)
  overage_usd:                          # a missing price withholds that overage (20.5)
    transfer_tib: 3                     # data_code's 1tib rate (:221-222)
    storage_gib_month: ~                # from §19.6's cost per usable TB of the decided hardware (4 hosts
                                        # of 2 x PM9A3 1.92 TB and 16 x 16 TB HDD, spares included; owner
                                        # decisions 122, 136-139), reviewed yearly
sidecar_abuse:                          # every tier; owners set defaults, §21 tightens
  mail_group_members: 100               # §15.7
  mail_inbound_recipients: 100          # per message; receivers apply it (§15.7)
  probation_dns_entries: 5              # user RRsets while on probation (§21.7, owner decision 97)
  evs_closure_bytes_per_day: 64mib      # each erasing sidecar's own CLOSURE bytes a UTC day, uploads and inline
                                        # records, counted at the storage limit or while spent (20.7)
  evs_closure_bytes_floor: 4mib         # fixed (owner decision 146): no override sets the allowance below it,
                                        # and a floor under 1,088 KiB, one full i/ re-key, counts as 1,088 KiB
  evs_closure_uploads_per_s: 4          # fixed: a network's ?closure=1 uploads at the limit or while spent, in
                                        # equal turns per asking eraser (20.7)
  evs_drop_previews_per_day: 20         # a repo's drop dry runs a UTC day, each a P2 queue entry (§11.13)
  directory_requests_pending: 20        # §16.11's access requests per requesting sidecar: pending, a day and
  directory_requests_per_day: 50        # a run; its daemon refuses past them, and the directory's readers
  directory_requests_per_run: 5         # ignore the excess and alarm
  directory_target_pending: 100         # pending per target; past it, older ones show first and new ones wait
  directory_card_bytes: 16kib           # a card's padded record: <= 16 items in 16,208 B (§16.11)
  # with the caps of §11.10, §12.7, §13.9 (per visitor) and §14.7;
  # forwarding and sockets have none (owner decision 66)
```

### 20.5 Entitlement model

```go
// server/model: pro.go, pro_model.go
type NetworkTier string // "free" (Community), "pro", "team"
func (self *ProConfig) TierFor(tier NetworkTier) *ProTier // Tier(pro bool) remains
func NetworkTierOf(ctx context.Context, networkId server.Id) NetworkTier // highest in-window tier, Pro's cache
func NetworkSidecarLimits(ctx context.Context, networkId server.Id) *ProSidecarLimits // tier, then overrides
```

**Source.** The Team grant writes an in-window balance with `pro=true` and a new nullable `tier='team'`, so `pro` readers stay correct.

**Overrides.** `network_sidecar_limit` rows raise a limit (ops) or tighten one (§21), snapshotted only for networks with rows, like Embed-plan rows (server/model/network_client_limit_model.go:13-25). A row never takes `evs_closure_bytes_per_day` below `evs_closure_bytes_floor`, and none overrides the floor or `evs_closure_uploads_per_s`: §21's `POST /abuse/action` refuses such a row, and `NetworkSidecarLimits` clamps to the floor (owner decision 146) and ignores a pacing row, which every eraser's turn needs (20.7).

**Switch and zero.** Refusals ship dark behind `enforce_sidecar_limits`, like `enforce_concurrent_clients` (config/all/pro.yml:46-57), though an empty balance refuses as escrow does. Enforced, zero means "not included": it refuses creation, never activation, reads, deletes, erasure, export or maintenance pushes (20.7; :23-30); a missing price withholds its overage (:17-21). server/model/pro_absent_test.go pins both states.

**Seats** are `network_member` rows (§7) active within 30 days, except Auditor and Billing admin.

**Becoming Team.** `POST /network/team-create` (§7), then `POST /network/team-checkout`; `invoice.paid` writes the `team` renewal, grant and credit line and calls `UpdateProNetwork`. Invoiced teams use market `manual`; lapse follows Pro.

### 20.6 X11: what counts toward the transfer balance

Decided (Q-QUOTA-2, Q-QUOTA-5, Q-QUOTA-6).

| Traffic | Mode | Payer |
|---|---|---|
| Sidecar↔sidecar, bridge, forwards and remote search (§11.14), one network | Network | the network: reserved at CreateContract, debited from close reports, while relayed; C19 reports a marked requester-indexer pair per §6.10's window, both directions, at a fixed floor (`round`, below) |
| tlsedge→listener, mxedge→receiver | Service (C9) | listening network, by lease |
| sidecar→smtpedge | Service (C9) | sending network, by lease |
| evs transfer (HTTPS) | — | caller's network, by usage batches |
| Cross-network share | FriendsAndFamily | dialer's network, escrowed as Public |

**Leases**, one per edge process and active (network, meter), draw on escrow's per-balance Redis reservations, so both see one balance; they name no host or peer (§13.9 keeps per-host bytes 24 h).

```text
edge (tlsedge, mxedge, smtpedge)   Redis: per-balance reservations      taskworker
 Lease(network, meter) --------> reserve 64 MiB (16 MiB on Community) in 20.9's draw order
 Spend(n): atomic add, no I/O
 at 75% used: renew -----------> reserve the next 64 MiB
 every 60 s: a UsageBatch -------------------------------------------> service_debit_journal
 Close or expiry: release -----> return the unused rest, in reverse     a FlushTransferDebits-style
                                 draw order                             worker debits, no payout
```

**Usage batches** (§11.13, edges' leases): every 60 s each producer sends one `UsageBatch` (20.7), applied once by `batch_id` and flushed on SIGTERM; its stored-byte deltas move 20.7's nightly count; evs re-reads `OverLimit` every 5 s, so writes overshoot by about a minute.

```text
adds     an upload adds its segment's size, a committed push its record's length; evacuation moves records into
         parcels and packs, changing the count only by the log pages packed with them
purge    from format 2, a replaced versionless version's content leaves once deleted or kept only by a hold: the
         committing evs process reports kind-5 segments at seg/ (a staged version's only once its batch was
         evacuated), taskworker staged records as their batch is deleted; the sweep reports nothing, and the
         nightly count catches what only it freed
drop     from format 2, taskworker's drop job subtracts each seg/ object it deletes or moves to held at its stored
         size, within 60 s and once: its batch ids derive from (scan id, cursor range), not from its instance and
         window, and a held object's DELETE after its hold reports nothing; slots, outside the count, report
         nothing, and inline records and packed segments count until compaction (20.7, §11.13)
apply    api inserts service_usage_batch(batch_id) with the batch's service_debit_journal rows and
         network_quota_state deltas in one transaction, the linearization point; a batch_id already present is
         a no-op answering 200
retry    a producer retries an unanswered batch for at most 10 min, then drops it, counted and alerting
         (under-billing only); batch rows live 24 h, past that horizon: one row per producer a minute, not one
         per network
loss     bytes are lost only by an unclean exit (its open window, <= 60 s of that process's metered bytes) and
         by any batch dropped after 10 min unanswered, as in a Postgres outage over 10 min (§19.10); no byte counts
         twice; an edge's reserve behind lost bytes returns within its 24 h lease; 20.7's count corrects stored bytes
```

**Relayed bytes (owner decision 10).**

```text
when     CreateContract for a Network-mode contract between two marked sidecar clients of one network, unless
         the pair already rides a P2P stream (server/model/contract_stream_binding.go); P2P bytes never count
reserve  before the contract transaction, from the network's balances in 20.9's draw order, through the
         per-balance Redis reservations escrow and edge leases use (server/model/subscription_redis_admission.go);
         grant = min(requested, MaxContractTransferByteCount, max(MinContractTransferByteCount,
         available / 8)), signed into the contract, which clients size from (server/controller/
         connect_controller.go:43-58, :1291-1294); the reservation succeeding is the linearization point, and
         its pending marker the retry identity
refuse   no available balance: the network is spent (below), and CreateContract answers InsufficientBalance
         (connect/protocol/transfer.proto:539)
settle   the settled count (the mean of both parties' close reports) debits once, keyed by contract_id in
         service_debit_journal; the rest returns; a contract later bound to a P2P stream returns all of it
round    a pair that a Hello's requester bit marks (feature bit 1, §6.4) is reported per §6.10's 55-minute
         windows: both clients report each direction's window as F = 256 KiB on its first contract, or F plus
         128 KiB steps past it, and 0 on its other contracts, the debit never passing the contracts'
         reservations, whose rest returns at the window's end (C19; owner decisions 176, 188); a window
         then debits 512 KiB whatever up to five pages ran in it: ~10 MiB a day for a phone foregrounded in 20
         separate hours, at most 13.5 MiB a day a pair held in the foreground all day (27 windows), a second
         warmed indexer doubling it, against Community's 30 GiB daily grant (config/all/pro.yml:88-89)
bound    overshoot past the balance is only what Redis loss over-admits, as for leases (20.15); grants shrink as
         the balance nears zero, so 380 pairs at Community's 20 sidecars cannot overdraw 30 GiB
cost     one Redis script per relayed contract (one per 1-256 MiB moved); no Postgres round trip added
```

**Empty balance.** A failed lease or relayed reservation, or an evs debit that finds no balance, marks the network *spent*: new streams get `quota` (§9.6), open ones reset as leases run out (§6.7), mxedge answers temporary failures (§15.6), evs refuses payload-adding uploads and pushes (20.7), and CreateContract refuses relayed sidecar contracts, so remote searches over them fail and phones search what they hold (§11.14); the network reads its own repos at `evs_unpaid_read_rate`, a phone's fallback download of all included, others' not at all.

### 20.7 Enforcement points, counters, downgrade

**Counters.** Capacity other than storage is exact, recounted nightly: rows (entries, custom domains, clients, members) count in their transaction under a transaction-scoped per-network lock (PgBouncer-safe), and grants, admissions and ACL heads as api verifies them (§7.9). Storage counts from objects, below. Rates use one all-or-none Lua script per `{sq_<network_id>}` and `debit_id` (48 h keys), failing open for one window if Redis is lost. Producers cache limits 5 s.

| Limit | Checked at | At the limit | On downgrade |
|---|---|---|---|
| `storage` | evs's over-limit list (20.6) over the nightly stored count (below) | uploads and pushes adding payload refused (Team: above 2 TiB, metered above 200 GiB); maintenance pushes, an erasure's bounded CLOSURE push and its uploads, re-seeding, config and mailcfg pushes within §7.9's limits, reads, deletes and export work | read-only |
| `tls_endpoints`: publish grants per (host, port) | grant activation; `ValidateListen` (§13.9) | refused | grants expire; standing names over quota suspended after 14 days |
| `dns_entries`: user RRsets | record CAS (§12.8) | refused | newest over quota withheld after 14 days |
| custom domains, mail From included (§14.6) | `custom-host-add` (§12.8) | Team only | web hosts and mail From withheld after 14 days; mail hosts keep MX, TLSA and routing |
| `config_admissions`, `acl_*` | the writer's validation, api's verifier (§7.9, §8.8); from 90% of `config_admissions`, admins' devices' cleanup list (§7.10's `cleanup` row) | delta or head refused | existing ones stay; new ones must fit |
| `smtp_*` | smtpedge `{smq_}` script (§14.7) | QUOTA; mail stays queued | next preamble |
| `sidecar_clients`: connected | enrollment and connect, as `concurrent_clients` (server/connect/resident.go:1170-1187) | refused; 4001 at connect | connected clients stay |
| members, SSO (§7.5, §7.6) | §7.5's Team routes, by `NetworkTierOf` | Team only | frozen: sign-in, data kept; invites, roles, IdP, SCIM refused |

**Stored bytes and maintenance at the limit (D-QUOTA-3).**

```text
stored   a repo's stored bytes are the sizes of its seg/, pack/ and hp/ objects as LIST returns them, plus the
         record lengths its head windows and log pages give for versions still in shared batches (no payload
         reads), minus objects only a hold keeps (owner decision 133) and any pack or parcel whose every record a
         newer container's pidx/ entry names, which the nightly pass deletes unless held (§11.13): ciphertext as
         stored, padding and history included, the search index's files too (§11.14), in GiB (20.4); a deleted
         repo counts until shredded (§11.12), group mail once (§15.7), and a replaced versionless version's
         content only until the purge deletes it, a minute after its replacement, or while its batch lives when
         staged (at most 26 h; §11.13), the purge moving the count by usage batches, the nightly pass for what
         only its sweep frees (20.6; owner decision 165); a drop's listed content counts through its window until
         its job deletes it, the objects only a hold keeps leaving the count as above, so a held drop reads and
         bills as finished (owner decision 184), and its inline records and packed segments count until
         compaction (§11.13); the team directory counts like any repo, and its reads debit transfer (20.6), with
         no exemption (owner decision 10)
count    taskworker's nightly pass over each repo's prefixes on its metadata cluster (the one its place/ names,
         owner decision 145) and on the segment cluster is the one segment GC makes (§11.13), so one LIST of each
         prefix serves both; a version counts from head windows and log pages while its batch exists, then from
         the parcel or pack that holds it, or, staged versionless content, from the segment evacuation writes for
         it, if any, so a record mid-evacuation counts twice only until its minute's batches are deleted, and the
         next pass corrects it; the pass runs as shard jobs, each replacing its per-network sums for the night in
         Redis {evsn_<night>} (48 h), and a closing job, once every shard of every metadata cluster has reported,
         writes each network's sum, zero for a network with a count and no sums, while a night that some shard
         never finished, or whose sums Redis lost, leaves the old count (owner decision 198); usage batches move
         the count between passes (20.6); §11.13 gives its cost
limit    at the storage limit (Team: past storage_overage_max, or past storage while storage_gib_month is unset)
         and while spent, evs refuses new payload, segment uploads and pushes naming a new segment or inline
         record alike; it accepts maintenance pushes, which add no payload (CONSUME, BASE, ERASE, PATH_EPOCH and
         its maps, DELETE, deletion and restore, EvsReseed), a CUT, whose one staged record only replaces its
         ref's erasure set (§11.12), and re-seed uploads; an erasure's CLOSURE push, bound
         to its ERASE and re-keying existing derived-field chains under §11.12's rekey rule, each new chain within
         Padmé of the one it replaces, with its payload and its ?closure=1 segment uploads, within the closure
         bounds below; and config and mailcfg pushes within §7.9's limits; so a full network can still erase and
         change policy; the search index's heads stop with the content pushes they ride, and its merges, roll-ups
         and builds add payload and wait until the network is under the limit and not spent, search answering from
         its partitions as they stand; removing its files is a deletion, accepted, and the settings version that
         turns it off, a new record, lands once under the limit and not spent (§11.14); accepted bytes count and
         debit as usual; in v0 an erasure frees no stored bytes; from format 2 (v1), deleting versionless files
         adds no payload, so it is accepted at the limit and frees their bytes a minute later, staged ones with
         their batch, and a DROP push that uploads no segment (its written checkpoints inline within §11.12's
         rekey bound, chunk sets re-cited, or boundaries removed) is accepted as maintenance, its index rewrites
         waiting as merges do, while one whose written checkpoint needs an upload gets QuotaRefusal and a cancel,
         adding no payload, is accepted (§11.13); other ciphertext stays until v1's compaction (§11.12)
closure  at the limit and while spent, §11.12's rekey row takes an eraser's ?closure=1 uploads, each at most
         1,088 KiB, one padded §15.7 i/ segment or §11.14 index file (else QuotaRefusal), only within its own 60 a
         minute, which {sq_} counts per eraser (the erasing sidecar, its token's ur_sidecar_id, §11.8), and within
         its turn of the network's pacing, which takes at most R uploads a second however many erasers ask at
         once, R being evs_closure_uploads_per_s (4), in equal turns: with k of the network's erasers asking for
         one, a refused one counting until its turn, each takes one at most every k/R s; past either it answers
         that upload 429 with retry_after_ms; {sq_} counts the network's ERASE, CUT and CLOSURE pushes against
         the network's 60 a minute only to class them: P0 within it, and past it a push queues as P1 and commits
         (§11.12's push row, §11.13)
allow    each erasing sidecar has its own evs_closure_bytes_per_day a UTC day (20.4), never below
         evs_closure_bytes_floor whatever a row (20.5), §21 or an unusable value sets; {sq_} counts against it
         that sidecar's closure bytes, each of its ?closure=1 uploads and its CLOSURE pushes' inline records, and
         past it answers that upload or push 429 with retry_after_ms to the next 00:00 UTC, since a CLOSURE whose
         ERASE never follows keeps the replaced version readable; no other sidecar spends it, and no drop does:
         a DROP push writes no CLOSURE and takes no ?closure=1 upload (owner decision 146)
wait     an allowance covers ⌊allowance / 1,088 KiB⌋ full i/ segment or index file re-keys a UTC day, 60 by
         default and 3 at the floor; an eraser sizes each CLOSURE, with its ERASE, to what remains of its
         allowance (QuotaLimits gives the allowance, and only its own closures spend it), splitting a larger
         erasure into such pairs, since a push adopts an upload only within 24 h (§11.13); the pacing gives each
         asking eraser a turn at least every k/R s (~21 min with all 5,000 of a Team's admissions asking, still 69
         turns a day, above the default allowance's 60 re-keys); so at the floor a backlog re-keying n full
         segments, refused for bytes, commits its last pair within three turns of the ⌈n/3⌉-th 00:00 UTC after the
         refusal, under ⌈n/3⌉ days and three turns however many erasers wait, since none spends another's
         allowance or turns (closure row; §11.12's rekey row), and at once when the network is below the limit and
         not spent; in general an erasure with B closure bytes left when its allowance first refuses it commits
         its last pair after at most the ⌈B / (A - 1,088 KiB)⌉-th 00:00 UTC that follows, A its allowance, plus
         one turn per upload of that day (§11.13's wait row), B summing every i/ segment and index file version it
         re-keys: with the search index on, one message or record entry is one document per 1 MiB chunk of its
         text, each with its slots, large entry or shards and any copy a backfill, late companion push or hold
         made (§11.14's bound), so only a one-document entry with no copy waits at most for the next 00:00 UTC and
         two turns; its first ERASE takes the entry's own keys at once, its CUT is maintenance, and each pair's
         entries keep their index fields and postings openable to key holders, masked in search, until its ERASE
         commits; the eraser's device shows the estimate (§5.4's erasure event)
note     §16.8's erasure entry, a new record, waits until the network is below the limit and not spent, the
         committed ERASE standing as the record until then
```

**Refusals** carry `QuotaRefusal`; usage arrives in `UsageBatch`es:

```go
// sidecar/api_quota.go, every leg, no connect type (§4.4, §5.4): QuotaRefusal and QuotaLimits, which
// SidecarApi also decodes in the page Worker; QuotaLimits (Quota.Limits's result, GET /sidecar/limits's body)
// carries the network's effective limits after network_sidecar_limit rows (NetworkSidecarLimits, 20.5), the
// sidecar_abuse: directory_* keys among them, which §16.11's requesting daemons and directory readers apply
// (D-QUOTA-11), so §21.7's tightening reaches them.
// A refusal maps to 402 with x402 terms when a purchase lifts the limit, 429 with Retry-After when a
// window resets (server/controller/x402_controller.go:849; server/router/handler_utils.go:604-609),
// else Error{RESOURCE_EXHAUSTED} (§6.5) or stream quota.
type QuotaRefusal struct {
	LimitKey     string `json:"limit_key"`
	Limit        int64  `json:"limit"`
	Used         int64  `json:"used"`
	RetryAfterMs uint32 `json:"retry_after_ms"`
	Upgrade      bool   `json:"upgrade"` // a purchase or a higher tier lifts it
}

// sidecar/host_quota.go, //go:build !sidecar_http like every host_ file, since no hosted server engine runs in
// the page Worker (§4.4): ServiceHost.Quota (§4.5), implemented by server.
type UsageBatch struct {
	BatchId     connect.Id    // first 16 B of SHA-256(producerInstanceId || windowSeq): the retry identity;
	                          // producerInstanceId is 16 random bytes drawn at process start; a drop job's
	                          // batch: of SHA-256(scanId || cursor range) instead (20.6)
	Producer    string        // "evs", "tlsedge", "mxedge", "smtpedge"; "taskworker" for evacuation's staged
	                          // frees and the drop job's deletes and holds
	WindowStart time.Time     // 60 s windows
	Events      []*UsageEvent // per network and meter: transfer bytes, or a repo's stored-byte delta
}
type Quota interface {
	Limits(ctx context.Context, networkId connect.Id) (*QuotaLimits, error)
	CountRate(ctx context.Context, networkId connect.Id, keyAmounts map[string]int64, debitId connect.Id) (*QuotaRefusal, error)
	Lease(ctx context.Context, networkId connect.Id, meter string) (QuotaLease, *QuotaRefusal, error)
	ReportUsage(ctx context.Context, batch *UsageBatch) error // every 60 s per producer; idempotent per BatchId (20.6)
	OverLimit(ctx context.Context) (*QuotaOverLimit, error)   // evs, every 5 s: networks over their storage limit, or spent
}
type QuotaLease interface {
	Spend(byteCount int64) bool // atomic, no I/O
	Close()                     // settle, release
}
```

### 20.8 Counting sidecar clients (X10)

Owner decision 4: one client per sidecar, a child of the device client in its network, else top-level; one sidecar per device and network (owner decision 23), plus one per agent with its own reach (§5.5). Designs assume enforcement is on.

| Client | `concurrent_clients` | 100 create cap, peer valve | `sidecar_clients` |
|---|---|---|---|
| App device client | counts | counts | — |
| Sidecar child of a device client | exempt | — | counts |
| A sidecar's forwarding client and its window clients (§18.6; owner decision 197) | exempt | exempt | — (its sidecar counts once) |
| Standalone, declared no-egress (the extension worker too, §18.4) | exempt | exempt | counts |
| Standalone, with `ur proxy` or public exits | counts | counts | counts |

**Declaration** (§5.6, §7.7). A sidecar declares no-egress unless `ur proxy` or a public exit is set; the client JWT carries it, so connect needs no query, and window clients inherit it. `CreateContract` refuses such clients Public contracts (§8.10).

**Peer list.** Declared clients get a new peer category, unlisted and without peer subscriptions like isolated clients (server/model/peer_model.go:59-76), which the create cap's and peer valve's `NOT EXISTS` clauses (20.3) also skip. Other clients' create cap moves into pro.yml per tier.

### 20.9 Team billing and abuse limits

**Post-paid (owner decisions 92, 122).** One Stripe subscription per Team network prices the base, seats (graduated above `included_seats`; meter `team_seats`, formula `last`) and overage at 20.4's `team:` prices; Stripe holds only price ids, in `config/<env>/stripe.yml` as for Pro (server/controller/subscription_stripe_controller.go:64-65), and checkout refuses one whose amount differs. Transfer overage draws a 10 TiB credit line (`grant_kind` `team_credit`) that every draw uses last (D-QUOTA-9), metered as its daily GiB (pre-aggregated daily, `sum`; Meters below) at the data-pack rate, $3 per TiB (config/all/pro.yml:221-222). Settlement pays providers from balance revenue, so the line carries `net_revenue_nano_cents` at that rate, a per-period risk for URnetwork. Storage over 200 GiB is metered as daily GiB-days (pre-aggregated daily, `sum`), a GiB-day at 12/365 of the GiB-month price. `invoice.payment_failed`, like an exhausted line, stops renewal and refuses as an empty balance; `invoice.paid` renews. `team_subscription` (MG6) records each Team's Stripe subscription and customer ids, billing anchor and start: the first `invoice.paid` writes it, `customer.subscription.deleted` ends it, and the hourly reconciler can repair it from Stripe. `RefreshTeamTransferBalances` grants a period only to a Team whose row is live, with no unresolved payment failure, at the row's anchor, and the meter reports, which only such Teams get, take their customer and start from it (owner decision 199).

**Draw order (D-QUOTA-9).** One comparator orders every draw of a payer's transfer balances and, reversed, every return:

```go
// server/model: the only order of a payer's transfer balances, for escrow, Redis reservations, leases and settlement
func escrowDrawLess(a *escrowTransferBalance, b *escrowTransferBalance) bool // lexicographic on (isCredit, endTime,
                                                                              // startTime, balanceId), false first
```

```text
flag     isCredit is grant_kind IS NOT DISTINCT FROM 'team_credit', which every loader selects into
         escrowTransferBalance (server/model/prober_grant_selection_model.go:24-31); grant_kind is NULL on older
         balances (server/db_migrations.go:9578), and `grant_kind = 'team_credit'` would sort those NULLs after
         the line in an ascending ORDER BY
sites    contract escrow's sort (server/model/subscription_model.go:1782-1796); the Redis admission keyset
         (server/model/subscription_redis_selection.go:377-394) and the zero-byte anchor's read
         (prober_grant_selection_model.go:199-200), each ordered and keyed by the flag first, on a concurrent
         index (network_id, flag, end_time, start_time, balance_id) WHERE active beside today's
         (server/db_migrations.go:9339-9350), so a page stays one index scan; settlement's escrow read
         (subscription_model.go:3967-3987), ordered by all four keys; edge leases and relayed reservations
         (20.6); returns in reverse; the spread over large free grants (subscription_redis_selection.go:51-54)
         never takes the line, which carries revenue
E-a      a team_credit balance is drawn only when every other in-window balance of the payer has nothing available
E-b      a settlement keeps bytes in draw order and returns the rest in reverse, so the line pays only for bytes
         beyond the included balances
E-c      each byte the line pays appears once in that day's transfer-overage row (Meters, below)
E-d      a reservation on the line ends as a debit, or returns within its 24 h lease
         (server/model/subscription_redis_admission.go:38), so nothing holds the line without a debit
E-e      providers are paid at settlement from the line's net_revenue_nano_cents, the overage rate
```

**Gate (owner decision 92).** Escrow admission runs before every transfer pair (server/model/subscription_model.go:1727-1731). By M6's entry, which freezes the order (D-QUOTA-9; §23.6, §23.8), FS-46 (E-a to E-e) and §22.8's escrow benchmark pass: admission and settlement in this draw order at 2× their Y1 rates on production settings, with p99 admission latency and settlement throughput within 5% of main's baseline and no added Postgres round trip per admission. The benchmark reruns at M6's exit (§22.10). Every site switches to the comparator on sidecar.yml's `escrow_draw_order` gate (§19.11, D-OPS-10), off in main until M6's Gn-out registers MG6's index (§19.7); Team checkout, whose `invoice.paid` writes the first `team_credit` balance (20.5), opens only once every site has reread the gate on (60 s), and the gate never turns off while such a balance is in window, or E-a fails.

**Meters** (taskworker, daily):

```text
meters     transfer overage (GiB, sum) and storage overage (GiB-days, sum), each with event ingestion
           pre-aggregated daily (event_time_window day; stripe-go v82.5.1 billing_meter.go:24-35): Stripe keeps a
           day's most recently received event per customer, so a re-send replaces and never adds; seats (last);
           all configured once before M6, since a meter cannot change after creation except its display name
anchor     a Team Checkout session expires in 1 h (expires_at) and sets subscription_data.billing_cycle_anchor
           to the first 00:00:00 UTC after that (the pinned SDK's Checkout takes a timestamp, not
           billing_cycle_anchor_config: checkout_session.go:2486-2490), so periods start at 00:00:00 UTC and
           no UTC day spans two periods
grace      an invoice rule ("has a metered price" and "from a subscription cycle") delays finalization by 72 h,
           Stripe's maximum, for every Team invoice; prices change only at a period boundary, since a mid-period
           change drops grace-period usage
row        stripe_meter_report(network_id, meter, usage_day, version, identifier, value, state, attempts,
           next_time), primary key (network_id, meter, usage_day, version); value is the day's canonical quantity,
           fixed by RollupServiceUsage after the UTC day closes (a debit counts on the day it was applied);
           identifier = SHA-256(network_id || meter || usage_day || version)
states     queued -> sending -> sent | uncertain | failed | missed
send       timestamp: the later of 12:00:00 UTC of usage_day and 1 s after the subscription's start, so the
           first, partial day's event lies inside the first period; at most one send in flight per (customer,
           meter), Stripe's limit; the linearization point is Stripe's receipt of the day's newest version
outcomes   200, or a refusal naming a duplicate identifier: sent; any other 4xx: failed, alert; a timeout, 429 or
           5xx: uncertain, re-sent with the same identifier and value with backoff while the day is inside its
           invoice's grace and Stripe's 35-day timestamp window (stripe-go v82.5.1 billing_meterevent.go:16-20)
correct    a changed value is a new version, sent only once every earlier version's outcome is known
missed     a row unsent 6 h before its invoice finalizes alerts billing; one still unsent at finalization is
           missed: unbilled, counted, never added to a later invoice
audit      a daily job compares sent rows with meter event summaries; no re-send depends on a summary
billed     per (network, meter, period), the billed quantity is the sum of its rows' newest values, so no
           outcome order bills a day twice (FS-43)
cost       year two's ~1,000 Team networks x 3 meters: ~3,000 events a day; hourly windows would send 24 times as many
```

**Abuse limits:** 20.4's `sidecar_abuse:` caps and §14.7's send gate (D-QUOTA-7).

### 20.10 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Debit after use, with overdraft | no reservation | negative balances; late refusal | edges and relayed bytes: rejected (owner decision 10's leases and close reports); evs: chosen (owner decision 2) |
| Checkpointed debits on open relayed contracts | debits while open | a write per checkpoint; overshoot still grows with open pairs | rejected: reserve at CreateContract (20.6) |
| Re-send meter events after reading Stripe's summaries | no versioned rows | summaries lag, so a retry past the 24 h dedup window can bill twice | rejected: pre-aggregated daily meters (20.9) |
| Draw the credit line in its own query after escrow | today's order kept | one more Postgres round trip on each admission that reaches the line | rejected: one comparator and index (D-QUOTA-9) |
| A network-wide daily closure byte cap | bounds a network's closure bytes | one eraser's closures spend the others' allowance (owner decision 146) | rejected: per-eraser allowances, with 20.7's equal-turn pacing for rates |
| `network_plan` table | explicit | a second entitlement source (server/model/pro_model.go:15-16) | rejected |

### 20.11 Decisions proposed

**D-QUOTA-1 (proposed).** Tiers `free` (Community), `pro` and `team` resolve only in pro_model.go from in-window balances (`team` implies `pro`), with per-tier `sidecar:` blocks. *Why:* one entitlement source, Pro's cache and grace.

**D-QUOTA-2 (proposed).** Limits and prices come only from pro.yml, with `network_sidecar_limit` overrides; limits ship dark, unusable values refuse only creation, and a missing price withholds its overage (20.5). *Why:* R-QUOTA-5; owner decision 122.

**D-QUOTA-3 (proposed).** Capacity other than storage counts exactly; storage counts nightly from stored object sizes and batch-resident record lengths, moved between passes by usage batches, and at the limit only payload-adding uploads and pushes stop, except re-seeding, an erasure's CLOSURE push and its uploads within the erasing sidecar's own rate, daily allowance (never below its fixed floor; owner decision 146) and equal turn of the network's closure pacing, an upload-free DROP push (D-QUOTA-12), an erasure's CUT (§11.12), and config and mailcfg pushes within §7.9's limits; rates use one atomic Lua script per network (20.7). *Why:* exact counts survive Redis loss; stateless evs has no counter to lock (owner decision 2); maintenance and erasure must work in a full network, no eraser can spend another's allowance or turns, and paced closures stay within the HDD sets' rates (20.15).

**D-QUOTA-4 (proposed).** Service contracts escrow nothing; edges bill by lease, relayed sidecar contracts by a reservation at CreateContract settled from close reports, evs by usage batches, all into `service_debit_journal` without payout (20.6). *Why:* one balance view, refusal before overdraft, no per-frame I/O.

**D-QUOTA-5 (proposed).** Refusals are 20.7's `QuotaRefusal`; agents pay only under I-8. *Why:* existing conventions; spending is outward.

**D-QUOTA-6 (proposed).** Downgrade follows 20.7: nothing deleted, no inbound address broken, growth frozen. *Why:* a lapsed card must not cost data or a burner's password resets.

**D-QUOTA-7 (proposed).** Abuse limits (`sidecar_abuse:`) are separate from quotas, never sold, equal on every tier and tightened per network by §21; limits derived from a quota grow with it. *Why:* reputation and platform risk do not scale with payment.

**D-QUOTA-8 (proposed).** Taskworker rolls producers' usage into daily `network_service_usage` rows for `GET /network/usage`, invoices and meters; each day's row is sent to a pre-aggregated daily Stripe meter, so a re-send replaces it. *Why:* one record for display, billing and reconciliation, and a lost response must never bill twice.

**D-QUOTA-9 (proposed).** One comparator, `escrowDrawLess`, orders every draw and return of transfer balances, with `team_credit` last (20.9). *Why:* owner decision 92 draws the line last; any site with its own order would bill overage while a data pack remains.

**D-QUOTA-10 (proposed).** The search index counts as storage like any evs bytes (§11.14), including replaced heads while their batch lives (owner decision 165), and is shown apart in `ur status`. Deleting its files is accepted at the limit; the settings version that turns it off, its merges, roll-ups and builds wait until the network is under the limit and not spent. *Why:* the bytes are real, and storage is a tier quota counting every stored evs byte (owner decision 10; 20.7's `stored` row); search keeps answering from the partitions as they stand.

**D-QUOTA-11 (proposed).** `sidecar_abuse:` limits directory requests per sidecar (20 pending, 50 a day, 5 a run) and per target (100 pending), applied by the requesting daemon and the directory's readers, since no server sees a request's content (§16.11). Every directory byte counts toward storage, and every download debits transfer (owner decision 10). *Why:* requests reach persons, and spam costs attention, not bytes.

**D-QUOTA-12 (proposed).** A drop frees bytes as its job deletes them or moves them to held, counted once by usage batch; at the limit it is a maintenance push only when it uploads nothing; its cancel always is one, and never counts against `evs_drops_per_day`. *Why:* owner decisions 10, 173 and 184; freeing space must not need space, and any repo admin may cancel through the window (owner decision 183).

### 20.12 Open questions

**Q-QUOTA-1.** [X16] Which tier numbers, and what shape of Team price? **Decided by owner 2026-11-03 (owner decision 27):** (b), PLAN's quotas and 20.4's Team price, overage only on transfer and storage, and replies-only (UI:76-78) dropped as unenforceable on ciphertext. **Decided by owner 2026-11-04 (owner decision 122):** (a), existing rates: transfer at the data-pack rate ($3 per TiB), storage per GiB-month from §19.6's cost per usable TB of the decided hardware (owner decisions 136-139), reviewed yearly (20.9); so storage counts in GiB (20.13). *Residual:* none.

**Q-QUOTA-2.** [X11] What does "all of these count towards transfer balance" (PLAN.md:353) mean mechanically? **Decided by owner 2026-11-03 (owner decision 10):** (a), traffic bytes count; storage, sends, entries and endpoints are quotas (20.6). *Residual:* none.

**Q-QUOTA-3.** How is Team overage billed, and when are providers paid? **Decided by owner 2026-11-03 (owner decision 92):** (a), post-paid Stripe meters invoiced monthly, with a credit line drawn last so settlement pays providers at once (20.9). *Residual:* **Closed by peer review 2026-11-04:** 20.9's draw order (D-QUOTA-9) puts the credit line last on every draw and reverses it on every return, under invariants E-a to E-e (FS-46); with the benchmark (p99 within 5% at 2× year one, no added Postgres round trip), it gates M6's entry (§22.8).

**Q-QUOTA-4.** [X10] Cross-cutting (Q-CORE-2). How do sidecar clients count? **Decided by owner 2026-11-03 (owner decision 4):** (b), 20.8's rule. *Residual:* none.

**Q-QUOTA-5.** Cross-cutting (Q-PROTO-3, D-ACL-10). Who pays for cross-network share traffic? **Decided by owner 2026-11-03 (owner decision 11):** (a), the dialing network, by Public's source-pays escrow, outside the egress index (20.6). *Residual:* none.

**Q-QUOTA-6.** Cross-cutting (§6, §17). Do relayed same-network sidecar bytes count (D-PROTO-10)? **Decided by owner 2026-11-03 (owner decision 10):** (a), reserved at CreateContract and debited by close report from M2 (20.6, §23.4). *Residual:* none.

### 20.13 Departures from PLAN.md

- **PLAN.md:350, :356-358.** Team gains seats; only transfer and storage have overage; sends, entries and endpoints are hard caps (Q-QUOTA-1).
- **PLAN.md:353, :359.** Capacity is not converted to bytes, and after C3 direct P2P bytes between same-network sidecars do not count (Q-QUOTA-2, Q-QUOTA-6).
- **PLAN.md:355.** Storage is in GiB, pro.yml's binary unit (config/all/pro.yml:32-34) and owner decision 122's price unit, 7.4% above PLAN's GB (Q-QUOTA-1).
- **Not PLAN.md.** sidecar/design/pitch5.html:849's "Agents are never metered" changes: agents' bytes are debited (Q-QUOTA-2).

### 20.14 Interfaces

- **Provides:** `NetworkTierOf`, `ProConfig.TierFor`, `NetworkSidecarLimits`; `ServiceHost.Quota`, `UsageBatch`, and every leg's `QuotaRefusal` and `QuotaLimits`; 20.4's limits and prices; the stored-byte count; usage rollups; 20.8's counting; `escrowDrawLess`; Team checkout and meters.
- **Consumes:** §4 `ServiceHost`, C9, C19; §5.6, §7.7 the declaration; §6 modes, stream codes, Hello's requester bit; §7 Team tables, deltas, admissions; §8 grant activation, contract gate, `acl_*` checks; §9 `ValidateListen`; §11.13 usage batches (the purge's, evacuation's and drop job's frees included), the nightly pass and fair share; §11.14's index files; §12 entry counts; §13-§15 leases; §16 approvals; §19.6's cost per usable TB; §21 overrides; server/model/subscription_redis_admission.go's reservations.
- **Subprotocol messages:** none new; reuses `Error{RESOURCE_EXHAUSTED}` (§6.5), the stream codes and topic `team` (§6.8).
- **API routes:** `GET /network/usage` (Network, read roles; usage and limits); `GET /sidecar/limits` (Client; `QuotaLimits` for local pre-checks); `POST /network/team-checkout` (Network, Owner or Billing admin).
- **Tables** (api; additive; §2.8 api-13):

```text
table or key                                                             kept
transfer_balance.tier varchar(16) NULL                                   with its balance
transfer_balance index (network_id, (grant_kind IS NOT DISTINCT FROM     with the table; built concurrently
  'team_credit'), end_time, start_time, balance_id) WHERE active
network_sidecar_limit(network_id, limit_key, limit_value, reason)        until lifted
network_quota_state(network_id, stored_byte_count, storage_over,         until its network is deleted
  spent_time)
network_service_usage(network_id, usage_day, meter, quantity)            13 months
service_debit_journal(usage_id, balance_id, meter, debit_byte_count,     deleted once applied, with
  batch_id, applied)                                                     transfer_debit_journal's delete guard
                                                                         (server/db_transfer_debit_journal.go:3-6);
                                                                         its batch's id lives 24 h
service_usage_batch(batch_id PK, producer, window_start, applied_time)   24 h
stripe_meter_report(network_id, meter, usage_day, version, identifier,   13 months
  value, state, attempts, next_time)
team_subscription(network_id, subscription_id, customer_id,              until its network is deleted
  anchor_time, start_time, end_time NULL)
Redis {sq_<network_id>}: rates, and each erasing sidecar's closure       48 h
  uploads a minute, closure bytes a UTC day, last closure ask and next
  turn, which give k (20.7)
```

- **Services and config:** the 20.4 keys in pro.yml; sidecar.yml's `escrow_draw_order` gate (§19.11, 20.9); Team price ids in `config/<env>/stripe.yml`; the three meters, created once before M6; a Stripe invoice-finalization rule (72 h, metered subscription-cycle invoices); `POST /network/team-checkout`'s 1 h session with `subscription_data.billing_cycle_anchor` at 00:00:00 UTC (20.9); taskworker jobs `RefreshTeamTransferBalances`, `RollupServiceUsage`, `ReportStripeMeters`, `ReconcileSidecarCounters`.
- **Assumptions about other sections:** §14 and §15 bill by lease. §7.5's Team routes check `NetworkTierOf`; §7 carries the declaration in the client JWT and bounds admissions by `config_admissions`, with no member-device cap (§7.9; owner decision 144). §11.13 derives pack and parcel ids from their bytes, and its nightly pass lists each repo's prefixes for 20.7's count and deletes a pack or parcel whose every record a newer container's entries name; held-only objects and such containers never count, as FI-13(c) and FS-60 check; its fair share weighs networks by `store_weight`. §18.10's excluded list names the `host_` files, as §4.4 does. §2.8's api-13 and §19.7's migration groups carry these tables (`service_usage_batch` in MG2; the `team_credit` index, built concurrently, in MG6, pending under `sidecar_pending` from M4's dark build until M6's Gn-out registers it, the comparator's `escrow_draw_order` gate off in main until then; §19.7, §23.4, D-PHASE-7). FS-46 and 20.9's benchmark gate M6's entry in §22.8, §22.10, §23.6 and §23.8; FI-13(a) and FS-44 cover 20.6's 10-min drop; FS-47 covers 20.7's closure bounds (an ERASE or CLOSURE push past the network's rate committing as P1; 429 for an eraser's closure uploads past its own rate or turn and for its bytes past its own allowance, another eraser's passing; k erasers asking each served every k/4 s, none starved, the network at most 4 a second; no row below the floor or changing the pacing) and the waiting `erasure` entry; §11.12, §11.13 and §11.20 cite 20.7's allowance, pacing and 429, and §11.13 and §15.7 its wait at the floor, stated from an erasure's closure bytes, not per message (FS-112). §11.13's purge and evacuation report the versionless content they free, as 20.6 says and FS-71 tests, and its drop job the seg/ objects it deletes or holds, once, as FS-90 and FS-92 test; §11.8 answers a drop past `evs_drops_per_day` 429, never a cancel; §16.11's daemons and readers apply 20.4's `directory_*` keys, read through `QuotaLimits`; §11.14's files count as any file (D-QUOTA-10).

### 20.15 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Ranking `team_credit` last slows escrow on the hot path | Medium | High | 20.9's gate; one index keeps each keyset page one scan |
| Redis loss over-admits leases, relayed reservations and rates, or reservations confuse the contract reconciler | Medium | Medium | lease size; grants that shrink near zero; own namespace; nightly reconcile; FS-45 |
| Soft evs limits overshoot by about a minute | Medium | Low | 5 s over-limit reads; 20.7's nightly count; batch-resident bytes from head windows until each hourly evacuation deletes their batch |
| Closure bytes land on both clusters: each `?closure=1` upload is one HDD PUT, up to two writes on each of its set's 16 drives (136 KiB shards, cmd/erasure-coding.go:121-131, past §11.3's 128 KiB inline bound), and CLOSURE pushes' inline records and staged index files ride their NVMe batch until evacuation moves or drops them; unpaced, an eraser could spend its day's 64 MiB in a minute, 5,000 uploads a second for a Team's 5,000 erasers, 12-20× the HDD sets' ~8,000-12,800 drive operations a second (§19.6), though that day's ~312.5 GiB averages ~3.5 a second, ~1%; on NVMe, CLOSURE pushes within the network's 60 a minute are P0, at most ~0.3 MiB a second a drive a network (under 2% of a set's 0.8 DWPD), which §11.13's budget does not bound across networks (owner decision 186), and P1 past it, inside §11.13's budget | Low | Medium | 20.7's pacing: at most 4 uploads a second a network (~1-1.6% of the HDD sets) in equal turns, so no eraser starves another and each of 5,000 asking still gets 69 turns a day; at the floor, n full re-keys wait under ⌈n/3⌉ days and three turns, their entries openable meanwhile, and none waits below the limit (owner decision 146) |
| A network's closure bytes scale with its erasers, not its live admissions: §7.9 exempts revocations, so a day's erasers reach its admissions plus that day's admission statements, and in v0 every closure byte stays stored past the limit: ~3.1 GiB a day for a Community network's 50 erasers (~128 GiB with churn to 2,050), ~312.5 GiB for a Team's 5,000 (with churn, pacing caps its uploads at ~358 GiB) | Low | Medium | each erasure re-keys only its entry's chains, so growth ends with the network's entries; §21.7 tightens the allowance to its 4 MiB floor (200 MiB a day for 50 erasers) and the network's admission statements; v1's compaction frees erased ciphertext, and format 2's index rewrites free their replaced versions a minute later, staged ones with their batch |
| The search index, on by default, uses storage: ~15-30% of the text it indexes (~5-15% of a mailbox's stored bytes, ~20-40% of a record repo's), plus replaced heads for up to 26 h | Certain | Low | `ur status` shows its share; repo admins turn it off; deleting its files is accepted at the limit (D-QUOTA-10) |
| A declared sidecar gets VPN egress | Low | High | CreateContract refusal; §22 test |
| Storage priced at §19.6's cost per usable TB recovers ~60% of cost: at 70% fill and 15% overhead, ~310 of the HDDs' 512 TB holds data (owner decision 116), and each next metadata cluster (owner decision 145) adds cost without HDD space | Medium | Low | yearly review from §19.6's current hardware (owner decision 122); Team-only, ≤2 TiB a network |

### 20.16 Phasing

- **v0 (personal networks):** free and pro tiers, `sidecar:` blocks, overrides, counters, refusals and 20.8 (M1); the debit path, leases, usage batches, relayed reservations and the nightly stored count with maintenance at the limit, the per-eraser closure allowance and the network's closure pacing (M2; FS-44, FS-45, FS-47); C9 lease spending by tlsedge (M5), mxedge (M7) and smtpedge with the `smtp_*` quotas (M9, owner decision 35); usage rollups (§23.4).
- **v1 (Team at M6, format 2 at M10):** D-QUOTA-9's comparator, index and 20.9's benchmark harness, built dark in M4 (§23.4), its index pending in MG6 until M6's Gn-out (§19.7; 20.9's gate), so M6's entry runs that benchmark and FS-46 on built code; then the `team` tier and its prices, seats, checkout, meters, credit line, downgrade jobs and share escrow; 5,000 `config_admissions` with no member-device cap (owner decision 144); the team directory's request limits and accounting at M6 (D-QUOTA-11), its card cap with cards at M10 (D-PHASE-11); at M10 (owner decision 169), with storage format 2, the search index counting as storage (§11.14), versionless content's counting and freeing (20.6, §11.13), the drop's rates, `limit` rule and freed-byte reports (D-QUOTA-12), freeing nothing until §19.11's `drop` gate turns on (D-PHASE-12), and remote search's relayed bytes with C19's rounding, which add no counter or tier key (20.6).
- **Later:** auto-recharge of Community and Pro data packs (Team is post-paid), invoicing above 25 seats, the assurance stage (§23.4).
