## 22. Testing and verification

### 22.1 Purpose and scope

This section owns verification: tiers, harness, hot-path gates, fuzzing, scenarios, privacy, admission and revocation suites, load, soak, the fault-schedule program, storage benchmarks, conformance, platform budgets and internal review gates. Sections keep their targets and mechanisms; this one names each target's test, invariant and gate. §19 owns environments, §23 milestones and the gate map.

### 22.2 Requirements

| id | requirement | source |
|---|---|---|
| R-TEST-1 | Bug fixes get deterministic root-cause regression tests on synthetic data | connect/CODESTYLE.md:77, :200-212 |
| R-TEST-2 | Benchmarks use production settings and count allocations; inline paths prove no PostgreSQL | connect/CODESTYLE.md:113, :215; I-12 |
| R-TEST-3 | Servers never receive plaintext or keys, except §2.8 mx-4's report intake (D-TRUST-4); §2.8's list stays true | CONVENTIONS §0; I-2, I-18 |
| R-TEST-4 | A removed member reads nothing new | PLAN.md:149, :167; I-15 |
| R-TEST-5 | §10.4's MLS subset passes vectors, differential tests and fuzzing | owner decision 43; D-KEYS-10 |
| R-TEST-6 | No audit gates a freeze or the "end-to-end encrypted" claim | owner decisions 99, 119 |
| R-TEST-7 | Verify §8.9, §10.6, §11.13 with its drive-write budget on the PM9A3 set, §11.15, §13.5, §17.5 and D-SMTP-16; publish the twenty-agent test | sidecar/design/market2.md:513-531; owner decisions 137-140 |
| R-TEST-8 | Gate platform budgets; census before burners | §18.4, §18.10; D-MAIL-9 |
| R-TEST-9 | A failed attempt fails the run despite a passing retry | tests/RUN-ALL.md:956 |
| R-TEST-10 | Versionless purges, the index and search pass models and an oracle: no purge before its replacement is certain, results equal a scan of newest versions, index bytes are equal on every build leg, and a query leaves a device only end to end to a designated indexer §11.14 lets answer it | owner decisions 151-166, 175, 177, 178 |
| R-TEST-11 | Format 2's mix, with the index on in every eligible repo, meets the drive-write budget at 2× year one on the production block size | owner decisions 140, 156, 163, 174 |
| R-TEST-12 | Remote search's results pass the oracle, its frames have one size per kind, and evs sees no request from it | owner decisions 175, 178 |

### 22.3 What exists today

Unimportable Required test helpers (connect/transfer_encrypt_contract_test.go:21, :146); postgres:18 and one redis:8-alpine locally, no object store (server/local/docker-compose.yml:33-142), while production's Redis Cluster runs 48 masters without replicas (xops/main/ansible/REDIS.md:3) on 8.10.2 (xops/main/ansible/playbook-redis-clusters.yml:634); 4 reruns unless fail-fast (server/test_util.go:764-781); `DenyPostgresForTest` (server/db_packet_guard_test_support.go:14); an in-process `NewExchange` (server/connect/resident.go:902); Apple ceilings (sdk/build/check_apple_size.sh:7-9); wasm in Node (tests/TEST-ALL.md:10); PERFVAR (server/connect/perfvar/PERFVAR.md:5-12); LOWBAR (connect/LOWBAR.md:6-13); Playwright (mmm/ur.io/test-main.sh:18); no iPhone in acceptance (tests/ACCEPTANCE-TEST.md:15).

### 22.4 Tiers and harness

- **T1**, sidecar on all §4.7 legs: unit, property, vectors, fuzz seeds.
- **T2**, `sidecartest`: sidecars and engines in one process; fake stores; injected clock, store results and barriers.
- **T3**, server hosting engines on the stores below with Postgres and the in-process exchange; store suites and fault schedules.
- **T4**, sdk: binding gates, wasm in Node, size, memory, and from M10 phone search on the ios32 and Android surrogates and page search in wasm (FS-77), with phone remote search on those surrogates from the later of M10's and M8's exits (FS-83).
- **T5**, a PERFVAR-style host and M2's staging cluster on the production hosts' PM9A3 set (§19.11): 22.8; format 2's drive-write gate needs no T5 drives (D-TEST-13).
- **T6**, `tests/test-main.sh` in main, dark (owner decisions 91, 118): 22.9, per milestone.

```go
// sidecartest, built on exported connect API (Q-TEST-1)
func NewNet(ctx context.Context, settings *NetSettings) *Net // Required (D-PROTO-6)
func (self *Net) AddSidecar(name string, settings *sidecar.SidecarSettings) *TestSidecar
func (self *Net) AddEngines(host *sidecar.ServiceHost) // fakes (T2: conditional-write Blobs, Redis), server stores (T3)
func (self *Net) SetLink(a connect.Id, b connect.Id, link *LinkConditions) // loss, partition, TransportType
func (self *Net) Capture() *PrivacyCapture

// empty without build tag sidecar_testhooks, and make check fails a release leg that links it
func testHookSecret(kind string, secret []byte) // at every key creation, derivation and unwrap
func testHookBarrier(name string, key string)   // at each named protocol step (22.8's schedules)

// sidecartest, from M10: the search oracle (D-TEST-14), written apart from the index; it decrypts each repo's
// newest committed versions and scans their text under the index's published normalization tables, sharing no
// index code
func (self *Net) SearchOracle() *SearchOracle
func (self *SearchOracle) Matches(query string, scope *SearchScope) []*DocumentKey // what a search must find
func (self *SearchOracle) Covered(scope *SearchScope) []*DocumentKey               // newest commit indexed
```

```text
stores (Q-TEST-2)
local     a Redis Cluster of 3 masters and no replicas, production's shape, on Redis 8.10.2; MinIO from the production
          source with PR #21653, one process with 8 drive directories at EC:4, so drive quorum behaves as in
          production
T3 and    the same Redis Cluster; MinIO as 4 nodes x 2 drives at EC:4 (a metadata cluster) and 4 nodes x 4 drives at
release   EC:8 (the segment cluster), so host loss, QuorumLoss and DriveMiss run for real (FS-1, FS-40), and a second
          metadata cluster as one 8-drive process (FS-63)
lint      CROSSSLOT: every multi-key command and Lua script in sidecar engines and server's sidecar code runs once
          against keys spread over the 3 masters and fails on CROSSSLOT, and a static check refuses a multi-key call
          whose keys lack one shared hash tag
not       canary, which has no edges or mail (§19.11); a one-node Redis
release   build/all/run.sh's rewrite functions on a fixture copy, the tags served through GOPROXY=file:// with
fixture   GOWORK=off, an empty module cache and no replaces: root, protocol and an engine package import at the tag;
          ur builds from cli/; go list -m all shows one sidecar path; each protocol/<name>.proto registers once; sdk's
          go mod graph holds no smtpproof or prover dependency
```

### 22.5 Component matrix and hot-path gates

Parentheses hold T1 tests; the rest run in T2 and T3. Inline server paths (contract gate, Find, tlsedge, mxedge, preamble, quota leases, the write budget) run under `DenyPostgresForTest` with an op-counting `ServiceHost.Redis`.

```text
§5    (keychain wraps, keychain.wrap re-sealed at every change to the member's current binding, a cascade's void
      included, with no HPKE copy while none is current; states) other uids refused; replies hold no secret; git,
      IMAP and submission plaintext only on loopback, else TLS (git also ssh; owner decision 130); forwards labeled
      LAN-exposed; macOS keychain from the signed bundle, else §5.11; fail closed without admin_refused; §5.8's
      pairing and parent loss; one membership's recovery code, with a copy of the whole state directory, opens no
      other network's keychain; a member's revocation of its own other devices (5.6's rules and codes): FS-98
§6    (chunk limits; RPC idempotency; enum numbers stable and a zero code a protocol error; the descriptor lint walks
      the envelope, stream and push roots over the released descriptors and fails on any oneof outside its allowlist,
      empty in v0) lossy streams; PEER_TIMEOUT; nothing before a verified Hello; ControlId push dropped over p2p, kept
      over h1; team hints to acl_enforcing device clients; long-poll hints within 25 s, the 200 body round-tripping; a
      complete=false reset followed by a dropped tail applies nothing until versions are refetched; receive allocs;
      witnesses: FS-17, FS-21; C19's remote-search windows: FS-125
§7    (config-repo replay) 403 for marked tokens on §7.4's 37 routes, for unmarked device tokens on stage 2's six,
      and for a strict_exp bearer on each payment route; strict_exp only on sidecar-held tokens
      (owner decision 131), an expired one refused by api, the exchange and connect's transport auth with
      reject_expired off; a copied token fails refresh, exchange and auth-client, as do a replayed DPoP proof and
      one by an older generation's key; removing an API key ends its auth-code login token; a non-preview network
      refuses enrollment before stage 2; a one-command admin token changes neither its invite's email nor its role,
      works once, and answers a retry after a lost response with the stored result; an older head or unauthorized
      signer refused; 22.7's admission suite; §7.6's OIDC, JIT and IdP scoping; the log, forks and the recovery
      window: FS-14, FS-16; stale page Workers revoked at a newer Worker's admission (D-TEAM-29): FS-97; a copied
      auth-key bundle after its agents' revocations and its Delegation's end: FS-102; presence countersignatures,
      refused alike by api and every member device (7.9's presence row): FS-124
§8    (deterministic compile; compiled = reference; one definition's fixed vectors) readers' AclRows equal the
      writer's; lower or forked versions refused; suspension <= 5 s; no Network-mode edge or share contract; a
      non-admin's RepoGrant refused, a config writer's RepoRevoke winning; §8.5's no-document rules; §8.10's
      legacy-client rule; gate < 1 us, 0 allocs; the ephemeral ceiling: FS-19
§9    (P2C vs a stale-load oracle; admission; fixed vectors for 9.4's K_tok, K_seal, tokens and 152 B seals, a moved
      or mismatched seal dropped) replay refused; drain; one script per Find; a 3,000-name set registers
      as three pages under one set_version, none refused for size, each unlistening only names in its own key range;
      an entry outside its page's range, or an older set_version, refuses the page; after Redis loss one interval
      of pages rebuilds the set; a client looping registrations or Finds is shed with unavailable before signing,
      one with many established streams never limited; a spent network's Find answers quota with no ticket; an
      unused edge ticket from another source, or an edge-marked ticket for an application name, is refused invalid
      before any application byte, a valid edge splice working; ur share: no get or resume at or past
      expire_millis, a live stream reset there, a sharer restarted past it serving nothing, --expires over 30 days
      refused, uses never exceeded across a crash after a Reserve; on a fake clock, one dialer's 100 ms
      connections to one 256-stream listener: Find issues the bucket's 50 tickets a second after its burst
      of 500, none refused or delayed by 9.7's clamp, that dialer adding at most 25 to est between reports,
      and a second dialer that redeems none moving est by at most 25
§10   (§10.4's mapped vectors; X-Wing KATs; ladder; missing key refused) KF1-KF7 (one commit per epoch, one claim
      per KeyPackage, no early Welcome, retention by acks, which live in Redis: FS-62); path-only self-updates by
      any leaf, an Update proposal refused; no commit past the projection; once every ack has expired the newest
      epoch survives the sweep and a returning device commits the next; committers, wraps, seats and recovery: 22.7;
      generations, Delegations, their key drops and ends, and deposits: FS-15, FS-18, FS-20, FS-22 to FS-24, FS-102;
      wrap paths and wrap_aad as fixed vectors; delivery identity and authority: FS-103, FS-104; copied keychains:
      FS-105; key upkeep under r: FS-106
§11   (token, record, segment, push, batch and window vectors; fork, rollback refused; no key prefixes another; NFC
      and NFD names are two paths; any reader derives main's ref id; format-2 constructs refused by format-1 code as
      needing format 2, a malformed one still alarming; a purge's candidates and the kind-5 citation rule as pure
      functions with fixed vectors) path-level CAS races; disjoint file-mode pushes from one base land at v+1 and v+2,
      two exporters giving equal oids; a 2,000-file git-mode merge on a ref taking a push every 3 s seals inside its
      lease, an expired lease's seal failing TIP; a head-mode Write to a git-mode ref gets EVS_GIT_REF; uncommitted
      versions and parts invisible; path epochs; prefix subscriptions; the head cache never serves below a reader's
      pin or a hinted version; erasure leaves no prior version, openable body, deposit or index field, or decrypted
      copy on a current reader's device (§15.7, §16.8), chains verifying, and a restarted ingest recreates no erased
      message; deletion refused at once, restorable 7 d, then shredded, --now at once, both under a hold too (owner
      decision 133); restore and shred race behind a barrier at the CAS with one winner, a stale job of an earlier
      incarnation deleting nothing; at the exact storage limit maintenance pushes and an erasure's bounded CLOSURE
      push pass and an ordinary write is refused (FS-47); commits, batches, folds, receipts, evacuation, the write
      budget and placement: FS-1 to FS-12, FS-57 to FS-63; versionless content, its purge, migration and git-lfs:
      FS-64 to FS-73; drop history: FS-89 to FS-96; stable refusals: FS-113; the store's settle rule: FS-114; the
      write budget's accounts, P0 alone, path-epoch copies and cohorts: FS-116 to FS-119
§11.14 (normalization vectors: normalizer 1, NFKC, full case folding, marks dropped only after Latin, Greek, Cyrillic,
       Arabic and Hebrew letters, each run of characters that are not letters, marks or numbers folded to one space,
       Unicode 17.0.0 pinned; trigram completeness: every substring of three or more normalized bytes of a document
       yields only trigrams in its set; one- and two-character CJK queries; codec, doc-table, tombstone-table, entry,
       slot and shard vectors in testdata/index/, byte-equal on every leg; canonical decoding) entries ride the
       content push on file-mode refs and the companion push on git-mode refs and record streams; diff dependencies,
       deletion masks, mask memory and cold downloads: FS-107 to FS-110; head files, seals, merges, roll-ups,
       coverage, exclusions, erasure cuts and rewrites: FS-74 to FS-79, FS-111 and FS-112; remote search's
       serving side: FS-83
§12   (validator; labels; compact denial; CNAME lint) both NS alike at one serial, a drained or failed interface
      dropped from *, @, every copy of *'s records and each mx on both; a key set failing self-check never serves;
      §12.5's label uniqueness; §12.8's verification gate
§13   (ClientHello parser; 421) §13.9's kill switch and ValidateListen refusals, mta-sts served only as a receiver's
      system publish; §13.4's bench; tlsedge on 443, 8443, 8883 and 5671 only (owner decision 121); CAA, audiences and
      custom hosts: FS-32, FS-34, FS-35; custom-host readiness: FS-122; a hello offering ur-route-probe gets
      unrecognized_name with no lookup or Find
§14   (X-UR-Ref MAC; header-only report parse) every §14.8 halt row, burner labels included; a report replaying
      network A's X-UR-Ref under network B's verifying d= halts nothing, while a genuine one halts A; Redis loss
      fails open <= 1 day's quota; the preamble proof: FS-31; outbound DATA size outcomes: FS-123
§15   (every §15.4 dialog row) 250 only after a durable deposit; 451, not 530, after a closed handshake anywhere or
      under a closed gate; §15.4's direct-MX checks; erasure, strict MX and reports: FS-13, FS-33, FS-39;
      MailAuthEvidence at maximal identifiers within 8,192 B, and authentication bounds: FS-121
§16   (tiers; request_sha256; taint; redactor recall) in a tainted run harness evidence counts only where a requests
      rule names it, never through evidenceDefault (owner decision 142); other self-signed decisions refused; bare ur
      helps on a pty and speaks MCP on a pipe; §5.8's .ur rules; pinned Claude Code, Codex and Cursor; MCP 2024-11-05
      to 2026-07-28, each version with a small and an over-limit evs_read and mail_read that a strict client validates
      against the wire schema, following the reference and finding the trust tags and markers; 22.7's approval and
      restore suites, restore's apply racing writers that take no lock: FS-115; the search tools' scopes, consent
      receipts, filters, grouping, labels, taint and caches, each MCP version validating their results against the
      wire schema: FS-80; the directory's writers, requests, scale, removal and taint: FS-84 to FS-88, its erasure
      authority, decisions and repo items: FS-99 to FS-101; an approver refuses a CanonicalAction version it does not
      know (M3)
§17   (Classify = linear scan; hook = reference) reset vs drain; reset bucket; C18's aliases within §17.9's
      isolation; §17.5's Classify budget; blocks outside 100.64/10 and RFC 1918 refused (owner decision 132),
      readers keeping the previous block; native IP and the dial fence: FS-38, FS-56; from M8, an app's VPN
      component (owner decision 197): a delegation its forwarding key signs for its sidecar is admitted, while one
      signed by a superseded, revoked or voided forwarding Delegation's key, or by one whose forward names another
      sidecar, is refused before any byte, as is a link to an app host whose client key is not the host client its
      live forwarding Delegation names, each on FS-38's operator-minted contracts; api and every reader refuse a
      SidecarAdmit, statement or head a forwarding key signs; with the sidecar role stopped, a new grant and a
      revocation reach the host within §8.9's targets; a forward_only client gets only the config's r scope and no
      other route; after a 7-day lapse forwarding stays pending until the app's next run mints its client anew
§18   (SidecarKeyStore statuses through the generated Swift, Kotlin, C-ABI and js adapters: one terminal result, no
      panic) LOCKED then unlock keeps the identity, and nothing is created while LOCKED; Absent with a recorded id
      makes no new root; corrupt bytes are Failed; a child token expired on a fake clock, a re-pair under the same
      sidecar_id and a released old-generation logout event leave the identity and the new enrollment; a forged core
      revocation with no SidecarRevoke gives unenrolled and an alarm, a signed one revoked, on local and remote
      backends; the ios_extension leg links of the root only §18.10's forwarding files and registers only that
      list's descriptors (protocol's config, acl, evs and gkm, and protocol/bridge's), make size within owner
      decision 215's budget (M4); forwarding in the VPN component (owner decision 197): its posture restored
      before the first packet, rules and revocations applied with the sidecar role stopped, its forwarding client
      refreshed by its own proofs, nothing but its sidecar's delegations signed by its key (the §17 row); wakes and
      liveness: FS-36, FS-37; phone and page search within §18.4's budgets: FS-77, remote search's requester side:
      FS-83; the device list and revocation through each adapter: FS-98; the ios_extension leg links no index code
      (protocol's evsindex.proto and search.proto, the root's evs_index_ and search_ files), and make size keeps its
      margin with the index's ~0.4-0.6 MB of normalization tables on the app legs, which already link x/text's norm
      through connect's golang.org/x/net/idna (connect/net_http_doh.go:26;
      .gomodcache/golang.org/x/net@v0.57.0/idna/idna.go:26), so only the sidecar_http leg pays them in full;
      push-token projections in revision order: FS-120
§20   (Spend atomic, no I/O) all-or-none debits per debit_id; 402 and 429; §20.6's payers; relayed contracts reserve
      at CreateContract and debit once per contract_id, P2P none after C3 (FS-45); a usage batch retried after a
      lost response debits once, and a drained producer loses nothing (FS-44); meter rows re-sent after Stripe's
      24 h dedup window replace, never add, and a correction is a new version (FS-43); declared sidecars get no
      Public contract, only sidecar_clients
§21   TTL sweeps on an injected clock; an access-log row per read; holds pause only sweeps, GC and a drop's deletions,
      the last silently (owner decision 184; FS-92), each kind to its deadline (FS-48); abuse clocks on a fake clock
      across a weekend, every registrar or registry notice paging (FS-49)
```

### 22.6 Fuzzing

- **Envelope, chunks, every `sidecar/protocol` body:** the decoded message is `proto.Equal` to `proto.Unmarshal`'s, and its encoding equals `proto.MarshalOptions{Deterministic: true}`'s and decodes back equal; seeds hold reordered, repeated, unknown, packed and unpacked fields and non-minimal varints; signatures verify over the received bytes, never a re-marshal.
- **Typed `Signed` statements:** every registered type pair is refused as another type, a `GrantRevoke{grant_id}` presented as `OwnerConfirm{sidecar_id}` with equal field-1 bytes included.
- **`record.proto` headers:** a v1 reader verifies one with an unknown field and kind; re-encoding changes nothing a verifier checks; two writers' entries in one push order deterministically.
- **Stream, push and config-delta state machines:** nothing past `max_offset`; bounded memory; converge or resync.
- **tlsedge ClientHello, split across records:** SNI and ALPN equal `crypto/tls`'s.
- **PROXY v1 and v2:** pires/go-proxyproto agrees with mailgun/proxyproto.
- **SMTP at mxedge (pre-TLS), smtpedge (MX replies) and receivers:** §15.4 holds; nothing forwarded before STARTTLS's 220.
- **go-message, mox, ARF, RUA, TLS-RPT, DSN:** bounded expansion; no enclosed ARF body decoded.
- **Git pkt-line, pack, delta; head-mode codec:** equals go-git.
- **`EvsPush`, `EvsPushPart`, a DROP's `EvsDropHistory` and its lists, batch records, window entries, upload receipts, index entries, name tables, path maps, segments:** tampering fails before plaintext or adoption.
- **MLS messages, Welcome, GroupInfo, tree, `GkmCommitHeader`:** `mls_*` agrees with thomas-vilte/mls-go (0x0001) and tmc/mls (0x004F as 0x0010).
- **DNS feed, synthesis, validator; `dnssec_chain`:** no non-public or refused record; broken chains refused.
- **HuJSON compiler; `BridgeEgressPolicy`:** equal the reference.
- **Daemon hello, `.ur`, `ur hook` payloads, MCP arguments:** no secret echoed.
- **Index files** (slots, large entries, bucket and all shards, doc and tombstone tables, manifests, settings, the lock): decoding total and memory-bounded; tampering fails AEAD or the plaintext hash before use; re-encoding reproduces the bytes; non-minimal VByte, unsorted or repeated keys and docids, bitsets off their threshold, a key in both of a shard's tables and a tombstone in an all shard refused (FI-22); a current diff's chain that does not resolve leaves its document not yet searchable, never a miss, and a superseded diff's raises nothing.
- **Normalizer and trigram extractor:** idempotent; output within a fixed multiple of input; invalid UTF-8 mapped by one rule; trigram sets equal to a reference extractor's written apart.
- **Search arguments and cursors** (`ur search` and `ur agents` flags, MCP search arguments, §16.10's parser, planner and cursor decoder): bounded postings touched; forged or foreign cursors refused; no panic; no secret echoed.
- **`SearchRequest` and `SearchReply`** (pads, sizes, coverage, hits past their caps, unknown codes, repeated pages): decoding total and memory-bounded; the indexer answers a body off 4,016 B or with a non-zero pad as INVALID and a repeated page with its cursor's last reply; the phone refuses a reply off its steps × 16,384 B, drops hits and fields past their caps before the merge, and never reads an unknown status or served code as OK or served.
- **The remote-search merge**, against adversarial replies: it never adds a hit from a repo the request did not name or the requester does not read, never removes the phone's own confirmed hits, and collapses possible matches only inside the stated span (D-EVS-60).
- **`directory.proto`'s card, repo file, notice, request, decision and erasure request decoders:** decoding total and memory-bounded; a version past its caps (a card's 16 items in 16,208 B, a 4 KiB repo file, a 256 B notice) is ignored with an alarm, never shown; signatures verify over the received bytes (FI-25).

Seeds in `testdata/fuzz/` run in every `test.sh` (owner decision 101); crashers become seeds and regression tests.

### 22.7 Scenarios, privacy, revocation

Scenarios mirror §3.7's flows (D-ARCH-3) on T2 fakes, then T3 (S1 only T3), with §7.4's route allowlist on; T6 repeats S5-S8 and S10.

- **S1** (F1, enroll): code-create 403; token never in MCP, env or logs; a genesis other than the invite's refused.
- **S2** (F2, write, notify): hint p99 ≤ 2 s; owned refs land; on a shared ref, disjoint pushes land on file-mode refs, and on a git-mode ref the second gets a stock non-fast-forward and its merge lands (§11.7, §11.11; owner decision 141; FS-5); every acknowledged commit is reachable; a non-writer's head refused.
- **S3** (F3, add a reader): a server-forged admission, KeyPackage or ReaderKey refused, and an authentic ReaderKey past its not_after or valid over 7 days; Adds and wraps only for readers, each late wrap judged at its own pin (FS-104); device form S3a (KF2) from M2, member form S3b at M6.
- **S4** (F9, remove): the revocation suite; device form S4a (KF4) from M2, member form S4b at M6.
- **S5** (F4, publish HTTPS): key only on device; each §13.7 audience, login-less visitors reaching only edge login; Community publishes verified, ≤ 7 days.
- **S6** (F5, send mail, M9): no record forwarded before its proof verifies; no unauthenticated MX; §15.10's forwarding rules; a message over the DATA cap is `too_large` for the non-CHUNKING recipient domain alone (FS-123).
- **S7** (F6, receive mail): 530 to plaintext; unroutable gets a temporary failure, the edge holding nothing; abuse@`<root>` without SNI reaches the platform listener; DNS changed between reception and ingest leaves the reception-time result, and tampered evidence fails; a message whose checks a bound cut is deposited and labeled from what was verified (FS-121).
- **S8** (F7, subnets, port maps): rules only from the config repo; LAN by rule once a document exists, else open to untagged sources (owner decision 120) but never to the provider's own `127.0.0.1` daemon ports, while an unrelated loopback service passes; revoke resets.
- **S9** (F8, MCP work): vault only; redaction; gaps; evidence labels.
- **S10** (F10, burner lifecycle): a burned label gets 550 with no DNS change; a replying burner's first selector keeps its `<blabel>` MX and A, its last restores the wildcard-only state, and a receive-only burner creates no child.
- **S11** (F11, search and agents; FS-77 and FS-80, from M10): a claim filed on one device is in another's next search after its index entry lands: in a team network with the card push that carries it, in a vault after the writer's next companion push, at most a minute later on 1 KiB blocks, else five minutes (owner decision 172); hits are grouped by agent, active first; an untrusted hit returns as a stub with the run untainted, and `untrusted: include` taints first; a parked device's search omits its member's vault and lists it as consent pending; an EvsShare reader's receipt precedes each index decrypt; an erasure ends open cursors and empties the caches of its postings; two searches with different queries over one state send evs identical request sequences.
- **S12** (F12, remote search; FS-83; from M10, app hosts with M8 and team indexers with M6): in a network that designates a search indexer (none is designated by default, owner decision 177), a phone's "search more" asks its own indexer and shows verified hits merged with its own, a false possible match collapsed; with that indexer killed the next answers, and with none the repo falls back to the download; a team repo reaches the network's indexer only after the notice, and the member's vault never does; both devices' evs request logs are identical with and without the remote search; every search frame a relay carries has its kind's one size; the pair's close reports are each window's floor, whatever the searches (FS-125).
- **S13** (F13, announce, find and request; FS-84 to FS-88; from M6; owner decision 171): B's agent finds member A's run within one sync, by `directory_list` at M6 and `search_agents` from M10, grouped by agent, its title withheld from B's agent and B's run untainted; a run in a repo marked private at creation shows `private` and the repo id; a run in an announced general repo shows its name and branch to every member; a revoked announcement leaves no readable copy of the name (owner decision 181); B's agent requests read on the private repo by its id, a harness prompt endorsing it in an untainted run and device or presence evidence in a tainted one; the repo admin's devices are hinted, phones woken from M8; a person approves, B's devices read the repo, and B's daemon verifies the `RepoGrant` at its log position; B's agent then asks to reach a worker A owns or sponsors, A approving as `autogroup:dst-owner` (owner decisions 179, 180), and B spends the approval once into a `GrantActivate` and dials only the worker's announced ports (FS-85's worker case); a denial shows its note; A's opt-out stops A's announcements (owner decision 170), and A's removal masks them at once.

```text
privacy harness
canaries (32 random bytes) in contents, paths, names, commit messages, search queries,
  authors, ref names, repo labels, tags, groups, device and client names, policy text,
  application socket names, mail bodies (one reported through a fixture FBL, one to abuse@),
  subjects, local parts, HTTPS bodies, both Delegation seeds of an auth-key bundle (CLI, SDK
  and QR enrollment), from M6 run titles, repo display names and announced runs' prompts past
  the first line, tool inputs and outputs, touched paths and diffs, and from M10 index
  display fields and git-lfs objects
CC1 every engine Handler, both directions, but mx-4's listener input (§2.8's exception)
CC2 every TransferFrame: sealed unless ControlId, handshake or ack
CC3 sidecar Postgres tables, Redis SCAN+DUMP, every object in every metadata and segment cluster
CC4 logs, metrics, edge records, report parse output, Find calls, dns edge queries,
    a fake upstream resolver, fake APNs/FCM, MCP results, env, hooks, a TLS-intercepting
    fixture proxy with its own CA, which ur status reports, and from M10 both remote-search
    devices' logs, metrics, traces, crash reports and state directories
scan CC1-CC4 (raw, hex, base64/32, QP, percent, UTF-16, decompressed)
  for canaries and every testHookSecret key  =>  zero hits
declared values pass only if metadata_list.yml, generated from §2.8 and parsed by a strict
  YAML parser whose every parse error fails the build, names them; the guard carries v8's
  rows, connect-5, evs-26, evs-27 and evs-28 included
schema guard (I-18): every server-visible column (helo_name, network_client_lease and
  mail_connection_record included), Redis key family ({evsq_} {evsl_} {evsh_} {gka_} {evsd_}
  {nvb_} {dpop_} {tcb_} {acl_}e among them), object key family (place/ repo/ head/ log/ pb/
  hp/ idx/ slot/ pmap/ pidx/ spidx/ hold/ seg/ pack/ proj/ projrows/ rev/ gkm/ drops/
  dropscan/) and proto field maps to a list row and back, format 2's included (each
  version's versioning setting, kind-5 and staged locators, window bits 4 and 5, the DROP
  flag and drop_sha256, purge times), and a row without a purpose or a TTL fails; a proto
  field is one reachable from a message a service engine or a server decodes, the walk
  stopping at bytes the design seals; testdata/metadata/fields.yml and each area's
  metadata_rows.yml map each to its row, and "and back" holds for a row once its owning
  milestone has landed, a row ahead of it carrying planned: Mn there, never in
  metadata_list.yml, which stays §2.8's block byte for byte
self-test: a sidecar_leaktest build leaks into each class, which must catch it
assert every stored commit but an external commit parses as PrivateMessage, and in S3
         and S4 GkmCommitHeader carries only the generation and the auth pin (D-KEYS-3)
       evs and gkm touch no Postgres and write Redis only in {scp_} hints, {wakeq_} wake
         entries (§18.7), {nvb_} budget reports (§11.13), from M10 {evsd_} drop hints
         (§11.13) and the soft state {evsq_} {evsl_} {evsh_} {gka_}, each rebuilt or ignored
         on loss, and only api writes {acl_}e (owner decisions 2, 136; §7.9)
       a gate's view holds no run id, agent id, recipient or preview (AD4)
       wake payloads carry only a topic class and version (owner decision 88; WK4)
       a private name gets A or NODATA on the device for every qtype (owner decision 85)
       synthesized DMARC records carry no ruf, no fo and no rua into <root>
       a bridge flow from an unsealed peer is denied (C5 Sealed; before C16,
         app devices host no target)
       after C6a, public exits refuse 100.64/10 and RFC 1918 destinations, so no
         overlay flow leaves (owner decision 132)
       a FriendsAndFamily flow reaches only its share's targets under the sealed subject and
         network, a forged source_subject being overwritten by the signer, a companion reply
         carrying the same subject and only the dialer's network debited (C18, §17.9)
       a TCP flow idle 300-600 s keeps its link across a withdraw, a long-lived flow across
         an advertiser join, and a one-advertiser retarget's live flows through the drain,
         while a new pair's TCP connection takes the new rule at once and new UDP and ICMP
         pairs follow the pre-change link for 5 min; a fragmented UDP datagram stays on one
         link; a full pin table leaves new pairs unpinned, refusing none (owner decision 66),
         and moves no pinned pair; oversized (/8, /16) and full-block shares are refused
         with their reason, overlapping /24 requests allocate without collision, and aliases
         survive a drain
       no certificate whose key URnetwork holds names *.<root> or *.<net>.<root>, and no
         device outside a scope, or unconsented in a member scope, holds that scope's
         certificate or gets its key into the scope's TLSA (owner decision 126)
       SNI mx.<scope>.<net>.<root> reaches only that scope's receivers (owner decision 58)
       in strict mode receivers refuse spliced sessions for URnetwork-zone MX hosts and
         accept direct-MX sessions, and only mail through a customer-signed custom MX, from a
         sealed strict_chain, carries tls_basis.strict_custom_mx (owner decision 98; FS-33)
       tlsedge and mxedge splices are byte-identical
       mail is "validated" only under REQUIRETLS, or live TLSA for the SNI host plus a
         listed operator matched by forward-confirmed PTR or aligned DKIM d=, else
         "opportunistic", tls_basis naming the rule, operator and list version
         (owner decision 135); a two-hop fixture that reads a canary, keeps DKIM and adds
         REQUIRETLS yields no claim of exact path confidentiality, and a listed operator's
         message shows its inference basis, not proof
       no UI or API claims MTA-STS protection for mail to a burner domain, which has no
         MTA-STS policy: an operator listed only for MTA-STS enforcement still gets
         "validated" there (owner decision 135), its stated basis the listing alone, and a
         DANE-listed operator's its DANE enforcement (§15.5)
       no query canary in CC1, CC3 or CC4, and in CC2 only inside sealed remote-search
         frames to an indexer FI-24 allows (FI-21); a relay capture of remote searches shows
         one frame-size sequence per kind across ten queries with 0-20 hits and every
         post-parse failure (FI-24); both parties' close reports for the pair, both
         directions, are each window's floor and zeros, sent at its end (C19; FS-125)
       the directory's plaintext, decrypted with a member's keys, holds no canary from a
         prompt past the first line, a tool input or output, a touched path or a diff (I-20);
         title canaries reach it only in its sealed cards, entries and index files, and never
         evs metadata, logs or another network's repos; a private repo's display-name canary
         never reaches it, and after a revoke no stored card, entry or index file holding a
         revoked name has a readable key (owner decision 181)
       every shard, bucket and all, is sealed at a Padmé size over its body and §11.14's
         keyed pad, and nothing is compressed, so no compression context spans documents an
         outsider injects; in a DBREACH-style fixture, the server reading every padded size
         while a sender injects up to 1,000 messages a bucket recovers no fixture one-time
         code, the run reporting its per-guess advantage
       two different queries from equal sync states, on a desktop, a phone surrogate and a
         page Worker, give equal server-visible request traces and, with an indexer
         answering, equal relay frame-size sequences per page (FI-23)

admission suite (S1, S3; a malicious server and a lone admin as adversaries)
at k = 2 one signer's authority statement is refused, targets never counting: an AdminSet
  change (granting or removing owner, admin, network_admin or it_admin), or an AdminSet
  member's device admitted or revoked; that member's existing device counts as one of k for
  its new device and for revoking another of its own devices, the revoked device never
  counting, so its phone's revocation of its laptop completes on one other admin's cosign,
  while an AdminSet change's or a MemberRevoke's target member never counts (owner
  decisions 110, 112; §7.9's counted row); a member's devices and recovery key count once,
  and a read-only device's cosign is refused
outside the AdminSet, member M's consented device admits M's untagged device at once unless
  self_admit is off, and revokes one whatever self_admit says, so with it off an admin's
  device admits M's new device while M's phone still revokes M's lost laptop alone (§7.9's
  scoped row); M's recovery key admits it at once or, with self_admit off, only on one
  admin's cosign, the device then reading M's vault (consent: scoped)
  (owner decisions 112, 126)
the recovery window (FS-16; owner decision 127): at k = 1 a proposal activates 72 h after
  its entry, a veto at 71 h wins, and a veto api drops but HeadCheck gossips makes peers
  that verify it before applying the activation refuse it, while peers past it alarm and
  offer revocation; a veto backdated after an activation forks only devices still before
  it, until a compromise revocation of the recovered device; a proposal backdated 72 h
  raises recovery_unseen on devices that applied it under 72 h - 10 min before; a
  RecoveryRebind of the subject or of a member whose recovery key signed or cosigned it, an
  AdminSet change or the subject's removal voids it; at k = 2 it never activates alone, and
  with one admin's cosign activates after 72 h unless vetoed; a recovery cosign added 72 h
  or more after an admin's proposal activates only 72 h after the cosign, a veto between
  them winning (§7.9); until admitted, a code-only device reads only the log and M's
  recovery wraps, every other gkm or evs route refusing it; once admitted, one served a
  forged genesis whose log admits the real rotators, or a RecoveryWrap forged from M's
  recovery public keys, raises head_alarm (fork) and makes no commit, wrap, sealed
  write or further statement (§7.9's anchor); every recovery-key admission under M raises
  admission_alarm on M's devices
a recovery-admitted device self-joins the config group and M's written groups by external
  commit, with no leaf online in groups of at most 16 leaves (§10.6), and revokes M's lost
  devices; ranked past the config group's first 1,000, it reads the config by its
  RecoveryWrap instead; after recovery-rotate the old code admits nothing
  (owner decisions 128, 144; §10.8)
two first devices racing proj/<network_id>/1/_ leave one genesis, the loser admitted like
  any device, and a tagged or ephemeral enrollment before it gets no_genesis (§7.9)
owner consent (owner decision 126): in M's vault and mailbox an admin's grant to any reader
  but the visible audit reader is refused, while an admin's revocation lands; a device one
  admin admits under M reads neither and gets no M-scope mail until M's OwnerConfirm, while
  members refuse its Add and wrap, KF2 parks it, and M's devices raise admission_alarm and
  approval_pending; consented devices (scoped, first, confirmed) read at once (§8.5, §10.9,
  §15.5); a JIT member's first device is consented only through the admin's invite
committers (owner decisions 113, 128): any writer leaf commits the Add or Remove a signed
  grant, admission or revocation requires, and members reject one without it; in the config
  group the signing device commits it though no config writer, a config head from it still
  refused, so a self-admitted device reads with no admin online
seats (owner decisions 144, 182): the 1,001st live member device reads the config, and from
  M6 a team's directory, by ReaderWrap at once with no commit, and members refuse its Add or
  external join in either group; a wrapped device signing an admission writes the new
  device's first wrap, and signing a revocation rotates, the next leaf commit removing a
  leaf target; when a leaf-entitled device is revoked, the first wrapped one by rank becomes
  leaf-entitled and keeps its wraps until a leaf adds it, and nothing shrinks; a data repo's
  1,001st reading member device waits keyless, named in the writer's preview; 5,000
  admissions meet no member-device cap; in a team's directory group, gkm hints pending
  changes only to the statement's signer and the config writers (§10.9; D-KEYS-23): with the
  signer and the config writers offline and many unhinted writers pushing, each refused
  writer waits up to 15 s, one whose wait a covering generation ends adopting it and staging
  no wraps, and the gate reopens within ~20 s of the first refused push
agents cost no commit or leaf: a Delegation-admitted one reads at once by its reader key
  with no member device online, others once a writer wraps to them; a wrapped writer rotates
  by re-wrapping but commits no Remove (owner decision 114)
read-only page Workers at k = 1 and k = 2 send each refused statement directly (config
  statements, cosigns, Adds, approvals, admissions, wraps, GroupInfo): api, gkm and members
  refuse every one, while the Worker's own SidecarRevoke lands, its HeadCheck counts as a
  witness, its reads work and, under its r token alone, its ReaderKey and KeyPackage uploads,
  path-only commit, resync and ack land and members adopt them (FS-106)
a compromise revocation parks the closure P from its since_n, counting each record from its
  carrying entry, never its at: the revoked device, each device whose admission a device
  in P signed or whose park its AdmissionConfirm lifted, or whose consent rests only on
  its OwnerConfirm (A admits B, B admits C: both parked; A's OwnerConfirm of an
  admin-admitted G, G's only consent, parks G, and of an already consented H parks
  nothing), each agent under a Delegation one signed, which is void, for a revoked agent a
  Delegation admitted each agent that Delegation admitted from since_n, the Delegation
  ending there (FS-102), and each device a
  recovery key admitted under a binding a device in P signed (A rebinds M's key to K', K'
  admits E and E admits F, all before A's revocation: E and F parked); earlier records
  stay; parked devices read, write and witness nothing (a shrink); a RecoveryBind or
  RecoveryRebind, KeyRegister or EvsShare a device in P signed is void until a signer
  outside P signs it again; a void restores the newest earlier binding not void, which
  until so re-signed takes no wrap and admits only through the 72 h window, M's devices
  alarming, so K' admits nothing, nor at once a code a voided compromise rebind had
  retired: with M outside the AdminSet, self_admit on and A its only device, M's restored
  code K's plain SidecarAdmit of M's new device N is refused, and K's AuthorityProposal of
  that admission activates 72 h after its entry with no counted cosign unless an AdminSet
  device's RecoveryVeto lands first (one at 71 h wins), with self_admit off only on one
  admin's cosign as well, admins' devices showing recovery_window meanwhile; admitted, N,
  which no RecoveryWrap reaches, uploads its ReaderKey and no KeyPackage, takes the late
  ReaderWrap of the config's current generation a config writer gives it (KF2), and again
  the one a later rotation stages, and from its RK_g opens the config head and checks its
  chain to the genesis K's genesis_sig signs before any commit, wrap, sealed write or
  further statement, no Add preceding that; it then reads the config, self-joins the
  config group by the GroupInfo that RK_g opens, is added to M's other groups by KF2 once
  it uploads KeyPackages, and offers recovery-rotate, whose rebind gives M a current
  binding again, while given instead a ReaderWrap the server forged to its ReaderKey,
  over a matching C_g and a forged log, N raises head_alarm (fork) and acts no further
  (§7.9's anchor and restored rows); again with a second device D of M, which sealed
  keychain.wrap to K' on applying A's rebind: D re-seals it at the void with no HPKE copy
  while M has no current binding and raises recovery_rebind naming that span, A's
  revocation lists D, and each device that may revoke D offers its compromise revocation
  from the rebind's entry, after which the identity key in a backup of D taken in that
  span, opened under K', signs nothing members accept, an AdmissionConfirm of E or a
  RecoveryRebind included (owner decision 149); api and readers refuse a revocation whose
  P would hold one of its signers (a personal network revoking its stolen first device
  from a device that one admitted: refused at since_n 0, accepted at the loss position);
  each of M's devices alarms on every RecoveryRebind of M it did not itself sign, one
  another device of M signed included; a signer outside P lifts a park by
  AdmissionConfirm, the device then leaving P and what it signed in P staying parked or
  void, but a consent resting on what P signed returns only by M's own AdmissionConfirm or
  OwnerConfirm from a consented device outside P, an admin's AdmissionConfirm restoring
  all but owner-bound reads
stale page Workers (D-TEAM-29; FS-97): the device admitting a member's page Worker, an
  admin's where self_admit is off included, revokes as removed in that act, under its one
  presence check where it registered a live presence key (owner decision 187), each of the
  member's Workers that §10.9 removed as stale from every group it is a leaf of that
  seated it, at least one, and no other; a Worker that no group of the admin's device
  seated waits for the member's consented device, which revokes it at its OwnerConfirm or
  admission-alarm answer, and, below 90% of config_admissions, only that device offers to
  revoke the member's live Workers;
  a Worker back by KF5 resync or KF2 re-add is never revoked, and an AdminSet member's
  stale Workers at k = 2 go only by proposals of their own beside the admission's, which
  its cosigner also cosigns; from 90% of config_admissions every admin device raises
  admissions_near_cap, listing each member's page Workers but its newest, oldest first, and
  an admin's revoke frees their admissions before the cap refuses one
device revocation (D-CORE-20; FS-98): an approval-capable device revokes another of its
  member's devices as lost or compromise, never itself, another member's device or a
  tagged sidecar, and a read_only, ephemeral, unconsented or suspended caller gets
  REVOKE_NOT_CAPABLE; a compromise counts P from a since_n the person moved no later and
  is refused while P holds the caller; it signs only after presence wherever the member
  holds a live presence key this sidecar registered, the plan setting Presence from the
  log, and puts that check's countersignature on each statement of the act, without
  which api and every member device refuse it (owner decisions 185, 187), else after the
  person's confirmation, never on a hook's evidence, an MCP call or an unconfirmed control
  call, revokes keys only with presence, and answers REVOKE_STALE only when the plan's
  PlanId changed before signing, park and void items added meanwhile joining unasked; api
  and every member device verify the statement, and an AdminSet member's at k = 2 suspends
  the target at once and completes only on another admin's cosign
unverified state: a provider restarted in enforcing{doc}, or an app's forwarding role, given an
  unsigned has_document = false stays enforcing{doc} and opens no private destination over
  TCP, UDP or ICMP; a fresh enrollment is pending, denying private destinations and exits
  until verified; a legacy network and an app without a sidecar keep today's behavior; a
  verified enforcing{nodoc} network keeps allow-all; a verified base above document_seen_at
  with has_document = false moves enforcing{doc} to enforcing{nodoc}, and one at or below it
  does not
one definition: a file compiles to the same rows on every compiler; an untagged sidecar and
  has_document = false have fixed vectors
JIT: a password account registered with the email before domain verification is never linked
  by an IdP login, and links after its own login
auth keys: an auth_key containing # is refused unlogged; CLI, SDK and QR enrollment each
  verify the admission against its Delegation, which api and every reader refuse if it
  names tags other than the Delegation's, a non-ephemeral not_after before the
  Delegation's, or a position after the Delegation's end (FS-18, FS-102)

approval suite (FS-25 to FS-29; §16's AD1-AD4 and AU1-AU4)
decisions  S2 presenting S1's unspent decision for one sponsor and one action is refused by the daemon and the gate;
           a replayed GrantActivate makes one grant and, after the grant's revocation, none; a decision whose
           auth_pin digest differs from the spender's retained one is refused; an approver revoked after signing
           approves nothing; at k = 2, one approver's and one non-eligible signer's decisions are refused and two
           eligible approvers' pass
uses       two callers released together on uses = 1: one effect, which both get for one action, the second getting
           spent for two; kills after the Reserve fsync, after the component's commit and before the Outcome, then a
           retry through a new MCP session: a deterministic sink counts one effect, the retry returning the original
           result or uncertain; a gate's response lost after COMMIT: one row, the original result; two api instances
           racing: one wins use_index 0; uses = 2 with three actions: two effects, then spent; uses = 3, the run
           tainted after the first use: the second is refused stale and files a tainted request, a use reserved
           before the taint completing (TS1); on a fake clock a local reservation at not_after - 1 s completing at +5
           min succeeds and a retry at +11 min only reconciles, while the daemon refuses to reserve a server-gated
           use past not_after - 60 s, the gate refuses a first presentation past not_after, and a replay past
           not_after gets the stored result; a cancel after one of three uses, sent as POST /approval/cancel with
           §7.4's allowlist on, refuses the rest; mail counts outbox objects and claims no exactly-once SMTP
devices    each host pairing (one CLI, two CLIs, a CLI with a page Worker or a quick burner, two remote-mode
           desktops, a phone app with a CLI), with and without a presence key, reaches every allowed channel; a
           self-signed device decision is refused; admitting a Worker keeps harness_ok, a second CLI clears it, and
           ur approve there signs device evidence the first daemon accepts
presence   each profile refuses a wrong key or another key's attestation, a replayed challenge or a counter
           regression, UP or UV clear, another RP's rpIdHash or an unlisted origin, a software key as apple
           attestation, an ES256 assertion as ecdsa-p256-sha256, an app-integrity assertion without UV and an
           assertion over another action's bytes, and passes its positive vector; its countersign check (§7.9's
           presence row) refuses the same faults but the counter regression, and a path that misses its leaf,
           another act's root, another signer's act and an act over 65,535 statements, ignores
           signCount, and passes a five-statement act's vectors, each statement verified alone (owner
           decision 185; FS-124)
actions    an admin sidecar's agent calling evs_write or evs_read, or reading ur://evs, on the config repo, and ur
           acl push from a non-terminal caller, are refused, while team_members, team_agents, acl_grants and
           acl_check answer; on a secret repo holding a fixture ACME account key, evs_repos omits it and evs_list,
           evs_history, evs_read, evs_write, evs_delete and ur://evs reads and subscriptions are refused, CC4
           finding no testHookSecret key in any of these results; every MCP evs tool and ur://evs read and
           subscription on the search index's files (.ur-index/ on file-mode refs, the ur/index ref) is refused,
           evs_list naming them only when asked, as is every one on the team directory (§16.5, §16.6, D-MCP-17);
           deciding a directory_request (its RepoGrant, EvsShare or another's ApprovalDecision), announcing, revoking
           or marking a repo private, and a DROP push or its cancel are refused from MCP (§16.6, D-MCP-32); in a team
           network under claims off, record_append(kind: claim or handoff) answers FAILED_PRECONDITION naming the
           setting and announces nothing (§16.11's claims row); each MCP session's initialize and server/discover
           return the instructions for the claims value fixed at its start, one go-sdk Server per text (§16.11's
           instructions row), and a later change of claims leaves an open session's instructions unchanged; through
           MCP, bridge_expose files its own BridgeRoute, a re-signed retry keeping its rule id, and a host's first
           map files its own BridgeAddress, then the BridgeMap, and completes, while a path that would sign a
           BridgeAddress naming another sidecar_id or a second one for an addressed host, a BridgeBlock,
           BridgeEgress, Suspend, EvsShare, OwnerConfirm or access-log statement, or a GrantRevoke or BridgeWithdraw
           of another sidecar's grant or rule, is refused; an approver shown a dns_set whose preview claims other
           rdata sees dns_value; a descriptor lint finds every O tool filling its kind's fields
restore suite (FS-26, FS-115; §16's RV1-RV4)
           sessions A and B share one worktree: B's edit of f and new g between A's start and an unrelated A hook
           stay untouched and are reported foreign; f edited through an Edit hook and then by hand is chain-broken,
           refused, and f edited by hand and then by A's hooked edit in one scan interval is not edit-attributed, so
           restore keeps the hand edit, under Claude Code's, Codex's and Cursor's edit hooks; a file changed during
           the baseline walk is not exact, refused; a dirty file holding a synthetic secret is restored byte-exact
           from the local copy while the vault copy is redacted, and no marker is written; a file over the cap is
           hash-only, refused; after a daemon restart mid-run later changes are foreign; a change between preview and
           apply conflicts, keeping the path's bytes and writing only its restored copy beside it; a shell-attributed
           path is refused without paths and a decision; a writer that takes no lock (an editor, a shell, a second
           harness) and writes between apply's checks and its install is never overwritten: its bytes stay at the
           path or in a conflict copy, and the path reports a conflict (FS-115)

revocation suite
X loses access by member remove, SCIM active=false, device revoke (an admin's, or its own
  member's through §5.6's RevokeDevice as lost or compromise, FS-98), read loss, a grant's
  expiry, suspension or ephemeral reap, keeping its local state and raw store access, as a
  malicious server allows
writers seal nothing to an epoch or generation X holds, even with evs's gate off (§8.12)
once the projection drops X, or X's grant expires, heads and deposits whose generation does
  not cover it get 412 GATE_CLOSED, and receivers 451, until a generation covering it is
  claimed (§7.9, §10.5), gkm down or not (D-KEYS-6), a writer paused between its checks and
  its commit included, on the no-conflict and the disjoint-retry paths, and a new ref (FS-3)
members refuse a commit that adds a non-reader or omits a Remove its projection needs
  (§10.9)
after members write at generation g+1:
  X's tokens fail at api, sockets and edges at once, at evs and gkm through the revocation
    object, all within 15 min; connect closes X's clients within 90 s; members refuse X's
    external commit
  every g+1 segment, slot, GenWrap, GenLink, ReaderWrap and sealed GroupInfo fails AEAD
    under all X's keys, where X is a member device, an uncovered agent, a covered agent
    after its suspension or a revocation for any reason but reaped, its Delegation's
    key among its keys, or, after its DelegationRevoke, a Delegation (a covered agent's
    reap, or an ephemeral one's own not_after, starts no generation, §10.5)
  after a member removal or a compromise revocation, X cannot compute the new path epoch's
    tokens, a creation in a general repo waits for the map, a stale-source map and an
    old-epoch seal are refused, and two removals during a paused copy keep every path
    readable (FS-4); after other drops and expiries, a path epoch is due within 24 h, or, while
    two sources stand, once one drops (§11.6)
  each file's first write is a full checkpoint (owner decision 64), and after ur evs rekey
    every file of the repo opens only under the current generation
  X's sockets, publishes, forwards, DKIM selector and certificate end; a removed member's
    tagged agents keep their tags' grants, and autogroup:sponsor resolves to autogroup:admin
    until an admin's SponsorSet (owner decision 83)
five ephemeral agents keep writing through one's reap with no member device online, any
  writer re-wrapping the next generation to the rest (owner decision 114)
a Delegation's reader key opens no generation after its DelegationRevoke, a reaped agent
  holding it reading until then (§10.5); a covered agent's reap starts no gate, rotation or
  path epoch in the Delegation's repos while its individually granted repo shrinks and
  rotates; a passed not_after, or a Suspend or a revocation for any reason but reaped of
  one of its agents, drops the key at that position; after a Suspend or a lost or removed
  revocation, later agents read only after an individual wrap while the Delegation admits
  on; a compromise revocation of one of its agents ends it, api and every reader refusing
  its later admissions and the agents it admitted from since_n parked (FS-18, FS-102)
a reader-only key holder with evs's help gets no unsigned entry accepted in head mode, and a
  rollback after the pin is refused (FS-10)
a server withholding the Remove from writers it lets reach its holders, directly or through
  a peer relaying it as proven or unverified (FS-17), only delays: an agent's consistent HeadCheck counts
  as a witness; unwitnessed, writers alarm at 24 h and, in groups with another member's
  devices, stop at witness_bound_hours (72 h by default; values outside 24-168 refused),
  while rotations, Removes and revocations never stop (owner decision 129); two stale
  writers witnessing each other while every revoking device is offline keep writing, as
  §2.8 discloses, and the revoker shows unwitnessed
```

### 22.8 Load, soak, failure injection

- **sockets:** 100,000 listeners, ~6,700 registration calls/s (§9.8); Find p99 ≤ 50 ms server-side, in-flight share within ±25% of weight (proposed).
- **tlsedge:** 50,000 connections per process (§13.9), name scans, W2's per-address limits on the lb path; §13.5's p95.
- **evs:** the twenty-agent test: 20 agents push their owned refs and merge into `main` every 60 s for 1 h (4.3 pushes/s, §11.13), with no acknowledged commit lost, `git fsck` and export oids equal on a second device and §11.15's targets met; 1,000 subscribers per repo (§11.15).
- **push, config:** 10,000 networks save a config head in 1 min; 2× §19.6's Y2 hint rate, leases, push sequence and the head and projection caches included, at ≤ 50% Redis CPU per master; §8.9.
- **escrow:** §20.9's benchmark and FS-46 at M6's entry on M4's dark build (§23.4); the benchmark again at its exit.
- **smtpedge:** Team quota on many networks; halts ≤ 60 s, no overrun.
- **soak:** 72 h at 30%; heap, goroutines, Redis keys and orphan objects back to baseline.

```text
storage benchmark (M2's exit on the staging cluster, the production hosts' PM9A3 set, rebuilt empty and
SMART-rechecked before M3 (§19.11, D-PHASE-7); again on production before M3's pilot; §11.13's mix, §10.6's sizes;
D-TEST-11; at M10, the index row and the fold and trash rows' M10 runs on T3, format 2's projection from this run's
price table (D-TEST-13), confirmed on production after the freeze, and the phone, search, remote, directory and drop
rows)
mix      every GET, PUT, LIST and DELETE in §11.13's table at 2x year one with the write budget on (pushes with their
         batch writes, folds and evacuation, parts and seals, gkm commits, rotations, Adds, reconnects, full resyncs),
         a restart with every reset incomplete included: p99 <= 25 ms per operation; bytes written per push and per
         object on each drive (the nvme row)
tenants  a network flooding the store is refused first (429 RESOURCE_EXHAUSTED, retry_after_ms), its writes by the
         write budget, while the others keep that p99 (proposed); a restart writes nothing to the metadata cluster,
         since leases and acks are in Redis
groups   §10.6's table measured at 10, 100 and 1,000 leaves, GroupInfo above 16 leaves written at most once an epoch,
         on request; a config rotation, by a leaf and by a wrapped rotator, re-wrapping to 5,000 wrapped holders
         (§20.4's Team admissions: agents and member devices past the first 1,000; owner decision 144); a 1,000-leaf
         group on an ios32 cell within §18.4's iOS budget (22.9); a device a week behind a full group resyncs from
         one GroupInfo by external commit (KF5)
pushes   a 100,000-file commit imports as one multi-part push (§11.8); a reader during its parts sees the prior head;
         a crash between parts exposes nothing, and evacuation drops them; history older than 24 h packs onto the
         HDDs, a small repo's after up to 7 d in parcels, and still verifies (owner decision 136)
hosts    on the production clusters before M3's pilot: with a second host down (EC:8, EC:4), reads continue and
         writes get 503 until the cold spare returns a host within §19.6's RTO, out of hours too
         (owner decisions 116, 143); a write that misses a drive while a host is out, then a second host: as §19.6
         states (FS-40); heal throughput and times recorded
hdd      on the production segment cluster before it holds data (M3): small PUTs and GETs at year two's mix (~400 and
         ~1,600 a second, §19.6) for 1 h, recording achieved drive operations a second, by the HDDs' /sys/block reads
         and writes completed (stat fields 1 and 5), the counters from which §19.6 publishes each segment cluster's
         capacity, with p99 and the page-cache hit rate; that capacity is what §11.13's HDD admission and the drop
         job's 50% pause read, beside Q-OPS-2's packing switch; then 1 h each at year one's mix and at year two's with
         §11.13's HDD admission on at 50% of that capacity, reporting admitted PUTs and GETs a second, the foreground
         refusal rate and p99: year one's mix admits every upload, and the highest year-two PUT rate admitted with
         refusals under 0.1% is §19.9's hdd trigger's admitted throughput, neither a higher line nor refused uploads
         counting as throughput; at M10, again with admission on and versionless purges at year two's rate (1 TiB a
         day of 4 MiB-chunk churn, the index's bucket and all rewrites), the sweep's HEADs included, on synthetic
         objects in a bucket of its own on that cluster, since no production store holds format 2 before its freeze
         (D-PHASE-7), in a low-load window under §19.6's 50% drive-operation pause, the bucket emptied after (§19.11's
         M10 step)
nvme     on 4 KiB and on 1 KiB XFS blocks, every namespace at the 512 B LBA format (nvme id-ns, §19.6): each operation
         class alone for 10 min (create, overwrite and delete at 1, 4, 10, 16, 64 and 160 KiB; LIST; GET), then
         §11.13's mix with the write budget on and 25 h of batches preloaded, at 1x and 2x year one and at the
         budget's limit, 1 h each after 1 h of warm-up; per drive, per operation and per push: device bytes written
         (/sys/block stat), XFS log and file bytes, write and read IOs, p99, and SMART data units written and
         percentage used before and after; bytes and inodes per object class; DWPD at both years and the projected
         fill date; gate (D-TEST-11): at 2x year one, the budget refilled at 0.8 DWPD for the run, <= 43 KiB per push
         per drive (0.8 DWPD at 400 pushes/s) and <= 50% of rated IOPS, on the block size D-TEST-11 chooses, with no
         push refused by the budget, no ref at FOLD_BEHIND and evacuation keeping every batch under 26 h, so a push's
         bytes include the P2 work it causes, charged once from the wallet, after FS-116 passes; P0's bytes by kind
         against the refill, which set §19.8's P0 warn line, its page silent at that mix, the gate bounding that mix
         only (owner decision 186; FS-117); the per-operation costs become §11.13's price table; at
         M10, format 2's mix is priced by this run's per-operation table, its counts from the index row (D-TEST-13)
fold     the twenty-agent test and a mailbox stream at §19.6's rates: index writes per push (the fold ratio), records
         per batch per cluster and per parcel, how long a ref stays unfolded, and removal markers standing and their
         age at GC (owner decision 148); at M10, the search index's head-file overwrites, seals and merges per push
expiry   1 h requested grants expiring on 1M-file repos beside the mix: rotations, full checkpoints and path-epoch
         copy operations per day, live entries per rotating ref, deferred batched epochs and the oldest source's age,
         at most one batched epoch per repo a day (§10.5, §11.6), for §11.13's inputs and §19.9's gen/ and path-epoch
         rows; FS-118 holds the week-long backlog on the fake clock
trash    year two's per-set overwrite rate for 1 h, with MinIO's trash sweep at 5 min and at 30 s: .trash size, sweep
         throughput, inodes and bytes per overwrite; at M10, again with versionless purges at year two's rate
index    at M10 on T3's clusters, formatted as production: the twenty-agent test, a mailbox stream and a notes vault
         at §19.6's rates with the index on in every eligible repo (owner decision 156), against the same load with it
         off, recording the operations M2's price table prices (creates, overwrites at each size, deletes, idx/
         entries, folds, seals, merges; staged bytes, removal markers and their collection) per indexed push, per
         companion push of a git-mode ref or record stream, per roll-up (the expired bucket's removal and the
         rewritten all files), per erasure cut with the INDEX_EPOCH rebuilds it causes, per erasure rewrite and
         per migrated repo, with the HDD PUTs and DELETEs each causes: D-TEST-13's counts
phone    on T4's ios32 and Android surrogate cells, and wasm in Node and, through Playwright, Safari: decrypting all's
         shards in 64 KiB frames (MB/s), peak memory against §18.4's budgets, and a "search more" over five years of
         100 messages a day (~110-165 MB), on first fetch and cached
search   desktop p50 and p99 over the buckets and over all at five years of 100 and 300 messages a day, local
         verification included, and §16.10's warm targets on the desktop matrix and the surrogates; its cold
         contract with a 165 MB all at 10 MB/s, the sole match in the first, middle or last shard or none: first
         progress, each shard's arrival delay and completion time, and the median and p90 first all hit over
         FS-76's query set; phone p50 and p99 over the buckets on the surrogates, an iOS simulator (owner decision
         100) and Safari's wasm;
         ranking and typo quality on 20 Newsgroups (rare-word P@5 at least 0.40, top-1 at least 0.6 with confirmation;
         typo top-5 at least 0.9 on desktops and 0.8 on phones); Japanese and Chinese corpora and an HTML-heavy
         mailbox; one roll-up's time, natively and in wasm
remote   at M10 on T3 with real relays and netem (Wi-Fi at 30 ms RTT and 50 Mbit/s; LTE at 75 ms p50 and 300 ms p95
         RTT, at 10 and 2 Mbit/s): tap to first and to next page, p50 and p95, cold and pre-warmed, against §18.4's
         remote targets, and on T4's surrogates from the later of M10's and M8's exits; the indexer's service time on
         desktop amd64 and arm64 and a NAS-class arm64 host, over five years of 100 messages a day and a 50-runs-a-day
         vault; 100 and 1,000 simulated requesters at 1.5 pages a member in the peak hour and ten times it, local
         searches staying inside §16.10's targets, refusals inside the remote budget, and phones failing over within
         their timeout
directory
         FS-86's load (D-TEST-17), its M6 case at M6's exit and its card case at the later of M10's and M6's: 500
         members in physical time, and the Team limit (2,000 members) and 5,000 as fake-clock days with a
         physical peak hour at 3x bursts beside the 1x year-one mix; the cards ref's commit p99, 412 reruns and
         429s, priced NVMe bytes per push per drive, and readers' requests, path reads and bytes per reader-day
         and team-day against the golden schedule and §16.11's cost table, with a cold phone past 8 MiB
drop     at M10 on T3: dry-run and job scan rates, HDD drive operations, HEAD and DELETE costs, NVMe writes per job
         and per drop, and a 60 GB history's job time; the directory and drop rows' NVMe operations, priced by M2's
         table, join §11.13's price table
```

**Fault schedules (D-TEST-10).** Each schedule runs on the tiers its row names, under the rules below; an oracle with read access to every store checks the named invariants after every step and at the end. Owning sections give each mechanism, and this catalog its schedule, check, tier and gate.

```go
// sidecartest/fault: one Schedule per FS row; Await and Release name testHookBarrier sites (22.4)
type Schedule struct {
	Id    string      // "FS-1"
	Seed  int64       // only the explorer's interleavings use it
	Steps []*Step
	Check []Invariant // FI-n, after every step and at the end
}
type Step struct {
	Actor    string         // "writerA", "evs1", "gc", "shred", "daemonM", "stripe"
	Action   func(ctx context.Context, net *Net) error
	Await    string         // run until Actor reaches this barrier, then hold it there
	Release  []string       // barriers to release, in this order
	Fault    *FaultPlan     // the result the next matching store, Redis or Postgres operation gets
	Advance  time.Duration  // fake clock, shared by every actor
	Kill     bool           // drop Actor's memory; Restart builds it again from durable state alone
	Restart  string         // instance to restart Actor on ("evs2")
	Counters *DriveCounters // fake metadata drive counters (FS-61)
}
type FaultPlan struct {
	Op        string // "put", "get", "list", "delete", "redis", "pg-commit", "http"
	KeyPrefix string
	Nth       int
	Result    FaultResult // ApplyThenDrop | FailBeforeApply | Precondition | Delay | QuorumLoss (T3) | DriveMiss (T3)
}
```

```text
rules
barriers    each owning section names a barrier at every linearization point and at the steps before and after it: the
            head CAS (a refusal's fence included), place/, gen/ and epoch/ creation, batch and slot writes, folds and
            their markers' collection windows, evacuation's and the shredder's deletes, reservation and effect, the
            SHREDDING claim, map cut-over, the meter send and, from M10, the purge's certainty, its hold/ reread and
            each of its deletes, the sweep, evacuation's staged decision, seals, merges, the roll-up's lock, build and
            push, the migration's format flip, the drop job's take and phase CASes, its hold/ reread and each HEAD and
            DELETE, and a remote search's page replies
unknown     ApplyThenDrop applies a write and shows the caller a transport error; every write in FS-1, FS-3, FS-15,
            FS-25, FS-43 to FS-45, FS-57, FS-63, FS-65, FS-72 and FS-75 also runs with it
determinism fake clocks and barriers only, no sleeps; a schedule waiting over 10 s of real time for a barrier fails
            with its trace; WARP_TEST_ENV_FAIL_FAST=1, so a failed attempt fails the run (R-TEST-9)
twins       every refusal schedule has a twin that must succeed, so a disabled feature fails
real        T3 runs each T3 row through server's real handlers and stores (api, evs, gkm, the token exchange,
            Postgres, the 3-master Redis Cluster, D-OPS-20's MinIO build), never fixtures that pre-authorize
explorer    each schedule also runs with seeded random barrier orders: 10 seeds a merge for T2 rows, 100 a night for
            T3 rows; a failing seed becomes a fixed schedule
model       EvsCommit.tla (TLA+, checked by TLC: https://github.com/tlaplus/tlaplus) keeps head (its fence, refusal
            records, seal lease and collect window included), batch records, packs and parcels with their pidx/
            entries, index entries, segments with their upload receipts, slot, pmap, log, gen, epoch, repo, proj and
            rev as separate variables; its processes are writers (pushes, and in git mode the lease route, parts and
            seals, each attempt of a push id reaching evs at any step, before or after another attempt's answer,
            while its statement's time bound lasts), evs instances (each write may lose its response or take effect
            late, before the next request on its key or never, and never once taken or begun past its deadline,
            §19.6's 10 s or 11.7's earlier one for fold, copy and collection writes: D-OPS-20's settle rule, which
            StoreSettle.tla checks; each GET of a round is its own step, and a crashed instance may resume a stale
            step after a retry), segment GC (the evacuation horizon, the pidx/ entries read after it and a DELETE
            that names its object, with a first commit to a ref with no head stalled across it), the shredder, the
            folder (two at once, a removal fold run stale, duplicated or applying late, writing its markers
            If-Match), the marker collector (11.7's windows, each opening 150 ms after the last lapsed by the
            opener's clock, its DELETEs issued 15.3 s later with deadlines 50 ms before until_ms by its own clock),
            the evacuator, the path-epoch mapper and the remover; TLC checks
            I-EVS-1 to I-EVS-8, FI-1 to FI-6, FI-9 and FI-15, and per-path version monotonicity across collections and
            path-epoch copies, with 2 writers, 2 evs instances, 1 ref in each mode, 3 paths (a directory and its child
            among them, each removed and re-created), 2 segments, 2 generations and 10 versions, the fold trigger,
            fold size, base range and window bounds scaled from 96, 64, 63, 127 and 255 to 3, 2, 5, 7 and 9, so a
            window after a page-out stays above the base range, and a fold, a horizon-raising commit and a page-out
            fit between one push's step 4 and its step 7 or rerun, and that every member removal eventually gates and
            every due path epoch eventually commits (weak fairness); overlay refs are FS-5's, not the model's; from
            M10 it adds versionless versions, kind-5 and staged content and holds as variables, and the purger (a
            committing instance's delayed deletes, which may crash, run late or race a re-upload of the segment) and
            the sweep as processes, and TLC checks I-EVS-9, I-EVS-10, FI-16 and FI-17 with one of the 3 paths
            versionless through an overwrite, a rename, a removal, a directory removal and a hold; also from M10, at 2
            file-mode refs and 1 git-mode ref, 3 paths (X, a rename source of X and a reuse copy on the second ref), 3
            segments (one shared), 1 slot and 10 versions, it adds DROP pushes (a written or removed boundary, a list,
            a window step and a cancel) and the citation fence (5h's bit-5 and drop-mark checks, a seal's rerun) as
            variables, and as processes the drop job (start, resolve, mark at one snapshot, verify at a later one,
            delete with the hold reread and the 25 h age check, and young rounds; crashing at any step, resuming
            stale, or running in two instances once one lease lapses), a hold placer and ender, and writers that copy
            a listed version by reuse across refs (validated before the fence, with a late step 7), rename a path
            holding a candidate, re-upload a candidate's bytes for a receipt and write the path after the drop, beside
            the purge's processes; TLC checks I-EVS-15, FI-27 and I-EVS-1, and that every executing drop ends done,
            held or refused while no hold stands (weak fairness);
            IndexRollup.tla keeps one ref's head (its version, its index_epoch and the index files each version
            names), its erasure set, its current, previous and expired buckets, all, each writer's head and sealed
            slots with their entries (full, a diff and its base, a tombstone), the roll-up lock with its expiry, and
            each document's newest version and erasure state as variables, with two rollers (either may crash at any
            step, lose its lock at expiry or have its push apply late by §19.6's request deadline), a merger that
            reuses absorbed slots, a writer whose companion push, merge or backfill is built at any epoch and delayed
            past any number of commits, a backfiller, an eraser whose CUT, ERASE and CLOSURE steps may each be its
            last before a crash, and a finishing device as processes, and TLC checks I-EVS-11 to I-EVS-13 and
            I-EVS-17, FI-18's result-set equality across a seal, merge, slot reuse and roll-up, FI-19 and FI-20
            over three bucket lengths with 3 documents, one erased, one edited by diffs across a boundary, one deleted
            while all holds its old row, that every current diff's chain resolves and no tombstoned version counts,
            and that every expired bucket is rolled while a roller is live and every erasure whose CUT committed
            finishes while a finishing device is live (weak fairness);
            StoreSettle.tla keeps one key on 8 drives at EC:4 (4 hosts of 2): each drive's version, its stamp and
            its own lock on the key, each write's coordinator, which may crash, and its drive commits, each a check
            step then a commit step, the settler and heal; writes are cancelled, pass their deadline, arrive after
            it, hold a commit between check and commit past the drive timeout, or miss a host that is down; TLC
            checks FI-30 with PUTs and DELETEs mixed, breadth-first at 4 drives on 2 hosts and at 6 on 3 with 2 and
            3 writes, a coordinator crash and a host failure, and by simulation at 8 drives with 3 writes and 2
            coordinators, and that every held key is released once its stalled commits answer (weak fairness)
history     Porcupine (https://github.com/anishathalye/porcupine) checks T3 histories per ref with §11.8's commit
            rule; an unknown outcome has an open end time and matches any result
cadence     each FS runs on the tiers its row names: T2 rows on each merge, T3 rows nightly and at each Gn-out; a row
            using sidecartest's fake contract issuer or ControlId sink names T3 too, a divergence failing (Q-TEST-1),
            and a row in which the server forges, withholds or forks state names only T2, its success twin running on
            T3; model and history checks run at each Gn-out of a milestone that changes a modelled object
```

```text
FI-1   closure: a committed head's dependency closure (statements, records, entries, segments, slots, maps, wraps of
       its generation) is retrievable, from the one metadata cluster its place/ names or the packs evacuation made,
       and decrypts for a current reader, except what a durable, visible, authorized erasure, shred or executed drop
       removed (§11)
FI-2   outcomes: each operation ends committed, aborted or unknown; unknown never triggers destructive cleanup; a
       retry of a committed operation returns its original result, and a refusal a client received stays true:
       once any attempt of a push id is answered a refusal, no attempt of it commits, whenever it reaches evs,
       save one validated before its repo's shred began, which the shred destroys (I-EVS-3); a reclaimed
       preparation never commits later (§11, §16)
FI-3   commit-point authorization: every head transition carries, and the oracle re-verifies, the authorization pin,
       generation pin, path epoch and lifecycle state current at its head CAS, retries and seals included; nothing
       committing later than §10.6's window after a gate closes uses an excluded generation (§8, §10, §11)
FI-4   one ladder: each generation has one authenticated parent and commitment C_g, whichever path raised it; every
       reader converges on it; none regresses (§10)
FI-5   lifecycle: restore and shred have one winner; a restored repo holds its whole key closure; a shredded or erased
       object never returns, a stale re-seed included, unless no surviving device holds the ERASE (§11.12's
       residual), which §19.10's close report names, and a dropped object never returns, a stale re-seed included,
       except as FI-27 bounds it (§11, §19)
FI-6   visibility: nothing uncommitted evicts a file's newest committed version, which readers find in its entry or
       the head window, and no directory delta leaves the window before its name table holds it; every uncommitted
       object (a dead record with its slots, an unadopted segment, a staged wrap, an abandoned path map) becomes
       reclaimable after its deadline, found without the log; nothing committed or unknown is reclaimed (§11)
FI-7   effects: an approval use is reserved before its effect and stays consumed or explicitly uncertain after any
       crash; no second effect; run taint and requester bindings survive restarts (§16)
FI-8   attribution: a run restore changes only state attributable to its run, or reports ambiguity, and checks its
       preview on the bytes it moves aside, never on an earlier read, discarding no others (§16)
FI-9   git: an acknowledged push has the declared ref, tree, ancestry and per-ref outcome; stock clients see standard
       non-fast-forward errors; a git-mode tip commits only once ur/lfs holds every git-lfs object it requires, safe
       from every prune, and no prune removes an object a current tip requires (§11)
FI-10  witnesses: a witness names exactly the state it compared; stale peers cannot manufacture freshness; a fork
       under one epoch alarms or reads unwitnessed (§2, §6)
FI-11  path integrity: no application byte reaches a backend before its audience check, whatever the SNI or ALPN, nor
       a target after its flow's revocation (§17.6, D-BRIDGE-21); a proof accepts only what the MX's own state machine
       accepts (§13, §14, §17)
FI-12  recovery: after a Postgres or site loss, the newest copy a device or dump holds comes back exactly (oids, C_v,
       decryptability, identities, labels), save what §19.10's postgres step lists in the incident (a suffixed
       network name, a login left for a reset) or keeps at the main dump's age (rows the sidecar dump does not
       name), and nothing erased or dropped (but as FI-5 allows), shredded or revoked returns; an object whose every
       shard exists survives a second host (§19)
FI-13  accounting: (a) every metered byte debits at most once and, barring an unclean producer exit or a batch dropped
       past its 10-min retry horizon, exactly once; (b) a period's billed quantity equals its rows' newest values; (c)
       after each nightly pass, stored bytes equal the seg/, pack/ and hp/ objects' sizes plus the lengths heads and
       log pages give for records still in batches, less objects only a hold keeps, objects held for a drop included,
       and containers whose every record a newer container's pidx/ entry names (20.7); (d) 20.9's E-a to E-e (§20)
FI-14  write budget: (a) with the budget on, on each metadata set's busiest drive not under heal (§19.6's governor
       skips one), the writes of classes other than P0 over any 24 h stay within 24 h of refill plus the bucket's
       depth (0.8 DWPD) and one 5 s interval's issue times the pricing error, less the P0 writes the bucket held in
       those 24 h, which are P0's measured writes less its forgiven excess, the bytes past what the bucket held (owner
       decision 190), so the drive writes past that only by the forgiven excess; P0's bytes and forgiven excess are
       measured and reported by kind (§19.8), not bounded (owner decision 186); (b) conservation: each interval's P1
       and unfunded P2 debits stay within T, funded P2 spends only the wallet W, W never exceeds the priced funded
       backlog, and each push's deferred work is paid once, from W or as unfunded P2; (c) no P0 write waits or is
       refused; (d) a network is refused only while one with less queued priced bytes per weight is served (§11, §19)
FI-15  file-mode CAS (I-EVS-8): a file-mode push commits at u only if each file path it changes has, in the head
       history through u-1, newest version equal to its base_entry_version, 0 naming the path absent (never
       written, or removed), a removal being one of its versions, one past its last, which its marker keeps, and
       each creation's version max(its push's effective base version, the newest removal its marker or the window
       holds) + 1, an overlay's base counting its chain's base versions, so a path's versions never restart
       (owner decision 148) and no push based on a version from before a removal commits after it (5g while either
       holds the removal, 5f's base range once its marker is collected), however folds, reruns, copies and
       collection windows interleave, and 11.7's two-way directory checks hold; a head read or listing at head v
       serves each path's newest version through v, none newer (§11)
FI-16  purge: the content of a versionless version (a kind-5 segment, a staged record, a slot only that path's
       versions name) is deleted only after its replacing version is committed and a process saw that commit (its own
       200, a head reread or a Resolve), the 60 s in-flight allowance has passed on a checked clock, no hold keeps it
       when the delete issues (a hold covering the repo keeps what existed at its placement), and no version committed
       later names it; unknown and refused pushes purge nothing; every path's newest committed version keeps all its
       content; each candidate goes within the sweep's period once those conditions hold, and purged content never
       returns, a stale re-seed included (§11)
FI-17  versioning: a committed version names a kind-5 segment only as §11.7's citation rule allows, and a staged
       record only from its introducing version; versioning 1 never commits in config or mailcfg repos, on git-mode or
       creates-only refs or under a repo lock, and versioning 2 only under an index root (.ur-index/ on a file-mode
       ref, or ur/index) of a repo that may hold an index, a lock keeping it (owner decision 168); every version
       written with versioning on keeps its content for the repo's life (FI-1), whatever the path's later setting,
       unless an executed drop lists it (FI-27); format-1 code refuses each format-2 construct in use as needing
       format 2, or ignores or folds it where D-PHASE-9's reservation list says, never treating one as a fork,
       tampering or a missing segment (§11)
FI-18  index results: for every scope, device and sync state, the candidates for a normalized query include every
       covered document whose newest committed version in the scope contains it; a hit labeled verified or confirmed
       has a newest version whose text or display fields contain it, and a hit found through a corrected term says so;
       no hit rests only on a masked older version; an uncovered document is searched from the device's own text where
       it holds it, else reported not yet searchable, never silently absent; a seal, merge, slot reuse or roll-up
       changes no search's result set, nor does a fresh cache once the purge has taken every replaced index version,
       since every diff's chain and every tombstone a result needs stays in the committed index; a search's mask
       state stays within its working set whatever the partitions hold (§11, §16, §18)
FI-19  index erasure: once the erasure of a document completes, no committed version of an index file that a current
       reader's keys open holds its postings or display fields; every stored version that held them shares a key its
       ERASEs destroyed (one key per index path in slot-keyed repos), its ciphertext purged under FI-16 or kept
       unreadable under a hold; after the erasure's CUT on its ref no index file version but a CLOSURE's, which
       re-keys only a file that held it, is committed holding it, whatever index pushes were prepared before the CUT,
       delayed, resealed or retried, with no indexer and every hint lost; an erasure whose CUT committed finishes from
       evs's state on a device that may erase it; no device that applied the CUT or the hint returns the document from
       a search or a cache (§11, §15, §16)
FI-20  roll-up: each expired bucket of a ref is rolled into all by at most one committed roll-up, whose plaintext
       equals the deterministic merge of its inputs; the bucket's files leave the index only in the push that commits
       all holding their postings; a rerun after any crash converges to that result; until it commits, searches merge
       the expired bucket (§11)
FI-21  search scope and taint: every hit is from a repo the caller's subject may read by §8's local evaluation and
       §8.5's consent, an EvsShare or audit reader having deposited, and evs having acknowledged, a read receipt
       naming each index object before decrypting it; no hit, snippet or display field comes from a secret, config or
       mailcfg repo; an untrusted hit returns as a text-free stub unless its text is asked for, and a result carrying
       any field from untrusted content returns only after the run's taint is fsynced (I-9); no query, hit or cursor
       leaves the device except a remote search's, sealed end to end to an indexer FI-24 allows (§16, §2)
FI-22  determinism: every index object's plaintext is a function of its format version, normalization version and
       inputs alone, byte-equal on every build leg; decoders accept only canonical encodings, so re-encoding what one
       decoded reproduces its bytes; plaintext hashes are taken before encryption, and nothing is compressed (§11)
FI-23  fetch privacy: the index objects a search fetches, and their order, depend only on the device's sync state, its
       fetch rule and the results the user opens, never on the query; only a fetch's time shows that a search ran
       (§2.8, §11, §18)
FI-24  remote search: a query leaves an app host only for a designated search indexer §11.14's rule lets answer it,
       for repos both read, an owner-bound repo only on its owner's consented device, another member's device only
       after that member's notice; every hit names a repo the request named, which the requester reads, and a verified
       hit's newest version contains the query; each request body is 4,016 B and each reply steps x 16,384 B, whatever
       the query, scope, filters, results or failure after parsing; neither device sends evs, api or gkm a request
       because of a remote search; no query, hit, snippet or cursor persists on either device, and the served record
       names none; for a pair §6.11's bit 1 marks, each §6.10 window and direction has one report a contract, F on
       the first and 0 on the others, whenever its other bytes stay within the allowance and it carries at most five
       exchanges, none sent before the window's end, and no contract of the pair is created inside a foreground
       window but at its start, a session re-establishment or overflow (§4.6, §6.10, §11.14, §18.4, §2)
FI-25  directory authorship: every card, notice and run or worker announce entry a reader shows or acts on was written
       and signed as §16.11's path and signing rules require, by a signer that is admitted, unrevoked, unreaped,
       unsuspended and, for a member device, consented in the reader's state, and every repo item by a signer that
       held the right at its push's pin by retained history, its own pin within 4,096 positions before that one
       (§16.11's repo file row); evs takes a directory ERASE, CUT, CLOSURE, closure upload or slot deletion only at
       admin scope, so no other writer's erasure destroys a key, and readers count one only from a directory admin, a
       revocation's from the erasure runner over copies that name the requested repo (§16.11's revoke); any other
       version is ignored and alarms; no run or worker item shows as active past its expires_millis, and a repo item
       lasts until revoked, replaced or its repo's deletion (I-EVS-14, I-EVS-16)
FI-26  request soundness: every grant a directory decision produces (a RepoGrant, an EvsShare, or a GrantActivate
       spending its ApprovalDecision) is signed by an approver eligible for its target at its log position, names
       exactly the request's target (for a worker, dial on its announced services alone; owner decision 179) and a
       subject no wider than the request's, expires no later than asked when an expiry was asked, and exists only for
       an approved request; a denied, cancelled or expired request yields none, and a decision replayed onto another
       request activates nothing; once each decider's device runs again, every request's notice ends decided, naming
       the decision entries eligible deciders wrote for that request (a denial, or the rule's count of approvals),
       or removed by a cancel or past not_after, and a requester that leases only its notice reaches that outcome
       by one notice read and a head read per entry it names, the decided rewrite freeing its pending counts; a
       crash between a decision's steps repeats no entry, statement or rewrite (§8, §16)
FI-27  drop history: a drop deletes a segment or slot only if (1) every version that names it, committed at any time
       on any ref of the repo, is listed by a committed drop of that repo whose window passed with no cancel committed
       before its end and whose list equals its lineage's versions below its boundary; (2) the job's mark and its
       independent verification, at snapshots after every such drop's fence, found no other committed version naming
       it; (3) no hold covering the repo stood when the DELETE issued (a hold keeping what existed at its placement);
       and (4) the object was over 25 h old by a checked clock; no version commits naming a listed version as a base,
       rename or reuse source after its drop's fence; every path's newest version keeps all its content, a written
       boundary carrying its base's oid and mode; readers show a listed version as pending or dropped, never as
       missing or tampered, and alarm on a drop failing its checks; a cancelled, refused or observed drop deletes
       nothing; a crash, retry, stale job instance or concurrent push changes neither the delete set nor what
       survives; deleted content never returns, except from a stale mirror at a site-loss re-seed until the re-seeded
       drop's job runs again, which §19.10's close report names (§11)
FI-28  deliveries: each delivery of g has one immutable identity (group, g, C_g, recipient and the key sealed
       to), and one to a key never blocks, replaces or opens as one to another; every verifier, the oracle among
       them, judges each delivery at its own state (a staged one at its claim's) to one verdict, which no later
       revocation, key replacement or replay changes; a holder that asks for the newest generation gets a
       delivery its current key opens once a holder that gkm hints for it (§10.6's late wraps) and that is not
       read_only runs (§10)
FI-29  copies: no key in a passive keychain copy, a Delegation's reader key aside (§10.5's Residual), opens a
       generation claimed after both the device's next path commit, for a leaf, and the newest copied ReaderKey's
       not_after, whatever advertisement gkm serves; no key of an active clone opens one claimed after its
       compromise revocation (§10, §2)
FI-30  store settle (D-OPS-20): a PUT or DELETE takes effect, as every request on its key sees it, before the next
       request the store serves on that key, or never; none the store took, or began a drive commit of, past its
       deadline takes effect; no earlier write and no heal undoes a state a later write acknowledged or a read
       returned; a key is held only while a PUT lacking a write quorum could still reach a read quorum, or a
       DELETE lacking one has a drive commit yet to answer or be reverted (§19.6)
```

```text
id     §      schedule (actors, barriers, faults)                                              checks      tier   gate
FS-1   §11    head CAS applied, response dropped; evs killed; another writer adds 65+ commits  FI-1,2,9    T2+T3  M2-out
              across log pages; the retry runs on evs2 and returns the original version once,
              and GC then leaves the closure intact; outcome reads losing quorum give 503
              unknown and delete nothing; two concurrent retries of one push id commit once;
              evs1 killed with its step-7 PUT delayed while the gate closes: evs2, serving
              the client's retry or the lb's re-send of the first send after evs1's upstream
              error or 30 s read timeout, refuses only after recording P in the head, and
              the delayed PUT then fails (applied first, it makes evs2 answer 200); an
              attempt of P paused before that record answers the recorded refusal at its
              next head read, or fails step 7 on the record's ETag and then answers it;
              evs1 held past that timeout in its 412 loop while the re-send on evs2 exhausts
              its 8 tries: evs2 answers 429 BUSY with retry_after_ms, refusing nothing, and
              the client's retry returns the version evs1 then commits; a git-mode
              PATH_EPOCH push and an admin's FORCE push commit by TIP and are evacuated with
              their records kept, replaying readers raising no descent alarm; a stream of
              pushes failing a recorded check beside honest ones: the ref records at most
              one refusal a second and holds 8, later refusals answering 429 with
              retry_after_ms, and no honest push's attempt, lease, part or seal is ended by
              them, each rerunning at most once a record on its 412; evs2's clock 150 ms
              fast: no attempt commits after evs1's recorded refusal reached the client,
              evs2 answering 503 to pushes while its offset is over 50 ms or unknown
FS-2   §11    two pushes of one path, both based on committed v, write their batch records;    FI-1,2,3    T2+T3  M2-out
              the first wins the head CAS; the second, rechecked on the new head, gets 409
              naming the path, and its record and new slots stay until evacuation's Resolve
              finds it dead, then go
FS-3   §11,8  A paused after validation; a projection drop closes the gate; B rotates and      FI-2,3      T2+T3  M2-out
              commits disjointly; A resumes by the no-conflict and disjoint-retry paths:
              refused, the head's pins being newer; A's step 7 over 5 s after its step 4
              reruns the checks; A's PUT timing out after the gate closes is not reissued past
              5 s of its step 4: A reruns the checks, which refuse, raises the ref's fence on
              that ETag and answers 412 GATE_CLOSED, or 200 when its first PUT applied before
              the fence, and nothing commits under the old generation past §10.6's window;
              again with a multipart seal, a deposit, a new ref, a repo delete, a grant expiry
              and an evs restart before the CAS
FS-4   §11    paths inserted, deleted and renamed after a map's enumeration and before         FI-1,3,6    T2+T3  M2-out
              PATH_EPOCH commits; a creation in a general repo gets 412 PATH_EPOCH_DUE until
              the map lands; a PATH_EPOCH whose tail omits a path created after its map's
              source gets 409 naming it; a disjoint retry; a path created every second on a
              vault ref under an immediate epoch and on a general ref under a batched one:
              each epoch still commits, first by its tail, then within a mapper's 2-min
              creation block (§11.6), and a batched epoch whose mapper is offline alarms
              writers 1 h past due_by_ms; an old-epoch part and seal after cut-over get 412
              PATH_EPOCH; a mapper killed after half its parts while the window passes its
              source: a second mapper's map commits, and the first's parts are deleted; two
              removals during a paused copy, reads finding every path across three sources; a
              child added to an unmoved directory D during a paused copy and folded before the
              copy reaches it: readers verify D's carried rows under the source epoch; while
              the copy is still paused one carried child is removed and folded, and its row is
              dropped; the copy then resumes and translates the rest, a fold of D landing
              between its GET and its If-Match PUT making it reread, no row lost or
              duplicated; after the sources drop the listing is complete and every name
              verifies in the current epoch; D carried from p1 into p2, then into p3 after a
              superseded copy, listed and name-verified before and after the p3 copy; after
              cut-over and before the copy reaches them, a file removed, a directory removed,
              and a directory removed and re-created with one new child, each read and listed
              once the removal leaves the window and again after the sources drop: nothing
              removed is served or listed, and no reader alarms; a move landing between one
              step-4 round's current-epoch and source GETs, under a push creating the path, a
              push modifying it and a listing: the creation gets 409, the modification from
              the path's current version commits, and the listing shows it; no source-epoch
              token of a name created after cut-over reaches the server; a PATH_EPOCH that
              would list a fourth source gets 412 EPOCH_SOURCES_FULL only after the ref's
              fence; a kill at each copy boundary, a superseded job included: no source
              deleted before its newest copy exists; a lease holder re-subscribes under the
              new path epoch and is hinted every later commit
FS-5   §11    two stock git clients push sibling commits from one base to a shared git-mode    FI-9        T3     M2-out
              ref: the second gets a non-fast-forward, and its merge lands with export's tip,
              tree and parents equal to the clients'; a push whose head moved only by a
              commitless PATH_EPOCH re-signs and lands with no ng, and SEGMENT_GONE, 429 and
              GATE_CLOSED never reach git as a non-fast-forward; with a warm head cache, a
              multi-part push takes its lease, posts its parts and seals with no ng, a lease
              or a push taken after another push's refusal fence lands, one during another
              push's lease gets 429 with retry_after_ms, and a lease based below the tip gets
              non-fast-forward; an agent branch based on a main with unfolded changes to X,
              and one whose base entry for X keeps only versions newer than the branch's base:
              its first push changing X commits, and a read of a path it has not changed
              answers base {ref, version}; an overlay of a file-mode ref gets 409 REF_MODE; a
              two-ref atomic push whose second ref conflicts; the bridge killed after the
              remote commit and before the local update reconciles from its journal; a local
              ref-lock failure after pre-receive
FS-6   §11    restore raced against --now and the 7-day expiry, paused before and after the    FI-5        T2+T3  M2-out
              SHREDDING claim and before each destructive phase: one winner; the worker killed
              at each phase and restarted; a stale job of an earlier incarnation deletes
              nothing; a push validated just before the CAS is removed by phase 6; a fold, an
              evacuation, a gkm commit and a delayed ack write held at a barrier across a
              --now shred re-create nothing; a --now shred under a hold: keys gone and
              ciphertext kept, its records in batches over 25 h old packed, kept until the
              hold ends, then deleted; a device killed between filing RepoDelete and calling
              DELETE: the reconciler applies the statement, its deletion_id in repo/; a DELETE
              or restore without its projected statement gets 409 STATEMENT_MISSING; a re-seed
              refused for a repo whose RepoDelete carries now or is over 7 d old, while one
              soft-deleted under 7 d is placed deleted first and takes its history, group and
              slots with every other route refused, a restore then opening every file
FS-7   §11    five writers push one path from one base: one commits and the others get 409; a  FI-6        T2+T3  M2-out
              reader sees the committed version throughout, folded or in the window, across
              the losers' evacuation and a restart
FS-8   §11    kills after a segment upload, between parts, before a seal, and between a push's FI-6,13c    T2+T3  M2-out
              batch record and its slot PUTs; the fake clock passes 26 h, 2 d and 3 d:
              evacuation has dropped every dead record and its slots at 26 h and GC has
              deleted every orphan segment at 3 d (owner decision 203), leaving a committed
              and an unknown commit beside them; a delayed step-7 PUT after a fence write
              fails
FS-9   §11    a directory at its bound, built from real sealed names with nonce and tag, so    FI-1        T2     M2-out
              the 448 KiB of name table binds before the 4,096-child count (at 3,584 children
              with names under 64 B, sooner with longer ones), plus a concurrent child add,
              folded and unfolded: a complete listing, or 409 DIRECTORY_FULL from step 5g
              after the ref's fence, nothing else written; the same bound through a paused
              copy, its carried rows counted at their untagged size; on a file-mode ref, a
              push removing directory D, based before a committed push that created D/n, gets
              409 with D's path, as does a push creating D/n based before D's committed
              removal; both again as multi-part pushes sealed after the other commit, and one
              whose part adds to D sealed after other pushes filled it (409 DIRECTORY_FULL
              after the fence), while parts adding other children of D merge
FS-10  §11    a reader-only member plus the server forge an entry for a head-mode reader:      FI-3        T2     M2-out
              refused; a rollback of a path changed after the pin refused; a never-read path
              served before the pin at an older committed version, or at a refused push's
              writer-signed entry, accepted, as §2.8 publishes; after a 100,000-change push
              whose prefixes cover a path it left unchanged, a head reader of that path
              checks its absence by adjacent-leaf proofs from the read reply, fetching no
              change list, and a push whose change list is out of order is refused; a reader
              10,000 versions behind re-pins with a gap mark; P read at v20 at pin 25, the
              pin moved to 30, P changed at v28 by a statement with no inline change list:
              v20 and v10 each refused, and a path whose read record was evicted reads as
              never read (owner decision 209)
FS-11  §11    a reader paused after a negative pidx/ lookup while evacuation publishes a pack, FI-1        T2+T3  M2-out
              then deletes the batch: its one relist finds the record
FS-12  §11    a crash after the lease's Redis write and before the 200; the client retries     hint SLO    T2+T3  M2-out
              until 200; a commit 6 s after the 200 is hinted, and one before the holder's 5 s
              reread is caught by it, since that reread is fresh, a delayed or failed
              head-cache write included; the lease family lost: the holder's hourly resync
              re-creates it
FS-13  §15    an erased mailbox message's deposit and index copies after a CONSUME crash: none FI-1,5      T2     M7-out
              decrypts for a newly admitted reader, and a restarted ingest does not recreate
              the message
FS-14  §7,8   two readers with one base and different statements at n+1 (a socket              FI-3,10     T2     M2-out
              GrantRevoke, a KeyRegister), then connected: HeadCheck reports FORK with both
              A_{n+1} and refreshes no witnessed_at; Suspend and Unsuspend in both orders, a
              stale suspend_id a no-op; a base signed at tip n loses to a statement (409) and
              lands re-signed at n+2, folding a stream of statements, while a stale compile
              re-signed after a 409 that names an older config head or a lower folded_through
              is refused by api, and a FORK for readers if appended; after the 30-day
              retention a new device starting at a base folded below the previous one,
              skipping the BASE in its re-applied range, reaches a long-running reader's
              S(n); a GrantActivate whose requests rule the new config head deleted ends at
              that base for every reader; a lost append retried: one entry; a rotation at n1,
              then shrinks at n2 > n1, reopens no gate, and an expired RepoGrant fails a
              generation older than its expiry; a base off the reader's chain, or missing a
              folded statement: FORK; a statement 4,097 positions old, expired or repeated
              refused, as is one whose at, though within 4,096 positions, precedes the
              retention point of the state it lands on, by a device started at a base near
              the tip and a long-running reader alike; a subject a group edit drops gets 403
              at evs within 5 s
FS-15  §10    an agent removed with every leaf offline: an agent rotates with ReaderWraps to   FI-4        T2+T3  M2-out
              every leaf and the gate reopens, and a returning leaf commits the Remove first,
              its path-only commit carrying the newest GenWrap; a leaf's and a wrapped
              rotation race for g+1: one gen/<g+1>, every holder converging; kills before and
              after the claim and between the gen/, epoch/ and wrap writes; a claim's lost
              response retried: one success; a restart on another gkm instance; a commit whose
              header generation is below its predecessor's, other than a recovery self-join's
              generation 0 (FS-20), refused by gkm and members; in the config group the
              admission's signer rotates and commits, as does a reaped agent's admission
              signer after the reap, a config head from either refused; a delivery to a
              non-holder makes members alarm and rotate
FS-16  §7     the recovery window on a fake clock at k = 1 and k = 2: backdating, late         FI-3        T2     M2-out
              publication, replay, restart, an authority change, RecoveryRebind, a veto and
              finalization at once, again for a scoped admission by a binding a void
              restored, which needs no counted cosign (owner decision 149); a recovery
              cosign 72 h after an admin's proposal activates only 72 h after the cosign, and
              a veto between them wins; a RecoveryRebind of the cosigning code's member, not
              the subject, voids the proposal; a veto backdated after an activation: devices
              past it only alarm, those before it fork until a compromise revocation of the
              recovered device; a code-only recovery served a forged genesis whose log admits
              the real rotators alarms and seals nothing
FS-17  §6,11  one ref forked under an unchanged epoch; both peers replay, then meet: a fork    FI-10       T2     M2-out
              alarm or an unwitnessed status, more refs than one message carries covered
              within ceil(refs/16) rounds; a generation fork two agents see: GenHead reports
              FORK; writer A learns a higher pin while api withholds the entries: A's proof
              request verifies, and A stops sealing at once; with that proof dropped too,
              after HeadCheckFetchTimeout the pin is UNVERIFIED: A alarms, refreshes no
              witnessed_at and sends the pin as unverified, so no peer counts A until A
              reconciles, and witness_bound_hours runs; a desktop holder R, a CLI peer X and a
              writer W at X's pin, the server dropping W-R: X sends R's withheld tip as
              proven, X never counts as W's witness, and W stops at its next HeadCheck with X,
              at once with X's proof and at witness_bound_hours without it; again as R-X-Y-W,
              where Y verifies X's relayed proof, sends proven, and W stops at its next
              HeadCheck with Y; again with a phone as R, which serves the proof from its
              newest 64 KiB of entries (§7.9's retain row): X sends proven and W stops at
              once; again with R's proof to X dropped, and with a phone R whose kept entries
              do not reach back to X's n, which answers NOT_FOUND: X sends unverified with R
              as its path's claimant, never counts as W's witness, and W, relaying it, stops
              at witness_bound_hours, and a relayed copy clears once a sidecar on its path is
              revoked (owner decision 147); a revoked, parked or suspended peer at W's pin
              never counts; a peer that cannot catch up refreshes no witnessed_at, one that
              catches up does
FS-18  §10    a DelegationRevoke, a passed not_after, a non-reap revocation or a Suspend of a  FI-3,4      T2     M2-out
              covered agent, and a removed wrapped writer sampling the next generation: no
              generation the dropped party can open; a reaped covered agent, and an ephemeral
              one past its own not_after, start no rotation and read the Delegation's
              generations until its key drops; a dropped wrapped writer's GenRotate at a pin
              before its drop never satisfies the gate; an expired RepoGrant: the generation
              covering it is cause REMOVE, the next write to an inline file is a full
              checkpoint, and a path epoch is due within 24 h; with fixed keys on a fake
              clock, Delegation D admits agents A and B, then A is suspended while D and B
              stay live: with evs's gate off and every staged and late wrap delivered to A,
              no generation claimed after the Suspend's position, and no checkpoint sealed to
              one, opens under any key A kept, D's reader seed included, while B reads each
              by its own ReaderWrap; A unsuspended reads the current generation only by a
              late ReaderWrap of its own; a SidecarAdmit signed by D's key for a
              non-ephemeral sidecar with a not_after before D's, or naming other tags than
              D's, is refused by api and every reader, a new device included; a repo that
              only an autogroup:tagged grant reads lies outside D's reach, so D's
              non-ephemeral agent reads it by its own ReaderWrap and D's ephemeral one not at
              all; a lost or removed revocation of an already reaped covered agent lands and
              drops D's key
FS-19  §8     an untagged ephemeral admitted with no policy under a personal network's Owner   I-15        T2+T3  M2-out;
              (the config read, M2): it reads the config and deposits, holding no other repo's                    later runs
              generation, while general reads, writes and admin and owner-bound writes fail,                      at M4, M6
              api and every reader refuse its config head or base though its member is in the                     and M8-out
              AdminSet, and the exchange issues it no evs rw on the config;
              Delegation-admitted, after a DelegationRevoke it reads the config's next
              generation by its own ReaderWrap; again in a Pro network and tagged, only its
              tags' grants adding, a read grant naming it or a vault EvsShare to it opening
              exactly that repo at once, and the grant's removal or the share's revocation a
              shrink (M4); under a Member and an Admin in a Team network, reading the team
              directory and writing only its own directory paths and stream (§8.6's ceiling;
              D-ACL-24), and a member invite refusing an ephemeral enrollment, then consenting
              M's next untagged device from it (M6); through a quick burner's enrollment, one
              mailbox EvsShare opening exactly its repo (M8)
FS-20  §10    an epoch commits and its committer crashes before GroupInfo is published, then   FI-12       T2     M2-out
              every leaf's state is lost: code-only recovery works as documented, from the
              inline GroupInfo at 16 leaves or fewer; revoked lost leaves still in the tree:
              the self-join carries no GenWrap and gkm accepts its generation 0, its next
              commit removes them, and the rotation that follows is the first new generation;
              a kill at each KF1 step, then the creator's only device lost: the repo is still
              keying, or code-only recovery opens all it holds; gkm killed between an epoch's
              PUT 16 past the pointer and the pointer's rewrite: gkm rewrites it with the
              next epoch, and a resync's probe, run uncapped to a 404, finds the newest epoch
FS-21  §2,6   a document giving the writer's peers no reach to each other (a personal          FI-10       T3     M4-out;
              network's from M4, Team's default from M6): HeadCheck flows over control                            Team at
              contracts, and streams and IP on them are refused; a server partitioning relays:                    M6-out
              the HeadCheck path and the alarm as D-TRUST-10 states
FS-22  §10    an old recovery code's derived keys after RecoveryRebind{reason: compromise}: no I-15, FI-3  T2     M2-out
              new path token or post-cutover content opens, and a write at the old generation
              gets 412 GATE_CLOSED; a routine rebind only rotates; --compromise lists the
              member's devices live while the old binding was current, its own included,
              the rebind signer's since_n clamped past the rebind, so the rebind stands, and
              moved earlier the plan shows the rebind voiding; a personal
              network's last device enrolls its replacement, which revokes it from after that
              admission (owner decision 212)
FS-23  §10    a deposit-only principal, an agent depositing into a vault and, at M7, a         I-15        T2+T3  M2-out;
              receiver into a mailbox, fetches a rotated drop key, deposits and follows a                         mailbox at
              rotation, and every read, ReaderWrap, epoch, GroupInfo and recovery route                           M7-out
              refuses it; a depositor served an older, unexpired GenRotate after a removal
              refuses to seal, with evs's gate off
FS-24  §10    an idle writer gets pending and wrap-pending on its per-client topic at an       gate SLO    T2+T3  M2-out
              unchanged epoch, after a Redis loss too, and a rotation without a commit raises
              gkm:<group_id>: work completes within the gate's target
FS-25  §16    two callers barriered on uses = 1; kills after the reservation, after the outbox FI-2,7      T2+T3  M3-out
              commit and before completion; a retry through a new MCP session; a gate's
              response lost after COMMIT; two api instances racing; uses = 2, cancellation and
              expiry on a fake clock
FS-26  §16    two runs and a hand edit interleaved, hooks firing around B's edits: restoring   FI-8        T2     M3-out
              A leaves B and the hand edit intact, or names the ambiguity; a hand edit of a
              path that A then edits in one scan interval, under each harness's edit hook:
              never reverted; again across a restart
FS-27  §16    an untrusted read, a daemon and relay kill, a restart and a benign hook: an      FI-7        T2     M3-out
              outward call under a standing grant needs a fresh approval; a corrupt run file
              reads as tainted
FS-28  §16    a same-uid process (a shell child of the harness) submits a hook event for a     FI-7        T2     M3-out
              pending outward tool: in a tainted run no harness decision results unless the
              matching requests rule names harness, never through evidenceDefault
              (owner decision 142); in an untainted run the decision is labeled harness with
              source = hook, the disclosed residual; harness never approves a KeyRegister or
              OwnerConfirm; bypassPermissions, dontAsk and auto modes void harness evidence;
              the daemon's presence prompt yields channel presence; no binding to the harness
              binary is possible
FS-29  §16    an approval evaluated under pin P; the pin moves to P', which drops its          FI-3,7      T2     M3-out
              approver: the approval authorizes nothing under P'
FS-30  §16    an EvsShare reader's first read of a vault with the author offline: the receipt  I-4         T2     M3-out;
              is durable, one across a restart between deposit and read, and the reader's                         audit at
              other writes and deposits past the budget fail, while a non-read entry it                           M6-out
              deposits within budget is consumed, never ingested, and alarms; the audit
              reader's from M6
FS-31  §14    a scripted MX with no CHUNKING, pre-TLS-only CHUNKING, no PIPELINING, MAIL or    FI-11       T2+T3  M9-out
              RCPT refused, no 354, mixed recipients, a late NewSessionTicket, a second
              transaction in the body, record splits, replayed server replies, and a smuggled
              or bare-LF DATA terminator; padded and KeyUpdate BDAT body records, which may
              fail the send but smuggle nothing; both TLS versions and modes: every mismatch
              between proved and accepted fails before any effect, positive controls passing;
              an honest TLS 1.2 MX answers 451 while the edge forges 250 and EHLO replies: the
              sender keeps and retries the message, and the edge reads no MX reply
FS-32  §13    a customer pin, an empty alias target, then an operator CAA at the exact         FI-11       T2     M6-out
              target, wildcard and delegated-challenge cases included: strong mode refuses
              the topology; a customer-side ALIAS that also flattens CAA: certs' canary at
              the target, the customer's pin plus a nonce tag, appears in <host>.<domain>'s
              answers, so at setup the host, still pending and unmapped, is refused, and at
              renewal its effective_caa_chain_ok clears and an admin event recording §2.8
              EX1's exception alarms the admins, the host staying mapped, while an
              address-only ALIAS passes;
              both again at an apex host, whose pin sits at <domain>, so only the nonce shows
              the flattening, the canary sitting at a host owner in <net>.<root>, never @
FS-33  §15    a URnetwork-zone direct MX redirected by changing only operator records: a DANE  FI-11       T2     M7-out
              sender reaches the substitute, and no mail on that path carries
              tls_basis.strict_custom_mx; a customer-signed zone's custom MX cannot be
              redirected by operator records, and its mail carries the claim
FS-34  §13    each private audience with no, unknown, http/1.1 and h2 ALPN and                 FI-11       T2+T3  M5-out
              offered-selected mismatches: zero application bytes reach the backend before
              authentication, while explicit public raw services and TLS-ALPN-01 keep working
FS-35  §13    a ClientHello for a registered custom host through the real splitter reaches the FI-11       T3     M6-out
              customer listener and completes device-key TLS and TLS-ALPN-01, beside platform,
              user, unknown and absent SNI and ACME ALPN; removing the host withdraws the
              route at the next reload
FS-36  §18    wake dispatch on the 3-master cluster, the client's and the shard's keys in      WK1-WK4     T3     M8-out
              different slots, a fake clock and a vendor sink: live refreshed at 0 s and the
              client lost, a mail hint at 10 s gives one submission at 25 s +- 1 s; an acked
              hint none; a forced router miss one at once; an XADD failing past its retries
              is counted in urnetwork_wake_enqueue_dropped_total and a kill between the
              script and the XADD drops the wake, hint state intact in both (WK2, WK3);
              sender kills after XREADGROUP and after the send give at most one submission
              per 10 s; after a flush, wakes resume on a token POST or the sentinel pass, and
              after one master restarts empty and one from an older dump, the first pass at
              least 90 s after the one that found them reconciles their slots, so their
              clients' wakes resume with no app launch and none reaches a token deleted
              since the dump
FS-37  §18    an HTTPS-only page polling for 2 h, then killed with no unload: one reap 30-36   FI-2        T2+T3  M4-out
              min after its last poll, or at once on its close beacon; old-generation polls
              keep nothing alive; two tabs reap independently; an ephemeral connected 2 h,
              then disconnected 2 min, is not reaped, and is 35-36 min after the disconnect;
              a page Worker polling and refreshing for 31 days on a fake clock stays active
FS-38  §17    a FriendsAndFamily contract whose sealed source network differs from the         FI-11       T2+T3  M4-out;
              dialer's verified identity: refused before data; an operator-minted window                          shares at
              client with a correctly HMACed contract claiming subject S opens zero upstream                      M6-out
              sockets (TCP, UDP, ICMP), and a valid WindowDelegation is the positive twin,
              while mismatched key, expired, wrong target and wrong network fail and a
              substituted target key fails the sender's check, on a share link against the
              host key Y's BridgeAlias pinned; on a share link (C18), a ShareSigner-signed
              delegation is the positive twin, while a ShareCert below the host's newest
              verified generation, expired, over 7 days out or not signed by the pinned
              ShareKey is refused, after a host restart from 17.8's persisted state too; a
              sidecar Y removed is refused new contracts once a later generation's ShareCert
              reaches the host, at most 7 days after its removal; with no renewal for 7 days
              the share lapses; a current Y reader with no Y grant on X, its valid signer and
              an operator-minted contract to an X-granted target: the honest gate refuses the
              contract, the minted one reaches only X's granted targets and ports, and the run
              records X's grant and the gate, never Y's bypassed router, as what enforced
              (§8.11)
FS-39  §14,15 report intake: gzip XML and JSON aggregates count once per reporter and          FI-11       T2     M5-out;
              report_id, and an ARF body canary appears in no log; at M7, delayed DNS evidence                    the rest
              and REQUIRETLS added by an active second hop: labels as stated                                      at M7-out
FS-40  §19    4 nodes x 2 drives at EC:4 and 4 x 4 at EC:8: node A down; a drive of B fails    FI-12       T3     M2-out;
              one PUT; healing held; node C down: that object unreadable, protected ones                          M3 on
              readable, degraded then at_risk raised; C and A return; a full heal makes every                     production
              object protected; with every node up, a PUT that misses one drive of B
              (DriveMiss), then nodes C and D down: that object unreadable though its set was
              protected, objects whose every shard exists readable; for a head, a slot and a
              segment; the heal throughput is recorded
FS-41  §19    drives lost past parity first (readers alarm on heads naming missing segments),  FI-5,10,12  T3     M3-out;
              then site loss: buckets wiped and both dumps restored; identities re-register;                      M5 to M8
              the authorization log resumes from member devices' verbatim entries, positions                      per step
              and digests unchanged, so no reader sees a FORK; an entry takes its position
              only once two members' devices hold it, so one member's forged TICK (any
              time_ms) or reordered statement takes none, the log stopping there unless two
              members hold the genuine one, and a run whose newest base fails the new-device
              check against the re-seeded config repo is discarded; a Team whose other
              members' only devices are read_only page Workers resumes too, no device seeing
              a FORK; a statement no upload holds is re-submitted by its signer, and a device
              whose tail passes a position filled after resumption sees a FORK; readers
              accept a head below their pin only under an EvsReseed; an unread record entry
              comes back from a full mirror; an entry erased after a stale mirror's last sync
              stays erased once the eraser's device re-seeds; with only stale mirrors, the
              close report names the erasure; a shredded repo is not resurrected; a vault is
              re-formed by its owner's devices; a recovery-code-only member keeps access;
              each later step at its mechanism's Gn-out: CT replay re-binds a label allocated
              after the dump and TLS endpoints re-register (M5), meter rows re-send without
              double-billing (M6), a mailbox is re-formed and mail host keys re-register
              (M7), push tokens re-register (M8)
FS-42  §19    Postgres primary lost, both edge-6 dumps restored, in each order of their        FI-12       T3     M3-out;
              snapshot times: with the main dump older, a network, member and sidecar newer                       M5 to M9
              than it come back with their ids and rows, a network name or login a main-dump                      per step
              row holds being listed (the network suffixed, the login left for a reset), a
              client deactivated and a password reset between the dumps stay so, their old
              tokens refused, and before the token exchange reopens a sidecar and a member
              revoked between the dumps stay revoked: the client inactive, the member's API
              key, auth codes and network token refused; with the main dump newer, a network
              and a client deleted between the dumps stay deleted, and a client created after
              the sidecar dump is deactivated to re-enroll; either way each row both dumps
              hold equals the newer one's copy, less the incident's list; a network newer than
              both is lost, its repos marked deleted and shredded after 7 d, its proj/ and
              projrows/ deleted with the last shred, all listed; identities re-register; a
              revocation and a first policy document filed after both dumps are honoured once
              api has replayed proj/ past the restored head, before the token exchange and
              CreateContract reopen; each later step runs at its mechanism's Gn-out: labels
              re-bind and TLS endpoints re-register, a kill, a suspension and a lift mailed
              after the dump hold through the edges' first reloads, and §19.10's dns step
              (§12.6's restore step) answers dns writes 503 until every running NS serves
              restore_serial: a record written after it publishes on both, an ACME challenge
              committed above every SOA just before the loss and one at an older serial read
              stale and are rewritten, each changed RRset is listed, and an NS that misses the
              SOA read is stopped, writes reopening once the other serves restore_serial, and
              serves again only from a reload, its old snapshot taken as the replaced one,
              /dns/ready not counting it before it serves restore_serial (M5); meter rows
              re-send, and custom hosts added or removed after the dump leave or return to the
              regenerated map and are listed, each pending until every lb interface is current
              for the restore's map version (M6); mail host keys re-register, and a receiver
              revoked after the dump has no TLSA on either NS once api's replay ends (M7);
              push tokens re-register, every token row's revision raised past those the lost
              primary applied, and a client created after the dump re-registering a changed
              token in a row whose revision passes its lost row's, so no later apply is
              refused as stale (M8); a sending sidecar revoked after the dump has no DKIM
              selector on either NS once api's replay ends (M9)
FS-43  §20    a fake Stripe accepts an event, then drops the response; the 24 h dedup window   FI-13b      T2     M6-out
              expires; summaries lag; retries arrive in both orders; a correction follows its
              original; a period boundary at 00:00 UTC; finalization at +72 h; a missed row
FS-44  §20    a producer killed before ReportUsage; a ReportUsage response lost and retried; a FI-13a      T2+T3  M2-out
              SIGTERM drain: zero loss on a drain, at most one window on a kill, never double;
              api unavailable for 11 min: the batch is dropped, counted and alerted, and never
              applied
FS-45  §20    a network near empty with N relayed pairs: grants shrink and spending stops at   FI-13a      T2+T3  M2-out
              the balance; spent refuses CreateContract; a P2P-bound pair is unaffected; one
              debit per contract_id; Redis loss over-admits at most as for leases
FS-46  §20    a data pack ending in a year and a team_credit ending in 30 days: escrow takes   FI-13d      T2+T3  M6-in
              the pack first; a partial settlement returns to the line first; a lease on the
              line, the edge killed, 24 h later the reservation is gone with no debit; the
              provider is paid at the line's rate
FS-47  §20    at the exact storage limit, and spent: each maintenance push kind (DELETE,       FI-13c      T2+T3  M2-out;
              CONSUME, ERASE, BASE, PATH_EPOCH, config, re-seed) passes; a 1-byte ordinary                        §21 case
              push and a maintenance push naming a new segment are refused; on a synthetic                        at M5-out;
              record-class file whose one chain holds several entries' fields, an erasure's                       mail case
              CLOSURE push and its ?closure=1 uploads pass, one whose merged record crosses a                     at M7-out
              Padmé step included, then its ERASE, after which the erased entry's fields no
              longer open, its §16.8 erasure entry held by its device at the limit and
              committed once the network is under it and not spent; a CLOSURE push that
              creates, deletes, carries a directory delta, grows a chain past Padmé of the
              chain it replaces, omits a replaced slot or comes from a non-admin is refused,
              below the limit too; at the limit a non-admin closure upload, one over 1,088 KiB
              (§15.7's largest i/ segment, padded) and a plain segment upload are refused; an
              ERASE or CLOSURE push past the network's 60 a minute queues as P1 and commits,
              while closure uploads past their eraser's rate, its own 60 a minute, and closure
              uploads or CLOSURE pushes past their eraser's daily allowance, get 429 with
              retry_after_ms (the allowance's at the next 00:00 UTC); admin A past its rate,
              its ERASEs past the network's, or its allowance spent on CLOSUREs no ERASE
              follows leaves admin B's closure uploads passing and its erasures committing; k
              erasers asking at once, as when allowances reset at 00:00 UTC, are each served
              once every k/4 s, none starved, the network taking at most 4 uploads a second,
              and erasers obeying a retry_after_ms over a minute get equal turns against
              erasers re-asking every second; a §21 row below the floor or changing the pacing
              is refused, and one written directly is clamped to the floor or, for the pacing,
              ignored (§11.12's rekey row, §20.4, §20.7; owner decision 146); at M7, a mail
              erasure whose IndexEntry shares an i/ segment with other messages, its
              re-checkpoint crossing a Padmé step, and a 30-day trash shred spanning several
              i/ segments complete with no reader opening their index fields, and at the floor
              a shred of n full i/ segments, refused past its eraser's allowance, completes in
              CLOSURE and ERASE parts resuming at retry_after_ms, its last committing within
              ⌈n/3⌉ days of fake clock (§20.7's wait), the messages' bodies unreadable from
              its first ERASE, which spends no allowance; from M5, the abuse worker opens a
              case with no machine action for a network whose closure bytes taken at the
              storage limit grow its stored bytes past it, and a reviewed tightening row takes
              its erasers' allowances to the 4 MiB floor and lowers its
              config_statements_per_day, while revocations still append (§21.7); the nightly
              count corrects an injected drift
FS-48  §21    a §2258A hold across days 180-364 while §2703(f) holds expire at 90 and 180;     holds       T2     M5-out
              sweeps resume at expiry; --now and erasure proceed under both
FS-49  §21    abuse clocks on a fake clock across a weekend; every registrar or registry       clocks      T2     M5-out
              notice pages
FS-50  §19    a page-class condition at 02:00 on the fake clock (a set at_risk or refusing     D-OPS-9     T3     M3-out;
              writes, the Postgres primary down, budget burn; from M5 both nameservers                            drill: the
              failing, a broken 443 split, a failing canary signature, a registrar notice)                        hosts row
              reaches the rota's pager sink and pages the second person at 30 min
              unacknowledged; the out-of-hours return of a host within 4 h is 22.8's hosts
              row, run on production (owner decision 143)
FS-51  §20    a Team lapse: after 14 days web hosts and From are withheld, MX and TLSA kept,   D-QUOTA-6   T2     M6-out
              and mail still arrives
FS-52  §19    dns API blocks N and N+1 serve together at 25%; edges apply both journals; a     Q-OPS-5     T3     M5-out
              rollback from N+1 to N
FS-53  §19    a config repo with under 256 KiB of aged history: its records go to a parcel at  FI-1        T2+T3  M2-out
              25 h and pack at 7 d; reads verify at each step (owner decision 136)
FS-54  §19    server's build legs: a release leg built from a main that holds another track's  D-OPS-6     T3     M1-out
              pending group links main's migrations only; the T3 build with the tag links the
              pending group; a Gn-out promotes only its own group
FS-55  §19    migration N+1 applied while binary N runs; binary N restarted on the N+1 schema  R-OPS-5     T3     each
              (rollback); then N+1's gate enabled                                                                 Gn-out
FS-56  §17    the hook resolves a flow and its dial waits at a barrier; a revocation swaps the FI-11       T2+T3  M4-out
              policy and runs CloseFlows; the dial completes: reset before any byte reaches
              the target, for TCP and UDP, and for ICMP no echo reaches the target and none is
              answered, a silent drop; the twin without a revocation forwards; a bridged
              TCP/25 SYN gets the reject client's answer, and no local dial follows it
FS-57  §11    a batch PUT applied and its response dropped; evs killed after the batch write   FI-1,2,6    T2+T3  M2-out
              and before the head CAS; the push id retried on evs2, which writes a second
              record and commits; the first process's delayed head PUT fails; evacuation keeps
              the committed copy and drops the other; again with the store unreachable during
              the batch write (503, nothing committed)
FS-58  §11    a path changed in unfolded versions read, listed and CAS-checked, with and       FI-1,6,15   T2+T3  M2-out
              without the cached head; a directory changed in every version across a page-out
              keeps its whole listing; a fold killed after half its entries, then rerun; two
              folds of one entry race; a page-out whose fold meets 412s; folds blocked until
              the window reaches 255 (429 FOLD_BEHIND), then released; on an idle ref whose
              folded_through trails v, a PATH_EPOCH push folds every unfolded version and
              commits with folded_through = v; push A reads head v1 and X's entry, then waits
              before step 7 while B commits X at v1+1, a fold takes in v1+1 and a commit
              raises folded_through past it: A's 412 rerun, keeping the folded_through its
              entries were read after, gets 409 naming X; again with that fold and commit
              landing between A's head GET and its entry GET, and with A's rerun after the
              window paged out versions past A's horizon, A's step 4 once from a cluster head
              and once from a cached head minutes old: A reads X's entry again after the
              reread head and gets 409; an entry holding a version above the served head's v
              sends evs to a newer head, again with a fold and a horizon-raising commit
              between that entry GET and the newer head's GET, then a listing; head reads and
              listings at each barrier show B's change and nothing above the head they serve;
              two folds of (f, f+64], which holds directory D's removal, the first held in
              P2's queue: the second marks D and D/x removed and its commit raises
              folded_through, D and D/x are re-created past f+64, and a third fold takes them
              in, its commit raising folded_through past them; the first then runs, finds
              newest folded versions newer than the removal and writes nothing; again with its
              marker PUT, issued before the second's, applying late within §19.6's 10 s
              request deadline: its If-Match fails and its reread writes nothing; so reads and
              listings at every barrier show D/x, and another push creating D/x gets 409;
              again for a file X removed and re-created, where a push based on X's version
              from before the removal gets 409 before and after the re-creation, X's versions
              continuing from its marker, and X re-created after its marker's collection,
              after a path-epoch copy dropped its source marker and, on an overlay, after the
              base ref's higher versions, each time at a version above every earlier one,
              while a creation whose version is not max(b, m) + 1 gets 409 and replaying
              readers alarm; once the horizon passes a marker by a base range, a collection
              window held at a barrier while a fold re-creates the path deletes no live entry,
              with the collector's and the folder's clocks 50 ms off in opposite directions,
              the store host's clock 50 ms off, the fold's 15 s deadline slewed 100 ms and a
              fold write held at a drive barrier past it, a fold that read the window's head
              writing over the marker only 150 ms past until_ms by its clock, and a push
              based before the removal is refused by 5f's base range (owner decision 148)
FS-59  §11    a segment uploaded; a push checked 23 h 59 min later pauses before its head CAS  FI-6        T2+T3  M2-out
              on an idle ref; at 25 h GC deletes nothing; at 49 h evacuation fences the ref
              for the push's record and drops it; the push fails its CAS and answers 503
              unknown, and its retry gets 409 SEGMENT_GONE; GC then deletes the segment by a
              DELETE naming its LastModified (owner decision 203); again with a push that
              creates its ref and whose head write the store holds past 51 h: evacuation and
              GC wait, and the write landing keeps the segment while its revert lets the
              placeholder head fence the ref and GC delete; a creating push killed after its
              record: a fenced placeholder, the ref listing as absent, the record and its
              slots gone; two GC runs on one orphan with its bytes uploaded again and
              committed between their DELETEs: the second answers 412 and the segment stays;
              a re-upload of a 23.5 h old segment gets 409 SEGMENT_STALE; a forged or
              other-repo receipt is refused; the twin whose push commits before evacuation
              keeps the segment
FS-60  §11    evacuation killed after a pack, after its pidx/ entry and before the batch       FI-1,13c    T2+T3  M2-out
              delete; a reader at each step finds every record; a pending record on an idle
              ref fenced, then dropped; a shredded repo's records dropped, a deleted repo's
              kept; a held network's records, a shredding repo's included, packed and not
              deleted; a small repo's parcels pack at 7 d, the replacement killed between the
              pack's entries and the parcel's delete, readers taking a pack's entry over a
              parcel's; a seal evacuated a run after its parts, each container holding its
              entry; a run killed after a container and its pidx/ entries, restarted once a
              log page has turned 24 h old, moves only what no container holds, and the
              nightly pass deletes a container whose every record newer entries name; the
              nightly count equals LIST sizes plus batch-resident lengths, less held-only
              objects and superseded containers (20.7)
FS-61  §11,19 fake drive counters at 0.9 DWPD's rate: allowances fall within 10 s; a Pro       FI-14       T2+T3  M2-out
              network flooding pushes is refused first (429, retry_after_ms), shedding the P2
              work its pushes would cause, while a Community network keeps its p99;
              revocations, shreds, erasures and REMOVE rotations proceed at once (P0), their
              bytes reported by kind; folds and evacuation keep pace from the wallet; the
              governor killed: processes hold their share 60 s,
              then half, and a new process starts at the refill over twice the process count;
              at 2x year one's mix with the budget on, refilled at 0.8 DWPD as for the nvme
              row, over 26 h of fake clock each push's P2 work is charged once, so the budget
              refuses no push, no ref reaches FOLD_BEHIND and no batch outlives 26 h; with a
              full-rate path-epoch copy added, evacuation, first in P2's deadline order, still
              keeps every batch under 26 h
FS-62  §11,10 {evsq_}, {evsl_}, {evsh_} and {gka_} lost together: the next hint version        FI-1,2,3,10 T2+T3  M2-out
              exceeds every earlier one and no client alarms a lower version; holders
              re-create leases at their hourly resync and miss no later commit; a stale
              cached head sends a reader with a newer pin to the cluster, a ref's head cached
              over 10 min ago is not served though another ref of the repo kept writing, and
              a push with a stale cached ETag fails step 7 and costs one cluster read; FS-1
              with {evsh_} a version behind and the gate closing before the retry: 200,
              nothing deleted; {acl_}e lost, then stale (an older {acl_}v): api, evs and gkm
              read proj/ instead, and none accepts a lower n; the epoch reconciler deletes
              nothing for 30 d; exact versions (§6.8, §11.10): with the master's TIME fixed
              at 1793836800 s and 123456 µs, the sequence script seeds 1793836800123456000,
              and its next 1,024 raises, each read through the real publisher and decoded by
              the core on every build leg, are 1793836800123456001 to 1793836800123457024,
              each the exact successor of the one before; a twin script returning INCR's
              reply as a Lua number fails at the first, reading 1793836800123456000; lost
              again, a TIME of 1793836801 s seeds 1793836801000000000; the per-client script
              keeps 1793836800123457024 against 1793836800123457023 and against an equal
              value, raises it to 1793836800123457025, ranks a 19-digit value below a
              20-digit one, and raises a gkm clock version that is not above the stored
              one to the stored value plus one
FS-63  §11,19 placement and pools (owner decision 145): two creators race at place/<repo_id>'s FI-1,2,4    T2+T3  M2-out;
              If-None-Match: one places the repo, the other gets 409, and the winner's retry                      each next
              after a lost response continues on the cluster place/ names; with place_new                         cluster
              naming a second metadata cluster, new repos and their gkm groups, batch records
              included, land only there and placed repos' objects never do; evs and gkm
              restarted resolve every repo to the same cluster, a cached 404 clearing within
              5 s; place_new naming an unreachable cluster makes creates 503; a metadata or
              segment cluster with more than one pool fails the suite before any write, read
              from MinIO's admin info (madmin-go/v3@v3.0.109 info-commands.go:276,
              InfoMessage.Pools), and the one-pool twin passes
FS-64  §11    a 20 MiB versionless file X at version k, five 4 MiB kind-5 chunks; reader R1    FI-1,16,17  T2+T3  M10-out
              streams k by ranges and R2 holds k's locators from a head read, paused; a push
              replacing chunks 2 and 4 commits u on evs1, which reaches the purge's certainty
              with exactly those two as candidates; R1's ranges inside the 60 s allowance all
              succeed; after it evs1 deletes the two; R2 resumes, gets collected, rereads the
              head and reads k+1, alarming on nothing; a reader served a cached head that a
              failed cache write left at k gets 404, is sent to the cluster head and reads
              k+1, alarming on nothing; a history read of k returns its signed entry version
              and collected; chunks 1, 3 and 5, which k+1 cites, stay; a push based on k gets
              409, and a copy citing k's chunks from another path 409 VERSIONING; one push
              removing X and creating X' from k+1's chunks keeps them; a client re-uploading
              the exact sealed bytes of u's chunk 2 for a version k+2 gets 409 VERSIONING, the
              kind-5 header naming u's push, a versioned segment's equal bytes get an unmarked
              receipt no kind-5 locator may name, and the purge's reread keeps any candidate
              the path's newest version names, so k+2 reads whole; the twin without the
              overwrite deletes nothing
FS-65  §11    u's head CAS applied, its response dropped, the store then unreachable: evs1     FI-1,2,16   T2+T3  M10-out
              answers 503 unknown and purges nothing; the client's retry on evs2 resolves u
              committed, and the replaced content goes once, after that certainty and the
              allowance, by evs2 or the sweep as §11 names; again with the CAS never applied:
              the retry commits at a later version, the replaced version readable until then;
              evs1 killed at the purge's certainty: nothing goes until the sweep, the fake
              clock past its period, resolves u and deletes; evs1 killed after half its
              DELETEs: the sweep deletes the rest, 404 counting as done; a 412 rerun
              committing at v+2 purges what the path's newest version at that commit names,
              and a push another writer beats gets 409 and purges nothing; a GATE_CLOSED or
              other conclusive refusal after candidates were computed purges nothing; evs1's
              clock 150 ms fast, or its offset unknown: no DELETE before 60 s of checked time;
              a DELETE delayed to §19.6's request deadline removes only its own candidate
FS-66  §11    a staged head file replaced 10 min after its write: its record is dropped at its FI-6,16     T2+T3  M10-out;
              batch's evacuation, never reaching seg/, and from 60 s after the replacement                        hold case
              history reads answer collected; one still newest at its batch's evacuation:                         M5 (23.6)
              written to seg/ (If-None-Match, its id as checksum) before the batch DELETE,
              then replaced and purged by the committing process after the allowance;
              evacuation killed between the seg/ PUT and the batch DELETE, then rerun: equal
              bytes on 412, one object; a reader at each step gets the bytes, retrying seg/
              after a batch-range 404; a dead push's staged record never reaches seg/; one
              whose replacing push is pending at evacuation: the ref's fence, Resolve, then
              written or dropped; under a hold, staged records from batches before its
              placement are written at evacuation, and content written and replaced during the
              hold is purged as usual
FS-67  §11    a bucket directory removed by one push listing each versionless file below it:   FI-16       T2     M10-out
              each file's content is purged after certainty and the allowance; one file left
              unlisted: the removal fold alarms and carries its kind-5 segment and slot ids in
              its marker, whose collection deletes them; a ref DELETE listing its versionless
              files; a path re-created below the removed directory in that push keeps its own
              content; a removal racing a write of a listed file: one commits, the other gets
              409, and nothing the survivor names goes
FS-68  §11,7  on to off on a chunked file cites its chunks as kind 1, uploads nothing and      FI-1,17     T2+T3  M10-out
              never purges them; on to off on a small diffed file writes one checkpoint; off
              to on adopts uploaded kind-5 chunks as kind 1, never purged after; a repo under
              no VersioningRules takes the platform rule, versionless above 64 MiB: an honest
              client writes 65 MiB versionless and 63 MiB versioned, while a present
              VersioningRules record that matches no rule leaves a new 65 MiB file versioned;
              an admin's VersioningRules edit sets the paths created after it in every repo
              without its own rules, existing paths keeping theirs (owner decision 167), and a
              repo's own RepoVersioning rules replace it there; git-mode refs, creates-only
              refs, config and mailcfg never take it, a writer ignoring that getting 409
              VERSIONING; a lock by §8.8's signer (a repo admin or a config writer, in an
              owner-bound repo only its owner's consented device) refuses versioning off with
              409 VERSIONING, the index's own files still committing (owner decision 168), a
              push validated before the lock's projection committing within §11.8's 5 s window
              or refused, never later, and an unlock restores it; drop history is FS-89 to
              FS-96's
FS-69  §11,21 a hold placed before a replacement: what existed at its placement is kept, its   FI-5,16     T2+T3  later of
              staged records written to seg/ at evacuation, while content written and replaced                    M5-out and
              after placement is purged; a hold placed between the purge's certainty and its                      M10-out
              DELETEs: none issues after the purge rereads hold/ (cached at most 5 s), and one
              already issued completes; an ERASE of a versionless record-class entry under the
              hold destroys its key at once, the ciphertext staying; the hold ends: the sweep
              purges each held candidate since its placement; a --now shred under it keeps
              ciphertext as FS-6 states; holds ship at M5 (§21.9)
FS-70  §11,19 a desktop mirror syncing as a purge lands: its fetch of the replaced version     FI-5,12,16  T2     M10-out
              404s, it rereads the head, applies the replacement and alarms on nothing;
              re-seed after a site loss from a mirror holding only newest versions: history
              verifies, replaced versionless versions read collected, staged heads re-upload
              as segments, and evs refuses kind-5 content for a version the re-seeded history
              replaces, so a stale mirror resurrects nothing; a mirror whose copy ends before
              the replacement re-seeds the replaced version's content as newest
FS-71  §11,20 at the exact storage limit, deleting versionless files is accepted and stored    FI-13c,16   T2+T3  M10-out
              bytes fall after the purge and the nightly pass; an overwrite adding payload
              gets QuotaRefusal; staged records count only while their batch lives and kind-5
              segments until purged, the committing process reporting kind-5 deltas and
              taskworker those of the staged records its evacuation discards, the sweep's 204s
              counting nothing twice, and a staged candidate replaced 23-25 h after its push
              subtracted once; in D-TEST-12's observe mode replaced content counts until
              deletes turn on
FS-72  §11,7  format-1 code (M2) given each signed, well-formed format-2 construct (an entry   FI-1,2,17   T2+T3  M2-out;
              version with versioning 1 or 2, a kind-5 locator, a staged mark, a kind-5                           the rest at
              header, a versionless receipt, a format-2 batch, a window entry with bit 4 or 5,                    M10-out
              an EvsPush with flag 256 or 512 or field 33 or 34, a read reply's drop_pending
              or dropped state, repo/'s format 2, a write to .ur-index/, ur/index or ur/lfs)
              refuses each entry, locator, push and state as FORMAT_UNSUPPORTED
              {needs_format: 2}, ignores bits 4 and 5, from M3 sets and honors a push
              provenance's tainted bit (owner decision 245), and on repo/'s format 2 refuses
              pushes and serves stored bytes, writing nothing
              and raising no fork, tamper or missing-segment alarm, while a malformed or
              unsigned construct still alarms; given a config head holding a VersioningRules
              record it applies nothing from the record and still applies the head, with no
              FORK and no stall, and given a RepoVersioning statement it verifies it, folds
              its lock and enforces nothing, its rows equal to a format-2 device's; an
              EvsShare past its expires grants nothing, the directory kind is known and, given
              a team network's projection, its kind-default readers and writers equal an M6
              build's, agents' directory Adds and wraps accepted without alarm, an
              autogroup:dst-owner approver evaluates as §8.4 states, and
              ServiceSettings.directory is ignored; the descriptor lint finds format 1's
              reserved numbers equal the decided list, none for keep-last-n; at M10, a repo
              migrated by §11's step while a format-1 client pushes and reads: its versioned
              pushes commit, and it refuses format-2 entries as needing format 2; a migration
              killed at each step resumes, no repo left half-migrated; evs and taskworker
              rolled back to format-1 binaries after format-2 data exists refuse format-2
              pushes, purge nothing, and leave batches holding staged records to a format-2
              evacuator, alarming, so no newest version's content is lost
FS-73  §11    stock git and git-lfs push commits with LFS files: the transfer agent writes     FI-9,16     T3     M10-out
              each object's path in the ur/lfs store (<oid[0:2]>/<oid[2:4]>/<oid>) before the
              ref update, a creation or a touch citing stored content, and smudges it at
              checkout, the pointer blobs keeping export's oids; a daily prune by an indexer
              or a client holding every ref removes objects that no ref tip and no commit,
              upload or touch of the last 30 days (a repo setting) references, the purge
              following, and a client missing a ref refuses to prune; a git push racing the
              prune touches its objects first, so the prune's removal fails path-level CAS and
              reruns; an old commit whose objects were pruned checks out with pointer files
              under lfs.skipdownloaderrors (and GIT_LFS_SKIP_SMUDGE), ur naming them and when
              their prune committed; the tip check, with no skip option set: A holds pointer
              O and B, the tip, removes it, A and O's last version aged past N on the fake
              clock and O pruned, a force push from B back to A, a new branch and a tag at A
              each get lfs objects missing, naming O and git lfs push --object-id, the evs
              tip staying B until that upload, after which the push commits with O's version
              fresh; O unpruned and its version past N: the force push touches O before
              its POST, and a prune paused between its start read (tip B) and its removal
              fails path-level CAS and reruns, keeping O; a commit whose new object is
              absent, pushed with --no-verify or GIT_LFS_SKIP_PUSH=1, is refused alike; a
              .gitattributes change that puts a stored pointer under filter=lfs checks its
              object; ur evs import uploads its directory's objects first; an owned ref
              published after an offline push holds when its object was pruned meanwhile, ur
              status naming it; ordinary pushes upload each object once and write no extra
              touch, pointer bytes and oids exact; a settings file naming N below 7 days
              reads as 7
FS-74  §11    two writers' pushes to one file-mode ref, each changing only its own head file   FI-18,20    T2+T3  M10-out
              in the current bucket, land at v+1 and v+2, both documents found; one sidecar's
              two concurrent pushes race on its head file: one commits, the other gets 409,
              and its index code merges its delta into the winner's file and retries, losing
              and duplicating nothing, where a user's versionless file is never retried this
              way; a seal, only at 16,208 B and never on idle, racing the writer's next
              commit: the commit lands in the next slot or the seal reruns; two mergers of one
              bucket's seals race: equal plaintext, one commits, the other's uploads become
              orphans (§11.13); on a git-mode ref, a writer killed between its git push and
              its companion index push: that commit's documents are searched from local text
              where a device holds it, else reported not yet searchable, until a companion
              push or a backfill covers them; a commit from a client that skips the index, an
              old client or a phone, likewise until an indexer designated for search, else the
              next capable writer, backfills it; a commit just past a bucket boundary by its
              signed time writes its first slot in the new current bucket
FS-75  §11    the indexer designated for search rolls an expired bucket and is killed at each  FI-18,19,20 T2+T3  M10-out
              barrier (the lock taken, the merge built, its uploads, its batch write, its head
              CAS with the response dropped, after the commit before the purge): each rerun
              ends in one committed roll-up whose plaintext hash equals the deterministic
              merge; with that indexer offline, a writer committing a day past expiry rolls
              it, and with no indexer for the repo the first writer committing after expiry
              does; an indexer returning mid-roll waits on the lock, a holder that dies loses
              it at its expiry, and its late push fails at CAS; two rollers reaching CAS
              anyway build equal plaintext, one commits and the other gets 409; a search at
              every barrier merges the expired bucket until the roll-up commits, and a device
              holding a stale all keeps the dropped bucket's files until its all records the
              bucket absorbed, drops them at any ERASE in the repo and keeps them no more than
              2W days after the roll-up, so the result set is the same before, during and
              after; a device holding the roll-up's inputs reproduces it, checks
              content_sha256 and downloads nothing; at the storage limit the roll-up is
              refused (it adds payload), the expired bucket stays and searches merge it until
              the network is under the limit; a phone as the first writer rolls within §18.4's
              budget or defers to a capable writer; an erasure's CLOSURE of the expiring
              bucket racing the roll-up, in both orders: one gets 409 and redoes its work on
              the other's result, and the erased document's postings survive in no committed
              file current keys open; a roll-up built before an erasure's CUT gets 409
              INDEX_EPOCH at its push and reruns from step 1 without the listed documents; a
              window change applies from the next bucket (§11.14), every document staying
              searchable
FS-76  §11,16 a generated corpus of mail and notes (ASCII, CJK, combining marks, NFKC and      FI-18,19,22 T2+T3  M10-out;
              case-folding edge cases, punctuation runs; MIME with base64, quoted-printable                       team record
              and HTML parts) written over 200 days of fake clock by four writers, with edits,                    M6, mailbox
              renames, deletions, re-creations and commits that skip the index; at every                          M7, holds
              bucket boundary +- 1 s, every roll-up barrier and after each erasure, a query                       M5 (23.6)
              set (words, five-letter prefixes, four-letter infixes, two-word phrases, one-
              and two-character CJK, addresses with punctuation) runs on the buckets and on
              buckets plus all, on a desktop and a phone, against SearchOracle: the desktop's
              hits checked against its own text equal the oracle's; the phone's candidates
              include every covered oracle hit and none resting only on a version hidden by
              newest-version masking, a tombstone or the ERASE mask; an uncovered document is
              found from the device's own text where it holds it, else reported not yet
              searchable; buckets follow the commits' signed time, a reader 10 min skewed
              computing the same ones, and instant coverage spans 30-60 days; a writer's delta
              that omits a document or drops or adds trigrams, and a rebuild or roll-up whose
              uploaded bytes differ from what its inputs give, are caught by hosts holding the
              text (the indexer designated for search checking every repo it reads), which use
              their own result and raise index_mismatch; in the team record, an entry past
              searchable_days (90) is masked from every search at query time, all included,
              and is still readable by id; scopes network and all merge repos as the oracle
              does; erasing a document whose postings sit in an index file a hold kept from
              before a REMOVE generation re-keyed its path, and one that a merge and a roll-up
              moved after a hold's placement, leaves no stored version holding either under a
              readable key
FS-77  §11,18 an ios32 and an Android surrogate cell and a page Worker, each holding the       FI-18,23    T2+T4  M10-out;
              buckets and not all: a search answers from the buckets at once; with no indexer                     app hosts
              designated, the default (owner decision 177), "search more" fetches every all                       M8 (23.6)
              object the device lacks, whole and newest first, and lists its hits with
              subject, from and date from the display fields: a hit whose display field holds
              the query is confirmed with no fetch, and the rest are possible matches, ranked
              by trigram overlap, until opened, which confirms or drops them; no body or note
              is fetched before an open; two different queries from equal sync states, with
              and without more, give identical server-visible request traces; on cellular and
              unplugged nothing of all is fetched in the background; on Wi-Fi while charging
              it syncs only in an OS-granted window, which stops at its budget and resumes,
              Low Power Mode pausing it; a "search more" needing over 25 MiB on a metered link
              waits, reporting waiting=metered, until the host repeats it with AllowMetered; a
              device override holds either way, the key origin's search policy request as
              SetPolicy's; no hint, wake or mirror sync fetches all; a fetch of a replaced
              index file answering collected rereads the head and fetches the newest; the
              search stays within §18.4's budgets, all encrypted on disk and one 64 KiB frame
              decrypted at a time; the page Worker keeps all within 128 MiB a network, two
              ur.io tabs relaying to the Web Lock's holder, and the quick burner keeps its
              buckets in memory only; an erasure hint drops the erased document from every
              cached block before the next search; the page Worker's conditions come from the
              key-origin frame, so a Chromium-on-Android tab on Wi-Fi while charging keeps all
              while open, while Safari and Firefox, which hide them, count as metered and not
              charging: all waits for "search more", and one over 25 MiB for AllowMetered; an
              app that has not yet called SetConditions counts as metered; an iOS
              BGProcessingTask window on cellular fetches no all; ur search sync --evict,
              DropCache and the caps' eviction keep §5.9's non-derived search state (policy
              overrides, remote mode, notice answers and served records), while a browser's
              whole-origin eviction loses it with the keychain, the next Worker starting from
              defaults (§5.9's rebuild row); a phone runs its merges and roll-ups only in
              windows, within its cap (FS-75)
FS-78  §11,15 a mailbox and a vault, both indexed, at the exact storage limit and spent, the   FI-5,13c,19 T2+T3  M10-out;
              eraser at evs_closure_bytes_floor: an admin's erasure of one email first commits                    mailbox
              its CUT and an ERASE of the email's own keys, both at once, the email masked in                     M7, holds
              search from the CUT, then rewrites in place, by CLOSURE pushes, every                               M5 (23.6)
              versionless index file holding its postings or display fields (its bucket's
              files, the all files holding it), each upload at most 1,088 KiB and each chain
              within Padmé of the one it replaces, then the ERASE destroys the old keys; the
              old ciphertext is purged after certainty and the allowance, staged bytes leaving
              with their batches; the erasure completes within the days and turns §11.13's
              wait row gives for its closure bytes on the fake clock, its postings openable to
              key holders until its part's ERASE commits and never after; on the hint each
              reader drops the replaced index files, its local overlay and vocabulary entries
              for the document, any retained bucket and the document's journaled companion
              entries, so the desktop, the phone and the daemon's cache all miss it; a
              companion push built before the CUT gets 409 INDEX_EPOCH and rebuilds without
              the document, and no watch follows the ERASE (§11.14); a note edited across
              several windows has every all file holding any of its versions rewritten; an
              iOS-only eraser fetches the files holding the document, not all; under a hold
              the keys go at once and the ciphertext stays; a CLOSURE that would create,
              delete or grow an index file past its replaced length is refused; an ephemeral
              sidecar's in-memory index cache stays inside MemoryBudgetByteCount on a "search
              more" larger than it
FS-79  §11    a repo admin turns the index on: one full build by a device holding the text     FI-18,21    T2+T3  M10-out
              lands, searches answering not yet searchable until it does, two devices racing
              it building equal plaintext with one committing; turned off: one push removes
              every index file, purged after the allowance, and searches answer index off; a
              format-1 repo's migration ends with its first build; config, mailcfg and secret
              repos hold no index, honest writers write none there and readers ignore a forged
              one; content sniffed as binary, and chunks whose key set would pass 512 KiB, are
              skipped, text past 1 MiB indexed by 1 MiB chunk, and a versionless file above
              the network rule indexed only if text; a repo whose index is off takes no delta
              from an honest writer
FS-80  §16    a team network with its directory (owner decision 171) instead of a coordination FI-21,23    T2+T3  M10-out;
              log, the team record, two members' vaults and a mailbox; agents A, B and C claim                    team record
              tasks, run and hand off: ur agents and search_agents for a task's words return                      M6 (23.6)
              hits grouped by (network, sidecar, agent label) with run ids and titles, active
              groups first; another member's run is found through its announcement unless its
              member opted out (owner decision 170), and admins and auditors also see its
              team-record run card; ur search and the MCP search tool at scopes repo, network
              and all return exactly the oracle's set over the repos the session's subject may
              read, filters by agent, time, kind, path prefix and field equal the oracle's,
              and more adds all; no secret, config or mailcfg repo is searched, and
              search_status names each excluded repo with its reason, except secret repos,
              which it omits (§16.6), a parked device's member vault as consent pending; a
              repo named in repo scope with its index off is searched by §11.14's no-index
              rule, while network and all scope exclude it; an EvsShare reader deposits a read
              receipt before decrypting each index object, skips the repo when the deposit
              fails, and stays within D-MCP-18's budget over 300 searches a day; an untrusted
              hit returns as a text-free stub and leaves the run untainted, while untrusted:
              include fsyncs the run's taint before it returns, a failed fsync failing the
              call, and the run's next O action then needs a fresh decision; ur search
              --untrusted include from a harness's shell tool or an editor's integrated
              terminal taints the run its process ancestry binds, from a terminal outside
              every harness taints nothing, and with stdout not a terminal withholds untrusted
              text; an ERASE while a cursor is open: the next page answers cursor_expired, the
              cache's replaced objects and local-layer postings are gone before the hint is
              acknowledged, and a new search misses the document; after a read loss the repo's
              cache is deleted; a third search in a session waits up to wait_ms, then answers
              busy, retryable; a page holds at most 64 KiB, a query past 20,000 candidates
              answers too_broad, and more's downloads stop at Search.MoreByteCount, debited;
              every hit carries trust and source
FS-81  §11,19 fake drive counters at 0.9 DWPD's rate with format 2's mix: a network whose      FI-14       T2+T3  M10-out
              background index work (roll-ups, merges, backfills, full builds) floods its
              queue is refused first, the others keeping their p99, while erasures' CLOSURE
              pushes and slot rewrites proceed; at 2x year one, the budget refilled at 0.8
              DWPD and the index on in every eligible repo, over 26 h of fake clock no push is
              refused, no ref reaches FOLD_BEHIND, no batch outlives 26 h, and each companion
              and roll-up push is charged once
FS-82  §7,15  indexers (owner decision 150): an IndexerSet at network scope from an Owner or   I-4         T2+T3  M2-out;
              Admin, and at member scope from a consented device of the subject's member, is                      M7-out;
              accepted; one from a read_only, parked or other signer, naming an ephemeral or                      M8-out
              read_only subject, or asked through MCP, is refused, and the subject retires
              either; no designation adds a key, grant, ReaderWrap or read; with no mail
              indexer an online receiver still takes mail and GetReceiverCoverage reads
              foreground-only, then indexer once one is designated (M8); under team_mail:
              indexers an undesignated tag:mail device registers no listener, and internet
              mail naming it alarms readers (M7); with no mirror indexer, ur status names
              every unmirrored record-class repo
FS-83  §11,18 remote search (owner decisions 175, 178), with the member's indexers designated  FI-18,24    T2+T3  M10-out;
              (none by default, owner decision 177): a phone surrogate, its member's two                   +T4    app hosts
              search indexers (desktop, NAS), another member's network-scope search indexer,                      M8, team
              and a repo of each kind: the member's mailbox and vault, an EvsShare'd vault,                       M6 (23.6)
              the team record, the directory and a group inbox; eligibility: the mailbox and
              vault go only to the member's consented indexers, never to the other member's,
              even with every own indexer down (they fall back); a team repo goes to an own
              indexer that reads it, else to the network-scope one; another member's
              member-scope indexer, a retired, revoked, parked or suspended one, one without
              search, an app host, a read_only or ephemeral sidecar and a forged IndexerSet
              are never asked, and each refuses a request sent anyway; the indexer refuses
              repos the requester does not read in its own state, and a read revoked
              mid-cursor refuses that repo on the next page; notice: no request reaches the
              other member's indexer before the notice is answered, "only my devices" sets
              own, and a new answering member asks again; sizes: every request body is 4,016 B
              and every reply steps x 16,384 B in one frame sequence, for queries with 0, 1
              and 20 hits, TOO_BROAD, INVALID, CURSOR_EXPIRED and UNSUPPORTED_VERSION, and no
              Cancel is sent; connect: the pair's close reports follow C19's windows in both
              directions whatever ran in them (FS-125), and a pair whose Hellos carried no
              bit 1 reports its bytes exactly; evs: both devices' evs request logs are
              identical with and without
              the remote search, the indexer issuing no read at search time even with a hint
              pending; merge: against SearchOracle, the merged list equals the oracle's
              verified set over SERVED_TEXT repos, a local possible match inside the checked
              span that no page returned collapses, one outside it or newer than the pinned
              version stays, an ERASE mid-cursor answers CURSOR_EXPIRED and the erased
              document never shows; a fabricated hit is dropped on open with
              search_alarm{mismatch}, and a display-field match the indexer omits inside its
              span raises search_alarm{omission}; failover: the first own indexer killed
              before and after page 0, the second answers; both killed, the network indexer is
              never asked for the vault, which falls back to the download under the metered
              rule; limits: a fifth concurrent search queues or is refused, a requester past
              30 requests a minute gets RESOURCE_EXHAUSTED, and 100 requesters at once never
              push local searches past §16.10's targets; logs: the query canary is in no log,
              metric, trace, crash report or state file on either device, and the served
              record names no query
FS-84  §16,11 directory writers: a card signed or pushed by another sidecar, by a parked,      FI-25       T2     M6-out
              revoked, reaped or suspended one, with a seq not above the last or an auth pin                      (entries);
              out of range; a repo announcement by a non-admin, or for an owner-bound repo by                     later of
              an admin; a revoke by a non-admin of the repo; a notice rewritten by a                              M6-out and
              non-approver; a removal of a live sidecar's card by another member: every reader                    M10-out
              ignores it and alarms, and the rightful writer's repair restores the file                           (cards)
              (§16.11's repair row), no stream entry lost; a non-admin's ERASE, CLOSURE,
              closure upload or slots/delete is refused before any slot changes (FS-99); a
              repo admin's revoke files an erasure_request, which the erasure runner completes
              over exactly the copies that name its repo; a general or record repo's
              announcement is written at its creation, and a private marker instead when it is
              marked private, padded alike (owner decision 181); readers ignore an
              announcement for config, mailcfg or the directory; an admin's moderation removal
              is accepted, with an alarm on the member's devices; any writer may remove a
              revoked sidecar's card; run and worker items expire at expires_millis under
              +-60 s of skew, repo items never; announce entries and cards of one announcement
              fold to the same state
FS-85  §8,16  request lifecycle: a repo request that any repo admin approves yields one        FI-26       T2+T3  M6-out;
              RepoGrant with the asked subject and expiry, and a decision entry naming its log                    M8-out
              position, after which KF3 seats the subject, a request to a private repo by its                     (wakes)
              id included (owner decision 181); an owner-bound request is decided only by a
              consented device of the owner, every reader refusing an admin's EvsShare, and
              the share's expires ends it with no device online; a worker request under the
              directory rule is approved only by its owner's or sponsor's device or presence
              decision (autogroup:dst-owner; owner decision 180), a harness decision being
              refused, and the requester's GrantActivate passes §16.6's spend check once, the
              grant dialing only the services the worker announces (owner decision 179); deny,
              cancel and expiry yield no statement; a decision copied onto another request
              activates nothing; notices hint leasing approvers within §11.10's p99 and wake
              phones from M8; a sidecar's 21st pending and 51st daily request are refused
FS-86  §16,11 scale (D-TEST-17), against §16.11's cost table: 500 members' daemons for 26 h in FI-14       T2+T3  M6-out (M6
       ,19    physical time on T3's stores; the Team limit (2,000 members, 5,000 admissions)                      case);
              and 5,000 members (12,500, a stress case) as a day's events on the fake clock,                      later of
              each with one physical peak hour on T3 at its column's rate and 3x bursts beside                    M6-out and
              §22.8's 1x year-one mix, whose p99 must hold; 400 days of retention on the fake                     M10-out
              clock; a golden schedule (sidecartest's DirectoryCostOracle) computes, from the                     (cards)
              events and each reader's sync times alone, every reader's expected requests,
              path reads and ciphertext bytes, the measured ones staying within 1.25 times
              them per reader-day and per team-day, and three mutants, run one at a time, fail
              that check: no coalescing to each card's newest version, no head reproduction,
              and refetching unchanged cards; the cards ref's commits meet the table's
              ceilings (p99, 412 reruns, 429 BUSY, no FOLD_BEHIND), and injected 200 ms delays
              on head PUTs, or conflicts past those ceilings, fail the run; priced NVMe bytes
              per push per drive within the directory rows of §11.13's price table; heads
              reproduced with no head download on an honest stream; a cold desktop within the
              table's bytes; a cold phone whose current state passes 8 MiB on a metered link
              shows partial coverage naming what is left, and continues with AllowMetered or
              on Wi-Fi from where it stopped, never a complete or empty view; the M6 case runs
              the same on announce entries against the M6 rows, streams read 64 to a request;
              a miss at the Team limit blocks the gate, and the owner hears then
FS-87  §7,10, removal and retention: a MemberRevoke masks the member's cards, notices and      FI-19,25    T2+T3  M6-out;
       16     pending requests at its position in every reader; the directory group's Removes                     later of
              and rotation reach leaves and wraps (owner decision 182), and the removed                           M6-out and
              devices get no later generation; with no indexer designated                                         M10-out
              (owner decision 177), a member device's cleanup 24 h later removes their cards                      (index)
              and notices; a departing member's tagged agents announce under autogroup:admin
              until a SponsorSet; retention erases entries past keep_days and, at M6, announce
              entries 30 days after a newer entry or file for their item or after the item's
              expiry, keeping a live repo item's newest copy, its last M6 entry until the
              format-2 r/ file supersedes it, since repo items carry no expiry (§16.11's
              retention row), and roll-ups drop documents past searchable_days; after an
              admin's erasure of an announcement, no stored index or card version holding it
              has a readable key; a revoke, seeded with run items naming the repo (M6 announce
              entries; from M10 cards and index documents) and a daemon that renews its run
              before it reads the marker, writes the private marker over the announcement and
              files an erasure_request, and after the erasure runner's later sync no stored
              card, entry or index file holding the name has a readable key (owner decision
              181); retention's expiry runs through the runner, and with no directory admin's
              daemon running it waits, ur status naming the oldest one waiting
FS-88  §16,2  taint and the session boundary: directory_list from M6 and search_agents from    FI-21       T2     M6-out;
              M10 return prose as stubs and the run stays untainted; include taints first, a                      searches at
              failed fsync failing the call; identifier fields written in a tainted run come                      the later
              back untrusted; ur directory ls withholds prose on a non-terminal and taints an                     of M6-out
              ancestor run before printing; canaries in prompts past the first line, in tool                      and M10-out
              inputs and outputs, in touched paths and in diffs never appear in a card, entry,
              notice or index file (I-20); claims off and a project opt-out announce nothing
              (owner decision 170); a .ur narrowing applies at once, and a widening waits for
              the member's confirmation
FS-89  §11    a path of 30 versions (diff chains past two checkpoints, an era over 8 MiB as    FI-1,27     T2+T3  M10-out
              chunks, small inline versions) dropped with the window (owner decision 183):
              pending shown, content readable, a cancel before not_before deleting nothing;
              dropped again: after the window and fence the job deletes exactly the segments
              only listed versions name, the head written fresh with the same oid and mode,
              history verifying with dropped rows and no alarm, export writing stubs that git
              fsck passes, diff and restore reporting dropped; its twin, a live version's
              segment deleted by hand, alarms as a missing segment; --now deletes nothing
              before evacuation's horizon has passed the drop's commit by 2 min, about 25 to
              26 h after time_ms (owner decision 204), nor before not_before_ms + 25 min
FS-90  §11    the job killed at each barrier (start CAS, resolve, each mark checkpoint,        FI-2,13a,27 T2+T3  M10-out
              verify, between a HEAD and its DELETE, after half the DELETEs) and resumed by
              another instance; a stale instance whose lease lapsed issuing a delayed DELETE
              that the store refuses past its deadline, and one held at a drive barrier
              that lands before the new instance's first request on its key or never; two
              instances racing the take: one delete set, each id deleted once or 404, freed
              bytes reported once, no live content lost; taskworker's clock 150 ms fast or
              unknown: nothing starts or deletes
FS-91  §11    racing reuse copies: a push on ref R2 citing a listed version as reuse source,   FI-2,27     T2+T3  M10-out
              paused after its step 4, released (a) before the DROP commits: it commits, mark
              finds it and keeps the shared segments; (b) after: its step 7 past 5 s reruns 5h
              and gets 409 DROPPED; (c) validated after the commit against a cached head of
              the ref that a failed cache write left before the DROP: it commits before the
              fence, found by mark and kept; (d) a multi-part push whose part cited the
              version before the drop, sealed after: the seal refuses; (e) a client
              re-uploading a young candidate's exact bytes, adopting the receipt: the
              candidate waits for its 25 h, verify finds the adopter, nothing it names goes;
              past 23 h the re-upload gets SEGMENT_STALE
FS-92  §11,21 holds (owner decision 184): a hold placed (a) before the DROP: accepted, nothing FI-5,13c,27 T2+T3  later of
              deleted, the drop reads done, held bytes withheld (404), the stored count                           M5-out and
              falling once, when they move to held, and not again when the job deletes them                       M10-out
              after the hold ends; (b) between verify and delete, and between two DELETE
              batches: no DELETE after the reread (cached at most 5 s), one in flight
              completing; (c) a sealed hold: the admin's answers, listing, bill and reads
              equal a no-hold twin's; an ERASE under the hold still destroys keys at once
FS-93  §11    a rename chain: Z created, renamed to Y (one push removing Z and creating Y from FI-27       T2+T3  M10-out
              Z's chain), Y to X, X edited, a copy of an old X on ref R2: dropping X keeps
              what Z's, Y's and R2's versions name; --follow drops X, Y and Z in one push and
              one job, freeing what only they name, R2's copy keeping its segments; X live
              across a path epoch: one map-checked lineage; X removed before a cut-over and
              re-created after: two lineages; a lineage entry no committed map or tail links:
              refused {mismatch}
FS-94  §11    a shared inline record: one push writes small X and Y, Y a copy of X's bytes; X  FI-1,27     T2+T3  M10-out
              dropped: X's entry versions withheld after not_before, Y's served and verifying,
              the record's other entry versions keeping their hashes; a record-class twin: X's
              slot deleted (X unreadable at once), a slot Y also names kept; a general repo:
              X's inline bytes stay in the pack, never served; compaction's stub test, of a
              pure function that returns the bytes a live version needs from a record and
              deletes nothing, since compaction is Later (owner decision 247), keeps every
              byte Y needs
FS-95  §11,8  refusals: config and mailcfg (409 DROP_KIND); git-mode and creates-only refs     FI-17,27    T2+T3  M10-out;
              (409 REF_MODE); the ur/index and ur/lfs refs, .ur-index/ and a path naming a                        format-1
              directory (409 DROP_PATH); a versionless head (409 VERSIONING); a locked repo,                      cases at
              and a lock filed during a window voiding the drop at its start; owner-bound: an                     M2-out
              admin not the owner's consented device (409 DROP_CONSENT), the owner's device
              accepted, its page Worker refused; a non-admin (403); a written version whose
              oid differs (readers raise SidecarEvent history_drop in state invalid, naming
              the signer, and list nothing; §11.7, §5.4); a list missing or adding one version
              (refused {mismatch}, nothing deleted); a cancel after not_before less 60 s
              (409 DROP_STATE); a cancel accepted at the storage limit and after the network
              has spent its evs_drops_per_day, while its next drop gets 429; no MCP tool can
              drop; at the storage limit an inline-head drop accepted and one needing an
              upload refused; format-1 code given flag 256 or field 33 refusing them as
              FORMAT_UNSUPPORTED, and ignoring window bit 5; from M2, format-1 evs refusing a
              version naming a slot that neither its push introduced nor a version step 4 read
              names (§11.8's 5h), and a new-slot PUT meeting an equal object over 23 h old
              with 409 SLOT_STALE (step 6)
FS-96  §11,19 interactions: a versionless era inside the range stays collected, a              FI-5,13,16, T2+T3  M10-out
              kind-5-headed segment adopted as kind 1 and listed goes, one a live versionless  19,27
              head names stays; an ERASE meeting a slot the drop deleted counts done; the
              DROP's index rewrites leave no listed version's postings in any partition,
              searches equal, indexers reproducing them; a site-loss re-seed from a stale
              mirror: the content returns as listed, and the re-seeded job deletes it again;
              mirrors apply and delete local copies; stored bytes fall by each deleted seg/
              object's stored size as deletes land, slots reporting nothing; observe mode
              deletes nothing and logs its delete set, verify equal to the oracle; a drive
              returning from heal resurrects no deleted segment
FS-97  §7,18  stale page Workers (D-TEAM-29) on a fake clock: a member's page Worker           I-4,15,FI-2 T2+T3  M4-out;
              re-enrolled weekly for a year, each evicted Worker's leaves removed as stale                        Team at
              about 90 days on (§10.9); with self_admit on, each admission's signer revokes,                      M6-out
              as removed, every Worker that §10.9 removed as stale from every group it is a
              leaf of that seated it and lists the rest with their last change, so the
              member's admitted Workers stop growing after 13 weeks; in a Team with self_admit
              off, an admin's device admits each Worker and in that act revokes only the
              Workers it saw so removed from every group it is a leaf of that seated them,
              revoking and listing no live one; Workers ranked past the config and directory
              groups' first 1,000, which read both by wraps and no repo that device reads,
              stay until the member's consented device, at its OwnerConfirm or its answer to
              the admission alarm, revokes those its own groups saw removed and offers the
              others; that device offline for 60 days: their admissions stand until its next
              answer frees them; a member with only page Workers, in a Team past 1,000 member
              devices with self_admit off: Workers no admin's group seated stay, one admission
              per eviction, until at 90% of config_admissions every admin device raises
              admissions_near_cap, listing each member's page Workers but its newest, oldest
              first, and an admin's revoke frees them before any admission meets the cap; a
              Worker that resynced by KF5 or was re-added by KF2 after its stale Remove is
              never revoked; an AdminSet member's stale Workers at k = 2 go only by proposals
              of their own beside the admission's, which its cosigner also cosigns, and one
              whose cosign never comes expires at its not_after, the next admission proposing
              it again; a kill between an admission and its revocations: the restart re-checks
              and posts the same statements, one entry each; a Worker that resyncs after its
              admitting device last fetched the group, during a retry, or before a k = 2
              proposal's cosign is not revoked
FS-98  §5,18  a member revokes another of its own devices (D-CORE-20) in a personal network    I-4,15,FI-2 T2+T3  M3-out;
              and a Team with self_admit on and off, from a phone app with a presence signer,              +T4    Team at
              a remote-mode desktop app signing the first call's bytes, and ur devices revoke                     M6-out;
              confirmed on /dev/tty: GetDevices lists the member's devices, this one first; a                     app hosts
              lost revocation signs one SidecarRevoke{lost} after the presence check, and the                     at M8-out
              target then loses access as 22.7's revocation suite requires, this device
              committing its Removes first; a compromise revocation from a loss time parks and
              voids exactly 22.7's cascade sets, and a host where the member holds no presence
              key this sidecar registered signs on its confirmation alone, revoking no key;
              with the phone the member's only device online and no alarm pending, its app
              revokes a lost laptop and, again, an evicted page Worker not yet stale, as lost,
              each then losing access as above;
              each statement of an act signed under Presence carries the act's one presence
              countersignature, which api and every member device check (FS-124);
              refusals, each signing nothing: this sidecar (REVOKE_SELF); another member's
              device, a tagged agent it sponsors and an unknown id (REVOKE_NOT_OWN); a
              read_only page Worker, a quick burner and an unconsented device as caller
              (REVOKE_NOT_CAPABLE); a since_n later than proposed (REVOKE_SINCE); a target
              that admitted the caller or lifted its park after since_n (REVOKE_PARKS_SELF,
              naming that entry), while its OwnerConfirm of the already consented caller parks
              nothing; a failed or refused presence check, and a control call sending no
              presence evidence under Presence (REVOKE_CANCELLED); a statement api refuses at
              the tip (REVOKE_REFUSED); a harness hook and an MCP call; races: the target
              signing statements every few seconds between preview and signing (no
              REVOKE_STALE: the park and void items they add join, the result listing them), a
              key it registers then under a lost revocation (REVOKE_STALE, then the new plan),
              the post's response lost (one entry, the retry answering it), a kill after the
              SidecarRevoke and before a KeyRevoke (each lands once after restart); an
              AdminSet member's device at k = 2 answers authority_pending; the target is
              suspended at once, so its own revocation of the caller answers
              REVOKE_NOT_CAPABLE, and is revoked at another admin's device's cosign, by ur
              approve on /dev/tty or through Decide, or stays suspended when the proposal
              expires unsigned at its not_after; the gomobile, C-ABI and js adapters give one
              terminal result per call, js in Node as the extension's alarms-only host
              answering REVOKE_NOT_CAPABLE, its own Worker Later (§18.17)
FS-99  §16,11 directory erasure authority (meta review F01): writers A and B with entries      FI-25       T2+T3  M6-out
       ,7,8   (requests, decisions, coordination and, at M6, announce entries; from M10 cards                     (entries);
              and index files), no mirror, and an ordinary agent X with rw that caches no key                     later of
              or plaintext of theirs beyond its reads; X's ERASE naming A's entry slots, a                        M6-out and
              CLOSURE rewriting index files, a ?closure=1 upload and a POST .../slots/delete                      M10-out
              each get 403 before any slot GET, PUT or rewrite, every slot's ETag unchanged,                      (cards)
              as does a list mixing a slot X's own push introduced with one of A's; again
              under a preservation hold, from a device parked for consent under an ordinary
              member and under an AdminSet member, whose exchange mints rw and no admin, and
              from a read_only sidecar; positives: a directory admin's ERASE of A's entry
              destroys its keys, under the hold too; repo owner R revokes repo P with no
              directory admin daemon running: the marker hides P's name from every honest
              reader at once, nothing is erased, R's device, ur directory revoke and ur status
              show erasure pending with its age, and at 24 h directory_erasure raises on the
              admins' devices; an admin's daemon then starts and erases exactly the copies
              naming P (its announce entries and its runs', from M10 the cards' old versions
              and index documents by CLOSURE), each ERASE naming the request; a request by a
              non-admin of P, or after P is announced again, erases nothing and alarms; the
              runner killed between its CLOSURE and its ERASE, and two runners racing: one
              ERASE commits and the other skips; a fresh member device with an empty cache
              then opens every historical entry of A and B that names no P
FS-100 §16,18 directory decisions reach requesters (meta review F16): requester R a surrogate  FI-26       T2+T3  M6-out
              that leases only its own notice's path, with no directory view open, no indexer              +T4    (format 1);
              designated and no stream sync; approver A denies R's repo request: R gets                           M8-out
              exactly one hint (from M8 one wake, on T4's surrogate), reads that notice                           (wakes);
              version and the one decision entry its locator names and no other stream or                         later of
              index object, shows denied with A's note through access_decided, and its pending                    M6-out and
              count and the target's fall at once, so its 21st request is then taken; the same                    M10-out
              for an approval, KF3 seating R, and for a reach approval spent once by
              GrantActivate; A killed after its decision entry and before the notice's
              rewrite: R stays pending, and A's restart rewrites the notice once, the denial
              yielding no statement and no second entry, an approval's RepoGrant filed once; A
              killed after a RepoGrant and before its entry: the restart appends the entry
              once and then rewrites the notice; two approvers at once, one denying and one
              approving: the notice ends approved, naming the approval, the denial shown
              superseded; a cancel racing an approval: a rewrite first fails the cancel, which
              shows the approval, and a removal first leaves the filed grant standing, shown
              as granted after a cancel; under a two-approver reach rule the first approval
              leaves the notice pending with one DecisionRef, the second decides it, and R
              spends both; a notice whose DecisionRef names another request's entry, or whose
              hash or outcome mismatches, is ignored and alarms; expiry leaves a request
              expired, never denied; on format 1's versioned notices and on format 2's
              versionless ones
FS-101 §16,7, repo items across the retention horizon (meta review CC-07): repo admin E        FI-25       T2     M6-out
       8      announces repo P (an announce entry at M6, an r/ file from M10) at pin n0; on                       (entries);
              the fake clock with production fold and retention constants, the log runs 30                        later of
              days and 10 folds past n0, so api has deleted n0's entry and every base's chain                     M6-out and
              value older than 30 days; a fresh member device then accepts P's item, judging                      M10-out
              E's right by the access log's positions; after E's RepoAdmin remove the item                        (r/ file)
              still stands; after a compromise revocation of E from a since_n at or before n0
              it is void and alarms, and another admin's device of P re-signs it at a higher
              seq, as it does after E's lost revocation; E, removed as admin, signs a version
              whose pin n0 lies within 4,096 positions of its push's: refused, E holding no
              right at the push's pin; E's version with a pin over 4,096 positions before its
              push's: refused; a non-admin's version with a fresh pin: refused; at M6, P's
              item survives 4,096 positions of log growth, while a run item's card rule
              refuses a stale pin; E, removed as admin with no push since to its own stream
              (M6) or to an idle cards ref (M10), pushes a version at that ref's older head
              pin, where it still held the right: refused by every reader holding the
              removal's entry, timed over 10 min before the push's time_ms
FS-102 §7,10  a copied whole auth-key bundle (both seeds) on a fake clock: Delegation D, with  I-4,15,FI-3 T2+T3  M2-out
              max_admits 10, admits honest agents A and C, and a thief keeps a copy of D's
              bundle; (1) A revoked for compromise from a since_n after C's admission: D ends
              at that position and the next REMOVE generations exclude D's key; B, which the
              thief then admits with the copied signing seed, first by the auth key's old
              bearer and then through a client the operator mints, its statement appended
              past api's own check, is refused by every reader, a new device included, gets
              no wrap from any honest writer and opens no later generation; C reads on by its
              own ReaderWrap, and an agent D admitted after since_n is parked until an
              AdmissionConfirm; (2) A revoked as removed instead: the plan names D's key as
              retired and D as still admitting, B's admission lands and B reads only by its
              own ReaderWrap, and a later DelegationRevoke with a since_n before B's
              admission parks B, refuses every admission after it and keeps B parked
              against an AdmissionConfirm signed by D's copied key; (3) a thief holding
              only D's reader seed opens no generation claimed after any key drop and admits
              nothing; (4) after ten admissions, a fold and every earlier agent's not_after,
              an eleventh SidecarAdmit by D's key is still refused; (5) a kill between the
              compromise revocation's post and its landing: the restart posts the same bytes,
              one entry, D ending once
FS-103 §10    late delivery identity on a fake clock: g's staged ReaderWrap to agent A         FI-28       T2+T3  M2-out
              lies under A's key K0; A replaces its key every 6 days without fetching g,
              keeping K0 30 days past its not_after; aged past that, with no writer online
              and no rotation run, A asks for g with its current key K1's k8: after 15 min
              gkm hints a reader-only holder, which delivers RK_g LATE at A's K1 path while
              the K0 object stays, and A opens it; the K0 delivery never opens under K1, nor
              a K1 one under K0 (wrap_aad binds the key digest); two late deliverers
              barriered on one target: one 201, the other's 412 carrying the winner, which
              it judges; each killed before and after its PUT and retried, an unknown
              outcome resolved by repeating the PUT: one valid object; a K0 object fake-aged
              30 days past the K1 one's creation is collected; gkm refuses (409) a LATE
              delivery to a key it does not serve for A, of a generation not the newest or
              before the claim, and a STAGED one after it; again for a same-generation
              RecoveryRebind: the new binding's RecoveryWraps land at their own b8 before
              the old binding's go, a kill between leaving both and the retry deleting only
              the old, and the new code, the old's objects gone, opens g
FS-104 §10    delivery authority: g claimed at P0 with holders {A}; at P1 member B's           FI-28       T2     M2-out
              device is admitted and agent C granted, with no shrink and no new generation;
              A delivers RK_g LATE to both at P1: every member and the schedule's oracle,
              which judges from the log alone and shares no code with the members' delivery
              checks or gkm_*'s, judge both valid, and nothing rotates, as for a delivery
              just after the claim by a signer whose clock trails the rotator's by 50 s;
              refused by gkm when honest, then replayed past a colluding gkm to members,
              each poisons g (an alarm, a REMOVE rotation, the signer named): one signed at
              P0, before B's admission; an AuthPin off the chain (also a fork alarm); one A
              signs at a pin after A's revocation; one to a recipient revoked before its
              pin; a STAGED one carrying an auth, or by another than the claim's signer; one
              by a read_only page Worker; after B's revocation at P2 the P1 delivery,
              re-served and re-read, still judges valid and poisons nothing; a pin above a
              member's tip waits for the log, a withheld one raising withheld; a member
              whose previous base passed a delivery's pin judges nothing of it while its
              recipient still opens it
FS-105 §10,2  copied keychains (§2.10's row) on a fake clock, the auth and HeadCheck pins      FI-29       T2     M2-out
              current throughout: on day 0 a passive copy of uncovered agent A's keychain
              (its identity key and ClientKey unused); A replaces its ReaderKey every 6
              days, K0 by K1 on day 6; on day 29 gkm serves the authentic K0 advertisement
              to a rotator, which refuses it as expired (its not_after by day 7) and
              delivers to A only once A's current key is served; no copied key opens content
              sealed after day 37, nor, for member device D in a 60-leaf group copied the
              same way and running, after day 60; an advertisement valid over 7 days is
              refused; then an active clone of D signs a fresh ReaderKey and KeyPackage on
              day 10: rotators seal to it and it reads, D's path-only commit and key
              replacement ending nothing, until a SidecarRevoke{reason: compromise} from a
              since_n before the copy: gkm refuses the clone's uploads and tokens, members
              its commits, every later rotation excludes D, the device the clone admitted is
              parked, and D's member enrolls a new device
FS-106 §10,7  key upkeep under r (§7.9's read_only row, §10.6's scopes) through the            I-4,FI-2    T2+T3  M2-out;
              retention horizon, on a fake clock for 35 days: a read_only fixture device                          page
              (the page Worker at M4) and a reader-only member device, each a leaf of a                           Worker at
              10-leaf repo holding only r scopes, upload ReaderKeys every 6 days and a                            M4-out
              KeyPackage refill, commit path-only every 7 days, ack daily and, after a lost
              epoch, resync by external commit: gkm takes each and members adopt them, epoch
              retention passing their acks, and a third leaf resyncs from the sealed
              GroupInfo the read_only one's last path-only commit carries; the reader-only
              leaf's group-info write lands, while the read_only one's is refused, as are
              its wraps, claims, Welcomes and any commit carrying a proposal (members
              refusing what gkm cannot see); an agent's epoch PUT is refused; a parked
              device's ReaderKey waits for its lift
FS-107 §11    diff dependency (11.14's dependency, merges and chains rows), every cache        FI-18,22    T2+T3  M10-out
              discarded before each search, the purge and evacuation run between: D created
              and edited twice in one unsealed head, small (each full entry replacing the
              last) and large (a large entry, then diffs composed onto it), then a fresh phone
              holding only the current index searches an unchanged trigram and each added and
              removed one; again with D's base in a sealed slot that a merge absorbs and the
              writer then reuses, and with each edit by another writer; a merge based before a
              composed diff's push and committing after it, a backfilled copy of D's previous
              version sealed between, keeps the base the head names, and with the copy sealed
              before the merge's base the writer's next edit, pushed before the merge commits
              while its head holds its diff of that version, is full, and the merge keeps the
              base the head names; a diff that another writer's full edit superseded raises
              nothing once a merge drops its base; a DROP listing the base writes the kept
              head full; an entry late into the previous or an expired bucket is full; a
              forged diff whose base no file holds raises index_malformed and reads not yet
              searchable until a host with the text re-enters it, never no match; no body is
              fetched, and every search equals SearchOracle's
FS-108 §11    deletion masks (11.14's tombstones, merges and roll-up rows): D's old version    FI-18,20,22 T2+T3  M10-out
              rolled into all; D removed in the current bucket, its head sealed, merged into
              the bucket's shards and its slot reused, every replaced index version purged and
              every cache discarded: a fresh phone and desktop find no hit for D's old text
              before, during and after the bucket's roll-up, which drops all's row and then
              the tombstone; again for a rename, a version turning binary or skipped, a large
              file losing a chunk, and a git ref DELETE, whose ref tombstone masks every older
              document of the ref, a re-created ref's documents staying; two writers' clocks
              10 min apart at a bucket boundary leave a newer version, and then a tombstone,
              in the older bucket: searches mask the newer bucket's older entry, and the older
              bucket's roll-up removes it, rewriting its file in place; a late companion entry
              below an indexed version is dropped; every file passes the canonical decoder,
              which refuses a tombstone table out of order, a key in both of a shard's tables
              and a tombstone in an all shard; every search equals SearchOracle's
FS-109 §11    mask memory (11.14's newest row; §5.9's version table): a ref with 500,000, then FI-18,23    T2+T4  M10-out;
              1,000,000, recent nonmatching file updates in its latest buckets and a retained                     app hosts
              expired one, and one all row that a newer nonmatching version masks; a fresh                        M8 (23.6)
              ios32 and Android surrogate, a page Worker and a desktop sync, building the
              table within 1 MiB, then run each search alone and then DaemonSearchCount's
              concurrent searches, each matching the all row and a few bucket documents: the
              masked row never shows and every result equals SearchOracle's, while the heap
              (runtime/metrics' /memory/classes/heap/objects:bytes after a forced GC, sampled
              at each frame and page) less its value at the start stays within §18.4's working
              set for a search run alone and within Search.MemoryByteCount for the concurrent
              ones; a build that collects the buckets' keys per search fails the cap at
              500,000 keys, so the test catches its return
FS-110 §16    cold "search more" (16.10's cold contract) at a fake-clock 10 MB/s, with no      FI-18,23    T2+T4  M10-out;
              indexer: one 165 MB all partition and four queries, the sole exact match in its                     app hosts
              first, middle or last shard, or in none: the four fetch traces are equal in                         M8 (23.6)
              order and bytes; the first progress lands within 500 ms, then at least once a
              second and at each shard; each shard's hits within the arrival bound after it
              lands, none before; complete false until the last shard is searched, then
              complete, with a hit or with none, within B / R + 1 s; again across a 1 GiB
              MoreByteCount boundary, the next call's cursor fetching on from the first
              unsearched shard and never refetching a searched one, and with a cache cap under
              all's size, the call still reaching the last shard; on a desktop, a phone
              surrogate and a page Worker; the median and p90 first hit over FS-76's query set
              go to §22.8's search row
FS-111 §11,15 erasure's cut (meta review F09), with no indexer designated: writer A holds, for FI-2,18,19  T2+T3  M10-out;
       ,16    each kind, a prepared index push holding document D, paused just before its head                    mailbox
              CAS (a companion push to a fresh writer-head path and one to a large entry, a                       M7, team
              merge's new shard, a backfill's head, an i2 rebuild in parts and a reused old                       record
              slot); eraser B's CUT commits, every hint is dropped, B is killed after its                         M6 (23.6)
              first CLOSURE, and the fake clock passes 20 min, within a multi-part push's
              30-minute seal; each of A's pushes, its multi-part seal included, gets 409
              INDEX_EPOCH and rebuilds from the erasure set, committing without D, while a
              CLOSURE built before another eraser's CUT still commits; a push naming a stale
              index_epoch is refused at once and one naming a future epoch once recorded; a
              CUT changing any file but the erasure set, or past 16,208 B, is refused; a
              writer's journal begun below listed_since is rebuilt from content, where D no
              longer opens; B's device restarting finishes the erasure from evs's state, and
              with B's device gone another device of B's member does after 25 h, first
              committing the ERASE its orphaned CLOSURE names; afterwards no index file
              version that current reader keys open holds D's postings or fields, every stored
              version that held them, a held one included, shares a destroyed key, and a fresh
              device masks D from the CUT and opens none of its copies after the ERASE; in the
              team directory a CUT below admin is refused before it commits, as its ERASE is
              (FS-99)
FS-112 §11,15 erasure's wait (meta review F19), at the exact storage limit and spent, the      FI-13c,19   T2+T3  M10-out;
       ,20    eraser at evs_closure_bytes_floor: one admitted message with 5 MiB of text, so                      mailbox
              five chunk documents, each in its own large entry or bucket shard, one chunk                        M7 (23.6)
              also copied by a backfill, one left in an absorbed slot and an older index
              version a hold keeps; its CUT and first ERASE land at once and its body no
              longer opens; the eraser counts every closure byte and upload, and the erasure
              event's finish, from its remaining bytes, its allowance and its 429s'
              retry_after_ms, names the UTC day and turn at which the last ERASE commits,
              which agrees with the fake clock's to within one turn, the run starting 10 min
              before 00:00 UTC and the eraser restarting mid-run; a one-document message with
              no copy completes after the next 00:00 UTC within two turns, and the same
              message below the limit at once; across the run the message stays masked in
              search from its CUT, and its postings open to key holders only until its part's
              ERASE
FS-113 §11,8  stable refusals (D-EVS-23) on identical clocks: attempt A of push P held at a    FI-2,3      T2+T3  M2-out
              barrier before its handler records its arrival; the lb's re-send B reaches evs2,
              whose fresh over-limit list refuses P: B records P in the head and answers 409,
              its reply held until A starts; A released 150 ms after the record with a stale
              below-limit list: from a cluster head it answers B's refusal with recorded:
              true, and from a cached head without the record it passes its checks, fails step
              7 on the record's ETag and answers the same; P never commits; twin: A's step 7
              lands before B's record, so B's CAS fails, B rereads, finds P committed and
              answers 200; again for a multipart seal and for each recorded refusal (5b's
              time, 5c's scope and storage limit, 5d's predicate, DIRECTORY_FULL,
              EPOCH_SOURCES_FULL, SLOT_STALE, NOTHING_TO_ERASE); on T3 through the lb's own
              re-send (warp/warpctl/config.go:1317-1320), evs1's handler held past its 30 s
              read timeout; past P's until (fake clock), A refuses by 5b, its record lapsing
              at once for the next head write to drop; with 8 records live, or the newest
              under 1 s old, a further refusal answers 429, refusing nothing, and its retry is
              recorded once one lapses; time_ms 11 min ahead: 429 TIME_AHEAD, then a commit
              once within its bound; a push creating its ref, refused: its record in a
              placeholder head, which reads treat as absent, the delayed attempt failing
              If-None-Match and answering the refusal, and a later push creating the ref over
              it by If-Match; no other push's attempt, lease, part or seal ends because of a
              record
FS-114 §19,11 the store's settle rule (D-OPS-20) on T3's 4 × 2 EC:4 and 4 × 4 EC:8 sets, per   FI-30,1,2,6 T3     M2-out;
              build, upgrade and cluster: a head If-Match PUT's drive commits held at a                           purge and
              barrier after their checks past the 30 s drive timeout, on one host and on                          drop cases
              two; the request cancelled, and again with its coordinator killed and                               M10-out
              restarted; a newer same-key PUT and a GET: with one host held they commit and
              read at once, and once the held commits are released the newer acknowledged
              head stays, read through every host and after a full heal; with two hosts
              held they wait, then fail 503, until the held commits are released and the
              settle reverts them, the old write never read; again for a marker DELETE
              racing a fold's re-creation of the path, v1's kind-5 and slot purge DELETEs
              and a drop job's DELETE; a request delayed in the network past its
              x-ur-deadline-ms is refused, and a drive commit that would begin past it never
              begins; a storage host's clock unsure: it takes no request with a deadline; a
              drive host restarted mid-commit serves its drive only once the old process
              has exited; heal never spreads a version under a read quorum; a head written
              while a host was down, then a PUT to it short of its write quorum as a second
              host stalls mid-commit: every drive that took the PUT reverted, that head read
              throughout and after both hosts return and a full heal; two DELETEs of one key,
              each with a commit held past its deadline, on one host and with a host then
              down: the key is held until the held commits are released and reverted, and the
              object reads throughout and after; a create whose last drive commit is held
              before its check across an acknowledged DELETE of the key: released, it answers
              stale, and the key reads 404 through every host and after a full heal; a DELETE
              naming an older object's LastModified: 412, and the object stays (owner
              decision 225); a drive host restarted between a write's read of it and its
              commit: stale; a LIST with three drives of a set stopped, or one stopped while
              another heals: 503, and with two stopped it lists every acknowledged key (owner
              decision 226); twin: with no barrier every write releases at its write quorum
              and no key is held
FS-115 §16    apply barriered after its stage, after its aside's hash check and after its      FI-8        T2     M3-out
              install; there a process taking no daemon lock writes distinct bytes to the
              path in place, saves them by a temporary file and rename, deletes it, or
              deletes and recreates it: before the aside the path reports changed or deleted,
              the bytes at the path; after the check a write or save makes it recreated, the
              bytes at the path, and a delete finds no file; after the install a write lands
              over the restored bytes, which the point keeps; no written byte is lost, and
              none is reported restored over; two selected paths, only the second written to
              before its install: the first restored, the second a conflict, its restored copy
              beside it; a target of absent and a recreation, a current of absent and
              a creation: recreated, exists; a parent replaced by a symlink to outside the
              worktree, and a file replaced by a directory or a symlink: kind, nothing
              written outside or removed; a writer holding the file open and writing before
              end: written, its bytes in the conflict copy, which its handle keeps writing; a
              daemon killed after the aside: the restart puts the bytes back, or keeps both
              as recreated; killed after the install: the restart applies end's rule; on
              Windows a file held open without FILE_SHARE_DELETE: in-use, unchanged; a volume
              with neither no-replace rename nor hard links: unsupported before any aside,
              unchanged; FS-26's before-edit case still holds
FS-116 §11,19 the governor alone on the fake clock with exact prices (k = 1) and no P0, T      FI-14       T2     M2-out
              being 1,000 units an interval, each push 100 units (63 immediate, 37 deferred),
              W preloaded beside a steady funded P2 queue; after warm-up ten pushes are
              admitted and completed each interval, queues bounded, none waiting 100 ms or
              refused, W back at its preload each interval; P2 issue paused 100 intervals,
              then resumed: ten still admitted each interval while W drains, the bucket above
              its midpoint; each evs, gkm and taskworker process killed between an admission
              and its report, then restarted: every push's deferred units paid once, from W or
              as unfunded P2; {nvb_<set>} lost: W restarts at zero and P1 admits T less only
              what A_U issues; 200 units of unfunded backlog an interval: only A_U's issue,
              never past 40% of T, reduces A1; prices 10% low for 10 min: k converges, B's
              floor absorbs at most one interval's error and every 24 h window holds 0.8 DWPD;
              a mutant that debits funded P2 from T as well admits ~7.3 pushes an interval and
              fails
FS-117 §10,11 P0 alone past the refill for 24 h of fake counters on one metadata set, every    FI-3,14     T2     M2-out
              uploader, group and network under its own rate: 100 Teams of 5,000 admissions,
              each revoking a sidecar every 5 min, each revocation asking a config and a
              directory rotation of ~6,000 deliveries, with full 1,000-leaf Removes, 16-slot
              ERASEs at each network's 60 a minute, 10,000-slot ERASEs and --now shreds of
              1M-object repos, a Pro network's pushes and 2x year one's mix beside them, and,
              in other groups, a SCHEDULE and a REQUEST rotation whose claims state cause
              REMOVE though no shrink, authorization expiry or compromise retirement lies past
              gen/<g>'s auth pin; then the storm stops and the run goes on 24 h; then again
              with the governor killed for 10 min, its processes on fallback, and again with
              {nvb_<set>} lost mid-storm: every P0 write issues on arrival, none queued,
              refused or paced, every gate's close-to-reopen p99 stays under §10.6's 5 minutes
              and nothing commits after a gate closes at a generation a revoked holder reads;
              P1 and unfunded P2 issue nothing while P0 takes the refill, funded P2 nothing
              past what B holds, and B never falls below zero; the two mislabeled rotations'
              deliveries and claims are charged as P1 and shed; pushes and evacuation resume
              within one interval of the storm's end, evacuation's oldest minute directories
              first, T following its factor of B each interval; the other classes' writes hold
              FI-14 (a) in every 24 h window, a lost state restarting B and W at zero; the P0
              page fires within an hour of P0 passing the refill and never in a control day of
              2x year one's mix with a --now shred of a 1M-object repo; the run reports P0's
              forgiven excess by kind, the 24 h windows past 0.8 and 1 DWPD, the ramp's time
              to half and 90% of r, the pushes shed and the oldest batch's age past 26 h;
              §19.8's gauges and counters equal the oracle's; a mutant flooring T at a fifth
              of the refill while B is empty, one queuing P0 behind B, and one repaying P0's
              excess, B going below zero, each fail
FS-118 §11,19 path-epoch copies for 7 days of fake clock on one metadata cluster, entries and  FI-1,6,14   T2     M2-out
              copy limits scaled by 1/100 together: at the planned copy load (live entries of
              rotating refs times epochs a day times 3: half the cluster's 21.6M operations a
              day), with batched epochs due daily from 1 h requested grants and an immediate
              one every other day on a third of the refs, beside FS-61's mix: each source
              empties within 30 h of its cut-over, no ref holds three sources 10 min, no
              PATH_EPOCH meets EPOCH_SOURCES_FULL, no batched epoch waits, and the copies stay
              within A_U; then 30 one-million-entry refs with a batched epoch due daily each:
              batched epochs wait while two sources stand, with no block or writer alarm, each
              covering every expiry due when it lands, and no ref reaches a fourth source; an
              immediate epoch on such a ref commits at once onto its third source, and its
              copy runs first; no batched epoch blocks a creation; P1's admission is
              unchanged; §19.8's copy liability, drain time, deferrals and source counts equal
              the oracle's, warning past 24 h
FS-119 §11,19 two metadata clusters with fake drive counters and space and inode gauges: the   FI-1,14     T3     M3-out;
              first's cohort grows toward its marks while place_new names the second, mostly                      each next
              empty; the first sheds its own heaviest networks while networks placed on the                       cluster
              second keep their p99, as do every network's placements, KeyPackage claims and
              rev/ checks on the first (P0 and fair queues); at 80% raw on the first, pushes
              adding payload to its repos and their segment uploads get 507 CLUSTER_FULL with
              Retry-After while deletion, erasure, a --now shred, CONSUME, BASE, a DROP with
              no upload and config and mailcfg pushes pass, and the rota is paged; a network
              with repos on both clusters is refused only on the first; monitor projects each
              cluster's exhaustion from its own slopes, naming the earliest, the first
              cluster's control plane apart, and the estate's free space moves neither
FS-120 §18    token projection order on the 3-master cluster and a fake clock, a barrier       WK5         T3     M8-out
              after each change's commit and before its apply: two POSTs; a POST and an
              empty POST; a client's removal; a vendor 410 racing a new POST, each pair's
              applies delivered in reverse commit order: GET tok equals the newest committed
              row each time, a removed token stays absent with no app launch, and the 410
              removes no newer token; an apply held past 60 s answers EXPIRED and its retry,
              or with api killed the next pass's sweep, applies the newest row within 2 min;
              the reconcile pass before, during and after a held apply, and a master
              restarted from an RDB dump older than the newest change: no apply begun before
              the restart lands after the slot's reconcile, which waits 90 s from the pass
              that found it, and tok then equals the rows; a client whose first POST lands
              during a reconcile keeps its token; a removed client's row and keys are gone
              24 h after its removal
FS-121 §15    reception-time authentication on a fake resolver: a syntactically valid          D-MAIL-14   T2+T3  M7-out
              message carrying 64 DKIM signatures with distinct maximal d= and s= values and
              8, then 12, then 51 ARC sets, then a chain lacking instance 3, each selector
              answering slowly (4.9 s) or failing: at most 8 DKIM keys looked up, the 8-set
              chain's newest AMS and seals verified, the 12-set chain cv=incomplete and the
              51-set and gapped ones cv=fail with no lookup; at most 64 queries, 8 in flight,
              9 body hashes, 17 signature checks and 30 s a message; evidence at most 8,192 B
              with limits' counts; 250 once the deposit is durable; 15 such sessions at once
              while a 16th, normal message completes within 2 min, checked in full; a
              message whose aligned valid signature follows 3
              invalid ones passes DKIM and DMARC; a spoofed From with 9 aligned bogus
              signatures is a DMARC fail, never a pass, and its label opportunistic; no
              incomplete evidence makes a label validated
FS-122 §13,19 a custom host added while one lb interface's lbmap is stopped, then              FI-11       T3     M6-out
              again while its nginx -t refuses the map: past 15 and 20 min on a fake clock the
              host stays pending in GET /network/dns, naming that interface, and no
              TLS-ALPN-01 order starts, while a DNS-01 one may; at 20 min the interface is
              map-stale, left out of the dns edges' answers, never the last one, and paged;
              once it is current the host turns ready, and a CA surrogate forced to each
              advertised address reaches the sidecar's TLS-ALPN-01 answer; an lb restarted
              with an old map file loads the current version before serving 443, or with
              the dns API down is current for no version; three adds and a remove inside one
              15-min window load in one reload, each host ready at that version; a restore
              that adds and drops hosts (§12.6) leaves each pending until every interface
              is current for the new version; an lbmap that reports a version its nginx did
              not load stays not current, its route probe failing, as does one whose map
              routes the probe name but drops an added host, that host's probe failing until
              a reload fixes it; route probes reach no listener; unknown, absent, platform and
              user SNI route as FS-35 requires
FS-123 §14,18 a message 1 KiB over the prover host's measured smtp_data_proof_bytes            D-SMTP-20   T2+T3  M9-out
              to one CHUNKING and one non-CHUNKING scripted MX, sent from a desktop and
              queued from a phone: CheckSend predicts ok for the first and, once the second's
              mode is known, too_large with both byte counts, else unknown; the send delivers
              to the first and stops before MAIL at the second, whose outcome alone is
              too_large with size and cap, its copy naming that domain; a second prover host
              whose recorded cap fits takes the phone's message instead; deferred, refused
              and tls_refused outcomes per domain reach GetSendResult and mail_send;
              GetReceiverCoverage's copy and every send copy name no indexer, receiver or
              coverage setting
FS-124 §7,16  presence countersignatures (owner decisions 185, 187, 189, 192; D-TEAM-32),      I-4,FI-2    T2+T3  M2-out;
              with fixture keys of both §16.6 profiles registered by device D: at api and on               +T4    CLI at
              every member device alike, each statement 7.9's presence row covers that D                          M3-out;
              signs, a k = 2 proposal and its cosign included, is refused with no                                 Team at
              countersignature, one by another key, by a key another device registered, by a                      M6-out;
              revoked, voided or expired key, over another act's root or another signer's                         app hosts
              act, with a path that misses its leaf, or with UV clear, and lands with D's                         at M8-out
              valid one; one check covers a five-statement act whose statements land in any
              order or alone, each by its own path; a device that registered none signs them
              on its confirmation, and a countersignature whose key a KeyRevoke removed
              meanwhile is ignored; D's own sign-out and a recovery key's statements need
              none; the thief: a modified client on D, unlocked, signs a compromise revocation
              of the member's phone, a lost one, a Suspend of it, a KeyRevoke of D's key, then
              a KeyRegister of a software key and statements that key countersigns: api
              refuses each with the tip, and a malicious api sequencing them anyway sees
              every member device, evs and gkm refuse each at its position, while each other
              member device's forwarding role, the phone's included, applies the revocations
              and the Suspend only as denials its next compile reverses; in a
              personal network D's RecoveryVeto of the member's
              recovery proposal, its RecoveryRebind of the member and its SidecarAdmit of a
              fresh device T, which would sign on its confirmation, are each refused without
              the countersignature, and the proposal activates 72 h on; a page
              Worker's admission by D carries its stale revocations under one
              countersignature; the phone's countersigned compromise revocation of D lands; a
              kill after the check and before the post: the restart posts the same bytes,
              countersignature included, one entry each; ur devices revoke, ur approve
              <proposal_id>, an admission, ur approve's OwnerConfirm, ur keychain
              recovery-rotate, ur keys add-presence and ur keys rm through the daemon's prompt
              (CLI); an admin's countersigned Suspend, veto and cosign at k = 2, AdminSet
              change, member removal and parking DelegationRevoke, each refused without it
              (Team); SignWithPresence on each app host, Decide's admission and alarm answers
              included, in remote mode by 5.8's two calls, and both profiles' vectors
              byte-equal on every leg (app hosts)
FS-125 §4,6   C19's windows (owner decisions 176, 188) on a fake clock, with a fake            FI-24       T2+T3  M10-out;
              contract service that keeps every report and its time: a requester surrogate and             +T4    app hosts
              its indexer, on a control and on a data contract. Sweep: each direction's                           at M8-out
              background from 0 to its allowance (178,419 B down, 241,709 B up) through every
              multiple of 128 KiB and F, each ±1 B, then 0 to 5 exchanges of exact envelope
              sizes added, both directions, the bytes split across the window's first
              contract, a session re-establishment's contract and an overflow successor, and
              windows ending mid-exchange: both clients report F on the first contract and 0
              on the others, identical across the sweep, at the window's end and never before;
              past the allowance, and at a sixth exchange, F plus 128 KiB steps; the review's
              case, 120 KiB of background and one 16 KiB page, reports F both ways. Root
              cause: a receive sequence idling out mid-window sends no checkpoint and an idle
              send sequence no close, and no search opens a contract in either direction,
              30 min into a foreground window or 10 s after a window's end, the next window
              opening with the contract connect took at that end. Lifecycle: the Ping grid
              holds every sequence open for 55 min; a 3-min suspension re-establishes by a
              Hello at the next foreground, its contract inside the window reporting 0; a
              3-min network drop in the foreground re-establishes by the search that comes
              before the next tick, its contract inside the window reporting 0 and created,
              with its successor, at that search (owner decision 191); a failover search opens
              its own window then; a window ending in the background clears the mode, and the
              next foreground's Hello opens a new one; a suspended requester's reports go out
              at its next run, and the deadline close settles from the indexer's; marking
              retires the contracts each side already sent on, reported exactly; a pair whose
              Hellos carried no bit 1 reports its bytes exactly. Sizes: every frame kind's
              counted bytes are at most §6.10's table, a HeadCheck at its list caps (four
              vetoes, four unverified pins with 8-hop paths) within two envelopes
```

Beyond the schedules:

- **lb drain (warp/warpctl/run.go:1453); Redis failover; Postgres or PgBouncer restart; resident migration; 60 s ack timeout:** clients retry streamed PUTs, which nginx cannot (warp/warpctl/config.go:2307); sockets heal; halts reload; streams reset TRANSFER_FAILED; RPC retries.
- **Clocks ±10 min; migration N+1 before code; sidecar N vs server N±1:** tickets, skew and expiry hold; explicit VERSION or UNIMPLEMENTED.
- **Kills mid-keychain write:** the keychain opens at its old or new state (§5.9).

### 22.9 Conformance and platform budgets

- **git** (2.34, Ubuntu 22.04's, https://ubuntuupdates.org/package/core/jammy/main/base/git; 2.43, Ubuntu 24.04's and Claude Code cloud's; latest; Windows, Xcode; go-git, JGit, libgit2; OpenSSH): through the local tier, and `git-remote-ur` without a prior mount, oids equal a reference; stock non-fast-forward errors, sibling pushes from one base giving one; `git push --atomic` fails before any write; a two-ref push reports per-ref statuses; a daemon killed between the remote commit and update-ref reconciles from its journal; foreign new commits refused, signed imports accepted; a sha256 repository refused, naming it, before any evs write (owner decision 249).
- **git-lfs** (3.x as Ubuntu 22.04 and 24.04 ship it, and the latest; `lfs.standalonetransferagent`; `GIT_LFS_SKIP_SMUDGE`): FS-73's flows with stock clients, pointer files byte-exact and export's oids equal to git's, its tip check included over http, ssh and `git-remote-ur`, with no skip option set and with `--no-verify` and `GIT_LFS_SKIP_PUSH`.
- **Restore** (darwin on APFS; linux on ext4, xfs and an NFS mount; windows on NTFS; a FAT volume on each; symlinks on each, Windows with and without the symlink privilege): FS-115's apply through each volume's no-replace rename, its hard-link fallback, and `unsupported` where it has neither, with Windows's in-use refusal.
- **File clusters** (D-OPS-20's in-house MinIO build, every cluster, each build, upgrade and new cluster; D-OPS-4): stale conditions refused with a host or quorum lost (§11.3); §19.6's deadline and settle rules, by FS-114's late-drive cases: a request past its x-ur-deadline-ms refused where it takes its key's lock, no drive commit begun past it, and a PUT or DELETE whose drive commits are held after their checks past the 30 s drive timeout, its coordinator killed, taking effect before the next request on its key or never, the newer acknowledged state surviving release and a full heal, since a removal marker's collection deletes unconditionally (owner decision 148), as from v1 do the versionless purge's and the marker collection's kind-5 and slot DELETEs and a drop job's DELETEs; the lag from a cancel to a write's last drive answer, measured and reported, which no margin relies on; no heal resurrects a deleted object or spreads a version fewer than a read quorum of drives hold; read-after-write consistency, and a LIST answered whole or 503 (owner decision 226); checksums; ranged GET; Delete, and a DELETE naming its object's LastModified refused 412 for a newer one (owner decision 225); no lifecycle rule set on either bucket; one pool per cluster (FS-63).
- **MTAs** (Postfix (may, dane), Exim; Gmail, Outlook.com, Microsoft 365, Yahoo, iCloud, SES, Proton, Fastmail): in, D-MAIL-9's census with nothing lost; out, §14.4 levels, DKIM, strict DMARC, which B's selector fails for A's network and burners, FCrDNS, JMRP and CFL joins; aggregate reports as FS-39, a one-connection, ten-recipient send raising no alarm.
- **ZK preamble** (`smtpproof`, BDAT and DATA (owner decision 125), on D-SMTP-16's hardware; census MXs): D-SMTP-16's adversarial corpus, FS-31's server-state cases included, fails before any effect; p95 times, coverage, interop.
- **ACME** (Pebble with 5% bad nonces in T2 and T3; LE staging; GTS, ZeroSSL): §13.8's challenges, ARI, CAA, an operator CAA at a custom host's exact target refused (FS-32); custom-domain desktops order and renew on Pebble; LE staging refuses URnetwork's account under a customer `accounturi`, which Pebble never checks (https://github.com/letsencrypt/pebble/blob/main/va/va.go, 2026-11-04); CT watch on a fixture (staging CT is unreliable: https://letsencrypt.org/docs/staging-environment/, 2026-04-10).
- **DNS** (zonemaster; Unbound, BIND, Knot Resolver; two public resolvers): R-DNS-7; compact denial and wildcards validate; before the DS, Unbound validates against the KSK as a trust anchor; a broken canary signature pages.
- **Browsers** (Chrome, Firefox, Safari, curl; Playwright on ur.io's page Worker and the native companion): 421 on coalescing; split PQ hellos; other origins' POST, subresource GET and WebSocket arrive sessionless, and login works without Fetch Metadata (§13.7); private audiences without a usable ALPN (FS-34) and custom hosts through the split (FS-35); another origin, a framed copy and localhost are refused the key origin, no key or token crosses postMessage, and a script injected on ur.io finds neither the Worker's key nor its token; IndexedDB survives a reload, and after Safari's 7-day storage cap evicts the key origin its page Worker re-enrolls through a consented device, the old leaf leaving by §10.9's stale-leaf rule; a storage-pressure eviction of a non-persistent bucket does the same, the re-enrollment's admitting device, an admin's in a Team with self_admit off, revoking each Worker it saw removed as stale from every group it is a leaf of that seated it, and the member's consented device, in that act or at its OwnerConfirm, offering to revoke the evicted one (§7.10's stale row; FS-97); the key-origin frame calls navigator.storage.persist(), and the page tells the person what an eviction costs (§18.8); in two ur.io tabs on one network only the Web Lock's holder loads state, refreshes, commits and writes the keychain, the other Worker relaying, and closing the holder's tab hands over the lock, relayed requests retrying; a vault record opens with C4 absent; no ICE candidate in the overlay block (§17.17), and a CGNAT fixture whose WAN address lies in the block keeps its carrier path and overlay reachability; no torn writes; no network `by_jwt` in the worker.
- **Memory, size** (darwin/arm64 iOS settings in T4; ios32 surrogate cells, one with a link; §18.4's other hosts): §18.4's budgets, and forwarding's within owner decisions 215 and 216's on an ios32 cell whose forwarding role compiles a 3,000-device team's config within its 10 MiB cap and refuses a 5,000-device one with bridge_alarm (owner decisions 197, 216), a hooked NAT's per-flow UDP loop re-measured on constrained provider profiles at M8 (§17.6), in every LOWBAR phase on iOS, the link cell deciding links and holding an app-device host's NAT with bridge flows at §17.5's idles through C5's per-flow IdleTimeout, while its public egress flows keep the NAT's own; sizes unstripped (§18.10); `make check` fails an HTTP-only file importing connect; the mobile sender's 1,024-slot pin table, churned past 1,024 live pairs, routes the excess unpinned and refuses none (§17.5).
- **Index determinism** (darwin/arm64, linux/amd64 and arm64, windows/amd64, gomobile android/arm64 and the iOS settings, js/wasm in Node and, through Playwright, Chrome, Firefox and Safari): testdata/index/ reproduces byte-equal plaintext and hashes under GOMAXPROCS 1 and 16, repeated runs (Go randomizes map order) and changed TZ and locale; the linked `norm.Version`, `cases.UnicodeVersion` and `unicode.Version` equal the format's normalization version and x/text's linked module version equals `IndexFileHeader` field 14's, so a toolchain or x/text bump fails until a new one is assigned (D-TEST-15).

### 22.10 Internal review gates

Gates (§23.8), with no external review (owner decision 99). The build runs each gate's local checks and reports them, listing open what needs hardware, production or people, and no freeze moves (owner decision 194). Each format freezes twice (D-PHASE-7), its specification at Gn-in and its bytes at Gn-out:

```text
format                        spec freeze (Gn-in)                      final freeze (Gn-out)
§7.9's records, format 1,     peer review of the schemas and state     23.6's M2 schedules (FS-1 to FS-12, FS-14 to
credential 0xF552, suite      machines (their owning sections);        FS-18, FS-19's config read, FS-20, FS-22 to
0x0010, delivery wire (M2)    EvsCommit.tla and StoreSettle.tla        FS-24, FS-40, FS-44, FS-45, FS-47, FS-53, FS-57
                              written and passing TLC at their         to FS-63, FS-72's and FS-95's format-1 cases,
                              bounds; the FS rows written as tests     FS-82's statement cases) pass on their rows'
                              against the fakes; vector schemas        tiers; format 1's erasure and deposit bytes
                              fixed; RECORD.md reviewed (owner         freeze on 22.5's §11 cases, FS-23 and FS-47,
                              decision 25); format 2's reserved        FS-13 and the mail cases of FS-23 and FS-47
                              numbers and their refusal vectors        keeping their M7 gates; TLC passes
                                                                       EvsCommit.tla; Porcupine passes T3 histories
                                                                       with unknown outcomes; the 0x0010 interop
                                                                       below, a required step's gap holding it; mlswg
                                                                       vectors under 0x0001 and X-Wing KATs;
                                                                       differential runs (owner decision 43); fuzz
                                                                       seeds; twenty agents; the storage benchmark
                                                                       with D-TEST-11's nvme gate; 10.6's sizes;
                                                                       format vectors in testdata/, the wrap
                                                                       paths and wrap_aad among them;
                                                                       FS-102 to FS-106, FS-113, FS-114's head and
                                                                       marker cases, FS-116 to FS-118 and FS-124's
                                                                       M2 cases; TLC passes StoreSettle.tla
record.proto (M3)             RECORD.md's semantics; the hashed bytes  vectors over the stored bytes; fuzz; FS-25 to
                              named (stored canonical protobuf,        FS-29
                              unknown fields kept), a version field;
                              CanonicalAction's field 37 reserved,
                              and approvers refusing an unknown
                              version
smtpproof/SPEC.md (M9)        the relation, E1-E3 and Z1-Z9 (§14.5)    the M9 evidence below
escrow order (M6)             20.9's comparator (D-QUOTA-9), built     20.9's benchmark rerun; MG6, which
                              dark in M4 (§23.4), its team_credit      holds the index, registers (§19.7)
                              index pending in MG6; FS-46 and 20.9's
                              benchmark pass on that build
                              (Q-QUOTA-3's residual)
directory.proto (M6)          §16.11's announcement, request,          FS-84, FS-85, FS-87 and FS-88's M6 cases, and
                              decision, notice and erasure request     FS-100's and FS-101's, pass on their tiers;
                              messages and their caps, peer-reviewed;  22.6's directory.proto decoder seeds
                              the FS rows written
format 2 (M10)                peer review of format 2's schemas        23.6's M10 schedules pass on their tiers;
                              (§11's versionless fields and records,   testdata/index/ fixed, its vectors byte-equal
                              the index's objects and encodings, the   on every leg (22.9); D-TEST-13's projection;
                              rule, lock and migration records, the    D-TEST-12's observe evidence on T3; the model's
                              DROP push and its states, search.proto,  drop extension passing TLC; fuzz seeds; a
                              directory.proto's cards, §11.14's field  migration of a format-1 repo set and a rollback
                              registry and RECORD.md's search          to format-1 binaries (FS-72)
                              fields); EvsCommit.tla with the purger
                              and IndexRollup.tla passing TLC; FS-64
                              to FS-81 and FS-83 to FS-96 written
                              against the fakes; vector schemas fixed
data rule                     before a final freeze, only local, T3, canary and M2's staging cluster hold the format
```

- **§7.9's records, format 1, 0xF552, suite 0x0010 (M2):** at Gn-in, peer review (§11.5-§11.8 included), both models (EvsCommit.tla, StoreSettle.tla) passing TLC and the FS rows written; at Gn-out, the table's evidence, the 0x0010 artifact below included.
- **`record.proto` (M3):** RECORD.md's review and the hashed bytes named (Gn-in); vectors over the stored bytes, fuzzing, FS-25 to FS-29 (Gn-out).
- **Escrow order, owner decision 92 (M6):** by M6's entry, on M4's dark build, 20.9's draw order (D-QUOTA-9), FS-46 and 22.8's escrow run (Q-QUOTA-3's residual), the one Gn-in that runs code (D-PHASE-7); the benchmark again at M6's exit.
- **`directory.proto` (M6):** at Gn-in, §16.11's announcement, request, decision, notice and erasure request messages reviewed and specified; at Gn-out, their bytes freeze on FS-84, FS-85, FS-87, FS-88, FS-100 and FS-101's M6 cases (§23.8); its cards and repo files freeze with format 2 at M10.
- **`smtpproof/SPEC.md` (M9):** two non-authors' written soundness argument; a checker of the public relation written apart from the prover tree, deriving the public inputs from the ciphertext transcript and the edge's own values; for each of E1-E3 and Z1-Z9, a mutated witness that only that check refuses; FS-31's scripted MXs; 22.9's ZK row.
- **Format 2 (M10, owner decision 169):** at Gn-in, peer review of its schemas, both models passing TLC, its FS rows written and the vector schemas fixed; at Gn-out, the table's evidence with the vectors and D-TEST-13's projection; production only after, dark first, where D-TEST-13 confirms the projection (D-PHASE-10; owner decision 174).
- **0x0010 interop (M2's Gn-out):**

```text
0x0010 interop artifact
kem       X-Wing KATs from the draft's vectors pass for Go's crypto/hpke MLKEM768X25519, and tmc/mls's encapsulation
          and decapsulation equal it on fixed seeds; OpenMLS's 0x004D X-Wing agrees once the M0 KAT matches
stacks    mls_* and tmc/mls (its provisional 0x004F, mapped to 0x0010) run one scripted lifecycle in both directions:
          create, Add with Welcome, path commits, Remove, an external commit with ExternalInit, at least 10 epochs, a
          PrivateMessage decrypted per epoch; both compute equal epoch_authenticator and exporter outputs at every
          epoch, the "UR evs 1.0 kek" label included
ladder    mlsinterop/ (D-REPO-2) derives GenWrap, LeafWrap and GenLink from the exported secret with §10.5's AAD in
          code of its own, byte-equal to mls_*'s
vectors   the transcript is checked in as 0x0010 vectors (testdata/mls/0x0010/, mlswg's format) and runs in every
          test.sh
required  Welcome, path commit, Remove, external commit with ExternalInit and PrivateMessage are never gaps: one that
          tmc/mls lacks holds the freeze unless a second peer, OpenMLS's 0x004D once its M0 KAT matches, runs it in
          both directions with mls_*
gaps      any other step tmc/mls lacks is named in the artifact as a gap; mlswg vectors under 0x0001 cover its logic
          but count toward no part of the artifact (§10.4)
```

### 22.11 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Mock engines | fast | hide wire bugs | fakes at store interfaces |
| Random interleavings without named barriers | no hooks at protocol steps | a found race cannot be replayed; no commit point is held at its lost response | rejected: fixed schedules plus a seeded explorer (D-TEST-10) |
| Search results checked by the index's own decoder | simple | shares the index's bugs | rejected: an oracle written apart (D-TEST-14) |
| Purge or drop deletes on from format 2's first day | storage freed at once | a purge or drop bug destroys content no check restores | rejected: observe first (D-TEST-12, D-TEST-18) |

### 22.12 Decisions proposed

**D-TEST-1 (proposed).** T1-T4 gate merges, `sidecar/test.sh` running in RUN-ALL after connect; server tests of sidecar engines set `WARP_TEST_ENV_FAIL_FAST=1`; sidecar tests follow connect/CODESTYLE.md:200-217. *Why:* R-TEST-1, R-TEST-9.

**D-TEST-2 (proposed).** `sidecartest` rebuilds connect's helpers from exported API and ships fakes whose store suites server also runs on real stores. *Why:* the helpers are unimportable (Q-TEST-1); shared suites keep fakes honest.

**D-TEST-3 (proposed).** 22.5's gates and 22.9's budgets fail the build; raising one needs a reviewed change (sdk/build/APPLE_EXTENSION_MEMORY_BUDGET.md). *Why:* I-12; 4,690,096 B of iOS headroom.

**D-TEST-4 (proposed).** Every 22.6 target ships seeds and, given a second implementation, a differential oracle. *Why:* parsers face hostile peers, and protobuf encoding is not canonical (https://protobuf.dev/programming-guides/encoding/#field-order).

**D-TEST-5 (proposed).** Every scenario runs 22.7's harness and guard; later, a synthetic main network repeats S2 and S5-S7 hourly. *Why:* R-TEST-3 is a system property.

**D-TEST-6 (proposed).** The revocation suite runs with evs's gate off. *Why:* server refusal is defense in depth (I-5).

**D-TEST-7 (proposed).** 22.8 runs per milestone and its soak before each release; conformance peers are pinned and rerun per pin change. *Why:* fan-out fails only under load; peers change silently.

**D-TEST-8 (withdrawn).** Superseded by owner decision 99: no external review gates a freeze or the claim.

**D-TEST-9 (proposed).** Freezes pass 22.10's gates in D-PHASE-7's two steps. *Why:* one conditional write orders storage (owner decision 2), and nothing is audited (owner decision 99).

**D-TEST-10 (proposed).** Every state machine of §7-§21, and §5.6's device revocation, is tested by deterministic fault schedules (FS-1 to FS-125), each run on the tiers its row names (T2's fakes, T3's real stores) against FI-1 to FI-30, beside TLA+ models of the separate durable objects (`EvsCommit.tla`), of the index roll-up (`IndexRollup.tla`) and of the store's settle rule (`StoreSettle.tla`) and a Porcupine check of T3 histories with unknown outcomes. *Why:* single-object conditional writes order storage (owner decision 2) and no transaction spans objects, so every commit point, retry and cleanup must be shown under lost responses, crashes and stale processes, and the roll-up is a multi-push protocol whose lock, CAS and erasure race no schedule alone exhausts; nothing is audited (owner decision 99).

**D-TEST-11 (proposed).** §22.8's `nvme` run on the PM9A3 set gates M2's exit and format 1's freeze: at 2× year one's mix with the write budget on, refilled at 0.8 DWPD for the run, the budget refuses no push, at most 43 KiB is written per push per drive, its P2 work included and charged once from the wallet (FS-116, which runs first, on exact costs), P0's bytes by kind are measured against the refill, setting §19.8's P0 warn line at four times their hourly share, at most half the refill, with the P0 page silent at that mix (P0 past the refill is FS-117's, owner decision 186), and writes stay within 50% of rated IOPS, on 1 KiB XFS blocks, or on 4 KiB only if format 2's projected mix (format 1's measured price table applied to §11.13's per-push index operations, the index on in every eligible repo) also fits there; its per-operation costs become §11.13's price table. *Why:* owner decision 140's binding limits, at most 0.8 DWPD and 50% of rated write IOPS, which the design meets at ~27-43 KiB a push, 43 KiB being 0.8 DWPD at 400 pushes/s; the run refills at that limit, not production's 0.768, which leaves room for the bucket's 1 h of depth (§11.13); the head's If-Match overwrite alone writes ~14 KiB (owner decision 2), so the record's first ~10-15 KiB estimate was withdrawn (Q-EVS-9, decided); mkfs fixes the block size for format 2 too: at 2× year one format 1 writes ~40-43 KiB a push on 4 KiB blocks (~30-33 on 1 KiB), and the default-on index (owner decision 156) adds ~4 on 1 KiB blocks at one companion push a minute per writer, and ~2 on 4 KiB blocks at one every 5 minutes (owner decision 172; §11.13).

**D-TEST-12 (proposed).** The versionless purge ships in observe mode (§19.11's `purge: observe`), logging candidates and deleting nothing while taskworker checks that no retained version names one; deletes turn on once FS-64 to FS-71 pass on their rows' tiers and a production soak after the final freeze (at least 14 days and 10,000 candidates) finds none that a retained version names, and until then the gate admits only internal networks and design partners (D-PHASE-10), so later networks get owner decision 161's purge from their first format-2 push. *Why:* a purge bug destroys content no other check restores, and only production shows real clients' citations.

**D-TEST-13 (proposed).** Format 2's bytes freeze only when its drive-write cost, projected from §22.8's M2 price table (D-TEST-11) and the M10 `index` row's T3 operation counts, with the index on in every eligible repo, purges and staging on and each companion push charged to the content pushes it indexes, meets D-TEST-11's gate; after the freeze, while §19.11's `format2` gate holds format 2 to internal networks and design partners, production's write budget must show measured over priced drive bytes within 10%, and a larger ratio holds the gate there until §19.9's next cluster or a later format change restores the fit; runs with the index off attribute each increment. *Why:* owner decision 174, which buys no staging drives and accepts that a miss found after the freeze costs more clusters sooner (owner decision 145) or a format change; owner decision 140 binds format 2 too, and at owner decision 172's cadence §11.13's costs put a push, with the default-on index, at ~34-37 KiB at 2× year one on 1 KiB blocks but ~42-45 KiB on 4 KiB blocks, against the gate's 43.

**D-TEST-14 (proposed).** Every search schedule checks its results against `SearchOracle` (22.4), which shares no index code: a desktop's text-verified hits equal its set, every device's candidates include its covered set, and each uncovered document is found from local text or reported not yet searchable; the index schedules also search from a fresh cache after the purge has taken every replaced index version. *Why:* completeness needs extraction, masking, coverage and roll-ups all correct, and an oracle sharing their code shares their bugs; a warm cache or an uncollected version can hide a lost diff base or tombstone.

**D-TEST-15 (proposed).** testdata/index/ fixes vectors with plaintext hashes (normalization, trigram sets, deltas, head files, seals, merges, roll-ups, doc and tombstone tables, a merge keeping a head's base, a roll-up removing an older newer-bucket entry) that every test.sh reproduces byte for byte on every leg, js/wasm and gomobile included; decoders accept only canonical encodings; every leg builds with one Go toolchain, since x/text picks its Unicode 15.0.0 or 17.0.0 tables by toolchain (.gomodcache/golang.org/x/text@v0.43.0/unicode/norm/tables15.0.0.go:3, `//go:build !go1.27`; connect/go.mod:3 and sdk/go.mod:3, `go 1.27.4`), and the vectors check the linked `norm.Version`, `cases.UnicodeVersion` and `unicode.Version` and x/text's module version (`IndexFileHeader` field 14), and include examples of the 19,960 two-rune strings that v0.40.0's and v0.41.0's NFC compose wrongly under go1.27.3: the four Hebrew pairs (U+05D2 U+0307, U+05DA U+0307, U+FB32 U+0307, U+FB3A U+0307) and a supplementary letter, U+10044 U+0307, which v0.40.0 composes to U+1E0A (§4.7); v0.40.0, which connect/go.mod:33 requires, keys recomposition on runes clipped to 16 bits (.gomodcache/golang.org/x/text@v0.40.0/unicode/norm/forminfo.go:217; tables17.0.0.go:8070-8071 map 0x05D20307 to U+105C9 and 0x05DA0307 to U+105E4), while v0.43.0, which server/go.mod:59 requires, keys full runes (forminfo.go:217), and both report Unicode 17.0.0. *Why:* convergent roll-ups, local reproduction and the indexer's checks rest on determinism (FI-22), which map order, a toolchain or x/text's tables and code break silently.

**D-TEST-16 (proposed).** Remote search is checked against `SearchOracle` as local search is, and its privacy by a relay capture: one frame-size sequence per kind whatever the query, results or post-parse failure, and equal evs request logs on both devices with and without it (FS-83, FI-24). Its stored accounting is checked by FS-125's sweep: a window's reports are the same for zero to five exchanges over every background within its allowance, both directions, across its contracts. *Why:* fixed sizes and evs's blindness are owner decision 175's whole privacy claim, and one optimization would break either silently: an early short reply, or a sync before answering. Owner decision 176's claim fails just as silently when a fixture's background sits far from a multiple of 128 KiB (meta review F18).

**D-TEST-17 (proposed).** FS-86 gates the directory against §16.11's cost table: its M6 case on announce entries at M6's Gn-out, and its card case at the later of M6's and M10's, each at 500 members in physical time on T3 and, as fake-clock days with one physical peak hour at 3x bursts beside §22.8's 1x year-one mix, at the Team limit (2,000 members, 5,000 admissions) and at a 5,000-member stress case; a golden schedule (`DirectoryCostOracle`) computes each reader's expected requests, path reads and ciphertext bytes from the events and sync times alone, the measured ones staying within 1.25 times them per reader-day and per team-day, and disabling coalescing, head reproduction or unchanged-card suppression fails that check; the cards ref's commits meet the table's p99, rerun and 429 ceilings, and injected store delays fail them; the year-one mix keeps its p99; a cold phone past 8 MiB on a metered link shows partial coverage it can continue; priced NVMe bytes per push per drive meet §11.13's price table, and the directory's pushes join format 2's computed write gate, which production confirms after the freeze (D-TEST-13; owner decision 174). A miss at the Team limit blocks its gate, and the owner hears then. *Why:* reader transfer, per-stream reads and one ref's head are the directory's binding terms, and a number recorded with no ceiling cannot fail.

**D-TEST-18 (proposed).** Drop deletes ship in observe mode (§19.11's `drop: observe`): jobs run every phase and record their delete sets, deleting nothing, while the drop oracle (taskworker's verify, written apart from mark) checks each set against every retained version. Deletes turn on only once FS-89 to FS-96 pass on their tiers, TLC checks I-EVS-15 and FI-27, and a production soak on internal networks and design partners of at least 30 days and 200 jobs, half of them on repos with renames and cross-ref copies, finds no delete-set member that a retained version names. *Why:* a drop deletes keep-forever content (owner decision 173), the costliest bug class, and observe mode shows its sets on real histories first.

### 22.13 Open questions

**Q-TEST-1.** Cross-cutting (X9, §4): copy connect's test helpers or export them? **Closed by peer review 2026-11-04:** (a), `sidecartest` builds on connect's exported API; every T2 scenario using the fake contract issuer or ControlId sink also runs in T3 on server's exchange (server/connect/resident.go:902), and a divergence fails; a connect pin change reruns both tiers; a recurring drift, or a helper needing unexported state, raises an X9 row for `connect/connecttest` to the owner. *Residual:* none.

**Q-TEST-2.** The local stack lacks an object store, and its one Redis node accepts cross-slot commands production's cluster rejects. **Closed by peer review 2026-11-04:** (a) plus (b), in 22.4's topologies: locally a 3-master Redis Cluster on 8.10.2 and one 8-drive MinIO at EC:4 from the production source; in T3 and at the release gate the same cluster and MinIO as 4 × 2 at EC:4 and 4 × 4 at EC:8; a runtime and static CROSSSLOT lint; canary is no substitute. *Residual:* none.

**Q-TEST-3.** Who reviews externally? **Decided by owner 2026-11-03 (owner decision 99):** nobody for now; 22.10's gates stand in. *Residual:* none.

**Q-TEST-4.** How is the iOS tunnel's footprint verified without an iPhone (connect/MEMSTEADY.md:18)? **Decided by owner 2026-11-03 (owner decision 100):** (b), surrogate cells only (22.9), accepting 22.16's jetsam risk. *Residual:* none.

**Q-TEST-5 (withdrawn).** Superseded by owner decision 24; §11 holds the residual.

**Q-TEST-6.** Does §6.11's `oneof` ban cover every sidecar proto or only envelope, stream and push messages? **Closed by peer review 2026-11-04:** (b). No `oneof` appears in envelope, stream or push messages, or in any message they carry transitively; 22.5's descriptor lint walks from those roots over the released descriptors and fails on a oneof outside its explicit allowlist, empty in v0; other protos may use one. The reason is allocation: protobuf-go allocates a wrapper for each set oneof field, and hot-path decodes stay allocation-free (§10.4's `UrMlsCredential` has none). *Residual:* none.

**Q-TEST-7.** Where does continuous fuzzing run? **Decided by owner 2026-11-03 (owner decision 101):** (c), nowhere; seeds run as Go tests (22.6). *Residual:* none.

### 22.14 Departures from PLAN.md

None. PLAN.md says nothing about testing.

### 22.15 Interfaces

- **Provides:** `sidecartest` (harness, fakes, store suites, `PrivacyCapture`, `SearchOracle`, `DirectoryCostOracle`, which computes FS-86's expected reads and bytes from a schedule's events and sync times alone) and `sidecartest/fault` (schedules, faults, barriers); `sidecar/test.sh`; fuzz corpora; the `metadata_list.yml` guard; 22.7's suites; FI-1 to FI-30 and FS-1 to FS-125; the drop oracle (D-TEST-18); the storage benchmark, whose `nvme` costs become §11.13's price table (D-TEST-11); model checks (`EvsCommit.tla`, `IndexRollup.tla`, `StoreSettle.tla`); testdata/index/; the ZK corpus; the 0x0010 interop artifact.
- **Consumes:** §2.8's list; `make check` (§4); `testHookSecret` sites (§5, §9's `K_sock`, `K_tok` and `K_seal`, §10, §11, §13-§15, §17's ShareKey and ShareSigner seeds) and `testHookBarrier` sites at every linearization point (§7-§21, and §5.6's revocation posts); §5-§21's targets; §19's environments, W2, drive counters and M2's staging cluster (§19.11); §23's milestones and gate map; from M6, §16.11's directory; from M10, the barriers of the purge, the sweep, evacuation's staged decision, seals, merges, the roll-up lock, the migration and the drop job (§11), §11.14's remote search, §16's search tools, §18's injected network and charging state, RECORD.md's search fields and, after format 2's freeze, production's write-budget counters (owner decision 174).
- **Subprotocol messages, API routes, tables:** none; release builds carry no test route.
- **Services and config:** server/local's 3-master Redis Cluster and 8-drive MinIO, T3's MinIO clusters (22.4); RUN-ALL, TEST-PERF and test-main cells.
- **Assumptions about other sections:** §19 runs T6 with test roots and LE staging, runs M2's staging cluster on the production hosts' PM9A3 set with §19.6's settings and counters, rebuilt empty and SMART-rechecked before M3 (§19.11), runs 22.9's file-cluster suite on every new cluster before `place_new` names it, and gives §19.11's format2 gate a purge mode and a `drop` mode (observe, on) that admit only internal networks and design partners while observing (D-TEST-12, D-TEST-18); §23.8 gates freezes in D-PHASE-7's two steps, the escrow order at M6's entry on FS-46 and 20.9's benchmark, and burners on D-MAIL-9; §23.4's M2 exit names FS-57 to FS-63, FS-113, FS-114's head and marker cases, FS-116 to FS-118 and FS-72's and FS-95's format-1 cases, and §23.6's gate map lists each FS at every gate its row names, later parts included (FS-19, FS-23, FS-30, FS-38, FS-39, FS-41, FS-42, FS-47, FS-66, FS-69, FS-76 to FS-78, FS-80, FS-83 to FS-88, FS-92, FS-97 to FS-101, FS-106, FS-109 to FS-112, FS-114, FS-124 and FS-125; FS-82's mail and coverage cases at M7 and M8), FS-63 and FS-119 again at each next metadata cluster, FS-119 first at M3-out, M10's schedules, and S7's SNI-less abuse@`<root>` case at M5; every index file an erasure rewrites fits §11.12's closure upload bound; each owning section names a barrier at each linearization point (22.8's rules).

### 22.16 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Unaudited novel crypto passes every test, 0x0010 having no vectors (owner decision 99) | Medium | Critical | 22.10's interop artifact; §10.4's mapping and KATs; its disclosure (owner decision 119) |
| A scanner gap lets a leak pass | Medium | High | decompression, self-test, schema guard |
| A race no schedule names passes every test | Medium | High | barriers at every linearization point; the seeded explorer; TLC and Porcupine (D-TEST-10) |
| Measured drive writes miss D-TEST-11's gate (format 1) or D-TEST-13's (format 2, the index on everywhere) | Medium | High | 1 KiB blocks and §19.6's settings, chosen at M2 on format 2's projection too; owner decision 172's companion cadence; M2's exit and each freeze wait for their gate, format 2's on D-TEST-13's projection, confirmed on production after the freeze (owner decision 174) |
| The governor's accounts charge P2 twice, let a class other than P0 issue while P0 holds the bucket empty, or keep the other classes stopped after a P0 storm ends, so pushes are refused early or the drives wear past the budget by more than P0's forgiven excess | Low | High | one conservation equation and FI-14 (a) and (b), checked after every step; FS-116's exact-cost schedule and its mutant before D-TEST-11's hardware run; FS-117's day of P0 alone past the refill, the day after it, and its mutants |
| HE refuses port 25, blocking outbound conformance | Unknown | High | asked in M0 (§23.7) |
| Test hooks reach a release, exposing keys or stalling steps | Low | Critical | build tag; `make check` |
| A jetsam regression reaches users | Medium | Medium | surrogates; `make size` |
| A purge bug deletes a newest version's content | Low | Critical | observe mode and its soak (D-TEST-12); FI-16 model-checked; FS-64 to FS-71 |
| The oracle shares a normalization bug with the index | Medium | Medium | written apart, sharing only the published tables; fixed vectors; 22.6's reference extractor |
| A phone's "search more" leaks the query through what it fetches | Low | High | FI-23's trace equality; no body fetched before an open; a remote search's sizes and evs logs are FI-24's |
| A malicious server injecting mail reads trigram presence from padded sizes (DBREACH) | Medium | High | no compression; Padmé and §11.14's keyed pad; 22.7's fixture fails the build on a recovered code |
| A drop bug deletes live content | Low | Critical | D-TEST-18's observe soak; FI-27 and I-EVS-15 model-checked; FS-89 to FS-96 |

### 22.17 Phasing

Milestones, v0 and v1 follow §23.4.

- **v0:** T1-T4, seeds, 22.5's gates and 22.10 throughout; each FS at its gate (§23.6's gate map); each test at its component's milestone: S1, S2, S3a, S4a, 22.7's suites, twenty agents with §11's v0b, the storage benchmark with D-TEST-11's gate, FS-57 to FS-63, FS-113, FS-114's head and marker cases, FS-116 to FS-118, FS-72's and FS-95's format-1 refusals and FS-124's verification cases (M2); the `hosts` row, FS-50's out-of-hours host return included, the `hdd` row on production with its admitted mix, FS-119's cohort drill, the approvers' unknown-version refusal, and FS-98's and FS-124's CLI cases (M3); the page Worker's browser rows, FS-97's personal-network cases and the escrow harness, dark (M4); §13.7's browser rows, holds and S7's SNI-less abuse@`<root>` case (M5); the rest of S7 and the census (M7); FS-98's and FS-124's app-host cases (M8); S6, MTA and ZK rows (M9).
- **v1 (M6):** S3b, S4b, OIDC, JIT, SCIM and custom-domain rows, 22.7's seat cases (owner decisions 144, 182) and FS-30's audit reader; S13, FI-25, FI-26 and FS-84, FS-85, FS-87 and FS-88's M6 cases, FS-86's M6 case, FS-99, FS-100 and FS-101's M6 cases, FS-97's, FS-98's and FS-124's Team cases and §22.9's self_admit-off Browsers case, FS-85's and FS-100's wakes at M8-out; FS-46 and the escrow run by M6's entry; direct MX and strict mode from M7.
- **v1 (M10, owner decision 169):** S11, S12, FI-16 to FI-24, FI-27, FS-64 to FS-81, FS-83, FS-89 to FS-96, FS-107 to FS-112, FS-114's purge and drop cases and FS-125 on M10's mechanisms, FS-83's, FS-109's, FS-110's, FS-125's and FI-24's app-host cases at the later of M10-out and M8-out and their team cases at the later of M10-out and M6-out; FS-84's, FS-87's, FS-99's, FS-100's and FS-101's card and index cases, FS-86's card case and FS-88's search_agents cases at the later of M10-out and M6-out (D-PHASE-11); the index, phone, search, remote, directory and drop rows with D-TEST-13's projection; the index vectors on every leg; git-lfs conformance; both models and EvsCommit.tla's drop extension; the later cases of FS-66, FS-69, FS-76 to FS-78, FS-80, FS-92, FS-111 and FS-112 at the later of their rows' exits (M5, M6, M7, M8) and M10-out; D-TEST-12's and D-TEST-18's soaks after M10's Gn-out.
- **Later:** the synthetic main network; the extension's Worker; FS-63 and FS-119 before each next metadata cluster takes repos (owner decision 145).
- **Blocking:** each Gn-in needs its FS rows written, M2's `EvsCommit.tla` and `StoreSettle.tla` passing TLC (D-PHASE-7) and M6's FS-46 and 20.9's benchmark passing (Q-QUOTA-3's residual); D-TEST-11's gate needs the production hosts' PM9A3 set as M2's staging cluster, and §19.6's drive counters, before M2's exit; M10's Gn-in needs `EvsCommit.tla`'s purger and `IndexRollup.tla` passing TLC, and its Gn-out the drop extension passing TLC and D-TEST-13's projection from M2's price table and T3's counts.
