## 5. The Sidecar core: identity, keys, lifecycle, local state

### 5.1 Purpose and scope

This section owns `sidecar.Sidecar` (lifecycle, components, events, the outward-action gate); the client identity (X10); the client side of login, enrollment, pairing, admission, owner consent, refresh, revocation and AUTHZ1; and the daemon, local IPC, local state, keys, recovery and platform variants. §6 owns the subprotocol; §7 enrollment routes, auth keys, OAuth, the AUTHZ1 server fix and config records; §8 policy; §10 MLS; §11 evs; §16 MCP and approvals; §18 hosting; §20 counting.

### 5.2 Requirements

| Id | Requirement | Source |
|---|---|---|
| R-CORE-1 | Import connect only | PLAN.md:7 |
| R-CORE-2 | Hold "an authenticated jwt, connect client, api, and encryption key" | PLAN.md:14 |
| R-CORE-3 | The CLI speaks stdio MCP by default | PLAN.md:19-20 |
| R-CORE-4 | Run in the sdk, the apps, and the extension's web worker | PLAN.md:28 |
| R-CORE-5 | The git identity is the sidecar client id | PLAN.md:59 |
| R-CORE-6 | `--instance`; `ur login/logout/status/daemon/install-daemon/uninstall-daemon` | cli/UI.md:10-19 |
| R-CORE-7 | A keychain encoded with a pass; changing the pass re-encodes it | cli/UI.md:82-85 |
| R-CORE-8 | Any number of in-daemon agents, free, with their bytes debited (pitch5's "never metered" changes) | sidecar/design/pitch5.html:844, :849; owner decisions 4, 10 |
| R-CORE-9 | `ur connect --token`; "Log in with URnetwork" | sidecar/design/mocks/recurd-app.html:712, :930 |
| R-CORE-10 | Agent tokens ≤1 h, key-bound, never in the agent's environment | sidecar/FEEDBACK-SYSTEM.md:139; §2 I-7 |
| R-CORE-11 | No sidecar credential can administer the network | §2 I-6 |
| R-CORE-12 | Identities survive the client reaper | server/model/network_client_model.go:4179, :4199 |
| R-CORE-13 | Settings-owned tunables; a `Logger` with connect's methods; pure Go for wasm; mobile budgets | connect/CODESTYLE.md:140-151, :179-182; [R:sdk-clients] §3 |
| R-CORE-14 | Outward actions need an I-8 approval from every entry point | §2 I-8; owner decision 75 |
| R-CORE-15 | One person in several networks, no key linking them | §7 R-TEAM-3; owner decision 23 |
| R-CORE-16 | Admission and revocation only by signed config-repo records, from v0 | owner decisions 3, 5, 110, 112, 127 |
| R-CORE-17 | Owner-bound repos take only consented devices; members' devices alarm on admissions under them that they did not sign | owner decision 126 |
| R-CORE-18 | Each network's search index cache stays sealed on the device, is fetched by sync position, holds no query, and is deleted with the content or access it derives from | owner decision 166; §11 D-EVS-26 |
| R-CORE-19 | An indexer's remote serving leaves local searches their targets and persists no query, its served record one row a requester, repo and day | owner decisions 175, 294; I-13 |

### 5.3 What exists today

**connect**
- `BringYourApi` has `AuthNetworkClient(Sync)`, `RemoveNetworkClient` and `GetClientKey`, but no refresh (connect/api.go:20-62, :256-330, :548-570). `NewClient` (connect/transfer.go:2267) takes a `ClientKeySeed` (:1657-1663) and `ClientAuth` (connect/transport.go:348-364).
- `ClientKeyManager.Sign` signs without a label (connect/transfer_key.go:221-229), and the key history does not stop an operator malicious from first contact (connect/transfer_key_history.go:22-26). The ClientKey is plain Ed25519 from a 32-byte seed (connect/transfer_key.go:127-129).
- Package connect's untagged tun.go imports gVisor (connect/tun.go:38-50), so a file using any connect type, even `Id` (connect/id.go:15), `Logger` (connect/log.go:41), `MonitorValue` or `CallbackList` (connect/util.go:74, :220), links the IP stack.

**server**
- A client token creates only its own children (`source_client_id`, server/model/network_client_model.go:191, :374-394). A child is exempt from the client caps (:535, :757-779), never becomes a peer (connect/transfer.go:17611-17617) and ends with its parent (server/session/by_jwt.go:679-700).
- The reaper deactivates a top-level client after 30 idle days and deletes it 30 days later, and deletes a child after 30 days unseen (server/model/network_client_model.go:4179, :4199, :4467). One resident serves each client id and instance (server/model/network_client_resident_model.go:62-68).
- `/auth/code-create` escalates a client token (server/api/route_authz.go:123), and expiry is not enforced (server/session/AUTH.md:229; §7.3); a removed client's tokens stop at once (server/session/AUTH.md:197). `GET /auth/refresh` takes a bare Client token (route_authz.go:115), and `POST /network/auth-client` (OwnClient) mints and reissues client tokens (:132), neither with a proof of possession.

**Missing:** everything below.

### 5.4 Sidecar: fields, settings, lifecycle, components

```go
// Every leg: sidecar.go, settings.go and the root's id, log and monitor files import no connect package, so
// §18.10's sidecar_http leg links them (§4.4) and no connect package, its Id being the root's own twin of
// operator-core's (owner decision 276). Sidecar is safe for concurrent use.
type Id = operator.Id // operator-core's: server.Id moved, type Id connect.Id with its marshalling (§4.5;
                      // owner decision 251); connect-facing files convert: connect.Id(id); NewId stays here, on
                      // crypto/rand

type Logger interface { // connect.Logger's methods (connect/log.go:41); connect-facing files adapt it
	Info(args ...any)
	Infof(format string, args ...any)
	Warningf(format string, args ...any)
	Errorf(format string, args ...any)
	V(level int32) Verbose // Verbose: Enabled(), Info, Infof
}

// MonitorValue[T comparable] and CallbackList[T any]: the root's copies of connect/util.go:74, :220.

type SidecarApi struct { // net/http: bind, refresh, the exchange and the sidecar routes (§7-§20)
	stateLock  sync.Mutex
	byJwt      string                                        // the authenticated jwt
	dpopSigner func(method, url, ath string) (string, error) // the ClientKey's proof (§7.4), by crypto/ed25519
	transport  http.RoundTripper // connect leg: dials by its ClientStrategy's ConnectSettings().DialContext
	                             // (connect/net_http.go:777, connect/net.go:232), egress-bound as
	                             // connect/net_http.go:3663-3668 requires; sidecar_http: net/http's fetch
}

type Sidecar struct {
	host           SidecarHost // Store(); KeyStore() (nil: pass only); TokenSource() (nil: D-CORE-8's refresher)
	settings       *SidecarSettings
	sidecarApi     *SidecarApi
	state          *MonitorValue[SidecarState] // Locked → Unenrolled ⇄ Offline ⇄ Online (5.6); a locked
	                                           // store → Locked (5.9); only a verified SidecarRevoke → Revoked
	eventCallbacks *CallbackList[SidecarEventFunction]

	stateLock sync.Mutex
	keychain  *keychain        // nil while locked; holds this network's root key R_n (5.9)
	identity  *SidecarIdentity // ids and identity public key
	leg       *sidecarLeg      // declared per leg: !sidecar_http, a BringYourApi on the same jwt, the components
	                           // and one connect.Client per client generation; sidecar_http, the long-poll (§6.8)
}

type SidecarAction struct { // every outward action (I-8)
	Kind      SidecarActionKind // tls/ or smtp/ publish or listen; forward; expose; egress change; invite or share;
	                            // alias create or delete; agent-config write or delete in a shared repo (§16.5);
	                            // DNS user record set or delete; mail to a non-member with no approved-recipient
	                            // record (§15.7's rcpt/; owner decision 280), or to any non-member in a tainted
	                            // run; an access request through the team directory (§16.11; CanonicalAction
	                            // version 3); payment; a restore; a TL4 allowance for a recipient domain (§14.4).
	                            // On the wire one verb a value (§16.8): 1 publish,
	                            // 2 listen, 3 forward, 4 expose, 5 egress_change, 6 invite, 7 share,
	                            // 8 alias_create (burners too, §15.8), 9 alias_delete, 10 agent_config_write,
	                            // 11 agent_config_delete, 12 dns_set, 13 dns_delete, 14 mail_send,
	                            // 15 access_request, 16 payment, 17 restore, 18 mail_tls_unauthenticated (owner
	                            // decision 436), new kinds appending; publish and
	                            // listen cover tls/ and smtp/ alike, since host and socket_name say which
	Canonical []byte            // built by the daemon; payload_sha256 = SHA-256(Canonical)
	Risk      SidecarRisk       // 1 normal, 2 high, the wire's values (§16.8); every action is normal: no policy
	                            // field and no classifier raises one, and no decision needs an SSHSIG, in v0 and
	                            // every milestone until a customer asks (owner decision 279)
	RunId     *Id               // a decision binds (approval_id, run_id, agent_id) and authorizes at most
	AgentId   *Id               // `uses` distinct actions, each once (§16 D-MCP-11)
	Effect    SidecarEffect     // live, set by the caller: what Authorize runs once the use is reserved (§16.6)
	Outcome   *SidecarOutcome   // set by Authorize
}

type SidecarEffect interface { // one outward action's effect, idempotent per effectKey, which is empty under a
	// standing grant, where no ledger row is kept
	Run(ctx context.Context, effectKey []byte) (effectRef []byte, err error)
}
type SidecarOutcome struct { // what a use's effect came to (§16.6)
	State     string // done, not_done or uncertain
	EffectRef []byte // the component's reference to what it did
}
// A kind's lookup reads only the stored action, so a restart reconciles a reserved use with no caller alive; a
// kind with no registered lookup is refused before its Reserve.
type SidecarEffectLookup func(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error)

type SidecarEvent struct { // AddEventCallback, `ur status`, the sdk listener (§18.5), ur://acl/grants
	Kind        SidecarEventKind // state, approval_pending, member_added, member_removed, key_changed, refused,
	                             // admission_alarm, recovery_rebind, recovery_window, recovery_unseen (5.6),
	                             // admissions_near_cap: on admin devices, from 90% of config_admissions' cap, with
	                             // §7.10's cleanup list,
	                             // head_alarm (§6.4); index_mismatch, index_malformed (§11.14); search_alarm: an
	                             // indexer's hit that its text disproves, or a local hit it omitted (§11.14);
	                             // history_drop: a drop's state changed (§11.7); access_request: an approver's
	                             // pending directory request, and access_decided: the requester's, with its
	                             // outcome; directory_erasure: a repo owner's revocation still waiting for the
	                             // directory's erasure runner past 24 h, then done (§16.11); erasure: an erasure
	                             // this device runs or may finish changed state (§11.12); mail_send: an internet
	                             // send's outcome for a recipient domain changed (§14.5); evs_conflict: §11.11's
	                             // restart row left a local conflict ref, an ordinary event; evs_alarm: storage
	                             // that fails a reader's or writer's check (EvsAlarm); evs_gap: a re-pin past
	                             // §11.9's budget (VerifiedSince); record_alarm: the record's and the directory's
	                             // reader alarms (RecordAlarm; §16); credential_store: an enrolled daemon found a
	                             // readable network by_jwt in a host store (5.6), with no path or value, ur status
	                             // naming the store kind; ct_alarm: §13's CT watch, Evidence[0] the leaf's
	                             // SHA-256; mail_receiver_alarm: D-MAIL-15's (§15); bridge_alarm (§17); key_changed:
	                             // gkm serves under this sidecar's id a ReaderKey it never signed (§10.5's
	                             // readerkey row; owner decision 358)
	State       SidecarState
	Reason      SidecarStateReason // Unenrolled: expired, refused, parent_lost, session_ended, keystore_lost;
	                               // Revoked: signed (§18.5's GetStateReason)
	GroupId     *Id // membership kinds: the §10 group
	SidecarId   *Id // membership kinds: the leaf or wrapped reader; admission_alarm: the admitted sidecar;
	                // recovery_rebind: its signer; recovery_unseen: the recovered device; head_alarm: the peer,
	                // nil for a fork evs shows; index alarms, history_drop and evs_alarm: the signer;
	                // search_alarm: the indexer; record_alarm: the writer or signer; mail_receiver_alarm: the
	                // receiver
	RepoId      *Id    // index alarms, search_alarm, history_drop, directory_erasure, erasure, evs_conflict,
	                   // evs_alarm, evs_gap, record_alarm, mail_receiver_alarm
	RefId       *Id    // index alarms, history_drop, evs_alarm, evs_gap; evs_conflict: the local conflict ref
	Path        string // index alarms: the alarmed path; history_drop: its first listed path (§18.5's Drops
	                   // lists all); evs_conflict, evs_alarm: its path; a path local to this device, never
	                   // logged (I-13)
	DropId      *Id              // history_drop
	DropState   SidecarDropState // history_drop: pending, cancelled, executing, done (a held drop reads done,
	                             // owner decision 184), refused, or invalid: it failed this device's checks (§11.7)
	NotBefore   time.Time        // history_drop: its window's end (owner decision 183)
	SearchAlarm SidecarSearchAlarm // search_alarm: mismatch (an opened hit's text disproves it) or omission (a
	                               // local confirmed hit that no page of the checked span returned)
	RequestId   *Id // access_request, access_decided: the directory request; directory_erasure: its erasure request
	Outcome     string // access_decided: approved, denied, cancelled or expired; directory_erasure: pending or done
	SendId      *Id // mail_send: the send, whose outcomes §18.5's GetSendResult reads
	ApprovalId  *Id
	HeadAlarm   SidecarHeadAlarm // head_alarm: fork (two pins that disagree; a head evs serves that does not
	                             // extend this device's pin is one, SidecarId nil and Evidence this device's
	                             // RefHead and evs's), withheld (PROOF OF WITHHOLDING), unverified, unwitnessed
	                             // (24 h without a consistent witness; 1 h for a revocation it signed), or
	                             // rollback: a push reset presenting a durable topic below the version this
	                             // client holds (§6.8; owner decision 300), SidecarId nil and Evidence the
	                             // two TopicVersions as protobuf bytes, the held one first
	Evidence    [2][]byte        // head_alarm: my pin and the peer's or api's, as §6.5 encodes them (AuthPin,
	                             // GroupHead, GenHead or RefHead); recovery_rebind at a void: the AuthPins
	                             // at which keychain.wrap was sealed to the voided binding and re-sealed (5.9);
	                             // ct_alarm: [0], the leaf's SHA-256; key_changed: [0], the foreign key's SHA-256
	EvsAlarm    SidecarEvsAlarm  // evs_alarm, a closed set: missing_segment, tamper (a failed entry hash, AEAD,
	                             // oid or statement), version_rule (off §11.7's rule), epoch_overdue (a writer
	                             // 1 h past due_by_ms) or prefix_rule (from M6)
	VerifiedSince time.Time      // evs_gap: the time of the newest re-pin past §11.9's budget, which the pin
	                             // record holds; EvsRepo.VerifiedSince(refId) answers it later, zero when
	                             // nothing was skipped
	RecordAlarm SidecarRecordAlarm // record_alarm, a closed set of 14: chain_gap, chain_fork, bad_entry (RECORD.md
	                             // section 5.4's steps 1-4, section 5.5's steps 1-3, 5 and 6), depositor_kind,
	                             // early_removal (a BASE or ERASE taking an entry before keep_days, or a class 7
	                             // entry), path_rule, parked_writer, over_cap, over_limit (§16.11's limits row),
	                             // id_reuse, bad_erasure (an ERASE, CUT or CLOSURE from another signer, or an
	                             // erasure_request that fails its check), bad_decision, log_check (RECORD.md
	                             // section 10.2) and moderation, which apps show as a notice; head_alarm stays
	                             // HeadCheck's, index_mismatch the index's and evs_alarm storage tampering's
	BridgeAlarm string           // bridge_alarm: block_conflict (§17.4), share_holder_removed (§17.9),
	                             // principal_mismatch (§17.9's verify), state_unverified (§17.8), block_refused
	                             // (D-BRIDGE-16) or, from a VPN component, narrowing_overdue (§18.10's memory row,
	                             // backing off to daily; owner decision 487)
	Erasure     *SidecarErasure  // erasure: its id, state and what is left (§11.12, §11.13's wait)
}

type SidecarErasure struct { // §11.12's erasure as its eraser's device, or a device that may finish it, sees it
	ErasureId   Id
	State       string    // fenced: its CUTs committed, its documents masked and unpublishable, its own keys
	                      // gone with the first ERASE; rewriting; waiting: a 429 for its allowance or turn, or
	                      // room for its CUT in a ref's full erasure set (§11.12's cut row);
	                      // done: every key destroyed; stalled: no device that may finish it is running
	ObjectsLeft int64     // rekey objects not yet re-keyed (§11.13's wait row)
	BytesLeft   int64     // their closure bytes
	NextTry     time.Time // the last 429's retry_after_ms; zero when none waits
	Finish      time.Time // §11.13's bound from BytesLeft, the allowance and the turns; zero below the limit
}

type SidecarStatus struct { // Status(): `ur status`, §18.5's GetState and GetStateReason
	State       SidecarState
	Reason      SidecarStateReason
	Generation  int64     // the bound client generation (5.5)
	WitnessedAt time.Time // the newest consistent HeadCheck witness (§6.4); zero: none yet
	Unverified  [][]byte  // the open UNVERIFIED auth pins (§6.4), as AuthPin bytes; empty: none
	CtWatchDegraded bool  // §13's CT watch cannot run as it should
	Lines       []string  // one line a condition, such as an unmirrored log or a waiting erasure, filled by each
	                      // component through the core's status seam and printed by `ur status` as is; nothing
	                      // parses them
}

type SidecarIdentityBinding struct { // 5.5; signed by the ClientKey and the identity key
	NetworkId, SidecarId, ClientId Id
	Generation                     int64 // 1 for a sidecar_id's first binding, then n+1 for every new client:
	                                     // re-enrollment, pairing, fallback (5.8)
	ClientPublicKey                []byte
	IdentityPublicKey              []byte
	IssuedAt                       time.Time
}
// On the wire, in protocol/bridge/auth.proto: SidecarIdentityBinding{network_id = 1, sidecar_id = 2,
// client_id = 3, generation = 4 (int64), client_public_key = 5, identity_public_key = 6, issued_at_ms = 7 (int64)},
// carried as SignedSidecarIdentityBinding{body = 1, client_signature = 2, identity_signature = 3}, body being the
// first message's bytes. Each signature is Ed25519 over §6.9's signed bytes with SIGNED_SIDECAR_BINDING = 0x1A01:
// purpose binding-client by the ClientKey, binding-identity by the identity key. Verifiers check the received body
// bytes, never a re-marshal. Hello.binding and POST /sidecar/bind carry the marshalled wrapper, and 5.15's
// signatures column stores those bytes verbatim, since the table's other columns cannot rebuild them.

type SidecarSettings struct { // validate refuses every number that is not positive, on every leg, so zero is
	// never unlimited or off; only a field tagged settings:"zero" gives zero a meaning, which its comment states:
	// Search.CacheByteCount (in memory), AutoLockTimeout (never), IdleExitTimeout (never)
	Instance, ApiUrl, PlatformUrl, AuthUrl, AppVersion string
	EvsUrl, GkmUrl, SocketsUrl, DnsUrl                 string // every url empty in DefaultSidecarSettings, so
	                             // NewSidecar refuses until its host sets them from §18.9's embedded host table,
	                             // the one copy of these names (§19.4's; owner decision 282)
	Connect               *SidecarConnectSettings      // client generations (below)
	ProtocolSettings      *SidecarProtocolSettings     // §6.6
	TokenRefreshSettings  *SidecarTokenRefreshSettings // sdk's schedule (sdk/device_token_manager.go:20-27, :266-275): jti-drawn 0.4-0.5 window, 5 min floor, 15 min retry
	KeychainSettings      *SidecarKeychainSettings     // Argon2id parameters, pass attempts (5 per 10 min) and
	                             // AutoLockTimeout: 10 min with no request on any local socket (control, mcp, hook,
	                             // git), never while 5.8's busy rule holds; zero never locks (5.9; owner decision 284)
	LocalSettings         *SidecarLocalSettings        // sockets; IdleExitTimeout: 10 min, zero never exits, counted
	                             // only by an auto-spawned daemon (5.8); RequestTimeout: 30 s for a local request's
	                             // own work, a person's wait (a /dev/tty confirmation, the daemon's presence
	                             // prompt) running under its method's own bound, and git-mode streams and MCP
	                             // sessions keeping theirs (Mcp.CallTimeout); FirstPort: 17000 (5.8);
	                             // EventRingEventCount and EventWaitTimeout: 5.8's events method
	Mcp                   *SidecarMcpSettings          // §16
	Ingest                *SidecarIngestSettings       // §16.7
	Record                *SidecarRecordSettings       // §16.8
	Search                *SidecarSearchSettings       // §16.10; 5.9's index cache; §11.14's remote search
	Directory             *SidecarDirectorySettings    // §16.11
	ComponentQueueMessageCount, ComponentQueueByteCount int // 256 envelopes, four of §6.6's 64-message peer
	                             // queues; 1 MiB, 256 envelopes in their 4 KiB pool class, a reassembled body
	                             // counting by its size, so one 256 KiB body takes a quarter of the queue
	MemoryBudgetByteCount int64 // contains §6's process-wide reassembly, idempotency and credit caps; proving
	                            // (§14) sits outside it, under the injected prover's own MemoryMaxByteCount
	                            // (2,240 MiB: two loaded shapes and one proof in flight, kept by counting and a
	                            // collection after each proof; DESIGN-DETAILS.md section 3, 3.2.8):
	                            // SmtpSenderSettings.ProverConcurrency defaults to 1, and a host records p/ only
	                            // after Prover.Measure finishes inside that bound, one that cannot recording
	                            // none and only queueing
	StreamChunkByteCount  int
	Log                   Logger // nil: connect.DefaultLogger() (glog), adapted; sidecar_http: none unless set
}

type SidecarSearchSettings struct { // §16.10's limits, 5.9's cache and §11.14's remote search; defaults only from
	// DefaultSidecarSettings(), which hosts adjust per class as sdk's applyMobileLowMemoryClientSettings does
	// (sdk/mobile_memory_policy.go:332; §18.4); a daemon designated for search (§7.9) applies CacheByteCount
	// 16 GiB and MemoryBudgetByteCount 192 MiB (owner decision 175)
	CacheByteCount         int64            // 4 GiB; 0 keeps the cache in memory (ephemeral sidecars)
	MemoryByteCount        int64            // 64 MiB of decoded index state, inside MemoryBudgetByteCount; app
	                                        // and page hosts set §18.4's smaller working sets
	VersionCacheByteCount  int64            // 256 KiB of 5.9's version-table pages a process, inside MemoryByteCount
	BackgroundByteCount    int64            // 1 GiB a day a network of sync downloads
	MoreByteCount          int64            // 1 GiB a call
	AllPolicy              string           // §18.4's mode for all: background (desktops, indexers), on_demand
	                                        // (ephemeral, cloud)
	HintCoalesce           time.Duration    // 1 min a repo, on the leading edge: a quiet interval's first hint
	                                        //   fetches at once (§16.10; owner decision 450)
	CursorTimeout          time.Duration    // 10 min idle, local and remote cursors
	HeadRefreshInterval    time.Duration    // 10 min: at most one forced head refresh a repo
	NonWriterSyncInterval  time.Duration    // 15 min: a reader that is not a writer syncs an owner-bound index
	                                        // at most this often (§16.10's receipts)
	SessionSearchCount     int              // 2 at once a session
	SessionSearchRate      SidecarRate      // 5 a second, burst 10, a session
	SessionCursorCount     int              // 16 open a session, the oldest dropped
	DaemonSearchCount      int              // 4 local searches at once
	PageCpu                time.Duration    // 2 s of CPU a page, local or remote
	PageCandidateCount     int              // 1,000 candidates verified a page
	TooBroadCandidateCount int              // 20,000 candidates in a partition answer too_broad
	PageByteCount          int              // 64 KiB of MCP results a page
	RemoteMode             string           // "on" until the person picks on, own or off (5.9's state)
	RemoteTimeout          [2]time.Duration // 3 s unmetered, 5 s metered without a first page, then the next
	                                        // indexer
	RemoteServe            bool             // answer remote searches once designated: true on daemon hosts,
	                                        // false on app hosts
	RemoteSearchCount      int              // 4 remote searches computing at once, beside DaemonSearchCount
	RemoteQueueCount       int              // 16 waiting, each at most RemoteQueueTimeout, else
	                                        // RESOURCE_EXHAUSTED
	RemoteQueueTimeout     time.Duration    // 1 s
	RemoteCpuPerMinute     time.Duration    // 30 s of CPU a minute for all remote work
	RemoteCursorCount      int              // 64 open remote cursors, the oldest dropped
	RemoteRequesterRate    SidecarRate      // 30 a minute, burst 10: per requester at an indexer, and per
	                                        // indexer at a requester
	RemoteOwnAskCount      int              // 2 own indexers a search asks at once (§11.14's order row)
	RemoteSkipTimeout      time.Duration    // 2 min: a failed indexer is not asked (D-SDK-27)
	RemoteOnlineTimeout    time.Duration    // 10 min: how long a HelloResult, Pong or page keeps an indexer
	                                        // online, and the own indexer that answered last first
	RemoteRefusedTimeout   time.Duration    // 10 min: a repo an indexer refused in coverage is not asked of it
	RemoteServedTimeout    time.Duration    // 24 h: 5.9's memory of which repos each indexer served
	RemoteMismatchCount    int              // 3 mismatches from one indexer within RemoteMismatchInterval, 24 h,
	RemoteMismatchInterval time.Duration    // void its claims and skip it for RemoteDistrustTimeout, 24 h
	RemoteDistrustTimeout  time.Duration    // (§11.14's merge row)
	SkewGuard              time.Duration    // 40 min: evs's time check both ways (§11.8's 5b), which bounds a
	                                        // fold; a value of the format, changed on no side alone
	PinRingCount           int              // 64 (version, chain) pairs kept a ref, to match a coverage's pin
	RetainFactor           int              // 2: a retained bucket lives at most 2 of its windows past its
	                                        // roll-up
	ResyncInterval         time.Duration    // 1 h: §11.14's resync
	SyncRoundCount         int              // sync rounds at once a network: 4 on daemon hosts, 1 on app hosts
	                                        // and page Workers
	SyncRetryInterval      time.Duration    // 30 s, doubling to ResyncInterval: a round that failed on a read
	                                        // (these fourteen: DESIGN-DETAILS.md section 7, 7.2.1)
	ServedRecordTimeout    time.Duration    // 30 d: an owner's indexer keeps 5.9's served records, by their day
	ServedRecordCount      int              // 8,192 served rows at most, the oldest days dropped first: a last
	                                        // bound that ordinary use and one abusive reader never reach (owner
	                                        // decision 294)
	CompanionInterval      time.Duration    // 5 min on every host: the companion push's cadence (§11.14); 1 min once
	                                        // D-TEST-11's M2 run fixes 1 KiB blocks; no server signal carries it
}

type SidecarRate struct { // Count per Interval, bursting to Burst
	Count, Burst int
	Interval     time.Duration
}

type SidecarDirectorySettings struct { // §16.11's team directory, in team networks; its renewal and expiry
	// times are format values that every reader applies alike (§16.11), not settings (connect/CODESTYLE.md:145)
	SessionSyncInterval   time.Duration // 15 min while the daemon serves a harness session in the network
	IdleSyncInterval      time.Duration // 1 h otherwise
	ViewCoalesce          time.Duration // 30 s: a sync at each directory search or view, coalesced
	PhoneMeteredByteCount int64         // 8 MiB of cards a metered session on phones, which keep cards only while
	                                    // the view is open
	RenewJitter           time.Duration // ±5 min on hourly run renewals
}

func DefaultSidecarSettings() *SidecarSettings
func (self *Sidecar) Unlock(passphrase []byte) error // nil: the key store's wrap of U (5.9)
func (self *Sidecar) Enroll(ctx context.Context, credential *SidecarEnrollCredential) error
func (self *Sidecar) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error // runs the
	// effect: nil once action.Outcome exists, *ApprovalPendingError while pending, any other error a refusal
func (self *Sidecar) RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func()
func (self *Sidecar) Sign(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) // §6.9
func (self *Sidecar) ServiceToken(ctx context.Context, resource string, scopes []string) (string, error)
func (self *Sidecar) Status() SidecarStatus
func (self *Sidecar) AddEventCallback(callback SidecarEventFunction) func()
func (self *Sidecar) Close()
func (self *Sidecar) CloseAndWait(ctx context.Context) error

// 5.6's revocation of another of this member's devices (D-CORE-20), on every leg, a read_only or ephemeral
// caller answering REVOKE_NOT_CAPABLE: ur devices revoke confirmed on /dev/tty, a remote-mode app's control calls
// (5.8) and §18.5's SidecarApprovals reach it, never MCP
type MemberDevice struct { // Devices(): this member's admitted sidecars, this one first
	SidecarId  Id
	Name       string    // its config device name
	This       bool      // the calling sidecar, which signs out instead
	ReadOnly   bool      // a page Worker (§18.8)
	Ephemeral  bool      // a quick burner
	State      string    // live, pending (suspended while its revocation awaits cosigns), parked, stale (§10.9
	                     // removed its leaf as stale from every group this device is a leaf of that seated it,
	                     // at least one) or revoked
	AdmittedAt time.Time
	LastChange time.Time // its newest leaf change in a group this device is a leaf of, its credential's
	                     // not_after less 90 days in that group's tree (§10.9); zero: none seen
}
type DeviceRevokeItem struct { // one row of a plan
	Effect   string // park, void, stands, reseal (5.9's backup rule) or key (offered for KeyRevoke)
	Kind     string // what the row names: device, delegation, recovery_binding, key, evs_share, grant, ...
	Id       []byte // an Id's 16 bytes, a recovery_binding's 32-byte key hash or a key's key_id (§6.9)
	Name     string // a device's or key's name, or an EvsShare's repo
	Position uint64 // the entry that carries it
}
type DeviceRevokePlan struct {
	PlanId     Id     // the first 16 B of SHA-256 over the target and its revocation state, the reason, since_n,
	                  // Signatures, Presence and the key item ids, never a statement header (5.6's sign)
	SidecarId  Id
	Name       string // the target's config device name
	Reason     string // "lost" or "compromise", SidecarRevoke's reasons (§7.9)
	SinceN     uint64 // compromise: where P starts (5.6), with its entry's time
	SinceTime  time.Time
	Items      []DeviceRevokeItem
	Signatures int  // counted signatures needed: 1, or k for an AdminSet member's device, this one counting once
	Presence   bool // set from the log, never by the caller: RevokeDevice needs presence (5.6's approval)
}
type DeviceRevokeError struct { // every refusal of the two calls below
	Code     string // 5.6's REVOKE_ codes
	Position uint64 // REVOKE_PARKS_SELF: the entry that puts this sidecar in P
}
func (self *Sidecar) Devices() ([]MemberDevice, error) // FAILED_PRECONDITION while Locked or Unenrolled
func (self *Sidecar) PreviewDeviceRevoke(ctx context.Context, sidecarId Id, reason string, lostAt time.Time,
	sinceN uint64) (*DeviceRevokePlan, error) // sinceN 0: the proposed position, which needs a loss time (5.6's
	// plan; owner decision 292); lost ignores both
func (self *Sidecar) RevokeDevice(ctx context.Context, planId Id, revokeKeyIds [][]byte,
	presence func(challenge []byte) ([]byte, error)) (entry *bridge.AuthPin, proposalId []byte, err error)
	// presence: the host's check over the act's countersigned bytes (§7.9's presence row), returning §6.9's
	// WebAuthnEvidence, which becomes each statement's countersignature (in control mode by 5.8's two calls), nil
	// only while the plan's Presence is unset; revokeKeyIds: the plan's key items the person left selected;
	// proposalId: §7.9's 32-byte proposal_id, set while k > 1 pends

// The search engine, search_*.go on every leg, and search_remote_*.go, which asks and serves §11.14's remote
// search, where connect links; §16.10's tools and `ur search` call it, and §18.5's SidecarSearch wraps it.
type SearchRequest struct {
	Text         string              // §16.10's query
	Repos        []Id                // empty: every readable repo with its index on (never secret, config, mailcfg)
	Scope        SearchScope         // SearchCached (default: buckets and any cached all), SearchLatest, SearchAll:
	                                 // the partitions; §16.10's breadth is SearchBreadth (SearchBreadthRepo,
	                                 // SearchBreadthNetwork, SearchBreadthAll), §22.4's oracle parameter
	                                 // sidecartest.SearchScope, a struct holding one of each, and search.proto's
	                                 // scope keeps its own 1 and 2
	Since, Until time.Time           // zero: unbounded
	Fuzzy        bool                // near hits even when 3 or more exact hits exist
	Filters      []SearchFieldFilter // §16.10's doc-table filters: from, subject, agent, run, kind, path prefix
	IncludeSpam  bool                // mail the device's join marks spam, which a search otherwise leaves out, and
	IncludeTrash bool                //   trash likewise (§15.7, §16.10's include; owner decision 444)
	AllowMetered bool                // scope all may fetch past §18.4's 25 MiB on a metered link
	Remote       string              // "": the network's remote mode (5.9's state); "off": this search stays local
	PageSize     int                 // default 50
}
type SearchHit struct {
	Repo, Ref  Id
	Path       string         // or a derived document's registered name (§11.14)
	Version    uint64
	Time       time.Time
	Signer     Id             // the document version's writer, for grouping by agent (§16.10)
	Fields     []SearchField  // display fields: title or subject, from, and kind-specific ones
	Snippet    string         // verified hits: around the match; mail: i/'s snippet; else empty
	State      SearchHitState // SearchVerified, SearchConfirmed, SearchPossible, SearchNear, SearchUnmatched (a
	                          // local possible or near hit an indexer's checked span disproved, §11.14's merge)
	Partition  SearchPartition
	Correction string         // SearchNear: the corrected term
	By         string         // "": this device; else the answering indexer's config name (§11.14)
}
type SearchProgress struct {
	Searched, Total          int       // partitions
	FetchBytes, FetchedBytes int64     // scope all: bytes still to fetch, and fetched so far
	Uncovered                int       // changes not yet searchable
	Waiting                  string    // "", "metered", "offline", "update"
	CoveredFrom              time.Time
	Remote, FallbackReason   string    // §18.5's remote states and fallback reasons
	RemoteBy                 *Id       // the indexer asked, or the one a notice names
}
// SearchStatus and SearchIndexer carry §18.5's SidecarSearchStatus and SidecarIndexer fields.
func (self *Sidecar) Search(ctx context.Context, request *SearchRequest) (*SearchStream, error)
func (self *SearchStream) Next() (page []SearchHit, progress SearchProgress, done bool, err error) // replaces the last
func (self *Sidecar) GetSearchStatus(repoId *Id) (*SearchStatus, error) // search_status (§16.10), GetStatus (§18.5)
func (self *Sidecar) SetSearchConditions(unmetered, charging, lowPower bool) // the host's reports (§18.7)
func (self *Sidecar) SetSearchForeground(foreground bool) // the app's lifecycle and a page Worker's tab visibility
                                                          // (§18.7); unreported counts as background
func (self *Sidecar) RunSearchBackgroundSync(ctx context.Context) error // an OS window, ctx's deadline its budget
                                                                        // (§18.5's budgetMillis); resumes next time
func (self *Sidecar) SetSearchPolicy(repoId *Id, mode string) error // nil repoId: every repo; "": the host default
func (self *Sidecar) DropSearchCache(repoId *Id) error              // nil repoId: every repo; 5.9's state stays
// remote search's requester side, on app hosts only (§18.4; CLI and browser requesters are Later):
func (self *Sidecar) GetSearchIndexers() []SearchIndexer                      // those that may answer, own first
func (self *Sidecar) SetSearchRemote(mode string) error                       // on, own or off (5.9's state)
func (self *Sidecar) AcknowledgeSearchIndexer(memberId *Id, allow bool) error // the notice; false sets own

// !sidecar_http files only, with the client generations, streams, sockets, bridge, tls and smtp listeners and
// the engine host interfaces (host_*.go), as §4.4 says; the sidecar_http leg declares SidecarConnectSettings
// empty and NewSidecar without components.
type SidecarConnectSettings struct {
	ClientStrategySettings    *connect.ClientStrategySettings
	ClientSettings            *connect.ClientSettings // Required, no P2P; provides Network, plus Service while on tls/ or smtp/ (§13.6) and FriendsAndFamily while sharing (§8.11); never Public (§6)
	PlatformTransportSettings *connect.PlatformTransportSettings
}

type SidecarComponent interface {
	Name() string                 // "evs", "sockets", "mail", "bridge", "tls"
	Attach(env *SidecarEnv) error // per client generation; returns promptly
	Close()
}

type SidecarEnv struct { // immutable; Ctx ends with the generation
	Ctx         context.Context
	Client      *connect.Client
	Api         *connect.BringYourApi
	SidecarApi  *SidecarApi
	Identity    *SidecarIdentity
	Secrets     SidecarSecrets // keychain namespace
	Store       SidecarStore   // component directory, streaming I/O
	Subprotocol *Subprotocol   // §6: inline, zero-wait handlers; streams
	Authorize   func(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error // the gate: takes
	                                                    // the same action, its Effect included, and sets its Outcome
	Log         Logger
}

func NewSidecar(ctx context.Context, host SidecarHost, components []SidecarComponent, settings *SidecarSettings) (*Sidecar, error)
func (self *Sidecar) Pair(ctx context.Context, childJwt string) error // 5.8: same network, new ClientKey, generation n+1;
	// before anything is sent, childJwt must name this network and carry both the strict_exp and the admin_refused
	// claim (§7.4; D-CORE-7; owner decision 291)
func (self *Sidecar) AddComponent(component SidecarComponent) (func(), error)
```

**Lifecycle.** Per client generation, `run()` builds the client, registers §6's id 21842, handles §6's `core` push, and calls `Attach` outside `stateLock`; in the `sidecar_http` leg a generation is its long-poll (§6.8), which carries `core`, and no component attaches: §18.10's kept files run on `SidecarApi` and the keychain. Complete envelopes go to their component's bounded, zero-wait queue, which drops and counts when full (connect/CODESTYLE.md:119). `StreamData` fills per-stream buffers bounded by §6.7's credit instead, since stream bytes cannot be dropped (:123); an overrun resets the stream with PROTOCOL. Callbacks never block or call `CloseAndWait` (:171).

**Outward-action gate (I-8).** Every outward method calls `Authorize`, which passes under an active approved grant (§8) or a §16.6 decision that passes its spend check (owner decision 75), reserving the use durably before the effect (§16 D-MCP-11); otherwise it writes an `ApprovalRequest`, emits `approval_pending` and returns pending. `Authorize` runs the effect itself: under a decision, §16.6's steps 1 to 6 with the action's `Effect`; under a standing grant, the effect with an empty key and no ledger row. A retry returns the recorded `Outcome` without calling `Run` again unless that outcome is uncertain, and the approval's mutex covers steps 1 to 4 only, never `Run`. A kind with no registered `SidecarEffectLookup` is refused before its Reserve. In a tainted run (I-9) each outward action needs a fresh decision: the daemon spends no further use of a decision whose request was untainted (§16.6's TS1), and harness evidence counts only if the matching `requests` rule names it (owner decision 142). MCP, control mode, the CLI, local SMTP submission and the sdk remote backend all pass it; server-visible actions carry the decision to §8.10's gate.

### 5.5 Identity (X10)

| Level | Id | Durable | Key | Admitted by |
|---|---|---|---|---|
| Network | `network_id` | yes | — | platform |
| Member | `user_id` (§7) | yes | recovery keys (5.9) | login; an admin's config-repo record |
| Sidecar (a device instance in one network) | `sidecar_id` | until revoked | Ed25519 identity key (owner decision 44); X-Wing ReaderKey (§10.5) | `SidecarAdmit` in the config repo (5.6) |
| Client (transport) | `client_id` | until reaped | connect ClientKey | operator-signed history |
| Agent | `agent_id` in the sidecar | per registration | Ed25519 subkey, `not_after` ≤30 d (v1) | an attribution label |
| Forwarding (apps; owner decision 197) | its forwarding Delegation's `delegation_id` | until revoked, superseded or its sidecar's revocation | Ed25519 forwarding key; X-Wing forwarding reader key; its forwarding clients' ClientKeys, all generated in the VPN component and never exported | its sidecar's forwarding Delegation (§7.9, §18.6) |

- **Binding.** `POST /sidecar/bind` appends each `SidecarIdentityBinding` (5.4) to a never-reaped log, which §6's `Hello` checks (D-PROTO-13). A `sidecar_id`'s first binding has generation 1 and creates its `sidecar_identity` row; each new client (5.8) binds generation n+1, the newest plus one, under the same `sidecar_id` and identity key, which that row holds, keeping admissions and grants. A client binds once, whatever the `sidecar_id`: `sidecar_identity_binding.client_id` is unique across every sidecar, so a copied token cannot bind a key of its own, and a binding must carry the key enrollment stored in `network_client_owner.client_public_key` where that column is set (§7.4, §7.7; 5.15's refusals). The binding names the client id as well as its key, so a peer resolves a client to its sidecar from signed bytes (§17.9). The `sidecar_id` names MLS leaves, ReaderKeys, statements, admissions, client names and bridge addresses; the client id stays the transport, contract and policy subject. Git committers (owner decision 81) and §8's `sidecar:<id>` and `client:<id>` resolve through the log, and a sidecar reads a repo iff a subject it hosts does.
- **Agents.** A device or `--instance` is one sidecar per network. Agents are attribution labels on its client (`source = agent_asserted`) holding no credential or group key; the daemon signs, decrypts and enforces per-agent reads for them. Own reach (grants, an overlay address, an ssh key) needs the agent's own sidecar under its own OS user, container or VM (owner decision 4); otherwise grants attach to the sidecar, usable by any local process (owner decision 47). An in-daemon agent has a durable `agent_id`, one per (sidecar, label): a random `Id` minted at the label's first session and kept in the network's keychain.ur beside that agent's subkey record, so it is restored with keychain.ur (5.9's backup) and cannot be guessed from the label; once `AgentRevoke` tombstones it, the label's next session mints a new one, a new registration being a new `agent_id` (owner decision 285). The daemon resolves a session's label to its id, which `McpSession` exposes and every MCP tool passes, into evs pushes' sealed provenance and `NewSidecarAction`'s `agentId` (§16.5; owner decision 470); a session with no agent has none.
- **Signatures.** §6's typed `Signed` (a purpose and §6.11's `SignedType`), Ed25519 in v0: the identity key signs every statement the server stores or verifies, and approvals unless a presence key does (§16.6); agent subkeys only sealed provenance, ended by a local `AgentRevoke` and by `not_after` (below); the ClientKey only the binding and §7.4's DPoP proofs; an app's forwarding key only its sidecar's `WindowDelegation`s (§17.9). A compromised identity key means a `SidecarRevoke` for compromise and a new `sidecar_id`.
- **Agent subkeys (v1).** The identity key signs `AgentCert{sidecar_id, agent_id, public_key, not_after_ms}`, `not_after_ms` at most 30 days after signing, as a typed `Signed` with purpose `agent-cert` and `SIGNED_AGENT_CERT = 0x1A02` (§6.11). That `Signed` rides inside the sealed provenance it vouches for, RECORD.md section 5.3's `AgentSignedBody` and a push's sealed metadata (§11.6), never a log statement or config record. A reader checks the certificate under the identity key of the sidecar that signed the carrying entry, that the entry's time is before `not_after_ms`, and then the subkey's signature: a bad signature alarms, and an absent certificate reads `agent_asserted`. `AgentRevoke` is a local act, not a record (owner decision 285): `Sidecar.AgentRevoke(agentId)` deletes the subkey from `keychain.ur`, and the daemon signs nothing more with it, since a subkey never leaves the daemon; readers bound a subkey by its certificate's `not_after_ms`. A compromised daemon is a `SidecarRevoke{reason: compromise}`, and provenance from its `since_n` on reads unattributed.

### 5.6 Login, enrollment, admission, refresh, revocation

| Path | Credential (used once, then erased) | Client |
|---|---|---|
| `ur login [--invite <link>]` | §7.8's `ur-cli` (PKCE; the device grant in v1) mints a single-use, user-owned auth key (≤5 min) for the daemon, then drops the OAuth token, and offers to register a platform presence key (§16.6) | top-level (§20.8); a child after pairing (5.8, M8) |
| `ur connect --token ur-authkey-…` | A §7 auth key (expiry, uses, tags, ephemeral), whose server part alone enrollment sends (§7.8); from a pre-approved key's client-only `#<bundle>` the daemon signs its own `SidecarAdmit` with the Delegation's key, carrying exactly the Delegation's tags and, unless `--ephemeral`, a `not_after` no earlier than the Delegation's (§7.9's scoped), and keeps only its reader key (§10.5); `urn_` keys are refused | top-level; tagged or user-owned |
| `ur connect --token-file <path>` | The same key read from a mode 0600 file, which `ur` unlinks after enrolling, erasing its copy: a cloud VM's setup writes it and the `--project` cloud profile's SessionStart hook passes it (§16.9); `ur` reads no key from its environment and refuses to enroll if `ur-authkey-` appears there (owner decision 449) | top-level; tagged |
| sdk host | The device's token mints the child (`admin_refused: true`); the host's `TokenSource` refreshes it (§18.7), with the core's DPoP signer installed (`Api.SetDpopSigner`) | child |

- **Enrollment.** The daemon generates the ClientKey seed, identity key, ReaderKey and `sidecar_id`, calls `POST /network/enroll` (§7) or `/network/auth-client`, declaring no provider egress unless `ur proxy` or a public exit is set (§20.8), then `POST /sidecar/bind`, and persists the keychain only if the reply confirms `admin_refused`. The bind re-mints the client's `by_client_jwt` with its `sidecar_id` (§7.4), and the sidecar adopts it (owner decision 286): `SidecarApi.Bind` returns the re-minted token beside the generation, after checking that it names the same network, client and device; enrollment, child enrollment and pairing persist it in place of the pre-bind token, and `restore_required`'s re-registration (below) installs it through the token manager. A refresh keeps the claim as presented and never adds it from the binding row. An sdk host's Api session takes the re-mint the same way, by the core's optional `SidecarTokenSourceRemint`, whose `AdoptByJwt` holds the token and then sets it on the host's `Api`, refusing when the session is closed or holds no token, so an app's sidecar keeps its `sidecar_id` across the host's refreshes (§18.7). An `--ephemeral` keychain stays in memory, but a cloud VM's sidecar, enrolled by `--token-file`, keeps its keychain in a mode 0600 file, since a paused VM loses its processes, so a restored VM rejoins until its client is reaped (§7.7, 30-36 min; §16.9); reaping revokes it (§7.10).
- **Readable credentials (D-TRUST-3; owner decision 283).** `ur` refuses to enroll, and an enrolled daemon alarms at each start and at each `SyncRefetchInterval` (the `credential_store` event, 5.4), while a store on its host holds a readable network `by_jwt`, whatever §7.4's stage. The check is by state, with no signal: no reply field, config key or other spoofable input turns it off, a host the app and extension releases cleaned passes by itself, and a later `ur` release drops the check once the fleet has moved. It reports a store only if this user can read it and it holds a token, and never copies, logs or sends a value. App stores: under `%LOCALAPPDATA%\URnetwork`, `$XDG_STATE_HOME/urnetwork`, `~/Documents` and the Documents of the macOS containers `network.ur` and `com.bringyour.urnetwork`, any `.by/.auth_state` whose JSON `by_jwt` is non-empty (sdk/local_state_auth.go:31-35), or a non-empty legacy `.by/.by_jwt`. Extension stores (extension/src/background/index.ts:134): a Chrome, Chromium, Edge or Brave profile's `Extensions/*/*/manifest.json` naming URnetwork, or a Firefox profile's `extensions.json` naming `urnetwork@bringyour.com`, at a version below D-SDK-11's first non-persisting release, which stays unset, so every version counts, until that release ships. No extension's storage is opened, and no LevelDB or IndexedDB is parsed.
- **Recovery setup.** `ur login`, once its device is admitted or has signed Genesis and base 1 and its member has no current binding, offers recovery setup on `/dev/tty` (5.9's recovery code). `ur login --recover` is a code-only recovered device's command, reading the 12 words only from `/dev/tty`, as the pass is, never argv, env or stdin. `ur login --replace` and `ur connect --token <key> --replace` run on a restored state directory whose machine-id hash differs: they keep the `sidecar_id` and identity key, bind generation n+1 on the new client and remove the old client (5.9's backup).
- **Admission (owner decisions 3, 5, 6, 110, 112-114, 126-128, 144, 149).** Until a config-repo `SidecarAdmit` (§7.9) names it, a sidecar gets no peer, MLS group, wrap or grant. The rules:

```text
genesis  before the owner's first untagged device signs it (§7.9), tagged and ephemeral enrollments
         get no_genesis; a ur login device without an invite's or auth key's anchor shows a safety
         number over the genesis and its identity key for the admitter to compare (§2.8 EX5); a
         code-only recovered device, which has no admitter, passes §7.9's recovery anchor in this
         order before any commit, wrap, sealed write or further statement:
           1 it takes the config group's RK_g from its config RecoveryWrap once admitted (signers)
             or, under a restored binding, which takes no wrap, from the late ReaderWrap that
             §7.9's restored order fetches (KF2), no Add preceding 3
           2 that RK_g matches gen/<g>'s C_g and opens, down the ladder, the config head its newest
             verified base names
           3 the head's records chain to a genesis whose SHA-256 its own binding's genesis_sig there
             signs under the Ed25519 key its code derives
         a failed check raises head_alarm (fork, with that base's AuthPin) and it acts no further
         (§2.8 EX5)
safety   the safety number (owner decision 281): digest = SHA-256("urnetwork-sidecar-v1/safety-number" ||
         0x00 || genesis_sha256 || identity_public_key), both 32 bytes, genesis_sha256 being
         SHA-256(the Signed Genesis); N is the digest read big-endian, and the number is N mod 10^60,
         zero-padded to 60 decimal digits, shown as 12 groups of 5 in three lines of 4 groups; ur and
         §18.5's SidecarApprovals show it identically, and one vector is byte-equal on every leg
signers  one admin: a device of a member outside the AdminSet
         alone, the member's consented device (§8.5): its own untagged devices, admitting them
           unless the network turns self_admit off and revoking them always (§7.10); its recovery
           key admits the same, with one admin's cosign while self_admit is off
         k of n: an AdminSet member's device; its existing device counts as one, and a counted
           member's recovery key may stand for that member under §7.9's recovery window and veto
           (recovery_window), so a personal network (k = 1) recovers alone after it
         restored: a binding a cascade void restored (§7.9), until a signer outside P signs it
           again, admits only through that window: its scoped admission activates 72 h after it
           is filed, with no counted cosign, unless an AdminSet device vetoes (owner decision 149)
         a tag owner's device, or an auth key's Delegation: sidecars with its tags (§7.8)
         never a read_only device (§7.9)
consent  member M's owner-bound repos (vault, mailbox, secret) take a device d only if
         consented(d, M) (§8.5): M's consented device or recovery key signed its admission, d is M's
         first device and enrolled from an invite to M, d signed the Genesis, or M's consented device
         signed OwnerConfirm{d}; never an ephemeral d; others, such as one an admin alone admitted,
         stay parked there
alarm    M's devices raise admission_alarm for every admission under M that none of them signed,
         recovery-key ones included, and approval_pending for an unconsented one (D-CORE-13); for an
         admin-admitted page Worker, its OwnerConfirm or its answer to that alarm also revokes the
         stale Workers M's groups show and offers to revoke the others (§7.10's stale row);
         each raises recovery_rebind for every RecoveryRebind of M, naming for a compromise rebind the
         span its retired binding was current, one it signed itself included; for one it did not sign,
         another device of M's included, "not me" offers to revoke that signer for compromise from a
         since_n at or before the rebind, and "I did this" runs 5.9's compromise procedure (owner
         decision 212); and for every binding of M that §7.9's cascade voids, naming any span its
         keychain.wrap was sealed
         to it (5.9); every member device shows recovery_window while an authority statement with a
         recovery-key signature, or a restored binding's admission (signers), is pending, from
         §7.9's window start p, and raises recovery_unseen if it activates less than 72 h minus 10
         min after the device applied p, or if the device first verifies a valid veto only after
         applying the activation; each device that may revoke the recovered device then offers its
         revocation (§7.9); every admitted sidecar raises head_alarm for each of §6.4's alarms:
         FORK, PROOF OF WITHHOLDING, an UNVERIFIED pin, and no consistent witness (5.4)
reads    every admitted sidecar, ephemeral ones included, reads the config repo and, in a team
           network, the directory (owner decisions 6, 171; §8.6's ceiling excepts both)
         member devices: MLS leaves of each repo they read, at most 1,000 per group (D-KEYS-2); in
           the config group and a team's directory group by §7.9's leaves rule (owner decisions 144,
           182): live member devices rank by (live_since, sidecar_id), the first 1,000 are
           leaf-entitled and the rest read by per-generation wraps as agents do, moving between the
           two by §7.9's move rule; members accept an Add or external join there only of an
           entitled device
         config- and directory-group commits: in each, the signer of an admission or revocation
           commits what it requires (an entitled device's Add, a leaf's Remove and its rotation, or a
           wrapped reader's first wrap or rotation), so a self-admitted device reads with no admin
           online; a wrapped signer commits no Add or Remove, only wraps and rotations, and the next
           leaf commit removes a leaf target (§7.9, §10.9); a recovery-admitted device, once anchored
           (genesis), self-joins the config group by external commit if entitled, else reads by its
           RecoveryWrap, or under a restored binding by the ReaderWrap it anchored on, then by wraps
           (§7.9's commit and wrapped)
         tagged, ephemeral, CI and cloud sidecars: per-generation ReaderWraps (§10.5), with no
           commit or leaf, a Delegation-admitted one at once through its Delegation's reader key;
           on data repos they default to deposit (§8.5)
revoke   any writer leaf commits the Removes a signed revocation requires, never a wrapped device;
         revoking a wrapped sidecar is a new generation not wrapped to it; a SidecarRevoke for
         compromise parks §7.9's cascade closure P from its since_n, a log position, each record
         counted from its carrying entry, never its signer's at, each parked device until a signer
         outside P confirms it; it voids the Delegations a sidecar in P signed, and those sidecars'
         recovery bindings, KeyRegisters and EvsShares until a signer outside P signs them again,
         and ends the Delegation that admitted the revoked sidecar, if one did, parking the sidecars
         it admitted from since_n (§7.9's delegation row, D-TEAM-26)
```

- **Refresh.** `sidecarTokenManager`, a root file in both legs, runs the sdk schedule on `GET /auth/refresh` through `SidecarApi` with a DPoP proof that crypto/ed25519 signs by the ClientKey (§7.4), and on a refused credential (connect's `AuthorizationClosed`, connect/transport.go:528, or a 401), against §7's 7-day, no-grace expiry (D-TEAM-14); it installs tokens in `SidecarApi` and the keychain and, where connect links, by `api.SetByJwt` and `transport.SetAuth` (:1924). A refused refresh returns the sidecar to `Unenrolled` with its identity and admission; only a `SidecarRevoke` that verifies against the config, announced by the `core` push or a refused bind, means `Revoked`; an unverifiable claim leaves it Unenrolled and alarms (`refused`). Events of an older client generation are dropped. After a Postgres restore, a refresh whose identity, binding or registration api lacks answers `restore_required`, and the daemon re-registers its identity and newest binding (`POST /sidecar/bind`, taken once the re-published projection admits the key), then its mail host keys, TLS endpoints and push token (§19.10).
- **Revocation.** `ur logout` signs a `SidecarRevoke` (`removed`) for its own `sidecar_id`, removes its client (`POST /network/remove-client`) and wipes state. A signer allowed above revokes a lost device as `lost`, or as `compromise` with `since_n` (above): the device proposes the first entry timed at or after the loss time the person gives, or the tip where that time is past but later than the log's newest entry (plan, below; owner decision 292), which the person may move earlier, and lists what P parks and voids before the person confirms on `/dev/tty` or in an app's UI; it signs none whose P holds its own sidecar. The server removes the revoked client (§7.10), closing its connections within about 90 s (server/session/AUTH.md:197). Stale revocations (§7.10's `stale` row) ride the act that carries them, under that act's confirmation and, wherever this sidecar registered a live presence key, its one presence check (owner decision 187): a page Worker's admission, the member's `OwnerConfirm` of an admin-admitted page Worker (`ur approve` on `/dev/tty` included, D-CORE-13), or its answer to that admission's alarm. Every other revocation by a member of another of its own devices runs as 5.4's `PreviewDeviceRevoke` and `RevokeDevice` (D-CORE-20), §18.5's alarm answers that revoke a named device included (the admission alarm, `recovery_rebind` and `recovery_unseen`), with the `since_n` the alarm fixes; a `ur` command confirmed on `/dev/tty`, §18.5's `SidecarApprovals` in an app's UI and a remote-mode app's control calls (5.8) reach them, never MCP. `ur devices` lists 5.4's `Devices()`; `ur devices revoke <name|sidecar_id> [--compromise [--since <time|position>]] [--keep-key <key_id>]...`, which with `--compromise` and no `--since` asks on the terminal for an RFC 3339 time or a log position before it calls the daemon and fails without a terminal, prints the plan, signs once the person confirms on `/dev/tty`, under Presence after the daemon's presence prompt, and at k > 1 also signs the target's `Suspend` (sign); `ur approve <proposal_id>` prints a revocation proposal's plan and signs its `AuthorityCosign` under the same approval. The rules:

```text
scope     a sidecar whose admission names this sidecar's member M: M's untagged devices, page
          Workers and quick burners, parked, stale and admin-admitted ones included; never this
          sidecar, which signs out instead, nor a tagged sidecar M sponsors, which its tag owner or
          an admin revokes (§7.10's agents row)
caller    a device approval-capable for M (§16.6: consented, untagged, not ephemeral, not
          read_only, on a host that signs decisions) that is not suspended (§8.8)
approval  the person's approval at this device, recorded with its evidence in the membership entry
          the act writes (§16.8): presence wherever M holds a live presence key whose KeyRegister
          this sidecar signed (§7.9's KeyRegister signer row), the plan's derivation setting its
          Presence from the log, never from the caller (an app's SidecarPresenceSigner, in local
          mode or in remote mode by 5.8's two calls, or the daemon's presence prompt; §16.6's
          profiles), whose one per-use check, with UV, covers the act's root (§7.9's presence row)
          and becomes that key's countersignature on each of the act's statements, which api and
          every member device verify (owner decisions 185, 187), a check that fails, is refused or
          returns no evidence verifying against such a key cancelling the act; else the person's
          confirmation in an app's UI or of a ur command on /dev/tty (D-CORE-13); never a harness
          hook's evidence, MCP or an unconfirmed control call (§16.6's control mode, refused from
          MCP and never rows; owner decision 142)
reasons   lost: SidecarRevoke{reason: lost}, no cascade, what the device signed standing, also
          for an evicted page Worker not yet stale, lost acting as removed would (§7.10);
          compromise: SidecarRevoke{reason: compromise, since_n}, §7.9's cascade from since_n
          parking P and voiding what P signed as 7.9 lists, and a compromise retirement, so each
          repo the device read rotates as cause REMOVE with a path epoch due within 24 h, as every
          due is (§10.8, §11.6; owner decision 585)
plan      PreviewDeviceRevoke derives at the tip: since_n as above, the first entry timed at or after
          the loss time or, where that time is past but later than the log's newest entry, the tip, the
          largest since_n §7.9's verifier accepts for a revocation landing at the next position
          (0 < since_n < n), the plan then showing what that voids, the tip entry itself where the
          target signed it; a compromise with neither a loss time nor a position answers REVOKE_SINCE,
          since nothing says where P starts and no default is guessed, least of all the target's
          admission entry (owner decision 292); never later than proposed, and
          after a compromise rebind at r clamped to r + 1 for the rebind's signer and for any device
          whose closure would reach it, so the rebind stands, unless the person moves it earlier, when
          the plan shows the rebind voiding and who must sign it again (5.9; owner decision 212);
          §7.9's cascade list (what P parks and voids, what stands, and each device that sealed
          keychain.wrap to a binding it voids, under 5.9's backup rule); each presence or SSH key
          the target registered (§7.9's KeyRow signer) that the cascade does not void; the counted
          signatures it needs: 1, or k for an AdminSet member's device, this one counting once
          (§7.9's authority and counted rows); and its Presence (approval); a target already
          revoked answers that entry and, under Presence, its key items still registered, which
          RevokeDevice then revokes alone; compromise after a lost or removed revocation, or from
          an earlier since_n than a standing compromise one, signs anew
sign      RevokeDevice re-derives the plan at the tip it signs at, answering REVOKE_STALE only if
          its PlanId changed and REVOKE_PARKS_SELF if P now holds this sidecar, while park and
          void items that records entered after the preview add, each resting on a signature in
          P, join unasked, the result listing them; runs the approval; signs the SidecarRevoke or,
          at k > 1, its AuthorityProposal with, in the same act, Suspend{target} signed as its
          owner (§8.8's signer row), so the target loses scope within 5 s, and its leaves, while
          cosigns are due; other AdminSet devices cosign by ur approve <proposal_id> confirmed on
          /dev/tty or through §18.5's Decide, the proposal pending until the k-th cosign or its
          not_after; with presence evidence, also a KeyRevoke of each listed key the person left
          selected (§7.9's KeyRegister signer row), else none; and posts each as §7.9's statement,
          keeping its signed bytes in keychain.ur (5.9) until it lands, so a kill or an uncertain
          post retries the same bytes until its not_after
effects   from the revocation's position n', at k > 1 its completing cosign's (§7.10; §10.7's KF4):
          the target leaves every repo's key holders, so a write needs a generation covering n'
          (412; receivers 451); api removes its client, and evs and gkm refuse its tokens through
          rev/ (§7.8); this device first, then any writer leaf, commits its Removes, in the config
          and directory groups by rotation alone where this device is wrapped (§7.10's commit);
          each repo's next generation is cause REMOVE, each file's next write a full checkpoint,
          and paths re-key at once (§10.8); the target keeps only what it could decrypt through its
          last generation (owner decision 64), and verifiers refuse what its identity key signs
          later
codes     REVOKE_SELF         the target is this sidecar: sign out instead
          REVOKE_NOT_OWN      no admitted sidecar of M has that id: another member's, a tagged
                              one, or an unknown id
          REVOKE_NOT_CAPABLE  this device is not approval-capable for M, or is suspended
          REVOKE_CANCELLED    the person cancelled, or the presence check failed, was refused or,
                              under Presence, sent no evidence verifying against such a key
          REVOKE_SINCE        a since_n later than proposed or past the tip, a future loss time, or
                              a compromise with neither a loss time nor a position
          REVOKE_PARKS_SELF   P would hold this sidecar; it names the entry that puts it there
          REVOKE_STALE        the plan's PlanId changed at the tip: preview again
          REVOKE_REFUSED      api or a verifier refused a statement at the tip, or none landed by
                              its not_after
          and, as elsewhere, FAILED_PRECONDITION while Locked or Unenrolled, and UNAVAILABLE while
          api is unreachable before anything is signed
```

- **Presence countersignature (owner decisions 185, 187).** Wherever this sidecar registered a live presence key, an act that signs a statement §7.9's presence row covers runs one presence check over the act's root and puts that key's countersignature on each statement it signs, and api and every member device refuse a covered statement without it (D-TEAM-32). Such acts are 5.4's `RevokeDevice`, with its `Suspend` at k > 1 and §18.5's alarm answers that run through it; `ur approve <proposal_id>` and `Decide`'s cosign of a covered proposal; an admin's revocation of another member's device, §7.10's `cleanup` revocations included; an admin's or tag owner's revocation of a tagged sidecar (§7.10's `agents` row) and a `DelegationRevoke` that parks its agents (`since_n` > 0, §7.9's `delegation` row; owner decision 192); a page Worker's admission, `OwnerConfirm` or alarm answer that carries §7.10's stale revocations; a `Suspend` of another sidecar and a `RecoveryVeto`, from a `ur` command or `Decide`; `ur keys add-presence` and `ur keys rm` for a presence key, a device's first key needing none, since it has no live one; and, under owner decision 189, the admission or confirmation of a member device (the signers and alarm rows above, `ur approve` and `Decide` included), an admin's AdminSet change or member removal, and a `RecoveryBind` or `RecoveryRebind`, `ur keychain recovery-rotate`'s included. The device builds the act's statements first, so the check covers their exact bytes, and keeps them with their countersignatures in `keychain.ur` until each lands (5.9), a kill retrying the same bytes. The check runs where the key is, by the daemon's presence prompt or an app's `SidecarPresenceSigner`, a remote-mode app's by 5.8's two calls, with UV (§16.6's countersign row). A remote-mode app's two-call act decides at its hold where that is: when every live presence key of this sidecar's is one the daemon host's own authenticator holds, the first call answers no bytes and the second runs the daemon's presence prompt over the act's bytes before signing, the person's wait outside the request bound; otherwise the app's `SidecarPresenceSigner` countersigns as above; and for the app's own `KeyRegister` beside a host-held live key, the app proves its new key and the daemon's prompt countersigns (owner decision 290). A check that fails, is refused or returns no evidence verifying against such a key signs nothing, which 5.4's calls answer `REVOKE_CANCELLED`. A sidecar with no live presence key signs these on the person's confirmation (D-CORE-13), and a recovery key's statements carry none.

### 5.7 AUTHZ1: a sidecar token must not administer the network

**Threat.** A same-user agent, inside the trust boundary (owner decision 47), reads the client token and posts `/auth/code-create` for a network login. §7.4's P0 (D-TEAM-1) refuses child and admin-refused tokens on all 37 gated routes and confines `strict_exp` bearers to its sidecar-route allowlist, and D-TEAM-14 expires sidecar-held ones after 7 days, renewable only with the ClientKey's DPoP proof, all before any sidecar ships (owner decisions 45, 103, 131).

| Mitigation | Residual |
|---|---|
| Only the daemon holds the token: never in env, argv, logs, MCP, replies, or any file but the keychain (I-7) | a same-user process reading the keychain; a token copied alone renews, exchanges and mints nothing, but authenticates a transport until `exp` (Q-CORE-4 (c)) |
| Service tokens (§7.8): one audience, ClientKey-proved, never leaving the daemon; harness git uses the local git server and `git-remote-ur` (§11) | scoped, 15 min |
| No admin path in the daemon or MCP: `ur admin` and `ur login` run §7.8's `ur-cli` in the CLI process, with one-command, DPoP-bound admin tokens whose `cmd` digest binds method, path and body, used once (D-TEAM-7) | the person must check the consent code |

### 5.8 The daemon and local IPC

```text
harness --stdio-- ur (relay) ---+                                  ur daemon --instance X
git --- git-remote-ur ----------+-- unix socket / named pipe -->   local API | MCP sessions | git
ur status, ur login, app -------+   peer-credential check          a Sidecar per network --> platform

hello   {"ur_local":1,"mode":"mcp"|"control"|"hook","version","harness","agent","cwd","pid"}
        {"ur_local":1,"mode":"git","version","repo":"<net>/<repo>","service":"git-upload-pack"|"git-receive-pack"}
        {"ur_local":1,"mode":"git-hook","version","service":"pre-receive"|"proc-receive"}    names no repo
.ur     network = "k7q2m9"        # TOML at a project root: a label or alias
        agent = "api-refactor"    # optional default for --agent
        claims = "off"            # optional: off < prompt < auto, §16.11's announcement setting; narrower than
                                  # the member's applies at once, wider only once the member confirms it
        project = "billing-api"   # optional: the label this project's runs announce (§16.11)

pair    app (device client D, same network) --control socket--> daemon
        app: POST /network/auth-client {source_client_id: D, admin_refused: true} -> child C's jwt
        app --Pair(C's jwt)--> daemon: C's jwt must name this network and carry the strict_exp and
                                       admin_refused claims, else nothing is sent (owner decision 291);
                                       new ClientKey; POST /sidecar/bind generation n+1; remove any
                                       top-level client; the SidecarAdmit stands (it names sidecar_id)
lost    D removed or reaped -> C ends (5.3) -> daemon Unenrolled (parent_lost), identity kept -> ur login
        or re-pair
unpair  ur login -> top-level client as the next generation -> remove C
```

- **One daemon per instance.** `ur mcp`, and bare `ur` when stdin is not a terminal (owner decision 57), relay to the daemon, where MCP runs (§16), never logging to stdout. If none answers, `ur` spawns `ur daemon` detached, which is R-SDK-9's local device that listens: §18.5's `NewSidecarRemote` with no daemon reports `offline` and embeds none. A flock on `<state>/lock` keeps one, and an auto-spawned daemon exits when idle for `LocalSettings.IdleExitTimeout` (10 minutes) unless mail, sockets or bridge is on or its device is an indexer (§3.6; owner decision 150), which runs from its unit (below) and never idles out; a unit-run daemon never counts it. It hosts a `Sidecar` per network, sharing the unlock key U (5.9) and MCP endpoint but no client, root key or identity key (Q-CORE-6). Where a network designates it for search (§7.9), it registers §6.11's SEARCH handler on that network's `Sidecar` and sets Hello feature bit 0 (§6.4) while `Search.RemoteServe` is on, and serves §11.14's remote searches in its search engine within D-CORE-17's budget, outside every MCP session and run, so serving taints none (I-9).
- **Protocol.** After the hello, the socket carries newline-delimited JSON-RPC 2.0 or, after a `git` hello, raw pkt-line bytes for one repo of that `<net>`'s `Sidecar` (§11.11). A `git-hook` hello (owner decision 293) carries `ur git-hook <name>`'s relay of a mount's pre-receive and proc-receive hooks: its `service` is the hook's name, and after the hello the relay sends one JSON header line `{session, object_directory, alternate_object_directories}`, the session being the one the daemon set in `UR_GIT_SESSION` when it started git-receive-pack; then both sides send frames of one channel byte, a 4-byte big-endian length and the bytes: stdin and stdin's end from the relay; stdout, stderr and the one-byte exit code from the daemon. That stream may stay open up to `ReceivePublishTimeout` (30 min), not `RequestTimeout`; the session id grants nothing, and a relay that cannot reach the daemon exits 1, so the push is refused, never taken unhooked. The daemon registers each mode on the control socket under the peer-uid check below. The mode selects a protocol, never a privilege (D-CORE-9): authority statements, admissions, a revocation of another of the member's devices (5.6, with its presence check), `OwnerConfirm`, `KeyRegister`, `IndexerSet` and `ServiceSettings.directory` (§7.9), acl and bridge statements other than §16.6's own-resource filings, and the acts of control mode's `ur directory` methods (§16.11: announcing a repo or revoking its announcement, approving or denying a request, erasing, a `claims` value wider than `.ur`'s) are signed only for a `ur` command confirmed on /dev/tty or in an app's UI (D-CORE-13); a directory request passes 5.4's gate as an `access_request`. Where an act signs a statement §7.9's presence row covers and the live presence key the daemon registered is a remote-mode app's, the app's call takes two: the first returns the act's countersigned bytes over the statements the daemon built, which the app signs by `SignWithPresence` and sends back in the second, and only then does the daemon sign them, each carrying the countersignature (5.6's approval and presence countersignature); `RevokeDevice`, `Decide`'s admissions, confirmations, cosigns and vetoes, and the app's `KeyRegister` take that path alike. Where every live presence key of this sidecar's is instead one the daemon host's own authenticator holds, the first call answers no bytes, which the app shows as the host's prompt, and the second runs the daemon's presence prompt over the act's bytes before signing, the person's wait outside the request bound; for the app's own `KeyRegister` beside a host-held live key, the app proves its new key and the daemon's prompt countersigns (5.6; owner decision 290). The own-resource filings (a `GrantActivate` of this sidecar's own approved request, §8.8; a `GrantRevoke` of a grant whose subject it is; its own `BridgeAddress` for its first map as a host, §17.4; the `BridgeRoute`, `BridgeMap` and `BridgeWithdraw` of its own rules, §17.8) are signed from any mode, one for an outward action only through 5.4's gate. Version skew is refused; replies never carry tokens, keys, the pass or the recovery code, which a walk of each reply holds them to. A remote-mode `Sidecar` hears the daemon's events through the control method `events` (owner decision 287), a method, not a mode: `{after: <cursor>, wait_ms}` answers the events past the cursor from a bounded per-daemon ring, each with its generation and kind and the ids §18.5 lists, never a secret, or `gap: true` when the ring has passed the cursor, after which the app reads `GetState` for where things stand; the ring's size and the longest wait are settings (`LocalSettings.EventRingEventCount`, `EventWaitTimeout`). The sdk's remote backend keeps one long-poll open on a second control session and feeds `AddEventListener` from it, so every event kind reaches a remote-mode app, and the native host's allow-list carries `events`, so the extension hears the alarms. Mail adds three methods to the core's table (owner decision 288): `mail.check_send`, taking a draft's fields and answering §14.5's `SmtpSendCheck` as JSON (each recipient domain's mode, the encoded bytes, the DATA cap, the expected delay and the prediction), and `mail.send_result`, taking a `send_id` and answering `SmtpSendResult` (each domain's outcome), both plain reads that sign and send nothing and so need no confirmation (D-CORE-13); and `mail.send`, which goes through the daemon's gate like a submission, held for an I-8 approval (§15.10's step 1). The sdk's remote backend calls each, so desktop apps on `ur daemon` get §18.5's `CheckSend`, `GetSendResult` and `Send`. TLS adds one Confirm method, `tls.edge_login.sign` (owner decision 489), beside its `Sidecar.SignTlsEdgeLogin`: it signs the device's `TlsEdgeLogin` over an origin and a nonce for §13.7's members-device login only for a call confirmed on /dev/tty or in an app's UI (D-CORE-13), and an unconfirmed call is refused and signs nothing, so no same-user process, an agent's included, vouches as the device for a login the person never saw; the sdk's remote backend sends §18.5's `SignEdgeLogin` through it with `confirmed` set, the bound call being the person's act in the app's UI, as `AnnounceRepo` and `RevokeRepo` go. A control-mode `search` (§16.10) or `ur directory` listing (§16.11) returns untrusted text only when the call asks for it, as `ur search` and `ur directory` do by default only when stdout is a terminal, and first taints each run whose harness process is the caller's ancestor (§16.6; §16.7's pid ancestry).
- **Authentication.** The peer uid must equal the daemon's (SO_PEERCRED; LOCAL_PEERCRED in a 0700 directory; a go-winio pipe with a user-SID DACL); same-user agents may call it (owner decision 47), and outward actions still pass the gate. Control uses nothing else (owner decision 84): `--port` (cli/UI.md:17-18) sets the first port of the local services (§11, §15), `LocalSettings.FirstPort`, 17000 by default, in this order: git http or https 17000, git ssh 17001, submission 17002, IMAP 17003; a second instance on one host passes its own `--port`, and a taken port fails naming the flag. They bind `0.0.0.0/::` unless `--listen` narrows them (cli/UI.md:11), authenticate every caller and, off loopback, serve only TLS, or ssh for git (owner decision 130).
- **Project file (owner decisions 23, 170).** `.ur` names a label or alias, never a legacy network_name (D-DNS-2), holds no secret and may be committed. The daemon finds it from the hello's `cwd` up to the git top level or `$HOME`. A network-scoped call uses its `network` argument, else `.ur`, else the only network; otherwise it fails with FAILED_PRECONDITION naming the networks. A committed `.ur`'s `claims` narrows a member's setting at once and widens it only after the member confirms once, on /dev/tty or in an app, never through MCP; the value is fixed for each session (D-CORE-18; owner decision 170).
- **Pairing (owner decisions 4, 87).** A desktop app in remote mode (§18.4) pairs over the control socket, a sandboxed app (apple/app/app.xcodeproj/project.pbxproj:1129, :1762) through its app-group socket (5.9); the daemon never holds the device's token.
- **Units.** The daemon runs as the user (Q-CORE-3). `install-daemon` writes a LaunchAgent `network.ur.ur.<instance>` (macOS), `systemctl --user enable --now ur@<instance>` plus linger when headless (Linux), or a Task Scheduler logon task (Windows); `uninstall-daemon` removes it, first retiring the device's indexer designations (§7.9), and `--purge` also revokes the client and `sidecar_id` and deletes the state; `ur indexer add` installs the unit if absent, so an indexer restarts at the user's login, or at boot under linger (owner decision 150).

### 5.9 Local state, keychain, OS key stores, recovery

```text
<state>  macOS ~/Library/Application Support/ur/<i>; Linux $XDG_STATE_HOME/ur/<i>;
         Windows %LOCALAPPDATA%\URnetwork\ur\<i>
  sidecar.json      non-secret: urls, network/client/sidecar ids, instance id, machine-id hash
  unlock.wrap       the instance unlock key U (32 B), wrapped by the OS keystore and the pass (Argon2id
                    params, salt)
  net/<network_id>/
    keychain.wrap   R_n wrapped by U and, by HPKE, to its member's current recovery X-Wing key in n only,
                    re-sealed as the device applies each change to that member's current binding (a
                    RecoveryBind or RecoveryRebind, §7.9's cascade voiding one, or a signer outside P
                    signing a restored one again), with no HPKE copy while none is current
    keychain.ur     AEAD(R_n): n's client jwt, ClientKey seed, identity and agent keys, ReaderKeys
                    (a fresh X-Wing pair once the current is 6 days old, each with a not_after at most
                    7 days after signing, never re-signed; a replaced or lapsed private key kept until
                    30 days past its not_after, for the deliveries made to it, §10.5), a Delegation's
                    reader key (§7.8), a pending recovery proposal's or admission's id (§7.9),
                    statements signed and not yet landed, such as a revocation
                    and its KeyRevokes (5.6) or an admission and §7.10's stale revocations, each stale
                    one re-checked before a retry (§7.10), §10's key cache, which from v0's first
                    generation keeps each verified GenRotate's Signed bytes beside its RK_g (§10.5)
    authlog/        §7.9's retained log, as its retain row says: on a member device, every entry from
                    api's retention point on, for a site loss (§19.10)
    approvals/ runs/ restore/ <component>/   §16's approval ledger, run taint and restore points, and
                    each component's state, under keys derived from R_n, evs's with §11.9's pins and a
                    head reader's read records: one per path read (ref_id, path, entry version, pin at
                    last read), at most HeadReadRecordCount = 16,384 a network, least recently used out
                    (owner decision 209)
    search/<repo_id>/<ref_id>/  file class search: the index files this device keeps, as the sealed evs
                    records it fetched, and their derived data (below); never a query, hit or cursor
    search.state    file class search: the search state that is not derived (below)
    directory/      file class search: the team directory's fetched cards and entries and their folded state
                    (§16.11; on phones in memory, while its view is open), deleted with a lost read; never a
                    query (owner decision 171)
  lock, log/ (size-bounded glog)
socket   $XDG_RUNTIME_DIR/ur/<i>.sock; macOS DARWIN_USER_TEMP_DIR (104-byte sun_path), plus, for a
         sandboxed desktop app, a short-named socket in its app-group container, a group the ur
         bundle also claims (§4.10): ~/Library/Group Containers/6BGU69Q742.group.network.ur/
         (apple/app/network/network-macOS.entitlements:35-38; the direct build's group differs);
         Windows \\.\pipe\urnetwork-ur-<sid>-<i>
```

- **Instances.** Names match `[a-z0-9][a-z0-9-]{0,31}` (default `default`, or `UR_INSTANCE`). Each instance has its own state, daemon, sockets and U, and per network its own client, `sidecar_id`, R_n and persisted connect `InstanceId`, so restarts keep the resident.
- **At rest.** Each network's 32-byte random root key R_n derives an HKDF-SHA256 key per file class (`urnetwork-sidecar-v1/local/<class>`). Files are sealed in streamed chunks with XChaCha20-Poly1305 (wasm's AES is table-based), path in the AAD, via temp file, fsync, rename. A locked or failing store never resets identity (§18.5).
- **Index cache (D-CORE-16) and search state.** §16.10's search, remote serving and every host's §11.14 read path read only this cache; apps keep it in their StateDir and browsers in the key origin's own IndexedDB store (§18.8):

```text
holds     per indexed ref this device follows: the ref version it verified (§11.9) and each index file it
          keeps, as the sealed evs records it fetched under the repo's object keys, checked against its entry
          version's content_sha256 before it is kept (a mirror of the ref shares its copies), and beside each
          kept record its file id and its wrapped object key exactly as its segment header carried it, sealed
          under the repo generation's key, about 100 B a file, so no plaintext key rests on the device and the
          cache still holds no key: a reader that holds the repo key at that generation, from §10's client as
          any evs read does, unwraps it per file and opens the record one 64 KiB frame at a time, so searches
          read kept shards, postings and slots without reading evs; for a slot-keyed repo (record-class repos
          and group inboxes, §11.14's keys row) the slot's 72 B wrapped object key block exactly as the slot
          object carried it, that slot key's generation and the segment's generation whose manifest_g seals
          the record header, about 80 B more a file, a reader asking gkm for both generations when they differ
          (owner decision 289); derived data sealed under HKDF(R_n, "urnetwork-sidecar-v1/local/search") with
          XChaCha20-Poly1305, random nonces, AAD = repo || ref || path || version || part: the search manifest
          (what §11.14's pin row records, and the last Search.PinRingCount pins replayed) with the sync
          round's plan beside it (§11.14's Reads, DESIGN-DETAILS.md section 7), each shard's dictionary block
          index and n_d array, the version table (below), and on desktops the local layer (commits past
          indexed_through this device indexed from its own plaintext, dropped once the index covers them),
          mismatched entries and the local vocabulary; a bucket a roll-up dropped, kept where a stale all is
          cached until that all shows it rolled up (a/m's rolled_through_day), and never past two bucket
          lengths after the roll-up, so search stays complete between a roll-up and its download
versions  the version table, per index root: for each doc key and ref id the partitions this device keeps hold
          (shards' doc and tombstone tables, sealed slots, heads, large entries), its highest version there,
          whether that is a tombstone, and the file holding it, in key order in 4 KiB sealed pages under a page
          index; immutable runs, per bucket one for its shards, rewritten from the shards that changed when its
          manifest changes, and one for its other files, rewritten when one of them changes, and one for all
          where kept, at each roll-up or rewrite it applies; each by a streaming merge of key-ordered inputs (a
          slot's entries sorted in memory), at most 16 at once and 1 MiB; a running search keeps its snapshot's
          runs as it keeps its files; keys an ERASE names, and the documents a ref's erasure set lists (§11.14's
          epoch row), join it as erased, the former until the rewritten files are cached; §11.14's newest row
          probes it
state     not derived, so ur search sync --evict, DropCache and the bounds row's eviction keep it: per-device
          policy overrides (§18.4); remote search's mode, its notice answers, which repos each indexer served,
          for 24 h, and an indexer's distrust deadline (§18.4, §11.14's merge row); on an owner's indexer, the
          served record, one row per (requester sidecar_id, repo_id, UTC day): {requester, repo, day, count,
          first time, last time}, written at page 0 once a search and naming no query; the first remote search
          an EvsShare reader makes in an owner-bound repo on a day adds the row, and each later one that day
          raises its count and moves its last time; rows are kept Search.ServedRecordTimeout (30 days) by
          their day, so the owner's view holds exact counts for the whole 30 days in at most readers x repos x
          30 rows whatever a requester's rate, only the times inside a day going unkept, with
          Search.ServedRecordCount (8,192) a last bound, the oldest days dropped first (D-CORE-17; owner
          decision 294); deleted with the network's local state
never     a query, query history, hit, snippet, cursor (memory only, 10 min), result count or per-query verdict,
          local or remote, on the asking phone and on the answering indexer (owner decision 175); a file no
          verified entry version named
policy    latest of every repo in scope, from hints; all by Search.AllPolicy, §18.4's modes: background on
          desktops and indexers, wifi_charging plus "search more" on phones (for repos no designated indexer
          answers, owner decision 178) and in browser tabs, on_demand ("search more" only) on ephemeral and
          cloud sidecars, owner decision 154's per-device override, since their cache lives in memory and would
          re-download all at every start (owner decisions 150, 154; §18.4 for browsers); a device may reproduce
          a merge, roll-up or erasure rewrite from files it holds and check content_sha256 instead of
          downloading it (§11.14)
delete    at once, on an ERASE or CLOSURE hint (§11.12, §16.8): every cached version the CLOSURE replaced with
          its derived data, every kept record whose slot key the ERASE destroys, so the time a device could
          still unwrap an erased document's key ends at that deletion (I-EVS-13, read as evs's storage plus a
          device cache that drops at the ERASE hint; owner decision 289), the erased keys from the key cache,
          the repo's retained buckets, the erased
          documents' local-layer entries and those this device journaled for its next companion push
          (§11.14), and their words in the vocabulary (decremented from the text read before it is deleted),
          their keys masked until the replacements are cached; on a CUT's hint or a synced erasure set, the
          documents it lists: their journaled and local-layer entries, masked in search at once (§11.14);
          files a newer ref version no longer names,
          except a dropped bucket held as above; every file of a repo this sidecar no longer reads (a removal,
          a generation not wrapped to it, a revoked EvsShare or grant) or that is deleted, shredded or has its
          index turned off; ur search sync --evict; Locked drops the decoded state and open cursors
dropped   applying an executed drop (its window passed with no cancel, evs not reporting it refused; §11.7)
          deletes what only listed versions name wherever this device holds it: segments, inline records and
          slot copies in its sealed mirror, any copy in this cache, and every decrypted copy of a listed
          version, §16.7's restore points (file class restore) included, keeping statements, served entry
          versions and every id named by a version no executed drop lists (the kept head's re-cited chunk set,
          renames, copies on other refs, reverts), as §11.11's Drops paragraph and §11.13's job do; a device
          offline at the drop deletes when it syncs (owner decisions 173, 183; D-CORE-19)
bounds    Search.CacheByteCount (4 GiB; 16 GiB on a daemon designated for search, which evicts no all of a repo
          it serves while under it, §11.14; 0 on ephemeral sidecars, whose cache stays in memory inside
          MemoryBudgetByteCount), the version table's pages included: all partitions go first, least recently
          searched; phones and browsers keep §18.4's caps and drop all shards unused for 30 days; past a cap,
          "search more" searches each all shard as it lands and keeps the youngest that fit (§18.4); decoded
          dictionaries and doc tables in an LRU within Search.MemoryByteCount (64 MiB on the daemon, inside
          MemoryBudgetByteCount), with Search.VersionCacheByteCount (256 KiB a process) of version-table pages,
          one 64 KiB frame decrypted at a time; each search's own state, its frames, the query's lists and its
          pending candidates, within §18.4's working set (8 MiB a search on daemons, §16.10)
rebuild   all of it but state is derived: an AEAD failure drops the file and refetches it, and deleting the
          directory costs only the downloads; a browser evicts the key origin's storage whole (storage pressure
          on a best-effort origin; Safari's 7-day cap on script-written storage), keychain, MLS state and token
          with the cache, so its next Worker enrolls as a new sidecar_id (§18.8)
```

- **Pass (cli/UI.md:82-85).** Argon2id at 64 MiB, t=3, p=4 (RFC 9106 §4), or 19 MiB, t=2, p=1 on mobile and wasm (OWASP). The pass or the OS keystore yields U, which opens every R_n (owner decision 23's shared unlock); a pass change, `ur keychain pass`, rewraps U under a new pass, and `ur keychain rotate` rotates U and every R_n. The CLI reads the pass only from `/dev/tty` with echo off, and the pass approves nothing (owner decisions 47, 75).
- **Auto-lock (owner decision 284).** `KeychainSettings.AutoLockTimeout` defaults to 10 minutes. Idle means no request on any local socket (control, mcp, hook, git) for that long, and the lock never applies while 5.8's busy rule holds: mail, sockets or bridge on, or an indexer. Locking drops U and every R_n from memory and enters Locked; where a key store holds U, the next local request runs `Unlock(nil)` by itself. Zero never locks, for a host to set on purpose. `ur lock` drops U and every R_n at once, as auto-lock does, and needs no confirmation, since it only narrows.
- **Recovery code (owner decisions 62, 127, 149).** 128 bits as 12 BIP-39 words, shown once per membership, so no recovery key links a person's networks (owner decision 23) and no device keeps a master secret. The words are BIP-39 of 16 random bytes E with its standard 4-bit checksum (the first 4 bits of SHA-256 of the 16 bytes), on the English list, which the root embeds, so it gains no module; a bad checksum is refused at entry. The keys derive from E, not from the words and with no BIP-39 PBKDF2 step: `ed25519_seed = HKDF-SHA256(ikm = E, salt empty, info "urnetwork-sidecar-v1/recovery-ed25519", 32 bytes)`, and `xwing_seed` the same with info `"urnetwork-sidecar-v1/recovery-xwing"`, used as crypto/hpke's `MLKEM768X25519().NewPrivateKey(xwing_seed)`; E is zeroed once both are derived, and testdata/recovery/ pins a code to both public keys and a `genesis_sig`, byte-equal on every leg. The first code is made at `ur login`'s recovery setup (5.6); `ur keychain recovery-rotate` runs the same path, signing `RecoveryBind` when the member has no binding and `RecoveryRebind` otherwise. The `ur` process draws the 16 bytes, derives both keys, computes `genesis_sig` from the network id and Genesis hash the daemon returns, prints the 12 words once on `/dev/tty`, and sends the daemon only the two public keys and `genesis_sig` to sign, under §7.9's presence row; declining leaves no binding, so `keychain.wrap` has no HPKE copy and `ur status` says so. For apps, §18.5's `CreateRecoveryCode` on `SidecarApprovals` runs in process and hands the words to the host's UI, never over control mode. The code derives X-Wing and Ed25519 recovery keys, which a `RecoveryBind` config record binds to the member (§7.9); devices wrap that network's R_n and the member's repo key generations to the X-Wing key (§10.8). With the code alone, a new device restores, reading before admission only the authorization log and its member's recovery wraps (§7.9), admits itself under 5.6's signers, passes §7.9's recovery anchor in 5.6's order (genesis), then joins its groups (above 16 leaves, once one leaf is online to write the current GroupInfo) and revokes the lost devices, rotating their groups (§10.8). `ur keychain recovery-rotate` signs a `RecoveryRebind` (§7.9), countersigned where §7.9's presence row asks (owner decision 189): the old code then admits nothing and gets no new wrap, and if §7.9's cascade voids the rebind, admits only through the recovery window and gets none until a signer outside P signs its restored binding again (5.6); what it still reads, whatever the window or a veto, §10.8 says. A device a restored binding admits anchors on a config ReaderWrap (5.6's genesis) and joins its groups in §7.9's `restored` order (§10.8), then offers `recovery-rotate`, whose rebind gives its member a current binding again (§7.9's after).
- **Backup.** OS-keystore wraps are device-bound, so a backup restores only with the pass (U) or a network's code (its R_n); new hardware keeps the `sidecar_id` only via `--replace` (`ur login --replace`, or `ur connect --token <key> --replace`; 5.6), which binds generation n+1 on the new client and removes the old client. No re-seal reaches a backup sealed before it, whose `keychain.wrap` the code it was sealed to still opens, and with it all of `keychain.ur` (the client jwt, ClientKey seed, identity and agent keys, ReaderKeys, a Delegation's reader key, unlanded statements and §10's key cache) and, by keys derived from R_n, `approvals/`, `runs/`, `restore/` and component state. So each device whose backups may hold a sealing to a code retired for compromise, or to a binding §7.9's cascade voids (the span its `recovery_rebind` names, 5.6), is revoked for compromise and enrolled anew, never moved by `--replace`, which keeps its identity key (§7.9, §10.8); for a void, each device that may revoke it offers that revocation from a since_n at the voided binding's entry, since no keychain was sealed to that binding earlier. For a compromise rebind landing at position r, `recovery-rotate --compromise` lists each device of the member live while the retired binding was current, raises `recovery_rebind` naming that span on its own device too, and offers each a compromise revocation, since_n defaulting to §7.9's loss-time proposal, clamped to r + 1 for the rebind's signer and for any device whose closure would reach that signer, so the rebind stands; a person who believes a clone acted may move it earlier, and the plan then shows the rebind voiding and who must sign it again. The rebind's signer goes last: it enrolls a replacement, which revokes it from a since_n after that admission, so where no signer outside exists, what a clone signed before that position stands (owner decision 212).
- **Store states (D-CORE-15).** The OS key stores and the sdk's `SidecarKeyStore` (§18.5) answer reads with one of four statuses and writes with Ok, Locked or Failed:

```text
Present  a value that fails decoding or AEAD counts as Failed, never Absent
Locked   the sidecar enters Locked; once the store unlocks, the host calls Unlock(nil)
Failed   as Locked, and alarms; neither Locked nor Failed creates, overwrites or deletes anything
Absent   no sidecar_id recorded in sidecar.json: create U; R_n is created only at network n's first
         enrollment, with no sidecar_id recorded for n
         one recorded: the item is lost; open U by the pass, or R_n by n's recovery code, else
         Unenrolled (keystore_lost), creating nothing until the person confirms re-enrollment as a
         new device; a lost net/<network_id>/keychain.wrap is the same loss for network n
```

| Platform | Wrap of U |
|---|---|
| macOS CLI | The data protection keychain (`AfterFirstUnlockThisDeviceOnly`, group `<team>.network.ur.cli`) via purego, from a Developer ID `ur` bundle (§4.10; D-CORE-12) |
| Apps, extension | The host's `SidecarKeyStore` (§18.5, §18.7) |
| Windows | DPAPI |
| Linux desktop | Secret Service |
| Linux headless | The pass, else a 0600 key file with a warning |

**Forwarding's keys (owner decision 197).** An app's VPN component keeps its forwarding key, forwarding reader key, forwarding clients' ClientKey seeds and tokens, and a forwarding root key that seals its posture, compiled state and config cache by this section's file sealing, apart from the sidecar role's, so neither reads the other's (§18.6); its key sets sit in two slots, current and next, a set promoted only when the component's own state shows its Delegation live, beside the floor, the highest pin it committed, below which a restored store is pending (§18.6's setup and posture; DESIGN-DETAILS.md section 4); it generates them only at a setup, and after one a store state other than Present leaves forwarding pending, never resets it, and only its sidecar's own sign-out wipes it:

| VPN component | Forwarding's keys |
|---|---|
| iOS and macOS network extension | The extension's own keychain access group, never the app's `network.ur.sidecar` group or the app-group container, `AfterFirstUnlockThisDeviceOnly` |
| Android VPN service | Seeds sealed under an AndroidKeyStore key of its own alias in the service's `noBackupFilesDir`, unusable before the first unlock, when forwarding stays pending; app work runs the service in a process of its own (§18.15) |
| Windows app service | DPAPI under the service's own account, in its state directory |
| Linux app service | A 0600 file owned by the service's user, in its state directory |

### 5.10 Platform variants, build tags, logging, metrics, memory

| Variant | Build | Host | IPC |
|---|---|---|---|
| CLI darwin | `CGO_ENABLED=0`; keychain file `darwin && !ios && !sdk_mobile_bind` (purego; GOOS=ios satisfies `darwin`; 5.11's fallbacks) | `ur daemon` | socket |
| CLI linux | `CGO_ENABLED=0`; files `linux && !android` (GOOS=android satisfies `linux`) | `ur daemon` | socket |
| CLI windows | `CGO_ENABLED=0` | `ur daemon` | pipe |
| gomobile | sdk's `sdk_mobile_bind`; the `ios_extension` leg links only §18's forwarding role, `sidecar/device` and the root's forwarding files (D-SDK-20; owner decision 197); gomobile type-checks the macOS slices as GOOS=ios with its `macos` tag, on which desktop files also select, and compiles the archive they link as GOOS=darwin (§18.10's tags; owner decisions 493, 554) | app process; forwarding in the VPN component (§18) | none, or the socket for the macOS app's remote mode (§18.5); forwarding's setup over the device RPC (§18.6) |
| wasm | `GOOS=js GOARCH=wasm`, `_js.go` files; the page Worker builds `-tags sidecar_http`, leaving out the root's connect-facing files and linking no connect package, its `Id` the root's own twin of operator-core's (owner decisions 251, 276): 5.4's every-leg types and `SidecarApi` carry its identity, keychain, token path (bind, DPoP refresh, exchange) and approval views (§18.10) | extension worker, ur.io pages (owner decisions 26, 76) | none |

- **Settings, logs, memory.** `DefaultSidecarSettings()` is the only source of defaults (connect/CODESTYLE.md:144, :151). Logs go through `settings.Log` behind `V(n).Enabled()`, never with secrets, content or peer IPs; `SidecarStats` feeds `ur status --stats`, with no telemetry, and on a search indexer counts remote pages served, refusals by code, CPU seconds and queue waits, with no requester, repo or query label (I-13). The host sets the process limit (`sdk.SetMemoryLimit`; 32 MiB in the iOS app) and the sidecar keeps to `MemoryBudgetByteCount`, §16.10's decoded index state (`Search.MemoryByteCount`) and remote search's working sets and cursors included (≤ 8 MiB a computing search; D-CORE-17).

### 5.11 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Each MCP process embeds a Sidecar | no daemon | N child clients or a fight over the resident; an admission and a leaf or wrap per process | rejected |
| The ClientKey signs everything | already attested | reaped with its client; unlabeled | rejected |
| Connect's types in every root file | one `Id`, `Logger` and api client | the page Worker links gVisor: a connect-only js/wasm main is 55.0 MB (§18.10) | rejected (5.4; D-SDK-19) for `Logger` and the api client; the `Id` is operator-core's, composing connect's, on every leg but the page Worker's, which keeps a twin and so links no gVisor (owner decisions 251, 276) |
| Network credential beside the client token, as in sdk's `.auth_state` (sdk/local_state_auth.go:28-37) | admin from the CLI | an admin credential agents can read | rejected |
| Share the device's client in process (X10 option (c)) | no second client | Opportunistic (sdk/device_local_provider.go:258); escapes the admin-refused mark (I-6); no sidecar role in the iOS tunnel (D-SDK-1) | ruled out (owner decision 4; owner directive 2026-11-03) |
| One root key per instance, wrapped to each membership's recovery key | one key | one network's recovery code opens every network's keys (owner decision 23) | rejected (D-CORE-14) |
| macOS: the file-based login keychain, or a cgo leg | no bundle; Apple's C API | deprecating (D-CORE-12); cgo breaks §4.7 | fallbacks if the bundle or purego fails §22.5 |

### 5.12 Decisions proposed

**D-CORE-1 (proposed).** PLAN.md:14's jwt, client, api and encryption key are the sidecar's own `by_client_jwt`, one `connect.Client` per generation (none in the `sidecar_http` leg), the root's net/http `SidecarApi` plus, outside the `sidecar_http` leg, `BringYourApi`, and its network's keychain root key R_n; files outside `!sidecar_http` use only the root's `Id`, an alias of operator-core's but in the `sidecar_http` leg, where it is a twin with the same methods and encodings (owner decisions 251, 276), and its `Logger`, `MonitorValue` and `CallbackList` (5.4). Each `connect.Client` sets connect's `GateReceiveOnSignedIdentity` (§4.6 C15), so it opens no frame of a session whose signed-identity check is pending or failed. *Why:* PLAN.md:7; an agent-readable network credential is an admin credential; the page Worker runs no connect client, and importing connect links gVisor (5.3), which operator-core's `Id` brings to every leg that aliases it.

**D-CORE-2 (proposed).** `NewSidecar` returns a running Sidecar with its components attached; there is no `Start`. *Why:* connect/CODESTYLE.md:169.

**D-CORE-3 (proposed).** Envelopes go to bounded zero-wait component queues and stream bytes to credit-bounded buffers (5.4). *Why:* handlers must not block (connect/subprotocol.go:77-85); stream bytes cannot be dropped (connect/CODESTYLE.md:123).

**D-CORE-4 (proposed).** One client per sidecar, a child of the device client where an sdk host or pairing provides one, else top-level; agents are labels on it unless they run their own sidecar. *Why:* owner decision 4.

**D-CORE-5 (proposed).** Durable identity is the `sidecar_id` and identity key, admitted by a config-repo `SidecarAdmit` and bound to each client generation, its id and key, by a never-reaped, dual-signed binding. *Why:* clients are reaped and re-parented; operator attestation could add readers.

**D-CORE-6 (proposed).** The identity key signs every statement; agent subkeys sign only sealed provenance, each under an `AgentCert` of at most 30 days that the identity key signs, ended by a local `AgentRevoke` and by `not_after` (5.5; owner decision 285). *Why:* domain separation; survival across client generations; no agent id on the server (§11.5).

**D-CORE-7 (proposed).** Enrollment uses only one-time or scoped credentials, never a network credential or `urn_` key; the daemon declares no provider egress by default and fails closed without the admin-refused mark, `Pair` requiring both the `strict_exp` and the `admin_refused` claim of a token it did not mint (owner decision 291). *Why:* AUTHZ1, D-TEAM-6, §20.8.

**D-CORE-8 (proposed).** The core reimplements the sdk refresh schedule, and a refused refresh ends the client generation, not the sidecar; only a verified `SidecarRevoke` revokes. *Why:* connect has no refresh, sdk is not importable (§4.6), and a lost client is no revocation.

**D-CORE-9 (proposed).** One daemon per instance hosts a `Sidecar` per network behind uid-checked sockets or a pipe that return no secrets and grant nothing by mode. *Why:* one owner of the clients and keychain; owner decisions 23, 84.

**D-CORE-10 (proposed).** A random root key seals local files with XChaCha20-Poly1305, one per network, each wrapped by the instance unlock key, which the OS keystore and the pass wrap, and by only that network's recovery key (D-CORE-14). *Why:* cli/UI.md:82-85; unattended start; owner decisions 23, 62.

**D-CORE-11 (proposed).** Every outward action passes `Sidecar.Authorize` from every entry point, under an approved grant or a §16.6 decision labeled by its evidence, each use reserved before its effect (§16 D-MCP-11). *Why:* any same-user process can drive the CLI or control mode (owner decision 75).

**D-CORE-12 (proposed).** macOS wraps the unlock key in the data protection keychain via purego, from a bundled `ur`. *Why:* §4 forbids cgo; a bare CLI cannot use access groups; TN3137 puts the file-based keychain "on the road to deprecation" (https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).

**D-CORE-13 (proposed).** Members' devices alarm as 5.6 states and sign `OwnerConfirm` only through `ur approve` on `/dev/tty` or the app after the safety-number check (5.6's safety row; owner decision 281), never MCP. *Why:* owner decision 126; no rogue admin or stolen recovery code adds a reader, and no stolen device rebinds its member's code, unseen.

**D-CORE-14 (proposed).** Local roots are per network under one instance unlock key. *Why:* owner decision 23's shared unlock must not let one network's recovery code open another's keys.

**D-CORE-15 (proposed).** No store state but `Absent`, with no recorded `sidecar_id`, creates a root key; a lost item asks the person before a new identity. *Why:* a lock or a store fault must never reset identity.

**D-CORE-16 (proposed).** The index cache is per-network sealed local state (5.9) on every host: the sealed evs records fetched by sync position, each checked against its entry version's `content_sha256`, plus derived data under the local `search` key, which includes the version table that searches mask their candidates against, never a query, hit or cursor. It deletes at once what an erasure replaces, with its derived data, local-layer and journaled entries and vocabulary words, what a newer ref version drops (a dropped bucket is kept only until the cached all covers its roll-up), and every file of a repo the sidecar stops reading or whose index is turned off. *Why:* an index is a representation of its documents, which D-EVS-26 requires erasure to destroy, every decrypted copy included (§11.12); per-network roots keep networks unlinked (D-CORE-14).

**D-CORE-17 (proposed).** A daemon designated for search answers remote searches (§11.14) within its own budget (5.4's `Remote*` settings): 4 at once beside the 4 local searches and 16 queued for at most 1 s, 30 s of CPU a minute, 2 s and 1,000 verifications a page, 64 cursors, and per-requester rates. It keeps all of every repo it reads within a 16 GiB cache, and persists no query, hit, snippet, cursor or result count, only the owner-bound served record, one row per requester, repo and UTC day with its count and its first and last times, for 30 days and at most `Search.ServedRecordCount` rows (5.9; owner decision 294). *Why:* owner decision 175's phones must not starve local agents' searches (§16.10's targets), I-13 bars queries from every log, and an owner keeps D-MCP-18's view of shared reads without an evs write at search time.

**D-CORE-18 (proposed).** The harness config's `claims` (auto, prompt, off), set per member and per project, defaults to auto in team networks, unless `ServiceSettings.directory.runs` sets the team's default (§7.9), and to off in personal ones. A committed `.ur` may set it and the `project` label its runs announce: a narrower value applies at once, a wider one after one confirmation on /dev/tty or in an app, never through MCP. The value is fixed for each session with its instructions. *Why:* owner decision 170; a committed file must not widen what a member shares.

**D-CORE-19 (proposed).** Devices delete dropped content locally on applying an executed drop (5.9). *Why:* owner decision 173's "the dropped content is gone" covers the customer's own copies that the sidecar manages.

**D-CORE-20 (proposed).** Apart from §7.10's stale revocations, which ride the act that carries them, under its confirmation and, where its signer registered a live presence key, its one presence check (owner decision 187) (a page Worker's admission, or the member's `OwnerConfirm` of an admin-admitted page Worker, `ur approve` on `/dev/tty` included, or answer to that admission's alarm), a member revokes another of its own devices only through 5.4's `PreviewDeviceRevoke` and `RevokeDevice`, §18.5's alarm answers that revoke a named device included, with the `since_n` the alarm fixes: from a device approval-capable for that member and not suspended, never for itself, another member's device or a tagged sidecar; after the person's approval at that device, by presence wherever the member holds a live presence key whose `KeyRegister` this sidecar signed, the plan setting `Presence` from the log, never from the caller, the check's countersignature riding each statement of the act for api and every member device to verify (D-TEAM-32; owner decisions 185, 187), else by the person's confirmation in an app's UI or on `/dev/tty` (D-CORE-13), never on a harness hook's evidence, MCP or an unconfirmed control call; as `lost` or `compromise`, SidecarRevoke's own reasons, the second with §7.9's cascade from `since_n`; on a plan the person reviewed and the device re-derives when it signs, answering `REVOKE_STALE` only if its `PlanId` changed; at k > 1 suspending the target in the same act; with `KeyRevoke` of the keys the target registered only under presence evidence (5.6). *Why:* §5.6 promised an app path that no bound call carried: `Decide` answers only pending items, the core offered only the generic `Sign`, and `Core()` is Go-only; a compromise revocation parks devices and voids bindings, so a thief holding an unlocked device must pass its presence check (owner decision 142), which no caller can skip by omitting it, nor modified software by not running it, since every verifier checks its countersignature (owner decision 185); a plan whose target, reason, since_n, signatures or keys changed is not signed; a lost device must not keep its access while cosigns are due; and the scope keeps one member's device from revoking another's, which stays admin authority (§7.10).

### 5.13 Open questions

**Q-CORE-1.** [X10] What client identity does a sidecar run under? **Decided by owner 2026-11-03 (owner decision 4):** its own Required client (D-CORE-4, 5.8), never the device's own client (5.11). *Residual:* none.

**Q-CORE-2.** Cross-cutting. How do standalone and cloud-VM sidecars count? **Decided by owner 2026-11-03 (owner decision 4):** one declaring no egress is exempt from `concurrent_clients` and the 100-client cap and counts against `sidecar_clients` (§20.8, Q-QUOTA-4). *Residual:* none.

**Q-CORE-3.** Does the daemon run as the user or a service account? **Decided by owner 2026-11-03 (implied by owner decision 59):** the user, everywhere, since agents are inside the device trust boundary (owner decision 47). *Residual:* none.

**Q-CORE-4.** Cross-cutting (§6, §7). Must a sidecar prove possession of its ClientKey? **Closed by peer review 2026-11-04:** (b) in v0: a `strict_exp` bearer adds a DPoP proof (RFC 9449) by its ClientKey on refresh, the token exchange and `POST /network/auth-client` (§7.4), the jti single-use and the key the newest bound one; sdk hosts carry it through `Api.SetDpopSigner`, installed by sdk/sidecar.go, before D-CORE-8's refresher is switched off on any host; (c), proof on transport auth, later, with its residual stated in §7.4. *Residual:* none.

**Q-CORE-5.** Is the recovery code also an MLS recovery member? **Decided by owner 2026-11-03 (owner decision 62):** no; it derives keys for §10.8's recovery wraps (5.9), and an admin re-add restores team repos, not owner-bound ones (owner decision 126). *Residual:* none.

**Q-CORE-6.** Cross-cutting. How does one device join several networks? **Decided by owner 2026-11-03 (owner decision 23):** one daemon hosts a `Sidecar` per network (5.8), sharing the keychain unlock and MCP endpoint but no client, root key or identity key; a team sidecar is top-level there (§20.8). *Residual:* none.

### 5.14 Departures from PLAN.md

None: PLAN.md:14 and :59's git identity hold, and D-CORE-1 reads "encryption key". Bare `ur` on a terminal is §16's departure from PLAN.md:20 (owner decision 57).

### 5.15 Interfaces

- **Provides:** the 5.4 API, its alarms, state reasons and `Status()` with `witnessed_at`, open UNVERIFIED pins and the components' status lines; `Authorize` with its effect seam (`SidecarEffect`, `SidecarOutcome`, `RegisterEffectLookup`); 5.8's `events`, `mail.check_send`, `mail.send_result` and `mail.send` control methods and its `git-hook` mode; its every-leg root types and `SidecarApi`; the identity key, ReaderKey and binding; the client side of admission, owner consent, pairing and recovery; the per-network keychain and its store states; 5.8's local JSON-RPC, `git` mode, `ur directory` methods and `.ur` rules, with `claims` and `project` (D-CORE-18); 5.9's index cache and search state, the served record included, and 5.4's `Search` and `Directory` settings; the search engine's API (5.4); remote serving within D-CORE-17's budget; local deletion of dropped content (D-CORE-19); a member's revocation of its own other devices, through 5.4's `Devices`, `PreviewDeviceRevoke` and `RevokeDevice` under 5.6's rules and `REVOKE_` codes (D-CORE-20), with `ur devices` and `ur devices revoke`.
- **Consumes:** §6 (id 21842, typed `Signed` and §6.11's `SignedType`, both in `protocol/bridge`, `Hello` and its feature bit 0, `core` push, `SidecarProtocolSettings`, HeadCheck's `witnessed_at` and alarms, §6.11's SEARCH pair); §7 (enrollment, auth keys and their client-only bundle, Delegations, `ur-cli`, token exchange, P0 with its route allowlist and DPoP proof, D-TEAM-14, config records, the leaves rule); §8 (`autogroup:sidecar`, `sidecar:<id>`, consent); §10 (ReaderWraps, recovery wraps, external commits, the config and directory groups' leaves and wraps); §11.7's executed drops and drop states; §11.11; §11.14's search index (files, their entry versions' plaintext hashes, manifests, ERASE and CLOSURE hints, index alarms) and remote rules; §16 (`ur approve`, D-MCP-11's ledger, presence keys, the `Mcp`, `Ingest` and `Record` settings, 16.10's search limits, sync policy and taint rule, 16.11's directory, its signing rules and `claims`); §18 (`TokenSource`, `SidecarKeyStore`, remote mode, `sidecar_http`, 18.4's search modes, caps and working sets, 18.8's search store); §19.10; §20.8; §4 (purego, the bundle, §4.4's build tags).
- **Subprotocol messages:** `core` push (server → sidecar: a revocation hint, verified against the config (5.6); forced resync; §6). Its body is protocol/core.proto's `CoreHint{kind = 1, sidecar_id = 2, min_secure_version = 3}`, with `CoreHintKind` REVOCATION 1, RESYNC 2, WAKE 3, MIN_SECURE 4 and GATES 5 after UNSPECIFIED 0: `PushHint.kind` is 0x1A01 and `PushHint.hint` the marshalled message, under 256 B. `sidecar_id` is this client's own, set only on REVOCATION, and `min_secure_version` only on MIN_SECURE; an unknown kind or a dropped body is a bare resync, and no field carries authority (5.6).
- **API routes:** existing `POST /network/auth-client` (also the pairing child) and `POST /network/remove-client` (OwnClient), `GET /auth/refresh` (Client), auth-client and refresh taking a `strict_exp` bearer's DPoP proof (§7.4); refresh gains one error, `restore_required` (5.6, §19.10). New, classified by §7:
  - `POST /sidecar/bind` (Client; also re-registration after a restore, which stays gated on the projection admitting the identity key): the request is JSON `{"binding": "<base64 of the wrapper>"}`, 5.4's `SignedSidecarIdentityBinding`, and the reply 200 `{"generation": n}` with the re-minted `by_client_jwt` (5.6). A refusal uses the server's existing coded body, `{"error": "<text>", "code": "<code>"}`: 403 `sidecar_revoked`; 400 `binding_invalid` for a bad signature, a malformed body, or a bearer token whose client differs from the binding's `client_id` or whose network differs from its `network_id`; 409 `generation_conflict` for a later binding that is not the newest plus one or does not carry the row's `identity_public_key`; 409 `client_bound` for a second binding of a client, whatever its `sidecar_id`, and for a binding whose `client_public_key` differs from a non-NULL `network_client_owner.client_public_key`. A retry whose wrapper bytes equal the stored row's answers 200 with that generation and writes nothing, which also covers re-registration after a restore; any other bytes for a bound client answer `client_bound`.
  - `GET /sidecar/identity/<sidecar_id>` (Client, for the caller's own network or one with an active §8.11 share): `identity_public_key`, `identity_alg`, `status` and the current binding, never `user_id`, and `bindings`: that sidecar's stored wrappers in base64, newest first, 64 a page, `?before_generation=<g>` for the next.
  - `POST /sidecar/identity/clients` (internal, under §19.4's internal-route credential, never a client's token): `{sidecar_ids}`, at most 1,000, answering each id's current `client_id` and `generation` and omitting unknown or revoked ids; it logs no per-target record. Hosts that keep Postgres off §6.8's hint path, `server/cli/gkm` and mxedge's router among them, call it behind the `Push.HintSidecars` seam, each process keeping a map of at most 65,536 entries with a 5-minute TTL, a miss batching one call and a failed call returning an error the caller counts and passes over, since §6.8's hourly resync covers a lost hint; taskworker, which may read Postgres, resolves from `sidecar_identity_binding`.
  - `GET /sidecar/sync/core` (Client): §6.8's `core` state, JSON `{"version", "min_secure_version", "gates", "revoked"}`, always 200; `revoked` is a candidate the client verifies against the config (5.6), and `min_secure_version` an unsigned floor a device applies only as §6.4's live denial, never persisting it (owner decision 295).
  - `GET /sidecar/identity?client_id=<id>` (Client, under the same caller rule): `{sidecar_id, identity_public_key, identity_alg, status, binding}` for that client's binding of any generation, 404 if none. Verifiers check both signatures and the identity key against their pin, so api stays untrusted. Its callers are a replaying reader, only for a commit whose committer differs from `<client_id>@ur.invalid` taken from that push's own `EvsPush.client_id`, under the signature it already verifies (an equal committer passes with no lookup), which requires the binding's `sidecar_id` to equal the push's `signer_sidecar_id`, `SidecarCommitter` refusing what stays unresolved; §8's selector resolution; and §17's compile, for a subject's client ids. Never the packet path.
- **Tables:** owned by api; migration ≥926; never reaped, but deleted with their network.
  - `sidecar_identity(sidecar_id, network_id, identity_public_key, identity_alg, status, create_time, revoke_time)`;
  - `sidecar_identity_binding(sidecar_id, generation, client_id, client_public_key, signatures, create_time)`, append-only, `client_id` unique across every sidecar and `signatures` the wrapper's bytes verbatim (5.4).
- **Services and config:** no new server service; 5.8's client units, the `.ur` file and the macOS bundle.
- **Assumptions about other sections:** §7.9 and §8.8 define the signers, `self_admit`, the recovery window and its start p, how a restored binding's scoped admission enters it (owner decision 149), its veto, a late veto's precedence and `recovery_unseen`, the rebind alarm, the leaves rule of the config and directory groups (owner decisions 144, 182), `RecoveryBind`, `OwnerConfirm`, `SidecarRevoke`'s reasons and compromise cascade from `since_n`, the voids at which 5.6 alarms and 5.9 re-seals, `no_genesis` and the recovery `anchor` with its `restored` order, by which a device a restored binding admitted, which no RecoveryWrap reaches until that binding is signed again, anchors on the late config ReaderWrap a config writer gives it (KF2) or a later rotation stages (§10.5) before it uploads a KeyPackage or self-joins; §7.4 the DPoP rule and stage 2's wait for the app and extension releases; §10 makes member devices the leaves (in the config and directory groups the first 1,000 by §7.9's rank, the rest wrapped), agents wrapped readers and the signing leaf those groups' committer (owner decisions 114, 128, 182), and parks unconsented devices; §6.6 and §16 define `SidecarProtocolSettings` and the `Mcp`, `Ingest` and `Record` settings, and §16.6 the own-resource filings 5.8 admits from any mode and TS1's refusal (5.4); §7.9's retain row and fold cadence bound the log 5.9 retains, and §18.4 applies them per host; §6.4 and §7.9's anchor define `head_alarm`'s alarms; §18.5 relays 5.4's alarms, `recovery_rebind` (at a void too) and `head_alarm` included, offers admins the veto of a restored binding's admission, and maps its state reasons; §18.10's leg links only 5.4's every-leg files; §11.11 serves the `git` mode; §11.14's entry versions carry each index file's plaintext SHA-256 and a/m marks each roll-up, so 5.9 checks files and keeps a dropped bucket until all covers it; §16.10 binds a `ur` caller to its run by process ancestry (§16.7); §11.7 reports a held drop as done (owner decision 184) and states the reader checks whose failure 5.4 reports as `invalid`; §18.4 keeps its policy overrides, remote mode and notice answers in 5.9's search state; §18.5 binds 5.6's device revocation for apps, its presence check by the host's `SidecarPresenceSigner`, a remote-mode app's over 5.8's two calls, and lets other AdminSet devices cosign a revocation's AuthorityProposal through `Decide`; §16.8's membership entries carry the revocation's approval evidence; §7.10's `stale` row has the member's consented device, at its `OwnerConfirm` of an admin-admitted page Worker or its answer to that admission's alarm, revoke the member's stale Workers its groups show (D-TEAM-29); §7.9's `scoped` row lets the member's consented device revoke its own untagged devices whatever `self_admit` says, its `counted` and `authority` rows count an AdminSet member's existing device as one of the k, never the target, and its cascade adds a confirmation's subject to P only if that confirmation lifted the subject's park or the subject's consent rests on it alone; §8.8's `Suspend` signer row lets the owner of an AdminSet member's device suspend it alone (5.6's sign); §7.9's presence row and §6.9's `Signed.webauthn` define the countersignature 5.6's acts carry, §16.6's countersign row its check with UV, and §18.5's `SignWithPresence` returns its evidence (owner decisions 185, 187).

### 5.16 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A same-user agent uses the sidecar's token or keys (owner decision 47) | High | High | the P0, D-TEAM-14, ClientKey proofs, the gate |
| A same-uid process, such as a prompt-injected agent's shell, forges a PermissionRequest hook event (owner decisions 47, 75) | Medium | High | §16.17's row (owner decision 142) |
| The app's `.auth_state` or the extension's `chrome.storage.local` on the same host holds a network `by_jwt` | Medium | Critical | §7.4's stage 2, before the first desktop sidecar, waits for the app (§18.7) and extension releases that stop persisting it (owner decision 45); until then, preview networks only and 5.6's enrollment refusal (D-TRUST-3) |
| A sidecar ships before the P0 | Medium | Critical | fail closed (D-CORE-7) |
| A store loses its item, or a host reports a lock as absence | Medium | High | D-CORE-15: `keystore_lost` and the person's confirmation, never a silent new identity; the pass's wrap of U |
| An approver skips the safety-number comparison | Medium | High | invites and auth keys carry the genesis; every device sees admissions; HeadCheck (§6) |
| A paired daemon's parent client is removed or reaped (5.3), ending its child | Medium | Medium | identity and admission survive; `ur login` re-binds (5.8) |
| Losing every device and the code loses data | Low | High | recovery wraps; admin re-add (owner decision 62) |
| A rogue or compromised admin admits a device under a member | Medium | High | §8.18's row (owner decision 126) |
| A thief holding an unlocked device that registered no presence key, or a same-uid process speaking control mode for a remote-mode app whose daemon registered none (owner decision 47), revokes or suspends the member's other devices, as `compromise` parking what they admitted; in a personal network the thief's device is then the member's only AdminSet device and can veto every recovery window (§7.9's Recovery) | Low | High | wherever this sidecar registered a live presence key, as `ur login` and the apps offer (owner decision 142), 5.6's presence check, set from the log so no caller skips it, puts its countersignature on each statement of the act, which api and every member device verify, so modified software cannot skip it either (owner decisions 185, 187); with none, the person's confirmation alone, which a same-uid process can forge (disclosed; owner decision 47); every member device sees each revocation; P never holds its signer; a parked device returns by an AdmissionConfirm or OwnerConfirm from outside P, and a revoked one enrolls anew |
| An AdminSet member's lost device stays admitted, and what P would park and void stands, while its revocation's AuthorityProposal waits for another admin's cosign (k > 1; owner decision 110) | Medium | Medium | the proposer's Suspend ends its access within 5 s meanwhile (§8.8); other AdminSet devices cosign by `ur approve <proposal_id>` on `/dev/tty`, or list the proposal in `GetPending` and cosign through `Decide` (§18.5); an admin's remove-client denies at the server at once (§7.10) |
| A stolen recovery code, or the code a stolen device rebinds its member to, with that member's login or the operator's help, reads its wraps at once, whatever the window or a veto, until a compromise rebind or §7.9's cascade voids its binding, and opens keychain backups sealed to it; with `self_admit` on, for a member outside the AdminSet, it also admits a device at once, which reads the member's repos until revoked (owner decisions 112, 126, 127, 149) | Low | High | the member's devices alarm (`recovery_rebind` at the rebind and at its void) and revoke it; `ur keychain recovery-rotate --compromise`, then revoking for compromise and enrolling anew each device whose backups may hold a sealing to it (5.9); no device stores the code |
| An index cache keeps an erased document's postings, or a removed reader keeps a repo's index | Low | Medium | D-CORE-16 deletes on the ERASE or CLOSURE hint, on a ref version that drops a file, on a lost read and when the index is turned off; cursors end (§16 D-MCP-25); copies an agent already took stay (§11.12's residual) |
| Phones' searches starve local agents | Low | Medium | the remote budget (D-CORE-17) |

### 5.17 Phasing

- **v0 (§23 M1-M3)**, after §7's P0 and D-TEAM-14: M1, the daemon on darwin, linux and windows, top-level enrollment (`ur connect --token`, `ur login`), `/sidecar/bind`, refresh with DPoP proofs and `restore_required`, fail-closed, the per-network keychain under U with D-CORE-15's store states, the local API, and 5.4's every-leg root types and `SidecarApi`, which §4.7's `sidecar_http` check holds from M1; M2, config-repo admission and revocation with the key authority, owner consent, alarms, the config group's leaves and wraps, and ReaderKeys (owner decisions 3, 112, 114, 126, 127, 144), the recovery code, its wraps of R_n and its rotation, the `git` mode (§11), and `ur indexer` with 5.8's unit and idle rules (owner decision 150); M3, the gate with D-MCP-11's reserved uses and owner decision 142's tainted-run rule, a member's revocation of its own devices through 5.6's calls and `ur devices`, with their presence check, whose countersignature §7.9's M2 verifier already requires (D-CORE-20; owner decisions 185, 187), and `.ur`, with §16.
- **v0, app hosts (§23 M8):** sdk hosts and desktop pairing (§18.17), with `SidecarApprovals`' device list and revocation (D-SDK-30); forwarding's identity row and key stores in every app's VPN component (5.5, 5.9; owner decision 197).
- **Browser (§18.17):** the HTTPS-only wasm page Worker, built `-tags sidecar_http`, for ur.io/recurd at M4 and the team console at M6 (owner decisions 26, 76).
- **v1 (§23 M6):** several networks per daemon, with team networks (owner decisions 23, 55); the RFC 8628 device grant; agent subkeys; `.ur`'s `claims` and `project`, the directory's control methods, its group under 5.6's leaves rule, local state and `Directory` settings, and the `access_request` action and events (owner decisions 170, 171, 182).
- **v1, §23's M10 (owner decision 169):** 5.9's index cache and search state and the `Search` settings, with §16.10's search and 5.4's engine API (owner decision 163); remote serving and the served record with the index cache (owner decision 175); local deletion of dropped content (owner decision 173); the index, search and drop event kinds.
- **Later:** the extension's Worker and wasm streams (C4); transport proof of possession (Q-CORE-4 (c)).
