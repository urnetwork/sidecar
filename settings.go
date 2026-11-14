// A Sidecar's settings, on every leg. DefaultSidecarSettings is the only source of a default (§5.10;
// connect/CODESTYLE.md:144): hosts adjust what it returns per class, as sdk's
// applyMobileLowMemoryClientSettings does for connect (§18.4), and keep no second copy of a number.
// Defaults here are the desktop daemon's. A field's comment gives a mobile value after a semicolon
// where the design sets one, for the host that applies it.
//
// A ByteCount is in bytes and a time.Duration is a span of time. Every number in these structs must
// be positive: validate refuses anything else, so a zero is never unlimited or off, and no implementer
// has to decide what one means. A field tagged settings:"zero" gives zero the meaning its comment
// states, and refuses a negative value all the same.
//
// Format values that every reader applies alike are constants beside their formats, not settings
// (connect/CODESTYLE.md:145). settings_connect.go and settings_http.go declare the connect settings
// per leg, envelope_settings.go §6's, and settings_mcp.go §16's.

package sidecar

import (
	"fmt"
	"time"
)

// What a host adjusts and hands to NewSidecar, which refuses what validate refuses.
type SidecarSettings struct {
	// The instance name (§5.9): [a-z0-9][a-z0-9-]{0,31}, which names a directory, so anything else is
	// refused. Default "default". A host reads UR_INSTANCE or --instance and sets it here.
	Instance string
	// Service urls, absolute, with no trailing slash, query or fragment. None has a default yet, so
	// each host sets its environment's, and validate refuses one left empty. A dial would not catch
	// it: in the page Worker fetch resolves an empty url against the Worker's own origin, which
	// would send the bearer token to the page's host (api_transport.go). §5.4 has EvsUrl, GkmUrl,
	// SocketsUrl and DnsUrl default from §19.4, which waits on whether a production hostname may sit
	// in code.
	ApiUrl string
	// ws or wss, read only on connect legs. Every other url is http or https.
	PlatformUrl string
	AuthUrl     string
	EvsUrl      string
	GkmUrl      string
	SocketsUrl  string
	DnsUrl      string
	// What a client reports as its version. Default Version, which is empty in a development build,
	// and empty here reports none.
	AppVersion string

	// Client generations, empty on the sidecar_http leg.
	Connect *SidecarConnectSettings
	// §6.6's bounds.
	ProtocolSettings *SidecarProtocolSettings
	// sdk's schedule (sdk/device_token_manager.go:20-27, :266-275), which D-CORE-8's refresher
	// repeats, since sdk is not importable here.
	TokenRefreshSettings *SidecarTokenRefreshSettings
	// The pass's cost and limits, and auto-lock (§5.9).
	KeychainSettings *SidecarKeychainSettings
	// The daemon's sockets, idle exit and request bound (§5.8).
	LocalSettings *SidecarLocalSettings
	// §16.4's bounds on an MCP session.
	Mcp *SidecarMcpSettings
	// §16.7's capture bounds.
	Ingest *SidecarIngestSettings
	// §16.8's record defaults.
	Record *SidecarRecordSettings
	// §16.10's limits, 5.9's index cache and §11.14's remote search.
	Search *SidecarSearchSettings
	// §16.11's team directory.
	Directory *SidecarDirectorySettings
	// §11's client: its calls, verifying reader and local tier.
	Evs *EvsSettings
	// §13.8's device key and the self-signed leaf that stands in for an issued chain.
	Tls *SidecarTlsSettings
	// §10's client: its calls to gkm, its hints and its key upkeep.
	Gkm *GkmSettings
	// §9.5's registrar: its heartbeats, eager load reports and waits after a refusal.
	Sockets *SidecarSocketSettings
	// §5.5's agent subkeys: how long each certificate runs, the bound every reader holds it to, and when a new one
	// replaces it.
	AgentSubkeys *SidecarAgentSubkeySettings

	// Envelopes one component's queue holds. Complete envelopes wait here without blocking the
	// inline handler, and a full queue drops and counts (§5.4; connect/CODESTYLE.md:119). Default
	// 256, a reading: the design sets no number, so this is four of §6.6's 64-message peer queues.
	ComponentQueueMessageCount int
	// Bytes one component's queue holds: 1 MiB, a reading, ComponentQueueMessageCount envelopes of the
	// 4,080 B maximum in their 4 KiB pool class.
	ComponentQueueByteCount int
	// The process's whole budget, §6's process-wide reassembly, idempotency and credit caps and
	// Search.MemoryByteCount inside it: 128 MiB on a desktop or CLI daemon (§18.4), which a host
	// raises to 192 MiB on a daemon designated for search (owner decision 175); iOS 32 MiB, Android
	// 16 MiB added. A cap that would pass it answers RESOURCE_EXHAUSTED.
	MemoryBudgetByteCount int64
	// The most stream data one StreamData message carries: 4,000 B, the format's limit (§6.5). A
	// value above it is refused by peers.
	StreamChunkByteCount int
	// The most of one api answer's body a SidecarApi reads: 2 MiB, connect's own bound on an api
	// answer (connect/net_http.go:63's MaxHttpResponseBodyBytes), and far past any body §5's and
	// §7's routes answer. A longer answer is refused, so api cannot make a sidecar buffer more. §5.4
	// names no such bound, so this is a reading.
	ApiResponseByteCount int64
	// The longest round trip whose answer's Date a SidecarApi keeps as the api's clock (§7.4, QD-757): 30 s. The
	// api read its clock somewhere inside the round trip, so a reading is off by at most half of it and a Date's
	// whole second, 16 s here against §7.4's 60 s window; a longer answer leaves the reading before it standing.
	ApiClockMaxRoundTrip time.Duration
	// How far a refused DPoP proof's reading of the api's clock must lie from the one the refusal's own Date
	// gives for the request to go once more, signed by the newer reading (§7.4, QD-757): 5 s. Past the 1 s a
	// Date's whole seconds move a reading by, so a proof refused for anything but its iat is not sent again, and
	// far inside §7.4's 60 s window, so one refused for its iat always is.
	ApiClockRetryShift time.Duration
	// How long a statement this sidecar signs may wait to land: its StatementHeader's not_after, and so how long a
	// kill or a lost answer leaves it pending, retried with the same bytes (§5.6's sign row, §5.9). 7 days, §7.9's
	// most, a reading: §5.6 sets none shorter, and a cosign at k > 1 needs the whole of it.
	StatementTimeout time.Duration
	// Whether this sidecar signs a RecoveryBind or RecoveryRebind. Off, the default: QD-010 fixes the derivation
	// from a code to its keys (keys_recovery.go), and no real binding is signed until §5.9 states it, since a
	// printed code outlives any regeneration (plan-CORE-recovery-derivation #2's interim). While off,
	// RotateRecovery answers ErrRecoveryBindingGated and signs nothing; keychain.wrap's copy still follows a
	// binding another device signed.
	RecoveryBindings bool

	// Nil, the default: connect's default logger, glog, on connect legs (adapted, log_connect.go); no
	// logging at all on the sidecar_http leg.
	Log Logger
	// The time the Sidecar reads and waits on (clock.go). Nil, the default, is real time; a test
	// passes sidecartest's FakeClock. connect's own timers stay real (X9).
	Clock Clock
}

// sdk's refresh schedule (§5.4). A token refreshes at a point of its lifetime drawn from the window
// by its jti, so clients spread out and one token's point never moves.
type SidecarTokenRefreshSettings struct {
	// The window's start, as a fraction of the token's lifetime: 0.4, sdk's, which leaves a client
	// more than half a token's life to retry in.
	RefreshWindowStart float64
	// The window's end, as a fraction of the token's lifetime: 0.5, the half-life, which no token's
	// point passes. At or below RefreshWindowStart every token refreshes at the window's start.
	RefreshWindowEnd float64
	// The least time from one attempt to the next scheduled one, so a server-set lifetime can never
	// make a hot loop: 5 min.
	MinRefreshTimeout time.Duration
	// After a failed refresh the next attempt waits a uniform draw from [0, this): 15 min, which
	// spreads clients that failed together.
	RefreshRetryTimeout time.Duration
	// How long after it is first scheduled a token with no readable exp refreshes: 7 days, sdk's,
	// so a token without an expiration is revalidated weekly rather than kept for good.
	NoExpirationRefreshTimeout time.Duration
	// How long ServiceToken keeps a service token for its audience and scopes before it exchanges
	// again: 10 min, a reading of §5.6's "under 15 min", which leaves a token handed out at the end
	// of its stay 5 min of its 15 (§7.8). A token whose expires_in is shorter is kept no longer
	// than that.
	ServiceTokenCacheTimeout time.Duration
}

// The pass's Argon2id cost (§5.9) and the rules around it. Opening a keychain reads the parameters
// stored beside its wrap, so changing these moves only new wraps. A cost of zero would be a pass with
// no cost, and an interval of zero a limit that never counts, so these are held as every number is.
type SidecarKeychainSettings struct {
	// Argon2id memory: 64 MiB (RFC 9106 §4); 19 MiB on mobile and wasm (OWASP).
	PassMemoryByteCount int64
	// Argon2id passes: t=3 (RFC 9106 §4); 2 on mobile and wasm (OWASP).
	PassIterationCount int
	// Argon2id lanes: p=4 (RFC 9106 §4); 1 on mobile and wasm (OWASP).
	PassThreadCount int
	// A wrong pass is refused past this many attempts in an interval: 5 (§5.4), which bounds guessing
	// at this device.
	PassAttemptCount int
	// That interval: 10 min (§5.4).
	PassAttemptInterval time.Duration
	// Idle time before an unlocked keychain locks, dropping U and every R_n from memory: 10 min. §5.4
	// names the setting and no value, so this is a reading, kept on the side that protects keys until
	// the owner sets it, and the same bound as IdleExitTimeout. Zero never locks, which a host running
	// a daemon that must keep serving with no person present sets on purpose.
	AutoLockTimeout time.Duration `settings:"zero"`
}

// The daemon's local IPC (§5.8). §5.4 names sockets, idle exit and a request bound without values, so
// the numbers here are readings, each with its reason.
type SidecarLocalSettings struct {
	// The control socket or pipe. Empty: §5.9's per-platform path for the instance.
	SocketPath string
	// One more app-group socket for a sandboxed desktop app (§5.9), served beside the ones the daemon finds in the
	// app-group containers ur claims on macOS (daemon_pair.go): a host's own container path. Empty: none more.
	AppGroupSocketPath string
	// How long an auto-spawned daemon with nothing to serve waits before it exits: 10 min, so a run
	// of `ur` commands reuses one daemon. Zero never exits. A unit-run daemon and one that mail,
	// sockets, bridge or an indexer keeps busy never idle out (§5.8).
	IdleExitTimeout time.Duration `settings:"zero"`
	// The most one local request may hold: 4 MiB, above §16.7's 1 MiB body once JSON escapes it. A
	// larger one closes its session.
	RequestByteCount int64
	// How long a local request may run: 30 s, §16.4's call timeout.
	RequestTimeout time.Duration
	// The first port of the local services (§5.8, §11.11, §15): git over http or https at it, git's ssh one past it,
	// submission two past it and IMAP three past it: 17000 (plan-CORE-cli-ui-missing #6). ur daemon's --port sets
	// it, and a second instance on one host passes its own. Zero lets the OS choose each service's port, as a test
	// does.
	FirstPort int `settings:"zero"`
	// The longest hello line either end reads, the daemon's hello and its answer (§5.8): 16 KiB, far past any real
	// one, which a cwd of a few hundred bytes bounds, and far below RequestByteCount, so a hello cannot hold memory.
	// DaemonClientSettings carries the same value for a client.
	HelloByteCount int64
	// The read buffer of one local session: 4 KiB, a hello's size and a request line's usual one; a longer line
	// reads through it in pieces.
	SessionBufferByteCount int
}

// §16.10's limits, 5.9's cache and §11.14's remote search. A daemon designated for search (§7.9)
// applies CacheByteCount 16 GiB and MemoryBudgetByteCount 192 MiB (owner decision 175).
type SidecarSearchSettings struct {
	// The index cache on disk, past which all partitions go first: 4 GiB (§5.9). Zero keeps it in
	// memory, inside MemoryBudgetByteCount, as ephemeral sidecars do.
	CacheByteCount int64 `settings:"zero"`
	// Decoded index state, inside MemoryBudgetByteCount: 64 MiB; app and page hosts set §18.4's
	// smaller working sets.
	MemoryByteCount int64
	// 5.9's version-table pages a process, inside MemoryByteCount: 256 KiB, 64 pages of VersionPageByteCount.
	VersionCacheByteCount int64
	// Sync downloads a day a network, since each debits the transfer balance: 1 GiB (§16.10).
	BackgroundByteCount int64
	// Downloads a "search more" call, where its page turns partial: 1 GiB (§16.10).
	MoreByteCount int64
	// §18.4's mode for all: background (desktops, indexers), wifi_charging (phones, tabs), on_demand
	// (ephemeral, cloud) or never. Anything else is refused.
	AllPolicy string
	// Hints coalesce a repo over this, so a busy repo costs one sync: 1 min (§16.10).
	HintCoalesce time.Duration
	// Idle time before a local or remote cursor goes: 10 min (§16.10).
	CursorTimeout time.Duration
	// At most one forced head refresh a repo in this: 10 min (§16.10).
	HeadRefreshInterval time.Duration
	// A reader that is not a writer syncs an owner-bound index at most this often: 15 min (§16.10's
	// receipts).
	NonWriterSyncInterval time.Duration
	// Searches at once a session, inside §16.4's 8 calls in flight: 2. One past this waits up to its
	// wait_ms, then answers busy (§16.10).
	SessionSearchCount int
	// Searches a session may start: 5 a second, burst 10. One past this waits as above (§16.10).
	SessionSearchRate SidecarRate
	// Open cursors a session, the oldest dropped: 16 (§16.10).
	SessionCursorCount int
	// Local searches at once: 4 (§16.10).
	DaemonSearchCount int
	// CPU a page, local or remote: 2 s (§16.10).
	PageCpu time.Duration
	// Candidates verified a page: 1,000 (§16.10).
	PageCandidateCount int
	// Candidates in a partition past which it answers too_broad: 20,000 (§16.10).
	TooBroadCandidateCount int
	// MCP results a page: 64 KiB, under §16.4's 256 KiB result limit.
	PageByteCount int
	// "on" until the person picks on, own or off (5.9's state). Anything else is refused.
	RemoteMode string
	// How long a requester waits for a first page before it tries the next indexer: unmetered, then
	// metered, 3 s and 5 s (§11.14).
	RemoteTimeout [2]time.Duration
	// Answer remote searches once designated: true on daemon hosts; false on app hosts, which never
	// serve (§11.14).
	RemoteServe bool
	// Remote searches computing at once, beside DaemonSearchCount: 4 (§11.14).
	RemoteSearchCount int
	// Remote searches waiting, each at most RemoteQueueTimeout, else RESOURCE_EXHAUSTED: 16 (§11.14).
	RemoteQueueCount int
	// The most a remote search waits in that queue: 1 s (§11.14).
	RemoteQueueTimeout time.Duration
	// CPU a minute for all remote work, D-CORE-17's budget: 30 s (§11.14).
	RemoteCpuPerMinute time.Duration
	// Open remote cursors, the oldest dropped: 64 (§11.14).
	RemoteCursorCount int
	// Per requester at an indexer, and per indexer at a requester: 30 a minute, burst 10 (§11.14).
	RemoteRequesterRate SidecarRate
	// How long an owner's indexer keeps 5.9's served records: 30 d (D-CORE-17).
	ServedRecordTimeout time.Duration
	// The most served records an owner's indexer keeps a network, the oldest going first: 8,192, a reading, since the
	// design bounds them only by ServedRecordTimeout and RemoteRequesterRate, which would let one reader grow search.state
	// past StateByteCount (state_search_state.go).
	ServedRecordCount int
	// How long the asker remembers which repos each indexer served, in search.state: 24 h (DESIGN-DETAILS 7.2.1's
	// RemoteServedTimeout, §5.9's state row).
	RemoteServedTimeout time.Duration
	// The most search.state may hold: 4 MiB, a reading, above ServedRecordCount's records and a phone's served memory
	// of a few thousand repos. A file past it reads as failed, and a change that would pass it is refused.
	StateByteCount int64
	// Hits a page when a request names none: 50 (§5.4's SearchRequest.PageSize, §11.14's confirm row).
	PageHitCount int
	// Whether this host runs remote search's requester side (§18.4): true on app hosts, false on daemon hosts, the
	// default, whose remote-mode apps reach them and whose own searches stay local, and on page Workers, whose
	// requesters are Later (§5.4). A host without it lists no indexers and refuses SetSearchRemote and
	// AcknowledgeSearchIndexer (§18.7's control row), a reading: §5.4 sets no such field.
	RemoteAsk bool
	// The window RemoteCpuPerMinute is spent over: 1 min, sliding (D-CORE-17).
	RemoteCpuWindow time.Duration
	// The most one computing remote search holds: 8 MiB (D-CORE-17, §11.14's limits row), inside MemoryBudgetByteCount.
	RemoteSearchMemoryByteCount int64
	// How often a designated daemon checks its designation besides at each config entry, for an authority installed
	// after serving began: 10 min, a reading.
	ServeRecheckInterval time.Duration
	// A daemon designated for search's cache bound, which it holds while designated whatever CacheByteCount says: 16
	// GiB (owner decision 175, D-CORE-17).
	DesignatedCacheByteCount int64
	// A daemon designated for search's process budget, which ApplySearchDesignatedSettings raises
	// MemoryBudgetByteCount to: 192 MiB (owner decision 175).
	DesignatedMemoryBudgetByteCount int64
	// The version table's page (§5.9's versions row): 4 KiB, sealed one a file, so a probe decrypts one page.
	VersionPageByteCount int
	// The inputs one pass of the version table's merge holds open at once: 16 (§5.9's versions row).
	VersionMergeInputCount int
	// What one pass of the version table's merge holds in all, its inputs' buffers counted: 1 MiB (§5.9's versions
	// row).
	VersionMergeByteCount int64
}

// Count per Interval, bursting to Burst. All three must be positive, as every number here is, so a
// rate of zero never reads as no limit.
type SidecarRate struct {
	// Events an Interval, the long-run rate.
	Count int
	// Events at once from an idle start.
	Burst int
	// The span Count is over.
	Interval time.Duration
}

// §16.11's team directory, in team networks. Its renewal and expiry times are format values that
// every reader applies alike (§16.11), not settings.
type SidecarDirectorySettings struct {
	// How often cards sync while the daemon serves a harness session in the network: 15 min (§16.11).
	SessionSyncInterval time.Duration
	// How often they sync otherwise: 1 h (§16.11).
	IdleSyncInterval time.Duration
	// A sync at each directory search or view, coalesced over this: 30 s (§16.11).
	ViewCoalesce time.Duration
	// Cards a metered session on phones, which keep cards only while the view is open: 8 MiB (§16.11).
	PhoneMeteredByteCount int64
	// ±this on hourly run renewals, so a team's cards do not renew together: 5 min (§16.11).
	RenewJitter time.Duration
}

// §13.8's device key and the self-signed leaf a device presents until §13 issues it (§15.5, §11.11). The
// tls component's, declared on every leg so that SidecarSettings is one shape everywhere; the
// sidecar_http leg runs no tls component and reads none of it (§18.10).
type SidecarTlsSettings struct {
	// How long a device key serves before TlsKeyRotationDue answers true and a successor is ordered:
	// 180 days (§13.8). The old key serves until its successor's certificate installs.
	KeyRotationInterval time.Duration
	// How long a self-signed leaf is valid: 30 days, a reading, since §13.8 and §15.5 set none. Past
	// half of it the next call makes a new one on the same key, which TlsCertificateFingerprint
	// answers alike, since that pins the key.
	SelfSignedLifetime time.Duration
	// How far before its making a self-signed leaf's validity starts, so a peer whose clock runs
	// behind accepts it: 1 h, a reading.
	SelfSignedBackdate time.Duration

	// The certificate manager's (TLS-M5-18, tls_cert_manager.go).
	//
	// The url a certificate order's service token names as its audience, https://certs.<domain> (§7.8): absolute,
	// with no path. No default, since no hostname sits in code; empty orders nothing, and EnsureTlsCertificate
	// answers ErrTlsCertsUnconfigured. The routes themselves are api's, at ApiUrl.
	CertsResource string
	// How long the manager goes without reading GET /tls/certs when no hint asks: 1 h, §6.8's resync, which covers a
	// lost TlsHint.
	CertResyncInterval time.Duration
	// The least time between two reads hints ask for, so a burst of hints costs one read: 1 s.
	CertHintMinInterval time.Duration
	// How long to wait before asking GET /tls/cert-order/<id> again when its answer names no wait: 5 s.
	CertOrderPollInterval time.Duration
	// The bounds a server's retry_after is held to: 1 s, so a zero or tiny wait cannot spin, and 5 min, so a wrong
	// one cannot park an order past a person's patience.
	CertOrderPollMinInterval time.Duration
	CertOrderPollMaxInterval time.Duration
	// How long an order the background pass placed stays the open one before another is placed for the same key and
	// names: 24 h, past certs' longest hold for a set (§13.8's 34 h refill is the server's to wait out, and the row
	// it wrote first answers a second order with the same CSR).
	CertOrderOpenTimeout time.Duration
	// The wait after an order's refusal or failure before the background pass tries that name again, doubling from
	// the first to the second: 1 min to 1 h. A person's EnsureTlsCertificate does not wait on it.
	CertRetryMinInterval time.Duration
	CertRetryMaxInterval time.Duration
	// The most certificates a chain may hold, leaf first: 8 (DESIGN-DETAILS 17.2.15's ChainMaxCount).
	CertChainMaxCount int
	// The most bytes the chains and orders the manager keeps may take in its store: 1 MiB, some hundreds of chains.
	// Past it nothing new installs, the closed direction.
	CertStateMaxByteCount int
}

// §5.5's agent subkeys (identity_agent.go): each agent registration's Ed25519 subkey, which the daemon holds and
// signs sealed provenance with, under a certificate its identity key signs (QD-159).
type SidecarAgentSubkeySettings struct {
	// How long a new subkey's certificate runs: 30 days, §5.5's v1 most. A value past MaxLifetime mints at
	// MaxLifetime.
	Lifetime time.Duration
	// The format's bound, which signer and reader share: a certificate runs at most 30 days (§5.5), so a reader
	// attributes nothing to one whose not_after lies further than this past the entry it rides in, whatever its
	// signature (QD-159). Changing it is a format change, so no deployment changes it on one side alone.
	MaxLifetime time.Duration
	// A subkey with less than this left is replaced by a new one, under a new certificate, at its next use: 1 day, a
	// reading, so a run that spans the old one's end never signs with it past its not_after.
	RenewBefore time.Duration
}

// A fresh value each call.
func DefaultSidecarAgentSubkeySettings() *SidecarAgentSubkeySettings {
	return &SidecarAgentSubkeySettings{
		Lifetime:    30 * 24 * time.Hour,
		MaxLifetime: 30 * 24 * time.Hour,
		RenewBefore: 24 * time.Hour,
	}
}

// A fresh value each call.
func DefaultSidecarTlsSettings() *SidecarTlsSettings {
	return &SidecarTlsSettings{
		KeyRotationInterval: 180 * 24 * time.Hour,
		SelfSignedLifetime:  30 * 24 * time.Hour,
		SelfSignedBackdate:  1 * time.Hour,

		CertResyncInterval:       time.Hour,
		CertHintMinInterval:      time.Second,
		CertOrderPollInterval:    5 * time.Second,
		CertOrderPollMinInterval: time.Second,
		CertOrderPollMaxInterval: 5 * time.Minute,
		CertOrderOpenTimeout:     24 * time.Hour,
		CertRetryMinInterval:     time.Minute,
		CertRetryMaxInterval:     time.Hour,
		CertChainMaxCount:        8,
		CertStateMaxByteCount:    1024 * 1024,
	}
}

// §10's client (KEYS-M2-18): its calls to gkm, its hint intake and its key upkeep. Format values every reader
// applies alike stay constants beside their formats: a ReaderKey's 7-day bound (GkmReaderKeyLifetime), gkm's 10
// minutes of skew (GkmClockSkew) and a token's 64 repo scopes (§7.8).
type GkmSettings struct {
	// The longest one call to gkm takes: 30 s, inside the lb's 60 s idle bound, past gkm's 20 s for a wrap batch
	// (QD-066).
	RequestTimeout time.Duration
	// How many times a read retries a 429 or a 503, each after its Retry-After: 3. A write never retries here, since
	// each flow resolves its own unknown outcome.
	ReadRetryCount int
	// The longest Retry-After a read waits out before giving up with the refusal: 30 s.
	ReadRetryMaxWait time.Duration
	// The wait before a retry when gkm names none: 1 s.
	ReadRetryWait time.Duration
	// The most one answer may hold: 16 MiB, past an epochs page carrying a 1,000-leaf group's sealed GroupInfo of
	// about 2.8 MB (§10.6's sizes).
	ReplyMaxByteCount int64
	// How often every hint handler refetches whatever its hints would have told it, so a lost hint costs at most
	// this: 1 h (§6.8's hourly resync).
	ResyncInterval time.Duration
	// The wakes the hint intake holds pending, coalesced by kind and group: 4,096. Past it a new one is dropped and
	// a resync asked for instead.
	HintPendingCount int
	// How often key upkeep checks what is due: 1 h, besides each resync and each refill a hint asks for.
	UpkeepInterval time.Duration
	// D-KEYS-25: a ReaderKey is replaced by a fresh pair once it is this old: 6 days.
	ReaderKeyReplaceAge time.Duration
	// D-KEYS-25: a new ReaderKey's not_after after its signing: 7 days, at most GkmReaderKeyLifetime and past
	// ReaderKeyReplaceAge, so one key is always valid.
	ReaderKeyLifetime time.Duration
	// D-KEYS-25: a replaced or lapsed private key is kept this long past its not_after, for what was sealed to it:
	// 30 days.
	ReaderKeyKeepAfterNotAfter time.Duration
	// How often a sidecar reads its own ReaderKey back from gkm to compare it with those it signed: 24 h
	// (g0-recheck-0-readerkey-forgery #2).
	ReaderKeySelfCheckInterval time.Duration
	// §10.6's KeyPackages row: the one-time KeyPackages a full set holds at gkm, 128.
	KeyPackageCount int
	// The same row's refill point: 32, below which gkm hints key-packages-low and a refill brings the set back to
	// KeyPackageCount.
	KeyPackageLowCount int
	// A full set of one-time KeyPackages goes up again this long after the last upload: 90 days, a KeyPackage's
	// life, so every one uploaded before has lapsed and gkm takes the whole set.
	KeyPackageRenewAge time.Duration
	// A new last-resort KeyPackage goes up this long after the last: 60 days, well inside its 90, so one is always
	// valid.
	KeyPackageLastResortRenewAge time.Duration
	// A renewal gkm refused past its count is tried again this much later: 1 h.
	KeyPackageRetryInterval time.Duration
	// §10.6's ack row: a leaf acks a group at most this often: 24 h.
	AckInterval time.Duration
	// §10.6's late wraps: a recipient asks for a late delivery of one generation at most this often: 1 min.
	LateAskInterval time.Duration
	// QD-031 (decided): a GenRotate's drop key lives this long, drop_not_after_ms = time_ms + this: 90 days.
	DropKeyLifetime time.Duration
	// KF2 and KF3 (DESIGN-DETAILS 6.2.2): a writer leaf that did not sign the statement a pending change answers
	// waits this long before it commits it, so the granting device normally commits alone: 15 s.
	PendingCommitDelay time.Duration
	// The most a writer adds to PendingCommitDelay, drawn uniformly, so the others do not all commit at once: 5 s.
	PendingCommitJitter time.Duration
	// §10.6's re-add: a joiner whose Welcome has not appeared this long after its epoch is removed and added again
	// by a writer leaf: 10 min. A writer leaf that adopted the Add from another leaf's commit asks gkm once, this
	// long after the epoch, whether the Welcome stands (QD-747). Non-positive asks at the next run of the engine.
	WelcomeTimeout time.Duration
	// QD-747: the most Adds of other leaves' commits whose Welcomes a device watches for at once, per repo: 64, far
	// past the Adds ten minutes bring one group. Past it the oldest is dropped unasked, which leaves its joiners
	// waiting on their uploader; non-positive watches none.
	WelcomeWatchMaxCount int
	// A writer leaf commits a stale Remove only this long past §10.9's stale rule (plan-KEYS-stale-remove-evidence):
	// 24 h, so two clocks a minute apart do not disagree on it. Every committer follows it alike, so a deployment
	// never changes it on one device alone.
	StaleRemoveMargin time.Duration
	// §10.6: at most this many leaves, an epoch's object carries its sealed GroupInfo inline, and above, group-info
	// holds it: 16, the protocol's value, which gkm's EpochGroupInfoMaxByteCount is sized to.
	GroupInfoInlineLeafCount int
	// §10.14's bound on one POST /gkm/reader-keys (QD-066): 256 ids, the protocol's value, which gkm holds too.
	// Below 1 sends one id a request.
	ReaderKeysBatchCount int
	// The bound on one POST /gkm/delegation-keys (QD-637): 256 ids, reader-keys' own and gkm's
	// DelegationKeysMaxCount. Below 1 sends one id a request.
	DelegationKeysBatchCount int
	// §10.6's late wraps: a holder waits a random time up to this before it answers wrap-pending, so one normally
	// delivers: 15 s.
	LateDeliverJitter time.Duration
	// §10.4: a leaf that committed no path this long commits a path-only self-update: 7 days.
	SelfUpdateInterval time.Duration
	// The same above LargeGroupLeafCount leaves: 30 days.
	SelfUpdateIntervalLarge time.Duration
	// The leaf count above which SelfUpdateIntervalLarge applies: 50.
	LargeGroupLeafCount int
	// §10.5's SCHEDULE: a writer rotates a generation older than this: 30 days.
	ScheduleInterval time.Duration
	// KF5: a device at most this many epochs behind processes each in order, and one further behind resyncs: 100.
	ResyncReplayMax int
	// QD-066: the deliveries one staging request carries: 256, gkm's bound.
	RotateBatchSize int
	// How many staging requests of one rotation run at once: 4.
	RotateBatchConcurrency int
	// How many times one staging request is sent while gkm answers some delivery with no result: 3.
	RotateStageSendCount int
	// How many times a claim whose answer was lost is sent again with the same bytes, each after gen/ showed
	// nothing there: 3.
	RotateClaimSendCount int
	// How many generations one rotation may start, each after losing the claim before to a winner that does not
	// cover what it rotates for or is poisoned: 4.
	RotatePassCount int
	// §8.12: the most leaves a committer seats in a data repo's tree: 1,000, never past MLS's bound
	// (GkmSeatCount), which every member holds alike.
	SeatCount int
	// How many times one run of the pending engine commits again after losing an epoch to another's commit (KF6): 4.
	PendingPassCount int
	// How many times a commit, or a group's creation, whose answer was lost is sent again with the same bytes: 3.
	CommitSendCount int
	// KF1: how many group ids a creation draws while each is another repo's at the owner marker: 4. Ids are 16
	// random bytes, so a second draw means a squatter.
	CreateGroupDrawCount int
}

// The desktop daemon's gkm settings, the only source of their defaults.
func DefaultGkmSettings() *GkmSettings {
	return &GkmSettings{
		RequestTimeout:               30 * time.Second,
		ReadRetryCount:               3,
		ReadRetryMaxWait:             30 * time.Second,
		ReadRetryWait:                1 * time.Second,
		ReplyMaxByteCount:            16 * 1024 * 1024,
		ResyncInterval:               1 * time.Hour,
		HintPendingCount:             4096,
		UpkeepInterval:               1 * time.Hour,
		ReaderKeyReplaceAge:          6 * 24 * time.Hour,
		ReaderKeyLifetime:            7 * 24 * time.Hour,
		ReaderKeyKeepAfterNotAfter:   30 * 24 * time.Hour,
		ReaderKeySelfCheckInterval:   24 * time.Hour,
		KeyPackageCount:              128,
		KeyPackageLowCount:           32,
		KeyPackageRenewAge:           90 * 24 * time.Hour,
		KeyPackageLastResortRenewAge: 60 * 24 * time.Hour,
		KeyPackageRetryInterval:      1 * time.Hour,
		AckInterval:                  24 * time.Hour,
		LateAskInterval:              1 * time.Minute,
		DropKeyLifetime:              90 * 24 * time.Hour,
		PendingCommitDelay:           15 * time.Second,
		PendingCommitJitter:          5 * time.Second,
		WelcomeTimeout:               10 * time.Minute,
		WelcomeWatchMaxCount:         64,
		StaleRemoveMargin:            24 * time.Hour,
		GroupInfoInlineLeafCount:     16,
		ReaderKeysBatchCount:         256,
		DelegationKeysBatchCount:     256,
		LateDeliverJitter:            15 * time.Second,
		SelfUpdateInterval:           7 * 24 * time.Hour,
		SelfUpdateIntervalLarge:      30 * 24 * time.Hour,
		LargeGroupLeafCount:          50,
		ScheduleInterval:             30 * 24 * time.Hour,
		ResyncReplayMax:              100,
		RotateBatchSize:              256,
		RotateBatchConcurrency:       4,
		RotateStageSendCount:         3,
		RotateClaimSendCount:         3,
		RotatePassCount:              4,
		SeatCount:                    1000,
		PendingPassCount:             4,
		CommitSendCount:              3,
		CreateGroupDrawCount:         4,
	}
}

// What the walk of numbers cannot hold: a ReaderKey valid at most GkmReaderKeyLifetime and replaced before it lapses
// (D-KEYS-25), a refill point inside the full count, and a last-resort renewed before the set's renewal.
func (self *GkmSettings) validate() error {
	switch {
	case GkmReaderKeyLifetime < self.ReaderKeyLifetime || self.ReaderKeyLifetime <= self.ReaderKeyReplaceAge:
		return fmt.Errorf("%w: Gkm.ReaderKeyLifetime past §10.5's bound or not past its replacement", errInvalidSettings)
	case self.KeyPackageCount < self.KeyPackageLowCount:
		return fmt.Errorf("%w: Gkm.KeyPackageLowCount past the full count", errInvalidSettings)
	case self.KeyPackageRenewAge <= self.KeyPackageLastResortRenewAge:
		return fmt.Errorf("%w: Gkm.KeyPackageLastResortRenewAge not before the set's renewal", errInvalidSettings)
	case GkmSeatCount < self.SeatCount:
		return fmt.Errorf("%w: Gkm.SeatCount past a tree's 1,000 leaves", errInvalidSettings)
	case gkmWrapBatchMaxCount < self.RotateBatchSize:
		return fmt.Errorf("%w: Gkm.RotateBatchSize past gkm's 256 a request", errInvalidSettings)
	}
	return nil
}

// §9.5's registrar (socket_registrar.go): when it renews the client's leases, when it reports load between renewals,
// and how it waits after a refusal. §9.5 sets the heartbeat, its jitter and the eager report; the call's timeout and
// the waits after a failure are readings, each with its reason. A page's 1,024 entries is §9.5's format limit
// (SocketRegistrationPageMaxEntryCount), and K_sock's 10 min overlap the ring's (SocketKeyRingSettings), so neither
// is here. The tls component's sibling: declared on every leg so that SidecarSettings is one shape everywhere, and
// read only where a component runs.
type SidecarSocketSettings struct {
	// How often the whole set renews its 45 s leases: 15 s (§9.5, D-SOCK-3), so two lost heartbeats still leave each
	// lease standing.
	HeartbeatInterval time.Duration
	// ±this fraction, drawn uniformly, on each heartbeat and each wait after a failure: 0.2, §9.5's ±20%, so clients
	// that started together spread out. Below 1, so no wait reaches zero.
	Jitter float64
	// The least time from one eager load report to the next: 2 s (§9.5).
	EagerReportInterval time.Duration
	// An entry reports its in-flight count early once the count has moved from what the service last saw by at least
	// this many streams: 8, §9.5's max(8, ...).
	EagerReportMinMove int
	// ...and by at least this fraction of the entry's max_streams: 0.25, §9.5's 25%. At most 1.
	EagerReportMoveFraction float64
	// The longest one registrations call may take: 10 s, a reading: inside one heartbeat, so a call that hangs costs
	// no lease, and far past what a page of 1,024 entries needs.
	RequestTimeout time.Duration
	// The first wait after a failed call that names no retry_after_ms: 1 s, a reading, doubling with each failure in
	// a row.
	RetryInterval time.Duration
	// Where that doubling stops: 15 s, a reading, one heartbeat, so a failing service sees no more calls from a
	// client than a healthy one, and a 45 s lease outlasts two failures in a row.
	RetryMaxInterval time.Duration
	// The longest retry_after_ms the registrar waits out before it calls again: 5 min, a reading: §2.8's sock-5 keeps
	// a client's set 5 min after its last call, so a longer wait gains nothing that starting over does not, and a
	// bogus hint cannot silence the registrar for days.
	RetryAfterMaxWait time.Duration
	// How long one ticket's open waits for its listener's accept, Hello included, when a Dial names none: 5 s (§9.6,
	// D-SOCK-6), after which the next ticket is tried.
	DialAcceptTimeout time.Duration
	// The most Finds one Dial sends, the first included: 3 (§9.6, D-SOCK-6).
	DialFindCount int
	// The wait before a Find after one whose tickets or answer were busy: 250 ms, a reading, doubling with each busy
	// Find, drawn within ±Jitter, and never less than the service's retry_after_ms.
	DialBusyBackoff time.Duration
	// Where that doubling stops: 2 s, a reading, so three Finds stay well inside a caller's patience.
	DialBusyBackoffMax time.Duration
	// The longest quota retry_after_ms a dialer waits out before its next ticket: 30 s, a reading, so a listener's
	// answer cannot hold a Dial for longer than a person would wait.
	DialQuotaMaxWait time.Duration
	// How long Drain waits for a listener's in-flight streams to end before it resets the rest with RST_DRAINING:
	// 30 s (§9.5, cloudflared's default), unless the caller's ctx ends first.
	ListenDrainTimeout time.Duration
	// How long admission waits for this device's verified state to reach a ticket's log position before it answers
	// retry (§9.6's step 6): 2 s, a reading, inside the dialer's 5 s accept timeout so the dialer still has time for
	// its backup.
	ListenPositionWait time.Duration
	// The daemon's forwards: ur socket listen and ur socket dial (§9.9; daemon_socket.go).
	Forward *SidecarSocketForwardSettings
	// ur share (§9.9, D-SOCK-16; socket_share.go).
	Share *SidecarShareSettings
}

// The daemon's socket forwards (§9.9; daemon_socket.go): a listen forward's local target, which sets serving, and the
// listings `ur socket ls` reads. Every value is a reading: §9.9 names the behavior and no number.
type SidecarSocketForwardSettings struct {
	// How long one dial of a listen forward's local target may take before it counts as refusing: 2 s, a local
	// connect, which answers at once or not at all.
	TargetDialTimeout time.Duration
	// How often a listen forward whose local target refused dials it again, to take tickets once it answers: 2 s, as
	// often as §9.5's eager report may tell the service.
	TargetProbeInterval time.Duration
	// The most GET /socket/list pages one listing reads: 1,024 pages of the service's 1,024 names, each page one
	// token of the caller's bucket, after which the listing says it stopped short.
	ListPageMaxCount int
	// The bytes one splice copies at a time in each direction: 32 KiB, io.Copy's own buffer.
	SpliceBufferByteCount int
}

// ur share (§9.9, D-SOCK-16; socket_share.go): what a share may be asked for, and the sharer's waits on a getter.
type SidecarShareSettings struct {
	// --expires when a share names none: 24 h (§9.9).
	ExpiresDefault time.Duration
	// The longest --expires a share takes: 30 days, the longest ordinary grant (owner decision 74), so every share
	// ends. Longer is refused.
	ExpiresMax time.Duration
	// How long a sharer waits for a getter's header once its stream is admitted: 10 s, a reading, so a stream that
	// never speaks holds nothing.
	HeaderTimeout time.Duration
	// How long a sharer waits for a getter's done once the last byte is sent: 30 s, a reading, past a slow getter's
	// whole-file SHA-256.
	DoneTimeout time.Duration
	// The bytes a sharer reads of the file and a getter hashes at a time: 64 KiB, a reading.
	ChunkByteCount int
	// How long the daemon waits before it tries again to load and serve a network's shares while its store is locked
	// or its sockets cannot listen: 30 s, a reading, so a share comes back soon after an unlock or a reconnect.
	ResumeInterval time.Duration
}

// The desktop daemon's registrar settings, the only source of their defaults.
func DefaultSidecarSocketSettings() *SidecarSocketSettings {
	return &SidecarSocketSettings{
		HeartbeatInterval:       15 * time.Second,
		Jitter:                  0.2,
		EagerReportInterval:     2 * time.Second,
		EagerReportMinMove:      8,
		EagerReportMoveFraction: 0.25,
		RequestTimeout:          10 * time.Second,
		RetryInterval:           1 * time.Second,
		RetryMaxInterval:        15 * time.Second,
		RetryAfterMaxWait:       5 * time.Minute,
		DialAcceptTimeout:       5 * time.Second,
		DialFindCount:           3,
		DialBusyBackoff:         250 * time.Millisecond,
		DialBusyBackoffMax:      2 * time.Second,
		DialQuotaMaxWait:        30 * time.Second,
		ListenDrainTimeout:      30 * time.Second,
		ListenPositionWait:      2 * time.Second,
		Forward: &SidecarSocketForwardSettings{
			TargetDialTimeout:     2 * time.Second,
			TargetProbeInterval:   2 * time.Second,
			ListPageMaxCount:      1024,
			SpliceBufferByteCount: 32 * 1024,
		},
		Share: &SidecarShareSettings{
			ExpiresDefault: 24 * time.Hour,
			ExpiresMax:     30 * 24 * time.Hour,
			HeaderTimeout:  10 * time.Second,
			DoneTimeout:    30 * time.Second,
			ChunkByteCount: 64 * 1024,
			ResumeInterval: 30 * time.Second,
		},
	}
}

// What the walk of numbers cannot hold: a jitter that never takes a wait to zero, a move fraction no larger than the
// whole, and a backoff that starts at or below where it stops.
func (self *SidecarSocketSettings) validate() error {
	switch {
	case 1 <= self.Jitter:
		return fmt.Errorf("%w: Sockets.Jitter is not below 1", errInvalidSettings)
	case 1 < self.EagerReportMoveFraction:
		return fmt.Errorf("%w: Sockets.EagerReportMoveFraction is past 1", errInvalidSettings)
	case self.RetryMaxInterval < self.RetryInterval:
		return fmt.Errorf("%w: Sockets.RetryInterval is past RetryMaxInterval", errInvalidSettings)
	case self.DialBusyBackoffMax < self.DialBusyBackoff:
		return fmt.Errorf("%w: Sockets.DialBusyBackoff is past DialBusyBackoffMax", errInvalidSettings)
	case self.Share != nil && self.Share.ExpiresMax < self.Share.ExpiresDefault:
		return fmt.Errorf("%w: Sockets.Share.ExpiresDefault is past ExpiresMax", errInvalidSettings)
	}
	return nil
}

// A fresh value each call, sharing nothing mutable with any other (connect/CODESTYLE.md:151). The pass's Argon2id cost
// is the leg's (defaultSidecarPassCost).
func DefaultSidecarSettings() *SidecarSettings {
	passMemoryByteCount, passIterationCount, passThreadCount := defaultSidecarPassCost()
	return &SidecarSettings{
		Instance:   "default",
		AppVersion: Version,

		Connect:          defaultSidecarConnectSettings(),
		ProtocolSettings: DefaultSidecarProtocolSettings(),
		TokenRefreshSettings: &SidecarTokenRefreshSettings{
			RefreshWindowStart:         0.4,
			RefreshWindowEnd:           0.5,
			MinRefreshTimeout:          5 * time.Minute,
			RefreshRetryTimeout:        15 * time.Minute,
			NoExpirationRefreshTimeout: 7 * 24 * time.Hour,
			ServiceTokenCacheTimeout:   10 * time.Minute,
		},
		KeychainSettings: &SidecarKeychainSettings{
			PassMemoryByteCount: passMemoryByteCount,
			PassIterationCount:  passIterationCount,
			PassThreadCount:     passThreadCount,
			PassAttemptCount:    5,
			PassAttemptInterval: 10 * time.Minute,
			AutoLockTimeout:     10 * time.Minute,
		},
		LocalSettings: &SidecarLocalSettings{
			IdleExitTimeout:        10 * time.Minute,
			RequestByteCount:       4 * 1024 * 1024,
			RequestTimeout:         30 * time.Second,
			FirstPort:              17000,
			HelloByteCount:         16 * 1024,
			SessionBufferByteCount: 4 * 1024,
		},
		Mcp:    defaultSidecarMcpSettings(),
		Ingest: defaultSidecarIngestSettings(),
		Record: defaultSidecarRecordSettings(),
		Search: &SidecarSearchSettings{
			CacheByteCount:         4 * 1024 * 1024 * 1024,
			MemoryByteCount:        64 * 1024 * 1024,
			VersionCacheByteCount:  256 * 1024,
			BackgroundByteCount:    1024 * 1024 * 1024,
			MoreByteCount:          1024 * 1024 * 1024,
			AllPolicy:              "background",
			HintCoalesce:           1 * time.Minute,
			CursorTimeout:          10 * time.Minute,
			HeadRefreshInterval:    10 * time.Minute,
			NonWriterSyncInterval:  15 * time.Minute,
			SessionSearchCount:     2,
			SessionSearchRate:      SidecarRate{Count: 5, Burst: 10, Interval: 1 * time.Second},
			SessionCursorCount:     16,
			DaemonSearchCount:      4,
			PageCpu:                2 * time.Second,
			PageCandidateCount:     1000,
			TooBroadCandidateCount: 20000,
			PageByteCount:          64 * 1024,
			RemoteMode:             "on",
			RemoteTimeout:          [2]time.Duration{3 * time.Second, 5 * time.Second},
			RemoteServe:            true,
			RemoteSearchCount:      4,
			RemoteQueueCount:       16,
			RemoteQueueTimeout:     1 * time.Second,
			RemoteCpuPerMinute:     30 * time.Second,
			RemoteCursorCount:      64,
			RemoteRequesterRate:    SidecarRate{Count: 30, Burst: 10, Interval: 1 * time.Minute},
			ServedRecordTimeout:    30 * 24 * time.Hour,
			ServedRecordCount:      8192,
			RemoteServedTimeout:    24 * time.Hour,
			StateByteCount:         4 * 1024 * 1024,
			PageHitCount:           50,

			RemoteCpuWindow:                 1 * time.Minute,
			RemoteSearchMemoryByteCount:     8 * 1024 * 1024,
			ServeRecheckInterval:            10 * time.Minute,
			DesignatedCacheByteCount:        16 * 1024 * 1024 * 1024,
			DesignatedMemoryBudgetByteCount: 192 * 1024 * 1024,
			VersionPageByteCount:            4 * 1024,
			VersionMergeInputCount:          16,
			VersionMergeByteCount:           1024 * 1024,
		},
		Directory: &SidecarDirectorySettings{
			SessionSyncInterval:   15 * time.Minute,
			IdleSyncInterval:      1 * time.Hour,
			ViewCoalesce:          30 * time.Second,
			PhoneMeteredByteCount: 8 * 1024 * 1024,
			RenewJitter:           5 * time.Minute,
		},
		Evs:     DefaultEvsSettings(),
		Tls:     DefaultSidecarTlsSettings(),
		Gkm:     DefaultGkmSettings(),
		Sockets: DefaultSidecarSocketSettings(),

		AgentSubkeys: DefaultSidecarAgentSubkeySettings(),

		ComponentQueueMessageCount: 256,
		ComponentQueueByteCount:    1024 * 1024,
		MemoryBudgetByteCount:      128 * 1024 * 1024,
		StreamChunkByteCount:       4000,
		ApiResponseByteCount:       2 * 1024 * 1024,
		ApiClockMaxRoundTrip:       30 * time.Second,
		ApiClockRetryShift:         5 * time.Second,
		StatementTimeout:           7 * 24 * time.Hour,
	}
}
