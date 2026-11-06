// A Sidecar's settings, on every leg. DefaultSidecarSettings is the only source of a default (§5.10;
// connect/CODESTYLE.md:144): hosts adjust what it returns per class, as sdk's
// applyMobileLowMemoryClientSettings does for connect (§18.4), and keep no second copy of a number.
// Defaults here are the desktop daemon's. A field's comment gives a mobile value after a semicolon
// where the design sets one, for the host that applies it.
//
// Format values that every reader applies alike are constants beside their formats, not settings
// (connect/CODESTYLE.md:145). settings_connect.go and settings_http.go declare the connect settings
// per leg, settings_protocol.go §6's, and settings_mcp.go §16's.

package sidecar

import (
	"time"
)

type SidecarSettings struct {
	// The instance name (§5.9): [a-z0-9][a-z0-9-]{0,31}. Default "default". A host reads UR_INSTANCE
	// or --instance and sets it here.
	Instance string
	// Service urls, with no trailing slash. None has a default yet, so each host sets its
	// environment's, and empty means the service is not configured: a dial of it fails. §5.4 has
	// EvsUrl, GkmUrl, SocketsUrl and DnsUrl default from §19.4, which waits on whether a production
	// hostname may sit in code.
	ApiUrl      string
	PlatformUrl string
	AuthUrl     string
	EvsUrl      string
	GkmUrl      string
	SocketsUrl  string
	DnsUrl      string
	// What a client reports as its version. Default Version, which is empty in a development build.
	AppVersion string

	// Client generations, empty on the sidecar_http leg.
	Connect          *SidecarConnectSettings
	ProtocolSettings *SidecarProtocolSettings
	// sdk's schedule (sdk/device_token_manager.go:20-27, :266-275), which D-CORE-8's refresher
	// repeats, since sdk is not importable here.
	TokenRefreshSettings *SidecarTokenRefreshSettings
	KeychainSettings     *SidecarKeychainSettings
	LocalSettings        *SidecarLocalSettings
	Mcp                  *SidecarMcpSettings
	Ingest               *SidecarIngestSettings
	Record               *SidecarRecordSettings
	Search               *SidecarSearchSettings
	Directory            *SidecarDirectorySettings

	// Envelopes one component's queue holds. Complete envelopes wait here without blocking the
	// inline handler, and a full queue drops and counts (§5.4; connect/CODESTYLE.md:119). Default
	// 256, the design sets no number. Non-positive drops everything.
	ComponentQueueMessageCount int
	// Bytes one component's queue holds: 1 MiB, 256 envelopes of the 4,080 B maximum in their 4 KiB
	// pool class. Non-positive drops everything.
	ComponentQueueByteCount int
	// The process's whole budget, §6's process-wide reassembly, idempotency and credit caps and
	// Search.MemoryByteCount inside it: 128 MiB on a desktop or CLI daemon (§18.4), which a host
	// raises to 192 MiB on a daemon designated for search (owner decision 175); iOS 32 MiB, Android
	// 16 MiB added. A cap that would pass it answers RESOURCE_EXHAUSTED.
	MemoryBudgetByteCount int64
	// The most stream data one StreamData message carries: 4,000 B, the format's limit (§6.5). A
	// positive value above it is refused by peers.
	StreamChunkByteCount int

	// nil: connect's default logger, glog, on connect legs (adapted, log_connect.go); no logging at
	// all on the sidecar_http leg.
	Log Logger
}

// sdk's refresh schedule (§5.4). A token refreshes at a point of its lifetime drawn from the window
// by its jti, so clients spread out and one token's point never moves.
type SidecarTokenRefreshSettings struct {
	// The window's start, as a fraction of the token's lifetime: 0.4.
	RefreshWindowStart float64
	// The window's end: 0.5, the half-life, which no token's point passes. At or below
	// RefreshWindowStart every token refreshes at the window's start.
	RefreshWindowEnd float64
	// The least time from one attempt to the next scheduled one, so a server-set lifetime can never
	// make a hot loop: 5 min. Non-positive is for tests only.
	MinRefreshTimeout time.Duration
	// After a failed refresh the next attempt waits a uniform draw from [0, this): 15 min, which
	// spreads clients that failed together. Non-positive is for tests only.
	RefreshRetryTimeout time.Duration
}

// The pass's Argon2id cost (§5.9) and the rules around it. Opening a keychain reads the parameters
// stored beside its wrap, so changing these moves only new wraps.
type SidecarKeychainSettings struct {
	// Argon2id memory: 64 MiB (RFC 9106 §4); 19 MiB on mobile and wasm (OWASP).
	PassMemoryByteCount int64
	// Argon2id passes: t=3; 2 on mobile and wasm.
	PassIterationCount int
	// Argon2id lanes: p=4; 1 on mobile and wasm.
	PassThreadCount int
	// A wrong pass is refused past this many attempts in an interval: 5.
	PassAttemptCount int
	// That interval: 10 min.
	PassAttemptInterval time.Duration
	// Idle time before an unlocked keychain locks. Non-positive never locks, the default: §5.4 names
	// the setting and no value, and an unattended daemon must keep serving.
	AutoLockTimeout time.Duration
}

// The daemon's local IPC (§5.8). §5.4 names sockets, idle exit and a request bound without values.
type SidecarLocalSettings struct {
	// The control socket or pipe. Empty: §5.9's per-platform path for the instance.
	SocketPath string
	// A sandboxed desktop app's short-named socket in its app-group container (§5.9). Empty: none.
	AppGroupSocketPath string
	// How long an auto-spawned daemon with nothing to serve waits before it exits: 10 min, so a run
	// of `ur` commands reuses one daemon. Non-positive never exits. A unit-run daemon and one that
	// mail, sockets, bridge or an indexer keeps busy never idle out (§5.8).
	IdleExitTimeout time.Duration
	// The most one local request may hold: 4 MiB, above §16.7's 1 MiB body once JSON escapes it. A
	// larger one closes its session. Non-positive refuses every request.
	RequestByteCount int64
	// How long a local request may run: 30 s, §16.4's call timeout. Non-positive never times out.
	RequestTimeout time.Duration
}

// §16.10's limits, 5.9's cache and §11.14's remote search. A daemon designated for search (§7.9)
// applies CacheByteCount 16 GiB and MemoryBudgetByteCount 192 MiB (owner decision 175).
type SidecarSearchSettings struct {
	// The index cache: 4 GiB. 0 keeps it in memory (ephemeral sidecars).
	CacheByteCount int64
	// Decoded index state, inside MemoryBudgetByteCount: 64 MiB; app and page hosts set §18.4's
	// smaller working sets.
	MemoryByteCount int64
	// 5.9's version-table pages a process, inside MemoryByteCount: 256 KiB.
	VersionCacheByteCount int64
	// Sync downloads a day a network: 1 GiB.
	BackgroundByteCount int64
	// Downloads a "search more" call: 1 GiB.
	MoreByteCount int64
	// §18.4's mode for all: background (desktops, indexers), on_demand (ephemeral, cloud).
	AllPolicy string
	// Hints coalesce a repo over this: 1 min.
	HintCoalesce time.Duration
	// Idle time before a local or remote cursor goes: 10 min.
	CursorTimeout time.Duration
	// At most one forced head refresh a repo in this: 10 min.
	HeadRefreshInterval time.Duration
	// A reader that is not a writer syncs an owner-bound index at most this often: 15 min (§16.10's
	// receipts).
	NonWriterSyncInterval time.Duration
	// Searches at once a session: 2.
	SessionSearchCount int
	// Searches a session may start: 5 a second, burst 10.
	SessionSearchRate SidecarRate
	// Open cursors a session, the oldest dropped: 16.
	SessionCursorCount int
	// Local searches at once: 4.
	DaemonSearchCount int
	// CPU a page, local or remote: 2 s.
	PageCpu time.Duration
	// Candidates verified a page: 1,000.
	PageCandidateCount int
	// Candidates in a partition past which it answers too_broad: 20,000.
	TooBroadCandidateCount int
	// MCP results a page: 64 KiB.
	PageByteCount int
	// "on" until the person picks on, own or off (5.9's state).
	RemoteMode string
	// Unmetered, then metered: 3 s and 5 s without a first page, then the next indexer.
	RemoteTimeout [2]time.Duration
	// Answer remote searches once designated: true on daemon hosts; false on app hosts.
	RemoteServe bool
	// Remote searches computing at once, beside DaemonSearchCount: 4.
	RemoteSearchCount int
	// Remote searches waiting, each at most RemoteQueueTimeout, else RESOURCE_EXHAUSTED: 16.
	RemoteQueueCount int
	// 1 s.
	RemoteQueueTimeout time.Duration
	// CPU a minute for all remote work: 30 s.
	RemoteCpuPerMinute time.Duration
	// Open remote cursors, the oldest dropped: 64.
	RemoteCursorCount int
	// Per requester at an indexer, and per indexer at a requester: 30 a minute, burst 10.
	RemoteRequesterRate SidecarRate
	// How long an owner's indexer keeps 5.9's served records: 30 d.
	ServedRecordTimeout time.Duration
}

// Count per Interval, bursting to Burst.
type SidecarRate struct {
	Count    int
	Burst    int
	Interval time.Duration
}

// §16.11's team directory, in team networks. Its renewal and expiry times are format values that
// every reader applies alike (§16.11), not settings.
type SidecarDirectorySettings struct {
	// While the daemon serves a harness session in the network: 15 min.
	SessionSyncInterval time.Duration
	// Otherwise: 1 h.
	IdleSyncInterval time.Duration
	// A sync at each directory search or view, coalesced: 30 s.
	ViewCoalesce time.Duration
	// Cards a metered session on phones, which keep cards only while the view is open: 8 MiB.
	PhoneMeteredByteCount int64
	// ±this on hourly run renewals: 5 min.
	RenewJitter time.Duration
}

// A fresh value each call, sharing nothing mutable with any other (connect/CODESTYLE.md:151).
func DefaultSidecarSettings() *SidecarSettings {
	return &SidecarSettings{
		Instance:   "default",
		AppVersion: Version,

		Connect:          defaultSidecarConnectSettings(),
		ProtocolSettings: defaultSidecarProtocolSettings(),
		TokenRefreshSettings: &SidecarTokenRefreshSettings{
			RefreshWindowStart:  0.4,
			RefreshWindowEnd:    0.5,
			MinRefreshTimeout:   5 * time.Minute,
			RefreshRetryTimeout: 15 * time.Minute,
		},
		KeychainSettings: &SidecarKeychainSettings{
			PassMemoryByteCount: 64 * 1024 * 1024,
			PassIterationCount:  3,
			PassThreadCount:     4,
			PassAttemptCount:    5,
			PassAttemptInterval: 10 * time.Minute,
			AutoLockTimeout:     0,
		},
		LocalSettings: &SidecarLocalSettings{
			IdleExitTimeout:  10 * time.Minute,
			RequestByteCount: 4 * 1024 * 1024,
			RequestTimeout:   30 * time.Second,
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
		},
		Directory: &SidecarDirectorySettings{
			SessionSyncInterval:   15 * time.Minute,
			IdleSyncInterval:      1 * time.Hour,
			ViewCoalesce:          30 * time.Second,
			PhoneMeteredByteCount: 8 * 1024 * 1024,
			RenewJitter:           5 * time.Minute,
		},

		ComponentQueueMessageCount: 256,
		ComponentQueueByteCount:    1024 * 1024,
		MemoryBudgetByteCount:      128 * 1024 * 1024,
		StreamChunkByteCount:       4000,
	}
}
