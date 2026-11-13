// The engine's tunables (connect/CODESTYLE.md:140): DefaultSocketsSettings is the only source of a
// default, and server/cli/sockets lays config/<env>/sidecar.yml's sockets_control_qps over it (§19.11).
// Every limit is a field too, protocol and format limits included (QD-702): §9.5's and §9.6's field sizes
// are Format, the root's SocketFormatSettings, which the client side's settings carry as well, so their
// defaults stay the protocol's in one place. §9.5's 1,024 entries a page and §9.4's name sizes (request.go)
// are still constants until their files move.
//
// Every count and duration must be positive, and Validate refuses anything else, so no zero reads as
// unlimited or off. Nothing here bounds a count of names, listeners or streams (owner decision 66): the
// bounds below protect the service from a byte-free client and charge every network alike (D-SOCK-15).

package socketsservice

import (
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// A settings value the engine cannot run on. The wrapping error names the field.
var ErrSocketsSettingsRefused = errors.New("sockets settings refused")

// What a SocketStore keeps and for how long (§9.5, §9.8). The fake and the Redis store read the same
// values, which is what lets RunSocketStoreSuite hold both to one answer.
type SocketStoreSettings struct {
	// How long a registration lives past its last page: §9.5's 45 s hash-field ttl, three 15 s
	// heartbeats. At or past it the listener takes no tickets, and its streams stay up.
	Lease time.Duration
	// How long a client's set, {sc_<client_id>}set, outlives its last call (§9.8): 5 min.
	ClientSetTtl time.Duration
	// How many listeners a Find filters at most in a group without affinity (§9.7): 64. A larger
	// group is sampled first, which bounds a Find's cost whatever the group's size.
	SampleCount int
	// §9.6 and §9.7's ticket, clamp and ejection values, which a pick reads.
	Scheduler *SocketSchedulerSettings
	// How long a removal for cause, or a client's removal, fences its lease, and a pair removal its pairs
	// (DESIGN-DETAILS 13.2.3): 10 min. It must outlast the longest a sockets process can be stale without
	// knowing it, the gate cache's 5 min poll and one 30 s load, or a stale process's write could land
	// after the fence lapsed.
	TombstoneTtl time.Duration
	// How long an unlisten fences its lease against pages of an older set: 60 s, past any page a client
	// sent before it, since a call that waits longer has timed out.
	UnlistenFenceTtl time.Duration
	// The longest a tls/ or smtp/ pair lives past its listener's last accepted registration (QD-656):
	// 15 min. A Find writes one for the lesser of this and its grant's remaining life, and a registration
	// renews them, so a revoked, removed or dead listener's pairs end within it.
	EdgePairTtl time.Duration
	// How many name keys of a removed client's set one step of RemoveClient takes (§9.8): 1,024, a page's
	// worth, which bounds what one step examines however many names the client held.
	RemoveClientBatchCount int
}

// §9.5's, §9.7's and §9.8's values, with DESIGN-DETAILS 13.2.3's fences.
func DefaultSocketStoreSettings() *SocketStoreSettings {
	return &SocketStoreSettings{
		Lease:                  45 * time.Second,
		ClientSetTtl:           5 * time.Minute,
		SampleCount:            64,
		Scheduler:              DefaultSocketSchedulerSettings(),
		TombstoneTtl:           10 * time.Minute,
		UnlistenFenceTtl:       60 * time.Second,
		EdgePairTtl:            15 * time.Minute,
		RemoveClientBatchCount: 1024,
	}
}

// §9.10's control-plane bound: a token bucket per calling client and process, charged one token per
// Find and per registration page of at most 1,024 entries, and never for a stream or its bytes
// (D-SOCK-15). sockets_control_qps sets the first two; the edge pair replaces them for
// urnetwork-edge callers (§19.5's W2).
type SocketControlBoundSettings struct {
	// Tokens a second a client's bucket refills: 50.
	CallsPerSecond int
	// The most a bucket holds, and what a new client starts with: 500.
	Burst int
	// Tokens a second an urnetwork-edge client refills: W2's 2,000 Finds a second.
	EdgeCallsPerSecond int
	// The most an edge client's bucket holds: W2's burst of 3,000.
	EdgeBurst int
	// How often a charge also drops buckets that have refilled to full, since a full bucket says no
	// more than an absent one: 10 s. This bounds the map by the clients of the last interval, and
	// the sweep's work to one pass an interval.
	SweepInterval time.Duration
}

// §9.10's and §19.5's values.
func DefaultSocketControlBoundSettings() *SocketControlBoundSettings {
	return &SocketControlBoundSettings{
		CallsPerSecond:     50,
		Burst:              500,
		EdgeCallsPerSecond: 2000,
		EdgeBurst:          3000,
		SweepInterval:      10 * time.Second,
	}
}

// §9.10's fair queue: how many calls a process serves at once, and how many may wait in per-network
// fair-share order before the heaviest network is shed.
type SocketFairQueueSettings struct {
	// Calls that run at once in one process. 256: a call holds one Redis round trip or a page's
	// pipeline, and a process past this is saturated.
	Concurrency int
	// Calls that may wait for a turn, across all networks. 4,096. Past it the process is saturated,
	// and the heaviest network's newest waiting call is shed.
	QueueCount int
	// The longest a call waits for its turn before it is shed: 2 s, well inside a dialer's 5 s
	// accept timeout, so a shed call retries on its backup rather than timing out.
	MaxWait time.Duration
}

// §9.10's values for one lb host's process.
func DefaultSocketFairQueueSettings() *SocketFairQueueSettings {
	return &SocketFairQueueSettings{
		Concurrency: 256,
		QueueCount:  4096,
		MaxWait:     2 * time.Second,
	}
}

// The production gate's tunables (gate_projection.go, over_limit.go; DESIGN-DETAILS 13.2.3). The host builds
// SocketProjectionGate from SocketsSettings.Gate.
type SocketGateSettings struct {
	// How long evidence that a network's log passed what this process holds may go uncovered before the network
	// answers unavailable here (13.2.3's GateBehindGrace, QD-655): 5 s, §8.9's target for server gates.
	BehindGrace time.Duration
	// How often a network whose evidence stays uncovered asks the cache for another load: 5 s, the cache's own
	// FailureBackoff. A load that failed, or read a source still short of a position some process verified, is
	// retried by nothing else before §8.9's 5-minute poll.
	BehindReloadInterval time.Duration
	// How many loaded networks one step of the resubscription check reads {acl_}v for: 1,000, 13.2.3's batch.
	ResyncBatchCount int
	// How many of a step's reads run at once: 64. Each is a GET on a slot of its own, since every network's key
	// has its own hash tag and ServiceHost.Redis pipelines nothing across slots.
	ResyncConcurrency int
	// The bound on one {acl_}v read, at a load's start or in the resubscription check: 2 s.
	VersionReadTimeout time.Duration
	// How recently a network must have been served or loaded for the resubscription check to read its {acl_}v: 15 min,
	// three of §8.9's 5-minute polls, which load every network the cache holds, so a network the cache has evicted is
	// not reloaded by a resubscription.
	ResyncUsedWithin time.Duration
	// How many networks the gate follows at most: 100,000, the cache's own UnloadedCount. Past it the quiet networks
	// served or loaded longest ago are let go, some 200 B each, and taken up again at their next ask, load or event.
	MaxNetworkCount int
	// How often §20.7's OverLimit is read again: 5 s (13.2.3's OverLimitInterval).
	OverLimitInterval time.Duration
	// The bound on one read: 2 s (OverLimitTimeout), inside the interval, so a stalled api never stacks reads.
	OverLimitTimeout time.Duration
	// The process's one AclGateCache (C-09): §8.9's 5-minute poll, its load bounds and its byte budget. Its OnLoad
	// is the gate's, which calls any OnLoad set here after its own.
	Cache *sidecar.AclGateSettings
}

// 13.2.3's values, on §8.9's cache.
func DefaultSocketGateSettings() *SocketGateSettings {
	return &SocketGateSettings{
		BehindGrace:          5 * time.Second,
		BehindReloadInterval: 5 * time.Second,
		ResyncBatchCount:     1000,
		ResyncConcurrency:    64,
		VersionReadTimeout:   2 * time.Second,
		ResyncUsedWithin:     15 * time.Minute,
		MaxNetworkCount:      100000,
		OverLimitInterval:    5 * time.Second,
		OverLimitTimeout:     2 * time.Second,
		Cache:                sidecar.DefaultAclGateSettings(),
	}
}

// Whether a gate can run on these. A refusal names the field.
func (self *SocketGateSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no gate settings", ErrSocketsSettingsRefused)
	}
	if self.Cache == nil {
		return fmt.Errorf("%w: no gate cache settings", ErrSocketsSettingsRefused)
	}
	for _, check := range []struct {
		name     string
		positive bool
	}{
		{name: "gate.behind_grace", positive: 0 < self.BehindGrace},
		{name: "gate.behind_reload_interval", positive: 0 < self.BehindReloadInterval},
		{name: "gate.resync_batch_count", positive: 0 < self.ResyncBatchCount},
		{name: "gate.resync_concurrency", positive: 0 < self.ResyncConcurrency},
		{name: "gate.version_read_timeout", positive: 0 < self.VersionReadTimeout},
		{name: "gate.resync_used_within", positive: 0 < self.ResyncUsedWithin},
		{name: "gate.max_network_count", positive: 0 < self.MaxNetworkCount},
		{name: "gate.over_limit_interval", positive: 0 < self.OverLimitInterval},
		{name: "gate.over_limit_timeout", positive: 0 < self.OverLimitTimeout && self.OverLimitTimeout <= self.OverLimitInterval},
	} {
		if !check.positive {
			return fmt.Errorf("%w: %s", ErrSocketsSettingsRefused, check.name)
		}
	}
	return nil
}

// Everything the engine tunes. DefaultSocketsSettings makes one, and NewSocketsService refuses what
// Validate refuses. Read concurrently once built, and never changed after.
type SocketsSettings struct {
	Store     *SocketStoreSettings
	Bound     *SocketControlBoundSettings
	FairQueue *SocketFairQueueSettings
	// The production gate's, which the host builds SocketProjectionGate from; the engine reads none of it.
	Gate *SocketGateSettings
	// The longest a ur/ {svc_} pair lives past its last Find, whatever the grant says (§9.6,
	// plan-SMTP-small-readings' per-service constant): 60 min. A tls/ or smtp/ pair takes the store's
	// EdgePairTtl instead (QD-656).
	PlatformPairTtlMax time.Duration
	// How long one store call may take before it reads as unavailable: 2 s, inside a dialer's 5 s
	// accept timeout.
	StoreTimeout time.Duration
	// How often the engine pings its store to keep its readiness current: 5 s, the cadence §20.7's
	// over-limit snapshot keeps.
	ProbeInterval time.Duration
	// The most milliseconds a refusal asks a caller to wait when the bound or the queue refuses it:
	// 1 s. The bound's own answer is the time to its next token, which this caps.
	MaxRetryAfter time.Duration
	// How long a removed client stays in the removed-client set after its {X}c_removed event (DESIGN-DETAILS
	// 13.2.3): 10 min, past any lease it held, so this process refuses its pages and its leases from memory
	// while RemoveClient's tombstones and its token's revocation take over.
	RemovedClientTtl time.Duration
	// How often, at most, a registration that accepts a client's tls/ or smtp/ entry renews that client's
	// pairs in this process (QD-656): 5 min, a third of EdgePairTtl, so a live listener's pairs never lapse
	// between its heartbeats.
	EdgePairTouchInterval time.Duration
	// How long a pair this process wrote for one listener, listen, dialer and grant expiry stands before a
	// Find writes it again (DESIGN-DETAILS 13.2.3's find step 8): 60 s, so a busy edge writes a pair a minute
	// rather than one a Find.
	PairWriteInterval time.Duration
	// The wait a refusal asks for when this process cannot judge yet: a network unloaded or behind, or a
	// picked lease admitted above the view's position. 250 ms, by when this process has usually loaded.
	BehindRetryAfter time.Duration
	// The wait a page asks for when a newer removal fenced one of its entries: 1 s.
	FencedRetryAfter time.Duration
	// The wait Find's quota refusal asks for: 5 s, the period of §20.7's over-limit snapshot (§9.6's step 3),
	// so a dialer asks again once the answer can have changed.
	QuotaRetryAfter time.Duration
	// How many verified claims the engine remembers (DESIGN-DETAILS 13.2.3's registration step 5), so that a
	// heartbeat checks no signature: 131,072. It bounds memory and never names, since a claim it has
	// forgotten is checked again.
	ClaimMemoCount int
	// How many names one page of GET /socket/list examines: 1,024, a registration page's worth, each page one
	// token of the caller's bucket (SOCK.md reading 10).
	ListPageCount int
	// §9.5's and §9.6's field sizes and defaults, which a page's and a Find's shape checks read: the root's one
	// object, at the protocol's values (QD-702).
	Format *sidecar.SocketFormatSettings
	// The most bytes one registrations call's body holds: 4 MiB, a page of 1,024 entries, each at most a token
	// path, a seal, a claim and the rest in base64 and JSON. A longer body is invalid.
	RegistrationsMaxBodyByteCount int
	// The most bytes one Find's body holds: 64 KiB, two failed tickets, K client ids and the rest in base64 and
	// JSON, many times over. A longer body is invalid.
	FindMaxBodyByteCount int
	// The most client ids an edge's Find names: 64, an edge process's K clients (§13.6's 4 by default) with room.
	FindMaxClientIdCount int

	// The revocation sweep (sweep.go; DESIGN-DETAILS 13.2.3). The least time between two sweeps of one network by
	// this process: 10 s, so a run of revocations costs a network one sweep a period, always at its newest position.
	SweepMinInterval time.Duration
	// How long a sweep's claim on a network and position lives unrenewed: 30 s. The claimer renews it at each page,
	// so a claimer that dies holds no network past it.
	SweepClaimTtl time.Duration
	// How many names one page of a sweep lists: 256, which bounds what one step examines however large the network.
	SweepPageCount int
	// How many networks this process sweeps at once: 4.
	SweepConcurrency int
	// The most refused leases one removal of a sweep takes: 1,024, a page's worth.
	SweepRemoveBatchCount int
	// How long one sweep's store call may take: 10 s, since a group's listener read and a batch's removal are each
	// one call that may span many listeners.
	SweepStoreTimeout time.Duration

	// A removed client's store work (sweep.go, §9.8, D-SOCK-9). How many clients this process removes at once: 4.
	ClientRemovedConcurrency int
	// How many removed clients may wait for their store work: 65,536. Past it a removal does its memory half alone,
	// which refuses the client here for RemovedClientTtl while its leases lapse in one lease's time.
	ClientRemovedQueueCount int
	// How many times one client's RemoveClient is tried: 3, each resuming where the work stands.
	ClientRemovedAttemptCount int
	// The wait between two tries: 1 s.
	ClientRemovedRetryWait time.Duration
	// How long one RemoveClient may take: 30 s, since it works through the client's whole set a batch at a time.
	ClientRemovedTimeout time.Duration

	// How long a network's kill read that failed waits before it is tried again (sweep.go, §13.9): 1 s.
	KillRetryWait time.Duration
}

// §9's values.
func DefaultSocketsSettings() *SocketsSettings {
	return &SocketsSettings{
		Store:                 DefaultSocketStoreSettings(),
		Bound:                 DefaultSocketControlBoundSettings(),
		FairQueue:             DefaultSocketFairQueueSettings(),
		Gate:                  DefaultSocketGateSettings(),
		PlatformPairTtlMax:    60 * time.Minute,
		StoreTimeout:          2 * time.Second,
		ProbeInterval:         5 * time.Second,
		MaxRetryAfter:         time.Second,
		RemovedClientTtl:      10 * time.Minute,
		EdgePairTouchInterval: 5 * time.Minute,
		PairWriteInterval:     60 * time.Second,
		BehindRetryAfter:      250 * time.Millisecond,
		FencedRetryAfter:      time.Second,
		QuotaRetryAfter:       5 * time.Second,
		ClaimMemoCount:        128 * 1024,
		ListPageCount:         1024,

		Format:                        sidecar.DefaultSocketFormatSettings(),
		RegistrationsMaxBodyByteCount: 4 * 1024 * 1024,
		FindMaxBodyByteCount:          64 * 1024,
		FindMaxClientIdCount:          64,

		SweepMinInterval:      10 * time.Second,
		SweepClaimTtl:         30 * time.Second,
		SweepPageCount:        256,
		SweepConcurrency:      4,
		SweepRemoveBatchCount: 1024,
		SweepStoreTimeout:     10 * time.Second,

		ClientRemovedConcurrency:  4,
		ClientRemovedQueueCount:   64 * 1024,
		ClientRemovedAttemptCount: 3,
		ClientRemovedRetryWait:    time.Second,
		ClientRemovedTimeout:      30 * time.Second,

		KillRetryWait: time.Second,
	}
}

// Whether the store's settings can run a store. A refusal names the field.
func (self *SocketStoreSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no store settings", ErrSocketsSettingsRefused)
	}
	for _, check := range []struct {
		name     string
		positive bool
	}{
		{name: "lease", positive: 0 < self.Lease},
		{name: "client_set_ttl", positive: 0 < self.ClientSetTtl},
		{name: "sample_count", positive: 2 <= self.SampleCount},
		{name: "tombstone_ttl", positive: 0 < self.TombstoneTtl},
		{name: "unlisten_fence_ttl", positive: 0 < self.UnlistenFenceTtl},
		{name: "edge_pair_ttl", positive: 0 < self.EdgePairTtl},
		{name: "remove_client_batch_count", positive: 0 < self.RemoveClientBatchCount},
	} {
		if !check.positive {
			return fmt.Errorf("%w: %s", ErrSocketsSettingsRefused, check.name)
		}
	}
	return self.Scheduler.Validate()
}

// Whether a pick can run on these. A refusal names the field.
func (self *SocketSchedulerSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no scheduler settings", ErrSocketsSettingsRefused)
	}
	for _, check := range []struct {
		name     string
		positive bool
	}{
		{name: "ticket_lifetime", positive: 0 < self.TicketLifetime},
		{name: "clamp_floor_count", positive: 0 < self.ClampFloorCount},
		{name: "clamp_percent", positive: 0 < self.ClampPercent && self.ClampPercent <= 100},
		{name: "ejection_step", positive: 0 < self.EjectionStep},
		{name: "ejection_max", positive: self.EjectionStep <= self.EjectionMax},
		{name: "ejection_group_percent", positive: 0 < self.EjectionGroupPercent && self.EjectionGroupPercent <= 100},
		{name: "reporter_window", positive: 0 < self.ReporterWindow},
		{name: "reporter_network_count", positive: 0 < self.ReporterNetworkCount},
	} {
		if !check.positive {
			return fmt.Errorf("%w: %s", ErrSocketsSettingsRefused, check.name)
		}
	}
	return nil
}

// Whether the engine can run on these. A refusal names the field, never a value.
func (self *SocketsSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no settings", ErrSocketsSettingsRefused)
	}
	if err := self.Store.Validate(); err != nil {
		return err
	}
	if self.Bound == nil {
		return fmt.Errorf("%w: no bound settings", ErrSocketsSettingsRefused)
	}
	if self.FairQueue == nil {
		return fmt.Errorf("%w: no fair queue settings", ErrSocketsSettingsRefused)
	}
	if self.Format == nil {
		return fmt.Errorf("%w: no format settings", ErrSocketsSettingsRefused)
	}
	if err := self.Gate.Validate(); err != nil {
		return err
	}
	for _, check := range []struct {
		name     string
		positive bool
	}{
		{name: "calls_per_second", positive: 0 < self.Bound.CallsPerSecond},
		{name: "burst", positive: 0 < self.Bound.Burst},
		{name: "edge_calls_per_second", positive: 0 < self.Bound.EdgeCallsPerSecond},
		{name: "edge_burst", positive: 0 < self.Bound.EdgeBurst},
		{name: "sweep_interval", positive: 0 < self.Bound.SweepInterval},
		{name: "concurrency", positive: 0 < self.FairQueue.Concurrency},
		{name: "queue_count", positive: 0 < self.FairQueue.QueueCount},
		{name: "max_wait", positive: 0 < self.FairQueue.MaxWait},
		{name: "platform_pair_ttl_max", positive: 0 < self.PlatformPairTtlMax},
		{name: "store_timeout", positive: 0 < self.StoreTimeout},
		{name: "probe_interval", positive: 0 < self.ProbeInterval},
		{name: "max_retry_after", positive: 0 < self.MaxRetryAfter},
		{name: "removed_client_ttl", positive: 0 < self.RemovedClientTtl},
		{name: "edge_pair_touch_interval", positive: 0 < self.EdgePairTouchInterval},
		{name: "pair_write_interval", positive: 0 < self.PairWriteInterval},
		{name: "behind_retry_after", positive: 0 < self.BehindRetryAfter},
		{name: "fenced_retry_after", positive: 0 < self.FencedRetryAfter},
		{name: "quota_retry_after", positive: 0 < self.QuotaRetryAfter},
		{name: "claim_memo_count", positive: 2 <= self.ClaimMemoCount},
		{name: "list_page_count", positive: 0 < self.ListPageCount},
		{name: "registrations_max_body_byte_count", positive: 0 < self.RegistrationsMaxBodyByteCount},
		{name: "find_max_body_byte_count", positive: 0 < self.FindMaxBodyByteCount},
		{name: "find_max_client_id_count", positive: 0 < self.FindMaxClientIdCount},
		{name: "format.claim_max_byte_count", positive: 0 < self.Format.ClaimMaxByteCount},
		{name: "format.protocol_max_byte_count", positive: 0 < self.Format.ProtocolMaxByteCount},
		{name: "format.alpn_max_count", positive: 0 < self.Format.AlpnMaxCount},
		{name: "format.alpn_max_byte_count", positive: 0 < self.Format.AlpnMaxByteCount},
		{name: "format.app_mode_max_byte_count", positive: 0 < self.Format.AppModeMaxByteCount},
		{name: "format.max_weight", positive: 0 < self.Format.MaxWeight},
		{name: "format.default_weight", positive: 0 < self.Format.DefaultWeight && self.Format.DefaultWeight <= self.Format.MaxWeight},
		{name: "format.default_max_streams", positive: 0 < self.Format.DefaultMaxStreams},
		{name: "format.ticket_max_byte_count", positive: 0 < self.Format.TicketMaxByteCount},
		{name: "format.failed_ticket_max_count", positive: 0 < self.Format.FailedTicketMaxCount},
		{name: "format.affinity_key_max_byte_count", positive: 0 < self.Format.AffinityKeyMaxByteCount},
		{name: "sweep_min_interval", positive: 0 < self.SweepMinInterval},
		{name: "sweep_claim_ttl", positive: 0 < self.SweepClaimTtl},
		{name: "sweep_page_count", positive: 0 < self.SweepPageCount},
		{name: "sweep_concurrency", positive: 0 < self.SweepConcurrency},
		{name: "sweep_remove_batch_count", positive: 0 < self.SweepRemoveBatchCount},
		{name: "sweep_store_timeout", positive: 0 < self.SweepStoreTimeout},
		{name: "client_removed_concurrency", positive: 0 < self.ClientRemovedConcurrency},
		{name: "client_removed_queue_count", positive: 0 < self.ClientRemovedQueueCount},
		{name: "client_removed_attempt_count", positive: 0 < self.ClientRemovedAttemptCount},
		{name: "client_removed_retry_wait", positive: 0 < self.ClientRemovedRetryWait},
		{name: "client_removed_timeout", positive: 0 < self.ClientRemovedTimeout},
		{name: "kill_retry_wait", positive: 0 < self.KillRetryWait},
	} {
		if !check.positive {
			return fmt.Errorf("%w: %s", ErrSocketsSettingsRefused, check.name)
		}
	}
	return nil
}
