// The engine's tunables (connect/CODESTYLE.md:140): DefaultSocketsSettings is the only source of a
// default, and server/cli/sockets lays config/<env>/sidecar.yml's sockets_control_qps over it (§19.11).
// Protocol and format values, such as §9.5's 1,024 entries a page and §9.4's sizes, are constants beside
// the code that reads them, never settings.
//
// Every count and duration must be positive, and Validate refuses anything else, so no zero reads as
// unlimited or off. Nothing here bounds a count of names, listeners or streams (owner decision 66): the
// bounds below protect the service from a byte-free client and charge every network alike (D-SOCK-15).

package socketsservice

import (
	"errors"
	"fmt"
	"time"
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

// Everything the engine tunes. DefaultSocketsSettings makes one, and NewSocketsService refuses what
// Validate refuses. Read concurrently once built, and never changed after.
type SocketsSettings struct {
	Store     *SocketStoreSettings
	Bound     *SocketControlBoundSettings
	FairQueue *SocketFairQueueSettings
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
}

// §9's values.
func DefaultSocketsSettings() *SocketsSettings {
	return &SocketsSettings{
		Store:              DefaultSocketStoreSettings(),
		Bound:              DefaultSocketControlBoundSettings(),
		FairQueue:          DefaultSocketFairQueueSettings(),
		PlatformPairTtlMax: 60 * time.Minute,
		StoreTimeout:       2 * time.Second,
		ProbeInterval:      5 * time.Second,
		MaxRetryAfter:      time.Second,
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
	} {
		if !check.positive {
			return fmt.Errorf("%w: %s", ErrSocketsSettingsRefused, check.name)
		}
	}
	return nil
}
