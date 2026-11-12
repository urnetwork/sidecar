// SidecarStats, what `ur status --stats` shows (§5.10): running totals since NewSidecar, on this device only. No
// telemetry carries them anywhere, and none is labeled by a requester, repo or query (I-13): a component's name and an
// error code are the only labels, and they name code, not data. Nothing here names a connect type, so it builds on
// every leg; the connect legs add the subprotocol's counters (sidecar_new_connect.go).

package sidecar

import (
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// What Stats answers.
type SidecarStats struct {
	// Client generations this Sidecar has started.
	GenerationCount uint64
	// core pushes received. Until CoreHint's kinds have their consumers, each is a bare resync (§6.8).
	CoreHintCount uint64
	// One row a component that has had a queue, by name.
	Components []SidecarComponentStats
	// The current generation's dispatcher, zero with none running and on the sidecar_http leg.
	Subprotocol SidecarSubprotocolStats
	// On a search indexer, its remote serving (§5.10, D-CORE-17); zero elsewhere.
	RemoteSearch SidecarRemoteSearchStats
}

// One component's queue (D-CORE-3), across its generations.
type SidecarComponentStats struct {
	Name string
	// Envelopes the queue took.
	QueuedCount uint64
	// Envelopes its worker ran.
	RanCount uint64
	// Envelopes refused at a full queue, or dropped as a generation closed with them queued, and their bytes.
	DroppedCount     uint64
	DroppedByteCount uint64
	// Queued calls that panicked, each kept to itself.
	PanicCount uint64
}

// §6's dispatcher's counters for the running generation (rpc_subprotocol.go's subprotocolStats), each a total
// since that generation's client began.
type SidecarSubprotocolStats struct {
	// Refused by version, the source guard, the provide mode, the identity gate and §8's hook.
	VersionRefusedCount     uint64
	SourceDroppedCount      uint64
	ProvideModeDroppedCount uint64
	IdentityRefusedCount    uint64
	InboundRefusedCount     uint64
	// Refused at a full source queue.
	QueueFullCount    uint64
	QueuedCount       uint64
	DispatchedCount   uint64
	UnroutedCount     uint64
	PanicCount        uint64
	ReplyDroppedCount uint64
	ReplySentCount    uint64
}

// A search indexer's remote serving (D-CORE-17; daemon_search_serve.go, daemon_search_budget.go): pages served,
// refusals by code, CPU and queue waits, with no requester, repo or query label (I-13).
type SidecarRemoteSearchStats struct {
	// SEARCH requests answered with a reply.
	PageCount uint64
	// SEARCH requests answered with an Error instead, by its code, sorted by code.
	Refusals []SidecarRemoteRefusalStats
	// Compute slot time given back, the budget's measure of CPU.
	Cpu time.Duration
	// Requests that waited for a compute slot, and how long they waited in all.
	QueueWaitCount uint64
	QueueWait      time.Duration
}

// One error code's refusals.
type SidecarRemoteRefusalStats struct {
	// §6.6's ErrorCode name, such as ERR_RESOURCE_EXHAUSTED.
	Code  string
	Count uint64
}

// The Sidecar's own counters, beside the leg's.
type sidecarStats struct {
	generationCount atomic.Uint64
	coreHintCount   atomic.Uint64
	// remote serving's (SidecarRemoteSearchStats)
	remotePageCount      atomic.Uint64
	remoteCpuNanos       atomic.Int64
	remoteQueueWaitCount atomic.Uint64
	remoteQueueWaitNanos atomic.Int64

	stateLock         sync.Mutex
	componentCounters map[string]*sidecarQueueCounters
	// remote serving's refusals, by error code name
	remoteRefusalCounts map[string]uint64
}

// The counters of the component named, made on first use, so they outlive each generation's queue.
func (self *sidecarStats) componentQueueCounters(name string) *sidecarQueueCounters {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.componentCounters == nil {
		self.componentCounters = map[string]*sidecarQueueCounters{}
	}
	counters, ok := self.componentCounters[name]
	if !ok {
		counters = &sidecarQueueCounters{}
		self.componentCounters[name] = counters
	}
	return counters
}

// Counts one remote search request refused with an Error, by its code's name.
func (self *sidecarStats) remoteRefused(code string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.remoteRefusalCounts == nil {
		self.remoteRefusalCounts = map[string]uint64{}
	}
	self.remoteRefusalCounts[code] += 1
}

// A copy of every counter, components and refusals sorted by name.
func (self *sidecarStats) snapshot() SidecarStats {
	stats := SidecarStats{
		GenerationCount: self.generationCount.Load(),
		CoreHintCount:   self.coreHintCount.Load(),
		RemoteSearch: SidecarRemoteSearchStats{
			PageCount:      self.remotePageCount.Load(),
			Cpu:            time.Duration(self.remoteCpuNanos.Load()),
			QueueWaitCount: self.remoteQueueWaitCount.Load(),
			QueueWait:      time.Duration(self.remoteQueueWaitNanos.Load()),
		},
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for name, counters := range self.componentCounters {
		stats.Components = append(stats.Components, SidecarComponentStats{
			Name:             name,
			QueuedCount:      counters.queuedCount.Load(),
			RanCount:         counters.ranCount.Load(),
			DroppedCount:     counters.droppedCount.Load(),
			DroppedByteCount: counters.droppedByteCount.Load(),
			PanicCount:       counters.panicCount.Load(),
		})
	}
	slices.SortFunc(stats.Components, func(a SidecarComponentStats, b SidecarComponentStats) int {
		return strings.Compare(a.Name, b.Name)
	})
	for code, count := range self.remoteRefusalCounts {
		stats.RemoteSearch.Refusals = append(stats.RemoteSearch.Refusals, SidecarRemoteRefusalStats{Code: code, Count: count})
	}
	slices.SortFunc(stats.RemoteSearch.Refusals, func(a SidecarRemoteRefusalStats, b SidecarRemoteRefusalStats) int {
		return strings.Compare(a.Code, b.Code)
	})
	return stats
}

// Running totals since NewSidecar, for `ur status --stats`.
func (self *Sidecar) Stats() SidecarStats {
	stats := self.stats.snapshot()
	if self.leg != nil {
		stats.Subprotocol = self.leg.subprotocolStats()
	}
	return stats
}
