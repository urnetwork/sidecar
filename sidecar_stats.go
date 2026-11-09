// SidecarStats, what `ur status --stats` shows (§5.10): running totals since NewSidecar, on this device only. No
// telemetry carries them anywhere, and none is labeled by a requester, repo or query (I-13): a component's name is
// the one label, and it names code, not data. Nothing here names a connect type, so it builds on every leg; the
// connect legs add the subprotocol's counters (sidecar_new_connect.go).

package sidecar

import (
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// The Sidecar's own counters, beside the leg's.
type sidecarStats struct {
	generationCount atomic.Uint64
	coreHintCount   atomic.Uint64

	stateLock         sync.Mutex
	componentCounters map[string]*sidecarQueueCounters
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

// A copy of every counter, components sorted by name.
func (self *sidecarStats) snapshot() SidecarStats {
	stats := SidecarStats{
		GenerationCount: self.generationCount.Load(),
		CoreHintCount:   self.coreHintCount.Load(),
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
