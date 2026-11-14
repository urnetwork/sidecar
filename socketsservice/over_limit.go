// §20.7's over-limit list as Find's step 4 reads it (§9.6, §9.10, D-SOCK-15; DESIGN-DETAILS 13.2.3's over-limit
// poll): one goroutine reads Quota.OverLimit every OverLimitInterval, each read bounded by OverLimitTimeout, and
// keeps the spent set alone behind an atomic pointer, so Spent is one map read with no lock and no I/O (I-12).
//
// Only spent networks stop new streams: a network over its storage limit and still holding balance is never
// spent here (SOCK.md reading 9), so its Finds sign as before. A failed read keeps the last answer, counts
// urnetwork_sockets_over_limit_stale_total and leaves the answer's age in urnetwork_sockets_over_limit_age_seconds;
// the edge's own lease is the stop meanwhile (13.2.2). Before the first answer every network reads as spent, the
// closed direction, and the gate is not ready, so a host routes nothing to an engine that has not read it.
//
// Every wait is on the host's clock, so a test moves it. Safe for concurrent use.

package socketsservice

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// One answer, never changed once published.
type socketOverLimitSnapshot struct {
	spentNetworkIds map[connect.Id]bool
	readTime        time.Time
}

// The poll. newSocketOverLimit makes one and run reads it.
type socketOverLimit struct {
	quota    sidecar.Quota
	clock    sidecar.Clock
	settings *SocketGateSettings

	snapshot atomic.Pointer[socketOverLimitSnapshot]
	// when the poll began, so an age reads from then before the first answer
	startTime  time.Time
	staleCount sidecar.MetricsCounter
	age        sidecar.MetricsGauge
	// reads finished, each counted once the wait for the next is armed, so a test sees one land and moves the
	// clock past the next
	readCount *sidecar.MonitorValue[int]
}

// A poll of quota, nil reading nothing, which leaves every network spent and the gate never ready.
func newSocketOverLimit(quota sidecar.Quota, clock sidecar.Clock, metrics sidecar.Metrics, settings *SocketGateSettings) *socketOverLimit {
	return &socketOverLimit{
		quota:      quota,
		clock:      clock,
		settings:   settings,
		startTime:  clock.Now(),
		staleCount: metrics.Counter("urnetwork_sockets_over_limit_stale_total", "Over-limit reads that failed, the last answer kept."),
		age:        metrics.Gauge("urnetwork_sockets_over_limit_age_seconds", "Age of the over-limit answer Find reads."),
		readCount:  sidecar.NewMonitorValue(0),
	}
}

// Reads at once, then every OverLimitInterval, until ctx ends.
func (self *socketOverLimit) run(ctx context.Context) {
	for {
		self.read(ctx)
		wait := self.clock.After(self.settings.OverLimitInterval)
		self.readCount.Update(func(count int) int { return count + 1 })
		select {
		case <-ctx.Done():
			return
		case <-wait:
		}
	}
}

// One read under OverLimitTimeout on the host's clock. A failure keeps the last answer and its age grows.
func (self *socketOverLimit) read(ctx context.Context) {
	overLimit, err := func() (*sidecar.QuotaOverLimit, error) {
		if self.quota == nil {
			return nil, errSocketOverLimitNoQuota
		}
		readCtx, cancel := context.WithCancel(ctx)
		stop := self.clock.AfterFunc(self.settings.OverLimitTimeout, cancel)
		defer func() {
			stop()
			cancel()
		}()
		testHookBarrier("sockets.over_limit.read.before", "")
		defer testHookBarrier("sockets.over_limit.read.after", "")
		return self.quota.OverLimit(readCtx)
	}()
	now := self.clock.Now()
	if err != nil || overLimit == nil {
		self.staleCount.Add(1)
		since := self.startTime
		if previous := self.snapshot.Load(); previous != nil {
			since = previous.readTime
		}
		self.age.Set(now.Sub(since).Seconds())
		return
	}
	spentNetworkIds := make(map[connect.Id]bool, len(overLimit.SpentNetworkIdRefusals))
	for networkId, refusal := range overLimit.SpentNetworkIdRefusals {
		if refusal != nil {
			spentNetworkIds[networkId] = true
		}
	}
	self.snapshot.Store(&socketOverLimitSnapshot{spentNetworkIds: spentNetworkIds, readTime: now})
	self.age.Set(0)
}

// Whether the last answer marks networkId spent: one map read. Before the first answer, every network.
func (self *socketOverLimit) spent(networkId connect.Id) bool {
	snapshot := self.snapshot.Load()
	if snapshot == nil {
		return true
	}
	return snapshot.spentNetworkIds[networkId]
}

// Whether one read has answered.
func (self *socketOverLimit) ready() bool {
	return self.snapshot.Load() != nil
}

// A gate built with no Quota reads nothing.
var errSocketOverLimitNoQuota = errors.New("no ServiceHost.Quota to read the over-limit list from")
