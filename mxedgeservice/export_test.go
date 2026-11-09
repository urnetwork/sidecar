// A bridge to private fixtures for mxedgeservice_test, which is a separate package because sidecartest
// imports this one for FakeMxEdgeStore, so a test of this package importing sidecartest would be a
// cycle (connect/CODESTYLE.md:37).

package mxedgeservice

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
)

type (
	Caps             = mxCaps
	CapHold          = mxCapHold
	CapRefusal       = mxCapRefusal
	ClosedHandshakes = mxClosedHandshakes
)

const (
	CapRefusalNone            = mxCapRefusalNone
	CapRefusalProcess         = mxCapRefusalProcess
	CapRefusalSender          = mxCapRefusalSender
	CapRefusalSenderAggregate = mxCapRefusalSenderAggregate
	CapRefusalNetwork         = mxCapRefusalNetwork
	CapRefusalNetworkSender   = mxCapRefusalNetworkSender

	DailyKeyPrefix    = mxDailyKeyPrefix
	DailyKeyByteCount = mxDailyKeyByteCount
	DailyKeyTtl       = mxDailyKeyTtl
)

// Caps on settings' numbers.
func NewCaps(settings *MxEdgeSettings) *Caps {
	return newMxCaps(settings)
}

// How many entries every map holds, and the sessions counted, so a test can see nothing lingers.
func (self *mxCaps) State() (sessionCount int, entryCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sessionCount, len(self.senderCounts) + len(self.aggregateCounts) + len(self.networkCounts) + len(self.networkSenderCounts)
}

// The prefixes sender counts by.
func SenderPrefixes(sender netip.Addr) (netip.Prefix, netip.Prefix) {
	return mxSenderPrefixes(sender)
}

// The memory on one Redis, holding no k until its first Refresh.
func NewClosedHandshakes(redis sidecar.Redis, ttl time.Duration, clock sidecar.Clock) *ClosedHandshakes {
	return newMxClosedHandshakes(redis, ttl, clock)
}

// The UTC day t falls in, as days since the epoch.
func UtcDay(t time.Time) int64 {
	return mxUtcDay(t)
}

// Where the k of the day t falls in lives in Redis.
func DailyKeyName(t time.Time) string {
	return mxDailyKeyName(mxUtcDay(t))
}

// The memory's key for sender's /24 or /48 under dayKey.
func ClosedHandshakeKey(dayKey []byte, sender netip.Addr) string {
	_, aggregate := mxSenderPrefixes(sender)
	return mxClosedHandshakeKey(dayKey, aggregate)
}

// The key for sender's /24 or /48 under the k held for the day t falls in, empty with none held.
func (self *mxClosedHandshakes) Key(sender netip.Addr, t time.Time) string {
	dayKey := self.heldKey(mxUtcDay(t))
	if dayKey == nil {
		return ""
	}
	return ClosedHandshakeKey(dayKey, sender)
}

// The days whose k is held, and the days known to have none, each in order.
func (self *mxClosedHandshakes) HeldDays() (heldDays []int64, absentDays []int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Sorted(maps.Keys(self.dayKeys)), slices.Sorted(maps.Keys(self.absentDays))
}

// Returns once a Refresh has held the k of the day t falls in.
func (self *mxClosedHandshakes) AwaitKeyDay(t time.Time) {
	day := mxUtcDay(t)
	for {
		keyDay, update := self.keyDay.Get()
		if day <= keyDay {
			return
		}
		<-update
	}
}

// Returns once the engine's probe has held the k of the day t falls in.
func (self *MxEdgeService) AwaitKeyDay(t time.Time) {
	self.closedHandshakes.AwaitKeyDay(t)
}

// The sender a conn's peer address gives.
func SenderAddr(addr net.Addr) (netip.Addr, bool) {
	return mxSenderAddr(addr)
}

// Ends conn with a reset where it can.
func ResetConnection(conn net.Conn) {
	mxResetConnection(conn)
}

// Stands in for MAIL-M7-20's listings. Call it before any session starts.
func (self *MxEdgeService) SetBannerRefused(bannerRefused func(sender netip.Addr) bool) {
	self.bannerRefused = bannerRefused
}

// Returns once the last probe has found this, with no wait past the moment it does.
func (self *MxEdgeService) AwaitStoresReachable(want bool) {
	for {
		reachable, update := self.storesReachable.Get()
		if reachable == want {
			return
		}
		<-update
	}
}

// What the last probe found.
func (self *MxEdgeService) StoresReachable() bool {
	return self.storesReachable.Value()
}

// Probes finished so far.
func (self *MxEdgeService) ProbeCount() int {
	return self.probeCount.Value()
}

// Returns once count probes have finished, the last with the wait for the next armed, so a fake clock
// moved after this reaches that wait.
func (self *MxEdgeService) AwaitProbeCount(count int) {
	for {
		probeCount, update := self.probeCount.Get()
		if count <= probeCount {
			return
		}
		<-update
	}
}

// Returns once this many sessions are running.
func (self *MxEdgeService) AwaitSessionCount(want int) {
	for {
		count, update := self.sessionCount.Get()
		if count == want {
			return
		}
		<-update
	}
}

// The session record queue, on metrics of its own.
type ConnectionRecords = mxConnectionRecords

// A queue writing to store, on settings' numbers.
func NewConnectionRecords(store MxEdgeStore, settings *MxEdgeSettings, clock sidecar.Clock, metrics sidecar.Metrics) *ConnectionRecords {
	return newMxConnectionRecords(store, settings, clock, newMxMetrics(metrics), sidecar.NewNoopLogger())
}

// Writes what waits now.
func (self *mxConnectionRecords) Flush(ctx context.Context) error {
	return self.flush(ctx)
}

// Starts the writer, its first wait armed on return.
func (self *mxConnectionRecords) Start(ctx context.Context) {
	self.start(ctx)
}

// Closed once the writer has returned.
func (self *mxConnectionRecords) Done() <-chan struct{} {
	return self.done
}

// Returns once count waits have been armed: the first, and one after each flush.
func (self *mxConnectionRecords) AwaitFlushCount(count int) {
	for {
		flushCount, update := self.flushCount.Get()
		if count <= flushCount {
			return
		}
		<-update
	}
}

// The waits armed so far.
func (self *mxConnectionRecords) FlushCount() int {
	return self.flushCount.Value()
}

// The engine's queue.
func (self *MxEdgeService) ConnectionRecords() *ConnectionRecords {
	return self.records
}

// The most bytes the platform role's sessions have held at once.
func (self *MxEdgeService) PlatformBufferPeak() int64 {
	buffers := self.platform.buffers
	buffers.stateLock.Lock()
	defer buffers.stateLock.Unlock()
	return buffers.peakByteCount
}

// What the platform role's sessions hold now.
func (self *MxEdgeService) PlatformBufferHeld() int64 {
	buffers := self.platform.buffers
	buffers.stateLock.Lock()
	defer buffers.stateLock.Unlock()
	return buffers.heldByteCount
}

// What the router does at the end of a session that named networkId and began at startTime.
func (self *MxEdgeService) RecordSession(startTime time.Time, networkId sidecar.Id, byteCount int64, result string) bool {
	return self.recordSession(&mxSession{startTime: startTime}, networkId, byteCount, result)
}
