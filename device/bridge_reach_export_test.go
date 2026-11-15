// What the external tests of the reach events reach in this package's own tests: the event a share flow's row fills,
// which no decided flow carries until the hook admits share principals (BRIDGE-M6-05), and the holder between the
// ring and the callbacks with no goroutine, so a test orders an offer, a drain and a callback itself.

package device

import (
	"github.com/urnetwork/connect"
)

// The event the published state fills for flow as a row of grantId admitted it for the subject of subjectSidecarId:
// resolve's own fill, past the rules that chose the row.
func (self *BridgeEgressPolicy) ReachEventForTest(
	kind BridgeReachKind,
	grantId []byte,
	subjectSidecarId connect.Id,
	flow *connect.EgressFlow,
	targetPort uint16,
) BridgeReachEvent {
	var event BridgeReachEvent
	self.state.Load().reachEvent(
		&event,
		kind,
		&bridgePolicyReach{grantId: grantId},
		&bridgePolicySubject{sidecarId: subjectSidecarId},
		flow,
		targetPort,
	)
	return event
}

// The reports a policy's full ring dropped; 0 for a policy that reports nothing.
func (self *BridgeEgressPolicy) ReachDroppedCountForTest() uint64 {
	if self.reach == nil {
		return 0
	}
	return self.reach.droppedCount.Load()
}

// A ring and its holder as a bridge builds them, driven by the test in place of a hook and the drain's goroutine.
type BridgeReachForTest struct {
	reach *bridgeReach
}

// The holder on settings' ReachQueueCount and ReachWaitingCount.
func NewBridgeReachForTest(settings *BridgeSettings) *BridgeReachForTest {
	return &BridgeReachForTest{reach: newBridgeReach(newBridgeReachQueue(settings.ReachQueueCount), settings)}
}

// The ring's slots, 0 with no ring.
func (self *BridgeReachForTest) SlotCount() int {
	if self.reach.queue == nil {
		return 0
	}
	return len(self.reach.queue.slots)
}

// The hook's report: false when the ring is full, or there is none.
func (self *BridgeReachForTest) Offer(event BridgeReachEvent) bool {
	if self.reach.queue == nil {
		return false
	}
	return self.reach.queue.offer(&event)
}

// One pass of the drain.
func (self *BridgeReachForTest) Drain() {
	self.reach.drain()
}

// Bridge.AddReachCallback's registration, with no wake: the test drains.
func (self *BridgeReachForTest) AddCallback(callback BridgeReachFunction) func() {
	callbackId := self.reach.callbacks.Add(callback)
	return func() {
		self.reach.callbacks.Remove(callbackId)
	}
}

// What a status shows: flows a callback took, events waiting, flows dropped.
func (self *BridgeReachForTest) Counts() (notedCount uint64, waitingCount int, droppedCount uint64) {
	return self.reach.counts()
}
