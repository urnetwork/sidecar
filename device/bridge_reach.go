// Reach events (§16.8's reach receipts, §17.9; R-BRIDGE-6, R-BRIDGE-13, I-13): the provider enforces a forward's or a
// route's grant, so its hook is where a reach receipt starts. BridgeEgressPolicy reports each flow a granted row
// admitted, by the grant and the sealed source subject, and Bridge.AddReachCallback hands what it reported to the
// sidecar role, which writes the receipts (the root's bridge_reach.go). This role writes no record and holds no record
// key (owner decision 197; DESIGN-DETAILS 4.7).
//
//	what reports   a flow a row carrying a grant id admitted: rule 1's map and rule 3's hosted address by a dial row,
//	               a forward; rule 6's served prefix and its remap by a route row and rule 7's exit by an exit row, a
//	               route. A row of a policy rule carries no grant id, and rule 4 passes with no row, so neither
//	               reports, and a denied flow never does
//	packet path    ResolveEgress fills one event on its own stack and offers it to a ring of preallocated slots by a
//	               compare-and-swap: no allocation, no lock and no wait. A full ring drops the report, counted, and
//	               the flow goes on as decided. The one channel operation is the wake of a drain that sleeps, a
//	               non-blocking send on a one-slot channel, at most once each time the drain went idle
//	drain          one goroutine of the bridge's takes the ring empty, coalesces the events by (kind, grant, peer,
//	               source network, target port), and calls the callbacks with each, in the order first decided
//	waiting        with no callback, as in a VPN component whose app's sidecar role is not running, the coalesced
//	               events wait, at most ReachWaitingCount of them; one more distinct event is dropped and counted.
//	               The first callback added takes what waited
//	ids            an event names a grant, a sidecar or a client, a network, a port and counts: opaque ids alone,
//	               never a flow's source or destination address or a name (I-13)
//
// A share's flows name their source network (§17.9's isolation row), read from the verified principal, never from an
// address. The hook admits no share principal until shares land (BRIDGE-M6-05), so until then no decided flow carries
// one.
//
// Safe for concurrent use.

package device

import (
	"crypto/sha256"
	"math"
	"math/bits"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/connect"
)

// Which of §16.8's reach kinds a flow is, in RECORD.md section 6.2's numbers for ReachReceipt.kind.
type BridgeReachKind uint32

const (
	// A port forward into this host: a map or a hosted address, under a dial grant.
	BridgeReachKindForward BridgeReachKind = 3
	// A subnet route or an exit through this host, under a route grant.
	BridgeReachKindRoute BridgeReachKind = 4
)

// The name `ur bridge` and a log show.
func (self BridgeReachKind) String() string {
	switch self {
	case BridgeReachKindForward:
		return "forward"
	case BridgeReachKindRoute:
		return "route"
	default:
		return "unknown"
	}
}

// The flows one grant admitted from one peer since the last event of the pair. A value with no pointer in it, so a
// slot holds one whole and a report copies it.
type BridgeReachEvent struct {
	Kind BridgeReachKind
	// The requested grant whose row admitted the flows.
	GrantId [sha256.Size]byte
	// The sealed source subject, as the state resolves it: the subject's sidecar_id. At an sdk provider a client no
	// subject binds has no sidecar, and is named by the client id C13 sealed.
	Peer connect.Id
	// A share's source network (§17.9); zero for a flow of this network's own.
	SourceNetwork connect.Id
	// A forward's port on this host, past its map: what a model host declares its manifest on (RECORD.md section 12).
	// 0 for a route, and for a forward with no port, ICMP's.
	TargetPort uint16
	// The log position of the state that judged the newest of the flows: its pin's version.
	PolicyVersion uint64
	// When the grant's row stops admitting, Unix milliseconds, 0 for no end the rules name.
	GrantExpiresMillis int64
	// The flows decided. An event the hook reports counts one, and coalesced events add up, held at the largest
	// count rather than wrapping.
	StreamCount uint64
}

// Takes the events a bridge reported (Bridge.AddReachCallback).
type BridgeReachFunction func(event BridgeReachEvent)

// What coalesces: one event per kind, grant, peer, source network and target port.
type bridgeReachKey struct {
	kind          BridgeReachKind
	grantId       [sha256.Size]byte
	peer          connect.Id
	sourceNetwork connect.Id
	targetPort    uint16
}

// The key an event coalesces under.
func bridgeReachKeyOf(event *BridgeReachEvent) bridgeReachKey {
	return bridgeReachKey{
		kind:          event.Kind,
		grantId:       event.GrantId,
		peer:          event.Peer,
		sourceNetwork: event.SourceNetwork,
		targetPort:    event.TargetPort,
	}
}

// One slot of the ring.
type bridgeReachSlot struct {
	// p while the slot is free for the offer at position p, p+1 once that offer's event is in it, and p plus the
	// ring's size once it is taken
	sequence atomic.Uint64
	event    BridgeReachEvent
}

// The ring between the packet path and the drain (the file's comment): a bounded queue of events by value, many
// producers and one consumer, after Vyukov's bounded queue. offer and take never wait and never allocate.
type bridgeReachQueue struct {
	slots []bridgeReachSlot
	mask  uint64
	// the next position to offer at, and to take at
	head atomic.Uint64
	tail atomic.Uint64
	// reports a full ring dropped
	droppedCount atomic.Uint64
	// set by the drain before it sleeps; the offer that clears it wakes the drain
	idle atomic.Bool
	wake chan struct{}
}

// A ring of slotCount slots, rounded up to a power of two. Nil for a count that is not positive: a policy with no
// ring reports nothing.
func newBridgeReachQueue(slotCount int) *bridgeReachQueue {
	if slotCount <= 0 {
		return nil
	}
	if slotCount&(slotCount-1) != 0 {
		slotCount = 1 << bits.Len(uint(slotCount))
	}
	self := &bridgeReachQueue{
		slots: make([]bridgeReachSlot, slotCount),
		mask:  uint64(slotCount - 1),
		wake:  make(chan struct{}, 1),
	}
	for i := range self.slots {
		self.slots[i].sequence.Store(uint64(i))
	}
	return self
}

// Copies event into the next free slot, or counts it dropped when every slot is held. The packet path's half: it
// never waits. Wakes a drain that went idle.
func (self *bridgeReachQueue) offer(event *BridgeReachEvent) bool {
	position := self.head.Load()
	for {
		slot := &self.slots[position&self.mask]
		sequence := slot.sequence.Load()
		switch {
		case sequence == position:
			if self.head.CompareAndSwap(position, position+1) {
				slot.event = *event
				slot.sequence.Store(position + 1)
				if self.idle.CompareAndSwap(true, false) {
					select {
					case self.wake <- struct{}{}:
					default:
					}
				}
				return true
			}
			position = self.head.Load()
		case sequence < position:
			// the slot still holds the event a full turn back: the ring is full
			self.droppedCount.Add(1)
			return false
		default:
			// another offer took the position
			position = self.head.Load()
		}
	}
}

// Moves the oldest event into event, or answers false for an empty ring. The drain's half.
func (self *bridgeReachQueue) take(event *BridgeReachEvent) bool {
	position := self.tail.Load()
	for {
		slot := &self.slots[position&self.mask]
		sequence := slot.sequence.Load()
		switch {
		case sequence == position+1:
			if self.tail.CompareAndSwap(position, position+1) {
				*event = slot.event
				slot.sequence.Store(position + self.mask + 1)
				return true
			}
			position = self.tail.Load()
		case sequence < position+1:
			// the offer at this position has not finished, or none was made
			return false
		default:
			position = self.tail.Load()
		}
	}
}

// What the bridge keeps of the events its hook reported: the callbacks, and the events that wait for one.
type bridgeReach struct {
	// the policy's ring, nil where it reports nothing
	queue        *bridgeReachQueue
	waitingCount int
	callbacks    *connect.CallbackList[BridgeReachFunction]
	// wakes the drain when a callback is added, so what waited is delivered
	callbackAdded chan struct{}

	stateLock sync.Mutex
	// the coalesced events not yet delivered, in the order first decided, and each one's index by its key
	waitingEvents     []BridgeReachEvent
	waitingKeyIndexes map[bridgeReachKey]int
	// flows delivered to a callback, and flows whose event the waiting table had no room for
	notedCount   uint64
	droppedCount uint64
}

// The holder over the policy's ring, which may be nil. Nothing runs until the bridge starts runReach.
func newBridgeReach(queue *bridgeReachQueue, settings *BridgeSettings) *bridgeReach {
	return &bridgeReach{
		queue:             queue,
		waitingCount:      settings.ReachWaitingCount,
		callbacks:         connect.NewCallbackList[BridgeReachFunction](),
		callbackAdded:     make(chan struct{}, 1),
		waitingKeyIndexes: map[bridgeReachKey]int{},
	}
}

// a + b, held at the largest count rather than wrapping.
func bridgeReachSum(a uint64, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

// Coalesces one event into the waiting table. Answers false when the table is full and the event's key is new: the
// caller delivers what waits and adds again, or counts the event dropped.
func (self *bridgeReach) add(event *BridgeReachEvent) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := bridgeReachKeyOf(event)
	if i, ok := self.waitingKeyIndexes[key]; ok {
		waiting := &self.waitingEvents[i]
		waiting.StreamCount = bridgeReachSum(waiting.StreamCount, event.StreamCount)
		if waiting.PolicyVersion <= event.PolicyVersion {
			// the newer state's reading of the grant's end
			waiting.PolicyVersion = event.PolicyVersion
			waiting.GrantExpiresMillis = event.GrantExpiresMillis
		}
		return true
	}
	if self.waitingCount <= len(self.waitingEvents) {
		return false
	}
	self.waitingKeyIndexes[key] = len(self.waitingEvents)
	self.waitingEvents = append(self.waitingEvents, *event)
	return true
}

// Counts an event the waiting table had no room for.
func (self *bridgeReach) drop(event *BridgeReachEvent) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.droppedCount = bridgeReachSum(self.droppedCount, event.StreamCount)
}

// Hands every waiting event to every callback, in the order first decided, and answers whether a callback took
// them. With no callback they stay. Callbacks run under no lock of the bridge's.
func (self *bridgeReach) deliver() bool {
	callbacks := self.callbacks.Get()
	if len(callbacks) == 0 {
		return false
	}
	var events []BridgeReachEvent
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		events = self.waitingEvents
		self.waitingEvents = nil
		clear(self.waitingKeyIndexes)
		for i := range events {
			self.notedCount = bridgeReachSum(self.notedCount, events[i].StreamCount)
		}
	}()
	for _, event := range events {
		for _, callback := range callbacks {
			connect.HandleError(func() { callback(event) })
		}
	}
	return true
}

// Takes the ring empty into the waiting table, delivering where a callback stands and the table fills, then delivers
// what waits. Answers whether the ring held anything.
func (self *bridgeReach) drain() bool {
	took := false
	if self.queue != nil {
		var event BridgeReachEvent
		for self.queue.take(&event) {
			took = true
			if self.add(&event) {
				continue
			}
			// the table is full: a callback empties it, and with none the event is counted and lost
			if !self.deliver() || !self.add(&event) {
				self.drop(&event)
			}
		}
	}
	self.deliver()
	return took
}

// The counts a status shows: flows delivered to a callback, events waiting for one, and flows whose report was
// dropped, by a full ring or a full waiting table.
func (self *bridgeReach) counts() (notedCount uint64, waitingCount int, droppedCount uint64) {
	queueDroppedCount := uint64(0)
	if self.queue != nil {
		queueDroppedCount = self.queue.droppedCount.Load()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.notedCount, len(self.waitingEvents), bridgeReachSum(self.droppedCount, queueDroppedCount)
}

// Calls callback, on the bridge's reach goroutine, with each event its hook reported: the flows a grant admitted from
// a peer, coalesced since the pair's last event (the file's comment). The first callback added takes the events that
// waited for one. A callback may take its time, as the sidecar role's does to note a receipt: the packet path never
// waits on it, and reports past the ring's and the table's bounds while it runs are dropped and counted. The returned
// function removes it.
func (self *Bridge) AddReachCallback(callback BridgeReachFunction) func() {
	callbackId := self.reach.callbacks.Add(callback)
	select {
	case self.reach.callbackAdded <- struct{}{}:
	default:
	}
	return func() {
		self.reach.callbacks.Remove(callbackId)
	}
}

// The drain (the file's comment): sleeps until the hook reports into an empty ring or a callback is added, until the
// bridge closes, when it drains once more, so a callback that stands takes what was reported before the close.
func (self *Bridge) runReach() {
	defer close(self.reachDone)
	var wake chan struct{}
	if self.reach.queue != nil {
		wake = self.reach.queue.wake
	}
	for {
		select {
		case <-self.ctx.Done():
			// what the hook reported before the close reaches the callbacks that stand
			self.reach.drain()
			return
		default:
		}
		self.reach.drain()
		if queue := self.reach.queue; queue != nil {
			// say the drain sleeps, then take once more. An offer stores its event before it reads the flag, so one
			// this pass does not find reads the flag set and wakes the drain
			queue.idle.Store(true)
			if self.reach.drain() {
				continue
			}
		}
		select {
		case <-self.ctx.Done():
		case <-wake:
		case <-self.reach.callbackAdded:
		}
	}
}

// Fills event for a flow the row admitted, when the row carries a grant and the flow a peer to name; otherwise leaves
// it zero, which reports nothing. Called by resolve at each verdict a row admitted, on the packet path: it copies
// fixed-size values and allocates nothing.
func (self *bridgePolicyState) reachEvent(
	event *BridgeReachEvent,
	kind BridgeReachKind,
	row *bridgePolicyReach,
	subject *bridgePolicySubject,
	flow *connect.EgressFlow,
	targetPort uint16,
) {
	if event == nil || row == nil || len(row.grantId) != sha256.Size {
		return
	}
	peer := subject.sidecarId
	if peer == (connect.Id{}) {
		// another client at an sdk provider: no subject binds it, so the client id C13 sealed names it
		peer = flow.SourceSubject
	}
	if peer == (connect.Id{}) {
		return
	}
	event.Kind = kind
	event.GrantId = [sha256.Size]byte(row.grantId)
	event.Peer = peer
	if principal := flow.Principal; principal != nil && principal.ShareId != (connect.Id{}) {
		// a share link: the verified principal's network is the source network
		event.SourceNetwork = principal.Network
	}
	if kind == BridgeReachKindForward {
		event.TargetPort = targetPort
	}
	event.PolicyVersion = self.pinN
	if !row.expires.IsZero() {
		event.GrantExpiresMillis = row.expires.UnixMilli()
	}
	event.StreamCount = 1
}
