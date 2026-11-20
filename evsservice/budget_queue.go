// §11.13's queue and shed rows for P1 (owner decision 617): each process queues P1 per network (the token's) and
// serves the queues by weighted fair queuing on priced bytes, each network weighted by pro.yml's store_weight (1, 4
// and 16), within the process's P1 share. A network's waiters keep their order, and among the networks the head with
// the smallest virtual finish tag goes first, a finish tag growing by priced bytes over weight, so over a busy stretch
// each network is served in proportion to its weight.
//
// Admission is fair over time too. Every P1 write takes its finish tag as it asks, so one admitted at once advances
// its network's tag and the virtual time as a queued one does. Each interval's P1 share is split by weight among the
// networks of the share window, those that asked within ShareWindow, so a network that asked in the last interval
// has its weighted share held for it before its next push arrives. A network whose admissions this interval have
// reached its weighted share queues behind the others even while nothing else waits, and is served from the next
// interval's share; one below its share is served at once while the share covers it, whatever waits past its own
// share. So a flood cannot spend the share before the lighter networks' pushes arrive, and theirs are served within
// the interval. A network's last admission may take it past its share, so a network whose share is smaller than one
// push still has that push served each interval.
//
// Past ShedDelay of queueing delay the shed refuses (429 RESOURCE_EXHAUSTED with retry_after_ms) every waiter of one
// network at a time, while the delay lasts. A flood is a waiting network past its weighted share: it holds more than
// that share. A network is served while it waits, and, unless the shed refused it this interval, while it is below its
// share or was admitted P1 this interval.
//
//   - First the heaviest flood by queued priced bytes per weight, while another network of the share window that is
//     served, waiting or not, has less queued priced bytes per weight: a flood's waiters stand behind every share
//     held for another network, so a flood waiting alone is refused while lighter networks are served at once.
//   - While no flood waits, the heaviest network only while it is strictly heavier than the lightest one waiting. A
//     network below its share waits only for P1 the share does not hold, so it is weighed against the others
//     waiting alone, and equal light loads are kept.
//   - While floods wait with none lighter served, and every waiting network is equally loaded, a flood by id, the
//     larger first, while two networks or more wait, so a uniform overload still sheds and keeps its last network.
//
// So no network below its share is refused while a flood holds more than its weighted share, no network below its
// share is refused by id, and a network alone in the share window is never refused: it waits for the next share or
// its ctx (FI-14 (d)). Equal loads refuse the larger id first, so no choice depends on map order.
//
// The weights are cached per network from Quota.Limits, at most WeightMaxAge old, by the client's own goroutine, so
// admission makes no host call: a network whose weight is unread or stale weighs DefaultStoreWeight.

package evsservice

import (
	"cmp"
	"context"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// Where a waiter stands.
type writeBudgetWaiterState int

const (
	writeBudgetWaiting writeBudgetWaiterState = iota
	writeBudgetAdmitted
	writeBudgetRefused
	writeBudgetAbandoned
)

// One P1 admission asking.
type writeBudgetP1Waiter struct {
	networkId connect.Id
	cost      sidecar.WriteCost
	weight    int64
	finishTag float64
	// its place in the order the queue took its waiters, which breaks equal finish tags
	seq         uint64
	enqueueTime time.Time
	state       writeBudgetWaiterState
	// closed once state leaves waiting
	decided chan struct{}
}

// One network's P1 in an account: its waiters, its tags, and where it stands in the interval and the share window.
type writeBudgetP1Network struct {
	networkId       connect.Id
	waiters         []*writeBudgetP1Waiter
	queuedByteCount int64
	// the tag its next waiter starts from: its last waiter's, or its last admission's while none waits
	lastFinishTag float64
	// its last admission's finish tag, which lastFinishTag returns to once its waiters have left unadmitted
	admittedFinishTag float64
	// its weight as it last asked
	weight int64
	// the priced bytes admitted to it in the current interval
	admittedByteCount int64
	// the shed refused it in the current interval
	refused bool
	// the interval it last asked in
	askEpoch uint64
}

// The fair queues of one cluster's account. Its methods run under the account's stateLock.
type writeBudgetP1Queue struct {
	// the intervals a network stays in the share window, the one it last asked in counted
	windowIntervalCount uint64
	virtualTime         float64
	nextSeq             uint64
	// every network of the share window, and every network with waiters
	networkIdNetworks map[connect.Id]*writeBudgetP1Network
	// the networks with waiters
	waitingNetworkIdNetworks map[connect.Id]*writeBudgetP1Network
	queuedByteCount          int64
	// the current interval and its P1 share
	epoch          uint64
	shareByteCount int64
	// the summed weight of the share window
	windowWeight int64
}

// An empty queue at virtual time zero, with no share until its first interval. A network stays in the share window for
// windowIntervalCount intervals, at least one.
func newWriteBudgetP1Queue(windowIntervalCount int) *writeBudgetP1Queue {
	return &writeBudgetP1Queue{
		windowIntervalCount:      uint64(max(1, windowIntervalCount)),
		networkIdNetworks:        map[connect.Id]*writeBudgetP1Network{},
		waitingNetworkIdNetworks: map[connect.Id]*writeBudgetP1Network{},
	}
}

// Starts an interval whose P1 share is shareByteCount: each network's admissions count from zero again, and a network
// with nothing waiting that has not asked within the window leaves it, its tag with it.
func (self *writeBudgetP1Queue) startIntervalWithLock(shareByteCount int64) {
	self.epoch += 1
	self.shareByteCount = max(0, shareByteCount)
	self.windowWeight = 0
	for networkId, network := range self.networkIdNetworks {
		network.admittedByteCount = 0
		network.refused = false
		if len(network.waiters) == 0 && self.windowIntervalCount <= self.epoch-network.askEpoch {
			// a network with nothing waiting has its tag at or below the virtual time, so it loses no order
			delete(self.networkIdNetworks, networkId)
			continue
		}
		self.windowWeight += network.weight
	}
}

// Whether nothing waits.
func (self *writeBudgetP1Queue) emptyWithLock() bool {
	return len(self.waitingNetworkIdNetworks) == 0
}

// The network asking now with weight, in the share window from this interval on.
func (self *writeBudgetP1Queue) askWithLock(networkId connect.Id, weight int64) *writeBudgetP1Network {
	weight = max(1, weight)
	network, ok := self.networkIdNetworks[networkId]
	if !ok {
		network = &writeBudgetP1Network{networkId: networkId}
		self.networkIdNetworks[networkId] = network
	}
	self.windowWeight += weight - network.weight
	network.weight = weight
	network.askEpoch = self.epoch
	return network
}

// Queues waiter behind its network's others, its finish tag past both the queue's virtual time and its network's last,
// and puts its network in the share window.
func (self *writeBudgetP1Queue) enqueueWithLock(waiter *writeBudgetP1Waiter) {
	network := self.askWithLock(waiter.networkId, waiter.weight)
	start := max(self.virtualTime, network.lastFinishTag)
	waiter.finishTag = start + float64(waiter.cost.ByteCount())/float64(max(1, waiter.weight))
	waiter.seq = self.nextSeq
	self.nextSeq += 1
	network.lastFinishTag = waiter.finishTag
	network.waiters = append(network.waiters, waiter)
	network.queuedByteCount += waiter.cost.ByteCount()
	self.waitingNetworkIdNetworks[waiter.networkId] = network
	self.queuedByteCount += waiter.cost.ByteCount()
}

// Whether network's admissions this interval have reached its weighted share of the interval's P1, the share times its
// weight over the window's. With no share every network is past it.
func (self *writeBudgetP1Queue) pastShareWithLock(network *writeBudgetP1Network) bool {
	// cross-multiplied in floating point: exact far past any share and weight, and never overflowing
	return float64(self.shareByteCount)*float64(network.weight) <= float64(network.admittedByteCount)*float64(max(1, self.windowWeight))
}

// The head with the smallest finish tag among the networks below their weighted share, the earlier queued on equal
// tags; nil when none.
func (self *writeBudgetP1Queue) nextWithLock() *writeBudgetP1Waiter {
	var next *writeBudgetP1Waiter
	for _, network := range self.waitingNetworkIdNetworks {
		if self.pastShareWithLock(network) {
			continue
		}
		head := network.waiters[0]
		if next == nil || head.finishTag < next.finishTag || (head.finishTag == next.finishTag && head.seq < next.seq) {
			next = head
		}
	}
	return next
}

// Takes waiter out of its network's queue, wherever it stands. An admitted waiter counts toward its network's share of
// the interval and moves the virtual time to its tag. A network left with nothing waiting starts its next waiter from
// its last admission's tag, so waiters refused or abandoned leave no mark on its order.
func (self *writeBudgetP1Queue) removeWithLock(waiter *writeBudgetP1Waiter) {
	network, ok := self.networkIdNetworks[waiter.networkId]
	if !ok {
		return
	}
	waiters := network.waiters
	for i, other := range waiters {
		if other == waiter {
			if i == 0 {
				// the usual case, served at the head
				waiters = waiters[1:]
			} else {
				waiters = append(waiters[:i:i], waiters[i+1:]...)
			}
			break
		}
	}
	network.waiters = waiters
	network.queuedByteCount -= waiter.cost.ByteCount()
	self.queuedByteCount -= waiter.cost.ByteCount()
	switch waiter.state {
	case writeBudgetAdmitted:
		network.admittedByteCount += waiter.cost.ByteCount()
		network.admittedFinishTag = max(network.admittedFinishTag, waiter.finishTag)
		self.virtualTime = max(self.virtualTime, waiter.finishTag)
	case writeBudgetRefused:
		network.refused = true
	}
	if len(waiters) == 0 {
		network.waiters = nil
		network.lastFinishTag = network.admittedFinishTag
		delete(self.waitingNetworkIdNetworks, waiter.networkId)
	}
}

// When the oldest waiter was queued, false when nothing waits.
func (self *writeBudgetP1Queue) oldestEnqueueTimeWithLock() (time.Time, bool) {
	var oldest time.Time
	found := false
	for _, network := range self.waitingNetworkIdNetworks {
		if !found || network.waiters[0].enqueueTime.Before(oldest) {
			oldest = network.waiters[0].enqueueTime
			found = true
		}
	}
	return oldest, found
}

// Every waiter of networkId, oldest first.
func (self *writeBudgetP1Queue) networkWaitersWithLock(networkId connect.Id) []*writeBudgetP1Waiter {
	network, ok := self.waitingNetworkIdNetworks[networkId]
	if !ok {
		return nil
	}
	return append([]*writeBudgetP1Waiter{}, network.waiters...)
}

// Every waiter, each network's oldest first.
func (self *writeBudgetP1Queue) waitersWithLock() []*writeBudgetP1Waiter {
	waiters := []*writeBudgetP1Waiter{}
	for _, network := range self.waitingNetworkIdNetworks {
		waiters = append(waiters, network.waiters...)
	}
	return waiters
}

// The sign of a's queued priced bytes per weight against b's, cross-multiplied so equal loads compare equal.
func compareWriteBudgetP1Load(a *writeBudgetP1Network, b *writeBudgetP1Network) int {
	return cmp.Compare(a.queuedByteCount*b.weight, b.queuedByteCount*a.weight)
}

// The waiting network with the most queued priced bytes per weight, the larger id among equal loads, from those past
// their weighted share alone when floods; false when there is none.
func (self *writeBudgetP1Queue) heaviestWaitingWithLock(floods bool) (*writeBudgetP1Network, bool) {
	var heaviest *writeBudgetP1Network
	for _, network := range self.waitingNetworkIdNetworks {
		if floods && !self.pastShareWithLock(network) {
			continue
		}
		if heaviest == nil {
			heaviest = network
			continue
		}
		if c := compareWriteBudgetP1Load(network, heaviest); 0 < c || (c == 0 && heaviest.networkId.LessThan(network.networkId)) {
			heaviest = network
		}
	}
	return heaviest, heaviest != nil
}

// The waiting network with the least queued priced bytes per weight, false when nothing waits.
func (self *writeBudgetP1Queue) lightestWaitingWithLock() (*writeBudgetP1Network, bool) {
	var lightest *writeBudgetP1Network
	for _, network := range self.waitingNetworkIdNetworks {
		if lightest == nil || compareWriteBudgetP1Load(network, lightest) < 0 {
			lightest = network
		}
	}
	return lightest, lightest != nil
}

// The network the shed rule refuses next, false when it refuses none: see the file header.
func (self *writeBudgetP1Queue) shedNetworkWithLock() (connect.Id, bool) {
	flood, ok := self.heaviestWaitingWithLock(true)
	if !ok {
		heaviest, ok := self.heaviestWaitingWithLock(false)
		if !ok {
			return connect.Id{}, false
		}
		lightest, _ := self.lightestWaitingWithLock()
		if compareWriteBudgetP1Load(heaviest, lightest) <= 0 {
			// equal light loads are kept, and none is refused by id
			return connect.Id{}, false
		}
		return heaviest.networkId, true
	}
	for _, other := range self.networkIdNetworks {
		if other == flood || 0 <= compareWriteBudgetP1Load(other, flood) {
			continue
		}
		if 0 < len(other.waiters) || (!other.refused && (0 < other.admittedByteCount || !self.pastShareWithLock(other))) {
			// a lighter network served
			return flood.networkId, true
		}
	}
	// none lighter served: a uniform overload refuses its floods by id, the larger first, and keeps its last network
	if len(self.waitingNetworkIdNetworks) < 2 {
		return connect.Id{}, false
	}
	heaviest, _ := self.heaviestWaitingWithLock(false)
	lightest, _ := self.lightestWaitingWithLock()
	if compareWriteBudgetP1Load(heaviest, lightest) != 0 {
		return connect.Id{}, false
	}
	return flood.networkId, true
}

// One network's cached weight.
type writeBudgetWeight struct {
	weight   int64
	readTime time.Time
	usedTime time.Time
}

// store_weight per network, read from Quota.Limits by the client's goroutine for the networks it
// admitted within WeightActiveWindow, and read inline with no host call. Safe for concurrent use.
type writeBudgetWeights struct {
	settings *WriteBudgetSettings
	quota    sidecar.Quota

	stateLock        sync.Mutex
	networkIdWeights map[connect.Id]*writeBudgetWeight
}

// No weight read yet. quota may be nil, and then every network weighs DefaultStoreWeight.
func newWriteBudgetWeights(settings *WriteBudgetSettings, quota sidecar.Quota) *writeBudgetWeights {
	return &writeBudgetWeights{
		settings:         settings,
		quota:            quota,
		networkIdWeights: map[connect.Id]*writeBudgetWeight{},
	}
}

// The network's weight as of now: its cached store_weight while no older than WeightMaxAge, else
// DefaultStoreWeight. Marks the network in use, so the next refresh reads it.
func (self *writeBudgetWeights) weight(networkId connect.Id, now time.Time) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	cached, ok := self.networkIdWeights[networkId]
	if !ok {
		cached = &writeBudgetWeight{}
		self.networkIdWeights[networkId] = cached
	}
	cached.usedTime = now
	if cached.readTime.IsZero() || self.settings.WeightMaxAge < now.Sub(cached.readTime) {
		return self.settings.DefaultStoreWeight
	}
	return cached.weight
}

// Rereads the weight of every network used within WeightActiveWindow, and forgets the rest. A read that
// fails keeps the last weight, which goes stale in WeightMaxAge. No lock is held across a Quota call.
func (self *writeBudgetWeights) refresh(ctx context.Context, clock sidecar.Clock) {
	if self.quota == nil {
		return
	}
	now := clock.Now()
	networkIds := func() []connect.Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		networkIds := []connect.Id{}
		for networkId, cached := range self.networkIdWeights {
			if self.settings.WeightActiveWindow < now.Sub(cached.usedTime) {
				delete(self.networkIdWeights, networkId)
				continue
			}
			networkIds = append(networkIds, networkId)
		}
		return networkIds
	}()
	for _, networkId := range networkIds {
		limits, err := self.quota.Limits(ctx, networkId)
		if err != nil || limits == nil {
			continue
		}
		weight := limits.Limits[writeBudgetStoreWeightKey]
		if weight < 1 {
			// §20.5 reads an absent key as 0, not included: Community's weight, never none
			weight = self.settings.DefaultStoreWeight
		}
		readTime := clock.Now()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if cached, ok := self.networkIdWeights[networkId]; ok {
				cached.weight = weight
				cached.readTime = readTime
			}
		}()
	}
}

// pro.yml's <tier>.sidecar key, as QuotaLimits carries it (§20.4).
const writeBudgetStoreWeightKey = "store_weight"
