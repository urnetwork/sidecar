// §11.13's queue and shed rows for P1: each process queues P1 per network (the token's) and serves the
// queues by weighted fair queuing on priced bytes, each network weighted by pro.yml's store_weight (1,
// 4 and 16), within the process's P1 share. A network's waiters keep their order, and among the
// networks the head with the smallest virtual finish tag goes first, a finish tag growing by priced
// bytes over weight, so over a busy stretch each network is served in proportion to its weight.
//
// Past ShedDelay of queueing delay the network with the most queued priced bytes per weight is refused
// (429 RESOURCE_EXHAUSTED with retry_after_ms), every waiter it has, and then the next heaviest while
// the delay lasts, but never the last network waiting: a network is refused only while one with less
// queued priced bytes per weight is still to be served (FI-14 (d)), so one network alone waits for the
// next share or its ctx.
//
// The weights are cached per network from Quota.Limits, at most WeightMaxAge old, by the client's own
// goroutine, so admission makes no host call: a network whose weight is unread or stale weighs
// DefaultStoreWeight.

package evsservice

import (
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

// One P1 admission waiting.
type writeBudgetP1Waiter struct {
	networkId   connect.Id
	cost        sidecar.WriteCost
	weight      int64
	finishTag   float64
	enqueueTime time.Time
	state       writeBudgetWaiterState
	// closed once state leaves waiting
	decided chan struct{}
}

// The fair queues of one cluster's account. Its methods run under the account's stateLock.
type writeBudgetP1Queue struct {
	virtualTime             float64
	networkIdWaiters        map[connect.Id][]*writeBudgetP1Waiter
	networkIdLastFinishTags map[connect.Id]float64
	networkIdQueuedBytes    map[connect.Id]int64
	// each network's weight at its last enqueue
	networkIdWeights map[connect.Id]int64
	queuedByteCount  int64
}

// An empty queue at virtual time zero.
func newWriteBudgetP1Queue() *writeBudgetP1Queue {
	return &writeBudgetP1Queue{
		networkIdWaiters:        map[connect.Id][]*writeBudgetP1Waiter{},
		networkIdLastFinishTags: map[connect.Id]float64{},
		networkIdQueuedBytes:    map[connect.Id]int64{},
		networkIdWeights:        map[connect.Id]int64{},
	}
}

// Whether nothing waits.
func (self *writeBudgetP1Queue) emptyWithLock() bool {
	return len(self.networkIdWaiters) == 0
}

// Queues waiter behind its network's others, its finish tag past both the queue's virtual time and its
// network's last.
func (self *writeBudgetP1Queue) enqueueWithLock(waiter *writeBudgetP1Waiter) {
	start := max(self.virtualTime, self.networkIdLastFinishTags[waiter.networkId])
	waiter.finishTag = start + float64(waiter.cost.ByteCount())/float64(max(1, waiter.weight))
	self.networkIdLastFinishTags[waiter.networkId] = waiter.finishTag
	self.networkIdWaiters[waiter.networkId] = append(self.networkIdWaiters[waiter.networkId], waiter)
	self.networkIdQueuedBytes[waiter.networkId] += waiter.cost.ByteCount()
	self.networkIdWeights[waiter.networkId] = max(1, waiter.weight)
	self.queuedByteCount += waiter.cost.ByteCount()
}

// The head with the smallest finish tag, nil when nothing waits.
func (self *writeBudgetP1Queue) nextWithLock() *writeBudgetP1Waiter {
	var next *writeBudgetP1Waiter
	for _, waiters := range self.networkIdWaiters {
		head := waiters[0]
		if next == nil || head.finishTag < next.finishTag || (head.finishTag == next.finishTag && head.enqueueTime.Before(next.enqueueTime)) {
			next = head
		}
	}
	return next
}

// Takes waiter out of its network's queue, wherever it stands, and moves the virtual time to an
// admitted waiter's tag.
func (self *writeBudgetP1Queue) removeWithLock(waiter *writeBudgetP1Waiter) {
	waiters := self.networkIdWaiters[waiter.networkId]
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
	if len(waiters) == 0 {
		delete(self.networkIdWaiters, waiter.networkId)
		delete(self.networkIdQueuedBytes, waiter.networkId)
		delete(self.networkIdWeights, waiter.networkId)
		if self.networkIdLastFinishTags[waiter.networkId] <= self.virtualTime {
			delete(self.networkIdLastFinishTags, waiter.networkId)
		}
	} else {
		self.networkIdWaiters[waiter.networkId] = waiters
		self.networkIdQueuedBytes[waiter.networkId] -= waiter.cost.ByteCount()
	}
	self.queuedByteCount -= waiter.cost.ByteCount()
	if waiter.state == writeBudgetAdmitted {
		self.virtualTime = max(self.virtualTime, waiter.finishTag)
	}
}

// When the oldest waiter was queued, false when nothing waits.
func (self *writeBudgetP1Queue) oldestEnqueueTimeWithLock() (time.Time, bool) {
	var oldest time.Time
	found := false
	for _, waiters := range self.networkIdWaiters {
		if !found || waiters[0].enqueueTime.Before(oldest) {
			oldest = waiters[0].enqueueTime
			found = true
		}
	}
	return oldest, found
}

// The network with the most queued priced bytes per weight, false unless two or more networks wait:
// the last network waiting is never the one refused (FI-14 (d)).
func (self *writeBudgetP1Queue) heaviestNetworkWithLock() (connect.Id, bool) {
	if len(self.networkIdWaiters) < 2 {
		return connect.Id{}, false
	}
	var heaviest connect.Id
	heaviestLoad := -1.0
	for networkId := range self.networkIdWaiters {
		load := float64(self.networkIdQueuedBytes[networkId]) / float64(self.networkIdWeights[networkId])
		// equal loads refuse the larger id, so the choice does not depend on map order
		if heaviestLoad < load || (load == heaviestLoad && heaviest.LessThan(networkId)) {
			heaviest = networkId
			heaviestLoad = load
		}
	}
	return heaviest, true
}

// Every waiter of networkId, oldest first.
func (self *writeBudgetP1Queue) networkWaitersWithLock(networkId connect.Id) []*writeBudgetP1Waiter {
	return append([]*writeBudgetP1Waiter{}, self.networkIdWaiters[networkId]...)
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
