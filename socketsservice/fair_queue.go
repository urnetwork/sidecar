// §9.10's fair queue: a process serves at most Concurrency calls at once, and past that a call waits in
// per-network fair-share order, the networks with waiting calls taking turns, so one network's burst
// cannot starve the rest. Only when the waiting room is full, the process saturated, is anything shed,
// and then the heaviest network's newest waiting call goes first: a lighter network's call is never shed
// to make room for a heavier one. A call that waits past MaxWait is shed too, so a caller retries on its
// backup ticket rather than timing out.
//
// Calls already running are never shed or slowed, and nothing here outlives its call: a streams' bytes
// never pass through it. Waiting keeps the caller's ctx, so a caller that gives up leaves the queue at
// once (connect/CODESTYLE.md:137). Time is the host's clock. No network enters a metric label.
//
// Safe for concurrent use.

package socketsservice

import (
	"context"
	"errors"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// The process is saturated, or the call waited past MaxWait: the engine answers unavailable with
// retry_after_ms.
var ErrSocketShed = errors.New("socket call shed")

// Where a waiting call stands.
type socketFairWaiterState int

const (
	socketFairWaiting socketFairWaiterState = iota
	socketFairAdmitted
	socketFairShed
)

// One waiting call.
type socketFairWaiter struct {
	networkId connect.Id
	// Closed once state leaves waiting.
	decided chan struct{}
	state   socketFairWaiterState
	// Stops the MaxWait timer.
	stopTimer func() bool
}

// The queue's state. NewSocketFairQueue makes one.
type SocketFairQueue struct {
	settings *SocketFairQueueSettings
	clock    sidecar.Clock

	stateLock    sync.Mutex
	runningCount int
	waitingCount int
	// Each network's running calls, which how heavy a network is reads.
	networkIdRunningCounts map[connect.Id]int
	// Each network's waiting calls, oldest first.
	networkIdWaiters map[connect.Id][]*socketFairWaiter
	// The networks with waiting calls, in turn order, and whose turn is next.
	turnNetworkIds []connect.Id
	turnIndex      int
	// waitingCount, set in the same locked scope as each change, so a test can wait for a call to be
	// queued rather than poll for it.
	waitingMonitor *sidecar.MonitorValue[int]
}

// A queue on clock with settings, which the caller has validated.
func NewSocketFairQueue(settings *SocketFairQueueSettings, clock sidecar.Clock) *SocketFairQueue {
	return &SocketFairQueue{
		settings:               settings,
		clock:                  clock,
		networkIdRunningCounts: map[connect.Id]int{},
		networkIdWaiters:       map[connect.Id][]*socketFairWaiter{},
		waitingMonitor:         sidecar.NewMonitorValue(0),
	}
}

// Waits for networkId's turn. Once it may run, release ends the call and must be called exactly once.
// ErrSocketShed when the call is shed, or ctx's error when the caller gave up first, and then there is
// nothing to release.
func (self *SocketFairQueue) Acquire(ctx context.Context, networkId connect.Id) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	waiter, admitted, shed := func() (*socketFairWaiter, bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.runningCount < self.settings.Concurrency && self.waitingCount == 0 {
			self.startWithLock(networkId)
			return nil, true, false
		}
		if self.settings.QueueCount <= self.waitingCount && !self.shedHeaviestWithLock(networkId) {
			return nil, false, true
		}
		waiter := &socketFairWaiter{networkId: networkId, decided: make(chan struct{})}
		self.enqueueWithLock(waiter)
		return waiter, false, false
	}()
	if admitted {
		return self.releaseFunc(networkId), nil
	}
	if shed {
		return nil, ErrSocketShed
	}

	// armed outside the lock, since a fake clock may fire it on this goroutine
	stopTimer := self.clock.AfterFunc(self.settings.MaxWait, func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if waiter.state == socketFairWaiting {
			self.removeWaiterWithLock(waiter)
			self.decideWithLock(waiter, socketFairShed)
		}
	})
	defer stopTimer()

	select {
	case <-waiter.decided:
	case <-ctx.Done():
		gaveUp := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if waiter.state != socketFairWaiting {
				return false
			}
			self.removeWaiterWithLock(waiter)
			self.decideWithLock(waiter, socketFairShed)
			return true
		}()
		if gaveUp {
			return nil, ctx.Err()
		}
	}
	if waiter.state == socketFairAdmitted {
		if ctx.Err() != nil {
			// admitted as the caller gave up: hand the turn on rather than hold it
			self.releaseFunc(networkId)()
			return nil, ctx.Err()
		}
		return self.releaseFunc(networkId), nil
	}
	return nil, ErrSocketShed
}

// The release of one running call of networkId, which hands its turn to the next waiting call.
func (self *SocketFairQueue) releaseFunc(networkId connect.Id) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.runningCount -= 1
			if count := self.networkIdRunningCounts[networkId] - 1; 0 < count {
				self.networkIdRunningCounts[networkId] = count
			} else {
				delete(self.networkIdRunningCounts, networkId)
			}
			self.dispatchWithLock()
		})
	}
}

// Counts one more running call of networkId.
func (self *SocketFairQueue) startWithLock(networkId connect.Id) {
	self.runningCount += 1
	self.networkIdRunningCounts[networkId] += 1
}

// Marks waiter decided, once.
func (self *SocketFairQueue) decideWithLock(waiter *socketFairWaiter, state socketFairWaiterState) {
	waiter.state = state
	close(waiter.decided)
}

// Adds waiter at the back of its network's line, the network joining the turn order if it had none.
func (self *SocketFairQueue) enqueueWithLock(waiter *socketFairWaiter) {
	waiters := self.networkIdWaiters[waiter.networkId]
	if len(waiters) == 0 {
		self.turnNetworkIds = append(self.turnNetworkIds, waiter.networkId)
	}
	self.networkIdWaiters[waiter.networkId] = append(waiters, waiter)
	self.waitingCount += 1
	self.waitingMonitor.Set(self.waitingCount)
}

// Takes waiter out of its network's line, and the network out of the turn order once its line is
// empty.
func (self *SocketFairQueue) removeWaiterWithLock(waiter *socketFairWaiter) {
	waiters := self.networkIdWaiters[waiter.networkId]
	for index, candidate := range waiters {
		if candidate == waiter {
			waiters = append(waiters[:index:index], waiters[index+1:]...)
			self.waitingCount -= 1
			self.waitingMonitor.Set(self.waitingCount)
			break
		}
	}
	if 0 < len(waiters) {
		self.networkIdWaiters[waiter.networkId] = waiters
		return
	}
	delete(self.networkIdWaiters, waiter.networkId)
	for index, networkId := range self.turnNetworkIds {
		if networkId == waiter.networkId {
			self.turnNetworkIds = append(self.turnNetworkIds[:index:index], self.turnNetworkIds[index+1:]...)
			if index < self.turnIndex {
				self.turnIndex -= 1
			}
			break
		}
	}
	if len(self.turnNetworkIds) <= self.turnIndex {
		self.turnIndex = 0
	}
}

// Starts waiting calls while there is room, one per network in turn.
func (self *SocketFairQueue) dispatchWithLock() {
	for self.runningCount < self.settings.Concurrency && 0 < len(self.turnNetworkIds) {
		networkId := self.turnNetworkIds[self.turnIndex]
		waiter := self.networkIdWaiters[networkId][0]
		// the next network's turn is after this one's, whether or not this one has more waiting
		turnCount := len(self.turnNetworkIds)
		self.removeWaiterWithLock(waiter)
		if len(self.turnNetworkIds) == turnCount {
			self.turnIndex = (self.turnIndex + 1) % turnCount
		}
		self.startWithLock(networkId)
		self.decideWithLock(waiter, socketFairAdmitted)
	}
}

// How heavy a network is: what it runs and what it has waiting.
func (self *SocketFairQueue) weightWithLock(networkId connect.Id) int {
	return self.networkIdRunningCounts[networkId] + len(self.networkIdWaiters[networkId])
}

// Makes room for one call of arrivingNetworkId in a full waiting room, by shedding the newest waiting
// call of the heaviest network that has one. false when the arriving call's own network would be the
// heaviest, which sheds the arrival instead. A tie keeps what is already waiting.
func (self *SocketFairQueue) shedHeaviestWithLock(arrivingNetworkId connect.Id) bool {
	heaviestNetworkId := arrivingNetworkId
	heaviestWeight := self.weightWithLock(arrivingNetworkId) + 1
	for _, networkId := range self.turnNetworkIds {
		if networkId == arrivingNetworkId {
			continue
		}
		if weight := self.weightWithLock(networkId); heaviestWeight <= weight {
			heaviestNetworkId = networkId
			heaviestWeight = weight
		}
	}
	if heaviestNetworkId == arrivingNetworkId {
		return false
	}
	waiters := self.networkIdWaiters[heaviestNetworkId]
	newest := waiters[len(waiters)-1]
	self.removeWaiterWithLock(newest)
	self.decideWithLock(newest, socketFairShed)
	return true
}

// Running and waiting calls: a test's view.
func (self *SocketFairQueue) counts() (runningCount int, waitingCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.runningCount, self.waitingCount
}
