// §11.13's order row for P2: work waits by rank, then by Due, then by arrival, and is served from its
// own account in that order. Funded work spends the process's A2 share, and then, while the governor
// says the wallet no longer covers it, the uncovered part of its A_U share, so it is paid once either
// way; unfunded work spends the rest of A_U. Within an account a waiter that does not fit holds back
// those behind it, so a large unit of work is not starved by small ones; the two accounts do not hold
// each other back.
//
// A waiter's bytes are reserved when its turn comes, and its Recheck runs then, outside the lock,
// before the grant returns: P2 rereads repo/ when issued, not when queued (§11.13's skip row). A recheck
// that refuses gives the bytes back to the interval they came from.

package evsservice

import (
	"slices"

	"github.com/urnetwork/sidecar"
)

// Which part of a share a P2 reservation came from.
type writeBudgetPool int

const (
	writeBudgetPoolFunded writeBudgetPool = iota + 1
	writeBudgetPoolUncovered
	writeBudgetPoolUnfunded
)

// One P2 work waiting.
type writeBudgetP2Waiter struct {
	work  *sidecar.WriteP2Work
	seq   uint64
	state writeBudgetWaiterState
	// set when admitted: the pool and the interval its bytes came from
	pool  writeBudgetPool
	epoch uint64
	// closed once state leaves waiting
	decided chan struct{}
}

// The P2 waiters of one cluster's account, in §11.13's order. Its methods run under the account's
// stateLock.
type writeBudgetP2Queue struct {
	seq     uint64
	waiters []*writeBudgetP2Waiter
}

// Whether a goes before b.
func writeBudgetP2Before(a *writeBudgetP2Waiter, b *writeBudgetP2Waiter) bool {
	if a.work.Rank != b.work.Rank {
		return a.work.Rank < b.work.Rank
	}
	if !a.work.Due.Equal(b.work.Due) {
		return a.work.Due.Before(b.work.Due)
	}
	return a.seq < b.seq
}

// Queues work in order and returns its waiter.
func (self *writeBudgetP2Queue) enqueueWithLock(work *sidecar.WriteP2Work) *writeBudgetP2Waiter {
	self.seq += 1
	waiter := &writeBudgetP2Waiter{work: work, seq: self.seq, decided: make(chan struct{})}
	index, _ := slices.BinarySearchFunc(self.waiters, waiter, func(a *writeBudgetP2Waiter, b *writeBudgetP2Waiter) int {
		if writeBudgetP2Before(a, b) {
			return -1
		}
		return 1
	})
	self.waiters = slices.Insert(self.waiters, index, waiter)
	return waiter
}

// Takes waiter out of the queue.
func (self *writeBudgetP2Queue) removeWithLock(waiter *writeBudgetP2Waiter) {
	if index := slices.Index(self.waiters, waiter); 0 <= index {
		self.waiters = slices.Delete(self.waiters, index, index+1)
	}
}

// Whether a waiter of the same account waits at work's rank or before it, which TryAcquireP2 may not
// pass.
func (self *writeBudgetP2Queue) blocksWithLock(work *sidecar.WriteP2Work) bool {
	for _, waiter := range self.waiters {
		if waiter.work.Funded == work.Funded && waiter.work.Rank <= work.Rank {
			return true
		}
	}
	return false
}

// What waits, by rank, funded and not: the demand a report carries.
func (self *writeBudgetP2Queue) demandWithLock() (funded []int64, unfunded []int64) {
	funded = make([]int64, sidecar.WriteP2RankCount)
	unfunded = make([]int64, sidecar.WriteP2RankCount)
	for _, waiter := range self.waiters {
		if waiter.work.Funded {
			funded[waiter.work.Rank] += waiter.work.ByteCount
		} else {
			unfunded[waiter.work.Rank] += waiter.work.ByteCount
		}
	}
	return funded, unfunded
}
