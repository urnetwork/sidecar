//go:build !ios_extension && !sidecar_http

// D-CORE-17's budget for remote serving (CORE-M10-05; R-CORE-19, I-13, I-19, FI-24; DESIGN-DETAILS 7.2.5's step 2): what
// a daemon designated for search spends answering other devices' remote searches, beside its own local searches
// (Search.DaemonSearchCount, §16.10), which it never takes from, so phones' searches leave local agents their targets.
// One pool a daemon, shared by every network it serves, since the CPU and memory it bounds are the daemon's own; each
// network serves through its own handle (For), which counts that network's queue waits and CPU into its SidecarStats.
//
//	rate       RemoteRequesterRate a requester: a token bucket a sidecar_id, kept in memory while it is not full
//	cpu        RemoteCpuPerMinute over a sliding RemoteCpuWindow for all remote work, measured as the time requests
//	           hold a compute slot on the budget's clock (serving reads nothing from evs, api or gkm, so that time is
//	           compute), the slots still held counting what they have held so far
//	slots      RemoteSearchCount computing at once; past it at most RemoteQueueCount wait, each at most
//	           RemoteQueueTimeout, first come first served; the next past that, or a wait that times out, is refused
//	page       PageCpu and PageCandidateCount a page (SidecarRemotePage)
//	memory     RemoteSearchMemoryByteCount a computing search (SidecarRemoteAdmission.Reserve)
//	cursors    RemoteCursorCount open over every requester, the least recently used ended past it (AddCursor)
//
// The server calls Admit at step 2, before it reads the body, in step 2's order: the rate, then the CPU, then a slot.
// Every refusal is a *SidecarRemoteRefusal naming when to come back, which answers RESOURCE_EXHAUSTED with that
// retry_after_ms, and nothing of the request: it keys only on the requester's sidecar_id, so nothing the budget decides
// depends on a query. Nothing here is persisted, and nothing is logged with a requester, repo or query (I-13).
//
// On the legs a search server runs on: every connect leg but the forwarding one. Safe for concurrent use.

package sidecar

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Why the budget refused a request.
const (
	// The requester is past RemoteRequesterRate.
	SidecarRemoteRefusedRate = "rate"
	// RemoteCpuPerMinute is spent over the window.
	SidecarRemoteRefusedCpu = "cpu"
	// RemoteQueueCount requests already wait.
	SidecarRemoteRefusedQueueFull = "queue_full"
	// No slot freed within RemoteQueueTimeout.
	SidecarRemoteRefusedQueueTimeout = "queue_timeout"
)

// A request the budget refused at step 2: RESOURCE_EXHAUSTED, with when to come back.
type SidecarRemoteRefusal struct {
	// SidecarRemoteRefused*.
	Reason     string
	RetryAfter time.Duration
}

// The reason, never the requester.
func (self *SidecarRemoteRefusal) Error() string {
	return fmt.Sprintf("remote search budget: %s", self.Reason)
}

// The small envelope Error step 2 answers with (DESIGN-DETAILS 7.2.5): RESOURCE_EXHAUSTED and its retry_after_ms.
func (self *SidecarRemoteRefusal) SubprotocolError() *SubprotocolError {
	return &SubprotocolError{Code: protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED, RetryAfter: self.RetryAfter}
}

// The daemon's remote serving budget, or one network's handle on it (For). Construct with NewSidecarRemoteBudget.
type SidecarRemoteBudget struct {
	pool *remoteBudgetPool
	// the network this handle counts into, nil for none
	stats *sidecarStats
}

// What every handle of one budget shares.
type remoteBudgetPool struct {
	settings *SidecarSearchSettings
	clock    Clock

	stateLock sync.Mutex
	// the admissions holding a slot
	computing map[*SidecarRemoteAdmission]bool
	// the requests waiting for one, oldest first
	waiters []*remoteBudgetWaiter
	// the compute time slots gave back within the window, oldest first
	charges []remoteBudgetCharge
	// each requester's bucket while it is not full
	buckets map[Id]*remoteBudgetBucket
	// open cursors, the most recently used first
	cursors *list.List
}

// One request waiting for a slot: granted, when a slot was handed to it.
type remoteBudgetWaiter struct {
	// the handle it asked through, whose stats count its wait
	budget   *SidecarRemoteBudget
	queuedAt time.Time
	ready    chan struct{}
	granted  *SidecarRemoteAdmission
	gone     bool
}

// Compute time given back at at.
type remoteBudgetCharge struct {
	at  time.Time
	cpu time.Duration
}

// A requester's tokens as of at.
type remoteBudgetBucket struct {
	tokens float64
	at     time.Time
}

// One open cursor, and what ends it.
type remoteBudgetCursor struct {
	end func()
}

// A budget under settings' Remote* fields, on clock (nil: real time): one a daemon.
func NewSidecarRemoteBudget(settings *SidecarSearchSettings, clock Clock) (*SidecarRemoteBudget, error) {
	if settings == nil || settings.RemoteSearchCount <= 0 || settings.RemoteQueueCount < 0 || settings.RemoteQueueTimeout <= 0 ||
		settings.RemoteCpuPerMinute <= 0 || settings.RemoteCpuWindow <= 0 || settings.RemoteCursorCount <= 0 ||
		settings.RemoteRequesterRate.Count <= 0 || settings.RemoteRequesterRate.Burst <= 0 || settings.RemoteRequesterRate.Interval <= 0 ||
		settings.RemoteSearchMemoryByteCount <= 0 || settings.PageCpu <= 0 || settings.PageCandidateCount <= 0 {
		return nil, fmt.Errorf("%w: the remote search budget's settings", errInvalidSettings)
	}
	return &SidecarRemoteBudget{pool: &remoteBudgetPool{
		settings:  settings,
		clock:     clockOrReal(clock),
		computing: map[*SidecarRemoteAdmission]bool{},
		buckets:   map[Id]*remoteBudgetBucket{},
		cursors:   list.New(),
	}}, nil
}

// A handle on the same pool that counts its queue waits and CPU into sidecar's SidecarStats: each network serves
// through its own.
func (self *SidecarRemoteBudget) For(sidecar *Sidecar) *SidecarRemoteBudget {
	return &SidecarRemoteBudget{pool: self.pool, stats: &sidecar.stats}
}

// A requester's bucket refilled to now, made full on first use.
func (self *remoteBudgetPool) bucketWithLock(requesterId Id, now time.Time) *remoteBudgetBucket {
	rate := self.settings.RemoteRequesterRate
	bucket := self.buckets[requesterId]
	if bucket == nil {
		bucket = &remoteBudgetBucket{tokens: float64(rate.Burst), at: now}
		self.buckets[requesterId] = bucket
	}
	if elapsed := now.Sub(bucket.at); 0 < elapsed {
		bucket.tokens = min(float64(rate.Burst), bucket.tokens+float64(rate.Count)*float64(elapsed)/float64(rate.Interval))
		bucket.at = now
	}
	return bucket
}

// Drops every bucket that is full again, so memory follows the requesters that are active.
func (self *remoteBudgetPool) pruneBucketsWithLock(now time.Time) {
	burst := float64(self.settings.RemoteRequesterRate.Burst)
	for requesterId := range self.buckets {
		if self.bucketWithLock(requesterId, now).tokens >= burst {
			delete(self.buckets, requesterId)
		}
	}
}

// The compute time spent within the window ending now: what slots gave back, and what the slots still held have held.
func (self *remoteBudgetPool) cpuSpentWithLock(now time.Time) time.Duration {
	since := now.Add(-self.settings.RemoteCpuWindow)
	kept := self.charges[:0]
	spent := time.Duration(0)
	for _, charge := range self.charges {
		if charge.at.After(since) {
			kept = append(kept, charge)
			spent += charge.cpu
		}
	}
	self.charges = kept
	for admission := range self.computing {
		spent += now.Sub(admission.admittedAt)
	}
	return spent
}

// How long until the window frees enough of spent to admit again: the oldest charges leave it in turn. The slots still
// held leave nothing, so with them alone past the cap it is a queue's wait.
func (self *remoteBudgetPool) cpuRetryWithLock(now time.Time, spent time.Duration) time.Duration {
	for _, charge := range self.charges {
		spent -= charge.cpu
		if spent < self.settings.RemoteCpuPerMinute {
			return charge.at.Add(self.settings.RemoteCpuWindow).Sub(now)
		}
	}
	return self.settings.RemoteQueueTimeout
}

// Admits one request of requesterId (DESIGN-DETAILS 7.2.5's step 2): within the requester's rate and the window's CPU,
// a compute slot at once or after waiting at most RemoteQueueTimeout. Answers the admission, which holds its slot until
// Release, or a *SidecarRemoteRefusal; ctx's error if ctx ends while it waits.
func (self *SidecarRemoteBudget) Admit(ctx context.Context, requesterId Id) (*SidecarRemoteAdmission, error) {
	pool := self.pool
	settings := pool.settings
	now := pool.clock.Now()
	waiter, admission, refusal := func() (*remoteBudgetWaiter, *SidecarRemoteAdmission, *SidecarRemoteRefusal) {
		pool.stateLock.Lock()
		defer pool.stateLock.Unlock()
		bucket := pool.bucketWithLock(requesterId, now)
		if bucket.tokens < 1 {
			rate := settings.RemoteRequesterRate
			wait := time.Duration((1 - bucket.tokens) * float64(rate.Interval) / float64(rate.Count))
			return nil, nil, &SidecarRemoteRefusal{Reason: SidecarRemoteRefusedRate, RetryAfter: wait}
		}
		bucket.tokens -= 1
		defer pool.pruneBucketsWithLock(now)
		if spent := pool.cpuSpentWithLock(now); settings.RemoteCpuPerMinute <= spent {
			return nil, nil, &SidecarRemoteRefusal{Reason: SidecarRemoteRefusedCpu, RetryAfter: pool.cpuRetryWithLock(now, spent)}
		}
		if len(pool.computing) < settings.RemoteSearchCount && len(pool.waiters) == 0 {
			admission := self.admitWithLock(now, 0)
			return nil, admission, nil
		}
		if settings.RemoteQueueCount <= len(pool.waiters) {
			return nil, nil, &SidecarRemoteRefusal{Reason: SidecarRemoteRefusedQueueFull, RetryAfter: settings.RemoteQueueTimeout}
		}
		waiter := &remoteBudgetWaiter{budget: self, queuedAt: now, ready: make(chan struct{})}
		pool.waiters = append(pool.waiters, waiter)
		return waiter, nil, nil
	}()
	if refusal != nil {
		return nil, refusal
	}
	if admission != nil {
		return admission, nil
	}
	timeout := pool.clock.After(settings.RemoteQueueTimeout)
	var waitErr error
	select {
	case <-waiter.ready:
	case <-timeout:
		waitErr = &SidecarRemoteRefusal{Reason: SidecarRemoteRefusedQueueTimeout, RetryAfter: settings.RemoteQueueTimeout}
	case <-ctx.Done():
		waitErr = ctx.Err()
	}
	granted := func() *SidecarRemoteAdmission {
		pool.stateLock.Lock()
		defer pool.stateLock.Unlock()
		if waiter.granted == nil {
			// still waiting: leave the queue, so no slot is handed to a request that went
			waiter.gone = true
			for index, queued := range pool.waiters {
				if queued == waiter {
					pool.waiters = append(pool.waiters[:index], pool.waiters[index+1:]...)
					break
				}
			}
		}
		return waiter.granted
	}()
	switch {
	case granted != nil && waitErr == nil:
		return granted, nil
	case granted != nil:
		// a slot came as the wait ended: take it, since the request is still here and the slot is held already
		if ctx.Err() != nil {
			granted.Release()
			return nil, ctx.Err()
		}
		return granted, nil
	}
	return nil, waitErr
}

// A new admission holding a slot from now, which waited queueWait, with the pool's lock held.
func (self *SidecarRemoteBudget) admitWithLock(now time.Time, queueWait time.Duration) *SidecarRemoteAdmission {
	admission := &SidecarRemoteAdmission{budget: self, admittedAt: now, queueWait: queueWait}
	self.pool.computing[admission] = true
	if self.stats != nil && 0 < queueWait {
		self.stats.remoteQueueWaitCount.Add(1)
		self.stats.remoteQueueWaitNanos.Add(int64(queueWait))
	}
	return admission
}

// Hands each freed slot to the oldest waiter, with the pool's lock held.
func (self *remoteBudgetPool) grantWithLock(now time.Time) {
	for 0 < len(self.waiters) && len(self.computing) < self.settings.RemoteSearchCount {
		waiter := self.waiters[0]
		self.waiters = self.waiters[1:]
		if waiter.gone {
			continue
		}
		waiter.granted = waiter.budget.admitWithLock(now, now.Sub(waiter.queuedAt))
		close(waiter.ready)
	}
}

// One request's hold on a compute slot, from Admit to Release. Safe for concurrent use.
type SidecarRemoteAdmission struct {
	budget     *SidecarRemoteBudget
	admittedAt time.Time
	queueWait  time.Duration

	stateLock sync.Mutex
	released  bool
	// the memory this search holds, within RemoteSearchMemoryByteCount
	reservedByteCount int64
}

// How long the request waited for its slot.
func (self *SidecarRemoteAdmission) QueueWait() time.Duration {
	return self.queueWait
}

// Gives the slot back, charging the window with the time it was held, which it answers: at the end of the request, or
// at step 4 for a repeat, which computes nothing. Safe to call again, which charges nothing.
func (self *SidecarRemoteAdmission) Release() time.Duration {
	released := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.released {
			return false
		}
		self.released = true
		self.reservedByteCount = 0
		return true
	}()
	if !released {
		return 0
	}
	pool := self.budget.pool
	pool.stateLock.Lock()
	defer pool.stateLock.Unlock()
	now := pool.clock.Now()
	held := now.Sub(self.admittedAt)
	delete(pool.computing, self)
	pool.charges = append(pool.charges, remoteBudgetCharge{at: now, cpu: held})
	if stats := self.budget.stats; stats != nil {
		stats.remoteCpuNanos.Add(int64(held))
	}
	pool.grantWithLock(now)
	return held
}

// Takes byteCount more of this search's memory: false, taking nothing, past RemoteSearchMemoryByteCount (8 MiB a
// computing search, D-CORE-17), and after Release.
func (self *SidecarRemoteAdmission) Reserve(byteCount int64) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.released || byteCount < 0 || self.budget.pool.settings.RemoteSearchMemoryByteCount < self.reservedByteCount+byteCount {
		return false
	}
	self.reservedByteCount += byteCount
	return true
}

// Gives byteCount of this search's memory back.
func (self *SidecarRemoteAdmission) Free(byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reservedByteCount = max(0, self.reservedByteCount-max(0, byteCount))
}

// A page's meter, started now: PageCpu and PageCandidateCount (§16.10, DESIGN-DETAILS 7.2.5's step 7).
func (self *SidecarRemoteAdmission) Page() *SidecarRemotePage {
	return &SidecarRemotePage{admission: self, startedAt: self.budget.pool.clock.Now()}
}

// One page's spend: its verifications and its compute time. Not safe for concurrent use: a page is one goroutine's.
type SidecarRemotePage struct {
	admission *SidecarRemoteAdmission
	startedAt time.Time
	verified  int
}

// Whether the page has spent its PageCpu or its PageCandidateCount verifications, when it stops PARTIAL.
func (self *SidecarRemotePage) Spent() bool {
	settings := self.admission.budget.pool.settings
	return settings.PageCandidateCount <= self.verified ||
		settings.PageCpu <= self.admission.budget.pool.clock.Now().Sub(self.startedAt)
}

// Counts one verification about to run: false, counting nothing, once the page has spent its budget.
func (self *SidecarRemotePage) Verify() bool {
	if self.Spent() {
		return false
	}
	self.verified += 1
	return true
}

// The verifications counted.
func (self *SidecarRemotePage) Verified() int {
	return self.verified
}

// Registers an open remote cursor (§11.14's limits row): past RemoteCursorCount over every requester the least recently
// used is ended, end called outside every lock. touch marks it used; release takes it off without ending it, as its own
// end does. Each is safe to call again.
func (self *SidecarRemoteBudget) AddCursor(end func()) (touch func(), release func()) {
	pool := self.pool
	cursor := &remoteBudgetCursor{end: end}
	ended := func() []func() {
		pool.stateLock.Lock()
		defer pool.stateLock.Unlock()
		pool.cursors.PushFront(cursor)
		ended := []func(){}
		for pool.settings.RemoteCursorCount < pool.cursors.Len() {
			oldest := pool.cursors.Back()
			pool.cursors.Remove(oldest)
			ended = append(ended, oldest.Value.(*remoteBudgetCursor).end)
		}
		return ended
	}()
	for _, end := range ended {
		if end != nil {
			end()
		}
	}
	find := func() *list.Element {
		for element := pool.cursors.Front(); element != nil; element = element.Next() {
			if element.Value.(*remoteBudgetCursor) == cursor {
				return element
			}
		}
		return nil
	}
	touch = func() {
		pool.stateLock.Lock()
		defer pool.stateLock.Unlock()
		if element := find(); element != nil {
			pool.cursors.MoveToFront(element)
		}
	}
	release = func() {
		pool.stateLock.Lock()
		defer pool.stateLock.Unlock()
		if element := find(); element != nil {
			pool.cursors.Remove(element)
		}
	}
	return touch, release
}

// The cursors open now.
func (self *SidecarRemoteBudget) CursorCount() int {
	self.pool.stateLock.Lock()
	defer self.pool.stateLock.Unlock()
	return self.pool.cursors.Len()
}

// The requests computing and waiting now.
func (self *SidecarRemoteBudget) Load() (computing int, waiting int) {
	self.pool.stateLock.Lock()
	defer self.pool.stateLock.Unlock()
	for _, waiter := range self.pool.waiters {
		if !waiter.gone {
			waiting += 1
		}
	}
	return len(self.pool.computing), waiting
}
