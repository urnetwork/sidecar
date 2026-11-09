// A component's inbound queue (§5.4, D-CORE-3): complete envelopes a source's dispatch worker hands on, offered
// with zero wait, bounded by ComponentQueueMessageCount and ComponentQueueByteCount, and drained in order by the
// queue's own worker. A full queue drops and counts (connect/CODESTYLE.md:119), so one slow component never holds
// up a source's worker, which serves every other component of that source. Stream bytes never come here: §6's
// credit bounds them, since they cannot be dropped (:123).
//
// One queue serves one component for one client generation, and closing it joins its worker. Its counters belong
// to the Sidecar and outlive the generation, so `ur status --stats` counts across them. Nothing here names a
// connect type, so it builds on every leg.

package sidecar

import (
	"context"
	"sync"
	"sync/atomic"
)

// One component's running totals, kept across its client generations. Each counts envelopes, never what they are
// or whom they came from (I-13).
type sidecarQueueCounters struct {
	// taken by offer
	queuedCount atomic.Uint64
	// run by the worker
	ranCount atomic.Uint64
	// refused by a full queue, one over the bounds by itself, or a queue closing with them in it
	droppedCount     atomic.Uint64
	droppedByteCount atomic.Uint64
	// a function that panicked, which the worker kept to that item
	panicCount atomic.Uint64
}

// One item: what it holds, for the byte bound, and the function the worker runs.
type sidecarQueueItem struct {
	byteCount int64
	run       func(ctx context.Context)
}

// A bounded, zero-wait queue and its worker. Construct with newSidecarComponentQueue, which starts the worker. Safe
// for concurrent use.
type sidecarComponentQueue struct {
	ctx          context.Context
	cancel       context.CancelFunc
	messageCount int
	byteCount    int64
	counters     *sidecarQueueCounters
	log          Logger
	// one slot: the worker's wake, which an offer fills and never waits on
	notify chan struct{}
	done   chan struct{}

	stateLock       sync.Mutex
	items           []sidecarQueueItem
	queuedByteCount int64
	closed          bool
}

// A running queue that holds at most messageCount items and byteCount bytes, its worker running each item with a
// ctx that ends with ctx or closeAndWait.
func newSidecarComponentQueue(ctx context.Context, messageCount int, byteCount int64, counters *sidecarQueueCounters, log Logger) *sidecarComponentQueue {
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &sidecarComponentQueue{
		ctx:          cancelCtx,
		cancel:       cancel,
		messageCount: messageCount,
		byteCount:    byteCount,
		counters:     counters,
		log:          log,
		notify:       make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
	go self.run()
	return self
}

// Takes run, which byteCount bytes of an envelope's body stand behind, or refuses it at once: when the queue is
// full by either bound, when the item alone passes the byte bound, or once the queue closes. Never waits, so a
// receive path may call it. A refusal is counted, and the caller drops what it holds.
func (self *sidecarComponentQueue) offer(byteCount int, run func(ctx context.Context)) bool {
	itemByteCount := int64(max(byteCount, 0))
	taken := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || self.messageCount <= len(self.items) || self.byteCount < self.queuedByteCount+itemByteCount {
			return false
		}
		self.items = append(self.items, sidecarQueueItem{byteCount: itemByteCount, run: run})
		self.queuedByteCount += itemByteCount
		return true
	}()
	if !taken {
		self.counters.droppedCount.Add(1)
		self.counters.droppedByteCount.Add(uint64(itemByteCount))
		return false
	}
	self.counters.queuedCount.Add(1)
	select {
	case self.notify <- struct{}{}:
	default:
	}
	return true
}

// Drains the queue in order until it closes. Each item runs outside the lock; a panic stays with its item.
func (self *sidecarComponentQueue) run() {
	defer close(self.done)
	for {
		var item sidecarQueueItem
		ok := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if len(self.items) == 0 {
				return false
			}
			item = self.items[0]
			self.items[0] = sidecarQueueItem{}
			self.items = self.items[1:]
			self.queuedByteCount -= item.byteCount
			return true
		}()
		if !ok {
			select {
			case <-self.ctx.Done():
				return
			case <-self.notify:
			}
			continue
		}
		if self.ctx.Err() != nil {
			self.counters.droppedCount.Add(1)
			self.counters.droppedByteCount.Add(uint64(item.byteCount))
			continue
		}
		self.runItem(item)
	}
}

// Runs one item, keeping a panic to it.
func (self *sidecarComponentQueue) runItem(item sidecarQueueItem) {
	defer func() {
		if r := recover(); r != nil {
			self.counters.panicCount.Add(1)
			self.log.Errorf("[sidecar]a queued component call panicked: %v", r)
		}
	}()
	self.counters.ranCount.Add(1)
	item.run(self.ctx)
}

// Refuses further offers, ends the worker's ctx, and waits for the worker, which drops what is still queued and
// counts it. Safe to call again.
func (self *sidecarComponentQueue) closeAndWait() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
	}()
	self.cancel()
	<-self.done
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, item := range self.items {
			self.counters.droppedCount.Add(1)
			self.counters.droppedByteCount.Add(uint64(item.byteCount))
		}
		self.items = nil
		self.queuedByteCount = 0
	}()
}
