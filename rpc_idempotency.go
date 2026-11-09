//go:build !sidecar_http

// Idempotency for mutating handlers (§6.6, D-PROTO-3): a retry keeps its request_id, so a receiver that
// remembers what it answered under (source, request_id) answers the retry from memory and runs nothing
// twice. A retry that arrives while the first run is live joins it rather than starting a second.
//
// What is kept is bounded three ways: IdempotencyTimeout after a run finishes, after which the entry
// expires; IdempotencyPeerByteCount per peer, past which that peer's oldest finished entries go first;
// and IdempotencyProcessByteCount, the process's share of §5's budget, past which an answer is not kept.
// A response over IdempotencyMaxResponseByteCount is never kept: the entry remembers only that it ran
// and the result_ref its handler set, and a retry gets Error{ALREADY_EXISTS} with that ref. An evicted
// or refused entry is forgotten, so a retry after it runs the handler again, which is what the caps cost.
//
// Read and written under its own lock, held for map and list work only.

package sidecar

import (
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// What every kept entry costs beyond its bytes: its key, times and bookkeeping.
const idempotencyEntryOverheadByteCount = 128

// One call by its peer and request_id.
type rpcCallKey struct {
	sourceId  connect.Id
	requestId uint64
}

// What a run answered, which a retry is answered with.
type idempotencyOutcome struct {
	body    []byte
	refusal *SubprotocolError
	// set when the response was too large to keep: a retry gets ALREADY_EXISTS with this ref
	uncached  bool
	resultRef []byte
}

// One call's entry: live while its run is, then its outcome until it expires.
type idempotencyEntry struct {
	key rpcCallKey
	// closed when the run finishes, after outcome is set
	done    chan struct{}
	outcome *idempotencyOutcome
	// what the entry holds against the caps, once finished
	byteCount  int64
	expireTime time.Time
	finished   bool
}

// What begin found.
type idempotencyBegin int

const (
	// no entry: the caller runs the handler and then calls finish
	idempotencyRun idempotencyBegin = iota
	// a run is live: wait on the entry's done and answer with its outcome
	idempotencyJoin
	// a finished entry: answer with its outcome now
	idempotencyAnswered
)

// One Subprotocol's kept answers. See the file header.
type idempotencyCache struct {
	settings *SidecarProtocolSettings
	budget   *SubprotocolBudget
	clock    Clock

	stateLock sync.Mutex
	entries   map[rpcCallKey]*idempotencyEntry
	// finished entries in the order they finished, which is the order they expire
	finishedEntries []*idempotencyEntry
	peerByteCounts  map[connect.Id]int64
}

// An empty cache under settings' bounds, reserving from budget, timed by clock.
func newIdempotencyCache(settings *SidecarProtocolSettings, budget *SubprotocolBudget, clock Clock) *idempotencyCache {
	return &idempotencyCache{
		settings:       settings,
		budget:         budget,
		clock:          clock,
		entries:        map[rpcCallKey]*idempotencyEntry{},
		peerByteCounts: map[connect.Id]int64{},
	}
}

// Takes entry out of the cache and gives back what it held. Called with stateLock held.
func (self *idempotencyCache) removeWithLock(entry *idempotencyEntry) {
	if self.entries[entry.key] == entry {
		delete(self.entries, entry.key)
	}
	if entry.finished && 0 < entry.byteCount {
		self.peerByteCounts[entry.key.sourceId] -= entry.byteCount
		if self.peerByteCounts[entry.key.sourceId] <= 0 {
			delete(self.peerByteCounts, entry.key.sourceId)
		}
		self.budget.releaseIdempotency(entry.byteCount)
		entry.byteCount = 0
	}
}

// Drops every finished entry whose time has passed, from the front of the finish order. Called with
// stateLock held.
func (self *idempotencyCache) expireWithLock(now time.Time) {
	dropCount := 0
	for _, entry := range self.finishedEntries {
		if now.Before(entry.expireTime) {
			break
		}
		self.removeWithLock(entry)
		dropCount += 1
	}
	if 0 < dropCount {
		self.finishedEntries = append(self.finishedEntries[:0], self.finishedEntries[dropCount:]...)
	}
}

// What key's call should do now: run, join a live run, or answer from a finished one.
func (self *idempotencyCache) begin(key rpcCallKey) (idempotencyBegin, *idempotencyEntry) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.expireWithLock(now)
	entry := self.entries[key]
	switch {
	case entry == nil:
		entry = &idempotencyEntry{key: key, done: make(chan struct{})}
		self.entries[key] = entry
		return idempotencyRun, entry
	case !entry.finished:
		return idempotencyJoin, entry
	}
	return idempotencyAnswered, entry
}

// Records entry's outcome, keeping it within the caps or forgetting it, and wakes every caller that
// joined it.
func (self *idempotencyCache) finish(entry *idempotencyEntry, outcome *idempotencyOutcome) {
	now := self.clock.Now()
	defer close(entry.done)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry.outcome = outcome
	entry.finished = true
	entry.expireTime = now.Add(self.settings.IdempotencyTimeout)
	byteCount := int64(idempotencyEntryOverheadByteCount + len(outcome.body) + len(outcome.resultRef))
	if outcome.refusal != nil {
		byteCount += int64(len(outcome.refusal.Message) + len(outcome.refusal.ResultRef))
	}
	if self.settings.IdempotencyPeerByteCount < byteCount {
		self.removeWithLock(entry)
		return
	}
	// this peer's oldest finished entries go first, until the new one fits its share
	for self.settings.IdempotencyPeerByteCount < self.peerByteCounts[entry.key.sourceId]+byteCount {
		oldest := -1
		for index, finished := range self.finishedEntries {
			if finished.key.sourceId == entry.key.sourceId && self.entries[finished.key] == finished {
				oldest = index
				break
			}
		}
		if oldest < 0 {
			break
		}
		evicted := self.finishedEntries[oldest]
		self.finishedEntries = append(self.finishedEntries[:oldest], self.finishedEntries[oldest+1:]...)
		self.removeWithLock(evicted)
	}
	if self.settings.IdempotencyPeerByteCount < self.peerByteCounts[entry.key.sourceId]+byteCount || !self.budget.reserveIdempotency(byteCount) {
		// past a cap: forgotten, so a retry runs again
		self.removeWithLock(entry)
		return
	}
	entry.byteCount = byteCount
	self.peerByteCounts[entry.key.sourceId] += byteCount
	self.finishedEntries = append(self.finishedEntries, entry)
}

// Forgets everything and gives back what it held: the Subprotocol has closed.
func (self *idempotencyCache) close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, entry := range self.finishedEntries {
		self.removeWithLock(entry)
	}
	self.finishedEntries = nil
}

// How many bytes the cache holds for sourceId now, for tests and stats.
func (self *idempotencyCache) peerByteCount(sourceId connect.Id) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.peerByteCounts[sourceId]
}

// The outcome a handler's answer makes: its body, kept only up to IdempotencyMaxResponseByteCount, or
// its refusal.
func (self *idempotencyCache) outcomeOf(body []byte, refusal *SubprotocolError, resultRef []byte) *idempotencyOutcome {
	if refusal != nil {
		return &idempotencyOutcome{refusal: refusal}
	}
	if self.settings.IdempotencyMaxResponseByteCount < int64(len(body)) {
		return &idempotencyOutcome{uncached: true, resultRef: append([]byte(nil), resultRef...)}
	}
	return &idempotencyOutcome{body: append([]byte(nil), body...)}
}

// The refusal a retry of an uncached response gets: ALREADY_EXISTS with the handler's result_ref.
func (self *idempotencyOutcome) retryRefusal() *SubprotocolError {
	if self.uncached {
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_ALREADY_EXISTS, ResultRef: self.resultRef}
	}
	return self.refusal
}
