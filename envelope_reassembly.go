// Rebuilding chunked bodies (§6.5), on every leg. A peer's chunks ride one sequence, so they arrive in
// order, and a group that breaks order or repeats its header wrongly is dropped: if the sequence exited,
// the sender resends the whole message, which arrives as a fresh index 0 and restarts the group
// (plan-PROTO-small-readings.md's reading 1).
//
// The first chunk reserves the whole declared length, so a peer that declares much and sends nothing
// costs what the caps allow and no more, and the reservation goes back when the group completes, breaks
// or sits idle past ReassemblyIdleTimeout. No chunk's bytes are kept: each is copied into the group.
//
// This layer takes no connect type. A connect-facing caller converts its source with Id(sourceId).

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What reassembly reads time from: the two methods of Clock it uses, so a test holds every wait on a
// clock it moves. The Subprotocol passes its own Clock, SubprotocolEnv.Clock or real time.
type subprotocolClock interface {
	Now() time.Time
	// Fires once the clock reaches now plus timeout.
	After(timeout time.Duration) <-chan time.Time
}

// Names one body from one source: (source, request_id, RESPONSE), the source being the map above this
// key, so a request and the response that echoes its id never share a group.
type reassemblyGroupKey struct {
	requestId uint64
	response  bool
}

// One body being rebuilt. The header fields are the first chunk's, which every later chunk repeats.
type reassemblyGroup struct {
	version        uint32
	messageType    uint32
	flags          uint32
	streamId       uint64
	timeoutMs      uint32
	totalByteCount uint32

	nextIndex uint32
	body      []byte
	// when the group goes if no chunk arrives first
	deadline time.Time
}

// Whether envelope is the chunk this group waits for, repeating everything the first chunk fixed. Its
// count needs no check here: chunkFitsLayout has held that to its total. The group is the reassembler's
// state, read under its lock.
func (self *reassemblyGroup) extendedByWithLock(envelope *protocol.Envelope) bool {
	return envelope.Version == self.version &&
		envelope.Type == self.messageType &&
		envelope.Flags&^EnvelopeFlagMore == self.flags &&
		envelope.StreamId == self.streamId &&
		envelope.TimeoutMs == self.timeoutMs &&
		envelope.Chunk.TotalByteCount == self.totalByteCount &&
		envelope.Chunk.Index == self.nextIndex
}

// One source's groups and what they reserve. A peer with no group has no entry, so sources that came and
// went cost nothing.
type reassemblyPeer struct {
	keyGroups map[reassemblyGroupKey]*reassemblyGroup
	byteCount int64
}

// What a reassembler has done, for a host's stats.
type reassemblyStats struct {
	// bodies rebuilt
	completedCount uint64
	// chunks that ended or found no group, hash failures included
	droppedCount uint64
	// first chunks over a cap
	refusedCount uint64
	// groups that sat idle past their deadline
	expiredCount uint64
}

// Rebuilds every peer's chunked bodies for one Subprotocol. Each cap answers errReassemblyExhausted at a
// body's first chunk: the body's own limit, the peer's count and bytes, and the process's budget, which
// is shared with every other Subprotocol the host runs.
//
// The constructor starts run, which expires idle groups. close stops it and gives every reservation
// back. offer is safe for concurrent use, and a caller keeps one peer's chunks in order.
type reassembler struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *SidecarProtocolSettings
	budget   *SubprotocolBudget
	clock    subprotocolClock
	log      Logger
	// closes when run has ended and let go of everything
	runDone chan struct{}

	stateLock     sync.Mutex
	sourceIdPeers map[Id]*reassemblyPeer
	closed        bool
	stats         reassemblyStats
	// groups held, which wakes run when the first arrives
	groupCount *MonitorValue[int]
}

// A running reassembler, which ends with ctx or close. A nil log discards. budget and settings are
// shared and outlive it.
func newReassembler(
	ctx context.Context,
	settings *SidecarProtocolSettings,
	budget *SubprotocolBudget,
	clock subprotocolClock,
	log Logger,
) *reassembler {
	if log == nil {
		log = NewNoopLogger()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &reassembler{
		ctx:           cancelCtx,
		cancel:        cancel,
		settings:      settings,
		budget:        budget,
		clock:         clock,
		log:           log,
		runDone:       make(chan struct{}),
		sourceIdPeers: map[Id]*reassemblyPeer{},
		groupCount:    NewMonitorValue(0),
	}
	go self.run()
	return self
}

// While any group is held, sleeps to the earliest deadline and then drops what is due. A group added
// during the sleep cannot beat that deadline, since every deadline is its last chunk's time plus one
// timeout, so only an empty set has to be woken. A group's arrival only wakes run to sleep: every drop
// follows a wait the clock fired, so whoever moves the clock decides when run drops anything.
func (self *reassembler) run() {
	defer close(self.runDone)
	defer self.dropAll()
	for {
		groupCount, notify := self.groupCount.Get()
		if groupCount == 0 {
			select {
			case <-self.ctx.Done():
				return
			case <-notify:
			}
			continue
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.untilNextDeadline()):
		}
		self.expire()
	}
}

// Stops run and waits for it. Every reservation is back in the budget when this returns.
func (self *reassembler) close() {
	self.cancel()
	<-self.runDone
}

// Refuses from here on and gives everything back.
func (self *reassembler) dropAll() {
	var freedByteCount int64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		for sourceId, peer := range self.sourceIdPeers {
			for key := range peer.keyGroups {
				freedByteCount += self.removeWithLock(sourceId, key)
			}
		}
	}()
	self.budget.releaseReassembly(freedByteCount)
}

// How long from now until the earliest deadline, which is due when this is not positive, and 0 when no
// group is held.
func (self *reassembler) untilNextDeadline() time.Duration {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var nextDeadline time.Time
	for _, peer := range self.sourceIdPeers {
		for _, group := range peer.keyGroups {
			if nextDeadline.IsZero() || group.deadline.Before(nextDeadline) {
				nextDeadline = group.deadline
			}
		}
	}
	if nextDeadline.IsZero() {
		return 0
	}
	return nextDeadline.Sub(now)
}

// Drops every group past its deadline.
func (self *reassembler) expire() {
	testHookBarrier("envelope.reassembly_expire.before", "")
	defer testHookBarrier("envelope.reassembly_expire.after", "")
	now := self.clock.Now()
	var freedByteCount int64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for sourceId, peer := range self.sourceIdPeers {
			for key, group := range peer.keyGroups {
				if !now.Before(group.deadline) {
					freedByteCount += self.removeWithLock(sourceId, key)
					self.stats.expiredCount += 1
				}
			}
		}
	}()
	self.budget.releaseReassembly(freedByteCount)
}

// Takes a group out and says what it reserved, which the caller gives back to the budget once it holds
// no lock. A key with no group is 0.
func (self *reassembler) removeWithLock(sourceId Id, key reassemblyGroupKey) int64 {
	peer := self.sourceIdPeers[sourceId]
	if peer == nil {
		return 0
	}
	group := peer.keyGroups[key]
	if group == nil {
		return 0
	}
	delete(peer.keyGroups, key)
	byteCount := int64(group.totalByteCount)
	peer.byteCount -= byteCount
	if len(peer.keyGroups) == 0 {
		delete(self.sourceIdPeers, sourceId)
	}
	self.groupCount.Update(func(groupCount int) int {
		return groupCount - 1
	})
	return byteCount
}

// Clears what a first chunk replaces: the group it restarts, and the source's groups past their
// deadline, so a cap never counts what has already expired.
func (self *reassembler) clearWithLock(sourceId Id, key reassemblyGroupKey, now time.Time) int64 {
	freedByteCount := self.removeWithLock(sourceId, key)
	if peer := self.sourceIdPeers[sourceId]; peer != nil {
		for otherKey, group := range peer.keyGroups {
			if !now.Before(group.deadline) {
				freedByteCount += self.removeWithLock(sourceId, otherKey)
				self.stats.expiredCount += 1
			}
		}
	}
	return freedByteCount
}

// Whether one more body of totalByteCount fits the source's caps and its own.
func (self *reassembler) fitsWithLock(sourceId Id, totalByteCount int64) bool {
	if self.closed {
		return false
	}
	maxBodyByteCount := min(self.settings.ReassemblyMaxBodyByteCount, MaxReassemblyBodyByteCount)
	if maxBodyByteCount < totalByteCount {
		return false
	}
	peer := self.sourceIdPeers[sourceId]
	if peer == nil {
		return totalByteCount <= self.settings.ReassemblyPeerByteCount
	}
	return len(peer.keyGroups) < self.settings.ReassemblyPeerCount &&
		totalByteCount <= self.settings.ReassemblyPeerByteCount-peer.byteCount
}

// Counts a chunk dropped, says why at a level that shows it, and hands back what offer returns.
func (self *reassembler) dropped(sourceId Id, reason string) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.stats.droppedCount += 1
	}()
	if self.log.V(1).Enabled() {
		self.log.Infof("[reassembly]%s drop: %s\n", sourceId, reason)
	}
	return errReassemblyDropped
}

// Counts a first chunk refused and hands back what offer returns.
func (self *reassembler) refused(sourceId Id) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.stats.refusedCount += 1
	}()
	if self.log.V(1).Enabled() {
		self.log.Infof("[reassembly]%s over a cap\n", sourceId)
	}
	return errReassemblyExhausted
}

// What reassembly has done so far.
func (self *reassembler) currentStats() reassemblyStats {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.stats
}

// Takes one envelope from source, in the order it arrived:
//
//   - the whole message, when envelope carries no chunk or completes a group. A plain envelope comes back
//     as it went in, and a rebuilt one is new and owns its body, with no Chunk and no MORE;
//   - nil and nil, when envelope extends a group that goes on;
//   - errReassemblyExhausted, when a first chunk would pass a cap, which answers RESOURCE_EXHAUSTED. Its
//     later chunks find no group and are dropped, so one body gets one answer;
//   - errReassemblyDropped otherwise, the group gone.
//
// envelope and its body are borrowed for the call.
func (self *reassembler) offer(sourceId Id, envelope *protocol.Envelope) (*protocol.Envelope, error) {
	if envelope.Chunk == nil {
		if envelope.Flags&EnvelopeFlagMore != 0 {
			return nil, self.dropped(sourceId, "more with no chunk")
		}
		return envelope, nil
	}
	key := reassemblyGroupKey{
		requestId: envelope.RequestId,
		response:  envelope.Flags&EnvelopeFlagResponse != 0,
	}
	if !chunkFitsLayout(envelope) {
		// a chunk that breaks §6.5's layout breaks its group too, wherever it falls
		var freedByteCount int64
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			freedByteCount = self.removeWithLock(sourceId, key)
		}()
		self.budget.releaseReassembly(freedByteCount)
		return nil, self.dropped(sourceId, "chunk off its layout")
	}
	if envelope.Chunk.Index == 0 {
		return nil, self.begin(sourceId, key, envelope)
	}
	return self.extend(sourceId, key, envelope)
}

// Whether a chunk has the shape its position in its declared length fixes. Only a body past
// MaxEnvelopeBodyByteCount is chunked, MORE marks every chunk but the final, and only the final holds the
// hash. A length this allows may still be over a cap, which begin answers differently.
func chunkFitsLayout(envelope *protocol.Envelope) bool {
	chunk := envelope.Chunk
	totalByteCount := int64(chunk.TotalByteCount)
	if totalByteCount <= MaxEnvelopeBodyByteCount {
		return false
	}
	_, _, chunkCount := chunkLayout(totalByteCount)
	index := int64(chunk.Index)
	if int64(chunk.Count) != chunkCount || chunkCount <= index {
		return false
	}
	if int64(len(envelope.Body)) != chunkByteCount(totalByteCount, index) {
		return false
	}
	more := envelope.Flags&EnvelopeFlagMore != 0
	if index == chunkCount-1 {
		return !more && len(chunk.Sha256) == sha256.Size
	}
	return more && len(chunk.Sha256) == 0
}

// Starts a group at its first chunk, replacing any group of that key, since a fresh index 0 means the
// sender resent the whole message. The budget sits outside this lock, so the caps are read, the budget
// taken, and the caps read again as the group goes in.
func (self *reassembler) begin(sourceId Id, key reassemblyGroupKey, envelope *protocol.Envelope) error {
	sourceKey := sourceId.String()
	testHookBarrier("envelope.reassembly_reserve.before", sourceKey)
	defer testHookBarrier("envelope.reassembly_reserve.after", sourceKey)

	now := self.clock.Now()
	totalByteCount := int64(envelope.Chunk.TotalByteCount)
	var freedByteCount int64
	fits := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		freedByteCount = self.clearWithLock(sourceId, key, now)
		fits = self.fitsWithLock(sourceId, totalByteCount)
	}()
	self.budget.releaseReassembly(freedByteCount)
	if !fits || !self.budget.reserveReassembly(totalByteCount) {
		return self.refused(sourceId)
	}

	testHookBarrier("envelope.reassembly_reserve", sourceKey)
	group := &reassemblyGroup{
		version:        envelope.Version,
		messageType:    envelope.Type,
		flags:          envelope.Flags &^ EnvelopeFlagMore,
		streamId:       envelope.StreamId,
		timeoutMs:      envelope.TimeoutMs,
		totalByteCount: envelope.Chunk.TotalByteCount,
		nextIndex:      1,
		body:           append(make([]byte, 0, totalByteCount), envelope.Body...),
		deadline:       now.Add(self.settings.ReassemblyIdleTimeout),
	}
	added := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		freedByteCount = self.clearWithLock(sourceId, key, now)
		if !self.fitsWithLock(sourceId, totalByteCount) {
			return
		}
		peer := self.sourceIdPeers[sourceId]
		if peer == nil {
			peer = &reassemblyPeer{keyGroups: map[reassemblyGroupKey]*reassemblyGroup{}}
			self.sourceIdPeers[sourceId] = peer
		}
		peer.keyGroups[key] = group
		peer.byteCount += totalByteCount
		self.groupCount.Update(func(groupCount int) int {
			return groupCount + 1
		})
		added = true
	}()
	self.budget.releaseReassembly(freedByteCount)
	if !added {
		self.budget.releaseReassembly(totalByteCount)
		return self.refused(sourceId)
	}
	return nil
}

// Adds a later chunk to its group, and at the final chunk checks the hash and gives the body back. The
// hash runs after the group is out and the lock is free, since it reads the whole body.
func (self *reassembler) extend(sourceId Id, key reassemblyGroupKey, envelope *protocol.Envelope) (*protocol.Envelope, error) {
	final := envelope.Chunk.Index+1 == envelope.Chunk.Count
	if final {
		sourceKey := sourceId.String()
		testHookBarrier("envelope.reassembly_complete.before", sourceKey)
		defer testHookBarrier("envelope.reassembly_complete.after", sourceKey)
	}

	now := self.clock.Now()
	var freedByteCount int64
	var completed *reassemblyGroup
	reason := ""
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		var group *reassemblyGroup
		if peer := self.sourceIdPeers[sourceId]; peer != nil {
			group = peer.keyGroups[key]
		}
		switch {
		case group == nil:
			reason = "no group"
		case !now.Before(group.deadline):
			freedByteCount = self.removeWithLock(sourceId, key)
			self.stats.expiredCount += 1
			reason = "group idle"
		case !group.extendedByWithLock(envelope):
			freedByteCount = self.removeWithLock(sourceId, key)
			reason = "chunk out of its group"
		default:
			group.body = append(group.body, envelope.Body...)
			group.nextIndex += 1
			group.deadline = now.Add(self.settings.ReassemblyIdleTimeout)
			if final {
				freedByteCount = self.removeWithLock(sourceId, key)
				completed = group
			}
		}
	}()
	self.budget.releaseReassembly(freedByteCount)
	if reason != "" {
		return nil, self.dropped(sourceId, reason)
	}
	if completed == nil {
		return nil, nil
	}
	hash := sha256.Sum256(completed.body)
	if !bytes.Equal(hash[:], envelope.Chunk.Sha256) {
		return nil, self.dropped(sourceId, "hash")
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.stats.completedCount += 1
	}()
	return &protocol.Envelope{
		Version:   completed.version,
		Type:      completed.messageType,
		RequestId: envelope.RequestId,
		Flags:     completed.flags,
		StreamId:  completed.streamId,
		TimeoutMs: completed.timeoutMs,
		Body:      completed.body,
	}, nil
}
