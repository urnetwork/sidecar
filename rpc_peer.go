//go:build !sidecar_http

// What the dispatcher keeps per source: a bounded queue with the worker that drains it, and the
// identity gate's record of a verified Hello.
//
// The queue is how the inline handler hands work on without waiting. It holds at most
// PeerQueueMessageCount envelopes, each with its body copied into a pool buffer the queue owns
// (connect.RetainSubprotocolBytes), so the frame connect lent the handler is free when the handler
// returns. A source has a worker while its queue holds anything: the handler starts one when it queues
// into an idle queue, and the worker retires, taking the queue with it, when it finds the queue empty.
// Both happen under stateLock, so an envelope is never queued behind a worker that has gone. One
// source's slow component stalls only that source: a full queue refuses with RESOURCE_EXHAUSTED and
// every other source keeps its own worker.
//
// The gate is closed for every peer until its Hello or HelloResult verifies (rpc_hello.go). A record
// names C15's key on the frame that verified it and the peer it showed, and ends at HelloCacheTimeout; a
// frame under another key closes the gate at once (plan-PROTO-small-readings.md's reading 1).

package sidecar

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// One source's queue. Read and written under the Subprotocol's stateLock.
type subprotocolPeer struct {
	sourceId connect.Id
	// oldest first, from head; at most PeerQueueMessageCount waiting
	queuedItems []subprotocolInbound
	head        int
	// whether a worker drains this queue
	running bool
}

// How many envelopes wait.
func (self *subprotocolPeer) queuedCountWithLock() int {
	return len(self.queuedItems) - self.head
}

// Adds item at the back. The slice is reused from its start rather than grown while it has room before
// head, so a source that is never quite drained holds at most a full queue's worth of it.
func (self *subprotocolPeer) pushWithLock(item subprotocolInbound) {
	switch {
	case self.head == len(self.queuedItems):
		self.queuedItems = self.queuedItems[:0]
		self.head = 0
	case 0 < self.head && len(self.queuedItems) == cap(self.queuedItems):
		waitingCount := copy(self.queuedItems, self.queuedItems[self.head:])
		clear(self.queuedItems[waitingCount:])
		self.queuedItems = self.queuedItems[:waitingCount]
		self.head = 0
	}
	self.queuedItems = append(self.queuedItems, item)
}

// Takes the oldest, which the caller has checked exists.
func (self *subprotocolPeer) popWithLock() subprotocolInbound {
	item := self.queuedItems[self.head]
	// what the slice keeps past this would otherwise pin the body's release
	self.queuedItems[self.head] = subprotocolInbound{}
	self.head += 1
	return item
}

// One envelope past the inline checks, waiting in its source's queue: every field the handler read,
// copied out of a message connect lent it. A value, so queueing it copies and allocates nothing more.
type subprotocolInbound struct {
	sourceId    connect.Id
	transferKey connect.TransferKey
	// C15's key on the frame, read once by the inline handler for the gate and for Hello's check
	clientPublicKey    [ed25519.PublicKeySize]byte
	hasClientPublicKey bool
	arrivalTime        time.Time

	version     uint32
	messageType uint32
	requestId   uint64
	flags       uint32
	streamId    uint64
	timeoutMs   uint32

	hasChunk            bool
	chunkIndex          uint32
	chunkCount          uint32
	chunkTotalByteCount uint32
	// only a final chunk carries a hash, of SHA-256's length; one of any other length can never sit in
	// §6.5's layout, so such a chunk keeps only that it was malformed, which reassembly then drops it for
	chunkSha256          [sha256.Size]byte
	hasChunkSha256       bool
	chunkSha256Malformed bool

	// a pool copy this item owns until release, or nil for an empty body
	body        []byte
	releaseBody func()
}

// Copies what the handler read out of envelope, retaining its body in a pool buffer.
func newSubprotocolInbound(
	sourceId connect.Id,
	transferKey connect.TransferKey,
	clientPublicKey [ed25519.PublicKeySize]byte,
	hasClientPublicKey bool,
	arrivalTime time.Time,
	envelope *protocol.Envelope,
) subprotocolInbound {
	item := subprotocolInbound{
		sourceId:           sourceId,
		transferKey:        transferKey,
		clientPublicKey:    clientPublicKey,
		hasClientPublicKey: hasClientPublicKey,
		arrivalTime:        arrivalTime,
		version:            envelope.Version,
		messageType:        envelope.Type,
		requestId:          envelope.RequestId,
		flags:              envelope.Flags,
		streamId:           envelope.StreamId,
		timeoutMs:          envelope.TimeoutMs,
	}
	if chunk := envelope.Chunk; chunk != nil {
		item.hasChunk = true
		item.chunkIndex = chunk.Index
		item.chunkCount = chunk.Count
		item.chunkTotalByteCount = chunk.TotalByteCount
		switch len(chunk.Sha256) {
		case 0:
		case sha256.Size:
			copy(item.chunkSha256[:], chunk.Sha256)
			item.hasChunkSha256 = true
		default:
			item.chunkSha256Malformed = true
		}
	}
	if 0 < len(envelope.Body) {
		item.body, item.releaseBody = connect.RetainSubprotocolBytes(envelope.Body)
	}
	return item
}

// The envelope again, borrowing the item's body, for reassembly and dispatch.
func (self *subprotocolInbound) envelope() *protocol.Envelope {
	envelope := &protocol.Envelope{
		Version:   self.version,
		Type:      self.messageType,
		RequestId: self.requestId,
		Flags:     self.flags,
		StreamId:  self.streamId,
		TimeoutMs: self.timeoutMs,
		Body:      self.body,
	}
	if self.hasChunk {
		envelope.Chunk = &protocol.Chunk{
			Index:          self.chunkIndex,
			Count:          self.chunkCount,
			TotalByteCount: self.chunkTotalByteCount,
		}
		switch {
		case self.chunkSha256Malformed:
			envelope.Chunk.Sha256 = []byte{0}
		case self.hasChunkSha256:
			envelope.Chunk.Sha256 = self.chunkSha256[:]
		}
	}
	return envelope
}

// Gives the body's pool buffer back. Once per item: the zero item and a released one hold none.
func (self *subprotocolInbound) release(stats *subprotocolStats) {
	if self.releaseBody != nil {
		self.releaseBody()
		self.releaseBody = nil
		self.body = nil
		stats.heldBufferCount.Add(-1)
	}
}

// Whether the item asks for an answer: a request from a peer, which ControlId never sends.
func (self *subprotocolInbound) answerable() bool {
	return self.sourceId != connect.ControlId && self.flags&(EnvelopeFlagResponse|EnvelopeFlagNoReply) == 0
}

// What enqueue did with an envelope.
type subprotocolEnqueueResult int

const (
	// in its source's queue
	subprotocolEnqueued subprotocolEnqueueResult = iota
	// the queue was full
	subprotocolQueueFull
	// the Subprotocol has closed
	subprotocolEnqueueClosed
)

// Offers an envelope that passed every inline check to its source's queue with zero wait, starting the
// source's worker if it has none. The body is retained before the lock and given back if the queue
// refuses, so a refusal leaves the pool as it found it.
func (self *Subprotocol) enqueue(
	sourceId connect.Id,
	transferKey connect.TransferKey,
	clientPublicKey [ed25519.PublicKeySize]byte,
	hasClientPublicKey bool,
	envelope *protocol.Envelope,
) subprotocolEnqueueResult {
	item := newSubprotocolInbound(sourceId, transferKey, clientPublicKey, hasClientPublicKey, self.clock.Now(), envelope)
	if item.releaseBody != nil {
		self.stats.heldBufferCount.Add(1)
	}
	result := subprotocolEnqueued
	var startPeer *subprotocolPeer
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			result = subprotocolEnqueueClosed
			return
		}
		peer := self.sourceIdPeers[sourceId]
		if peer == nil {
			peer = &subprotocolPeer{sourceId: sourceId}
			self.sourceIdPeers[sourceId] = peer
		}
		if self.settings.PeerQueueMessageCount <= peer.queuedCountWithLock() {
			result = subprotocolQueueFull
			return
		}
		peer.pushWithLock(item)
		if !peer.running {
			peer.running = true
			// under the lock, before Close can set closed and wait
			self.workers.Add(1)
			startPeer = peer
		}
	}()
	if result != subprotocolEnqueued {
		item.release(&self.stats)
		return result
	}
	self.stats.queuedCount.Add(1)
	if startPeer != nil {
		go self.runPeer(startPeer)
	}
	return result
}

// One source's worker: takes its queue in order until it is empty, then retires. Once the Subprotocol
// is closing it gives back what is queued without running it, so Close's join returns every buffer.
func (self *Subprotocol) runPeer(peer *subprotocolPeer) {
	defer self.workers.Done()
	// an opaque id, computed here and not on the inline path
	barrierKey := peer.sourceId.String()
	for {
		testHookBarrier("rpc.peer_take.before", barrierKey)
		item, ok := self.takeOrRetire(peer)
		if !ok {
			return
		}
		if self.ctx.Err() != nil {
			item.release(&self.stats)
			continue
		}
		self.process(&item, barrierKey)
	}
}

// The oldest queued item, or false once the queue is empty, in which case the worker has retired and
// the source's entry is gone: the inline handler, which queues under the same lock, then starts a new
// one.
func (self *Subprotocol) takeOrRetire(peer *subprotocolPeer) (subprotocolInbound, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if peer.queuedCountWithLock() == 0 {
		peer.running = false
		if self.sourceIdPeers[peer.sourceId] == peer {
			delete(self.sourceIdPeers, peer.sourceId)
		}
		return subprotocolInbound{}, false
	}
	return peer.popWithLock(), true
}

// One peer's verified Hello, as the gate reads it per frame.
type subprotocolPeerIdentity struct {
	// C15's key on the frame whose Hello verified, which every later frame must carry
	clientPublicKey [ed25519.PublicKeySize]byte
	// HelloCacheTimeout after the Hello verified
	expireTime time.Time
	// what the Hello showed; nil only where an internal test opened the gate by hand
	peer *SubprotocolPeerIdentity
}

// Opens the gate for sourceId with no peer behind it, as internal tests do by hand. See
// markPeerVerifiedAs.
func (self *Subprotocol) markPeerVerified(sourceId connect.Id, clientPublicKey [ed25519.PublicKeySize]byte) {
	self.markPeerVerifiedAs(sourceId, clientPublicKey, nil)
}

// Opens the gate for sourceId, as of now and until HelloCacheTimeout: what Hello's check does once a
// Hello or HelloResult from that peer verifies, with C15's key on that frame and the peer it showed.
func (self *Subprotocol) markPeerVerifiedAs(sourceId connect.Id, clientPublicKey [ed25519.PublicKeySize]byte, peer *SubprotocolPeerIdentity) {
	expireTime := self.clock.Now().Add(self.settings.HelloCacheTimeout)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sourceIdIdentities[sourceId] = subprotocolPeerIdentity{
		clientPublicKey: clientPublicKey,
		expireTime:      expireTime,
		peer:            peer,
	}
}

// Whether a verified Hello with clientId stands now, reading the gate and running nothing.
func (self *Subprotocol) peerVerified(clientId connect.Id) bool {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identity, ok := self.sourceIdIdentities[clientId]
	return ok && now.Before(identity.expireTime)
}

// Closes the gate for sourceId: on a send's ack error or a refused Hello (reading 1). A peer with no
// record is left as it is.
func (self *Subprotocol) forgetPeer(sourceId connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.sourceIdIdentities, sourceId)
}

// Whether an envelope belongs to the Hello exchange the gate exists for, and so passes it closed: a
// Hello, a HelloResult answering one this side sent, or an Error answering one. Call and OpenStream go
// through ensurePeerVerified, so a Hello is the only request this side ever sends a peer the gate is
// closed to, and an Error from one either answers it or matches no pending request at all.
func helloExchange(messageType uint32, flags uint32) bool {
	response := flags&EnvelopeFlagResponse != 0
	switch protocol.MessageType(messageType) {
	case protocol.MessageType_HELLO:
		return !response
	case protocol.MessageType_HELLO_RESULT, protocol.MessageType_ERROR:
		return response
	}
	return false
}

// Step 5, the identity gate (D-PROTO-13): open only while sourceId's verified Hello stands and this
// frame carries the C15 key it verified under. A frame with no key is refused and leaves the record;
// one under another key means the session was re-keyed, which closes the gate at once.
func (self *Subprotocol) identityAdmits(
	sourceId connect.Id,
	messageType uint32,
	flags uint32,
	clientPublicKey [ed25519.PublicKeySize]byte,
	hasClientPublicKey bool,
) bool {
	if helloExchange(messageType, flags) {
		return true
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identity, ok := self.sourceIdIdentities[sourceId]
	switch {
	case !ok:
		return false
	case !now.Before(identity.expireTime):
		delete(self.sourceIdIdentities, sourceId)
		return false
	case !hasClientPublicKey:
		return false
	case clientPublicKey != identity.clientPublicKey:
		delete(self.sourceIdIdentities, sourceId)
		return false
	}
	return true
}
