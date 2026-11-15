//go:build !sidecar_http

// The marked pair (§6.10's mark, window, keepalive and session rows; §6.11's bit 1; D-PROTO-22,
// D-SDK-27, C19, R-CTX-37): an app host asking remote search of an indexer, and that indexer, are
// accounted in C19's windows (connect/transfer_peer_window.go), whose reports show neither when search
// pages ran nor, below the floor, how many.
//
//   - mark: a sidecar that sends or receives a Hello or HelloResult carrying bit 1 while that peer is not
//     in C19's mode puts it there and, if that changed it, retires every contract it holds to the peer,
//     whose reports go out at once since no marked frame rode them. The sender does this before sending;
//     the receiver on receipt, before its reply, and it adopts the contract the marking frame rode as its
//     receive window's first. A sender that marked before its Hello adopts the contract of the peer's
//     answer. A bit-1 Hello while the mode holds, as at a session re-establishment, retires nothing.
//   - activity: each Ping, Pong, Hello and HelloResult with the peer, either way, is noted to connect, so
//     a window ending with none in its last 2 min clears the mode (plan-SEARCH-c19-first-contract).
//   - warm pairs: the requester names the indexers it keeps warm (MarkSearchPeers), at most
//     SidecarProtocolSettings.MarkedPeerMaxCount, the own ones first: the two a search asks at once
//     (QD-707), then another member's where SEARCH names one (DESIGN-DETAILS 7.2.3). An id past the cap
//     is refused, and an empty list names none. Each named pair keeps its own window, its own Ping grid
//     from that window's start and its own session, in a loop of its own, so a slow or dead indexer
//     delays no other pair's Ping.
//   - keepalive: while the host is in the foreground (SetForeground) the requester Pings each warm
//     indexer each MarkedKeepaliveInterval on a grid from that pair's send window's start, and the
//     indexer answers Pong, so no sequence of the pair idles out and no contract opens inside a
//     foreground window but at its start, a re-establishment or an overflow. Background hosts send none:
//     a tick whose wake was armed before the host left the foreground, or before its indexer left the
//     list, is dropped.
//   - session: the pair's Hello lasts while its session lives, past HelloCacheTimeout: each Pong, and at
//     the indexer each Ping, keeps it standing MarkedSessionTimeout past that frame's arrival, however
//     late its worker reaches it. The indexer records its Ping before it answers, so a requester holding
//     a Pong never finds the indexer's record behind its own. A session is lost after
//     MarkedSessionTimeout without one; it is re-established by the next Hello, at the next foreground
//     (each move into it counted, so one whose background the loop never saw still counts) or keepalive
//     tick, or at once by a search that comes first, whose new contract, and the successor connect
//     requests with it, keep that search's time in connect's rows (owner decision 191, connect-5).
//   - every search rides a marked pair: a SEARCH toward a peer this side sends bit 1, while that peer is
//     not in C19's mode, first runs a bit-1 Hello, so an indexer first asked on failover gets its Hello
//     then, which opens its window at that search, and a pair whose mode cleared in the background is
//     marked again before its next search.
//   - HeadCheck: in the foreground the round counts the first warm indexer among its own picks, the
//     others staying random (D-SDK-27; rpc_headcheck_rounds.go).
//
// The foreground and the warm indexers are the callers' (§18.7's host, SEARCH): plan-SEARCH-
// foreground-signal's Sidecar.SetSearchForeground feeds SetForeground.
//
// testHookBarrier runs at rpc.marked_pair_mark.before and .after around each mark, the mode's change and
// what it retires and adopts, and at rpc.marked_pair_tick.before and .after around each keepalive tick,
// keyed by the peer's client id, so a fault schedule can hold one pair's mark or tick while the others
// run.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// What the marked pair asks of connect's C19 ledger: the client's ContractManager, which internal tests
// fake. Every method returns at once.
type subprotocolPeerWindows interface {
	SetPeerWindowAccounting(peerId connect.Id, accounting bool) bool
	PeerWindow(peerId connect.Id) connect.PeerWindowStatus
	RetirePeerContracts(peerId connect.Id)
	NotePeerWindowActivity(peerId connect.Id)
	AdoptPeerWindowContract(peerId connect.Id, transferKey connect.TransferKey) bool
}

var (
	// Ids named past SidecarProtocolSettings.MarkedPeerMaxCount, which are not kept warm.
	errSubprotocolMarkedPeers = errors.New("subprotocol marked peers: past the most kept warm")
)

// The warm indexers as the caller ordered them. Never changed once made: a new list is a new value, so a
// pointer to one compares as the list does.
type subprotocolMarkedPeers struct {
	peerIds []connect.Id
}

// What the keepalives follow: the warm indexers, if any, and the foreground.
type subprotocolMarkedPairs struct {
	// nil for none, and replaced only by a list that differs, so two values with equal lists are equal
	peers      *subprotocolMarkedPeers
	foreground bool
	// moves into the foreground so far: a background a loop missed between two reads leaves the rest of
	// the value as it was, and this still tells it a move came, so the move's tick runs
	foregroundCount uint64
}

// What one pair's keepalive follows of subprotocolMarkedPairs: whether its indexer is named, and the
// foreground. It compares, so a loop tells a move of its own pair from a move of another.
type subprotocolMarkedPair struct {
	peerId          connect.Id
	hasPeer         bool
	foreground      bool
	foregroundCount uint64
}

// One named indexer's keepalive loop, kept under the dispatcher's stateLock while the loop runs.
type subprotocolKeepaliveLoop struct {
	// waits the loop has armed, so a test steps its clock with no sleep
	markCount uint64
}

// The warm indexers in the caller's order, which a caller must not change.
func (self subprotocolMarkedPairs) peerIds() []connect.Id {
	if self.peers == nil {
		return nil
	}
	return self.peers.peerIds
}

func (self subprotocolMarkedPairs) has(peerId connect.Id) bool {
	return slices.Contains(self.peerIds(), peerId)
}

// The part peerId's keepalive follows.
func (self subprotocolMarkedPairs) pair(peerId connect.Id) subprotocolMarkedPair {
	return subprotocolMarkedPair{
		peerId:          peerId,
		hasPeer:         self.has(peerId),
		foreground:      self.foreground,
		foregroundCount: self.foregroundCount,
	}
}

// Names the search indexers this side keeps warm, the peers the keepalive holds in the foreground and
// toward which this side's Hellos carry bit 1, in place of those named before: the own ones first, the
// two a search asks at once, then another member's where there is one (DESIGN-DETAILS 7.2.3, QD-707).
// The first is the one HeadCheck's foreground round counts. An empty list names none; a zero Id and a
// repeat of an id are passed over. At most SidecarProtocolSettings.MarkedPeerMaxCount are kept: each id
// past that is refused, named in the error, and the ids before it stand. SEARCH calls it at each
// foreground and as its mode, its notices' answers and the config's indexers move.
func (self *Subprotocol) MarkSearchPeers(clientIds []Id) error {
	maxCount := self.settings.MarkedPeerMaxCount
	peerIds := []connect.Id{}
	refusedIds := []connect.Id{}
	for _, clientId := range clientIds {
		peerId := connect.Id(clientId)
		if clientId == (Id{}) || slices.Contains(peerIds, peerId) || slices.Contains(refusedIds, peerId) {
			continue
		}
		if maxCount <= len(peerIds) {
			refusedIds = append(refusedIds, peerId)
			continue
		}
		peerIds = append(peerIds, peerId)
	}
	self.markedPairs.Update(func(pairs subprotocolMarkedPairs) subprotocolMarkedPairs {
		if slices.Equal(pairs.peerIds(), peerIds) {
			return pairs
		}
		pairs.peers = nil
		if 0 < len(peerIds) {
			pairs.peers = &subprotocolMarkedPeers{peerIds: peerIds}
		}
		return pairs
	})
	self.startKeepalives()
	if 0 < len(refusedIds) {
		return fmt.Errorf("%w: %d kept, %v refused", errSubprotocolMarkedPeers, len(peerIds), refusedIds)
	}
	return nil
}

// Tells the dispatcher whether its host is in the foreground (plan-SEARCH-foreground-signal): only then
// do the keepalives run, and a move into it re-establishes each warm pair's lost session at once. A host
// that never calls it is in the background.
func (self *Subprotocol) SetForeground(foreground bool) {
	self.markedPairs.Update(func(pairs subprotocolMarkedPairs) subprotocolMarkedPairs {
		if foreground && !pairs.foreground {
			pairs.foregroundCount += 1
		}
		pairs.foreground = foreground
		return pairs
	})
}

// The first warm indexer while the host is in the foreground: what HeadCheck's round counts among its
// own picks (D-SDK-27), the caller naming its own indexers first. False in the background or with none
// named.
func (self *Subprotocol) foregroundSearchPeer() (connect.Id, bool) {
	pairs := self.markedPairs.Value()
	peerIds := pairs.peerIds()
	if !pairs.foreground || len(peerIds) == 0 {
		return connect.Id{}, false
	}
	return peerIds[0], true
}

// Whether this side sends bit 1 to peerId: toward each warm indexer and each peer SetFeatures' function
// names.
func (self *Subprotocol) asksSearch(peerId connect.Id) bool {
	return self.featuresToward(peerId)&SubprotocolFeatureAsksSearch != 0
}

// Puts peerId in C19's mode before this side sends it a frame carrying bit 1, retiring what it holds to
// it if that changed the mode. Answers whether it did, which a Hello's sender adopts its answer for.
func (self *Subprotocol) markBeforeSend(peerId connect.Id) bool {
	testHookBarrier("rpc.marked_pair_mark.before", peerId.String())
	defer testHookBarrier("rpc.marked_pair_mark.after", peerId.String())
	if !self.peerWindows.SetPeerWindowAccounting(peerId, true) {
		return false
	}
	self.peerWindows.RetirePeerContracts(peerId)
	return true
}

// Puts peerId in C19's mode on receipt of a frame carrying bit 1, before any reply: if that changed the
// mode, retires what this side holds to it and adopts the contract the frame rode.
func (self *Subprotocol) markOnReceipt(peerId connect.Id, transferKey connect.TransferKey) {
	testHookBarrier("rpc.marked_pair_mark.before", peerId.String())
	defer testHookBarrier("rpc.marked_pair_mark.after", peerId.String())
	if !self.peerWindows.SetPeerWindowAccounting(peerId, true) {
		return
	}
	self.peerWindows.RetirePeerContracts(peerId)
	self.peerWindows.AdoptPeerWindowContract(peerId, transferKey)
}

// Tells connect a Ping, Pong, Hello or HelloResult moved with peerId, either way. connect ignores a peer
// not in the mode.
func (self *Subprotocol) noteWindowActivity(peerId connect.Id) {
	self.peerWindows.NotePeerWindowActivity(peerId)
}

// Records that the session with peerId showed live at arrivalTime, when a Pong passed this side's gate at
// the requester or a Ping at the indexer, and, while the pair is in C19's mode, keeps its Hello standing
// MarkedSessionTimeout past that arrival, however long ago it verified. It reads the frame's arrival, not
// the clock as it runs, so a frame the gate admitted under a standing Hello keeps that Hello however late
// its worker reaches it; a Hello already ended at the arrival, or closed since, is left as it is, and the
// session's time never moves back.
func (self *Subprotocol) touchSession(peerId connect.Id, arrivalTime time.Time) {
	marked := self.peerWindows.PeerWindow(peerId).Accounting
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identity, ok := self.sourceIdIdentities[peerId]
	if !ok || !arrivalTime.Before(identity.expireTime) {
		return
	}
	if identity.sessionTime.Before(arrivalTime) {
		identity.sessionTime = arrivalTime
	}
	if marked {
		if until := arrivalTime.Add(self.settings.MarkedSessionTimeout); identity.expireTime.Before(until) {
			identity.expireTime = until
		}
	}
	self.sourceIdIdentities[peerId] = identity
}

// When the session with peerId last showed live, and false with no Hello standing.
func (self *Subprotocol) sessionTime(peerId connect.Id) (time.Time, bool) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identity, ok := self.sourceIdIdentities[peerId]
	if !ok || !now.Before(identity.expireTime) {
		return time.Time{}, false
	}
	return identity.sessionTime, true
}

// Before a SEARCH toward a peer this side asks: a pair not in C19's mode loses its standing Hello, so the
// Hello the call then runs carries bit 1 and marks it first.
func (self *Subprotocol) prepareSearchPair(peerId connect.Id) {
	if !self.asksSearch(peerId) || self.peerWindows.PeerWindow(peerId).Accounting {
		return
	}
	self.forgetPeer(peerId)
}

// Starts a keepalive loop for each warm indexer that has none, unless the dispatcher has closed. Close
// joins them. The list is read under stateLock, as endKeepalive reads it, so an indexer named while its
// loop ends keeps one loop: never two, never none.
func (self *Subprotocol) startKeepalives() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return
	}
	for _, peerId := range self.markedPairs.Value().peerIds() {
		if _, ok := self.keepaliveLoops[peerId]; ok {
			continue
		}
		self.keepaliveLoops[peerId] = &subprotocolKeepaliveLoop{}
		self.handlers.Add(1)
		go self.runKeepalive(peerId)
	}
}

// Ends peerId's keepalive loop, unless the indexer has been named again since the loop read the list,
// when the loop goes on. Answers whether it ended.
func (self *Subprotocol) endKeepalive(peerId connect.Id) bool {
	ended := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.closed && self.markedPairs.Value().has(peerId) {
			return false
		}
		delete(self.keepaliveLoops, peerId)
		return true
	}()
	if ended {
		self.keepaliveMark.Update(func(mark uint64) uint64 {
			return mark + 1
		})
	}
	return ended
}

// Counts a wait peerId's keepalive armed, for whoever steps the clock.
func (self *Subprotocol) markKeepalive(peerId connect.Id) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if loop, ok := self.keepaliveLoops[peerId]; ok {
			loop.markCount += 1
		}
	}()
	self.keepaliveMark.Update(func(mark uint64) uint64 {
		return mark + 1
	})
}

// One warm pair's keepalive (§6.10): in the foreground, a tick on the grid from the pair's send window's
// start, or from now with none open; at a move into the foreground, or at the indexer's naming in it, a
// tick at once. It follows only its own pair: another indexer joining or leaving the list moves neither
// its grid nor a wake it armed. It ends once its indexer has left the list. Each wait is on the clock, a
// change or the dispatcher's end, so the loop never spins.
func (self *Subprotocol) runKeepalive(peerId connect.Id) {
	defer self.handlers.Done()
	// whether the loop has run the tick for this stretch of the foreground, and the move into the
	// foreground that stretch began with
	wasForeground := false
	foregroundCount := uint64(0)
	for {
		pairs, changed := self.markedPairs.Get()
		pair := pairs.pair(peerId)
		if !pair.hasPeer {
			if self.endKeepalive(peerId) {
				return
			}
			// named again before the loop ended: a new stretch
			wasForeground = false
			continue
		}
		if !pair.foreground {
			wasForeground = false
			select {
			case <-changed:
				continue
			case <-self.ctx.Done():
				return
			}
		}
		if !wasForeground || foregroundCount != pair.foregroundCount {
			// a move into the foreground, even one whose background went by while the loop waited on a tick:
			// re-establish a lost session now, the grid keeping the Pings
			wasForeground = true
			foregroundCount = pair.foregroundCount
			self.keepaliveTick(peerId, false)
			continue
		}
		// the tick this wake is for, unless the pair moved while it was armed: a host gone into the
		// background, or out and back, or an indexer that left the list, sends nothing for it, and the
		// loop takes the move at its next read
		tick := func() {
			if current := self.markedPairs.Value().pair(peerId); current != pair {
				return
			}
			self.keepaliveTick(peerId, true)
		}
		now := self.clock.Now()
		next := self.nextKeepaliveTick(peerId, now)
		// timed from the clock as it reads once next is worked out, so a clock moved meanwhile does not push
		// the wake past next
		wake := self.clock.After(max(0, next.Sub(self.clock.Now())))
		self.markKeepalive(peerId)
		if !self.clock.Now().Before(next) {
			// the clock reached next while the wake was armed, so the wake may fire late: tick now
			tick()
			continue
		}
		for armed := true; armed; {
			select {
			case <-wake:
				tick()
				armed = false
			case <-changed:
				// another pair's move leaves this wake armed, so no Ping of this grid is passed over for it
				var current subprotocolMarkedPairs
				current, changed = self.markedPairs.Get()
				armed = current.pair(peerId) == pair
			case <-self.ctx.Done():
				return
			}
		}
	}
}

// The next point on the keepalive grid after now: the pair's send window's start plus a whole number of
// MarkedKeepaliveInterval, or now plus one interval while no send window is open.
func (self *Subprotocol) nextKeepaliveTick(peerId connect.Id, now time.Time) time.Time {
	interval := self.settings.MarkedKeepaliveInterval
	window := self.peerWindows.PeerWindow(peerId).Send
	if window == nil || now.Before(window.StartTime) {
		return now.Add(interval)
	}
	elapsed := now.Sub(window.StartTime)
	return window.StartTime.Add((elapsed/interval + 1) * interval)
}

// One keepalive tick of peerId's pair: a lost session, no Hello standing or none live for
// MarkedSessionTimeout, is re-established by a Hello, which carries bit 1 toward the indexer; a live one
// gets a Ping when ping says so, as each tick on the grid does.
func (self *Subprotocol) keepaliveTick(peerId connect.Id, ping bool) {
	testHookBarrier("rpc.marked_pair_tick.before", peerId.String())
	defer testHookBarrier("rpc.marked_pair_tick.after", peerId.String())
	sessionTime, standing := self.sessionTime(peerId)
	if !standing || self.settings.MarkedSessionTimeout <= self.clock.Now().Sub(sessionTime) {
		self.forgetPeer(peerId)
		if err := self.ensurePeerVerified(self.ctx, peerId); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[subprotocol]marked pair %s not re-established: %s\n", peerId, err)
		}
		return
	}
	if !ping {
		return
	}
	if err := self.ping(self.ctx, peerId); err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[subprotocol]keepalive to %s: %s\n", peerId, err)
	}
}

// Sends peerId a Ping and waits at most PingTimeout for its Pong, which shows the session live. A Ping
// carries no body, and its Pong echoes its request_id with none (§6.5).
func (self *Subprotocol) ping(ctx context.Context, peerId connect.Id) error {
	requestId := newRequestId()
	timeout := self.settings.PingTimeout
	pending, remove, err := self.addPending(peerId, requestId, protocol.MessageType_PONG)
	if err != nil {
		return err
	}
	defer remove()
	envelope := &protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(protocol.MessageType_PING),
		RequestId: requestId,
		TimeoutMs: uint32(timeout / time.Millisecond),
	}
	self.noteWindowActivity(peerId)
	if err := self.sendEnvelopeAcked(peerId, envelope, self.forgetPeerOnAckError(peerId), timeout); err != nil {
		return sendFailure(err, requestId)
	}
	response, err := self.awaitPending(ctx, pending, timeout, requestId)
	if err != nil {
		return err
	}
	if response.envelope.Type != uint32(protocol.MessageType_PONG) || response.envelope.Flags&EnvelopeFlagError != 0 {
		return ErrSubprotocolResponse
	}
	self.noteWindowActivity(peerId)
	self.touchSession(peerId, response.arrivalTime)
	return nil
}
