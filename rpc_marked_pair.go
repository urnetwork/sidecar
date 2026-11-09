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
//   - keepalive: while the host is in the foreground (SetForeground) the requester Pings its first-choice
//     indexer (MarkSearchPeer) each MarkedKeepaliveInterval on a grid from its send window's start, and
//     the indexer answers Pong, so no sequence of the pair idles out and no contract opens inside a
//     foreground window but at its start, a re-establishment or an overflow. Background hosts send none.
//   - session: the pair's Hello lasts while its session lives, past HelloCacheTimeout: each Pong, and at
//     the indexer each Ping, keeps it standing MarkedSessionTimeout more. A session is lost after
//     MarkedSessionTimeout without one; it is re-established by the next Hello, at the next foreground or
//     keepalive tick, or at once by a search that comes first, whose new contract, and the successor
//     connect requests with it, keep that search's time in connect's rows (owner decision 191,
//     connect-5).
//   - every search rides a marked pair: a SEARCH toward a peer this side sends bit 1, while that peer is
//     not in C19's mode, first runs a bit-1 Hello, so an indexer first asked on failover gets its Hello
//     then, which opens its window at that search, and a pair whose mode cleared in the background is
//     marked again before its next search.
//   - HeadCheck: in the foreground the round counts the first-choice indexer among its own picks, the
//     others staying random (D-SDK-27; rpc_headcheck_rounds.go).
//
// The foreground and the first-choice indexer are the callers' (§18.7's host, SEARCH): plan-SEARCH-
// foreground-signal's Sidecar.SetSearchForeground feeds SetForeground.

package sidecar

import (
	"context"
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

// What the keepalive follows: the first-choice indexer, if any, and the foreground.
type subprotocolMarkedPair struct {
	peerId     connect.Id
	hasPeer    bool
	foreground bool
}

// Names the first-choice search indexer, the peer the keepalive holds in the foreground and toward which
// this side's Hellos carry bit 1; the zero Id names none. SEARCH calls it as its mode and designation
// move.
func (self *Subprotocol) MarkSearchPeer(clientId Id) {
	self.markedPair.Update(func(pair subprotocolMarkedPair) subprotocolMarkedPair {
		pair.peerId = connect.Id(clientId)
		pair.hasPeer = clientId != (Id{})
		return pair
	})
	self.startKeepalive()
}

// Tells the dispatcher whether its host is in the foreground (plan-SEARCH-foreground-signal): only then
// does the keepalive run, and a move into it re-establishes a lost session at once. A host that never
// calls it is in the background.
func (self *Subprotocol) SetForeground(foreground bool) {
	self.markedPair.Update(func(pair subprotocolMarkedPair) subprotocolMarkedPair {
		pair.foreground = foreground
		return pair
	})
	self.startKeepalive()
}

// The first-choice indexer while the host is in the foreground: what HeadCheck's round counts among its
// own picks (D-SDK-27). False in the background or with none named.
func (self *Subprotocol) foregroundSearchPeer() (connect.Id, bool) {
	pair, _ := self.markedPair.Get()
	return pair.peerId, pair.hasPeer && pair.foreground
}

// Whether this side sends bit 1 to peerId: toward the first-choice indexer and each peer SetFeatures'
// function names.
func (self *Subprotocol) asksSearch(peerId connect.Id) bool {
	return self.featuresToward(peerId)&SubprotocolFeatureAsksSearch != 0
}

// Puts peerId in C19's mode before this side sends it a frame carrying bit 1, retiring what it holds to
// it if that changed the mode. Answers whether it did, which a Hello's sender adopts its answer for.
func (self *Subprotocol) markBeforeSend(peerId connect.Id) bool {
	if !self.peerWindows.SetPeerWindowAccounting(peerId, true) {
		return false
	}
	self.peerWindows.RetirePeerContracts(peerId)
	return true
}

// Puts peerId in C19's mode on receipt of a frame carrying bit 1, before any reply: if that changed the
// mode, retires what this side holds to it and adopts the contract the frame rode.
func (self *Subprotocol) markOnReceipt(peerId connect.Id, transferKey connect.TransferKey) {
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

// Records that the session with peerId showed live now, a Pong at the requester or a Ping at the
// indexer, and, while the pair is in C19's mode, keeps its Hello standing MarkedSessionTimeout past now,
// however long ago it verified.
func (self *Subprotocol) touchSession(peerId connect.Id) {
	marked := self.peerWindows.PeerWindow(peerId).Accounting
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identity, ok := self.sourceIdIdentities[peerId]
	if !ok || !now.Before(identity.expireTime) {
		return
	}
	identity.sessionTime = now
	if marked {
		if until := now.Add(self.settings.MarkedSessionTimeout); identity.expireTime.Before(until) {
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

// Starts the keepalive loop once, unless the dispatcher has closed. Close joins it.
func (self *Subprotocol) startKeepalive() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed || self.keepaliveStarted {
		return
	}
	self.keepaliveStarted = true
	self.handlers.Add(1)
	go self.runKeepalive()
}

// The keepalive (§6.10): in the foreground with a first-choice indexer, a tick on the grid from the pair's
// send window's start, or from now with none open; at a move into the foreground, a tick at once. Each
// wait is on the clock, a change or the dispatcher's end, so the loop never spins.
func (self *Subprotocol) runKeepalive() {
	defer self.handlers.Done()
	wasForeground := false
	for {
		pair, changed := self.markedPair.Get()
		if !pair.hasPeer || !pair.foreground {
			wasForeground = false
			select {
			case <-changed:
				continue
			case <-self.ctx.Done():
				return
			}
		}
		if !wasForeground {
			// a move into the foreground: re-establish a lost session now, the grid keeping the Pings
			wasForeground = true
			self.keepaliveTick(pair.peerId, false)
			continue
		}
		now := self.clock.Now()
		next := self.nextKeepaliveTick(pair.peerId, now)
		wake := self.clock.After(next.Sub(now))
		self.keepaliveMark.Update(func(mark uint64) uint64 {
			return mark + 1
		})
		select {
		case <-wake:
			self.keepaliveTick(pair.peerId, true)
		case <-changed:
		case <-self.ctx.Done():
			return
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

// One keepalive tick: a lost session, no Hello standing or none live for MarkedSessionTimeout, is
// re-established by a Hello, which carries bit 1 toward the indexer; a live one gets a Ping when ping
// says so, as each tick on the grid does.
func (self *Subprotocol) keepaliveTick(peerId connect.Id, ping bool) {
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
	self.touchSession(peerId)
	return nil
}
