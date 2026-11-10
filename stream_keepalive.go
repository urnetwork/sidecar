//go:build !sidecar_http

// §6.7's keepalive (§22.5's PEER_TIMEOUT row): while a peer has streams open, PingTimeout without inbound
// traffic from it sends a Ping, and PeerSilenceTimeout resets every stream with it with PEER_TIMEOUT,
// before connect's 60 s sequence exit would end them without a word. Inbound traffic is any frame from the
// peer that passed the inline checks, its Pong or the Error a gate that let its Hello lapse answers a Ping
// with among them, so a pair whose streams are idle stays live on Pings alone.
//
// The same loop rereads, for each sidecar peer with streams, its admission in this side's state: a peer the
// state has since revoked, parked or let expire has its streams reset REVOKED, at the next wake, at most
// PingTimeout after the state moved while streams run (rpc_admission.go's standing).
//
// One loop per dispatcher, started with the first stream, which waits on the clock, a change to the
// streams or the dispatcher's end, so it never spins.

package sidecar

import (
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// What one wake found to do with one peer.
type streamKeepaliveAct struct {
	peerId connect.Id
	ping   bool
	// reset its streams with code; UNSPECIFIED for none
	code protocol.StreamResetCode
}

// The keepalive loop. See the file header.
func (self *Subprotocol) runStreamKeepalive() {
	defer self.handlers.Done()
	for {
		_, changed := self.streams.change.Get()
		now := self.clock.Now()
		acts, next := self.streamKeepaliveActs(now)
		for _, act := range acts {
			if act.ping {
				self.sendStreamPing(act.peerId)
			}
			if act.code != protocol.StreamResetCode_RST_UNSPECIFIED {
				key := act.peerId.String()
				testHookBarrier("stream.keepalive_reset.before", key)
				self.resetPeerStreams(act.peerId, act.code, nil)
				testHookBarrier("stream.keepalive_reset.after", key)
			}
		}
		var wake <-chan time.Time
		if !next.IsZero() {
			// timed from the clock as it reads after the acts, not from now, so a clock moved meanwhile does
			// not push the wake past next
			wake = self.clock.After(max(0, next.Sub(self.clock.Now())))
		}
		// what a test steps its clock to, once the wait for it is armed
		self.streamKeepaliveArmed.Set(next)
		if !next.IsZero() && !self.clock.Now().Before(next) {
			// the clock reached next while the wake was armed, so the wake may fire late: act again now
			continue
		}
		select {
		case <-wake:
		case <-changed:
		case <-self.ctx.Done():
			return
		}
	}
}

// What is due at now for each peer with streams, and when the next thing falls due, zero for nothing.
func (self *Subprotocol) streamKeepaliveActs(now time.Time) ([]streamKeepaliveAct, time.Time) {
	type peerSnapshot struct {
		peerId          connect.Id
		edge            bool
		lastInboundTime time.Time
		pinged          bool
		identity        *SubprotocolPeerIdentity
	}
	snapshots := []peerSnapshot{}
	func() {
		streams := &self.streams
		streams.stateLock.Lock()
		defer streams.stateLock.Unlock()
		for _, peer := range streams.peers {
			if len(peer.streams) == 0 {
				continue
			}
			snapshot := peerSnapshot{peerId: peer.peerId, edge: peer.edge, lastInboundTime: peer.lastInboundTime, pinged: peer.pinged}
			for _, stream := range peer.streams {
				if stream.identity != nil && stream.identity.Admission != nil {
					snapshot.identity = stream.identity
					break
				}
			}
			snapshots = append(snapshots, snapshot)
		}
	}()
	acts := []streamKeepaliveAct{}
	next := time.Time{}
	due := func(at time.Time) {
		if next.IsZero() || at.Before(next) {
			next = at
		}
	}
	for _, snapshot := range snapshots {
		silence := now.Sub(snapshot.lastInboundTime)
		switch {
		case self.settings.PeerSilenceTimeout <= silence:
			acts = append(acts, streamKeepaliveAct{peerId: snapshot.peerId, code: protocol.StreamResetCode_RST_PEER_TIMEOUT})
			continue
		case !snapshot.edge && snapshot.identity != nil && !self.streamPeerStands(snapshot.identity):
			acts = append(acts, streamKeepaliveAct{peerId: snapshot.peerId, code: protocol.StreamResetCode_RST_REVOKED})
			continue
		case self.settings.PingTimeout <= silence && !snapshot.pinged:
			acts = append(acts, streamKeepaliveAct{peerId: snapshot.peerId, ping: true})
			self.markStreamPinged(snapshot.peerId)
			due(snapshot.lastInboundTime.Add(self.settings.PeerSilenceTimeout))
		case snapshot.pinged:
			due(snapshot.lastInboundTime.Add(self.settings.PeerSilenceTimeout))
		default:
			due(snapshot.lastInboundTime.Add(self.settings.PingTimeout))
		}
		// a sidecar peer's standing is read again at least each PingTimeout while its streams run
		if !snapshot.edge && snapshot.identity != nil {
			due(now.Add(self.settings.PingTimeout))
		}
	}
	return acts, next
}

// Records that a Ping went to peerId since its last inbound frame.
func (self *Subprotocol) markStreamPinged(peerId connect.Id) {
	streams := &self.streams
	streams.stateLock.Lock()
	defer streams.stateLock.Unlock()
	if peer := streams.peers[peerId]; peer != nil {
		peer.pinged = true
	}
}

// Whether a sidecar peer's admission, as its stream's Hello verified it, still stands in this side's state:
// neither revoked, parked nor expired, and this side itself admitted. Under M1's first-use pins there is no
// admission to read, and it stands.
func (self *Subprotocol) streamPeerStands(identity *SubprotocolPeerIdentity) bool {
	if self.admissions == nil {
		return true
	}
	authority := self.admissions.Authority()
	if authority == nil || !self.admissions.Admitted() {
		return false
	}
	if authority.Pin().GetVersion() == identity.AdmissionVersion {
		// an agent's admission ends at its not_after whatever the state does (§7.9)
		notAfter := identity.Admission.Row.GetNotAfter()
		return notAfter == 0 || self.clock.Now().UnixMilli() < notAfter
	}
	return admissionStanding(authority.Admission(identity.SidecarId), identity.SidecarId, self.clock.Now().UnixMilli()) == nil
}

// A Ping to peerId through the stream sender: no body, PingTimeout as its deadline, and its Pong read
// only as inbound traffic, so nothing waits on it.
func (self *Subprotocol) sendStreamPing(peerId connect.Id) {
	self.streams.stats.pingCount.Add(1)
	self.queueStreamOutbound(&streamOutbound{destinationId: peerId, envelope: &protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(protocol.MessageType_PING),
		RequestId: newRequestId(),
		TimeoutMs: uint32(self.settings.PingTimeout / time.Millisecond),
	}})
}
