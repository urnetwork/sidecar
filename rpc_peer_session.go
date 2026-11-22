//go:build !sidecar_http

// A peer that lost its connect session with this client (QD-1185): connect reports it when the peer's unknown-wrap
// nack names no epoch, so the peer restarted or forgot its session state, and the dispatcher ends its Hello with that
// peer, a fourth ending beside HelloCacheTimeout, a change of C15's key and a send's ack error (QD-290). The peer's
// gate lost its Hello with this side too, and a peer restarted under its kept generation shows the same C15 key, so
// nothing else would end this side's Hello before HelloCacheTimeout. A stream open made under the ended Hello and
// rejected INVALID goes once more under a fresh one (stream_open.go), as a call answers the gate's UNAUTHENTICATED.
// An edge runs no Hello and keeps no subscription.

package sidecar

import (
	"github.com/urnetwork/connect"
)

// Subscribes lost to client's EncryptionEventPeerSessionLost, answering the unsubscribe.
func connectPeerSessionLost(client *connect.Client) func(lost func(peerId connect.Id)) (remove func()) {
	return func(lost func(peerId connect.Id)) func() {
		return client.EncryptionSessionManager().AddEncryptionEventCallback(func(event *connect.EncryptionEvent) {
			if event != nil && event.Type == connect.EncryptionEventPeerSessionLost {
				lost(event.PeerId)
			}
		})
	}
}

// Ends the Hello with peerId, whose connect session with this client is gone: the next call or open to it runs a
// fresh Hello. Called from connect's callbacks, so it only takes the state lock.
func (self *Subprotocol) peerSessionLost(peerId connect.Id) {
	self.forgetPeer(peerId)
	if self.log.V(1).Enabled() {
		self.log.Infof("[subprotocol]%s lost its session with this client: its Hello ended\n", peerId)
	}
}
