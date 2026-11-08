// §6.4's relay row: the UNVERIFIED pins a device holds and passes on, so a stop crosses each HeadCheck
// hop at that pair's next HeadCheck, at once with a proof and at witness_bound_hours without one. A
// device holds at most HeadCheckMaxUnverifiedCount pins, HeadCheckMaxUnverifiedPeerCount of them taken
// from one peer, keeping the highest, and sends at most HeadCheckMaxUnverifiedSendCount, highest first,
// each with its path: the claimant, then each sidecar that relayed it. A false copy stalls writers only
// until a sidecar on its path, its maker included, is revoked or parked (headCheckState.sweep), the
// denial §6.4's FORK row accepts (D-PROTO-17).
//
// A copy is held once per pin: a second path to a pin already held adds nothing, and if the held
// copy's path is later cleared by a revocation, the other path's next relay brings the pin back.
//
// These are headCheckState's methods, with its rules: pure, and not safe for concurrent use.

package sidecar

import (
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Holds held as UNVERIFIED unless its pin is held already or a sidecar on its path is revoked or
// parked, then keeps the highest HeadCheckMaxUnverifiedPeerCount taken from its peer and the highest
// HeadCheckMaxUnverifiedCount overall. A pin first held here goes to step, to alarm.
func (self *headCheckState) hold(mine *headCheckMine, held *headCheckUnverified, step *headCheckStep) {
	for _, existing := range self.unverified {
		if headCheckPinEqual(existing.pin, held.pin) {
			return
		}
	}
	peers := mine.sources.Peers
	if slices.ContainsFunc(held.path, func(sidecarId Id) bool {
		peer := peers.HeadCheckPeer(sidecarId)
		return peer.Revoked || peer.Parked
	}) {
		return
	}
	self.unverified = append(self.unverified, held)
	slices.SortFunc(self.unverified, func(a *headCheckUnverified, b *headCheckUnverified) int {
		return headCheckPinCompare(a.pin, b.pin)
	})
	peerId := held.peerId()
	peerCount := 0
	self.unverified = slices.DeleteFunc(self.unverified, func(existing *headCheckUnverified) bool {
		if existing.peerId() != peerId {
			return false
		}
		peerCount += 1
		return HeadCheckMaxUnverifiedPeerCount < peerCount
	})
	if HeadCheckMaxUnverifiedCount < len(self.unverified) {
		self.unverified = self.unverified[:HeadCheckMaxUnverifiedCount]
	}
	if slices.Contains(self.unverified, held) {
		step.unverified = append(step.unverified, held)
	}
}

// What this device's HeadCheck to peerId carries of §6.4's relay rows: proven, while it holds proof of
// withholding or an auth fork, and its UNVERIFIED pins, highest first, at most
// HeadCheckMaxUnverifiedSendCount. A copy the peer would ignore is left out, so the four it gets are
// four it keeps: one whose path holds the peer, and one whose path would pass HeadCheckMaxPathCount once
// the peer appends this device.
func (self *headCheckState) relayed(peerId Id) (*bridge.AuthPin, []*protocol.UnverifiedPin) {
	var proven *bridge.AuthPin
	switch {
	case self.withheld != nil:
		proven = headCheckPinCopy(self.withheld.pin)
	case self.forked != nil:
		proven = headCheckPinCopy(self.forked.pin)
	}
	unverified := []*protocol.UnverifiedPin{}
	for _, held := range self.unverified {
		if len(unverified) == HeadCheckMaxUnverifiedSendCount {
			break
		}
		if HeadCheckMaxPathCount <= len(held.path) || slices.Contains(held.path, peerId) {
			continue
		}
		path := make([][]byte, 0, len(held.path))
		for _, sidecarId := range held.path {
			path = append(path, sidecarId.Bytes())
		}
		unverified = append(unverified, &protocol.UnverifiedPin{Pin: headCheckPinCopy(held.pin), Path: path})
	}
	return proven, unverified
}

// The UNVERIFIED pins held, as AuthPin bytes, highest first: what Status shows (§6.4's alarms row).
func (self *headCheckState) unverifiedPins() [][]byte {
	pins := make([][]byte, 0, len(self.unverified))
	for _, held := range self.unverified {
		pins = append(pins, headCheckEvidence(held.pin))
	}
	return pins
}
