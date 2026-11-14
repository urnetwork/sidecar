//go:build !sidecar_http && !ios_extension

// §8.19's peer-list filter as the contract gate reads it (ACL-M6-04; R-ACL-1, R-ACL-8, D-ACL-5, D-ACL-11). In a
// network with a head row, a client is sent only the peers it may reach: reach(client, peer) as §8.10's contract rule
// reads it, from the network's verified state in the process's gate cache, with D-ACL-5's legacy rule for a peer
// that enforces nothing. A peer acting as the client's own subject, another client of the same sidecar, is listed
// while that subject stands. The witness exception lists nothing: a control contract is no reach.
//
// A network with no head row is unfiltered, today's exact path at one map miss (R-ACL-8). Before the gate's first
// heads load, or for a network with a head row and no verified state, the view is unavailable and its lists empty,
// never unfiltered, and the state is asked to load.
//
// A view is a value at one verified position: two views differ exactly when the listing, the position or the state
// moved, which is when a resident sends its whole list again (server/connect's recheck). Reads two maps and allocates
// nothing.

package sidecar

import (
	"time"
)

// How a network's peer lists are sent.
type AclPeerListing int

const (
	// the network has no head row: every peer, today's path
	AclPeerListingUnfiltered AclPeerListing = iota + 1
	// only the peers each client may reach in the network's verified state
	AclPeerListingFiltered
	// no heads snapshot yet, or a network with a head row and no verified state: no peer at all
	AclPeerListingUnavailable
)

// One network's view for its peer lists. A value, comparable: views of one network at one state are equal.
type AclPeerView struct {
	Listing AclPeerListing
	// The verified position n the view reads. Zero unless Filtered.
	Version uint64
	// the state, nil unless Filtered
	state *AclState
}

// The view of networkId's peer lists now, from the heads snapshot and the cache's state alone: no lock and no I/O.
// A network with a head row and no loaded state is asked to load.
func (self *AclContractGate) PeerView(networkId Id) AclPeerView {
	heads := self.heads.Load()
	if heads == nil {
		return AclPeerView{Listing: AclPeerListingUnavailable}
	}
	if _, found := (*heads)[networkId]; !found {
		return AclPeerView{Listing: AclPeerListingUnfiltered}
	}
	snapshot, status := self.states.State(networkId)
	if status != AclGateLoaded || snapshot == nil || snapshot.Acl == nil {
		self.states.Changed(networkId)
		return AclPeerView{Listing: AclPeerListingUnavailable}
	}
	return AclPeerView{Listing: AclPeerListingFiltered, Version: snapshot.Pin.GetVersion(), state: snapshot.Acl}
}

// Whether viewer is sent peer under the view: every peer when unfiltered, none when unavailable, and when filtered
// a peer viewer reaches (see the file header), never one whose subject the facts cannot tell or the state
// hard-denies, nor any peer of a viewer it cannot tell or hard-denies.
func (self AclPeerView) Listed(viewer *AclContractEnd, peer *AclContractEnd, now time.Time) bool {
	switch self.Listing {
	case AclPeerListingUnfiltered:
		return true
	case AclPeerListingFiltered:
	default:
		return false
	}
	viewerSubject, viewerKnown := viewer.subject()
	peerSubject, peerKnown := peer.subject()
	if !viewerKnown || !peerKnown {
		return false
	}
	nowMs := now.UnixMilli()
	if viewerSubject.Kind == peerSubject.Kind && viewerSubject.Id == peerSubject.Id {
		return self.state.resolve(&viewerSubject, nowMs).deny == 0
	}
	return self.state.contractReach(&viewerSubject, &peerSubject, peer.legacy(), nowMs).Allowed
}
