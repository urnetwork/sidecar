//go:build !sidecar_http && !ios_extension

// §8.19's peer-list view on hand-made rows (T2's shape): a network with no head row unfiltered, one with no loaded
// state or no heads unavailable and asked to load, reach listing a peer and its absence not, D-ACL-5's legacy rule,
// the viewer's own subject, hard denies, a new state a new view, and a listing that allocates nothing. Server's
// TestFilterNetworkPeers* run it under the resident's filter.

package sidecar

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network with no head row lists every peer; one with a head row and no state lists none and is asked to load; a
// gate with no heads lists none anywhere.
func TestAclPeerViewListings(t *testing.T) {
	net := newAclContractTestNet()
	a, b := net.fixture.device(net.owner), net.fixture.device(net.owner)
	gate, _, _ := newAclContractTestGate(t, net.states, net.heads)
	viewer, peer := net.sidecarEnd(a), net.sidecarEnd(b)

	headless := gate.PeerView(NewId())
	if headless.Listing != AclPeerListingUnfiltered || !headless.Listed(&viewer, &peer, aclTestNow) {
		t.Errorf("no head row: %+v", headless)
	}
	unloaded := gate.PeerView(net.networkId)
	if unloaded.Listing != AclPeerListingUnavailable || unloaded.Listed(&viewer, &peer, aclTestNow) {
		t.Errorf("no state: %+v", unloaded)
	}
	if _, changed := net.states.asked(); !slices.Contains(changed, net.networkId) {
		t.Error("the unloaded network was not asked to load")
	}

	held := &aclContractTestHeads{hold: make(chan struct{})}
	defer close(held.hold)
	coldGate, _, _ := newAclContractTestGate(t, net.states, held)
	if cold := coldGate.PeerView(NewId()); cold.Listing != AclPeerListingUnavailable {
		t.Errorf("before the first heads load: %+v", cold)
	}
}

// Under a loaded state a viewer is listed the peers it reaches, its own subject's other clients, and an app device a
// rule reaches; not a peer it does not reach, a legacy client only a ports-limited rule names, an end the facts cannot
// tell, or anything at all when it is suspended. A new state is a new view.
func TestAclPeerViewListsWhatTheViewerReaches(t *testing.T) {
	net := newAclContractTestNet()
	a, b, c := net.fixture.device(net.owner), net.fixture.device(net.owner), net.fixture.device(net.owner)
	enforcing, legacy := NewId(), NewId()
	net.dial(a, b)
	limited := net.fixture.rule([]Id{net.sidecarAtom(a)}, []*protocol.AclTarget{{ClientId: enforcing.Bytes()}, {ClientId: legacy.Bytes()}}, protocol.AclAction_ACL_ACTION_DIAL)
	limited.PortsLimited = true
	gate := net.gate(t)
	view := gate.PeerView(net.networkId)
	if view.Listing != AclPeerListingFiltered || view.Version != 1 {
		t.Fatalf("view: %+v", view)
	}
	viewer := net.sidecarEnd(a)
	ownOther := net.sidecarEnd(a)
	cases := []struct {
		name   string
		peer   AclContractEnd
		listed bool
	}{
		{name: "a peer it reaches", peer: net.sidecarEnd(b), listed: true},
		{name: "a peer it does not reach", peer: net.sidecarEnd(c), listed: false},
		{name: "its own sidecar's other client", peer: ownOther, listed: true},
		{name: "an enforcing app device a limited rule names", peer: net.clientEnd(enforcing, net.owner, true), listed: true},
		{name: "a legacy client a limited rule names", peer: net.clientEnd(legacy, Id{}, false), listed: false},
		{name: "an end the facts cannot tell", peer: AclContractEnd{}, listed: false},
		{name: "an unadmitted sidecar", peer: net.sidecarEnd(NewId()), listed: false},
	}
	for _, c := range cases {
		if listed := view.Listed(&viewer, &c.peer, aclTestNow); listed != c.listed {
			t.Errorf("%s: listed %t", c.name, listed)
		}
	}
	unknownViewer := AclContractEnd{}
	peerB := net.sidecarEnd(b)
	if view.Listed(&unknownViewer, &peerB, aclTestNow) {
		t.Error("a viewer the facts cannot tell was listed a peer")
	}

	// a suspension is a new state, a new view, and the suspended viewer is listed nothing, its own clients included
	net.fixture.rows.Suspensions = append(net.fixture.rows.Suspensions, &protocol.AclSuspension{Subject: a.Bytes(), SuspendId: NewId().Bytes()})
	net.states.install(net.networkId, net.fixture.state(t))
	suspended := gate.PeerView(net.networkId)
	if suspended == view {
		t.Fatal("a new state read as the same view")
	}
	if suspended.Listed(&viewer, &peerB, aclTestNow) || suspended.Listed(&viewer, &ownOther, aclTestNow) {
		t.Error("a suspended viewer was listed a peer")
	}
}

// Listing a peer allocates nothing (§22.5's gate).
func TestAclPeerViewListedAllocatesNothing(t *testing.T) {
	net := newAclContractTestNet()
	owner := net.fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	a, b := net.fixture.device(owner), net.fixture.device(owner)
	net.dial(a, b)
	gate := net.gate(t)
	view := gate.PeerView(net.networkId)
	viewer, peer, stranger := net.sidecarEnd(a), net.sidecarEnd(b), net.sidecarEnd(NewId())
	for _, listed := range []*AclContractEnd{&peer, &stranger} {
		if allocations := testing.AllocsPerRun(100, func() { view.Listed(&viewer, listed, aclTestNow) }); 0 < allocations {
			t.Errorf("allocates %v", allocations)
		}
	}
}
