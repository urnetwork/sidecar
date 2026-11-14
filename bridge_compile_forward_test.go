// The compiler's forwarding fields (§17.9's verify and target rows, owner decision 197; DESIGN-DETAILS 4.2.2): each
// subject's BridgeIdentity carries its forwarding Delegation and key only while that Delegation is live at the state,
// so a superseded or revoked one leaves at the next compile, and a link to an app host targets the device client its
// forwarding Delegation names and pins that client's key.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The identity the compiled state lists for a sidecar, nil for none.
func testBridgeCompileIdentity(state *bridge.BridgeState, sidecarId Id) *bridge.BridgeIdentity {
	for _, identity := range state.GetIdentities() {
		if Id(identity.GetSidecarId()) == sidecarId {
			return identity
		}
	}
	return nil
}

// A forwarding Delegation's statement naming device and its host client: the device client the VPN component runs in
// and that client's key.
func (self *testConfigNet) hostForwardingStatement(device testConfigDevice, label string, hostClientId Id, hostClientKey []byte) *protocol.Delegation {
	statement, _ := self.forwardingStatement(device, label)
	statement.Forward.HostClientId = hostClientId.Bytes()
	statement.Forward.HostClientPublicKey = bytes.Clone(hostClientKey)
	return statement
}

// A live forwarding Delegation fills its subject's identity; a newer one replaces it at the next compile; a revoked
// one leaves, with nothing in its place; a subject with none has neither field.
func TestCompileFillsForwardingFieldsOnlyForALiveDelegation(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	compiled, _ := testBridgeCompile(t, net.view(), net.local())
	for _, device := range []testConfigDevice{net.peer, net.other} {
		identity := testBridgeCompileIdentity(compiled.State, device.sidecarId)
		if identity == nil || len(identity.GetForwardDelegationId()) != 0 || len(identity.GetForwardPublicKey()) != 0 {
			t.Fatalf("a subject with no forwarding Delegation: %v", identity)
		}
	}

	first := net.forward(net.peer, "peer first")
	compiled, _ = testBridgeCompile(t, net.view(), net.local())
	identity := testBridgeCompileIdentity(compiled.State, net.peer.sidecarId)
	if !bytes.Equal(identity.GetForwardDelegationId(), first.id) || !bytes.Equal(identity.GetForwardPublicKey(), first.key.Public().(ed25519.PublicKey)) {
		t.Fatalf("the live Delegation's fields: %x and %x", identity.GetForwardDelegationId(), identity.GetForwardPublicKey())
	}
	if other := testBridgeCompileIdentity(compiled.State, net.other.sidecarId); len(other.GetForwardDelegationId()) != 0 {
		t.Fatal("another subject took the peer's forwarding Delegation")
	}

	// superseded: the newer one alone
	second := net.forward(net.peer, "peer second")
	compiled, _ = testBridgeCompile(t, net.view(), net.local())
	identity = testBridgeCompileIdentity(compiled.State, net.peer.sidecarId)
	if !bytes.Equal(identity.GetForwardDelegationId(), second.id) || !bytes.Equal(identity.GetForwardPublicKey(), second.key.Public().(ed25519.PublicKey)) {
		t.Fatalf("after a supersession: %x", identity.GetForwardDelegationId())
	}

	// revoked: none
	net.mustPost(net.peer, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(second.id, 0))
	compiled, _ = testBridgeCompile(t, net.view(), net.local())
	identity = testBridgeCompileIdentity(compiled.State, net.peer.sidecarId)
	if identity == nil || len(identity.GetForwardDelegationId()) != 0 || len(identity.GetForwardPublicKey()) != 0 {
		t.Fatalf("after its revocation: %v", identity)
	}
}

// §17.9's target row for an app host: the link targets the device client the peer's live forwarding Delegation names
// and pins that client's key, in place of the binding's client, which is the sidecar's own; a peer whose Delegation
// names no host client links by its binding with no pin.
func TestCompileLinksAnAppHostByItsForwardingDelegationsHostClient(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	hostClientId := testConfigId("the peer's device client")
	hostClientKey := testConfigDeviceKey("the peer's device client key").Public().(ed25519.PublicKey)
	net.mustPost(net.peer, bridge.SignedType_SIGNED_DELEGATION, net.hostForwardingStatement(net.peer, "peer host", hostClientId, hostClientKey))
	net.forward(net.other, "other, no host")

	_, rules := testBridgeCompile(t, net.view(), net.local())
	entry := testBridgeCompileEntry(rules, testBridgePrefix(100, 80, 3, 9, 32))
	if entry == nil || len(entry.GetLinks()) != 1 {
		t.Fatalf("the app host's entry: %v", entry)
	}
	link := entry.GetLinks()[0]
	if Id(link.GetTargetClientId()) != hostClientId || !bytes.Equal(link.GetTargetClientPublicKey(), hostClientKey) {
		t.Fatalf("the app host's link targets %x pinning %x", link.GetTargetClientId(), link.GetTargetClientPublicKey())
	}
	if Id(link.GetTargetSidecarId()) != net.peer.sidecarId || !bytes.Equal(link.GetTargetIdentityPublicKey(), net.peer.publicKey()) {
		t.Fatalf("the app host's link names sidecar %x", link.GetTargetSidecarId())
	}
	if Id(link.GetTargetClientId()) == testBridgeCompileClientId(net.peer, 1) {
		t.Fatal("the app host's link targets the sidecar's own client")
	}

	twin := testBridgeCompileEntry(rules, testBridgePrefix(100, 80, 4, 10, 32))
	if twin == nil || len(twin.GetLinks()) != 1 {
		t.Fatalf("the twin's entry: %v", twin)
	}
	twinLink := twin.GetLinks()[0]
	if Id(twinLink.GetTargetClientId()) != testBridgeCompileClientId(net.other, 1) || len(twinLink.GetTargetClientPublicKey()) != 0 {
		t.Fatalf("a peer with no host client: client %x, pin %x", twinLink.GetTargetClientId(), twinLink.GetTargetClientPublicKey())
	}

	// its revocation returns the link to the binding at the next compile
	live := net.log.State().ForwardingDelegation(net.peer.sidecarId)
	net.mustPost(net.peer, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(live.GetDelegationId(), 0))
	_, rules = testBridgeCompile(t, net.view(), net.local())
	link = testBridgeCompileEntry(rules, testBridgePrefix(100, 80, 3, 9, 32)).GetLinks()[0]
	if Id(link.GetTargetClientId()) != testBridgeCompileClientId(net.peer, 1) || len(link.GetTargetClientPublicKey()) != 0 {
		t.Fatalf("after the revocation: client %x, pin %x", link.GetTargetClientId(), link.GetTargetClientPublicKey())
	}
}
