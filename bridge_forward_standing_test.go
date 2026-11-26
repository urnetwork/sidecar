//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// A forward the gate passes as standing on the activated grant that covers it is live on that grant
// (acl_grant_port_consistency_test.go's active grant row; QD-1428): AclEngine.ActiveGrant covers a forward asked again
// by its own grant's sealed ports, and BridgeFiler.ForwardRoute, on the legs that file forwards, serves the forward
// filed under that pass on the grant. Synthetic values only.

package sidecar

import (
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A forward asked again once its own grant is in force passes as standing (§16.6's step 2), and the forward filed under
// that pass, naming no grant, is live on the grant: ActiveGrant covers the very action the person approved by the
// grant's sealed port, and no forward to another port or protocol; ForwardRoute with no grant serves the request on the
// grant at its expiry, and no other port; and once the grant is revoked neither stands. Before this change ActiveGrant
// covered no forward by a port-limited grant, and ForwardRoute with no grant read document rules alone, so a forward the
// gate passed as standing on its grant would not have been live.
func TestBridgeForwardAskedAgainRidesItsActivatedGrant(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := t.Context()
	net := world.net
	state := net.log.State()
	base := state.Base()
	head, err := world.heads.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanAclSave(ctx, &AclSaveInput{
		Policy: []byte(`{"requests":[{"src":["autogroup:member"],"dst":["autogroup:self"],"allow":["dial"]}]}`),
		Head:   head, State: state, Now: world.clock.Now(), Random: world.filer.random,
	})
	if err != nil {
		t.Fatal(err)
	}
	net.writerFold(net.owner, plan.Head, base.GetFoldedThrough())
	ledger := newTestBridgeLedgerNetOver(t, net)
	ledger.heads[net.log.State().Base().GetConfigVersion()] = plan.Head
	world.heads.saved = plan.Head
	world.filer.args.AclLocal = func() *AclLocalPolicy { return plan.Local }
	world.install()
	net.log.settings.AclSpendCheck = NewSpendCheck(nil)
	world.gate.signDecision = func(action *StoredCanonicalAction) *bridge.Signed {
		decision := testSpendDecisionBody(action, testConfigId("forward asked again"), world.member,
			protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, world.hostId, net.log.State().Pin(), world.gate.notAfterMs)
		return testSpendSignedBy(t, world.laptop.sidecarId, world.laptop.key, decision)
	}
	target := world.laptop.sidecarId
	net.mustPost(world.laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(world.laptop, testBridgeIpv4(100, 80, 1, 14)))
	request := &BridgeForwardRequest{Target: target, Protocol: bridgeProtocolUdp, Port: 5353, LocalPort: 10053, Lifetime: 15 * time.Minute}
	deadline := world.clock.Now().Add(request.Lifetime)
	filed, err := world.filer.Forward(ctx, world.mcp(), request)
	if err != nil || len(filed.GrantId) == 0 {
		t.Fatalf("filing the forward: %+v, %v", filed, err)
	}
	calls := world.gate.seen()
	approved, err := ParseStoredCanonicalAction(calls[len(calls)-1].canonical)
	if err != nil {
		t.Fatal(err)
	}
	install := func() {
		t.Helper()
		acl, err := net.log.State().Acl()
		if err != nil {
			t.Fatal(err)
		}
		if err := world.engine.InstallWithGrants(acl, plan.Local, newAclStateGrantDetails(net.log.State(), nil, world.filer.repoKeyAt())); err != nil {
			t.Fatal(err)
		}
	}
	install()
	now := world.clock.Now()
	if !world.engine.ActiveGrant(approved, world.hostId, now) {
		t.Fatal("the approved forward asked again is not covered by its own grant")
	}
	for _, other := range []*BridgeForwardRequest{
		{Target: target, Protocol: bridgeProtocolUdp, Port: 5354},
		{Target: target, Protocol: bridgeProtocolTcp, Port: 5353},
	} {
		protocolName := map[uint32]string{bridgeProtocolTcp: "tcp", bridgeProtocolUdp: "udp"}[other.Protocol]
		destination := "sidecar:" + hex.EncodeToString(target.Bytes())
		stored, err := world.filer.args.Grants.Action(ctx, &protocol.CanonicalAction{Kind: uint32(SidecarActionForward)}, &AclGrantRequest{
			Subject: world.hostId, GrantDst: []string{destination}, GrantAllow: []string{"dial"},
			Detail: &protocol.CanonicalActionDetail{TargetPort: other.Port, GrantDst: []string{destination + ":" + protocolName + ":" + strconv.FormatUint(uint64(other.Port), 10)}},
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		if world.engine.ActiveGrant(stored, world.hostId, now) {
			t.Errorf("a forward to %s %d is covered by the grant of %d", protocolName, other.Port, request.Port)
		}
		if route, err := world.filer.ForwardRoute(ctx, other, nil); err != nil || route.Live {
			t.Errorf("a standing forward to %s %d: %+v, %v", protocolName, other.Port, route, err)
		}
	}

	// the gate passes the forward asked again as standing, as its ActiveGrant answered
	func() {
		world.gate.stateLock.Lock()
		defer world.gate.stateLock.Unlock()
		world.gate.standing = true
	}()
	standing, err := world.filer.Forward(ctx, world.mcp(), request)
	if err != nil || len(standing.GrantId) != 0 {
		t.Fatalf("the forward asked again under the standing pass: %+v, %v", standing, err)
	}
	route, err := world.filer.ForwardRoute(ctx, request, standing.GrantId)
	if err != nil || !route.Live || !route.ExpiresAt.Equal(deadline) {
		t.Fatalf("the standing forward's route: %+v, %v", route, err)
	}

	if _, err := world.filer.Close(ctx, world.confirmed(), filed.GrantId, false); err != nil {
		t.Fatal(err)
	}
	install()
	if world.engine.ActiveGrant(approved, world.hostId, world.clock.Now()) {
		t.Error("the forward is covered by its revoked grant")
	}
	if route, err := world.filer.ForwardRoute(ctx, request, nil); err != nil || route.Live {
		t.Errorf("the standing forward's route after the revoke: %+v, %v", route, err)
	}
}
