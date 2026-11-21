//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A cold device anchors the retained base in the signed records of its head.
type testForwardProviderRows struct {
	*testConfigRowsSource
	head *ConfigHead
}

func (self *testForwardProviderRows) CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error) {
	return CheckConfigBase(self.head, check, check.CompileRows)
}

// The signed fixture crosses into the external test so the sidecar role keeps its device-independent build.
type ForwardProviderFixture struct {
	State                          *bridge.BridgeState
	Clock                          Clock
	NetworkId, SubjectId, TargetId Id
	Target                         netip.AddrPort
}

// The listener and the target's provider compile the same signed activation. Its approved port is
// available only at the named target, with the matching protocol, and disappears on a signed withdrawal.
func CheckActivatedForwardProvider(t *testing.T, checkAdmission func(ForwardProviderFixture, bool)) {
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
		decision := testSpendDecisionBody(action, testConfigId("approved forward"), world.member,
			protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, world.hostId, net.log.State().Pin(), world.gate.notAfterMs)
		return testSpendSignedBy(t, world.laptop.sidecarId, world.laptop.key, decision)
	}
	target := world.laptop.sidecarId
	address := testBridgeIpv4(100, 80, 1, 14)
	world.net.mustPost(world.laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, world.net.bridgeAddress(world.laptop, address))
	request := &BridgeForwardRequest{Target: target, Protocol: bridgeProtocolUdp, Port: 5353, LocalPort: 10053, Lifetime: 15 * time.Minute}
	deadline := world.clock.Now().Add(request.Lifetime)
	filed, err := world.filer.Forward(ctx, world.mcp(), request)
	if err != nil || len(filed.GrantId) == 0 {
		t.Fatalf("filing the forward: %+v, %v", filed, err)
	}
	route, err := world.filer.ForwardRoute(ctx, request, filed.GrantId)
	if err != nil || !route.Live || route.Address != bridgeAddressOf(address) || !route.ExpiresAt.Equal(deadline) {
		t.Fatalf("approved route: %+v, %v", route, err)
	}
	for _, other := range []*BridgeForwardRequest{
		{Target: target, Protocol: bridgeProtocolTcp, Port: 5353},
		{Target: target, Protocol: bridgeProtocolUdp, Port: 5354},
	} {
		if route, err := world.filer.ForwardRoute(ctx, other, filed.GrantId); err != nil || route.Live {
			t.Fatalf("nearby route: %+v, %v", route, err)
		}
	}
	provider := ForwardProviderFixture{
		Clock: world.clock, NetworkId: net.log.State().NetworkId(), SubjectId: world.hostId, TargetId: target,
		Target: netip.AddrPortFrom(bridgeAddressOf(address), uint16(request.Port)),
	}
	dialRows := func(recipient Id, withKey bool) []*bridge.BridgeRuleReach {
		t.Helper()
		state := net.log.State()
		base := state.Base()
		head, err := world.heads.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
		if err != nil {
			t.Fatal(err)
		}
		keyAt := world.filer.repoKeyAt()
		if !withKey {
			keyAt = nil
		}
		view, err := NewBridgeConfigView(state, head, plan.Local, keyAt, nil)
		if err != nil {
			t.Fatal(err)
		}
		compiled, rules := testBridgeCompile(t, view, &BridgeCompileLocal{SidecarId: recipient})
		if recipient == target && withKey {
			if !compiled.State.GetHasDocument() || !slices.Contains(rules.GetAddresses(), address) {
				t.Fatal("the target's compiled policy is missing its document or its hosted address")
			}
			provider.State = compiled.State
		}
		var reaches []*bridge.BridgeRuleReach
		for _, row := range testBridgeCompileSubject(rules, world.hostId).GetDial() {
			if bytes.Equal(row.GetGrantId(), filed.GrantId) {
				reaches = append(reaches, row)
			}
		}
		return reaches
	}
	matchingPort := func() {
		t.Helper()
		rows := dialRows(target, true)
		if len(rows) != 1 || rows[0].GetProtocol() != bridgeProtocolUdp || len(rows[0].GetPorts()) != 1 ||
			rows[0].GetPorts()[0].GetFirst() != request.Port || rows[0].GetPorts()[0].GetLast() != request.Port ||
			rows[0].GetExpires() != route.ExpiresAt.UnixMilli() {
			t.Fatalf("provider's grant rows: %v", rows)
		}
		checkAdmission(provider, true)
	}
	matchingPort()
	if len(dialRows(world.net.owner.sidecarId, true)) != 0 || len(dialRows(target, false)) != 0 {
		t.Fatal("provider compiled a port without its authorized target and key")
	}
	tip := net.n
	if reached := ledger.foldLedger(tip, nil); reached != tip {
		t.Fatalf("the bridge ledger folded through %d, want %d", reached, tip)
	}
	world.heads.saved = ledger.heads[net.log.State().Base().GetConfigVersion()]
	matchingPort()
	retained := net.log.Retained()
	retained.Entries = retained.Entries[len(retained.Entries)-1:]
	cold, err := RestoreConfigLog(ledger.readerSettings(), retained, &testForwardProviderRows{testConfigRowsSource: net.source, head: world.heads.saved})
	if err != nil {
		t.Fatal(err)
	}
	net.log = cold
	matchingPort()
	if reopened, err := world.filer.ForwardRoute(ctx, request, filed.GrantId); err != nil || !reopened.Live || !reopened.ExpiresAt.Equal(deadline) {
		t.Fatalf("restored route: %+v, %v", reopened, err)
	}
	// A host still holding the last live state must enforce the signed deadline on its own clock.
	expiring := provider
	expiryClock := &identityTestClock{current: route.ExpiresAt.Add(-time.Millisecond)}
	expiring.Clock = expiryClock
	checkAdmission(expiring, true)
	expiryClock.advance(time.Millisecond)
	checkAdmission(expiring, false)
	world.install()
	if _, err := world.filer.Close(ctx, world.confirmed(), filed.GrantId, false); err != nil {
		t.Fatal(err)
	}
	if route, err := world.filer.ForwardRoute(ctx, request, filed.GrantId); err != nil || route.Live || len(dialRows(target, true)) != 0 {
		t.Fatalf("withdrawn route: %+v, %v", route, err)
	}
	checkAdmission(provider, false)
}
