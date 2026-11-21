//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

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
	target := world.laptop.sidecarId
	address := testBridgeIpv4(100, 80, 1, 14)
	world.net.mustPost(world.laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, world.net.bridgeAddress(world.laptop, address))
	request := &BridgeForwardRequest{Target: target, Protocol: bridgeProtocolUdp, Port: 5353, LocalPort: 10053}
	filed, err := world.filer.Forward(ctx, world.mcp(), request)
	if err != nil || len(filed.GrantId) == 0 {
		t.Fatalf("filing the forward: %+v, %v", filed, err)
	}
	route, err := world.filer.ForwardRoute(ctx, request, filed.GrantId)
	if err != nil || !route.Live || route.Address != bridgeAddressOf(address) || !route.ExpiresAt.After(world.clock.Now()) {
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
	readState := world.net.log.State
	provider := ForwardProviderFixture{
		Clock: world.clock, NetworkId: readState().NetworkId(), SubjectId: world.hostId, TargetId: target,
		Target: netip.AddrPortFrom(bridgeAddressOf(address), uint16(request.Port)),
	}
	dialRows := func(recipient Id, withKey bool) []*bridge.BridgeRuleReach {
		t.Helper()
		state := readState()
		base := state.Base()
		head, err := world.heads.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
		if err != nil {
			t.Fatal(err)
		}
		keyAt := world.filer.repoKeyAt()
		if !withKey {
			keyAt = nil
		}
		view, err := NewBridgeConfigView(state, head, nil, keyAt, nil)
		if err != nil {
			t.Fatal(err)
		}
		compiled, rules := testBridgeCompile(t, view, &BridgeCompileLocal{SidecarId: recipient})
		if recipient == target && withKey {
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
	if verdict := world.net.fold(world.net.owner, world.net.n, world.net.log.State().Base().GetConfigVersion()+1); !verdict.Accepted() {
		t.Fatalf("folding the activation: %+v", verdict)
	}
	world.heads.reader.publish(world.net)
	matchingPort()
	retained := world.net.log.Retained()
	retained.Entries = retained.Entries[len(retained.Entries)-1:]
	cold, err := RestoreConfigLogRowsOnly(world.net.log.settings, retained, world.net.source, nil)
	if err != nil {
		t.Fatal(err)
	}
	readState = cold.State
	matchingPort()
	readState = world.net.log.State
	world.install()
	if _, err := world.filer.Close(ctx, world.confirmed(), filed.GrantId, false); err != nil {
		t.Fatal(err)
	}
	if route, err := world.filer.ForwardRoute(ctx, request, filed.GrantId); err != nil || route.Live || len(dialRows(target, true)) != 0 {
		t.Fatalf("withdrawn route: %+v, %v", route, err)
	}
	checkAdmission(provider, false)
}
