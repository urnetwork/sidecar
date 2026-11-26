//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// §17.6's exposed prefixes at the compile and the filer (owner decision 778): S's map onto an address of its own
// remapped route's exposed prefix compiles, its target read into the block, where the device's hook dials the served
// address; a map onto an address of the block that no exposed prefix of S's holds is void with map_refused; and the
// filer plans the first and refuses the second.

package sidecar

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestCompileKeepsAMapOntoItsOwnExposedPrefix(t *testing.T) {
	net := newTestBridgeRouteSelfNet(t)
	lanPrefix, exposedPrefix := testBridgePrefix(192, 168, 7, 0, 24), testBridgePrefix(100, 80, 200, 0, 24)
	approval, routeId := testBridgeExposeApproval(t, "remap", net.host.sidecarId, []string{"192.168.7.0/24"}, net.host.sidecarId, net.member, net.timeMs+testBridgeDayMs)
	body := testBridgeApprovedSubnet(lanPrefix, approval)
	body.ExposedPrefix = exposedPrefix
	net.mustPost(net.host, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(net.host, routeId, body))
	if rule := net.ledgerOf(net.log).Rule(routeId); rule == nil || !rule.Active() {
		t.Fatalf("the remapped route: %+v", rule)
	}
	hostAddress := testBridgeIpv4(100, 80, 3, 7)
	mapOf := func(label string, port uint32, target []byte) []byte {
		ruleId := testBridgeRuleId(label)
		mapBody := testBridgeMapBody(hostAddress, port, 0)
		mapBody.Target = target
		net.mustPost(net.host, bridge.SignedType_SIGNED_BRIDGE_MAP, net.bridgeMap(net.host, ruleId, 0, mapBody))
		return ruleId
	}
	exposed := mapOf("onto the exposed /24", 62078, []byte{100, 80, 200, 9})
	mapOf("onto the block outside it", 62079, []byte{100, 80, 201, 9})

	compiled, rules := testBridgeCompile(t, net.view(), net.local())
	if len(rules.GetMaps()) != 1 || !bytes.Equal(rules.GetMaps()[0].GetMapId(), exposed) ||
		!bytes.Equal(rules.GetMaps()[0].GetTarget(), []byte{100, 80, 200, 9}) {
		t.Fatalf("maps %v", rules.GetMaps())
	}
	refused := 0
	for _, alarm := range compiled.Alarms {
		if alarm.Reason == SidecarBridgeAlarmMapRefused {
			refused += 1
		}
	}
	if refused != 1 {
		t.Fatalf("%d maps refused, alarms %v", refused, compiled.Alarms)
	}

	// the filer plans a map onto the exposed /24 and refuses one onto the rest of the block
	view := &bridgeFileView{
		ledger: net.ledgerOf(net.log),
		block:  &bridge.BridgeBlock{Ipv4Prefix: testBridgePrefix(100, 80, 0, 0, 16)},
		self:   net.host.sidecarId,
	}
	filer := &BridgeFiler{clock: RealClock{}, settings: DefaultBridgeFilerSettings()}
	if _, err := filer.mapPlan(view, &BridgeMapRequest{FirstPort: 62078, Target: netip.MustParseAddr("100.80.200.9")}); err != nil {
		t.Fatalf("a map onto the exposed /24: %v", err)
	}
	if _, err := filer.mapPlan(view, &BridgeMapRequest{FirstPort: 62079, Target: netip.MustParseAddr("100.80.201.9")}); !errors.Is(err, ErrBridgeFileRefused) {
		t.Fatalf("a map onto the block outside it: %v", err)
	}
	// another host's exposed prefix is not this one's
	view.self = net.peer.sidecarId
	if _, err := filer.mapPlan(view, &BridgeMapRequest{FirstPort: 62078, Target: netip.MustParseAddr("100.80.200.9")}); !errors.Is(err, ErrBridgeFileRefused) {
		t.Fatalf("a map onto another host's exposed /24: %v", err)
	}
}
