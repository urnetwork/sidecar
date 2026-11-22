// QD-1184 at every reader (bridge_statement_rules.go's CheckBridgeApproval): an approved bridge_expose action's shape
// fixes the type of the statement filed under it, so a decision a person signed for a route files no map and one signed
// for a map files no route. Found at §16.6's gate by approval-gate-standing-exposures, whose standing check holds a rule
// to its action by the same predicate (record_gate_standing.go).

package sidecar

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Each statement judged where it lands, on real decisions under the test's spend check: a map filed under a route's
// approval is void where before it stood active; a route under an action naming a target_port or an expiry beside its
// cidrs is void, and so is a map under such an action, which names cidrs; a route under a route's approval and a map
// under a map's stay active. Each approval's own label fixes its own rule id.
func TestABridgeApprovalFixesTheStatementType(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop, _ := testBridgeCast(net)
	net.log.settings.BridgeBodyJudge = testBridgeJudge()
	net.log.settings.AclSpendCheck = testBridgeSpendCheck{}
	notAfter := net.timeMs + testBridgeDayMs
	expires := net.timeMs + testConfigHourMs
	// an approval of the bridge_expose action fields give, its rule id the one its single use fixes
	approval := func(label string, fields *protocol.CanonicalAction) (*bridge.BridgeApproval, []byte) {
		fields.Kind, fields.Version, fields.TargetSidecarId = uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_EXPOSE), 1, laptop.sidecarId.Bytes()
		action := testConfigMarshal(t, fields)
		decision := testBridgeDecision(t, label, action, 1, laptop.sidecarId, member, notAfter)
		return &bridge.BridgeApproval{CanonicalAction: action, Decisions: []*bridge.Signed{decision}}, testBridgeUseRuleId(label, action)
	}
	route := func(label string, fields *protocol.CanonicalAction) uint64 {
		approved, ruleId := approval(label, fields)
		body := testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site")
		body.Approval = approved
		return net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(laptop, ruleId, body)).Pin.GetVersion()
	}
	mapped := func(label string, fields *protocol.CanonicalAction) uint64 {
		approved, ruleId := approval(label, fields)
		body := testBridgeMapBody(testBridgeIpv4(100, 80, 3, 7), 8443, 22)
		body.Approval = approved
		return net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_MAP, net.bridgeMap(laptop, ruleId, expires, body)).Pin.GetVersion()
	}
	// what a void filing's reason names: the shape check's refusal
	mapsRefusal, routesRefusal := "names a route's cidrs", "names a map's target_port or expiry"
	cases := []struct {
		name string
		at   uint64
		want BridgeDisposition
		// a void filing's reason, which must name the shape check
		reason string
	}{
		{name: "a map under a route's approval", at: mapped("map under route", &protocol.CanonicalAction{Cidrs: []string{"192.168.0.0/16"}}),
			want: BridgeDispositionVoid, reason: mapsRefusal},
		{name: "a route under an approval naming a target_port", at: route("route under port", &protocol.CanonicalAction{Cidrs: []string{"192.168.0.0/16"}, TargetPort: 22}),
			want: BridgeDispositionVoid, reason: routesRefusal},
		{name: "a route under an approval naming an expiry", at: route("route under expiry", &protocol.CanonicalAction{Cidrs: []string{"192.168.0.0/16"}, ExpiresMillis: expires}),
			want: BridgeDispositionVoid, reason: routesRefusal},
		{name: "a map under an approval naming cidrs and a target_port", at: mapped("map under both", &protocol.CanonicalAction{Cidrs: []string{"192.168.0.0/16"}, TargetPort: 22}),
			want: BridgeDispositionVoid, reason: mapsRefusal},
		{name: "a route under a route's approval", at: route("route under route", &protocol.CanonicalAction{Cidrs: []string{"192.168.0.0/16"}}),
			want: BridgeDispositionActive},
		{name: "a map under a map's approval", at: mapped("map under map", &protocol.CanonicalAction{TargetPort: 22, ExpiresMillis: expires}),
			want: BridgeDispositionActive},
	}
	ledger := net.bridgeLedger()
	for _, c := range cases {
		entry := testBridgeEntryAt(t, ledger, c.at)
		switch {
		case entry.Disposition != c.want:
			t.Errorf("%s: disposition %d (%v), want %d", c.name, entry.Disposition, entry.Reason, c.want)
		case c.reason != "" && (entry.Reason == nil || !strings.Contains(entry.Reason.Error(), c.reason)):
			t.Errorf("%s: void for %v, not the shape check", c.name, entry.Reason)
		}
	}
}
