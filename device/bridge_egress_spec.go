// §17.9's egress spec on the sender's default route (D-BRIDGE-13): Route sends a packet no entry holds to an approved
// exit's link under exits and rejects it under none (bridge_route.go). An app device's VPN component runs the device's
// IP and port forwarding and nothing else (owner decision 197), and §17.9's egress spec on app devices follows M8
// (§18.17), so until an app switches it on (BRIDGE-M8-02) its bridge runs with BridgeSettings.EgressSpecOff: the rules
// its router reads carry no egress, today's route stays the device's, no link to an exit is built, and the status reads
// auto. The rules the provider hook reads keep the spec, which no hook decision reads, and the entries are routed as
// ever. A sidecar's own Public contracts stay §8.10's gate's to refuse under exits or none.

package device

import (
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The rules the router reads: rules, or under EgressSpecOff a copy whose egress spec is auto, today's route, with no
// exit. Off the packet path, once a publish.
func bridgeRouteRulesFor(rules *bridge.BridgeRules, settings *BridgeSettings) *bridge.BridgeRules {
	if rules == nil || !settings.EgressSpecOff || rules.GetEgress() == nil {
		return rules
	}
	routeRules := proto.Clone(rules).(*bridge.BridgeRules)
	routeRules.Egress = &bridge.BridgeRuleEgress{Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO}
	return routeRules
}
