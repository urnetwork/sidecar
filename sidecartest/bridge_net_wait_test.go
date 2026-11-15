//go:build !sidecar_http && !ios_extension

// BridgeNetHost.WaitDecisions against the lost wakeup FS-38's port-target check had (sidecartest/fault/fs_bridge_m6.go):
// that check sent its two flows and then waited for one decision more than it could count, so a decision the hook
// recorded between its look and its count was never waited for, and the run stalled. A wait on the decisions
// themselves, armed before each read, sees a decision recorded before the wait began and one recorded after its read.

package sidecartest

import (
	"net/netip"
	"testing"

	"github.com/urnetwork/connect"
)

// A host with nothing but the hook's record, which WaitDecisions reads.
func newBridgeNetWaitHost(t *testing.T) *BridgeNetHost {
	return &BridgeNetHost{
		bridgeNet: &BridgeNet{t: t, settings: DefaultBridgeNetSettings()},
		Device:    &BridgeNetDevice{Name: "wait host"},
		records:   connect.NewMonitorValue(0),
	}
}

func (self *BridgeNetHost) recordDecision(sourceId connect.Id, ipProtocol connect.IpProtocol, to netip.AddrPort) {
	self.record(func() {
		self.decisions = append(self.decisions, &BridgeNetDecision{SourceId: sourceId, Protocol: ipProtocol, To: to, Verdict: connect.EgressVerdictDeny})
	})
}

// Whether decisions hold a UDP flow to udpTo and a TCP flow to tcpTo, as the port-target check waits for.
func bridgeNetWaitBoth(decisions []*BridgeNetDecision, udpTo netip.AddrPort, tcpTo netip.AddrPort) bool {
	udp, tcp := false, false
	for _, decision := range decisions {
		udp = udp || (decision.Protocol == connect.IpProtocolUdp && decision.To == udpTo)
		tcp = tcp || (decision.Protocol == connect.IpProtocolTcp && decision.To == tcpTo)
	}
	return udp && tcp
}

// Both decisions landed before the wait looked, the interleaving that stalled: the wait answers them at once.
func TestBridgeNetHostWaitDecisionsSeesDecisionsRecordedBeforeTheWait(t *testing.T) {
	host := newBridgeNetWaitHost(t)
	sourceId := connect.NewId()
	udpTo := netip.MustParseAddrPort("100.90.128.2:50001")
	tcpTo := netip.MustParseAddrPort("100.90.128.2:50002")
	host.recordDecision(sourceId, connect.IpProtocolUdp, udpTo)
	host.recordDecision(connect.NewId(), connect.IpProtocolTcp, tcpTo)
	host.recordDecision(sourceId, connect.IpProtocolTcp, tcpTo)

	decisions := host.WaitDecisions(sourceId, func(decisions []*BridgeNetDecision) bool {
		return bridgeNetWaitBoth(decisions, udpTo, tcpTo)
	})
	if len(decisions) != 2 {
		t.Fatalf("the wait answered %d decisions of the source, not its 2", len(decisions))
	}
	for _, decision := range decisions {
		if decision.SourceId != sourceId {
			t.Fatalf("the wait answered another source's decision: %+v", decision)
		}
	}
}

// The second decision lands only once the wait has read the first alone: the monitor armed before that read wakes the
// wait, which answers both.
func TestBridgeNetHostWaitDecisionsWakesOnADecisionRecordedAfterItsRead(t *testing.T) {
	host := newBridgeNetWaitHost(t)
	sourceId := connect.NewId()
	udpTo := netip.MustParseAddrPort("100.90.128.2:50001")
	// the same port number on the other protocol, which a wait on destinations alone would take for the UDP flow's
	tcpTo := netip.MustParseAddrPort("100.90.128.2:50001")
	host.recordDecision(sourceId, connect.IpProtocolUdp, udpTo)

	reads := 0
	decisions := host.WaitDecisions(sourceId, func(decisions []*BridgeNetDecision) bool {
		reads += 1
		if reads == 1 {
			if bridgeNetWaitBoth(decisions, udpTo, tcpTo) {
				t.Errorf("the first read held the TCP decision before it was recorded")
			}
			// after the read the wait armed for, so only the monitor can wake it
			go host.recordDecision(sourceId, connect.IpProtocolTcp, tcpTo)
			return false
		}
		return bridgeNetWaitBoth(decisions, udpTo, tcpTo)
	})
	if len(decisions) != 2 || reads < 2 {
		t.Fatalf("the wait answered %d decisions after %d reads", len(decisions), reads)
	}
}
