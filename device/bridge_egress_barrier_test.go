//go:build sidecar_testhooks

// A publish's swap is the policy's linearization point, and nothing on the packet path waits on it: a flow resolved
// while a publish is held before its swap is decided whole by the state in force, at its generation, and the next one
// after the swap by the new state, by the driver's barriers rather than by timing.

package device_test

import (
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestBridgeEgressResolvesWhileAPublishIsHeld(t *testing.T) {
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	actors := sidecartest.NewActorTable(sidecartest.NewFakeClock(sidecartest.DefaultClockStart()), driver)
	remove, err := sidecartest.InstallTestHooks(nil, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	lan := func() *connect.EgressFlow {
		return egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:443")
	}
	test.expectPass("before", lan(), egressTestTag(egressTestUntagged, []byte{device.BridgeRuleAllowAll}))

	site := sidecartest.BarrierSite("bridge_egress.publish.before", "")
	if err := driver.Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	documented := *test.input
	documented.State = device.PostureEnforcingDocument
	run := driver.Start(actors.Actor(t.Context(), "publisher"), func() error {
		test.policy.Publish(&documented)
		return nil
	})
	if err := driver.AwaitHeld(t.Context(), site, ""); err != nil {
		t.Fatal(err)
	}
	// held before its swap: the old state decides, at its own generation, and the resolve returns
	if decision := test.policy.ResolveEgress(lan()); decision.Verdict != connect.EgressVerdictPass || decision.PolicyGeneration != 1 {
		t.Fatalf("while held: %+v", decision)
	}
	if err := driver.Release(site); err != nil {
		t.Fatal(err)
	}
	<-run.Ended()
	if decision := test.policy.ResolveEgress(lan()); decision.Verdict != connect.EgressVerdictDeny || decision.PolicyGeneration != 2 {
		t.Fatalf("after the swap: %+v", decision)
	}
	if violations := driver.Violations(); len(violations) != 0 {
		t.Errorf("the sites broke the naming rule: %v", violations)
	}
}
