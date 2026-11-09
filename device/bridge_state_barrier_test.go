//go:build sidecar_testhooks

// D-BRIDGE-21's order, by the driver's barriers: a revocation publishes the next policy before any CloseFlows, so a
// flow held between the two already meets the new generation, and one that resolved before the swap and dials across
// it is caught by connect's recheck, which reads the newer generation and resolves it again to a deny.

package device_test

import (
	"slices"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestBridgeRevocationPublishesBeforeCloseFlows(t *testing.T) {
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	actors := sidecartest.NewActorTable(sidecartest.NewFakeClock(sidecartest.DefaultClockStart()), driver)
	remove, err := sidecartest.InstallTestHooks(nil, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	test := newStateTest(t, dispositionTestFixture(), true)
	hook := test.bridge.EgressHook()
	exit := test.flow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
	// registered at g, its dial in progress
	registered := hook.ResolveEgress(exit)
	if registered.Verdict != connect.EgressVerdictPass {
		t.Fatalf("before: %+v", registered)
	}

	site := sidecartest.BarrierSite("bridge_state.close.before", "")
	if err := driver.Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	run := driver.Start(actors.Actor(t.Context(), "revoker"), func() error {
		return test.bridge.Revoke(bridge.SignedType_SIGNED_SIDECAR_REVOKE, sidecartest.BridgeFixtureSidecarId(egressTestUntagged), 0)
	})
	if err := driver.AwaitHeld(t.Context(), site, ""); err != nil {
		t.Fatal(err)
	}
	// between the swap and the closes: g+1 is published and nothing has closed yet
	if hook.PolicyGeneration() != registered.PolicyGeneration+1 {
		t.Fatalf("generation %d while held, %d before", hook.PolicyGeneration(), registered.PolicyGeneration)
	}
	if tags, _ := test.closer.take(); 0 < len(tags) {
		t.Fatalf("closed %v before the swap's closes", tags)
	}
	// connect's recheck: the published generation moved past the registered one, so the flow resolves again
	if recheck := hook.ResolveEgress(exit); registered.PolicyGeneration < hook.PolicyGeneration() && recheck.Verdict != connect.EgressVerdictDeny {
		t.Fatalf("the recheck: %+v", recheck)
	}
	if err := driver.Release(site); err != nil {
		t.Fatal(err)
	}
	<-run.Ended()
	tags, generations := test.closer.take()
	if !slices.Contains(tags, egressTestTag(egressTestUntagged, []byte{device.BridgeRuleExit})) {
		t.Fatalf("closed %v", tags)
	}
	for _, generation := range generations {
		if generation != registered.PolicyGeneration+1 {
			t.Fatalf("a close at generation %d", generation)
		}
	}
	if violations := driver.Violations(); len(violations) != 0 {
		t.Errorf("the sites broke the naming rule: %v", violations)
	}
}
