// DecisionNow (bridge_state.go): what a forwarding role's producer reads at each time the posture's overdue alarm is
// due (DESIGN-DETAILS 4.2.5, QD-696). Decision answers the decision the bridge last adopted, whose Overdue that
// adoption read, so a producer reading it at an alarm time raised nothing: BRIDGE-M8-07's schedule on BridgeNet found
// the alarm never reached the Forwarder.

package device

import (
	"context"
	"testing"
	"time"
)

// A bridge restored over an uncheckable revocation: at 10 min Decision still answers no Overdue, DecisionNow raises
// the alarm and adopts it, the status showing the condition, a read between points raises nothing new, the 30 min
// point raises again, and none of it republishes the hook's state.
func TestBridgeDecisionNowRaisesTheOverdueAlarm(t *testing.T) {
	fixture := newPostureFixture(t)
	clock := newPostureTestClock()
	postureSettings := testPostureSettingsOn(clock)
	store := newMemoryPostureStore()
	firstSeen := clock.Now()
	_, revoke := fixture.uncheckableRevocation(store, postureSettings)
	settings := DefaultBridgeSettings()
	settings.PostureSettings = postureSettings
	bridge, err := NewBridge(context.Background(), store.survivor(), nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	generation := bridge.EgressHook().PolicyGeneration()

	clock.advance(10 * time.Minute)
	if decision := bridge.Decision(); decision.Overdue != nil || len(postureOverdueAlarms(decision)) != 0 {
		t.Fatalf("the adopted decision moved with the clock: %+v, %v", decision.Overdue, decision.Alarms)
	}
	checkPostureOverdue(t, bridge.DecisionNow(), firstSeen, revoke, 10, 30, revoke, 10)
	// adopted: Decision answers it from here on, and the status shows the condition
	checkPostureOverdue(t, bridge.Decision(), firstSeen, revoke, 10, 30, revoke, 10)
	if overdue := bridge.Status().Overdue; overdue == nil || overdue.N != revoke || overdue.Age != 10*time.Minute {
		t.Fatalf("the status's overdue condition: %+v", overdue)
	}
	// between points a read finds the same raise, which its reader holds to once
	clock.advance(5 * time.Minute)
	checkPostureOverdue(t, bridge.DecisionNow(), firstSeen, revoke, 15, 30, revoke, 10)
	clock.advance(15 * time.Minute)
	checkPostureOverdue(t, bridge.DecisionNow(), firstSeen, revoke, 30, 70, revoke, 30)
	if after := bridge.EgressHook().PolicyGeneration(); after != generation {
		t.Errorf("reading the decision republished the hook's state: generation %d, then %d", generation, after)
	}
}
